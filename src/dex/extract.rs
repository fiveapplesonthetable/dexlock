// Copyright (C) 2026 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Per-method extraction for lock resolution. A linear pass over the decoded
//! instructions recovers, per register, the lock identity of every value, and
//! records each monitor-enter / `Lock.lock` site plus the field stores, parameter
//! stores, and call-site argument bindings the global phase needs to resolve those
//! locks interprocedurally.

use super::{subst_or_self, Summary};
use crate::dex::juc::{self, LockCall};
use crate::dex::model::*;
use std::collections::HashMap;

pub(super) fn extract(m: &Method, value_summaries: &HashMap<String, Lock>) -> Summary {
    let mut s = Summary { key: m.key(), class: m.class.clone(), ..Default::default() };
    let mut regs: HashMap<Reg, Lock> = HashMap::new();
    let mut alloc_ty: HashMap<String, String> = HashMap::new();
    let mut last_ret: Option<Lock> = None;
    let mut returns: Vec<Option<Lock>> = Vec::new();

    // Receiver in the low param register, formals above it (`this` = registers-ins).
    if let Some(t) = m.this_reg() {
        regs.insert(t, Lock::new(Root::This));
        for j in 1..m.ins {
            regs.insert(t + j, Lock::new(Root::Param(j)));
        }
    } else if m.ins > 0 {
        let base = m.registers.saturating_sub(m.ins);
        for j in 0..m.ins {
            regs.insert(base + j, Lock::new(Root::Param(j)));
        }
    }

    let opaque = |off: u32| Lock::new(Root::Opaque(format!("{}+{:04x}", m.key(), off)));

    for insn in &m.insns {
        let line = m.line_at(insn.offset);
        match &insn.op {
            Op::Sget { dst, class, field } => {
                regs.insert(*dst, Lock::field(Root::Static(class.clone()), field.clone()));
            }
            Op::Iget { dst, class, field, .. } => {
                regs.insert(*dst, Lock::field(Root::Recv(class.clone()), field.clone()));
            }
            Op::Iput { src, base, class, field } => {
                // `this.field = <value>`: a formal stays symbolic (resolved
                // interprocedurally via `param_stores`); a concrete field/static is
                // aliased directly. So `mGlobalLock = Service.this` makes the field
                // the same lock as `synchronized(this)`.
                if regs.get(base).is_some_and(|l| matches!(l.root, Root::This)) {
                    let key = format!("{class}.{field}");
                    if let Some(v) = regs.get(src).cloned() {
                        if let Root::Param(idx) = v.root {
                            s.param_stores.push((key, idx));
                        } else {
                            let g = v.ground(&m.class, &m.key());
                            if matches!(g.root, Root::Recv(_) | Root::Static(_)) && g.name() != key {
                                s.field_aliases.push((key, g));
                            }
                        }
                    }
                }
                if let Some(Root::Alloc(site)) = regs.get(src).map(|l| l.root.clone()) {
                    if let Some(ty) = alloc_ty.get(&site) {
                        s.alloc_stores.push((format!("{class}.{field}"), ty.clone()));
                    }
                }
                // Must-alias: an allocation stored into `this.field` IS that field
                // henceforth, so a later use of the same register — e.g. the register
                // R8 forwards straight into a setter instead of reloading with an
                // `iget` — carries the field identity instead of an opaque allocation.
                if regs.get(base).is_some_and(|l| matches!(l.root, Root::This))
                    && regs.get(src).is_some_and(|l| matches!(l.root, Root::Alloc(_)))
                {
                    regs.insert(
                        *src,
                        Lock::new(Root::This).append(std::slice::from_ref(field), Mode::Plain),
                    );
                }
            }
            Op::ConstClass { dst, class } => {
                regs.insert(*dst, Lock::new(Root::ClassConst(class.clone())));
            }
            Op::NewInstance { dst, class } => {
                let site = format!("{}+{:04x}", m.key(), insn.offset);
                regs.insert(*dst, Lock::new(Root::Alloc(site.clone())));
                alloc_ty.insert(site, class.clone());
            }
            Op::Move { dst, src } => match regs.get(src).cloned() {
                Some(v) => { regs.insert(*dst, v); }
                None => { regs.remove(dst); }
            },
            Op::MoveResult { dst } => match last_ret.take() {
                Some(v) => { regs.insert(*dst, v); }
                None => { regs.remove(dst); }
            },
            Op::Def(dst) => { regs.remove(dst); }
            Op::Return(r) => returns.push(r.and_then(|rr| regs.get(&rr).cloned())),
            Op::Invoke(inv) => {
                last_ret = None;
                // Call-site binding for interprocedural parameter propagation: record
                // the resolved actuals of any invoke passing an object (receiver at
                // index 0, aligning with the callee's formal index).
                let bound = arg_vals(&regs, inv);
                if bound.iter().flatten().any(|l| {
                    matches!(l.root, Root::This | Root::Param(_) | Root::Recv(_) | Root::Static(_))
                }) {
                    s.arg_bindings.push((inv.key(), bound));
                }
                match juc::classify(&inv.class, &inv.name) {
                    // `readLock()`/`writeLock()` return a view of the same lock, tagged
                    // with the mode, so `rw.readLock().lock()` resolves to `rw`.
                    Some(LockCall::ReadView) => {
                        last_ret =
                            inv.args.first().and_then(|r| regs.get(r)).map(|l| l.with_mode(Mode::Read));
                    }
                    Some(LockCall::WriteView) => {
                        last_ret =
                            inv.args.first().and_then(|r| regs.get(r)).map(|l| l.with_mode(Mode::Write));
                    }
                    // `Lock.lock()` / `tryLock()`: a lock acquisition site, named by
                    // the receiver object.
                    Some(LockCall::Acquire | LockCall::TryAcquire) => {
                        let lock = inv
                            .args
                            .first()
                            .and_then(|r| regs.get(r))
                            .cloned()
                            .unwrap_or_else(|| opaque(insn.offset));
                        s.acq_sites.push((lock, line));
                    }
                    Some(LockCall::Release) => {}
                    // A trivial getter's return flows to its result, so
                    // `synchronized(getLock())` resolves through it.
                    None => {
                        last_ret = value_summaries
                            .get(&inv.key())
                            .and_then(|vs| subst_or_self(vs, &arg_vals(&regs, inv)));
                    }
                }
            }
            Op::MonitorEnter(r) => {
                let lock = regs.get(r).cloned().unwrap_or_else(|| opaque(insn.offset));
                s.acq_sites.push((lock, line));
            }
            Op::MonitorExit(_) | Op::Goto(_) | Op::Branch(_) | Op::Throw | Op::Other => {}
        }
    }

    // A method whose every `return` yields the same simple value is a getter: record
    // that value so callers resolve `synchronized(getX())` through it.
    if let Some(Some(first)) = returns.first().cloned() {
        if returns.iter().all(|r| r.as_ref() == Some(&first)) && simple_value(&first) {
            s.value_summary = Some(first);
        }
    }
    s
}

fn simple_value(l: &Lock) -> bool {
    matches!(
        l.root,
        Root::This | Root::Param(_) | Root::Recv(_) | Root::Static(_) | Root::ClassConst(_)
    )
}

fn arg_vals(regs: &HashMap<Reg, Lock>, inv: &Invoke) -> Vec<Option<Lock>> {
    inv.args.iter().map(|r| regs.get(r).cloned()).collect()
}
