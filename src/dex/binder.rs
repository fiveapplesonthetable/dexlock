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

//! Binder-call-while-locked: flag a (potentially blocking) binder transaction made
//! while holding a lock — a classic system_server ANR / lock-inversion source.
//!
//! A binder call is recognized structurally: an invoke of `IBinder.transact`, or an
//! invoke of a method on an AIDL interface (a type transitively extending
//! `android.os.IInterface`) — that is the client surface whose call does a
//! synchronous transact. The held-lock set is tracked exactly as elsewhere
//! (monitor-enter/exit, `Lock.lock/unlock`, and a `synchronized` method's implicit
//! monitor). This pass is intra-procedural, so it **under**-reports (it misses calls
//! made from a `…Locked` helper whose lock is held by the caller) rather than
//! over-reporting: a finding is a lock demonstrably held across a binder call.

use crate::dex::juc::{self, LockCall};
use crate::dex::model::*;
use rayon::prelude::*;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

const IINTERFACE: &str = "android.os.IInterface";

/// A binder call made while holding a lock.
pub struct Finding {
    pub method: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub held: Vec<String>,
    pub callee: String,
}

/// Find every binder call made while a lock is held.
pub fn binder_under_lock(dex: &Dex) -> Vec<Finding> {
    let ifaces = binder_interfaces(dex);
    let mut out: Vec<Finding> = dex
        .classes
        .par_iter()
        .flat_map_iter(|c| c.methods.iter())
        .flat_map(|m| scan_method(m, &ifaces))
        .collect();
    out.sort_by(|a, b| {
        (&a.method, a.line, &a.callee).cmp(&(&b.method, b.line, &b.callee))
    });
    out
}

/// Classes that transitively extend `android.os.IInterface` — the AIDL surface.
fn binder_interfaces(dex: &Dex) -> HashSet<String> {
    // parent edges: class -> its superclass and interfaces.
    let mut parents: HashMap<&str, Vec<&str>> = HashMap::default();
    for c in &dex.classes {
        let e = parents.entry(c.descriptor.as_str()).or_default();
        if let Some(s) = &c.super_class {
            e.push(s.as_str());
        }
        for i in &c.interfaces {
            e.push(i.as_str());
        }
    }
    let mut memo: HashMap<&str, bool> = HashMap::default();
    fn reaches<'a>(
        c: &'a str,
        parents: &HashMap<&'a str, Vec<&'a str>>,
        memo: &mut HashMap<&'a str, bool>,
        depth: usize,
    ) -> bool {
        if c == IINTERFACE {
            return true;
        }
        if depth > 64 {
            return false;
        }
        if let Some(&v) = memo.get(c) {
            return v;
        }
        memo.insert(c, false); // break cycles
        let v = parents
            .get(c)
            .map(|ps| ps.iter().any(|p| reaches(p, parents, memo, depth + 1)))
            .unwrap_or(false);
        memo.insert(c, v);
        v
    }
    let names: Vec<&str> = dex.classes.iter().map(|c| c.descriptor.as_str()).collect();
    let mut out = HashSet::default();
    for c in names {
        if reaches(c, &parents, &mut memo, 0) {
            out.insert(c.to_string());
        }
    }
    out
}

/// True if this invoke is a *remote* binder call.
///
/// The low-level `IBinder.transact` counts directly. Otherwise it must be an AIDL
/// call dispatched **through the interface type** (`invoke-interface` on a type that
/// transitively extends `IInterface`) or into a generated `$Stub$Proxy` — that is
/// the client surface whose call blocks on a synchronous transact. A service
/// invoking its *own* helper is `invoke-virtual`/`-direct` on the concrete impl
/// (which merely happens to implement a `$Stub`); that is a local call, not a
/// transaction, so restricting to interface dispatch excludes it. Static factories
/// (`asInterface`, `Stub.getDefaultImpl`) and the non-transacting `IInterface`
/// plumbing never count.
fn is_binder_call(inv: &Invoke, ifaces: &HashSet<String>) -> bool {
    if inv.class == "android.os.IBinder" && inv.name.starts_with("transact") {
        return true;
    }
    if inv.name.starts_with('<') || inv.name == "asBinder" || inv.name == "getInterfaceDescriptor" {
        return false;
    }
    if inv.class.ends_with("$Stub$Proxy") {
        return true;
    }
    inv.kind == InvokeKind::Interface && ifaces.contains(&inv.class)
}

fn scan_method(m: &Method, ifaces: &HashSet<String>) -> Vec<Finding> {
    let mut regs: HashMap<Reg, Lock> = HashMap::default();
    if let Some(t) = m.this_reg() {
        regs.insert(t, Lock::new(Root::This));
        for j in 1..m.ins {
            regs.insert(t + j, Lock::new(Root::Param(j)));
        }
    }

    // No seeding for `synchronized` methods: d8/R8 lower them to explicit
    // monitor-enter/exit over the body (the DEX flag is the informational
    // `ACC_DECLARED_SYNCHRONIZED` 0x20000, not the runtime-enforced 0x20), so the
    // implicit monitor is already tracked by the MonitorEnter arm below.
    let mut held: Vec<Lock> = Vec::new();
    let ground = |l: &Lock| l.ground(&m.class, &m.key());
    // Only nameable (non-opaque) held locks: a `synchronized(param)` that doesn't
    // resolve intra-procedurally grounds to an opaque, which we don't report on.
    let names = |held: &[Lock]| -> Vec<String> {
        held.iter().filter(|l| !l.is_opaque()).map(|l| l.name()).collect()
    };

    let mut out = Vec::new();
    for insn in &m.insns {
        match &insn.op {
            Op::Iget { dst, class, field, .. } => {
                regs.insert(*dst, Lock::field(Root::Recv(class.clone()), field.clone()));
            }
            Op::Sget { dst, class, field } => {
                regs.insert(*dst, Lock::field(Root::Static(class.clone()), field.clone()));
            }
            Op::ConstClass { dst, class } => {
                regs.insert(*dst, Lock::new(Root::ClassConst(class.clone())));
            }
            Op::Move { dst, src } => match regs.get(src).cloned() {
                Some(v) => { regs.insert(*dst, v); }
                None => { regs.remove(dst); }
            },
            Op::NewInstance { dst, .. } | Op::MoveResult { dst } => {
                regs.remove(dst);
            }
            Op::MonitorEnter(r) => {
                if let Some(l) = regs.get(r).cloned() {
                    held.push(ground(&l));
                }
            }
            Op::MonitorExit(r) => {
                let name = regs.get(r).map(|l| ground(l).name());
                match name.and_then(|n| held.iter().rposition(|h| h.name() == n)) {
                    Some(pos) => { held.remove(pos); }
                    None => { held.pop(); }
                }
            }
            Op::Invoke(inv) => {
                match juc::classify(&inv.class, &inv.name) {
                    Some(LockCall::Acquire | LockCall::TryAcquire) => {
                        if let Some(l) = inv.args.first().and_then(|r| regs.get(r)).cloned() {
                            held.push(ground(&l));
                        }
                    }
                    Some(LockCall::Release) => {
                        if let Some(n) = inv.args.first().and_then(|r| regs.get(r)).map(|l| ground(l).name()) {
                            if let Some(pos) = held.iter().rposition(|h| h.name() == n) {
                                held.remove(pos);
                            }
                        }
                    }
                    _ => {
                        if is_binder_call(inv, ifaces) && held.iter().any(|l| !l.is_opaque()) {
                            out.push(Finding {
                                method: m.key(),
                                file: m.source_file.clone(),
                                line: m.line_at(insn.offset),
                                held: names(&held),
                                callee: format!("{}.{}", inv.class, inv.name),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}
