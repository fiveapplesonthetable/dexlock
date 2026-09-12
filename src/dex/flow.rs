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

//! Held-lock dataflow shared by the hazard analyses.
//!
//! [`scan`] is the intra-procedural pass: it walks a method maintaining the set of
//! locks held at each point (monitor-enter/exit, j.u.c `Lock.lock`/`unlock`, and an
//! `entry` seed) and reports the held set at every call. [`entry_held`] lifts that
//! past the caller-holds-the-lock convention (`…Locked` / `@GuardedBy` helpers,
//! where the lock is taken one frame up): it infers the locks held on entry to each
//! *private* method as the intersection of the held sets at all of its call sites,
//! solved as a monotone fixpoint over the call graph.
//!
//! Only private methods are inferred: a private method is callable only from within
//! its own class, so every call site is inside the analyzed DEX and the intersection
//! is over the *complete* set of callers. A public/protected/package method could be
//! called from outside the analyzed artifacts with no lock held, so assuming a lock
//! there would be unsound; those get an empty entry set. Instance-field locks are
//! named per class (`Recv(C).f`), so a lock held in a caller carries its canonical
//! name into a same-class callee with no per-object substitution needed.

use crate::dex::juc::{self, LockCall};
use crate::dex::model::*;
use rayon::prelude::*;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

const ACC_PRIVATE: u32 = 0x2;
/// Cap on fixpoint rounds. The lock universe is finite and entry sets grow
/// monotonically, so this converges well within the cap on real inputs; the bound
/// is only a backstop against a pathological call graph.
const MAX_ROUNDS: usize = 16;

/// Walk `m` maintaining the held-lock set (seeded with `entry`), invoking `on_call`
/// at each non-lock `Invoke` with the locks held there (grounded) and the source
/// line. Monitor-enter/exit and j.u.c `Lock.lock`/`unlock` adjust the held set.
pub(super) fn scan<F: FnMut(&Invoke, &[Lock], Option<u32>)>(m: &Method, entry: &[Lock], mut on_call: F) {
    let mut regs: HashMap<Reg, Lock> = HashMap::default();
    if let Some(t) = m.this_reg() {
        regs.insert(t, Lock::new(Root::This));
        for j in 1..m.ins {
            regs.insert(t + j, Lock::new(Root::Param(j)));
        }
    }
    let ground = |l: &Lock| l.ground(&m.class, &m.key());
    let mut held: Vec<Lock> = entry.to_vec();

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
            Op::NewInstance { dst, .. } | Op::MoveResult { dst } | Op::Def(dst) => {
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
            Op::Invoke(inv) => match juc::classify(&inv.class, &inv.name) {
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
                _ => on_call(inv, &held, m.line_at(insn.offset)),
            },
            _ => {}
        }
    }
}

/// Locks held on entry to each private method, inferred interprocedurally. Keyed by
/// method key; a method absent from the map (or mapping to an empty vec) has no
/// inferred entry lock. Values are sorted by lock name so rounds compare cleanly.
pub(super) fn entry_held(dex: &Dex) -> HashMap<String, Vec<Lock>> {
    let methods: Vec<&Method> = dex.classes.iter().flat_map(|c| c.methods.iter()).collect();
    // Eligible callees: private methods, whose every caller is in-class (visible).
    let eligible: HashSet<String> =
        methods.iter().filter(|m| m.access & ACC_PRIVATE != 0).map(|m| m.key()).collect();
    if eligible.is_empty() {
        return HashMap::default();
    }

    let mut entry: HashMap<String, Vec<Lock>> = HashMap::default();
    let empty: Vec<Lock> = Vec::new();
    for _round in 0..MAX_ROUNDS {
        // Each method contributes, per call site targeting an eligible callee, the
        // set of locks held there (seeded with the callee-independent current entry
        // set of the *calling* method).
        let per_method: Vec<Vec<(String, Vec<Lock>)>> = methods
            .par_iter()
            .map(|m| {
                let seed = entry.get(&m.key()).unwrap_or(&empty);
                let mut out = Vec::new();
                scan(m, seed, |inv, held, _line| {
                    let k = inv.key();
                    if eligible.contains(&k) {
                        out.push((k, held.to_vec()));
                    }
                });
                out
            })
            .collect();

        let mut sites: HashMap<String, Vec<Vec<Lock>>> = HashMap::default();
        for v in per_method {
            for (k, held) in v {
                sites.entry(k).or_default().push(held);
            }
        }

        let mut next: HashMap<String, Vec<Lock>> = HashMap::default();
        for (k, sets) in sites {
            let inter = intersect(sets);
            if !inter.is_empty() {
                next.insert(k, inter);
            }
        }
        if next == entry {
            break;
        }
        entry = next;
    }
    entry
}

/// Intersect held-lock sets by canonical name (a lock counts only if held at *every*
/// site), dropping opaque/unnameable locks. Result sorted by name.
fn intersect(sets: Vec<Vec<Lock>>) -> Vec<Lock> {
    let mut it = sets.into_iter();
    let Some(first) = it.next() else { return Vec::new() };
    let mut acc: HashMap<String, Lock> =
        first.into_iter().filter(|l| !l.is_opaque()).map(|l| (l.name(), l)).collect();
    for s in it {
        if acc.is_empty() {
            break;
        }
        let names: HashSet<String> = s.iter().filter(|l| !l.is_opaque()).map(|l| l.name()).collect();
        acc.retain(|n, _| names.contains(n));
    }
    let mut v: Vec<Lock> = acc.into_values().collect();
    v.sort_by_key(|l| l.name());
    v
}
