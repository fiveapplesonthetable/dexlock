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

//! Inconsistent-locking (data-race) detection, RacerD-style and annotation-free.
//!
//! For each method a linear pass tracks the lock in each register and the set of
//! locks *held* at each point (monitor-enter/exit, `Lock.lock/unlock`, and the
//! implicit monitor of a `synchronized` method). Every instance-field access is
//! recorded with the locks held at it. Globally, a field that is written somewhere,
//! is not `final`/`volatile`, and is accessed **under a lock in several places but
//! with no lock in others** is flagged: the guard is inferred as the lock held on
//! most of its guarded accesses, and the unguarded accesses are the race sites.
//!
//! This is a heuristic (like RacerD): it infers intent from the guarded accesses,
//! so it can miss races on never-guarded fields and can flag benign
//! single-threaded ones. It is a lint signal, not a proof.

use crate::dex::juc::{self, LockCall};
use crate::dex::model::*;
use rayon::prelude::*;
use rustc_hash::FxHashMap as HashMap;

const ACC_SYNCHRONIZED: u32 = 0x20;

/// One access to a field, with the locks held at it.
#[derive(Clone)]
pub struct Access {
    pub method: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub write: bool,
    pub held: Vec<String>,
}

/// A field accessed inconsistently: guarded by `guard` in `guarded` places, but
/// touched with no lock at the `unguarded` sites (at least one side a write).
pub struct Race {
    pub field: String,
    pub guard: String,
    pub guarded: usize,
    pub unguarded: Vec<Access>,
}

/// Find inconsistent-locking races across the whole program.
pub fn races(dex: &Dex) -> Vec<Race> {
    // Per-method scan (independent) -> (field -> accesses), merged.
    let per_method: Vec<Vec<(String, Access)>> = dex
        .classes
        .par_iter()
        .flat_map_iter(|c| c.methods.iter())
        .map(scan_method)
        .collect();

    let mut by_field: HashMap<String, Vec<Access>> = HashMap::default();
    for accs in per_method {
        for (field, a) in accs {
            by_field.entry(field).or_default().push(a);
        }
    }

    let mut out = Vec::new();
    for (field, accesses) in by_field {
        if dex.final_or_volatile_fields.contains(&field) {
            continue; // final = write-once, volatile = lock-free by design
        }
        if !accesses.iter().any(|a| a.write) {
            continue; // read-only sharing is not a race
        }
        let guarded: Vec<&Access> = accesses.iter().filter(|a| !a.held.is_empty()).collect();
        let unguarded: Vec<Access> =
            accesses.iter().filter(|a| a.held.is_empty()).cloned().collect();
        // Intentionally guarded (>=2 locked accesses) yet touched unlocked elsewhere.
        if guarded.len() < 2 || unguarded.is_empty() {
            continue;
        }
        // Infer the guard: the lock held on the most guarded accesses.
        let mut freq: HashMap<&str, usize> = HashMap::default();
        for a in &guarded {
            for l in &a.held {
                *freq.entry(l.as_str()).or_insert(0) += 1;
            }
        }
        let Some((guard, cover)) = freq.into_iter().max_by_key(|&(_, n)| n) else { continue };
        // The guard must be the norm for this field, not incidental.
        if cover < 2 {
            continue;
        }
        out.push(Race { field, guard: guard.to_string(), guarded: guarded.len(), unguarded });
    }
    out.sort_by(|a, b| a.field.cmp(&b.field));
    out
}

/// The top-level class of a (possibly nested) class name: `pkg.Foo$Bar` -> `pkg.Foo`.
fn top_level(class: &str) -> &str {
    class.split('$').next().unwrap_or(class)
}

/// Track register locks + the held-lock set, emitting one entry per instance-field
/// access as `(Class.field, access)`.
fn scan_method(m: &Method) -> Vec<(String, Access)> {
    // Skip construction: the object is not yet shared, so unlocked access is benign.
    if m.name == "<init>" || m.name == "<clinit>" {
        return Vec::new();
    }

    let mut regs: HashMap<Reg, Lock> = HashMap::default();
    if let Some(t) = m.this_reg() {
        regs.insert(t, Lock::new(Root::This));
        for j in 1..m.ins {
            regs.insert(t + j, Lock::new(Root::Param(j)));
        }
    }

    // A `synchronized` method holds its receiver (instance) or class for the whole body.
    let mut held: Vec<Lock> = Vec::new();
    if m.access & ACC_SYNCHRONIZED != 0 {
        held.push(if m.is_static() {
            Lock::new(Root::ClassConst(m.class.clone()))
        } else {
            Lock::new(Root::Recv(m.class.clone()))
        });
    }

    let ground = |l: &Lock| l.ground(&m.class, &m.key());
    // A held lock counts as a *guard* for a field only when it belongs to the same
    // top-level class as the field. A field on `Foo` (or `Foo$Inner`) guarded by
    // `Foo.mLock` is a real intra-class invariant; `ApplicationInfo.uid` merely read
    // while some service holds *its own* lock is incidental, not a guard — filtering
    // by owner class removes that whole class of false positives.
    let held_for = |held: &[Lock], field_class: &str| -> Vec<String> {
        let ft = top_level(field_class);
        held.iter()
            .filter_map(|l| {
                let owner = match &l.root {
                    Root::Recv(c) | Root::Static(c) | Root::ClassConst(c) => c.as_str(),
                    _ => return None,
                };
                (top_level(owner) == ft)
                    .then(|| l.name())
                    .filter(|n| !n.starts_with("?@"))
            })
            .collect()
    };

    let mut out = Vec::new();
    for insn in &m.insns {
        match &insn.op {
            Op::Iget { dst, class, field, .. } => {
                out.push((
                    format!("{class}.{field}"),
                    Access {
                        method: m.key(),
                        file: m.source_file.clone(),
                        line: m.line_at(insn.offset),
                        write: false,
                        held: held_for(&held, class),
                    },
                ));
                regs.insert(*dst, Lock::field(Root::Recv(class.clone()), field.clone()));
            }
            Op::Iput { class, field, .. } => {
                out.push((
                    format!("{class}.{field}"),
                    Access {
                        method: m.key(),
                        file: m.source_file.clone(),
                        line: m.line_at(insn.offset),
                        write: true,
                        held: held_for(&held, class),
                    },
                ));
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
                // Pop the matching held lock (else the most recent) — a linear
                // approximation of the structured enter/exit nesting.
                if let Some(l) = regs.get(r).map(&ground) {
                    let name = l.name();
                    if let Some(pos) = held.iter().rposition(|h| h.name() == name) {
                        held.remove(pos);
                    } else {
                        held.pop();
                    }
                } else {
                    held.pop();
                }
            }
            Op::Invoke(inv) => match juc::classify(&inv.class, &inv.name) {
                Some(LockCall::Acquire | LockCall::TryAcquire) => {
                    if let Some(l) = inv.args.first().and_then(|r| regs.get(r)).cloned() {
                        held.push(ground(&l));
                    }
                }
                Some(LockCall::Release) => {
                    if let Some(l) = inv.args.first().and_then(|r| regs.get(r)).map(&ground) {
                        let name = l.name();
                        if let Some(pos) = held.iter().rposition(|h| h.name() == name) {
                            held.remove(pos);
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
    out
}
