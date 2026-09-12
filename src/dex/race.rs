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

//! Inconsistent locking: a field guarded by a lock nearly everywhere, and written
//! somewhere with **no lock held on any path**.
//!
//! `@GuardedBy` is source-retained, so nothing here reads an annotation, and no
//! guard is guessed from a name. Each finding is three facts about the call graph:
//!
//! 1. **Lock `L` is held at these accesses.** A *must* set: taken in the accessing
//!    method, or held on entry to a private helper by every one of its callers
//!    (`flow::entry_held`). What is reported is what the bytecode does.
//! 2. **This write holds nothing, on any path.** A *may* set: the write's method has
//!    no lock on entry from any caller within [`ctx::Options::max_depth`] frames
//!    ([`ctx::Index::may_held`]), and takes none itself before the write. This is
//!    what the previous, withdrawn version of this pass got wrong: it called an
//!    access unguarded when it merely could not *see* a lock, so every
//!    caller-locked `…Locked` helper was a false positive. Such a helper now has
//!    its caller's lock in its may set and is never reported.
//! 3. **The write is reachable from a thread that runs concurrently** — a method
//!    serving an AIDL interface (a binder thread), a `Runnable`/`Thread` `run`, or
//!    a `Handler.handleMessage` — over the same call graph. Reported per access;
//!    an unreachable one is evidence of nothing.
//!
//! Together these say the field's locking discipline is inconsistent, with a
//! witness for each half. Whether that inconsistency is a bug — the field may be
//! benign, racy-but-tolerated, or published safely — is left to the reader; this
//! pass does not claim it.
//!
//! Excluded, by definition rather than by guess: `final` and `volatile` fields,
//! fields never written, and writes in `<init>`/`<clinit>` (a constructor runs
//! before publication and a static initializer is serialized by the runtime).
//!
//! An access inside a compiler-generated accessor — the forwarder emitted so an
//! inner class can touch an outer field — is reported at the *call sites* instead.
//! The forwarder is not a program point anyone wrote: it carries no line number, and
//! the locks that matter are the ones held where it is called. Such a method is
//! recognized structurally, by having no real line table (d8 gives it a single
//! entry of line 0) and a body of nothing but the field access, never by its name.

use crate::dex::ctx::{self, Index};
use crate::dex::flow::{self, Event};
use crate::dex::model::*;
use rayon::prelude::*;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::collections::VecDeque;

const IINTERFACE: &str = "android.os.IInterface";

/// Thresholds for calling a field's locking discipline established. Both are
/// stated rather than tuned away: a lock is the field's guard when it is held at
/// `min_ratio` of the accesses and at least `min_guarded` of them.
pub struct Options {
    pub min_guarded: usize,
    pub min_ratio: f64,
    /// Passed through to the lock-context index.
    pub ctx: ctx::Options,
}

impl Default for Options {
    fn default() -> Self {
        Options { min_guarded: 3, min_ratio: 0.8, ctx: ctx::Options::default() }
    }
}

/// One access to a field.
pub struct Access {
    pub method: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub write: bool,
    /// Locks demonstrably held here (empty on an unguarded access).
    pub held: Vec<String>,
    /// The access is reachable from a binder, `Runnable`/`Thread` or `Handler` entry.
    pub concurrent: bool,
}

/// A field whose locking discipline is inconsistent.
pub struct Finding {
    pub field: String,
    /// The lock held at `guarded` of the field's `total` accesses.
    pub guard: String,
    pub guarded: usize,
    pub total: usize,
    /// Accesses holding `guard`, as evidence of the discipline.
    pub guarded_at: Vec<Access>,
    /// Writes holding no lock on any path.
    pub unguarded: Vec<Access>,
}

/// One raw access, before fields are grouped.
struct Raw {
    field: String,
    method: u32,
    line: Option<u32>,
    write: bool,
    held: Vec<String>,
    /// No lock is held here on any path into the method.
    unlocked: bool,
}

/// Fields with an inconsistent locking discipline, strongest evidence first.
pub fn races(dex: &Dex, opts: &Options) -> Vec<Finding> {
    let t0 = std::time::Instant::now();
    let idx = ctx::build(dex, &opts.ctx);
    let concurrent = concurrent_methods(dex, &idx);
    log::debug!("race: index + concurrency roots {:.2?}", t0.elapsed());

    // The index enumerates methods in this same order, so a position is a method id
    // in both. Method keys are not unique across merged artifacts (14k of 700k
    // repeat on a full system image), so they cannot serve as the identity here.
    let methods: Vec<&Method> = dex.classes.iter().flat_map(|c| c.methods.iter()).collect();
    debug_assert_eq!(methods.len(), idx.methods.len());
    let entry = flow::entry_held(dex, false);
    let effects = flow::effects(dex);
    let empty: Vec<Lock> = Vec::new();

    // Compiler-generated field accessors: no line table, and a body that does
    // nothing but touch the field. Their accesses are attributed to their callers.
    let forwarder: Vec<bool> = methods
        .iter()
        .map(|m| {
            // d8 gives these a line table whose only entry is line 0 — the absence
            // of a source line, not a line.
            m.positions.iter().all(|&(_, l)| l == 0)
                && m.insns.iter().any(|i| matches!(i.op, Op::Iget { .. } | Op::Iput { .. } | Op::Sget { .. } | Op::Sput { .. }))
                && !m.insns.iter().any(|i| matches!(i.op, Op::Invoke(_) | Op::MonitorEnter(_) | Op::MonitorExit(_)))
        })
        .collect();
    log::debug!("race: {} compiler-generated field accessors", forwarder.iter().filter(|f| **f).count());

    let raw: Vec<Raw> = methods
        .par_iter()
        .enumerate()
        .filter(|(_, m)| !m.name.starts_with('<'))
        .flat_map_iter(|(id, m)| {
            let key = m.key();
            let id = id as u32;
            // A lock may reach this method only through a caller; with none, an
            // empty held set here is empty on every path.
            let may_free = idx.may_held(id).is_empty();
            let mut out = Vec::new();
            flow::walk(m, entry.get(&key).unwrap_or(&empty), &effects, |e| {
                if let Event::Field { class, field, write, held, line } = e {
                    let name = format!("{class}.{field}");
                    if forwarder[id as usize] {
                        // The access happens wherever the accessor is called, under
                        // whatever is held there. With no call site there is no path
                        // to it at all, and so nothing to report.
                        for &k in idx.callers_of(id) {
                            let c = &idx.calls[k as usize];
                            let held: Vec<String> =
                                c.held.iter().map(|&l| idx.locks[l as usize].clone()).collect();
                            out.push(Raw {
                                field: name.clone(),
                                method: c.caller,
                                line: Some(c.line),
                                write,
                                unlocked: idx.may_held(c.caller).is_empty() && held.is_empty(),
                                held,
                            });
                        }
                        return;
                    }
                    let held: Vec<String> =
                        held.iter().filter(|l| !l.is_opaque()).map(|l| l.name()).collect();
                    out.push(Raw {
                        field: name,
                        method: id,
                        line,
                        write,
                        unlocked: may_free && held.is_empty(),
                        held,
                    });
                }
            });
            out
        })
        .collect();
    log::debug!("race: {} field accesses in {:.2?}", raw.len(), t0.elapsed());

    let mut by_field: HashMap<String, Vec<Raw>> = HashMap::default();
    for r in raw {
        by_field.entry(r.field.clone()).or_default().push(r);
    }

    let access = |r: &Raw| Access {
        method: idx.methods[r.method as usize].key.clone(),
        file: Some(idx.files[idx.methods[r.method as usize].file as usize].clone()).filter(|f| !f.is_empty()),
        line: r.line,
        write: r.write,
        held: r.held.clone(),
        concurrent: concurrent[r.method as usize],
    };

    let mut out: Vec<Finding> = by_field
        .into_iter()
        .filter(|(f, _)| !dex.final_or_volatile_fields.contains(f))
        .filter(|(_, a)| a.iter().any(|r| r.write))
        .filter_map(|(field, accesses)| {
            // The candidate guard: the lock held at the most accesses.
            let mut counts: HashMap<&str, usize> = HashMap::default();
            for r in &accesses {
                for l in &r.held {
                    *counts.entry(l.as_str()).or_default() += 1;
                }
            }
            let (guard, guarded) = counts.into_iter().max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(a.0)))?;
            let total = accesses.len();
            if guarded < opts.min_guarded || (guarded as f64) < opts.min_ratio * total as f64 {
                return None;
            }
            let unguarded: Vec<Access> =
                accesses.iter().filter(|r| r.write && r.unlocked).map(&access).collect();
            if unguarded.is_empty() {
                return None;
            }
            let guarded_at: Vec<Access> =
                accesses.iter().filter(|r| r.held.iter().any(|l| l == guard)).map(&access).collect();
            Some(Finding { field, guard: guard.to_string(), guarded, total, guarded_at, unguarded })
        })
        .collect();
    // Strongest first: most corroborated discipline, then fewest exceptions.
    out.sort_by(|a, b| {
        let key = |f: &Finding| {
            (
                std::cmp::Reverse(f.unguarded.iter().filter(|u| u.concurrent).count().min(1)),
                std::cmp::Reverse(f.guarded),
                f.unguarded.len(),
            )
        };
        key(a).cmp(&key(b)).then(a.field.cmp(&b.field))
    });
    log::debug!("race: {} findings in {:.2?}", out.len(), t0.elapsed());
    out
}

/// Every method reachable from a thread entry point: a method serving an AIDL
/// interface (run on a binder thread), a `Runnable`/`Thread` `run`, or a
/// `Handler.handleMessage`. Forward reachability over the index's call graph.
fn concurrent_methods(dex: &Dex, idx: &Index) -> Vec<bool> {
    let mut parents: HashMap<&str, Vec<&str>> = HashMap::default();
    for c in &dex.classes {
        let e = parents.entry(c.descriptor.as_str()).or_default();
        e.extend(c.super_class.as_deref());
        e.extend(c.interfaces.iter().map(String::as_str));
    }
    let ancestors = |c: &str| -> HashSet<&str> {
        let mut seen: HashSet<&str> = HashSet::default();
        let mut q: VecDeque<&str> = VecDeque::from([c]);
        while let Some(x) = q.pop_front() {
            for &p in parents.get(x).map(Vec::as_slice).unwrap_or(&[]) {
                if seen.insert(p) {
                    q.push_back(p);
                }
            }
        }
        seen
    };
    // The AIDL surface, and the signatures each of its interfaces declares.
    let mut aidl: HashMap<&str, HashSet<String>> = HashMap::default();
    for c in &dex.classes {
        if ancestors(&c.descriptor).contains(IINTERFACE) {
            aidl.insert(
                c.descriptor.as_str(),
                c.methods.iter().map(|m| format!("{}:{}", m.name, m.sig)).collect(),
            );
        }
    }

    // Positional ids again: the index enumerates the same methods in the same order.
    let methods: Vec<&Method> = dex.classes.iter().flat_map(|c| c.methods.iter()).collect();
    let mut roots: Vec<usize> = Vec::new();
    let mut anc_memo: HashMap<&str, HashSet<&str>> = HashMap::default();
    for (i, m) in methods.iter().enumerate() {
        if m.is_static() || m.name.starts_with('<') {
            continue;
        }
        let sig = format!("{}:{}", m.name, m.sig);
        let anc = anc_memo.entry(m.class.as_str()).or_insert_with(|| ancestors(&m.class));
        let served = anc.iter().any(|a| aidl.get(a).is_some_and(|sigs| sigs.contains(&sig)));
        let threaded = (sig == "run:()V" && (anc.contains("java.lang.Runnable") || anc.contains("java.lang.Thread")))
            || (sig == "handleMessage:(Landroid/os/Message;)V" && anc.contains("android.os.Handler"));
        if served || threaded {
            roots.push(i);
        }
    }

    let mut seen = vec![false; idx.methods.len()];
    let mut q: VecDeque<usize> = VecDeque::new();
    for r in roots {
        if !seen[r] {
            seen[r] = true;
            q.push_back(r);
        }
    }
    while let Some(m) = q.pop_front() {
        let (c0, c1) = idx.methods[m].calls;
        for k in c0..c1 {
            for &t in &idx.calls[k as usize].targets {
                if !seen[t as usize] {
                    seen[t as usize] = true;
                    q.push_back(t as usize);
                }
            }
        }
    }
    seen
}
