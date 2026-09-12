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

//! Held-lock dataflow shared by the hazard analyses and the context index.
//!
//! [`walk`] is the intra-procedural pass: which locks are held at every acquire,
//! release, and call in a method. It is control-flow aware. A `synchronized` block
//! with an early `return` compiles to a `monitor-exit` on that path *before* the
//! block's remaining code, and every block gets a catch-all handler that exits the
//! monitor and rethrows; a linear scan pops the lock at the first textual exit and
//! misreads everything after it as unlocked. So the method is split into basic
//! blocks (branch, switch, return/throw, and try-range boundaries), the held set is
//! solved forward over the block graph — branch, switch, fall-through, and
//! exception edges — and events are then replayed per block from its converged
//! entry state. The join is intersection: Java's structured locking makes the
//! monitor set path-independent, and for `tryLock` (acquired on the success path
//! only) intersection keeps the lock from leaking past the join.
//!
//! Register-to-lock tracking (what object a `monitor-enter`/`lock()` operand names)
//! stays a linear pass, as in resolution; the operand is defined immediately
//! before its use, so that is exact where it matters and byte-verified there.
//!
//! Locks taken or released *through a helper* — `acquireFooLock()` that returns
//! holding the lock, `releaseFooLock()` that drops it — are invisible to a walk that
//! treats calls as opaque. [`effects`] computes each method's net lock effect (the
//! locks it still holds on every return and the locks it releases for its caller),
//! as a fixpoint so nested helpers compose, and [`walk`] applies the callee's
//! effect at each call site.
//!
//! [`entry_held`] lifts the intra pass past the caller-holds-the-lock convention
//! (`…Locked` / `@GuardedBy` helpers): it infers the locks held on entry to each
//! *private* method as the intersection of the held sets at all of its call sites,
//! solved as a monotone fixpoint over the call graph.
//!
//! By default only private methods are inferred: a private method is callable only
//! from within its own class, so every call site is inside the analyzed DEX and the
//! intersection is over the *complete* set of callers. A public/protected/package
//! method could be called from outside the analyzed artifacts with no lock held, so
//! assuming a lock there would be unsound; those get an empty entry set.
//!
//! `closed_world` additionally infers any method whose exact `(name, sig)` is
//! declared by *no other class* in the analyzed program. A globally-unique signature
//! cannot be an override or a polymorphic target, so every `invoke-* U.name:sig`
//! resolves to that one method regardless of the static receiver type `U` — the full
//! caller set is exactly the call sites with that signature, with no class-hierarchy
//! guessing. This recovers non-private `…Locked` helpers, but its soundness rests on
//! the analyzed jars being the *whole* program: a caller in an omitted artifact would
//! be missed and could turn the must-intersection into a false positive. Off by
//! default; the caller asserts completeness by opting in.
//!
//! Instance-field locks are named per class (`Recv(C).f`), so a lock held in a caller
//! carries its canonical name into a same-class callee with no per-object
//! substitution needed.

use crate::dex::juc::{self, LockCall};
use crate::dex::model::*;
use rayon::prelude::*;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::collections::VecDeque;

const ACC_PRIVATE: u32 = 0x2;
/// Cap on fixpoint rounds. The lock universe is finite and entry sets grow
/// monotonically, so this converges well within the cap on real inputs; the bound
/// is only a backstop against a pathological call graph.
const MAX_ROUNDS: usize = 16;

/// One step of the held-lock walk over a method.
pub(super) enum Event<'a> {
    /// A lock was taken (monitor-enter / `Lock.lock`), grounded, at `line`, with
    /// `held` the locks already held there.
    Acquire { lock: &'a Lock, line: Option<u32>, held: &'a [Lock] },
    /// A lock was released (monitor-exit / `unlock`) at `line`; `enter` is the line
    /// of the acquisition it balances (`None` for a lock held on entry).
    Release { lock: &'a Lock, line: Option<u32>, enter: Option<u32> },
    /// A non-lock call, with every lock held at that point (grounded).
    Call { inv: &'a Invoke, held: &'a [Lock], line: Option<u32> },
}

/// The lock-relevant effect of one instruction, from the linear register pass.
enum LockOp {
    Enter(Lock),
    Exit(Option<Lock>),
    Acquire(Lock),
    Release(Option<Lock>),
    Call,
    None,
}

/// A method's net lock effect on its caller: locks it still holds on every return
/// (taken inside and not released) and locks it releases that it did not take.
#[derive(Clone, Default, PartialEq)]
pub(super) struct Effect {
    pub acquires: Vec<Lock>,
    pub releases: Vec<Lock>,
}

/// Net lock effects by method key; methods with no effect are absent.
pub(super) type Effects = HashMap<String, Effect>;

/// Held-lock stack: the locks plus the line each was taken on (`None` = on entry),
/// and the named releases that matched nothing (released on the caller's behalf).
#[derive(Clone, PartialEq)]
struct State {
    locks: Vec<Lock>,
    enters: Vec<Option<u32>>,
    unmatched: Vec<Lock>,
}

impl State {
    fn push(&mut self, l: Lock, line: Option<u32>) {
        self.locks.push(l);
        self.enters.push(line);
    }
    /// Release `name`: pop the innermost such lock, or note it as released for the caller.
    fn release(&mut self, name: &str, lock: &Lock) -> Option<(Lock, Option<u32>)> {
        let popped = self.pop(Some(name));
        if popped.is_none() && !self.unmatched.iter().any(|u| u.name() == name) {
            self.unmatched.push(lock.clone());
        }
        popped
    }
    /// Pop the innermost lock named `name` (or the innermost of all when `None`).
    fn pop(&mut self, name: Option<&str>) -> Option<(Lock, Option<u32>)> {
        let pos = match name {
            Some(n) => self.locks.iter().rposition(|h| h.name() == n)?,
            None => self.locks.len().checked_sub(1)?,
        };
        Some((self.locks.remove(pos), self.enters.remove(pos)))
    }
    /// Intersection by name, keeping this state's order. True if anything shrank.
    fn meet(&mut self, other: &State) -> bool {
        let before = (self.locks.len(), self.unmatched.len());
        let keep: Vec<bool> = self.locks.iter().map(|l| other.locks.iter().any(|o| o.name() == l.name())).collect();
        let mut i = 0;
        self.locks.retain(|_| { let k = keep[i]; i += 1; k });
        let mut i = 0;
        self.enters.retain(|_| { let k = keep[i]; i += 1; k });
        self.unmatched.retain(|u| other.unmatched.iter().any(|o| o.name() == u.name()));
        (self.locks.len(), self.unmatched.len()) != before
    }
}

/// Walk `m` reporting each acquire, release, and call with the locks held there,
/// seeded with `entry` (locks held on entry) and applying callees' `effects`.
pub(super) fn walk<F: FnMut(Event)>(m: &Method, entry: &[Lock], effects: &Effects, mut f: F) {
    run(m, entry, effects, Some(&mut f));
}

/// Callback type used when `run` is driven for its return states only.
type NoEmit = fn(Event);

/// The held-lock dataflow over `m`. Emits events through `emit` (replaying each
/// reachable block from its converged entry state) and returns the out-states of
/// the reachable blocks that end in a `return`.
fn run<F: FnMut(Event)>(m: &Method, entry: &[Lock], effects: &Effects, mut emit: Option<&mut F>) -> Vec<State> {
    let n = m.insns.len();
    if n == 0 {
        return Vec::new();
    }
    let key = m.key();
    let ground = |l: &Lock| l.ground(&m.class, &key);
    let opaque = |off: u32| Lock::new(Root::Opaque(format!("{key}+{off:04x}")));

    // 1. Linear register pass: the lock operand of every lock-shaped instruction.
    let mut regs: HashMap<Reg, Lock> = HashMap::default();
    if let Some(t) = m.this_reg() {
        regs.insert(t, Lock::new(Root::This));
        for j in 1..m.ins {
            regs.insert(t + j, Lock::new(Root::Param(j)));
        }
    }
    let mut last_ret: Option<Lock> = None;
    let mut ops: Vec<LockOp> = Vec::with_capacity(n);
    for insn in &m.insns {
        let mut op = LockOp::None;
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
            Op::MoveResult { dst } => match last_ret.take() {
                Some(v) => { regs.insert(*dst, v); }
                None => { regs.remove(dst); }
            },
            Op::NewInstance { dst, .. } | Op::Def(dst) => {
                regs.remove(dst);
            }
            // An unknown operand still pushes (an opaque) so exits stay balanced.
            Op::MonitorEnter(r) => {
                op = LockOp::Enter(regs.get(r).map(ground).unwrap_or_else(|| opaque(insn.offset)));
            }
            Op::MonitorExit(r) => op = LockOp::Exit(regs.get(r).map(ground)),
            Op::Invoke(inv) => {
                last_ret = None;
                let arg0 = inv.args.first().and_then(|r| regs.get(r));
                match juc::classify(&inv.class, &inv.name) {
                    // `readLock()` / `writeLock()` return a mode-tagged view of the
                    // same lock, so `rw.readLock().lock()` acquires `rw` (read).
                    Some(LockCall::ReadView) => last_ret = arg0.map(|l| l.with_mode(Mode::Read)),
                    Some(LockCall::WriteView) => last_ret = arg0.map(|l| l.with_mode(Mode::Write)),
                    Some(LockCall::Acquire | LockCall::TryAcquire) => {
                        op = LockOp::Acquire(arg0.map(ground).unwrap_or_else(|| opaque(insn.offset)));
                    }
                    Some(LockCall::Release) => op = LockOp::Release(arg0.map(ground)),
                    None => op = LockOp::Call,
                }
            }
            _ => {}
        }
        ops.push(op);
    }

    // 2. Basic blocks over the instruction list.
    let idx_of = |off: u32| -> usize { m.insns.partition_point(|i| i.offset < off) };
    let mut leader = vec![false; n + 1];
    leader[0] = true;
    for (i, insn) in m.insns.iter().enumerate() {
        match &insn.op {
            Op::Goto(t) | Op::Branch(t) => {
                leader[idx_of(*t)] = true;
                leader[i + 1] = true;
            }
            Op::Switch(ts) => {
                for t in ts {
                    leader[idx_of(*t)] = true;
                }
                leader[i + 1] = true;
            }
            Op::Return(_) | Op::Throw => leader[i + 1] = true,
            _ => {}
        }
    }
    for &(s, e, h) in &m.catches {
        leader[idx_of(s)] = true;
        leader[idx_of(e)] = true;
        leader[idx_of(h)] = true;
    }
    let mut blocks: Vec<(usize, usize)> = Vec::new();
    let mut block_of = vec![0usize; n];
    let mut start = 0;
    for (i, &lead) in leader.iter().enumerate().skip(1) {
        if i == n || lead {
            blocks.push((start, i));
            for b in block_of.iter_mut().take(i).skip(start) {
                *b = blocks.len() - 1;
            }
            start = i;
        }
    }
    let nb = blocks.len();
    let blk = |off: u32| -> Option<usize> {
        let i = idx_of(off);
        (i < n).then(|| block_of[i])
    };
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); nb];
    let mut exc: Vec<Vec<usize>> = vec![Vec::new(); nb];
    let mut returns: Vec<bool> = vec![false; nb];
    for (b, &(_, end)) in blocks.iter().enumerate() {
        let fall = (b + 1 < nb).then_some(b + 1);
        match &m.insns[end - 1].op {
            Op::Goto(t) => succ[b].extend(blk(*t)),
            Op::Branch(t) => {
                succ[b].extend(blk(*t));
                succ[b].extend(fall);
            }
            Op::Switch(ts) => {
                succ[b].extend(ts.iter().filter_map(|t| blk(*t)));
                succ[b].extend(fall);
            }
            Op::Return(_) => returns[b] = true,
            Op::Throw => {}
            _ => succ[b].extend(fall),
        }
    }
    for &(s, e, h) in &m.catches {
        let (si, ei) = (idx_of(s), idx_of(e));
        let Some(hb) = blk(h) else { continue };
        for (b, &(bs, be)) in blocks.iter().enumerate() {
            if bs < ei && be > si && !exc[b].contains(&hb) {
                exc[b].push(hb);
            }
        }
    }

    // 3. Forward dataflow of the held stack, intersection join.
    let transfer = |st: &mut State, b: usize, mut emit: Option<&mut F>| {
        let (bs, be) = blocks[b];
        for (insn, op) in m.insns[bs..be].iter().zip(&ops[bs..be]) {
            let line = m.line_at(insn.offset);
            match op {
                LockOp::Enter(l) | LockOp::Acquire(l) => {
                    if let Some(f) = emit.as_deref_mut() {
                        f(Event::Acquire { lock: l, line, held: &st.locks });
                    }
                    st.push(l.clone(), line);
                }
                LockOp::Exit(l) => {
                    let name = l.as_ref().map(|l| l.name());
                    if let Some((lock, enter)) = st.pop(name.as_deref()) {
                        if let Some(f) = emit.as_deref_mut() {
                            f(Event::Release { lock: &lock, line, enter });
                        }
                    }
                }
                LockOp::Release(l) => {
                    // Only a named unlock releases; an untracked one cannot be matched.
                    if let Some(l) = l {
                        if let Some((lock, enter)) = st.release(&l.name(), l) {
                            if let Some(f) = emit.as_deref_mut() {
                                f(Event::Release { lock: &lock, line, enter });
                            }
                        }
                    }
                }
                LockOp::Call => {
                    let Op::Invoke(inv) = &insn.op else { continue };
                    if let Some(f) = emit.as_deref_mut() {
                        f(Event::Call { inv, held: &st.locks, line });
                    }
                    // A helper's net effect: it may release for us, or return holding.
                    if let Some(eff) = effects.get(&inv.key()) {
                        for r in &eff.releases {
                            if let Some((lock, enter)) = st.release(&r.name(), r) {
                                if let Some(f) = emit.as_deref_mut() {
                                    f(Event::Release { lock: &lock, line, enter });
                                }
                            }
                        }
                        for a in &eff.acquires {
                            if let Some(f) = emit.as_deref_mut() {
                                f(Event::Acquire { lock: a, line, held: &st.locks });
                            }
                            st.push(a.clone(), line);
                        }
                    }
                }
                LockOp::None => {}
            }
        }
    };
    let mut inn: Vec<Option<State>> = vec![None; nb];
    inn[0] = Some(State { locks: entry.to_vec(), enters: vec![None; entry.len()], unmatched: Vec::new() });
    let mut queued = vec![false; nb];
    let mut work: VecDeque<usize> = VecDeque::from([0]);
    queued[0] = true;
    while let Some(b) = work.pop_front() {
        queued[b] = false;
        let entry_st = inn[b].clone().expect("queued blocks have a state");
        let mut out = entry_st.clone();
        transfer(&mut out, b, None);
        // Normal successors see the block's out state; handlers see its entry state
        // (a try range starts at a block boundary, so the locks held across it are
        // exactly those held on entry to each block it covers).
        let edges = succ[b].iter().map(|&s| (s, &out)).chain(exc[b].iter().map(|&h| (h, &entry_st)));
        for (s, st) in edges {
            let changed = match &mut inn[s] {
                None => {
                    inn[s] = Some(st.clone());
                    true
                }
                Some(cur) => cur.meet(st),
            };
            if changed && !queued[s] {
                queued[s] = true;
                work.push_back(s);
            }
        }
    }

    // 4. Replay each reachable block from its converged entry state, in order, and
    //    collect the out-states at returns.
    let mut outs = Vec::new();
    for (b, st) in inn.iter().enumerate() {
        let Some(st) = st else { continue };
        let mut st = st.clone();
        transfer(&mut st, b, emit.as_deref_mut());
        if returns[b] {
            outs.push(st);
        }
    }
    outs
}

/// A method's own net lock effect, given its callees' effects: the nameable locks
/// still held on every return (none were held on entry, so all were taken inside)
/// and the named releases that matched nothing on every return.
fn effect_of(m: &Method, effects: &Effects) -> Effect {
    let outs = run::<NoEmit>(m, &[], effects, None);
    let Some(first) = outs.first() else { return Effect::default() };
    let all = |pick: &dyn Fn(&State) -> Vec<Lock>| -> Vec<Lock> {
        let mut acc: Vec<Lock> = pick(first).into_iter().filter(|l| !l.is_opaque()).collect();
        for o in &outs[1..] {
            let names: HashSet<String> = pick(o).iter().map(|l| l.name()).collect();
            acc.retain(|l| names.contains(&l.name()));
        }
        acc.sort_by_key(|l| l.name());
        acc.dedup_by_key(|l| l.name());
        acc
    };
    Effect { acquires: all(&|s| s.locks.clone()), releases: all(&|s| s.unmatched.clone()) }
}

/// Net lock effects of every method, solved to a fixpoint so a helper that calls a
/// helper composes. Only methods with a non-empty effect appear.
pub(super) fn effects(dex: &Dex) -> Effects {
    let methods: Vec<&Method> = dex.classes.iter().flat_map(|c| c.methods.iter()).collect();
    let mut cur: Effects = HashMap::default();
    for _ in 0..MAX_ROUNDS {
        let next: Effects = methods
            .par_iter()
            .filter_map(|m| {
                let e = effect_of(m, &cur);
                (!e.acquires.is_empty() || !e.releases.is_empty()).then(|| (m.key(), e))
            })
            .collect();
        if next == cur {
            break;
        }
        cur = next;
    }
    cur
}

/// [`walk`] restricted to calls: `on_call(invoke, held, line)`.
pub(super) fn scan<F: FnMut(&Invoke, &[Lock], Option<u32>)>(m: &Method, entry: &[Lock], effects: &Effects, mut on_call: F) {
    walk(m, entry, effects, |e| {
        if let Event::Call { inv, held, line } = e {
            on_call(inv, held, line);
        }
    });
}

/// Locks held on entry to each inferable method, computed interprocedurally. Keyed
/// by method key; a method absent from the map (or mapping to an empty vec) has no
/// inferred entry lock. Values are sorted by lock name so rounds compare cleanly.
/// With `closed_world`, methods with a globally-unique `(name, sig)` are inferred too
/// (see the module docs for the soundness condition).
pub(super) fn entry_held(dex: &Dex, closed_world: bool) -> HashMap<String, Vec<Lock>> {
    let methods: Vec<&Method> = dex.classes.iter().flat_map(|c| c.methods.iter()).collect();

    // Exact-key callees: private methods, whose every caller is in-class (visible).
    let eligible_exact: HashSet<String> =
        methods.iter().filter(|m| m.access & ACC_PRIVATE != 0).map(|m| m.key()).collect();

    // Closed-world: methods whose `(name, sig)` is declared exactly once program-wide.
    // Any `invoke-* U.name:sig` then resolves to this method whatever `U` is, so a
    // call site is matched by signature, not by the static receiver class.
    let mut sig_to_key: HashMap<String, String> = HashMap::default();
    if closed_world {
        let mut count: HashMap<String, u32> = HashMap::default();
        for m in &methods {
            let sig = format!("{}:{}", m.name, m.sig);
            *count.entry(sig.clone()).or_default() += 1;
            sig_to_key.insert(sig, m.key());
        }
        sig_to_key.retain(|sig, _| count.get(sig) == Some(&1));
    }

    if eligible_exact.is_empty() && sig_to_key.is_empty() {
        return HashMap::default();
    }
    // Resolve a call site to the method key it feeds, if that method is inferable.
    let target = |inv: &Invoke| -> Option<String> {
        let ek = inv.key();
        if eligible_exact.contains(&ek) {
            return Some(ek);
        }
        if closed_world {
            return sig_to_key.get(&format!("{}:{}", inv.name, inv.sig)).cloned();
        }
        None
    };

    let eff = effects(dex);
    let mut entry: HashMap<String, Vec<Lock>> = HashMap::default();
    let empty: Vec<Lock> = Vec::new();
    for _round in 0..MAX_ROUNDS {
        // Each method contributes, per call site targeting an inferable callee, the
        // set of locks held there (seeded with the callee-independent current entry
        // set of the *calling* method).
        let per_method: Vec<Vec<(String, Vec<Lock>)>> = methods
            .par_iter()
            .map(|m| {
                let seed = entry.get(&m.key()).unwrap_or(&empty);
                let mut out = Vec::new();
                scan(m, seed, &eff, |inv, held, _line| {
                    if let Some(k) = target(inv) {
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
