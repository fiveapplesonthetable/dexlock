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

//! Lock-context index: for any method, source line, or lock, which locks *may* be
//! held there, how many call frames away each was taken and by what path, and the
//! lock-order graph.
//!
//! The index is one interned call graph. Every method records its lock *spans*
//! (each acquisition with the line range it is held over) and its call sites, each
//! tagged with the locks held intra-procedurally at that point. Call sites link to
//! their static target (resolved up the class hierarchy) and, for virtual /
//! interface dispatch with a small implementation set, to each override (a
//! bounded class-hierarchy analysis — a broad interface such as `Runnable.run`
//! is deliberately not linked, since "every lock any caller holds" is noise).
//!
//! Over that graph, `dist[m][l]` — the fewest call frames between a frame holding
//! lock `l` and entry to `m` — is the least fixpoint of
//! `dist[m][l] = min over callers c of (1 if l is held at the call site, else
//! dist[c][l] + 1)`, cut off at [`Options::max_depth`]. A lock is "may-held" on
//! entry to `m` iff it has a distance. Distance is what makes a *may* set usable:
//! unbounded propagation makes a lock taken near the top of a service reachable
//! from most of the program, so queries rank by distance and the lock-order graph
//! only relates locks within [`Options::order_depth`] frames. Every member is
//! backed by a concrete call path, which [`Index::witness`] recovers by walking
//! the distances back to the acquiring frame. Lock names are the canonical
//! identities from [`crate::dex::acquisitions`], so a lock reached through an
//! alias or a getter is one lock here too.
//!
//! The lock-order graph (`Y -> X`: X acquired while Y is held) falls out of the
//! same data; its non-trivial strongly connected components are the deadlock
//! candidates. The index persists as a compact little-endian binary
//! ([`Index::write`] / [`Index::read`]) so a query loads in well under a second.

use crate::dex::flow::{self, Event};
use crate::dex::model::*;
use anyhow::{bail, Context, Result};
use rayon::prelude::*;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::collections::VecDeque;
use std::io::{Read, Write};

/// Line used when a method has no debug position for an instruction.
const NO_LINE: u32 = 0;
/// A span whose release was not observed is held to the end of the method.
const TO_END: u32 = u32::MAX;
const MAGIC: &[u8; 8] = b"DXLKCTX1";

/// A lock acquisition and the source-line range it is held over.
#[derive(Clone, Debug)]
pub struct Span {
    pub lock: u32,
    pub enter: u32,
    /// Exclusive; [`TO_END`] when the release was not observed in the method.
    pub exit: u32,
    /// Locks (intra-procedural) already held when this one was taken.
    pub held: Vec<u32>,
}

/// A call site: where in the caller, what is held there, and what it may reach.
#[derive(Clone, Debug)]
pub struct Call {
    pub caller: u32,
    pub line: u32,
    /// Locks held intra-procedurally at the call.
    pub held: Vec<u32>,
    /// Resolved target methods (static target plus bounded overrides).
    pub targets: Vec<u32>,
}

#[derive(Clone, Debug)]
pub struct MethodRec {
    pub key: String,
    pub file: u32,
    pub line_lo: u32,
    pub line_hi: u32,
    pub spans: Vec<Span>,
    /// Range into [`Index::calls`] of this method's call sites.
    pub calls: (u32, u32),
}

/// `to` is acquired while `from` is held; `method`/`line` is one such site and
/// `dist` how many frames away `from` was taken there (0 = same method).
#[derive(Clone, Debug)]
pub struct OrderEdge {
    pub from: u32,
    pub to: u32,
    pub count: u32,
    pub method: u32,
    pub line: u32,
    pub dist: u8,
}

#[derive(Default)]
pub struct Index {
    pub methods: Vec<MethodRec>,
    pub locks: Vec<String>,
    pub files: Vec<String>,
    pub calls: Vec<Call>,
    /// CSR: `callers[caller_off[m]..caller_off[m+1]]` are indices into `calls`
    /// whose targets include `m`.
    pub callers: Vec<u32>,
    pub caller_off: Vec<u32>,
    /// CSR: `may_lock/may_dist[may_off[m]..may_off[m+1]]` — locks that may be held
    /// on entry to `m`, sorted by lock id, with the fewest frames to a holder.
    pub may_off: Vec<u32>,
    pub may_lock: Vec<u32>,
    pub may_dist: Vec<u8>,
    pub order: Vec<OrderEdge>,
}

/// One frame of a witness path, from the acquiring method down to the queried one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    pub method: u32,
    /// Where this frame acquires the lock (head frame only).
    pub acquire: Option<u32>,
    /// Where this frame calls the next one (all but the last frame).
    pub call: Option<u32>,
}

/// Build options.
pub struct Options {
    /// Link a virtual/interface call to its overrides only when the program has at
    /// most this many declarations of that signature; larger sets are left
    /// unlinked (static target only).
    pub cha_cap: usize,
    /// Furthest (in call frames) a held lock propagates; beyond this it is dropped.
    pub max_depth: u8,
    /// Lock-order edges relate an acquisition only to locks taken within this
    /// many frames.
    pub order_depth: u8,
}

impl Default for Options {
    fn default() -> Self {
        Options { cha_cap: 16, max_depth: 8, order_depth: 3 }
    }
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// A call site before target resolution.
struct RawCall {
    caller: u32,
    class: String,
    sig: String, // name:sig
    kind: InvokeKind,
    line: u32,
    held: Vec<u32>,
}

/// Per-method output of the parallel walk, before global interning.
struct Scanned {
    spans: Vec<(String, u32, u32, Vec<String>)>,
    calls: Vec<(String, String, String, InvokeKind, u32, Vec<String>)>,
}

pub fn build(dex: &Dex, opts: &Options) -> Index {
    let t0 = std::time::Instant::now();
    let methods: Vec<&Method> = dex.classes.iter().flat_map(|c| c.methods.iter()).collect();
    let n = methods.len();
    let id_of: HashMap<String, u32> =
        methods.iter().enumerate().map(|(i, m)| (m.key(), i as u32)).collect();

    // Canonical lock per acquisition site, shared with resolution: (method, line)
    // -> name, or None when two different acquisitions share a line.
    let mut site: HashMap<(String, u32), Option<String>> = HashMap::default();
    for a in crate::dex::acquisitions(dex) {
        let k = (a.method, a.line.unwrap_or(NO_LINE));
        match site.get(&k) {
            None => { site.insert(k, Some(a.lock)); }
            Some(Some(prev)) if *prev == a.lock => {}
            Some(_) => { site.insert(k, None); }
        }
    }
    log::debug!("ctx: canonical sites {:.2?}", t0.elapsed());

    // Parallel per-method walk.
    let scanned: Vec<Scanned> = methods
        .par_iter()
        .map(|m| {
            let key = m.key();
            let mut canon: HashMap<String, String> = HashMap::default();
            let mut name_of = |l: &Lock, line: u32| -> String {
                let g = l.name();
                if let Some(c) = canon.get(&g) {
                    return c.clone();
                }
                let c = match site.get(&(key.clone(), line)) {
                    Some(Some(c)) => c.clone(),
                    _ => g.clone(),
                };
                canon.insert(g, c.clone());
                c
            };
            let mut open: Vec<(String, String, u32, Vec<String>)> = Vec::new(); // (ground, canon, enter, held)
            let mut spans = Vec::new();
            let mut calls = Vec::new();
            flow::walk(m, &[], |e| match e {
                Event::Acquire { lock, line } => {
                    let line = line.unwrap_or(NO_LINE);
                    let c = name_of(lock, line);
                    let held: Vec<String> = open.iter().map(|o| o.1.clone()).collect();
                    open.push((lock.name(), c, line, held));
                }
                Event::Release { lock, line } => {
                    let g = lock.name();
                    let pos = open.iter().rposition(|o| o.0 == g).or(if open.is_empty() { None } else { Some(open.len() - 1) });
                    if let Some(p) = pos {
                        let (_, c, enter, held) = open.remove(p);
                        // Exclusive exit; a block opened and closed on one line still covers it.
                        spans.push((c, enter, line.unwrap_or(NO_LINE).max(enter + 1), held));
                    }
                }
                Event::Call { inv, held, line } => {
                    let line = line.unwrap_or(NO_LINE);
                    let held: Vec<String> = held.iter().filter(|l| !l.is_opaque()).map(|l| name_of(l, line)).collect();
                    calls.push((inv.class.clone(), inv.name.clone(), inv.sig.clone(), inv.kind, line, held));
                }
            });
            for (_, c, enter, held) in open {
                spans.push((c, enter, TO_END, held));
            }
            Scanned { spans, calls }
        })
        .collect();
    log::debug!("ctx: walk {:.2?}", t0.elapsed());

    // Intern locks and files; assemble method records and raw calls.
    let mut locks: Vec<String> = Vec::new();
    let mut lock_id: HashMap<String, u32> = HashMap::default();
    let intern = |s: &str, locks: &mut Vec<String>, lock_id: &mut HashMap<String, u32>| -> u32 {
        if let Some(&i) = lock_id.get(s) {
            return i;
        }
        let i = locks.len() as u32;
        locks.push(s.to_string());
        lock_id.insert(s.to_string(), i);
        i
    };
    let mut files: Vec<String> = vec![String::new()];
    let mut file_id: HashMap<String, u32> = HashMap::default();
    file_id.insert(String::new(), 0);

    let mut recs: Vec<MethodRec> = Vec::with_capacity(n);
    let mut raw_calls: Vec<RawCall> = Vec::new();
    for (i, (m, s)) in methods.iter().zip(scanned).enumerate() {
        let file = match &m.source_file {
            Some(f) => *file_id.entry(f.clone()).or_insert_with(|| {
                files.push(f.clone());
                (files.len() - 1) as u32
            }),
            None => 0,
        };
        let (lo, hi) = m
            .positions
            .iter()
            .fold((u32::MAX, 0u32), |(lo, hi), &(_, l)| (lo.min(l), hi.max(l)));
        let (line_lo, line_hi) = if lo == u32::MAX { (NO_LINE, NO_LINE) } else { (lo, hi) };
        let spans = s
            .spans
            .into_iter()
            .map(|(c, enter, exit, held)| Span {
                lock: intern(&c, &mut locks, &mut lock_id),
                enter,
                exit,
                held: held.iter().map(|h| intern(h, &mut locks, &mut lock_id)).collect(),
            })
            .collect();
        let c0 = raw_calls.len() as u32;
        for (class, name, sig, kind, line, held) in s.calls {
            let held = held.iter().map(|h| intern(h, &mut locks, &mut lock_id)).collect();
            raw_calls.push(RawCall { caller: i as u32, class, sig: format!("{name}:{sig}"), kind, line, held });
        }
        recs.push(MethodRec { key: m.key(), file, line_lo, line_hi, spans, calls: (c0, raw_calls.len() as u32) });
    }
    log::debug!("ctx: intern {:.2?} ({} locks)", t0.elapsed(), locks.len());

    // Class hierarchy for target resolution.
    let parents: HashMap<&str, Vec<&str>> = dex
        .classes
        .iter()
        .map(|c| {
            let mut p: Vec<&str> = c.super_class.iter().map(|s| s.as_str()).collect();
            p.extend(c.interfaces.iter().map(|s| s.as_str()));
            (c.descriptor.as_str(), p)
        })
        .collect();
    let ancestors = |c: &str| -> HashSet<String> {
        let mut seen: HashSet<String> = HashSet::default();
        let mut q: VecDeque<&str> = VecDeque::from([c]);
        while let Some(x) = q.pop_front() {
            if let Some(ps) = parents.get(x) {
                for &p in ps {
                    if seen.insert(p.to_string()) {
                        q.push_back(p);
                    }
                }
            }
        }
        seen
    };
    let mut anc_memo: HashMap<String, HashSet<String>> = HashMap::default();
    // Declarations by signature, for override linking.
    let mut decl: HashMap<String, Vec<u32>> = HashMap::default();
    for (i, m) in methods.iter().enumerate() {
        decl.entry(format!("{}:{}", m.name, m.sig)).or_default().push(i as u32);
    }
    // Static target: a class at or above `class` declaring name:sig.
    let mut static_memo: HashMap<(String, String), Option<u32>> = HashMap::default();

    let mut calls: Vec<Call> = Vec::with_capacity(raw_calls.len());
    for RawCall { caller, class, sig: sigk, kind, line, held } in raw_calls {
        let exact = id_of.get(&format!("{class}.{sigk}")).copied();
        let stat = match exact {
            Some(t) => Some(t),
            None => *static_memo.entry((class.clone(), sigk.clone())).or_insert_with(|| {
                let anc = anc_memo.entry(class.clone()).or_insert_with(|| ancestors(&class));
                anc.iter().find_map(|a| id_of.get(&format!("{a}.{sigk}")).copied())
            }),
        };
        let mut targets: Vec<u32> = stat.into_iter().collect();
        if matches!(kind, InvokeKind::Virtual | InvokeKind::Interface) {
            if let Some(ds) = decl.get(&sigk) {
                if ds.len() <= opts.cha_cap {
                    for &d in ds {
                        if targets.contains(&d) {
                            continue;
                        }
                        let dc = methods[d as usize].class.as_str();
                        if dc == class {
                            targets.push(d);
                            continue;
                        }
                        let anc = anc_memo.entry(dc.to_string()).or_insert_with(|| ancestors(dc));
                        if anc.contains(&class) {
                            targets.push(d);
                        }
                    }
                }
            }
        }
        calls.push(Call { caller, line, held, targets });
    }
    log::debug!("ctx: resolve {:.2?} ({} calls)", t0.elapsed(), calls.len());

    // Callers CSR.
    let mut deg = vec![0u32; n + 1];
    for c in &calls {
        for &t in &c.targets {
            deg[t as usize + 1] += 1;
        }
    }
    for i in 0..n {
        deg[i + 1] += deg[i];
    }
    let caller_off = deg.clone();
    let mut fill = deg;
    let mut callers = vec![0u32; caller_off[n] as usize];
    for (k, c) in calls.iter().enumerate() {
        for &t in &c.targets {
            let slot = &mut fill[t as usize];
            callers[*slot as usize] = k as u32;
            *slot += 1;
        }
    }

    // dist[m][l] = min over callers (1 if held at site, else dist[caller][l] + 1),
    // cut at max_depth: a min-plus worklist to the least fixpoint.
    let mut dist: Vec<HashMap<u32, u8>> = vec![HashMap::default(); n];
    let mut queued = vec![true; n];
    let mut work: VecDeque<u32> = (0..n as u32).collect();
    let mut visits: u64 = 0;
    while let Some(m) = work.pop_front() {
        queued[m as usize] = false;
        visits += 1;
        let mut acc: HashMap<u32, u8> = HashMap::default();
        for &k in &callers[caller_off[m as usize] as usize..caller_off[m as usize + 1] as usize] {
            let c = &calls[k as usize];
            for &l in &c.held {
                acc.entry(l).and_modify(|d| *d = (*d).min(1)).or_insert(1);
            }
            for (&l, &d) in &dist[c.caller as usize] {
                if d < opts.max_depth {
                    acc.entry(l).and_modify(|e| *e = (*e).min(d + 1)).or_insert(d + 1);
                }
            }
        }
        if acc != dist[m as usize] {
            dist[m as usize] = acc;
            let (c0, c1) = recs[m as usize].calls;
            for k in c0..c1 {
                for &t in &calls[k as usize].targets {
                    if !queued[t as usize] {
                        queued[t as usize] = true;
                        work.push_back(t);
                    }
                }
            }
        }
    }
    log::debug!("ctx: distance fixpoint {:.2?} ({visits} visits)", t0.elapsed());

    // Flatten to CSR, sorted by lock id.
    let mut may_off = Vec::with_capacity(n + 1);
    let mut may_lock = Vec::new();
    let mut may_dist = Vec::new();
    may_off.push(0);
    for d in &dist {
        let mut v: Vec<(u32, u8)> = d.iter().map(|(&l, &x)| (l, x)).collect();
        v.sort_unstable();
        for (l, x) in v {
            may_lock.push(l);
            may_dist.push(x);
        }
        may_off.push(may_lock.len() as u32);
    }

    // Lock-order edges: X acquired while Y is held — intra (dist 0) or on entry
    // within order_depth frames.
    let mut edges: HashMap<(u32, u32), OrderEdge> = HashMap::default();
    for (m, r) in recs.iter().enumerate() {
        for s in &r.spans {
            let mut froms: Vec<(u32, u8)> = s.held.iter().map(|&h| (h, 0)).collect();
            froms.extend(dist[m].iter().filter(|(_, &d)| d <= opts.order_depth).map(|(&l, &d)| (l, d)));
            for (y, d) in froms {
                if y == s.lock {
                    continue;
                }
                edges
                    .entry((y, s.lock))
                    .and_modify(|e| {
                        e.count += 1;
                        if d < e.dist {
                            e.dist = d;
                            e.method = m as u32;
                            e.line = s.enter;
                        }
                    })
                    .or_insert(OrderEdge { from: y, to: s.lock, count: 1, method: m as u32, line: s.enter, dist: d });
            }
        }
    }
    let mut order: Vec<OrderEdge> = edges.into_values().collect();
    order.sort_by_key(|e| (e.from, e.to));
    log::debug!("ctx: order graph {:.2?} ({} edges)", t0.elapsed(), order.len());

    Index { methods: recs, locks, files, calls, callers, caller_off, may_off, may_lock, may_dist, order }
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

impl Index {
    /// Methods in `file` (basename) whose line range contains `line`.
    pub fn locate(&self, file: &str, line: u32) -> Vec<u32> {
        let base = file.rsplit('/').next().unwrap_or(file);
        let Some(fid) = self.files.iter().position(|f| f == base) else { return Vec::new() };
        let fid = fid as u32;
        self.methods
            .iter()
            .enumerate()
            .filter(|(_, m)| m.file == fid && m.line_lo <= line && line <= m.line_hi)
            .map(|(i, _)| i as u32)
            .collect()
    }

    /// Methods whose key contains `needle`.
    pub fn find_methods(&self, needle: &str) -> Vec<u32> {
        self.methods.iter().enumerate().filter(|(_, m)| m.key.contains(needle)).map(|(i, _)| i as u32).collect()
    }

    /// Locks whose name contains `needle`.
    pub fn find_locks(&self, needle: &str) -> Vec<u32> {
        self.locks.iter().enumerate().filter(|(_, l)| l.contains(needle)).map(|(i, _)| i as u32).collect()
    }

    /// Locks held intra-procedurally at `line` of method `m`.
    pub fn intra_held(&self, m: u32, line: u32) -> Vec<u32> {
        let mut v: Vec<u32> = self.methods[m as usize]
            .spans
            .iter()
            .filter(|s| s.enter <= line && line < s.exit)
            .map(|s| s.lock)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Locks that may be held on entry to `m`, with the fewest frames to a holder,
    /// nearest first.
    pub fn may_held(&self, m: u32) -> Vec<(u32, u8)> {
        let (a, b) = (self.may_off[m as usize] as usize, self.may_off[m as usize + 1] as usize);
        let mut v: Vec<(u32, u8)> = self.may_lock[a..b].iter().copied().zip(self.may_dist[a..b].iter().copied()).collect();
        v.sort_by_key(|&(l, d)| (d, l));
        v
    }

    /// Frames from a holder of `lock` to entry of `m`, if `lock` may be held there.
    pub fn dist(&self, m: u32, lock: u32) -> Option<u8> {
        let (a, b) = (self.may_off[m as usize] as usize, self.may_off[m as usize + 1] as usize);
        self.may_lock[a..b].binary_search(&lock).ok().map(|i| self.may_dist[a + i])
    }

    /// Call sites (indices into `calls`) that target `m`.
    fn callers_of(&self, m: u32) -> &[u32] {
        &self.callers[self.caller_off[m as usize] as usize..self.caller_off[m as usize + 1] as usize]
    }

    /// A shortest call path by which `lock` comes to be held on entry to `m`, from
    /// the frame that acquires it down to `m`. `None` if `lock` is not may-held.
    pub fn witness(&self, m: u32, lock: u32) -> Option<Vec<Hop>> {
        let d0 = self.dist(m, lock)?;
        // Walk the distances back: from a frame at distance d, some caller either
        // holds the lock at the call site (d == 1) or sits at distance d - 1.
        let mut chain: Vec<u32> = Vec::new(); // call indices, target-side first
        let (mut cur, mut d) = (m, d0);
        while d > 0 {
            let k = *self.callers_of(cur).iter().find(|&&k| {
                let c = &self.calls[k as usize];
                if d == 1 { c.held.contains(&lock) } else { self.dist(c.caller, lock) == Some(d - 1) }
            })?;
            chain.push(k);
            cur = self.calls[k as usize].caller;
            d -= 1;
        }
        let mut path = Vec::with_capacity(chain.len() + 1);
        for (i, &k) in chain.iter().rev().enumerate() {
            let c = &self.calls[k as usize];
            let acquire = if i == 0 {
                self.methods[c.caller as usize]
                    .spans
                    .iter()
                    .find(|s| s.lock == lock && s.enter <= c.line && c.line < s.exit)
                    .map(|s| s.enter)
            } else {
                None
            };
            path.push(Hop { method: c.caller, acquire, call: Some(c.line) });
        }
        path.push(Hop { method: m, acquire: None, call: None });
        Some(path)
    }

    /// Acquisition sites of `lock`: (method, line).
    pub fn sites(&self, lock: u32) -> Vec<(u32, u32)> {
        let mut v: Vec<(u32, u32)> = self
            .methods
            .iter()
            .enumerate()
            .flat_map(|(i, m)| m.spans.iter().filter(|s| s.lock == lock).map(move |s| (i as u32, s.enter)))
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Methods on whose entry `lock` may be held, with distance, nearest first.
    pub fn holders(&self, lock: u32) -> Vec<(u32, u8)> {
        let mut v: Vec<(u32, u8)> =
            (0..self.methods.len() as u32).filter_map(|m| self.dist(m, lock).map(|d| (m, d))).collect();
        v.sort_by_key(|&(m, d)| (d, m));
        v
    }

    /// Non-trivial strongly connected components of the lock-order graph — sets of
    /// locks that can be acquired in inconsistent orders (deadlock candidates).
    pub fn cycles(&self) -> Vec<Vec<u32>> {
        let n = self.locks.len();
        let mut out_adj: Vec<Vec<u32>> = vec![Vec::new(); n];
        let mut in_adj: Vec<Vec<u32>> = vec![Vec::new(); n];
        for e in &self.order {
            out_adj[e.from as usize].push(e.to);
            in_adj[e.to as usize].push(e.from);
        }
        // Kosaraju, iterative.
        let mut order: Vec<u32> = Vec::with_capacity(n);
        let mut seen = vec![false; n];
        for s in 0..n {
            if seen[s] {
                continue;
            }
            let mut stack: Vec<(u32, usize)> = vec![(s as u32, 0)];
            seen[s] = true;
            while let Some((v, i)) = stack.last_mut() {
                if *i < out_adj[*v as usize].len() {
                    let w = out_adj[*v as usize][*i];
                    *i += 1;
                    if !seen[w as usize] {
                        seen[w as usize] = true;
                        stack.push((w, 0));
                    }
                } else {
                    order.push(*v);
                    stack.pop();
                }
            }
        }
        let mut comp = vec![u32::MAX; n];
        let mut comps: Vec<Vec<u32>> = Vec::new();
        for &s in order.iter().rev() {
            if comp[s as usize] != u32::MAX {
                continue;
            }
            let id = comps.len() as u32;
            let mut members = Vec::new();
            let mut stack = vec![s];
            comp[s as usize] = id;
            while let Some(v) = stack.pop() {
                members.push(v);
                for &w in &in_adj[v as usize] {
                    if comp[w as usize] == u32::MAX {
                        comp[w as usize] = id;
                        stack.push(w);
                    }
                }
            }
            comps.push(members);
        }
        let mut cyc: Vec<Vec<u32>> = comps.into_iter().filter(|c| c.len() > 1).collect();
        for c in &mut cyc {
            c.sort_unstable();
        }
        cyc.sort_by_key(|c| std::cmp::Reverse(c.len()));
        cyc
    }

    pub fn order_out(&self, lock: u32) -> Vec<&OrderEdge> {
        self.order.iter().filter(|e| e.from == lock).collect()
    }
    pub fn order_in(&self, lock: u32) -> Vec<&OrderEdge> {
        self.order.iter().filter(|e| e.to == lock).collect()
    }
}

// ---------------------------------------------------------------------------
// Persistence: little-endian binary, length-prefixed sections.
// ---------------------------------------------------------------------------

struct Out<W: Write>(W);
impl<W: Write> Out<W> {
    fn u8(&mut self, v: u8) -> Result<()> { Ok(self.0.write_all(&[v])?) }
    fn u32(&mut self, v: u32) -> Result<()> { Ok(self.0.write_all(&v.to_le_bytes())?) }
    fn u32s(&mut self, v: &[u32]) -> Result<()> {
        self.u32(v.len() as u32)?;
        for &x in v { self.u32(x)?; }
        Ok(())
    }
    fn str(&mut self, s: &str) -> Result<()> {
        self.u32(s.len() as u32)?;
        Ok(self.0.write_all(s.as_bytes())?)
    }
    fn strs(&mut self, v: &[String]) -> Result<()> {
        self.u32(v.len() as u32)?;
        for s in v { self.str(s)?; }
        Ok(())
    }
}

struct In<R: Read>(R);
impl<R: Read> In<R> {
    fn u8(&mut self) -> Result<u8> { let mut b = [0u8; 1]; self.0.read_exact(&mut b)?; Ok(b[0]) }
    fn u32(&mut self) -> Result<u32> { let mut b = [0u8; 4]; self.0.read_exact(&mut b)?; Ok(u32::from_le_bytes(b)) }
    fn u32s(&mut self) -> Result<Vec<u32>> {
        let n = self.u32()? as usize;
        let mut bytes = vec![0u8; n * 4];
        self.0.read_exact(&mut bytes)?;
        Ok(bytes.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect())
    }
    fn str(&mut self) -> Result<String> {
        let n = self.u32()? as usize;
        let mut b = vec![0u8; n];
        self.0.read_exact(&mut b)?;
        Ok(String::from_utf8(b)?)
    }
    fn strs(&mut self) -> Result<Vec<String>> {
        let n = self.u32()? as usize;
        (0..n).map(|_| self.str()).collect()
    }
}

impl Index {
    pub fn write(&self, w: impl Write) -> Result<()> {
        let mut o = Out(w);
        o.0.write_all(MAGIC)?;
        o.strs(&self.locks)?;
        o.strs(&self.files)?;
        o.u32(self.methods.len() as u32)?;
        for m in &self.methods {
            o.str(&m.key)?;
            o.u32(m.file)?;
            o.u32(m.line_lo)?;
            o.u32(m.line_hi)?;
            o.u32(m.spans.len() as u32)?;
            for s in &m.spans {
                o.u32(s.lock)?;
                o.u32(s.enter)?;
                o.u32(s.exit)?;
                o.u32s(&s.held)?;
            }
            o.u32(m.calls.0)?;
            o.u32(m.calls.1)?;
        }
        o.u32(self.calls.len() as u32)?;
        for c in &self.calls {
            o.u32(c.caller)?;
            o.u32(c.line)?;
            o.u32s(&c.held)?;
            o.u32s(&c.targets)?;
        }
        o.u32s(&self.callers)?;
        o.u32s(&self.caller_off)?;
        o.u32s(&self.may_off)?;
        o.u32s(&self.may_lock)?;
        o.u32(self.may_dist.len() as u32)?;
        o.0.write_all(&self.may_dist)?;
        o.u32(self.order.len() as u32)?;
        for e in &self.order {
            o.u32(e.from)?;
            o.u32(e.to)?;
            o.u32(e.count)?;
            o.u32(e.method)?;
            o.u32(e.line)?;
            o.u8(e.dist)?;
        }
        Ok(o.0.flush()?)
    }

    pub fn read(r: impl Read) -> Result<Index> {
        let mut i = In(r);
        let mut magic = [0u8; 8];
        i.0.read_exact(&mut magic).context("reading index header")?;
        if &magic != MAGIC {
            bail!("not a dexlock ctx index");
        }
        let locks = i.strs()?;
        let files = i.strs()?;
        let n = i.u32()? as usize;
        let mut methods = Vec::with_capacity(n);
        for _ in 0..n {
            let key = i.str()?;
            let file = i.u32()?;
            let line_lo = i.u32()?;
            let line_hi = i.u32()?;
            let ns = i.u32()? as usize;
            let mut spans = Vec::with_capacity(ns);
            for _ in 0..ns {
                spans.push(Span { lock: i.u32()?, enter: i.u32()?, exit: i.u32()?, held: i.u32s()? });
            }
            let calls = (i.u32()?, i.u32()?);
            methods.push(MethodRec { key, file, line_lo, line_hi, spans, calls });
        }
        let nc = i.u32()? as usize;
        let mut calls = Vec::with_capacity(nc);
        for _ in 0..nc {
            calls.push(Call { caller: i.u32()?, line: i.u32()?, held: i.u32s()?, targets: i.u32s()? });
        }
        let callers = i.u32s()?;
        let caller_off = i.u32s()?;
        let may_off = i.u32s()?;
        let may_lock = i.u32s()?;
        let nd = i.u32()? as usize;
        let mut may_dist = vec![0u8; nd];
        i.0.read_exact(&mut may_dist)?;
        let ne = i.u32()? as usize;
        let mut order = Vec::with_capacity(ne);
        for _ in 0..ne {
            order.push(OrderEdge { from: i.u32()?, to: i.u32()?, count: i.u32()?, method: i.u32()?, line: i.u32()?, dist: i.u8()? });
        }
        Ok(Index { methods, locks, files, calls, callers, caller_off, may_off, may_lock, may_dist, order })
    }
}
