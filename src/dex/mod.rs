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

//! DEX lock-site analysis: turn decoded bytecode into the set of monitor-enter
//! sites, each named by the canonical lock taken there.
//!
//! Per-method extraction (parallel) records the raw facts — every `synchronized`
//! operand as a `Root` plus a bounded access path, plus the field/parameter stores
//! and call-site argument bindings needed to resolve those roots interprocedurally.
//! A global phase then resolves lock-field aliases (a field that merely holds
//! another object's lock is followed to that object, across constructors, setters
//! and inheritance, as a monotone parameter/copy-propagation fixpoint) and names
//! each site by its canonical lock. The `binder` module reuses the same held-lock
//! tracking to flag binder calls made while a lock is held; deadlock-cycle and race
//! analysis remain out of scope.

use crate::dex::model::*;
use rayon::prelude::*;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

pub mod archive;
pub mod binder;
pub mod ctx;
mod dexdump;
mod extract;
mod flow;
mod juc;
mod native;
pub mod input;
pub mod model;
pub mod resolve;

/// Decode one DEX section blob into the [`model::Dex`] shape. Uses the native
/// in-process reader by default; set `$DEXLOCK_USE_DEXDUMP` to fall back to the
/// `dexdump` subprocess (the two produce the same model — native is a drop-in). The
/// fallback stages the blob in a temp `.dex` because `dexdump` needs a file.
pub fn parse_dex_blob(data: &[u8]) -> anyhow::Result<model::Dex> {
    if std::env::var_os("DEXLOCK_USE_DEXDUMP").is_some() {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "dexlock-{}-{}.dex",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, data)?;
        let r = dexdump::parse_dex(&path);
        let _ = std::fs::remove_file(&path);
        r
    } else {
        native::parse_dex_bytes(data)
    }
}

/// Per-method facts the resolver consumes: the lock-acquisition sites to be named,
/// plus the evidence used to resolve a lock's identity across calls.
#[derive(Debug, Clone, Default)]
struct Summary {
    key: String,
    class: String,
    /// every `monitor-enter` / `Lock.lock` in this method: (pre-ground lock, source
    /// line) — the site a contention record lands on.
    acq_sites: Vec<(Lock, Option<u32>)>,
    /// a trivial getter's return value, so `synchronized(getX())` resolves through it.
    value_summary: Option<Lock>,
    /// `field = new T(...)`: (field key, type). A type allocated once and stored in a
    /// single field is a singleton, whose `this`-monitor is the same lock as
    /// `owner.field`.
    alloc_stores: Vec<(String, String)>,
    /// `this.f = <concrete lock>` (another field, a static, or `Service.this`):
    /// `Class.field` names that same object.
    field_aliases: Vec<(String, Lock)>,
    /// `this.f = formal` in ANY method (declaring-class field key so it threads
    /// through `super`, formal index with receiver `this` = 0): the field aliases
    /// that formal, resolved interprocedurally.
    param_stores: Vec<(String, u32)>,
    /// resolved actual arguments of every object-passing invoke: (callee key,
    /// actuals), actual index aligned with the callee's formal index (receiver at 0).
    arg_bindings: Vec<(String, Vec<Option<Lock>>)>,
}

/// A resolved `synchronized` / `monitor-enter` site: the canonical lock taken,
/// the holder class, and the source line. `class` may be a nested class
/// (`Outer$Inner`); the top-level class fixes the source file.
pub struct Acquisition {
    pub class: String,
    /// holder method key — the stable anchor when line numbers drift.
    pub method: String,
    /// source file name (e.g. `ActivityManagerService.java`); with `line` this is
    /// exactly the `File.java:line` a monitor-contention record names, so the output
    /// resolves a contention by a direct (file, line) lookup.
    pub source_file: Option<String>,
    pub line: Option<u32>,
    pub lock: String,
}

/// If `l` is a directly-locked object parameter, name it by its declared class
/// (the same instance-monitor rendering `this` gets). Returns None for non-param
/// or primitive-typed params, so the caller falls back to normal grounding.
fn param_type_name(l: &Lock, m: Option<&Method>) -> Option<String> {
    let crate::dex::model::Root::Param(j) = l.root else { return None };
    if !l.fields.is_empty() {
        return None;
    }
    let m = m?;
    let reg = m.registers.saturating_sub(m.ins) + j;
    m.object_param_regs().into_iter().find(|(r, _)| *r == reg).map(|(_, t)| t)
}

/// Analyze decoded DEX and return every monitor-enter site named by its canonical
/// lock. This is the resolution path only: per-method extraction, interprocedural
/// lock-field/parameter resolution (a monotone worklist fixpoint), and canonical
/// naming. No deadlock-cycle, binder, or race analysis is performed.
pub fn acquisitions(dex: &Dex) -> Vec<Acquisition> {
    let _prof = std::time::Instant::now();
    let methods: Vec<&Method> = dex.classes.iter().flat_map(|c| c.methods.iter()).collect();

    // Two passes: value summaries first (so `synchronized(getX())` resolves through
    // a trivial getter), then the full summaries.
    let empty: HashMap<String, Lock> = HashMap::default();
    let value_summaries: HashMap<String, Lock> = methods
        .par_iter()
        .filter_map(|m| extract::extract(m, &empty).value_summary.map(|v| (m.key(), v)))
        .collect();
    let summaries: Vec<Summary> =
        methods.par_iter().map(|m| extract::extract(m, &value_summaries)).collect();
    let mut by_key: HashMap<String, Summary> = HashMap::default();
    for s in summaries {
        by_key.entry(s.key.clone()).or_insert(s);
    }
    log::debug!("extract: {:.2?}", _prof.elapsed());
    let _prof = std::time::Instant::now();

    // Interprocedural injection resolver (parameter/copy propagation over the call
    // graph). Seed the fixpoint with the fields it must resolve AND every
    // `synchronized(param)` operand, solve once, and reuse the solution for both the
    // alias map and for naming parameter-locks.
    let injector = Injector::build(&by_key);
    let inj_solution = {
        let mut seeds: Vec<(&str, u32)> =
            injector.field_stores.values().flatten().copied().collect();
        for s in by_key.values() {
            for (l, _) in &s.acq_sites {
                if let Root::Param(j) = l.root {
                    seeds.push((s.key.as_str(), j));
                }
            }
        }
        injector.solve(&seeds)
    };
    log::debug!("injector solve: {:.2?}", _prof.elapsed());
    let _prof = std::time::Instant::now();

    // Lock-field aliases: `Class.field` -> the shared lock it actually names.
    //   (a) direct assignment in a method: `this.f = svc.getLock()` / a field / a static;
    //   (b) constructor/setter parameter: `this.f = param_i`, resolved to the actual
    //       argument across all call sites (the injector);
    //   (c) singleton self-monitor: a class allocated once and stored in a single
    //       field, locked via `synchronized(this)` internally, is that field externally.
    // A field assigned different objects at different sites is left distinct (sound).
    let alias: HashMap<String, Lock> = {
        let mut seen: HashMap<String, Option<Lock>> = HashMap::default();
        let note = |key: String, v: Option<Lock>, seen: &mut HashMap<String, Option<Lock>>| {
            match (seen.get(&key), &v) {
                (None, _) => { seen.insert(key, v); }
                (Some(None), _) => {}
                (Some(Some(e)), Some(nv)) if e == nv => {}
                _ => { seen.insert(key, None); }
            }
        };
        for s in by_key.values() {
            for (k, v) in &s.field_aliases {
                note(k.clone(), Some(v.clone()), &mut seen);
            }
        }
        for (field, v) in injector.resolve_fields(&inj_solution) {
            note(field, Some(v), &mut seen);
        }
        let self_sync: HashSet<&str> = by_key
            .values()
            .filter(|s| s.acq_sites.iter().any(|(l, _)| matches!(l.root, Root::This)))
            .map(|s| s.class.as_str())
            .collect();
        let mut stored_in: HashMap<&str, HashSet<&str>> = HashMap::default();
        for s in by_key.values() {
            for (field, ty) in &s.alloc_stores {
                stored_in.entry(ty.as_str()).or_default().insert(field.as_str());
            }
        }
        for (ty, fields) in &stored_in {
            if self_sync.contains(ty) && fields.len() == 1 {
                let field = (*fields.iter().next().expect("len == 1")).to_string();
                if !seen.contains_key(&field) {
                    note(field, Some(Lock::new(Root::Recv((*ty).to_string()))), &mut seen);
                }
            }
        }
        seen.into_iter().filter_map(|(k, v)| v.map(|l| (k, l))).collect()
    };

    // Name every monitor-enter site by its canonical lock. A `synchronized(param)`
    // first resolves the parameter to the concrete object bound at the method's call
    // sites; else falls back to the parameter's declared class; else grounds and
    // canonicalizes. The answer is a real definition or an opaque, never a guess.
    log::debug!("alias: {:.2?}", _prof.elapsed());
    let _prof = std::time::Instant::now();
    let method_by_key: HashMap<String, &Method> = methods.iter().map(|m| (m.key(), *m)).collect();
    // Naming is independent per site (read-only over the solved maps), so fan it out.
    // Rebind as references so the parallel closures copy the borrow, not the value.
    let (injector, alias, inj_solution, method_by_key) =
        (&injector, &alias, &inj_solution, &method_by_key);
    let out: Vec<Acquisition> = by_key
        .par_iter()
        .flat_map_iter(|(_, s)| {
            s.acq_sites.iter().map(move |(l, line)| {
                let lock = injector
                    .resolve_param_lock(s.key.as_str(), l, inj_solution)
                    .map(|obj| canonicalize(&obj, alias).name())
                    .or_else(|| param_type_name(l, method_by_key.get(&s.key).copied()))
                    .unwrap_or_else(|| canonicalize(&ground(l, &s.class, &s.key), alias).name());
                Acquisition {
                    class: s.class.clone(),
                    method: s.key.clone(),
                    source_file: method_by_key.get(&s.key).and_then(|m| m.source_file.clone()),
                    line: *line,
                    lock,
                }
            })
        })
        .collect();
    log::debug!("naming: {:.2?}", _prof.elapsed());
    out
}

/// Follow lock-field aliases: a field assigned a shared lock is canonicalized to
/// that lock's identity, so a singleton lock split across fields collapses to one.
fn canonicalize(lock: &Lock, canon: &HashMap<String, Lock>) -> Lock {
    if canon.is_empty() {
        return lock.clone();
    }
    let mut cur = lock.clone();
    for _ in 0..6 {
        if !matches!(cur.root, Root::Recv(_) | Root::Static(_)) {
            break;
        }
        let base = Lock { mode: Mode::Plain, ..cur.clone() }.name();
        match canon.get(&base) {
            Some(t) => cur = t.with_mode(cur.mode),
            None => break,
        }
    }
    cur
}

// ---------------------------------------------------------------------------
// Interprocedural injection resolution
// ---------------------------------------------------------------------------
// Resolve each lock field to the concrete object it names, by parameter/copy
// propagation over the call graph. `this.f = param_i` (in ANY method) makes the
// field an alias of formal `i`; a formal is the meet, over every call site that
// binds it, of the resolved actual argument. This is a monotone dataflow system
// solved by a worklist to its LEAST fixpoint: cycles converge naturally (a
// grounded cycle settles on its grounded value, an ungrounded one stays
// unresolved), and constructors, setters and `super(...)` are all just call
// sites, so ctor / setter / inheritance injection fall out of one algorithm.
// Sound: a conflict, or an actual that does not resolve to a single object,
// yields Top and produces no alias.

// A resolution in the meet-semilattice  Bottom (no info) < Val(x) < Top (conflict).
#[derive(Clone, PartialEq)]
enum Res {
    Bottom,
    Val(Lock),
    Top,
}

impl Res {
    fn meet(self, other: Res) -> Res {
        match (self, other) {
            (Res::Top, _) | (_, Res::Top) => Res::Top,
            (Res::Bottom, x) | (x, Res::Bottom) => x,
            (Res::Val(a), Res::Val(b)) => {
                if a == b { Res::Val(a) } else { Res::Top }
            }
        }
    }
}

/// A `(method key, formal index)` variable of the analysis (receiver = 0).
type Formal<'a> = (&'a str, u32);

/// One observed call site of a method: who called it and with what actuals.
struct CallSite<'a> {
    class: &'a str,               // caller's class
    key: &'a str,                 // caller's method key
    actuals: &'a [Option<Lock>],  // actuals[i] binds the callee's formal i
}

struct Injector<'a> {
    sites: HashMap<&'a str, Vec<CallSite<'a>>>,
    field_stores: HashMap<&'a str, Vec<Formal<'a>>>,
}

impl<'a> Injector<'a> {
    fn build(by_key: &'a HashMap<String, Summary>) -> Self {
        let mut sites: HashMap<&str, Vec<CallSite>> = HashMap::default();
        let mut field_stores: HashMap<&str, Vec<Formal>> = HashMap::default();
        for s in by_key.values() {
            for (callee, actuals) in &s.arg_bindings {
                sites.entry(callee.as_str()).or_default().push(CallSite {
                    class: s.class.as_str(),
                    key: s.key.as_str(),
                    actuals: actuals.as_slice(),
                });
            }
            for (field, formal) in &s.param_stores {
                field_stores.entry(field.as_str()).or_default().push((s.key.as_str(), *formal));
            }
        }
        Injector { sites, field_stores }
    }

    /// The value of one actual argument under the current partial solution `f`.
    fn eval(&self, actual: Option<&Lock>, cs: &CallSite<'a>, f: &HashMap<Formal<'a>, Res>) -> Res {
        let Some(l) = actual else { return Res::Top };
        match &l.root {
            // the caller's own formal: take its current value, re-appending this
            // actual's field path (an actual of `param.mLock`).
            Root::Param(j) => match f.get(&(cs.key, *j)).cloned().unwrap_or(Res::Bottom) {
                Res::Val(base) => Res::Val(base.append(&l.fields, l.mode)),
                other => other,
            },
            // `this` / a field-of-this / a static: ground in the caller's frame.
            _ => {
                let g = ground(l, cs.class, cs.key);
                match g.root {
                    Root::Recv(_) | Root::Static(_) => Res::Val(g),
                    _ => Res::Top,
                }
            }
        }
    }

    /// Transfer: a formal is the meet of its actuals over all call sites. A method
    /// with no observed call site is unconstrained -> Top.
    fn transfer(&self, (m, i): Formal<'a>, f: &HashMap<Formal<'a>, Res>) -> Res {
        let Some(css) = self.sites.get(m).filter(|v| !v.is_empty()) else {
            return Res::Top;
        };
        let mut acc = Res::Bottom;
        for cs in css {
            let a = cs.actuals.get(i as usize).and_then(|o| o.as_ref());
            acc = acc.meet(self.eval(a, cs, f));
            if acc == Res::Top {
                break;
            }
        }
        acc
    }

    /// Least-fixpoint solve: gather the reachable formals (the field stores plus
    /// any `extra_seeds`, e.g. `synchronized(param)` operands) and their
    /// dependency edges, then run a monotone worklist to convergence.
    fn solve(&self, extra_seeds: &[Formal<'a>]) -> HashMap<Formal<'a>, Res> {
        let mut vars: HashSet<Formal> = HashSet::default();
        let mut rev: HashMap<Formal, Vec<Formal>> = HashMap::default(); // dep -> readers
        let mut stack: Vec<Formal> = self.field_stores.values().flatten().copied().collect();
        stack.extend_from_slice(extra_seeds);
        while let Some((m, i)) = stack.pop() {
            if !vars.insert((m, i)) {
                continue;
            }
            for cs in self.sites.get(m).into_iter().flatten() {
                if let Some(Some(a)) = cs.actuals.get(i as usize) {
                    if let Root::Param(j) = a.root {
                        rev.entry((cs.key, j)).or_default().push((m, i));
                        stack.push((cs.key, j));
                    }
                }
            }
        }
        let mut f: HashMap<Formal, Res> = vars.iter().map(|&v| (v, Res::Bottom)).collect();
        let mut wl: Vec<Formal> = vars.into_iter().collect();
        while let Some(v) = wl.pop() {
            let nv = self.transfer(v, &f);
            if f.get(&v) != Some(&nv) {
                f.insert(v, nv);
                if let Some(deps) = rev.get(&v) {
                    wl.extend(deps.iter().copied());
                }
            }
        }
        f
    }

    /// Resolve a `synchronized(param)` operand to the concrete object bound at the
    /// method's call sites, if it resolves to one. `None` for a non-parameter lock
    /// or one that does not resolve (the caller then names it by its type).
    fn resolve_param_lock(&self, method: &'a str, l: &Lock, f: &HashMap<Formal<'a>, Res>) -> Option<Lock> {
        let Root::Param(j) = l.root else { return None };
        match f.get(&(method, j)) {
            Some(Res::Val(base)) => Some(base.append(&l.fields, l.mode)),
            _ => None,
        }
    }

    /// Every field that resolves to a single concrete object other than itself.
    fn resolve_fields(&self, f: &HashMap<Formal<'a>, Res>) -> Vec<(String, Lock)> {
        let mut out = Vec::new();
        for (field, stores) in &self.field_stores {
            let mut acc = Res::Bottom;
            for &(m, i) in stores {
                // Residual Bottom (ungrounded) is unresolved -> Top.
                let r = match f.get(&(m, i)) {
                    Some(Res::Val(v)) => Res::Val(v.clone()),
                    _ => Res::Top,
                };
                acc = acc.meet(r);
                if acc == Res::Top {
                    break;
                }
            }
            if let Res::Val(v) = acc {
                if v.name().as_str() != *field {
                    out.push(((*field).to_string(), v));
                }
            }
        }
        out
    }
}
// ---------------------------------------------------------------------------
// mayAcquire fixpoint
// ---------------------------------------------------------------------------

fn subst_or_self(lock: &Lock, args: &[Option<Lock>]) -> Option<Lock> {
    if lock.is_parametric() {
        subst(lock, args)
    } else {
        Some(lock.clone())
    }
}

fn ground(lock: &Lock, class: &str, key: &str) -> Lock {
    if lock.is_parametric() {
        lock.ground(class, key)
    } else {
        lock.clone()
    }
}
