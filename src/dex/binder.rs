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
//! A binder call is recognized structurally: an invoke of `IBinder.transact`, an
//! invoke of a method whose body performs one (the generated client proxy), or an
//! invoke of a method on an AIDL interface (a type transitively extending
//! `android.os.IInterface`) — that is the client surface whose call does a
//! synchronous transact. The held-lock set is tracked exactly as elsewhere
//! (monitor-enter/exit, `Lock.lock/unlock`, and a `synchronized` method's implicit
//! monitor). This pass is intra-procedural, so it **under**-reports (it misses calls
//! made from a `…Locked` helper whose lock is held by the caller) rather than
//! over-reporting: a finding is a lock demonstrably held across a binder call.

use crate::dex::flow;
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

/// Find every binder call made while a lock is held. Held locks include those taken
/// intra-procedurally (monitor / `Lock.lock`) and those inferred to be held on entry
/// to a method by `flow::entry_held`, so a call in a `…Locked` helper whose lock is
/// taken one frame up is still caught. `closed_world` widens that inference past
/// private methods to any uniquely-signed one (see `flow::entry_held`).
pub fn binder_under_lock(dex: &Dex, closed_world: bool) -> Vec<Finding> {
    let ifaces = binder_interfaces(dex);
    let transacting = transacting_methods(dex);
    let entry = flow::entry_held(dex, closed_world);
    let effects = flow::effects(dex);
    let empty: Vec<Lock> = Vec::new();
    let mut out: Vec<Finding> = dex
        .classes
        .par_iter()
        .flat_map_iter(|c| c.methods.iter())
        .flat_map(|m| {
            let seed = entry.get(&m.key()).unwrap_or(&empty);
            let mut fs = Vec::new();
            flow::scan(m, seed, &effects, |inv, held, line| {
                if is_binder_call(inv, &ifaces, &transacting) && held.iter().any(|l| !l.is_opaque()) {
                    fs.push(Finding {
                        method: m.key(),
                        file: m.source_file.clone(),
                        line,
                        held: held.iter().filter(|l| !l.is_opaque()).map(|l| l.name()).collect(),
                        callee: format!("{}.{}", inv.class, inv.name),
                    });
                }
            });
            fs
        })
        .collect();
    out.sort_by(|a, b| (&a.method, a.line, &a.callee).cmp(&(&b.method, b.line, &b.callee)));
    out
}

/// True if this invoke is the low-level binder transaction itself.
pub(super) fn is_transact(inv: &Invoke) -> bool {
    matches!(inv.class.as_str(), "android.os.IBinder" | "android.os.BinderProxy")
        && inv.name.starts_with("transact")
}

/// Methods whose body performs a binder transaction — the generated client proxies,
/// found by what they do rather than by what they are called.
pub(super) fn transacting_methods(dex: &Dex) -> HashSet<String> {
    dex.classes
        .iter()
        .flat_map(|c| c.methods.iter())
        .filter(|m| {
            m.insns.iter().any(|i| matches!(&i.op, Op::Invoke(inv) if is_transact(inv)))
        })
        .map(|m| m.key())
        .collect()
}

/// Classes that transitively extend `android.os.IInterface` — the AIDL surface.
pub(super) fn binder_interfaces(dex: &Dex) -> HashSet<String> {
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
/// (which merely happens to implement a generated stub); that is a local call, not a
/// transaction, so restricting to interface dispatch excludes it. Static factories
/// (`asInterface`, `Stub.getDefaultImpl`) and the non-transacting `IInterface`
/// plumbing never count. The proxy is recognized by its body performing a
/// transaction, not by its class name.
fn is_binder_call(inv: &Invoke, ifaces: &HashSet<String>, transacting: &HashSet<String>) -> bool {
    if is_transact(inv) {
        return true;
    }
    if inv.name.starts_with('<') || inv.name == "asBinder" || inv.name == "getInterfaceDescriptor" {
        return false;
    }
    if transacting.contains(&inv.key()) {
        return true;
    }
    inv.kind == InvokeKind::Interface && ifaces.contains(&inv.class)
}

