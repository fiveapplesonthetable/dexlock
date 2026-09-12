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

//! End-to-end coverage of the native DEX front-end against a committed fixture
//! (`fixtures/locks.dex`, built from `fixtures/Locks.java`). No toolchain needed:
//! the fixture is parsed from bytes and its resolved locks are asserted directly.

use dexlock::dex;

/// One acquisition as a comparable tuple: (method key, source line, canonical lock).
fn triples(d: &dex::model::Dex) -> Vec<(String, Option<u32>, String)> {
    let mut v: Vec<_> = dex::acquisitions(d)
        .into_iter()
        .map(|a| (a.method, a.line, a.lock))
        .collect();
    v.sort();
    v
}

#[test]
fn fixture_locks_resolve_natively() {
    let bytes = include_bytes!("fixtures/locks.dex");
    let d = dex::parse_dex_blob(bytes).expect("parse fixture");

    // Every method's source file resolves to Locks.java (regression for the
    // source_file column that a monitor-contention record joins on).
    for c in &d.classes {
        for m in &c.methods {
            assert_eq!(m.source_file.as_deref(), Some("Locks.java"), "{}", m.key());
        }
    }

    // The four synchronized forms each resolve to their canonical lock:
    //   a() synchronized(mLock)   -> instance field
    //   b() synchronized(sLock)   -> static field
    //   c() synchronized method   -> this (the class instance monitor)
    //   d() static synchronized   -> the class object
    assert_eq!(
        triples(&d),
        vec![
            ("t.Locks.a:()V".to_string(), Some(5), "t.Locks.mLock".to_string()),
            ("t.Locks.b:()V".to_string(), Some(6), "t.Locks.sLock".to_string()),
            ("t.Locks.c:()V".to_string(), None, "t.Locks".to_string()),
            ("t.Locks.d:()V".to_string(), None, "t.Locks.class".to_string()),
        ]
    );
}

/// The binder-under-lock pass flags exactly the interface-dispatched binder calls
/// made while a lock is held: a `synchronized` block (a field lock), a `synchronized`
/// method (holding `this`, which d8 lowers to an explicit monitor), and — the
/// interprocedural case — a binder call in a private helper whose caller holds the
/// lock (`entry_held` infers it one frame up). Neither the same call without a lock
/// nor a plain (non-binder) helper under the lock is flagged. From `Binder.java`.
#[test]
fn fixture_binder_under_lock() {
    let bytes = include_bytes!("fixtures/binder.dex");
    let d = dex::parse_dex_blob(bytes).expect("parse fixture");
    let mut got: Vec<(String, Vec<String>, String)> = dex::binder::binder_under_lock(&d, false)
        .into_iter()
        .map(|f| {
            assert_eq!(f.file.as_deref(), Some("Binder.java"));
            (f.method, f.held, f.callee)
        })
        .collect();
    got.sort();
    let remote = "t.Binder$IFoo.doRemote".to_string();
    let mlock = vec!["t.Binder$Holder.mLock".to_string()];
    assert_eq!(
        got,
        vec![
            // interprocedural: lock held by the caller of a private helper
            ("t.Binder$Holder.helperLocked:()V".to_string(), mlock.clone(), remote.clone()),
            // intra: synchronized block holding a field lock
            ("t.Binder$Holder.underLock:()V".to_string(), mlock, remote.clone()),
            // intra: synchronized method holding `this`
            ("t.Binder$Holder.underSyncMethod:()V".to_string(), vec!["t.Binder$Holder".to_string()], remote),
        ]
    );
}

/// The lock-context index over `fixtures/ctx.dex`: mA may be held on entry to
/// leaf() by the path top() -> mid() -> leaf(), and nested()/other() take mA and mB
/// in opposite orders, so the lock-order graph has exactly the cycle {mA, mB}.
#[test]
fn fixture_ctx_index() {
    let bytes = include_bytes!("fixtures/ctx.dex");
    let d = dex::parse_dex_blob(bytes).expect("parse fixture");
    let idx = dex::ctx::build(&d, &dex::ctx::Options::default());
    let m = |k: &str| {
        let v = idx.find_methods(k);
        assert_eq!(v.len(), 1, "{k}");
        v[0]
    };
    let l = |k: &str| {
        let v = idx.find_locks(k);
        assert_eq!(v.len(), 1, "{k}");
        v[0]
    };
    let (top, mid, leaf) = (m("t.Ctx.top:"), m("t.Ctx.mid:"), m("t.Ctx.leaf:"));
    let (ma, mb) = (l("t.Ctx.mA"), l("t.Ctx.mB"));

    assert_eq!(idx.may_held(top), Vec::<(u32, u8)>::new());
    assert_eq!(idx.may_held(mid), vec![(ma, 1)]);
    assert_eq!(idx.may_held(leaf), vec![(ma, 2)]);
    assert_eq!(idx.intra_held(top, 12), vec![ma]);

    let path = idx.witness(leaf, ma).expect("mA reaches leaf");
    assert_eq!(path.iter().map(|h| h.method).collect::<Vec<_>>(), vec![top, mid, leaf]);
    assert_eq!((path[0].acquire, path[0].call), (Some(12), Some(12)));
    assert_eq!((path[1].acquire, path[1].call), (None, Some(13)));
    assert_eq!((path[2].acquire, path[2].call), (None, None));

    let mut edges: Vec<(u32, u32)> = idx.order.iter().map(|e| (e.from, e.to)).collect();
    edges.sort_unstable();
    let mut want = vec![(ma, mb), (mb, ma)];
    want.sort_unstable();
    assert_eq!(edges, want);
    assert_eq!(idx.cycles(), vec![vec![ma.min(mb), ma.max(mb)]]);
}

/// Binder-under-lock phrased over the lock-context index agrees with the dedicated
/// pass on `binder.dex`: the two intra sites at distance 0 and the private helper
/// at distance 1 (its lock is held by the caller), and nothing else.
#[test]
fn fixture_ctx_binder_sites() {
    let bytes = include_bytes!("fixtures/binder.dex");
    let d = dex::parse_dex_blob(bytes).expect("parse fixture");
    let idx = dex::ctx::build(&d, &dex::ctx::Options::default());
    let mut got: Vec<(String, String, u8)> = idx
        .binder_sites(8)
        .into_iter()
        .map(|(k, _, l, dist)| (idx.methods[idx.calls[k as usize].caller as usize].key.clone(), idx.locks[l as usize].clone(), dist))
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            ("t.Binder$Holder.helperLocked:()V".to_string(), "t.Binder$Holder.mLock".to_string(), 1),
            ("t.Binder$Holder.underLock:()V".to_string(), "t.Binder$Holder.mLock".to_string(), 0),
            ("t.Binder$Holder.underSyncMethod:()V".to_string(), "t.Binder$Holder".to_string(), 0),
        ]
    );
}

/// Control-flow-aware held-lock tracking over `fixtures/cfg.dex`: the locks held at
/// each helper call are exactly those of its enclosing block, across an early
/// return, a catch handler, try/finally, a switch, a loop, a successful `tryLock`,
/// a read-write lock view, a lock taken/released through helper methods, and lambdas
/// the callee invokes (directly or transitively), stores, or cannot be inspected.
#[test]
fn fixture_cfg_held() {
    let bytes = include_bytes!("fixtures/cfg.dex");
    let d = dex::parse_dex_blob(bytes).expect("parse fixture");
    let idx = dex::ctx::build(&d, &dex::ctx::Options::default());
    let held_at = |callee: &str| -> Vec<String> {
        let key = format!("t.Cfg.{callee}:()V");
        let t = idx.find_methods(&key);
        assert_eq!(t.len(), 1, "{key}");
        let mut v: Vec<String> = idx
            .calls
            .iter()
            .filter(|c| c.targets.contains(&t[0]))
            .flat_map(|c| c.held.iter().map(|&l| idx.locks[l as usize].clone()))
            .collect();
        v.sort();
        v.dedup();
        v
    };
    let a = vec!["t.Cfg.mA".to_string()];
    assert_eq!(held_at("after"), a, "code after an early return is still inside the block");
    assert_eq!(held_at("outside"), Vec::<String>::new());
    assert_eq!(held_at("inCatch"), a, "catch handler inherits the monitor");
    assert_eq!(held_at("inFinally"), a);
    assert_eq!(held_at("s1"), a);
    assert_eq!(held_at("s2"), a);
    assert_eq!(held_at("s3"), a);
    assert_eq!(held_at("body"), a);
    assert_eq!(held_at("tail"), Vec::<String>::new());
    assert_eq!(held_at("inTry"), vec!["t.Cfg.mL".to_string()]);
    assert_eq!(held_at("post"), Vec::<String>::new(), "tryLock result does not leak past the join");
    assert_eq!(held_at("inRead"), vec!["t.Cfg.mRw.read".to_string()]);
    assert_eq!(held_at("afterRead"), Vec::<String>::new());
    assert_eq!(held_at("inHelperLock"), vec!["t.Cfg.mL".to_string()], "lock taken by a helper is held after it returns");
    assert_eq!(held_at("afterHelper"), Vec::<String>::new(), "lock released by a helper");

    // A lambda inherits the block's lock iff the callee invokes it — directly or
    // by passing it on. A stored one gets nothing; so does one handed to a callee
    // outside the inputs (its body cannot be inspected: assumed not held).
    let ma = idx.find_locks("t.Cfg.mA")[0];
    let caller_of = |callee: &str| -> u32 {
        let t = idx.find_methods(&format!("t.Cfg.{callee}:()V"))[0];
        idx.calls.iter().find(|c| c.targets.contains(&t)).expect("called").caller
    };
    assert!(idx.dist(caller_of("inLambda"), ma).is_some(), "callee invokes the lambda");
    assert!(idx.dist(caller_of("inLambda2"), ma).is_some(), "callee passes it to one that invokes it");
    assert_eq!(idx.dist(caller_of("inPosted"), ma), None, "stored lambda is not invoked");
    assert_eq!(idx.dist(caller_of("inExternal"), ma), None, "callee outside the inputs: assumed not held");
}

/// When `$DEXLOCK_DEXDUMP` points at a `dexdump`, the native and dexdump front-ends
/// must produce identical resolution (the no-op guarantee). Skipped otherwise.
#[test]
fn native_matches_dexdump_on_fixture() {
    if std::env::var_os("DEXLOCK_DEXDUMP").is_none() {
        return; // no dexdump available; the fixture test above still covers native
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/locks.dex");
    let bytes = std::fs::read(path).expect("read fixture");

    let native = triples(&dex::parse_dex_blob(&bytes).expect("native parse"));

    std::env::set_var("DEXLOCK_USE_DEXDUMP", "1");
    let viadexdump = triples(&dex::parse_dex_blob(&bytes).expect("dexdump parse"));
    std::env::remove_var("DEXLOCK_USE_DEXDUMP");

    assert_eq!(native, viadexdump, "native and dexdump front-ends diverged");
}
