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
