//! End-to-end pipeline test that needs no DEX toolchain: it seeds a cached index
//! (the same JSON the resolver writes after analysis) and runs the full
//! load -> group -> resolve -> save path in-process.

use dexlock::artifact::MockArtifactProvider;
use dexlock::model::Query;
use dexlock::pipeline::{self, Output};
use dexlock::resolver::{Options, Resolver};
use dexlock::traces::{CsvTraceSource, TraceSource};
use std::fs;

#[test]
fn resolves_from_cached_index() {
    let tmp = tempdir();

    // A cached index: two sites in one file, exactly the resolver's on-disk shape.
    let cache = tmp.join("cache");
    fs::create_dir_all(&cache).unwrap();
    let index = r#"{
      "version": 1,
      "sites": [
        {"relpath":"demo/Svc.java","method":"demo.Svc.a:()V","line":10,"lock":"demo.Svc.mLock"},
        {"relpath":"demo/Svc.java","method":"demo.Svc.b:()V","line":20,"lock":"demo.Other.mGuard"}
      ]
    }"#;
    fs::write(cache.join("BUILD1.idx.json"), index).unwrap();

    // A contention table referencing those sites.
    let input = tmp.join("in.csv");
    fs::write(
        &input,
        "build_id,device_name,blocked_src,blocking_src,short_blocked_method,short_blocking_method\n\
         BUILD1,demo,Svc.java:10,Svc.java:20,a,b\n\
         BUILD1,demo,Svc.java:20,Svc.java:10,b,a\n",
    )
    .unwrap();

    let rows = CsvTraceSource { path: input.clone() }.fetch(&Query::default()).unwrap();
    let table = dexlock::csv_io::load(&input).unwrap();
    let provider = MockArtifactProvider { dir: tmp.clone() }; // unused: cache hit
    let resolver = Resolver::new(cache, None, Options::default());
    let out = tmp.join("out.csv");

    pipeline::run(
        rows,
        &provider,
        &resolver,
        &table.headers,
        &Output { path: out.clone(), compact: false },
    )
    .unwrap();

    let text = fs::read_to_string(&out).unwrap();
    assert!(text.contains("resolved_blocked_lock"));
    // Row 1: blocked=Svc.java:10 -> demo.Svc.mLock, blocking=Svc.java:20 -> demo.Other.mGuard
    assert!(text.contains("demo.Svc.mLock"), "output:\n{text}");
    assert!(text.contains("demo.Other.mGuard"), "output:\n{text}");

    // Every data row got both columns filled (no leftover N/A on known sites).
    for line in text.lines().skip(1) {
        assert!(!line.contains("N/A"), "unexpected N/A: {line}");
    }
}

#[test]
fn compact_counts_aggregates() {
    let tmp = tempdir();
    let cache = tmp.join("cache");
    fs::create_dir_all(&cache).unwrap();
    fs::write(
        cache.join("B.idx.json"),
        r#"{"version":1,"sites":[{"relpath":"demo/Svc.java","method":"demo.Svc.a:()V","line":10,"lock":"demo.Svc.mLock"}]}"#,
    )
    .unwrap();

    let input = tmp.join("in.csv");
    let mut csv = String::from(
        "build_id,device_name,blocked_src,blocking_src,short_blocked_method,short_blocking_method\n",
    );
    for _ in 0..5 {
        csv.push_str("B,demo,Svc.java:10,Svc.java:10,a,a\n");
    }
    fs::write(&input, &csv).unwrap();

    let rows = CsvTraceSource { path: input.clone() }.fetch(&Query::default()).unwrap();
    let table = dexlock::csv_io::load(&input).unwrap();
    let out = tmp.join("out.csv");
    pipeline::run(
        rows,
        &MockArtifactProvider { dir: tmp.clone() },
        &Resolver::new(cache, None, Options::default()),
        &table.headers,
        &Output { path: out.clone(), compact: true },
    )
    .unwrap();

    let text = fs::read_to_string(&out).unwrap();
    assert!(text.contains("traces"));
    assert!(text.trim().ends_with(",5"), "expected an aggregate of 5:\n{text}");
}

/// A unique temp directory without pulling in an extra crate.
fn tempdir() -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!("dexlock_test_{}", std::process::id()));
    let dir = base.join(format!("{:?}", std::thread::current().id()).replace(['(', ')', ' '], "_"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
