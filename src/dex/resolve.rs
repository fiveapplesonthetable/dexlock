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

//! Query-only projection of an analysis, plus the `FILE:LINE` resolution logic
//! shared by `resolve` and `query`.
//!
//! Resolving a monitor-contention site to the lock taken there reads only the
//! monitor-enter sites — never the lock graph, races, or binder edges. A
//! [`ResolveIndex`] is exactly that projection: one [`Site`] per acquisition. It
//! is independent of the slow dexdump + fixpoint that produced it and is ~1000x
//! smaller than the input jars, so it can be built once, serialized, and reloaded
//! in milliseconds to answer millions of queries without re-analyzing anything.

use crate::dex::Acquisition;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// The top-level class fixes the source file: strip any nested `$Inner` and turn
/// the dotted class into a `path/to/File.java` package-relative path.
fn relpath(class: &str) -> String {
    let top = class.split('$').next().unwrap_or(class);
    format!("{}.java", top.replace('.', "/"))
}

/// One monitor-enter site, projected for querying. `relpath` is precomputed at
/// index time so a query never re-derives it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    /// source path relative to a package root, e.g.
    /// `com/example/pkg/Service.java`.
    pub relpath: String,
    /// holder method key — the drift-immune anchor for `--method`.
    pub method: String,
    pub line: Option<u32>,
    /// canonical lock name taken at this site.
    pub lock: String,
}

/// A serializable, query-only index: every monitor-enter site and nothing else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveIndex {
    /// bumped when the on-disk shape changes so a stale index fails loudly.
    pub version: u32,
    pub sites: Vec<Site>,
}

impl ResolveIndex {
    /// On-disk format version. Bump on any breaking change to [`Site`].
    pub const VERSION: u32 = 1;

    /// Project an analysis' acquisitions into an index.
    pub fn from_acquisitions(acqs: &[Acquisition]) -> Self {
        let sites = acqs
            .iter()
            .map(|a| Site {
                relpath: relpath(&a.class),
                method: a.method.clone(),
                line: a.line,
                lock: a.lock.clone(),
            })
            .collect();
        ResolveIndex { version: Self::VERSION, sites }
    }

    /// Prepare for querying: bucket sites by source-file basename so a lookup
    /// touches only one file's sites instead of scanning all of them. Build this
    /// once, then call [`Lookup::resolve`] per query.
    pub fn prepare(&self) -> Lookup<'_> {
        let mut by_base: HashMap<&str, Vec<u32>> = HashMap::new();
        for (i, s) in self.sites.iter().enumerate() {
            let base = s.relpath.rsplit('/').next().unwrap_or(&s.relpath);
            by_base.entry(base).or_default().push(i as u32);
        }
        Lookup { sites: &self.sites, by_base }
    }
}

/// A prepared [`ResolveIndex`] with a basename bucket map, so each query is a
/// single-file bucket scan rather than a walk over every site in the program.
pub struct Lookup<'a> {
    sites: &'a [Site],
    by_base: HashMap<&'a str, Vec<u32>>,
}

/// The outcome of resolving one `FILE:LINE`.
pub struct Resolved {
    /// distinct canonical locks taken at the site (usually exactly one).
    pub locks: Vec<String>,
    /// human note, e.g. a fuzz snap or the `if_unique` fallback (empty if none).
    pub note: String,
}

impl Lookup<'_> {
    /// Resolve one `FILE:LINE`. `file` is a bare basename or a path suffix;
    /// `method` (a substring of the holder key) anchors through line drift;
    /// `fuzz` snaps to the nearest monitor-enter within N lines; `if_unique`
    /// returns the sole lock in scope when the line can't be matched.
    ///
    /// This is the single source of truth for resolution — `resolve` (live) and
    /// `query` (from a persisted index) both call it, so their answers cannot
    /// drift apart.
    pub fn resolve(
        &self,
        file: &str,
        line: i64,
        fuzz: u32,
        method: Option<&str>,
        if_unique: bool,
    ) -> Resolved {
        // Candidate sites live in one basename bucket. Within it: a path-suffix
        // check when the query carries a slash (a bare basename already matched
        // the bucket key), the optional method anchor, and a known line.
        let want_base = file.rsplit('/').next().unwrap_or(file);
        let cands: Vec<&Site> = self
            .by_base
            .get(want_base)
            .into_iter()
            .flatten()
            .filter_map(|&i| {
                let s = &self.sites[i as usize];
                let file_ok = !file.contains('/') || file.ends_with(&s.relpath);
                let method_ok = method.is_none_or(|m| s.method.contains(m));
                (file_ok && method_ok && s.line.is_some()).then_some(s)
            })
            .collect();

        let mut note = String::new();

        // 1) exact line.
        let mut hits: Vec<String> = cands
            .iter()
            .filter(|s| s.line == Some(line as u32))
            .map(|s| s.lock.clone())
            .collect();

        // 2) nearest monitor-enter within the fuzz window.
        if hits.is_empty() && fuzz > 0 {
            if let Some((_, nl)) = cands
                .iter()
                .filter_map(|s| s.line.map(|l| ((l as i64 - line).abs(), l)))
                .filter(|(d, _)| *d <= fuzz as i64)
                .min_by_key(|(d, _)| *d)
            {
                hits = cands
                    .iter()
                    .filter(|s| s.line == Some(nl))
                    .map(|s| s.lock.clone())
                    .collect();
                note = format!("  [snapped {:+} line(s) to {nl}]", nl as i64 - line);
            }
        }

        // 3) unambiguous fallback: a single distinct lock in scope.
        if hits.is_empty() && if_unique {
            let mut distinct: Vec<String> = cands.iter().map(|s| s.lock.clone()).collect();
            distinct.sort();
            distinct.dedup();
            if distinct.len() == 1 {
                hits = distinct;
                note = format!(
                    "  [unambiguous: sole lock in {}]",
                    if method.is_some() { "method" } else { "file" }
                );
            }
        }

        hits.sort();
        hits.dedup();
        Resolved { locks: hits, note }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acq(class: &str, method: &str, line: u32, lock: &str) -> Acquisition {
        Acquisition {
            class: class.into(),
            method: method.into(),
            source_file: None,
            line: Some(line),
            lock: lock.into(),
        }
    }

    fn index() -> ResolveIndex {
        ResolveIndex::from_acquisitions(&[
            acq("com.example.Foo", "com.example.Foo.a:()V", 10, "com.example.Foo.mLock"),
            acq("com.example.Foo", "com.example.Foo.b:()V", 20, "com.example.Foo"),
            acq("com.example.bar.Foo", "com.example.bar.Foo.c:()V", 30, "com.example.bar.Foo.mOther"),
            // nested class shares the top-level source file.
            acq("com.example.Foo$Inner", "com.example.Foo$Inner.d:()V", 40, "com.example.Foo.mLock"),
        ])
    }

    #[test]
    fn exact_line_by_basename() {
        let idx = index();
        let l = idx.prepare();
        assert_eq!(l.resolve("Foo.java", 10, 0, None, false).locks, ["com.example.Foo.mLock"]);
        assert_eq!(l.resolve("Foo.java", 20, 0, None, false).locks, ["com.example.Foo"]);
    }

    #[test]
    fn nested_class_maps_to_top_level_file() {
        let idx = index();
        let l = idx.prepare();
        // line 40 lives in Foo$Inner but resolves under Foo.java.
        assert_eq!(l.resolve("Foo.java", 40, 0, None, false).locks, ["com.example.Foo.mLock"]);
    }

    #[test]
    fn path_suffix_disambiguates_same_basename() {
        let idx = index();
        let l = idx.prepare();
        // Bare basename `Foo.java` at line 30 matches both packages' Foo.java bucket;
        // only com/example/bar/Foo.java has a site there, so it still resolves.
        assert_eq!(l.resolve("Foo.java", 30, 0, None, false).locks, ["com.example.bar.Foo.mOther"]);
        // A full path pins the package: the com.example.Foo path has no line 30.
        assert!(l.resolve("com/example/Foo.java", 30, 0, None, false).locks.is_empty());
        // ...and the matching path resolves.
        assert_eq!(
            l.resolve("some/root/com/example/bar/Foo.java", 30, 0, None, false).locks,
            ["com.example.bar.Foo.mOther"]
        );
    }

    #[test]
    fn fuzz_snaps_to_nearest_and_notes_offset() {
        let idx = index();
        let l = idx.prepare();
        let miss = l.resolve("Foo.java", 12, 0, None, false);
        assert!(miss.locks.is_empty());
        let snap = l.resolve("Foo.java", 12, 5, None, false);
        assert_eq!(snap.locks, ["com.example.Foo.mLock"]);
        assert!(snap.note.contains("snapped -2 line(s) to 10"), "note: {}", snap.note);
        // outside the window: no snap.
        assert!(l.resolve("Foo.java", 12, 1, None, false).locks.is_empty());
    }

    #[test]
    fn method_anchor_and_if_unique() {
        let idx = index();
        let l = idx.prepare();
        // Wrong line, but the method takes exactly one distinct lock.
        let r = l.resolve("Foo.java", 999, 0, Some("Foo.b"), true);
        assert_eq!(r.locks, ["com.example.Foo"]);
        assert!(r.note.contains("sole lock in method"), "note: {}", r.note);
        // if_unique across the whole file is ambiguous (mLock and Foo), so no answer.
        assert!(l.resolve("Foo.java", 999, 0, None, true).locks.is_empty());
    }

    #[test]
    fn unknown_file_is_empty() {
        let idx = index();
        let l = idx.prepare();
        assert!(l.resolve("Nope.java", 10, 5, None, true).locks.is_empty());
    }

    #[test]
    fn json_roundtrip_preserves_answers() {
        let idx = index();
        let json = serde_json::to_string(&idx).unwrap();
        let back: ResolveIndex = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, ResolveIndex::VERSION);
        assert_eq!(
            back.prepare().resolve("Foo.java", 10, 0, None, false).locks,
            ["com.example.Foo.mLock"]
        );
    }
}
