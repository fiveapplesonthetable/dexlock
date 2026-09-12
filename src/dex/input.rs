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

//! Input pipeline: turn a set of paths (jars/apks/dex/archives/dirs) into one merged
//! [`Dex`]. Containers are extracted natively and recursively in memory
//! ([`crate::dex::archive`]) — no `unzip` subprocess, no temp files — then every DEX
//! section is parsed in parallel and merged, so the call graph resolves across
//! artifact boundaries.

use crate::dex::archive;
use crate::dex::model::Dex;
use anyhow::Result;
use rayon::prelude::*;
use rustc_hash::FxHashSet as HashSet;
use std::path::PathBuf;

/// Gather, parse and merge every DEX reachable from `paths` into one `Dex`.
pub fn parse_inputs(paths: &[PathBuf], scope: Option<&str>) -> Result<Dex> {
    if paths.is_empty() {
        anyhow::bail!("no inputs to analyze");
    }
    let blobs: Vec<Vec<u8>> = paths
        .iter()
        .map(|p| archive::dex_blobs(p, scope))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    if blobs.is_empty() {
        anyhow::bail!("no dex found in the given inputs");
    }
    parse_blobs(blobs)
}

/// Parse a set of DEX section blobs in parallel and merge them.
pub fn parse_blobs(blobs: Vec<Vec<u8>>) -> Result<Dex> {
    let parsed: Vec<Dex> = blobs
        .par_iter()
        .map(|b| crate::dex::parse_dex_blob(b))
        .collect::<Result<Vec<_>>>()?;
    Ok(merge_dexes(parsed))
}

/// Merge per-dex parses into one. Every field of [`Dex`] must be carried over —
/// dropping `final_or_volatile_fields` silently disables the race exclusion for the
/// whole jar (regression-tested below).
///
/// A class that appears in more than one artifact is kept once, from the artifact
/// given first, as the runtime resolves it once from the classpath. Keeping every
/// copy does not just waste work: calls resolve to one of them, so the rest are left
/// with no callers at all, and an analysis that reads "no caller holds a lock here"
/// off the call graph draws exactly the wrong conclusion about them. A full system
/// image has ~2.3k such copies.
fn merge_dexes(parsed: Vec<Dex>) -> Dex {
    let mut merged = Dex::default();
    let mut seen: HashSet<String> = HashSet::default();
    let mut dropped = 0usize;
    for d in parsed {
        for c in d.classes {
            if seen.insert(c.descriptor.clone()) {
                merged.classes.push(c);
            } else {
                dropped += 1;
            }
        }
        merged.final_or_volatile_fields.extend(d.final_or_volatile_fields);
    }
    if dropped > 0 {
        log::info!("merged {} classes ({dropped} duplicate copies dropped)", merged.classes.len());
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A class in two artifacts is kept once, from the first, so that calls cannot
    /// resolve to one copy and orphan another — an orphan has no callers, and
    /// "no caller holds a lock" is then read off the call graph as a fact.
    #[test]
    fn merge_keeps_one_copy_of_a_duplicated_class() {
        let cls = |d: &str, m: &str| crate::dex::model::Class {
            descriptor: d.to_string(),
            super_class: None,
            interfaces: Vec::new(),
            methods: vec![crate::dex::model::Method {
                class: d.to_string(),
                name: m.to_string(),
                sig: "()V".to_string(),
                access: 0,
                registers: 0,
                ins: 0,
                insns: Vec::new(),
                positions: Vec::new(),
                catches: Vec::new(),
                source_file: None,
            }],
        };
        let mut a = Dex::default();
        a.classes.push(cls("pkg.Shared", "first"));
        a.classes.push(cls("pkg.OnlyA", "a"));
        let mut b = Dex::default();
        b.classes.push(cls("pkg.Shared", "second"));
        b.classes.push(cls("pkg.OnlyB", "b"));
        let merged = merge_dexes(vec![a, b]);
        let names: Vec<&str> = merged.classes.iter().map(|c| c.descriptor.as_str()).collect();
        assert_eq!(names, ["pkg.Shared", "pkg.OnlyA", "pkg.OnlyB"]);
        // The copy kept is the one from the artifact given first.
        assert_eq!(merged.classes[0].methods[0].name, "first");
    }

    #[test]
    fn merge_preserves_final_or_volatile_fields() {
        let mut a = Dex::default();
        a.final_or_volatile_fields.insert("pkg.A.mState".to_string());
        let mut b = Dex::default();
        b.final_or_volatile_fields.insert("pkg.B.mFlag".to_string());
        let merged = merge_dexes(vec![a, b]);
        assert!(merged.final_or_volatile_fields.contains("pkg.A.mState"));
        assert!(merged.final_or_volatile_fields.contains("pkg.B.mFlag"));
    }
}
