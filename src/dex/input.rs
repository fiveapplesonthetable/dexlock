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
fn merge_dexes(parsed: Vec<Dex>) -> Dex {
    let mut merged = Dex::default();
    for d in parsed {
        merged.classes.extend(d.classes);
        merged.final_or_volatile_fields.extend(d.final_or_volatile_fields);
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

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
