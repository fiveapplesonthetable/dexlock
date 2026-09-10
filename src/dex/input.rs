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

//! Input resolution: turn a path into a set of `classes*.dex` files to analyze.
//!
//! Accepts:
//!   * a `.dex` file directly;
//!   * a `.jar` / `.apk` / `.zip` (extracts every `classes*.dex`, i.e. multidex);
//!   * a directory — a Soong `out` tree (locates `system_server_dexjars/*.jar`,
//!     and as a fallback any `*.jar` with dex / loose `classes*.dex`).
//!
//! Multiple dexes are parsed in parallel and merged into one `Dex` so the call
//! graph resolves across dex boundaries.

use crate::dex::dexdump;
use crate::dex::model::Dex;
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A dex source: either a real `.dex` file, or a member inside a jar/zip that we
/// extract to a temp dir on demand.
pub struct DexSet {
    pub files: Vec<PathBuf>,
    _tmp: Option<tempdir::TempDir>,
}

/// Minimal temp-dir holder (no external crate): created under $TMPDIR.
mod tempdir {
    use std::path::{Path, PathBuf};
    pub struct TempDir(PathBuf);
    impl TempDir {
        pub fn new(tag: &str) -> std::io::Result<Self> {
            let base = std::env::temp_dir();
            // unique-ish name without rand: pid + tag + counter via dir existence.
            let pid = std::process::id();
            let mut n = 0;
            loop {
                let p = base.join(format!("dexlock-{tag}-{pid}-{n}"));
                match std::fs::create_dir(&p) {
                    Ok(()) => return Ok(TempDir(p)),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => n += 1,
                    Err(e) => return Err(e),
                }
            }
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn extract_dexes(archive: &Path, tag: &str) -> Result<(Vec<PathBuf>, tempdir::TempDir)> {
    let td = tempdir::TempDir::new(tag).context("creating temp dir")?;
    let status = Command::new("unzip")
        .args(["-o", "-q"])
        .arg(archive)
        .arg("classes*.dex")
        .arg("-d")
        .arg(td.path())
        .status()
        .context("running unzip")?;
    if !status.success() {
        anyhow::bail!("unzip failed on {}", archive.display());
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(td.path())?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "dex").unwrap_or(false))
        .collect();
    files.sort();
    Ok((files, td))
}

/// Resolve an input path to a `DexSet`. `scope` optionally narrows a Soong out dir.
pub fn resolve(path: &Path, scope: Option<&str>) -> Result<DexSet> {
    let meta = std::fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?;

    if meta.is_file() {
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if ext == "dex" {
            return Ok(DexSet { files: vec![path.to_path_buf()], _tmp: None });
        }
        // jar/apk/zip
        let (files, td) = extract_dexes(path, "ar")?;
        return Ok(DexSet { files, _tmp: Some(td) });
    }

    // directory: gather candidate jars, then extract.
    let jars = collect_soong_jars(path, scope);
    if jars.is_empty() {
        anyhow::bail!(
            "no dex jars found under {} (looked for system_server_dexjars/*.jar and *.jar)",
            path.display()
        );
    }
    let td = tempdir::TempDir::new("out")?;
    let mut files = Vec::new();
    for (i, jar) in jars.iter().enumerate() {
        let sub = td.path().join(format!("j{i}"));
        std::fs::create_dir_all(&sub)?;
        let status = Command::new("unzip")
            .args(["-o", "-q"])
            .arg(jar)
            .arg("classes*.dex")
            .arg("-d")
            .arg(&sub)
            .status()?;
        if status.success() {
            for e in std::fs::read_dir(&sub)?.flatten() {
                let p = e.path();
                if p.extension().map(|x| x == "dex").unwrap_or(false) {
                    files.push(p);
                }
            }
        }
    }
    files.sort();
    Ok(DexSet { files, _tmp: Some(td) })
}

/// Find dex-bearing jars in a Soong `out` tree.
fn collect_soong_jars(dir: &Path, scope: Option<&str>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    // Preferred, stable location for the whole system_server.
    let ss = dir.join("soong/system_server_dexjars");
    if ss.is_dir() {
        for e in std::fs::read_dir(&ss).into_iter().flatten().flatten() {
            let p = e.path();
            let is_jar = p.extension().is_some_and(|x| x == "jar");
            let in_scope = scope
                .is_none_or(|s| p.file_stem().is_some_and(|f| f.to_string_lossy().contains(s)));
            if is_jar && in_scope {
                out.push(p);
            }
        }
    }
    if !out.is_empty() {
        return out;
    }
    // fallback: jars / dexes directly inside the directory.
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
        if ext == "jar" || ext == "apk" || ext == "dex" {
            out.push(p);
        }
    }
    out
}

/// Resolve, parse and merge several inputs (jars/apks/dex files/dirs) into one
/// `Dex`, so the interprocedural resolver sees calls across all of them. Every
/// input's dexes are gathered first, then all are parsed in a single parallel pass
/// (so the `dexdump` subprocesses overlap across jars, not just within one).
pub fn parse_inputs(paths: &[PathBuf], scope: Option<&str>) -> Result<Dex> {
    if paths.is_empty() {
        anyhow::bail!("no inputs to analyze");
    }
    // Keep the DexSets (and their temp dirs) alive until parsing finishes.
    let sets: Vec<DexSet> = paths
        .iter()
        .map(|p| resolve(p, scope).with_context(|| format!("locating dex in {}", p.display())))
        .collect::<Result<_>>()?;
    let files: Vec<&PathBuf> = sets.iter().flat_map(|s| s.files.iter()).collect();
    if files.is_empty() {
        anyhow::bail!("no dex files found in the given inputs");
    }
    let parsed: Vec<Dex> =
        files.par_iter().map(|p| dexdump::parse_dex(p)).collect::<Result<Vec<_>>>()?;
    Ok(merge_dexes(parsed))
}

/// Parse every dex (in parallel) and merge into one `Dex`.
pub fn parse_all(set: &DexSet) -> Result<Dex> {
    if set.files.is_empty() {
        anyhow::bail!("no dex files to analyze");
    }
    let parsed: Vec<Dex> = set
        .files
        .par_iter()
        .map(|p| dexdump::parse_dex(p))
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
