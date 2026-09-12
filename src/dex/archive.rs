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

//! Native extraction of DEX section blobs from the artifacts that actually carry
//! dex: a bare `.dex`, a zip-family archive (`.jar`/`.apk`/`.zip`/`.aar`), an APEX
//! (`.apex`/`.capex`, whose `javalib/*.jar` are read out of the payload image), a
//! directory of them, or a zip that nests more jars/apks. Archives are read in
//! memory (no `unzip` subprocess, no temp files) and recognized by magic first,
//! then extension, so an odd name still works.

use anyhow::{Context, Result};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

const DEX_MAGIC: &[u8] = b"dex\n";
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
const MAX_DEPTH: usize = 8;

/// Every DEX blob reachable from `path`. Directories prefer the Soong
/// `system_server_dexjars` layout (respecting `scope` on jar names), else scan for
/// jars/apks/dex in the directory.
pub fn dex_blobs(path: &Path, scope: Option<&str>) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    collect_path(path, scope, &mut out)?;
    Ok(out)
}

fn collect_path(path: &Path, scope: Option<&str>, out: &mut Vec<Vec<u8>>) -> Result<()> {
    let meta = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if meta.is_dir() {
        for jar in soong_jars(path, scope) {
            collect_path(&jar, None, out)?;
        }
        return Ok(());
    }
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if super::apex::is_apex_name(name) {
        // An APEX carries its jars inside a filesystem image: unpack natively
        // (deapexer as a fallback), then treat each jar as an input of its own.
        for (jar, jar_bytes) in super::apex::javalib_jars_at(path, &bytes)? {
            collect_bytes(&jar, jar_bytes, out, 1)?;
        }
        return Ok(());
    }
    collect_bytes(name, bytes, out, 0)
}

fn collect_bytes(name: &str, bytes: Vec<u8>, out: &mut Vec<Vec<u8>>, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Ok(()); // guard against pathological nesting / cycles
    }
    if bytes.starts_with(DEX_MAGIC) {
        out.push(bytes);
    } else if bytes.starts_with(ZIP_MAGIC) || is_zip_ext(name) {
        let mut z = zip::ZipArchive::new(Cursor::new(&bytes))
            .with_context(|| format!("opening zip {name}"))?;
        for i in 0..z.len() {
            let mut e = z.by_index(i)?;
            if !e.is_file() {
                continue;
            }
            let ename = base(e.name());
            if !interesting(&ename) {
                continue;
            }
            let mut buf = Vec::with_capacity(e.size() as usize);
            e.read_to_end(&mut buf)?;
            collect_bytes(&ename, buf, out, depth + 1)?;
        }
    }
    Ok(())
}

fn base(name: &str) -> String {
    name.rsplit('/').next().unwrap_or(name).to_string()
}

/// Recurse only into members that could hold dex.
fn interesting(name: &str) -> bool {
    name.ends_with(".dex") || name.starts_with("classes") || is_zip_ext(name)
}

fn is_zip_ext(name: &str) -> bool {
    matches!(name.rsplit('.').next(), Some("jar" | "apk" | "zip" | "aar"))
}

/// Dex-bearing jars in a directory: the Soong `system_server_dexjars` if present
/// (narrowed by `scope`), else any jar/apk/dex directly inside.
fn soong_jars(dir: &Path, scope: Option<&str>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let ss = dir.join("soong/system_server_dexjars");
    if ss.is_dir() {
        for e in std::fs::read_dir(&ss).into_iter().flatten().flatten() {
            let p = e.path();
            let is_jar = p.extension().is_some_and(|x| x == "jar");
            let in_scope =
                scope.is_none_or(|s| p.file_stem().is_some_and(|f| f.to_string_lossy().contains(s)));
            if is_jar && in_scope {
                out.push(p);
            }
        }
    }
    if !out.is_empty() {
        return out;
    }
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
        if matches!(ext, "jar" | "apk" | "zip" | "dex" | "apex" | "capex") {
            out.push(p);
        }
    }
    out
}
