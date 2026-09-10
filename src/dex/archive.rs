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

//! Native, recursive extraction of DEX section blobs from any reasonable container:
//! a bare `.dex`; a zip family member (`.jar`/`.apk`/`.zip`); a `.tar`; a
//! gzip (`.gz`/`.tgz`/`.tar.gz`); or a directory — including *nested* archives (a
//! zip of jars, a tar.gz of apks). Everything is read in memory: no `unzip`
//! subprocess and no temp files. Containers are recognized by magic first, then by
//! extension, so an odd name still works.

use anyhow::{Context, Result};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

const DEX_MAGIC: &[u8] = b"dex\n";
const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
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
    collect_bytes(name, bytes, out, 0)
}

fn collect_bytes(name: &str, bytes: Vec<u8>, out: &mut Vec<Vec<u8>>, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Ok(()); // guard against pathological nesting / cycles
    }
    if bytes.starts_with(DEX_MAGIC) {
        out.push(bytes);
    } else if bytes.starts_with(ZIP_MAGIC) || is_zip_ext(name) {
        let mut z = zip::ZipArchive::new(Cursor::new(&bytes)).with_context(|| format!("opening zip {name}"))?;
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
    } else if bytes.starts_with(&GZIP_MAGIC) || name.ends_with(".gz") || name.ends_with(".tgz") {
        let mut inner = Vec::new();
        flate2::read::GzDecoder::new(Cursor::new(&bytes))
            .read_to_end(&mut inner)
            .with_context(|| format!("gunzip {name}"))?;
        // .tgz / .tar.gz decompress to a tar; a plain .gz to its single member.
        let inner_name = if name.ends_with(".tgz") || name.ends_with(".tar.gz") {
            "inner.tar".to_string()
        } else {
            name.strip_suffix(".gz").unwrap_or(name).to_string()
        };
        collect_bytes(&inner_name, inner, out, depth + 1)?;
    } else if is_tar(&bytes) || name.ends_with(".tar") {
        let mut a = tar::Archive::new(Cursor::new(&bytes));
        for entry in a.entries()? {
            let mut entry = entry?;
            let ename = entry
                .path()
                .ok()
                .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
                .unwrap_or_default();
            if !interesting(&ename) {
                continue;
            }
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
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
    name.ends_with(".dex")
        || name.starts_with("classes")
        || is_zip_ext(name)
        || name.ends_with(".tar")
        || name.ends_with(".gz")
        || name.ends_with(".tgz")
}

fn is_zip_ext(name: &str) -> bool {
    matches!(name.rsplit('.').next(), Some("jar" | "apk" | "zip" | "aar"))
}

fn is_tar(bytes: &[u8]) -> bool {
    bytes.len() > 262 && &bytes[257..262] == b"ustar"
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
        if matches!(ext, "jar" | "apk" | "zip" | "dex") {
            out.push(p);
        }
    }
    out
}
