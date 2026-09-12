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

//! APEX packages: the dex-bearing jars (`javalib/*.jar`) of an `.apex`, or of a
//! compressed `.capex` (a zip whose `original_apex` member is the `.apex`).
//!
//! Everything happens in memory: the zip is opened from bytes, `apex_payload.img`
//! is read out, and an in-process EROFS or ext4 reader walks the image to
//! `/javalib`. If the payload uses a feature the native readers do not cover, the
//! `deapexer` host tool is used instead (found via `$DEXLOCK_DEAPEXER`, then
//! `PATH`; its `debugfs`/`fsck.erofs` helpers via `$DEXLOCK_DEBUGFS` /
//! `$DEXLOCK_FSCK_EROFS`, then beside `deapexer`, then `PATH`).

mod erofs;
mod ext4;
mod lz4;

use anyhow::{bail, Context, Result};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

const PAYLOAD: &str = "apex_payload.img";
const ORIGINAL: &str = "original_apex";
const JAVALIB: &str = "javalib";

pub fn is_apex_name(name: &str) -> bool {
    matches!(name.rsplit('.').next(), Some("apex" | "capex"))
}

/// `(jar name, jar bytes)` for every `javalib/*.jar` in the package, natively.
pub fn javalib_jars(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let img = payload(bytes, 0)?;
    jars_in_image(&img)
}

/// Like [`javalib_jars`], falling back to `deapexer` on the on-disk `path` when
/// the native readers cannot handle the payload.
pub fn javalib_jars_at(path: &Path, bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    match javalib_jars(bytes) {
        Ok(jars) => Ok(jars),
        Err(native) => {
            log::warn!("{}: native apex read failed ({native:#}); trying deapexer", path.display());
            deapexer(path).with_context(|| format!("{}: native read failed ({native:#}) and so did deapexer", path.display()))
        }
    }
}

/// The filesystem image inside an apex/capex zip.
fn payload(bytes: &[u8], depth: usize) -> Result<Vec<u8>> {
    if depth > 2 {
        bail!("apex: nested too deep");
    }
    let mut z = zip::ZipArchive::new(Cursor::new(bytes)).context("apex: not a zip")?;
    let member = |z: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str| -> Result<Option<Vec<u8>>> {
        match z.by_name(name) {
            Ok(mut e) => {
                let mut buf = Vec::with_capacity(e.size() as usize);
                e.read_to_end(&mut buf)?;
                Ok(Some(buf))
            }
            Err(zip::result::ZipError::FileNotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    };
    if let Some(inner) = member(&mut z, ORIGINAL)? {
        return payload(&inner, depth + 1);
    }
    member(&mut z, PAYLOAD)?.with_context(|| format!("apex: no {PAYLOAD} member"))
}

fn jars_in_image(img: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    if erofs::is_erofs(img) {
        let fs = erofs::Erofs::parse(img)?;
        for e in fs.read_dir(JAVALIB)?.unwrap_or_default() {
            if e.ftype == erofs::FT_REG && e.name.ends_with(".jar") {
                out.push((e.name.clone(), fs.read_nid(e.nid).with_context(|| format!("apex: reading {}", e.name))?));
            }
        }
    } else if ext4::is_ext4(img) {
        let fs = ext4::Ext4::parse(img)?;
        for e in fs.read_dir(JAVALIB)?.unwrap_or_default() {
            if e.ftype == ext4::FT_REG && e.name.ends_with(".jar") {
                out.push((e.name.clone(), fs.read_ino(e.ino).with_context(|| format!("apex: reading {}", e.name))?));
            }
        }
    } else {
        bail!("apex: payload is neither erofs nor ext4");
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Locate a host tool: an explicit env var, a sibling of `near`, then `PATH`.
fn tool(env: &str, name: &str, near: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(env) {
        return Some(PathBuf::from(p));
    }
    if let Some(dir) = near.and_then(Path::parent) {
        let p = dir.join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    std::env::var_os("PATH").and_then(|paths| std::env::split_paths(&paths).map(|d| d.join(name)).find(|p| p.is_file()))
}

/// Extract with the `deapexer` host tool and read `javalib/*.jar` back.
pub fn deapexer(apex: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let bin = tool("DEXLOCK_DEAPEXER", "deapexer", None).context("deapexer not found ($DEXLOCK_DEAPEXER or PATH)")?;
    let dir = std::env::temp_dir().join(format!("dexlock-apex-{}-{}", std::process::id(), apex.file_name().and_then(|s| s.to_str()).unwrap_or("apex")));
    let _ = std::fs::remove_dir_all(&dir);
    let mut cmd = std::process::Command::new(&bin);
    if let Some(p) = tool("DEXLOCK_DEBUGFS", "debugfs", Some(&bin)) {
        cmd.arg("--debugfs_path").arg(p);
    }
    if let Some(p) = tool("DEXLOCK_FSCK_EROFS", "fsck.erofs", Some(&bin)) {
        cmd.arg("--fsckerofs_path").arg(p);
    }
    let status = cmd.arg("extract").arg(apex).arg(&dir).output().context("running deapexer")?;
    if !status.status.success() {
        let _ = std::fs::remove_dir_all(&dir);
        bail!("deapexer failed: {}", String::from_utf8_lossy(&status.stderr).trim());
    }
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir.join(JAVALIB)) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "jar") {
                let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
                out.push((name, std::fs::read(&p)?));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}
