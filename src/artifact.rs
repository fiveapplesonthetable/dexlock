//! Where the DEX-bearing artifacts for a build come from.
//!
//! The resolver needs a directory of `.jar` / `.apk` files for a build; how that
//! directory is produced is a pluggable seam. Portable providers ship here: a
//! directory that already holds the jars, an in-process unpacker for a local
//! archive, and a fixed-directory mock. Wire in an environment-specific downloader
//! by implementing [`ArtifactProvider`] (fetch from a build server, unpack, and
//! return the directory) — no other code changes.

use anyhow::{Context, Result};
use rayon::prelude::*;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Yields a directory of DEX-bearing files (`.jar` / `.apk`) for a build.
pub trait ArtifactProvider: Sync {
    /// Directory containing the artifacts for `(build_id, device)`, ready to hand
    /// to the resolver.
    fn artifacts(&self, build_id: &str, device: &str) -> Result<PathBuf>;
}

/// Artifacts already laid out on disk: `root/<build_id>/` if that subdirectory
/// exists, otherwise `root` itself (a single flat directory of jars).
pub struct DirArtifactProvider {
    pub root: PathBuf,
}

impl ArtifactProvider for DirArtifactProvider {
    fn artifacts(&self, build_id: &str, _device: &str) -> Result<PathBuf> {
        let per_build = self.root.join(build_id);
        Ok(if per_build.is_dir() { per_build } else { self.root.clone() })
    }
}

/// A fixed directory, regardless of build — for tests and demos.
pub struct MockArtifactProvider {
    pub dir: PathBuf,
}

impl ArtifactProvider for MockArtifactProvider {
    fn artifacts(&self, _build_id: &str, _device: &str) -> Result<PathBuf> {
        Ok(self.dir.clone())
    }
}

/// Unpacks a local archive per build in-process (no `unzip` subprocess): it reads
/// `root/<build_id>.zip`, extracts every `.jar` / `.apk` entry into a per-build
/// output directory, and returns it. Extraction is parallelized across entries.
/// Already-extracted builds are reused.
pub struct ZipArtifactProvider {
    /// Directory holding `<build_id>.zip` archives.
    pub root: PathBuf,
    /// Where extracted per-build directories are written.
    pub out_root: PathBuf,
}

impl ArtifactProvider for ZipArtifactProvider {
    fn artifacts(&self, build_id: &str, _device: &str) -> Result<PathBuf> {
        let dest = self.out_root.join(build_id);
        if is_nonempty_dir(&dest) {
            return Ok(dest); // already unpacked
        }
        std::fs::create_dir_all(&dest)?;
        let archive = self.root.join(format!("{build_id}.zip"));
        extract_dex_bearing(&archive, &dest)
            .with_context(|| format!("unpacking {}", archive.display()))?;
        Ok(dest)
    }
}

fn is_nonempty_dir(p: &Path) -> bool {
    std::fs::read_dir(p).ok().is_some_and(|mut e| e.next().is_some())
}

/// Extract every `.jar` / `.apk` entry of a zip into `dest` (flattened), decoding
/// entries in parallel. Each worker opens its own reader over the shared archive
/// bytes, so decompression scales across cores without a shared cursor.
fn extract_dex_bearing(archive: &Path, dest: &Path) -> Result<()> {
    let bytes: Arc<Vec<u8>> = Arc::new(
        std::fs::read(archive).with_context(|| format!("reading {}", archive.display()))?,
    );

    // One pass to enumerate the entries worth extracting.
    let targets: Vec<(usize, String)> = {
        let mut zip = zip::ZipArchive::new(Cursor::new(bytes.as_slice()))?;
        (0..zip.len())
            .filter_map(|i| {
                let f = zip.by_index(i).ok()?;
                if !f.is_file() {
                    return None;
                }
                let name = f.name();
                let keep = name.ends_with(".jar") || name.ends_with(".apk");
                keep.then(|| (i, base_name(name)))
            })
            .collect()
    };

    // Decode/write entries concurrently; unique output names avoid collisions when
    // the same basename appears under different archive directories.
    targets.par_iter().try_for_each(|(idx, base)| -> Result<()> {
        let mut zip = zip::ZipArchive::new(Cursor::new(bytes.as_slice()))?;
        let mut entry = zip.by_index(*idx)?;
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;
        let out = dest.join(format!("{idx:04}_{base}"));
        std::fs::write(&out, &buf).with_context(|| format!("writing {}", out.display()))?;
        Ok(())
    })
}

fn base_name(zip_name: &str) -> String {
    zip_name.rsplit('/').next().unwrap_or(zip_name).to_string()
}
