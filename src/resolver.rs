//! The resolver: turn contention source sites into canonical locks.
//!
//! Resolution runs entirely in-process — there is no per-query subprocess and no
//! on-the-wire index file. For a build, the expensive step (parse the DEX, run the
//! lock analysis in [`crate::dex`]) is done once, its site→lock projection is
//! cached to disk, and then every site is answered from an in-memory lookup.
//! Re-runs against the same build skip the analysis entirely and load the cached
//! projection in milliseconds.

use crate::dex::{self, input, resolve::ResolveIndex};
use crate::site;
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// How to resolve: line-drift tolerance and the "sole lock in the file" fallback.
/// Defaults to exact-line, no fallback.
#[derive(Clone, Copy, Default)]
pub struct Options {
    /// Snap to the nearest monitor-enter within this many lines (0 = exact only).
    pub fuzz: u32,
    /// When the line can't be matched, return the file's sole lock if unambiguous.
    pub if_unique: bool,
}

/// Resolves sites for builds, caching each build's index on disk.
pub struct Resolver {
    cache_dir: PathBuf,
    scope: Option<String>,
    opts: Options,
}

impl Resolver {
    pub fn new(cache_dir: PathBuf, scope: Option<String>, opts: Options) -> Self {
        Resolver { cache_dir, scope, opts }
    }

    /// The site→lock index for a build. Loads the on-disk projection if present,
    /// otherwise analyzes `artifact_dir` once and caches the result.
    pub fn index_for(&self, build_id: &str, artifact_dir: &Path) -> Result<ResolveIndex> {
        let cache = self.cache_dir.join(format!("{}.idx.json", sanitize(build_id)));
        if cache.is_file() {
            let raw = std::fs::read_to_string(&cache)
                .with_context(|| format!("reading cached index {}", cache.display()))?;
            if let Ok(idx) = serde_json::from_str::<ResolveIndex>(&raw) {
                if idx.version == ResolveIndex::VERSION {
                    log::info!("loaded cached index for {build_id} ({} sites)", idx.sites.len());
                    return Ok(idx);
                }
            }
            log::warn!("stale/unreadable cache for {build_id}; rebuilding");
        }

        let idx = build_index(artifact_dir, self.scope.as_deref())
            .with_context(|| format!("analyzing artifacts for {build_id}"))?;
        std::fs::create_dir_all(&self.cache_dir).ok();
        if let Ok(json) = serde_json::to_string(&idx) {
            let _ = std::fs::write(&cache, json);
        }
        log::info!("built index for {build_id} ({} sites)", idx.sites.len());
        Ok(idx)
    }

    /// Resolve a set of sites against a build's index. Returns `site → lock name`
    /// (`"N/A"` when unresolved). Sites are answered concurrently.
    pub fn resolve(&self, index: &ResolveIndex, sites: &[String]) -> HashMap<String, String> {
        let lookup = index.prepare();
        sites
            .par_iter()
            .map(|s| {
                let name = match site::parse(s) {
                    Some((file, line)) => {
                        let r = lookup.resolve(file, line, self.opts.fuzz, None, self.opts.if_unique);
                        if r.locks.is_empty() {
                            "N/A".to_string()
                        } else {
                            r.locks.join(", ")
                        }
                    }
                    None => "N/A".to_string(),
                };
                (s.clone(), name)
            })
            .collect()
    }
}

/// Analyze a directory (or single jar/apk/archive) and project it to a site→lock
/// index. This is the one place the DEX front-end runs — natively in-process by
/// default (set `$DEXLOCK_USE_DEXDUMP` to use the `dexdump` subprocess instead).
pub fn build_index(artifact: &Path, scope: Option<&str>) -> Result<ResolveIndex> {
    let parsed = input::parse_inputs(std::slice::from_ref(&artifact.to_path_buf()), scope)
        .with_context(|| format!("analyzing dex in {}", artifact.display()))?;
    Ok(ResolveIndex::from_acquisitions(&dex::acquisitions(&parsed)))
}

/// Make a build id safe as a filename.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
        .collect()
}
