//! Orchestration: group observations by build, resolve each build's sites once,
//! write results (progressively, so a long run yields partial output as it goes).

use crate::artifact::ArtifactProvider;
use crate::csv_io;
use crate::model::Contention;
use crate::resolver::Resolver;
use crate::site;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// Output configuration for a run.
pub struct Output {
    pub path: PathBuf,
    /// Emit the compacted aggregate (structural columns + trace count) instead of
    /// the full per-row table.
    pub compact: bool,
}

/// Resolve every observation's two sites and write the result table.
///
/// Observations are grouped by `(build_id, device)` — all sites for one build
/// resolve against the same artifacts, so each build is fetched and analyzed once,
/// largest group first. Output is rewritten after each build so partial results
/// are available immediately.
pub fn run(
    mut rows: Vec<Contention>,
    provider: &dyn ArtifactProvider,
    resolver: &Resolver,
    headers: &[String],
    out: &Output,
) -> Result<()> {
    // Group row indices by build/device, largest group first.
    let mut groups: HashMap<(String, String), Vec<usize>> = HashMap::new();
    for (i, r) in rows.iter().enumerate() {
        groups.entry(r.group_key()).or_default().push(i);
    }
    let mut order: Vec<((String, String), Vec<usize>)> = groups.into_iter().collect();
    order.sort_by_key(|(_, idxs)| std::cmp::Reverse(idxs.len()));
    log::info!("{} build/device group(s) over {} rows", order.len(), rows.len());

    for ((build_id, device), idxs) in order {
        // Distinct resolvable sites in this group.
        let mut sites: HashSet<String> = HashSet::new();
        for &i in &idxs {
            for s in [&rows[i].blocked_src, &rows[i].blocking_src] {
                if site::is_resolvable(s) {
                    sites.insert(s.clone());
                }
            }
        }
        if sites.is_empty() {
            continue;
        }

        let dir = match provider.artifacts(&build_id, &device) {
            Ok(d) => d,
            Err(e) => {
                log::error!("artifacts for {build_id}/{device}: {e:#}");
                continue;
            }
        };
        let index = match resolver.index_for(&build_id, &dir) {
            Ok(i) => i,
            Err(e) => {
                log::error!("indexing {build_id}: {e:#}");
                continue;
            }
        };

        let site_vec: Vec<String> = sites.into_iter().collect();
        let resolved = resolver.resolve(&index, &site_vec);
        let lookup = |s: &str| resolved.get(s).cloned().unwrap_or_else(|| "N/A".to_string());
        for &i in &idxs {
            rows[i].resolved_blocked_lock = lookup(&rows[i].blocked_src);
            rows[i].resolved_blocking_lock = lookup(&rows[i].blocking_src);
        }

        csv_io::save(&out.path, headers, &rows, out.compact)?;
        log::info!(
            "resolved {build_id}/{device} ({} sites); wrote {}",
            site_vec.len(),
            out.path.display()
        );
    }

    // Ensure output exists even if no group resolved.
    csv_io::save(&out.path, headers, &rows, out.compact)?;
    Ok(())
}
