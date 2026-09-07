//! Where contention observations come from.
//!
//! The pipeline only needs a `Vec<Contention>`; how that batch is obtained is a
//! pluggable seam. Two portable sources ship here: read from a CSV file, and a
//! synthetic mock for tests. Wire in an environment-specific source (a query
//! against a trace store, an HTTP endpoint, ...) by implementing [`TraceSource`].

use crate::csv_io;
use crate::model::{Contention, Query};
use anyhow::Result;
use std::path::PathBuf;

/// A batch provider of monitor-contention observations.
pub trait TraceSource {
    /// Return the observations selected by `query`.
    fn fetch(&self, query: &Query) -> Result<Vec<Contention>>;
}

/// Reads contention rows from a CSV file (see [`crate::csv_io`] for the expected
/// columns). The most portable source: whatever produces the table upstream, this
/// consumes it.
pub struct CsvTraceSource {
    pub path: PathBuf,
}

impl TraceSource for CsvTraceSource {
    fn fetch(&self, query: &Query) -> Result<Vec<Contention>> {
        let mut rows = csv_io::load(&self.path)?.rows;
        if let Some(b) = &query.build_id {
            rows.retain(|r| &r.build_id == b);
        }
        if let Some(d) = &query.device {
            rows.retain(|r| &r.device == d);
        }
        if query.limit > 0 && rows.len() > query.limit {
            rows.truncate(query.limit);
        }
        Ok(rows)
    }
}

/// A synthetic source for tests and demos — deterministic, no I/O.
pub struct MockTraceSource {
    pub rows: Vec<Contention>,
}

impl MockTraceSource {
    /// Build `n` observations for one build, alternating two source sites so the
    /// grouping and resolution paths are exercised without any external system.
    pub fn synthetic(build_id: &str, device: &str, sites: &[(&str, &str)], n: usize) -> Self {
        let rows = (0..n)
            .map(|i| {
                let (a, b) = sites[i % sites.len().max(1)];
                Contention {
                    build_id: build_id.to_string(),
                    device: device.to_string(),
                    blocked_src: a.to_string(),
                    blocking_src: b.to_string(),
                    short_blocked_method: "blocked".to_string(),
                    short_blocking_method: "blocking".to_string(),
                    raw: vec![
                        build_id.to_string(),
                        device.to_string(),
                        a.to_string(),
                        b.to_string(),
                    ],
                    resolved_blocked_lock: "N/A".to_string(),
                    resolved_blocking_lock: "N/A".to_string(),
                }
            })
            .collect();
        MockTraceSource { rows }
    }
}

impl TraceSource for MockTraceSource {
    fn fetch(&self, _query: &Query) -> Result<Vec<Contention>> {
        Ok(self.rows.clone())
    }
}
