//! CSV load/save. Input is a contention table with (at least) the columns
//! `build_id`, `device_name`, `blocked_src`, `blocking_src`,
//! `short_blocked_method`, `short_blocking_method`. Output is the same table with
//! `resolved_blocked_lock` / `resolved_blocking_lock` filled in, or a compacted
//! aggregate keyed by the structural columns.

use crate::model::Contention;
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::path::Path;

/// The header of a loaded contention table, kept so output can round-trip columns.
pub struct Table {
    pub headers: Vec<String>,
    pub rows: Vec<Contention>,
}

fn col(headers: &csv::StringRecord, name: &str) -> Result<usize> {
    headers
        .iter()
        .position(|h| h == name)
        .ok_or_else(|| anyhow!("missing column '{name}' in CSV"))
}

/// Load a contention table from a CSV file.
pub fn load(path: &Path) -> Result<Table> {
    let mut rdr = csv::Reader::from_path(path)
        .with_context(|| format!("opening CSV {}", path.display()))?;
    let headers = rdr.headers()?.clone();

    let build = col(&headers, "build_id")?;
    let device = col(&headers, "device_name")?;
    let blocked = col(&headers, "blocked_src")?;
    let blocking = col(&headers, "blocking_src")?;
    let sbm = col(&headers, "short_blocked_method")?;
    let sbgm = col(&headers, "short_blocking_method")?;

    let get = |r: &csv::StringRecord, i: usize| r.get(i).unwrap_or("").trim().to_string();

    let mut rows = Vec::new();
    for rec in rdr.records() {
        let rec = rec?;
        rows.push(Contention {
            build_id: get(&rec, build),
            device: get(&rec, device),
            blocked_src: get(&rec, blocked),
            blocking_src: get(&rec, blocking),
            short_blocked_method: get(&rec, sbm),
            short_blocking_method: get(&rec, sbgm),
            raw: rec.iter().map(|s| s.to_string()).collect(),
            resolved_blocked_lock: "N/A".to_string(),
            resolved_blocking_lock: "N/A".to_string(),
        });
    }

    Ok(Table {
        headers: headers.iter().map(|s| s.to_string()).collect(),
        rows,
    })
}

/// Write the resolved table. With `compact`, emit an aggregate keyed by the four
/// structural columns with a trace count, sorted by count descending; otherwise
/// emit every row with the two resolved-lock columns appended (or overwritten).
pub fn save(path: &Path, headers: &[String], rows: &[Contention], compact: bool) -> Result<()> {
    let mut w = csv::Writer::from_path(path)
        .with_context(|| format!("creating CSV {}", path.display()))?;

    if compact {
        let mut counts: HashMap<(&str, &str, &str, &str), usize> = HashMap::new();
        for r in rows {
            *counts
                .entry((
                    &r.resolved_blocked_lock,
                    &r.resolved_blocking_lock,
                    &r.short_blocked_method,
                    &r.short_blocking_method,
                ))
                .or_default() += 1;
        }
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by_key(|&(_, n)| std::cmp::Reverse(n));

        w.write_record([
            "resolved_blocked_lock",
            "resolved_blocking_lock",
            "short_blocked_method",
            "short_blocking_method",
            "traces",
        ])?;
        for ((rb, rk, sb, sk), n) in sorted {
            w.write_record([rb, rk, sb, sk, &n.to_string()])?;
        }
    } else {
        // Append the resolved columns if absent; otherwise overwrite them in place.
        let mut out_headers = headers.to_vec();
        let bi = index_or_push(&mut out_headers, "resolved_blocked_lock");
        let ki = index_or_push(&mut out_headers, "resolved_blocking_lock");
        w.write_record(&out_headers)?;

        for r in rows {
            let mut fields = r.raw.clone();
            if fields.len() < out_headers.len() {
                fields.resize(out_headers.len(), String::new());
            }
            fields[bi] = r.resolved_blocked_lock.clone();
            fields[ki] = r.resolved_blocking_lock.clone();
            w.write_record(&fields)?;
        }
    }

    w.flush()?;
    Ok(())
}

fn index_or_push(headers: &mut Vec<String>, name: &str) -> usize {
    match headers.iter().position(|h| h == name) {
        Some(i) => i,
        None => {
            headers.push(name.to_string());
            headers.len() - 1
        }
    }
}
