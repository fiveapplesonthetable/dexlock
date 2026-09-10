//! `dexlock dump`: analyze DEX artifacts and emit EVERY resolved lock point — each
//! monitor-enter named by its canonical lock definition — in a compact form.
//!
//! This is the whole DEX analysis (`crate::dex::acquisitions`) run once over the
//! merged inputs, then serialized. Output is either JSON (one object per lock
//! point, for humans and quick greps) or a protobuf `LockPoints` message (see
//! `dexlock.proto`): a deduplicated string pool plus packed-uint32 columns, which
//! interns every repeated class / method / lock name once. Rows are sorted, so the
//! output is deterministic across runs and threads.

use crate::dex::{self, input};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Serialization format for the dump.
#[derive(Clone, Copy, Debug)]
pub enum Format {
    Json,
    Proto,
}

/// Interns strings to dense ids, preserving first-seen order for a stable pool.
#[derive(Default)]
struct Pool {
    ids: HashMap<String, u32>,
    strings: Vec<String>,
}

impl Pool {
    fn intern(&mut self, s: &str) -> u32 {
        if let Some(&i) = self.ids.get(s) {
            return i;
        }
        let i = self.strings.len() as u32;
        self.strings.push(s.to_string());
        self.ids.insert(s.to_string(), i);
        i
    }
}

/// Analyze `inputs` (jars/apks/dex files/dirs, merged so the resolver sees calls
/// across all of them) and write every lock point to `out`. Returns the count.
pub fn run(inputs: &[PathBuf], scope: Option<&str>, format: Format, out: &Path) -> Result<usize> {
    let t0 = Instant::now();
    let dex = input::parse_inputs(inputs, scope).context("parsing dex inputs")?;
    log::info!(
        "parsed {} classes from {} input(s) in {:.2?}",
        dex.classes.len(),
        inputs.len(),
        t0.elapsed()
    );

    let t1 = Instant::now();
    let mut acqs = dex::acquisitions(&dex);
    log::info!(
        "resolved {} lock points in {:.2?}",
        acqs.len(),
        t1.elapsed()
    );

    // Deterministic output regardless of thread scheduling / hash order.
    acqs.sort_unstable_by(|a, b| {
        (&a.class, &a.method, a.line, &a.lock).cmp(&(&b.class, &b.method, b.line, &b.lock))
    });

    let n = acqs.len();
    let file = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let mut w = BufWriter::new(file);
    match format {
        Format::Json => write_json(&mut w, &acqs)?,
        Format::Proto => write_proto(&mut w, &acqs)?,
    }
    w.flush()?;
    log::info!(
        "wrote {n} lock points to {} ({:.2?} total)",
        out.display(),
        t0.elapsed()
    );
    Ok(n)
}

/// Stream a JSON array of `{class, method, line, lock}` without a second copy.
fn write_json(w: &mut impl Write, acqs: &[dex::Acquisition]) -> Result<()> {
    #[derive(serde::Serialize)]
    struct Row<'a> {
        class: &'a str,
        method: &'a str,
        line: Option<u32>,
        lock: &'a str,
    }
    w.write_all(b"[")?;
    for (i, a) in acqs.iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        let row = Row {
            class: &a.class,
            method: &a.method,
            line: a.line,
            lock: &a.lock,
        };
        serde_json::to_writer(&mut *w, &row)?;
    }
    w.write_all(b"]")?;
    Ok(())
}

/// Intern all names into a pool and emit the columnar `LockPoints` protobuf.
fn write_proto(w: &mut impl Write, acqs: &[dex::Acquisition]) -> Result<()> {
    let mut pool = Pool::default();
    let mut class_id = Vec::with_capacity(acqs.len());
    let mut method_id = Vec::with_capacity(acqs.len());
    let mut lock_id = Vec::with_capacity(acqs.len());
    let mut line = Vec::with_capacity(acqs.len());
    for a in acqs {
        class_id.push(pool.intern(&a.class));
        method_id.push(pool.intern(&a.method));
        lock_id.push(pool.intern(&a.lock));
        line.push(a.line.unwrap_or(0));
    }
    let bytes =
        crate::proto::encode_lock_points(&pool.strings, &class_id, &method_id, &lock_id, &line);
    w.write_all(&bytes)?;
    Ok(())
}
