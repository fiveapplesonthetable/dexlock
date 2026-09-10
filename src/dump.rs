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
    /// A gzipped pprof profile of the lock graph (`method -> lock` edges).
    Pprof,
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
    // pprof is a self-contained gzipped protobuf — write it straight out.
    if let Format::Pprof = format {
        let bytes = crate::pprof::lock_graph(&acqs)?;
        std::fs::write(out, &bytes).with_context(|| format!("creating {}", out.display()))?;
        log::info!("wrote pprof lock graph ({n} edges) to {} ({:.2?} total)", out.display(), t0.elapsed());
        return Ok(n);
    }
    let file = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let w = BufWriter::new(file);
    // gzip when the output path ends in `.gz` (e.g. locks.pb.gz, locks.json.gz).
    if out.extension().is_some_and(|e| e == "gz") {
        let mut gz = flate2::write::GzEncoder::new(w, flate2::Compression::default());
        match format {
            Format::Json => write_json(&mut gz, &acqs)?,
            Format::Proto => write_proto(&mut gz, &acqs)?,
            Format::Pprof => unreachable!(),
        }
        gz.finish()?;
    } else {
        let mut w = w;
        match format {
            Format::Json => write_json(&mut w, &acqs)?,
            Format::Proto => write_proto(&mut w, &acqs)?,
            Format::Pprof => unreachable!(),
        }
        w.flush()?;
    }
    log::info!(
        "wrote {n} lock points to {} ({:.2?} total)",
        out.display(),
        t0.elapsed()
    );
    Ok(n)
}

/// Stream a JSON array of `{class, method, file, line, lock}` without a second copy.
/// `file`+`line` are the `File.java:line` a monitor-contention record names.
fn write_json(w: &mut impl Write, acqs: &[dex::Acquisition]) -> Result<()> {
    #[derive(serde::Serialize)]
    struct Row<'a> {
        class: &'a str,
        method: &'a str,
        file: Option<&'a str>,
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
            file: a.source_file.as_deref(),
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
    pool.intern(""); // id 0 = "" so an absent file/name is a stable sentinel
    let mut class_id = Vec::with_capacity(acqs.len());
    let mut method_id = Vec::with_capacity(acqs.len());
    let mut file_id = Vec::with_capacity(acqs.len());
    let mut lock_id = Vec::with_capacity(acqs.len());
    let mut line = Vec::with_capacity(acqs.len());
    for a in acqs {
        class_id.push(pool.intern(&a.class));
        method_id.push(pool.intern(&a.method));
        file_id.push(pool.intern(a.source_file.as_deref().unwrap_or("")));
        lock_id.push(pool.intern(&a.lock));
        line.push(a.line.unwrap_or(0));
    }
    let bytes = crate::proto::encode_lock_points(&pool.strings, &class_id, &method_id, &file_id, &lock_id, &line);
    w.write_all(&bytes)?;
    Ok(())
}
