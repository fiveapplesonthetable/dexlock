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
    let w = BufWriter::new(file);
    // gzip when the output path ends in `.gz` (e.g. locks.pb.gz, locks.json.gz).
    if out.extension().is_some_and(|e| e == "gz") {
        let mut gz = flate2::write::GzEncoder::new(w, flate2::Compression::default());
        match format {
            Format::Json => write_json(&mut gz, &acqs)?,
            Format::Proto => write_proto(&mut gz, &acqs)?,
        }
        gz.finish()?;
    } else {
        let mut w = w;
        match format {
            Format::Json => write_json(&mut w, &acqs)?,
            Format::Proto => write_proto(&mut w, &acqs)?,
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

/// `dexlock binder`: analyze `inputs` and write every binder call made while a lock
/// is held, as a JSON array. Returns the count.
pub fn run_binder(inputs: &[PathBuf], scope: Option<&str>, closed_world: bool, out: &Path) -> Result<usize> {
    let t0 = Instant::now();
    let dex = input::parse_inputs(inputs, scope).context("parsing dex inputs")?;
    log::info!("parsed {} classes in {:.2?}", dex.classes.len(), t0.elapsed());

    let t1 = Instant::now();
    let findings = dex::binder::binder_under_lock(&dex, closed_world);
    log::info!("found {} binder-under-lock sites in {:.2?}", findings.len(), t1.elapsed());

    #[derive(serde::Serialize)]
    struct Row<'a> {
        method: &'a str,
        file: Option<&'a str>,
        line: Option<u32>,
        held: &'a [String],
        callee: &'a str,
    }
    let n = findings.len();
    let file = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let mut w = BufWriter::new(file);
    w.write_all(b"[")?;
    for (i, f) in findings.iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        let row = Row {
            method: &f.method,
            file: f.file.as_deref(),
            line: f.line,
            held: &f.held,
            callee: &f.callee,
        };
        serde_json::to_writer(&mut w, &row)?;
    }
    w.write_all(b"]")?;
    w.flush()?;
    log::info!("wrote {n} findings to {} ({:.2?} total)", out.display(), t0.elapsed());
    Ok(n)
}

/// `dexlock race`: analyze `inputs` and write every field whose locking discipline
/// is inconsistent, as a JSON array. Returns the count.
pub fn run_race(inputs: &[PathBuf], scope: Option<&str>, opts: &dex::race::Options, out: &Path) -> Result<usize> {
    let t0 = Instant::now();
    let dex = input::parse_inputs(inputs, scope).context("parsing dex inputs")?;
    log::info!("parsed {} classes in {:.2?}", dex.classes.len(), t0.elapsed());

    let t1 = Instant::now();
    let findings = dex::race::races(&dex, opts);
    log::info!("found {} inconsistently locked fields in {:.2?}", findings.len(), t1.elapsed());

    #[derive(serde::Serialize)]
    struct Acc<'a> {
        method: &'a str,
        file: Option<&'a str>,
        line: Option<u32>,
        write: bool,
        held: &'a [String],
        concurrent: bool,
    }
    #[derive(serde::Serialize)]
    struct Row<'a> {
        field: &'a str,
        guard: &'a str,
        guarded: usize,
        total: usize,
        guarded_at: Vec<Acc<'a>>,
        unguarded: Vec<Acc<'a>>,
    }
    fn acc(a: &dex::race::Access) -> Acc<'_> {
        Acc {
            method: &a.method,
            file: a.file.as_deref(),
            line: a.line,
            write: a.write,
            held: &a.held,
            concurrent: a.concurrent,
        }
    }
    let n = findings.len();
    let file = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let mut w = BufWriter::new(file);
    w.write_all(b"[")?;
    for (i, f) in findings.iter().enumerate() {
        if i > 0 {
            w.write_all(b",")?;
        }
        let row = Row {
            field: &f.field,
            guard: &f.guard,
            guarded: f.guarded,
            total: f.total,
            // The discipline is corroborated by every guarded access; a handful is
            // enough evidence to read, and the counts above carry the rest.
            guarded_at: f.guarded_at.iter().take(5).map(acc).collect(),
            unguarded: f.unguarded.iter().map(acc).collect(),
        };
        serde_json::to_writer(&mut w, &row)?;
    }
    w.write_all(b"]")?;
    w.flush()?;
    log::info!("wrote {n} findings to {} ({:.2?} total)", out.display(), t0.elapsed());
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
