//! `dexlock ctx`: build the lock-context index from DEX artifacts, persist it, and
//! answer queries against it — for a source line, a method, or a lock: which locks
//! may be held there, by what call path, and how locks order against each other.

use crate::dex::ctx::{self, Hop, Index, OrderEdge, Options};
use crate::dex::input;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Analyze `inputs`, build the index, and write it to `out` (gzipped when the
/// path ends in `.gz`). Returns the index for immediate querying.
pub fn build(inputs: &[PathBuf], scope: Option<&str>, opts: &Options, out: &Path) -> Result<Index> {
    let t0 = Instant::now();
    let dex = input::parse_inputs(inputs, scope).context("parsing dex inputs")?;
    log::info!("parsed {} classes in {:.2?}", dex.classes.len(), t0.elapsed());
    let t1 = Instant::now();
    let idx = ctx::build(&dex, opts);
    log::info!(
        "indexed {} methods, {} locks, {} calls, {} order edges in {:.2?}",
        idx.methods.len(),
        idx.locks.len(),
        idx.calls.len(),
        idx.order.len(),
        t1.elapsed()
    );
    let file = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let w = BufWriter::new(file);
    if out.extension().is_some_and(|e| e == "gz") {
        let mut gz = flate2::write::GzEncoder::new(w, flate2::Compression::default());
        idx.write(&mut gz)?;
        gz.finish()?;
    } else {
        idx.write(w)?;
    }
    log::info!("wrote {} ({:.2?} total)", out.display(), t0.elapsed());
    Ok(idx)
}

/// Load an index written by [`build`].
pub fn load(path: &Path) -> Result<Index> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let r = BufReader::new(file);
    if path.extension().is_some_and(|e| e == "gz") {
        Index::read(flate2::read::GzDecoder::new(r))
    } else {
        Index::read(r)
    }
}

pub enum Query {
    /// A source position: `File.java:line`.
    At { file: String, line: u32 },
    /// Methods whose key contains the string.
    Method(String),
    /// Locks whose name contains the string.
    Lock(String),
    /// Lock-order cycles (deadlock candidates).
    Cycles,
    /// Binder calls made while a lock is (or may be) held.
    Binder,
}

/// Answer `q` against `idx`, writing a human-readable report to `w`. Locks held
/// more than `depth` call frames away are omitted.
pub fn query(idx: &Index, q: &Query, depth: u8, w: &mut impl Write) -> Result<()> {
    match q {
        Query::At { file, line } => {
            let ms = idx.locate(file, *line);
            if ms.is_empty() {
                writeln!(w, "no method covers {file}:{line}")?;
            }
            for m in ms {
                report_point(idx, m, *line, depth, w)?;
            }
        }
        Query::Method(needle) => {
            let ms = idx.find_methods(needle);
            if ms.is_empty() {
                writeln!(w, "no method matches {needle:?}")?;
            }
            for m in ms.iter().take(20) {
                let r = &idx.methods[*m as usize];
                report_point(idx, *m, r.line_lo, depth, w)?;
            }
            if ms.len() > 20 {
                writeln!(w, "... {} more matches; narrow the query", ms.len() - 20)?;
            }
        }
        Query::Lock(needle) => {
            let ls = idx.find_locks(needle);
            if ls.is_empty() {
                writeln!(w, "no lock matches {needle:?}")?;
            }
            for l in ls.iter().take(10) {
                report_lock(idx, *l, depth, w)?;
            }
            if ls.len() > 10 {
                writeln!(w, "... {} more matches; narrow the query", ls.len() - 10)?;
            }
        }
        Query::Cycles => {
            let inv = idx.inversions();
            let ungated = inv.iter().filter(|(_, _, g)| g.is_none()).count();
            writeln!(
                w,
                "{} lock pair(s) acquired in both orders: {ungated} with no common outer lock, {} gated (both orders taken under one lock)",
                inv.len(),
                inv.len() - ungated
            )?;
            for (a, b, _) in inv.iter().filter(|(_, _, g)| g.is_none()).take(40) {
                writeln!(w, "\n  {}  <->  {}", idx.locks[a.from as usize], idx.locks[a.to as usize])?;
                for e in [a, b] {
                    writeln!(
                        w,
                        "    {} -> {}   ({}x, d={}, e.g. {} in {})",
                        short(&idx.locks[e.from as usize]),
                        short(&idx.locks[e.to as usize]),
                        e.count,
                        e.dist,
                        loc(idx, e.method, e.line),
                        idx.methods[e.method as usize].key
                    )?;
                }
            }
            if ungated > 40 {
                writeln!(w, "\n  ... {} more ungated", ungated - 40)?;
            }
            if inv.len() > ungated {
                writeln!(w, "\ngated (both orders occur under a common outer lock, so they serialize):")?;
                for (a, b, gate) in inv.iter().filter(|(_, _, g)| g.is_some()).take(30) {
                    writeln!(
                        w,
                        "  {}  <->  {}   under {}   ({}x / {}x)",
                        short(&idx.locks[a.from as usize]),
                        short(&idx.locks[a.to as usize]),
                        short(&idx.locks[gate.expect("gated") as usize]),
                        a.count,
                        b.count
                    )?;
                }
                if inv.len() - ungated > 30 {
                    writeln!(w, "  ... {} more gated", inv.len() - ungated - 30)?;
                }
            }
            let cyc = idx.cycles();
            writeln!(w, "\n{} strongly connected group(s) in the lock-order graph:", cyc.len())?;
            for (i, c) in cyc.iter().enumerate() {
                let names: Vec<&str> = c.iter().take(6).map(|&l| short(&idx.locks[l as usize])).collect();
                let more = if c.len() > 6 { format!(", +{} more", c.len() - 6) } else { String::new() };
                writeln!(w, "  [{}] {} locks: {}{}", i + 1, c.len(), names.join(", "), more)?;
            }
        }
        Query::Binder => {
            let sites = idx.binder_sites(depth);
            writeln!(w, "{} binder call(s) with a lock held within {depth} frame(s) (nearest first):", sites.len())?;
            let mut last_d = u8::MAX;
            for (k, t, l, d) in sites.iter().take(300) {
                let c = &idx.calls[*k as usize];
                if *d != last_d {
                    writeln!(w, "\n-- d={d} --")?;
                    last_d = *d;
                }
                writeln!(
                    w,
                    "  {}  {}  ->  {}   holding {}",
                    loc(idx, c.caller, c.line),
                    idx.methods[c.caller as usize].key,
                    idx.methods[*t as usize].key,
                    idx.locks[*l as usize]
                )?;
                if *d > 0 {
                    if let Some(path) = idx.witness(c.caller, *l) {
                        write_path(idx, &path, w)?;
                    }
                }
            }
            if sites.len() > 300 {
                writeln!(w, "\n  ... {} more; lower --depth to narrow", sites.len() - 300)?;
            }
        }
    }
    Ok(())
}

/// A lock name without its package, for dense listings.
fn short(name: &str) -> &str {
    let cut = name.rfind('.').map(|i| name[..i].rfind('.').map(|j| j + 1).unwrap_or(0)).unwrap_or(0);
    &name[cut..]
}

fn loc(idx: &Index, m: u32, line: u32) -> String {
    let f = &idx.files[idx.methods[m as usize].file as usize];
    if f.is_empty() { format!(":{line}") } else { format!("{f}:{line}") }
}

fn report_point(idx: &Index, m: u32, line: u32, depth: u8, w: &mut impl Write) -> Result<()> {
    let r = &idx.methods[m as usize];
    writeln!(w, "{}  in  {}", loc(idx, m, line), r.key)?;
    let intra = idx.intra_held(m, line);
    if intra.is_empty() {
        writeln!(w, "  held by this method here: (none)")?;
    } else {
        writeln!(w, "  held by this method here:")?;
        for l in intra {
            let at = r.spans.iter().filter(|s| s.lock == l && s.enter <= line && line < s.exit).map(|s| s.enter).next();
            writeln!(w, "    {}   (acquired at {})", idx.locks[l as usize], at.map(|a| loc(idx, m, a)).unwrap_or_default())?;
        }
    }
    let may = idx.may_held(m);
    let shown = may.iter().filter(|&&(_, d)| d <= depth).count();
    if may.is_empty() {
        writeln!(w, "  may be held on entry (from callers): (none)")?;
    } else {
        writeln!(w, "  may be held on entry (from callers): {shown} within {depth} frame(s), {} total", may.len())?;
        for (l, d) in may {
            if d > depth {
                break;
            }
            writeln!(w, "    [d={d}] {}", idx.locks[l as usize])?;
            if let Some(path) = idx.witness(m, l) {
                write_path(idx, &path, w)?;
            }
        }
    }
    writeln!(w)?;
    Ok(())
}

fn write_path(idx: &Index, path: &[Hop], w: &mut impl Write) -> Result<()> {
    for (i, h) in path.iter().enumerate() {
        let key = &idx.methods[h.method as usize].key;
        let mut note = Vec::new();
        if let Some(a) = h.acquire {
            note.push(format!("acquires at {}", loc(idx, h.method, a)));
        }
        if let Some(c) = h.call {
            note.push(format!("calls at {}", loc(idx, h.method, c)));
        }
        let arrow = if i == 0 { "      via " } else { "          -> " };
        if note.is_empty() {
            writeln!(w, "{arrow}{key}")?;
        } else {
            writeln!(w, "{arrow}{key}  ({})", note.join("; "))?;
        }
    }
    Ok(())
}

fn report_lock(idx: &Index, l: u32, depth: u8, w: &mut impl Write) -> Result<()> {
    writeln!(w, "{}", idx.locks[l as usize])?;
    let sites = idx.sites(l);
    writeln!(w, "  acquired at {} site(s):", sites.len())?;
    for (m, line) in sites.iter().take(15) {
        writeln!(w, "    {}  {}", loc(idx, *m, *line), idx.methods[*m as usize].key)?;
    }
    if sites.len() > 15 {
        writeln!(w, "    ... {} more", sites.len() - 15)?;
    }
    let holders = idx.holders(l);
    let near = holders.iter().filter(|&&(_, d)| d <= depth).count();
    writeln!(w, "  may be held on entry to {near} method(s) within {depth} frame(s), {} total", holders.len())?;
    for (m, d) in holders.iter().take(10) {
        writeln!(w, "    [d={d}] {}", idx.methods[*m as usize].key)?;
    }
    if holders.len() > 10 {
        writeln!(w, "    ... {} more", holders.len() - 10)?;
    }
    let mut outs = idx.order_out(l);
    outs.sort_by_key(|e| (e.dist, std::cmp::Reverse(e.count)));
    if !outs.is_empty() {
        writeln!(w, "  held while acquiring ({}):", outs.len())?;
        for e in outs.iter().take(15) {
            writeln!(w, "    -> {}   ({}x, d={}, e.g. {})", idx.locks[e.to as usize], e.count, e.dist, loc(idx, e.method, e.line))?;
        }
    }
    let mut ins = idx.order_in(l);
    ins.sort_by_key(|e| (e.dist, std::cmp::Reverse(e.count)));
    if !ins.is_empty() {
        writeln!(w, "  acquired while holding ({}):", ins.len())?;
        for e in ins.iter().take(15) {
            writeln!(w, "    <- {}   ({}x, d={}, e.g. {})", idx.locks[e.from as usize], e.count, e.dist, loc(idx, e.method, e.line))?;
        }
    }
    writeln!(w)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Machine-readable answers
// ---------------------------------------------------------------------------

fn method_json(idx: &Index, m: u32) -> Value {
    let r = &idx.methods[m as usize];
    json!({ "method": r.key, "file": idx.files[r.file as usize] })
}

fn path_json(idx: &Index, path: &[Hop]) -> Value {
    Value::Array(
        path.iter()
            .map(|h| json!({ "method": idx.methods[h.method as usize].key, "file": idx.files[idx.methods[h.method as usize].file as usize], "acquire": h.acquire, "call": h.call }))
            .collect(),
    )
}

fn edge_json(idx: &Index, e: &OrderEdge) -> Value {
    json!({
        "from": idx.locks[e.from as usize], "to": idx.locks[e.to as usize], "count": e.count, "dist": e.dist,
        "method": idx.methods[e.method as usize].key, "file": idx.files[idx.methods[e.method as usize].file as usize], "line": e.line
    })
}

fn point_json(idx: &Index, m: u32, line: u32, depth: u8) -> Value {
    let r = &idx.methods[m as usize];
    let held: Vec<Value> = idx
        .intra_held(m, line)
        .into_iter()
        .map(|l| {
            let at = r.spans.iter().filter(|s| s.lock == l && s.enter <= line && line < s.exit).map(|s| s.enter).next();
            json!({ "lock": idx.locks[l as usize], "acquired_at": at })
        })
        .collect();
    let may: Vec<Value> = idx
        .may_held(m)
        .into_iter()
        .filter(|&(_, d)| d <= depth)
        .map(|(l, d)| json!({ "lock": idx.locks[l as usize], "dist": d, "path": idx.witness(m, l).map(|p| path_json(idx, &p)) }))
        .collect();
    json!({ "method": r.key, "file": idx.files[r.file as usize], "line": line, "held": held, "may_held": may })
}

/// The same answer as [`query`], as JSON.
pub fn query_json(idx: &Index, q: &Query, depth: u8) -> Value {
    match q {
        Query::At { file, line } => Value::Array(idx.locate(file, *line).into_iter().map(|m| point_json(idx, m, *line, depth)).collect()),
        Query::Method(needle) => Value::Array(
            idx.find_methods(needle).into_iter().map(|m| point_json(idx, m, idx.methods[m as usize].line_lo, depth)).collect(),
        ),
        Query::Lock(needle) => Value::Array(
            idx.find_locks(needle)
                .into_iter()
                .map(|l| {
                    json!({
                        "lock": idx.locks[l as usize],
                        "sites": idx.sites(l).into_iter().map(|(m, line)| json!({ "method": idx.methods[m as usize].key, "file": idx.files[idx.methods[m as usize].file as usize], "line": line })).collect::<Vec<_>>(),
                        "holders": idx.holders(l).into_iter().filter(|&(_, d)| d <= depth).map(|(m, d)| json!({ "method": idx.methods[m as usize].key, "dist": d })).collect::<Vec<_>>(),
                        "held_while_acquiring": idx.order_out(l).into_iter().map(|e| edge_json(idx, e)).collect::<Vec<_>>(),
                        "acquired_while_holding": idx.order_in(l).into_iter().map(|e| edge_json(idx, e)).collect::<Vec<_>>(),
                    })
                })
                .collect(),
        ),
        Query::Cycles => json!({
            "inversions": idx.inversions().into_iter().map(|(a, b, g)| json!({ "a": edge_json(idx, a), "b": edge_json(idx, b), "gate": g.map(|g| idx.locks[g as usize].clone()) })).collect::<Vec<_>>(),
            "groups": idx.cycles().into_iter().map(|c| c.into_iter().map(|l| idx.locks[l as usize].clone()).collect::<Vec<_>>()).collect::<Vec<_>>(),
        }),
        Query::Binder => Value::Array(
            idx.binder_sites(depth)
                .into_iter()
                .map(|(k, t, l, d)| {
                    let c = &idx.calls[k as usize];
                    json!({
                        "caller": method_json(idx, c.caller), "line": c.line, "callee": idx.methods[t as usize].key,
                        "lock": idx.locks[l as usize], "dist": d,
                        "path": if d > 0 { idx.witness(c.caller, l).map(|p| path_json(idx, &p)) } else { None }
                    })
                })
                .collect(),
        ),
    }
}
