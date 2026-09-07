//! dexlock CLI: resolve a contention table's source sites to canonical locks.
//!
//! Portable by default — it reads a CSV and resolves against local artifacts, with
//! no dependency on any particular build or trace infrastructure. Point it at a
//! directory of jars/apks (or per-build subdirectories), or supply your own
//! artifact/trace providers via the library API.

use anyhow::Result;
use clap::Parser;
use dexlock::artifact::{ArtifactProvider, DirArtifactProvider, ZipArtifactProvider};
use dexlock::model::Query;
use dexlock::pipeline::{self, Output};
use dexlock::resolver::{Options, Resolver};
use dexlock::traces::{CsvTraceSource, TraceSource};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "dexlock", about = "Resolve monitor-contention sites to their canonical locks")]
struct Args {
    /// Input contention CSV (columns: build_id, device_name, blocked_src,
    /// blocking_src, short_blocked_method, short_blocking_method, ...).
    #[arg(long)]
    input: PathBuf,

    /// Directory of DEX artifacts. Either a flat directory of jars/apks, or a
    /// parent with a `<build_id>/` subdirectory per build. With `--zip`, instead a
    /// directory of `<build_id>.zip` archives, unpacked in-process.
    #[arg(long)]
    artifacts: PathBuf,

    /// Treat `--artifacts` as a directory of `<build_id>.zip` archives.
    #[arg(long)]
    zip: bool,

    /// Output CSV path.
    #[arg(long, default_value = "dexlock_out.csv")]
    output: PathBuf,

    /// Where per-build indexes are cached (so re-runs skip re-analysis).
    #[arg(long, default_value = "cache")]
    cache_dir: PathBuf,

    /// Narrow analysis to jars whose name contains this substring.
    #[arg(long)]
    scope: Option<String>,

    /// Tolerate line drift: snap to the nearest monitor-enter within N lines.
    #[arg(long, default_value_t = 0)]
    fuzz: u32,

    /// When a line can't be matched, return the file's sole lock if unambiguous.
    #[arg(long)]
    if_unique: bool,

    /// Emit the compacted aggregate (structural columns + trace count).
    #[arg(long)]
    compact_counts: bool,

    /// Path to `dexdump` (else `$LOCKDEX_DEXDUMP`, else `PATH`).
    #[arg(long)]
    dexdump: Option<PathBuf>,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();
    let args = Args::parse();

    if let Some(d) = &args.dexdump {
        std::env::set_var("LOCKDEX_DEXDUMP", d);
    }

    let rows = CsvTraceSource { path: args.input.clone() }.fetch(&Query::default())?;
    let table = dexlock::csv_io::load(&args.input)?; // headers for round-tripping columns
    log::info!("loaded {} rows from {}", rows.len(), args.input.display());

    let provider: Box<dyn ArtifactProvider> = if args.zip {
        Box::new(ZipArtifactProvider {
            root: args.artifacts.clone(),
            out_root: args.cache_dir.join("unpacked"),
        })
    } else {
        Box::new(DirArtifactProvider { root: args.artifacts.clone() })
    };

    let resolver = Resolver::new(
        args.cache_dir.clone(),
        args.scope.clone(),
        Options { fuzz: args.fuzz, if_unique: args.if_unique },
    );

    pipeline::run(
        rows,
        provider.as_ref(),
        &resolver,
        &table.headers,
        &Output { path: args.output.clone(), compact: args.compact_counts },
    )?;

    println!("Done. Wrote {}", args.output.display());
    Ok(())
}
