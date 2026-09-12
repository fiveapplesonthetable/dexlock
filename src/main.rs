//! dexlock CLI.
//!
//! Two subcommands:
//!   * `resolve` — the portable path: read a contention CSV and resolve each source
//!     site to its canonical lock against local artifacts.
//!   * `dump` — analyze jars directly and emit *every* lock point, each resolved to
//!     its canonical definition, as JSON or a compact columnar protobuf.
//!
//! `-j/--threads` bounds the worker pool for either subcommand (default: all cores).

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use dexlock::artifact::{ArtifactProvider, DirArtifactProvider, ZipArtifactProvider};
use dexlock::dump::{self, Format};
use dexlock::model::Query;
use dexlock::pipeline::{self, Output};
use dexlock::resolver::{Options, Resolver};
use dexlock::traces::{CsvTraceSource, TraceSource};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "dexlock", about = "Resolve monitor locks from DEX bytecode", version)]
struct Cli {
    /// Worker threads for parsing and analysis (default: all available cores).
    #[arg(short = 'j', long, global = true)]
    threads: Option<usize>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Resolve a contention CSV's source sites to their canonical locks.
    Resolve(ResolveArgs),
    /// Dump every lock point in the given jars, each resolved to its definition.
    Dump(DumpArgs),
    /// Flag binder calls made while holding a lock (a system_server ANR hazard).
    Binder(BinderArgs),
}

#[derive(Parser, Debug)]
struct ResolveArgs {
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

    /// Use the `dexdump` back-end instead of the native reader (path to dexdump;
    /// else `$DEXLOCK_DEXDUMP`, else `PATH`).
    #[arg(long)]
    dexdump: Option<PathBuf>,
}

#[derive(Parser, Debug)]
struct DumpArgs {
    /// Jars / apks / `.dex` files / directories to analyze. Multiple inputs are
    /// merged so the resolver sees calls across all of them.
    #[arg(required = true)]
    inputs: Vec<PathBuf>,

    /// Narrow a directory input to jars whose name contains this substring.
    #[arg(long)]
    scope: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Fmt::Proto)]
    format: Fmt,

    /// Output path.
    #[arg(long, short = 'o', default_value = "dexlock_locks.pb")]
    output: PathBuf,

    /// Use the `dexdump` back-end instead of the native reader (path to dexdump;
    /// else `$DEXLOCK_DEXDUMP`, else `PATH`).
    #[arg(long)]
    dexdump: Option<PathBuf>,
}

#[derive(Parser, Debug)]
struct BinderArgs {
    /// Jars / apks / `.dex` files / directories to analyze. Multiple inputs are
    /// merged so binder-interface types resolve across all of them.
    #[arg(required = true)]
    inputs: Vec<PathBuf>,

    /// Narrow a directory input to jars whose name contains this substring.
    #[arg(long)]
    scope: Option<String>,

    /// Output path (JSON array).
    #[arg(long, short = 'o', default_value = "dexlock_binder.json")]
    output: PathBuf,

    /// Use the `dexdump` back-end instead of the native reader (path to dexdump;
    /// else `$DEXLOCK_DEXDUMP`, else `PATH`).
    #[arg(long)]
    dexdump: Option<PathBuf>,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
enum Fmt {
    Json,
    Proto,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();
    let cli = Cli::parse();

    if let Some(j) = cli.threads {
        match rayon::ThreadPoolBuilder::new().num_threads(j).build_global() {
            Ok(()) => log::info!("using {j} worker threads"),
            Err(e) => log::warn!("could not set thread pool to {j}: {e}"),
        }
    }

    match cli.cmd {
        Cmd::Resolve(a) => run_resolve(a),
        Cmd::Dump(a) => run_dump(a),
        Cmd::Binder(a) => run_binder(a),
    }
}

fn run_resolve(args: ResolveArgs) -> Result<()> {
    if let Some(d) = &args.dexdump {
        // Passing --dexdump selects the dexdump back-end (and points at the binary).
        std::env::set_var("DEXLOCK_DEXDUMP", d);
        std::env::set_var("DEXLOCK_USE_DEXDUMP", "1");
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

fn run_dump(args: DumpArgs) -> Result<()> {
    if let Some(d) = &args.dexdump {
        // Passing --dexdump selects the dexdump back-end (and points at the binary).
        std::env::set_var("DEXLOCK_DEXDUMP", d);
        std::env::set_var("DEXLOCK_USE_DEXDUMP", "1");
    }
    let format = match args.format {
        Fmt::Json => Format::Json,
        Fmt::Proto => Format::Proto,
    };
    let n = dump::run(&args.inputs, args.scope.as_deref(), format, &args.output)?;
    println!("Wrote {n} lock points to {}", args.output.display());
    Ok(())
}

fn run_binder(args: BinderArgs) -> Result<()> {
    if let Some(d) = &args.dexdump {
        // Passing --dexdump selects the dexdump back-end (and points at the binary).
        std::env::set_var("DEXLOCK_DEXDUMP", d);
        std::env::set_var("DEXLOCK_USE_DEXDUMP", "1");
    }
    let n = dump::run_binder(&args.inputs, args.scope.as_deref(), &args.output)?;
    println!("Wrote {n} binder-under-lock findings to {}", args.output.display());
    Ok(())
}
