# dexlock

Resolve monitor-contention source sites to the canonical lock taken at each one,
by static analysis of DEX bytecode.

Input is a table of contention observations — each naming two `File.java:line`
sites (the thread that was blocked and the thread that held the lock) and the build
they came from. Output is the same table with two columns added: the canonical lock
for each site. dexlock groups observations by build, obtains that build's DEX
artifacts, analyzes them once with its in-process analyzer (`src/dex`), and answers
every site from an in-memory index. There is no subprocess per query and no external
service dependency; where artifacts and observations come from are pluggable
interfaces.

## What "resolving a site" means

A monitor-contention record tells you *where* a thread blocked (`Foo.java:1234`) but
not *which lock* it blocked on. Two different fields synchronized on nearby lines are
indistinguishable by source location, and the same lock is reached under many names
(`this`, `mLock`, `svc.getLock()`, an injected constructor argument, a field that
merely holds another object's lock). Resolution maps a site to one canonical lock
identity so that contention on the *same* lock through *different* code paths
aggregates together.

Example: a site sitting on `synchronized (mProcLock)` inside a class that received
its lock through a builder resolves to the single field that actually owns the lock
(`com.example.Service.mProcLock`), even though the lock reaches that site through a
builder field that was assigned the service's lock.

## How resolution works

Resolution is bytecode dataflow, not text matching or naming heuristics. The
analyzer in `src/dex` runs, per build:

1. **Decode.** Each `classes*.dex` is decoded into an instruction model:
   monitor-enter/exit, field loads/stores (`iget`/`iput`/`sget`), moves, invokes,
   allocations, returns, branches. This is a native in-process reader by default
   (`src/dex/native`, no subprocess; see [The DEX front-end](#the-dex-front-end));
   `--dexdump` / `$DEXLOCK_USE_DEXDUMP` switches to parsing `dexdump -d` text instead,
   which produces an identical model.

2. **Per-method abstract interpretation.** Each method is summarized by tracking an
   abstract *lock value* per register. When a `monitor-enter v` is seen, register `v`
   is traced back to its definition — `iget` (a field, including an outer class's
   `this$0` field), `sget` (a static), `move`/`move-result` (a local alias or a
   getter's return), `check-cast`, `new-instance` — yielding a structured identity
   rather than a register number.

3. **Lock identity = root + bounded access path.** A lock is a `Root` plus a list of
   field hops:
   - `Root ∈ { This, Param(i), Recv(class), Static(field), ClassConst, Alloc(site), Opaque }`.
   - `This`/`Param(i)` are *parametric* — valid only inside a method summary — and are
     substituted at call sites. `Recv`/`Static` are grounded, program-wide identities.
   - The access path is capped at a small length *k* (RacerD-style). A path that grows
     past *k* truncates to a distinct opaque, which bounds the analysis lattice and
     keeps two unrelated deep paths from colliding. Real `synchronized` operands are
     0–2 hops, so the cap costs no precision in practice.

4. **Interprocedural propagation as a monotone fixpoint.** Parametric roots are
   resolved across the call graph by parameter/copy propagation, solved as a Kleene
   least fixpoint over the meet-semilattice `Bottom < Val(lock) < Top`:
   - A formal parameter's value is the *meet* of the actual arguments bound at every
     observed call site. A conflict, or an argument that does not resolve to a single
     object, yields `Top` (unresolved) rather than a wrong merge.
   - `this.field = param` (in a constructor, a setter, or a `super(...)` call — all
     just call sites) makes the field an alias of that formal, resolved to the concrete
     object passed in. Constructor injection, setter injection, and inheritance
     threading fall out of the one algorithm with no special cases.
   - **Must-alias for allocations.** Once a freshly allocated object is stored into
     `this.field`, that register *is* `this.field`; it is renamed accordingly, so a
     later use of the same register (including the register an optimizer forwards
     straight into a setter instead of reloading with an `iget`) carries the field
     identity and grounds correctly.

5. **Canonicalization.** A field that holds a reference to another object's lock is
   followed to that object; the alias map is chased transitively so
   `A.mProcLock → Builder.mProcLock → Service.mProcLock` collapses to the root. A
   singleton object stored in exactly one field and locked via `synchronized(this)`
   internally is unified with `owner.field` externally.

The result is a real definition or nothing: a site whose lock genuinely escapes the
analysis (a per-call allocation, a collection element, an object from a call site not
present in the analyzed artifacts) is left unresolved rather than guessed.

## The index and the lookup

Resolving a site reads only the set of monitor-enter sites. The analyzer projects
its result to a `ResolveIndex`: one record per site,
`{ source_file, holder_method, line, canonical_lock }`. dexlock:

- **Caches** that projection to `cache/<build_id>.idx.json`. The expensive step
  (decode + fixpoint) runs once per build; a subsequent run loads the projection
  (milliseconds) and skips analysis entirely.
- **Buckets** sites by source-file basename, so a query scans one file's records
  rather than the whole program.
- **Answers** each query by: exact line match; else, with `--fuzz N`, the nearest
  monitor-enter within `N` lines (recovering from line drift between the trace's build
  and the analyzed build); else, with `--if-unique`, the file's sole lock when
  unambiguous. Per-site lookup is a hash-bucket probe.

Queries within a build are resolved in parallel. Because the lookup is a bucketed
map probe (constant work per site), a build with a handful of distinct sites and one
with millions cost about the same beyond the one-time analysis.

## Pipeline

```
observations (CSV)
      │  group by (build_id, device), largest group first
      ▼
for each build:
   ArtifactProvider.artifacts(build)     → directory of .jar/.apk
   Resolver.index_for(build)             → ResolveIndex   (disk-cached; analyze once)
   Resolver.resolve(index, sites)        → site → canonical lock   (parallel)
      │  write output after each build (progressive)
      ▼
resolved table (CSV), or a compacted aggregate keyed by the structural columns
```

## Pluggable interfaces

Everything environment-specific is behind a trait; the shipped implementations are
generic and depend on nothing but the filesystem.

- `TraceSource` — where observations come from. `CsvTraceSource` reads a table from a
  CSV file; `MockTraceSource` generates synthetic rows. Implement it to query your own
  trace store or endpoint.
- `ArtifactProvider` — where a build's jars/apks come from. `DirArtifactProvider` uses
  a directory already on disk (flat, or a `<build_id>/` subdirectory per build);
  `ZipArtifactProvider` unpacks `<build_id>.zip` in-process (parallel extraction, no
  `unzip` subprocess) and reuses already-unpacked builds; `MockArtifactProvider`
  returns a fixed directory. Implement it to download from your own build store.

## Integrating your environment

The two seams isolate everything specific to your setup. The core (grouping, index
build, disk cache, lookup, CSV I/O) needs no changes; you provide how observations
and artifacts are obtained.

**Artifact download seam.** Fetch a build's binaries however your infrastructure
exposes them, lay the DEX-bearing files (`.jar` / `.apk`) into a directory, and return
it. Cache by build so a build is fetched once.

```rust
use anyhow::Result;
use dexlock::artifact::ArtifactProvider;
use std::path::PathBuf;

struct MyDownloader { cache_root: PathBuf }

impl ArtifactProvider for MyDownloader {
    fn artifacts(&self, build_id: &str, device: &str) -> Result<PathBuf> {
        let dir = self.cache_root.join(build_id);
        if dir.is_dir() { return Ok(dir); }              // already fetched
        std::fs::create_dir_all(&dir)?;
        // 1. resolve build_id/device to a downloadable artifact via your API
        // 2. download it (parallelise for speed)
        // 3. unpack the .jar/.apk (and, if needed, any container archives) into `dir`
        //    — reuse dexlock's in-process unpacker or your own
        Ok(dir)
    }
}
```

`ArtifactProvider` requires `Sync` so builds can be processed without shared-state
hazards; keep the implementation stateless or use interior locking. The resolver only
needs the directory to contain jars/apks whose entries include `classes*.dex`.

**Trace/query seam.** Return the batch of observations from wherever they live — a
CSV export (shipped), a database query, an HTTP endpoint. Populate the six required
fields; the raw record is preserved for round-tripping other columns.

```rust
use anyhow::Result;
use dexlock::model::{Contention, Query};
use dexlock::traces::TraceSource;

struct MyTraceStore { /* client/handles */ }

impl TraceSource for MyTraceStore {
    fn fetch(&self, q: &Query) -> Result<Vec<Contention>> {
        // run your query (respect q.limit / q.last_days / q.build_id / q.device),
        // map each result row into a Contention { build_id, device, blocked_src,
        // blocking_src, short_blocked_method, short_blocking_method, raw, .. }
        Ok(vec![])
    }
}
```

Then drive the same pipeline with your implementations:

```rust
let rows = MyTraceStore { /* .. */ }.fetch(&Query { limit: 1000, last_days: 30, ..Default::default() })?;
let provider = MyDownloader { cache_root: "cache/artifacts".into() };
let resolver = Resolver::new("cache/index".into(), None, Options::default());
pipeline::run(rows, &provider, &resolver, &headers, &Output { path: "out.csv".into(), compact: false })?;
```

Nothing in the core assumes any particular build server, trace store, or artifact
format beyond "a directory of jars/apks" and "rows with the six fields." Swap the two
implementations and the resolver, cache, and lookup are unchanged.

## CLI

Two subcommands. `-j/--threads` bounds the worker pool for either (default: all cores).

### `resolve` — answer a contention CSV

```sh
dexlock resolve \
  --input contention.csv \
  --artifacts ./jars \        # dir of jars/apks, or a parent with <build_id>/ subdirs
  --output resolved.csv \
  --cache-dir ./cache         # per-build indexes cached here
# options: --zip (artifacts are <build_id>.zip), --fuzz N, --if-unique,
#          --compact-counts, --scope <substr>, --dexdump <path>
```

Input columns required: `build_id`, `device_name`, `blocked_src`, `blocking_src`,
`short_blocked_method`, `short_blocking_method`. Any other columns are preserved.
`--compact-counts` emits `(resolved_blocked_lock, resolved_blocking_lock,
short_blocked_method, short_blocking_method, traces)` sorted by count.

### `dump` — every lock point, resolved to its definition

Skip the CSV. Point `dump` at jars and it emits *every* monitor-enter in them, each
named by its canonical lock (the same analysis `resolve` uses, run once over the
merged inputs). Output is JSON or a compact columnar protobuf.

```sh
dexlock -j 16 dump services.jar framework.jar --format proto -o locks.pb
dexlock dump services.jar framework.jar --format json -o locks.json
# a directory or a Soong out tree also works; --scope <substr> narrows it
```

Each lock point is `(class, method, file, line, lock)` where `lock` is the canonical
definition (e.g. `com.android.server.am.ActivityManagerService.mProcLock`, or an
opaque `?@…` when the lock genuinely escapes the analysis). `file` + `line` are the
`File.java:line` a monitor-contention record names (what ART logs at a contention),
so a contention site resolves against the dump by a direct `(file, line)` lookup —
no re-analysis. Rows are sorted, so the output is byte-deterministic.

- **`--format json`** — a JSON array of `{class, method, file, line, lock}` objects.
- **`--format proto`** (default) — a `dexlock.LockPoints` message (see
  [`dexlock.proto`](dexlock.proto)): a deduplicated string pool plus packed-uint32
  columns (`class_id`, `method_id`, `file_id`, `lock_id`, `line`), so every repeated
  name — filenames included — is stored once. Inspect with
  `protoc --decode=dexlock.LockPoints dexlock.proto < locks.pb`.
- **Compressed output**: give the output an `.gz` suffix (`-o locks.pb.gz`,
  `locks.json.gz`) to gzip it.

**Inputs** are `.dex`, a zip-family archive (`.jar`/`.apk`/`.zip`/`.aar`), or a
directory — including a zip that nests more jars/apks. They are extracted natively in
memory (no `unzip` subprocess).

### The DEX front-end

Parsing is a native in-process reader by default — it decodes the DEX binary
straight into the model (handling the v41 container format), with no `dexdump`
subprocess. It is byte-for-byte identical to the `dexdump` path (verified on the
whole `services.jar` dump) and ~2.5× faster end to end. Pass `--dexdump <path>` (or
set `$DEXLOCK_USE_DEXDUMP` and point `$DEXLOCK_DEXDUMP` at the binary) to switch to the
`dexdump` back-end instead. On `services.jar` +
`framework.jar` (~53k classes) it resolves ~18k lock points in a few seconds; the
protobuf is roughly half the JSON size and loads columnar without a parse step.

## `race` — inconsistent-locking (data-race) findings

```sh
dexlock race services.jar -o races.json
```

Builds on the same lock resolution: for each method it tracks the set of locks
*held* at every point (monitor-enter/exit, `Lock.lock/unlock`, and a `synchronized`
method's implicit monitor) and records each instance-field access with the locks held
at it. A field is flagged when it is written somewhere, is not `final`/`volatile`,
and is accessed **under a lock in several places but with no lock in others** — the
guard is inferred as the lock held on most of its guarded accesses (restricted to a
lock of the field's own class, which removes the incidental cross-class noise), and
the unlocked accesses are reported with `file:line`.

```json
{ "field": "com.example.Foo.mX", "guard": "com.example.Foo.mLock",
  "guarded_accesses": 12,
  "unguarded": [ { "method": "com.example.Foo.peek:()I",
                   "file": "Foo.java", "line": 42, "write": false, "held": [] } ] }
```

It is a heuristic, like [RacerD](https://fbinfer.com/docs/checker-racerd/): it infers
the intended guard from the guarded accesses, so it can miss races on never-guarded
fields and flag benign single-threaded ones. Treat it as a lint signal — most useful
as a presubmit that diffs findings before/after a change and flags a newly-unguarded
access to an otherwise-guarded field.

## Library

```rust
use dexlock::artifact::DirArtifactProvider;
use dexlock::resolver::{Options, Resolver};
use dexlock::{csv_io, pipeline, pipeline::Output, traces::{CsvTraceSource, TraceSource}, model::Query};

let rows = CsvTraceSource { path: "in.csv".into() }.fetch(&Query::default())?;
let headers = csv_io::load("in.csv".as_ref())?.headers;
let resolver = Resolver::new("cache".into(), None, Options::default());
pipeline::run(rows, &DirArtifactProvider { root: "jars".into() }, &resolver, &headers,
              &Output { path: "out.csv".into(), compact: false })?;
```

`Resolver::index_for` / `Resolver::resolve` are usable directly for non-CSV flows.

## Building

```sh
cargo build --release
```

No external service, subprocess, or crate beyond the published dependencies — the
whole DEX front-end (container parse, decode, archive extraction) is in-tree under
`src/dex`. `dexdump` is **not** required; it is only used if you opt into the fallback
with `--dexdump` / `$DEXLOCK_USE_DEXDUMP`.

## Tests

```sh
cargo test
```

The tests are self-contained: they seed a cached index (the resolver's on-disk shape)
and exercise the full load → group → resolve → save path in-process, with no DEX
toolchain, network, or external service.
