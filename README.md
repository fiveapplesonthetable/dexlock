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

Four subcommands. `-j/--threads` bounds the worker pool for any of them (default: all cores).

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

**Inputs** are `.dex`, a zip-family archive (`.jar`/`.apk`/`.zip`/`.aar`), an APEX
(`.apex`, or compressed `.capex`), or a directory — including a zip that nests more
jars/apks. They are extracted natively in memory (no `unzip` subprocess).

An APEX carries its jars inside a filesystem image (`apex_payload.img`), so its
`javalib/*.jar` are read out with an in-process **EROFS** reader (LZ4, legacy and
compact index layouts — what `mkfs.erofs` produces for Android) or **ext4** reader
(extent trees, block maps, 64-bit descriptors); a `.capex` is unwrapped first. No
`deapexer`, `debugfs` or `fsck.erofs` subprocess is needed. If a payload uses a
feature the native readers do not cover, `deapexer` is used as a fallback (found via
`$DEXLOCK_DEAPEXER`, then `PATH`; its helpers via `$DEXLOCK_DEBUGFS` /
`$DEXLOCK_FSCK_EROFS`, then beside `deapexer`). The native reader is verified
byte-for-byte against `deapexer` on every APEX of an AOSP build (61 jars). With
`system/framework` and `system/apex` both given, the whole system_server class
space is in: 95,923 classes, 2.68M call sites, 99.94% of them linked, 0.06% into
classes outside the inputs.

### `binder` — binder calls made while holding a lock

Holding a lock across a synchronous binder transaction is a classic system_server
hazard: the call blocks on another process (or an app callback), and every thread
that wants the lock is stuck behind it — a common ANR and lock-inversion source.
`binder` flags each such site.

```sh
dexlock binder services.jar framework.jar -o binder.json
# --closed-world  infer caller-held locks past private methods (see below)
# --scope <substr> narrows a directory input; --dexdump <path> selects the back-end
```

A binder call is recognized structurally, not by name: an `IBinder.transact`, or a
call **dispatched through** an AIDL interface (an `invoke-interface` on a type that
transitively extends `android.os.IInterface`) or a generated `$Stub$Proxy`. A
service invoking its own helper is `invoke-virtual`/`-direct` on the concrete impl —
which merely happens to implement a `$Stub` — so restricting to interface dispatch
excludes it. The held-lock set is tracked exactly as resolution tracks it
(monitor-enter/exit, `Lock.lock`/`unlock`, and a `synchronized` method's implicit
monitor).

Output is a JSON array of `{method, file, line, held, callee}`, where `held` is the
lock(s) demonstrably held at the call and `callee` is the binder method invoked, e.g.

```json
{"method":"…TelephonyRegistry.notifyActiveDataSubIdChanged:(I)V","file":"TelephonyRegistry.java",
 "line":2776,"held":["com.android.server.TelephonyRegistry.mRecords"],
 "callee":"com.android.internal.telephony.IPhoneStateListener.onActiveDataSubIdChanged"}
```

The held-lock set is **interprocedural** for the common `…Locked` / `@GuardedBy`
convention, where the lock is taken one frame up. A call in a *private* helper whose
callers all hold a lock is still flagged: dexlock infers "locks held on entry" to
each private method as the intersection of the held sets at all of its call sites,
solved as a fixpoint over the call graph, and seeds the scan with it. Only private
methods are inferred — their callers are all inside the analyzed DEX, so the
intersection is over the *complete* set of callers; a public/package method could be
called from outside with no lock held, so it is left unseeded rather than assumed
(the analysis under-reports rather than inventing findings). This recovers real
cases intra-procedural analysis misses — e.g. `UiAutomationConnection`'s
`restoreRotationStateLocked()` calls `IWindowManager.freezeRotation` with `mLock`
held by its caller (the AOSP source even comments that the call-out is deliberate).

**`--closed-world`** widens the inference: it treats the given inputs as the whole
program and infers caller-held locks for any method whose exact `(name, sig)` is
declared by no other class. A globally-unique signature cannot be an override or a
polymorphic target, so every call site with that signature resolves to that one
method — the full caller set is known without class-hierarchy guessing. This recovers
non-private `…Locked` helpers, singleton constructors called under a class lock, and
calls that reach a private method through a synthetic accessor bridge (which has a
unique signature). Its soundness rests on the inputs being complete: pass *all*
relevant jars/apks, because a caller in an omitted artifact would be missed and could
turn the must-intersection into a false positive. On `services.jar` + `framework.jar`
it lifts the count (default inference finds 1,024 on those two jars). It is off by
default; the default (private-only) inference needs no whole-program assumption.

Two caveats it cannot resolve statically: a binder whose service lives in the *same*
process (e.g. a system_server-internal AIDL) is a local call, not a real IPC; and a
`oneway` call does not block. Both are still reported, so treat findings as "a lock
held across a potentially blocking IPC" — a ranked starting point, not a proof.

### `ctx` — which locks may be held here, and how they got here

The lock-context index answers, for any **source line**, **method**, or **lock**:
which locks may be held at that point, how many call frames away each was taken,
the call path that brings it, and how locks order against each other. It is the
substrate the other analyses can be phrased over (binder-under-lock, races,
deadlock candidates), built once and queried in well under a second.

```sh
dexlock ctx build services.jar framework.jar -o sys.ctx     # ~10s; add .gz to compress
dexlock ctx query sys.ctx --at ActivityManagerService.java:4600
dexlock ctx query sys.ctx --method ActivityManagerService.attachApplicationLocked:
dexlock ctx query sys.ctx --lock ActivityManagerService.mProcLock
dexlock ctx query sys.ctx --cycles                            # lock-order SCCs
# --depth N (default 4) omits locks held more than N frames away; --json for tooling
```

A line or method query reports the locks the method itself holds at that line
(with the acquiring line) and the locks that *may* be held on entry, each with its
distance and a witness path from the acquiring frame:

```
ActivityManagerService.java:4589  in  …ActivityManagerService.attachApplicationLocked:(…)V
  held by this method here: (none)
  may be held on entry (from callers): 1 within 4 frame(s), 1 total
    [d=1] com.android.server.am.ActivityManagerService
      via …ActivityManagerService.attachApplication:(…)V  (acquires at ActivityManagerService.java:4922; calls at ActivityManagerService.java:4926)
          -> …ActivityManagerService.attachApplicationLocked:(…)V
```

A lock query reports where it is acquired, the methods it may be held on entry to
(nearest first), and its lock-order neighbours in both directions — each edge with
a count, its distance, and an example site. `--cycles` leads with the pairs
of locks acquired in both orders — the concrete deadlock candidates — each with
both witness sites, and separates the pairs that are *gated* (both orders occur
under a common outer lock, so they serialize) from those with no such lock; the
strongly connected groups of the order graph follow.

How it works. Every method is walked once for its lock *spans* (each acquisition
with the line range it is held over) and its call sites, each tagged with the locks
held there. That walk is control-flow aware: a `synchronized` block with an early
`return` compiles to a `monitor-exit` on that path before the block's remaining
code, and every block has a catch-all handler that exits the monitor and rethrows,
so the held set is solved as a forward dataflow over basic blocks (branch, switch,
fall-through, and exception edges) rather than read off a linear scan — which
misreads everything after the first textual exit as unlocked. `tryLock` is held on
its success path only; `readLock()`/`writeLock()` views are the parent lock in that
mode. A lock taken or released *through a helper* (`acquireFooLock()` that returns
holding it, `releaseFooLock()`) is tracked too: each method's net lock effect on its
caller is solved as a fixpoint and applied at its call sites. Call sites link to their static target and, for virtual/interface
dispatch with a small implementation set (`--cha-cap`, default 16), to each
override; a broad interface such as `Runnable.run` is left unlinked on purpose,
since "every lock any caller holds" is noise. When the receiver's concrete class is
known from the bytecode (`new`, `this`, a field's declared type) the call is
devirtualized to that one method instead. Calls on a *parameter* are resolved by
parameter type-flow: for every formal that is invoked on (directly, or after being
passed on), the classes callers actually pass in are collected — a lambda, an
anonymous class, a `new`, a field's declared type — and the invoke inside the callee
links to exactly those classes' methods. So `each(a) { a.go(); }` called with a lambda
links that lambda, and the lambda body inherits the locks held at the call; a callee
that only *stores* its argument (`Handler.post`, a listener registry) invokes nothing
and links nothing. There is no list of "async" method names: what runs a callback
is read from the code. A callee outside the inputs (`java.util.List.forEach`)
cannot be inspected, so the lock is assumed **not** held through it — an
under-approximation, never an invention; include the jar to close that gap. On `services.jar` + `framework.jar`: 1.56M call sites, 1.08M
linked (12.6k devirtualized, 69k callback edges), 472k into classes outside the
inputs, 0.4% unlinked by wide dispatch. Lock names are the canonical
identities from resolution, so a lock reached through an alias — `mGlobalLockWithoutBoost`
is `mGlobalLock` — is one lock here. Over that graph the index solves, per method
and lock, the fewest call frames from a holder (a min-plus fixpoint, cut at
`--max-depth`, default 8). Distance is what makes a *may* analysis usable: without
it a lock taken near the top of a service is "possibly held" in most of the
program (60k methods for `mProcLock`, a 775-lock order cycle); ranked and bounded
by distance, `mProcLock` has ~2.7k methods within 4 frames and the order graph is
6.7k edges. The lock-order graph relates an acquisition only to locks held within
`--order-depth` frames (default 3), and ignores a *reentrant* acquisition — a lock
the method or a caller already holds orders nothing, and treating it as a fresh
acquisition manufactures inversions out of nested `First → Second` blocks re-entered
from a callee. On all 40 `system/framework` jars that filter takes the inversion list
from 85 pairs to 18 (15 with no common outer lock), each backed by two witness sites.

Limits: a callback reached only through a wide interface on a non-parameter
receiver, or through reflection, is not linked, so lock context does not flow into
it; a callback run by code outside the inputs is treated as not under the lock; a
*may* set is a superset, and every witness path is real but not necessarily the
only or the common one.

### The DEX front-end

Parsing is a native in-process reader by default — it decodes the DEX binary
straight into the model (handling the v41 container format), with no `dexdump`
subprocess. It is byte-for-byte identical to the `dexdump` path (verified on the
whole `services.jar` dump) and ~2.5× faster end to end. Pass `--dexdump <path>` (or
set `$DEXLOCK_USE_DEXDUMP` and point `$DEXLOCK_DEXDUMP` at the binary) to switch to the
`dexdump` back-end instead. On `services.jar` +
`framework.jar` (~53k classes) it resolves ~18k lock points in a few seconds; the
protobuf is roughly half the JSON size and loads columnar without a parse step.

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
