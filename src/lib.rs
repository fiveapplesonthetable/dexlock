//! dexlock — fast lock-contention resolver.
//!
//! Given monitor-contention observations (each naming two `File:line` source
//! sites) and the DEX artifacts for the build they came from, dexlock resolves
//! each site to the canonical lock taken there. The DEX analysis runs in-process
//! (see [`dex`]) — no subprocess per query.
//!
//! The moving parts are pluggable seams:
//! - [`traces::TraceSource`] — where observations come from (a CSV file ships;
//!   plug in a query against your own store).
//! - [`artifact::ArtifactProvider`] — where a build's jars/apks come from (a
//!   directory and an in-process archive unpacker ship; plug in a downloader).
//! - [`resolver::Resolver`] — the in-process, disk-cached resolution core.

pub mod artifact;
pub mod csv_io;
pub mod dex;
pub mod model;
pub mod pipeline;
pub mod resolver;
pub mod site;
pub mod traces;
