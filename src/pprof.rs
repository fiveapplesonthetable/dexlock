//! Emit the lock graph as a gzipped pprof profile (`github.com/google/pprof`).
//!
//! Every acquisition becomes a two-frame sample `method -> lock` (leaf = lock), so
//! standard pprof tooling renders a graph whose nodes are methods and locks and
//! whose edges are "method acquires lock", weighted by the number of acquisition
//! sites. `go tool pprof lock.pb.gz` (or speedscope) opens it directly; focus a lock
//! to see every method that takes it, or a method to see the locks it holds.

use crate::dex::Acquisition;
use rustc_hash::FxHashMap as HashMap;

fn varint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            buf.push(b | 0x80);
        } else {
            buf.push(b);
            break;
        }
    }
}
fn tag(buf: &mut Vec<u8>, field: u32, wire: u32) {
    varint(buf, ((field << 3) | wire) as u64);
}
fn field_varint(buf: &mut Vec<u8>, field: u32, v: u64) {
    tag(buf, field, 0);
    varint(buf, v);
}
fn field_bytes(buf: &mut Vec<u8>, field: u32, payload: &[u8]) {
    tag(buf, field, 2);
    varint(buf, payload.len() as u64);
    buf.extend_from_slice(payload);
}

/// Intern strings for the pprof string_table (index 0 must be "").
#[derive(Default)]
struct Strings {
    idx: HashMap<String, i64>,
    list: Vec<String>,
}
impl Strings {
    fn intern(&mut self, s: &str) -> i64 {
        if let Some(&i) = self.idx.get(s) {
            return i;
        }
        let i = self.list.len() as i64;
        self.list.push(s.to_string());
        self.idx.insert(s.to_string(), i);
        i
    }
}

/// Build the gzipped pprof profile for the lock graph of `acqs`.
pub fn lock_graph(acqs: &[Acquisition]) -> std::io::Result<Vec<u8>> {
    let mut s = Strings::default();
    s.intern(""); // id 0

    // A node per distinct lock and per distinct method; each gets a function + a
    // location (pprof needs a location to reference in a sample).
    let mut node_loc: HashMap<String, u64> = HashMap::default();
    let mut functions: Vec<u8> = Vec::new();
    let mut locations: Vec<u8> = Vec::new();
    let mut next_id: u64 = 1;
    let node = |name: &str, file: &str, s: &mut Strings, functions: &mut Vec<u8>, locations: &mut Vec<u8>, node_loc: &mut HashMap<String, u64>, next_id: &mut u64| -> u64 {
        if let Some(&id) = node_loc.get(name) {
            return id;
        }
        let id = *next_id;
        *next_id += 1;
        let name_idx = s.intern(name) as u64;
        let file_idx = s.intern(file) as u64;
        // Function { id=1, name=2, system_name=3, filename=4 }
        let mut f = Vec::new();
        field_varint(&mut f, 1, id);
        field_varint(&mut f, 2, name_idx);
        field_varint(&mut f, 3, name_idx);
        field_varint(&mut f, 4, file_idx);
        field_bytes(functions, 5, &f); // Profile.function = 5
                                        // Location { id=1, line=4:[Line{function_id=1,line=2}] }
        let mut line = Vec::new();
        field_varint(&mut line, 1, id); // function_id
        let mut loc = Vec::new();
        field_varint(&mut loc, 1, id);
        field_bytes(&mut loc, 4, &line);
        field_bytes(locations, 4, &loc); // Profile.location = 4
        node_loc.insert(name.to_string(), id);
        id
    };

    // Aggregate acquisitions into method->lock edges with a count.
    let mut edges: HashMap<(String, String, String), i64> = HashMap::default();
    for a in acqs {
        let file = a.source_file.clone().unwrap_or_default();
        *edges.entry((a.method.clone(), a.lock.clone(), file)).or_insert(0) += 1;
    }

    let mut samples: Vec<u8> = Vec::new();
    for ((method, lock, file), count) in &edges {
        let mloc = node(method, file, &mut s, &mut functions, &mut locations, &mut node_loc, &mut next_id);
        let lloc = node(lock, "", &mut s, &mut functions, &mut locations, &mut node_loc, &mut next_id);
        // Sample { location_id=1 (leaf first: lock, then method), value=2 }
        let mut sample = Vec::new();
        field_varint(&mut sample, 1, lloc);
        field_varint(&mut sample, 1, mloc);
        field_varint(&mut sample, 2, *count as u64);
        field_bytes(&mut samples, 2, &sample); // Profile.sample = 2
    }

    // ValueType { type=1, unit=2 } for sample_type = field 1.
    let type_idx = s.intern("acquisitions") as u64;
    let unit_idx = s.intern("count") as u64;
    let mut value_type = Vec::new();
    field_varint(&mut value_type, 1, type_idx);
    field_varint(&mut value_type, 2, unit_idx);

    // Assemble Profile.
    let mut prof = Vec::new();
    field_bytes(&mut prof, 1, &value_type); // sample_type
    prof.extend_from_slice(&samples); // sample (already tagged, field 2)
    prof.extend_from_slice(&locations); // location (field 4)
    prof.extend_from_slice(&functions); // function (field 5)
    for st in &s.list {
        field_bytes(&mut prof, 6, st.as_bytes()); // string_table (field 6)
    }

    // pprof files are gzip-compressed by convention.
    use std::io::Write;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&prof)?;
    gz.finish()
}
