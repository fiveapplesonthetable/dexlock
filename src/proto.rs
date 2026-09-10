//! Minimal protobuf wire-format writer for the columnar lock-point dump.
//!
//! Just enough of the wire format to emit `dexlock.proto`'s `LockPoints` message —
//! a string pool plus packed-uint32 columns — with no external dependency and no
//! build step. The output decodes with any standard protobuf reader against
//! `dexlock.proto` (verified with `protoc --decode`).

/// Append a base-128 varint.
fn put_varint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            buf.push(byte | 0x80);
        } else {
            buf.push(byte);
            break;
        }
    }
}

/// Append a field tag (field number + wire type).
fn tag(buf: &mut Vec<u8>, field: u32, wire: u32) {
    put_varint(buf, ((field << 3) | wire) as u64);
}

/// Append a length-delimited field (wire type 2): tag, length, bytes.
fn len_delim(buf: &mut Vec<u8>, field: u32, payload: &[u8]) {
    tag(buf, field, 2);
    put_varint(buf, payload.len() as u64);
    buf.extend_from_slice(payload);
}

/// Append a `packed` repeated uint32 field: one length-delimited blob of varints.
fn packed_u32(buf: &mut Vec<u8>, field: u32, vals: &[u32]) {
    let mut tmp = Vec::with_capacity(vals.len() * 2);
    for &v in vals {
        put_varint(&mut tmp, v as u64);
    }
    len_delim(buf, field, &tmp);
}

/// Encode a `LockPoints` message. The columns must be parallel (equal length);
/// row `i` is `(class_id[i], method_id[i], lock_id[i], line[i])`, ids indexing
/// into `strings`.
pub fn encode_lock_points(
    strings: &[String],
    class_id: &[u32],
    method_id: &[u32],
    lock_id: &[u32],
    line: &[u32],
) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(class_id.len() * 6 + strings.iter().map(|s| s.len() + 2).sum::<usize>());
    for s in strings {
        len_delim(&mut buf, 1, s.as_bytes());
    }
    packed_u32(&mut buf, 2, class_id);
    packed_u32(&mut buf, 3, method_id);
    packed_u32(&mut buf, 4, lock_id);
    packed_u32(&mut buf, 5, line);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        let mut b = Vec::new();
        put_varint(&mut b, 0);
        put_varint(&mut b, 127);
        put_varint(&mut b, 128);
        put_varint(&mut b, 300);
        assert_eq!(b, vec![0x00, 0x7f, 0x80, 0x01, 0xac, 0x02]);
    }

    #[test]
    fn message_shape() {
        // one string, one row: tag(1,2) len=1 'a'; then packed columns each tag+len+1 byte.
        let bytes = encode_lock_points(&["a".into()], &[0], &[0], &[0], &[5]);
        assert_eq!(bytes[0], (1 << 3) | 2); // field 1, wire 2
        assert_eq!(bytes[1], 1); // len 1
        assert_eq!(bytes[2], b'a');
        // remainder is four packed columns; the last (line) must carry the value 5.
        assert!(bytes.ends_with(&[5]));
    }
}
