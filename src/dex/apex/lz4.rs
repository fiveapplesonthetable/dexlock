// Copyright (C) 2026 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! LZ4 block decompression — the raw block format, no frame — which is what an
//! EROFS physical cluster holds.

use anyhow::{bail, Result};

/// Decompress one LZ4 block into exactly `out_len` bytes.
pub fn decompress(src: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let mut dst: Vec<u8> = Vec::with_capacity(out_len);
    let n = src.len();
    let mut i = 0;
    // A length nibble of 15 continues in bytes until one is not 255.
    let extend = |i: &mut usize, mut len: usize| -> Result<usize> {
        loop {
            let Some(&b) = src.get(*i) else { bail!("lz4: truncated length") };
            *i += 1;
            len += b as usize;
            if b != 255 {
                return Ok(len);
            }
        }
    };
    while i < n && dst.len() < out_len {
        let token = src[i];
        i += 1;
        let mut lit = (token >> 4) as usize;
        if lit == 15 {
            lit = extend(&mut i, lit)?;
        }
        if i + lit > n {
            bail!("lz4: literals past end of block");
        }
        dst.extend_from_slice(&src[i..i + lit]);
        i += lit;
        if i >= n || dst.len() >= out_len {
            break; // a block ends with literals
        }
        if i + 2 > n {
            bail!("lz4: truncated match offset");
        }
        let off = u16::from_le_bytes([src[i], src[i + 1]]) as usize;
        i += 2;
        if off == 0 || off > dst.len() {
            bail!("lz4: match offset {off} outside output of {}", dst.len());
        }
        let mut ml = (token & 15) as usize;
        if ml == 15 {
            ml = extend(&mut i, ml)?;
        }
        ml += 4;
        // Matches may overlap their own output (run-length style): copy bytewise.
        let start = dst.len() - off;
        for k in 0..ml {
            let b = dst[start + k];
            dst.push(b);
        }
    }
    if dst.len() < out_len {
        bail!("lz4: block decompressed to {} bytes, expected {out_len}", dst.len());
    }
    dst.truncate(out_len);
    Ok(dst)
}

#[cfg(test)]
mod tests {
    use super::decompress;

    #[test]
    fn literals_and_overlapping_match() {
        // token 0x50: 5 literals "abcde", then match len 4 (nibble 0 + 4) at offset 5
        // -> "abcdeabcd"; then a final literal-only token for "!".
        let src = [0x50, b'a', b'b', b'c', b'd', b'e', 0x05, 0x00, 0x10, b'!'];
        assert_eq!(decompress(&src, 10).unwrap(), b"abcdeabcd!");
        // An offset of 1 repeats the last byte: "x" + 6 x 'x'.
        let src = [0x12, b'x', 0x01, 0x00];
        assert_eq!(decompress(&src, 7).unwrap(), b"xxxxxxx");
    }

    #[test]
    fn rejects_bad_offset() {
        assert!(decompress(&[0x10, b'a', 0x09, 0x00], 6).is_err());
    }
}
