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
//! Little-endian byte reader for the DEX container: fixed-width integers, the
//! LEB128 variants DEX uses, and MUTF-8 strings.
//!
//! Every DEX offset is from the start of the file, so the reader is just a borrow
//! of the whole mapped image plus a movable position; random-access reads take an
//! absolute offset and never mutate the cursor.

#![allow(dead_code)]

use anyhow::{bail, Result};

/// A cursor over an in-memory DEX image. Sequential reads advance `pos`; the
/// `*_at` reads are absolute and leave `pos` untouched.
pub struct Reader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn seek(&mut self, off: usize) {
        self.pos = off;
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.pos + n > self.data.len() {
            bail!("read past end of dex ({} + {} > {})", self.pos, n, self.data.len());
        }
        Ok(())
    }

    pub fn u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn u16(&mut self) -> Result<u16> {
        self.need(2)?;
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    pub fn u32(&mut self) -> Result<u32> {
        self.need(4)?;
        let b = &self.data[self.pos..self.pos + 4];
        self.pos += 4;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a u32 at an absolute offset without moving the cursor.
    pub fn u32_at(&self, off: usize) -> Result<u32> {
        if off + 4 > self.data.len() {
            bail!("u32 read past end at {off}");
        }
        let b = &self.data[off..off + 4];
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u16_at(&self, off: usize) -> Result<u16> {
        if off + 2 > self.data.len() {
            bail!("u16 read past end at {off}");
        }
        Ok(u16::from_le_bytes([self.data[off], self.data[off + 1]]))
    }

    /// Unsigned LEB128.
    pub fn uleb128(&mut self) -> Result<u32> {
        let mut result: u32 = 0;
        let mut shift = 0;
        loop {
            let b = self.u8()?;
            result |= ((b & 0x7f) as u32) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 35 {
                bail!("uleb128 too long");
            }
        }
        Ok(result)
    }

    /// Signed LEB128.
    pub fn sleb128(&mut self) -> Result<i32> {
        let mut result: i32 = 0;
        let mut shift = 0;
        loop {
            let b = self.u8()?;
            result |= ((b & 0x7f) as i32) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 32 && (b & 0x40) != 0 {
                    result |= -(1i32 << shift);
                }
                break;
            }
            if shift > 35 {
                bail!("sleb128 too long");
            }
        }
        Ok(result)
    }

    /// `uleb128p1`: an unsigned LEB128 biased by one, so it can encode -1 (NO_INDEX).
    pub fn uleb128p1(&mut self) -> Result<i64> {
        Ok(self.uleb128()? as i64 - 1)
    }

    /// A `string_data_item`: a uleb128 utf16 length prefix, then MUTF-8 bytes ended
    /// by a NUL. Returned as a Rust `String` (lossy on malformed units).
    pub fn string_data_at(&self, off: usize) -> Result<String> {
        let mut r = Reader { data: self.data, pos: off };
        let _utf16_units = r.uleb128()?; // decorative; we scan to the NUL terminator
        let start = r.pos;
        let mut end = start;
        while end < self.data.len() && self.data[end] != 0 {
            end += 1;
        }
        Ok(mutf8_to_string(&self.data[start..end]))
    }
}

/// Decode Modified UTF-8 (as DEX stores strings) to a `String`. Handles the 1–3
/// byte forms and the two-unit encoding of the NUL byte; surrogate pairs come
/// through as their two encoded 3-byte units and are folded back by `from_utf16`.
pub fn mutf8_to_string(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b & 0x80 == 0 {
            units.push(b as u16);
            i += 1;
        } else if b & 0xe0 == 0xc0 {
            if i + 1 >= bytes.len() {
                break;
            }
            let u = (((b & 0x1f) as u16) << 6) | ((bytes[i + 1] & 0x3f) as u16);
            units.push(u);
            i += 2;
        } else if b & 0xf0 == 0xe0 {
            if i + 2 >= bytes.len() {
                break;
            }
            let u = (((b & 0x0f) as u16) << 12)
                | (((bytes[i + 1] & 0x3f) as u16) << 6)
                | ((bytes[i + 2] & 0x3f) as u16);
            units.push(u);
            i += 3;
        } else {
            units.push(0xfffd);
            i += 1;
        }
    }
    String::from_utf16_lossy(&units)
}
