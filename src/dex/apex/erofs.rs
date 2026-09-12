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

//! Read-only EROFS: walk directories and read files, including LZ4-compressed
//! ones in both the legacy (8-byte per logical cluster) and the compact
//! (bit-packed, `COMPACTED_2B`) index layouts — what `mkfs.erofs` produces for
//! an APEX payload. Layouts and advise bits outside that (big pclusters, inline
//! or fragment pclusters, chunk-based files, non-LZ4 algorithms) are reported as
//! errors so the caller can fall back.

use super::lz4;
use anyhow::{bail, Context, Result};

const SB_OFF: usize = 1024;
const MAGIC: u32 = 0xE0F5_E1E2;
/// The compressed bytes of a pcluster sit at the end of the block, zero-padded
/// at the front.
const FEATURE_INCOMPAT_ZERO_PADDING: u32 = 0x1;

// Inode data layouts (`i_format` bits 1..3).
const LAYOUT_FLAT_PLAIN: u16 = 0;
const LAYOUT_COMPRESSED_FULL: u16 = 1;
const LAYOUT_FLAT_INLINE: u16 = 2;
const LAYOUT_COMPRESSED_COMPACT: u16 = 3;

// z_erofs map header advise bits.
const ADVISE_COMPACTED_2B: u16 = 0x1;
/// big pcluster 1/2, inline pcluster, interlaced, fragment pcluster.
const ADVISE_UNSUPPORTED: u16 = 0x4 | 0x8 | 0x10 | 0x20 | 0x40;
const ALGO_LZ4: u8 = 0;

// Logical cluster types.
const T_PLAIN: u32 = 0;
const T_NONHEAD: u32 = 2;

const DIRENT_SIZE: usize = 12;
pub const FT_REG: u8 = 1;

pub fn is_erofs(d: &[u8]) -> bool {
    d.len() >= SB_OFF + 4 && u32_at(d, SB_OFF) == MAGIC
}

fn u16_at(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}
fn u32_at(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}
fn u64_at(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().expect("8 bytes"))
}

pub struct Erofs<'a> {
    d: &'a [u8],
    blkszbits: u32,
    meta_blkaddr: u64,
    root_nid: u64,
    zero_padding: bool,
}

#[derive(Clone)]
struct Inode {
    off: usize,
    layout: u16,
    size: u64,
    raw_blkaddr: u64,
    /// inode record size (32 compact / 64 extended) and the xattr area after it.
    isize: usize,
    xsize: usize,
    is_dir: bool,
}

pub struct Entry {
    pub name: String,
    pub nid: u64,
    pub ftype: u8,
}

impl<'a> Erofs<'a> {
    pub fn parse(d: &'a [u8]) -> Result<Self> {
        if !is_erofs(d) || d.len() < SB_OFF + 128 {
            bail!("not an erofs image");
        }
        let sb = &d[SB_OFF..];
        let blkszbits = sb[12] as u32;
        if !(9..=16).contains(&blkszbits) {
            bail!("erofs: bad block size bits {blkszbits}");
        }
        Ok(Erofs {
            d,
            blkszbits,
            meta_blkaddr: u32_at(sb, 40) as u64,
            root_nid: u16_at(sb, 14) as u64,
            zero_padding: u32_at(sb, 80) & FEATURE_INCOMPAT_ZERO_PADDING != 0,
        })
    }

    fn bs(&self) -> usize {
        1 << self.blkszbits
    }

    fn slice(&self, off: usize, len: usize) -> Result<&'a [u8]> {
        self.d.get(off..off + len).ok_or_else(|| anyhow::anyhow!("erofs: read past end of image"))
    }

    fn block(&self, addr: u64) -> Result<&'a [u8]> {
        let off = (addr as usize) << self.blkszbits;
        let end = (off + self.bs()).min(self.d.len());
        self.d.get(off..end).filter(|b| !b.is_empty()).ok_or_else(|| anyhow::anyhow!("erofs: block {addr} past end"))
    }

    fn inode(&self, nid: u64) -> Result<Inode> {
        let off = ((self.meta_blkaddr as usize) << self.blkszbits) + (nid as usize) * 32;
        let h = self.slice(off, 32)?;
        let format = u16_at(h, 0);
        let layout = (format >> 1) & 7;
        let xattr_icount = u16_at(h, 2) as usize;
        let xsize = if xattr_icount == 0 { 0 } else { 12 + (xattr_icount - 1) * 4 };
        // Both records: i_mode at 4, i_size at 8 (u32 compact / u64 extended),
        // i_u (raw_blkaddr) at 16.
        let (mode, size, raw_blkaddr, isize) = if format & 1 == 1 {
            let h = self.slice(off, 64)?;
            (u16_at(h, 4), u64_at(h, 8), u32_at(h, 16) as u64, 64)
        } else {
            (u16_at(h, 4), u32_at(h, 8) as u64, u32_at(h, 16) as u64, 32)
        };
        Ok(Inode { off, layout, size, raw_blkaddr, isize, xsize, is_dir: mode & 0xF000 == 0x4000 })
    }

    /// Whole contents of an inode.
    fn read(&self, ino: &Inode) -> Result<Vec<u8>> {
        match ino.layout {
            LAYOUT_FLAT_PLAIN | LAYOUT_FLAT_INLINE => {
                let size = ino.size as usize;
                let bs = self.bs();
                let full = size / bs;
                let mut out = Vec::with_capacity(size);
                for b in 0..full as u64 {
                    out.extend_from_slice(self.block(ino.raw_blkaddr + b)?);
                }
                let tail = size - full * bs;
                if tail > 0 {
                    if ino.layout == LAYOUT_FLAT_INLINE {
                        out.extend_from_slice(self.slice(ino.off + ino.isize + ino.xsize, tail)?);
                    } else {
                        out.extend_from_slice(&self.block(ino.raw_blkaddr + full as u64)?[..tail]);
                    }
                }
                Ok(out)
            }
            LAYOUT_COMPRESSED_FULL | LAYOUT_COMPRESSED_COMPACT => self.read_compressed(ino),
            other => bail!("erofs: unsupported inode layout {other}"),
        }
    }

    /// Decode every logical cluster's index, collect the pcluster heads, and
    /// decompress each pcluster into its logical extent.
    fn read_compressed(&self, ino: &Inode) -> Result<Vec<u8>> {
        let mh = (ino.off + ino.isize + ino.xsize).div_ceil(8) * 8;
        let h = self.slice(mh, 8)?;
        let advise = u16_at(h, 4);
        let algos = h[6];
        if advise & ADVISE_UNSUPPORTED != 0 {
            bail!("erofs: unsupported pcluster layout (advise {advise:#x})");
        }
        if algos & 15 != ALGO_LZ4 || (algos >> 4 != ALGO_LZ4 && algos >> 4 != 0) {
            bail!("erofs: unsupported compression algorithm {algos:#x}");
        }
        let lcbits = self.blkszbits + (h[7] & 7) as u32;
        let lcs = 1u64 << lcbits;
        let total = ino.size.div_ceil(lcs) as usize;
        let ebase = mh + 8;

        let mut heads: Vec<(u64, u32, u64)> = Vec::new(); // (logical start, type, pblk)
        for lcn in 0..total {
            let (ty, lo, pblk) = if ino.layout == LAYOUT_COMPRESSED_FULL {
                self.legacy_index(ebase, lcn)?
            } else {
                self.compact_index(ebase, total, lcn, lcbits, advise & ADVISE_COMPACTED_2B != 0)?
            };
            if ty != T_NONHEAD {
                heads.push((lcn as u64 * lcs + lo as u64, ty, pblk));
            }
        }
        let mut out: Vec<u8> = Vec::with_capacity(ino.size as usize);
        for (k, &(start, ty, pblk)) in heads.iter().enumerate() {
            let end = heads.get(k + 1).map(|h| h.0).unwrap_or(ino.size);
            if start != out.len() as u64 {
                bail!("erofs: pcluster at {start} does not follow the previous one ({})", out.len());
            }
            let len = (end - start) as usize;
            if len == 0 {
                continue;
            }
            let blk = self.block(pblk)?;
            if ty == T_PLAIN {
                out.extend_from_slice(blk.get(..len).context("erofs: plain pcluster shorter than its extent")?);
            } else {
                let src = if self.zero_padding {
                    let lead = blk.iter().take_while(|&&b| b == 0).count();
                    &blk[lead..]
                } else {
                    blk
                };
                out.extend_from_slice(&lz4::decompress(src, len)?);
            }
        }
        if out.len() as u64 != ino.size {
            bail!("erofs: decoded {} bytes of {}", out.len(), ino.size);
        }
        Ok(out)
    }

    /// Legacy index: `z_erofs_lcluster_index` — advise (type in bits 0..2),
    /// clusterofs, then blkaddr for a head or delta[0] for a non-head.
    fn legacy_index(&self, ebase: usize, lcn: usize) -> Result<(u32, u32, u64)> {
        let e = self.slice(ebase + lcn * 8, 8)?;
        let ty = (u16_at(e, 0) & 3) as u32;
        if ty == T_NONHEAD {
            Ok((ty, u16_at(e, 4) as u32, 0))
        } else {
            Ok((ty, u16_at(e, 2) as u32, u32_at(e, 4) as u64))
        }
    }

    /// Compact index: entries are bit-packed into packs of 2 (4-byte amortized)
    /// or 16 (2-byte amortized) with one block address per pack. The file's
    /// indexes begin with 4-byte entries up to a 32-byte boundary, then 2-byte
    /// packs, then 4-byte entries for the remainder.
    fn compact_index(&self, ebase: usize, total: usize, lcn: usize, lcbits: u32, two_byte: bool) -> Result<(u32, u32, u64)> {
        let initial = {
            let v = (32 - ebase % 32) / 4;
            if v == 8 { 0 } else { v }
        };
        let c2b = if two_byte && initial < total { (total - initial) / 16 * 16 } else { 0 };
        let (amort, pos) = if lcn < initial {
            (2, ebase + lcn * 4)
        } else {
            let l = lcn - initial;
            if l < c2b {
                (1, ebase + initial * 4 + l * 2)
            } else {
                (2, ebase + initial * 4 + c2b * 2 + (l - c2b) * 4)
            }
        };
        let vcnt = if amort == 2 { 2 } else { 16 };
        let packsize = vcnt << amort;
        let bs = self.bs();
        let eofs = pos % bs;
        let base = eofs / packsize * packsize;
        let pack = self.slice(pos - eofs + base, packsize)?;
        let i = (eofs - base) >> amort;
        let lobits = lcbits.max(12);
        let encodebits = (packsize - 4) * 8 / vcnt;
        let decode = |idx: usize| -> (u32, u32) {
            let p = encodebits * idx;
            let v = u32_at(pack, p / 8) >> (p & 7);
            (v & ((1 << lobits) - 1), (v >> lobits) & 3)
        };
        let (lo, ty) = decode(i);
        if ty == T_NONHEAD {
            return Ok((ty, lo, 0));
        }
        // The pack's block address is that of the pcluster running into it; each
        // head before this one in the pack owns the next block.
        let heads_before = (0..i).filter(|&j| decode(j).1 != T_NONHEAD).count() as u64;
        let blkaddr = u32_at(pack, packsize - 4) as u64;
        Ok((ty, lo, blkaddr + 1 + heads_before))
    }

    /// Entries of a directory inode.
    fn entries(&self, ino: &Inode) -> Result<Vec<Entry>> {
        if !ino.is_dir {
            bail!("erofs: not a directory");
        }
        let data = self.read(ino)?;
        let bs = self.bs();
        let mut out = Vec::new();
        let mut off = 0;
        while off < data.len() {
            let blk = &data[off..(off + bs).min(data.len())];
            off += bs;
            if blk.len() < DIRENT_SIZE {
                break;
            }
            let count = u16_at(blk, 8) as usize / DIRENT_SIZE;
            for k in 0..count {
                let e = &blk[k * DIRENT_SIZE..];
                let nid = u64_at(e, 0);
                let nameoff = u16_at(e, 8) as usize;
                let ftype = e[10];
                let end = if k + 1 < count { u16_at(blk, (k + 1) * DIRENT_SIZE + 8) as usize } else { blk.len() };
                if nameoff > end || end > blk.len() {
                    bail!("erofs: corrupt directory entry");
                }
                let raw = &blk[nameoff..end];
                let name = raw.iter().position(|&b| b == 0).map_or(raw, |p| &raw[..p]);
                out.push(Entry { name: String::from_utf8_lossy(name).into_owned(), nid, ftype });
            }
        }
        Ok(out)
    }

    fn lookup(&self, path: &str) -> Result<Option<(u64, Inode)>> {
        let mut nid = self.root_nid;
        let mut ino = self.inode(nid)?;
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            let Some(e) = self.entries(&ino)?.into_iter().find(|e| e.name == comp) else { return Ok(None) };
            nid = e.nid;
            ino = self.inode(nid)?;
        }
        Ok(Some((nid, ino)))
    }

    /// Directory listing at `path`, or `None` if the path does not exist.
    pub fn read_dir(&self, path: &str) -> Result<Option<Vec<Entry>>> {
        match self.lookup(path)? {
            Some((_, ino)) => Ok(Some(self.entries(&ino)?)),
            None => Ok(None),
        }
    }

    /// Contents of the regular file with inode `nid`.
    pub fn read_nid(&self, nid: u64) -> Result<Vec<u8>> {
        self.read(&self.inode(nid)?)
    }
}
