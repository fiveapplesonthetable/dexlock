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

//! Read-only ext4: walk directories and read files, with extent trees, the
//! classic block map, 64-bit group descriptors, and inline directory data. An
//! APEX payload built with `mke2fs` uses extents throughout.

use anyhow::{bail, Context, Result};

const SB_OFF: usize = 1024;
const MAGIC: u16 = 0xEF53;
const INCOMPAT_64BIT: u32 = 0x80;
const EXTENTS_FL: u32 = 0x8_0000;
const INLINE_DATA_FL: u32 = 0x1000_0000;
const EXTENT_MAGIC: u16 = 0xF30A;
const ROOT_INO: u32 = 2;
pub const FT_REG: u8 = 1;

pub fn is_ext4(d: &[u8]) -> bool {
    d.len() >= SB_OFF + 58 && u16_at(d, SB_OFF + 56) == MAGIC
}

fn u16_at(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}
fn u32_at(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

pub struct Ext4<'a> {
    d: &'a [u8],
    bs: usize,
    inodes_per_group: u32,
    inode_size: usize,
    desc_size: usize,
    gdt_off: usize,
}

struct Inode {
    mode: u16,
    size: u64,
    flags: u32,
    /// `i_block`, 60 bytes: an extent tree root, a block map, or inline data.
    block: [u8; 60],
}

pub struct Entry {
    pub name: String,
    pub ino: u32,
    pub ftype: u8,
}

impl<'a> Ext4<'a> {
    pub fn parse(d: &'a [u8]) -> Result<Self> {
        if !is_ext4(d) || d.len() < SB_OFF + 1024 {
            bail!("not an ext4 image");
        }
        let sb = &d[SB_OFF..];
        let bs = 1024usize << u32_at(sb, 24);
        let first_data_block = u32_at(sb, 20) as usize;
        let incompat = u32_at(sb, 96);
        let desc_size = if incompat & INCOMPAT_64BIT != 0 { (u16_at(sb, 254) as usize).max(32) } else { 32 };
        Ok(Ext4 {
            d,
            bs,
            inodes_per_group: u32_at(sb, 40),
            inode_size: u16_at(sb, 88) as usize,
            desc_size,
            gdt_off: (first_data_block + 1) * bs,
        })
    }

    fn slice(&self, off: usize, len: usize) -> Result<&'a [u8]> {
        self.d.get(off..off + len).ok_or_else(|| anyhow::anyhow!("ext4: read past end of image"))
    }

    fn block(&self, n: u64) -> Result<&'a [u8]> {
        self.slice(n as usize * self.bs, self.bs)
    }

    fn inode(&self, ino: u32) -> Result<Inode> {
        if ino == 0 {
            bail!("ext4: inode 0");
        }
        let group = ((ino - 1) / self.inodes_per_group) as usize;
        let index = ((ino - 1) % self.inodes_per_group) as usize;
        let gd = self.slice(self.gdt_off + group * self.desc_size, self.desc_size)?;
        let mut table = u32_at(gd, 8) as u64;
        if self.desc_size >= 64 {
            table |= (u32_at(gd, 40) as u64) << 32;
        }
        let off = table as usize * self.bs + index * self.inode_size;
        let r = self.slice(off, 128)?;
        let mut block = [0u8; 60];
        block.copy_from_slice(&r[40..100]);
        Ok(Inode {
            mode: u16_at(r, 0),
            size: u32_at(r, 4) as u64 | (u32_at(r, 108) as u64) << 32,
            flags: u32_at(r, 32),
            block,
        })
    }

    /// Physical blocks of a file in logical order (`None` = hole), from its
    /// extent tree or classic block map.
    fn blocks(&self, ino: &Inode) -> Result<Vec<Option<u64>>> {
        let n = (ino.size as usize).div_ceil(self.bs);
        let mut map: Vec<Option<u64>> = vec![None; n];
        if ino.flags & EXTENTS_FL != 0 {
            self.extents(&ino.block, &mut map, 0)?;
        } else {
            let direct: Vec<u32> = (0..15).map(|k| u32_at(&ino.block, k * 4)).collect();
            let mut lblk = 0usize;
            let mut put = |map: &mut Vec<Option<u64>>, pblk: u32| {
                if lblk < map.len() && pblk != 0 {
                    map[lblk] = Some(pblk as u64);
                }
                lblk += 1;
            };
            for &p in &direct[..12] {
                put(&mut map, p);
            }
            let per = self.bs / 4;
            let ptrs = |b: u32| -> Result<Vec<u32>> {
                if b == 0 { return Ok(vec![0; per]) }
                Ok(self.block(b as u64)?.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect())
            };
            for &p in &ptrs(direct[12])? {
                put(&mut map, p);
            }
            for &q in &ptrs(direct[13])? {
                for &p in &ptrs(q)? {
                    put(&mut map, p);
                }
            }
            if direct[14] != 0 && lblk < n {
                bail!("ext4: triple-indirect block map not supported");
            }
        }
        Ok(map)
    }

    fn extents(&self, node: &[u8], map: &mut Vec<Option<u64>>, depth_guard: u32) -> Result<()> {
        if depth_guard > 8 {
            bail!("ext4: extent tree too deep");
        }
        if u16_at(node, 0) != EXTENT_MAGIC {
            bail!("ext4: bad extent header");
        }
        let entries = u16_at(node, 2) as usize;
        let depth = u16_at(node, 6);
        for k in 0..entries {
            let e = node.get(12 + k * 12..24 + k * 12).context("ext4: extent past node")?;
            if depth == 0 {
                let lblk = u32_at(e, 0) as usize;
                let raw_len = u16_at(e, 4) as usize;
                let (len, init) = if raw_len > 32768 { (raw_len - 32768, false) } else { (raw_len, true) };
                let start = u32_at(e, 8) as u64 | (u16_at(e, 6) as u64) << 32;
                for j in 0..len {
                    if lblk + j < map.len() && init {
                        map[lblk + j] = Some(start + j as u64);
                    }
                }
            } else {
                let child = u32_at(e, 4) as u64 | (u16_at(e, 8) as u64) << 32;
                self.extents(self.block(child)?, map, depth_guard + 1)?;
            }
        }
        Ok(())
    }

    fn read(&self, ino: &Inode) -> Result<Vec<u8>> {
        if ino.flags & INLINE_DATA_FL != 0 {
            bail!("ext4: inline file data not supported");
        }
        let size = ino.size as usize;
        let mut out = Vec::with_capacity(size);
        for b in self.blocks(ino)? {
            match b {
                Some(p) => out.extend_from_slice(self.block(p)?),
                None => out.extend(std::iter::repeat_n(0u8, self.bs)),
            }
        }
        out.truncate(size);
        Ok(out)
    }

    /// Linear directory entries (`ext4_dir_entry_2`); an htree index is an
    /// overlay on the same blocks, so a linear walk still sees every entry.
    fn entries(&self, ino: &Inode) -> Result<Vec<Entry>> {
        if ino.mode & 0xF000 != 0x4000 {
            bail!("ext4: not a directory");
        }
        let data = if ino.flags & INLINE_DATA_FL != 0 {
            // Inline: parent inode number, then entries in the rest of i_block.
            ino.block[4..].to_vec()
        } else {
            self.read(ino)?
        };
        let mut out = Vec::new();
        let mut off = 0;
        while off + 8 <= data.len() {
            let e = &data[off..];
            let inode = u32_at(e, 0);
            let rec_len = u16_at(e, 4) as usize;
            let name_len = e[6] as usize;
            let ftype = e[7];
            if rec_len < 8 {
                break;
            }
            if inode != 0 && 8 + name_len <= rec_len && off + 8 + name_len <= data.len() {
                let name = String::from_utf8_lossy(&data[off + 8..off + 8 + name_len]).into_owned();
                out.push(Entry { name, ino: inode, ftype });
            }
            off += rec_len;
        }
        Ok(out)
    }

    fn lookup(&self, path: &str) -> Result<Option<(u32, Inode)>> {
        let mut ino_no = ROOT_INO;
        let mut ino = self.inode(ino_no)?;
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            let Some(e) = self.entries(&ino)?.into_iter().find(|e| e.name == comp) else { return Ok(None) };
            ino_no = e.ino;
            ino = self.inode(ino_no)?;
        }
        Ok(Some((ino_no, ino)))
    }

    /// Directory listing at `path`, or `None` if the path does not exist.
    pub fn read_dir(&self, path: &str) -> Result<Option<Vec<Entry>>> {
        match self.lookup(path)? {
            Some((_, ino)) => Ok(Some(self.entries(&ino)?)),
            None => Ok(None),
        }
    }

    /// Contents of the regular file with inode number `ino`.
    pub fn read_ino(&self, ino: u32) -> Result<Vec<u8>> {
        self.read(&self.inode(ino)?)
    }
}
