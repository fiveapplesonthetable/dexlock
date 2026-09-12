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

//! Native DEX front-end: decode the binary directly into the [`crate::dex::model`]
//! shape, with no `dexdump` subprocess. Bundled from the `rdex` reader; the decode
//! here maps each opcode to the SAME [`Op`] the textual `dexdump` parser produces,
//! so the resulting analysis is identical (a drop-in for `dexdump::parse_dex`).
//!
//! It handles the v41 *container* format (several concatenated sections sharing one
//! file-relative data area) and fans class parsing out across cores; the shared
//! string pool is built once, in parallel. Only the operands the lock analysis
//! consumes are decoded (monitors, field access, invokes, allocations, moves,
//! returns) plus per-instruction offsets and the debug line table — everything else
//! is `Op::Other`, exactly as the textual path treats it.

mod reader;

use crate::dex::model::*;
use anyhow::{bail, Result};
use rayon::prelude::*;
use reader::Reader;
use std::collections::HashSet;

const NO_INDEX: u32 = 0xffff_ffff;
const ACC_FINAL: u32 = 0x10;
const ACC_VOLATILE: u32 = 0x40;

/// A parsed code_item: `(registers, ins, decoded instructions, address→line)`.
type CodeItem = (u32, u32, Vec<Insn>, Vec<(u32, u32)>, Vec<(u32, u32, u32)>);

// --- instruction widths (code units) --------------------------------------
const fn build_widths() -> [u8; 256] {
    let mut w = [1u8; 256];
    w[0x02] = 2; w[0x03] = 3; w[0x05] = 2; w[0x06] = 3; w[0x08] = 2; w[0x09] = 3;
    w[0x13] = 2; w[0x14] = 3; w[0x15] = 2; w[0x16] = 2; w[0x17] = 3; w[0x18] = 5; w[0x19] = 2;
    w[0x1a] = 2; w[0x1b] = 3; w[0x1c] = 2;
    w[0x1f] = 2; w[0x20] = 2; w[0x22] = 2; w[0x23] = 2; w[0x24] = 3; w[0x25] = 3; w[0x26] = 3;
    w[0x29] = 2; w[0x2a] = 3; w[0x2b] = 3; w[0x2c] = 3;
    let mut i = 0x2d; while i <= 0x31 { w[i] = 2; i += 1; }
    i = 0x32; while i <= 0x37 { w[i] = 2; i += 1; }
    i = 0x38; while i <= 0x3d { w[i] = 2; i += 1; }
    i = 0x44; while i <= 0x51 { w[i] = 2; i += 1; }
    i = 0x52; while i <= 0x5f { w[i] = 2; i += 1; }
    i = 0x60; while i <= 0x6d { w[i] = 2; i += 1; }
    i = 0x6e; while i <= 0x72 { w[i] = 3; i += 1; }
    i = 0x74; while i <= 0x78 { w[i] = 3; i += 1; }
    i = 0x90; while i <= 0xaf { w[i] = 2; i += 1; }
    i = 0xd0; while i <= 0xd7 { w[i] = 2; i += 1; }
    i = 0xd8; while i <= 0xe2 { w[i] = 2; i += 1; }
    w[0xfa] = 4; w[0xfb] = 4; w[0xfc] = 3; w[0xfd] = 3; w[0xfe] = 2; w[0xff] = 2;
    w
}
const WIDTHS: [u8; 256] = build_widths();

/// Absolute code-unit offset of a branch relative to instruction `i`.
fn rel(i: usize, off: i32) -> u32 {
    (i as i64 + off as i64).max(0) as u32
}

/// Case targets of a switch at `i`, read from its payload; empty if malformed.
fn switch_targets(u: &[u16], i: usize, packed: bool) -> Vec<u32> {
    let rel_off = (u[i + 1] as u32 | (u[i + 2] as u32) << 16) as i32;
    let p = i as i64 + rel_off as i64;
    if p < 0 || p as usize + 2 > u.len() {
        return Vec::new();
    }
    let p = p as usize;
    let size = u[p + 1] as usize;
    let i32_at = |k: usize| -> Option<i32> { u.get(k + 1).map(|hi| (u[k] as u32 | (*hi as u32) << 16) as i32) };
    // packed: ident, size, first_key(2), targets(2*size); sparse: ident, size, keys(2*size), targets(2*size)
    let first = if packed { p + 4 } else { p + 2 + 2 * size };
    (0..size).filter_map(|k| i32_at(first + 2 * k)).map(|t| rel(i, t)).collect()
}

fn insn_width(insns: &[u16], i: usize) -> Option<usize> {
    let u0 = *insns.get(i)?;
    if (u0 & 0xff) == 0x00 {
        return Some(match u0 {
            0x0000 => 1,
            0x0100 => (*insns.get(i + 1)? as usize) * 2 + 4,
            0x0200 => (*insns.get(i + 1)? as usize) * 4 + 2,
            0x0300 => {
                let ew = *insns.get(i + 1)? as usize;
                let count = (*insns.get(i + 2)? as usize) | ((*insns.get(i + 3)? as usize) << 16);
                (count * ew).div_ceil(2) + 4
            }
            _ => 1,
        });
    }
    Some(WIDTHS[(u0 & 0xff) as usize] as usize)
}

// --- public entry ----------------------------------------------------------

/// Parse a DEX image (single section or v41 container) into the model.
pub fn parse_dex_bytes(data: &[u8]) -> Result<Dex> {
    if data.len() < 0x70 || &data[0..4] != b"dex\n" {
        bail!("not a dex file (bad magic)");
    }
    let bound = if dex_version(data) >= 41 {
        u32_at(data, 0x70)? as usize
    } else {
        u32_at(data, 0x20)? as usize
    }
    .min(data.len());

    // Shared string pool (all container sections point at the same one). Built once,
    // in parallel — otherwise the single biggest serial cost.
    let r0 = Reader::new(data);
    let string_ids_size = u32_at(data, 0x38)? as usize;
    let string_ids_off = u32_at(data, 0x3c)? as usize;
    let strings: Vec<String> = (0..string_ids_size)
        .into_par_iter()
        .map(|k| r0.string_data_at(u32_at(data, string_ids_off + k * 4)? as usize))
        .collect::<Result<Vec<_>>>()?;

    let mut dex = Dex::default();
    let mut off = 0usize;
    while off + 0x70 <= bound && &data[off..off + 4] == b"dex\n" {
        let p = Section::new(data, off, &strings)?;
        let (classes, final_vol) = p.run()?;
        dex.classes.extend(classes);
        dex.final_or_volatile_fields.extend(final_vol);
        let file_size = u32_at(data, off + 0x20)? as usize;
        if file_size == 0 {
            break;
        }
        off += file_size;
    }
    Ok(dex)
}

fn dex_version(data: &[u8]) -> u32 {
    std::str::from_utf8(&data[4..7]).ok().and_then(|s| s.trim_end_matches('\0').parse().ok()).unwrap_or(0)
}

fn u32_at(data: &[u8], off: usize) -> Result<u32> {
    if off + 4 > data.len() {
        bail!("u32 read past end at {off}");
    }
    Ok(u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]))
}

// --- one DEX section -------------------------------------------------------

struct Section<'a> {
    r: Reader<'a>,
    strings: &'a [String],
    types: Vec<u32>,
    proto_ids_off: usize,
    field_ids_off: usize,
    method_ids_off: usize,
    class_defs_off: usize,
    class_defs_size: usize,
}

impl<'a> Section<'a> {
    fn new(data: &'a [u8], base: usize, strings: &'a [String]) -> Result<Self> {
        let r = Reader::new(data);
        let type_ids_size = r.u32_at(base + 0x40)? as usize;
        let type_ids_off = r.u32_at(base + 0x44)? as usize;
        let mut types = Vec::with_capacity(type_ids_size);
        for k in 0..type_ids_size {
            types.push(r.u32_at(type_ids_off + k * 4)?);
        }
        Ok(Section {
            proto_ids_off: r.u32_at(base + 0x4c)? as usize,
            field_ids_off: r.u32_at(base + 0x54)? as usize,
            method_ids_off: r.u32_at(base + 0x5c)? as usize,
            class_defs_size: r.u32_at(base + 0x60)? as usize,
            class_defs_off: r.u32_at(base + 0x64)? as usize,
            r,
            strings,
            types,
        })
    }

    fn s(&self, i: u32) -> &str {
        self.strings.get(i as usize).map(|x| x.as_str()).unwrap_or("")
    }
    fn type_desc(&self, i: u32) -> &str {
        self.types.get(i as usize).map(|&si| self.s(si)).unwrap_or("")
    }
    fn type_dotted(&self, i: u32) -> String {
        descriptor_to_dotted(self.type_desc(i))
    }

    /// field_id -> (declaring class dotted, field name, dotted/raw type descriptor).
    fn field(&self, i: u32) -> Result<(String, String, String)> {
        let base = self.field_ids_off + i as usize * 8;
        let class_idx = self.r.u16_at(base)? as u32;
        let type_idx = self.r.u16_at(base + 2)? as u32;
        let name_idx = self.r.u32_at(base + 4)?;
        let ty = self.type_desc(type_idx);
        let ty = if ty.starts_with('L') && ty.ends_with(';') { descriptor_to_dotted(ty) } else { ty.to_string() };
        Ok((self.type_dotted(class_idx), self.s(name_idx).to_string(), ty))
    }

    /// method_id -> (declaring class dotted, name, JVM descriptor).
    fn method(&self, i: u32) -> Result<(String, String, String)> {
        let base = self.method_ids_off + i as usize * 8;
        let class_idx = self.r.u16_at(base)? as u32;
        let proto_idx = self.r.u16_at(base + 2)? as u32;
        let name_idx = self.r.u32_at(base + 4)?;
        Ok((self.type_dotted(class_idx), self.s(name_idx).to_string(), self.proto_sig(proto_idx)?))
    }

    fn proto_sig(&self, proto_idx: u32) -> Result<String> {
        let base = self.proto_ids_off + proto_idx as usize * 12;
        let ret_idx = self.r.u32_at(base + 4)?;
        let params_off = self.r.u32_at(base + 8)? as usize;
        let mut d = String::from("(");
        if params_off != 0 {
            let n = self.r.u32_at(params_off)? as usize;
            for k in 0..n {
                let ti = self.r.u16_at(params_off + 4 + k * 2)? as u32;
                d.push_str(self.type_desc(ti));
            }
        }
        d.push(')');
        d.push_str(self.type_desc(ret_idx));
        Ok(d)
    }

    fn run(&self) -> Result<(Vec<Class>, HashSet<String>)> {
        let parsed = (0..self.class_defs_size)
            .into_par_iter()
            .map(|k| self.parse_class(k))
            .collect::<Result<Vec<_>>>()?;
        let mut classes = Vec::with_capacity(parsed.len());
        let mut final_vol = HashSet::new();
        for (c, fv) in parsed {
            classes.push(c);
            final_vol.extend(fv);
        }
        Ok((classes, final_vol))
    }

    fn parse_class(&self, k: usize) -> Result<(Class, HashSet<String>)> {
        let base = self.class_defs_off + k * 32;
        let class_idx = self.r.u32_at(base)?;
        let superclass_idx = self.r.u32_at(base + 8)?;
        let interfaces_off = self.r.u32_at(base + 12)? as usize;
        let source_file_idx = self.r.u32_at(base + 16)?;
        let class_data_off = self.r.u32_at(base + 24)? as usize;

        let descriptor = self.type_dotted(class_idx);
        let super_class = (superclass_idx != NO_INDEX).then(|| self.type_dotted(superclass_idx));
        let source_file = (source_file_idx != NO_INDEX).then(|| self.s(source_file_idx).to_string());
        let mut interfaces = Vec::new();
        if interfaces_off != 0 {
            let n = self.r.u32_at(interfaces_off)? as usize;
            for j in 0..n {
                interfaces.push(self.type_dotted(self.r.u16_at(interfaces_off + 4 + j * 2)? as u32));
            }
        }

        let (methods, final_vol) = if class_data_off == 0 {
            (Vec::new(), HashSet::new())
        } else {
            self.parse_class_data(class_data_off, &descriptor, source_file.as_deref())?
        };
        Ok((Class { descriptor, super_class, interfaces, methods }, final_vol))
    }

    fn parse_class_data(
        &self,
        off: usize,
        class_name: &str,
        source_file: Option<&str>,
    ) -> Result<(Vec<Method>, HashSet<String>)> {
        let mut rd = Reader { data: self.r.data, pos: off };
        let static_fields = rd.uleb128()?;
        let instance_fields = rd.uleb128()?;
        let direct_methods = rd.uleb128()?;
        let virtual_methods = rd.uleb128()?;

        // fields: keep `Class.field` for final/volatile (excluded from race analysis).
        let mut final_vol = HashSet::new();
        for group in [static_fields, instance_fields] {
            let mut field_idx: u32 = 0;
            for j in 0..group {
                let diff = rd.uleb128()?;
                field_idx = if j == 0 { diff } else { field_idx + diff };
                let access = rd.uleb128()?;
                if access & (ACC_FINAL | ACC_VOLATILE) != 0 {
                    let (fclass, fname, _) = self.field(field_idx)?;
                    final_vol.insert(format!("{fclass}.{fname}"));
                }
            }
        }

        let mut methods = Vec::with_capacity((direct_methods + virtual_methods) as usize);
        for group in [direct_methods, virtual_methods] {
            let mut method_idx: u32 = 0;
            for j in 0..group {
                let diff = rd.uleb128()?;
                method_idx = if j == 0 { diff } else { method_idx + diff };
                let access = rd.uleb128()?;
                let code_off = rd.uleb128()? as usize;
                let (mclass, name, sig) = self.method(method_idx)?;
                let (registers, ins, insns, positions, catches) =
                    if code_off == 0 { (0, 0, Vec::new(), Vec::new(), Vec::new()) } else { self.parse_code(code_off)? };
                methods.push(Method {
                    class: mclass,
                    name,
                    sig,
                    access,
                    registers,
                    ins,
                    insns,
                    positions,
                    catches,
                    source_file: source_file.map(str::to_string),
                });
            }
        }
        // `class_name` names the declaring class; method class comes from method_ids
        // (identical for defined methods) — keep the argument for symmetry/debugging.
        let _ = class_name;
        Ok((methods, final_vol))
    }

    fn parse_code(&self, off: usize) -> Result<CodeItem> {
        let r = &self.r;
        let registers = r.u16_at(off)? as u32;
        let ins = r.u16_at(off + 2)? as u32;
        let debug_info_off = r.u32_at(off + 8)? as usize;
        let insns_size = r.u32_at(off + 12)? as usize;
        let insns_start = off + 16;
        let mut units: Vec<u16> = Vec::with_capacity(insns_size);
        for k in 0..insns_size {
            units.push(r.u16_at(insns_start + k * 2)?);
        }

        let mut insns = Vec::new();
        let mut i = 0usize;
        while i < units.len() {
            let w = match insn_width(&units, i) {
                Some(w) if w > 0 => w,
                _ => break,
            };
            // A truncated tail instruction (fewer code units than its width) would
            // make decode() read past the end; stop rather than index out of bounds.
            if i + w > units.len() {
                break;
            }
            let u0 = units[i];
            let is_payload = (u0 & 0xff) == 0 && u0 != 0;
            if !is_payload {
                insns.push(Insn { offset: i as u32, op: self.decode(&units, i)? });
            }
            i += w;
        }

        let positions =
            if debug_info_off == 0 { Vec::new() } else { self.debug_positions(debug_info_off).unwrap_or_default() };
        let tries_size = r.u16_at(off + 6)? as usize;
        let catches = if tries_size == 0 {
            Vec::new()
        } else {
            let tries_off = insns_start + insns_size * 2 + if insns_size % 2 == 1 { 2 } else { 0 };
            self.catches(tries_off, tries_size).unwrap_or_default()
        };
        Ok((registers, ins, insns, positions, catches))
    }

    /// The try items and their encoded handlers: every `(start, end, handler)` in
    /// code units, catch-all included. `tries_off` is the (4-aligned) try list.
    fn catches(&self, tries_off: usize, tries_size: usize) -> Result<Vec<(u32, u32, u32)>> {
        let r = &self.r;
        let list_off = tries_off + tries_size * 8;
        let mut out = Vec::new();
        for t in 0..tries_size {
            let base = tries_off + t * 8;
            let start = r.u32_at(base)?;
            let count = r.u16_at(base + 4)? as u32;
            let handler_off = r.u16_at(base + 6)? as usize;
            let mut h = Reader::new(r.data);
            h.pos = list_off + handler_off;
            let size = h.sleb128()?;
            for _ in 0..size.unsigned_abs() {
                let _type_idx = h.uleb128()?;
                out.push((start, start + count, h.uleb128()?));
            }
            if size <= 0 {
                out.push((start, start + count, h.uleb128()?));
            }
        }
        Ok(out)
    }

    /// Map one instruction to the model `Op`, matching the textual dexdump parser.
    fn decode(&self, u: &[u16], i: usize) -> Result<Op> {
        let u0 = u[i];
        let op = (u0 & 0xff) as u8;
        let aa = ((u0 >> 8) & 0xff) as u32;
        let a = ((u0 >> 8) & 0xf) as u32;
        let b = ((u0 >> 12) & 0xf) as u32;
        Ok(match op {
            0x1d => Op::MonitorEnter(aa),
            0x1e => Op::MonitorExit(aa),
            // move (12x / 22x / 32x), incl. -wide and -object width variants
            0x01 | 0x04 | 0x07 => Op::Move { dst: a, src: b },
            0x02 | 0x05 | 0x08 => Op::Move { dst: aa, src: u[i + 1] as u32 },
            0x03 | 0x06 | 0x09 => Op::Move { dst: u[i + 1] as u32, src: u[i + 2] as u32 },
            0x0a..=0x0c => Op::MoveResult { dst: aa }, // move-result / -wide / -object
            0x0e..=0x10 => Op::Return(None),           // return-void / return / -wide
            0x11 => Op::Return(Some(aa)),              // return-object
            0x1c => Op::ConstClass { dst: aa, class: self.type_dotted(u[i + 1] as u32) },
            0x22 => Op::NewInstance { dst: aa, class: self.type_dotted(u[i + 1] as u32) },
            0x27 => Op::Throw,
            // goto (+AA), goto/16 (+AAAA), goto/32 (+AAAAAAAA): signed code-unit offsets.
            0x28 => Op::Goto(rel(i, (aa as u8) as i8 as i32)),
            0x29 => Op::Goto(rel(i, u[i + 1] as i16 as i32)),
            0x2a => Op::Goto(rel(i, (u[i + 1] as u32 | (u[i + 2] as u32) << 16) as i32)),
            // packed-switch / sparse-switch: targets live in a payload at +BBBBBBBB.
            0x2b | 0x2c => Op::Switch(switch_targets(u, i, op == 0x2b)),
            // if-test vA, vB, +CCCC / if-testz vAA, +BBBB
            0x32..=0x3d => Op::Branch(rel(i, u[i + 1] as i16 as i32)),
            0x52..=0x58 => {
                let (class, field, ty) = self.field(u[i + 1] as u32)?;
                Op::Iget { dst: a, base: b, class, field, ty: Some(ty) }
            }
            0x59..=0x5f => {
                let (class, field, _) = self.field(u[i + 1] as u32)?;
                Op::Iput { src: a, base: b, class, field }
            }
            0x60..=0x66 => {
                let (class, field, _) = self.field(u[i + 1] as u32)?;
                Op::Sget { dst: aa, class, field }
            }
            0x67..=0x6d => {
                let (class, field, _) = self.field(u[i + 1] as u32)?;
                Op::Sput { src: aa, class, field }
            }
            0x6e..=0x72 => self.invoke(op, u, i, false)?,
            0x74..=0x78 => self.invoke(op, u, i, true)?,
            // Everything else (const*, arith, aget/aput, ...) is
            // `Other`, exactly as the textual path treats it (the resolve path ignores
            // goto/branch/throw/monitor-exit and never clears a register on Other).
            _ => Op::Other,
        })
    }

    fn invoke(&self, op: u8, u: &[u16], i: usize, range: bool) -> Result<Op> {
        let kind = match op {
            0x6f | 0x75 => InvokeKind::Super,
            0x70 | 0x76 => InvokeKind::Direct,
            0x71 | 0x77 => InvokeKind::Static,
            0x72 | 0x78 => InvokeKind::Interface,
            _ => InvokeKind::Virtual, // 0x6e / 0x74
        };
        let method_idx = u[i + 1] as u32;
        let args: Vec<Reg> = if range {
            let count = (u[i] >> 8) & 0xff;
            let first = u[i + 2] as u32;
            (0..count as u32).map(|k| first + k).collect()
        } else {
            let count = ((u[i] >> 12) & 0xf) as usize;
            let u2 = u[i + 2];
            let regs = [
                (u2 & 0xf) as u32,
                ((u2 >> 4) & 0xf) as u32,
                ((u2 >> 8) & 0xf) as u32,
                ((u2 >> 12) & 0xf) as u32,
                ((u[i] >> 8) & 0xf) as u32,
            ];
            regs[..count.min(5)].to_vec()
        };
        let (class, name, sig) = self.method(method_idx)?;
        Ok(Op::Invoke(Invoke { kind, args, class, name, sig }))
    }

    /// Debug line program -> `(code_offset, line)` ascending.
    fn debug_positions(&self, off: usize) -> Result<Vec<(u32, u32)>> {
        let mut rd = Reader { data: self.r.data, pos: off };
        let mut line = rd.uleb128()? as i64;
        let params = rd.uleb128()?;
        for _ in 0..params {
            rd.uleb128p1()?;
        }
        let mut address: u32 = 0;
        let mut out = Vec::new();
        const LINE_BASE: i64 = -4;
        const LINE_RANGE: i64 = 15;
        loop {
            let opcode = rd.u8()?;
            match opcode {
                0x00 => break,
                0x01 => address += rd.uleb128()?,
                0x02 => line += rd.sleb128()? as i64,
                0x03 => { rd.uleb128()?; rd.uleb128p1()?; rd.uleb128p1()?; }
                0x04 => { rd.uleb128()?; rd.uleb128p1()?; rd.uleb128p1()?; rd.uleb128p1()?; }
                0x05 | 0x06 => { rd.uleb128()?; }
                0x07 | 0x08 => {}
                0x09 => { rd.uleb128p1()?; }
                _ => {
                    let adjusted = opcode as i64 - 0x0a;
                    address += (adjusted / LINE_RANGE) as u32;
                    line += LINE_BASE + (adjusted % LINE_RANGE);
                    if line >= 0 {
                        out.push((address, line as u32));
                    }
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_spot_check() {
        assert_eq!(WIDTHS[0x1d], 1); // monitor-enter (11x)
        assert_eq!(WIDTHS[0x52], 2); // iget (22c)
        assert_eq!(WIDTHS[0x60], 2); // sget (21c)
        assert_eq!(WIDTHS[0x6e], 3); // invoke-virtual (35c)
        assert_eq!(WIDTHS[0x74], 3); // invoke-virtual/range (3rc)
        assert_eq!(WIDTHS[0x18], 5); // const-wide (51l)
        assert_eq!(WIDTHS[0x00], 1); // nop
    }

    #[test]
    fn insn_width_payloads() {
        // packed-switch-payload: ident 0x0100, size 3 -> 3*2 + 4 = 10 units
        assert_eq!(insn_width(&[0x0100, 3], 0), Some(10));
        // sparse-switch-payload: ident 0x0200, size 2 -> 2*4 + 2 = 10 units
        assert_eq!(insn_width(&[0x0200, 2], 0), Some(10));
        // fill-array-data-payload: ident 0x0300, ew 1, count 5 -> ceil(5/2) + 4 = 7
        assert_eq!(insn_width(&[0x0300, 1, 5, 0], 0), Some(7));
        assert_eq!(insn_width(&[0x0000], 0), Some(1)); // plain nop
        assert_eq!(insn_width(&[0x001d], 0), Some(1)); // monitor-enter v0
    }

    #[test]
    fn version_parse() {
        assert_eq!(dex_version(b"dex\n041\0"), 41);
        assert_eq!(dex_version(b"dex\n035\0"), 35);
    }
}
