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

//! Dex front-end: shell out to `dexdump -d` and parse its fully-decoded textual
//! disassembly into our [`Dex`] model. `dexdump` decodes instructions to a stable,
//! readable form (`monitor-enter v0`, `iget-object v0, v1, Lcls;.f:Lt;`,
//! `invoke-static {}, Lcls;.m:()V`), which this module parses line by line.

use crate::dex::model::*;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Locate the `dexdump` binary: `$DEXLOCK_DEXDUMP`, else `dexdump` on `PATH`.
pub fn dexdump_bin() -> String {
    std::env::var("DEXLOCK_DEXDUMP").unwrap_or_else(|_| "dexdump".to_string())
}

pub fn parse_dex(path: &Path) -> Result<Dex> {
    let out = Command::new(dexdump_bin())
        .arg("-d")
        .arg(path)
        .output()
        .with_context(|| format!("running dexdump on {}", path.display()))?;
    if !out.status.success() {
        anyhow::bail!(
            "dexdump failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut dex = parse_dexdump_text(&text);
    dex.final_or_volatile_fields = scan_field_flags(&text);
    Ok(dex)
}

/// Collect `Class.field` keys declared `final` or `volatile`, scanning the field
/// sections independently of the method parser (those fields are not race
/// candidates: final is write-once, volatile is lock-free by design).
fn scan_field_flags(text: &str) -> std::collections::HashSet<String> {
    const ACC_FINAL: u32 = 0x10;
    const ACC_VOLATILE: u32 = 0x40;
    let mut out = std::collections::HashSet::new();
    let mut class: Option<String> = None;
    let mut in_fields = false;
    let mut name: Option<String> = None;
    for raw in text.lines() {
        let t = raw.trim();
        if let Some(rest) = t.strip_prefix("Class descriptor") {
            class = Some(descriptor_to_dotted(&quoted(rest)));
            in_fields = false;
            name = None;
        } else if t.starts_with("Static fields") || t.starts_with("Instance fields") {
            in_fields = true;
            name = None;
        } else if t.starts_with("Direct methods") || t.starts_with("Virtual methods") {
            in_fields = false;
        } else if in_fields {
            if let Some(rest) = t.strip_prefix("name") {
                name = Some(quoted(rest));
            } else if let Some(rest) = t.strip_prefix("access") {
                let flags = hex_after_colon(rest);
                if let (Some(n), Some(c)) = (name.take(), class.as_ref()) {
                    if flags & (ACC_FINAL | ACC_VOLATILE) != 0 {
                        out.insert(format!("{c}.{n}"));
                    }
                }
            }
        }
    }
    out
}

/// Parse the textual output of `dexdump -d`.
pub fn parse_dexdump_text(text: &str) -> Dex {
    let mut dex = Dex::default();
    let mut cur_class: Option<Class> = None;
    let mut cur_method: Option<Method> = None;
    let mut source_file: Option<String> = None;
    // Header fields appear BEFORE the `[addr] FQN` body line that creates the
    // method, so they are stashed and applied at method creation. dexdump always
    // emits one such header per method, so each field is overwritten before the
    // next method is created — no reset at method/class boundaries is needed.
    let mut pending_access: u32 = 0;
    let mut pending_registers: u32 = 0;
    let mut pending_ins: u32 = 0;
    let mut in_positions = false;
    let mut in_interfaces = false;
    let mut in_catches = false;
    let mut pending_try: Option<(u32, u32)> = None;

    let flush_method = |cur_method: &mut Option<Method>, cur_class: &mut Option<Class>| {
        if let (Some(m), Some(c)) = (cur_method.take(), cur_class.as_mut()) {
            c.methods.push(m);
        }
    };
    let flush_class = |cur_class: &mut Option<Class>, dex: &mut Dex| {
        if let Some(c) = cur_class.take() {
            dex.classes.push(c);
        }
    };

    for raw in text.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();

        // ---- class boundary ------------------------------------------------
        if let Some(rest) = trimmed.strip_prefix("Class descriptor") {
            flush_method(&mut cur_method, &mut cur_class);
            flush_class(&mut cur_class, &mut dex);
            in_positions = false;
            let desc = quoted(rest);
            cur_class = Some(Class {
                descriptor: descriptor_to_dotted(&desc),
                super_class: None,
                interfaces: Vec::new(),
                methods: Vec::new(),
            });
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Superclass") {
            if let Some(c) = cur_class.as_mut() {
                c.super_class = Some(descriptor_to_dotted(&quoted(rest)));
            }
            in_interfaces = false;
            continue;
        }
        if trimmed.starts_with("Interfaces") {
            in_interfaces = true;
            continue;
        }
        if in_interfaces {
            // "#0              : 'Ljava/lang/Runnable;'"
            if trimmed.starts_with('#') && trimmed.contains('\'') {
                if let Some(c) = cur_class.as_mut() {
                    c.interfaces.push(descriptor_to_dotted(&quoted(trimmed)));
                }
                continue;
            }
            in_interfaces = false; // fell through to next section
        }
        if let Some(rest) = trimmed.strip_prefix("source_file_idx") {
            // e.g. "source_file_idx   : #5 (T01_SimpleABBA.java)"
            source_file = paren(rest);
            continue;
        }
        // method header access flag (applies to the next body)
        if let Some(rest) = trimmed.strip_prefix("access") {
            pending_access = hex_after_colon(rest);
            continue;
        }

        // ---- positions (line table) ----------------------------------------
        if trimmed.starts_with("positions") {
            in_positions = true;
            in_catches = false;
            continue;
        }
        if trimmed.starts_with("catches") {
            in_positions = false;
            in_catches = true;
            pending_try = None;
            continue;
        }
        if trimmed.starts_with("locals") {
            in_positions = false;
            in_catches = false;
            continue;
        }
        if in_catches {
            // "0x0008 - 0x001e" (try range) then "<any> -> 0x0022" (handler).
            if let Some((s, e)) = parse_try_range(trimmed) {
                pending_try = Some((s, e));
            } else if let Some(handler) = parse_handler(trimmed) {
                if let (Some((s, e)), Some(m)) = (pending_try, cur_method.as_mut()) {
                    m.catches.push((s, e, handler));
                }
            }
            continue;
        }
        if in_positions {
            // "0x0000 line=5"
            if let Some((off, line_no)) = parse_position(trimmed) {
                if let Some(m) = cur_method.as_mut() {
                    m.positions.push((off, line_no));
                }
            }
            continue;
        }

        // ---- body lines (contain a '|') ------------------------------------
        if let Some(idx) = line.find('|') {
            let right = line[idx + 1..].trim_start();
            // method header: "[000160] corpus.Foo.bar:()V"
            if let Some(after) = right.strip_prefix('[') {
                flush_method(&mut cur_method, &mut cur_class);
                in_positions = false;
                in_catches = false;
                if let Some(close) = after.find(']') {
                    let fqn_sig = after[close + 1..].trim();
                    if let Some((class, name, sig)) = split_fqn_sig(fqn_sig) {
                        cur_method = Some(Method {
                            class,
                            name,
                            sig,
                            access: pending_access,
                            registers: pending_registers,
                            ins: pending_ins,
                            insns: Vec::new(),
                            positions: Vec::new(),
                            catches: Vec::new(),
                            source_file: source_file.clone(),
                        });
                    }
                }
                continue;
            }
            // instruction: "0006: invoke-static {}, Lcls;.m:()V // method@4"
            if let Some((offset, body)) = split_insn(right) {
                if let Some(m) = cur_method.as_mut() {
                    let op = parse_insn(body);
                    m.insns.push(Insn { offset, op });
                }
            }
            continue;
        }

        // ---- registers / ins counts (stashed for the next method body) ------
        if let Some(rest) = trimmed.strip_prefix("registers") {
            pending_registers = num_after_colon(rest);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("ins ") {
            pending_ins = num_after_colon(rest);
            continue;
        }
    }
    flush_method(&mut cur_method, &mut cur_class);
    flush_class(&mut cur_class, &mut dex);
    dex
}

// --------------------------------------------------------------------------
// instruction decoding
// --------------------------------------------------------------------------

/// `right` is the text after `|`. Returns (offset, instruction-body without comment).
fn split_insn(right: &str) -> Option<(u32, &str)> {
    let colon = right.find(':')?;
    let off = u32::from_str_radix(right[..colon].trim(), 16).ok()?;
    let mut body = right[colon + 1..].trim();
    if let Some(c) = body.find(" // ") {
        body = body[..c].trim_end();
    }
    Some((off, body))
}

fn parse_insn(body: &str) -> Op {
    let mut parts = body.splitn(2, char::is_whitespace);
    let mnem = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("").trim();

    match mnem {
        "monitor-enter" => reg(rest).map(Op::MonitorEnter).unwrap_or(Op::Other),
        "monitor-exit" => reg(rest).map(Op::MonitorExit).unwrap_or(Op::Other),
        _ if mnem.starts_with("const-class") => {
            // "v0, Lcls;"
            let (dst, t) = two_then_type(rest);
            match (dst, t) {
                (Some(dst), Some(class)) => Op::ConstClass { dst, class },
                _ => Op::Other,
            }
        }
        _ if mnem.starts_with("new-instance") => {
            let (dst, t) = two_then_type(rest);
            match (dst, t) {
                (Some(dst), Some(class)) => Op::NewInstance { dst, class },
                _ => Op::Other,
            }
        }
        _ if mnem.starts_with("sget") => {
            // "v0, Lcls;.field:type"
            let mut it = rest.splitn(2, ',');
            let dst = it.next().and_then(reg);
            let fref = it.next().map(str::trim).and_then(parse_field_ref);
            match (dst, fref) {
                (Some(dst), Some((class, field))) => Op::Sget { dst, class, field },
                (Some(dst), None) => Op::Def(dst),
                _ => Op::Other,
            }
        }
        _ if mnem.starts_with("iget") => {
            // "v0, v1, Lcls;.field:type"
            let mut it = rest.splitn(3, ',');
            let dst = it.next().and_then(reg);
            let base = it.next().and_then(reg);
            let raw = it.next().map(str::trim);
            let fref = raw.and_then(parse_field_ref);
            let ty = raw.and_then(parse_field_type);
            match (dst, base, fref) {
                (Some(dst), Some(base), Some((class, field))) => {
                    Op::Iget { dst, base, class, field, ty }
                }
                (Some(dst), _, _) => Op::Def(dst),
                _ => Op::Other,
            }
        }
        _ if mnem.starts_with("iput") => {
            // "v0, v1, Lcls;.field:type"  (src, base, field)
            let mut it = rest.splitn(3, ',');
            let src = it.next().and_then(reg);
            let base = it.next().and_then(reg);
            let fref = it.next().map(str::trim).and_then(parse_field_ref);
            match (src, base, fref) {
                (Some(src), Some(base), Some((class, field))) => Op::Iput { src, base, class, field },
                _ => Op::Other,
            }
        }
        "move-result-object" | "move-result" | "move-result-wide" => {
            reg(rest).map(|dst| Op::MoveResult { dst }).unwrap_or(Op::Other)
        }
        _ if mnem.starts_with("move-object") || mnem == "move" || mnem.starts_with("move/")
            || mnem.starts_with("move-wide") =>
        {
            let mut it = rest.splitn(2, ',');
            let dst = it.next().and_then(reg);
            let src = it.next().and_then(reg);
            match (dst, src) {
                (Some(dst), Some(src)) => Op::Move { dst, src },
                (Some(dst), None) => Op::Def(dst),
                _ => Op::Other,
            }
        }
        "return-object" => Op::Return(reg(rest)),
        "return-void" | "return" | "return-wide" => Op::Return(None),
        "throw" => Op::Throw,
        _ if mnem.starts_with("goto") => branch_target(rest).map(Op::Goto).unwrap_or(Op::Other),
        _ if mnem.starts_with("if-") => branch_target(rest).map(Op::Branch).unwrap_or(Op::Other),
        _ if mnem.starts_with("invoke") => parse_invoke(mnem, rest),
        // Unmodeled opcode: in practice it never defines a lock-typed register, so
        // treating it as opaque is safe (the dst-clearing forms are handled above).
        _ => Op::Other,
    }
}

/// The branch target of a `goto`/`if-*` operand — the last hex token before the
/// disassembler comment (`v0, 0014 // +0009` -> `0x0014`, an absolute code offset).
fn branch_target(s: &str) -> Option<u32> {
    let operands = s.split("//").next().unwrap_or(s);
    let tok = operands.split(|c: char| c == ',' || c.is_whitespace()).rfind(|t| !t.is_empty())?;
    u32::from_str_radix(tok, 16).ok()
}

fn parse_invoke(mnem: &str, rest: &str) -> Op {
    let kind = if mnem.contains("direct") {
        InvokeKind::Direct
    } else if mnem.contains("static") {
        InvokeKind::Static
    } else if mnem.contains("interface") {
        InvokeKind::Interface
    } else if mnem.contains("super") {
        InvokeKind::Super
    } else {
        InvokeKind::Virtual
    };
    // rest = "{v1, v2}, Lcls;.name:sig"  (or "{v1 .. v4}" for /range)
    let close = match rest.find('}') {
        Some(c) => c,
        None => return Op::Other,
    };
    let regs_str = rest[..close].trim_start_matches('{');
    let args = parse_reg_list(regs_str);
    let mref = rest[close + 1..].trim_start_matches(',').trim();
    match parse_method_ref(mref) {
        Some((class, name, sig)) => Op::Invoke(Invoke { kind, args, class, name, sig }),
        None => Op::Other,
    }
}

// --------------------------------------------------------------------------
// small parsers / helpers
// --------------------------------------------------------------------------

fn reg(s: &str) -> Option<Reg> {
    let s = s.trim();
    s.strip_prefix('v').and_then(|n| n.parse().ok())
}

/// "v0, Lcls;" -> (Some(0), Some("dotted"))
fn two_then_type(rest: &str) -> (Option<Reg>, Option<String>) {
    let mut it = rest.splitn(2, ',');
    let dst = it.next().and_then(reg);
    let ty = it
        .next()
        .map(str::trim)
        .filter(|t| t.starts_with('L'))
        .map(descriptor_to_dotted);
    (dst, ty)
}

fn parse_reg_list(s: &str) -> Vec<Reg> {
    let s = s.trim();
    if s.is_empty() {
        return Vec::new();
    }
    if let Some((a, b)) = s.split_once("..") {
        // range form "v1 .. v4". A real invoke/range spans at most 256 registers;
        // bound the span so a garbled operand can't request a multi-GB allocation.
        if let (Some(lo), Some(hi)) = (reg(a), reg(b)) {
            if hi >= lo && hi - lo < 256 {
                return (lo..=hi).collect();
            }
            return Vec::new();
        }
    }
    s.split(',').filter_map(reg).collect()
}

/// "Lcls;.field:type" -> (dotted class, field)
fn parse_field_ref(s: &str) -> Option<(String, String)> {
    let s = s.trim();
    let sep = s.find(";.")?;
    let class = descriptor_to_dotted(&s[..=sep]); // include ';'
    let after = &s[sep + 2..];
    let name = after.split(':').next()?.to_string();
    Some((class, name))
}

/// Extract a field's declared type from `Lcls;.name:type`. Object types
/// (`Lcom/example/Uri;`) are returned dotted; primitives (`I`, `Z`, `[I`, ...)
/// are returned verbatim.
fn parse_field_type(s: &str) -> Option<String> {
    let s = s.trim();
    let sep = s.find(";.")?;
    let after = &s[sep + 2..];
    let ty = after.split(':').nth(1)?.trim();
    if ty.is_empty() {
        return None;
    }
    if ty.starts_with('L') && ty.ends_with(';') {
        Some(descriptor_to_dotted(ty))
    } else {
        Some(ty.to_string())
    }
}

/// "Lcls;.name:sig" -> (dotted class, name, sig)
fn parse_method_ref(s: &str) -> Option<(String, String, String)> {
    let s = s.trim();
    let sep = s.find(";.")?;
    let class = descriptor_to_dotted(&s[..=sep]);
    let after = &s[sep + 2..];
    let colon = after.find(':')?;
    let name = after[..colon].to_string();
    let sig = after[colon + 1..].to_string();
    Some((class, name, sig))
}

/// "corpus.Foo.bar:()V" -> (class, name, sig)
fn split_fqn_sig(s: &str) -> Option<(String, String, String)> {
    let colon = s.find(':')?;
    let fqn = &s[..colon];
    let sig = s[colon + 1..].to_string();
    let dot = fqn.rfind('.')?;
    Some((fqn[..dot].to_string(), fqn[dot + 1..].to_string(), sig))
}

fn parse_position(s: &str) -> Option<(u32, u32)> {
    // "0x0000 line=5"
    let mut it = s.split_whitespace();
    let off = it.next()?;
    let off = off.strip_prefix("0x")?;
    let off = u32::from_str_radix(off, 16).ok()?;
    let line = it.next()?.strip_prefix("line=")?.parse().ok()?;
    Some((off, line))
}

/// A try range: "0x0008 - 0x001e" -> (0x0008, 0x001e). Distinguished from a handler
/// line by the bare `-` separator (a handler uses `->`).
fn parse_try_range(s: &str) -> Option<(u32, u32)> {
    let (a, b) = s.split_once(" - ")?;
    let start = u32::from_str_radix(a.trim().strip_prefix("0x")?, 16).ok()?;
    let end = u32::from_str_radix(b.trim().strip_prefix("0x")?, 16).ok()?;
    Some((start, end))
}

/// A catch handler: "Lcls; -> 0x0022" or "<any> -> 0x0022" -> 0x0022.
fn parse_handler(s: &str) -> Option<u32> {
    let (_, h) = s.rsplit_once("-> ")?;
    u32::from_str_radix(h.trim().strip_prefix("0x")?, 16).ok()
}

/// Extract the contents of the first single-quoted run: `xxx : 'VALUE'` -> VALUE.
fn quoted(s: &str) -> String {
    let mut chars = s.split('\'');
    chars.nth(1).unwrap_or("").to_string()
}

/// Extract `(VALUE)` from a string.
fn paren(s: &str) -> Option<String> {
    let open = s.find('(')?;
    let close = s[open..].find(')')? + open;
    Some(s[open + 1..close].to_string())
}

fn hex_after_colon(s: &str) -> u32 {
    let v = s.split(':').nth(1).unwrap_or("").trim();
    let tok = v.split_whitespace().next().unwrap_or("");
    let tok = tok.strip_prefix("0x").unwrap_or(tok);
    u32::from_str_radix(tok, 16).unwrap_or(0)
}

fn num_after_colon(s: &str) -> u32 {
    s.split(':')
        .nth(1)
        .unwrap_or("")
        .split_whitespace()
        .next()
        .unwrap_or("")
        .parse()
        .unwrap_or(0)
}
