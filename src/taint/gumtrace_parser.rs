use memchr::memmem;
use smallvec::SmallVec;

use super::parser::{
    determine_elem_width, extract_reg_values, find_reg_value, first_data_reg_name,
    parse_hex_u64, parse_operands_into,
};
use super::types::*;

/// Returns true if line doesn't start with `[` (i.e., not an instruction line).
pub fn is_special_line(raw: &str) -> bool {
    !raw.starts_with('[')
}

/// Classification of special (non-instruction) lines in gumtrace output.
#[derive(Debug, Clone)]
pub enum SpecialLine {
    /// `call func: name(args...)` or `call jni func: name(args...)`
    CallFunc {
        name: String,
        is_jni: bool,
        args: Vec<String>,
    },
    /// `args<N>: value`
    Arg { index: String, value: String },
    /// `ret: value`
    Ret { value: String },
    /// `hexdump at address 0x... with length 0x...:` or hex dump data lines
    HexDump(String),
}

/// Parse a special (non-instruction) line into a SpecialLine variant.
pub fn parse_special_line(raw: &str) -> Option<SpecialLine> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    // call jni func: Name(args...)
    if let Some(rest) = raw.strip_prefix("call jni func: ") {
        return parse_call_func(rest, true);
    }

    // call func: Name(args...)
    if let Some(rest) = raw.strip_prefix("call func: ") {
        return parse_call_func(rest, false);
    }

    // args<N>: value
    if let Some(rest) = raw.strip_prefix("args") {
        if let Some(colon_pos) = rest.find(": ") {
            let index = rest[..colon_pos].to_string();
            let value = rest[colon_pos + 2..].to_string();
            return Some(SpecialLine::Arg { index, value });
        }
    }

    // ret: value
    if let Some(rest) = raw.strip_prefix("ret: ") {
        return Some(SpecialLine::Ret {
            value: rest.to_string(),
        });
    }

    // hexdump lines or hex data lines
    if raw.starts_with("hexdump ") || raw.chars().next().map_or(false, |c| c.is_ascii_hexdigit()) {
        return Some(SpecialLine::HexDump(raw.to_string()));
    }

    None
}

fn parse_call_func(rest: &str, is_jni: bool) -> Option<SpecialLine> {
    let paren_pos = rest.find('(')?;
    let name = rest[..paren_pos].to_string();
    let args_str = rest[paren_pos + 1..].trim_end_matches(')');
    let args = if args_str.is_empty() {
        Vec::new()
    } else {
        args_str.split(", ").map(|s| s.to_string()).collect()
    };
    Some(SpecialLine::CallFunc { name, is_jni, args })
}

/// Parse a gumtrace line (lightweight mode — skips arrow register extraction).
///
/// Returns `None` for special lines, empty lines, and unparseable lines.
pub fn parse_line_gumtrace(raw: &str) -> Option<ParsedLine> {
    parse_line_gumtrace_inner(raw, false)
}

/// Parse a gumtrace line (full mode — includes arrow register extraction).
#[allow(dead_code)]
pub fn parse_line_gumtrace_full(raw: &str) -> Option<ParsedLine> {
    parse_line_gumtrace_inner(raw, true)
}

fn parse_line_gumtrace_inner(raw: &str, extract_regs: bool) -> Option<ParsedLine> {
    let bytes = raw.as_bytes();

    // Empty or special lines
    if bytes.is_empty() || bytes[0] != b'[' {
        return None;
    }

    // 1. Extract module name from [module_name]
    let close_bracket = memchr::memchr(b']', bytes)?;
    // After "] " we expect the address
    let after_module = close_bracket + 2; // skip "] "
    if after_module >= bytes.len() {
        return None;
    }

    // 2. Extract absolute address and offset: 0xABS!0xOFFSET
    // Find the '!' separator
    let rest = &bytes[after_module..];
    let excl_pos = memchr::memchr(b'!', rest)?;
    let abs_excl = after_module + excl_pos;

    // Find the space after offset
    let after_excl = abs_excl + 1;
    let space_after_offset = memchr::memchr(b' ', &bytes[after_excl..])
        .map(|p| after_excl + p)
        .unwrap_or(bytes.len());

    // 3. Extract instruction text: from after offset space to ';' (or end of line)
    let insn_start = space_after_offset + 1;
    if insn_start >= bytes.len() {
        return None;
    }

    let semicolon_pos = memchr::memchr(b';', &bytes[insn_start..]).map(|p| insn_start + p);
    let insn_end = semicolon_pos.unwrap_or(bytes.len());

    // SAFETY: trace lines are ASCII
    let insn_text = unsafe { std::str::from_utf8_unchecked(&bytes[insn_start..insn_end]) }.trim();

    if insn_text.is_empty() {
        return None;
    }

    // 4. Split mnemonic and operand text
    let (mnemonic, operand_text) = match insn_text.find(' ') {
        Some(pos) => (&insn_text[..pos], insn_text[pos + 1..].trim()),
        None => (insn_text, ""),
    };

    if mnemonic.is_empty() {
        return None;
    }

    // 5. Parse operands
    let mut result_line = ParsedLine::default();
    let raw_first_reg_prefix = parse_operands_into(operand_text, &mut result_line);

    // 6. Find " -> " arrow (gumtrace uses -> instead of =>)
    let search_start = semicolon_pos.unwrap_or(insn_end);
    let tail = &bytes[search_start..];
    let arrow_rel = memmem::find(tail, b" -> ");
    let has_arrow = arrow_rel.is_some();
    let arrow_abs_pos = arrow_rel.map(|rel| search_start + rel);

    // 7. Extract register values if in full mode
    let (pre_arrow_regs, post_arrow_regs);
    if extract_regs {
        if let Some(arrow_pos) = arrow_abs_pos {
            pre_arrow_regs = Some(Box::new(extract_reg_values(&raw[..arrow_pos])));
            post_arrow_regs = Some(Box::new(extract_reg_values(&raw[arrow_pos + 4..])));
        } else {
            pre_arrow_regs = Some(Box::new(extract_reg_values(raw)));
            post_arrow_regs = Some(Box::new(SmallVec::new()));
        }
    } else {
        pre_arrow_regs = None;
        post_arrow_regs = None;
    }

    // 8. Parse memory ops: mem_w=0xADDR or mem_r=0xADDR
    let mem_op = if let Some(sc) = semicolon_pos {
        find_gumtrace_mem_op(&bytes[sc..], mnemonic, operand_text, raw_first_reg_prefix, bytes, arrow_abs_pos)
    } else {
        None
    };

    // 9. Detect writeback
    let op_bytes = operand_text.as_bytes();
    let writeback =
        memchr::memchr(b'!', op_bytes).is_some() || memmem::find(op_bytes, b"], #").is_some();

    result_line.mnemonic = Mnemonic::new(mnemonic);
    result_line.mem_op = mem_op;
    result_line.has_arrow = has_arrow;
    result_line.arrow_pos = arrow_abs_pos;
    result_line.writeback = writeback;
    result_line.pre_arrow_regs = pre_arrow_regs;
    result_line.post_arrow_regs = post_arrow_regs;

    Some(result_line)
}

/// Find mem_w=0xADDR or mem_r=0xADDR in gumtrace format.
fn find_gumtrace_mem_op(
    search: &[u8],
    mnemonic: &str,
    operand_text: &str,
    raw_first_reg_prefix: Option<u8>,
    full_bytes: &[u8],
    arrow_abs_pos: Option<usize>,
) -> Option<MemOp> {
    // Look for mem_w= or mem_r=
    let (is_write, addr) = if let Some(pos) = memmem::find(search, b"mem_w=0x") {
        let val_start = pos + 8; // len("mem_w=0x")
        let val_end = search[val_start..]
            .iter()
            .position(|b| !b.is_ascii_hexdigit())
            .map(|p| val_start + p)
            .unwrap_or(search.len());
        let addr = parse_hex_u64(&search[val_start..val_end])?;
        (true, addr)
    } else if let Some(pos) = memmem::find(search, b"mem_r=0x") {
        let val_start = pos + 8; // len("mem_r=0x")
        let val_end = search[val_start..]
            .iter()
            .position(|b| !b.is_ascii_hexdigit())
            .map(|p| val_start + p)
            .unwrap_or(search.len());
        let addr = parse_hex_u64(&search[val_start..val_end])?;
        (false, addr)
    } else {
        return None;
    };

    let elem_width = determine_elem_width(mnemonic, raw_first_reg_prefix);

    // Extract value for pass-through pruning
    let value = if elem_width <= 8 {
        first_data_reg_name(operand_text).and_then(|reg_name| {
            // For gumtrace, register values appear after the semicolon
            // The semicolon position is at the start of `search` relative to full_bytes
            let sc_abs = full_bytes.len() - search.len();
            let search_start = if is_write {
                sc_abs // STORE: search from after semicolon
            } else {
                // LOAD: search after -> to get loaded value
                match arrow_abs_pos {
                    Some(apos) => apos + 4,
                    None => return None,
                }
            };
            let raw_val = find_reg_value(full_bytes, reg_name.as_bytes(), search_start)?;
            let mask = if elem_width >= 8 {
                u64::MAX
            } else {
                (1u64 << (elem_width as u32 * 8)) - 1
            };
            Some(raw_val & mask)
        })
    } else {
        None
    };

    Some(MemOp {
        is_write,
        abs: addr,
        elem_width,
        value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint::types::*;

    #[test]
    fn test_parse_gumtrace_basic_insn() {
        let raw = "[libmetasec_ov.so] 0x7522e85ce0!0x82ce0 sub x0, x29, #0x80; x0=0x75150f2e20 fp=0x75150f2ec0 -> x0=0x75150f2e40";
        let line = parse_line_gumtrace(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "sub");
        assert_eq!(line.operands.len(), 3);
        assert_eq!(line.operands[0].as_reg(), Some(RegId::X0));
        assert_eq!(line.operands[1].as_reg(), Some(RegId::X29));
        assert!(matches!(line.operands[2], Operand::Imm(0x80)));
        assert!(line.has_arrow);
    }

    #[test]
    fn test_parse_gumtrace_mem_write() {
        let raw = "[libmetasec_ov.so] 0x7522f46438!0x143438 str x21, [sp, #-0x30]!; x21=0x1 sp=0x75150f2be0 mem_w=0x75150f2bb0";
        let line = parse_line_gumtrace(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "str");
        let mem = line.mem_op.as_ref().unwrap();
        assert!(mem.is_write);
        assert_eq!(mem.abs, 0x75150f2bb0);
        assert!(line.writeback);
    }

    #[test]
    fn test_parse_gumtrace_mem_read() {
        let raw = "[libmetasec_ov.so] 0x7522e31a94!0x2ea94 ldr x17, [x16, #0xf80]; x17=0x51 x16=0x7522fe1000 mem_r=0x7522fe1f80 -> x17=0x79b745a4c0";
        let line = parse_line_gumtrace(raw).unwrap();
        let mem = line.mem_op.as_ref().unwrap();
        assert!(!mem.is_write);
        assert_eq!(mem.abs, 0x7522fe1f80);
    }

    #[test]
    fn test_parse_gumtrace_no_semicolon() {
        let raw = "[libmetasec_ov.so] 0x7522e85ce4!0x82ce4 bl #0x7522f46438";
        let line = parse_line_gumtrace(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "bl");
        assert!(!line.has_arrow);
    }

    #[test]
    fn test_parse_gumtrace_br_instruction() {
        let raw = "[libmetasec_ov.so] 0x7522e31a9c!0x2ea9c br x17; x17=0x79b745a4c0";
        let line = parse_line_gumtrace(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "br");
    }

    #[test]
    fn test_parse_gumtrace_cbz() {
        let raw = "[libmetasec_ov.so] 0x7522f4644c!0x14344c cbz x1, #0x7522f46488; x1=0x75150f2e20";
        let line = parse_line_gumtrace(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "cbz");
    }

    #[test]
    fn test_parse_gumtrace_special_lines_return_none() {
        assert!(parse_line_gumtrace("call func: __strlen_aarch64(0x75150f2e20)").is_none());
        assert!(parse_line_gumtrace("args0: HttpRequestCallback").is_none());
        assert!(parse_line_gumtrace("ret: 0x13").is_none());
        assert!(
            parse_line_gumtrace("hexdump at address 0x75150f2e20 with length 0x14:").is_none()
        );
        assert!(parse_line_gumtrace(
            "75150f2e20: 48 74 74 70 52 65 71 75 65 73 74 43 61 6c 6c 62 |HttpRequestCallb|"
        )
        .is_none());
        assert!(parse_line_gumtrace("").is_none());
    }

    #[test]
    fn test_parse_gumtrace_ret_insn() {
        let raw = "[libmetasec_ov.so] 0x7522f464bc!0x1434bc ret";
        let line = parse_line_gumtrace(raw).unwrap();
        assert_eq!(line.mnemonic.as_str(), "ret");
    }

    #[test]
    fn test_parse_special_line_call_func() {
        let sl = parse_special_line("call func: __strlen_aarch64(0x75150f2e20)").unwrap();
        match sl {
            SpecialLine::CallFunc { name, is_jni, .. } => {
                assert_eq!(name, "__strlen_aarch64");
                assert!(!is_jni);
            }
            _ => panic!("expected CallFunc"),
        }
    }

    #[test]
    fn test_parse_special_line_jni() {
        let sl =
            parse_special_line("call jni func: GetMethodID(0x78f4342950, 0x799ac3f209)").unwrap();
        match sl {
            SpecialLine::CallFunc { name, is_jni, .. } => {
                assert_eq!(name, "GetMethodID");
                assert!(is_jni);
            }
            _ => panic!("expected JNI CallFunc"),
        }
    }

    #[test]
    fn test_parse_special_line_arg() {
        let sl = parse_special_line("args0: HttpRequestCallback").unwrap();
        match sl {
            SpecialLine::Arg { index, value } => {
                assert_eq!(index, "0");
                assert_eq!(value, "HttpRequestCallback");
            }
            _ => panic!("expected Arg"),
        }
    }

    #[test]
    fn test_parse_special_line_ret() {
        let sl = parse_special_line("ret: 0x13").unwrap();
        match sl {
            SpecialLine::Ret { value } => assert_eq!(value, "0x13"),
            _ => panic!("expected Ret"),
        }
    }
}
