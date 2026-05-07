use std::fmt;

pub const MAX_INSN_LENGTH: usize = 15;
pub const RAW_REPORT_INSN_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InstructionBytes {
    bytes: [u8; RAW_REPORT_INSN_BYTES],
    specified_len: usize,
}

impl InstructionBytes {
    pub fn new(bytes: [u8; RAW_REPORT_INSN_BYTES], specified_len: usize) -> Self {
        Self {
            bytes,
            specified_len: specified_len.min(RAW_REPORT_INSN_BYTES),
        }
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        let mut raw = [0_u8; RAW_REPORT_INSN_BYTES];
        let len = bytes.len().min(RAW_REPORT_INSN_BYTES);
        raw[..len].copy_from_slice(&bytes[..len]);
        Self::new(raw, len)
    }

    pub fn bytes(&self) -> &[u8; RAW_REPORT_INSN_BYTES] {
        &self.bytes
    }

    pub fn specified_len(&self) -> usize {
        self.specified_len
    }

    pub fn set_specified_len(&mut self, len: usize) {
        self.specified_len = len.min(RAW_REPORT_INSN_BYTES);
    }

    pub fn executed_prefix(&self, len: usize) -> &[u8] {
        &self.bytes[..len.min(RAW_REPORT_INSN_BYTES)]
    }

    pub fn full_hex(&self) -> String {
        format_full_hex(&self.bytes)
    }

    pub fn compact_hex(&self) -> String {
        format_compact_hex(&self.bytes[..self.specified_len])
    }
}

impl Default for InstructionBytes {
    fn default() -> Self {
        Self::new([0_u8; RAW_REPORT_INSN_BYTES], 0)
    }
}

impl fmt::Display for InstructionBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.compact_hex())
    }
}

pub fn parse_hex_instruction(input: &str) -> Result<InstructionBytes, String> {
    let trimmed = input.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err("hex input must have an even length".to_string());
    }
    if trimmed.len() / 2 > RAW_REPORT_INSN_BYTES {
        return Err(format!(
            "hex input is longer than {} bytes",
            RAW_REPORT_INSN_BYTES
        ));
    }

    let mut bytes = [0_u8; RAW_REPORT_INSN_BYTES];
    for (index, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| "hex input is not valid UTF-8")?;
        bytes[index] =
            u8::from_str_radix(pair, 16).map_err(|_| format!("invalid hex byte '{pair}'"))?;
    }

    Ok(InstructionBytes::new(bytes, trimmed.len() / 2))
}

pub fn format_full_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(hex_digit(byte >> 4));
        out.push(hex_digit(byte & 0x0f));
    }
    out
}

pub fn format_compact_hex(bytes: &[u8]) -> String {
    format_full_hex(bytes)
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!("nibble out of range"),
    }
}

#[cfg(test)]
mod tests {
    use super::{format_full_hex, parse_hex_instruction, RAW_REPORT_INSN_BYTES};

    #[test]
    fn parses_hex_into_fixed_array() {
        let instruction = parse_hex_instruction("90cc").expect("parse should succeed");
        assert_eq!(instruction.specified_len(), 2);
        assert_eq!(&instruction.bytes()[..4], &[0x90, 0xcc, 0x00, 0x00]);
    }

    #[test]
    fn rejects_odd_length_hex() {
        let error = parse_hex_instruction("9").expect_err("odd-length input should fail");
        assert!(error.contains("even length"));
    }

    #[test]
    fn formats_full_array_hex() {
        let bytes = [0x41_u8; RAW_REPORT_INSN_BYTES];
        let text = format_full_hex(&bytes);
        assert_eq!(text.len(), RAW_REPORT_INSN_BYTES * 2);
        assert!(text.starts_with("4141"));
    }
}
