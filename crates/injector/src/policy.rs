use sandblaster_core::{InstructionBytes, RAW_REPORT_INSN_BYTES};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefixPolicy {
    pub max_prefix: usize,
    pub allow_duplicate_prefixes: bool,
}

impl PrefixPolicy {
    pub fn validate(&self, instruction: &InstructionBytes) -> Result<(), &'static str> {
        let prefixes = leading_prefix_bytes(instruction.bytes());
        if prefixes.len() > self.max_prefix {
            return Err("prefix violation");
        }

        if !self.allow_duplicate_prefixes {
            let mut seen = [false; 256];
            for prefix in prefixes {
                let index = usize::from(prefix);
                if seen[index] {
                    return Err("prefix violation");
                }
                seen[index] = true;
            }
        }

        Ok(())
    }
}

pub fn default_opcode_blacklist() -> Vec<(InstructionBytes, &'static str)> {
    const ENTRIES: &[(&str, &str)] = &[
        ("0f34", "sysenter"),
        ("0fa1", "pop fs"),
        ("0fa9", "pop gs"),
        ("8e", "mov seg"),
        ("c8", "enter"),
        ("0fb2", "lss"),
        ("0fb4", "lfs"),
        ("0fb5", "lgs"),
        ("bc", "mov sp"),
        ("d1ec", "shr sp, 1"),
        ("d1e4", "shl sp, 1"),
        ("d1fc", "sar sp, 1"),
        ("d1dc", "rcr sp, 1"),
        ("d1d4", "rcl sp, 1"),
        ("d1cc", "ror sp, 1"),
        ("d1c4", "rol sp, 1"),
        ("8da2", "lea sp"),
        ("c7f8", "xbegin"),
        ("cd80", "int 0x80"),
        ("0f05", "syscall"),
        ("0fb9", "ud2"),
    ];

    ENTRIES
        .iter()
        .map(|(hex, reason)| (parse(hex), *reason))
        .collect()
}

pub fn default_prefix_blacklist(is_x86_64: bool) -> Vec<(u8, &'static str)> {
    if is_x86_64 {
        Vec::new()
    } else {
        vec![(0x65, "gs")]
    }
}

pub fn violates_blacklist(
    instruction: &InstructionBytes,
    opcode_blacklist: &[(InstructionBytes, &'static str)],
    prefix_blacklist: &[(u8, &'static str)],
) -> Option<&'static str> {
    if let Some(reason) = opcode_blacklist.iter().find_map(|(opcode, reason)| {
        if has_opcode(instruction, opcode) {
            Some(*reason)
        } else {
            None
        }
    }) {
        return Some(reason);
    }

    prefix_blacklist.iter().find_map(|(prefix, reason)| {
        if leading_prefix_bytes(instruction.bytes()).contains(prefix) {
            Some(*reason)
        } else {
            None
        }
    })
}

pub fn is_prefix(byte: u8, is_x86_64: bool) -> bool {
    matches!(
        byte,
        0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 | 0x66 | 0x67
    ) || (is_x86_64 && (0x40..=0x4f).contains(&byte))
}

fn leading_prefix_bytes(bytes: &[u8; RAW_REPORT_INSN_BYTES]) -> Vec<u8> {
    let is_x86_64 = cfg!(target_arch = "x86_64");
    let mut prefixes = Vec::new();
    for byte in bytes {
        if is_prefix(*byte, is_x86_64) {
            prefixes.push(*byte);
        } else {
            break;
        }
    }
    prefixes
}

fn has_opcode(instruction: &InstructionBytes, opcode: &InstructionBytes) -> bool {
    let is_x86_64 = cfg!(target_arch = "x86_64");
    let bytes = instruction.bytes();
    let start = bytes
        .iter()
        .position(|byte| !is_prefix(*byte, is_x86_64))
        .unwrap_or(bytes.len());
    let opcode_len = opcode.specified_len();
    start + opcode_len <= bytes.len()
        && bytes[start..start + opcode_len] == opcode.bytes()[..opcode_len]
}

fn parse(hex: &str) -> InstructionBytes {
    sandblaster_core::parse_hex_instruction(hex).expect("hard-coded blacklist entry should parse")
}

#[cfg(test)]
mod tests {
    use sandblaster_core::InstructionBytes;

    use crate::policy::{default_opcode_blacklist, violates_blacklist, PrefixPolicy};

    #[test]
    fn detects_blacklisted_opcode() {
        let instruction = InstructionBytes::from_slice(&[0x0f, 0x34]);
        let reason = violates_blacklist(&instruction, &default_opcode_blacklist(), &[]);
        assert_eq!(reason, Some("sysenter"));
    }

    #[test]
    fn rejects_duplicate_prefixes_when_disabled() {
        let policy = PrefixPolicy {
            max_prefix: 4,
            allow_duplicate_prefixes: false,
        };
        let instruction = InstructionBytes::from_slice(&[0xf3, 0xf3, 0x90]);
        assert_eq!(policy.validate(&instruction), Err("prefix violation"));
    }
}
