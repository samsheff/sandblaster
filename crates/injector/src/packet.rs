use sandblaster_core::{
    format_full_hex, parse_hex_instruction, ExecutionResult, TargetSpec, RAW_REPORT_INSN_BYTES,
};

pub const VERSIONED_PACKET_PREFIX: &str = "SB1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawInjectorPacket {
    pub disas_length: u32,
    pub disas_known: u32,
    pub raw_insn: [u8; RAW_REPORT_INSN_BYTES],
    pub valid: u32,
    pub length: u32,
    pub signum: u32,
    pub si_code: u32,
    pub fault_addr: u32,
}

impl RawInjectorPacket {
    pub fn from_execution_result(result: &ExecutionResult) -> Self {
        Self {
            disas_length: result.disasm.length,
            disas_known: u32::from(result.disasm.known),
            raw_insn: *result.instruction.bytes(),
            valid: result.valid,
            length: result.length,
            signum: result.signum,
            si_code: result.si_code,
            fault_addr: result.fault_addr,
        }
    }

    pub fn to_bytes(self) -> [u8; 44] {
        let mut out = [0_u8; 44];
        out[0..4].copy_from_slice(&self.disas_length.to_ne_bytes());
        out[4..8].copy_from_slice(&self.disas_known.to_ne_bytes());
        out[8..24].copy_from_slice(&self.raw_insn);
        out[24..28].copy_from_slice(&self.valid.to_ne_bytes());
        out[28..32].copy_from_slice(&self.length.to_ne_bytes());
        out[32..36].copy_from_slice(&self.signum.to_ne_bytes());
        out[36..40].copy_from_slice(&self.si_code.to_ne_bytes());
        out[40..44].copy_from_slice(&self.fault_addr.to_ne_bytes());
        out
    }

    pub fn from_bytes(bytes: [u8; 44]) -> Self {
        Self {
            disas_length: u32::from_ne_bytes(bytes[0..4].try_into().expect("slice has 4 bytes")),
            disas_known: u32::from_ne_bytes(bytes[4..8].try_into().expect("slice has 4 bytes")),
            raw_insn: bytes[8..24].try_into().expect("slice has 16 bytes"),
            valid: u32::from_ne_bytes(bytes[24..28].try_into().expect("slice has 4 bytes")),
            length: u32::from_ne_bytes(bytes[28..32].try_into().expect("slice has 4 bytes")),
            signum: u32::from_ne_bytes(bytes[32..36].try_into().expect("slice has 4 bytes")),
            si_code: u32::from_ne_bytes(bytes[36..40].try_into().expect("slice has 4 bytes")),
            fault_addr: u32::from_ne_bytes(bytes[40..44].try_into().expect("slice has 4 bytes")),
        }
    }

    pub fn into_execution_result(self) -> ExecutionResult {
        let mut instruction =
            sandblaster_core::InstructionBytes::new(self.raw_insn, RAW_REPORT_INSN_BYTES);
        instruction.set_specified_len(self.length as usize);
        ExecutionResult {
            disasm: sandblaster_core::DisasmResult {
                length: self.disas_length,
                known: self.disas_known != 0,
            },
            instruction,
            valid: self.valid,
            length: self.length,
            signum: self.signum,
            si_code: self.si_code,
            fault_addr: self.fault_addr,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionedPacket {
    pub target: TargetSpec,
    pub result: ExecutionResult,
}

impl VersionedPacket {
    pub fn from_execution_result(target: TargetSpec, result: &ExecutionResult) -> Self {
        Self {
            target,
            result: result.clone(),
        }
    }

    pub fn to_line(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:08x}\t{}\n",
            VERSIONED_PACKET_PREFIX,
            self.target.platform,
            self.target.architecture,
            self.result.disasm.length,
            u8::from(self.result.disasm.known),
            self.result.valid,
            self.result.length,
            self.result.signum,
            self.result.si_code,
            self.result.fault_addr,
            self.result.raw_payload_hex()
        )
    }

    pub fn parse_line(line: &str) -> Result<Self, String> {
        let fields: Vec<&str> = line.trim_end().split('\t').collect();
        if fields.len() != 11 || fields[0] != VERSIONED_PACKET_PREFIX {
            return Err("not a sandblaster v1 packet".to_string());
        }

        let target = match (fields[1], fields[2]) {
            ("linux", "x86_64") => TargetSpec::linux_x86_64(),
            ("android", "arm64") => TargetSpec::android_arm64(),
            ("ios", "arm64") => TargetSpec::ios_arm64(),
            ("macos", "arm64") => TargetSpec::macos_arm64(),
            _ => {
                return Err(format!(
                    "unsupported packet target {}/{}",
                    fields[1], fields[2]
                ))
            }
        };
        let mut instruction =
            parse_hex_instruction(fields[10]).map_err(|error| format!("bad raw hex: {error}"))?;
        let length = parse_u32(fields[6], "length")?;
        instruction.set_specified_len(length as usize);

        Ok(Self {
            target,
            result: ExecutionResult {
                disasm: sandblaster_core::DisasmResult {
                    length: parse_u32(fields[3], "disas_length")?,
                    known: parse_u32(fields[4], "disas_known")? != 0,
                },
                instruction,
                valid: parse_u32(fields[5], "valid")?,
                length,
                signum: parse_u32(fields[7], "signum")?,
                si_code: parse_u32(fields[8], "si_code")?,
                fault_addr: u32::from_str_radix(fields[9], 16)
                    .map_err(|_| "bad fault_addr".to_string())?,
            },
        })
    }
}

fn parse_u32(value: &str, field: &'static str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|_| format!("bad numeric field {field}: {value}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextReport(pub String);

impl TextReport {
    pub fn from_execution_result(result: &ExecutionResult) -> Self {
        let length_marker = if result.disasm.length == result.length {
            " "
        } else {
            "."
        };
        let signal_name = match result.signum {
            4 => "sigill ",
            11 => "sigsegv",
            8 => "sigfpe ",
            7 => "sigbus ",
            5 => "sigtrap",
            _ => "unknown",
        };
        let raw_prefix =
            format_full_hex(result.instruction.executed_prefix(result.length as usize));
        let raw_tail = format_full_hex(
            &result.instruction.bytes()[result.length.min(RAW_REPORT_INSN_BYTES as u32) as usize..],
        );

        Self(format!(
            " {length_marker}r: ({:2}) {signal_name} {:3} {:08x} {}{}\n",
            result.length, result.si_code, result.fault_addr, raw_prefix, raw_tail
        ))
    }
}

#[cfg(test)]
mod tests {
    use sandblaster_core::{DisasmResult, ExecutionResult, InstructionBytes, TargetSpec};

    use crate::packet::VersionedPacket;

    #[test]
    fn versioned_packet_round_trips_target_and_result() {
        let result = ExecutionResult {
            disasm: DisasmResult {
                length: 4,
                known: true,
            },
            instruction: InstructionBytes::from_slice(&[0x1f, 0x20, 0x03, 0xd5]),
            valid: 1,
            length: 4,
            signum: 5,
            si_code: 0,
            fault_addr: u32::MAX,
        };
        let line =
            VersionedPacket::from_execution_result(TargetSpec::android_arm64(), &result).to_line();
        let parsed = VersionedPacket::parse_line(&line).expect("packet should parse");

        assert_eq!(parsed.target, TargetSpec::android_arm64());
        assert_eq!(parsed.result.disasm, result.disasm);
        assert_eq!(parsed.result.raw_payload_hex(), result.raw_payload_hex());
        assert_eq!(parsed.result.length, result.length);
    }

    #[test]
    fn versioned_packet_round_trips_macos_arm64_target() {
        let result = ExecutionResult {
            disasm: DisasmResult {
                length: 4,
                known: true,
            },
            instruction: InstructionBytes::from_slice(&[0x1f, 0x20, 0x03, 0xd5]),
            valid: 1,
            length: 4,
            signum: 0,
            si_code: 0,
            fault_addr: u32::MAX,
        };
        let line =
            VersionedPacket::from_execution_result(TargetSpec::macos_arm64(), &result).to_line();
        let parsed = VersionedPacket::parse_line(&line).expect("packet should parse");

        assert_eq!(parsed.target, TargetSpec::macos_arm64());
        assert_eq!(parsed.result.raw_payload_hex(), result.raw_payload_hex());
    }
}
