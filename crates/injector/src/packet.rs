use sandblaster_core::{format_full_hex, ExecutionResult, RAW_REPORT_INSN_BYTES};

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
