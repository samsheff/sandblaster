use crate::instruction::{format_full_hex, InstructionBytes};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DisasmResult {
    pub length: u32,
    pub known: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExecutionResult {
    pub disasm: DisasmResult,
    pub instruction: InstructionBytes,
    pub valid: u32,
    pub length: u32,
    pub signum: u32,
    pub si_code: u32,
    pub fault_addr: u32,
}

impl ExecutionResult {
    pub fn executed_key_hex(&self) -> String {
        format_full_hex(self.instruction.executed_prefix(self.length as usize))
    }

    pub fn raw_payload_hex(&self) -> String {
        format_full_hex(self.instruction.bytes())
    }
}
