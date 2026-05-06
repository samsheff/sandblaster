use sandblaster_core::InstructionBytes;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodeOutput {
    pub mnemonic: String,
    pub operands: String,
    pub length: u32,
    pub known: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodeError {
    pub message: String,
}

pub trait DisasmBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn decode_first(&self, instruction: &InstructionBytes) -> Result<DecodeOutput, DecodeError>;
}

#[derive(Clone, Debug, Default)]
pub struct NullDisassembler;

impl DisasmBackend for NullDisassembler {
    fn name(&self) -> &'static str {
        "null"
    }

    fn decode_first(&self, _instruction: &InstructionBytes) -> Result<DecodeOutput, DecodeError> {
        Ok(DecodeOutput {
            mnemonic: "(unk)".to_string(),
            operands: String::new(),
            length: 0,
            known: false,
        })
    }
}
