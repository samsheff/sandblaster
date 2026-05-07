use sandblaster_core::InstructionBytes;

const X86_64_BITNESS: u32 = 64;

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

#[derive(Clone, Debug, Default)]
pub struct IcedX86Disassembler;

impl DisasmBackend for IcedX86Disassembler {
    fn name(&self) -> &'static str {
        "iced-x86"
    }

    fn decode_first(&self, instruction: &InstructionBytes) -> Result<DecodeOutput, DecodeError> {
        let bytes = &instruction.bytes()[..sandblaster_core::MAX_INSN_LENGTH];
        let mut decoder =
            iced_x86::Decoder::new(X86_64_BITNESS, bytes, iced_x86::DecoderOptions::NONE);
        let decoded = decoder.decode();

        if decoded.is_invalid() {
            return Ok(DecodeOutput {
                mnemonic: "(unk)".to_string(),
                operands: String::new(),
                length: 0,
                known: false,
            });
        }

        Ok(DecodeOutput {
            mnemonic: format!("{:?}", decoded.mnemonic()).to_ascii_lowercase(),
            operands: String::new(),
            length: decoded.len() as u32,
            known: true,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct Arm64FixedDisassembler;

impl DisasmBackend for Arm64FixedDisassembler {
    fn name(&self) -> &'static str {
        "arm64-fixed"
    }

    fn decode_first(&self, instruction: &InstructionBytes) -> Result<DecodeOutput, DecodeError> {
        if instruction.specified_len() < 4 {
            return Ok(DecodeOutput {
                mnemonic: "(short)".to_string(),
                operands: String::new(),
                length: 0,
                known: false,
            });
        }

        Ok(DecodeOutput {
            mnemonic: "aarch64".to_string(),
            operands: String::new(),
            length: 4,
            known: true,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct Arm64HeuristicDisassembler;

impl DisasmBackend for Arm64HeuristicDisassembler {
    fn name(&self) -> &'static str {
        "arm64-heuristic"
    }

    fn decode_first(&self, instruction: &InstructionBytes) -> Result<DecodeOutput, DecodeError> {
        if instruction.specified_len() < 4 {
            return Ok(DecodeOutput {
                mnemonic: "(short)".to_string(),
                operands: String::new(),
                length: 0,
                known: false,
            });
        }

        let raw = &instruction.bytes()[..4];
        let word = u32::from_le_bytes(raw.try_into().expect("slice has four bytes"));
        let known = arm64_word_is_likely_allocated(word);
        Ok(DecodeOutput {
            mnemonic: if known { "aarch64" } else { "(unk)" }.to_string(),
            operands: String::new(),
            length: if known { 4 } else { 0 },
            known,
        })
    }
}

fn arm64_word_is_likely_allocated(word: u32) -> bool {
    if word == 0 {
        return false;
    }

    // UDF occupies the permanently undefined encoding space.
    if (word & 0xffff_0000) == 0 {
        return false;
    }

    // BRK/HLT/HLT-like exception encodings are architecturally allocated.
    if (word & 0xffe0_001f) == 0xd420_0000 {
        return true;
    }

    // This is deliberately conservative without pulling a full AArch64 decoder
    // into the mobile staticlib: top-level op0 classes 100x/101x are the broad
    // data-processing/load-store/branch regions where useful probes live.
    matches!((word >> 25) & 0x0f, 0b0100..=0b1011)
}

#[cfg(test)]
mod tests {
    use sandblaster_core::InstructionBytes;

    use crate::backend::{
        Arm64FixedDisassembler, Arm64HeuristicDisassembler, DisasmBackend, IcedX86Disassembler,
    };

    #[test]
    fn iced_decodes_known_instruction_length() {
        let decoded = IcedX86Disassembler
            .decode_first(&InstructionBytes::from_slice(&[0x90]))
            .expect("decode should succeed");

        assert!(decoded.known);
        assert_eq!(decoded.length, 1);
    }

    #[test]
    fn iced_reports_unknown_instruction_like_capstone_raw_path() {
        let decoded = IcedX86Disassembler
            .decode_first(&InstructionBytes::from_slice(&[0x82]))
            .expect("decode should succeed");

        assert!(!decoded.known);
        assert_eq!(decoded.length, 0);
    }

    #[test]
    fn arm64_fixed_width_reports_four_byte_instructions() {
        let decoded = Arm64FixedDisassembler
            .decode_first(&InstructionBytes::from_slice(&[0x1f, 0x20, 0x03, 0xd5]))
            .expect("decode should succeed");

        assert!(decoded.known);
        assert_eq!(decoded.length, 4);
    }

    #[test]
    fn arm64_heuristic_marks_permanent_undefined_as_unknown() {
        let decoded = Arm64HeuristicDisassembler
            .decode_first(&InstructionBytes::from_slice(&[0x00, 0x00, 0x00, 0x00]))
            .expect("decode should succeed");

        assert!(!decoded.known);
        assert_eq!(decoded.length, 0);
    }

    #[test]
    fn arm64_heuristic_marks_nop_as_known() {
        let decoded = Arm64HeuristicDisassembler
            .decode_first(&InstructionBytes::from_slice(&[0x1f, 0x20, 0x03, 0xd5]))
            .expect("decode should succeed");

        assert!(decoded.known);
        assert_eq!(decoded.length, 4);
    }
}
