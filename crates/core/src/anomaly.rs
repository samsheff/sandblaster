use crate::result::ExecutionResult;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FilterConfig {
    pub search_unknown: bool,
    pub search_length: bool,
    pub search_disasm_length: bool,
    pub search_invalid_known: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnomalyKind {
    UnknownInstruction,
    LengthMismatchAny,
    LengthMismatchKnownValid,
    InvalidKnownInstruction,
}

impl FilterConfig {
    pub fn detect(&self, result: &ExecutionResult) -> Option<AnomalyKind> {
        if result.valid == 0 {
            return None;
        }

        if self.search_unknown && !result.disasm.known && result.signum != 4 {
            return Some(AnomalyKind::UnknownInstruction);
        }

        if self.search_length && result.disasm.known && result.disasm.length != result.length {
            return Some(AnomalyKind::LengthMismatchAny);
        }

        if self.search_disasm_length
            && result.disasm.known
            && result.disasm.length != result.length
            && result.signum != 4
        {
            return Some(AnomalyKind::LengthMismatchKnownValid);
        }

        if self.search_invalid_known && result.disasm.known && result.signum == 4 {
            return Some(AnomalyKind::InvalidKnownInstruction);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        anomaly::{AnomalyKind, FilterConfig},
        instruction::InstructionBytes,
        result::{DisasmResult, ExecutionResult},
    };

    fn base_result() -> ExecutionResult {
        ExecutionResult {
            disasm: DisasmResult {
                length: 1,
                known: true,
            },
            instruction: InstructionBytes::from_slice(&[0x90]),
            valid: 1,
            length: 1,
            signum: 5,
            si_code: 1,
            fault_addr: u32::MAX,
        }
    }

    #[test]
    fn matches_unknown_logic_from_reference() {
        let mut result = base_result();
        result.disasm.known = false;
        let config = FilterConfig {
            search_unknown: true,
            ..FilterConfig::default()
        };
        assert_eq!(
            config.detect(&result),
            Some(AnomalyKind::UnknownInstruction)
        );
        result.signum = 4;
        assert_eq!(config.detect(&result), None);
    }

    #[test]
    fn matches_length_difference_logic() {
        let mut result = base_result();
        result.length = 2;
        let config = FilterConfig {
            search_length: true,
            ..FilterConfig::default()
        };
        assert_eq!(config.detect(&result), Some(AnomalyKind::LengthMismatchAny));
    }

    #[test]
    fn ignores_results_marked_invalid() {
        let mut result = base_result();
        result.valid = 0;
        let config = FilterConfig {
            search_length: true,
            search_unknown: true,
            search_disasm_length: true,
            search_invalid_known: true,
        };
        assert_eq!(config.detect(&result), None);
    }
}
