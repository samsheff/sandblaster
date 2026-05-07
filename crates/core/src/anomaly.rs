use crate::result::ExecutionResult;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FilterConfig {
    pub search_unknown: bool,
    pub search_length: bool,
    pub search_disasm_length: bool,
    pub search_invalid_known: bool,
    /// Detect unknown instructions that executed cleanly (signum=0, disasm.known=false).
    /// These are the most interesting findings: the CPU did something the disassembler
    /// doesn't know about.
    pub search_executed_unknown: bool,
    /// Detect unusual si_code values for known signal types.
    pub search_si_code: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnomalyKind {
    UnknownInstruction,
    LengthMismatchAny,
    LengthMismatchKnownValid,
    InvalidKnownInstruction,
    /// Unknown instruction that executed without signalling (sentinel BRK was the only trap).
    ExecutedUnknown,
    /// Signal delivered with an unusual si_code for its type.
    UnexpectedSiCode,
}

impl FilterConfig {
    pub fn detect(&self, result: &ExecutionResult) -> Option<AnomalyKind> {
        if result.valid == 0 {
            return None;
        }

        // Most exciting: unknown instruction that actually ran (signum=0 after sentinel fix)
        if self.search_executed_unknown && !result.disasm.known && result.signum == 0 {
            return Some(AnomalyKind::ExecutedUnknown);
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

        if self.search_si_code && is_unusual_si_code(result.signum, result.si_code) {
            return Some(AnomalyKind::UnexpectedSiCode);
        }

        None
    }
}

/// Returns true when the si_code is unexpected for the given signal.
///
/// Expected codes per signal (POSIX / XNU):
///   SIGILL  (4): ILL_ILLOPC=1 (illegal opcode) — anything else is unusual
///   SIGTRAP (5): TRAP_BRKPT=1 (breakpoint) — anything else is unusual
///   SIGBUS  (7): BUS_ADRALN=1 (alignment), BUS_ADRERR=2 (nonexistent addr)
///   SIGSEGV(11): SEGV_MAPERR=1 (unmapped), SEGV_ACCERR=2 (permission)
fn is_unusual_si_code(signum: u32, si_code: u32) -> bool {
    match signum {
        4 => si_code != 1, // SIGILL: expect ILL_ILLOPC
        5 => si_code != 1, // SIGTRAP: expect TRAP_BRKPT
        7 => si_code > 2,  // SIGBUS: expect 1 or 2
        11 => si_code > 2, // SIGSEGV: expect 1 or 2
        _ => false,
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
    fn matches_executed_unknown() {
        let mut result = base_result();
        result.disasm.known = false;
        result.signum = 0;
        let config = FilterConfig {
            search_executed_unknown: true,
            ..FilterConfig::default()
        };
        assert_eq!(config.detect(&result), Some(AnomalyKind::ExecutedUnknown));
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
            search_executed_unknown: true,
            search_si_code: true,
        };
        assert_eq!(config.detect(&result), None);
    }

    #[test]
    fn detects_unusual_si_code() {
        let mut result = base_result();
        result.signum = 4; // SIGILL
        result.si_code = 7; // unusual
        let config = FilterConfig {
            search_si_code: true,
            ..FilterConfig::default()
        };
        assert_eq!(config.detect(&result), Some(AnomalyKind::UnexpectedSiCode));

        result.si_code = 1; // expected ILL_ILLOPC
        assert_eq!(config.detect(&result), None);
    }
}
