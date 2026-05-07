use sandblaster_core::{InstructionBytes, RAW_REPORT_INSN_BYTES};

use crate::strategy::{instruction_lt, SearchMode, SearchRange, SearchStrategy, StrategyFeedback};

#[derive(Clone, Debug)]
pub struct TunnelStrategy {
    bytes: [u8; RAW_REPORT_INSN_BYTES],
    end: InstructionBytes,
    index: usize,
    last_length: Option<u32>,
    started: bool,
    done: bool,
}

impl TunnelStrategy {
    pub fn new() -> Self {
        Self::with_range(SearchRange::default())
    }

    pub fn with_range(range: SearchRange) -> Self {
        Self {
            bytes: *range.start.bytes(),
            end: range.end,
            index: range.start.specified_len(),
            last_length: None,
            started: false,
            done: false,
        }
    }

    fn current_instruction(&self) -> Option<InstructionBytes> {
        let instruction = InstructionBytes::new(self.bytes, self.index + 1);
        if instruction_lt(&instruction, &self.end) {
            Some(instruction)
        } else {
            None
        }
    }

    fn zero_tail_after_index(&mut self) {
        for byte in self.bytes.iter_mut().skip(self.index + 1) {
            *byte = 0;
        }
    }

    fn should_descend_structural_byte(&self) -> bool {
        if self.index + 1 >= RAW_REPORT_INSN_BYTES {
            return false;
        }

        let prefix_len = leading_prefix_len(&self.bytes);
        if self.index < prefix_len {
            return true;
        }

        let map_start = prefix_len;
        matches!(
            self.bytes.get(map_start..=self.index),
            Some([0x0f])
                | Some([0x0f, 0x38 | 0x3a])
                | Some([0xc5])
                | Some([0xc5, _])
                | Some([0xc4])
                | Some([0xc4, _])
                | Some([0xc4, _, _])
                | Some([0x62])
                | Some([0x62, _])
                | Some([0x62, _, _])
                | Some([0x62, _, _, _])
        )
    }
}

fn leading_prefix_len(bytes: &[u8; RAW_REPORT_INSN_BYTES]) -> usize {
    bytes.iter().take_while(|byte| is_prefix(**byte)).count()
}

fn is_prefix(byte: u8) -> bool {
    matches!(
        byte,
        0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 | 0x66 | 0x67 | 0x40..=0x4f
    )
}

#[cfg(test)]
mod tests {
    use sandblaster_core::InstructionBytes;

    use crate::{SearchRange, SearchStrategy, TunnelStrategy};

    #[test]
    fn tunnel_honors_start_and_exclusive_end() {
        let range = SearchRange {
            start: InstructionBytes::from_slice(&[0x90]),
            end: InstructionBytes::from_slice(&[0x90, 0x01]),
        };
        let mut strategy = TunnelStrategy::with_range(range);
        assert_eq!(
            strategy.next_candidate(),
            Some(InstructionBytes::from_slice(&[0x90, 0x00]))
        );
        assert_eq!(strategy.next_candidate(), None);
    }

    #[test]
    fn tunnel_descends_when_observed_length_changes() {
        let range = SearchRange {
            start: InstructionBytes::from_slice(&[]),
            end: InstructionBytes::from_slice(&[0x01]),
        };
        let mut strategy = TunnelStrategy::with_range(range);
        assert_eq!(
            strategy.next_candidate(),
            Some(InstructionBytes::from_slice(&[0x00]))
        );
        strategy.observe(crate::StrategyFeedback {
            observed_length: 2,
            signum: 5,
            disasm_length: 0,
            disasm_known: false,
        });
        assert_eq!(
            strategy.next_candidate(),
            Some(InstructionBytes::from_slice(&[0x00, 0x01]))
        );
    }

    #[test]
    fn tunnel_does_not_descend_into_known_matching_operands() {
        let range = SearchRange {
            start: InstructionBytes::from_slice(&[0x00, 0x14]),
            end: InstructionBytes::from_slice(&[0x00, 0x16]),
        };
        let mut strategy = TunnelStrategy::with_range(range);
        assert_eq!(
            strategy.next_candidate(),
            Some(InstructionBytes::from_slice(&[0x00, 0x14, 0x00]))
        );
        strategy.observe(crate::StrategyFeedback {
            observed_length: 6,
            signum: 5,
            disasm_length: 6,
            disasm_known: true,
        });
        assert_eq!(
            strategy.next_candidate(),
            Some(InstructionBytes::from_slice(&[0x00, 0x15]))
        );
    }

    #[test]
    fn tunnel_backs_out_of_unknown_sigill_space() {
        let range = SearchRange {
            start: InstructionBytes::from_slice(&[0x82, 0x04]),
            end: InstructionBytes::from_slice(&[0x82, 0x06]),
        };
        let mut strategy = TunnelStrategy::with_range(range);
        assert_eq!(
            strategy.next_candidate(),
            Some(InstructionBytes::from_slice(&[0x82, 0x04, 0x00]))
        );
        strategy.observe(crate::StrategyFeedback {
            observed_length: 8,
            signum: 4,
            disasm_length: 0,
            disasm_known: false,
        });
        assert_eq!(
            strategy.next_candidate(),
            Some(InstructionBytes::from_slice(&[0x82, 0x05]))
        );
    }

    #[test]
    fn tunnel_backs_out_to_fault_length_for_unknown_sigill() {
        let mut strategy = strategy_at(&[0x62, 0x08, 0x16, 0xbd, 0x00], 4);
        strategy.observe(crate::StrategyFeedback {
            observed_length: 2,
            signum: 4,
            disasm_length: 0,
            disasm_known: false,
        });
        assert_eq!(
            strategy.next_candidate(),
            Some(InstructionBytes::from_slice(&[0x62, 0x09]))
        );
    }

    #[test]
    fn tunnel_descends_through_prefix_and_escape_bytes() {
        let mut prefix_strategy = strategy_at(&[0x66], 0);
        prefix_strategy.observe(crate::StrategyFeedback {
            observed_length: 1,
            signum: 5,
            disasm_length: 1,
            disasm_known: true,
        });
        assert_eq!(
            prefix_strategy.next_candidate(),
            Some(InstructionBytes::from_slice(&[0x66, 0x01]))
        );

        let mut escape_strategy = strategy_at(&[0x0f], 0);
        escape_strategy.observe(crate::StrategyFeedback {
            observed_length: 1,
            signum: 4,
            disasm_length: 0,
            disasm_known: false,
        });
        assert_eq!(
            escape_strategy.next_candidate(),
            Some(InstructionBytes::from_slice(&[0x0f, 0x01]))
        );
    }

    fn strategy_at(bytes: &[u8], index: usize) -> TunnelStrategy {
        let mut raw = [0_u8; sandblaster_core::RAW_REPORT_INSN_BYTES];
        raw[..bytes.len()].copy_from_slice(bytes);
        TunnelStrategy {
            bytes: raw,
            end: InstructionBytes::new([0xff; sandblaster_core::RAW_REPORT_INSN_BYTES], 15),
            index,
            last_length: None,
            started: true,
            done: false,
        }
    }
}

impl Default for TunnelStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl SearchStrategy for TunnelStrategy {
    fn mode(&self) -> SearchMode {
        SearchMode::Tunnel
    }

    fn next_candidate(&mut self) -> Option<InstructionBytes> {
        if self.done {
            return None;
        }

        if !self.started {
            self.started = true;
            return self.current_instruction();
        }

        self.bytes[self.index] = self.bytes[self.index].wrapping_add(1);
        while self.index < RAW_REPORT_INSN_BYTES && self.bytes[self.index] == 0 {
            if self.index == 0 {
                self.done = true;
                return None;
            }
            self.index -= 1;
            self.bytes[self.index] = self.bytes[self.index].wrapping_add(1);
            self.last_length = None;
        }

        self.current_instruction().or_else(|| {
            self.done = true;
            None
        })
    }

    fn observe(&mut self, feedback: StrategyFeedback) {
        if self.should_descend_structural_byte() {
            self.index += 1;
            self.last_length = None;
            return;
        }

        if feedback.is_unknown_invalid() && self.index > 0 {
            let fault_index = feedback.observed_length.saturating_sub(1) as usize;
            self.index = fault_index.min(self.index - 1);
            self.zero_tail_after_index();
            self.last_length = None;
            return;
        }

        if feedback.is_known_length_match()
            && self.index > 1
            && self.index + 1 < feedback.observed_length as usize
        {
            self.index -= 1;
            self.zero_tail_after_index();
            self.last_length = None;
            return;
        }

        if !feedback.is_unknown_invalid()
            && !feedback.is_known_length_match()
            && self.index + 1 < RAW_REPORT_INSN_BYTES
            && self.last_length != Some(feedback.observed_length)
            && self.index + 1 < feedback.observed_length as usize
        {
            self.index += 1;
        }
        self.last_length = Some(feedback.observed_length);
    }
}
