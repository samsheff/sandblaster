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
        if self.index + 1 < RAW_REPORT_INSN_BYTES
            && self.last_length != Some(feedback.observed_length)
            && self.index + 1 < feedback.observed_length as usize
        {
            self.index += 1;
        }
        self.last_length = Some(feedback.observed_length);
    }
}
