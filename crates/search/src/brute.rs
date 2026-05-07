use sandblaster_core::{InstructionBytes, RAW_REPORT_INSN_BYTES};

use crate::strategy::{instruction_lt, SearchMode, SearchRange, SearchStrategy};

#[derive(Clone, Debug)]
pub struct BruteStrategy {
    current: [u8; RAW_REPORT_INSN_BYTES],
    end: InstructionBytes,
    depth: usize,
    started: bool,
    done: bool,
}

#[cfg(test)]
mod tests {
    use sandblaster_core::InstructionBytes;

    use crate::{BruteStrategy, SearchRange, SearchStrategy};

    #[test]
    fn brute_honors_start_and_exclusive_end() {
        let range = SearchRange {
            start: InstructionBytes::from_slice(&[0x90]),
            end: InstructionBytes::from_slice(&[0x92]),
        };
        let mut strategy = BruteStrategy::with_range(1, range);
        assert_eq!(
            strategy.next_candidate(),
            Some(InstructionBytes::from_slice(&[0x90]))
        );
        assert_eq!(
            strategy.next_candidate(),
            Some(InstructionBytes::from_slice(&[0x91]))
        );
        assert_eq!(strategy.next_candidate(), None);
    }
}

impl BruteStrategy {
    pub fn new(depth: usize) -> Self {
        Self::with_range(depth, SearchRange::default())
    }

    pub fn with_range(depth: usize, range: SearchRange) -> Self {
        let depth = depth
            .max(range.start.specified_len())
            .clamp(1, RAW_REPORT_INSN_BYTES);
        Self {
            current: *range.start.bytes(),
            end: range.end,
            depth,
            started: false,
            done: false,
        }
    }

    fn current_instruction(&self) -> Option<InstructionBytes> {
        let instruction = InstructionBytes::new(self.current, self.depth);
        if instruction_lt(&instruction, &self.end) {
            Some(instruction)
        } else {
            None
        }
    }
}

impl SearchStrategy for BruteStrategy {
    fn mode(&self) -> SearchMode {
        SearchMode::Brute
    }

    fn next_candidate(&mut self) -> Option<InstructionBytes> {
        if self.done {
            return None;
        }

        if !self.started {
            self.started = true;
            return self.current_instruction();
        }

        let mut index = self.depth;
        while index > 0 {
            index -= 1;
            self.current[index] = self.current[index].wrapping_add(1);
            if self.current[index] != 0 {
                return self.current_instruction().or_else(|| {
                    self.done = true;
                    None
                });
            }
        }

        self.done = true;
        None
    }
}
