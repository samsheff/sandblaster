use sandblaster_core::{InstructionBytes, RAW_REPORT_INSN_BYTES};

use crate::strategy::{SearchMode, SearchRange, SearchStrategy};

#[derive(Clone, Debug)]
pub struct RandomStrategy {
    state: u64,
    range: SearchRange,
}

impl RandomStrategy {
    pub fn new(seed: u64, range: SearchRange) -> Self {
        Self {
            state: seed.max(1),
            range,
        }
    }

    fn next_u32(&mut self) -> u32 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state as u32
    }
}

impl SearchStrategy for RandomStrategy {
    fn mode(&self) -> SearchMode {
        SearchMode::Random
    }

    fn next_candidate(&mut self) -> Option<InstructionBytes> {
        let mut bytes = [0_u8; RAW_REPORT_INSN_BYTES];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let min = self.range.start.bytes()[index];
            let max = self.range.end.bytes()[index];
            *byte = if min <= max {
                min.wrapping_add((self.next_u32() % (u32::from(max - min) + 1)) as u8)
            } else {
                self.next_u32() as u8
            };
        }
        Some(InstructionBytes::new(
            bytes,
            self.range.start.specified_len().max(1),
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::{RandomStrategy, SearchRange, SearchStrategy};

    #[test]
    fn random_strategy_is_seed_deterministic() {
        let range: SearchRange = Default::default();
        let mut left = RandomStrategy::new(123, range.clone());
        let mut right = RandomStrategy::new(123, range);
        assert_eq!(left.next_candidate(), right.next_candidate());
    }
}
