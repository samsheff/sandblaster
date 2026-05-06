use sandblaster_core::{InstructionBytes, MAX_INSN_LENGTH};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchMode {
    Brute,
    Random,
    Tunnel,
    Driven,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchRange {
    pub start: InstructionBytes,
    pub end: InstructionBytes,
}

impl Default for SearchRange {
    fn default() -> Self {
        Self {
            start: InstructionBytes::from_slice(&[]),
            end: InstructionBytes::new([0xff; 16], MAX_INSN_LENGTH),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StrategyFeedback {
    pub observed_length: u32,
    pub signum: u32,
    pub disasm_length: u32,
    pub disasm_known: bool,
}

impl StrategyFeedback {
    pub fn is_known_length_match(self) -> bool {
        self.disasm_known && self.disasm_length == self.observed_length
    }
}

pub trait SearchStrategy {
    fn mode(&self) -> SearchMode;
    fn next_candidate(&mut self) -> Option<InstructionBytes>;
    fn observe(&mut self, _feedback: StrategyFeedback) {}
}

pub(crate) fn instruction_lt(left: &InstructionBytes, right: &InstructionBytes) -> bool {
    left.bytes() < right.bytes()
}
