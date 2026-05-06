use std::collections::VecDeque;

use sandblaster_core::InstructionBytes;

use crate::strategy::{SearchMode, SearchStrategy};

#[derive(Clone, Debug, Default)]
pub struct DrivenStrategy {
    queue: VecDeque<InstructionBytes>,
}

impl DrivenStrategy {
    pub fn new(queue: VecDeque<InstructionBytes>) -> Self {
        Self { queue }
    }
}

impl SearchStrategy for DrivenStrategy {
    fn mode(&self) -> SearchMode {
        SearchMode::Driven
    }

    fn next_candidate(&mut self) -> Option<InstructionBytes> {
        self.queue.pop_front()
    }
}
