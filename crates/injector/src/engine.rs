use std::collections::VecDeque;

use sandblaster_core::{DisasmResult, ExecutionResult, InstructionBytes};
use sandblaster_disasm::DisasmBackend;
use sandblaster_search::{
    BruteStrategy, DrivenStrategy, RandomStrategy, SearchMode, SearchRange, SearchStrategy,
    StrategyFeedback, TunnelStrategy,
};

use crate::{
    decode_with_backend, policy::violates_blacklist, BackendObservation, InjectorConfig,
    PrefixPolicy,
};

pub trait ExecutionBackend {
    fn execute(&mut self, instruction: &InstructionBytes) -> Result<BackendObservation, String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InjectorEvent {
    Executed(ExecutionResult),
    Skipped(ExecutionResult, &'static str),
}

pub struct InjectorEngine<D, E> {
    disasm: D,
    backend: E,
    strategy: Box<dyn SearchStrategy>,
    opcode_blacklist: Vec<(InstructionBytes, &'static str)>,
    prefix_blacklist: Vec<(u8, &'static str)>,
    prefix_policy: PrefixPolicy,
}

impl<D, E> InjectorEngine<D, E>
where
    D: DisasmBackend,
    E: ExecutionBackend,
{
    pub fn new(disasm: D, backend: E, config: &InjectorConfig) -> Self {
        Self::new_with_strategy(disasm, backend, config, None)
    }

    pub fn new_with_driven_candidates(
        disasm: D,
        backend: E,
        config: &InjectorConfig,
        candidates: VecDeque<InstructionBytes>,
    ) -> Self {
        Self::new_with_strategy(
            disasm,
            backend,
            config,
            Some(Box::new(DrivenStrategy::new(candidates))),
        )
    }

    fn new_with_strategy(
        disasm: D,
        backend: E,
        config: &InjectorConfig,
        strategy: Option<Box<dyn SearchStrategy>>,
    ) -> Self {
        let range = SearchRange {
            start: config.start_instruction.unwrap_or_default(),
            end: config
                .end_instruction
                .unwrap_or_else(|| InstructionBytes::new([0xff; 16], 15)),
        };
        let strategy = strategy.unwrap_or_else(|| strategy_from_config(config, range));
        Self {
            disasm,
            backend,
            strategy,
            opcode_blacklist: crate::default_opcode_blacklist()
                .into_iter()
                .chain(
                    config
                        .blacklists
                        .iter()
                        .copied()
                        .map(|item| (item, "user_blacklist")),
                )
                .collect(),
            prefix_blacklist: crate::default_prefix_blacklist(cfg!(target_arch = "x86_64")),
            prefix_policy: PrefixPolicy {
                max_prefix: config.max_prefix,
                allow_duplicate_prefixes: config.allow_duplicate_prefixes,
            },
        }
    }

    pub fn next_event(&mut self) -> Result<Option<InjectorEvent>, String> {
        let Some(instruction) = self.strategy.next_candidate() else {
            return Ok(None);
        };

        let disasm = decode_with_backend(&self.disasm, &instruction);
        if let Some(reason) =
            violates_blacklist(&instruction, &self.opcode_blacklist, &self.prefix_blacklist)
        {
            return Ok(Some(InjectorEvent::Skipped(
                skipped_result(instruction, disasm),
                reason,
            )));
        }

        if let Err(reason) = self.prefix_policy.validate(&instruction) {
            return Ok(Some(InjectorEvent::Skipped(
                skipped_result(instruction, disasm),
                reason,
            )));
        }

        let observation = self.backend.execute(&instruction)?;
        self.strategy.observe(StrategyFeedback {
            observed_length: observation.length,
            signum: observation.signum,
            disasm_length: disasm.length,
            disasm_known: disasm.known,
        });
        Ok(Some(InjectorEvent::Executed(
            observation.into_execution_result(instruction, disasm),
        )))
    }
}

fn skipped_result(instruction: InstructionBytes, disasm: DisasmResult) -> ExecutionResult {
    BackendObservation::default().into_execution_result(instruction, disasm)
}

fn strategy_from_config(config: &InjectorConfig, range: SearchRange) -> Box<dyn SearchStrategy> {
    match config.mode {
        SearchMode::Brute => Box::new(BruteStrategy::with_range(config.brute_depth, range)),
        SearchMode::Random => Box::new(RandomStrategy::new(config.seed.unwrap_or(0x5eed), range)),
        SearchMode::Tunnel => Box::new(TunnelStrategy::with_range(range)),
        SearchMode::Driven => Box::new(DrivenStrategy::new(VecDeque::new())),
    }
}

#[cfg(test)]
mod tests {
    use sandblaster_core::InstructionBytes;
    use sandblaster_disasm::{DecodeError, DecodeOutput, DisasmBackend};
    use sandblaster_search::SearchMode;

    use crate::{
        engine::{ExecutionBackend, InjectorEngine, InjectorEvent},
        BackendObservation, InjectorConfig,
    };

    struct FakeDisassembler;

    impl DisasmBackend for FakeDisassembler {
        fn name(&self) -> &'static str {
            "fake"
        }

        fn decode_first(
            &self,
            instruction: &InstructionBytes,
        ) -> Result<DecodeOutput, DecodeError> {
            Ok(DecodeOutput {
                mnemonic: "db".to_string(),
                operands: instruction.compact_hex(),
                length: instruction.specified_len() as u32,
                known: true,
            })
        }
    }

    struct FakeBackend;

    impl ExecutionBackend for FakeBackend {
        fn execute(
            &mut self,
            instruction: &InstructionBytes,
        ) -> Result<BackendObservation, String> {
            Ok(BackendObservation {
                valid: 1,
                length: instruction.specified_len() as u32,
                signum: 5,
                si_code: 1,
                fault_addr: u32::MAX,
            })
        }
    }

    #[test]
    fn emits_skipped_event_for_blacklist() {
        let config = InjectorConfig {
            mode: SearchMode::Driven,
            blacklists: vec![InstructionBytes::from_slice(&[0x90])],
            ..InjectorConfig::default()
        };
        let mut engine = InjectorEngine::new(FakeDisassembler, FakeBackend, &config);
        engine = engine_with_single_candidate(engine, InstructionBytes::from_slice(&[0x90]));
        let event = engine.next_event().expect("engine should succeed");
        assert!(matches!(
            event,
            Some(InjectorEvent::Skipped(_, "user_blacklist"))
        ));
    }

    #[test]
    fn emits_executed_event_for_clean_instruction() {
        let config = InjectorConfig {
            mode: SearchMode::Driven,
            ..InjectorConfig::default()
        };
        let mut engine = InjectorEngine::new(FakeDisassembler, FakeBackend, &config);
        engine = engine_with_single_candidate(engine, InstructionBytes::from_slice(&[0x90]));
        let event = engine.next_event().expect("engine should succeed");
        assert!(matches!(event, Some(InjectorEvent::Executed(_))));
    }

    fn engine_with_single_candidate(
        mut engine: InjectorEngine<FakeDisassembler, FakeBackend>,
        candidate: InstructionBytes,
    ) -> InjectorEngine<FakeDisassembler, FakeBackend> {
        engine.strategy = Box::new(sandblaster_search::DrivenStrategy::new(
            std::iter::once(candidate).collect(),
        ));
        engine
    }
}
