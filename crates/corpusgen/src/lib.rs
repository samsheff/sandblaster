//! Host-side generator for the iOS static instruction corpus.
//!
//! Precomputes the candidate instructions a real `ios-arm64` scan would
//! execute and renders them as ARM64 assembly: each candidate becomes an
//! ordinary compiled function (its 4 bytes followed by the shared
//! `brk #0x1337` sentinel from `sandblaster_injector::arm64_fault`), so the
//! iOS static-corpus backend (`IosStaticCorpusBackend`) never needs to write
//! to executable memory at runtime. Invoked from `crates/mobile_ffi/build.rs`.

use std::fmt::Write as _;

use sandblaster_core::{InstructionBytes, TargetSpec};
use sandblaster_disasm::Arm64HeuristicDisassembler;
use sandblaster_injector::{
    arm64_fault, BackendObservation, ExecutionBackend, InjectorConfig, InjectorEngine,
    InjectorEvent, MacosArm64Backend,
};
use sandblaster_search::SearchMode;

/// What to bake into the corpus.
#[derive(Clone, Debug)]
pub struct CorpusConfig {
    pub mode: SearchMode,
    pub start: Option<InstructionBytes>,
    pub end: Option<InstructionBytes>,
    pub seed: Option<u64>,
    pub max_count: usize,
}

impl Default for CorpusConfig {
    fn default() -> Self {
        Self {
            mode: SearchMode::Tunnel,
            start: None,
            end: None,
            seed: None,
            // Keep the out-of-the-box build fast; widen via
            // SANDBLASTER_IOS_CORPUS_COUNT for a real research corpus.
            max_count: 4_096,
        }
    }
}

impl CorpusConfig {
    /// Build a config from `SANDBLASTER_IOS_CORPUS_*` environment variables,
    /// falling back to [`CorpusConfig::default`] for anything unset.
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Ok(value) = std::env::var("SANDBLASTER_IOS_CORPUS_MODE") {
            if let Some(mode) = parse_mode(&value) {
                config.mode = mode;
            }
        }
        if let Ok(value) = std::env::var("SANDBLASTER_IOS_CORPUS_START") {
            if let Ok(instruction) = sandblaster_core::parse_hex_instruction(&value) {
                config.start = Some(instruction);
            }
        }
        if let Ok(value) = std::env::var("SANDBLASTER_IOS_CORPUS_END") {
            if let Ok(instruction) = sandblaster_core::parse_hex_instruction(&value) {
                config.end = Some(instruction);
            }
        }
        if let Ok(value) = std::env::var("SANDBLASTER_IOS_CORPUS_SEED") {
            if let Ok(seed) = value.parse() {
                config.seed = Some(seed);
            }
        }
        if let Ok(value) = std::env::var("SANDBLASTER_IOS_CORPUS_COUNT") {
            if let Ok(count) = value.parse() {
                config.max_count = count;
            }
        }
        config
    }
}

fn parse_mode(value: &str) -> Option<SearchMode> {
    match value {
        "tunnel" => Some(SearchMode::Tunnel),
        "brute" => Some(SearchMode::Brute),
        "random" => Some(SearchMode::Random),
        _ => None,
    }
}

/// The generated corpus: one 4-byte ARM64 candidate per baked probe, in the
/// exact order a real `ios-arm64` scan with this config would execute them.
#[derive(Clone, Debug, Default)]
pub struct GeneratedCorpus {
    pub candidates: Vec<[u8; 4]>,
}

/// Generate the corpus.
///
/// On Apple Silicon (where [`MacosArm64Backend`] can actually execute ARM64
/// instructions natively) `SearchMode::Tunnel` runs against real execution
/// feedback, exactly like the on-device scan would — Tunnel's
/// `SearchStrategy::observe` branches on that feedback, so it can't be
/// reproduced correctly without real execution. `Brute`/`Random` modes don't
/// use feedback at all, so they're generated with a backend that reports a
/// synthetic "ran cleanly" result everywhere, no native execution needed.
pub fn generate(config: &CorpusConfig) -> Result<GeneratedCorpus, String> {
    let injector_config = InjectorConfig {
        target: TargetSpec::ios_arm64(),
        mode: config.mode,
        start_instruction: config.start,
        end_instruction: config.end,
        seed: config.seed,
        ..InjectorConfig::default()
    };

    if config.mode == SearchMode::Tunnel {
        return match MacosArm64Backend::try_new() {
            Ok(backend) => run_engine(injector_config, backend, config.max_count),
            Err(error) => Err(format!(
                "SearchMode::Tunnel needs real ARM64 execution feedback to branch \
                 correctly, which requires running this generator on Apple Silicon \
                 macOS ({error}). Set SANDBLASTER_IOS_CORPUS_MODE=brute or =random to \
                 generate without native execution."
            )),
        };
    }

    run_engine(injector_config, AlwaysCleanBackend, config.max_count)
}

/// A backend that never actually executes anything and always reports "ran
/// cleanly, 4 bytes, no fault". Only used for `Brute`/`Random` modes, whose
/// `SearchStrategy::observe` is a no-op, so this can't desync corpus
/// generation from a real on-device scan using the same mode/range/seed.
struct AlwaysCleanBackend;

impl ExecutionBackend for AlwaysCleanBackend {
    fn execute(&mut self, _instruction: &InstructionBytes) -> Result<BackendObservation, String> {
        Ok(BackendObservation {
            valid: 1,
            length: 4,
            signum: 0,
            si_code: 0,
            fault_addr: u32::MAX,
        })
    }
}

fn run_engine(
    config: InjectorConfig,
    backend: impl ExecutionBackend,
    max_count: usize,
) -> Result<GeneratedCorpus, String> {
    let mut engine = InjectorEngine::new(Arm64HeuristicDisassembler, backend, &config);
    let mut candidates = Vec::new();
    while candidates.len() < max_count {
        match engine.next_event()? {
            Some(InjectorEvent::Executed(result)) => {
                let bytes: [u8; 4] = result.instruction.bytes()[..4]
                    .try_into()
                    .expect("ios-arm64 candidates are always 4 bytes");
                candidates.push(bytes);
            }
            Some(InjectorEvent::Skipped(_, _)) => continue,
            None => break,
        }
    }
    Ok(GeneratedCorpus { candidates })
}

/// Render the generated corpus as Darwin ARM64 assembly (GAS syntax, as
/// accepted by `clang -target arm64-apple-ios`/`arm64-apple-macos`).
///
/// Emits one `_sb_probe_<N>` function per candidate (its 4 bytes followed by
/// the `brk #0x1337` sentinel), plus `_SB_PROBE_COUNT`, `_SB_PROBE_BYTES`
/// (the raw candidate bytes, for the Rust-side lookup table), and
/// `_SB_PROBE_TABLE` (matching function pointers).
pub fn render_assembly(corpus: &GeneratedCorpus) -> String {
    let sentinel_word = u32::from_le_bytes(arm64_fault::BRK_SENTINEL);

    let mut out = String::new();
    let _ = writeln!(out, "// Generated by sandblaster-corpusgen. Do not edit by hand.");
    let _ = writeln!(out, ".section __TEXT,__text,regular,pure_instructions");
    let _ = writeln!(out, ".p2align 2");
    for (i, bytes) in corpus.candidates.iter().enumerate() {
        let word = u32::from_le_bytes(*bytes);
        let _ = writeln!(out, ".globl _sb_probe_{i}");
        let _ = writeln!(out, "_sb_probe_{i}:");
        let _ = writeln!(out, "    .word 0x{word:08x}");
        let _ = writeln!(out, "    .word 0x{sentinel_word:08x}");
    }

    let _ = writeln!(out, ".section __DATA,__const");
    let _ = writeln!(out, ".p2align 3");
    let _ = writeln!(out, ".globl _SB_PROBE_TABLE");
    let _ = writeln!(out, "_SB_PROBE_TABLE:");
    for i in 0..corpus.candidates.len() {
        let _ = writeln!(out, "    .quad _sb_probe_{i}");
    }

    let _ = writeln!(out, ".globl _SB_PROBE_BYTES");
    let _ = writeln!(out, "_SB_PROBE_BYTES:");
    for bytes in &corpus.candidates {
        let word = u32::from_le_bytes(*bytes);
        let _ = writeln!(out, "    .word 0x{word:08x}");
    }

    let _ = writeln!(out, ".globl _SB_PROBE_COUNT");
    let _ = writeln!(out, "_SB_PROBE_COUNT:");
    let _ = writeln!(out, "    .long {}", corpus.candidates.len());

    let _ = writeln!(out, ".subsections_via_symbols");
    out
}

#[cfg(test)]
mod tests {
    use sandblaster_core::InstructionBytes;
    use sandblaster_search::SearchMode;

    use super::{generate, render_assembly, CorpusConfig};

    #[test]
    fn brute_mode_matches_engine_candidate_order_without_native_execution() {
        // Brute over a tiny range: every candidate from 00000000 up to
        // (exclusive) 00000003 should be baked in, in order, regardless of
        // whether the host can execute ARM64 natively.
        let config = CorpusConfig {
            mode: SearchMode::Brute,
            start: Some(InstructionBytes::new([0; 16], 4)),
            end: Some(InstructionBytes::new(
                [0x00, 0x00, 0x00, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                4,
            )),
            seed: None,
            max_count: 100,
        };
        let corpus = generate(&config).expect("brute generation should not need native exec");
        assert_eq!(
            corpus.candidates,
            vec![[0, 0, 0, 0], [0, 0, 0, 1], [0, 0, 0, 2]]
        );
    }

    #[test]
    fn render_assembly_emits_one_probe_per_candidate() {
        let corpus = super::GeneratedCorpus {
            candidates: vec![[0xe0, 0x66, 0x22, 0xd4], [0x1f, 0x20, 0x03, 0xd5]],
        };
        let asm = render_assembly(&corpus);
        assert!(asm.contains("_sb_probe_0:"));
        assert!(asm.contains("_sb_probe_1:"));
        assert!(asm.contains("_SB_PROBE_COUNT:"));
        assert!(asm.contains(".long 2"));
        assert!(!asm.contains("_sb_probe_2:"));
    }

    #[test]
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn tunnel_mode_runs_real_native_execution_on_apple_silicon() {
        // The default mode/path build.rs uses: real ARM64 execution feedback
        // drives the Tunnel strategy's branching, exactly as it would for a
        // real on-device scan.
        let config = CorpusConfig {
            mode: SearchMode::Tunnel,
            start: Some(InstructionBytes::new([0; 16], 4)),
            end: None,
            seed: None,
            max_count: 32,
        };
        let corpus = generate(&config).expect("native tunnel generation should succeed on arm64 macOS");
        assert_eq!(corpus.candidates.len(), 32);
    }

    #[test]
    fn max_count_bounds_generated_candidates() {
        let config = CorpusConfig {
            mode: SearchMode::Brute,
            start: Some(InstructionBytes::new([0; 16], 4)),
            end: None,
            seed: None,
            max_count: 5,
        };
        let corpus = generate(&config).expect("brute generation should not need native exec");
        assert_eq!(corpus.candidates.len(), 5);
    }
}
