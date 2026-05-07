use std::collections::VecDeque;
use std::env;
use std::io::{self, Read, Write};
use std::process::{Command, ExitCode, Stdio};

use sandblaster_core::{Architecture, Platform};
use sandblaster_disasm::{Arm64FixedDisassembler, IcedX86Disassembler};
use sandblaster_injector::{
    apply_cpu_affinity, split_search_range, AndroidArm64Backend, BackendObservation,
    ExecutionBackend, InjectorConfig, InjectorEngine, InjectorEvent, LinuxX86Backend, OutputMode,
    TextReport, VersionedPacket,
};
use sandblaster_search::{SearchMode, SearchRange};

const TICK_MASK: u64 = 0xffff;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "-?" || arg == "--help") {
        print!("{}", InjectorConfig::help_text());
        return ExitCode::SUCCESS;
    }

    match InjectorConfig::parse_args(&args) {
        Ok(config) => {
            if config.jobs > 1 && !config.worker {
                return run_supervisor(&args, &config);
            }
            if let Some(core) = config.core {
                if let Err(error) = apply_cpu_affinity(core) {
                    eprintln!("failed to set CPU affinity to core {core}: {error}");
                    return ExitCode::from(2);
                }
            }
            run_selected_target(&config)
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn run_selected_target(config: &InjectorConfig) -> ExitCode {
    if config.dry_run {
        let backend = DryRunBackend {
            fixed_len: config.target.fixed_instruction_len,
        };
        return match config.target.architecture {
            Architecture::Arm64 => run_backend(Arm64FixedDisassembler, backend, config),
            Architecture::X86_64 => run_backend(IcedX86Disassembler, backend, config),
        };
    }

    match (config.target.platform, config.target.architecture) {
        (Platform::Linux, Architecture::X86_64) => {
            let backend = match LinuxX86Backend::from_config(config) {
                Ok(backend) => backend,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(2);
                }
            };
            run_backend(IcedX86Disassembler, backend, config)
        }
        (Platform::Android, Architecture::Arm64) => {
            let backend = match AndroidArm64Backend::from_config(config) {
                Ok(backend) => backend,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(2);
                }
            };
            run_backend(Arm64FixedDisassembler, backend, config)
        }
        (Platform::Ios, Architecture::Arm64) => {
            eprintln!(
                "ios-arm64 native execution is provided by the iOS app/agent, not this CLI binary"
            );
            ExitCode::from(2)
        }
        _ => {
            eprintln!("unsupported target {}", config.target.name());
            ExitCode::from(2)
        }
    }
}

fn run_backend<D, E>(disasm: D, backend: E, config: &InjectorConfig) -> ExitCode
where
    D: sandblaster_disasm::DisasmBackend,
    E: sandblaster_injector::ExecutionBackend,
{
    let candidates = driven_candidates(config);
    let mut engine = if let Some(candidates) = candidates {
        InjectorEngine::new_with_driven_candidates(disasm, backend, config, candidates)
    } else {
        InjectorEngine::new(disasm, backend, config)
    };
    run_engine(&mut engine, config)
}

fn driven_candidates(
    config: &InjectorConfig,
) -> Option<VecDeque<sandblaster_core::InstructionBytes>> {
    if !matches!(config.mode, SearchMode::Driven) {
        return None;
    }

    let mut input = Vec::new();
    if io::stdin().read_to_end(&mut input).is_err() {
        return Some(VecDeque::new());
    }
    let candidates = input
        .chunks(sandblaster_core::RAW_REPORT_INSN_BYTES)
        .filter(|chunk| chunk.len() == sandblaster_core::RAW_REPORT_INSN_BYTES)
        .map(sandblaster_core::InstructionBytes::from_slice)
        .collect();
    Some(candidates)
}

fn run_supervisor(original_args: &[String], config: &InjectorConfig) -> ExitCode {
    if !matches!(config.mode, SearchMode::Brute | SearchMode::Tunnel) {
        eprintln!("-j is only supported for finite brute and tunnel searches; use -j 1 for random or driven mode");
        return ExitCode::from(2);
    }

    let total = SearchRange {
        start: config.start_instruction.unwrap_or_default(),
        end: config.end_instruction.unwrap_or_else(|| {
            sandblaster_core::InstructionBytes::new([0xff; 16], config.target.max_instruction_len)
        }),
    };
    let range_bytes = config.range_bytes.max(1);
    let ranges = split_search_range(total, range_bytes);
    let exe = match env::current_exe() {
        Ok(exe) => exe,
        Err(error) => {
            eprintln!("failed to locate injector executable: {error}");
            return ExitCode::from(2);
        }
    };

    let mut active = Vec::new();
    let mut next_range = 0;
    while next_range < ranges.len() || !active.is_empty() {
        while next_range < ranges.len() && active.len() < config.jobs {
            let args = worker_args(original_args, &ranges[next_range]);
            match Command::new(&exe)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
            {
                Ok(child) => active.push(child),
                Err(error) => {
                    eprintln!("failed to spawn injector worker: {error}");
                    return ExitCode::from(2);
                }
            }
            next_range += 1;
        }

        let mut child = active.remove(0);
        match child.wait() {
            Ok(status) if status.success() => {}
            Ok(status) => {
                eprintln!("injector worker exited with {status}");
                return ExitCode::from(2);
            }
            Err(error) => {
                eprintln!("failed to wait for injector worker: {error}");
                return ExitCode::from(2);
            }
        }
    }

    ExitCode::SUCCESS
}

fn worker_args(original_args: &[String], range: &SearchRange) -> Vec<String> {
    let mut args = strip_value_flags(original_args, &["-i", "-e", "-j"]);
    args.push("--worker".to_string());
    args.push("-j".to_string());
    args.push("1".to_string());
    args.push("-i".to_string());
    args.push(range.start.compact_hex());
    args.push("-e".to_string());
    args.push(range.end.compact_hex());
    args
}

fn strip_value_flags(args: &[String], flags: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if flags.contains(&arg.as_str()) {
            index += 2;
            continue;
        }
        if flags
            .iter()
            .any(|flag| arg.starts_with(flag) && arg.len() > flag.len())
        {
            index += 1;
            continue;
        }
        out.push(arg.clone());
        index += 1;
    }
    out
}

#[derive(Clone, Copy)]
struct DryRunBackend {
    fixed_len: Option<usize>,
}

impl ExecutionBackend for DryRunBackend {
    fn execute(
        &mut self,
        instruction: &sandblaster_core::InstructionBytes,
    ) -> Result<BackendObservation, String> {
        Ok(BackendObservation {
            valid: 1,
            length: self
                .fixed_len
                .unwrap_or_else(|| instruction.specified_len().max(1)) as u32,
            signum: 5,
            si_code: 0,
            fault_addr: u32::MAX,
        })
    }
}

fn run_engine<D, E>(engine: &mut InjectorEngine<D, E>, config: &InjectorConfig) -> ExitCode
where
    D: sandblaster_disasm::DisasmBackend,
    E: sandblaster_injector::ExecutionBackend,
{
    let mut emitted = 0_u64;
    loop {
        match engine.next_event() {
            Ok(Some(InjectorEvent::Executed(result))) => {
                if emit_result(&result, config).is_err() {
                    return ExitCode::from(1);
                }
                emitted += 1;
                maybe_emit_tick(&result, config, emitted);
            }
            Ok(Some(InjectorEvent::Skipped(result, reason))) => {
                if emit_result(&result, config).is_err() {
                    return ExitCode::from(1);
                }
                emitted += 1;
                maybe_emit_tick(&result, config, emitted);
                if matches!(config.output_mode, OutputMode::Text) {
                    eprintln!("skipped candidate: {reason}");
                }
            }
            Ok(None) => return ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::from(2);
            }
        }
    }
}

fn maybe_emit_tick(
    result: &sandblaster_core::ExecutionResult,
    config: &InjectorConfig,
    emitted: u64,
) {
    if config.show_tick && (emitted & TICK_MASK) == 0 {
        eprintln!("t: {}", result.instruction.full_hex());
    }
}

fn emit_result(
    result: &sandblaster_core::ExecutionResult,
    config: &InjectorConfig,
) -> io::Result<()> {
    match config.output_mode {
        OutputMode::Raw => {
            let packet = VersionedPacket::from_execution_result(config.target, result);
            io::stdout().write_all(packet.to_line().as_bytes())
        }
        OutputMode::Text => {
            let report = TextReport::from_execution_result(result);
            print!("{}", report.0);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use sandblaster_core::InstructionBytes;
    use sandblaster_search::SearchRange;

    use crate::{strip_value_flags, worker_args};

    #[test]
    fn worker_args_replace_range_and_jobs() {
        let original = vec![
            "-t".to_string(),
            "-j4".to_string(),
            "-i00".to_string(),
            "-e".to_string(),
            "ff".to_string(),
        ];
        let range = SearchRange {
            start: InstructionBytes::from_slice(&[0x10]),
            end: InstructionBytes::from_slice(&[0x11]),
        };
        let args = worker_args(&original, &range);
        assert_eq!(args, ["-t", "--worker", "-j", "1", "-i", "10", "-e", "11"]);
    }

    #[test]
    fn strip_value_flags_handles_split_and_compact_forms() {
        let args = vec![
            "-j".to_string(),
            "4".to_string(),
            "-l1".to_string(),
            "-P1".to_string(),
        ];
        assert_eq!(strip_value_flags(&args, &["-j", "-l"]), ["-P1"]);
    }
}
