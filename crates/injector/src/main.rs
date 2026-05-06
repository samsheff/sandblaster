use std::env;
use std::io::{self, Write};
use std::process::ExitCode;

use sandblaster_disasm::NullDisassembler;
use sandblaster_injector::{
    InjectorConfig, InjectorEngine, InjectorEvent, LinuxX86Backend, OutputMode, RawInjectorPacket,
    TextReport,
};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "-?" || arg == "--help") {
        print!("{}", InjectorConfig::help_text());
        return ExitCode::SUCCESS;
    }

    match InjectorConfig::parse_args(&args) {
        Ok(config) => {
            let backend = match LinuxX86Backend::from_config(&config) {
                Ok(backend) => backend,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::from(2);
                }
            };
            let mut engine = InjectorEngine::new(NullDisassembler, backend, &config);
            run_engine(&mut engine, &config)
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn run_engine<D, E>(engine: &mut InjectorEngine<D, E>, config: &InjectorConfig) -> ExitCode
where
    D: sandblaster_disasm::DisasmBackend,
    E: sandblaster_injector::ExecutionBackend,
{
    loop {
        match engine.next_event() {
            Ok(Some(InjectorEvent::Executed(result))) => {
                if emit_result(&result, config.output_mode).is_err() {
                    return ExitCode::from(1);
                }
            }
            Ok(Some(InjectorEvent::Skipped(result, reason))) => {
                if emit_result(&result, config.output_mode).is_err() {
                    return ExitCode::from(1);
                }
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

fn emit_result(
    result: &sandblaster_core::ExecutionResult,
    output_mode: OutputMode,
) -> io::Result<()> {
    match output_mode {
        OutputMode::Raw => {
            let packet = RawInjectorPacket::from_execution_result(result);
            io::stdout().write_all(&packet.to_bytes())
        }
        OutputMode::Text => {
            let report = TextReport::from_execution_result(result);
            print!("{}", report.0);
            Ok(())
        }
    }
}
