mod android_arm64;
mod engine;
mod ios_arm64;
mod linux_x86;
mod packet;
mod policy;
mod range;

use std::fmt;

use sandblaster_core::{
    parse_hex_instruction, DisasmResult, ExecutionResult, InstructionBytes, TargetSpec,
};
use sandblaster_disasm::DisasmBackend;
use sandblaster_search::SearchMode;

pub use android_arm64::AndroidArm64Backend;
pub use engine::{ExecutionBackend, InjectorEngine, InjectorEvent};
pub use ios_arm64::IosArm64Backend;
pub use linux_x86::{apply_cpu_affinity, LinuxX86Backend};
pub use packet::{RawInjectorPacket, TextReport, VersionedPacket, VERSIONED_PACKET_PREFIX};
pub use policy::{default_opcode_blacklist, default_prefix_blacklist, PrefixPolicy};
pub use range::split_search_range;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputMode {
    Raw,
    Text,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InjectorConfig {
    pub target: TargetSpec,
    pub mode: SearchMode,
    pub output_mode: OutputMode,
    pub show_tick: bool,
    pub allow_null_access: bool,
    pub allow_duplicate_prefixes: bool,
    pub nx_support: bool,
    pub seed: Option<u64>,
    pub brute_depth: usize,
    pub max_prefix: usize,
    pub start_instruction: Option<InstructionBytes>,
    pub end_instruction: Option<InstructionBytes>,
    pub core: Option<usize>,
    pub blacklists: Vec<InstructionBytes>,
    pub jobs: usize,
    pub range_bytes: usize,
    pub dry_run: bool,
    pub worker: bool,
}

impl Default for InjectorConfig {
    fn default() -> Self {
        Self {
            target: TargetSpec::host(),
            mode: SearchMode::Tunnel,
            output_mode: OutputMode::Text,
            show_tick: false,
            allow_null_access: false,
            allow_duplicate_prefixes: false,
            nx_support: true,
            seed: None,
            brute_depth: 4,
            max_prefix: 0,
            start_instruction: None,
            end_instruction: None,
            core: None,
            blacklists: Vec::new(),
            jobs: 1,
            range_bytes: 0,
            dry_run: false,
            worker: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InjectorParseError {
    MissingValue(&'static str),
    InvalidValue(&'static str, String),
    UnexpectedArgument(String),
}

impl fmt::Display for InjectorParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingValue(flag) => write!(f, "missing value for {flag}"),
            Self::InvalidValue(flag, value) => write!(f, "invalid value for {flag}: {value}"),
            Self::UnexpectedArgument(value) => write!(f, "unexpected argument: {value}"),
        }
    }
}

impl std::error::Error for InjectorParseError {}

impl InjectorConfig {
    pub fn parse_args(args: &[String]) -> Result<Self, InjectorParseError> {
        let mut config = Self::default();
        let mut index = 0;
        while index < args.len() {
            let arg = &args[index];
            match arg.as_str() {
                "-b" => config.mode = SearchMode::Brute,
                "-r" => config.mode = SearchMode::Random,
                "-t" => config.mode = SearchMode::Tunnel,
                "-d" => config.mode = SearchMode::Driven,
                "-R" => config.output_mode = OutputMode::Raw,
                "-T" => config.output_mode = OutputMode::Text,
                "-x" => config.show_tick = true,
                "-0" => config.allow_null_access = true,
                "-D" => config.allow_duplicate_prefixes = true,
                "-N" => config.nx_support = false,
                "--dry-run" => config.dry_run = true,
                "--worker" => config.worker = true,
                "--target" => {
                    index += 1;
                    config.target = parse_target(next_arg(args, index, "--target")?)?;
                }
                "-s" => {
                    index += 1;
                    config.seed = Some(parse_number(next_arg(args, index, "-s")?, "-s")?);
                }
                "-B" => {
                    index += 1;
                    config.brute_depth = parse_number(next_arg(args, index, "-B")?, "-B")?;
                }
                "-P" => {
                    index += 1;
                    config.max_prefix = parse_number(next_arg(args, index, "-P")?, "-P")?;
                }
                "-i" => {
                    index += 1;
                    config.start_instruction =
                        Some(parse_instruction(next_arg(args, index, "-i")?, "-i")?);
                }
                "-e" => {
                    index += 1;
                    config.end_instruction =
                        Some(parse_instruction(next_arg(args, index, "-e")?, "-e")?);
                }
                "-c" => {
                    index += 1;
                    config.core = Some(parse_number(next_arg(args, index, "-c")?, "-c")?);
                }
                "-X" => {
                    index += 1;
                    config
                        .blacklists
                        .push(parse_instruction(next_arg(args, index, "-X")?, "-X")?);
                }
                "-j" => {
                    index += 1;
                    config.jobs = parse_number(next_arg(args, index, "-j")?, "-j")?;
                }
                "-l" => {
                    index += 1;
                    config.range_bytes = parse_number(next_arg(args, index, "-l")?, "-l")?;
                }
                "-?" | "--help" => {}
                _ if arg.starts_with("-s") && arg.len() > 2 => {
                    config.seed = Some(parse_number(&arg[2..], "-s")?);
                }
                _ if arg.starts_with("-B") && arg.len() > 2 => {
                    config.brute_depth = parse_number(&arg[2..], "-B")?;
                }
                _ if arg.starts_with("-P") && arg.len() > 2 => {
                    config.max_prefix = parse_number(&arg[2..], "-P")?;
                }
                _ if arg.starts_with("-i") && arg.len() > 2 => {
                    config.start_instruction = Some(parse_instruction(&arg[2..], "-i")?);
                }
                _ if arg.starts_with("-e") && arg.len() > 2 => {
                    config.end_instruction = Some(parse_instruction(&arg[2..], "-e")?);
                }
                _ if arg.starts_with("-c") && arg.len() > 2 => {
                    config.core = Some(parse_number(&arg[2..], "-c")?);
                }
                _ if arg.starts_with("-X") && arg.len() > 2 => {
                    config.blacklists.push(parse_instruction(&arg[2..], "-X")?);
                }
                _ if arg.starts_with("-j") && arg.len() > 2 => {
                    config.jobs = parse_number(&arg[2..], "-j")?;
                }
                _ if arg.starts_with("-l") && arg.len() > 2 => {
                    config.range_bytes = parse_number(&arg[2..], "-l")?;
                }
                _ => return Err(InjectorParseError::UnexpectedArgument(arg.clone())),
            }
            index += 1;
        }
        Ok(config)
    }

    pub fn help_text() -> &'static str {
        "injector [OPTIONS...]\n\
\t[-b|-r|-t|-d] ....... mode: brute, random, tunnel, directed (default: tunnel)\n\
\t[-R|-T] ............. output: raw, text (default: text)\n\
\t[-x] ................ show tick\n\
\t[-0] ................ allow null dereference (requires sudo)\n\
\t[-D] ................ allow duplicate prefixes\n\
\t[-N] ................ no nx bit support\n\
\t[-s seed] ........... in random search, seed\n\
\t[-B brute_depth] .... in brute search, maximum search depth\n\
\t[-P max_prefix] ..... maximum number of prefixes to search\n\
\t[-i instruction] .... instruction at which to start search, inclusive\n\
\t[-e instruction] .... instruction at which to end search, exclusive\n\
\t[-c core] ........... core on which to perform search\n\
\t[-X blacklist] ...... blacklist the specified instruction\n\
\t[-j jobs] ........... number of simultaneous jobs to run\n\
\t[-l range_bytes] .... number of base instruction bytes in each sub range\n\
\t[--target target] ... linux-x86_64, android-arm64, ios-arm64, or host\n\
\t[--dry-run] ......... generate deterministic synthetic observations\n"
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BackendObservation {
    pub valid: u32,
    pub length: u32,
    pub signum: u32,
    pub si_code: u32,
    pub fault_addr: u32,
}

impl BackendObservation {
    pub fn into_execution_result(
        self,
        instruction: InstructionBytes,
        disasm: DisasmResult,
    ) -> ExecutionResult {
        ExecutionResult {
            disasm,
            instruction,
            valid: self.valid,
            length: self.length,
            signum: self.signum,
            si_code: self.si_code,
            fault_addr: self.fault_addr,
        }
    }
}

pub fn decode_with_backend(
    backend: &dyn DisasmBackend,
    instruction: &InstructionBytes,
) -> DisasmResult {
    match backend.decode_first(instruction) {
        Ok(decoded) => DisasmResult {
            length: decoded.length,
            known: decoded.known,
        },
        Err(_) => DisasmResult::default(),
    }
}

fn next_arg<'a>(
    args: &'a [String],
    index: usize,
    flag: &'static str,
) -> Result<&'a str, InjectorParseError> {
    args.get(index)
        .map(String::as_str)
        .ok_or(InjectorParseError::MissingValue(flag))
}

fn parse_number<T>(value: &str, flag: &'static str) -> Result<T, InjectorParseError>
where
    T: std::str::FromStr,
{
    value
        .parse()
        .map_err(|_| InjectorParseError::InvalidValue(flag, value.to_string()))
}

fn parse_instruction(
    value: &str,
    flag: &'static str,
) -> Result<InstructionBytes, InjectorParseError> {
    parse_hex_instruction(value)
        .map_err(|msg| InjectorParseError::InvalidValue(flag, msg.to_string()))
}

fn parse_target(value: &str) -> Result<TargetSpec, InjectorParseError> {
    value
        .parse()
        .map_err(|_| InjectorParseError::InvalidValue("--target", value.to_string()))
}

#[cfg(test)]
mod tests {
    use sandblaster_core::{DisasmResult, InstructionBytes};
    use sandblaster_disasm::{DecodeError, DecodeOutput, DisasmBackend};
    use sandblaster_search::SearchMode;

    use crate::{
        decode_with_backend, BackendObservation, InjectorConfig, OutputMode, RawInjectorPacket,
    };

    struct TestDisassembler;

    impl DisasmBackend for TestDisassembler {
        fn name(&self) -> &'static str {
            "test"
        }

        fn decode_first(
            &self,
            _instruction: &InstructionBytes,
        ) -> Result<DecodeOutput, DecodeError> {
            Ok(DecodeOutput {
                mnemonic: "nop".to_string(),
                operands: String::new(),
                length: 1,
                known: true,
            })
        }
    }

    #[test]
    fn parses_reference_flags() {
        let args = vec![
            "-t".to_string(),
            "-R".to_string(),
            "-s".to_string(),
            "7".to_string(),
            "-j".to_string(),
            "4".to_string(),
        ];
        let config = InjectorConfig::parse_args(&args).expect("injector args should parse");
        assert_eq!(config.mode, SearchMode::Tunnel);
        assert_eq!(config.output_mode, OutputMode::Raw);
        assert_eq!(config.seed, Some(7));
        assert_eq!(config.jobs, 4);
    }

    #[test]
    fn parses_compact_value_flags() {
        let args = vec![
            "-t".to_string(),
            "-P1".to_string(),
            "-B1".to_string(),
            "-i00".to_string(),
            "-eff".to_string(),
        ];
        let config = InjectorConfig::parse_args(&args).expect("injector args should parse");
        assert_eq!(config.mode, SearchMode::Tunnel);
        assert_eq!(config.max_prefix, 1);
        assert_eq!(config.brute_depth, 1);
        assert_eq!(
            config.start_instruction,
            Some(InstructionBytes::from_slice(&[0x00]))
        );
        assert_eq!(
            config.end_instruction,
            Some(InstructionBytes::from_slice(&[0xff]))
        );
    }

    #[test]
    fn raw_packet_layout_matches_reference_fields() {
        let observation = BackendObservation {
            valid: 1,
            length: 2,
            signum: 5,
            si_code: 1,
            fault_addr: 0xffff_fffe,
        };
        let result = observation.into_execution_result(
            InstructionBytes::from_slice(&[0x90, 0xcc]),
            DisasmResult {
                length: 1,
                known: true,
            },
        );
        let packet = RawInjectorPacket::from_execution_result(&result);
        let bytes = packet.to_bytes();
        assert_eq!(bytes.len(), 44);
    }

    #[test]
    fn disasm_adapter_preserves_known_and_length() {
        let decoded =
            decode_with_backend(&TestDisassembler, &InstructionBytes::from_slice(&[0x90]));
        assert_eq!(decoded.length, 1);
        assert!(decoded.known);
    }
}
