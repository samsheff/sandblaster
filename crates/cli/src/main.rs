use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use sandblaster_core::{
    CpuMetadata, ExecutionResult, FilterConfig, LegacyArtifactRecord, LegacyHeader, LegacyLog,
    RAW_REPORT_INSN_BYTES,
};
use sandblaster_injector::RawInjectorPacket;

const DATA_DIR: &str = "data";
const LOG_PATH: &str = "data/log";
const SYNC_PATH: &str = "data/sync";
const LAST_PATH: &str = "data/last";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct CliConfig {
    filters: FilterConfig,
    tick: bool,
    save: bool,
    resume: bool,
    sync: bool,
    low_mem: bool,
    injector_args: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CliParseError {
    UnexpectedArgument(String),
}

impl fmt::Display for CliParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedArgument(arg) => write!(f, "unexpected argument: {arg}"),
        }
    }
}

#[derive(Debug)]
struct ScanStats {
    tested: u64,
    artifacts_found: u64,
    last_result: Option<ExecutionResult>,
    artifacts: BTreeMap<Vec<u8>, ExecutionResult>,
    started: Instant,
}

impl ScanStats {
    fn new() -> Self {
        Self {
            tested: 0,
            artifacts_found: 0,
            last_result: None,
            artifacts: BTreeMap::new(),
            started: Instant::now(),
        }
    }

    fn elapsed_text(&self) -> String {
        let elapsed = self.started.elapsed();
        format!("{}.{:03}s", elapsed.as_secs(), elapsed.subsec_millis())
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print!("{}", help_text());
        return ExitCode::SUCCESS;
    }

    let config = match parse_cli_args(&args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(1);
        }
    };

    match run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn run(config: CliConfig) -> Result<(), String> {
    fs::create_dir_all(DATA_DIR)
        .map_err(|error| format!("failed to create {DATA_DIR}: {error}"))?;

    let mut injector_args = config.injector_args.clone();
    if config.resume {
        apply_resume(&mut injector_args, Path::new(LAST_PATH))?;
    }
    if config.tick && !injector_args.iter().any(|arg| arg == "-x") {
        injector_args.push("-x".to_string());
    }
    injector_args.push("-R".to_string());

    let command_line = env::args().collect::<Vec<_>>().join(" ");
    let injector_command = format!("{} {}", injector_path().display(), injector_args.join(" "));
    let mut sync_file = if config.sync {
        Some(create_sync_log(&command_line, &injector_command)?)
    } else {
        None
    };

    let mut child = spawn_injector(&injector_args)?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture injector stdout".to_string())?;
    let mut stats = ScanStats::new();
    let mut raw = [0_u8; 44];

    loop {
        match stdout.read_exact(&mut raw) {
            Ok(()) => {
                let result = RawInjectorPacket::from_bytes(raw).into_execution_result();
                stats.tested += 1;
                stats.last_result = Some(result.clone());
                if config.filters.detect(&result).is_some() {
                    record_artifact(&mut stats, result, config.low_mem, sync_file.as_mut())?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(error) => return Err(format!("failed to read injector packet: {error}")),
        }
    }

    let status = child
        .wait()
        .map_err(|error| format!("failed to wait for injector: {error}"))?;
    if !status.success() {
        return Err(format!("injector exited with {status}"));
    }

    write_final_log(&stats, &command_line, &injector_command)?;
    if config.save {
        write_last(&stats)?;
    }

    Ok(())
}

fn parse_cli_args(args: &[String]) -> Result<CliConfig, CliParseError> {
    let mut config = CliConfig::default();
    let mut passthrough = false;

    for arg in args {
        if passthrough {
            config.injector_args.push(arg.clone());
            continue;
        }

        match arg.as_str() {
            "--" => passthrough = true,
            "--len" => config.filters.search_length = true,
            "--dis" => config.filters.search_disasm_length = true,
            "--unk" => config.filters.search_unknown = true,
            "--ill" => config.filters.search_invalid_known = true,
            "--tick" => config.tick = true,
            "--save" => config.save = true,
            "--resume" => config.resume = true,
            "--sync" => config.sync = true,
            "--low-mem" => config.low_mem = true,
            _ => return Err(CliParseError::UnexpectedArgument(arg.clone())),
        }
    }

    Ok(config)
}

fn apply_resume(injector_args: &mut Vec<String>, last_path: &Path) -> Result<(), String> {
    if injector_args.iter().any(|arg| arg == "-i") {
        return Err("--resume is incompatible with -i".to_string());
    }
    let instruction = fs::read_to_string(last_path)
        .map_err(|_| format!("no resume file found at {}", last_path.display()))?;
    injector_args.push("-i".to_string());
    injector_args.push(instruction.trim().to_string());
    Ok(())
}

fn spawn_injector(args: &[String]) -> Result<Child, String> {
    Command::new(injector_path())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("failed to spawn injector: {error}"))
}

fn injector_path() -> PathBuf {
    env::var_os("SANDBLASTER_INJECTOR")
        .map(PathBuf::from)
        .or_else(|| {
            env::current_exe()
                .ok()
                .and_then(|path| path.parent().map(|parent| parent.join("injector")))
        })
        .unwrap_or_else(|| PathBuf::from("injector"))
}

fn create_sync_log(command_line: &str, injector_command: &str) -> Result<File, String> {
    let mut file = File::create(SYNC_PATH)
        .map_err(|error| format!("failed to create {SYNC_PATH}: {error}"))?;
    write_header(&mut file, command_line, injector_command, None, None, None)?;
    Ok(file)
}

fn record_artifact(
    stats: &mut ScanStats,
    result: ExecutionResult,
    low_mem: bool,
    sync_file: Option<&mut File>,
) -> Result<(), String> {
    let key = result
        .instruction
        .executed_prefix(result.length as usize)
        .to_vec();
    let is_new = low_mem || !stats.artifacts.contains_key(&key);
    if is_new {
        stats.artifacts_found += 1;
        if !low_mem {
            stats.artifacts.insert(key, result.clone());
        }
        if let Some(file) = sync_file {
            write_artifact_line(file, &result)?;
        }
    }
    Ok(())
}

fn write_final_log(
    stats: &ScanStats,
    command_line: &str,
    injector_command: &str,
) -> Result<(), String> {
    let mut log = LegacyLog {
        header: LegacyHeader {
            command_line: Some(command_line.to_string()),
            injector_command: Some(injector_command.to_string()),
            insn_tested: Some(stats.tested),
            artifacts_found: Some(stats.artifacts_found),
            runtime: Some(stats.elapsed_text()),
            seed: None,
            arch: Some((usize::BITS).to_string()),
            date: Some(epoch_seconds_text()),
            cpu: CpuMetadata::from_cpuinfo_path("/proc/cpuinfo").unwrap_or_default(),
            extra_comments: Vec::new(),
        },
        records: stats
            .artifacts
            .values()
            .cloned()
            .map(|result| LegacyArtifactRecord { result })
            .collect(),
    };
    log.records.sort_by_key(|record| {
        record
            .result
            .instruction
            .executed_prefix(record.result.length as usize)
            .to_vec()
    });
    fs::write(LOG_PATH, log.to_text())
        .map_err(|error| format!("failed to write {LOG_PATH}: {error}"))
}

fn write_header(
    file: &mut File,
    command_line: &str,
    injector_command: &str,
    tested: Option<u64>,
    found: Option<u64>,
    runtime: Option<&str>,
) -> Result<(), String> {
    writeln!(file, "#").map_err(write_error)?;
    writeln!(file, "# {command_line}").map_err(write_error)?;
    writeln!(file, "# {injector_command}").map_err(write_error)?;
    writeln!(file, "#").map_err(write_error)?;
    if let Some(tested) = tested {
        writeln!(file, "# insn tested: {tested}").map_err(write_error)?;
    }
    if let Some(found) = found {
        writeln!(file, "# artf found: {found}").map_err(write_error)?;
    }
    if let Some(runtime) = runtime {
        writeln!(file, "# runtime: {runtime}").map_err(write_error)?;
    }
    writeln!(file, "# cpu:").map_err(write_error)?;
    if let Ok(cpu) = CpuMetadata::from_cpuinfo_path("/proc/cpuinfo") {
        for line in cpu.raw_lines {
            writeln!(file, "# {line}").map_err(write_error)?;
        }
    }
    writeln!(file, "#                              v  l  s  c").map_err(write_error)?;
    Ok(())
}

fn write_artifact_line(file: &mut File, result: &ExecutionResult) -> Result<(), String> {
    let record = LegacyArtifactRecord {
        result: result.clone(),
    };
    writeln!(file, "{}", record.to_legacy_line()).map_err(write_error)
}

fn write_last(stats: &ScanStats) -> Result<(), String> {
    let Some(result) = &stats.last_result else {
        return Ok(());
    };
    let text = sandblaster_core::format_full_hex(
        &result.instruction.bytes()[..result.length.min(RAW_REPORT_INSN_BYTES as u32) as usize],
    );
    fs::write(LAST_PATH, text).map_err(|error| format!("failed to write {LAST_PATH}: {error}"))
}

fn write_error(error: io::Error) -> String {
    format!("failed to write log: {error}")
}

fn epoch_seconds_text() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn help_text() -> &'static str {
    "sifter [--len] [--dis] [--unk] [--ill] [--tick] [--save] [--resume] [--sync] [--low-mem] -- [injector args...]\n"
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{apply_resume, parse_cli_args};

    #[test]
    fn parses_frontend_and_passthrough_flags() {
        let args = vec![
            "--unk".to_string(),
            "--sync".to_string(),
            "--".to_string(),
            "-P1".to_string(),
            "-t".to_string(),
        ];
        let config = parse_cli_args(&args).expect("args should parse");
        assert!(config.filters.search_unknown);
        assert!(config.sync);
        assert_eq!(config.injector_args, ["-P1", "-t"]);
    }

    #[test]
    fn resume_appends_start_instruction() {
        let dir = std::env::temp_dir().join(format!("sandblaster-test-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        let last = dir.join("last");
        fs::write(&last, "90").expect("last should be written");
        let mut args = vec!["-t".to_string()];
        apply_resume(&mut args, &last).expect("resume should apply");
        assert_eq!(args, ["-t", "-i", "90"]);
        let _ = fs::remove_file(last);
        let _ = fs::remove_dir(dir);
    }
}
