use std::collections::{BTreeMap, VecDeque};
use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sandblaster_core::{
    CpuMetadata, ExecutionResult, FilterConfig, LegacyArtifactRecord, LegacyHeader, LegacyLog,
    TargetSpec, RAW_REPORT_INSN_BYTES,
};
use sandblaster_injector::VersionedPacket;

const DATA_DIR: &str = "data";
const LOG_PATH: &str = "data/log";
const SYNC_PATH: &str = "data/sync";
const LAST_PATH: &str = "data/last";
const TICK_PATH: &str = "data/tick";
const FINDINGS_PATH: &str = "data/findings.tsv";
const SUMMARY_PATH: &str = "data/summary";
const INSTRUCTION_LOG_LEN: usize = 20;
const ARTIFACT_LOG_LEN: usize = 10;
const UI_REFRESH_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Debug, Eq, PartialEq)]
struct CliConfig {
    filters: FilterConfig,
    tick: bool,
    save: bool,
    resume: bool,
    sync: bool,
    low_mem: bool,
    live_ui: bool,
    input_path: Option<PathBuf>,
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
    recent_results: VecDeque<ExecutionResult>,
    recent_artifacts: VecDeque<ExecutionResult>,
    artifacts: BTreeMap<Vec<u8>, ExecutionResult>,
    target: Option<TargetSpec>,
    started: Instant,
}

impl ScanStats {
    fn new() -> Self {
        Self {
            tested: 0,
            artifacts_found: 0,
            last_result: None,
            recent_results: VecDeque::with_capacity(INSTRUCTION_LOG_LEN),
            recent_artifacts: VecDeque::with_capacity(ARTIFACT_LOG_LEN),
            artifacts: BTreeMap::new(),
            target: None,
            started: Instant::now(),
        }
    }

    fn elapsed_text(&self) -> String {
        let elapsed = self.started.elapsed();
        format!("{}.{:03}s", elapsed.as_secs(), elapsed.subsec_millis())
    }
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            filters: FilterConfig::default(),
            tick: false,
            save: false,
            resume: false,
            sync: false,
            low_mem: false,
            live_ui: true,
            input_path: None,
            injector_args: Vec::new(),
        }
    }
}

struct LiveDisplay {
    enabled: bool,
    last_draw: Instant,
    last_tested: u64,
    last_rate_at: Instant,
    rate_per_second: u64,
}

impl LiveDisplay {
    fn new(enabled: bool) -> Self {
        if enabled {
            print!("\x1b[?25l");
            let _ = io::stdout().flush();
        }
        Self {
            enabled,
            last_draw: Instant::now() - UI_REFRESH_INTERVAL,
            last_tested: 0,
            last_rate_at: Instant::now(),
            rate_per_second: 0,
        }
    }

    fn maybe_draw(&mut self, stats: &ScanStats, force: bool) -> io::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if !force && self.last_draw.elapsed() < UI_REFRESH_INTERVAL {
            return Ok(());
        }
        self.draw(stats)
    }

    fn draw(&mut self, stats: &ScanStats) -> io::Result<()> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_rate_at);
        if elapsed >= Duration::from_secs(1) {
            self.rate_per_second =
                ((stats.tested - self.last_tested) as f64 / elapsed.as_secs_f64()) as u64;
            self.last_tested = stats.tested;
            self.last_rate_at = now;
        }
        self.last_draw = now;

        let mut out = String::new();
        out.push_str("\x1b[H\x1b[2J");
        out.push_str("sandblaster live scan\n");
        out.push_str("=====================\n\n");
        out.push_str(&format!(
            "tested: {:>12}    artifacts: {:>8}    rate: {:>8}/s    elapsed: {}\n",
            comma(stats.tested),
            comma(stats.artifacts_found),
            comma(self.rate_per_second),
            stats.elapsed_text()
        ));

        if let Some(result) = &stats.last_result {
            out.push_str(&format!(
                "current: v={:<2} len={:<2} sig={:<2} code={:<3} addr={:08x} disas_len={} known={} {}\n",
                result.valid,
                result.length,
                result.signum,
                result.si_code,
                result.fault_addr,
                result.disasm.length,
                u8::from(result.disasm.known),
                result_hex(result)
            ));
        } else {
            out.push_str("current: waiting for injector results...\n");
        }

        out.push_str("\nrecent instructions\n");
        out.push_str("  v  l  s  c  dis known  bytes\n");
        for result in stats.recent_results.iter().rev().take(INSTRUCTION_LOG_LEN) {
            out.push_str(&format_result_row(result));
            out.push('\n');
        }

        out.push_str("\nrecent findings\n");
        if stats.recent_artifacts.is_empty() {
            out.push_str("  none yet\n");
        } else {
            out.push_str("  v  l  s  c  dis known  bytes\n");
            for result in stats.recent_artifacts.iter().rev().take(ARTIFACT_LOG_LEN) {
                out.push_str(&format_result_row(result));
                out.push('\n');
            }
        }

        out.push_str("\nPress Ctrl-C to stop. Final log is written to data/log when the injector exits cleanly.\n");
        print!("{out}");
        io::stdout().flush()
    }

    fn finish(&mut self) {
        if self.enabled {
            print!("\x1b[?25h");
            let _ = io::stdout().flush();
        }
    }
}

impl Drop for LiveDisplay {
    fn drop(&mut self) {
        self.finish();
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
    let injector_command = if let Some(path) = &config.input_path {
        format!("import {}", path.display())
    } else {
        format!("{} {}", injector_path().display(), injector_args.join(" "))
    };
    let mut sync_file = if config.sync {
        Some(create_sync_log(&command_line, &injector_command)?)
    } else {
        None
    };

    let mut child = if config.input_path.is_none() {
        Some(spawn_injector(&injector_args)?)
    } else {
        None
    };
    let input_file = if let Some(path) = &config.input_path {
        Some(File::open(path).map_err(|error| {
            format!(
                "failed to open input packet log {}: {error}",
                path.display()
            )
        })?)
    } else {
        None
    };
    let mut lines: Box<dyn Iterator<Item = io::Result<String>>> = if let Some(file) = input_file {
        Box::new(BufReader::new(file).lines())
    } else {
        let stdout = child
            .as_mut()
            .and_then(|child| child.stdout.take())
            .ok_or_else(|| "failed to capture injector stdout".to_string())?;
        Box::new(BufReader::new(stdout).lines())
    };
    let mut stats = ScanStats::new();
    let mut live = LiveDisplay::new(config.live_ui && io::stdout().is_terminal());
    live.maybe_draw(&stats, true).map_err(write_error)?;

    for line in lines.by_ref() {
        match line {
            Ok(line) => {
                if line.trim().is_empty() || line.starts_with('#') {
                    continue;
                }
                let packet = VersionedPacket::parse_line(&line)?;
                stats.target = Some(packet.target);
                let result = packet.result;
                stats.tested += 1;
                stats.last_result = Some(result.clone());
                if config.tick {
                    write_tick(&result)?;
                }
                if config.save {
                    write_last_result(&result)?;
                }
                push_bounded(
                    &mut stats.recent_results,
                    result.clone(),
                    INSTRUCTION_LOG_LEN,
                );
                if config.filters.detect(&result).is_some() {
                    record_artifact(&mut stats, result, config.low_mem, sync_file.as_mut())?;
                    live.maybe_draw(&stats, true).map_err(write_error)?;
                } else {
                    live.maybe_draw(&stats, false).map_err(write_error)?;
                }
            }
            Err(error) => return Err(format!("failed to read injector packet: {error}")),
        }
    }

    if let Some(mut child) = child {
        let status = child
            .wait()
            .map_err(|error| format!("failed to wait for injector: {error}"))?;
        if !status.success() {
            return Err(format!("injector exited with {status}"));
        }
    }

    write_final_log(&stats, &command_line, &injector_command)?;
    write_findings(&stats, &command_line, &injector_command)?;
    write_summary(&stats)?;
    live.maybe_draw(&stats, true).map_err(write_error)?;
    if config.save {
        write_last(&stats)?;
    }

    Ok(())
}

fn parse_cli_args(args: &[String]) -> Result<CliConfig, CliParseError> {
    let mut config = CliConfig::default();
    let mut passthrough = false;

    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if passthrough {
            config.injector_args.push(arg.clone());
            index += 1;
            continue;
        }

        match arg.as_str() {
            "--" => passthrough = true,
            "--input" => {
                index += 1;
                let Some(path) = args.get(index) else {
                    return Err(CliParseError::UnexpectedArgument(
                        "--input requires a path".to_string(),
                    ));
                };
                config.input_path = Some(PathBuf::from(path));
                config.live_ui = false;
            }
            "--len" => config.filters.search_length = true,
            "--dis" => config.filters.search_disasm_length = true,
            "--unk" => config.filters.search_unknown = true,
            "--ill" => config.filters.search_invalid_known = true,
            "--tick" => config.tick = true,
            "--save" => config.save = true,
            "--resume" => config.resume = true,
            "--sync" => config.sync = true,
            "--low-mem" => config.low_mem = true,
            "--no-ui" => config.live_ui = false,
            _ => return Err(CliParseError::UnexpectedArgument(arg.clone())),
        }
        index += 1;
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
        push_bounded(
            &mut stats.recent_artifacts,
            result.clone(),
            ARTIFACT_LOG_LEN,
        );
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
            arch: Some(
                stats
                    .target
                    .map(|target| target.name().to_string())
                    .unwrap_or_else(|| (usize::BITS).to_string()),
            ),
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
    write_last_result(result)
}

fn write_last_result(result: &ExecutionResult) -> Result<(), String> {
    let text = sandblaster_core::format_full_hex(
        &result.instruction.bytes()[..result.length.min(RAW_REPORT_INSN_BYTES as u32) as usize],
    );
    fs::write(LAST_PATH, text).map_err(|error| format!("failed to write {LAST_PATH}: {error}"))
}

fn write_tick(result: &ExecutionResult) -> Result<(), String> {
    let text = sandblaster_core::format_full_hex(result.instruction.bytes());
    fs::write(TICK_PATH, text).map_err(|error| format!("failed to write {TICK_PATH}: {error}"))
}

fn write_findings(
    stats: &ScanStats,
    command_line: &str,
    injector_command: &str,
) -> Result<(), String> {
    let mut out = String::new();
    out.push_str("# command\t");
    out.push_str(command_line);
    out.push('\n');
    out.push_str("# injector\t");
    out.push_str(injector_command);
    out.push('\n');
    out.push_str("target\texecuted_hex\traw_hex\tvalid\tlength\tsignum\tsi_code\tfault_addr\tdisas_known\tdisas_length\n");
    for result in stats.artifacts.values() {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:08x}\t{}\t{}\n",
            stats
                .target
                .map(|target| target.name())
                .unwrap_or("unknown"),
            result.executed_key_hex(),
            result.raw_payload_hex(),
            result.valid,
            result.length,
            result.signum,
            result.si_code,
            result.fault_addr,
            u8::from(result.disasm.known),
            result.disasm.length
        ));
    }
    fs::write(FINDINGS_PATH, out)
        .map_err(|error| format!("failed to write {FINDINGS_PATH}: {error}"))
}

fn write_summary(stats: &ScanStats) -> Result<(), String> {
    let mut groups: BTreeMap<String, u64> = BTreeMap::new();
    for result in stats.artifacts.values() {
        let executed = result.instruction.executed_prefix(result.length as usize);
        let opcode = first_opcode_byte(executed);
        let prefix = first_prefix_byte(executed);
        let disasm_class = if result.disasm.known {
            "known"
        } else {
            "unknown"
        };
        let key = format!(
            "opcode={opcode} prefix={prefix} signal={} disasm={disasm_class}",
            result.signum
        );
        *groups.entry(key).or_default() += 1;
    }

    let mut out = String::new();
    out.push_str(&format!("tested\t{}\n", stats.tested));
    out.push_str(&format!("artifacts\t{}\n", stats.artifacts_found));
    for (key, count) in groups {
        out.push_str(&format!("{count}\t{key}\n"));
    }
    fs::write(SUMMARY_PATH, out).map_err(|error| format!("failed to write {SUMMARY_PATH}: {error}"))
}

fn first_opcode_byte(bytes: &[u8]) -> String {
    bytes
        .iter()
        .copied()
        .find(|byte| !is_prefix(*byte))
        .map(|byte| format!("{byte:02x}"))
        .unwrap_or_else(|| "none".to_string())
}

fn first_prefix_byte(bytes: &[u8]) -> String {
    bytes
        .iter()
        .copied()
        .take_while(|byte| is_prefix(*byte))
        .next()
        .map(|byte| format!("{byte:02x}"))
        .unwrap_or_else(|| "none".to_string())
}

fn is_prefix(byte: u8) -> bool {
    matches!(
        byte,
        0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 | 0x66 | 0x67 | 0x40..=0x4f
    )
}

fn write_error(error: io::Error) -> String {
    format!("failed to write log: {error}")
}

fn push_bounded<T>(items: &mut VecDeque<T>, item: T, max_len: usize) {
    if items.len() == max_len {
        items.pop_front();
    }
    items.push_back(item);
}

fn comma(value: u64) -> String {
    let text = value.to_string();
    let mut out = String::new();
    for (index, ch) in text.chars().rev().enumerate() {
        if index > 0 && index % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

fn result_hex(result: &ExecutionResult) -> String {
    sandblaster_core::format_full_hex(result.instruction.bytes())
}

fn format_result_row(result: &ExecutionResult) -> String {
    format!(
        "{:>3} {:>2} {:>2} {:>2} {:>4} {:>5}  {}",
        result.valid,
        result.length,
        result.signum,
        result.si_code,
        result.disasm.length,
        u8::from(result.disasm.known),
        result_hex(result)
    )
}

fn epoch_seconds_text() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn help_text() -> &'static str {
    "sifter [--input sb1.log] [--len] [--dis] [--unk] [--ill] [--tick] [--save] [--resume] [--sync] [--low-mem] [--no-ui] -- [injector args...]\n"
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
            "--no-ui".to_string(),
            "--".to_string(),
            "-P1".to_string(),
            "-t".to_string(),
        ];
        let config = parse_cli_args(&args).expect("args should parse");
        assert!(config.filters.search_unknown);
        assert!(config.sync);
        assert!(!config.live_ui);
        assert_eq!(config.injector_args, ["-P1", "-t"]);
    }

    #[test]
    fn parses_input_import_path() {
        let args = vec![
            "--input".to_string(),
            "ios.log".to_string(),
            "--unk".to_string(),
        ];
        let config = parse_cli_args(&args).expect("args should parse");
        assert_eq!(
            config.input_path.as_deref(),
            Some(std::path::Path::new("ios.log"))
        );
        assert!(config.filters.search_unknown);
        assert!(!config.live_ui);
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
