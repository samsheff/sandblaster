use std::fmt;
use std::str::FromStr;

use crate::{
    cpu::CpuMetadata,
    instruction::{format_compact_hex, parse_hex_instruction, InstructionBytes},
    result::{DisasmResult, ExecutionResult},
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LegacyHeader {
    pub command_line: Option<String>,
    pub injector_command: Option<String>,
    pub insn_tested: Option<u64>,
    pub artifacts_found: Option<u64>,
    pub runtime: Option<String>,
    pub seed: Option<u64>,
    pub arch: Option<String>,
    pub date: Option<String>,
    pub cpu: CpuMetadata,
    pub extra_comments: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyArtifactRecord {
    pub result: ExecutionResult,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LegacyLog {
    pub header: LegacyHeader,
    pub records: Vec<LegacyArtifactRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyTick(pub InstructionBytes);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LegacyParseError {
    InvalidHeader(String),
    InvalidRecord(String),
}

impl fmt::Display for LegacyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeader(msg) => write!(f, "invalid legacy header: {msg}"),
            Self::InvalidRecord(msg) => write!(f, "invalid legacy record: {msg}"),
        }
    }
}

impl std::error::Error for LegacyParseError {}

impl LegacyArtifactRecord {
    pub fn to_legacy_line(&self) -> String {
        format!(
            "{} {:2} {:2} {:2} {:2} ({})",
            self.result.executed_key_hex(),
            self.result.valid,
            self.result.length,
            self.result.signum,
            self.result.si_code,
            self.result.raw_payload_hex(),
        )
    }
}

impl FromStr for LegacyArtifactRecord {
    type Err = LegacyParseError;

    fn from_str(line: &str) -> Result<Self, Self::Err> {
        let mut fields = line.split_whitespace();
        let insn_hex = fields
            .next()
            .ok_or_else(|| LegacyParseError::InvalidRecord("missing instruction bytes".into()))?;
        let valid = parse_u32(fields.next(), "valid")?;
        let length = parse_u32(fields.next(), "length")?;
        let signum = parse_u32(fields.next(), "signum")?;
        let si_code = parse_u32(fields.next(), "si_code")?;
        let raw = fields
            .next()
            .ok_or_else(|| LegacyParseError::InvalidRecord("missing raw payload".into()))?;

        let raw = raw
            .strip_prefix('(')
            .and_then(|value| value.strip_suffix(')'))
            .ok_or_else(|| {
                LegacyParseError::InvalidRecord("raw payload is not parenthesized".into())
            })?;
        let raw_instruction = parse_hex_instruction(raw).map_err(|msg| {
            LegacyParseError::InvalidRecord(format!("invalid raw payload: {msg}"))
        })?;
        let executed_instruction = parse_hex_instruction(insn_hex).map_err(|msg| {
            LegacyParseError::InvalidRecord(format!("invalid executed key: {msg}"))
        })?;

        let mut instruction = raw_instruction;
        instruction.set_specified_len(executed_instruction.specified_len());

        Ok(Self {
            result: ExecutionResult {
                disasm: DisasmResult::default(),
                instruction,
                valid,
                length,
                signum,
                si_code,
                fault_addr: u32::MAX,
            },
        })
    }
}

impl LegacyLog {
    pub fn parse(input: &str) -> Result<Self, LegacyParseError> {
        let mut log = Self::default();
        let mut in_cpu_block = false;

        for line in input.lines() {
            if let Some(comment) = line.strip_prefix("# ") {
                if comment == "cpu:" {
                    in_cpu_block = true;
                    continue;
                }

                if in_cpu_block && comment.contains('\t') {
                    log.header.cpu.raw_lines.push(comment.to_string());
                    if let Some((key, value)) = comment.split_once(':') {
                        match key.trim() {
                            "processor" => log.header.cpu.processor = Some(value.trim().into()),
                            "vendor_id" => log.header.cpu.vendor_id = Some(value.trim().into()),
                            "cpu family" => log.header.cpu.cpu_family = Some(value.trim().into()),
                            "model" => log.header.cpu.model = Some(value.trim().into()),
                            "model name" => log.header.cpu.model_name = Some(value.trim().into()),
                            "stepping" => log.header.cpu.stepping = Some(value.trim().into()),
                            "microcode" => log.header.cpu.microcode = Some(value.trim().into()),
                            _ => {}
                        }
                    }
                    continue;
                }

                in_cpu_block = false;
                parse_header_comment(comment, &mut log.header)?;
                continue;
            }

            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }

            log.records.push(line.parse()?);
        }

        if let Some(arch) = &log.header.arch {
            if let Some(bits) = arch.parse::<u32>().ok() {
                log.header.cpu.architecture_bits = Some(bits);
            }
        }

        Ok(log)
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str("#\n");
        if let Some(command_line) = &self.header.command_line {
            out.push_str("# ");
            out.push_str(command_line);
            out.push('\n');
        }
        if let Some(injector_command) = &self.header.injector_command {
            out.push_str("# ");
            out.push_str(injector_command);
            out.push('\n');
        }
        out.push_str("#\n");

        emit_kv(&mut out, "insn tested", self.header.insn_tested);
        emit_kv(&mut out, "artf found", self.header.artifacts_found);
        emit_kv_str(&mut out, "runtime", self.header.runtime.as_deref());
        emit_kv(&mut out, "seed", self.header.seed);
        emit_kv_str(&mut out, "arch", self.header.arch.as_deref());
        emit_kv_str(&mut out, "date", self.header.date.as_deref());

        out.push_str("#\n# cpu:\n");
        for line in &self.header.cpu.raw_lines {
            out.push_str("# ");
            out.push_str(line);
            out.push('\n');
        }
        out.push_str("#                              v  l  s  c\n");

        for record in &self.records {
            out.push_str(&record.to_legacy_line());
            out.push('\n');
        }

        out
    }
}

impl LegacyTick {
    pub fn parse(input: &str) -> Result<Self, LegacyParseError> {
        let instruction = parse_hex_instruction(input.trim())
            .map_err(|msg| LegacyParseError::InvalidRecord(format!("invalid tick hex: {msg}")))?;
        Ok(Self(instruction))
    }

    pub fn to_text(&self) -> String {
        format_compact_hex(&self.0.bytes()[..self.0.specified_len()])
    }
}

fn parse_header_comment(comment: &str, header: &mut LegacyHeader) -> Result<(), LegacyParseError> {
    if let Some((key, value)) = comment.split_once(':') {
        match key.trim() {
            "insn tested" => {
                header.insn_tested =
                    Some(value.trim().parse().map_err(|_| {
                        LegacyParseError::InvalidHeader("invalid insn tested".into())
                    })?);
            }
            "artf found" => {
                header.artifacts_found =
                    Some(value.trim().parse().map_err(|_| {
                        LegacyParseError::InvalidHeader("invalid artf found".into())
                    })?);
            }
            "runtime" => header.runtime = Some(value.trim().to_string()),
            "seed" => {
                header.seed = Some(
                    value
                        .trim()
                        .parse()
                        .map_err(|_| LegacyParseError::InvalidHeader("invalid seed".into()))?,
                );
            }
            "arch" => header.arch = Some(value.trim().to_string()),
            "date" => header.date = Some(value.trim().to_string()),
            _ => header.extra_comments.push(comment.to_string()),
        }
    } else if header.command_line.is_none() {
        header.command_line = Some(comment.to_string());
    } else if header.injector_command.is_none() {
        header.injector_command = Some(comment.to_string());
    } else {
        header.extra_comments.push(comment.to_string());
    }
    Ok(())
}

fn parse_u32(value: Option<&str>, label: &str) -> Result<u32, LegacyParseError> {
    let value =
        value.ok_or_else(|| LegacyParseError::InvalidRecord(format!("missing {label} field")))?;
    value
        .parse()
        .map_err(|_| LegacyParseError::InvalidRecord(format!("invalid {label} value")))
}

fn emit_kv(out: &mut String, key: &str, value: Option<u64>) {
    if let Some(value) = value {
        out.push_str("# ");
        out.push_str(key);
        out.push_str(": ");
        out.push_str(&value.to_string());
        out.push('\n');
    }
}

fn emit_kv_str(out: &mut String, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        out.push_str("# ");
        out.push_str(key);
        out.push_str(": ");
        out.push_str(value);
        out.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::{LegacyArtifactRecord, LegacyLog, LegacyTick};

    #[test]
    fn parses_legacy_record_lines() {
        let record: LegacyArtifactRecord = "90  1  1  5  1 (90000000000000000000000000000000)"
            .parse()
            .expect("record should parse");
        assert_eq!(record.result.length, 1);
        assert_eq!(record.result.executed_key_hex(), "90");
    }

    #[test]
    fn parses_and_round_trips_log() {
        let input = "\
#\n\
# sudo ./sifter.py --unk\n\
# ./injector -t -R\n\
#\n\
# insn tested: 7\n\
# artf found:  1\n\
# runtime: 00:00:01.00\n\
# seed: 42\n\
# arch: 64\n\
# date: 2026-04-16 12:00:00\n\
#\n\
# cpu:\n\
# processor\t: 0\n\
# vendor_id\t: GenuineIntel\n\
# model name\t: Example CPU\n\
#                              v  l  s  c\n\
90  1  1  5  1 (90000000000000000000000000000000)\n";

        let parsed = LegacyLog::parse(input).expect("log should parse");
        assert_eq!(parsed.header.arch.as_deref(), Some("64"));
        assert_eq!(parsed.records.len(), 1);

        let rendered = parsed.to_text();
        assert!(rendered.contains("artf found"));
        assert!(rendered.contains("90000000000000000000000000000000"));
    }

    #[test]
    fn parses_tick_hex() {
        let tick = LegacyTick::parse("90cc").expect("tick should parse");
        assert_eq!(tick.to_text(), "90cc");
    }
}
