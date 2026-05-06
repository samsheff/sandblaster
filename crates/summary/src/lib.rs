use std::collections::{BTreeMap, BTreeSet};

use sandblaster_core::{ExecutionResult, LegacyLog};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CondensedArtifact {
    pub raw: Vec<u8>,
    pub valids: BTreeSet<u32>,
    pub lengths: BTreeSet<u32>,
    pub signums: BTreeSet<u32>,
    pub si_codes: BTreeSet<u32>,
    pub prefixes: BTreeSet<u8>,
}

pub fn load_legacy_log(input: &str) -> Result<LegacyLog, sandblaster_core::LegacyParseError> {
    LegacyLog::parse(input)
}

pub fn condense_by_stripped_prefix(
    records: &[ExecutionResult],
    prefixes: &[u8],
) -> Vec<CondensedArtifact> {
    let mut grouped: BTreeMap<Vec<u8>, CondensedArtifact> = BTreeMap::new();

    for result in records {
        let full = result.instruction.executed_prefix(result.length as usize);
        let (prefixes_seen, stripped) = split_prefixes(full, prefixes);
        let entry = grouped
            .entry(stripped.to_vec())
            .or_insert_with(|| CondensedArtifact {
                raw: stripped.to_vec(),
                valids: BTreeSet::new(),
                lengths: BTreeSet::new(),
                signums: BTreeSet::new(),
                si_codes: BTreeSet::new(),
                prefixes: BTreeSet::new(),
            });
        entry.valids.insert(result.valid);
        entry.lengths.insert(stripped.len() as u32);
        entry.signums.insert(result.signum);
        entry.si_codes.insert(result.si_code);
        if prefixes_seen.is_empty() {
            entry.prefixes.insert(0);
        } else {
            entry.prefixes.extend(prefixes_seen);
        }
    }

    grouped.into_values().collect()
}

fn split_prefixes<'a>(bytes: &'a [u8], prefixes: &[u8]) -> (BTreeSet<u8>, &'a [u8]) {
    let mut seen = BTreeSet::new();
    let mut index = 0;
    while index < bytes.len() && prefixes.contains(&bytes[index]) {
        seen.insert(bytes[index]);
        index += 1;
    }
    (seen, &bytes[index..])
}

#[cfg(test)]
mod tests {
    use sandblaster_core::{DisasmResult, ExecutionResult, InstructionBytes};

    use crate::condense_by_stripped_prefix;

    #[test]
    fn condenses_prefix_variants() {
        let records = vec![
            ExecutionResult {
                disasm: DisasmResult::default(),
                instruction: InstructionBytes::from_slice(&[0xf3, 0x90]),
                valid: 1,
                length: 2,
                signum: 5,
                si_code: 1,
                fault_addr: 0,
            },
            ExecutionResult {
                disasm: DisasmResult::default(),
                instruction: InstructionBytes::from_slice(&[0x90]),
                valid: 1,
                length: 1,
                signum: 5,
                si_code: 1,
                fault_addr: 0,
            },
        ];
        let condensed = condense_by_stripped_prefix(&records, &[0xf3]);
        assert_eq!(condensed.len(), 1);
        assert!(condensed[0].prefixes.contains(&0));
        assert!(condensed[0].prefixes.contains(&0xf3));
    }
}
