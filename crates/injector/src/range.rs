use sandblaster_core::{InstructionBytes, RAW_REPORT_INSN_BYTES};
use sandblaster_search::SearchRange;

pub fn split_search_range(range: SearchRange, range_bytes: usize) -> Vec<SearchRange> {
    let marker_len = range_bytes.min(RAW_REPORT_INSN_BYTES);
    if marker_len == 0 || range.start.bytes() >= range.end.bytes() {
        return vec![range];
    }

    let mut ranges = Vec::new();
    let mut marker = range.start;
    while marker.bytes() < range.end.bytes() {
        let mut next = marker;
        if !increment_range(&mut next, marker_len) || next.bytes() > range.end.bytes() {
            next = range.end;
        }
        ranges.push(SearchRange {
            start: marker,
            end: next,
        });
        if next.bytes() >= range.end.bytes() {
            break;
        }
        marker = next;
    }

    ranges
}

fn increment_range(instruction: &mut InstructionBytes, marker: usize) -> bool {
    let mut bytes = *instruction.bytes();
    for byte in bytes.iter_mut().skip(marker) {
        *byte = 0;
    }

    let mut index = marker;
    while index > 0 {
        index -= 1;
        bytes[index] = bytes[index].wrapping_add(1);
        if bytes[index] != 0 {
            *instruction = InstructionBytes::new(bytes, marker);
            return true;
        }
    }

    *instruction = InstructionBytes::new(bytes, marker);
    false
}

#[cfg(test)]
mod tests {
    use sandblaster_core::InstructionBytes;
    use sandblaster_search::SearchRange;

    use crate::range::split_search_range;

    #[test]
    fn split_range_uses_exclusive_end() {
        let ranges = split_search_range(
            SearchRange {
                start: InstructionBytes::from_slice(&[0x00]),
                end: InstructionBytes::from_slice(&[0x03]),
            },
            1,
        );
        let rendered: Vec<_> = ranges
            .iter()
            .map(|range| (range.start.compact_hex(), range.end.compact_hex()))
            .collect();
        assert_eq!(
            rendered,
            [
                ("00".into(), "01".into()),
                ("01".into(), "02".into()),
                ("02".into(), "03".into())
            ]
        );
    }

    #[test]
    fn zero_range_bytes_keeps_single_range() {
        let range = SearchRange {
            start: InstructionBytes::from_slice(&[0x90]),
            end: InstructionBytes::from_slice(&[0x91]),
        };
        assert_eq!(split_search_range(range.clone(), 0), [range]);
    }
}
