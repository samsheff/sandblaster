use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CpuMetadata {
    pub processor: Option<String>,
    pub vendor_id: Option<String>,
    pub cpu_family: Option<String>,
    pub model: Option<String>,
    pub model_name: Option<String>,
    pub stepping: Option<String>,
    pub microcode: Option<String>,
    pub architecture_bits: Option<u32>,
    pub raw_lines: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CpuCapabilities {
    pub vendor: String,
    pub max_basic_leaf: u32,
    pub max_extended_leaf: u32,
    pub has_tsc: bool,
    pub has_msr: bool,
    pub has_apic: bool,
    pub has_syscall_sysret: bool,
    pub has_nx: bool,
    pub has_1gib_pages: bool,
    pub has_rdtscp: bool,
    pub has_long_mode: bool,
}

impl CpuMetadata {
    pub fn from_cpuinfo_path(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let content = fs::read_to_string(path)?;
        Ok(Self::from_cpuinfo_str(&content))
    }

    pub fn from_cpuinfo_str(content: &str) -> Self {
        let mut metadata = Self {
            raw_lines: content.lines().take(7).map(str::to_string).collect(),
            ..Self::default()
        };

        for line in content.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim().to_string();
            match key {
                "processor" => metadata.processor = Some(value),
                "vendor_id" => metadata.vendor_id = Some(value),
                "cpu family" => metadata.cpu_family = Some(value),
                "model" => metadata.model = Some(value),
                "model name" => metadata.model_name = Some(value),
                "stepping" => metadata.stepping = Some(value),
                "microcode" => metadata.microcode = Some(value),
                _ => {}
            }
        }

        metadata
    }
}

impl CpuCapabilities {
    pub fn detect() -> Option<Self> {
        detect_capabilities_impl()
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn detect_capabilities_impl() -> Option<CpuCapabilities> {
    #[cfg(target_arch = "x86")]
    use std::arch::x86::{__cpuid, __cpuid_count};
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{__cpuid, __cpuid_count};

    // SAFETY: CPUID is a stable, unprivileged architectural instruction on x86/x86_64.
    let basic = unsafe { __cpuid(0) };
    let vendor = [
        basic.ebx.to_le_bytes(),
        basic.edx.to_le_bytes(),
        basic.ecx.to_le_bytes(),
    ]
    .concat();
    let vendor = String::from_utf8(vendor).ok()?;

    // SAFETY: same rationale as above; these leaves are queried conditionally.
    let leaf1 = unsafe { __cpuid(1) };
    // SAFETY: same rationale as above.
    let extended = unsafe { __cpuid(0x8000_0000) };
    let ext_features = if extended.eax >= 0x8000_0001 {
        // SAFETY: extended feature leaf is guarded by the maximum supported extended leaf.
        unsafe { __cpuid(0x8000_0001) }
    } else {
        // SAFETY: leaf 0 is always supported on x86/x86_64 and serves as a zero-ish fallback.
        unsafe { __cpuid(0) }
    };
    let _ext_7 = if basic.eax >= 7 {
        // SAFETY: structured extended feature leaf is guarded by the max basic leaf.
        unsafe { __cpuid_count(7, 0) }
    } else {
        // SAFETY: leaf 0 is always supported on x86/x86_64 and serves as a zero-ish fallback.
        unsafe { __cpuid(0) }
    };

    Some(CpuCapabilities {
        vendor,
        max_basic_leaf: basic.eax,
        max_extended_leaf: extended.eax,
        has_tsc: leaf1.edx & (1 << 4) != 0,
        has_msr: leaf1.edx & (1 << 5) != 0,
        has_apic: leaf1.edx & (1 << 9) != 0,
        has_syscall_sysret: ext_features.edx & (1 << 11) != 0,
        has_nx: ext_features.edx & (1 << 20) != 0,
        has_1gib_pages: ext_features.edx & (1 << 26) != 0,
        has_rdtscp: ext_features.edx & (1 << 27) != 0,
        has_long_mode: ext_features.edx & (1 << 29) != 0,
    })
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn detect_capabilities_impl() -> Option<CpuCapabilities> {
    None
}

#[cfg(test)]
mod tests {
    use super::{CpuCapabilities, CpuMetadata};

    #[test]
    fn parses_cpuinfo_metadata() {
        let metadata = CpuMetadata::from_cpuinfo_str(
            "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Example CPU\n",
        );
        assert_eq!(metadata.processor.as_deref(), Some("0"));
        assert_eq!(metadata.vendor_id.as_deref(), Some("GenuineIntel"));
    }

    #[test]
    fn detects_capabilities_or_gracefully_absent() {
        let capabilities = CpuCapabilities::detect();
        if let Some(capabilities) = capabilities {
            assert!(!capabilities.vendor.is_empty());
        }
    }
}
