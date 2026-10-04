use std::fmt;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Architecture {
    X86_64,
    Arm64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Platform {
    Linux,
    Android,
    Ios,
    Macos,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetSpec {
    pub architecture: Architecture,
    pub platform: Platform,
    pub max_instruction_len: usize,
    pub fixed_instruction_len: Option<usize>,
}

impl TargetSpec {
    pub fn host() -> Self {
        Self {
            architecture: host_architecture(),
            platform: host_platform(),
            max_instruction_len: if cfg!(target_arch = "aarch64") { 4 } else { 15 },
            fixed_instruction_len: if cfg!(target_arch = "aarch64") {
                Some(4)
            } else {
                None
            },
        }
    }

    pub fn linux_x86_64() -> Self {
        Self {
            architecture: Architecture::X86_64,
            platform: Platform::Linux,
            max_instruction_len: 15,
            fixed_instruction_len: None,
        }
    }

    pub fn android_arm64() -> Self {
        Self {
            architecture: Architecture::Arm64,
            platform: Platform::Android,
            max_instruction_len: 4,
            fixed_instruction_len: Some(4),
        }
    }

    pub fn ios_arm64() -> Self {
        Self {
            architecture: Architecture::Arm64,
            platform: Platform::Ios,
            max_instruction_len: 4,
            fixed_instruction_len: Some(4),
        }
    }

    pub fn macos_arm64() -> Self {
        Self {
            architecture: Architecture::Arm64,
            platform: Platform::Macos,
            max_instruction_len: 4,
            fixed_instruction_len: Some(4),
        }
    }

    pub fn name(self) -> &'static str {
        match (self.platform, self.architecture) {
            (Platform::Linux, Architecture::X86_64) => "linux-x86_64",
            (Platform::Android, Architecture::Arm64) => "android-arm64",
            (Platform::Ios, Architecture::Arm64) => "ios-arm64",
            (Platform::Macos, Architecture::Arm64) => "macos-arm64",
            (_, Architecture::X86_64) => "x86_64",
            (_, Architecture::Arm64) => "arm64",
        }
    }

    pub fn is_x86(self) -> bool {
        matches!(self.architecture, Architecture::X86_64)
    }
}

impl Default for TargetSpec {
    fn default() -> Self {
        Self::host()
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::X86_64 => "x86_64",
            Self::Arm64 => "arm64",
        })
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Linux => "linux",
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Macos => "macos",
            Self::Unknown => "unknown",
        })
    }
}

impl FromStr for TargetSpec {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "linux-x86_64" | "x86_64-linux" => Ok(Self::linux_x86_64()),
            "android-arm64" | "android-aarch64" => Ok(Self::android_arm64()),
            "ios-arm64" | "ios-aarch64" => Ok(Self::ios_arm64()),
            "macos-arm64" | "macos-aarch64" | "darwin-arm64" | "darwin-aarch64" => {
                Ok(Self::macos_arm64())
            }
            "host" => Ok(Self::host()),
            _ => Err(format!("unknown target '{value}'")),
        }
    }
}

fn host_architecture() -> Architecture {
    if cfg!(target_arch = "aarch64") {
        Architecture::Arm64
    } else {
        Architecture::X86_64
    }
}

fn host_platform() -> Platform {
    if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "android") {
        Platform::Android
    } else if cfg!(target_os = "ios") {
        Platform::Ios
    } else if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::{Architecture, Platform, TargetSpec};

    #[test]
    fn parses_mobile_targets() {
        let android: TargetSpec = "android-arm64".parse().expect("target should parse");
        assert_eq!(android.architecture, Architecture::Arm64);
        assert_eq!(android.platform, Platform::Android);
        assert_eq!(android.fixed_instruction_len, Some(4));

        let ios: TargetSpec = "ios-arm64".parse().expect("target should parse");
        assert_eq!(ios.name(), "ios-arm64");

        let macos: TargetSpec = "darwin-aarch64".parse().expect("target should parse");
        assert_eq!(macos, TargetSpec::macos_arm64());
        assert_eq!(macos.name(), "macos-arm64");
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn apple_silicon_host_is_macos_arm64() {
        assert_eq!(TargetSpec::host(), TargetSpec::macos_arm64());
    }
}
