// iOS ARM64 static-corpus execution backend.
//
// Unlike `ios_arm64.rs`, this backend never writes to executable memory at
// runtime, so it needs no `MAP_JIT`, no dynamic-codesigning entitlement, and
// no debugger attached. The entire candidate corpus is generated on the host
// at build time (`sandblaster-corpusgen`, invoked from
// `crates/mobile_ffi/build.rs`) and assembled directly into the app binary:
// each candidate becomes an ordinary compiled function (its 4 bytes followed
// by the shared `brk #0x1337` sentinel), so every instruction this backend
// ever executes was present in the binary when it was signed.
//
// At link time the generated object exposes three C symbols:
//   `SB_PROBE_COUNT`  : u32                    - number of baked probes
//   `SB_PROBE_BYTES`  : [[u8; 4]; COUNT]       - each probe's raw instruction
//   `SB_PROBE_TABLE`  : [unsafe extern "C" fn(); COUNT] - matching function pointers
//
// `try_new()` builds a `bytes -> index` lookup once; `execute()` looks the
// candidate up and runs the matching pre-baked function through the same
// `arm64_fault::run_probe` fault-recovery path the JIT backend uses.

use std::io;

use sandblaster_core::InstructionBytes;

use crate::{BackendObservation, ExecutionBackend};

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
use std::collections::HashMap;

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
extern "C" {
    static SB_PROBE_COUNT: u32;
    static SB_PROBE_BYTES: u8; // first element of a [[u8; 4]; COUNT] array
    static SB_PROBE_TABLE: u8; // first element of a [unsafe extern "C" fn(); COUNT] array
}

pub struct IosStaticCorpusBackend {
    #[cfg(all(target_os = "ios", target_arch = "aarch64"))]
    index: HashMap<[u8; 4], usize>,
    #[cfg(all(target_os = "ios", target_arch = "aarch64"))]
    table: *const unsafe extern "C" fn(),
}

// SAFETY: `table` points at a `static` array baked into the binary at link
// time (see module docs); it is never written to and outlives the process.
#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
unsafe impl Send for IosStaticCorpusBackend {}

impl IosStaticCorpusBackend {
    pub fn try_new() -> io::Result<Self> {
        #[cfg(all(target_os = "ios", target_arch = "aarch64"))]
        {
            let count = unsafe { SB_PROBE_COUNT } as usize;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "static corpus is empty: rebuild with SANDBLASTER_IOS_CORPUS_* set to a \
                     non-empty range",
                ));
            }

            let bytes_ptr = unsafe { &SB_PROBE_BYTES as *const u8 as *const [u8; 4] };
            let table_ptr =
                unsafe { &SB_PROBE_TABLE as *const u8 as *const unsafe extern "C" fn() };

            let mut index = HashMap::with_capacity(count);
            for i in 0..count {
                let bytes = unsafe { *bytes_ptr.add(i) };
                index.insert(bytes, i);
            }

            Ok(Self {
                index,
                table: table_ptr,
            })
        }
        #[cfg(not(all(target_os = "ios", target_arch = "aarch64")))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "iOS static-corpus backend is only available on aarch64 iOS",
            ))
        }
    }
}

impl ExecutionBackend for IosStaticCorpusBackend {
    fn execute(&mut self, instruction: &InstructionBytes) -> Result<BackendObservation, String> {
        #[cfg(all(target_os = "ios", target_arch = "aarch64"))]
        {
            let key: [u8; 4] = instruction.bytes()[..4]
                .try_into()
                .expect("ios-arm64 candidates are always 4 bytes");
            let Some(&i) = self.index.get(&key) else {
                return Err(format!(
                    "instruction {} not present in baked static corpus; widen \
                     SANDBLASTER_IOS_CORPUS_* and rebuild",
                    instruction.compact_hex()
                ));
            };
            let entry = unsafe { *self.table.add(i) };
            crate::arm64_fault::run_probe(entry)
        }
        #[cfg(not(all(target_os = "ios", target_arch = "aarch64")))]
        {
            let _ = instruction;
            Err("iOS static-corpus backend not available on this host".to_string())
        }
    }
}
