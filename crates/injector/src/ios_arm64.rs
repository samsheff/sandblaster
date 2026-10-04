// iOS ARM64 native execution backend.
//
// iOS forbids fork() in sandboxed apps, so probe isolation uses signal-based
// recovery: sigsetjmp/siglongjmp catch faults in-process (see
// `arm64_fault::run_probe`). The JIT page is allocated once with MAP_JIT and
// reused for every probe. W^X is toggled via pthread_jit_write_protect_np
// (Apple Silicon, loaded lazily via dlsym).
//
// This backend only works when the OS actually grants MAP_JIT for the
// process (the restricted dynamic-codesigning entitlement, or a debugger
// attached). See `ios_static_corpus.rs` for a backend that needs neither.

use std::io;

use sandblaster_core::InstructionBytes;

use crate::{BackendObservation, ExecutionBackend};

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
use crate::arm64_fault::{self, BRK_SENTINEL};

pub struct IosArm64Backend {
    #[cfg(all(target_os = "ios", target_arch = "aarch64"))]
    jit_page: JitPage,
}

impl IosArm64Backend {
    pub fn try_new() -> io::Result<Self> {
        #[cfg(all(target_os = "ios", target_arch = "aarch64"))]
        {
            // PT_TRACE_ME asks the kernel to treat this process as debuggable,
            // setting CS_DEBUGGED which may enable MAP_JIT on some iOS versions
            // without the restricted dynamic-codesigning entitlement.
            // With a debugger already attached (Xcode) this is a no-op.
            let _ = unsafe { libc::ptrace(libc::PT_TRACE_ME, 0, std::ptr::null_mut(), 0) };

            let page = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    PAGE_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_JIT,
                    -1,
                    0,
                )
            };
            if page == libc::MAP_FAILED {
                let err = io::Error::last_os_error();
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "MAP_JIT failed (errno {}): run via Xcode with debugger attached, \
                         use a jailbroken device, obtain the dynamic-codesigning entitlement, \
                         or use the static-corpus backend instead",
                        err.raw_os_error().unwrap_or(-1)
                    ),
                ));
            }
            Ok(Self {
                jit_page: JitPage(page),
            })
        }
        #[cfg(not(all(target_os = "ios", target_arch = "aarch64")))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "iOS ARM64 backend is only available on aarch64 iOS",
            ))
        }
    }
}

impl ExecutionBackend for IosArm64Backend {
    fn execute(&mut self, instruction: &InstructionBytes) -> Result<BackendObservation, String> {
        #[cfg(all(target_os = "ios", target_arch = "aarch64"))]
        {
            execute_probe(self.jit_page.0, instruction)
        }
        #[cfg(not(all(target_os = "ios", target_arch = "aarch64")))]
        {
            let _ = instruction;
            Err("iOS ARM64 native backend not available on this host".to_string())
        }
    }
}

// ─── iOS implementation ───────────────────────────────────────────────────────

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
const PAGE_SIZE: usize = 4096;

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
const MAP_JIT: libc::c_int = 0x800;

// ─── RAII JIT page ────────────────────────────────────────────────────────────

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
struct JitPage(*mut libc::c_void);

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
unsafe impl Send for JitPage {}

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
impl Drop for JitPage {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { libc::munmap(self.0, PAGE_SIZE) };
        }
    }
}

// ─── Core probe execution ─────────────────────────────────────────────────────

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
fn execute_probe(
    jit_page: *mut libc::c_void,
    instruction: &InstructionBytes,
) -> Result<BackendObservation, String> {
    arm64_fault::jit_write_protect(false);
    unsafe {
        std::ptr::copy_nonoverlapping(instruction.bytes().as_ptr(), jit_page.cast::<u8>(), 4);
        std::ptr::copy_nonoverlapping(BRK_SENTINEL.as_ptr(), jit_page.cast::<u8>().add(4), 4);
        arm64_fault::flush_icache(jit_page.cast::<u8>(), 8);
    }
    arm64_fault::jit_write_protect(true);

    let entry: unsafe extern "C" fn() =
        unsafe { std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn()>(jit_page) };
    arm64_fault::run_probe(entry)
}
