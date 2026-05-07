// iOS ARM64 native execution backend.
//
// iOS forbids fork() in sandboxed apps, so probe isolation uses signal-based
// recovery: sigsetjmp/siglongjmp catch faults in-process.  The JIT page is
// allocated once with MAP_JIT and reused for every probe.  W^X is toggled via
// pthread_jit_write_protect_np (Apple Silicon, loaded lazily via dlsym).

use std::io;

use sandblaster_core::InstructionBytes;

use crate::{BackendObservation, ExecutionBackend};

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
use std::sync::{Mutex, OnceLock};

pub struct IosArm64Backend {
    #[cfg(all(target_os = "ios", target_arch = "aarch64"))]
    jit_page: JitPage,
}

impl IosArm64Backend {
    pub fn try_new() -> io::Result<Self> {
        #[cfg(all(target_os = "ios", target_arch = "aarch64"))]
        {
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
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "MAP_JIT failed ({}); ensure dynamic-codesigning entitlement is present",
                        io::Error::last_os_error()
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

// MAP_JIT on Darwin — not exposed by libc for iOS, but the constant is stable.
#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
const MAP_JIT: libc::c_int = 0x800;

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
const BRK_ZERO: [u8; 4] = [0x00, 0x00, 0x20, 0xd4]; // brk #0

// ─── sigjmp_buf / sigsetjmp / siglongjmp ────────────────────────────────────
//
// libc for aarch64-apple-ios does not expose sigjmp_buf, sigsetjmp, or
// siglongjmp.  We declare them directly.  The buffer is sized conservatively
// at 512 bytes (arm64-apple sigjmp_buf is ~200 bytes in practice) with 16-byte
// alignment to satisfy any platform ABI requirement.

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
#[repr(C, align(16))]
struct SigJmpBuf([u8; 512]);

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
extern "C" {
    // Returns 0 on first call; returns `val` when resumed via siglongjmp.
    // savemask != 0 saves and restores the signal mask.
    fn sigsetjmp(env: *mut SigJmpBuf, savemask: libc::c_int) -> libc::c_int;
    fn siglongjmp(env: *mut SigJmpBuf, val: libc::c_int) -> !;
}

// ─── RAII JIT page ────────────────────────────────────────────────────────────

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
struct JitPage(*mut libc::c_void);

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
// SAFETY: The JIT page raw pointer is owned exclusively by IosArm64Backend.
unsafe impl Send for JitPage {}

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
impl Drop for JitPage {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { libc::munmap(self.0, PAGE_SIZE) };
        }
    }
}

// ─── Probe execution globals (serialized by PROBE_LOCK) ──────────────────────

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
static PROBE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
fn probe_lock() -> &'static Mutex<()> {
    PROBE_LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
static PROBE_ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
static PROBE_SIGNUM: AtomicI32 = AtomicI32::new(0);

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
static PROBE_SI_CODE: AtomicI32 = AtomicI32::new(0);

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
static PROBE_FAULT_ADDR: AtomicU32 = AtomicU32::new(u32::MAX);

// SAFETY: Access is serialized by PROBE_LOCK — exactly one probe runs at a time.
// The signal handler runs on the same thread as the probe (POSIX signal delivery).
#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
static mut RECOVERY_BUF: SigJmpBuf = SigJmpBuf([0u8; 512]);

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
const PROBE_SIGNALS: [libc::c_int; 5] = [
    libc::SIGILL,
    libc::SIGSEGV,
    libc::SIGBUS,
    libc::SIGFPE,
    libc::SIGTRAP,
];

// ─── Signal handler ───────────────────────────────────────────────────────────

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
unsafe extern "C" fn probe_signal_handler(
    signum: libc::c_int,
    info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    if !PROBE_ACTIVE.load(Ordering::Acquire) {
        // Signal arrived outside a probe — restore default and re-raise.
        unsafe {
            libc::signal(signum, libc::SIG_DFL);
            libc::raise(signum);
        }
        return;
    }

    PROBE_SIGNUM.store(signum, Ordering::Relaxed);

    if !info.is_null() {
        unsafe {
            let si = &*info;
            PROBE_SI_CODE.store(si.si_code, Ordering::Relaxed);
            // Truncate 64-bit fault address to 32 bits to match BackendObservation.
            PROBE_FAULT_ADDR.store(si.si_addr as usize as u32, Ordering::Relaxed);
        }
    }

    // Jump back to the sigsetjmp point inside execute_probe.
    // The RECOVERY_BUF frame is still live — only frames between the signal
    // delivery site and sigsetjmp are abandoned (no Rust destructors there).
    unsafe {
        siglongjmp(&raw mut RECOVERY_BUF, 1);
    }
}

// ─── Signal handler install / restore ────────────────────────────────────────

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
fn install_probe_handlers(old: &mut [libc::sigaction; 5]) -> bool {
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = probe_signal_handler as libc::sighandler_t;
    sa.sa_flags = libc::SA_SIGINFO;
    unsafe { libc::sigemptyset(&mut sa.sa_mask) };

    for (i, &sig) in PROBE_SIGNALS.iter().enumerate() {
        if unsafe { libc::sigaction(sig, &sa, &mut old[i]) } != 0 {
            return false;
        }
    }
    true
}

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
fn restore_probe_handlers(old: &[libc::sigaction; 5]) {
    for (i, &sig) in PROBE_SIGNALS.iter().enumerate() {
        unsafe { libc::sigaction(sig, &old[i], std::ptr::null_mut()) };
    }
}

// ─── W^X toggle (pthread_jit_write_protect_np) ───────────────────────────────

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
fn jit_write_protect(protect: bool) {
    type JwpFn = unsafe extern "C" fn(libc::c_int);
    static FN: OnceLock<Option<JwpFn>> = OnceLock::new();

    let f = FN.get_or_init(|| unsafe {
        let sym = libc::dlsym(
            libc::RTLD_DEFAULT,
            b"pthread_jit_write_protect_np\0".as_ptr().cast(),
        );
        if sym.is_null() {
            None
        } else {
            Some(std::mem::transmute::<*mut libc::c_void, JwpFn>(sym))
        }
    });

    if let Some(f) = *f {
        // 0 = write mode, 1 = execute mode
        unsafe { f(libc::c_int::from(protect)) };
    }
    // If not available (older device/OS), the mmap flags already cover it.
}

// ─── I-cache flush (same as Android backend) ─────────────────────────────────

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
unsafe fn flush_icache(start: *mut u8, len: usize) {
    let line_size = 64_usize;
    let begin = (start as usize) & !(line_size - 1);
    let end = (start as usize).saturating_add(len);
    let mut addr = begin;
    while addr < end {
        unsafe {
            core::arch::asm!(
                "dc cvau, {addr}",
                addr = in(reg) addr,
                options(nostack, preserves_flags)
            );
        }
        addr = addr.saturating_add(line_size);
    }
    unsafe { core::arch::asm!("dsb ish", options(nostack, preserves_flags)) };
    addr = begin;
    while addr < end {
        unsafe {
            core::arch::asm!(
                "ic ivau, {addr}",
                addr = in(reg) addr,
                options(nostack, preserves_flags)
            );
        }
        addr = addr.saturating_add(line_size);
    }
    unsafe { core::arch::asm!("dsb ish", options(nostack, preserves_flags)) };
    unsafe { core::arch::asm!("isb", options(nostack, preserves_flags)) };
}

// ─── Core probe execution ─────────────────────────────────────────────────────

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
fn execute_probe(
    jit_page: *mut libc::c_void,
    instruction: &InstructionBytes,
) -> Result<BackendObservation, String> {
    // Serialize probes: global signal state is not re-entrant.
    let _guard = probe_lock()
        .lock()
        .unwrap_or_else(|p| p.into_inner());

    let mut old_actions: [libc::sigaction; 5] = unsafe { std::mem::zeroed() };
    if !install_probe_handlers(&mut old_actions) {
        return Err(format!(
            "sigaction failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    PROBE_SIGNUM.store(0, Ordering::Relaxed);
    PROBE_SI_CODE.store(0, Ordering::Relaxed);
    PROBE_FAULT_ADDR.store(u32::MAX, Ordering::Relaxed);
    PROBE_ACTIVE.store(true, Ordering::Release);

    // sigsetjmp saves CPU state and signal mask (savemask=1).
    // Returns 0 on first call; returns 1 when resumed by siglongjmp.
    //
    // When the probe causes a signal:
    //   probe_signal_handler → siglongjmp → sigsetjmp returns 1
    // _guard and old_actions live in *this* frame, which survives the jump;
    // only frames between signal delivery and sigsetjmp are abandoned.
    let setjmp_ret = unsafe { sigsetjmp(&raw mut RECOVERY_BUF, 1) };

    if setjmp_ret == 0 {
        jit_write_protect(false); // enable write
        unsafe {
            std::ptr::copy_nonoverlapping(instruction.bytes().as_ptr(), jit_page.cast::<u8>(), 4);
            std::ptr::copy_nonoverlapping(BRK_ZERO.as_ptr(), jit_page.cast::<u8>().add(4), 4);
            flush_icache(jit_page.cast::<u8>(), 8);
        }
        jit_write_protect(true); // enable exec

        // Execute. BRK or a fault fires → siglongjmp → setjmp_ret = 1 path.
        let entry: unsafe extern "C" fn() =
            unsafe { std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn()>(jit_page) };
        unsafe { entry() };
        // Unreachable: BRK always fires after any valid instruction.
    }

    PROBE_ACTIVE.store(false, Ordering::Release);
    restore_probe_handlers(&old_actions);

    Ok(BackendObservation {
        valid: 1,
        length: 4,
        signum: PROBE_SIGNUM.load(Ordering::Relaxed) as u32,
        si_code: PROBE_SI_CODE.load(Ordering::Relaxed) as u32,
        fault_addr: PROBE_FAULT_ADDR.load(Ordering::Relaxed),
    })
}
