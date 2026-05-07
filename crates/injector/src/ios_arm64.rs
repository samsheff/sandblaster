// iOS ARM64 native execution backend.
//
// iOS forbids fork() in sandboxed apps, so probe isolation uses signal-based
// recovery: sigsetjmp/siglongjmp catch faults in-process.  The JIT page is
// allocated once with MAP_JIT and reused for every probe.  W^X is toggled via
// pthread_jit_write_protect_np (Apple Silicon, loaded lazily via dlsym).
//
// Sentinel detection uses the ESR (Exception Syndrome Register) from the
// ucontext machine context rather than the fault PC or siginfo.  On arm64e
// (all iPhones with A12+), the thread state's __pc field is PAC-authenticated,
// making direct address comparison unreliable.  The exception state's __esr
// field is set by the CPU hardware and is never PAC-signed.
//
// The sentinel instruction is `brk #0x1337`.  Its ESR has EC=0x3C
// (BRK A64) and ISS[15:0]=0x1337, making it trivially distinguishable from
// any fault the probe instruction itself could generate.

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
                         use a jailbroken device, or obtain the dynamic-codesigning entitlement",
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

// Sentinel: `brk #0x1337` = 0xD422_66E0 (little-endian bytes below).
//
// ESR for brk #0x1337:
//   EC  [31:26] = 0x3C  (BRK instruction, AArch64 state)
//   IL  [25]    = 1     (32-bit instruction)
//   ISS [15:0]  = 0x1337 (the BRK immediate)
//
// We check EC==0x3C and ISS==0x1337 in the signal handler.  This identifies
// our sentinel without relying on fault PC or any PAC-sensitive value.
#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
const BRK_SENTINEL: [u8; 4] = [0xe0, 0x66, 0x22, 0xd4]; // brk #0x1337

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
const SENTINEL_BRK_IMM: u32 = 0x1337;

// ─── sigjmp_buf / sigsetjmp / siglongjmp ────────────────────────────────────

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
#[repr(C, align(16))]
struct SigJmpBuf([u8; 512]);

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
extern "C" {
    fn sigsetjmp(env: *mut SigJmpBuf, savemask: libc::c_int) -> libc::c_int;
    fn siglongjmp(env: *mut SigJmpBuf, val: libc::c_int) -> !;
}

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

// ─── ESR sentinel detection ───────────────────────────────────────────────────
//
// Darwin ARM64 ucontext_t memory layout (from Apple open-source headers):
//
//   ucontext_t:
//     +  0  uc_onstack    i32   (4 bytes)
//     +  4  uc_sigmask    u32   (4 bytes)
//     +  8  uc_stack      {*void(8) + size_t(8) + int(4) + pad(4)} = 24 bytes
//     + 32  uc_link       *ucontext_t   (8 bytes)
//     + 40  uc_mcsize     usize         (8 bytes)
//     + 48  uc_mcontext   *mcontext     (8 bytes) ← pointer we need
//
//   __darwin_mcontext64:
//     +  0  __es  __darwin_arm_exception_state64:
//              +0  __far  u64   (fault address — may be 0 for non-memory faults)
//              +8  __esr  u32   (exception syndrome register ← we read this)
//              +12 __exception u32
//     + 16  __ss  __darwin_arm_thread_state64  (272 bytes; __pc is at +256, PAC-signed on arm64e)
//
// We read __esr at mcontext+8.  The exception state is not PAC-protected
// so this works on arm64e devices running arm64 binaries.

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
unsafe fn sentinel_fired_via_esr(ctx: *mut libc::c_void) -> bool {
    if ctx.is_null() {
        return false;
    }

    let uc = ctx as *const u8;

    // Read the raw value at the uc_mcontext slot (offset 48).
    // On arm64e, this pointer may carry PAC bits in the upper bytes.
    // We validate it looks like a user-space address before dereferencing.
    let mcontext_raw: u64 = unsafe { *(uc.add(48) as *const u64) };

    // iOS user-space addresses sit below 2^47 (~128 TiB).
    // If the upper bits are set the pointer is PAC-signed or garbage.
    if mcontext_raw == 0 || mcontext_raw >= (1u64 << 47) {
        return false;
    }

    let mcontext = mcontext_raw as *const u8;

    // Read __esr at mcontext+8.
    let esr: u32 = unsafe { *(mcontext.add(8) as *const u32) };

    // EC (bits [31:26]) == 0x3C → BRK instruction in AArch64 state
    // ISS[15:0]          == 0x1337 → our distinctive sentinel immediate
    let ec = (esr >> 26) & 0x3F;
    let iss = esr & 0xFFFF;

    ec == 0x3C && iss == SENTINEL_BRK_IMM
}

// ─── Signal handler ───────────────────────────────────────────────────────────

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
unsafe extern "C" fn probe_signal_handler(
    signum: libc::c_int,
    info: *mut libc::siginfo_t,
    ctx: *mut libc::c_void,
) {
    if !PROBE_ACTIVE.load(Ordering::Acquire) {
        unsafe {
            libc::signal(signum, libc::SIG_DFL);
            libc::raise(signum);
        }
        return;
    }

    // Check the ESR to see if this SIGTRAP is our sentinel `brk #0x1337`.
    // This is reliable on arm64e because ESR lives in the exception state,
    // which is not PAC-protected, unlike the thread state's __pc.
    if signum == libc::SIGTRAP && unsafe { sentinel_fired_via_esr(ctx) } {
        // Probe instruction executed cleanly; report as signum=0 (no fault).
        PROBE_SIGNUM.store(0, Ordering::Relaxed);
        PROBE_SI_CODE.store(0, Ordering::Relaxed);
        PROBE_FAULT_ADDR.store(u32::MAX, Ordering::Relaxed);
    } else {
        // Real fault from the probe instruction itself.
        PROBE_SIGNUM.store(signum, Ordering::Relaxed);

        if !info.is_null() {
            let si = unsafe { &*info };
            PROBE_SI_CODE.store(si.si_code, Ordering::Relaxed);
            PROBE_FAULT_ADDR.store(si.si_addr as usize as u32, Ordering::Relaxed);
        } else {
            // Debugger stripped siginfo; record si_code=0 and fault_addr from
            // the exception state's __far if available.
            PROBE_SI_CODE.store(0, Ordering::Relaxed);

            // Try to read __far (fault address) from mcontext+0 for memory faults.
            let far = if !ctx.is_null() {
                let mcontext_raw: u64 = unsafe { *(ctx as *const u8).add(48).cast::<u64>() };
                if mcontext_raw != 0 && mcontext_raw < (1u64 << 47) {
                    let far_val: u64 = unsafe { *(mcontext_raw as *const u64) };
                    far_val as u32
                } else {
                    u32::MAX
                }
            } else {
                u32::MAX
            };
            PROBE_FAULT_ADDR.store(far, Ordering::Relaxed);
        }
    }

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
        unsafe { f(libc::c_int::from(protect)) };
    }
}

// ─── I-cache flush ────────────────────────────────────────────────────────────

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
    let _guard = probe_lock().lock().unwrap_or_else(|p| p.into_inner());

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

    let setjmp_ret = unsafe { sigsetjmp(&raw mut RECOVERY_BUF, 1) };

    if setjmp_ret == 0 {
        jit_write_protect(false);
        unsafe {
            std::ptr::copy_nonoverlapping(instruction.bytes().as_ptr(), jit_page.cast::<u8>(), 4);
            std::ptr::copy_nonoverlapping(BRK_SENTINEL.as_ptr(), jit_page.cast::<u8>().add(4), 4);
            flush_icache(jit_page.cast::<u8>(), 8);
        }
        jit_write_protect(true);

        let entry: unsafe extern "C" fn() =
            unsafe { std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn()>(jit_page) };
        unsafe { entry() };
        // Unreachable: the sentinel brk always fires after any non-faulting instruction.
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
