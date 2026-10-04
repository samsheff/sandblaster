// Shared ARM64 Darwin fault-recovery machinery.
//
// `ios_arm64.rs`, `macos_arm64.rs`, and `ios_static_corpus.rs` all need the
// same trick to survive executing an attacker/fuzzer-controlled instruction
// in-process: install signal handlers for the signals a bad instruction can
// raise, `sigsetjmp`, run the instruction, and recover via `siglongjmp` from
// the handler. They also all need to tell "the probe instruction faulted"
// apart from "the probe instruction executed cleanly and fell through to our
// `brk #0x1337` sentinel" — done by reading the ESR (Exception Syndrome
// Register) out of the signal `ucontext_t` rather than trusting the fault PC,
// which is PAC-signed on arm64e and therefore unreliable to compare directly.
//
// This module holds that machinery once; each backend only supplies how its
// probe gets into executable memory (a freshly written JIT page, or a
// function baked into the binary at build time) and then calls [`run_probe`].

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::BackendObservation;

// Sentinel: `brk #0x1337` = 0xD422_66E0 (little-endian bytes below).
//
// ESR for brk #0x1337:
//   EC  [31:26] = 0x3C  (BRK instruction, AArch64 state)
//   IL  [25]    = 1     (32-bit instruction)
//   ISS [15:0]  = 0x1337 (the BRK immediate)
pub const BRK_SENTINEL: [u8; 4] = [0xe0, 0x66, 0x22, 0xd4]; // brk #0x1337
pub const SENTINEL_BRK_IMM: u32 = 0x1337;

#[cfg(any(
    all(target_os = "ios", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
mod darwin_arm64 {
    use super::*;

    const PROBE_SIGNALS: [libc::c_int; 5] = [
        libc::SIGILL,
        libc::SIGSEGV,
        libc::SIGBUS,
        libc::SIGFPE,
        libc::SIGTRAP,
    ];

    #[repr(C, align(16))]
    struct SigJmpBuf([u8; 512]);

    extern "C" {
        fn sigsetjmp(env: *mut SigJmpBuf, savemask: libc::c_int) -> libc::c_int;
        fn siglongjmp(env: *mut SigJmpBuf, val: libc::c_int) -> !;
    }

    static PROBE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    fn probe_lock() -> &'static Mutex<()> {
        PROBE_LOCK.get_or_init(|| Mutex::new(()))
    }

    static PROBE_ACTIVE: AtomicBool = AtomicBool::new(false);
    static PROBE_SIGNUM: AtomicI32 = AtomicI32::new(0);
    static PROBE_SI_CODE: AtomicI32 = AtomicI32::new(0);
    static PROBE_FAULT_ADDR: AtomicU32 = AtomicU32::new(u32::MAX);
    static mut RECOVERY_BUF: SigJmpBuf = SigJmpBuf([0u8; 512]);

    // ─── Darwin ARM64 ucontext_t memory layout (from Apple open-source headers) ───
    //
    //   ucontext_t:
    //     +  0  uc_onstack    i32   (4 bytes)
    //     +  4  uc_sigmask    u32   (4 bytes)
    //     +  8  uc_stack      {*void(8) + size_t(8) + int(4) + pad(4)} = 24 bytes
    //     + 32  uc_link       *ucontext_t   (8 bytes)
    //     + 40  uc_mcsize     usize         (8 bytes)
    //     + 48  uc_mcontext   *mcontext     (8 bytes) <- pointer we need
    //
    //   __darwin_mcontext64:
    //     +  0  __es  __darwin_arm_exception_state64:
    //              +0  __far  u64   (fault address - may be 0 for non-memory faults)
    //              +8  __esr  u32   (exception syndrome register <- we read this)
    //              +12 __exception u32
    //     + 16  __ss  __darwin_arm_thread_state64  (272 bytes; __pc at +256, PAC-signed on arm64e)
    //
    // We read __esr at mcontext+8 and __far at mcontext+0. Neither is
    // PAC-protected, so this works on arm64e devices running arm64 binaries.
    unsafe fn mcontext_from_ucontext(ctx: *mut libc::c_void) -> Option<*const u8> {
        if ctx.is_null() {
            return None;
        }
        let uc = ctx as *const u8;
        let mcontext_raw: u64 = unsafe { *(uc.add(48) as *const u64) };
        // iOS/macOS user-space addresses sit below 2^47 (~128 TiB). If the
        // upper bits are set the pointer is PAC-signed or garbage.
        if mcontext_raw == 0 || mcontext_raw >= (1u64 << 47) {
            return None;
        }
        Some(mcontext_raw as *const u8)
    }

    unsafe fn sentinel_fired_via_esr(ctx: *mut libc::c_void) -> bool {
        let Some(mcontext) = (unsafe { mcontext_from_ucontext(ctx) }) else {
            return false;
        };
        let esr: u32 = unsafe { *(mcontext.add(8) as *const u32) };
        let ec = (esr >> 26) & 0x3f;
        let iss = esr & 0xffff;
        ec == 0x3c && iss == SENTINEL_BRK_IMM
    }

    unsafe fn fault_addr_from_context(ctx: *mut libc::c_void) -> u32 {
        let Some(mcontext) = (unsafe { mcontext_from_ucontext(ctx) }) else {
            return u32::MAX;
        };
        let far: u64 = unsafe { *(mcontext as *const u64) };
        far as u32
    }

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
        // This is reliable on arm64e because ESR lives in the exception
        // state, which is not PAC-protected, unlike the thread state's __pc.
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
                // Debugger stripped siginfo; record si_code=0 and fault_addr
                // from the exception state's __far if available.
                PROBE_SI_CODE.store(0, Ordering::Relaxed);
                PROBE_FAULT_ADDR.store(unsafe { fault_addr_from_context(ctx) }, Ordering::Relaxed);
            }
        }

        unsafe {
            siglongjmp(&raw mut RECOVERY_BUF, 1);
        }
    }

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

    fn restore_probe_handlers(old: &[libc::sigaction; 5]) {
        for (i, &sig) in PROBE_SIGNALS.iter().enumerate() {
            unsafe { libc::sigaction(sig, &old[i], std::ptr::null_mut()) };
        }
    }

    /// Flush the instruction cache for `[start, start+len)`. Only needed by
    /// backends that write fresh bytes into executable memory before calling
    /// them (the JIT-page backends); a backend that calls a function already
    /// present in the binary at link time doesn't need this.
    ///
    /// # Safety
    /// `start` must point to at least `len` bytes of valid, mapped memory.
    pub unsafe fn flush_icache(start: *mut u8, len: usize) {
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

    /// Toggle W^X on a `MAP_JIT` page via `pthread_jit_write_protect_np`.
    /// Only needed by backends that write into their own JIT page.
    pub fn jit_write_protect(protect: bool) {
        type JwpFn = unsafe extern "C" fn(libc::c_int);
        static FN: OnceLock<Option<JwpFn>> = OnceLock::new();

        let f = FN.get_or_init(|| unsafe {
            let sym = libc::dlsym(
                libc::RTLD_DEFAULT,
                c"pthread_jit_write_protect_np".as_ptr(),
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

    /// Run `entry` as a probe: install fault handlers, call it, and recover
    /// via `siglongjmp` if it raises `SIGILL`/`SIGSEGV`/`SIGBUS`/`SIGFPE`, or
    /// falls through cleanly into the `brk #0x1337` sentinel appended after
    /// it. Serialized by an internal lock; safe to call from any thread.
    pub fn run_probe(entry: unsafe extern "C" fn()) -> Result<BackendObservation, String> {
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
            unsafe { entry() };
            // Unreachable: the sentinel brk always fires after any
            // non-faulting instruction.
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
}

#[cfg(any(
    all(target_os = "ios", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
pub use darwin_arm64::{flush_icache, jit_write_protect, run_probe};
