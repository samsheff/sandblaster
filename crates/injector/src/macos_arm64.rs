use std::io;

use sandblaster_core::InstructionBytes;

use crate::{BackendObservation, ExecutionBackend};

#[derive(Debug, Default)]
pub struct MacosArm64Backend;

impl MacosArm64Backend {
    pub fn from_config(_config: &crate::InjectorConfig) -> io::Result<Self> {
        Self::try_new()
    }

    pub fn try_new() -> io::Result<Self> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            Ok(Self)
        }

        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "macOS ARM64 backend is only available on aarch64 macOS",
            ))
        }
    }
}

impl ExecutionBackend for MacosArm64Backend {
    fn execute(&mut self, instruction: &InstructionBytes) -> Result<BackendObservation, String> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            execute_in_child(instruction)
        }

        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            let _ = instruction;
            Err("macOS ARM64 native execution backend is not available on this host".to_string())
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod native {
    use std::io;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
    use std::sync::OnceLock;

    use sandblaster_core::InstructionBytes;

    use crate::BackendObservation;

    const PAGE_SIZE: usize = 4096;
    const MAP_JIT: libc::c_int = 0x800;
    const OBSERVATION_BYTES: usize = 20;
    const BRK_SENTINEL: [u8; 4] = [0xe0, 0x66, 0x22, 0xd4]; // brk #0x1337
    const SENTINEL_BRK_IMM: u32 = 0x1337;
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

    static PROBE_ACTIVE: AtomicBool = AtomicBool::new(false);
    static PROBE_SIGNUM: AtomicI32 = AtomicI32::new(0);
    static PROBE_SI_CODE: AtomicI32 = AtomicI32::new(0);
    static PROBE_FAULT_ADDR: AtomicU32 = AtomicU32::new(u32::MAX);
    static mut RECOVERY_BUF: SigJmpBuf = SigJmpBuf([0u8; 512]);

    pub(super) fn execute_in_child(
        instruction: &InstructionBytes,
    ) -> Result<BackendObservation, String> {
        let mut pipe_fds = [0; 2];
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return Err(format!("pipe failed: {}", io::Error::last_os_error()));
        }

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            close_fd(pipe_fds[0]);
            close_fd(pipe_fds[1]);
            return Err(format!("fork failed: {}", io::Error::last_os_error()));
        }

        if pid == 0 {
            close_fd(pipe_fds[0]);
            child_execute_probe(instruction, pipe_fds[1]);
        }

        close_fd(pipe_fds[1]);
        let observation = read_observation(pipe_fds[0])?;
        close_fd(pipe_fds[0]);

        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            if waited >= 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(format!("waitpid failed: {error}"));
        }

        if let Some(observation) = observation {
            return Ok(observation);
        }

        let signum = if libc::WIFSIGNALED(status) {
            libc::WTERMSIG(status) as u32
        } else {
            0
        };
        Ok(BackendObservation {
            valid: 1,
            length: 4,
            signum,
            si_code: 0,
            fault_addr: u32::MAX,
        })
    }

    fn child_execute_probe(instruction: &InstructionBytes, write_fd: libc::c_int) -> ! {
        unsafe {
            libc::alarm(1);
        }

        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANON | MAP_JIT,
                -1,
                0,
            )
        };

        if mapping == libc::MAP_FAILED {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
            write_observation(
                write_fd,
                BackendObservation {
                    valid: 0,
                    length: 0,
                    signum: 0,
                    si_code: errno,
                    fault_addr: u32::MAX,
                },
            );
            unsafe { libc::_exit(125) };
        }

        let mut old_actions: [libc::sigaction; 5] = unsafe { std::mem::zeroed() };
        if !install_probe_handlers(&mut old_actions) {
            let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
            write_observation(
                write_fd,
                BackendObservation {
                    valid: 0,
                    length: 0,
                    signum: 0,
                    si_code: errno,
                    fault_addr: u32::MAX,
                },
            );
            unsafe { libc::_exit(126) };
        }

        PROBE_SIGNUM.store(0, Ordering::Relaxed);
        PROBE_SI_CODE.store(0, Ordering::Relaxed);
        PROBE_FAULT_ADDR.store(u32::MAX, Ordering::Relaxed);
        PROBE_ACTIVE.store(true, Ordering::Release);

        let setjmp_ret = unsafe { sigsetjmp(&raw mut RECOVERY_BUF, 1) };

        if setjmp_ret == 0 {
            jit_write_protect(false);
            unsafe {
                std::ptr::copy_nonoverlapping(
                    instruction.bytes().as_ptr(),
                    mapping.cast::<u8>(),
                    4,
                );
                std::ptr::copy_nonoverlapping(
                    BRK_SENTINEL.as_ptr(),
                    mapping.cast::<u8>().add(4),
                    4,
                );
                flush_icache(mapping.cast::<u8>(), 8);
            }
            jit_write_protect(true);

            let entry: unsafe extern "C" fn() = unsafe {
                std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn()>(mapping)
            };
            unsafe { entry() };
        }

        PROBE_ACTIVE.store(false, Ordering::Release);
        restore_probe_handlers(&old_actions);

        write_observation(
            write_fd,
            BackendObservation {
                valid: 1,
                length: 4,
                signum: PROBE_SIGNUM.load(Ordering::Relaxed) as u32,
                si_code: PROBE_SI_CODE.load(Ordering::Relaxed) as u32,
                fault_addr: PROBE_FAULT_ADDR.load(Ordering::Relaxed),
            },
        );
        unsafe { libc::_exit(0) };
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

        if signum == libc::SIGTRAP && unsafe { sentinel_fired_via_esr(ctx) } {
            PROBE_SIGNUM.store(0, Ordering::Relaxed);
            PROBE_SI_CODE.store(0, Ordering::Relaxed);
            PROBE_FAULT_ADDR.store(u32::MAX, Ordering::Relaxed);
        } else {
            PROBE_SIGNUM.store(signum, Ordering::Relaxed);
            if !info.is_null() {
                let si = unsafe { &*info };
                PROBE_SI_CODE.store(si.si_code, Ordering::Relaxed);
                PROBE_FAULT_ADDR.store(si.si_addr as usize as u32, Ordering::Relaxed);
            } else {
                PROBE_SI_CODE.store(0, Ordering::Relaxed);
                PROBE_FAULT_ADDR.store(unsafe { fault_addr_from_context(ctx) }, Ordering::Relaxed);
            }
        }

        unsafe {
            siglongjmp(&raw mut RECOVERY_BUF, 1);
        }
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

    unsafe fn mcontext_from_ucontext(ctx: *mut libc::c_void) -> Option<*const u8> {
        if ctx.is_null() {
            return None;
        }
        let uc = ctx as *const u8;
        let mcontext_raw: u64 = unsafe { *(uc.add(48) as *const u64) };
        if mcontext_raw == 0 || mcontext_raw >= (1u64 << 47) {
            return None;
        }
        Some(mcontext_raw as *const u8)
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

    fn jit_write_protect(protect: bool) {
        type JwpFn = unsafe extern "C" fn(libc::c_int);
        static FN: OnceLock<Option<JwpFn>> = OnceLock::new();

        let f = FN.get_or_init(|| unsafe {
            let sym = libc::dlsym(libc::RTLD_DEFAULT, c"pthread_jit_write_protect_np".as_ptr());
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

    fn read_observation(fd: libc::c_int) -> Result<Option<BackendObservation>, String> {
        let mut bytes = [0_u8; OBSERVATION_BYTES];
        let mut offset = 0;
        while offset < bytes.len() {
            let n = unsafe {
                libc::read(
                    fd,
                    bytes[offset..].as_mut_ptr().cast::<libc::c_void>(),
                    bytes.len() - offset,
                )
            };
            if n == 0 {
                break;
            }
            if n < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(format!("read failed: {error}"));
            }
            offset += n as usize;
        }
        if offset == 0 {
            return Ok(None);
        }
        if offset != bytes.len() {
            return Err(format!(
                "short observation from child: expected {}, got {} bytes",
                bytes.len(),
                offset
            ));
        }

        let values = [
            read_u32(&bytes, 0),
            read_u32(&bytes, 4),
            read_u32(&bytes, 8),
            read_u32(&bytes, 12),
            read_u32(&bytes, 16),
        ];
        Ok(Some(BackendObservation {
            valid: values[0],
            length: values[1],
            signum: values[2],
            si_code: values[3],
            fault_addr: values[4],
        }))
    }

    fn read_u32(bytes: &[u8; OBSERVATION_BYTES], offset: usize) -> u32 {
        u32::from_ne_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    fn write_observation(fd: libc::c_int, observation: BackendObservation) {
        let values = [
            observation.valid,
            observation.length,
            observation.signum,
            observation.si_code,
            observation.fault_addr,
        ];
        let mut bytes = [0_u8; OBSERVATION_BYTES];
        for (index, value) in values.into_iter().enumerate() {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_ne_bytes());
        }

        let mut offset = 0;
        while offset < bytes.len() {
            let n = unsafe {
                libc::write(
                    fd,
                    bytes[offset..].as_ptr().cast::<libc::c_void>(),
                    bytes.len() - offset,
                )
            };
            if n <= 0 {
                break;
            }
            offset += n as usize;
        }
    }

    fn close_fd(fd: libc::c_int) {
        unsafe { libc::close(fd) };
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use native::execute_in_child;

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use sandblaster_core::InstructionBytes;

    use crate::{ExecutionBackend, MacosArm64Backend};

    #[test]
    fn native_nop_probe_reaches_sentinel() {
        let mut backend = MacosArm64Backend::try_new().expect("backend should be available");
        let result = backend
            .execute(&InstructionBytes::from_slice(&[0x1f, 0x20, 0x03, 0xd5]))
            .expect("probe should execute");

        assert_eq!(result.valid, 1);
        assert_eq!(result.length, 4);
        assert_eq!(result.signum, 0);
    }

    #[test]
    fn native_udf_probe_reports_sigill() {
        let mut backend = MacosArm64Backend::try_new().expect("backend should be available");
        let result = backend
            .execute(&InstructionBytes::from_slice(&[0x00, 0x00, 0x00, 0x00]))
            .expect("probe should execute");

        assert_eq!(result.valid, 1);
        assert_eq!(result.length, 4);
        assert_eq!(result.signum, libc::SIGILL as u32);
    }
}
