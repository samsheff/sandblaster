use std::io;

use sandblaster_core::InstructionBytes;

use crate::{BackendObservation, ExecutionBackend};

#[derive(Debug, Default)]
pub struct AndroidArm64Backend;

impl AndroidArm64Backend {
    pub fn from_config(_config: &crate::InjectorConfig) -> io::Result<Self> {
        Self::try_new()
    }

    pub fn try_new() -> io::Result<Self> {
        #[cfg(all(target_os = "android", target_arch = "aarch64"))]
        {
            Ok(Self)
        }

        #[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Android ARM64 backend is only available on aarch64 Android",
            ))
        }
    }
}

impl ExecutionBackend for AndroidArm64Backend {
    fn execute(&mut self, instruction: &InstructionBytes) -> Result<BackendObservation, String> {
        #[cfg(all(target_os = "android", target_arch = "aarch64"))]
        {
            execute_in_child(instruction)
        }

        #[cfg(not(all(target_os = "android", target_arch = "aarch64")))]
        {
            let _ = instruction;
            Err("Android ARM64 native execution backend is not available on this host".to_string())
        }
    }
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
fn execute_in_child(instruction: &InstructionBytes) -> Result<BackendObservation, String> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork failed: {}", io::Error::last_os_error()));
    }

    if pid == 0 {
        unsafe {
            // ponytail: bionic's debuggerd_init() installs handlers for these
            // signals that fork crash_dump64 + write a tombstone on every
            // fault (~60ms each). Reset to default so the kernel just kills
            // the child instead; that's most of the per-instruction cost.
            for sig in [
                libc::SIGSEGV,
                libc::SIGBUS,
                libc::SIGILL,
                libc::SIGFPE,
                libc::SIGTRAP,
                libc::SIGABRT,
            ] {
                libc::signal(sig, libc::SIG_DFL);
            }
            libc::alarm(1);
        }
        child_execute_probe(instruction);
    }

    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    if waited < 0 {
        return Err(format!("waitpid failed: {}", io::Error::last_os_error()));
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

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
fn child_execute_probe(instruction: &InstructionBytes) -> ! {
    const PAGE_SIZE: usize = 4096;
    const BRK_ZERO: [u8; 4] = [0x00, 0x00, 0x20, 0xd4];

    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    if mapping == libc::MAP_FAILED {
        unsafe { libc::_exit(125) };
    }

    unsafe {
        std::ptr::copy_nonoverlapping(instruction.bytes().as_ptr(), mapping.cast::<u8>(), 4);
        std::ptr::copy_nonoverlapping(BRK_ZERO.as_ptr(), mapping.cast::<u8>().add(4), 4);
        flush_instruction_cache(mapping.cast::<u8>(), 8);
        let entry: extern "C" fn() = std::mem::transmute(mapping);
        entry();
        libc::_exit(0);
    }
}

#[cfg(all(target_os = "android", target_arch = "aarch64"))]
unsafe fn flush_instruction_cache(start: *mut u8, len: usize) {
    let line_size = 64_usize;
    let begin = (start as usize) & !(line_size - 1);
    let end = (start as usize).saturating_add(len);
    let mut addr = begin;
    while addr < end {
        core::arch::asm!("dc cvau, {addr}", addr = in(reg) addr, options(nostack, preserves_flags));
        addr = addr.saturating_add(line_size);
    }
    core::arch::asm!("dsb ish", options(nostack, preserves_flags));

    addr = begin;
    while addr < end {
        core::arch::asm!("ic ivau, {addr}", addr = in(reg) addr, options(nostack, preserves_flags));
        addr = addr.saturating_add(line_size);
    }
    core::arch::asm!("dsb ish", options(nostack, preserves_flags));
    core::arch::asm!("isb", options(nostack, preserves_flags));
}
