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

    use sandblaster_core::InstructionBytes;

    use crate::arm64_fault::{self, BRK_SENTINEL};
    use crate::BackendObservation;

    const PAGE_SIZE: usize = 4096;
    const MAP_JIT: libc::c_int = 0x800;
    const OBSERVATION_BYTES: usize = 20;

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

        arm64_fault::jit_write_protect(false);
        unsafe {
            std::ptr::copy_nonoverlapping(instruction.bytes().as_ptr(), mapping.cast::<u8>(), 4);
            std::ptr::copy_nonoverlapping(BRK_SENTINEL.as_ptr(), mapping.cast::<u8>().add(4), 4);
            arm64_fault::flush_icache(mapping.cast::<u8>(), 8);
        }
        arm64_fault::jit_write_protect(true);

        let entry: unsafe extern "C" fn() =
            unsafe { std::mem::transmute::<*mut libc::c_void, unsafe extern "C" fn()>(mapping) };
        let observation = arm64_fault::run_probe(entry).unwrap_or(BackendObservation {
            valid: 0,
            length: 0,
            signum: 0,
            si_code: 0,
            fault_addr: u32::MAX,
        });

        write_observation(write_fd, observation);
        unsafe { libc::_exit(0) };
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
