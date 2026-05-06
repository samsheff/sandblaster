use std::io;
#[cfg(target_os = "linux")]
use std::mem::{self, MaybeUninit};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicUsize, Ordering};

use sandblaster_core::{CpuCapabilities, InstructionBytes, MAX_INSN_LENGTH};

use crate::{BackendObservation, ExecutionBackend, InjectorConfig};

#[cfg(target_os = "linux")]
use std::ffi::c_void;
#[cfg(target_os = "linux")]
use std::ptr::NonNull;

#[cfg(target_os = "linux")]
const DEFAULT_ALTSTACK_SIZE: usize = 64 * 1024;
const TF: usize = 0x100;
const UD2_SIZE: usize = 2;
const JMP_LENGTH: usize = 16;

#[cfg(target_os = "linux")]
const PROT_NONE: i32 = 0x0;
#[cfg(target_os = "linux")]
const PROT_READ: i32 = 0x1;
#[cfg(target_os = "linux")]
const PROT_WRITE: i32 = 0x2;
#[cfg(target_os = "linux")]
const PROT_EXEC: i32 = 0x4;

#[cfg(target_os = "linux")]
const MAP_PRIVATE: i32 = 0x02;
#[cfg(target_os = "linux")]
const MAP_ANONYMOUS: i32 = 0x20;
#[cfg(target_os = "linux")]
const MAP_FIXED: i32 = 0x10;

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn mmap(
        addr: *mut c_void,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: isize,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, length: usize) -> i32;
    fn mprotect(addr: *mut c_void, length: usize, prot: i32) -> i32;
    fn getpagesize() -> i32;
    fn geteuid() -> u32;
}

#[cfg(not(target_os = "linux"))]
unsafe extern "C" {
    fn geteuid() -> u32;
    fn getpagesize() -> i32;
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
static SIGNAL_HITS: AtomicUsize = AtomicUsize::new(0);

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static mut BASELINE_CONTEXT: Option<libc::mcontext_t> = None;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static mut CURRENT_OBSERVATION: FaultObservation = FaultObservation {
    signum: 0,
    si_code: 0,
    fault_addr: 0,
    fault_ip: 0,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static mut PACKET_START: usize = 0;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static mut PREAMBLE_LENGTH: usize = 0;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static mut RESUME_IP: usize = 0;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static mut SIGNAL_MODE: SignalMode = SignalMode::CaptureState;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static mut HAVE_BASELINE_CONTEXT: bool = false;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignalMode {
    CaptureState,
    ExecuteProbe,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxRuntimeEnvironment {
    pub page_size: usize,
    pub is_root: bool,
    pub capabilities: Option<CpuCapabilities>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultModel {
    pub max_instruction_length: usize,
    pub jump_length: usize,
}

impl Default for FaultModel {
    fn default() -> Self {
        Self {
            max_instruction_length: MAX_INSN_LENGTH,
            jump_length: JMP_LENGTH,
        }
    }
}

impl FaultModel {
    pub fn infer_instruction_length(
        &self,
        fault_ip: usize,
        packet_start: usize,
        preamble_length: usize,
    ) -> usize {
        let packet_with_preamble = packet_start.saturating_add(preamble_length);
        let Some(delta) = fault_ip.checked_sub(packet_with_preamble) else {
            return self.jump_length;
        };
        if delta > self.max_instruction_length {
            self.jump_length
        } else {
            delta
        }
    }

    pub fn should_stop_length_probe(&self, fault_addr: u32, page_end: usize) -> bool {
        fault_addr != page_end as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrapFlagPreamble {
    pub trap_flag_mask: usize,
    pub ud2_size: usize,
}

impl Default for TrapFlagPreamble {
    fn default() -> Self {
        Self {
            trap_flag_mask: TF,
            ud2_size: UD2_SIZE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultObservation {
    pub signum: u32,
    pub si_code: u32,
    pub fault_addr: usize,
    pub fault_ip: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProbeContext {
    pub packet_start: usize,
    pub page_end: usize,
    pub preamble_length: usize,
    pub probe_length: usize,
}

impl ProbeContext {
    pub fn infer_fault_result(
        &self,
        model: &FaultModel,
        observation: FaultObservation,
    ) -> BackendObservation {
        let inferred_length = model.infer_instruction_length(
            observation.fault_ip,
            self.packet_start,
            self.preamble_length,
        ) as u32;
        BackendObservation {
            valid: 1,
            length: inferred_length,
            signum: observation.signum,
            si_code: observation.si_code,
            fault_addr: normalize_fault_addr(observation.signum, observation.fault_addr),
        }
    }

    pub fn should_continue_probing(
        &self,
        model: &FaultModel,
        observation: &BackendObservation,
    ) -> bool {
        !model.should_stop_length_probe(observation.fault_addr, self.page_end)
            && self.probe_length < model.max_instruction_length
    }
}

fn normalize_fault_addr(signum: u32, fault_addr: usize) -> u32 {
    match signum {
        11 | 7 => fault_addr as u32,
        _ => u32::MAX,
    }
}

impl LinuxRuntimeEnvironment {
    pub fn detect() -> io::Result<Self> {
        let page_size = page_size()?;
        Ok(Self {
            page_size,
            // SAFETY: geteuid is a side-effect-free libc query.
            is_root: unsafe { geteuid() } == 0,
            capabilities: CpuCapabilities::detect(),
        })
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
#[allow(dead_code)]
pub struct SignalStack {
    stack: Vec<u8>,
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
impl SignalStack {
    pub fn install() -> io::Result<Self> {
        let mut stack = vec![0_u8; DEFAULT_ALTSTACK_SIZE];
        let ss = libc::stack_t {
            ss_sp: stack.as_mut_ptr().cast::<c_void>(),
            ss_flags: 0,
            ss_size: stack.len(),
        };
        // SAFETY: `ss` points to valid process-owned memory for the alternate signal stack.
        let result = unsafe { libc::sigaltstack(&ss, std::ptr::null_mut()) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { stack })
    }

    pub fn len(&self) -> usize {
        self.stack.len()
    }
}

#[cfg(target_os = "linux")]
impl Drop for SignalStack {
    fn drop(&mut self) {
        let disable = libc::stack_t {
            ss_sp: std::ptr::null_mut(),
            ss_flags: libc::SS_DISABLE,
            ss_size: 0,
        };
        // SAFETY: disabling the previously installed alt stack is the matching cleanup.
        let _ = unsafe { libc::sigaltstack(&disable, std::ptr::null_mut()) };
    }
}

#[cfg(target_os = "linux")]
pub type RawSignalHandler = unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut c_void);

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct SignalHandlers {
    previous: Vec<(i32, libc::sigaction)>,
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
impl SignalHandlers {
    pub fn install(handler: RawSignalHandler) -> io::Result<Self> {
        let signals = [
            libc::SIGILL,
            libc::SIGSEGV,
            libc::SIGFPE,
            libc::SIGBUS,
            libc::SIGTRAP,
        ];

        let mut previous = Vec::with_capacity(signals.len());
        for signum in signals {
            let mut action = new_sigaction(handler);
            let mut old_action = MaybeUninit::<libc::sigaction>::uninit();
            // SAFETY: all pointers are valid and `action` is fully initialized.
            let result = unsafe { libc::sigaction(signum, &mut action, old_action.as_mut_ptr()) };
            if result != 0 {
                let error = io::Error::last_os_error();
                for (installed_signum, old) in previous.iter().rev() {
                    // SAFETY: restore previously saved handlers during rollback.
                    let _ =
                        unsafe { libc::sigaction(*installed_signum, old, std::ptr::null_mut()) };
                }
                return Err(error);
            }
            // SAFETY: sigaction initialized `old_action` on success.
            previous.push((signum, unsafe { old_action.assume_init() }));
        }

        Ok(Self { previous })
    }

    pub fn count(&self) -> usize {
        self.previous.len()
    }
}

#[cfg(target_os = "linux")]
impl Drop for SignalHandlers {
    fn drop(&mut self) {
        for (signum, previous) in self.previous.iter().rev() {
            // SAFETY: restore the original handler that was captured during install.
            let _ = unsafe { libc::sigaction(*signum, previous, std::ptr::null_mut()) };
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
unsafe extern "C" fn scaffold_signal_handler(
    _signum: i32,
    _siginfo: *mut libc::siginfo_t,
    _context: *mut c_void,
) {
    SIGNAL_HITS.fetch_add(1, Ordering::Relaxed);
}

#[cfg(target_os = "linux")]
fn new_sigaction(handler: RawSignalHandler) -> libc::sigaction {
    // SAFETY: zeroed `sigaction` is immediately populated below.
    let mut action: libc::sigaction = unsafe { mem::zeroed() };
    action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
    action.sa_sigaction = handler as usize;
    // SAFETY: the mask pointer is valid for the local struct.
    unsafe {
        libc::sigfillset(&mut action.sa_mask);
    }
    action
}

#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct ExecutableRegion {
    #[cfg(target_os = "linux")]
    base: NonNull<u8>,
    page_size: usize,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl ExecutableRegion {
    pub fn allocate(page_size: usize, nx_support: bool) -> io::Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (page_size, nx_support);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "executable region allocation is only implemented on Linux",
            ))
        }

        #[cfg(target_os = "linux")]
        {
            let length = page_size
                .checked_mul(2)
                .ok_or_else(|| io::Error::other("page size overflow"))?;
            // SAFETY: arguments are validated in this function; kernel performs the actual mapping.
            let raw = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    length,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if raw as isize == -1 {
                return Err(io::Error::last_os_error());
            }

            let base = NonNull::new(raw.cast::<u8>())
                .ok_or_else(|| io::Error::other("mmap returned null"))?;
            let next_page = unsafe { base.as_ptr().add(page_size) }.cast::<c_void>();
            let next_prot = if nx_support {
                PROT_READ | PROT_WRITE
            } else {
                PROT_NONE
            };
            // SAFETY: `next_page` points into the just-created mapping and covers one full page.
            let protect_result = unsafe { mprotect(next_page, page_size, next_prot) };
            if protect_result != 0 {
                let error = io::Error::last_os_error();
                // SAFETY: mapping was created above and must be released on error.
                let _ = unsafe { munmap(base.as_ptr().cast::<c_void>(), length) };
                return Err(error);
            }

            Ok(Self { base, page_size })
        }
    }

    #[allow(dead_code)]
    pub fn code_page(&self) -> *mut u8 {
        #[cfg(not(target_os = "linux"))]
        {
            std::ptr::null_mut()
        }

        #[cfg(target_os = "linux")]
        {
            self.base.as_ptr()
        }
    }

    pub fn sentinel_page(&self) -> *mut u8 {
        #[cfg(not(target_os = "linux"))]
        {
            std::ptr::null_mut()
        }

        #[cfg(target_os = "linux")]
        {
            // SAFETY: sentinel page starts exactly one page after the mapping base.
            unsafe { self.base.as_ptr().add(self.page_size) }
        }
    }

    #[allow(dead_code)]
    pub fn load_instruction(&mut self, instruction: &InstructionBytes) {
        self.load_probe(
            instruction,
            instruction.specified_len().max(MAX_INSN_LENGTH),
        );
    }

    pub fn load_probe(&mut self, instruction: &InstructionBytes, probe_length: usize) {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (instruction, probe_length);
        }

        #[cfg(target_os = "linux")]
        {
            let target = self.packet_start(probe_length);
            // SAFETY: the instruction is copied into the writable/executable code page.
            unsafe {
                std::ptr::write_bytes(self.base.as_ptr(), 0, self.page_size);
                std::ptr::copy_nonoverlapping(
                    instruction.bytes().as_ptr(),
                    target,
                    instruction.specified_len().min(probe_length),
                );
            }
        }
    }

    pub fn packet_start(&self, insn_size: usize) -> *mut u8 {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = insn_size;
            std::ptr::null_mut()
        }

        #[cfg(target_os = "linux")]
        {
            let offset = self.page_size.saturating_sub(insn_size);
            // SAFETY: offset is bounded to the page size, so this stays inside the code page.
            unsafe { self.base.as_ptr().add(offset) }
        }
    }

    pub fn map_null_page(&self) -> io::Result<NullPageGuard> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "null-page mapping is only implemented on Linux",
            ))
        }

        #[cfg(target_os = "linux")]
        {
            // SAFETY: mapping at address 0 is explicitly requested; the kernel enforces permissions.
            let raw = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    self.page_size,
                    PROT_READ | PROT_WRITE,
                    MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if raw as isize == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(NullPageGuard {
                page_size: self.page_size,
            })
        }
    }
}

impl Drop for ExecutableRegion {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: this releases the exact two-page mapping owned by the region.
            let _ = unsafe { munmap(self.base.as_ptr().cast::<c_void>(), self.page_size * 2) };
        }
    }
}

#[derive(Debug)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct NullPageGuard {
    page_size: usize,
}

impl Drop for NullPageGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: this releases the fixed null-page mapping created by `map_null_page`.
            let _ = unsafe { munmap(std::ptr::null_mut(), self.page_size) };
        }
    }
}

#[derive(Debug)]
pub struct LinuxX86Backend {
    environment: LinuxRuntimeEnvironment,
    region: ExecutableRegion,
    fault_model: FaultModel,
    preamble: TrapFlagPreamble,
    enable_null_access: bool,
    #[allow(dead_code)]
    nx_support: bool,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    dummy_stack: Vec<u8>,
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    null_page_guard: Option<NullPageGuard>,
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    signal_stack: SignalStack,
    #[cfg(target_os = "linux")]
    #[allow(dead_code)]
    signal_handlers: SignalHandlers,
}

impl LinuxX86Backend {
    pub fn new() -> Self {
        match Self::try_new() {
            Ok(backend) => backend,
            Err(error) => panic!("failed to initialize Linux x86 backend scaffolding: {error}"),
        }
    }

    pub fn from_config(config: &InjectorConfig) -> io::Result<Self> {
        Self::try_new_with_options(config.nx_support, config.allow_null_access)
    }

    pub fn try_new() -> io::Result<Self> {
        Self::try_new_with_options(true, false)
    }

    pub fn try_new_with_options(nx_support: bool, enable_null_access: bool) -> io::Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (nx_support, enable_null_access);
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Linux x86 backend is only implemented on Linux hosts",
            ));
        }

        #[cfg(target_os = "linux")]
        {
            let environment = LinuxRuntimeEnvironment::detect()?;
            let effective_nx = nx_support
                && environment
                    .capabilities
                    .as_ref()
                    .map(|caps| caps.has_nx)
                    .unwrap_or(true);
            let region = ExecutableRegion::allocate(environment.page_size, effective_nx)?;
            let null_page_guard = if enable_null_access {
                Some(region.map_null_page()?)
            } else {
                None
            };
            let signal_stack = SignalStack::install()?;
            let signal_handlers = SignalHandlers::install(native_or_scaffold_signal_handler())?;
            Ok(Self {
                environment,
                region,
                fault_model: FaultModel::default(),
                preamble: TrapFlagPreamble::default(),
                enable_null_access,
                nx_support: effective_nx,
                #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                dummy_stack: vec![0_u8; DEFAULT_ALTSTACK_SIZE],
                null_page_guard,
                signal_stack,
                signal_handlers,
            })
        }
    }

    pub fn environment(&self) -> &LinuxRuntimeEnvironment {
        &self.environment
    }

    pub fn fault_model(&self) -> FaultModel {
        self.fault_model
    }

    pub fn build_probe_context(&self, probe_length: usize) -> ProbeContext {
        ProbeContext {
            packet_start: self.region.packet_start(probe_length) as usize,
            page_end: self.region.sentinel_page() as usize,
            preamble_length: self.preamble.ud2_size,
            probe_length,
        }
    }
}

impl ExecutionBackend for LinuxX86Backend {
    fn execute(&mut self, instruction: &InstructionBytes) -> Result<BackendObservation, String> {
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            self.capture_baseline_context();
            let mut result = BackendObservation::default();
            for probe_length in 1..=self.fault_model.max_instruction_length {
                self.region.load_probe(instruction, probe_length);
                if self.enable_null_access {
                    // SAFETY: when enabled, `null_page_guard` owns a writable null page.
                    unsafe {
                        libc::memset(std::ptr::null_mut(), 0, self.environment.page_size);
                    }
                }
                let probe = self.build_probe_context(probe_length);
                let observation = self.run_probe(&probe)?;
                result = probe.infer_fault_result(&self.fault_model, observation);
                result.length = probe_length as u32;
                if !probe.should_continue_probing(&self.fault_model, &result) {
                    break;
                }
            }
            Ok(result)
        }

        #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
        {
            let _ = instruction;
            Err(format!(
                "native Linux x86_64 execution backend is not available on this host; environment: root={} page_size={} nx={} null={}",
                self.environment.is_root,
                self.environment.page_size,
                self.nx_support,
                self.enable_null_access,
            ))
        }
    }
}

#[cfg(target_os = "linux")]
fn native_or_scaffold_signal_handler() -> RawSignalHandler {
    #[cfg(target_arch = "x86_64")]
    {
        native_signal_handler
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        scaffold_signal_handler
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl LinuxX86Backend {
    fn capture_baseline_context(&mut self) {
        // SAFETY: signal handler mode is process-global and the injector currently runs probes
        // synchronously in one thread.
        unsafe {
            if HAVE_BASELINE_CONTEXT {
                return;
            }
            SIGNAL_MODE = SignalMode::CaptureState;
            core::arch::asm!("ud2", options(nostack));
            HAVE_BASELINE_CONTEXT = true;
        }
    }

    fn run_probe(&mut self, probe: &ProbeContext) -> Result<FaultObservation, String> {
        let stack_top = self.dummy_stack.as_mut_ptr() as usize + self.dummy_stack.len() - 16;
        // SAFETY: the signal handler restores the original context and resumes at the local
        // label recorded in `RESUME_IP`.
        unsafe {
            PACKET_START = probe.packet_start;
            PREAMBLE_LENGTH = probe.preamble_length;
            SIGNAL_MODE = SignalMode::ExecuteProbe;
            jump_to_probe(probe.packet_start, stack_top);
            Ok(CURRENT_OBSERVATION)
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn jump_to_probe(packet: usize, stack_top: usize) {
    let resume_slot = std::ptr::addr_of_mut!(RESUME_IP) as usize;
    // SAFETY: control intentionally transfers to generated code. Faults are redirected by the
    // installed signal handler back to label 3.
    unsafe {
        core::arch::asm!(
            "lea r11, [rip + 3f]",
            "mov [{resume_slot}], r11",
            "xor rax, rax",
            "xor rcx, rcx",
            "xor rdx, rdx",
            "xor rsi, rsi",
            "xor rdi, rdi",
            "xor r8, r8",
            "xor r9, r9",
            "xor r10, r10",
            "xor r12, r12",
            "xor r13, r13",
            "xor r14, r14",
            "xor r15, r15",
            "mov rsp, {stack_top}",
            "jmp {packet}",
            "3:",
            resume_slot = in(reg) resume_slot,
            stack_top = in(reg) stack_top,
            packet = in(reg) packet,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("rsi") _,
            out("rdi") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
        );
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe extern "C" fn native_signal_handler(
    signum: i32,
    siginfo: *mut libc::siginfo_t,
    context: *mut c_void,
) {
    let uc = &mut *(context.cast::<libc::ucontext_t>());
    match SIGNAL_MODE {
        SignalMode::CaptureState => {
            BASELINE_CONTEXT = Some(uc.uc_mcontext);
            uc.uc_mcontext.gregs[libc::REG_RIP as usize] += UD2_SIZE as i64;
        }
        SignalMode::ExecuteProbe => {
            let fault_ip = uc.uc_mcontext.gregs[libc::REG_RIP as usize] as usize;
            let fault_addr = if signum == libc::SIGSEGV || signum == libc::SIGBUS {
                (*siginfo).si_addr() as usize
            } else {
                usize::MAX
            };
            CURRENT_OBSERVATION = FaultObservation {
                signum: signum as u32,
                si_code: (*siginfo).si_code as u32,
                fault_addr,
                fault_ip,
            };

            let baseline = BASELINE_CONTEXT.expect("baseline context should be captured");
            uc.uc_mcontext.gregs = baseline.gregs;
            uc.uc_mcontext.gregs[libc::REG_RIP as usize] = RESUME_IP as i64;
            uc.uc_mcontext.gregs[libc::REG_EFL as usize] &= !(TF as i64);
            let _ = (PACKET_START, PREAMBLE_LENGTH);
        }
    }
}

fn page_size() -> io::Result<usize> {
    // SAFETY: getpagesize is a side-effect-free libc query.
    let page_size = unsafe { getpagesize() };
    if page_size <= 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(page_size as usize)
    }
}

#[cfg(test)]
mod tests {
    use crate::linux_x86::{
        normalize_fault_addr, FaultModel, FaultObservation, LinuxRuntimeEnvironment, ProbeContext,
        TrapFlagPreamble, JMP_LENGTH, TF, UD2_SIZE,
    };

    #[test]
    fn detects_runtime_environment() {
        let environment =
            LinuxRuntimeEnvironment::detect().expect("environment detection should work");
        assert!(environment.page_size >= 4096);
    }

    #[test]
    fn infers_fault_length_like_reference_code() {
        let model = FaultModel::default();
        let packet = 0x1000_usize;
        assert_eq!(model.infer_instruction_length(0x1005, packet, 2), 3);
        assert_eq!(
            model.infer_instruction_length(0x0fff, packet, 2),
            JMP_LENGTH
        );
        assert_eq!(
            model.infer_instruction_length(0x2000, packet, 2),
            JMP_LENGTH
        );
    }

    #[test]
    fn stops_length_probe_when_fault_moves_off_page_end() {
        let model = FaultModel::default();
        assert!(!model.should_stop_length_probe(0x2000, 0x2000));
        assert!(model.should_stop_length_probe(0x1fff, 0x2000));
    }

    #[test]
    fn translates_fault_observation_to_backend_result() {
        let model = FaultModel::default();
        let probe = ProbeContext {
            packet_start: 0x1000,
            page_end: 0x2000,
            preamble_length: 2,
            probe_length: 4,
        };
        let observation = FaultObservation {
            signum: 11,
            si_code: 2,
            fault_addr: 0x2000,
            fault_ip: 0x1005,
        };
        let result = probe.infer_fault_result(&model, observation);
        assert_eq!(result.length, 3);
        assert_eq!(result.signum, 11);
        assert_eq!(result.fault_addr, 0x2000);
    }

    #[test]
    fn normalizes_non_memory_fault_addresses() {
        assert_eq!(normalize_fault_addr(5, 0x1234), u32::MAX);
        assert_eq!(normalize_fault_addr(11, 0x1234), 0x1234);
        assert_eq!(normalize_fault_addr(7, 0x4567), 0x4567);
    }

    #[test]
    fn probe_context_decides_whether_to_continue_length_probing() {
        let model = FaultModel::default();
        let probe = ProbeContext {
            packet_start: 0x1000,
            page_end: 0x2000,
            preamble_length: 2,
            probe_length: 4,
        };
        let continue_result = crate::BackendObservation {
            valid: 1,
            length: 4,
            signum: 11,
            si_code: 1,
            fault_addr: 0x2000,
        };
        let stop_result = crate::BackendObservation {
            fault_addr: 0x1fff,
            ..continue_result
        };
        assert!(probe.should_continue_probing(&model, &continue_result));
        assert!(!probe.should_continue_probing(&model, &stop_result));
    }

    #[test]
    fn exposes_trap_flag_preamble_constants() {
        let preamble = TrapFlagPreamble::default();
        assert_eq!(preamble.trap_flag_mask, TF);
        assert_eq!(preamble.ud2_size, UD2_SIZE);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn allocates_executable_region_and_loads_instruction() {
        use sandblaster_core::{InstructionBytes, MAX_INSN_LENGTH};

        use crate::linux_x86::ExecutableRegion;

        let environment =
            LinuxRuntimeEnvironment::detect().expect("environment detection should work");
        let mut region =
            ExecutableRegion::allocate(environment.page_size, true).expect("mapping should work");
        let instruction = InstructionBytes::from_slice(&[0x90, 0xcc]);
        region.load_instruction(&instruction);
        let packet_start = region.packet_start(instruction.specified_len().max(MAX_INSN_LENGTH));
        // SAFETY: `packet_start` points to bytes we just copied into the code page.
        let loaded =
            unsafe { std::slice::from_raw_parts(packet_start, instruction.specified_len()) };
        assert_eq!(loaded, &[0x90, 0xcc]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installs_signal_runtime_scaffold() {
        use crate::linux_x86::{SignalHandlers, SignalStack};

        let stack = SignalStack::install().expect("alt stack should install");
        assert!(stack.len() >= super::DEFAULT_ALTSTACK_SIZE);

        let handlers = SignalHandlers::install(super::scaffold_signal_handler)
            .expect("handlers should install");
        assert_eq!(handlers.count(), 5);
    }
}
