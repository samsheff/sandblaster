use std::collections::VecDeque;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use sandblaster_core::{parse_hex_instruction, InstructionBytes, TargetSpec};
use sandblaster_disasm::Arm64HeuristicDisassembler;
use sandblaster_injector::{
    BackendObservation, ExecutionBackend, InjectorConfig, InjectorEngine, InjectorEvent,
    IosArm64Backend, VersionedPacket,
};
use sandblaster_search::SearchMode;

// ─── Dry-run backend (no executable memory needed) ───────────────────────────

struct DryRunBackend {
    fixed_len: Option<usize>,
}

impl ExecutionBackend for DryRunBackend {
    fn execute(&mut self, instruction: &InstructionBytes) -> Result<BackendObservation, String> {
        Ok(BackendObservation {
            valid: 1,
            length: self
                .fixed_len
                .unwrap_or_else(|| instruction.specified_len().max(1)) as u32,
            signum: 5,
            si_code: 0,
            fault_addr: u32::MAX,
        })
    }
}

// ─── Backend enum for unified dispatch ───────────────────────────────────────

enum AnyBackend {
    DryRun(DryRunBackend),
    Native(IosArm64Backend),
}

impl ExecutionBackend for AnyBackend {
    fn execute(&mut self, instruction: &InstructionBytes) -> Result<BackendObservation, String> {
        match self {
            Self::DryRun(b) => b.execute(instruction),
            Self::Native(b) => b.execute(instruction),
        }
    }
}

// ─── Scan state ──────────────────────────────────────────────────────────────

struct SharedState {
    queue: Mutex<VecDeque<String>>,
    stop: AtomicBool,
    done: AtomicBool,
    emitted: AtomicU64,
    skipped: AtomicU64,
    queue_capacity: usize,
    error: Mutex<String>,
    last_instruction: Mutex<String>,
}

struct ScanHandle {
    state: Arc<SharedState>,
    thread: Option<std::thread::JoinHandle<()>>,
}

static SCAN: OnceLock<Mutex<Option<ScanHandle>>> = OnceLock::new();

fn global_scan() -> &'static Mutex<Option<ScanHandle>> {
    SCAN.get_or_init(|| Mutex::new(None))
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Clone, Debug)]
struct MobileScanConfig {
    mode: i32,
    strategy: SearchMode,
    start_instruction: Option<InstructionBytes>,
    end_instruction: Option<InstructionBytes>,
    seed: Option<u64>,
    max_packets: u64,
    queue_capacity: usize,
    require_native: bool,
}

impl MobileScanConfig {
    fn legacy(mode: i32) -> Self {
        Self {
            mode,
            strategy: SearchMode::Tunnel,
            start_instruction: None,
            end_instruction: None,
            seed: None,
            max_packets: 0,
            queue_capacity: 5_000,
            require_native: mode == 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SandblasterScanStatus {
    pub running: u32,
    pub done: u32,
    pub emitted: u64,
    pub skipped: u64,
    pub queue_depth: u32,
    pub queue_capacity: u32,
    pub has_error: u32,
}

fn parse_strategy(value: i32) -> SearchMode {
    match value {
        1 => SearchMode::Brute,
        2 => SearchMode::Random,
        3 => SearchMode::Driven,
        _ => SearchMode::Tunnel,
    }
}

unsafe fn parse_optional_instruction(
    ptr: *const c_char,
    field: &'static str,
) -> Result<Option<InstructionBytes>, String> {
    if ptr.is_null() {
        return Ok(None);
    }
    let value = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| format!("{field} is not valid UTF-8"))?;
    if value.trim().is_empty() {
        return Ok(None);
    }
    parse_hex_instruction(value)
        .map(Some)
        .map_err(|error| format!("bad {field}: {error}"))
}

fn new_shared_state(queue_capacity: usize) -> Arc<SharedState> {
    Arc::new(SharedState {
        queue: Mutex::new(VecDeque::new()),
        stop: AtomicBool::new(false),
        done: AtomicBool::new(false),
        emitted: AtomicU64::new(0),
        skipped: AtomicU64::new(0),
        queue_capacity,
        error: Mutex::new(String::new()),
        last_instruction: Mutex::new(String::new()),
    })
}

fn set_error(state: &SharedState, error: impl Into<String>) {
    let error = error.into();
    eprintln!("[sandblaster-mobile-ffi] {error}");
    *lock(&state.error) = error;
}

fn wait_for_queue_capacity(state: &SharedState) -> bool {
    loop {
        if state.stop.load(Ordering::Acquire) {
            return false;
        }
        let q = lock(&state.queue);
        if q.len() < state.queue_capacity {
            return true;
        }
        drop(q);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

// ─── Sandbox operation list ───────────────────────────────────────────────────

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
const SANDBOX_OPS: &[&str] = &[
    "file-read-data",
    "file-write-data",
    "file-read-metadata",
    "file-write-metadata",
    "file-issue-extension",
    "file-read-xattr",
    "file-write-xattr",
    "network-bind",
    "network-connect",
    "network-inbound",
    "network-outbound",
    "mach-lookup",
    "mach-register",
    "mach-cross-domain-lookup",
    "ipc-posix-sem",
    "ipc-posix-shm",
    "ipc-sysv-sem",
    "ipc-sysv-shm",
    "process-fork",
    "process-exec",
    "process-info-pidinfo",
    "iokit-open",
    "iokit-user-client-class",
    "nvram-get",
    "nvram-set",
    "nvram-delete",
    "system-preferences-read",
    "system-preferences-write",
    "sysctl-read",
    "sysctl-write",
    "signal",
    "socket",
    "pseudo-tty",
    "user-preference-read",
    "user-preference-write",
    "distributed-notifications-post",
    "distributed-notifications-receive",
    "authorization-right-obtain",
    "app-group-data-access",
    "file-map-executable",
    "file-read-xattr",
    "file-write-xattr",
    "generic-issue-extension",
    "hid-control",
    "iokit-set-properties",
    "iokit-get-properties",
];

// ─── sandbox_check FFI (private Apple API) ───────────────────────────────────

#[cfg(all(target_os = "ios", target_arch = "aarch64"))]
extern "C" {
    // sandbox_check(pid, operation, type) → 0=allow, 1=deny, -1=error
    // SANDBOX_FILTER_NONE = 0
    fn sandbox_check(
        pid: libc::pid_t,
        operation: *const libc::c_char,
        filter_type: libc::c_int,
        ...
    ) -> libc::c_int;
}

// ─── Sandbox worker ───────────────────────────────────────────────────────────

fn run_sandbox_worker(state_arc: Arc<SharedState>) {
    #[cfg(all(target_os = "ios", target_arch = "aarch64"))]
    {
        use std::ffi::CString;

        let pid = unsafe { libc::getpid() };

        for &op in SANDBOX_OPS {
            if state_arc.stop.load(Ordering::Acquire) {
                break;
            }

            if !wait_for_queue_capacity(&state_arc) {
                break;
            }

            let op_cstr = match CString::new(op) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Clear errno before the call
            unsafe { *libc::__error() = 0 };
            let result = unsafe { sandbox_check(pid, op_cstr.as_ptr(), 0) };
            let errno_val = unsafe { *libc::__error() };

            // result: 0=allow, 1=deny; anything else is unexpected
            let classified = if result < 0 || result > 1 { 2 } else { result };

            // SB2<TAB>ios<TAB>arm64<TAB>operation<TAB>result<TAB>errno<TAB>param
            let line = format!("SB2\tios\tarm64\t{}\t{}\t{}\t\n", op, classified, errno_val);
            state_arc.emitted.fetch_add(1, Ordering::Relaxed);
            lock(&state_arc.queue).push_back(line);
        }
    }

    #[cfg(not(all(target_os = "ios", target_arch = "aarch64")))]
    {
        // Emit a single informational line when not on device
        let line = "SB2\tios\tarm64\tsandbox-check-unavailable\t-1\t0\t\n".to_string();
        state_arc.emitted.fetch_add(1, Ordering::Relaxed);
        lock(&state_arc.queue).push_back(line);
    }

    state_arc.done.store(true, Ordering::Release);
}

// ─── ARM64 instruction fuzzer worker ─────────────────────────────────────────

fn run_instruction_worker(state_arc: Arc<SharedState>, scan_config: MobileScanConfig) {
    let dry_run = scan_config.mode == 1;
    let backend: AnyBackend = if !dry_run {
        match IosArm64Backend::try_new() {
            Ok(b) => AnyBackend::Native(b),
            Err(e) => {
                if scan_config.require_native {
                    let msg = format!("native backend unavailable: {e}");
                    set_error(&state_arc, msg);
                    state_arc.done.store(true, Ordering::Release);
                    return;
                }
                let msg = format!(
                    "[sandblaster] native backend unavailable ({e}); falling back to dry-run\n"
                );
                lock(&state_arc.queue).push_back(msg);
                AnyBackend::DryRun(DryRunBackend { fixed_len: Some(4) })
            }
        }
    } else {
        AnyBackend::DryRun(DryRunBackend { fixed_len: Some(4) })
    };

    let config = InjectorConfig {
        target: TargetSpec::ios_arm64(),
        dry_run: false,
        mode: scan_config.strategy,
        start_instruction: scan_config.start_instruction,
        end_instruction: scan_config.end_instruction,
        seed: scan_config.seed,
        ..InjectorConfig::default()
    };
    let mut engine = InjectorEngine::new(Arm64HeuristicDisassembler, backend, &config);

    loop {
        if state_arc.stop.load(Ordering::Acquire) {
            break;
        }
        if scan_config.max_packets != 0
            && state_arc.emitted.load(Ordering::Relaxed) >= scan_config.max_packets
        {
            break;
        }
        if !wait_for_queue_capacity(&state_arc) {
            break;
        }

        match engine.next_event() {
            Ok(Some(InjectorEvent::Executed(result))) => {
                let line = VersionedPacket::from_execution_result(TargetSpec::ios_arm64(), &result)
                    .to_line();
                *lock(&state_arc.last_instruction) = result.instruction.compact_hex();
                state_arc.emitted.fetch_add(1, Ordering::Relaxed);
                lock(&state_arc.queue).push_back(line);
            }
            Ok(Some(InjectorEvent::Skipped(_, _))) => {
                state_arc.skipped.fetch_add(1, Ordering::Relaxed);
            }
            Ok(None) => break,
            Err(e) => {
                set_error(&state_arc, e);
                break;
            }
        }
    }

    state_arc.done.store(true, Ordering::Release);
}

// ─── C ABI ───────────────────────────────────────────────────────────────────

/// Start a scan with legacy defaults.
///
/// `mode`:
///   0 = ARM64 native instruction fuzzing (uses MAP_JIT; fails if unavailable)
///   1 = ARM64 dry-run (synthetic observations, no JIT required)
///   2 = sandbox_check policy fuzzing (probes known sandbox operations)
///
/// Returns 0 on success, -1 if a scan is already running.
///
/// # Safety
/// No pointer arguments; safe to call from any thread.
#[no_mangle]
pub extern "C" fn sandblaster_scan_start(mode: i32) -> i32 {
    start_scan(MobileScanConfig::legacy(mode))
}

/// Start a configured scan.
///
/// `strategy`: 0=tunnel, 1=brute, 2=random, 3=driven-empty.
/// `max_packets`: 0 means run until stopped or range exhaustion.
/// `queue_capacity`: 0 uses the default bounded queue.
///
/// Returns 0 on success, -1 if already running, -2 for invalid config.
///
/// # Safety
/// `start_hex` and `end_hex`, when non-null, must be valid NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn sandblaster_scan_start_config(
    mode: i32,
    strategy: i32,
    start_hex: *const c_char,
    end_hex: *const c_char,
    seed: u64,
    max_packets: u64,
    queue_capacity: u32,
    require_native: i32,
) -> i32 {
    let start_instruction = match unsafe { parse_optional_instruction(start_hex, "start_hex") } {
        Ok(value) => value,
        Err(error) => {
            let state = new_shared_state(queue_capacity.max(1) as usize);
            set_error(&state, error);
            return -2;
        }
    };
    let end_instruction = match unsafe { parse_optional_instruction(end_hex, "end_hex") } {
        Ok(value) => value,
        Err(error) => {
            let state = new_shared_state(queue_capacity.max(1) as usize);
            set_error(&state, error);
            return -2;
        }
    };

    start_scan(MobileScanConfig {
        mode,
        strategy: parse_strategy(strategy),
        start_instruction,
        end_instruction,
        seed: if seed == 0 { None } else { Some(seed) },
        max_packets,
        queue_capacity: if queue_capacity == 0 {
            5_000
        } else {
            queue_capacity as usize
        },
        require_native: require_native != 0,
    })
}

fn start_scan(scan_config: MobileScanConfig) -> i32 {
    let mut guard = lock(global_scan());
    if guard.is_some() {
        return -1;
    }

    let state = new_shared_state(scan_config.queue_capacity);

    let state_arc = Arc::clone(&state);
    let thread = std::thread::spawn(move || match scan_config.mode {
        2 => run_sandbox_worker(state_arc),
        _ => run_instruction_worker(state_arc, scan_config),
    });

    *guard = Some(ScanHandle {
        state,
        thread: Some(thread),
    });
    0
}

/// Poll for the next packet line (SB1 for instructions, SB2 for sandbox).
///
/// Returns bytes written (> 0), 0 if queue is empty but scan is still running,
/// -1 if scan is done and queue is fully drained, -2 on a null/invalid argument,
/// or -3 if `out_buf` is too small for the next complete line.
///
/// # Safety
/// `out_buf` must point to at least `buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sandblaster_scan_next(out_buf: *mut u8, buf_len: i32) -> i32 {
    if out_buf.is_null() || buf_len <= 0 {
        return -2;
    }
    // SAFETY: caller guarantees out_buf points to buf_len writable bytes.
    let buf = unsafe { slice::from_raw_parts_mut(out_buf, buf_len as usize) };

    let guard = lock(global_scan());
    let Some(handle) = guard.as_ref() else {
        return -1;
    };

    let mut q = lock(&handle.state.queue);
    if let Some(line) = q.front() {
        let bytes = line.as_bytes();
        if bytes.len() > buf.len() {
            return -3;
        }
        let line = q.pop_front().expect("front existed");
        let bytes = line.as_bytes();
        buf[..bytes.len()].copy_from_slice(bytes);
        return bytes.len() as i32;
    }

    if handle.state.done.load(Ordering::Acquire) {
        -1
    } else {
        0
    }
}

/// Copy current scan counters into `out_status`.
///
/// # Safety
/// `out_status` must point to writable memory for one `SandblasterScanStatus`.
#[no_mangle]
pub unsafe extern "C" fn sandblaster_scan_status(out_status: *mut SandblasterScanStatus) -> i32 {
    if out_status.is_null() {
        return -2;
    }
    let guard = lock(global_scan());
    let status = if let Some(handle) = guard.as_ref() {
        let q = lock(&handle.state.queue);
        let has_error = !lock(&handle.state.error).is_empty();
        SandblasterScanStatus {
            running: u32::from(!handle.state.done.load(Ordering::Acquire)),
            done: u32::from(handle.state.done.load(Ordering::Acquire)),
            emitted: handle.state.emitted.load(Ordering::Relaxed),
            skipped: handle.state.skipped.load(Ordering::Relaxed),
            queue_depth: q.len().min(u32::MAX as usize) as u32,
            queue_capacity: handle.state.queue_capacity.min(u32::MAX as usize) as u32,
            has_error: u32::from(has_error),
        }
    } else {
        SandblasterScanStatus {
            done: 1,
            ..SandblasterScanStatus::default()
        }
    };
    unsafe { *out_status = status };
    0
}

/// Copy the last emitted instruction hex into `out_buf`.
///
/// # Safety
/// `out_buf` must point to at least `buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sandblaster_last_instruction(out_buf: *mut u8, buf_len: i32) -> i32 {
    if out_buf.is_null() || buf_len <= 0 {
        return -2;
    }
    let buf = unsafe { slice::from_raw_parts_mut(out_buf, buf_len as usize) };
    let guard = lock(global_scan());
    let Some(handle) = guard.as_ref() else {
        return 0;
    };
    let last = lock(&handle.state.last_instruction);
    let bytes = last.as_bytes();
    if bytes.len() > buf.len() {
        return -3;
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    bytes.len() as i32
}

/// Signal the running scan to stop and wait for the worker thread to exit.
///
/// # Safety
/// Safe to call from any thread.
#[no_mangle]
pub extern "C" fn sandblaster_scan_stop() {
    let mut guard = lock(global_scan());
    if let Some(handle) = guard.as_mut() {
        handle.state.stop.store(true, Ordering::Release);
        if let Some(thread) = handle.thread.take() {
            drop(guard);
            let _ = thread.join();
            *lock(global_scan()) = None;
        }
    }
}

/// Copy the last error string into `out_buf`. Returns bytes written, or -2 on bad args.
///
/// # Safety
/// `out_buf` must point to at least `buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn sandblaster_last_error(out_buf: *mut u8, buf_len: i32) -> i32 {
    if out_buf.is_null() || buf_len <= 0 {
        return -2;
    }
    // SAFETY: caller guarantees out_buf points to buf_len writable bytes.
    let buf = unsafe { slice::from_raw_parts_mut(out_buf, buf_len as usize) };

    let guard = lock(global_scan());
    let Some(handle) = guard.as_ref() else {
        return 0;
    };

    let err = lock(&handle.state.error);
    let bytes = err.as_bytes();
    let n = bytes.len().min(buf.len());
    buf[..n].copy_from_slice(&bytes[..n]);
    n as i32
}
