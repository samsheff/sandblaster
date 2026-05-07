use std::collections::VecDeque;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use sandblaster_core::{InstructionBytes, TargetSpec};
use sandblaster_disasm::Arm64FixedDisassembler;
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
                .unwrap_or_else(|| instruction.specified_len().max(1))
                as u32,
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
    error: Mutex<String>,
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

// ─── C ABI ───────────────────────────────────────────────────────────────────

/// Start a scan. Pass `dry_run = 1` for synthetic observations (no JIT needed),
/// or `dry_run = 0` to use the native iOS ARM64 execution backend.
/// Returns 0 on success, -1 if a scan is already running.
///
/// # Safety
/// No pointer arguments; safe to call from any thread.
#[no_mangle]
pub extern "C" fn sandblaster_scan_start(dry_run: i32) -> i32 {
    let mut guard = lock(global_scan());
    if guard.is_some() {
        return -1;
    }

    let state = Arc::new(SharedState {
        queue: Mutex::new(VecDeque::new()),
        stop: AtomicBool::new(false),
        done: AtomicBool::new(false),
        error: Mutex::new(String::new()),
    });

    let state_arc = Arc::clone(&state);
    let thread = std::thread::spawn(move || {
        // Choose backend: native first, dry-run as fallback.
        let backend: AnyBackend = if dry_run == 0 {
            match IosArm64Backend::try_new() {
                Ok(b) => AnyBackend::Native(b),
                Err(e) => {
                    let msg = format!("[sandblaster] native backend unavailable ({e}); falling back to dry-run\n");
                    lock(&state_arc.queue).push_back(msg);
                    AnyBackend::DryRun(DryRunBackend { fixed_len: Some(4) })
                }
            }
        } else {
            AnyBackend::DryRun(DryRunBackend { fixed_len: Some(4) })
        };

        let config = InjectorConfig {
            target: TargetSpec::ios_arm64(),
            dry_run: false, // we handle dry-run ourselves via AnyBackend
            mode: SearchMode::Tunnel,
            ..InjectorConfig::default()
        };
        let mut engine = InjectorEngine::new(Arm64FixedDisassembler, backend, &config);

        loop {
            if state_arc.stop.load(Ordering::Acquire) {
                break;
            }

            // Back off when the queue is full to avoid runaway memory use.
            {
                let q = lock(&state_arc.queue);
                if q.len() >= 5_000 {
                    drop(q);
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }
            }

            match engine.next_event() {
                Ok(Some(InjectorEvent::Executed(result))) => {
                    let line =
                        VersionedPacket::from_execution_result(TargetSpec::ios_arm64(), &result)
                            .to_line();
                    lock(&state_arc.queue).push_back(line);
                }
                Ok(Some(InjectorEvent::Skipped(_, _))) => {}
                Ok(None) => break,
                Err(e) => {
                    *lock(&state_arc.error) = e;
                    break;
                }
            }
        }

        state_arc.done.store(true, Ordering::Release);
    });

    *guard = Some(ScanHandle {
        state,
        thread: Some(thread),
    });
    0
}

/// Poll for the next SB1 packet line.
///
/// Returns bytes written (> 0), 0 if queue is empty but scan is still running,
/// -1 if scan is done and queue is fully drained, or -2 on a null/invalid argument.
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
    if let Some(line) = q.pop_front() {
        let bytes = line.as_bytes();
        let n = bytes.len().min(buf.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        return n as i32;
    }

    if handle.state.done.load(Ordering::Acquire) {
        -1
    } else {
        0
    }
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
