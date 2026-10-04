# iOS ARM64 Integration Guide

This guide describes how to integrate Sandblaster into a signed iOS developer
app so ARM64 scans can run on physical iOS devices later.

## Goal

Run Sandblaster in-process inside an iOS app or debug-only agent. Do not spawn
the `injector` CLI on iOS. The app should call Rust code directly, write `SB1`
packet lines, and export those logs from the app container.

## Rust Build Shape

1. Add an iOS-facing Rust crate, for example `crates/mobile_ffi`, that depends
   on `sandblaster-core`, `sandblaster-injector`, and `sandblaster-disasm`.
2. Expose a small C ABI:
   - `sandblaster_scan_start(config_json_or_flags)`
   - `sandblaster_scan_next(out_buffer, out_buffer_len)`
   - `sandblaster_scan_stop()`
   - `sandblaster_last_error(out_buffer, out_buffer_len)`
3. Build it as a `staticlib` for `aarch64-apple-ios`.
4. Package the static library and headers into an XCFramework or link the
   static library directly from the Xcode project.

## App Architecture

The iOS app should own the scan loop:

1. UI/debug command selects target `ios-arm64`.
2. App constructs a scan config with ARM64 fixed-width candidates.
3. Rust engine runs in-process and returns one `SB1` packet line per result.
4. App appends packet lines to a log file in the app container.
5. User retrieves logs through Xcode Devices, Finder file sharing, or a
   debug-only export action.

Do not rely on `std::process::Command`, shell scripts, or stdout pipes on iOS.

## Native Execution Phases

Start with three phases:

1. Dry-run only:
   - Link Rust into the app.
   - Run `ios-arm64` dry-run scans.
   - Confirm packet export and log parsing on the host.

2. Executable-memory feasibility:
   - Allocate one executable probe page using the narrowest entitlement and
     memory API combination available for the signing profile.
   - Copy a single ARM64 `nop` (`1f2003d5`) followed by a trap instruction.
   - Flush instruction cache.
   - Execute from a controlled worker context.
   - Record whether execution, trap delivery, and recovery are viable.

3. Bounded native scan:
   - Enable tiny fixed ranges only.
   - Keep the app watchdog-safe by running in short batches.
   - Persist progress after each batch.
   - Add a hard stop button in the app UI.

## iOS Security And Signing Notes

Non-jailbroken iOS has stricter executable-memory and code-signing rules than
Android. Treat native generated-code execution as a device-specific feasibility
item until proven on the exact signing setup.

Important constraints:

- The app must be signed.
- JIT/executable-memory behavior depends on platform version, device class, and
  entitlements.
- `MAP_JIT` and related protections may be required or unavailable depending on
  the profile.
- App Store distribution is not a goal for this tool; use a development or
  internal research signing profile.

If executable memory is blocked, keep iOS support as dry-run plus disassembly
and logging until a permitted execution mechanism is available.

## Result Format

Use the same line-oriented `SB1` packet format as the CLI:

```text
SB1<TAB>ios<TAB>arm64<TAB>disas_len<TAB>disas_known<TAB>valid<TAB>length<TAB>signum<TAB>si_code<TAB>fault_addr_hex<TAB>raw_hex
```

The host-side `sifter` parser already understands `ios arm64` packet metadata.

## Minimum Acceptance Criteria

- Xcode builds and launches a physical-device app linked against Rust.
- App can run an `ios-arm64` dry-run scan and export `SB1` logs.
- Host tooling can parse the exported logs.
- A single-instruction executable-memory probe is documented as either passing
  or blocked with the exact device, iOS version, signing profile, and error.

## Follow-Up Work

- Add the `mobile_ffi` crate and C header.
- Add an Xcode project under `mobile/ios-agent`.
- Add a host import command for app-exported `SB1` logs.
- Add native iOS execution only after the feasibility probe succeeds.

## Static Corpus (No Entitlement Needed)

The `MAP_JIT`-based execution phases above only work when the OS actually
grants the process executable, writable memory — which depends on the
restricted dynamic-codesigning entitlement being approved, or a debugger
being attached. When neither is available, use the static-corpus path
instead (`IosStaticCorpusBackend`, mode 3 in `mobile_ffi`):

- `crates/corpusgen` precomputes the candidate corpus on the host at build
  time, using the real `InjectorEngine` (with `MacosArm64Backend` driving
  real ARM64 execution feedback on Apple Silicon macOS, so `Tunnel` mode
  branches exactly as it would on-device).
- `crates/mobile_ffi/build.rs` writes the generated candidates as ARM64
  assembly; `crates/mobile_ffi/src/lib.rs` embeds it directly into the crate
  via `core::arch::global_asm!`. Each candidate becomes an ordinary compiled
  function (its bytes plus the shared `brk #0x1337` sentinel) — there is no
  separate archive to link and no extra Xcode step.
- At runtime, `IosStaticCorpusBackend` looks up each candidate in a table
  built from the linked `SB_PROBE_*` symbols and calls the matching
  pre-baked function directly. No `mmap`, no `MAP_JIT`, no
  `pthread_jit_write_protect_np`.
- The corpus range/mode is controlled by `SANDBLASTER_IOS_CORPUS_*`
  environment variables at build time (see `README.md`); the on-device
  start/end/strategy selection must stay within whatever range was baked
  in, or candidates outside it report a clear "not present" error.

This is a stricter signing posture than the JIT phases, not a weaker one:
every instruction this backend ever executes was present in the binary when
it was code-signed, exactly like any other compiled function in the app.
