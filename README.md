![Sandblaster banner](.github/readmebanner.png)

# Sandblaster

Sandblaster is a multiplatform processor fuzzer for discovering unusual
instruction behavior on real hardware. It generates, executes, disassembles,
and records processor test cases through a Rust workspace with native runners
for Linux/x86_64, Android/ARM64, and a signed iOS/ARM64 app agent.

The workspace includes:

- target-aware instruction generation, execution, packet, and summary crates
- Linux/x86_64 generated-code execution for real x86 hosts
- Android/ARM64 generated-code execution for on-device `adb shell` runs
- iOS/ARM64 in-process execution through `mobile/ios-agent/SandblasterApp`
- `SB1` line-oriented result packets with platform and architecture metadata
- an `iced-x86` disassembler backend for x86 result classification
- a terminal sifter UI for live scans, logs, sync files, and summaries

## Quick Check

Run the Rust workspace tests from the repository root:

```sh
cargo test --workspace
```

The main scripts wrap target-specific setup and keep platform checks close to
the runner they exercise.

## Linux x86_64

On a real x86_64 Linux system, use the native runner:

```sh
scripts/x86-linux.sh check
scripts/x86-linux.sh build
scripts/x86-linux.sh test
```

Start the backend without executing generated probes:

```sh
scripts/x86-linux.sh smoke
```

Run a bounded generated-code probe:

```sh
scripts/x86-linux.sh exec-smoke
```

Run the injector or sifter directly by passing the remaining arguments through:

```sh
scripts/x86-linux.sh injector -T -b -B 1 -i 90 -e 91
SANDBLASTER_INJECTOR="$PWD/target/debug/injector" \
scripts/x86-linux.sh sifter --unk --dis --len --sync --tick -- -t -P1
```

By default, `sifter` renders a live terminal dashboard with tested count,
finding count, estimated rate, elapsed time, current result, recent
instructions, and recent findings. Use `--no-ui` for log-only automation:

```sh
scripts/x86-linux.sh sifter --no-ui --unk --sync -- -b -B 1 -i 00 -e 10
```

Run a bounded live scan that writes `data/log`, `data/sync`, and `data/last`:

```sh
scripts/x86-linux.sh build

SANDBLASTER_INJECTOR="$PWD/target/debug/injector" \
scripts/x86-linux.sh sifter --unk --dis --len --sync --tick --save -- -b -B 1 -i 00 -e ff
```

Resume a saved run:

```sh
SANDBLASTER_INJECTOR="$PWD/target/debug/injector" \
scripts/x86-linux.sh sifter --unk --dis --len --sync --tick --save --resume -- -b -B 1 -e ff
```

Parallel workers are supported for finite brute and tunnel ranges:

```sh
scripts/x86-linux.sh injector -T -b -B 1 -i 00 -e ff -j 4 -l 1

SANDBLASTER_INJECTOR="$PWD/target/debug/injector" \
scripts/x86-linux.sh sifter --no-ui --unk --sync --save -- -b -B 1 -i 00 -e ff -j 4 -l 1
```

Pin injector workers to a CPU with `-c`:

```sh
scripts/x86-linux.sh injector -T -c 0 -b -B 1 -i 90 -e 91
```

Validate the frontend, logs, and UI without executing generated instructions by
passing `--dry-run` through to the injector:

```sh
scripts/x86-linux.sh injector --dry-run -T -b -B 1 -i 90 -e 91

SANDBLASTER_INJECTOR="$PWD/target/debug/injector" \
scripts/x86-linux.sh sifter --unk --sync --tick -- --dry-run -b -B 1 -i 90 -e 91
```

The native runner intentionally refuses to run unless `uname` reports Linux on
`x86_64`/`amd64`. Smoke commands avoid `-0` null-page mode and do not need root;
scans that use `-0` still need root and a kernel configuration that allows
mapping page zero.

## Android ARM64

The Android backend targets `aarch64-linux-android` and runs on a real ARM64
device through `adb shell`:

```sh
scripts/android-arm64.sh check
scripts/android-arm64.sh build
scripts/android-arm64.sh push
```

Run a dry-run smoke test:

```sh
scripts/android-arm64.sh smoke
```

Run a bounded native probe using the ARM64 `nop` encoding:

```sh
scripts/android-arm64.sh exec-smoke
```

Run the local `sifter` frontend against the device injector:

```sh
scripts/android-arm64.sh sifter --no-ui --unk --sync -- -b -B 4 -i 1f2003d5 -e 1f2003d6
```

The Android backend is intentionally conservative: ARM64 candidates are
fixed-width 4-byte instructions, x86 prefix handling is disabled, and result
records currently include the child process signal rather than full `siginfo`
and register-context recovery.

## iOS ARM64

The iOS agent lives in `mobile/ios-agent/SandblasterApp`. iOS generated-code
execution runs in-process inside a signed developer app instead of a spawned CLI
binary, matching non-jailbroken iOS app constraints.

Build the Rust static library and copy it into the Xcode project:

```sh
scripts/ios-build.sh
```

Then open the app project in Xcode:

```sh
open mobile/ios-agent/SandblasterApp/SandblasterApp.xcodeproj
```

Select your development team, connect a physical iOS device, and run the
`SandblasterApp` scheme. Results are written to the app container and can be
retrieved through Xcode Devices and Simulators.

The iOS app uses the same target-aware packet plumbing as the other runners and
exports `SB1` logs for `ios-arm64`. Start with dry-run or narrow ARM64 ranges
before broader generated-code sweeps.

Import an exported iOS `SB1` log into the host-side sifter pipeline:

```sh
cargo run -p sandblaster-cli --bin sifter -- \
  --input path/to/logs.txt --unk --dis --len --sync --no-ui
```

## macOS and Docker

The low-level x86 injector is written for `linux + x86_64`. On Apple Silicon
macOS, use Docker Desktop's `linux/amd64` emulation to build and smoke-test it
without a physical x86 machine:

```sh
scripts/x86-docker.sh build
scripts/x86-docker.sh test
scripts/x86-docker.sh smoke
```

Try the generated-code execution path under Docker's amd64 emulation:

```sh
scripts/x86-docker.sh exec-smoke
```

Open an interactive shell in the same environment:

```sh
scripts/x86-docker.sh shell
```

Treat Docker as a development and compatibility check. It is useful for
exercising Linux/x86 builds and startup, but generated-code signal handling may
differ from a real x86 Linux host and is not authoritative evidence of behavior
on real x86 silicon.

## Results

`data/log` and `data/sync` keep the reference-compatible legacy text record
shape. `data/findings.tsv` adds reproducible command metadata and raw fields for
each deduplicated finding, while `data/summary` groups findings by opcode,
leading prefix, signal, and disassembler class.

New scans use `SB1` packets with explicit target metadata. The x86 fields record
`disas_known` and `disas_length`; mnemonic and operand formatting differences
are intentionally outside the compatibility contract.
