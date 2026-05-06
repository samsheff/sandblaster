# Sandblaster

Sandblaster is a processor fuzzer for discovering unusual instruction behavior
on real x86_64 CPUs. It generates, executes, disassembles, and records processor
test cases through a Rust workspace built for local scans and repeatable
automation.

The current implementation provides:

- a Rust workspace split into `core`, `injector`, `search`, `disasm`, `summary`, `tui`, and `cli`
- exact legacy log/tick parsing and writing primitives
- anomaly filtering semantics copied from the Python frontend
- search strategy abstractions for brute, random, tunnel, and driven modes
- a Linux/x86_64 generated-code injector backend
- an `iced-x86` disassembler backend wired into injector raw packets

Current status:

- `cargo test --workspace` validates the shared compatibility layer
- `injector` emits legacy-compatible 44-byte raw packets
- `disas_known` and `disas_length` are populated by a real x86_64 decoder
- `sifter` records legacy findings in `data/log` and `data/sync`, plus additive
  `data/findings.tsv` and `data/summary` metadata
- the native low-level execution backend is implemented for real `x86_64` Linux
- `injector -j` supervises multiple worker processes for finite brute/tunnel
  ranges, with `-l` controlling the split width

## Running on real x86_64 Linux

On an actual x86_64 Linux system, use the native runner:

```sh
scripts/x86-linux.sh check
scripts/x86-linux.sh build
scripts/x86-linux.sh test
```

Start the Linux/x86 backend without executing generated probes:

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

By default, `sifter` renders a live terminal dashboard with the tested count,
finding count, estimated rate, elapsed time, current result, recent instructions,
and recent findings. Use `--no-ui` for log-only automation:

```sh
scripts/x86-linux.sh sifter --no-ui --unk --sync -- -b -B 1 -i 00 -e 10
```

Run a bounded live scan that writes `data/log`, `data/sync`, and `data/last`:

```sh
scripts/x86-linux.sh build

SANDBLASTER_INJECTOR="$PWD/target/debug/injector" \
scripts/x86-linux.sh sifter --unk --dis --len --sync --tick --save -- -b -B 1 -i 00 -e ff
```

Resume a saved run. `--save` updates `data/last` as packets arrive, and
`--resume` appends that value as the injector start instruction:

```sh
SANDBLASTER_INJECTOR="$PWD/target/debug/injector" \
scripts/x86-linux.sh sifter --unk --dis --len --sync --tick --save --resume -- -b -B 1 -e ff
```

When passed directly to `injector`, `-x` emits periodic progress ticks to
stderr. Through `sifter`, `--tick` writes the latest raw instruction bytes to
`data/tick`.

Run a bounded scan with multiple worker processes. Parallel workers are
supported for finite brute and tunnel ranges; random and driven modes should use
`-j 1`. If `-j` is greater than one and `-l` is omitted, the injector splits on
one leading byte:

```sh
scripts/x86-linux.sh injector -T -b -B 1 -i 00 -e ff -j 4 -l 1

SANDBLASTER_INJECTOR="$PWD/target/debug/injector" \
scripts/x86-linux.sh sifter --no-ui --unk --sync --save -- -b -B 1 -i 00 -e ff -j 4 -l 1
```

Pin injector workers to a CPU with `-c`:

```sh
scripts/x86-linux.sh injector -T -c 0 -b -B 1 -i 90 -e 91
```

Run a full tunnel scan:

```sh
scripts/x86-linux.sh build

SANDBLASTER_INJECTOR="$PWD/target/debug/injector" \
scripts/x86-linux.sh sifter --unk --dis --len --sync --tick --save -- -t -P1
```

To validate the frontend, logs, and UI without executing generated processor
instructions, pass `--dry-run` through to the injector:

```sh
scripts/x86-linux.sh injector --dry-run -T -b -B 1 -i 90 -e 91

SANDBLASTER_INJECTOR="$PWD/target/debug/injector" \
scripts/x86-linux.sh sifter --unk --sync --tick -- --dry-run -b -B 1 -i 90 -e 91
```

If dry-run increments `tested` but the same command without `--dry-run` stays at
zero, the unsafe native execution backend is stuck before its first result.

Meaningful `--unk`, `--dis`, and `--len` findings depend on the injector's
disassembler fields. The Rust injector now fills those fields using `iced-x86`,
so `--unk` no longer reports every successfully executed instruction as
unknown.

The runner intentionally refuses to run unless `uname` reports Linux on
`x86_64`/`amd64`. The smoke commands avoid `-0` null-page mode and do not need
root; scans that use `-0` still need root and a kernel configuration that allows
mapping page zero. If `-0` fails, the injector exits with the underlying mmap
error rather than silently continuing without null-page access.

`data/log` and `data/sync` keep the reference-compatible legacy text record
shape. `data/findings.tsv` adds reproducible command metadata and raw fields for
each deduplicated finding, while `data/summary` groups findings by opcode,
leading prefix, signal, and disassembler class.

The Rust disassembler is `iced-x86`; the reference used Capstone. The raw packet
contract only records `disas_known` and `disas_length`, so mnemonic and operand
formatting differences are intentionally not part of compatibility. If a bounded
Capstone comparison is added locally, expected differences should be documented
rather than hidden by changing raw packet layout.

## Testing x86 Linux from macOS/arm

The injector backend is written for `linux + x86_64`. On Apple Silicon macOS,
use Docker Desktop's `linux/amd64` emulation to build and smoke-test it without a
physical x86 machine.

Start Docker Desktop first, then build the amd64 development image:

```sh
scripts/x86-docker.sh build
```

Run the workspace tests inside the emulated x86_64 Linux container:

```sh
scripts/x86-docker.sh test
```

Run a bounded injector smoke test:

```sh
scripts/x86-docker.sh smoke
```

This smoke test starts the Linux/x86 backend and exits without executing
generated instruction probes. To try the generated-code execution path under
Docker's amd64 emulation, run:

```sh
scripts/x86-docker.sh exec-smoke
```

Open an interactive shell in the same environment:

```sh
scripts/x86-docker.sh shell
```

The smoke tests intentionally avoid `-0` null-page mode, so they do not require
a privileged container. Treat this setup as a development and compatibility
check: Docker's amd64 emulation is useful for exercising Linux/x86 builds and
startup, but generated-code signal handling may differ from a real x86 Linux
host and is not authoritative evidence of behavior on real x86 silicon.
