# Sandblaster

This repository is the Rust rewrite workspace for Sandsifter. The reference implementation remains in [`reference/`](reference/) and is currently the source of truth for behavior and compatibility.

The first milestone implemented here establishes:

- a Rust workspace split into `core`, `injector`, `search`, `disasm`, `summary`, `tui`, and `cli`
- exact legacy log/tick parsing and writing primitives
- anomaly filtering semantics copied from the Python frontend
- search strategy abstractions for brute, random, tunnel, and driven modes
- injector and disassembler interface boundaries for the later Linux/x86 unsafe backend port

Current status:

- `cargo test` validates the shared compatibility layer
- `sifter` and `injector` binaries currently provide compatibility-oriented CLI parsing shells
- the native low-level execution backend is not implemented yet

Reference code architecture and migration intent are tracked in the conversation plan that drove this workspace layout.

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
