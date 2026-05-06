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
