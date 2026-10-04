# Sandblaster iOS ARM64 Agent

This directory is the integration point for the signed iOS developer app/agent.
The Rust workspace now exposes target-aware dry-run and packet plumbing for
`ios-arm64`, but native generated-code execution is intentionally not wired to
the CLI binary because non-jailbroken iOS apps must run inside a signed app
container.

The app target should:

- link the Rust core/injector library as a static library or XCFramework
- call the scan loop in-process instead of spawning `injector`
- request the narrowest executable-memory/JIT entitlement available for the
  development profile
- export the same `SB1` versioned packet lines that Android and Linux emit
- start with dry-run and a one-instruction executable-memory feasibility test on
  physical devices before enabling broader ARM64 ranges

The first iOS implementation should keep the host transport simple: write packet
logs into the app container and retrieve them through Xcode Devices or a small
debug-only share/export action.

When no executable-memory/JIT entitlement is available at all, use the
static-corpus mode instead of the JIT feasibility test above: the candidate
corpus is precomputed on the host at build time and baked into the signed
binary as ordinary compiled functions, so nothing is ever written to
executable memory at runtime. See `INTEGRATION.md`'s "Static Corpus" section.
