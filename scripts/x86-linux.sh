#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
TIMEOUT_DURATION="${SANDBLASTER_NATIVE_TIMEOUT:-20s}"

usage() {
    cat <<USAGE
Usage: $(basename "$0") <check|build|test|smoke|exec-smoke|injector|sifter> [args...]

Commands:
  check        Run cargo check for the native Linux/x86_64 injector.
  build        Build the native injector and sifter binaries.
  test         Run cargo test --workspace on the native host.
  smoke        Start the Linux/x86 backend without executing probes.
  exec-smoke   Run a bounded generated-code probe on the native host.
  injector     Run the injector with the remaining arguments.
  sifter       Run the sifter frontend with the remaining arguments.

Environment:
  SANDBLASTER_NATIVE_TIMEOUT  Timeout for smoke commands (default: 20s).
USAGE
}

require_linux_x86_64() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    if [[ "${os}" != "Linux" ]]; then
        echo "error: this script must run on Linux, got ${os}" >&2
        exit 2
    fi

    case "${arch}" in
        x86_64|amd64)
            ;;
        *)
            echo "error: this script must run on x86_64 Linux, got ${arch}" >&2
            exit 2
            ;;
    esac
}

require_cargo() {
    if ! command -v cargo >/dev/null 2>&1; then
        echo "error: cargo is required; install Rust from https://rustup.rs/" >&2
        exit 2
    fi
}

run_with_timeout() {
    if command -v timeout >/dev/null 2>&1; then
        timeout "${TIMEOUT_DURATION}" "$@"
    else
        echo "warning: timeout command not found; running without a timeout" >&2
        "$@"
    fi
}

command="${1:-}"
if [[ $# -gt 0 ]]; then
    shift
fi

case "${command}" in
    -h|--help|help)
        usage
        exit 0
        ;;
esac

require_linux_x86_64
require_cargo
cd "${REPO_ROOT}"

case "${command}" in
    check)
        cargo check -p sandblaster-injector
        ;;
    build)
        cargo build -p sandblaster-injector -p sandblaster-cli "$@"
        ;;
    test)
        cargo test --workspace "$@"
        ;;
    smoke)
        run_with_timeout cargo run -p sandblaster-injector --bin injector -- -T -d "$@"
        ;;
    exec-smoke)
        run_with_timeout cargo run -p sandblaster-injector --bin injector -- -T -b -B 1 -i 90 -e 91 "$@"
        ;;
    injector)
        cargo run -p sandblaster-injector --bin injector -- "$@"
        ;;
    sifter)
        cargo run -p sandblaster-cli --bin sifter -- "$@"
        ;;
    "")
        usage >&2
        exit 2
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
