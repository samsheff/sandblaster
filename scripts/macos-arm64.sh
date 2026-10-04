#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
TIMEOUT_DURATION="${SANDBLASTER_MACOS_TIMEOUT:-20}"

usage() {
    cat <<USAGE
Usage: $(basename "$0") <check|build|test|smoke|exec-smoke|injector|sifter> [args...]

Commands:
  check        Type-check the native macOS/ARM64 injector.
  build        Build the native injector and sifter binaries.
  test         Run cargo test --workspace on the native host.
  smoke        Run a dry-run ARM64 probe on the native host.
  exec-smoke   Run one native ARM64 probe on the native host.
  injector     Run the injector with --target macos-arm64 and remaining arguments.
  sifter       Run the sifter frontend against the macOS injector.

Environment:
  SANDBLASTER_MACOS_TIMEOUT  Timeout for smoke commands in seconds (default: 20).
USAGE
}

require_macos_arm64() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    if [[ "${os}" != "Darwin" ]]; then
        echo "error: this script must run on macOS, got ${os}" >&2
        exit 2
    fi

    if [[ "${arch}" != "arm64" ]]; then
        echo "error: this script must run on Apple Silicon arm64, got ${arch}" >&2
        exit 2
    fi
}

require_cargo() {
    if ! command -v cargo >/dev/null 2>&1; then
        echo "error: cargo is required; install Rust from https://rustup.rs/" >&2
        exit 2
    fi
}

run_with_timeout() {
    perl -e 'alarm shift; exec @ARGV' "${TIMEOUT_DURATION}" "$@"
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

require_macos_arm64
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
        run_with_timeout cargo run -p sandblaster-injector --bin injector -- --target macos-arm64 --dry-run -R -b -B 4 -i 1f2003d5 -e 1f2003d6 "$@"
        ;;
    exec-smoke)
        run_with_timeout cargo run -p sandblaster-injector --bin injector -- --target macos-arm64 -R -b -B 4 -i 1f2003d5 -e 1f2003d6 "$@"
        ;;
    injector)
        cargo run -p sandblaster-injector --bin injector -- --target macos-arm64 "$@"
        ;;
    sifter)
        frontend_args=()
        injector_args=(--target macos-arm64)
        passthrough=0
        for arg in "$@"; do
            if [[ "${passthrough}" -eq 1 ]]; then
                injector_args+=("${arg}")
            elif [[ "${arg}" == "--" ]]; then
                passthrough=1
            else
                frontend_args+=("${arg}")
            fi
        done
        SANDBLASTER_INJECTOR="${REPO_ROOT}/target/debug/injector" \
            cargo run -p sandblaster-cli --bin sifter -- "${frontend_args[@]}" -- "${injector_args[@]}"
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
