#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="${SANDBLASTER_X86_IMAGE:-sandblaster-x86:dev}"
PLATFORM="${SANDBLASTER_X86_PLATFORM:-linux/amd64}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

usage() {
    cat <<USAGE
Usage: $(basename "$0") <build|test|smoke|exec-smoke|shell> [args...]

Commands:
  build         Build the amd64 Linux Docker image.
  test          Run cargo test --workspace inside the amd64 container.
  smoke         Start the Linux/x86 injector backend without executing probes.
  exec-smoke    Run a bounded generated-code probe under amd64 emulation.
  shell         Open an interactive amd64 Linux shell in the mounted repo.

Environment:
  SANDBLASTER_X86_IMAGE     Image tag to build/run (default: sandblaster-x86:dev)
  SANDBLASTER_X86_PLATFORM  Docker platform (default: linux/amd64)
USAGE
}

docker_run() {
    docker run --rm \
        --platform "${PLATFORM}" \
        --volume "${REPO_ROOT}:/work" \
        --volume sandblaster-x86-cargo:/cargo \
        --volume sandblaster-x86-target:/target \
        --env CARGO_INCREMENTAL=0 \
        --env CARGO_TARGET_DIR=/target \
        --env CARGO_PROFILE_DEV_DEBUG=0 \
        --env CARGO_PROFILE_TEST_DEBUG=0 \
        --workdir /work \
        "$@"
}

command="${1:-}"
if [[ $# -gt 0 ]]; then
    shift
fi

case "${command}" in
    build)
        docker build \
            --platform "${PLATFORM}" \
            --tag "${IMAGE_NAME}" \
            --file "${REPO_ROOT}/docker/x86_64/Dockerfile" \
            "${REPO_ROOT}" \
            "$@"
        ;;
    test)
        docker_run "${IMAGE_NAME}" cargo test --workspace "$@"
        ;;
    smoke)
        docker_run "${IMAGE_NAME}" timeout 20s cargo run -p sandblaster-injector --bin injector -- -T -d "$@"
        ;;
    exec-smoke)
        docker_run "${IMAGE_NAME}" timeout 20s cargo run -p sandblaster-injector --bin injector -- -T -b -B 1 -i 90 -e 91 "$@"
        ;;
    shell)
        docker_run --interactive --tty "${IMAGE_NAME}" /bin/bash "$@"
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
