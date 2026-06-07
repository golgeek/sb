#!/usr/bin/env bash
#
# e2e-local.sh — one-command local runner for the end-to-end suite.
#
# The e2e suite is split across two working directories: the demo stack must be
# brought up from demo/ (docker-compose.yml mounts ${PWD}/assets/...), while
# tests/e2e.sh must run from the repo root (it references $(pwd)/demo/... and
# SCPs ./docs). CI handles that split by hand; this script does it for you so a
# local run is a single command, and it always tears the stack down afterwards.
#
# Usage:
#   tests/e2e-local.sh              # build, up, wait, test, then down
#   KEEP_STACK=1 tests/e2e-local.sh # leave the stack running for debugging
#   NO_BUILD=1   tests/e2e-local.sh # skip the image rebuild (faster reruns)
#
# Exit code is the e2e suite's own exit code; teardown never masks it.

set -euo pipefail

# Resolve the repo root from this script's own location so the script works no
# matter where it is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEMO_DIR="${REPO_ROOT}/demo"

# The two bastions the suite talks to (host TCP ports published by the stack).
SB1_PORT=22001
SB2_PORT=22002

# How long to wait for the bastions' SSH ports to start accepting connections
# before giving up (seconds).
WAIT_TIMEOUT=120

# tcp_open <port> — return success if a TCP connection to 127.0.0.1:<port>
# succeeds. Uses bash's /dev/tcp so we don't depend on nc(1) being installed.
tcp_open() {
    local port="$1"
    # The subshell + redirect either connects or fails; suppress its output.
    (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null
}

# wait_for_port <port> — block until the port accepts connections or we hit the
# timeout. Fails closed (non-zero) so the caller can abort the run.
wait_for_port() {
    local port="$1"
    local waited=0
    until tcp_open "${port}"; do
        if (( waited >= WAIT_TIMEOUT )); then
            echo "Timed out after ${WAIT_TIMEOUT}s waiting for 127.0.0.1:${port}" >&2
            return 1
        fi
        sleep 2
        (( waited += 2 ))
    done
}

# teardown — bring the stack down unless the user asked to keep it. Registered
# as an EXIT trap so it runs on success, failure, or interrupt. It preserves the
# script's exit status: we capture $? first and re-exit with it at the end.
teardown() {
    local status=$?
    if [[ "${KEEP_STACK:-0}" == "1" ]]; then
        echo "KEEP_STACK=1 set — leaving the demo stack running."
        echo "Tear it down later with: (cd '${DEMO_DIR}' && docker compose down)"
    else
        echo "Tearing down the demo stack..."
        # Best-effort: don't let a teardown hiccup overwrite the real status.
        (cd "${DEMO_DIR}" && docker compose down) || true
    fi
    exit "${status}"
}
trap teardown EXIT

echo "Bringing up the demo stack (this builds images on first run)..."
build_flag="--build"
[[ "${NO_BUILD:-0}" == "1" ]] && build_flag=""
# shellcheck disable=SC2086  # build_flag is intentionally word-split (may be empty).
(cd "${DEMO_DIR}" && docker compose up -d ${build_flag})

echo "Waiting for the bastions to accept SSH connections..."
wait_for_port "${SB1_PORT}"
wait_for_port "${SB2_PORT}"

echo "Running the e2e suite..."
# Run from the repo root, which is what tests/e2e.sh expects.
(cd "${REPO_ROOT}" && bash ./tests/e2e.sh)
