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

# The demo account and ingress key the suite connects with (provisioned by the
# containers' entrypoint); the readiness probe uses the same credentials.
SB_USER=t800
SB_KEY="${DEMO_DIR}/assets/ssh-keys/id_ed25519"

# How long to wait for the bastions to become fully usable before giving up
# (seconds).
WAIT_TIMEOUT=120

# ssh_ready <port> — return success if a real SSH exec on the bastion works:
# authenticate as the demo account and run the `info` command end to end. A
# bare TCP-connect (or even an SSH banner) is not enough: sshd starts accepting
# connections while the container's provisioning is still creating the demo
# account, and a connection in that window is closed before the forced command
# runs — the suite's first command then flakes with "Connection closed by".
# Only a successful exec proves the account, its key and the sb binary are all
# in place.
#
# No BatchMode here, on purpose: the bastion's sshd requires
# "publickey,keyboard-interactive" (the keyboard-interactive step is the PAM
# TOTP hook, which completes without prompting when the account has no TOTP),
# and BatchMode disables keyboard-interactive client-side, turning every probe
# into "Permission denied". Stdin comes from /dev/null instead so the probe
# can never hang waiting for input.
ssh_ready() {
    local port="$1"
    ssh -i "${SB_KEY}" \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -o LogLevel=ERROR \
        -p "${port}" "${SB_USER}@127.0.0.1" -- info >/dev/null 2>&1 </dev/null
}

# wait_for_ssh <port> — block until the bastion answers a real SSH exec or we
# hit the timeout. Fails closed (non-zero) so the caller can abort the run.
wait_for_ssh() {
    local port="$1"
    local waited=0
    until ssh_ready "${port}"; do
        if (( waited >= WAIT_TIMEOUT )); then
            echo "Timed out after ${WAIT_TIMEOUT}s waiting for a working SSH exec on 127.0.0.1:${port}" >&2
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

# The probe authenticates with the demo key, which ssh refuses to use when the
# checked-out file is group/world-readable.
chmod 600 "${SB_KEY}"

echo "Waiting for the bastions to answer a real SSH exec..."
wait_for_ssh "${SB1_PORT}"
wait_for_ssh "${SB2_PORT}"

echo "Running the e2e suite..."
# Run from the repo root, which is what tests/e2e.sh expects.
(cd "${REPO_ROOT}" && bash ./tests/e2e.sh)
