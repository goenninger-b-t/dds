#!/usr/bin/env bash
# linux-repro — run this repo on REAL Linux x86_64 from the macOS dev box, in one command.
#
# WHY THIS EXISTS. The dev box is macOS/arm64; CI is Linux x86_64. A whole class of defect here is
# INVISIBLE on macOS and reproduces on Linux every time:
#
#   * uninitialized memory that only shows up on the wire;
#   * a stack that cannot shut down under Linux thread scheduling;
#   * a discovery window wide enough there to drop the first sample of every pairing (ADR 0096);
#   * the arm64-Linux compile failure nobody knew about (see PLATFORM below).
#
# Every one of those was found by Linux and none by macOS. Before this script the only way to reach
# the CI platform was to push and wait; now it is ~90 s for one focused test and ~7 min for the suite.
#
# USAGE
#   ./scripts/linux-repro.sh                                  # the full test suite (exit != 0 on any failure)
#   ./scripts/linux-repro.sh --eval '(dds.tests::run-x-test)' # arbitrary forms, in the SAME process as the load
#   ./scripts/linux-repro.sh --shell                          # an interactive shell in the container
#   ./scripts/linux-repro.sh --build-only                     # (re)build the image and stop
#
# ENV OVERRIDES
#   IMAGE=neodds-linux-amd64   the image tag
#   PLATFORM=linux/amd64       the docker platform (see the trap below — do not change casually)
#   SHM_SIZE=512m              container /dev/shm (the ZC pools need more than docker's 64 MB default)
#   CACHE_VOLUME=neodds-linux-fasl-cache   named volume holding the fasl cache ("" disables it)
#   REBUILD=1                  force a docker build even if the image exists
#
# THE FIVE TRAPS THIS SCRIPT ENCODES — every one of them cost a wasted run before it existed:
#
#   1. PIN --platform linux/amd64. Docker on Apple silicon defaults to linux/arm64, which is NOT what
#      CI runs, and the two fail COMPLETELY DIFFERENTLY: on aarch64 the build dies in the PAL with an
#      SBCL INTERNAL BUG (`full call to (SB-EXT:CAS SB-SYS:SAP-REF-64)` in CAS-SAP-U64) before a single
#      test runs. An unpinned run reproduces a different platform's problems than the one you are
#      debugging. (That arm64-Linux failure is real and unscoped — NFR-PORT is Linux-first/64-bit and
#      Graviton/Ampere are targets — but it is not what this harness is for.)
#   2. THE LOAD AND THE RUN MUST BE ONE PROCESS. Each `docker run` is a fresh container, so a preload
#      from an earlier invocation is gone and a bare `asdf:load-system` dies with
#      `Component "static-vectors" not found`. CI gets away with a separate preload STEP only because
#      the runner filesystem persists between steps. Hence the single --eval chain below.
#   3. --shm-size. Docker's default /dev/shm is 64 MB; several Zero-Copy pools plus the SHMEM transport
#      segments do not fit, and the failure looks like an unrelated transport error.
#   4. THE FASL CACHE MUST NOT LAND IN THE REPO. This tree lives in a synced Dropbox folder and the
#      cache is hundreds of megabytes of churning build output. It goes to a named docker volume
#      (fast on repeat runs) or, with CACHE_VOLUME="", to the container's throwaway layer.
#   5. amd64 runs under emulation and is SLOW (full suite ~7 min). Run it in the background.
#
# Docker Desktop may simply not be running; that is the most common failure and it is reported here
# rather than as an opaque socket error.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${IMAGE:-neodds-linux-amd64}"
PLATFORM="${PLATFORM:-linux/amd64}"
SHM_SIZE="${SHM_SIZE:-512m}"
CACHE_VOLUME="${CACHE_VOLUME-neodds-linux-fasl-cache}"

if ! command -v docker >/dev/null 2>&1; then
  echo "linux-repro: docker not found on PATH" >&2
  exit 127
fi
if ! docker info >/dev/null 2>&1; then
  echo "linux-repro: the docker daemon is not reachable — start Docker Desktop (open -a Docker) and retry" >&2
  exit 1
fi

if [ "${1:-}" = "--build-only" ]; then REBUILD=1; shift; BUILD_ONLY=1; fi

if [ -n "${REBUILD:-}" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "linux-repro: building $IMAGE ($PLATFORM) — a few minutes the first time" >&2
  docker build --platform "$PLATFORM" -t "$IMAGE" -f "${REPO}/docker/linux-amd64.Dockerfile" "${REPO}/docker"
fi
if [ -n "${BUILD_ONLY:-}" ]; then echo "linux-repro: $IMAGE ready ($PLATFORM)"; exit 0; fi

# Trap 4: the fasl cache goes to a named volume, never into the bind-mounted (Dropbox-synced) repo.
# ASDF's own staleness check keeps it honest across source edits; `make linux-clean-cache` drops it.
CACHE_ARGS=()
if [ -n "$CACHE_VOLUME" ]; then
  CACHE_ARGS=(-v "${CACHE_VOLUME}:/lispcache")
fi

# The default payload: load, run every test, and exit non-zero if any failed (run-all-tests signals).
# Trap 2 — the ql:quickload and the forms are ONE --eval chain in ONE process.
if [ "$#" -eq 0 ]; then
  set -- --eval '(handler-case (progn (dds.tests:run-all-tests) (uiop:quit 0)) (error (e) (format t "~&SUITE FAILED: ~a~%" e) (uiop:quit 1)))'
fi

if [ "${1:-}" = "--shell" ]; then
  exec docker run --rm -it --platform "$PLATFORM" --shm-size="$SHM_SIZE" \
    -v "${REPO}:/src" "${CACHE_ARGS[@]}" -w /src -e XDG_CACHE_HOME=/lispcache \
    "$IMAGE" bash
fi

exec docker run --rm --platform "$PLATFORM" --shm-size="$SHM_SIZE" \
  -v "${REPO}:/src" "${CACHE_ARGS[@]}" -w /src -e XDG_CACHE_HOME=/lispcache \
  "$IMAGE" ./scripts/with-sbcl.sh --eval '(ql:quickload :dds-tests :silent t)' "$@"
