#!/usr/bin/env bash
# FR-IO-2 Fast DDS toolchain env: pins the pinned-source install prefix and the
# dylib path, then execs the given command (default: a shell). See
# docs/provenance.md for the toolchain pin and provenance.
set -euo pipefail

FASTDDS_PREFIX="${FASTDDS_PREFIX:-$HOME/gbt Dropbox/gbt/projects/fastdds/install}"
FASTDDSGEN="${FASTDDSGEN:-$HOME/gbt Dropbox/gbt/projects/fastdds/src/fastddsgen/scripts/fastddsgen}"

if [[ ! -d "$FASTDDS_PREFIX/lib" ]]; then
  echo "with-fastdds: install prefix not found: $FASTDDS_PREFIX" >&2
  exit 127
fi

# Warn only: run-only callers (harness binaries) never invoke fastddsgen.
if [[ ! -x "$FASTDDSGEN" ]]; then
  echo "with-fastdds: warning: fastddsgen not found/executable: $FASTDDSGEN" >&2
fi

export FASTDDS_PREFIX FASTDDSGEN
export DYLD_LIBRARY_PATH="$FASTDDS_PREFIX/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"

exec "${@:-$SHELL}"
