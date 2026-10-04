#!/usr/bin/env bash
# Runs the ADR 0119 ring-primitive A/B (bench/report/2026-10-03-shmem-lane-poison.md) under the given
# launcher, e.g.:  bench/shmem-lane-ab/run.sh ./scripts/with-sbcl.sh
# Both files are compile-file'd (same defun* policy as the system) into a temporary directory.
set -euo pipefail
LAUNCHER="${1:?usage: run.sh <./scripts/with-sbcl.sh|./scripts/with-allegro.sh>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
"$LAUNCHER" \
  --eval '(asdf:load-system :dds-xport)' \
  --eval "(load (compile-file \"$HERE/old-ring.lisp\" :output-file \"$OUT/old-ring.fasl\"))" \
  --eval "(load (compile-file \"$HERE/ab-bench.lisp\" :output-file \"$OUT/ab-bench.fasl\"))" \
  --eval '(uiop:quit 0)'
