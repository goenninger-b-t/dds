#!/usr/bin/env bash
# The ASDF fasl-cache root for this project. Sourced by every Lisp entry point
# (scripts/with-sbcl.sh, scripts/with-clasp.sh, scripts/gate-build.sh).
#
# WHY THIS EXISTS: ASDF's default output-translations put every project's fasls in ONE shared
# root, ~/.cache/common-lisp/, keyed only by implementation+version. Two things follow, and both
# have bitten this repo:
#
#   1. gate-build.sh deliberately does `rm -rf "$CACHE"/*` — a clean-cache rebuild is the whole
#      point of that gate (a stale fasl let an uncompilable tree report 563/563 for two days).
#      Against the shared root that wipes the fasls of every OTHER project's live Lisp too,
#      mid-run, producing a failure in an unrelated project that looks like that project's bug.
#   2. Two builds sharing one root write the same fasl paths, so neither result is trustworthy.
#
# A private root fixes both, and is a STRONGER clean-cache guarantee than the wipe: nothing else
# writes here, so what the gate clears is all there was.
#
# It MUST be one definition. If the gate wiped one root while the Lisp wrote another, the gate
# would quietly stop being a clean-cache gate while still reporting PASS — the exact class of
# permanently-green gate this repo has been burned by twice.
#
# Deliberately OUTSIDE the repo: this tree lives in a synced Dropbox folder, and a fasl cache is
# hundreds of megabytes of churning build output that must never be synced.
#
# Override by exporting XDG_CACHE_HOME yourself; that wins.
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HOME/.cache/hofvarpnir}"
