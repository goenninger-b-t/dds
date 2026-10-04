#!/usr/bin/env bash
# gate-quit-lint — Lisp code in src/ ends the process ONLY through dds.pal:exit-process (ADR 0121).
#
# WHY. dds.pal:exit-process runs the shutdown-hook chain (log-sink flush, durability store fsync, DARE secret
# wipe, SHMEM shm_unlink) under a watchdog, then a hard exit that waits for no other thread. Every other way
# out skips that chain, and one of them hangs: on AllegroCL, UIOP:QUIT calls EXCL:EXIT without :NO-UNWIND,
# which waits for every Lisp process to unwind, and a process parked in a foreign call never does. That is
# how the full AllegroCL suite hung at exit with 10 live threads until an outer timeout killed it.
#
# THE RULE. Outside src/dds-pal/ (the only place an implementation's own exit primitive may appear), no file
# under src/ may name: uiop:quit, uiop/image:quit, sb-ext:exit, sb-ext:quit, excl:exit, excl::exit or
# cl-user::quit — in code, a string or a comment — nor reach them indirectly through uiop:symbol-call or a
# CFFI foreign-funcall of exit / _exit. Prose that names the banned call invites it back, and a
# child-process form is a string, so strings must count too.
#
# The gate falsifies itself on every run before scanning: it plants each banned spelling in a scratch tree,
# requires the scan to find every one and to ignore near-misses, and requires a dds-pal/ file to be exempt.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Case-insensitive, because the reader is. The package-qualified spellings only: a bare (quit) or (exit) is
# not a portable call in any of our packages and would not compile without one of these packages in use.
QUIT_RE='(uiop|uiop/image|sb-ext|excl|cl-user)::?(quit|exit)([^a-z0-9*+-]|$)'
# The two indirect spellings: a symbol looked up at run time, (uiop:symbol-call :uiop :quit ...) or
# (uiop:symbol-call "UIOP" "QUIT" ...), and a foreign call to libc exit(3) / _exit(2) through CFFI.
INDIRECT_RE='symbol-call[^)]*[: "](quit|exit)([^a-z0-9*+-]|$)|foreign-funcall[^)]*"_?exit"'
BANNED_RE="$QUIT_RE|$INDIRECT_RE"

scan() {   # $1 = root directory; prints file:line: text for every banned token outside <root>/dds-pal/
  grep -rnEi --include='*.lisp' --include='*.asd' "$BANNED_RE" "$1" 2>/dev/null \
    | grep -v "^$1/dds-pal/" || true
}

# ---- 0. FALSIFICATION ----
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/src/dds-x" "$tmp/src/dds-pal"
cat > "$tmp/src/dds-x/canary.lisp" <<'EOF'
(defun a () (uiop:quit 1))
(defun b () (UIOP:QUIT 0))
(defun c () (sb-ext:exit :code 2 :abort t))
(defun d () (excl:exit 3 :no-unwind t))
(defun e () (excl::exit 4))
(defun f () "a child form string: (uiop:quit 0)")
;; a comment naming uiop/image:quit
(defun g () (sb-ext:quit))
(defun i () (uiop:symbol-call :uiop :quit 5))
(defun j () (uiop:symbol-call "UIOP" "QUIT" 6))
(defun k () (cffi:foreign-funcall "_exit" :int 7 :void))
(defun l () (cffi:foreign-funcall "exit" :int 8 :void))
;; must NOT count: dds.pal:exit-process, uiop:quit-ish, sb-ext:*exit-hooks*, excl:exit-foo
(defun h () (list 'dds.pal:exit-process 'uiop:quitter 'sb-ext:*exit-hooks* 'excl:exit-foo))
(defun m () (uiop:symbol-call :dds.pal :exit-process 0) (uiop:symbol-call :uiop :quitter))
(defun n () (cffi:foreign-funcall "exit_group_wrapper" :int 0 :void) (cffi:foreign-funcall "atexit" :pointer p :int))
EOF
cat > "$tmp/src/dds-pal/pal-x.lisp" <<'EOF'
(defun %hard-exit (code) (excl:exit code :no-unwind t :quiet t) (sb-ext:exit :code code :abort t))
EOF
hits="$(scan "$tmp/src" | sed -E 's#^[^:]*:([0-9]+):.*#\1#' | tr '\n' ' ')"
if [[ "$hits" != "1 2 3 4 5 6 7 8 9 10 11 12 " ]]; then
  echo "gate-quit-lint: FAIL — self-test: the scan must flag canary lines 1-12 exactly, skip lines 13-16 and" >&2
  echo "                exempt dds-pal/; got: '$hits'. The gate is BLIND or over-eager — a green run would" >&2
  echo "                prove nothing." >&2
  exit 1
fi

# ---- 1. THE SCAN ----
found="$(scan src)"
mapfile -t asds < <(ls ./*.asd 2>/dev/null)
if ((${#asds[@]})); then
  found+="$(grep -nEi "$BANNED_RE" "${asds[@]}" 2>/dev/null || true)"
fi
if [[ -n "$found" ]]; then
  printf '%s\n' "$found"
  echo "gate-quit-lint: FAIL — a process exit outside dds.pal:exit-process (ADR 0121). Call" >&2
  echo "                (dds.pal:exit-process CODE) instead; it runs the shutdown-hook chain and cannot hang." >&2
  exit 1
fi
echo "gate-quit-lint: PASS — no uiop:quit / implementation exit outside src/dds-pal/ (the gate is proven"
echo "                able to fail on 12 spellings, including a string, a comment, a run-time symbol lookup and
                a CFFI exit)."
