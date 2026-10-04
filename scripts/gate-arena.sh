#!/usr/bin/env bash
# gate-arena — FR-PF-7's static-memory property, made checkable (ADR 0095).
#
# WHY THIS EXISTS. FR-PF-7 (MUST) says "all hot-path memory comes from the static, startup-allocated,
# non-GC'd arena sized by *static-arena-bytes*". Before ADR 0095 that was not true and nothing noticed:
# every production carve built its OWN arena sized to that one pool, so *static-arena-bytes* was never
# read outside tests, no component could answer "what has this process reserved?", and the operating
# contract's claim that `make mem` checks this was false — `make mem` measures the CODEC in isolation.
#
# So this gate asserts the property directly, and — per the standing rule that a green gate proves nothing
# until it has been seen to fail — IT FALSIFIES ITSELF ON EVERY RUN before asserting anything.
#
#   ARM 1  FALSIFICATION. Against a deliberately tiny budget, a carve that cannot fit MUST be refused
#          (NIL + :ARENA-EXHAUSTED, ADR 0064 — a status, never a condition, never a GC-heap fill-in).
#          If it succeeds, the budget is not being enforced and every assertion below is worthless.
#   ARM 2  THE BUDGET IS REAL. A live participant pair must charge the PROCESS arena — bytes-used > 0.
#          Before ADR 0095 this was always 0 in production, which is the whole finding.
#   ARM 3  TEARDOWN IS EXACT (ADR 0095 option (a), the owner's decision). A participant create/delete
#          cycle must be BUDGET-NEUTRAL: the process arena's bytes-used must return to where it started.
#          This is the assertion that would catch the leak option (a) exists to prevent — a shared arena
#          is bump-allocated with no way to return a carve, so without sub-arena teardown a long-running
#          process that churns participants eventually cannot carve at all.
#   ARM 4  HIGH-WATER < BUDGET, and reported, so "how close are we?" has an answer.
#   ARM 5  PRE-ALLOCATED, NOT LAZY (ADR 0095 slice 2), with its own falsification.
#   ARM 6  FIXED MODE NEVER GROWS (ADR 0125, owner decision D29). A process arena forced to :FIXED runs a
#          real participant pair: afterwards its budget, ceiling and growth count are exactly what init set
#          (budget = ceiling = *static-arena-bytes*, growths 0), and a carve one byte larger than what is left
#          is REFUSED with :ARENA-EXHAUSTED with the budget still unchanged. A :FIXED arena that grew even
#          once fails here.
#   ARM 7  GROWABLE MODE STOPS AT ITS CEILING (ADR 0102/0125). The CONTRAST to ARM 6: forced :GROWABLE with
#          a ceiling one chunk above the initial budget, a carve that fits inside the ceiling GROWS (proving
#          the arena could grow, so ARM 6's "did not grow" is the mode's doing), and a carve past the ceiling
#          is REFUSED with the budget stopped at, never above, the ceiling.
#   The startup arena report (mode and why) is printed, so the mode :AUTO chose on this host is on record.
#
# Usage: scripts/gate-arena.sh [LISP]   (default ./scripts/with-sbcl.sh; ./scripts/with-allegro.sh for alisp).
# The forms end through dds.pal:exit-process (ADR 0121), which both launchers support; the launchers already
# make the Lisp non-interactive (SBCL --non-interactive, AllegroCL -batch).
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lisp-cache-env.sh
LISP="${1:-./scripts/with-sbcl.sh}"

"$LISP" \
  --eval '(asdf:load-system :dds-bench)' \
  --eval '
(handler-case
 (let ((fail nil))
  (flet ((chk (ok fmt &rest args)
           (format t "~&gate-arena: ~a ~a~%" (if ok "ok  " "FAIL") (apply #'"'"'format nil fmt args))
           (unless ok (setf fail t))))

    ;; ARM 1 — FALSIFY FIRST. A 4 KiB budget must refuse a 256 KiB carve.
    ;; ADR 0102: the arena GROWS in chunks now, so pinning only the initial budget no longer proves a
    ;; refusal — growth would simply absorb the carve. The falsification must pin the CEILING.
    (format t "~&gate-arena: startup arena report (default :AUTO mode) ~s~%"
            (dds.core.arena:arena-report (dds.core.arena:process-arena)))
    (let ((dds.core.arena:*process-arena* nil)
          (dds.core.arena:*static-arena-bytes* 4096)
          (dds.core.arena:*static-arena-max-bytes* 4096))
      (let ((sub (dds.core.arena:make-sub-arena (dds.core.arena:process-arena))))
        (multiple-value-bind (pool status) (dds.core.arena:make-buffer-pool sub 65536 4)
          (chk (and (null pool) (eq status :arena-exhausted))
               "FALSIFICATION: a 256 KiB carve against a 4 KiB budget is refused (~a/~a)"
               (if pool "POOL" "nil") status))))

    ;; ARMS 2-4 — a real participant pair on its own domain, created and deleted twice.
    (let* ((arena (dds.core.arena:process-arena))
           (base  (dds.core.arena:arena-bytes-used arena))
           (peak  base))
      (dotimes (i 2)
        (let* ((dom (+ 231 i))
               (ts (dds.types:find-type-support "perf-data"))
               (pw (dds.dcps:create-participant :domain dom :autonomous t :advertise-address "127.0.0.1"))
               (pr (dds.dcps:create-participant :domain dom :autonomous t :advertise-address "127.0.0.1")))
          (unwind-protect
               (let* ((tw (dds.dcps:create-topic pw "PerfPing" "PerfData" ts))
                      (tr (dds.dcps:create-topic pr "PerfPing" "PerfData" ts))
                      (dw (dds.dcps:create-datawriter (dds.dcps:create-publisher pw) tw))
                      (dr (dds.dcps:create-datareader (dds.dcps:create-subscriber pr) tr)))
                 (loop repeat 200 until (and (plusp (dds.dcps:matched-count pw))
                                             (plusp (dds.dcps:matched-count pr)))
                       do (sleep 0.05))
                 (dotimes (k 200)
                   (dds.dcps:write-sample dw (dds.bench::make-perf-data :id 1 :data (dds.bench::%perf-payload 0)))
                   (let ((got (dds.dcps:take-samples dr)))
                     (when (listp got) (dds.dcps:return-loan dr got))))
                 (setf peak (max peak (dds.core.arena:arena-bytes-used arena)))
                 (when (zerop i)
                   (chk (> (dds.core.arena:arena-bytes-used arena) base)
                        "THE BUDGET IS REAL: a live participant pair charges the process arena (~d B used)"
                        (dds.core.arena:arena-bytes-used arena))))
            (progn (dds.dcps:delete-participant pw) (dds.dcps:delete-participant pr)))))
      (chk (= (dds.core.arena:arena-bytes-used arena) base)
           "TEARDOWN IS EXACT: 2 create/delete cycles are budget-neutral (~d B before, ~d B after)"
           base (dds.core.arena:arena-bytes-used arena))
      (chk (< peak (dds.core.arena:arena-byte-budget arena))
           "HIGH-WATER < BUDGET: peak ~d B of ~d B (~,2f %)"
           peak (dds.core.arena:arena-byte-budget arena)
           (/ (* 100.0 peak) (max 1 (dds.core.arena:arena-byte-budget arena)))))

    ;; ARM 5 — PRE-ALLOCATED, NOT LAZY (ADR 0095 slice 2). start-node must carve what the node CONFIGURATION
    ;; already determines it will use, BEFORE the first sample. Asserted on the slot directly, not on a
    ;; timing proxy: the rx-store pool is the unconditional one (every copy-path receive draws from it), so
    ;; if it is still NIL after start-node the carve is still landing on the first sample.
    ;; FALSIFIES ITSELF: with *rx-store-pool-enabled* NIL the pool must be ABSENT, proving the assertion
    ;; below is reading the real slot and not something that is trivially always set.
    (let ((node (dds.disc:make-disc-node :domain 239 :host "127.0.0.1" :port 0 :multicast nil)))
      (unwind-protect
           (let ((dds.disc:*rx-store-pool-enabled* nil))
             (dds.disc:start-node node)
             (chk (null (dds.disc::disc-node-rx-store-pool node))
                  "FALSIFICATION: with the RX store pool DISABLED, start-node carves nothing"))
        (dds.disc:stop-node node)))
    (let ((node (dds.disc:make-disc-node :domain 240 :host "127.0.0.1" :port 0 :multicast nil)))
      (unwind-protect
           (progn
             (dds.disc:start-node node)
             (chk (not (null (dds.disc::disc-node-rx-store-pool node)))
                  "PRE-ALLOCATED: start-node carved the RX store pool — no first-sample carve (slice 2)"))
        (dds.disc:stop-node node)))

    ;; ARM 6 — FIXED MODE NEVER GROWS (ADR 0125), under a real participant-pair workload.
    (let* ((dds.core.arena:*process-arena* nil)
           (dds.core.arena:*static-arena-mode* :fixed)
           (arena (dds.core.arena:process-arena))
           (b0 (dds.core.arena:arena-byte-budget arena)))
      (format t "~&gate-arena: forced :FIXED arena report ~s~%" (dds.core.arena:arena-report arena))
      (let* ((dom 231)   ; reused: ARMS 2-4 deleted their participants; 233+ overflows the RTPS port range
             (ts (dds.types:find-type-support "perf-data"))
             (pw (dds.dcps:create-participant :domain dom :autonomous t :advertise-address "127.0.0.1"))
             (pr (dds.dcps:create-participant :domain dom :autonomous t :advertise-address "127.0.0.1")))
        (unwind-protect
             (let* ((tw (dds.dcps:create-topic pw "PerfPing" "PerfData" ts))
                    (tr (dds.dcps:create-topic pr "PerfPing" "PerfData" ts))
                    (dw (dds.dcps:create-datawriter (dds.dcps:create-publisher pw) tw))
                    (dr (dds.dcps:create-datareader (dds.dcps:create-subscriber pr) tr)))
               (loop repeat 200 until (and (plusp (dds.dcps:matched-count pw))
                                           (plusp (dds.dcps:matched-count pr)))
                     do (sleep 0.05))
               (dotimes (k 200)
                 (dds.dcps:write-sample dw (dds.bench::make-perf-data :id 1 :data (dds.bench::%perf-payload 0)))
                 (let ((got (dds.dcps:take-samples dr)))
                   (when (listp got) (dds.dcps:return-loan dr got))))
               (chk (and (eq (dds.core.arena:arena-mode arena) :fixed)
                         (plusp (dds.core.arena:arena-bytes-used arena)))
                    "FIXED: the forced :FIXED arena is the one the workload charged (~d B used)"
                    (dds.core.arena:arena-bytes-used arena))
               ;; one byte more than what is left: the smallest carve that would need growth
               (let ((over (1+ (- (dds.core.arena:arena-byte-budget arena)
                                  (dds.core.arena:arena-bytes-used arena)))))
                 (multiple-value-bind (pool status)
                     (dds.core.arena:make-buffer-pool (dds.core.arena:make-sub-arena arena) over 1)
                   (chk (and (null pool) (eq status :arena-exhausted))
                        "FIXED: a carve of ~d B (1 B past what is left) is REFUSED, not grown into (~a/~a)"
                        over (if pool "POOL" "nil") status))))
          (progn (dds.dcps:delete-participant pw) (dds.dcps:delete-participant pr))))
      (chk (and (= (dds.core.arena:arena-byte-budget arena) b0)
                (= (dds.core.arena:arena-max-bytes arena) b0)
                (zerop (dds.core.arena:arena-growths arena)))
           "FIXED NEVER GROWS: budget ~d B = initial ~d B = ceiling ~d B, growths ~d"
           (dds.core.arena:arena-byte-budget arena) b0 (dds.core.arena:arena-max-bytes arena)
           (dds.core.arena:arena-growths arena)))

    ;; ARM 7 — GROWABLE MODE STOPS AT ITS CEILING: the contrast that makes ARM 6 falsifiable.
    (let* ((mib (* 1024 1024))
           (dds.core.arena:*process-arena* nil)
           (dds.core.arena:*static-arena-mode* :growable)
           (dds.core.arena:*static-arena-bytes* mib)
           (dds.core.arena:*static-arena-growth-bytes* mib)
           (dds.core.arena:*static-arena-max-bytes* (* 2 mib))
           (arena (dds.core.arena:process-arena)))
      (multiple-value-bind (pool status) (dds.core.arena:make-buffer-pool arena (* 3 (/ mib 2)) 1)
        (chk (and pool (null status) (= 1 (dds.core.arena:arena-growths arena)))
             "GROWABLE CONTRAST: a 1.5 MiB carve over a 1 MiB budget GROWS (~a/~a, growths ~d)"
             (if pool "POOL" "nil") status (dds.core.arena:arena-growths arena)))
      (multiple-value-bind (pool status) (dds.core.arena:make-buffer-pool arena mib 1)
        (chk (and (null pool) (eq status :arena-exhausted)
                  (<= (dds.core.arena:arena-byte-budget arena) (dds.core.arena:arena-max-bytes arena)))
             "GROWABLE CEILING: a carve past the 2 MiB ceiling is REFUSED (~a/~a), budget ~d B <= max ~d B"
             (if pool "POOL" "nil") status (dds.core.arena:arena-byte-budget arena)
             (dds.core.arena:arena-max-bytes arena)))
      (dds.core.arena:teardown-arena arena)))

  (if fail
      (progn (format t "~&gate-arena: FAIL~%") (dds.pal:exit-process 1))
      (progn (format t "~&gate-arena: PASS — the process budget is enforced, charged and returned (ADR 0095), and the fixed / growable modes hold (ADR 0125).~%")
             (dds.pal:exit-process 0))))
 (error (e) (format t "~&gate-arena: FAIL — ~a~%" e) (dds.pal:exit-process 1)))'
