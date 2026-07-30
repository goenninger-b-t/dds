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
#
# SBCL only: it is the implementation whose static allocation the ratchet is measured on.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/lisp-cache-env.sh

./scripts/with-sbcl.sh --non-interactive \
  --eval '(asdf:load-system :dds-bench)' \
  --eval '
(handler-case
 (let ((fail nil))
  (flet ((chk (ok fmt &rest args)
           (format t "~&gate-arena: ~a ~a~%" (if ok "ok  " "FAIL") (apply #'"'"'format nil fmt args))
           (unless ok (setf fail t))))

    ;; ARM 1 — FALSIFY FIRST. A 4 KiB budget must refuse a 256 KiB carve.
    (let ((dds.core.arena:*process-arena* nil)
          (dds.core.arena:*static-arena-bytes* 4096))
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
        (dds.disc:stop-node node))))

  (if fail
      (progn (format t "~&gate-arena: FAIL~%") (uiop:quit 1))
      (progn (format t "~&gate-arena: PASS — the process budget is enforced, charged and returned (ADR 0095).~%")
             (uiop:quit 0))))
 (error (e) (format t "~&gate-arena: FAIL — ~a~%" e) (uiop:quit 1)))'
