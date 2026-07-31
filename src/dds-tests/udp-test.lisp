(in-package #:dds.tests)

;;; Native UDPv4 PAL loopback (FR-XPORT-1): bind a receiver, send a datagram from
;;; a second socket to 127.0.0.1:<rx-port>, receive it, verify the octets. Uses
;;; each implementation's own sb-bsd-sockets; no portability library.

(defun* run-udp-loopback-test ()
    (function () t)
  "Test: the UDPv4 PAL sends and receives a datagram over loopback — under BOTH send mechanisms.

   THIS TEST IS THE FALSIFIER FOR THE struct sockaddr_in LAYOUT (ADR 0065) AND FOR THE RAW recvfrom(2)
   PATH (ADR 0066). The raw arm builds the destination address in our own foreign block and calls
   sendto(2)/recvfrom(2) directly; the NIL arm takes the sb-bsd-sockets SOCKET-SEND / SOCKET-RECEIVE
   path. The sockaddr_in layouts differ between Darwin and Linux in their first two octets, and getting
   them wrong is not a crash — the kernel rejects the address family and the datagram silently goes
   nowhere. Asserting DELIVERY under the raw arm is what turns that into a loud, platform-specific
   failure; CI/Linux is the oracle for the non-Darwin branch, which macOS cannot see.

   Runs on the test runner's own thread, which the PAL did not spawn, so *THREAD-SOCKADDR* is NIL and
   this exercises UDP-SEND-TO's WITH-FOREIGN-OBJECT fallback; the per-thread fast path is exercised by
   every integration test (a receiver thread answers each HEARTBEAT with an ACKNACK)."
  (let ((rx (dds.pal:udp-open :host "127.0.0.1" :port 0)))
    (unwind-protect
        (let ((tx (dds.pal:udp-open :host "127.0.0.1" :port 0))
              ;; PAL-static both ways: the kernel reads OUT and writes IN by raw pointer (NFR-MEM).
              (out (dds.pal:alloc-static 4))
              (in (dds.pal:alloc-static 16)))
          (replace out #(#xde #xad #xbe #xef))
          (unwind-protect
              (let ((port (dds.pal:udp-local-port rx)))
                (dolist (raw '(t nil))
                  (let ((dds.pal:*udp-raw-sendto* raw)
                        (dds.pal:*udp-raw-recvfrom* raw))
                    (fill in 0)
                    (dds.pal:udp-send-to tx out 4 "127.0.0.1" port)
                    (sleep 0.2)
                    (multiple-value-bind (n status) (dds.pal:udp-recv rx in 4)
                      (declare (ignore status))
                      (%check (if raw :udp-loopback-raw-syscalls :udp-loopback)
                              (and (= n 4) (= (aref in 0) #xde) (= (aref in 1) #xad)
                                   (= (aref in 2) #xbe) (= (aref in 3) #xef))
                              (format nil "UDP loopback datagram round-trip (raw syscalls ~a)"
                                      raw))))))
            (dds.pal:free-static out)
            (dds.pal:free-static in)
            (dds.pal:udp-close tx)))
      (dds.pal:udp-close rx))
    t))

;;; Bounded teardown (ADR 0092). Every teardown wait in the stack is bounded and reports where it
;;; expired; this is the falsifier for that work — each leg below either hangs forever or reports a
;;; false positive if its bound or its gate is removed.

(defun* run-arena-scratch-test ()
    (function () (eql t))
  "ADR 0095 slice 3: a node's LONG-LIVED receive/TX scratch comes from its SUB-ARENA, not bare alloc-static.

   THE BYPASS THIS PINS. Before slice 3 the three TX buffers (2 x *max-datagram-bytes* + the metatraffic
   payload = ~128 KiB) and each receiver thread's 64 KiB datagram buffer (~192 KiB for three threads) were
   allocated by dds.pal:alloc-static directly. That put ~328 KB per node OUTSIDE *static-arena-bytes*, so
   FR-PF-7's 'all hot-path memory comes from the static arena' was false for its single largest consumer —
   and a budget that cannot see the biggest allocation bounds nothing.

   Asserted as a DELTA on the PROCESS arena across one node's lifetime, because that is the quantity FR-PF-7
   is about, plus the ownership flag itself so a future change that silently reverts to alloc-static is
   caught by name rather than by an arithmetic coincidence. The RETURN half matters as much as the charge:
   an arena-backed buffer must NOT also be free-static'd at stop-node (that would be a double free of static
   memory), and it must not leak (the charge must come back)."
  (let* ((arena  (dds.core.arena:process-arena))
         (before (dds.core.arena:arena-bytes-used arena))
         (node   (dds.disc:make-disc-node :domain 243 :host "127.0.0.1" :port 0 :multicast nil)))
    (unwind-protect
         (let ((charged (- (dds.core.arena:arena-bytes-used arena) before))
               (tx-floor (+ (* 2 dds.disc::*max-datagram-bytes*) dds.disc::*metatraffic-payload-bytes*)))
           (%check :arena-scratch-backed (dds.disc::disc-node-scratch-arena-backed node)
                   "the node's TX scratch must be ARENA-BACKED, not bare alloc-static")
           (%check :arena-scratch-charged (>= charged tx-floor)
                   (format nil "creating a node must CHARGE the process arena for its TX scratch (~d B charged, ~d B expected floor)"
                           charged tx-floor)))
      (dds.disc:stop-node node))
    (%check :arena-scratch-returned (= (dds.core.arena:arena-bytes-used arena) before)
            (format nil "stop-node must RETURN the arena-backed scratch (~d B before, ~d B after)"
                    before (dds.core.arena:arena-bytes-used arena))))
  t)

(defun* run-arena-growth-test ()
    (function () (eql t))
  "ADR 0102 (owner requirement 2026-07-31): the arena grows in CONFIGURABLE CHUNKS up to a CONFIGURABLE MAX.

   WHY GROWTH IS SAFE HERE, and would not be everywhere: the arena is ACCOUNTING, not a slab. Every buffer is
   its own dds.pal:alloc-static region and the arena only tracks budget-vs-used, so raising the budget
   allocates nothing, moves nothing, and cannot invalidate an address an earlier carve already handed out.
   The same operation on a bump allocator over one contiguous block would be a use-after-free waiting to
   happen — which is why this is written against the BUDGET and never against a region.

   Four arms, each pinning one half of the requirement:
     1 GROWS      — a carve too big for the INITIAL budget but within MAX succeeds, and the budget rose.
     2 CEILING    — the same carve with MAX below it is REFUSED, and the budget stopped AT max (it grew as
                    far as it was allowed and no further). Without this arm growth would be unbounded and
                    'configurable max' would mean nothing.
     3 DISABLABLE — chunk 0 restores the exact pre-ADR-0102 fixed-ceiling behaviour: refused, budget
                    untouched, zero growths. A configuration, not an error.
     4 WHOLE CHUNKS — a carve just over the budget grows by a FULL chunk, not by the exact shortfall.
                    Exact-fit growth would make every later carve another growth step, so the budget would
                    creep up one allocation at a time and the ceiling would stop being an operating signal."
  (let ((mib (* 1024 1024)))
    ;; 1 — GROWS
    (let ((dds.core.arena:*process-arena* nil)
          (dds.core.arena:*static-arena-bytes* 4096)
          (dds.core.arena:*static-arena-growth-bytes* mib)
          (dds.core.arena:*static-arena-max-bytes* (* 8 mib)))
      (let ((a (dds.core.arena:process-arena)))
        (multiple-value-bind (pool status) (dds.core.arena:make-buffer-pool a 65536 4)
          (%check :arena-grow-succeeds (and pool (null status))
                  (format nil "a carve over the INITIAL budget but under MAX must succeed (got ~a/~a)"
                          (if pool "pool" "nil") status))
          (%check :arena-grow-budget-rose (> (dds.core.arena:arena-byte-budget a) 4096)
                  "the budget must have GROWN to accommodate it")
          (%check :arena-grow-counted (plusp (dds.core.arena:arena-growths a))
                  "the growth must be COUNTED, so it is observable rather than silent"))))
    ;; 2 — CEILING
    (let ((dds.core.arena:*process-arena* nil)
          (dds.core.arena:*static-arena-bytes* 4096)
          (dds.core.arena:*static-arena-growth-bytes* mib)
          (dds.core.arena:*static-arena-max-bytes* 8192))
      (let ((a (dds.core.arena:process-arena)))
        (multiple-value-bind (pool status) (dds.core.arena:make-buffer-pool a 65536 4)
          (%check :arena-grow-ceiling (and (null pool) (eq status :arena-exhausted))
                  (format nil "growth must STOP at MAX and refuse (got ~a/~a)"
                          (if pool "pool" "nil") status))
          (%check :arena-grow-stops-at-max (<= (dds.core.arena:arena-byte-budget a)
                                               (dds.core.arena:arena-max-bytes a))
                  "the budget must never exceed the configured MAX"))))
    ;; 3 — DISABLABLE
    (let ((dds.core.arena:*process-arena* nil)
          (dds.core.arena:*static-arena-bytes* 4096)
          (dds.core.arena:*static-arena-growth-bytes* 0)
          (dds.core.arena:*static-arena-max-bytes* (* 8 mib)))
      (let ((a (dds.core.arena:process-arena)))
        (multiple-value-bind (pool status) (dds.core.arena:make-buffer-pool a 65536 4)
          (%check :arena-grow-disabled (and (null pool) (eq status :arena-exhausted)
                                            (= 4096 (dds.core.arena:arena-byte-budget a))
                                            (zerop (dds.core.arena:arena-growths a)))
                  "chunk 0 must restore the fixed-ceiling behaviour exactly (refused, budget untouched)"))))
    ;; 4 — WHOLE CHUNKS
    (let ((dds.core.arena:*process-arena* nil)
          (dds.core.arena:*static-arena-bytes* 4096)
          (dds.core.arena:*static-arena-growth-bytes* mib)
          (dds.core.arena:*static-arena-max-bytes* (* 64 mib)))
      (let ((a (dds.core.arena:process-arena)))
        (dds.core.arena:make-buffer-pool a 8192 1)
        (%check :arena-grow-whole-chunks (= (dds.core.arena:arena-byte-budget a) (+ 4096 mib))
                (format nil "growth must take a WHOLE chunk, not the exact shortfall (budget ~a, expected ~a)"
                        (dds.core.arena:arena-byte-budget a) (+ 4096 mib))))))
  t)

(defun* run-arena-exhaustion-test ()
    (function () (eql t))
  "ADR 0095 slice 4: *static-arena-bytes* is a REAL ceiling, exercised END TO END with a budget deliberately
   too small to carve anything.

   WHAT THIS PINS. FR-PF-7 / NFR-MEM require arena exhaustion to be an ORDINARY, EXPECTED outcome — a status
   the stack degrades on, never a condition, never a crash, and never a silent claim of a zero it did not
   achieve. Every %ensure-*-pool already returns NIL + :ARENA-EXHAUSTED (gate-arena ARM 1 proves the refusal
   in isolation); what was never checked is that a WHOLE NODE still behaves correctly when EVERY carve is
   refused at once — which is the only form of the question an operator ever meets.

   So: a node is created and started against a 4 KiB process budget, so every carve — the pre-allocated TX
   scratch (slice 3), the RX store pool (slice 2), the receiver's datagram buffer — is refused. It asserts
   the node still STARTS, still STOPS cleanly, and reports its scratch as NOT arena-backed, i.e. it took the
   documented alloc-static fallback rather than failing to come up.

   ⚠️ WHAT IT DELIBERATELY DOES NOT ASSERT: that exhaustion produces RESOURCE_LIMITS on the data path. It
   does not, today — the pools degrade to allocating fallbacks that each docstring defends as 'correct,
   byte-identical wire'. That is a DIVERGENCE FROM ADR 0095 slice 4's wording ('the engine maps it to
   RESOURCE_LIMITS') and from the operating contract's 'never a silent GC-heap fallback', and it is recorded
   as such rather than papered over by a test that asserts only what the code already does."
  ;; ADR 0102: pin the CEILING as well as the initial budget — the arena grows in chunks now, so a small
  ;; *static-arena-bytes* alone no longer exhausts anything; growth would absorb every carve and this test
  ;; would silently stop testing exhaustion at all.
  (let ((dds.core.arena:*process-arena* nil)
        (dds.core.arena:*static-arena-bytes* 4096)
        (dds.core.arena:*static-arena-max-bytes* 4096))
    (let ((node (dds.disc:make-disc-node :domain 244 :host "127.0.0.1" :port 0 :multicast nil)))
      (%check :arena-exh-node-created (not (null node))
              "a node must still be CREATED when the arena budget refuses every carve")
      (%check :arena-exh-scratch-fallback (not (dds.disc::disc-node-scratch-arena-backed node))
              "with the budget exhausted the TX scratch must take the alloc-static FALLBACK, not claim to be arena-backed")
      (dds.disc:start-node node)
      (%check :arena-exh-started (not (null (dds.disc::disc-node-rx-thread node)))
              "the node must still START (a receiver thread) with every carve refused")
      (%check :arena-exh-no-rx-store (null (dds.disc::disc-node-rx-store-pool node))
              "the RX store pool must be ABSENT (refused), not silently carved outside the budget")
      (%check :arena-exh-stopped (eq t (dds.disc:stop-node node))
              "the node must still STOP cleanly with every carve refused (no double free of a buffer it never owned)")))
  t)

(defun* run-teardown-deadline-test ()
    (function () t)
  "Test: every teardown wait is BOUNDED and REPORTED — and reports NOTHING when the teardown is clean.

   (1) NO FALSE POSITIVE. A thread that exits promptly is joined without touching the report. A bound
       that counted every join would make the counter worthless as a defect signal.
   (2) THE BOUND FIRES. A thread that never exits yields (values NIL :TIMEOUT) instead of blocking, and
       is counted under ITS OWN site keyword — the report must say WHICH wait failed, not merely that
       one did. Asserting the SITE is what proves the report is diagnostic rather than decorative.
   (3) THE EMIT BARRIER TERMINATES. CURRENT-EMIT-NODE is pinned with no scheduler able to clear it (the
       controller has no registered writers, so the scheduler never enters the arming branch). Before
       this fix that was an UNBOUNDED loop around a bounded CONDVAR-WAIT and this leg ran FOREVER at
       ~2 wakes/second at 0% CPU. Asserting the ELAPSED time — not just the status — is what proves the
       loop terminates rather than that the return value happens to be right.
   (4) A REAL TEARDOWN IS CLEAN. A participant create+delete stops its receiver threads through the very
       paths this work bounded; the report must not move by a single count. This is the leg that would
       catch a bound set so tight that healthy teardown trips it."
  (let ((before (dds.pal:stuck-teardown-joins)))
    ;; (1) a healthy join reports nothing
    (let ((th (dds.pal:spawn (lambda () t) :name "teardown-healthy-probe")))
      (multiple-value-bind (r status) (dds.pal:join-bounded th :test-healthy-join 5)
        (declare (ignore r))
        (%check :teardown-healthy-status (null status)
                (format nil "a thread that exits must join cleanly, got status ~s" status))))
    (%check :teardown-healthy-silent (= before (dds.pal:stuck-teardown-joins))
            "a clean join must not touch the teardown report")
    ;; (2) a wedged thread is bounded, and named
    (let* ((release (list nil))
           (th (dds.pal:spawn (lambda () (loop until (car release) do (sleep 0.01)))
                              :name "teardown-wedged-probe")))
      (multiple-value-bind (r status) (dds.pal:join-bounded th :test-wedged-join 0.3)
        (declare (ignore r))
        (%check :teardown-wedged-status (eq status :timeout)
                (format nil "a thread that never exits must yield :TIMEOUT, got ~s" status)))
      (multiple-value-bind (total alist) (dds.pal:stuck-teardown-joins)
        (%check :teardown-wedged-counted (= total (1+ before))
                (format nil "the wedged join must add exactly one to the report (~d -> ~d)" before total))
        (%check :teardown-wedged-site (eql 1 (cdr (assoc :test-wedged-join alist)))
                (format nil "the report must name the SITE that expired; alist=~s" alist)))
      (setf (car release) t)
      (dds.pal:join-bounded th :test-wedged-release 5))
    ;; (3) the flow-controller emit barrier terminates instead of spinning forever
    (let ((fc (dds.disc:make-flow-controller :tokens-per-period 10000 :period 100000000 :max-burst 10000))
          (pinned (list :not-a-real-node))   ; %flow-emit-barrier types NODE as T, so a sentinel is enough
          (start (get-internal-real-time))
          (status nil))
      (unwind-protect
           (let ((dds.pal:*join-timeout-seconds* 1))
             (dds.pal:with-lock ((dds.disc::flow-controller-lock fc))
               (setf (dds.disc::flow-controller-current-emit-node fc) pinned)
               (setf status (nth-value 1 (dds.disc::%flow-emit-barrier fc pinned :test-emit-barrier)))))
        (setf (dds.disc::flow-controller-current-emit-node fc) nil)
        (dds.disc:destroy-flow-controller fc))
      (let ((elapsed (/ (float (- (get-internal-real-time) start))
                        internal-time-units-per-second)))
        (%check :teardown-barrier-status (eq status :timeout)
                (format nil "a pinned emit barrier must yield :TIMEOUT, got ~s" status))
        (%check :teardown-barrier-terminates (< elapsed 10)
                (format nil "the emit barrier must TERMINATE, not spin: took ~,2fs" elapsed))))
    ;; (4) a real participant lifecycle adds nothing to the report
    (let ((mark (dds.pal:stuck-teardown-joins))
          (p (dds.dcps:create-participant :domain (test-domain))))
      (dds.dcps:delete-participant p)
      (%check :teardown-participant-clean (= mark (dds.pal:stuck-teardown-joins))
              (format nil "a healthy participant teardown must report NOTHING (~d -> ~d)"
                      mark (dds.pal:stuck-teardown-joins)))))
  t)
