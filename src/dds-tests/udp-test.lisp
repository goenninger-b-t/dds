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
                    creep up one allocation at a time and the ceiling would stop being an operating signal.

   Every arm pins *STATIC-ARENA-MODE* :GROWABLE (ADR 0125). Without it the default :AUTO resolves to :FIXED
   on a real-time kernel and arms 1 and 4 would fail there for a reason that has nothing to do with growth."
  (let ((mib (* 1024 1024)))
    ;; 1 — GROWS
    (let ((dds.core.arena:*process-arena* nil)
          (dds.core.arena:*static-arena-mode* :growable)   ; ADR 0125: ADR 0102 is the :GROWABLE mode
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
          (dds.core.arena:*static-arena-mode* :growable)   ; ADR 0125: ADR 0102 is the :GROWABLE mode
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
          (dds.core.arena:*static-arena-mode* :growable)   ; ADR 0125: ADR 0102 is the :GROWABLE mode
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
          (dds.core.arena:*static-arena-mode* :growable)   ; ADR 0125: ADR 0102 is the :GROWABLE mode
          (dds.core.arena:*static-arena-bytes* 4096)
          (dds.core.arena:*static-arena-growth-bytes* mib)
          (dds.core.arena:*static-arena-max-bytes* (* 64 mib)))
      (let ((a (dds.core.arena:process-arena)))
        (dds.core.arena:make-buffer-pool a 8192 1)
        (%check :arena-grow-whole-chunks (= (dds.core.arena:arena-byte-budget a) (+ 4096 mib))
                (format nil "growth must take a WHOLE chunk, not the exact shortfall (budget ~a, expected ~a)"
                        (dds.core.arena:arena-byte-budget a) (+ 4096 mib))))))
  t)

(defun* run-arena-mode-test ()
    (function () (eql t))
  "ADR 0125 (owner decision D29, 2026-10-04): the arena is GROWABLE up to a configured ceiling by default and
   FIXED on real-time Linux; *STATIC-ARENA-MODE* (:AUTO / :GROWABLE / :FIXED) overrides the detection.

   Each arm can fail, and the CONTRAST arm is what proves the FIXED arms test the mode rather than the
   numbers: the identical configuration under :GROWABLE grows and carves, so a refusal under :FIXED is the
   mode's doing.
     1 FIXED NEVER GROWS — 4 KiB initial, 8 MiB max, 1 MiB chunk: a 256 KiB carve is REFUSED with
                          :ARENA-EXHAUSTED; budget stays 4096, ceiling is 4096, zero growths, chunk 0.
                          1b: an arena marked :FIXED that still carries a chunk and a high ceiling does
                          not grow either, so the guarantee is the mode test, not only INIT-ARENA's zeroing.
     2 CONTRAST          — the same numbers under :GROWABLE: the carve succeeds and the budget grew.
     3 FIXED, SUB-ARENA  — a carve through a participant-style sub-arena of a :FIXED root is refused and the
                          ROOT did not grow (growth is asked of the budget-holder, ADR 0102 §2).
     4 FIXED STILL CARVES — within the budget a :FIXED arena carves normally, and a later carve past it is
                          refused, the budget unchanged throughout.
     5 AUTO FOLLOWS THE KERNEL — :AUTO resolves to :FIXED iff dds.pal:real-time-kernel-p says so, with that
                          probe's source as the reason.
     6 INVALID MODE      — an unknown value runs :FIXED with reason :INVALID-MODE (bounded, reported).
                          6b: OVERSIZE settings (bignum budget/ceiling/chunk, negative chunk) are clamped
                          to the arena's fixnum slots, never signalled (ADR 0064).
     7 READ ONCE         — rebinding *STATIC-ARENA-MODE* after the process arena exists changes nothing, and
                          PROCESS-ARENA-STATUS reports the mode chosen at init (NIL before init).
     8 PAL CLASSIFIER    — every branch of dds.pal:classify-real-time-kernel on fixture text, including the
                          near-misses PREEMPT_RTX / PREEMPT_DYNAMIC / a sysfs file reading 0, and the
                          bounded read of an over-long probe file through *RT-SYSFS-PATH*."
  (let ((mib (* 1024 1024)))
    (flet ((fresh (mode thunk)
             (let ((dds.core.arena:*process-arena* nil)
                   (dds.core.arena:*static-arena-mode* mode)
                   (dds.core.arena:*static-arena-bytes* 4096)
                   (dds.core.arena:*static-arena-growth-bytes* mib)
                   (dds.core.arena:*static-arena-max-bytes* (* 8 mib)))
               (let ((a (dds.core.arena:process-arena)))
                 (unwind-protect (funcall thunk a)
                   (dds.core.arena:teardown-arena a))))))   ; idempotent; frees what an arm carved
      ;; 1 — FIXED NEVER GROWS
      (fresh :fixed
             (lambda (a)
               (multiple-value-bind (pool status) (dds.core.arena:make-buffer-pool a 65536 4)
                 (%check :arena-mode-fixed-refuses (and (null pool) (eq status :arena-exhausted))
                         (format nil "a :FIXED arena must REFUSE a carve over its budget, not grow (got ~a/~a)"
                                 (if pool "pool" "nil") status))
                 (%check :arena-mode-fixed-no-growth
                         (and (= 4096 (dds.core.arena:arena-byte-budget a))
                              (= 4096 (dds.core.arena:arena-max-bytes a))
                              (zerop (dds.core.arena:arena-growths a))
                              (zerop (dds.core.arena:arena-growth-bytes a)))
                         (format nil "a :FIXED arena's budget must never change (budget ~d, max ~d, growths ~d, chunk ~d)"
                                 (dds.core.arena:arena-byte-budget a) (dds.core.arena:arena-max-bytes a)
                                 (dds.core.arena:arena-growths a) (dds.core.arena:arena-growth-bytes a)))
                 (let ((r (dds.core.arena:arena-report a)))
                   (%check :arena-mode-fixed-reported
                           (and (eq (getf r :mode) :fixed) (eq (getf r :mode-reason) :configured))
                           (format nil "the arena report must name the mode and why (~s)" r))))))
      ;; 1b — the MODE itself refuses growth, not only the zeroed chunk/ceiling INIT-ARENA installs: an arena
      ;; marked :FIXED but carrying a live chunk and a high ceiling must still not grow (%arena-grow-to-fit's
      ;; first test). Built directly, because INIT-ARENA can never produce this combination.
      (let ((a (dds.core.arena::%make-arena :byte-budget 4096 :initialized t :mode :fixed
                                            :mode-reason :configured :growth-bytes mib :max-bytes (* 8 mib))))
        (multiple-value-bind (pool status) (dds.core.arena:make-buffer-pool a 65536 4)
          (%check :arena-mode-fixed-guard
                  (and (null pool) (eq status :arena-exhausted) (= 4096 (dds.core.arena:arena-byte-budget a)))
                  (format nil "the :FIXED mode test must refuse growth even with a live chunk and ceiling (got ~a/~a, budget ~d)"
                          (if pool "pool" "nil") status (dds.core.arena:arena-byte-budget a))))
        (dds.core.arena:teardown-arena a))
      ;; 2 — CONTRAST: the same numbers, growable
      (fresh :growable
             (lambda (a)
               (multiple-value-bind (pool status) (dds.core.arena:make-buffer-pool a 65536 4)
                 (%check :arena-mode-growable-contrast
                         (and pool (null status) (> (dds.core.arena:arena-byte-budget a) 4096)
                              (eq (dds.core.arena:arena-mode a) :growable))
                         (format nil "CONTRAST: the same carve under :GROWABLE must succeed by growing (got ~a/~a, budget ~d)"
                                 (if pool "pool" "nil") status (dds.core.arena:arena-byte-budget a))))))
      ;; 3 — FIXED through a sub-arena
      (fresh :fixed
             (lambda (a)
               (let ((sub (dds.core.arena:make-sub-arena a)))
                 (multiple-value-bind (pool status) (dds.core.arena:make-buffer-pool sub 65536 4)
                   (%check :arena-mode-fixed-sub-refuses
                           (and (null pool) (eq status :arena-exhausted)
                                (= 4096 (dds.core.arena:arena-byte-budget a))
                                (zerop (dds.core.arena:arena-growths a))
                                (eq (dds.core.arena:arena-mode sub) :fixed))
                           (format nil "a sub-arena of a :FIXED root must be refused and the root must not grow (got ~a/~a, root budget ~d)"
                                   (if pool "pool" "nil") status (dds.core.arena:arena-byte-budget a))))
                 (dds.core.arena:teardown-arena sub))))
      ;; 4 — FIXED still carves within its budget
      (fresh :fixed
             (lambda (a)
               (multiple-value-bind (p1 s1) (dds.core.arena:make-buffer-pool a 1024 2)
                 (multiple-value-bind (p2 s2) (dds.core.arena:make-buffer-pool a 1024 4)
                   (%check :arena-mode-fixed-carves-within
                           (and p1 (null s1) (null p2) (eq s2 :arena-exhausted)
                                (= 2048 (dds.core.arena:arena-bytes-used a))
                                (= 4096 (dds.core.arena:arena-byte-budget a)))
                           (format nil "a :FIXED arena must carve within its budget and refuse past it (~a/~a then ~a/~a, used ~d)"
                                   (if p1 "pool" "nil") s1 (if p2 "pool" "nil") s2
                                   (dds.core.arena:arena-bytes-used a)))))
               (dds.core.arena:teardown-arena a))))
    ;; 5 — AUTO follows the kernel probe
    (multiple-value-bind (rt source) (dds.pal:real-time-kernel-p)
      (multiple-value-bind (mode reason) (dds.core.arena:resolve-arena-mode :auto)
        (%check :arena-mode-auto-follows-kernel
                (and (eq mode (if rt :fixed :growable)) (eq reason source))
                (format nil ":AUTO must resolve to :FIXED iff the kernel is real-time (probe ~a/~a, resolved ~a/~a)"
                        rt source mode reason))))
    ;; 6 — INVALID mode is bounded and reported
    (multiple-value-bind (mode reason) (dds.core.arena:resolve-arena-mode :elastic)
      (%check :arena-mode-invalid-is-fixed (and (eq mode :fixed) (eq reason :invalid-mode))
              (format nil "an unknown mode must run :FIXED with reason :INVALID-MODE (got ~a/~a)" mode reason)))
    ;; 6b — OVERSIZE settings are clamped to the fixnum slots, never signalled (ADR 0064, ADR 0125 §5): a
    ;; bignum budget / ceiling / chunk and a negative chunk build an arena instead of raising a type error.
    ;; Accounting only — nothing is allocated, so the huge numbers cost nothing.
    (let ((a (handler-case (dds.core.arena:init-arena :bytes (1+ most-positive-fixnum)
                                                      :max-bytes (* 2 most-positive-fixnum)
                                                      :growth-bytes (expt 2 70) :mode :growable)
               (error (e) e)))
          (b (handler-case (dds.core.arena:init-arena :bytes 4096 :max-bytes 8192 :growth-bytes -5
                                                      :mode :growable)
               (error (e) e))))
      (%check :arena-mode-oversize-clamped
              (and (typep a 'dds.core.arena:arena)
                   (= most-positive-fixnum (dds.core.arena:arena-byte-budget a))
                   (= most-positive-fixnum (dds.core.arena:arena-max-bytes a))
                   (= most-positive-fixnum (dds.core.arena:arena-growth-bytes a))
                   (typep b 'dds.core.arena:arena)
                   (zerop (dds.core.arena:arena-growth-bytes b)))
              (format nil "oversize / negative arena settings must clamp, not signal (got ~a / ~a)" a b))
      (when (typep a 'dds.core.arena:arena) (dds.core.arena:teardown-arena a))
      (when (typep b 'dds.core.arena:arena) (dds.core.arena:teardown-arena b)))
    ;; 7 — READ ONCE, and the status
    (let ((dds.core.arena:*process-arena* nil)
          (dds.core.arena:*static-arena-mode* :growable)
          (dds.core.arena:*static-arena-bytes* 4096)
          (dds.core.arena:*static-arena-growth-bytes* mib)
          (dds.core.arena:*static-arena-max-bytes* (* 8 mib)))
      (%check :arena-mode-status-before-init (null (dds.core.arena:process-arena-status))
              "PROCESS-ARENA-STATUS must be NIL, and must not create the arena, before anything carved")
      (let ((a (dds.core.arena:process-arena)))
        (let ((dds.core.arena:*static-arena-mode* :fixed))
          (multiple-value-bind (pool status) (dds.core.arena:make-buffer-pool a 65536 4)
            (%check :arena-mode-read-once
                    (and pool (null status) (eq (dds.core.arena:arena-mode a) :growable))
                    (format nil "rebinding the mode after init must have no effect (got ~a/~a, mode ~a)"
                            (if pool "pool" "nil") status (dds.core.arena:arena-mode a)))))
        (let ((st (dds.core.arena:process-arena-status)))
          (%check :arena-mode-status
                  (and (eq (getf st :mode) :growable) (eq (getf st :mode-reason) :configured)
                       (= (getf st :growths) 1) (eq (getf st :pools 'absent) 'absent)
                       (eql (getf st :byte-budget) (dds.core.arena:arena-byte-budget a)))
                  (format nil "PROCESS-ARENA-STATUS must report the init-time mode and the growth (~s)" st)))
        (dds.core.arena:teardown-arena a))))
  ;; 8 — the PAL classifier, every branch
  (flet ((cls (linux sys uts) (multiple-value-list (dds.pal:classify-real-time-kernel linux sys uts))))
    (loop for (linux sys uts want) in
          '((nil "1" "#1 SMP PREEMPT_RT x" (nil :not-linux))
            (t "1" nil (t :sysfs-realtime))
            (t "  1 " nil (t :sysfs-realtime))
            (t "0" "#1 SMP PREEMPT_DYNAMIC x" (nil :not-real-time))
            (t "10" nil (nil :not-real-time))
            (t nil "#1 SMP PREEMPT_RT Mon Sep 14 16:37:11 UTC 2026" (t :uts-version))
            (t "0" "#1 SMP PREEMPT_RT x" (t :uts-version))
            (t nil "#1 SMP PREEMPT_RTX x" (nil :not-real-time))
            (t nil "#38~24.04.4-Ubuntu SMP PREEMPT_DYNAMIC Mon Sep 14 16:37:11 UTC 2" (nil :not-real-time))
            (t nil "" (nil :not-real-time))
            (t nil nil (nil :not-real-time)))
          for got = (cls linux sys uts)
          do (%check :arena-mode-pal-classifier (equal got want)
                     (format nil "classify-real-time-kernel ~s ~s ~s: got ~s, want ~s" linux sys uts got want))))
  ;; the real probe reads a fixture through *RT-SYSFS-PATH*, bounded
  (when (member :linux *features*)
    (let ((path (merge-pathnames (format nil "dds-rt-probe-~d.txt" (dds.pal:process-id))
                                 (uiop:temporary-directory))))
      (unwind-protect
           (progn
             (with-open-file (o path :direction :output :if-exists :supersede)
               (write-string "1" o)
               (loop repeat 10000 do (write-char #\Space o)))
             (let ((dds.pal:*rt-sysfs-path* (namestring path)))
               (multiple-value-bind (rt source) (dds.pal:real-time-kernel-p)
                 (%check :arena-mode-pal-fixture (and rt (eq source :sysfs-realtime))
                         (format nil "a sysfs fixture reading 1 must be detected (got ~a/~a)" rt source)))
               (%check :arena-mode-pal-bounded
                       (= dds.pal:+rt-probe-max-chars+
                          (length (dds.pal::read-rt-probe-file (namestring path))))
                       "the probe read must be bounded by +RT-PROBE-MAX-CHARS+"))
             (let ((dds.pal:*rt-sysfs-path* "/nonexistent/dds-rt-probe"))
               (multiple-value-bind (rt source) (dds.pal:real-time-kernel-p)
                 (%check :arena-mode-pal-absent-file
                         (or (eq source :uts-version) (and (null rt) (eq source :not-real-time)))
                         (format nil "an absent sysfs file must fall through to the UTS check (got ~a/~a)" rt source)))))
        (ignore-errors (delete-file path)))))
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
    ;; ADR 0101 slice 3: creation now REFUSES rather than reverting to an alloc-static path outside the
    ;; budget. A process that cannot fit its configured arena learns at INIT, not at the first sample.
    (multiple-value-bind (node status)
        (dds.disc:make-disc-node :domain 244 :host "127.0.0.1" :port 0 :multicast nil)
      (%check :arena-exh-node-refused (and (null node) (eq status :arena-exhausted))
              (format nil "creation must be REFUSED with :ARENA-EXHAUSTED when the ceiling admits no carve (got ~a/~a)"
                      (if node "node" "nil") status))))
  ;; ADR 0101: exhaustion REJECTS. Drive a real secured receive under a ceiling too small to carve anything
  ;; and assert the node COUNTS the rejects rather than quietly heap-allocating its way through them.
  ;; The counter is the observable the contract's 'never a SILENT GC-heap fallback' turns on.
  (let ((dds.core.arena:*process-arena* nil)
        (dds.core.arena:*static-arena-bytes* 4096)
        (dds.core.arena:*static-arena-max-bytes* 4096))
    ;; and the refusal must be REPEATABLE, not a first-call artefact of a fresh process arena
    (multiple-value-bind (node status)
        (dds.disc:make-disc-node :domain 245 :host "127.0.0.1" :port 0 :multicast nil)
      (%check :arena-exh-refusal-repeatable (and (null node) (eq status :arena-exhausted))
              "the refusal must be repeatable, not a one-shot artefact")))
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
