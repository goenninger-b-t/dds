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
