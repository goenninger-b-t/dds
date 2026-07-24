;;;; Logging-service macro-API test (ADR 0082 §5, FR-LOG-3/4). Proves, over a real logger -> DDS ->
;;;; collector round-trip driven by the per-severity macros and with-trace-scope: (a) the per-category
;;;; threshold GATES emission — a DEBUG call is dropped while :net is at the default INFO threshold and
;;;; delivered once set-log-threshold raises it; (b) the enclosing DEFUN* function name is captured at
;;;; COMPILE TIME (dds.lang:current-function-name) and rides into the collector-rendered line; (c) the
;;;; category and severity render; (d) with-trace-scope emits ENTER/EXIT only when TRACE is enabled and
;;;; always returns BODY's value.
(in-package #:dds.tests)

;;; Helper call sites — the log macros expand INSIDE these DEFUN* bodies, so current-function-name
;;; captures THESE names. The function name the collector must see is the name of the emitting function.

(defun* %log-macro-emit-basic (lg)
    (function (dds.log:logger) t)
  "Emit an INFO + a CRIT (both on by default) and a DEBUG (:net, off by default). The captured function
   name for all three is %log-macro-emit-basic."
  (dds.log:log-info lg :sup "supervisor started")
  (dds.log:log-crit lg :mem "segmentation fault in ~a" "core")
  (dds.log:log-debug lg :net "flow-control window ~d" 4096)   ; :net default INFO -> DEBUG dropped
  t)

(defun* %log-macro-emit-net-debug (lg)
    (function (dds.log:logger) t)
  "Emit a DEBUG in :net — arrives only after :net's threshold is raised to DEBUG."
  (dds.log:log-debug lg :net "flow-control window ~d" 8192)
  t)

(defun* %log-macro-traced (lg)
    (function (dds.log:logger) (integer 0))
  "A with-trace-scope body returning 3; ENTER/EXIT are emitted only when :sup TRACE is enabled."
  (dds.log:with-trace-scope (lg :sup)
    (+ 1 2)))

(defun* %log-drain-until (collector n)
    (function (dds.log:log-collector (integer 0)) t)
  "Drain COLLECTOR until it has received >= N events or a safety bound elapses."
  (loop repeat 300 until (>= (dds.log:log-collector-received collector) n)
        do (dds.log:collector-drain collector) (sleep 0.02)))

(defun* run-log-disabled-alloc-test ()
    (function () t)
  "Test (FR-LOG-4): a DISABLED log level allocates NOTHING — MEASURED, not asserted. Measures bytes
   consed (dds.pal:bytes-consed) across 100000 disabled log-debug calls; the per-call allocation must
   round to 0. The disabled path is one (aref *log-thresholds* <compile-time-const>) + a compare + a
   short-circuited WHEN, so the message-building format never runs and the logger (here NIL — never
   dereferenced when disabled) is never touched. SBCL is the oracle: dds.pal:bytes-consed is 0 on Clasp,
   so the Clasp run is vacuously consistent while the real measurement is SBCL (the gate-mem oracle)."
  (dds.log:set-log-threshold :net dds.log:+severity-info+)   ; ensure :net DEBUG is DISABLED (default)
  ;; a BARE logger struct: no participant, hence no background receiver thread, so dds.pal:bytes-consed
  ;; (a process-wide counter) measures ONLY the disabled-call path. NIL cannot be used — logger-emit's
  ;; first arg is logger-typed, so the (unreachable, when-false) call still type-checks at compile time.
  (let ((logger (dds.log::%make-logger))
        (n 100000))
    (dotimes (i 1000) (dds.log:log-debug logger :net "warmup ~d" i))   ; warm up; not measured
    (let ((before (dds.pal:bytes-consed)))
      (dotimes (i n) (dds.log:log-debug logger :net "disabled ~d" i))
      (let ((delta (- (dds.pal:bytes-consed) before)))
        (%check :log-disabled-zero-alloc (zerop (floor delta n))
                (format nil "a disabled log-debug must allocate ~~0 bytes/call; measured ~d bytes over ~
                             ~d calls (~,4f B/call)" delta n (/ delta n 1.0))))))
  t)

(defun* run-log-macros-test ()
    (function () t)
  "Test: the ergonomic logging macro API (ADR 0082 §5, FR-LOG-3/4) end to end over DDS."
  (let* ((domain (test-domain +td-log-macros+))
         (captured '())
         (sink (dds.log:make-function-sink
                (lambda (event) (push (dds.log:format-log-event-text event) captured))))
         (logger (dds.log:make-logger :domain domain :app-id "gbttctools"))
         (collector (dds.log:make-log-collector :domain domain :sinks (list sink))))
    (unwind-protect
         (progn
           ;; default thresholds: INFO on, DEBUG/TRACE off (FR-LOG-4).
           (%check :logmac-defaults
                   (and (= (dds.log:get-log-threshold :sup) dds.log:+severity-info+)
                        (= (dds.log:get-log-threshold :net) dds.log:+severity-info+))
                   "categories default to the INFO threshold (DEBUG/TRACE off)")
           ;; match writer <-> reader.
           (loop repeat 400
                 until (and (plusp (dds.dcps:matched-count (dds.log::logger-participant logger)))
                            (plusp (dds.dcps:matched-count (dds.log::log-collector-participant collector))))
                 do (dds.log:logger-spin logger) (dds.log:collector-drain collector) (sleep 0.02))
           (%check :logmac-matched
                   (plusp (dds.dcps:matched-count (dds.log::log-collector-participant collector)))
                   "logger and collector must match")
           ;; (a)+(b)+(c): emit INFO+CRIT (delivered) and DEBUG on :net (GATED OUT at default threshold).
           (%log-macro-emit-basic logger)
           (loop repeat 400 do (dds.log:logger-spin logger) until (>= (length captured) 2)
                 do (dds.log:collector-drain collector) (sleep 0.02))
           (dds.log:collector-drain collector)
           (let ((info-line (find-if (lambda (l) (search "supervisor started" l)) captured))
                 (crit-line (find-if (lambda (l) (search "segmentation fault in core" l)) captured))
                 (debug-line (find-if (lambda (l) (search "flow-control window 4096" l)) captured)))
             (%check :logmac-info-delivered
                     (and info-line (search "%log-macro-emit-basic()" info-line)
                          (search "| SUP |" info-line) (search "INFO" info-line))
                     (format nil "INFO must be delivered with captured function/category; got ~s" info-line))
             (%check :logmac-crit-formatted
                     (and crit-line (search "%log-macro-emit-basic()" crit-line) (search "| MEM |" crit-line))
                     (format nil "CRIT with format args must be delivered; got ~s" crit-line))
             (%check :logmac-debug-gated (null debug-line)
                     "a DEBUG call on :net (default INFO threshold) must be GATED OUT — not delivered"))
           ;; raise :net to DEBUG, re-emit -> now delivered (threshold is dynamic).
           (dds.log:set-log-threshold :net dds.log:+severity-debug+)
           (%log-macro-emit-net-debug logger)
           (%log-drain-until collector (1+ (dds.log:log-collector-received collector)))
           (%check :logmac-debug-enabled
                   (find-if (lambda (l) (search "flow-control window 8192" l)) captured)
                   "after set-log-threshold :net DEBUG, a :net DEBUG call must be delivered")
           ;; (d) with-trace-scope: TRACE off for :sup -> body runs, returns 3, NO enter/exit.
           (let ((before (dds.log:log-collector-received collector))
                 (result (%log-macro-traced logger)))
             (%check :logmac-trace-value (= result 3) "with-trace-scope must return BODY's value")
             (loop repeat 60 do (dds.log:logger-spin logger) (dds.log:collector-drain collector) (sleep 0.01))
             (%check :logmac-trace-off-silent
                     (and (= (dds.log:log-collector-received collector) before)
                          (notany (lambda (l) (search "ENTER" l)) captured))
                     "with TRACE off, with-trace-scope must emit NOTHING (clock not read, FR-LOG-4)"))
           ;; enable TRACE for :sup -> enter + exit events now emitted.
           (dds.log:set-log-threshold :sup dds.log:+severity-trace+)
           (let ((r (%log-macro-traced logger)))
             (%check :logmac-trace-value2 (= r 3) "with-trace-scope still returns BODY's value when TRACE on"))
           (%log-drain-until collector (+ 2 (dds.log:log-collector-received collector)))
           (%check :logmac-trace-on-brackets
                   (and (find-if (lambda (l) (and (search "ENTER" l) (search "%log-macro-traced" l))) captured)
                        (find-if (lambda (l) (and (search "EXIT" l) (search "%log-macro-traced" l))) captured))
                   "with TRACE on, with-trace-scope must emit ENTER and EXIT for the scope"))
      ;; restore mutated global thresholds so the suite's shared state is unchanged.
      (dds.log:set-log-threshold :net dds.log:+severity-info+)
      (dds.log:set-log-threshold :sup dds.log:+severity-info+)
      (dds.log:close-logger logger)
      (dds.log:close-log-collector collector)))
  t)
