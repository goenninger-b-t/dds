;;;; Async-logger test (ADR 0082 §5/§6, FR-LOG-5/6): the non-blocking bounded ring + worker + severity-
;;;; graded shedding. Three parts: (a) the watermark POLICY is pure-checked (EMERG..ERR = capacity so
;;;; they shed only when full; TRACE < DEBUG < INFO so low severities shed first); (b) SHEDDING is
;;;; verified deterministically with the worker STOPPED (a TRACE past its 25% watermark is shed and
;;;; counted while a CRIT is still accepted; a CRIT is shed only once the ring is full); (c) the async
;;;; path DELIVERS end to end — the worker drains the ring into a collector — and closes cleanly.
(in-package #:dds.tests)

(defun* run-log-async-test ()
    (function () t)
  "Test: the async logger's non-blocking ring, severity-graded shedding, and worker delivery (FR-LOG-5/6)."
  ;; ---- (a) watermark policy (pure) ----
  (let ((w (dds.log::%compute-watermarks 1024)))
    (%check :async-wm-highsev
            (and (= (aref w 0) 1024) (= (aref w 1) 1024) (= (aref w 2) 1024) (= (aref w 3) 1024))
            "EMERG..ERR watermarks must equal capacity (shed only when NO slot remains)")
    (%check :async-wm-order
            (and (< (aref w 8) (aref w 7)) (< (aref w 7) (aref w 6))
                 (< (aref w 6) (aref w 5)) (< (aref w 5) (aref w 4)) (<= (aref w 4) 1024))
            "TRACE < DEBUG < INFO < NOTICE < WARN <= capacity (low severities shed first)"))
  ;; ---- (b) shedding, deterministic with the worker STOPPED ----
  (let ((logger (dds.log:make-logger :domain (test-domain +td-log-async+) :app-id "gbttctools"
                                     :async t :ring-capacity 8))   ; TRACE wm = floor(8*25/100)=2
        (shed-events '()))
    (unwind-protect
         (progn
           (dds.log::%logger-stop-worker logger)   ; freeze the ring so enqueue/shed is deterministic
           ;; FR-LOG-6 push: capture each shed as (severity-number . cumulative-count).
           (dds.log:logger-set-shed-listener logger (lambda (sev count) (push (cons sev count) shed-events)))
           ;; three TRACE: wm=2 -> #1,#2 enqueue (count 0,1 < 2), #3 sheds (count 2 >= 2).
           (dotimes (i 3) (dds.log:logger-emit logger :severity :trace :category "NET" :message "t"))
           (let ((shed (dds.log:logger-shed-counts logger)))
             (%check :async-trace-shed
                     (and (= (aref shed 8) 1) (= (dds.log::logger-count logger) 2))
                     (format nil "a TRACE past the 25%% watermark must shed (count ~d, trace-drops ~d)"
                             (dds.log::logger-count logger) (aref shed 8))))
           ;; a CRIT with 2 slots used of 8: wm=capacity=8, count 2 < 8 -> ACCEPTED (never shed while a slot remains).
           (dds.log:logger-emit logger :severity :crit :category "MEM" :message "c")
           (%check :async-crit-accepted
                   (and (= (aref (dds.log:logger-shed-counts logger) 2) 0)
                        (= (dds.log::logger-count logger) 3))
                   "a CRIT must be accepted while a slot remains (0 crit-drops, count 3)")
           ;; fill to capacity with CRIT (5 more -> count 8), then one more CRIT sheds (ring full).
           (dotimes (i 5) (dds.log:logger-emit logger :severity :crit :category "MEM" :message "c"))
           (dds.log:logger-emit logger :severity :crit :category "MEM" :message "c")
           (%check :async-crit-shed-when-full
                   (and (= (dds.log::logger-count logger) 8) (= (aref (dds.log:logger-shed-counts logger) 2) 1))
                   (format nil "a CRIT sheds only once the ring is FULL (count ~d, crit-drops ~d)"
                           (dds.log::logger-count logger) (aref (dds.log:logger-shed-counts logger) 2)))
           ;; FR-LOG-6 reporting: the listener fired per shed (TRACE=8, CRIT=2), the status changed-bit
           ;; is set, and reset clears it (the DDS status read-then-reset shape).
           (%check :async-shed-listener
                   (and (member '(8 . 1) shed-events :test #'equal)
                        (member '(2 . 1) shed-events :test #'equal))
                   (format nil "the shed listener must fire per shed with (severity . count); got ~s" shed-events))
           (%check :async-shed-changed (dds.log:logger-shed-status-changed-p logger)
                   "the shed status-changed flag must be set after a shed")
           (dds.log:logger-reset-shed-status logger)
           (%check :async-shed-reset (not (dds.log:logger-shed-status-changed-p logger))
                   "logger-reset-shed-status must clear the changed flag"))
      (dds.log:close-logger logger)))
  ;; ---- (c) async delivery end to end (worker running) ----
  (let* ((domain (test-domain +td-log-async+))
         (captured '())
         (sink (dds.log:make-function-sink
                (lambda (event) (push (dds.log:format-log-event-text event) captured))))
         (collector (dds.log:make-log-collector :domain domain :sinks (list sink)))
         (logger (dds.log:make-logger :domain domain :app-id "gbttctools" :async t)))
    (unwind-protect
         (progn
           (%check :async-spin-noop (eq t (dds.log:logger-spin logger))
                   "logger-spin is a harmless no-op on an async logger")
           ;; the worker drives the logger side; the test drives the collector side.
           (dotimes (i 5)
             (dds.log:logger-emit logger :severity :notice :category "SUP"
                                         :message (format nil "async event ~d" i)))
           (loop repeat 500 until (>= (dds.log:log-collector-received collector) 5)
                 do (dds.log:collector-drain collector) (sleep 0.02))
           (%check :async-delivered (>= (dds.log:log-collector-received collector) 5)
                   (format nil "the async worker must deliver all 5 events; got ~d"
                           (dds.log:log-collector-received collector)))
           (%check :async-no-shed
                   (every #'zerop (dds.log:logger-shed-counts logger))
                   "no event should shed in normal (non-overflow) async flow")
           (%check :async-content
                   (find-if (lambda (l) (search "async event 0" l)) captured)
                   "the delivered async events must carry their message"))
      ;; close-logger stops + joins the worker, then deletes the participant — must not hang or crash.
      (dds.log:close-logger logger)
      (dds.log:close-log-collector collector)))
  t)
