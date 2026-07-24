;;;; OTP-supervisor test (ADR 0082 §6/§7, FR-LOG-7). Uses the runner's *log-runner-fault* hook to KILL a
;;;; collector's drain thread (collectors are otherwise condition-free and never die), then asserts the
;;;; supervisor (a) RESTARTS it — a new drain thread replaces the dead one and the restart is recorded —
;;;; and (b) SHEDS the collector once the restart intensity (MAX-RESTARTS deaths in the window) is
;;;; exceeded (it stops restarting). log-supervisor-stop then joins the monitor + drain threads cleanly.
(in-package #:dds.tests)

(defun* %log-sup-wait-changed (runner idx thread sup)
    (function (dds.log:log-service-runner (integer 0) t dds.log:log-supervisor) t)
  "Kill collector IDX's current drain THREAD via the fault hook and wait until the supervisor either
   restarts it (threads[IDX] changes) or sheds it — bounded."
  (setf dds.log::*log-runner-fault* (svref (dds.log::log-service-runner-collectors runner) idx))
  (loop repeat 300
        until (or (svref (dds.log::log-supervisor-shed sup) idx)
                  (not (eq (svref (dds.log::log-service-runner-threads runner) idx) thread)))
        do (sleep 0.02)))

(defun* run-log-supervisor-test ()
    (function () t)
  "Test: the FR-LOG-7 OTP supervisor — restart a dead drain thread, shed past the intensity cap."
  (let* ((d (test-domain +td-log-supervisor+))
         (c (dds.log:make-log-collector :domain d :sinks '()))
         (runner (dds.log:make-log-service-runner (list c)))
         (sup (dds.log:make-log-supervisor runner :max-restarts 2 :window-seconds 30 :poll-seconds 0.02d0)))
    (unwind-protect
         (progn
           (dds.log:log-supervisor-start sup)   ; starts the runner + the monitor
           (loop repeat 100 until (svref (dds.log::log-service-runner-threads runner) 0) do (sleep 0.01))
           ;; (a) kill the drain thread; the supervisor must restart it.
           (let ((t0 (svref (dds.log::log-service-runner-threads runner) 0)))
             (%log-sup-wait-changed runner 0 t0 sup)
             (%check :sup-restarted
                     (and (not (eq (svref (dds.log::log-service-runner-threads runner) 0) t0))
                          (not (svref (dds.log::log-supervisor-shed sup) 0)))
                     "the supervisor must RESTART a dead drain thread (a new thread replaces it, not shed)")
             (%check :sup-restart-recorded
                     (>= (length (svref (dds.log::log-supervisor-restarts sup) 0)) 1)
                     "the restart must be recorded in the intensity history"))
           ;; (b) keep killing it; past MAX-RESTARTS (2) deaths in the window it must be SHED.
           (loop repeat 5
                 until (svref (dds.log::log-supervisor-shed sup) 0)
                 do (%log-sup-wait-changed runner 0 (svref (dds.log::log-service-runner-threads runner) 0) sup))
           (%check :sup-shed
                   (svref (dds.log::log-supervisor-shed sup) 0)
                   "after MAX-RESTARTS deaths in the window the collector must be SHED (no more restarts)"))
      (setf dds.log::*log-runner-fault* nil)   ; clear the fault hook so no other test is affected
      (dds.log:log-supervisor-stop sup)))      ; joins the monitor FIRST, then the drain threads + closes
  t)
