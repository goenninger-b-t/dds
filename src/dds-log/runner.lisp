;;;; The multi-service runner (ADR 0082 §6/§7, FR-LOG-7): run N log collectors concurrently under one
;;;; process, each drained by its own thread, with a clean start/stop lifecycle. This is the runner half
;;;; of FR-LOG-7's "durability-service shape"; the OTP-style SUPERVISOR (restart a drain thread that
;;;; unexpectedly dies, bounded by a restart-intensity cap — mirroring dds.durability's supervisor) is a
;;;; follow-on slice.

(in-package #:net.goenninger.dds.log)

(defstruct* (log-service-runner (:constructor %make-log-service-runner))
  "Runs N log collectors concurrently (FR-LOG-7), one drain thread each, under one process. OWNS its
   collectors — log-runner-stop closes them. RUNNING gates the drain threads; guarded (with THREADS) by
   LOCK so start/stop are safe against each other. The embedded library entity a host app holds."
  (collectors nil :type list)
  (threads    nil :type list)
  (running    nil :type boolean)
  (lock       (dds.pal:make-lock "dds-log-runner") :type t))

(defun* make-log-service-runner (collectors)
    (function (list) log-service-runner)
  "A runner over COLLECTORS (a list of log-collector it will OWN and, on log-runner-stop, close). Not
   started until log-runner-start. Build the collectors with make-log-collector / make-service-collector
   (any domains/sinks) and hand them here to run them all under one supervised process."
  (%make-log-service-runner :collectors collectors))

(defun* %log-runner-drain-loop (runner collector)
    (function (log-service-runner log-collector) t)
  "One collector's drain-thread body: drain COLLECTOR while RUNNER is running. Each collector's
   participant is touched only by its own drain thread (spin + take inside collector-drain), so N
   collectors run without cross-thread participant races."
  (loop while (log-service-runner-running runner)
        do (collector-drain collector) (sleep 0.02))
  t)

(defun* log-runner-start (runner)
    (function (log-service-runner) log-service-runner)
  "Start a drain thread for each of RUNNER's collectors (FR-LOG-7). A second start while already running
   is a no-op. Returns RUNNER."
  (dds.pal:with-lock ((log-service-runner-lock runner))
    (unless (log-service-runner-running runner)
      (setf (log-service-runner-running runner) t
            (log-service-runner-threads runner)
            (mapcar (lambda (c)
                      (dds.pal:spawn (lambda () (%log-runner-drain-loop runner c))
                                     :name "dds-log-collector"))
                    (log-service-runner-collectors runner)))))
  runner)

(defun* log-runner-stop (runner)
    (function (log-service-runner) (eql t))
  "Stop all drain threads (clear RUNNING, then JOIN each), then close every collector (releasing its
   sinks + participant). Idempotent — a second stop is a no-op. After this no runner thread touches any
   collector or participant, so the process can exit cleanly."
  (dds.pal:with-lock ((log-service-runner-lock runner))
    (setf (log-service-runner-running runner) nil))
  (dolist (th (log-service-runner-threads runner)) (dds.pal:join th))
  (setf (log-service-runner-threads runner) nil)
  (dolist (c (log-service-runner-collectors runner)) (close-log-collector c))
  t)
