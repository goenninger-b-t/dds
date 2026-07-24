;;;; The multi-service runner (ADR 0082 §6/§7, FR-LOG-7): run N log collectors concurrently under one
;;;; process, each drained by its own thread, with a clean start/stop lifecycle. Threads + collectors
;;;; are parallel vectors so the OTP supervisor (supervisor.lisp) can RESTART a specific collector's
;;;; drain thread by index. *log-runner-fault* is a test-only hook that makes one collector's drain
;;;; thread exit, so the supervisor's restart path can be exercised (collectors are otherwise
;;;; condition-free and never die).

(in-package #:net.goenninger.dds.log)

(defvar *log-runner-fault* nil
  "TEST-ONLY fault injection (FR-LOG-7 supervisor test): when bound to a collector, THAT collector's
   drain thread EXITS once (simulating an unexpected thread death the supervisor must restart), and the
   binding is cleared so only the one thread dies. NIL in production — no drain thread ever exits on its
   own (the drain loop is condition-free).")

(defstruct* (log-service-runner (:constructor %make-log-service-runner))
  "Runs N log collectors concurrently (FR-LOG-7), one drain thread each, under one process. OWNS its
   collectors — log-runner-stop closes them. COLLECTORS and THREADS are PARALLEL vectors (threads[i]
   drains collectors[i]) so the supervisor can restart a single collector by index. RUNNING gates the
   drain threads; guarded (with THREADS) by LOCK so start/stop/restart are safe against each other."
  (collectors #() :type simple-vector)
  (threads    #() :type simple-vector)
  (running    nil :type boolean)
  (lock       (dds.pal:make-lock "dds-log-runner") :type t))

(defun* make-log-service-runner (collectors)
    (function (list) log-service-runner)
  "A runner over COLLECTORS (a list of log-collector it will OWN and, on log-runner-stop, close). Not
   started until log-runner-start. Build the collectors with make-log-collector / make-service-collector
   (any domains/sinks) and hand them here to run them all under one supervised process."
  (%make-log-service-runner :collectors (coerce collectors 'simple-vector)))

(defun* %log-runner-fault-p (collector)
    (function (log-collector) boolean)
  "T (once) iff COLLECTOR is the current test-only fault-injection target (*log-runner-fault*), clearing
   the target so only one thread dies. Always NIL in production (*log-runner-fault* is nil)."
  (and *log-runner-fault* (eq collector *log-runner-fault*)
       (progn (setf *log-runner-fault* nil) t)))

(defun* %log-runner-drain-loop (runner collector)
    (function (log-service-runner log-collector) t)
  "One collector's drain-thread body: drain COLLECTOR while RUNNER is running. Each collector's
   participant is touched only by its own drain thread (spin + take inside collector-drain), so N
   collectors run without cross-thread participant races. Exits early ONLY on the test fault hook."
  (loop while (log-service-runner-running runner)
        do (when (%log-runner-fault-p collector) (return))   ; test-only: simulate an unexpected death
           (collector-drain collector) (sleep 0.02))
  t)

(defun* %log-runner-spawn (runner index)
    (function (log-service-runner (integer 0)) t)
  "Spawn a drain thread for collector INDEX and return it. Used by log-runner-start and by the
   supervisor's restart (%log-runner-respawn)."
  (dds.pal:spawn (lambda () (%log-runner-drain-loop runner (svref (log-service-runner-collectors runner) index)))
                 :name "dds-log-collector"))

(defun* %log-runner-respawn (runner index)
    (function (log-service-runner (integer 0)) t)
  "Re-spawn the drain thread for collector INDEX, replacing threads[INDEX] (the supervisor's restart).
   Caller holds RUNNER's lock, so the join loop in log-runner-stop sees a consistent threads vector."
  (setf (svref (log-service-runner-threads runner) index) (%log-runner-spawn runner index)))

(defun* log-runner-start (runner)
    (function (log-service-runner) log-service-runner)
  "Start a drain thread for each of RUNNER's collectors (FR-LOG-7). A second start while already running
   is a no-op. Returns RUNNER."
  (dds.pal:with-lock ((log-service-runner-lock runner))
    (unless (log-service-runner-running runner)
      (setf (log-service-runner-running runner) t)
      (let ((n (length (log-service-runner-collectors runner))))
        (setf (log-service-runner-threads runner)
              (let ((v (make-array n)))
                (dotimes (i n v) (setf (svref v i) (%log-runner-spawn runner i))))))))
  runner)

(defun* log-runner-stop (runner)
    (function (log-service-runner) (eql t))
  "Stop all drain threads (clear RUNNING, then JOIN each — the CURRENT threads, including any the
   supervisor restarted), then close every collector (releasing its sinks + participant). Idempotent. A
   supervisor must stop its monitor BEFORE calling this, so no restart races the join/close."
  (dds.pal:with-lock ((log-service-runner-lock runner))
    (setf (log-service-runner-running runner) nil))
  (loop for th across (log-service-runner-threads runner) do (dds.pal:join th))
  (setf (log-service-runner-threads runner) #())
  (loop for c across (log-service-runner-collectors runner) do (close-log-collector c))
  t)
