;;;; OTP-style one-for-one supervisor for a log-service-runner (ADR 0082 §6/§7, FR-LOG-7 — the
;;;; durability-service shape). A monitor thread polls each collector's drain-thread liveness (via
;;;; dds.pal:live-threads membership — there is no thread-alive-p primitive) and RESTARTS a dead one,
;;;; unless the restart intensity (MAX-RESTARTS deaths within WINDOW-SECONDS) is exceeded, in which case
;;;; the collector is SHED (given up). Collectors are condition-free, so a drain thread never dies on its
;;;; own — this is defense-in-depth for an out-of-our-control death (a signal, a foreign crash); the test
;;;; exercises it through the runner's *log-runner-fault* hook.

(in-package #:net.goenninger.dds.log)

(defstruct* (log-supervisor (:constructor %make-log-supervisor))
  "One-for-one supervisor over a log-service-runner (FR-LOG-7). RESTARTS is a per-collector vector of
   restart timestamps (monotonic-ns) within the window; SHED a per-collector boolean (given up after the
   intensity cap). The MONITOR thread polls liveness every POLL-SECONDS. Created by make-log-supervisor,
   run by log-supervisor-start, torn down by log-supervisor-stop (which stops the monitor BEFORE the
   runner, so no restart races the collector close)."
  (runner         nil :type (or null log-service-runner))
  (max-restarts   3   :type (integer 0))
  (window-seconds 5   :type (integer 1))
  (poll-seconds   0.05d0 :type real)
  (restarts       #() :type simple-vector)
  (shed           #() :type simple-vector)
  (monitor        nil :type t)
  (running        nil :type boolean)
  (lock           (dds.pal:make-lock "dds-log-supervisor") :type t))

(defun* make-log-supervisor (runner &key (max-restarts 3) (window-seconds 5) (poll-seconds 0.05d0))
    (function (log-service-runner &key (:max-restarts (integer 0)) (:window-seconds (integer 1))
                                  (:poll-seconds real))
              log-supervisor)
  "A supervisor for RUNNER (FR-LOG-7). MAX-RESTARTS deaths within WINDOW-SECONDS is the restart-intensity
   cap (one-for-one): beyond it a collector is shed. POLL-SECONDS is the monitor's liveness poll period.
   Not started until log-supervisor-start."
  (let ((n (length (log-service-runner-collectors runner))))
    (%make-log-supervisor :runner runner :max-restarts max-restarts :window-seconds window-seconds
                          :poll-seconds poll-seconds
                          :restarts (make-array n :initial-element nil)
                          :shed (make-array n :initial-element nil))))

(defun* %log-thread-alive-p (thread)
    (function (t) boolean)
  "T iff THREAD is still alive (membership in dds.pal:live-threads — the PAL exposes no thread-alive-p).
   A drain thread that exited is absent from the live set."
  (and (member thread (dds.pal:live-threads)) t))

(defun* %log-supervisor-restart (sup index now)
    (function (log-supervisor (integer 0) integer) t)
  "Record a death for collector INDEX at monotonic time NOW, prune the window, and either RESPAWN the
   drain thread (within the intensity cap) or SHED the collector (cap exceeded). Caller holds the
   runner's lock (via %log-supervisor-check), so %log-runner-respawn's contract is met."
  (let* ((window-ns (* (log-supervisor-window-seconds sup) 1000000000))
         (hist (cons now (remove-if (lambda (ts) (> (- now ts) window-ns))
                                    (svref (log-supervisor-restarts sup) index)))))
    (setf (svref (log-supervisor-restarts sup) index) hist)
    (if (> (length hist) (log-supervisor-max-restarts sup))
        (setf (svref (log-supervisor-shed sup) index) t)          ; intensity exceeded -> give up
        (%log-runner-respawn (log-supervisor-runner sup) index))  ; restart (we hold the runner lock)
    t))

(defun* %log-supervisor-check (sup)
    (function (log-supervisor) t)
  "One monitor poll: under the runner lock (so a restart cannot race log-runner-stop's join/close), for
   each collector still running and not shed, restart it if its drain thread has died."
  (let ((runner (log-supervisor-runner sup)))
    (dds.pal:with-lock ((log-service-runner-lock runner))
      (when (log-service-runner-running runner)
        (let ((threads (log-service-runner-threads runner))
              (now (dds.pal:monotonic-ns)))
          (dotimes (i (length threads))
            (unless (or (svref (log-supervisor-shed sup) i)
                        (%log-thread-alive-p (svref threads i)))
              (%log-supervisor-restart sup i now))))))
    t))

(defun* %log-supervisor-monitor (sup)
    (function (log-supervisor) t)
  "The monitor-thread body: poll liveness every POLL-SECONDS while the supervisor runs."
  (loop while (log-supervisor-running sup)
        do (%log-supervisor-check sup)
           (sleep (log-supervisor-poll-seconds sup)))
  t)

(defun* log-supervisor-start (sup)
    (function (log-supervisor) log-supervisor)
  "Start SUP's runner (log-runner-start, idempotent) and then the monitor thread. Returns SUP."
  (log-runner-start (log-supervisor-runner sup))
  (dds.pal:with-lock ((log-supervisor-lock sup))
    (unless (log-supervisor-running sup)
      (setf (log-supervisor-running sup) t
            (log-supervisor-monitor sup)
            (dds.pal:spawn (lambda () (%log-supervisor-monitor sup)) :name "dds-log-supervisor"))))
  sup)

(defun* log-supervisor-stop (sup)
    (function (log-supervisor) (values (eql t) (or null keyword)))
  "Stop SUP: clear RUNNING and JOIN the monitor FIRST — BOUNDED — (so no restart is in flight), then stop
   the runner (join drain threads + close collectors). This ordering guarantees no thread is restarted
   while the runner tears its collectors down. Idempotent.

   Returns (values T NIL), or (values T :TIMEOUT) if the monitor or any drain thread could not be proven
   stopped. ⚠️ THE RUNNER STOP IS GATED ON THE MONITOR JOIN (ADR 0092): 'this ordering guarantees no thread
   is restarted while the runner tears its collectors down' holds ONLY once the monitor is provably gone. A
   monitor still running can RESPAWN a drain thread onto a collector the runner is closing — so on a
   monitor timeout the runner is left ALONE, its collectors stay open, and the timeout is reported via
   dds.pal:stuck-teardown-joins. Tearing down under a live restarter is worse than not tearing down."
  (setf (log-supervisor-running sup) nil)
  (let ((m (log-supervisor-monitor sup)))
    (when m
      (multiple-value-bind (r status) (dds.pal:join-bounded m :log-supervisor-monitor)
        (declare (ignore r))
        (when status (return-from log-supervisor-stop (values t status)))
        (setf (log-supervisor-monitor sup) nil))))
  (multiple-value-bind (ok status) (log-runner-stop (log-supervisor-runner sup))
    (declare (ignore ok))
    (values t status)))
