(in-package #:dds.durability)

;;; Task 7 — OTP-style one-for-one supervisor with restart-intensity cap (ADR 0021 cap. 4).
;;; Monitors each running service via SERVICE-ALIVE-P on a dedicated watcher thread;
;;; on a death, restarts the service from its SPEC (same spec, fresh instance) unless
;;; the restart-intensity cap (MAX-RESTARTS in WINDOW-SECONDS) is exceeded, in which
;;; case the service is marked SHED and *DURABILITY-ERROR-HOOK* is fired with :SUPERVISOR-SHED.
;;; Uses standard CL GET-INTERNAL-REAL-TIME (allowed on the control-plane; NOT restricted hot-path).
;;; Restart semantics: OTP permanent — any termination (crash OR deliberate service-stop) triggers
;;; a restart; the cap bounds pathological crash-loops. To stop a service permanently, stop the
;;; supervisor (or the runner), never call service-stop on an individually supervised service.

;;; --- pure restart-intensity helper (unit-testable without threads) ---

(defun* %restart-allowed-p (timestamps now window-seconds max-restarts)
    (function (list integer integer integer) boolean)
  "T iff another restart is permitted under the restart-intensity policy.
   TIMESTAMPS is a list of GET-INTERNAL-REAL-TIME values of prior restarts.
   NOW is the current GET-INTERNAL-REAL-TIME value.
   WINDOW-SECONDS and MAX-RESTARTS define the cap: count restarts within
   [NOW - WINDOW-SECONDS * INTERNAL-TIME-UNITS-PER-SECOND, NOW]; allow iff count < MAX-RESTARTS."
  (let* ((itu    internal-time-units-per-second)
         (cutoff (- now (* window-seconds itu)))
         (in-win (count-if (lambda (ts) (>= ts cutoff)) timestamps)))
    (< in-win max-restarts)))

;;; --- supervisor struct ---

(defstruct* (supervisor (:constructor %make-supervisor))
  "OTP-style one-for-one supervisor for a SERVICE-RUNNER.
   Watches each service's ALIVE-P on a watcher thread; restarts dead services unless
   RESTART-INTENSITY (MAX-RESTARTS in WINDOW-SECONDS) is exceeded, in which case the service
   is added to the SHED set and *DURABILITY-ERROR-HOOK* is fired with :SUPERVISOR-SHED.
   Restart semantics: OTP permanent — a supervised service that terminates for ANY reason
   (crash or deliberate service-stop) is restarted until the restart-intensity cap sheds it.
   To stop a single service permanently, stop the supervisor or the runner instead."
  (runner         nil :type (or null service-runner))
  (max-restarts   3   :type (integer 0))
  (window-seconds 5   :type (integer 1))
  (poll-ms        50  :type (integer 1))
  ;; restart-history: alist of (name . list-of-timestamps)
  (history        nil :type list)
  ;; shed: hash-table of name → T for services that hit the intensity cap
  (shed           (make-hash-table :test #'equal) :type hash-table)
  (lock           (dds.pal:make-lock "dds-durability-supervisor") :type t)
  (running        nil :type t)
  (thread         nil :type t))

(defun* make-supervisor (runner &key (max-restarts 3) (window-seconds 5) (poll-ms 50))
    (function (service-runner &key (:max-restarts integer)
                                   (:window-seconds integer)
                                   (:poll-ms integer))
              supervisor)
  "Construct a SUPERVISOR for RUNNER. Not started until SUPERVISOR-START.
   MAX-RESTARTS and WINDOW-SECONDS define the restart-intensity cap (one-for-one).
   POLL-MS is the watcher thread's service liveness poll interval."
  (%make-supervisor :runner runner
                    :max-restarts max-restarts
                    :window-seconds window-seconds
                    :poll-ms poll-ms))

;;; --- internal helpers ---

(defun* %supervisor-history-add (sup name ts)
    (function (supervisor string integer) t)
  "Append restart timestamp TS to the history list for NAME in SUP (caller holds SUP lock)."
  (let ((entry (assoc name (supervisor-history sup) :test #'equal)))
    (if entry
        (setf (cdr entry) (cons ts (cdr entry)))
        (setf (supervisor-history sup)
              (cons (cons name (list ts)) (supervisor-history sup)))))
  t)

(defun* %supervisor-history-for (sup name)
    (function (supervisor string) list)
  "Return the list of restart timestamps for NAME (caller holds SUP lock), or NIL."
  (let ((entry (assoc name (supervisor-history sup) :test #'equal)))
    (if entry (cdr entry) nil)))

(defun* %supervisor-shed! (sup name)
    (function (supervisor string) t)
  "Mark service NAME as shed in SUP (caller holds SUP lock)."
  (setf (gethash name (supervisor-shed sup)) t))

(defun* %supervisor-shed-p-locked (sup name)
    (function (supervisor string) boolean)
  "T iff NAME is in the shed set (caller holds SUP lock)."
  (if (gethash name (supervisor-shed sup)) t nil))

(defun* %supervisor-replace-service (runner old-svc new-svc)
    (function (service-runner durability-service durability-service) t)
  "Replace OLD-SVC with NEW-SVC in RUNNER's services list (under RUNNER lock)."
  (dds.pal:with-lock ((service-runner-lock runner))
    (setf (service-runner-services runner)
          (mapcar (lambda (s) (if (eq s old-svc) new-svc s))
                  (service-runner-services runner))))
  t)

(defun* %supervisor-fire-shed-hook (svc)
    (function (durability-service) t)
  "Fire *DURABILITY-ERROR-HOOK* with :SUPERVISOR-SHED context for SVC."
  (ignore-errors
   (funcall *durability-error-hook*
            (make-condition 'simple-error
                            :format-control "dds.durability supervisor: service ~s shed (restart-intensity exceeded)"
                            :format-arguments (list (service-spec-name (durability-service-spec svc))))
            :supervisor-shed
            1))
  t)

(defun* %supervisor-restart-service (sup svc)
    (function (supervisor durability-service) t)
  "Attempt to restart SVC under the restart-intensity policy.
   The restart timestamp is recorded BEFORE service-start so that a fault-induced immediate
   death still counts toward the intensity cap. If the cap is exceeded on this attempt, shed
   the service and fire *DURABILITY-ERROR-HOOK* (:SUPERVISOR-SHED)."
  (let* ((spec   (durability-service-spec svc))
         (name   (service-spec-name spec))
         (runner (supervisor-runner sup))
         (now    (get-internal-real-time))
         (action nil))   ; :restart | :shed | :already-shed
    (dds.pal:with-lock ((supervisor-lock sup))
      (cond
        ((%supervisor-shed-p-locked sup name)
         (setf action :already-shed))
        ((%restart-allowed-p (%supervisor-history-for sup name) now
                             (supervisor-window-seconds sup)
                             (supervisor-max-restarts sup))
         ;; record the timestamp BEFORE attempting start (counts even if start fails)
         (%supervisor-history-add sup name now)
         (setf action :restart))
        (t
         (%supervisor-shed! sup name)
         (setf action :shed))))
    (ecase action
      (:restart
       (let ((new-svc (make-durability-service spec)))
         (handler-case
             (progn
               (service-start new-svc)
               ;; Orphan guard: recheck running AFTER start, BEFORE install.
               ;; If supervisor-stop flipped running NIL during the (slow) service-start,
               ;; stop the just-started service immediately and do not install it.
               (let ((still-running nil))
                 (dds.pal:with-lock ((supervisor-lock sup))
                   (setf still-running (supervisor-running sup)))
                 (if still-running
                     (%supervisor-replace-service runner svc new-svc)
                     (ignore-errors (service-stop new-svc)))))
           (error (c)
             ;; start failed; new-svc is dead — watcher will pick it up on next poll
             ;; and decrement the cap further; just log this attempt
             (ignore-errors
              (funcall *durability-error-hook* c :supervisor-restart-failed 1))
             ;; replace anyway so watcher references the new (dead) svc next cycle
             (%supervisor-replace-service runner svc new-svc)))))
      (:shed
       (%supervisor-fire-shed-hook svc))
      (:already-shed
       nil))
    t))

;;; --- watcher loop ---

(defun* %supervisor-watch-loop (sup)
    (function (supervisor) t)
  "Watcher thread body: polls each service in RUNNER every POLL-MS milliseconds.
   On a dead service (ALIVE-P → NIL) that is not yet shed, attempts a restart via
   %SUPERVISOR-RESTART-SERVICE. Exits when RUNNING is set to NIL by SUPERVISOR-STOP."
  (let ((poll-s (/ (supervisor-poll-ms sup) 1000.0d0)))
    (loop
      (unless (dds.pal:with-lock ((supervisor-lock sup))
                (supervisor-running sup))
        (return))
      (let ((runner (supervisor-runner sup))
            (svcs nil))
        (dds.pal:with-lock ((service-runner-lock runner))
          (setf svcs (copy-list (service-runner-services runner))))
        (dolist (svc svcs)
          (unless (service-alive-p svc)
            (let* ((spec (durability-service-spec svc))
                   (name (service-spec-name spec))
                   (shed-p (dds.pal:with-lock ((supervisor-lock sup))
                              (%supervisor-shed-p-locked sup name))))
              (unless shed-p
                (ignore-errors (%supervisor-restart-service sup svc)))))))
      (sleep poll-s)))
  t)

;;; --- public API ---

(defun* supervisor-start (supervisor)
    (function (supervisor) supervisor)
  "Spawn the watcher thread for SUPERVISOR. Idempotent if already running.
   Restart semantics are OTP permanent: any service termination (crash or app service-stop)
   triggers a restart until the restart-intensity cap sheds the service. To stop a supervised
   service permanently, call supervisor-stop (or runner-stop), not service-stop directly."
  (dds.pal:with-lock ((supervisor-lock supervisor))
    (unless (supervisor-running supervisor)
      (setf (supervisor-running supervisor) t)
      (let ((th (dds.pal:spawn (lambda () (%supervisor-watch-loop supervisor))
                               :name "dds-durability-supervisor")))
        (setf (supervisor-thread supervisor) th))))
  supervisor)

(defun* supervisor-stop (supervisor)
    (function (supervisor) (eql t))
  "Signal the watcher thread to stop and join it. Idempotent."
  (let ((th nil))
    (dds.pal:with-lock ((supervisor-lock supervisor))
      (setf (supervisor-running supervisor) nil)
      (setf th (supervisor-thread supervisor))
      (setf (supervisor-thread supervisor) nil))
    (when th
      (ignore-errors (dds.pal:join th))))
  t)

(defun* supervisor-shed-p (supervisor name)
    (function (supervisor string) boolean)
  "T iff the service named NAME has been shed by this SUPERVISOR (restart-intensity exceeded)."
  (dds.pal:with-lock ((supervisor-lock supervisor))
    (%supervisor-shed-p-locked supervisor name)))
