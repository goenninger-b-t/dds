(in-package #:dds.durability)

;;; Task 6+8 — multi-service runner: registry of N service-specs, started as durability-services.
;;; :thread mode (default): service runs in the host Lisp image (ADR 0021 cap. 1-2).
;;; :process mode (Task 8): service is launched via uiop:launch-program as a child SBCL
;;; invoking durability-service-main with %spec->argv-serialized CLI args (ADR 0021 cap. 5).

(defstruct* (service-runner (:constructor %make-service-runner))
  "Registry of N SERVICE-SPECs, each started as a DURABILITY-SERVICE in thread mode.
   The embedded library entity held by the host application (ADR 0021 capability 1).
   SPECS is the initial spec list; SERVICES is populated by RUNNER-START (NIL when stopped).
   STARTED is T between runner-start and runner-stop; guarded by LOCK to prevent double-start."
  (specs    nil   :type list)
  (services nil   :type list)
  (started  nil   :type t)
  (lock     (dds.pal:make-lock "dds-durability-runner") :type t))

(defun* make-service-runner (specs)
    (function (list) service-runner)
  "Construct a SERVICE-RUNNER from SPECS (a list of SERVICE-SPEC). Not started until RUNNER-START."
  (%make-service-runner :specs specs))

(defun* %process-mode-store-conveyable-p (spec)
    (function (service-spec) boolean)
  "T iff SPEC's store factory produces a store the :PROCESS CLI can HONESTLY reconstruct in the
   child. The durability CLI (%SPEC->ARGV / DURABILITY-SERVICE-MAIN) conveys ONLY the in-memory
   TRANSIENT tier (domain/topics/mode/name) — it does NOT serialize a file/DARE store factory
   (full factory serialization over argv is the recorded FEATURE follow-on, ADR 0026 §10.11). So a
   :memory store IS conveyable; any file/encrypted store is NOT. Probes by CONSTRUCTING the store,
   reading its NAME, then STORE-CLOSEing it (unwind-protect): construction MAY have side effects —
   a v1 encrypted store opens its key provider and derives a fresh DEK at construction — so the
   probed instance is always closed to release them (every built-in store's close is safe on a
   never-opened instance: memory/file closes are no-ops on empty state; encrypted closes free the
   DEK/provider idempotently). Used to FAIL-FAST a :process PERSISTENT spec rather than let it
   silently run the in-memory tier (looks durable, is not — the worst failure mode)."
  (let ((probe (funcall (service-spec-store spec))))
    (unwind-protect
         (eq (durable-store-name probe) :memory)
      (ignore-errors (store-close probe)))))

(defun* %start-process-service (spec)
    (function (service-spec) (values (or null durability-service) (or null keyword)))
  "Start a :PROCESS-mode service by launching a child Lisp invoking DURABILITY-SERVICE-MAIN.
   Returns a DURABILITY-SERVICE proxy whose THREAD slot is a monitor thread that tracks
   UIOP:PROCESS-ALIVE-P; SERVICE-ALIVE-P reflects the subprocess liveness transparently.
   The subprocess is launched via UIOP:LAUNCH-PROGRAM with %SPEC->ARGV-serialized CLI args.
   Non-SBCL impls fall back to in-thread mode with a note. On SBCL, a spec whose store cannot cross the
   subprocess boundary, or an unavailable UIOP:ARGV0, returns (VALUES NIL STATUS) —
   :PROCESS-MODE-NON-MEMORY-STORE or :NO-ARGV0 (ADR 0064: fail-fast as a status, the runner sheds the
   spec) — never an unwind. Success returns (VALUES PROXY NIL).
   Runtime dispatch on PAL-IMPL-NAME — no reader conditionals (operating contract §10)."
  (if (eq (dds.pal:pal-impl-name) :sbcl)
      (let* ((_conveyable
              (unless (%process-mode-store-conveyable-p spec)
                ;; FAIL-FAST: never launch a subprocess that would silently drop durability
                ;; (the CLI cannot convey a file/DARE store factory) — use :thread mode for the
                ;; PERSISTENT tier (ADR 0026 §10.11). Bailing a status here (ADR 0064) beats a
                ;; service that looks durable but is not; the runner sheds the spec.
                (bail :process-mode-non-memory-store)))
             (argv (dds.durability::%spec->argv spec))
             ;; ADR 0116: the flags are PER IMPLEMENTATION and the PAL owns them. This list used to be
             ;; written with SBCL's CLI inline — "--dynamic-space-size" and "--eval" — which AllegroCL
             ;; does not accept (it evaluates with -e and has no dynamic-space flag). A child handed
             ;; another implementation's flags does not report an error: it never starts, and the parent
             ;; waits for a service that will never come up, which STALLED THE WHOLE TEST SUITE there.
             (cmd  (dds.pal:lisp-eval-command
                    (list "(require :asdf)"
                          "(asdf:load-system :dds-durability)"
                          (format nil "(dds.durability:durability-service-main :argv ~s)" argv))))
             (_ (unless cmd (bail :no-argv0)))   ; ADR 0064: cannot launch a subprocess — the runner sheds the spec

             (proc  (uiop:launch-program cmd
                                         :output :interactive
                                         :error-output :interactive))
             (svc   (%make-durability-service :spec spec))
             (lock  (durability-service-lock svc)))
        (declare (ignore _ _conveyable))
        (dds.pal:with-lock (lock)
          (setf (durability-service-running svc) t))
        ;; monitor thread: polls subprocess liveness; flips running flag when process exits
        (let ((th (dds.pal:spawn
                   (lambda ()
                     (loop
                       (sleep 0.1)
                       (unless (dds.pal:with-lock (lock)
                                 (durability-service-running svc))
                         (return))
                       (unless (uiop:process-alive-p proc)
                         (dds.pal:with-lock (lock)
                           (setf (durability-service-running svc) nil))
                         (return))))
                   :name "dds-durability-process-monitor")))
          (dds.pal:with-lock (lock)
            (setf (durability-service-thread svc) th)))
        svc)
      (progn
        (format t "~&dds.durability runner: :process mode not available on ~a — starting in-thread~%"
                (dds.pal:pal-impl-name))
        (let ((svc (make-durability-service spec)))
          (multiple-value-bind (started st) (service-start svc)
            (declare (ignore started))
            (if st (values nil st) svc))))))

(defun* %stop-process-service (svc)
    (function (durability-service) (values (eql t) (or null keyword)))
  "Stop a :PROCESS-mode proxy service: clear the running flag, join the monitor thread — BOUNDED.
   The underlying subprocess will exit when its collect loop detects the parent gone or is killed.
   Returns (values T NIL), or (values T :TIMEOUT) if the monitor could not be proven stopped.

   The timeout is REPORTED and the caller PROCEEDS (ADR 0092): unlike the collect threads, this monitor
   only polls UIOP:PROCESS-ALIVE-P on a subprocess — it owns no store, no node and no static buffer, so
   there is nothing here whose free a live monitor could corrupt. Bounding it still matters: an unbounded
   join on a wedged monitor hangs runner teardown exactly as the UDP receiver hung stop-node."
  (let ((th nil) (status nil))
    (dds.pal:with-lock ((durability-service-lock svc))
      (setf (durability-service-running svc) nil)
      (setf th (durability-service-thread svc))
      (setf (durability-service-thread svc) nil))
    (when th
      (multiple-value-bind (r st) (dds.pal:join-bounded th :durability-process-service-monitor)
        (declare (ignore r))
        (setf status st)))
    (values t status)))

(defun* runner-start (runner)
    (function (service-runner) (values service-runner (or null keyword)))
  "Instantiate and start a DURABILITY-SERVICE for each spec in RUNNER.
   :THREAD mode: service runs in-image (ADR 0021 cap. 1).
   :PROCESS mode: subprocess launched via UIOP:LAUNCH-PROGRAM of this Lisp invoking
   DURABILITY-SERVICE-MAIN with %SPEC->ARGV CLI args; a monitor thread tracks liveness
   (ADR 0021 cap. 5).
   Concurrent or double-start is a no-op: the second call returns the runner unchanged.
   After runner-stop, the runner may be runner-started again (started flag is reset).
   Returns (VALUES RUNNER STATUS): STATUS is NIL on full success, or :SERVICE-START-FAILED if one or
   more specs failed to start. A tamper/corruption refusal at store-open (ADR 0045, a SECURITY-FAILCLOSED
   signal) — or any other per-spec start failure — is CAUGHT at this boundary (ADR 0064 rule 2: nothing
   escapes to the caller's thread), logged via *DURABILITY-ERROR-HOOK*, and the offending spec is SHED
   (not installed); the surviving specs run. The toplevel (DURABILITY-SERVICE-MAIN) maps a non-NIL STATUS
   to a fail-closed non-zero process exit."
  (let ((already nil))
    (dds.pal:with-lock ((service-runner-lock runner))
      (if (service-runner-started runner)
          (setf already t)
          (setf (service-runner-started runner) t)))
    (when already
      (warn "dds.durability runner: runner-start called on an already-started runner; ignoring.")   ; NOCOND(WARN): non-unwinding diagnostic; the runner is returned unchanged
      (return-from runner-start (values runner nil))))
  ;; Build and start services outside the lock (service-start spawns threads — slow). Each spec's start
  ;; is wrapped so a store-open tamper (or any start error) is contained here, not unwound to the caller.
  (let ((svcs '()) (failed nil))
    (dolist (spec (service-runner-specs runner))
      (if (eq (service-spec-mode spec) :process)
          (handler-case
              (multiple-value-bind (proxy st) (%start-process-service spec)
                (if st
                    (progn (setf failed t)
                           (ignore-errors (funcall *durability-error-hook* st :runner-start-failed 1)))
                    (push proxy svcs)))
            (error (c)
              (setf failed t)
              (ignore-errors (funcall *durability-error-hook* c :runner-start-failed 1))))
          (let ((s (make-durability-service spec)))
            (handler-case
                (multiple-value-bind (svc st) (service-start s)
                  (declare (ignore svc))
                  (if st
                      (progn (setf failed t)
                             (ignore-errors (service-stop s))
                             (ignore-errors (funcall *durability-error-hook* st :runner-start-failed 1)))
                      (push s svcs)))
              (error (c)
                (setf failed t)
                (ignore-errors (service-stop s))   ; reclaim a partially-started svc: close store, zeroize DEKs
                (ignore-errors (funcall *durability-error-hook* c :runner-start-failed 1)))))))
    (dds.pal:with-lock ((service-runner-lock runner))
      (setf (service-runner-services runner) (nreverse svcs)))
    (values runner (when failed :service-start-failed))))

(defun* %runner-stop-service (svc)
    (function (durability-service) t)
  "Stop SVC, choosing the appropriate stop path by inspecting its mode via its spec."
  (if (eq (service-spec-mode (durability-service-spec svc)) :process)
      (ignore-errors (%stop-process-service svc))
      (ignore-errors (service-stop svc)))
  t)

(defun* runner-stop (runner)
    (function (service-runner) (eql t))
  "Stop every DURABILITY-SERVICE held by RUNNER. Idempotent.
   After stopping, sets SERVICES to NIL and resets STARTED so the runner may be restarted.
   A repeat runner-stop on an already-stopped runner is a true zero-cost no-op."
  (let ((svcs nil))
    (dds.pal:with-lock ((service-runner-lock runner))
      (setf svcs (service-runner-services runner))
      (setf (service-runner-services runner) nil)
      (setf (service-runner-started runner) nil))
    (dolist (svc svcs)
      (%runner-stop-service svc)))
  t)

(defun* runner-status (runner)
    (function (service-runner) list)
  "Return a list of (name . alive-p) for each service in RUNNER."
  (let ((svcs nil))
    (dds.pal:with-lock ((service-runner-lock runner))
      (setf svcs (service-runner-services runner)))
    (mapcar (lambda (svc)
              (cons (service-spec-name (durability-service-spec svc))
                    (service-alive-p svc)))
            svcs)))
