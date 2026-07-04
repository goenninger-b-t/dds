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
    (function (service-spec) durability-service)
  "Start a :PROCESS-mode service by launching a child Lisp invoking DURABILITY-SERVICE-MAIN.
   Returns a DURABILITY-SERVICE proxy whose THREAD slot is a monitor thread that tracks
   UIOP:PROCESS-ALIVE-P; SERVICE-ALIVE-P reflects the subprocess liveness transparently.
   The subprocess is launched via UIOP:LAUNCH-PROGRAM with %SPEC->ARGV-serialized CLI args.
   On impls where UIOP:ARGV0 is unavailable or empty, falls back to in-thread mode with a note.
   Runtime dispatch on PAL-IMPL-NAME — no reader conditionals (operating contract §10)."
  (if (eq (dds.pal:pal-impl-name) :sbcl)
      (let* ((_conveyable
              (unless (%process-mode-store-conveyable-p spec)
                ;; FAIL-FAST: never launch a subprocess that would silently drop durability
                ;; (the CLI cannot convey a file/DARE store factory) — use :thread mode for the
                ;; PERSISTENT tier (ADR 0026 §10.11). Erroring here beats a service that looks
                ;; durable but is not.
                (error "dds.durability: :process-mode service ~s is configured with a non-memory ~
                        (persistent/file) store, which the CLI cannot convey across the subprocess ~
                        boundary — launching would SILENTLY run the in-memory tier (no durability). ~
                        Use :thread mode for the PERSISTENT tier (ADR 0026 §10.11)."
                       (service-spec-name spec))))
             (argv (dds.durability::%spec->argv spec))
             (lisp-bin (uiop:argv0))
             (_ (unless (and lisp-bin (plusp (length lisp-bin)))
                  (error "dds.durability: (uiop:argv0) returned nil/empty — cannot launch subprocess")))
             (cmd  (list* lisp-bin
                          "--dynamic-space-size" "512"
                          "--eval" "(require :asdf)"
                          "--eval" (format nil "(asdf:load-system :dds-durability)")
                          "--eval" (format nil "(dds.durability:durability-service-main :argv ~s)"
                                           argv)
                          '()))
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
          (service-start svc)
          svc))))

(defun* %stop-process-service (svc)
    (function (durability-service) (eql t))
  "Stop a :PROCESS-mode proxy service: clear the running flag, join the monitor thread.
   The underlying subprocess will exit when its collect loop detects the parent gone or is killed."
  (let ((th nil))
    (dds.pal:with-lock ((durability-service-lock svc))
      (setf (durability-service-running svc) nil)
      (setf th (durability-service-thread svc))
      (setf (durability-service-thread svc) nil))
    (when th
      (ignore-errors (dds.pal:join th))))
  t)

(defun* runner-start (runner)
    (function (service-runner) service-runner)
  "Instantiate and start a DURABILITY-SERVICE for each spec in RUNNER.
   :THREAD mode: service runs in-image (ADR 0021 cap. 1).
   :PROCESS mode: subprocess launched via UIOP:LAUNCH-PROGRAM of this Lisp invoking
   DURABILITY-SERVICE-MAIN with %SPEC->ARGV CLI args; a monitor thread tracks liveness
   (ADR 0021 cap. 5).
   Concurrent or double-start is a no-op: the second call returns the runner unchanged.
   After runner-stop, the runner may be runner-started again (started flag is reset)."
  (let ((already nil))
    (dds.pal:with-lock ((service-runner-lock runner))
      (if (service-runner-started runner)
          (setf already t)
          (setf (service-runner-started runner) t)))
    (when already
      (warn "dds.durability runner: runner-start called on an already-started runner; ignoring.")
      (return-from runner-start runner)))
  ;; Build and start services outside the lock (service-start spawns threads — slow).
  (let ((svcs '()))
    (dolist (spec (service-runner-specs runner))
      (let ((svc (if (eq (service-spec-mode spec) :process)
                     (%start-process-service spec)
                     (let ((s (make-durability-service spec)))
                       (service-start s)
                       s))))
        (push svc svcs)))
    (dds.pal:with-lock ((service-runner-lock runner))
      (setf (service-runner-services runner) (nreverse svcs))))
  runner)

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
