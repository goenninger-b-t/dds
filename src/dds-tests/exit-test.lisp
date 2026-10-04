;;;; ADR 0121 — dds.pal:exit-process and its shutdown-hook chain.
;;;;
;;;;  run-exit-hook-chain-test      IN PROCESS: the chain mechanics on synthetic hooks (LIFO, per-hook guard,
;;;;                                status-as-failure, register/replace/unregister) and the four resource
;;;;                                registries the built-in hooks read. It never runs a built-in hook here:
;;;;                                that would wipe, unlink and sync THIS image's live state.
;;;;  run-exit-process-subprocess-test  THREE CHILD PROCESSES of this same Lisp (dds.pal:lisp-eval-command),
;;;;                                run one at a time, each of which can only end cleanly through the chain:
;;;;                                  DIRECT     — a thread parked in read(2), then exit-process 3
;;;;                                  WEDGED     — a hook that never returns, chain bounded at 2 s
;;;;                                  DURABILITY — the real durability-service-main, stopped with SIGTERM
;;;;                                The bodies live in exit-child.lisp, which the child LOADs.

(in-package #:dds.tests)

;;; ---- in process ----

(defun* run-exit-hook-chain-test ()
    (function () (eql t))
  "ADR 0121, in process. (1) DDS.PAL::%RUN-HOOK-CHAIN runs every entry in list order; an entry that signals
   and an entry that returns a non-NIL second value both FAIL, are reported on the stream, and do not stop
   the entries after them. (2) REGISTER-SHUTDOWN-HOOK is LIFO, re-registration replaces in place, and
   UNREGISTER-SHUTDOWN-HOOK reports whether it removed anything. (3) The four built-in hooks are registered
   and the PAL's runs last. (4) Each registry a built-in hook reads tracks its resource exactly from creation
   to release: shm names (SHM-CREATE / SHM-DESTROY), secrets (OCTETS->SECRET / FREE-SECRET-OCTETS), open
   stores (STORE-OPEN / STORE-CLOSE) and sink streams (MAKE-STREAM-SINK / CLOSE-SINK)."
  ;; (1) the chain
  (let* ((trace '())
         (entries (list (cons :h-a (lambda () (push :a trace) t))
                        (cons :h-b (lambda () (push :b trace) (error "hook b exploded")))
                        (cons :h-c (lambda () (push :c trace) (values nil :c-failed)))
                        (cons :h-d (lambda () (push :d trace) (values 4 nil)))))
         (report (make-string-output-stream)))
    (multiple-value-bind (ran failed) (dds.pal::%run-hook-chain entries report)
      (let ((text (get-output-stream-string report)))
        (%check :chain-order (equal (reverse trace) '(:a :b :c :d))
                (format nil "every hook must run, in list order, even after a failure; ran ~s" (reverse trace)))
        (%check :chain-ran (equal ran '(:h-a :h-d))
                (format nil "RAN must be exactly the hooks that succeeded, in order; got ~s" ran))
        (%check :chain-failed (equal failed '(:h-b :h-c))
                (format nil "a signal AND a non-NIL second value must both count as failure; got ~s" failed))
        (%check :chain-reported (and (search ":H-B" text) (search "exploded" text)
                                     (search ":H-C" text) (search ":C-FAILED" text))
                (format nil "each failure must be reported with its name and cause; report was ~s" text)))))
  ;; (2) registration
  (unwind-protect
       (progn
         (dds.pal:register-shutdown-hook :test-exit-x1 (lambda () t))
         (dds.pal:register-shutdown-hook :test-exit-x2 (lambda () t))
         (%check :register-lifo
                 (equal (subseq (dds.pal:shutdown-hook-names) 0 2) '(:test-exit-x2 :test-exit-x1))
                 (format nil "the newest hook must run first; names ~s" (dds.pal:shutdown-hook-names)))
         (let ((n (length (dds.pal:shutdown-hook-names))))
           (dds.pal:register-shutdown-hook :test-exit-x1 (lambda () nil))
           (%check :register-replace
                   (and (= n (length (dds.pal:shutdown-hook-names)))
                        (equal (subseq (dds.pal:shutdown-hook-names) 0 2) '(:test-exit-x2 :test-exit-x1)))
                   "re-registering a name must replace it in place: same count, same position"))
         (%check :unregister-t (eq t (dds.pal:unregister-shutdown-hook :test-exit-x1))
                 "unregistering a registered hook must answer T")
         (%check :unregister-nil (null (dds.pal:unregister-shutdown-hook :test-exit-x1))
                 "unregistering an absent hook must answer NIL"))
    (dds.pal:unregister-shutdown-hook :test-exit-x1)
    (dds.pal:unregister-shutdown-hook :test-exit-x2))
  (%check :no-test-hooks-left
          (notany (lambda (n) (member n '(:test-exit-x1 :test-exit-x2))) (dds.pal:shutdown-hook-names))
          "the test must leave no hook of its own registered")
  ;; (3) the built-in hooks
  (let ((names (dds.pal:shutdown-hook-names)))
    (dolist (h '(:pal-shm-unlink :dare-secret-wipe :durability-store-sync :log-sink-flush))
      (%check :builtin-hook-registered (member h names)
              (format nil "built-in shutdown hook ~s must be registered; have ~s" h names)))
    (%check :pal-hook-last (eq :pal-shm-unlink (car (last names)))
            (format nil "the PAL's hook is registered first, so it must run LAST; order ~s" names)))
  ;; (4) the registries
  (let ((name (format nil "/ddsxreg~x" (dds.pal:process-id))))
    (multiple-value-bind (seg status) (dds.pal:shm-create name 4096)
      (%check :reg-shm-created (and seg (null status)) (format nil "shm-create ~a: ~s" name status))
      (unwind-protect
           (%check :reg-shm-owned (member name (dds.pal::%owned-shm-names) :test #'string=)
                   "a created segment must be in the owned-shm registry")
        (when seg (dds.pal:shm-detach seg))
        (dds.pal:shm-destroy name))
      (%check :reg-shm-released (not (member name (dds.pal::%owned-shm-names) :test #'string=))
              "shm-destroy must remove the name from the owned-shm registry")))
  (let ((v (dds.dare:octets->secret (make-array 8 :element-type '(unsigned-byte 8) :initial-element 7))))
    (%check :reg-secret-live (gethash v dds.dare::*live-secrets*)
            "a new secret buffer must be in the live-secret registry")
    (dds.dare:free-secret-octets v)
    (%check :reg-secret-released (not (gethash v dds.dare::*live-secrets*))
            "free-secret-octets must remove the buffer from the live-secret registry"))
  (let ((st (dds.durability:make-memory-store)))
    (dds.durability:store-open st)
    (%check :reg-store-open (gethash st dds.durability::*open-stores*)
            "an opened store must be in the open-store registry")
    (dds.durability:store-close st)
    (%check :reg-store-closed (not (gethash st dds.durability::*open-stores*))
            "store-close must remove the store from the open-store registry"))
  (let* ((s (make-string-output-stream))
         (sink (dds.log:make-stream-sink s)))
    (%check :reg-sink-live (gethash s dds.log::*live-sink-streams*)
            "a stream sink's stream must be in the live-sink registry")
    (dds.log:close-sink sink)
    (%check :reg-sink-closed (not (gethash s dds.log::*live-sink-streams*))
            "close-sink must remove the stream from the live-sink registry"))
  t)

;;; ---- child processes ----

(defstruct* (exit-child (:constructor %make-exit-child))
  "One exit-process test child: its SCENARIO keyword, the UIOP process-info, its stdout/stderr files, and
   the shm object name it planted."
  (scenario nil :type keyword)
  (process nil :type t)
  (out nil :type t)
  (err nil :type t)
  (shm "" :type string))

(defun* %exit-child-launch (scenario call dir shm)
    (function (keyword string pathname string) (or null exit-child))
  "Start a child of this same Lisp that loads :DDS-DURABILITY, LOADs exit-child.lisp and evaluates CALL (a
   form, as a string, in that file's package). Its stdout and stderr go to files under DIR. NIL when this
   image cannot name its own binary (DDS.PAL:LISP-EVAL-COMMAND answers NIL)."
  (let* ((child-src (namestring (asdf:system-relative-pathname :dds-tests "src/dds-tests/exit-child.lisp")))
         (cmd (dds.pal:lisp-eval-command
               (list "(require :asdf)"
                     "(asdf:load-system :dds-durability)"
                     (format nil "(load ~s)" child-src)
                     (format nil "(let ((*package* (find-package \"NET.GOENNINGER.DDS.EXIT-CHILD\"))) (eval (read-from-string ~s)))"
                             call))))
         (out (merge-pathnames (format nil "~(~a~).out" scenario) dir))
         (err (merge-pathnames (format nil "~(~a~).err" scenario) dir)))
    (when cmd
      (%make-exit-child :scenario scenario :shm shm :out out :err err
                        :process (uiop:launch-program cmd :output out :if-output-exists :supersede
                                                          :error-output err :if-error-output-exists :supersede)))))

(defun* %exit-child-text (child)
    (function (exit-child) string)
  "The child's stdout so far (empty when the file does not exist yet)."
  (or (ignore-errors (uiop:read-file-string (exit-child-out child))) ""))

(defun* %exit-child-await-line (child marker seconds)
    (function (exit-child string real) t)
  "Poll the child's stdout until a line containing MARKER appears (T), the child exits first (NIL), or
   SECONDS pass (NIL)."
  (let ((deadline (+ (get-internal-real-time) (* seconds internal-time-units-per-second))))
    (loop
      (when (search marker (%exit-child-text child)) (return t))
      (unless (uiop:process-alive-p (exit-child-process child))
        (return (and (search marker (%exit-child-text child)) t)))
      (when (> (get-internal-real-time) deadline) (return nil))
      (sleep 0.2))))

(defun* %exit-child-await-exit (child seconds)
    (function (exit-child real) (values (or null integer) real))
  "Wait up to SECONDS for the child to end. (VALUES EXIT-CODE ELAPSED-SECONDS); EXIT-CODE is NIL when it
   was still alive at the deadline, in which case it is KILLed (so the suite never inherits it)."
  (let* ((t0 (get-internal-real-time))
         (deadline (+ t0 (* seconds internal-time-units-per-second)))
         (p (exit-child-process child)))
    (loop while (and (uiop:process-alive-p p) (< (get-internal-real-time) deadline))
          do (sleep 0.1))
    (let ((elapsed (/ (- (get-internal-real-time) t0) internal-time-units-per-second)))
      (if (uiop:process-alive-p p)
          (progn (ignore-errors (uiop:terminate-process p :urgent t))
                 (ignore-errors (uiop:wait-process p))
                 (values nil elapsed))
          (values (uiop:wait-process p) elapsed)))))

(defun* %shm-gone-p (name)
    (function (string) t)
  "T iff no shm object NAME exists any more, i.e. SHM-ATTACH cannot open and map it (every object these
   tests plant is 4096 octets, mode 0600, owned by this uid, so an existing one always attaches). Any
   failure status counts as gone, not only :SHM-OPEN-FAILED: on AllegroCL a failed shm_open's -1 currently
   comes back from CFFI as 4294967295 (the :INT sign-extension defect, governing plan §1), so the attach
   fails one step later with :MMAP-FAILED. If the object DOES still exist, the test detaches and unlinks it
   so a failure here leaks nothing."
  (let ((seg (dds.pal:shm-attach name 4096)))
    (if seg
        (progn (dds.pal:shm-detach seg) (dds.pal:shm-destroy name) nil)
        t)))

(defun* %readback-ok-p (text)
    (function (string) t)
  "T iff TEXT has a read-back of the planted 32-octet secret that is all zero, and no non-zero read-back."
  (and (search "WIPE-READBACK len=32 zero=T" text)
       (not (search "zero=NIL" text))))

(defun* %exit-child-owned-names (child)
    (function (exit-child) list)
  "The shm object names a DURABILITY child reported on its 'SHM-OWNED <names...>' line, or NIL."
  (let* ((text (%exit-child-text child))
         (p (search "SHM-OWNED" text))
         (line (and p (subseq text p (or (position #\Newline text :start p) (length text))))))
    (and line (remove "" (rest (uiop:split-string line :separator " ")) :test #'string=))))

(defun* %exit-child-reap (child)
    (function (exit-child) (eql t))
  "Failure-path cleanup for one child: if it is still alive, SIGTERM it and give it 30 s to take the orderly
   path (whose hooks unlink its segments), KILL it after that; then unlink its planted shm object and every
   name it reported owning, so a failed run leaves nothing in the shm namespace."
  (when (uiop:process-alive-p (exit-child-process child))
    (ignore-errors (uiop:terminate-process (exit-child-process child)))
    (%exit-child-await-exit child 30))
  (%shm-gone-p (exit-child-shm child))
  (dolist (n (%exit-child-owned-names child)) (%shm-gone-p n))
  t)

(defun* run-exit-process-subprocess-test ()
    (function () (eql t))
  "ADR 0121, end to end, on whichever implementation runs the suite (SBCL or AllegroCL), in three child
   processes of that same implementation, run ONE AT A TIME: on AllegroCL each child recompiles part of the
   tree on load, and three concurrent children racing on the same fasl names made one fail its load
   (realpath ENOENT), measured in a full AllegroCL run.
     DIRECT     a secret and an shm object are planted and never released, a thread is parked in read(2),
                then (dds.pal:exit-process 3). Must exit with 3 within 30 s of its last line (the old
                unwinding exit hung forever on this on AllegroCL), the read-back must show the secret wiped
                to zeros, and the shm object must be gone.
     WEDGED     a hook that never returns is registered last (so it runs first) with the chain bounded at
                2 s, then (dds.pal:exit-process 0). Must exit with 70 (+EXIT-SHUTDOWN-INCOMPLETE+, not 0)
                within 30 s, and say on stderr that the hooks overran.
     DURABILITY the real DURABILITY-SERVICE-MAIN, plus a planted secret and shm object, is sent SIGTERM once
                it prints DURABILITY-SERVICE-READY. Must exit with 0 within 60 s; the planted secret must be
                wiped, and the planted segment AND every segment the service's participant created must
                be gone.
   Whatever fails, no child outlives the test and no planted or reported shm object is left behind."
  (let* ((dir (uiop:ensure-directory-pathname
               (merge-pathnames (format nil "dds-exit-test-~d/" (dds.pal:process-id))
                                (uiop:temporary-directory))))
         (pid (dds.pal:process-id))
         (children '()))
    (ensure-directories-exist dir)
    (flet ((launch (scenario fn-name shm &rest more)
             (let ((c (%exit-child-launch scenario
                                          (format nil "(~a ~s~{ ~s~})" fn-name shm more)
                                          dir shm)))
               (%check :exit-child-launched c
                       "this image must be able to launch a child of itself (dds.pal:lisp-eval-command)")
               (push c children)
               c))
           (stderr (c) (or (ignore-errors (uiop:read-file-string (exit-child-err c))) "")))
      (unwind-protect
           (progn
             ;; DIRECT
             (let ((direct (launch :direct "child-direct" (format nil "/ddsxitd~x" pid))))
               (%check :exit-direct-reached (%exit-child-await-line direct "CHILD-EXITING" 300)
                       (format nil "the DIRECT child must reach its exit; stdout:~%~a~%stderr:~%~a"
                               (%exit-child-text direct) (stderr direct)))
               (multiple-value-bind (code secs) (%exit-child-await-exit direct 30)
                 (let ((text (%exit-child-text direct)))
                   (%check :exit-direct-code (eql code 3)
                           (format nil "DIRECT must exit with 3 within 30 s (a parked foreign thread must not hang the exit); code ~s after ~,1f s~%~a"
                                   code secs text))
                   (%check :exit-direct-wiped (%readback-ok-p text)
                           (format nil "DIRECT: the planted secret must be read back all-zero by the exit chain:~%~a" text))
                   (%check :exit-direct-unlinked (%shm-gone-p (exit-child-shm direct))
                           (format nil "DIRECT: the planted shm object ~a must be unlinked by the exit chain; stdout:~%~a~%stderr:~%~a"
                                   (exit-child-shm direct) text (stderr direct))))))
             ;; WEDGED
             (let ((wedged (launch :wedged "child-wedged" (format nil "/ddsxitw~x" pid))))
               (%check :exit-wedged-reached (%exit-child-await-line wedged "CHILD-EXITING" 300)
                       (format nil "the WEDGED child must reach its exit; stdout:~%~a~%stderr:~%~a"
                               (%exit-child-text wedged) (stderr wedged)))
               (multiple-value-bind (code secs) (%exit-child-await-exit wedged 30)
                 (%check :exit-wedged-code (eql code dds.pal:+exit-shutdown-incomplete+)
                         (format nil "WEDGED must be ended by the watchdog with ~d within 30 s; code ~s after ~,1f s"
                                 dds.pal:+exit-shutdown-incomplete+ code secs))
                 (%check :exit-wedged-reported (search "overran" (stderr wedged))
                         (format nil "WEDGED: the watchdog must say so on stderr; stderr:~%~a" (stderr wedged)))))
             ;; DURABILITY
             (let ((dur (launch :durability "child-durability" (format nil "/ddsxitc~x" pid)
                                (test-domain +td-exit-process+))))
               (%check :exit-durability-ready (%exit-child-await-line dur "DURABILITY-SERVICE-READY" 300)
                       (format nil "the durability child must print DURABILITY-SERVICE-READY; stdout:~%~a~%stderr:~%~a"
                               (%exit-child-text dur) (stderr dur)))
               (%check :exit-durability-owned (%exit-child-await-line dur "SHM-OWNED" 60)
                       (format nil "the durability child must report its shm segments; stdout:~%~a" (%exit-child-text dur)))
               (uiop:terminate-process (exit-child-process dur))   ; SIGTERM: 15 (bits/signum-generic.h:53)
               (multiple-value-bind (code secs) (%exit-child-await-exit dur 60)
                 (let ((text (%exit-child-text dur))
                       (names (%exit-child-owned-names dur)))
                   (%check :exit-durability-code (eql code 0)
                           (format nil "the SIGTERMed durability service must exit 0 within 60 s; code ~s after ~,1f s~%~a~%stderr:~%~a"
                                   code secs text (stderr dur)))
                   (%check :exit-durability-wiped (%readback-ok-p text)
                           (format nil "DURABILITY: the planted secret must be read back all-zero:~%~a" text))
                   (%check :exit-durability-names (>= (length names) 2)
                           (format nil "DURABILITY: expected the planted and the participant's segment; got ~s" names))
                   (dolist (n names)
                     (%check :exit-durability-unlinked (%shm-gone-p n)
                             (format nil "DURABILITY: shm object ~a must be gone after SIGTERM" n)))))))
        ;; never leave a child or a planted object behind, whatever failed above
        (dolist (c children) (ignore-errors (%exit-child-reap c)))
        (ignore-errors (uiop:delete-directory-tree dir :validate t)))))
  t)
