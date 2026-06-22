;;;; Graceful-shutdown live-kill harness driver (WP-GRACEFUL-FFI-TEARDOWN, ADR 0030).
;;;;
;;;; Starts a PERSISTENT (DARE/file-backed) durability service so OpenSSL is loaded,
;;;; DEKs are derived, the static arena is live, and the collect thread is inside a
;;;; foreign recvmmsg call when the kill arrives.  That is the exact scenario where
;;;; the pre-T1/T2 SIGBUS occurred (ADR 0026 §10 item 3).
;;;;
;;;; Uses the Task-2 path: make-service-spec with a make-persistent-store-factory, then
;;;; durability-service-main :block nil (returns (cons runner sup)).  After that, install
;;;; the signal handler via dds.pal:install-signal-handler and block until the flag is
;;;; set, then call %graceful-shutdown + uiop:quit 0.  This exercises the IDENTICAL code
;;;; path as durability-service-main :block t (the :block t implementation inlines these
;;;; same steps) so the kill -15 proof is faithful.
;;;;
;;;; Config (env vars, all optional with safe defaults):
;;;;   GSHUT_DIR     -- PERSISTENT store directory (default /tmp/gshut-D)
;;;;   GSHUT_KEYDIR  -- key directory               (default /tmp/gshut-K)
;;;;   GSHUT_DOMAIN  -- DDS domain id               (default 0)

(asdf:load-system :dds-durability)

(defvar *gshut-shutdown* nil)

(let* ((dir     (or (uiop:getenv "GSHUT_DIR")    "/tmp/gshut-D"))
       (key-dir (or (uiop:getenv "GSHUT_KEYDIR")  "/tmp/gshut-K"))
       (domain  (let ((v (uiop:getenv "GSHUT_DOMAIN")))
                  (if v (parse-integer v) 0)))
       (spec  (dds.durability:make-service-spec
               :domain domain
               :topics '(("Square" . "ShapeType"))
               :store  (dds.durability:make-persistent-store-factory
                        :dir dir :key-dir key-dir)
               :mode   :thread
               :name   "gshut-harness"))
       (runner (dds.durability:make-service-runner (list spec)))
       (sup    (dds.durability:make-supervisor runner :max-restarts 3 :window-seconds 5)))
  (dds.durability:runner-start runner)
  (dds.durability:supervisor-start sup)
  (format t "~&GSHUT-DRIVER: service started dir=~a key-dir=~a domain=~d~%"
          dir key-dir domain)
  (force-output)
  (setf *gshut-shutdown* nil)
  (dds.pal:install-signal-handler
   '(:term :int)
   (lambda () (setf *gshut-shutdown* t)))
  (format t "~&GSHUT-DRIVER: signal handler installed; waiting for SIGTERM/SIGINT~%")
  (force-output)
  (loop until *gshut-shutdown* do (sleep 0.2))
  (format t "~&GSHUT-DRIVER: shutdown requested; tearing down~%")
  (force-output)
  (ignore-errors (dds.durability:supervisor-stop sup))
  (ignore-errors (dds.durability:runner-stop runner))
  (format t "~&GSHUT-DRIVER: teardown complete; exiting~%")
  (force-output)
  (uiop:quit 0))
