;;;; MICROSERVICE durability backend — the SERVER PROCESS (ADR 0050 §4.8, the live 2-process capstone).
;;;;
;;;; A standalone reference microservice server (make-microservice-server) over a PERSISTENT, DARE-BLIND
;;;; file inner store, run as its OWN OS process so the microservice backend is exercised process-to-process
;;;; (not just in one Lisp image). The server is DARE-BLIND: it stores OPAQUE frames (topic-hash surrogate,
;;;; 16-byte GUID surrogate, sn=0, sealed∥mac∥chain_seq blob); the CLIENT processes (driver-ms-client.lisp)
;;;; hold the DARE key + the log-MAC chain in their LOCAL epoch-dir/key-dir and wrap every record encrypted.
;;;; So the server's inner is a plain make-file-store — NO encryption, NO key — opened KEEP_ALL (the
;;;; encrypted-store decorator owns retention end-to-end; the server must stay KEEP_ALL, ADR 0050 §4.2).
;;;;
;;;; Lifecycle: bind the FIXED port, open the persistent inner (replays prior frames from disk across a
;;;; restart), log "MS-SERVER-LISTENING port=P" (the harness readiness signal), BLOCK until SIGTERM/SIGINT,
;;;; then microservice-server-stop (the clean §4.8 tcp-shutdown wake → join serve threads → fsync the inner)
;;;; and log "MS-SERVER-STOPPED". Mirrors driver-serve.lisp's env/log/quit shape + durability-service-main's
;;;; signal-driven block-until-teardown.
;;;;
;;;; Config (env vars): DPERSIST_MS_PORT (REQUIRED, the fixed listen port), DPERSIST_MS_INNER (REQUIRED, the
;;;; server-side persistent file-inner dir), DPERSIST_MS_HOST (default 127.0.0.1).

(asdf:load-system :dds-durability)

(let* ((host  (or (uiop:getenv "DPERSIST_MS_HOST") "127.0.0.1"))
       (port  (parse-integer (or (uiop:getenv "DPERSIST_MS_PORT")
                                 (error "driver-ms-server: DPERSIST_MS_PORT is required"))))
       (inner (or (uiop:getenv "DPERSIST_MS_INNER")
                  (error "driver-ms-server: DPERSIST_MS_INNER (server file-inner dir) is required")))
       (stop  (list nil))
       (srv   (dds.durability:make-microservice-server
               :host host :port port
               :inner (dds.durability:make-file-store
                       :dir (uiop:ensure-directory-pathname inner) :history-kind :keep-all))))
  (format t "~%MS-SERVER-LISTENING port=~d host=~a inner=~a~%"
          (dds.durability:microservice-server-port srv) host inner)
  (force-output)
  (dds.pal:install-signal-handler '(:term :int) (lambda () (setf (car stop) t)))
  (loop until (car stop) do (sleep 0.2))
  (dds.durability:microservice-server-stop srv)
  (format t "~%MS-SERVER-STOPPED port=~d~%" port) (force-output)
  (finish-output)
  (uiop:quit 0))
