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

;;;; NOTE (WP-DURABILITY-MS-SERVER-CLI, ADR 0050 §4.8 follow-on): the whole server-run lifecycle — build
;;;; the DARE-blind persistent KEEP_ALL inner, bind the port, log MS-SERVER-LISTENING, block until
;;;; SIGTERM/SIGINT, microservice-server-stop (clean §4.8 tcp-shutdown wake), log MS-SERVER-STOPPED, quit —
;;;; now lives in the SHARED dds.durability::%run-microservice-server helper that durability-service-main's
;;;; --backend server mode ALSO calls (DRY: one server-run entrypoint, no duplicated body). This driver is
;;;; the direct-helper entrypoint; driver-ms-server-cli.lisp is the SAME server via the operator CLI.

(asdf:load-system :dds-durability)

(let ((host  (or (uiop:getenv "DPERSIST_MS_HOST") "127.0.0.1"))
      (port  (parse-integer (or (uiop:getenv "DPERSIST_MS_PORT")
                                (error "driver-ms-server: DPERSIST_MS_PORT is required"))))
      (inner (or (uiop:getenv "DPERSIST_MS_INNER")
                 (error "driver-ms-server: DPERSIST_MS_INNER (server file-inner dir) is required"))))
  (dds.durability::%run-microservice-server
   :host host :port port :inner-backend :file :inner-dir inner :block t))
