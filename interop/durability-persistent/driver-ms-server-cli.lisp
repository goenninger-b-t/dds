;;;; MICROSERVICE durability SERVER via the OPERATOR CLI entrypoint (durability-service-main --backend
;;;; server) — WP-DURABILITY-MS-SERVER-CLI, ADR 0050 §4.8 follow-on (semantics B: run the KV SERVER).
;;;;
;;;; Same reference server as driver-ms-server.lisp, but launched through the REAL CLI path
;;;; (durability-service-main parses --backend server + the server flags and dispatches to the shared
;;;; %run-microservice-server) instead of calling the helper directly — so run-microservice.sh's LEG 3
;;;; proves the operator CLI entrypoint STARTS, LISTENS, PERSISTS across a stop+restart, and STOPS cleanly.
;;;; DARE-BLIND file inner (KEEP_ALL); blocks until SIGTERM/SIGINT; the shared helper emits the SAME
;;;; MS-SERVER-LISTENING / MS-SERVER-STOPPED markers the harness greps.
;;;;
;;;; Config (env vars, shared with driver-ms-server.lisp): DPERSIST_MS_PORT (REQUIRED, the fixed listen
;;;; port), DPERSIST_MS_INNER (REQUIRED, the server-side persistent inner dir), DPERSIST_MS_HOST
;;;; (default 127.0.0.1), DPERSIST_MS_BACKEND (inner store: file|sqlite, default file).

(asdf:load-system :dds-durability)

(let ((host    (or (uiop:getenv "DPERSIST_MS_HOST") "127.0.0.1"))
      (port    (or (uiop:getenv "DPERSIST_MS_PORT")
                   (error "driver-ms-server-cli: DPERSIST_MS_PORT is required")))
      (inner   (or (uiop:getenv "DPERSIST_MS_INNER")
                   (error "driver-ms-server-cli: DPERSIST_MS_INNER (server inner dir) is required")))
      (backend (or (uiop:getenv "DPERSIST_MS_BACKEND") "file")))
  (dds.durability:durability-service-main
   :argv (list "--backend" "server" "--host" host "--port" port
               "--inner-backend" backend "--inner-dir" inner)
   :env '() :block t))
