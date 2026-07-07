;;;; PERSISTENT durability service — PROCESS 2 of the restart proof (reload + serve late-joiner).
;;;;
;;;; A FRESH process.  Starts a NEW PERSISTENT service on the SAME on-disk dirs written by
;;;; driver-collect.lisp (process 1).  service-start -> store-open reloads + DECRYPTS the
;;;; sealed records (re-derives the per-epoch DEKs from epochs.dat via the ML-KEM-1024 key in
;;;; K) and %seed-relay-from-store seeds the replay writer's TRANSIENT_LOCAL/KEEP_ALL history.
;;;; A foreign LATE-JOINING TL subscriber that starts AFTER this process is up receives the
;;;; retained N samples — proving cross-PROCESS persistence + cross-DDS wire transparency of
;;;; the DARE-at-rest store.
;;;;
;;;; Config (env vars): DPERSIST_DIR, DPERSIST_KEYDIR, DPERSIST_SECS, DPERSIST_BACKEND
;;;; (file [default] | sqlite | microservice; DPERSIST_MS_HOST/DPERSIST_MS_PORT for the remote client
;;;; tier — see driver-collect.lisp).  Same overrides as proc 1.

(asdf:load-system :dds-durability)

(let* ((dir     (or (uiop:getenv "DPERSIST_DIR") "/tmp/dpersist-D"))
       (key-dir (or (uiop:getenv "DPERSIST_KEYDIR") "/tmp/dpersist-K"))
       (secs    (parse-integer (or (uiop:getenv "DPERSIST_SECS") "60")))
       (backend (or (uiop:getenv "DPERSIST_BACKEND") "file"))
       (ms-host (or (uiop:getenv "DPERSIST_MS_HOST") "127.0.0.1"))
       (ms-port (let ((p (uiop:getenv "DPERSIST_MS_PORT"))) (when p (parse-integer p))))
       (peers   (loop for p in (uiop:split-string
                                (or (uiop:getenv "DPERSIST_PEERS") "7410,7412,7414,7416,7418")
                                :separator ",")
                      collect (cons "127.0.0.1" (parse-integer p))))
       (spec (dds.durability:make-service-spec
              :domain 0
              :topics '(("Square" . "ShapeType"))
              :store (dds.durability:make-durability-store-factory
                      backend :dir dir :key-dir key-dir :ms-host ms-host :ms-port ms-port)
              :qos-overrides (list :data-representation '(:xcdr1) :peers peers)
              :name "dpersist-run2"))
       (svc (dds.durability:make-durability-service spec)))
  (dds.durability:service-start svc)
  (let ((n (dds.durability:store-count (dds.durability:durability-service-store svc) "Square")))
    (format t "~%SVC2-RELOADED-FROM-DISK Square=~d (decrypted on reopen)~%" n) (force-output))
  (format t "~%SVC2-STARTED dir=~a key-dir=~a backend=~a~%" dir key-dir backend) (force-output)
  (sleep secs)
  (dds.durability:service-stop svc)
  (format t "~%SVC2-STOPPED~%") (force-output)
  (finish-output)
  (uiop:quit 0))
