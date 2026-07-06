;;;; PERSISTENT durability service — PROCESS 1 of the restart proof (collect + persist + EXIT).
;;;;
;;;; Starts a PERSISTENT (disk-backed + DARE-at-rest) durability service on the shared
;;;; on-disk dirs (D = store/epochs, K = ML-KEM-1024 keypair), collects whatever a foreign
;;;; TRANSIENT_LOCAL publisher writes on Square/ShapeType, then service-stop (store-close ->
;;;; fsync of the sealed log + epochs.dat to D) and EXITS the process.  Process 2
;;;; (driver-serve.lisp) re-opens the SAME D + K, proving cross-PROCESS persistence.
;;;;
;;;; Config (env vars): DPERSIST_DIR, DPERSIST_KEYDIR, DPERSIST_SECS.
;;;; The two :qos-overrides are identical to interop/durability-transient/ +
;;;; interop/durability-dare/: :data-representation (:xcdr1) so XCDR1-only ShapeType readers
;;;; match in SEDP, and :peers (("127.0.0.1" . 7410)) unicast SPDP to the domain-0
;;;; participant-0 well-known SPDP port (RTPS 2.5 §9.6.1.1).

(asdf:load-system :dds-durability)

(let* ((dir     (or (uiop:getenv "DPERSIST_DIR") "/tmp/dpersist-D"))
       (key-dir (or (uiop:getenv "DPERSIST_KEYDIR") "/tmp/dpersist-K"))
       (secs    (parse-integer (or (uiop:getenv "DPERSIST_SECS") "22")))
       (backend (or (uiop:getenv "DPERSIST_BACKEND") "file"))
       (peers   (loop for p in (uiop:split-string
                                (or (uiop:getenv "DPERSIST_PEERS") "7410,7412,7414,7416,7418")
                                :separator ",")
                      collect (cons "127.0.0.1" (parse-integer p))))
       (spec (dds.durability:make-service-spec
              :domain 0
              :topics '(("Square" . "ShapeType"))
              :store (if (string-equal backend "sqlite")
                         (dds.durability:make-sqlite-store-factory :dir dir :key-dir key-dir)
                         (dds.durability:make-persistent-store-factory :dir dir :key-dir key-dir))
              :qos-overrides (list :data-representation '(:xcdr1) :peers peers)
              :name "dpersist-run1"))
       (svc (dds.durability:make-durability-service spec)))
  (dds.durability:service-start svc)
  (format t "~%SVC1-STARTED dir=~a key-dir=~a backend=~a~%" dir key-dir backend) (force-output)
  (sleep secs)
  (let ((n (dds.durability:store-count (dds.durability:durability-service-store svc) "Square")))
    (format t "~%SVC1-COLLECTED Square=~d~%" n) (force-output))
  (dds.durability:service-stop svc)
  (format t "~%SVC1-STOPPED-AND-PERSISTED~%") (force-output)
  (finish-output)
  (uiop:quit 0))
