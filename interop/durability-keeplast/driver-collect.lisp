;;;; KEEP_LAST interop — PROCESS 1 of the restart proof (collect M samples + EXIT).
;;;;
;;;; Starts a PERSISTENT (disk-backed + DARE-at-rest) durability service with
;;;; KEEP_LAST D policy on the shared on-disk dirs (D = store/epochs, K = ML-KEM-1024).
;;;; Collects whatever a foreign TRANSIENT_LOCAL publisher writes on Square/ShapeType (all M
;;;; samples for one keyed color instance), then service-stop (store-close -> fsync) and EXITS.
;;;; Process 2 (driver-serve.lisp) re-opens the SAME dirs with the same :keep-last D spec,
;;;; triggering compaction-on-open that keeps only the D newest per-instance records.
;;;;
;;;; KEEP_LAST manifests to a late-joiner ONLY via the file-store restart-seed (this scenario).
;;;; A same-running-service late-joiner would receive ALL M (the replay writer is KEEP_ALL +
;;;; publish-on-collect); that is the as-built live-late-joiner path, documented in the harness.
;;;;
;;;; Config (env vars): DKL_DIR, DKL_KEYDIR, DKL_SECS, DKL_DEPTH (default: 2).
;;;; The two :qos-overrides match interop/durability-persistent/:
;;;;   :data-representation (:xcdr1) — SEDP RxO for XCDR1-only foreign readers.
;;;;   :peers (("127.0.0.1" . 7410)) — unicast SPDP to domain-0 participant-0 SPDP port.

(asdf:load-system :dds-durability)

(let* ((dir     (or (uiop:getenv "DKL_DIR") "/tmp/dkl-D"))
       (key-dir (or (uiop:getenv "DKL_KEYDIR") "/tmp/dkl-K"))
       (secs    (parse-integer (or (uiop:getenv "DKL_SECS") "22")))
       (depth   (parse-integer (or (uiop:getenv "DKL_DEPTH") "2")))
       (spec (dds.durability:make-service-spec
              :domain 0
              :topics '(("Square" . "ShapeType"))
              :store (dds.durability:make-persistent-store-factory
                      :dir dir :key-dir key-dir
                      :history-kind :keep-last :history-depth depth)
              :history-kind  :keep-last
              :history-depth depth
              :qos-overrides `(:data-representation (:xcdr1)
                               :peers (("127.0.0.1" . 7410)))
              :name "dkl-collect"))
       (svc (dds.durability:make-durability-service spec)))
  (dds.durability:service-start svc)
  (format t "~%DKL-SVC1-STARTED dir=~a key-dir=~a keep-last=~d~%" dir key-dir depth)
  (force-output)
  (sleep secs)
  (let ((n (dds.durability:store-count (dds.durability:durability-service-store svc) "Square")))
    (format t "~%DKL-SVC1-COLLECTED Square=~d (keep-last=~d; all M before compaction)~%" n depth)
    (force-output))
  (dds.durability:service-stop svc)
  (format t "~%DKL-SVC1-STOPPED-AND-PERSISTED~%")
  (force-output)
  (finish-output)
  (uiop:quit 0))
