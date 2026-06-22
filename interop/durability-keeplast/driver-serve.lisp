;;;; KEEP_LAST interop — PROCESS 2 of the restart proof (compaction-on-open + serve late-joiner).
;;;;
;;;; A FRESH process.  Starts a NEW PERSISTENT service on the SAME on-disk dirs written by
;;;; driver-collect.lisp (process 1).  service-start -> store-open with :keep-last D triggers
;;;; compaction-on-open: the file-store discards all but the D newest :data records per non-NIL
;;;; key-hash instance, so the replay writer is seeded with only D records, not M.
;;;; A foreign LATE-JOINING TL subscriber that starts AFTER this process is up receives D,
;;;; not M — proving per-instance KEEP_LAST compaction is effective after a process restart.
;;;;
;;;; THE NUANCE (documented here, not a defect): the replay writer is KEEP_ALL + publish-on-collect
;;;; (as built). A live-late-joiner connecting to the SAME running process-1 would receive ALL M.
;;;; KEEP_LAST manifests only via the restart-seed path (this scenario): compaction-on-open
;;;; reduces the on-disk log to D records before seeding, so %seed-relay-from-store publishes D
;;;; records into the replay writer's TL+KEEP_ALL cache, and that is what the late-joiner gets.
;;;;
;;;; Config (env vars): DKL_DIR, DKL_KEYDIR, DKL_SECS, DKL_DEPTH (default: 2).

(asdf:load-system :dds-durability)

(let* ((dir     (or (uiop:getenv "DKL_DIR") "/tmp/dkl-D"))
       (key-dir (or (uiop:getenv "DKL_KEYDIR") "/tmp/dkl-K"))
       (secs    (parse-integer (or (uiop:getenv "DKL_SECS") "60")))
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
              :name "dkl-serve"))
       (svc (dds.durability:make-durability-service spec)))
  (dds.durability:service-start svc)
  (let ((n (dds.durability:store-count (dds.durability:durability-service-store svc) "Square")))
    (format t "~%DKL-SVC2-RELOADED-AND-COMPACTED Square=~d (expected=~d, keep-last=~d)~%"
            n depth depth)
    (force-output)
    (if (= n depth)
        (format t "~%DKL-SVC2-KEEPL-COMPACTION-VERIFIED: store holds exactly D=~d records~%" depth)
        (format t "~%DKL-SVC2-KEEPL-COMPACTION-UNEXPECTED: expected ~d got ~d~%" depth n))
    (force-output))
  (format t "~%DKL-SVC2-STARTED dir=~a key-dir=~a keep-last=~d~%" dir key-dir depth)
  (force-output)
  (sleep secs)
  (dds.durability:service-stop svc)
  (format t "~%DKL-SVC2-STOPPED~%")
  (force-output)
  (finish-output)
  (uiop:quit 0))
