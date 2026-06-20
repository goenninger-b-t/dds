;;;; TRANSIENT-tier coexistence driver — our durability service as RELAY 2 alongside RTI PS.
;;;;
;;;; WP-DURABILITY-PERSISTENT carry-forward (the Phase-2 CLOSED_WITH_FINDINGS leg C, ADR 0024).
;;;; A single long-running PERSISTENT service on domain 0: its TRANSIENT_LOCAL collecting reader
;;;; matches the foreign TRANSIENT publisher (RxO: offered TRANSIENT rank 2 >= requested
;;;; TRANSIENT_LOCAL rank 1), collects + seals each origin sample to the encrypted-on-disk store,
;;;; and its TRANSIENT_LOCAL replay writer (emitting PID_ORIGINAL_WRITER_INFO + PID_SERVICE_KIND=
;;;; PERSISTENCE_SERVICE) serves a late-joining TRANSIENT_LOCAL subscriber.  RTI Persistence Service
;;;; (RELAY 1) relays the same origin samples at the TRANSIENT tier; the late-joiner's receiver-side
;;;; OWI dedup collapses the dual relay to exactly-once.
;;;;
;;;; Same two QoS overrides as the transient/restart runbooks (:data-representation (:xcdr1) for the
;;;; XCDR1-only ShapeType peers; :peers (("127.0.0.1" . 7410)) unicast SPDP to the domain-0
;;;; participant-0 well-known port).  Config (env): DPERSIST_DIR, DPERSIST_KEYDIR, DPERSIST_SECS.

(asdf:load-system :dds-durability)

(let* ((dir     (or (uiop:getenv "DPERSIST_DIR") "/tmp/dcoexist-D"))
       (key-dir (or (uiop:getenv "DPERSIST_KEYDIR") "/tmp/dcoexist-K"))
       (secs    (parse-integer (or (uiop:getenv "DPERSIST_SECS") "60")))
       (spec (dds.durability:make-service-spec
              :domain 0
              :topics '(("Square" . "ShapeType"))
              :store (dds.durability:make-persistent-store-factory
                      :dir dir :key-dir key-dir)
              :qos-overrides '(:data-representation (:xcdr1)
                               :peers (("127.0.0.1" . 7410)))
              :name "dcoexist-relay2"))
       (svc (dds.durability:make-durability-service spec)))
  (dds.durability:service-start svc)
  (format t "~%SVC-COEXIST-STARTED dir=~a key-dir=~a (relay 2 of 2)~%" dir key-dir)
  (force-output)
  (let ((store (dds.durability:durability-service-store svc)))
    (dotimes (i secs)
      (sleep 1)
      (when (zerop (mod (1+ i) 5))
        (format t "SVC-COEXIST-COLLECTED Square=~d (t+~ds)~%"
                (dds.durability:store-count store "Square") (1+ i))
        (force-output)))
    (format t "~%SVC-COEXIST-FINAL Square=~d~%"
            (dds.durability:store-count store "Square"))
    (force-output))
  (dds.durability:service-stop svc)
  (format t "~%SVC-COEXIST-STOPPED~%")
  (finish-output)
  (uiop:quit 0))
