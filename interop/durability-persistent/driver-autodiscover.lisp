;;;; DISCOVERY-DRIVEN dynamic-topic-add — cross-vendor interop driver (single process).
;;;;
;;;; Proves the :auto-discover path (ADR 0026 Phase-2b) ON THE WIRE against a FOREIGN
;;;; (RTI Connext / eProsima Fast DDS) vendor: the service starts with an EMPTY topic
;;;; start-list + :auto-discover t; a foreign TRANSIENT_LOCAL publisher for a topic the
;;;; service was NEVER configured for (Square/ShapeType) appears; our bare SPDP/SEDP
;;;; discovery node parses the foreign writer's SEDP DiscoveredWriterData (PID_TOPIC_NAME
;;;; 0x0005 + PID_TYPE_NAME 0x0007, XCDR1 CDR strings) and auto-adds the topic
;;;; (service-add-topic, reused verbatim); the service collects the foreign samples as
;;;; OPAQUE bytes (only the topic-NAME + type-NAME strings are used, no XTypes/type
;;;; registration); then a foreign late-joiner subscriber is served the collected history
;;;; from our replay writer (RELIABLE + TRANSIENT_LOCAL, type-name advertised verbatim).
;;;;
;;;; The wire-surface being validated is exactly the foreign-SEDP topic/type-name decode
;;;; -> auto-add: the topic name reaches our service ONLY via the foreign vendor's SEDP.
;;;;
;;;; Config (env vars): DAD_DIR, DAD_KEYDIR, DAD_SECS (total up-time window),
;;;; DAD_FILTER (auto-discover topic-name filter, default "Square"), DAD_BACKEND
;;;; (file | sqlite | memory), DAD_PEERS (comma-sep SPDP ports).
;;;; The two :qos-overrides are identical to the sibling durability drivers:
;;;; :data-representation (:xcdr1) so XCDR1-only ShapeType readers match in SEDP, and
;;;; :peers unicast SPDP to the domain-0 well-known SPDP port(s) (RTPS 2.5 §9.6.1.1).

(asdf:load-system :dds-durability)

(let* ((dir     (or (uiop:getenv "DAD_DIR") "/tmp/dad-D"))
       (key-dir (or (uiop:getenv "DAD_KEYDIR") "/tmp/dad-K"))
       (secs    (parse-integer (or (uiop:getenv "DAD_SECS") "90")))
       (filter  (or (uiop:getenv "DAD_FILTER") "Square"))
       (backend (or (uiop:getenv "DAD_BACKEND") "file"))
       (peers   (loop for p in (uiop:split-string
                                (or (uiop:getenv "DAD_PEERS") "7410,7412,7414,7416,7418")
                                :separator ",")
                      collect (cons "127.0.0.1" (parse-integer p))))
       (store   (cond ((string-equal backend "sqlite")
                       (dds.durability:make-sqlite-store-factory :dir dir :key-dir key-dir))
                      ((string-equal backend "memory")
                       (lambda () (dds.durability:make-memory-store)))
                      (t (dds.durability:make-persistent-store-factory :dir dir :key-dir key-dir))))
       (spec (dds.durability:make-service-spec
              :domain 0
              :topics '()                          ; EMPTY — nothing pre-configured
              :auto-discover t                     ; discover + auto-serve at runtime
              :auto-discover-filter filter          ; serve only topics matching (default "Square")
              :store store
              :qos-overrides (list :data-representation '(:xcdr1) :peers peers)
              :name "dad-run"))
       (svc (dds.durability:make-durability-service spec)))
  (dds.durability:service-start svc)
  (let ((hard-end (+ (get-universal-time) secs)))
    (format t "~%DAD-STARTED empty auto-discover filter=~a backend=~a nodes=~d~%"
            filter backend (length (dds.durability:durability-service-nodes svc)))
    (force-output)
    ;; Phase 1: wait (bounded) for the FOREIGN SEDP to drive the auto-add of "Square".
    (loop until (or (dds.durability:service-serves-topic-p svc "Square")
                    (> (get-universal-time) hard-end))
          do (sleep 0.2))
    (if (dds.durability:service-serves-topic-p svc "Square")
        (format t "~%DAD-AUTO-ADDED Square nodes=~d (discovered via foreign SEDP, no pre-config)~%"
                (length (dds.durability:durability-service-nodes svc)))
        (format t "~%DAD-AUTO-ADD-TIMEOUT Square not discovered within ~ds~%" secs))
    (force-output)
    ;; Phase 2: stay up (to the SAME hard deadline) through the collect + serve windows,
    ;; reporting the collected count (climbs while the foreign pub writes; the foreign
    ;; late-joiner then reads the replay from our writer, not changing the store count).
    (let ((store-obj (dds.durability:durability-service-store svc)))
      (loop while (< (get-universal-time) hard-end) do
        (sleep 3)
        (format t "~%DAD-COLLECTED Square=~d~%"
                (dds.durability:store-count store-obj "Square"))
        (force-output))))
  (let ((n (dds.durability:store-count (dds.durability:durability-service-store svc) "Square")))
    (format t "~%DAD-FINAL Square=~d served=~a~%"
            n (dds.durability:service-serves-topic-p svc "Square"))
    (force-output))
  (dds.durability:service-stop svc)
  (format t "~%DAD-STOPPED~%") (force-output)
  (finish-output)
  (uiop:quit 0))
