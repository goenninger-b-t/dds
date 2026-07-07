(in-package #:dds.tests)

;;; --- WP-DURABILITY-METADATA-CONF-3c test helpers ---
;;; After 3c, an encrypted store puts records under the k_meta topic-HASH, not the plaintext topic
;;; name. These helpers derive k_meta from the persisted log-MAC anchor (same deterministic path the
;;; store uses) so tests that reach the raw on-disk state (log filename / SQLite topic column) can
;;; compute the actual on-disk identifiers for a real topic.

(defun* %enc-meta-key (d-dir k-dir)
    (function (t t) (simple-array (unsigned-byte 8) (*)))
  "Derive the encrypted-store k_meta from the persisted anchor (3c test helper). Caller frees it."
  (let ((kp (dds.dare:make-file-key-provider :dir k-dir)))
    (dds.dare:key-provider-open kp)
    (unwind-protect
         (multiple-value-bind (lk gf mk)
             (dds.durability::%load-logmac-anchor kp (uiop:ensure-directory-pathname d-dir))
           (declare (ignore gf))
           (dds.dare:free-secret-octets lk)
           mk)
      (dds.dare:key-provider-close kp))))

(defun* %enc-topic-hash (d-dir k-dir topic)
    (function (t t string) string)
  "The on-disk topic-hash HEX string an encrypted store uses for TOPIC (the SQLite topic column and
   the pre-%topic->id id; 3c). Derives + frees k_meta from the anchor."
  (let ((mk (%enc-meta-key d-dir k-dir)))
    (unwind-protect
         (dds.durability::%meta-hex (dds.durability::%meta-topic-hash-bytes mk topic))
      (dds.dare:free-secret-octets mk))))

(defun* %enc-topic-tid (d-dir k-dir topic)
    (function (t t string) string)
  "The on-disk file-store log basename (tid) an encrypted store uses for TOPIC (3c): %topic->id of
   the k_meta topic-hash HEX string."
  (dds.durability::%topic->id (%enc-topic-hash d-dir k-dir topic)))

(defun* run-durability-store-test ()
    (function () t)
  "In-memory durable-store: put/get-range ordering, idempotent re-put, topic isolation, bounded reject."
  (let ((s (dds.durability:make-memory-store :max-samples 0))
        (g0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
        (g1 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 1))
        (p (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b))))
    (%check :put1 (eq t (dds.durability:store-put s "A" g0 2 nil :data (funcall p '(2)))) "put sn2")
    (%check :put2 (eq t (dds.durability:store-put s "A" g0 1 nil :data (funcall p '(1)))) "put sn1")
    (%check :put-dup (eq t (dds.durability:store-put s "A" g0 1 nil :data (funcall p '(9)))) "re-put sn1 ok")
    (%check :count-dedup (= 2 (dds.durability:store-count s "A")) "re-put must not double-store")
    (let ((recs (dds.durability:store-get-range s "A")))
      (%check :order (and (= 1 (dds.durability:durable-record-sn (first recs)))
                          (= 2 (dds.durability:durable-record-sn (second recs)))) "get-range ordered by sn"))
    (dds.durability:store-put s "B" g1 1 nil :data (funcall p '(7)))
    (%check :topic-isolation (and (= 2 (dds.durability:store-count s "A"))
                                  (= 1 (dds.durability:store-count s "B"))) "topics isolated")
    (%check :topics (equal '("A" "B") (sort (copy-list (dds.durability:store-topics s)) #'string<)) "topics list")
    (let ((bs (dds.durability:make-memory-store :max-samples 1)))
      (dds.durability:store-put bs "A" g0 1 nil :data (funcall p '(1)))
      (%check :bounded (eq :rejected (dds.durability:store-put bs "A" g0 2 nil :data (funcall p '(2)))) "full store rejects"))
    ;; Multi-writer ordering: guid with first byte 2 must sort before guid with first byte 10.
    ;; string< puts "(10 ...)" before "(2 ...)" (lexicographic); byte-sequence order puts 2 first.
    (let* ((s2 (dds.durability:make-memory-store))
           (gw2  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
           (gw10 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
      (setf (aref gw2  0) 2)
      (setf (aref gw10 0) 10)
      (dds.durability:store-put s2 "T" gw10 1 nil :data (funcall p '(10)))
      (dds.durability:store-put s2 "T" gw2  1 nil :data (funcall p '(2)))
      (let* ((recs (dds.durability:store-get-range s2 "T"))
             (first-byte (aref (dds.durability:durable-record-writer-guid (first recs)) 0)))
        (%check :multi-writer-order (= 2 first-byte)
                "byte-2 guid must precede byte-10 guid in store-get-range")))
    t))

(defun* run-durability-spec-test ()
    (function () t)
  "service-spec topic-filter matching: explicit list and predicate forms."
  (let ((s1 (dds.durability:make-service-spec :domain (test-domain) :topics '(("Square" . "ShapeType")) :name "shapes"))
        (s2 (dds.durability:make-service-spec :domain (test-domain)
              :topics (lambda (topic type) (declare (ignore type)) (eql 0 (search "Sensor" topic))) :name "sensors")))
    (%check :list-hit (dds.durability:service-spec-matches-p s1 "Square" "ShapeType") "list match")
    (%check :list-miss-type (not (dds.durability:service-spec-matches-p s1 "Square" "Other")) "type must match")
    (%check :list-miss-topic (not (dds.durability:service-spec-matches-p s1 "Circle" "ShapeType")) "topic must match")
    (%check :pred-hit (dds.durability:service-spec-matches-p s2 "SensorA" "X") "predicate match")
    (%check :pred-miss (not (dds.durability:service-spec-matches-p s2 "Square" "X")) "predicate miss")
    t))

;;; --- relay tier QoS override (WP-DURABILITY-COEXIST-DEDUP Task 2) ---
;;; Asserts that service-start honors :relay-durability in service-spec qos-overrides:
;;;   (a) explicit :transient override -> writer advertises :transient     [cross-vendor path]
;;;   (b) no override                  -> writer advertises :transient-local [no-regression default]
;;; Mirrors run-durability-writer-rep-test's structure via disc-node-local-writers ->
;;; endpoint-data-qos -> qos-durability.  Domain 137 avoids collision with all prior tests.

(defun* run-durability-relay-tier-test ()
    (function () t)
  "QoS override plumbing: relay writer advertises :relay-durability per qos-overrides;
   absent override keeps the default :transient-local byte-identical to the prior behavior."
  ;; --- (a) explicit :transient override ---
  (let* ((spec-transient (dds.durability:make-service-spec
                          :domain (test-domain +td-relay-tier+)
                          :topics '(("RTSquare" . "ShapeType"))
                          :qos-overrides '(:relay-durability :transient)
                          :name "relay-tier-transient"))
         (svc-transient (dds.durability:make-durability-service spec-transient)))
    (unwind-protect
         (progn
           (dds.durability:service-start svc-transient)
           (let* ((node (dds.durability:durability-service-node svc-transient))
                  (writers (dds.disc::disc-node-local-writers node))
                  (dur (when writers
                         (dds.qos:qos-durability
                          (dds.rtps.discovery:endpoint-data-qos (first writers))))))
             (%check :relay-tier-transient
                     (eq :transient dur)
                     (format nil "expected :transient relay durability, got ~s" dur))))
      (ignore-errors (dds.durability:service-stop svc-transient))))
  ;; --- (b) no override -> default :transient-local ---
  (let* ((spec-default (dds.durability:make-service-spec
                        :domain (test-domain +td-relay-tier+)
                        :topics '(("RTCircle" . "ShapeType"))
                        :name "relay-tier-default"))
         (svc-default (dds.durability:make-durability-service spec-default)))
    (unwind-protect
         (progn
           (dds.durability:service-start svc-default)
           (let* ((node (dds.durability:durability-service-node svc-default))
                  (writers (dds.disc::disc-node-local-writers node))
                  (dur (when writers
                         (dds.qos:qos-durability
                          (dds.rtps.discovery:endpoint-data-qos (first writers))))))
             (%check :relay-tier-default
                     (eq :transient-local dur)
                     (format nil "expected default :transient-local relay durability, got ~s" dur))))
      (ignore-errors (dds.durability:service-stop svc-default))))
  t)

;;; --- collect-reader tier QoS override (WP-DURABILITY-COEXIST-DEDUP Task 3) ---
;;; Asserts service-start honors :collect-durability in service-spec qos-overrides:
;;;   (a) explicit :transient override -> the COLLECT READER requests :transient   [coexistence path]
;;;   (b) no override                  -> the collect reader requests :transient-local [default]
;;; Why this matters (B2 origin-convergence, README): when a foreign persistence service (RTI PS) is
;;; co-relaying, RTI PS stamps PID_ORIGINAL_WRITER_INFO (the original publisher's GUID) ONLY when it
;;; replays to a TRANSIENT reader.  A TRANSIENT_LOCAL collect reader therefore receives RTI PS's copies
;;; WITHOUT OWI and records them under RTI PS's own (virtual) GUID — a divergent origin.  A TRANSIENT
;;; collect reader receives RTI PS's OWI-stamped copies, whose origin (the publisher's GUID) collapses
;;; against the publisher samples collected directly, so the relay re-stamps the single publisher origin.
;;; Reaches the advertised QoS via disc-node-local-readers -> endpoint-data-qos -> qos-durability.
;;; Domain 138 avoids collision with all prior tests.

(defun* run-durability-collect-tier-test ()
    (function () t)
  "QoS override plumbing: the collect READER requests :collect-durability per qos-overrides;
   absent override keeps the default :transient-local byte-identical to the prior behavior."
  ;; --- (a) explicit :transient override ---
  (let* ((spec-transient (dds.durability:make-service-spec
                          :domain (test-domain +td-collect-tier+)
                          :topics '(("CTSquare" . "ShapeType"))
                          :qos-overrides '(:collect-durability :transient)
                          :name "collect-tier-transient"))
         (svc-transient (dds.durability:make-durability-service spec-transient)))
    (unwind-protect
         (progn
           (dds.durability:service-start svc-transient)
           (let* ((node (dds.durability:durability-service-node svc-transient))
                  (readers (dds.disc::disc-node-local-readers node))
                  (dur (when readers
                         (dds.qos:qos-durability
                          (dds.rtps.discovery:endpoint-data-qos (first readers))))))
             (%check :collect-tier-transient
                     (eq :transient dur)
                     (format nil "expected :transient collect durability, got ~s" dur))))
      (ignore-errors (dds.durability:service-stop svc-transient))))
  ;; --- (b) no override -> default :transient-local ---
  (let* ((spec-default (dds.durability:make-service-spec
                        :domain (test-domain +td-collect-tier+)
                        :topics '(("CTCircle" . "ShapeType"))
                        :name "collect-tier-default"))
         (svc-default (dds.durability:make-durability-service spec-default)))
    (unwind-protect
         (progn
           (dds.durability:service-start svc-default)
           (let* ((node (dds.durability:durability-service-node svc-default))
                  (readers (dds.disc::disc-node-local-readers node))
                  (dur (when readers
                         (dds.qos:qos-durability
                          (dds.rtps.discovery:endpoint-data-qos (first readers))))))
             (%check :collect-tier-default
                     (eq :transient-local dur)
                     (format nil "expected default :transient-local collect durability, got ~s" dur))))
      (ignore-errors (dds.durability:service-stop svc-default))))
  t)

;;; --- durability-service collect path (Task 4) ---
;;; An our-stack publisher writes 3 TRANSIENT_LOCAL "Square"/"ShapeType" samples; the
;;; durability-service on the same domain collects them into the store. Domain 7 avoids
;;; collisions with other harness tests. Both nodes communicate via loopback unicast (:peers).

(defun* %make-test-prefix (b0)
    (function ((unsigned-byte 8)) (simple-array (unsigned-byte 8) (12)))
  "Build a 12-octet GUID prefix with first byte B0 and the rest zero (deterministic, test-only)."
  (let ((p (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref p 0) b0)
    p))

(defun* %make-small-payload (n)
    (function ((unsigned-byte 8)) (simple-array (unsigned-byte 8) (*)))
  "Tiny 4-octet XCDR2 payload with discriminator byte N (CDR_LE encap + 4 data bytes)."
  (make-array 8 :element-type '(unsigned-byte 8)
                :initial-contents (list 0 7 0 0 n 0 0 0)))

(defun* run-durability-collect-test ()
    (function () t)
  "Live stack collect path: a TL publisher writes 3 samples; the durability-service collects
   all 3 into the store. Verifies count=3, monotonically-increasing SNs, and a consistent
   writer GUID across all records. Domain 7, loopback unicast, no multicast. MVP: one topic."
  (let* ((svc-store (dds.durability:make-memory-store))
         (spec (dds.durability:make-service-spec
                :domain (test-domain +td-collect+)
                :topics '(("Square" . "ShapeType"))
                :store (lambda () svc-store)
                :name "collect-test"))
         (svc (dds.durability:make-durability-service spec :store svc-store))
         ;; publisher node on domain 7, loopback — port 0 = OS-assigned
         (pub-prefix (%make-test-prefix #xC1))
         (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain (test-domain +td-collect+)
                                            :host "127.0.0.1" :port 0
                                            :multicast nil)))
    (unwind-protect
         (progn
           ;; service start: binds port, spawns collect loop
           (dds.durability:service-start svc)
           ;; wire the pub -> service unicast after both have bound ports
           (let ((svc-port (dds.disc:disc-node-port (dds.durability:durability-service-node svc))))
             (setf (dds.disc:disc-node-peers pub-node)
                   (list (cons "127.0.0.1" svc-port))))
           ;; also wire service -> pub
           (dds.disc:add-local-writer pub-node :topic "Square" :type "ShapeType"
                                      :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                     :durability :transient-local))
           (dds.disc:enable-publisher pub-node :history-kind :keep-all)
           (dds.disc:start-node pub-node)
           (let ((pub-port (dds.disc:disc-node-port pub-node))
                 (svc-node (dds.durability:durability-service-node svc)))
             (setf (dds.disc:disc-node-peers svc-node)
                   (list (cons "127.0.0.1" pub-port))))
           ;; discovery phase: announce until the service reader matches the publisher
           (dds.disc:announce-participant pub-node)
           (dds.disc:announce-endpoints pub-node)
           (dds.disc:announce-participant (dds.durability:durability-service-node svc))
           (dds.disc:announce-endpoints (dds.durability:durability-service-node svc))
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-matched-count pub-node))
                            (plusp (dds.disc:disc-node-matched-count
                                    (dds.durability:durability-service-node svc))))
                 do (dds.disc:announce-participant pub-node)
                    (dds.disc:announce-endpoints pub-node)
                    (dds.disc:announce-participant (dds.durability:durability-service-node svc))
                    (dds.disc:announce-endpoints (dds.durability:durability-service-node svc))
                    (sleep 0.02))
           ;; publish 3 TL samples
           (dotimes (i 3)
             (dds.disc:publish-sample pub-node (%make-small-payload (1+ i))))
           ;; drain: push heartbeats so the service's reader NACKs and gets them
           (loop repeat 60
                 do (dds.disc:announce-participant pub-node)
                    (dds.disc:announce-endpoints pub-node)
                    (sleep 0.05))
           ;; settle loop: poll the store up to 5 s
           (loop repeat 1000
                 until (= 3 (dds.durability:store-count svc-store "Square"))
                 do (sleep 0.005))
           ;; assertions
           (%check :collect-count
                   (= 3 (dds.durability:store-count svc-store "Square"))
                   (format nil "expected 3 records in store, got ~d"
                           (dds.durability:store-count svc-store "Square")))
           (let ((recs (dds.durability:store-get-range svc-store "Square")))
             (%check :collect-sn-order
                     (apply #'< (mapcar #'dds.durability:durable-record-sn recs))
                     "records must have strictly increasing SNs")
             (%check :collect-guid-consistent
                     (let ((g0 (dds.durability:durable-record-writer-guid (first recs))))
                       (every (lambda (r)
                                (equalp g0 (dds.durability:durable-record-writer-guid r)))
                              recs))
                     "all records must share the same writer GUID"))
           t)
      (ignore-errors (dds.disc:stop-node pub-node))
      (ignore-errors (dds.durability:service-stop svc)))))

;;; --- durability-service replay path (Task 5) ---
;;; Headline end-to-end test: a TL publisher writes N=5 samples and then STOPS (writer gone).
;;; A durability-service running on the same domain has collected all 5 via the collect loop
;;; and re-published them through its TL+KEEP_ALL replay writer (publish-on-collect model).
;;; A TL late-joiner reader that starts AFTER the publisher is gone receives all 5 from the
;;; service via the shipped HEARTBEAT/ACKNACK late-joiner replay machinery.
;;; A VOLATILE late-joiner receives 0 of the pre-join history (the VOLATILE contrast).
;;; Domain 17 (avoids collision with domain 7 collect test above). Loopback unicast.

(defun* %wire-unicast (from-node to-node)
    (function (dds.disc:disc-node dds.disc:disc-node) t)
  "Point FROM-NODE's peer list at TO-NODE's loopback port (and vice versa)."
  (let ((from-port (dds.disc:disc-node-port from-node))
        (to-port   (dds.disc:disc-node-port to-node)))
    (setf (dds.disc:disc-node-peers from-node) (list (cons "127.0.0.1" to-port)))
    (setf (dds.disc:disc-node-peers to-node)   (list (cons "127.0.0.1" from-port))))
  t)

(defun* %announce-both (a b)
    (function (dds.disc:disc-node dds.disc:disc-node) t)
  "Send one round of SPDP + SEDP announcements on both nodes."
  (dds.disc:announce-participant a) (dds.disc:announce-endpoints a)
  (dds.disc:announce-participant b) (dds.disc:announce-endpoints b)
  t)

(defun* %await-match (a b &key (retries 300) (sleep-s 0.02))
    (function (dds.disc:disc-node dds.disc:disc-node &key (:retries integer) (:sleep-s real)) t)
  "Poll until both nodes have matched at least one endpoint, announcing each cycle."
  (loop repeat retries
        until (and (plusp (dds.disc:disc-node-matched-count a))
                   (plusp (dds.disc:disc-node-matched-count b)))
        do (%announce-both a b) (sleep sleep-s))
  t)

(defun* %await-store-count (store topic n &key (retries 1200) (sleep-s 0.005))
    (function (dds.durability:durable-store string integer &key (:retries integer) (:sleep-s real)) t)
  "Poll until STORE has at least N records for TOPIC (up to retries*sleep-s seconds)."
  (loop repeat retries
        until (>= (dds.durability:store-count store topic) n)
        do (sleep sleep-s))
  t)

(defun* %await-sample-count (node n &key (retries 1200) (sleep-s 0.005))
    (function (dds.disc:disc-node integer &key (:retries integer) (:sleep-s real)) t)
  "Poll until NODE has received at least N user samples."
  (loop repeat retries
        until (>= (dds.disc:node-sample-count node) n)
        do (sleep sleep-s))
  t)

(defun* %inject-discovered-writer (node topic type b0)
    (function (dds.disc:disc-node string string (unsigned-byte 8)) t)
  "Test helper: inject a synthetic discovered remote WRITER (topic/type + a GUID whose first byte is B0)
   into disc-NODE's discovered-writers table under the node lock — simulating an SEDP DiscoveredWriterData
   arrival WITHOUT a live publisher, so the :auto-discover auto-add path is exercisable deterministically
   on both impls (no discovery timing)."
  (let ((ep (dds.rtps.discovery:make-endpoint-data
             :role :writer :topic-name topic :type-name type
             :guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element b0))))
    (dds.pal:with-lock ((dds.disc::disc-node-lock node))
      (dds.disc::%record-discovered (dds.disc::disc-node-discovered-writers node) ep)))
  t)

(defun* run-durability-transient-test ()
    (function () t)
  "Headline replay end-to-end: publisher writes N=5 TL samples, STOPS (writer gone);
   service collected + re-published them; TL late-joiner receives all 5; VOLATILE
   late-joiner receives 0.  Domain 17, loopback unicast, no multicast.
   Replay model: publish-on-collect (service writer is TL+KEEP_ALL; shipped
   HEARTBEAT/ACKNACK late-joiner machinery delivers the retained history)."
  (let* ((n 5)
         (svc-store (dds.durability:make-memory-store))
         (spec (dds.durability:make-service-spec
                :domain (test-domain +td-transient+)
                :topics '(("Square" . "ShapeType"))
                :store (lambda () svc-store)
                :name "transient-test"))
         (svc (dds.durability:make-durability-service spec :store svc-store))
         (pub-prefix (%make-test-prefix #xD1))
         (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain (test-domain +td-transient+)
                                            :host "127.0.0.1" :port 0 :multicast nil)))
    (unwind-protect
         (progn
           ;; start service first so it can collect from the publisher
           (dds.durability:service-start svc)
           (let ((svc-node (dds.durability:durability-service-node svc)))
             ;; wire pub <-> service
             (setf (dds.disc:disc-node-peers pub-node)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-node))))
             (setf (dds.disc:disc-node-peers svc-node)
                   (list (cons "127.0.0.1" 0)))  ; updated after pub starts
             ;; set up publisher writer
             (dds.disc:add-local-writer pub-node :topic "Square" :type "ShapeType"
                                        :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                       :durability :transient-local))
             (dds.disc:enable-publisher pub-node :history-kind :keep-all)
             (dds.disc:start-node pub-node)
             ;; now wire service -> pub (port is known after start)
             (setf (dds.disc:disc-node-peers svc-node)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port pub-node))))
             ;; discovery: announce until matched
             (%await-match pub-node svc-node :retries 300 :sleep-s 0.02)
             ;; publish N TL samples
             (dotimes (i n)
               (dds.disc:publish-sample pub-node (%make-small-payload (1+ i))))
             ;; drain heartbeats so service reader gets them
             (loop repeat 80
                   do (%announce-both pub-node svc-node) (sleep 0.05))
             ;; wait for service store to fill
             (%await-store-count svc-store "Square" n)
             (%check :collect-pre-stop
                     (= n (dds.durability:store-count svc-store "Square"))
                     (format nil "service should have collected ~d before publisher stopped, got ~d"
                             n (dds.durability:store-count svc-store "Square")))
             ;; STOP the publisher — writer is now gone
             (ignore-errors (dds.disc:stop-node pub-node))
             ;; give service a moment to notice the disconnect
             (sleep 0.1)
             ;; late-joiner 1: TL reader — expects all N from service
             (let* ((lj-prefix (%make-test-prefix #xE1))
                    (lj-node (dds.disc:make-disc-node :guid-prefix lj-prefix :domain (test-domain +td-transient+)
                                                      :host "127.0.0.1" :port 0 :multicast nil)))
               (unwind-protect
                    (progn
                      (dds.disc:add-local-reader lj-node :topic "Square" :type "ShapeType"
                                                 :qos (dds.qos:make-reader-qos
                                                       :reliability :reliable
                                                       :durability :transient-local))
                      (dds.disc:enable-subscriber lj-node)
                      ;; wire on-match: call reader-durability-init so TL reader requests history
                      (setf (dds.disc:disc-node-on-match lj-node)
                            (lambda (kind remote &optional local-eid) (declare (ignore local-eid))
                              (when (eq kind :remote-writer)
                                (dds.disc:%reader-durability-init
                                 lj-node
                                 (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                                 (dds.qos:qos-durability
                                  (dds.rtps.discovery:endpoint-data-qos remote))))))
                      (dds.disc:start-node lj-node)
                      ;; wire lj <-> service
                      (setf (dds.disc:disc-node-peers lj-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-node))))
                      (setf (dds.disc:disc-node-peers svc-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port lj-node))))
                      ;; discovery + drain
                      (%await-match lj-node svc-node :retries 300 :sleep-s 0.02)
                      ;; poll for N samples (up to ~6 s)
                      (%await-sample-count lj-node n :retries 1200 :sleep-s 0.005)
                      (%check :tl-latejoiner-count
                              (= n (dds.disc:node-sample-count lj-node))
                              (format nil "TL late-joiner expected ~d samples, got ~d"
                                      n (dds.disc:node-sample-count lj-node))))
                 (ignore-errors (dds.disc:stop-node lj-node))))
             ;; late-joiner 2: VOLATILE reader — expects 0 pre-join history
             (let* ((vl-prefix (%make-test-prefix #xE2))
                    (vl-node (dds.disc:make-disc-node :guid-prefix vl-prefix :domain (test-domain +td-transient+)
                                                      :host "127.0.0.1" :port 0 :multicast nil)))
               (unwind-protect
                    (progn
                      (dds.disc:add-local-reader vl-node :topic "Square" :type "ShapeType"
                                                 :qos (dds.qos:make-reader-qos
                                                       :reliability :reliable
                                                       :durability :volatile))
                      (dds.disc:enable-subscriber vl-node)
                      ;; wire on-match: call reader-durability-init so VOLATILE reader SKIPS history
                      (setf (dds.disc:disc-node-on-match vl-node)
                            (lambda (kind remote &optional local-eid) (declare (ignore local-eid))
                              (when (eq kind :remote-writer)
                                (dds.disc:%reader-durability-init
                                 vl-node
                                 (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                                 (dds.qos:qos-durability
                                  (dds.rtps.discovery:endpoint-data-qos remote))))))
                      (dds.disc:start-node vl-node)
                      ;; wire vl <-> service
                      (setf (dds.disc:disc-node-peers vl-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-node))))
                      (setf (dds.disc:disc-node-peers svc-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port vl-node))))
                      ;; Settle (WP-RESIDUAL-FIXES-BATCH-A A5): bounded condition-wait on the match (on-match arms the
                      ;; VOLATILE skip-history) + a bounded announce pump so a wrongly-repaired pre-join sample WOULD
                      ;; have arrived before the assert; replaces the blind sleep 0.3 + 20x0.05 settle. The ZERO
                      ;; assertion is UNCHANGED (no tolerance for a wrong delivery). PRODUCT RACE FIXED by
                      ;; WP-ACKNACK-MATCH-GATE (RTPS 2.5 §8.4.10.1; DDS 1.4 §2.2.3.4): the pre-fix flake was a real
                      ;; DURABILITY violation — when the service's periodic user HEARTBEAT reached this node BEFORE
                      ;; the SEDP match (UDP arrival order), %on-user-heartbeat created the WriterProxy pre-match
                      ;; (skip-history NIL) and ACKNACKed the FULL [1..N] history, so the writer repaired all N
                      ;; pre-join samples. The fix match-gates %on-user-heartbeat on the writer being MATCHED
                      ;; (%guid-matched-p): a pre-match HEARTBEAT is dropped, and the writer's next periodic HEARTBEAT
                      ;; re-arrives post-match with skip-history armed (VOLATILE baselines at the current lastSN → 0
                      ;; pre-join samples). This test is now deterministically green (15/15 SBCL loop, 2026-07-04).
                      (%await-match vl-node svc-node :retries 400 :sleep-s 0.02)
                      (loop repeat 40 do (%announce-both vl-node svc-node) (sleep 0.02))
                      (%check :volatile-latejoiner-zero
                              (zerop (dds.disc:node-sample-count vl-node))
                              (format nil "VOLATILE late-joiner expected 0 pre-join samples, got ~d"
                                      (dds.disc:node-sample-count vl-node))))
                 (ignore-errors (dds.disc:stop-node vl-node))))
             t))
      (ignore-errors (dds.durability:service-stop svc)))))

;;; --- runner: multi-service registry + thread mode (Task 6) ---
;;; Two specs on domain 27: spec-A collects "Square"/"ShapeType",
;;; spec-B collects "Circle"/"ShapeType".  A publisher writes TL samples to
;;; BOTH topics; the runner is started; we assert topic isolation (each store
;;; sees ONLY its own topic) and runner-status/runner-stop lifecycle.
;;; Domain 27 avoids collision with domain 7 (collect) and domain 17 (transient).

(defun* run-durability-runner-test ()
    (function () t)
  "Runner lifecycle + topic isolation: two specs (Square, Circle) on domain 27;
   each service's store collects ONLY its own topic; runner-status shows both alive;
   runner-stop stops all services. Uses two separate publisher nodes (one per topic)
   because disc-node supports one user-writer at a time (one-writer-per-node invariant)."
  (let* ((store-a  (dds.durability:make-memory-store))
         (store-b  (dds.durability:make-memory-store))
         (spec-a   (dds.durability:make-service-spec
                    :domain (test-domain +td-runner+)
                    :topics '(("Square" . "ShapeType"))
                    :store  (lambda () store-a)
                    :name   "runner-square"))
         (spec-b   (dds.durability:make-service-spec
                    :domain (test-domain +td-runner+)
                    :topics '(("Circle" . "ShapeType"))
                    :store  (lambda () store-b)
                    :name   "runner-circle"))
         (runner   (dds.durability:make-service-runner (list spec-a spec-b)))
         ;; Two publisher nodes: one per topic (one-writer-per-node invariant)
         (pub-sq-node (dds.disc:make-disc-node
                       :guid-prefix (%make-test-prefix #xF1) :domain (test-domain +td-runner+)
                       :host "127.0.0.1" :port 0 :multicast nil))
         (pub-ci-node (dds.disc:make-disc-node
                       :guid-prefix (%make-test-prefix #xF2) :domain (test-domain +td-runner+)
                       :host "127.0.0.1" :port 0 :multicast nil)))
    (unwind-protect
         (progn
           ;; Square publisher
           (dds.disc:add-local-writer pub-sq-node :topic "Square" :type "ShapeType"
                                      :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                     :durability :transient-local))
           (dds.disc:enable-publisher pub-sq-node :history-kind :keep-all)
           (dds.disc:start-node pub-sq-node)
           ;; Circle publisher
           (dds.disc:add-local-writer pub-ci-node :topic "Circle" :type "ShapeType"
                                      :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                     :durability :transient-local))
           (dds.disc:enable-publisher pub-ci-node :history-kind :keep-all)
           (dds.disc:start-node pub-ci-node)
           ;; start runner: starts both services (binds ports, spawns collect loops)
           (dds.durability:runner-start runner)
           (let* ((svcs       (dds.durability:service-runner-services runner))
                  (svc-a      (first  svcs))
                  (svc-b      (second svcs))
                  (svc-a-node (dds.durability:durability-service-node svc-a))
                  (svc-b-node (dds.durability:durability-service-node svc-b))
                  (sq-port    (dds.disc:disc-node-port pub-sq-node))
                  (ci-port    (dds.disc:disc-node-port pub-ci-node)))
             ;; wire unicast: svc-a <-> sq-pub, svc-b <-> ci-pub
             (setf (dds.disc:disc-node-peers pub-sq-node)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-a-node))))
             (setf (dds.disc:disc-node-peers pub-ci-node)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-b-node))))
             (setf (dds.disc:disc-node-peers svc-a-node)
                   (list (cons "127.0.0.1" sq-port)))
             (setf (dds.disc:disc-node-peers svc-b-node)
                   (list (cons "127.0.0.1" ci-port)))
             ;; discovery: announce until both services have matched their respective publishers
             (loop repeat 300
                   until (and (plusp (dds.disc:disc-node-matched-count svc-a-node))
                              (plusp (dds.disc:disc-node-matched-count svc-b-node)))
                   do (dds.disc:announce-participant pub-sq-node)
                      (dds.disc:announce-endpoints   pub-sq-node)
                      (dds.disc:announce-participant pub-ci-node)
                      (dds.disc:announce-endpoints   pub-ci-node)
                      (dds.disc:announce-participant svc-a-node)
                      (dds.disc:announce-endpoints   svc-a-node)
                      (dds.disc:announce-participant svc-b-node)
                      (dds.disc:announce-endpoints   svc-b-node)
                      (sleep 0.02))
             ;; publish 2 Square + 3 Circle samples
             (dotimes (i 2) (dds.disc:publish-sample pub-sq-node (%make-small-payload (1+ i))))
             (dotimes (i 3) (dds.disc:publish-sample pub-ci-node (%make-small-payload (+ 10 i))))
             ;; drain heartbeats so service readers get the data
             (loop repeat 60
                   do (dds.disc:announce-participant pub-sq-node)
                      (dds.disc:announce-endpoints   pub-sq-node)
                      (dds.disc:announce-participant pub-ci-node)
                      (dds.disc:announce-endpoints   pub-ci-node)
                      (sleep 0.05))
             ;; settle: wait for stores to fill (up to 6 s each)
             (%await-store-count store-a "Square" 2 :retries 1200 :sleep-s 0.005)
             (%await-store-count store-b "Circle" 3 :retries 1200 :sleep-s 0.005)
             ;; stop publishers before assertions
             (ignore-errors (dds.disc:stop-node pub-sq-node))
             (ignore-errors (dds.disc:stop-node pub-ci-node))
             ;; topic isolation: store-a has Square, no Circle; store-b has Circle, no Square
             (%check :runner-store-a-square
                     (= 2 (dds.durability:store-count store-a "Square"))
                     (format nil "store-a expected 2 Square records, got ~d"
                             (dds.durability:store-count store-a "Square")))
             (%check :runner-store-a-no-circle
                     (zerop (dds.durability:store-count store-a "Circle"))
                     (format nil "store-a must have 0 Circle records (isolation), got ~d"
                             (dds.durability:store-count store-a "Circle")))
             (%check :runner-store-b-circle
                     (= 3 (dds.durability:store-count store-b "Circle"))
                     (format nil "store-b expected 3 Circle records, got ~d"
                             (dds.durability:store-count store-b "Circle")))
             (%check :runner-store-b-no-square
                     (zerop (dds.durability:store-count store-b "Square"))
                     (format nil "store-b must have 0 Square records (isolation), got ~d"
                             (dds.durability:store-count store-b "Square")))
             ;; runner-status: both alive
             (let ((status (dds.durability:runner-status runner)))
               (%check :runner-status-count
                       (= 2 (length status))
                       (format nil "runner-status must list 2 entries, got ~d" (length status)))
               (%check :runner-status-alive
                       (every #'cdr status)
                       (format nil "both services must be alive: ~a" status)))
             ;; runner-stop: all services go idle
             (dds.durability:runner-stop runner)
             (let ((status2 (dds.durability:runner-status runner)))
               (%check :runner-stopped
                       (notany #'cdr status2)
                       (format nil "after runner-stop all services must be stopped: ~a" status2))))
           t)
      (ignore-errors (dds.durability:runner-stop runner))
      (ignore-errors (dds.disc:stop-node pub-sq-node))
      (ignore-errors (dds.disc:stop-node pub-ci-node)))))

;;; --- supervisor: OTP-style one-for-one + restart-intensity (Task 7) ---
;;; Sub-test 1 (PURE, both impls): %restart-allowed-p restart-intensity math.
;;; Sub-test 2 (SBCL; Clasp-skip): liveness restart — kill service, assert revived.
;;; Sub-test 3 (SBCL; Clasp-skip): crash-loop shed — *durability-debug-start-fault*
;;;            makes a fresh service die immediately; after max-restarts the service
;;;            must be shed and the hook must have fired with :supervisor-shed.
;;; NFR-PORT: sub-tests 2+3 may be skipped on Clasp due to intermittent Clasp CLOS
;;; error-signaling SIGSEGV on multithreaded teardown (memory: clasp-threading-gap).
;;; Domain 37 avoids collision with domains 7/17/27.

(defun* run-durability-supervisor-test ()
    (function () t)
  "OTP-style supervisor: restart-intensity math (PURE), liveness restart, crash-loop shed."

  ;; --- Sub-test 1: PURE restart-intensity math (no threads) ---
  (let* ((now (get-internal-real-time))
         (itu  internal-time-units-per-second)
         (win  5)   ; 5-second window
         (cap  3))  ; max-restarts = 3
    ;; 2 stamps within the window: count=2 < cap=3 -> ALLOWED
    (let ((ts-2in (list (- now (* 1 itu))
                        (- now (* 2 itu)))))
      (%check :intensity-allow2
              (dds.durability::%restart-allowed-p ts-2in now win cap)
              "2 stamps in window, cap=3: next restart must be ALLOWED (count=2 < cap=3)"))
    ;; 3 stamps within the window: count=3 >= cap=3 -> DISALLOWED
    (let ((ts-in (list (- now (* 1 itu))
                       (- now (* 2 itu))
                       (- now (* 3 itu)))))
      (%check :intensity-shed-at3
              (not (dds.durability::%restart-allowed-p ts-in now win cap))
              "3 stamps in window, cap=3: next restart must be DISALLOWED (count=3 >= cap=3)")
      ;; 4 in-window stamps: count=4 > cap -> also DISALLOW
      (let ((ts-full (cons now ts-in)))
        (%check :intensity-shed4
                (not (dds.durability::%restart-allowed-p ts-full now win cap))
                "4 stamps in window, cap=3: must be DISALLOWED")))
    ;; timestamps strictly outside the window do NOT count toward the cap
    (let ((ts-old (list (- now (* (+ win 1) itu))
                        (- now (* (+ win 2) itu))
                        (- now (* (+ win 3) itu))
                        (- now (* (+ win 4) itu)))))
      (%check :intensity-outside-window
              (dds.durability::%restart-allowed-p ts-old now win cap)
              "timestamps outside window must not count toward cap: restart must be ALLOWED")))

  ;; --- Sub-tests 2+3 (live threads) ---
  (cond
    ((eq (dds.pal:pal-impl-name) :clasp)
     ;; NFR-PORT: Clasp intermittently SIGSEGVs in its own CLOS error-signaling on
     ;; multithreaded condvar teardown (memory: clasp-threading-gap). Skip the thread
     ;; sub-tests; the pure restart-intensity math above ran on both impls.
     (format t "~&    [supervisor] Clasp: skipping live-thread sub-tests (NFR-PORT gap)~%"))
    (t
     ;; Sub-test 2: liveness restart.
     ;; Start a runner+supervisor; forcibly stop the service; assert supervisor revives it.
     (let* ((spec (dds.durability:make-service-spec
                   :domain (test-domain +td-supervisor+)
                   :topics '(("SupSquare" . "ShapeType"))
                   :name "sup-liveness-test"))
            (runner (dds.durability:make-service-runner (list spec))))
       (unwind-protect
            (progn
              (dds.durability:runner-start runner)
              (let* ((svc (first (dds.durability:service-runner-services runner)))
                     (sup (dds.durability:make-supervisor runner
                                                         :max-restarts 3
                                                         :window-seconds 5
                                                         :poll-ms 50)))
                (dds.durability:supervisor-start sup)
                (%check :sup-start-alive
                        (dds.durability:service-alive-p svc)
                        "service must be alive after runner-start")
                ;; kill the service to simulate collect-loop death
                (dds.durability:service-stop svc)
                (%check :sup-killed
                        (not (dds.durability:service-alive-p svc))
                        "service must report dead after service-stop")
                ;; wait up to 2 s for the supervisor to restart it
                (loop repeat 400
                      until (let ((svcs2 (dds.durability:service-runner-services runner)))
                              (and svcs2 (dds.durability:service-alive-p (first svcs2))))
                      do (sleep 0.005))
                (let* ((svcs3 (dds.durability:service-runner-services runner))
                       (svc3  (first svcs3)))
                  (%check :sup-revived
                          (and svc3 (dds.durability:service-alive-p svc3))
                          "supervisor must revive the dead service within 2 s"))
                (dds.durability:supervisor-stop sup)
                ;; Orphan guard: the runner must still have exactly 1 service after supervisor-stop.
                ;; A stop-during-restart bug would cause the runner to have 0 (if the orphan was
                ;; never installed) or would leave a live orphan outside the runner (undetectable
                ;; from here). The count-1 assertion proves no spurious extra install occurred.
                (sleep 0.1)
                (let ((svcs4 (dds.durability:service-runner-services runner)))
                  (%check :sup-stop-services-count
                          (= 1 (length svcs4))
                          (format nil "after supervisor-stop, runner must have exactly 1 service, got ~d"
                                  (length svcs4))))))
         (ignore-errors (dds.durability:runner-stop runner))))

     ;; Sub-test 3: crash-loop shed via *durability-debug-start-fault*.
     ;; Sequence: runner-start (no fault) -> kill service -> supervisor-start WITH fault
     ;; so every restart attempt fails immediately -> supervisor sheds after max-restarts.
     (let* ((spec (dds.durability:make-service-spec
                   :domain (test-domain +td-supervisor+)
                   :topics '(("SupSquare2" . "ShapeType"))
                   :name "sup-crash-test"))
            (runner (dds.durability:make-service-runner (list spec)))
            (shed-context nil)
            (hook-fired nil))
       (let ((saved-hook dds.durability:*durability-error-hook*))
         (setf dds.durability:*durability-error-hook*
               (lambda (c ctx n)
                 (declare (ignore c n))
                 (setf hook-fired t)
                 (setf shed-context ctx)
                 t))
         (unwind-protect
              (progn
                (dds.durability:runner-start runner)
                ;; kill the initial service so the supervisor sees a dead service to restart
                (let ((svc0 (first (dds.durability:service-runner-services runner))))
                  (ignore-errors (dds.durability:service-stop svc0)))
                (let ((sup (dds.durability:make-supervisor runner
                                                           :max-restarts 2
                                                           :window-seconds 10
                                                           :poll-ms 30)))
                  ;; fault: set global so watcher thread (different thread) also sees it
                  (setf dds.durability:*durability-debug-start-fault* t)
                  (unwind-protect
                       (progn
                         (dds.durability:supervisor-start sup)
                         ;; wait up to 5 s for shed
                         (loop repeat 1000
                               until (dds.durability:supervisor-shed-p sup "sup-crash-test")
                               do (sleep 0.005)))
                    (setf dds.durability:*durability-debug-start-fault* nil))
                  (%check :sup-shed
                          (dds.durability:supervisor-shed-p sup "sup-crash-test")
                          "supervisor must shed service after max-restarts crash-loop")
                  (%check :sup-hook-fired
                          hook-fired
                          "supervisor must fire *durability-error-hook* with :supervisor-shed context")
                  (%check :sup-hook-context
                          (eq :supervisor-shed shed-context)
                          (format nil "hook context must be :supervisor-shed, got ~s" shed-context))
                  (dds.durability:supervisor-stop sup)))
           (ignore-errors (dds.durability:runner-stop runner))
           (setf dds.durability:*durability-error-hook* saved-hook))))))
  t)

;;; --- config parser + process-mode smoke (Task 8) ---
;;; run-durability-config-test: PURE (no I/O) — tests parse-durability-config.
;;; run-durability-process-smoke-test: %spec->argv round-trip proof (deterministic fallback);
;;; see task-8-report.md for the rationale (live subprocess too heavy for the CI harness).

(defun* run-durability-config-test ()
    (function () t)
  "PURE parse-durability-config: CLI tokens, env alist, CLI>env precedence, malformed guard,
   --name round-trip, supervisor opts (max-restarts/window-seconds) surfaced."
  ;; --- basic CLI parse: domain + two topics ---
  (let ((specs (dds.durability:parse-durability-config
                :argv (list "--domain" (princ-to-string (test-domain +td-cfg-domain+))
                            "--topic" "Square:ShapeType" "--topic" "Circle:ShapeType")
                :env  '())))
    (%check :cfg-one-spec (= 1 (length specs)) "CLI parse must yield exactly one spec")
    (let ((s (first specs)))
      (%check :cfg-domain (= (test-domain +td-cfg-domain+) (dds.durability:service-spec-domain s))
              "parsed --domain must equal the configured cfg-domain")
      (%check :cfg-square (dds.durability:service-spec-matches-p s "Square" "ShapeType")
              "Square:ShapeType must match")
      (%check :cfg-circle (dds.durability:service-spec-matches-p s "Circle" "ShapeType")
              "Circle:ShapeType must match")
      (%check :cfg-no-triangle (not (dds.durability:service-spec-matches-p s "Triangle" "ShapeType"))
              "Triangle must not match")))
  ;; --- env fallback: DDS_DURABILITY_TOPICS read when no --topic ---
  (let ((specs (dds.durability:parse-durability-config
                :argv '()
                :env  '(("DDS_DURABILITY_TOPICS" . "Square:ShapeType")))))
    (%check :cfg-env-topic
            (dds.durability:service-spec-matches-p (first specs) "Square" "ShapeType")
            "env DDS_DURABILITY_TOPICS must supply the topic filter"))
  ;; --- CLI --domain overrides env DDS_DURABILITY_DOMAIN ---
  (let ((specs (dds.durability:parse-durability-config
                :argv (list "--domain" (princ-to-string (test-domain +td-cfg-domain+)))
                :env  (list (cons "DDS_DURABILITY_DOMAIN"
                                  (princ-to-string (test-domain +td-cfg-env-domain+)))))))
    (%check :cfg-cli-overrides-env (= (test-domain +td-cfg-domain+) (dds.durability:service-spec-domain (first specs)))
            "CLI --domain must override env DDS_DURABILITY_DOMAIN"))
  ;; --- --name round-trip: CLI --name surfaced on spec, env DDS_DURABILITY_NAME fallback ---
  (multiple-value-bind (specs-n)
      (dds.durability:parse-durability-config
       :argv (list "--name" "my-service" "--domain" (princ-to-string (test-domain +td-cfg-domain+)))
       :env  '())
    (%check :cfg-name-cli (string= "my-service" (dds.durability:service-spec-name (first specs-n)))
            "CLI --name must be surfaced on the spec"))
  (multiple-value-bind (specs-env)
      (dds.durability:parse-durability-config
       :argv '()
       :env  '(("DDS_DURABILITY_NAME" . "env-svc")))
    (%check :cfg-name-env (string= "env-svc" (dds.durability:service-spec-name (first specs-env)))
            "env DDS_DURABILITY_NAME must supply the name when no CLI --name"))
  ;; CLI --name overrides env DDS_DURABILITY_NAME
  (multiple-value-bind (specs-prec)
      (dds.durability:parse-durability-config
       :argv '("--name" "cli-wins")
       :env  '(("DDS_DURABILITY_NAME" . "env-loses")))
    (%check :cfg-name-cli-wins (string= "cli-wins"
                                        (dds.durability:service-spec-name (first specs-prec)))
            "CLI --name must override env DDS_DURABILITY_NAME"))
  ;; --- supervisor opts surfaced: max-restarts and window-seconds returned as 2nd+3rd values ---
  (multiple-value-bind (specs-s mr ws)
      (dds.durability:parse-durability-config
       :argv '("--max-restarts" "7" "--window-seconds" "30")
       :env  '())
    (declare (ignore specs-s))
    (%check :cfg-max-restarts (= 7 mr) "parsed max-restarts must be 7")
    (%check :cfg-window-seconds (= 30 ws) "parsed window-seconds must be 30"))
  ;; defaults when not specified
  (multiple-value-bind (specs-d mr-d ws-d)
      (dds.durability:parse-durability-config :argv '() :env '())
    (declare (ignore specs-d))
    (%check :cfg-mr-default (= 3 mr-d) "default max-restarts must be 3")
    (%check :cfg-ws-default (= 5 ws-d) "default window-seconds must be 5"))
  ;; --- malformed --topic (no colon) must signal a clean condition, never crash ---
  (let ((errored nil))
    (handler-case
        (dds.durability:parse-durability-config
         :argv '("--topic" "NoColonHere") :env '())
      (error () (setf errored t)))
    (%check :cfg-malformed-topic errored
            "malformed --topic (no colon) must signal a condition"))
  ;; --- (safety 0) variant: the guard must be an explicit check, not a runtime type error ---
  (let ((errored nil))
    (handler-case
        (locally (declare (optimize (safety 0)))
          (dds.durability:parse-durability-config
           :argv '("--topic" "StillBad") :env '()))
      (error () (setf errored t)))
    (%check :cfg-malformed-safety0 errored
            "malformed --topic must signal even at (safety 0) — explicit manual check"))
  t)

(defun* run-durability-process-smoke-test ()
    (function () t)
  "Process-mode smoke: %spec->argv round-trip proof (deterministic; see task-8-report.md).
   Verifies domain, topics, mode AND name survive %spec->argv → parse-durability-config.
   On Clasp this test is skipped (Clasp threading gap; subprocess mode is SBCL-oriented)."
  (unless (eq (dds.pal:pal-impl-name) :sbcl)
    (format t "~&    [process-smoke] Clasp: skipping (NFR-PORT gap — subprocess mode is SBCL-oriented)~%")
    (return-from run-durability-process-smoke-test t))
  (let* ((spec (dds.durability:make-service-spec
                :domain (test-domain +td-writer-rep+)
                :topics '(("Square" . "ShapeType") ("Circle" . "ShapeType"))
                :mode :process
                :name "proc-smoke"))
         (argv (dds.durability::%spec->argv spec)))
    (multiple-value-bind (reparsed)
        (dds.durability:parse-durability-config :argv argv :env '())
      (let ((r (first reparsed)))
        (%check :proc-smoke-domain (= (test-domain +td-writer-rep+) (dds.durability:service-spec-domain r))
                "round-tripped spec domain must survive the %spec->argv round-trip")
        (%check :proc-smoke-square (dds.durability:service-spec-matches-p r "Square" "ShapeType")
                "round-tripped spec must match Square:ShapeType")
        (%check :proc-smoke-circle (dds.durability:service-spec-matches-p r "Circle" "ShapeType")
                "round-tripped spec must match Circle:ShapeType")
        (%check :proc-smoke-one-spec (= 1 (length reparsed))
                "round-trip must yield exactly one spec")
        (%check :proc-smoke-name (string= "proc-smoke" (dds.durability:service-spec-name r))
                "round-tripped spec name must equal original"))))
  t)

;;; --- runner lifecycle: null-services + concurrent-start guard (Task 7, owner directive) ---
;;; (a) After runner-stop, service-runner-services is NIL and runner-status is empty.
;;; (b) Calling runner-start twice does not double the services list.
;;; Uses lightweight specs on domains that receive no real traffic; we only need the
;;; services to START (bind a port, spawn a collect thread) for lifecycle assertions.
;;; Domain 47 avoids collision with domains 7/17/27/37.

;;; --- writer data-representation override (qos-overrides plumbing) ---
;;; Asserts that service-start honors :data-representation in service-spec qos-overrides:
;;;   (a) explicit (:xcdr1) override -> writer advertises (:xcdr1)  [foreign interop path]
;;;   (b) no override              -> writer advertises (:xcdr2)   [no-regression default]
;;; Reaches the advertised QoS via disc-node-local-writers -> endpoint-data-qos ->
;;; qos-data-representation.  Domain 57 avoids collision with domains 7/17/27/37/47.

(defun* run-durability-writer-rep-test ()
    (function () t)
  "QoS override plumbing: replay writer advertises :data-representation per qos-overrides;
   absent override keeps the default (:xcdr2) byte-identical to the prior behavior."
  ;; --- (a) explicit (:xcdr1) override ---
  (let* ((spec-xcdr1 (dds.durability:make-service-spec
                      :domain (test-domain +td-writer-rep+)
                      :topics '(("WRSquare" . "ShapeType"))
                      :qos-overrides '(:data-representation (:xcdr1))
                      :name "wr-rep-xcdr1"))
         (svc-xcdr1 (dds.durability:make-durability-service spec-xcdr1)))
    (unwind-protect
         (progn
           (dds.durability:service-start svc-xcdr1)
           (let* ((node (dds.durability:durability-service-node svc-xcdr1))
                  (writers (dds.disc::disc-node-local-writers node))
                  (rep (when writers
                         (dds.qos:qos-data-representation
                          (dds.rtps.discovery:endpoint-data-qos (first writers))))))
             (%check :wr-rep-xcdr1
                     (equal '(:xcdr1) rep)
                     (format nil "expected (:xcdr1) data-representation, got ~s" rep))))
      (ignore-errors (dds.durability:service-stop svc-xcdr1))))
  ;; --- (b) no override -> default (:xcdr2) ---
  (let* ((spec-default (dds.durability:make-service-spec
                        :domain (test-domain +td-writer-rep+)
                        :topics '(("WRCircle" . "ShapeType"))
                        :name "wr-rep-default"))
         (svc-default (dds.durability:make-durability-service spec-default)))
    (unwind-protect
         (progn
           (dds.durability:service-start svc-default)
           (let* ((node (dds.durability:durability-service-node svc-default))
                  (writers (dds.disc::disc-node-local-writers node))
                  (rep (when writers
                         (dds.qos:qos-data-representation
                          (dds.rtps.discovery:endpoint-data-qos (first writers))))))
             (%check :wr-rep-default
                     (equal '(:xcdr2) rep)
                     (format nil "expected default (:xcdr2) data-representation, got ~s" rep))))
      (ignore-errors (dds.durability:service-stop svc-default))))
  t)

(defun* run-durability-runner-lifecycle-test ()
    (function () t)
  "Runner lifecycle (owner directive): runner-stop nulls services; double runner-start is no-op."
  ;; --- (a) runner-stop nulls services ---
  (let* ((spec-a (dds.durability:make-service-spec
                  :domain (test-domain +td-runner-lifecycle+)
                  :topics '(("LCSquare" . "ShapeType"))
                  :name "lc-runner-a"))
         (spec-b (dds.durability:make-service-spec
                  :domain (test-domain +td-runner-lifecycle+)
                  :topics '(("LCCircle" . "ShapeType"))
                  :name "lc-runner-b"))
         (runner (dds.durability:make-service-runner (list spec-a spec-b))))
    (unwind-protect
         (progn
           (dds.durability:runner-start runner)
           (%check :lc-started-count
                   (= 2 (length (dds.durability:service-runner-services runner)))
                   (format nil "after runner-start, services must have 2 entries, got ~d"
                           (length (dds.durability:service-runner-services runner))))
           (dds.durability:runner-stop runner)
           (%check :lc-services-nil
                   (null (dds.durability:service-runner-services runner))
                   "after runner-stop, service-runner-services must be NIL")
           (%check :lc-status-empty
                   (null (dds.durability:runner-status runner))
                   "after runner-stop, runner-status must return an empty list"))
      (ignore-errors (dds.durability:runner-stop runner))))
  ;; --- (b) double runner-start is a no-op (services count must NOT double) ---
  (let* ((spec (dds.durability:make-service-spec
                :domain (test-domain +td-runner-lifecycle+)
                :topics '(("LCDouble" . "ShapeType"))
                :name "lc-double-start"))
         (runner (dds.durability:make-service-runner (list spec))))
    (unwind-protect
         (progn
           (dds.durability:runner-start runner)
           ;; the second start deliberately trips the concurrent-start guard, which WARNs by
           ;; design; muffle that EXPECTED warning so the suite output stays pristine.
           (handler-bind ((warning #'muffle-warning))
             (dds.durability:runner-start runner))   ; second call must be a no-op
           (%check :lc-no-double
                   (= 1 (length (dds.durability:service-runner-services runner)))
                   (format nil "double runner-start must not double services; got ~d"
                           (length (dds.durability:service-runner-services runner)))))
      (ignore-errors (dds.durability:runner-stop runner))))
  t)

;;; --- relay emit test (Task 3) ---
;;; Goal: the durability service's replay writer attaches PID_ORIGINAL_WRITER_INFO to every
;;; relayed DATA, carrying the ORIGINAL publisher's GUID and SN (not the relay writer's).
;;; Domain 67 avoids collisions with all prior tests.
;;;
;;; Approach:
;;;   1. Start service + publisher (domain 67), let service collect N=3 samples.
;;;   2. Stop the publisher (writer gone).
;;;   3. Bring up a TL late-joiner; capture the service node's outbound datagrams via
;;;      *datagram-sink* (bound around the late-joiner drain phase).
;;;   4. Parse the captured datagrams: find DATA submessages with Q-bit set, walk the
;;;      inline-QoS ParameterList to locate PID_ORIGINAL_WRITER_INFO (0x0061), extract
;;;      (guid, sn), assert GUID == original publisher's GUID and SN is one of {1..N}.

(defun* %parse-owi-from-datagram (datagram)
    (function ((simple-array (unsigned-byte 8) (*))) list)
  "Parse DATAGRAM (raw RTPS message bytes) and return a list of (guid . sn) pairs extracted
   from any PID_ORIGINAL_WRITER_INFO parameters found in inline-QoS of DATA submessages.
   Returns NIL if no such parameters are found. Bounds-checked throughout."
  (let ((buf (dds.core.buffer:octet-buffer-over datagram))
        (results '()))
    (dds.rtps.message:dispatch-message
     (dds.core.buffer:cursor buf :endianness :little)
     (lambda (id flags cursor body-len)
       (when (= id dds.rtps.message:+submsg-data+)
         (let ((body-end (+ (dds.core.buffer:cursor-position cursor) body-len)))
           (when (logtest flags dds.rtps.message:+data-flag-inline-qos+)
             (let ((pos (dds.core.buffer:cursor-position cursor)))
               (when (>= (- body-end pos) 20)
                 (dds.core.buffer:cursor-set-position cursor (+ pos 20))
                 (dds.rtps.message:parse-parameter-list
                  cursor
                  (lambda (pid c plen)
                    (when (= pid dds.rtps.message:+pid-original-writer-info+)
                      (let ((off (dds.core.buffer:cursor-position c)))
                        (multiple-value-bind (g s)
                            (dds.rtps.message:parse-original-writer-info
                             (dds.core.buffer:octet-buffer-vec (dds.core.buffer:cursor-buffer c))
                             off plen)
                          (when g
                            (push (cons g s) results)))))))))))))
     (length datagram))
    results))

(defun* run-relay-emit-test ()
    (function () t)
  "Relay emit: service replay writer attaches PID_ORIGINAL_WRITER_INFO with the ORIGINAL
   publisher's GUID + SN on every relayed DATA. Domain 67, loopback unicast, N=3 samples.
   Captures the service node's outbound datagrams via *datagram-sink* during the late-joiner
   drain phase and asserts on the DISTINCT (GUID,SN) OWI PID set (retransmit-insensitive, so
   deterministic under full-suite load where a reliable TL replay may re-send): (1) exactly N
   distinct OWI PIDs; (2) every distinct GUID matches the original publisher; (3) the distinct
   SN set is exactly {1..N}."
  (let* ((n 3)
         (svc-store (dds.durability:make-memory-store))
         (spec (dds.durability:make-service-spec
                :domain (test-domain +td-relay-emit+)
                :topics '(("RSquare" . "ShapeType"))
                :store (lambda () svc-store)
                :name "relay-emit-test"))
         (svc (dds.durability:make-durability-service spec :store svc-store))
         (pub-prefix (%make-test-prefix #xD7))
         (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain (test-domain +td-relay-emit+)
                                            :host "127.0.0.1" :port 0 :multicast nil))
         ;; original publisher GUID: prefix + user-writer EntityId (0x00000102 = key 1, kind 02)
         (orig-guid (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
                      (replace g pub-prefix :end1 12)
                      (setf (aref g 12) #x00 (aref g 13) #x00
                            (aref g 14) #x01 (aref g 15) #x02)
                      g)))
    (unwind-protect
         (progn
           (dds.durability:service-start svc)
           (let ((svc-node (dds.durability:durability-service-node svc)))
             ;; wire pub <-> service
             (setf (dds.disc:disc-node-peers pub-node)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-node))))
             (setf (dds.disc:disc-node-peers svc-node)
                   (list (cons "127.0.0.1" 0)))
             ;; configure publisher writer
             (dds.disc:add-local-writer pub-node :topic "RSquare" :type "ShapeType"
                                        :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                       :durability :transient-local))
             (dds.disc:enable-publisher pub-node :history-kind :keep-all)
             (dds.disc:start-node pub-node)
             (setf (dds.disc:disc-node-peers svc-node)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port pub-node))))
             ;; discovery
             (%await-match pub-node svc-node :retries 300 :sleep-s 0.02)
             ;; publish N samples
             (dotimes (i n)
               (dds.disc:publish-sample pub-node (%make-small-payload (1+ i))))
             ;; drain until service has collected all N
             (loop repeat 80
                   do (%announce-both pub-node svc-node) (sleep 0.05))
             (%await-store-count svc-store "RSquare" n)
             (%check :relay-collect
                     (= n (dds.durability:store-count svc-store "RSquare"))
                     (format nil "service should collect ~d before pub stops, got ~d"
                             n (dds.durability:store-count svc-store "RSquare")))
             ;; STOP publisher — original writer gone
             (ignore-errors (dds.disc:stop-node pub-node))
             (sleep 0.1)
             ;; bring up TL late-joiner
             (let* ((lj-prefix (%make-test-prefix #xE7))
                    (lj-node (dds.disc:make-disc-node :guid-prefix lj-prefix :domain (test-domain +td-relay-emit+)
                                                      :host "127.0.0.1" :port 0 :multicast nil))
                    (captured (make-array 0 :element-type t :adjustable t :fill-pointer 0)))
               (unwind-protect
                    (progn
                      (dds.disc:add-local-reader lj-node :topic "RSquare" :type "ShapeType"
                                                 :qos (dds.qos:make-reader-qos
                                                       :reliability :reliable
                                                       :durability :transient-local))
                      (dds.disc:enable-subscriber lj-node)
                      (setf (dds.disc:disc-node-on-match lj-node)
                            (lambda (kind remote &optional local-eid) (declare (ignore local-eid))
                              (when (eq kind :remote-writer)
                                (dds.disc:%reader-durability-init
                                 lj-node
                                 (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                                 (dds.qos:qos-durability
                                  (dds.rtps.discovery:endpoint-data-qos remote))))))
                      (dds.disc:start-node lj-node)
                      ;; wire lj <-> service
                      (setf (dds.disc:disc-node-peers lj-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-node))))
                      (setf (dds.disc:disc-node-peers svc-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port lj-node))))
                      ;; capture ALL outbound datagrams during drain (global setf — the service
                      ;; sends from its receiver thread, not the test thread, so a LET binding
                      ;; would be invisible there; restore in unwind-protect)
                      (unwind-protect
                           (progn
                             (setf dds.disc:*datagram-sink*
                                   (lambda (dg) (vector-push-extend (copy-seq dg) captured)))
                             (%await-match lj-node svc-node :retries 300 :sleep-s 0.02)
                             (%await-sample-count lj-node n :retries 1200 :sleep-s 0.005))
                        (setf dds.disc:*datagram-sink* nil))
                      ;; assert late-joiner got the samples
                      (%check :relay-lj-count
                              (= n (dds.disc:node-sample-count lj-node))
                              (format nil "TL late-joiner expected ~d relayed samples, got ~d"
                                      n (dds.disc:node-sample-count lj-node)))
                      ;; parse captured datagrams for PID_ORIGINAL_WRITER_INFO
                      (let ((owi-hits '()))
                        (loop for dg across captured
                              do (dolist (pair (%parse-owi-from-datagram dg))
                                   (push pair owi-hits)))
                        ;; a reliable TL replay may RETRANSMIT a relayed DATA (NACK/HEARTBEAT under load), re-emitting the same (GUID,SN) OWI PID;
                        ;; the tested property is the SET of relayed origins, so dedup by (GUID,SN) — a retransmit adds no new member (deterministic).
                        (let ((distinct (remove-duplicates
                                         owi-hits
                                         :test (lambda (a b) (and (equalp (car a) (car b)) (= (cdr a) (cdr b)))))))
                          ;; exactly N DISTINCT OWI PIDs — one per relayed origin sample (retransmits dedup out)
                          (%check :relay-owi-count
                                  (= n (length distinct))
                                  (format nil "expected ~d DISTINCT OWI PIDs, got ~d (raw hits ~d)"
                                          n (length distinct) (length owi-hits)))
                          ;; every distinct OWI GUID must match the original publisher
                          (%check :relay-owi-guid
                                  (every (lambda (pair) (equalp orig-guid (car pair))) distinct)
                                  (format nil "OWI GUID mismatch — expected ~s, got ~s"
                                          (coerce orig-guid 'list)
                                          (mapcar (lambda (p) (coerce (car p) 'list)) distinct)))
                          ;; the distinct OWI SNs must be EXACTLY the original set {1..N}
                          (%check :relay-owi-sn
                                  (equal (sort (mapcar #'cdr distinct) #'<)
                                         (loop for i from 1 to n collect i))
                                  (format nil "OWI SN set must be {1..~d}, got ~s"
                                          n (sort (mapcar #'cdr distinct) #'<))))))
                 (ignore-errors (dds.disc:stop-node lj-node))))))
      (ignore-errors (dds.durability:service-stop svc)))))

;;; --- cross-vendor N-relay dedup confirmation (WP-DURABILITY-COEXIST-DEDUP) ---
;;; The receiver dedup keys on the standard PID_ORIGINAL_WRITER_INFO (origin GUID, SN) tuple,
;;; independent of which / how-many relays delivered it. RTI Persistence Service stamps that SAME
;;; standard tuple on its retained-history replay (Task-1 spike), so to the dedup it is just another
;;; standard-OWI relay — any number of relays of one publisher collapse to exactly N. Deterministic.

(defun* run-durability-multi-relay-dedup-test ()
    (function () t)
  "Receiver dedup is relay-count-agnostic (the cross-vendor essence, ADR 0026 §10): K relays each
   delivering the SAME origin (GUID, SN) set 1..N collapse to EXACTLY N deliveries; a distinct origin
   is independent (no false cross-origin reject); interleaved/reordered relays still deliver each SN
   exactly once (RTPS 2.5 §8.3.5.4, ADR 0024). No networking — exercises reader-dedup-accept-p directly."
  (let* ((reader (dds.rtps.reliable:make-rtps-reader))
         (g  (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x5A))
         (n  50)
         (k  3)
         (accepts 0))
    ;; K relays (our relay + RTI PS + a third), each delivering origin (g, 1..n): exactly N accepts total
    (dotimes (_ k)
      (loop for sn from 1 to n
            when (dds.rtps.reliable:reader-dedup-accept-p reader g sn) do (incf accepts)))
    (%check :multi-relay-exactly-once
            (= n accepts)
            (format nil "K=~d relays of one origin must collapse to exactly N=~d, got ~d" k n accepts))
    ;; a DIFFERENT origin is independent (per-origin dedup, never a false cross-origin reject)
    (let ((g2 (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x6B)))
      (%check :multi-relay-distinct-origin
              (dds.rtps.reliable:reader-dedup-accept-p reader g2 1)
              "a different origin GUID must be accepted (dedup is strictly per-origin)"))
    ;; interleaved/reordered relays: relay A sends odd SNs, relay B then sends ALL — still exactly N
    (let* ((reader2 (dds.rtps.reliable:make-rtps-reader))
           (g3 (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x7C))
           (acc2 0))
      (loop for sn from 1 to n by 2
            when (dds.rtps.reliable:reader-dedup-accept-p reader2 g3 sn) do (incf acc2))
      (loop for sn from 1 to n
            when (dds.rtps.reliable:reader-dedup-accept-p reader2 g3 sn) do (incf acc2))
      (%check :multi-relay-reordered-exactly-once
              (= n acc2)
              (format nil "interleaved relays (odds then all) must deliver exactly N=~d, got ~d" n acc2))))
  t)

;;; --- no-double-delivery test (Task 4: WP-DURABILITY-DEDUP) ---
;;; Headline end-to-end: an ALIVE original writer + a durability service relay BOTH
;;; send the same N samples to the same reader. The original-GUID max-SN dedup gate
;;; must collapse both copies so the reader receives exactly N samples, not 2N.
;;; Domain 77 (avoids collision with existing tests). Loopback unicast, triangular wiring:
;;;   pub <-> svc  (service collects via HEARTBEAT/ACKNACK repair)
;;;   svc <-> sub  (relay sends retained history to the subscriber)
;;;   pub <-> sub  (original writer also sends live DATA directly to subscriber)
;;; The service relay attaches PID_ORIGINAL_WRITER_INFO (Task 3); the original writer's
;;; direct DATA carries no PID (treated as "carries the original GUID natively" via
;;; the effective-GUID fallback in the disc dispatcher). Either copy arrives first; the
;;; dedup map collapses the second. Expected: sub sample count == N (not 2N).

(defun* run-durability-no-double-delivery-test ()
    (function () t)
  "No-double-delivery: alive original writer + service relay both send N samples to
   a reader; original-GUID dedup collapses them to exactly N deliveries. Domain 77."
  (let* ((n 3)
         (svc-store (dds.durability:make-memory-store))
         (spec (dds.durability:make-service-spec
                :domain (test-domain +td-no-double-delivery+)
                :topics '(("DSquare" . "ShapeType"))
                :store (lambda () svc-store)
                :name "no-double-delivery-test"))
         (svc (dds.durability:make-durability-service spec :store svc-store))
         (pub-prefix (%make-test-prefix #xD9))
         (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain (test-domain +td-no-double-delivery+)
                                            :host "127.0.0.1" :port 0 :multicast nil))
         (sub-prefix (%make-test-prefix #xE9))
         (sub-node (dds.disc:make-disc-node :guid-prefix sub-prefix :domain (test-domain +td-no-double-delivery+)
                                            :host "127.0.0.1" :port 0 :multicast nil)))
    (unwind-protect
         (progn
           ;; start durability service
           (dds.durability:service-start svc)
           (let ((svc-node (dds.durability:durability-service-node svc)))
             ;; configure publisher
             (dds.disc:add-local-writer pub-node :topic "DSquare" :type "ShapeType"
                                        :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                       :durability :transient-local))
             (dds.disc:enable-publisher pub-node :history-kind :keep-all)
             (dds.disc:start-node pub-node)
             ;; configure subscriber (TL reader, matched to both pub + relay)
             (dds.disc:add-local-reader sub-node :topic "DSquare" :type "ShapeType"
                                        :qos (dds.qos:make-reader-qos :reliability :reliable
                                                                       :durability :transient-local))
             (dds.disc:enable-subscriber sub-node)
             ;; install on-match to init durability so TL reader requests history from relay
             (setf (dds.disc:disc-node-on-match sub-node)
                   (lambda (kind remote &optional local-eid) (declare (ignore local-eid))
                     (when (eq kind :remote-writer)
                       (dds.disc:%reader-durability-init
                        sub-node
                        (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                        (dds.qos:qos-durability
                         (dds.rtps.discovery:endpoint-data-qos remote))))))
             (dds.disc:start-node sub-node)
             ;; triangular wiring: pub <-> svc, pub <-> sub, svc <-> sub
             (let ((pub-port (dds.disc:disc-node-port pub-node))
                   (svc-port (dds.disc:disc-node-port svc-node))
                   (sub-port (dds.disc:disc-node-port sub-node)))
               (setf (dds.disc:disc-node-peers pub-node)
                     (list (cons "127.0.0.1" svc-port) (cons "127.0.0.1" sub-port)))
               (setf (dds.disc:disc-node-peers svc-node)
                     (list (cons "127.0.0.1" pub-port) (cons "127.0.0.1" sub-port)))
               (setf (dds.disc:disc-node-peers sub-node)
                     (list (cons "127.0.0.1" pub-port) (cons "127.0.0.1" svc-port))))
             ;; discovery: announce until everyone has matched
             (loop repeat 400
                   until (and (>= (dds.disc:disc-node-matched-count pub-node) 2)
                              (plusp (dds.disc:disc-node-matched-count
                                      (dds.durability:durability-service-node svc)))
                              (>= (dds.disc:disc-node-matched-count sub-node) 2))
                   do (dds.disc:announce-participant pub-node)
                      (dds.disc:announce-endpoints pub-node)
                      (dds.disc:announce-participant (dds.durability:durability-service-node svc))
                      (dds.disc:announce-endpoints (dds.durability:durability-service-node svc))
                      (dds.disc:announce-participant sub-node)
                      (dds.disc:announce-endpoints sub-node)
                      (sleep 0.02))
             ;; publish N samples from the original writer (alive; sends to sub AND svc)
             (dotimes (i n)
               (dds.disc:publish-sample pub-node (%make-small-payload (1+ i))))
             ;; drain heartbeats: push HBs so svc and sub process the data
             (loop repeat 120
                   do (dds.disc:announce-participant pub-node)
                      (dds.disc:announce-endpoints pub-node)
                      (dds.disc:announce-participant (dds.durability:durability-service-node svc))
                      (dds.disc:announce-endpoints (dds.durability:durability-service-node svc))
                      (dds.disc:announce-participant sub-node)
                      (dds.disc:announce-endpoints sub-node)
                      (sleep 0.05))
             ;; wait for service store to fill (it collects from the pub)
             (%await-store-count svc-store "DSquare" n :retries 1200 :sleep-s 0.005)
             ;; wait for subscriber to have settled (relay + direct both delivered)
             (%await-sample-count sub-node n :retries 1200 :sleep-s 0.005)
             ;; key assertion: exactly N samples, NOT 2N (the dedup collapsed both copies)
             (%check :no-double-delivery
                     (= n (dds.disc:node-sample-count sub-node))
                     (format nil "expected exactly ~d samples (no double delivery), got ~d"
                             n (dds.disc:node-sample-count sub-node)))
             t))
      (ignore-errors (dds.disc:stop-node sub-node))
      (ignore-errors (dds.disc:stop-node pub-node))
      (ignore-errors (dds.durability:service-stop svc)))))

;;; --- multi-topic service test (Task 5: WP-DURABILITY-DEDUP Phase 2) ---
;;; A single durability-service with topics '(("Square" . "ShapeType") ("Circle" . "ShapeType"))
;;; holds two disc-nodes (one per topic). Two separate publisher nodes write TL samples to each
;;; topic respectively (one-writer-per-node invariant), then exit. A late-joiner on each topic
;;; receives that topic's retained history from the service. Topic isolation is asserted:
;;; the service's per-topic store entries are counted per topic. Domain 87.

(defun* run-durability-multitopic-test ()
    (function () t)
  "Multi-topic service (K=2): one service, two disc-nodes, two pub nodes, two late-joiners.
   Asserts per-topic store isolation, late-joiner delivery on both topics, and pristine stop.
   Domain 87, loopback unicast, no multicast."
  (let* ((n-sq 3)
         (n-ci 2)
         (svc-store (dds.durability:make-memory-store))
         (spec (dds.durability:make-service-spec
                :domain (test-domain +td-multitopic+)
                :topics '(("Square" . "ShapeType") ("Circle" . "ShapeType"))
                :store (lambda () svc-store)
                :name "multitopic-test"))
         (svc (dds.durability:make-durability-service spec :store svc-store))
         ;; two publisher nodes: one per topic (one-writer-per-node invariant)
         (pub-sq-node (dds.disc:make-disc-node
                       :guid-prefix (%make-test-prefix #xA1) :domain (test-domain +td-multitopic+)
                       :host "127.0.0.1" :port 0 :multicast nil))
         (pub-ci-node (dds.disc:make-disc-node
                       :guid-prefix (%make-test-prefix #xA2) :domain (test-domain +td-multitopic+)
                       :host "127.0.0.1" :port 0 :multicast nil)))
    (unwind-protect
         (progn
           ;; start service: builds two disc-nodes (one per topic), spawns two collect loops
           (dds.durability:service-start svc)
           (let* ((svc-nodes (dds.durability:durability-service-nodes svc))
                  (svc-sq-node (car (first  svc-nodes)))
                  (svc-ci-node (car (second svc-nodes))))
             ;; set up Square publisher
             (dds.disc:add-local-writer pub-sq-node :topic "Square" :type "ShapeType"
                                        :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                       :durability :transient-local))
             (dds.disc:enable-publisher pub-sq-node :history-kind :keep-all)
             (dds.disc:start-node pub-sq-node)
             ;; set up Circle publisher
             (dds.disc:add-local-writer pub-ci-node :topic "Circle" :type "ShapeType"
                                        :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                       :durability :transient-local))
             (dds.disc:enable-publisher pub-ci-node :history-kind :keep-all)
             (dds.disc:start-node pub-ci-node)
             ;; wire unicast: svc-sq-node <-> pub-sq-node, svc-ci-node <-> pub-ci-node
             (setf (dds.disc:disc-node-peers pub-sq-node)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-sq-node))))
             (setf (dds.disc:disc-node-peers pub-ci-node)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-ci-node))))
             (setf (dds.disc:disc-node-peers svc-sq-node)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port pub-sq-node))))
             (setf (dds.disc:disc-node-peers svc-ci-node)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port pub-ci-node))))
             ;; discovery: announce until both service nodes matched their respective publishers
             (loop repeat 300
                   until (and (plusp (dds.disc:disc-node-matched-count svc-sq-node))
                              (plusp (dds.disc:disc-node-matched-count svc-ci-node)))
                   do (dds.disc:announce-participant pub-sq-node)
                      (dds.disc:announce-endpoints   pub-sq-node)
                      (dds.disc:announce-participant pub-ci-node)
                      (dds.disc:announce-endpoints   pub-ci-node)
                      (dds.disc:announce-participant svc-sq-node)
                      (dds.disc:announce-endpoints   svc-sq-node)
                      (dds.disc:announce-participant svc-ci-node)
                      (dds.disc:announce-endpoints   svc-ci-node)
                      (sleep 0.02))
             ;; publish N-SQ Square samples and N-CI Circle samples
             (dotimes (i n-sq) (dds.disc:publish-sample pub-sq-node (%make-small-payload (1+ i))))
             (dotimes (i n-ci) (dds.disc:publish-sample pub-ci-node (%make-small-payload (+ 10 i))))
             ;; drain heartbeats so service readers collect the data
             (loop repeat 80
                   do (dds.disc:announce-participant pub-sq-node)
                      (dds.disc:announce-endpoints   pub-sq-node)
                      (dds.disc:announce-participant pub-ci-node)
                      (dds.disc:announce-endpoints   pub-ci-node)
                      (sleep 0.05))
             ;; wait for both topics to be collected
             (%await-store-count svc-store "Square" n-sq :retries 1200 :sleep-s 0.005)
             (%await-store-count svc-store "Circle" n-ci :retries 1200 :sleep-s 0.005)
             ;; assert per-topic store isolation before stopping publishers
             (%check :mt-sq-count
                     (= n-sq (dds.durability:store-count svc-store "Square"))
                     (format nil "service Square store expected ~d, got ~d"
                             n-sq (dds.durability:store-count svc-store "Square")))
             (%check :mt-ci-count
                     (= n-ci (dds.durability:store-count svc-store "Circle"))
                     (format nil "service Circle store expected ~d, got ~d"
                             n-ci (dds.durability:store-count svc-store "Circle")))
             (%check :mt-store-isolation
                     (and (= n-sq (dds.durability:store-count svc-store "Square"))
                          (= n-ci (dds.durability:store-count svc-store "Circle"))
                          (null (set-difference (dds.durability:store-topics svc-store)
                                                '("Square" "Circle") :test #'string=)))
                     "per-topic isolation: store has exactly {Square:~d, Circle:~d} and no other topic")
             ;; stop publishers — original writers gone
             (ignore-errors (dds.disc:stop-node pub-sq-node))
             (ignore-errors (dds.disc:stop-node pub-ci-node))
             (sleep 0.1)
             ;; late-joiner 1: TL reader on Square expects N-SQ from the service
             (let* ((lj-sq (dds.disc:make-disc-node
                             :guid-prefix (%make-test-prefix #xB1) :domain (test-domain +td-multitopic+)
                             :host "127.0.0.1" :port 0 :multicast nil)))
               (unwind-protect
                    (progn
                      (dds.disc:add-local-reader lj-sq :topic "Square" :type "ShapeType"
                                                 :qos (dds.qos:make-reader-qos
                                                       :reliability :reliable
                                                       :durability :transient-local))
                      (dds.disc:enable-subscriber lj-sq)
                      (setf (dds.disc:disc-node-on-match lj-sq)
                            (lambda (kind remote &optional local-eid) (declare (ignore local-eid))
                              (when (eq kind :remote-writer)
                                (dds.disc:%reader-durability-init
                                 lj-sq
                                 (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                                 (dds.qos:qos-durability
                                  (dds.rtps.discovery:endpoint-data-qos remote))))))
                      (dds.disc:start-node lj-sq)
                      (setf (dds.disc:disc-node-peers lj-sq)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-sq-node))))
                      (setf (dds.disc:disc-node-peers svc-sq-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port lj-sq))))
                      (%await-match lj-sq svc-sq-node :retries 300 :sleep-s 0.02)
                      (%await-sample-count lj-sq n-sq :retries 1200 :sleep-s 0.005)
                      (%check :mt-lj-sq-count
                              (= n-sq (dds.disc:node-sample-count lj-sq))
                              (format nil "TL Square late-joiner expected ~d, got ~d"
                                      n-sq (dds.disc:node-sample-count lj-sq))))
                 (ignore-errors (dds.disc:stop-node lj-sq))))
             ;; late-joiner 2: TL reader on Circle expects N-CI from the service
             (let* ((lj-ci (dds.disc:make-disc-node
                             :guid-prefix (%make-test-prefix #xB2) :domain (test-domain +td-multitopic+)
                             :host "127.0.0.1" :port 0 :multicast nil)))
               (unwind-protect
                    (progn
                      (dds.disc:add-local-reader lj-ci :topic "Circle" :type "ShapeType"
                                                 :qos (dds.qos:make-reader-qos
                                                       :reliability :reliable
                                                       :durability :transient-local))
                      (dds.disc:enable-subscriber lj-ci)
                      (setf (dds.disc:disc-node-on-match lj-ci)
                            (lambda (kind remote &optional local-eid) (declare (ignore local-eid))
                              (when (eq kind :remote-writer)
                                (dds.disc:%reader-durability-init
                                 lj-ci
                                 (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                                 (dds.qos:qos-durability
                                  (dds.rtps.discovery:endpoint-data-qos remote))))))
                      (dds.disc:start-node lj-ci)
                      (setf (dds.disc:disc-node-peers lj-ci)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-ci-node))))
                      (setf (dds.disc:disc-node-peers svc-ci-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port lj-ci))))
                      (%await-match lj-ci svc-ci-node :retries 300 :sleep-s 0.02)
                      (%await-sample-count lj-ci n-ci :retries 1200 :sleep-s 0.005)
                      (%check :mt-lj-ci-count
                              (= n-ci (dds.disc:node-sample-count lj-ci))
                              (format nil "TL Circle late-joiner expected ~d, got ~d"
                                      n-ci (dds.disc:node-sample-count lj-ci))))
                 (ignore-errors (dds.disc:stop-node lj-ci))))
             t))
      (ignore-errors (dds.disc:stop-node pub-sq-node))
      (ignore-errors (dds.disc:stop-node pub-ci-node))
      (ignore-errors (dds.durability:service-stop svc)))))

;;; --- dispose-replay test (Task 6: WP-DURABILITY-DEDUP Phase 2) ---
;;; A TL publisher writes N=3 samples to a topic, then DISPOSES an instance
;;; (via dds.disc:dispose-instance).  The durability service collects the data
;;; AND the dispose into the store (kind=:dispose record).  Then the original
;;; writer STOPS.  A TL late-joiner receives the full pre-join history: N data
;;; samples + the dispose lifecycle change.  Assert that the late-joiner's
;;; node-lifecycle-count >= 1 and the lifecycle change has kind :dispose.
;;; Domain 97 avoids collision with all prior tests.

(defun* run-durability-dispose-replay-test ()
    (function () t)
  "Dispose/unregister capture + replay: publisher writes N TL samples then disposes
   an instance; service collects data + dispose; TL late-joiner receives data history
   AND the dispose (lifecycle kind :dispose observed).  Domain 97, loopback unicast."
  (let* ((n 3)
         (svc-store (dds.durability:make-memory-store))
         (spec (dds.durability:make-service-spec
                :domain (test-domain +td-dispose-replay+)
                :topics '(("DRSquare" . "ShapeType"))
                :store (lambda () svc-store)
                :name "dispose-replay-test"))
         (svc (dds.durability:make-durability-service spec :store svc-store))
         (pub-prefix (%make-test-prefix #xC9))
         (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain (test-domain +td-dispose-replay+)
                                            :host "127.0.0.1" :port 0 :multicast nil))
         ;; key-hash used for dispose: 16 bytes, first byte 0xAB
         (kh (let ((k (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref k 0) #xAB) k)))
    (unwind-protect
         (progn
           (dds.durability:service-start svc)
           (let ((svc-node (dds.durability:durability-service-node svc)))
             (setf (dds.disc:disc-node-peers pub-node)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-node))))
             (setf (dds.disc:disc-node-peers svc-node)
                   (list (cons "127.0.0.1" 0)))
             (dds.disc:add-local-writer pub-node :topic "DRSquare" :type "ShapeType"
                                        :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                       :durability :transient-local))
             (dds.disc:enable-publisher pub-node :history-kind :keep-all)
             (dds.disc:start-node pub-node)
             (setf (dds.disc:disc-node-peers svc-node)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port pub-node))))
             (%await-match pub-node svc-node :retries 300 :sleep-s 0.02)
             ;; publish N data samples
             (dotimes (i n)
               (dds.disc:publish-sample pub-node (%make-small-payload (1+ i))))
             ;; dispose the instance
             (dds.disc:dispose-instance pub-node kh)
             ;; drain heartbeats so service reader collects data + lifecycle
             (loop repeat 80
                   do (%announce-both pub-node svc-node) (sleep 0.05))
             ;; wait for store to have N data records + 1 lifecycle record (N+1 total)
             (%await-store-count svc-store "DRSquare" (1+ n) :retries 1200 :sleep-s 0.005)
             ;; verify store has the dispose record
             (%check :dr-store-total
                     (= (1+ n) (dds.durability:store-count svc-store "DRSquare"))
                     (format nil "store must have ~d records (data+dispose), got ~d"
                             (1+ n) (dds.durability:store-count svc-store "DRSquare")))
             (let* ((recs (dds.durability:store-get-range svc-store "DRSquare"))
                    (dispose-recs (remove-if-not
                                   (lambda (r) (eq :dispose (dds.durability:durable-record-kind r)))
                                   recs)))
               (%check :dr-store-dispose-kind
                       (= 1 (length dispose-recs))
                       (format nil "store must have 1 dispose record, got ~d" (length dispose-recs))))
             ;; stop the publisher — original writer gone
             (ignore-errors (dds.disc:stop-node pub-node))
             (sleep 0.1)
             ;; TL late-joiner: receives data history + dispose from the service
             (let* ((lj-prefix (%make-test-prefix #xD9))
                    (lj-node (dds.disc:make-disc-node :guid-prefix lj-prefix :domain (test-domain +td-dispose-replay+)
                                                      :host "127.0.0.1" :port 0 :multicast nil)))
               (unwind-protect
                    (progn
                      (dds.disc:add-local-reader lj-node :topic "DRSquare" :type "ShapeType"
                                                 :qos (dds.qos:make-reader-qos
                                                       :reliability :reliable
                                                       :durability :transient-local))
                      (dds.disc:enable-subscriber lj-node)
                      (setf (dds.disc:disc-node-on-match lj-node)
                            (lambda (kind remote &optional local-eid) (declare (ignore local-eid))
                              (when (eq kind :remote-writer)
                                (dds.disc:%reader-durability-init
                                 lj-node
                                 (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                                 (dds.qos:qos-durability
                                  (dds.rtps.discovery:endpoint-data-qos remote))))))
                      (dds.disc:start-node lj-node)
                      (setf (dds.disc:disc-node-peers lj-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-node))))
                      (setf (dds.disc:disc-node-peers svc-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port lj-node))))
                      (%await-match lj-node svc-node :retries 300 :sleep-s 0.02)
                      ;; wait for data samples
                      (%await-sample-count lj-node n :retries 1200 :sleep-s 0.005)
                      ;; wait for lifecycle change (dispose) to arrive
                      (loop repeat 1200
                            until (plusp (dds.disc:node-lifecycle-count lj-node))
                            do (sleep 0.005))
                      ;; data assertion
                      (%check :dr-lj-data-count
                              (= n (dds.disc:node-sample-count lj-node))
                              (format nil "TL late-joiner expected ~d data samples, got ~d"
                                      n (dds.disc:node-sample-count lj-node)))
                      ;; lifecycle assertion: at least one dispose received
                      (%check :dr-lj-lifecycle-count
                              (plusp (dds.disc:node-lifecycle-count lj-node))
                              (format nil "TL late-joiner must receive at least 1 lifecycle change, got ~d"
                                      (dds.disc:node-lifecycle-count lj-node)))
                      ;; verify the lifecycle kind is :dispose
                      (let* ((lc-sns (dds.disc:node-lifecycle-sns lj-node))
                             (lc-rec (and lc-sns (dds.disc:node-lifecycle-change lj-node (first lc-sns)))))
                        (%check :dr-lj-dispose-kind
                                (and lc-rec (eq :dispose (first lc-rec)))
                                (format nil "lifecycle change must be :dispose, got ~s"
                                        (and lc-rec (first lc-rec))))))
                 (ignore-errors (dds.disc:stop-node lj-node)))))
           t)
      (ignore-errors (dds.disc:stop-node pub-node))
      (ignore-errors (dds.durability:service-stop svc)))))

;;; --- DARE-wrapped service transparency (Task 6 cap.7) ---
;;; Publisher writes N=5 TL samples; service collects via an encrypted store (DARE-sealed);
;;; TL late-joiner receives all N byte-exact — DARE is transparent to the relay path.
;;; Domain 107 avoids collision with all other harness domains (7,17,27,37,47,57,67,77,87,97).

(defun* run-dare-service-transparency-test ()
    (function () t)
  "DARE-wrapped durability service: publisher writes N TL samples; service seals into encrypted store;
   TL late-joiner receives all N byte-exact (DARE transparent to relay path). Domain 107, loopback unicast."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [dare-service-transparency] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-dare-service-transparency-test t)))
  (let* ((n 5)
         (tmp-dir (uiop:merge-pathnames*
                   (make-pathname :directory (list :relative
                                                   (format nil "dds-dare-svc-test-~a"
                                                           (get-universal-time))))
                   (uiop:temporary-directory)))
         (kp (dds.dare:make-file-key-provider :dir tmp-dir))
         (svc-store (dds.durability:make-encrypted-store
                     (dds.durability:make-memory-store) kp))
         (spec (dds.durability:make-service-spec
                :domain (test-domain +td-dare-transparency+)
                :topics '(("Square" . "ShapeType"))
                :store (lambda () svc-store)
                :name "dare-transparency-test"))
         (svc (dds.durability:make-durability-service spec :store svc-store))
         (pub-prefix (%make-test-prefix #xD3))
         (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain (test-domain +td-dare-transparency+)
                                            :host "127.0.0.1" :port 0 :multicast nil)))
    (unwind-protect
         (progn
           (dds.durability:service-start svc)
           (let ((svc-node (dds.durability:durability-service-node svc)))
             (setf (dds.disc:disc-node-peers pub-node)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-node))))
             (setf (dds.disc:disc-node-peers svc-node)
                   (list (cons "127.0.0.1" 0)))
             (dds.disc:add-local-writer pub-node :topic "Square" :type "ShapeType"
                                        :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                       :durability :transient-local))
             (dds.disc:enable-publisher pub-node :history-kind :keep-all)
             (dds.disc:start-node pub-node)
             (setf (dds.disc:disc-node-peers svc-node)
                   (list (cons "127.0.0.1" (dds.disc:disc-node-port pub-node))))
             (%await-match pub-node svc-node :retries 300 :sleep-s 0.02)
             (dotimes (i n) (dds.disc:publish-sample pub-node (%make-small-payload (1+ i))))
             (loop repeat 80
                   do (%announce-both pub-node svc-node) (sleep 0.05))
             (%await-store-count svc-store "Square" n)
             (%check :dare-svc-collected
                     (= n (dds.durability:store-count svc-store "Square"))
                     (format nil "service should have collected ~d before publisher stopped, got ~d"
                             n (dds.durability:store-count svc-store "Square")))
             (ignore-errors (dds.disc:stop-node pub-node))
             (sleep 0.1)
             (let* ((lj-prefix (%make-test-prefix #xE3))
                    (lj-node (dds.disc:make-disc-node :guid-prefix lj-prefix :domain (test-domain +td-dare-transparency+)
                                                      :host "127.0.0.1" :port 0 :multicast nil)))
               (unwind-protect
                    (progn
                      (dds.disc:add-local-reader lj-node :topic "Square" :type "ShapeType"
                                                 :qos (dds.qos:make-reader-qos
                                                       :reliability :reliable
                                                       :durability :transient-local))
                      (dds.disc:enable-subscriber lj-node)
                      (setf (dds.disc:disc-node-on-match lj-node)
                            (lambda (kind remote &optional local-eid) (declare (ignore local-eid))
                              (when (eq kind :remote-writer)
                                (dds.disc:%reader-durability-init
                                 lj-node
                                 (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                                 (dds.qos:qos-durability
                                  (dds.rtps.discovery:endpoint-data-qos remote))))))
                      (dds.disc:start-node lj-node)
                      (setf (dds.disc:disc-node-peers lj-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-node))))
                      (setf (dds.disc:disc-node-peers svc-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port lj-node))))
                      (%await-match lj-node svc-node :retries 300 :sleep-s 0.02)
                      (%await-sample-count lj-node n :retries 1200 :sleep-s 0.005)
                      (%check :dare-transparency-lj-count
                              (= n (dds.disc:node-sample-count lj-node))
                              (format nil "DARE-wrapped service: TL late-joiner expected ~d, got ~d"
                                      n (dds.disc:node-sample-count lj-node))))
                 (ignore-errors (dds.disc:stop-node lj-node))))
             t))
      (ignore-errors (dds.durability:service-stop svc))
      (ignore-errors (dds.disc:stop-node pub-node))
      ;; close the encrypted store so its DEK (foreign static-vector) is zeroized + freed
      (ignore-errors (dds.durability:store-close svc-store))
      (when (uiop:directory-exists-p tmp-dir)
        (uiop:delete-directory-tree tmp-dir :validate t)))))

;;; --- file-store backend (Task 1 of WP-DURABILITY-PERSISTENT) ---
;;; Round-trip + reopen-from-disk + idempotent re-put test for make-file-store.
;;; Domain-independent (no network — purely local file I/O).

(defun* run-durability-file-store-test ()
    (function () t)
  "make-file-store: put 5 records across 2 topics, get-range byte-exact + sorted, idempotent
   re-put, topics=2, count=5, store-close; then reopen from same dir and verify all 5 survive."
  (let* ((tmp-dir (uiop:merge-pathnames*
                   (make-pathname :directory (list :relative
                                                   (format nil "dds-file-store-test-~a"
                                                           (get-universal-time))))
                   (uiop:temporary-directory)))
         (g0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (g1 (let ((v (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref v 0) 1) v))
         (p (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b)))
         (s (dds.durability:make-file-store :dir tmp-dir)))
    (unwind-protect
         (progn
           (dds.durability:store-open s)
           ;; put 3 records on topic "A" (two guids, varied sn/kind)
           (%check :fs-put-a1 (eq t (dds.durability:store-put s "A" g0 1 nil :data (funcall p '(10 20)))) "put A/g0/1")
           (%check :fs-put-a2 (eq t (dds.durability:store-put s "A" g0 2 nil :data (funcall p '(30 40)))) "put A/g0/2")
           (%check :fs-put-a3 (eq t (dds.durability:store-put s "A" g1 1 nil :dispose (funcall p '(50)))) "put A/g1/1 dispose")
           ;; put 2 records on topic "B"
           (%check :fs-put-b1 (eq t (dds.durability:store-put s "B" g0 1 nil :data (funcall p '(1 2 3)))) "put B/g0/1 data")
           (%check :fs-put-b2 (eq t (dds.durability:store-put s "B" g1 5 nil :unregister (funcall p '(99)))) "put B/g1/5 unregister")
           ;; counts
           (%check :fs-count-total (= 5 (dds.durability:store-count s)) "total count 5")
           (%check :fs-count-a     (= 3 (dds.durability:store-count s "A")) "topic A count 3")
           (%check :fs-count-b     (= 2 (dds.durability:store-count s "B")) "topic B count 2")
           ;; topics
           (%check :fs-topics (equal '("A" "B") (sort (copy-list (dds.durability:store-topics s)) #'string<)) "topics A+B")
           ;; get-range: A sorted by (guid bytes asc, sn asc) — g0 < g1; within g0: sn 1 then 2
           (let ((recs-a (dds.durability:store-get-range s "A")))
             (%check :fs-a-len  (= 3 (length recs-a)) "A get-range 3 records")
             (%check :fs-a-ord0 (and (equalp g0 (dds.durability:durable-record-writer-guid (first recs-a)))
                                     (= 1 (dds.durability:durable-record-sn (first recs-a))))
                     "A[0] is g0/sn1")
             (%check :fs-a-ord1 (and (equalp g0 (dds.durability:durable-record-writer-guid (second recs-a)))
                                     (= 2 (dds.durability:durable-record-sn (second recs-a))))
                     "A[1] is g0/sn2")
             (%check :fs-a-ord2 (and (equalp g1 (dds.durability:durable-record-writer-guid (third recs-a)))
                                     (= 1 (dds.durability:durable-record-sn (third recs-a))))
                     "A[2] is g1/sn1")
             ;; payload byte-exact
             (%check :fs-a-payload0 (equalp (funcall p '(10 20))
                                             (dds.durability:durable-record-payload (first recs-a)))
                     "A[0] payload byte-exact")
             (%check :fs-a-payload2 (equalp (funcall p '(50))
                                             (dds.durability:durable-record-payload (third recs-a)))
                     "A[2] payload byte-exact"))
           ;; idempotent re-put: same (topic,guid,sn) -> T, count unchanged
           (%check :fs-reput (eq t (dds.durability:store-put s "A" g0 1 nil :data (funcall p '(99)))) "re-put A/g0/1 -> T")
           (%check :fs-reput-count (= 5 (dds.durability:store-count s)) "count still 5 after re-put")
           (dds.durability:store-close s)
           ;; reopen from same dir — all 5 records must survive disk round-trip
           (let ((s2 (dds.durability:make-file-store :dir tmp-dir)))
             (unwind-protect
                  (progn
                    (dds.durability:store-open s2)
                    (%check :fs-reopen-count  (= 5 (dds.durability:store-count s2)) "reopen: count=5")
                    (%check :fs-reopen-topics (equal '("A" "B")
                                                     (sort (copy-list (dds.durability:store-topics s2)) #'string<))
                            "reopen: topics A+B")
                    (let ((recs2 (dds.durability:store-get-range s2 "A")))
                      (%check :fs-reopen-a-len (= 3 (length recs2)) "reopen A: 3 records")
                      (%check :fs-reopen-a-payload0
                              (equalp (funcall p '(10 20))
                                      (dds.durability:durable-record-payload (first recs2)))
                              "reopen A[0] payload byte-exact"))
                    (dds.durability:store-close s2))
               (ignore-errors (dds.durability:store-close s2)))))
      (ignore-errors (dds.durability:store-close s))
      (when (uiop:directory-exists-p tmp-dir)
        (uiop:delete-directory-tree tmp-dir :validate t))))
  t)

;;; --- PERSISTENT service tier: restart → replay (Task 4 of WP-DURABILITY-PERSISTENT) ---
;;; Write N TL samples → service-stop (store persists to disk, sealed + epoch-keyed).
;;; Construct a FRESH service on the same dirs (simulating a restart) → service-start
;;; (store-open re-derives prior epochs' DEKs, replays sealed logs).
;;; A TL late-joiner that appears AFTER the restart receives all N retained samples
;;; byte-exact (decrypted-on-replay via the replay writer — no original writer present).
;;; Domain 117 avoids collision with all prior tests.

(defun* run-durability-persistent-service-test ()
    (function () t)
  "PERSISTENT service tier: write N TL samples; service-stop (store persists); fresh service
   on same dirs simulates restart; TL late-joiner receives all N byte-exact. Domain 117."
  (unless (dds.dare:dare-available-p)
    (format t "~&  [persistent-service] SKIP — OpenSSL >= 3.5 not available~%")
    (return-from run-durability-persistent-service-test t))
  (let* ((n 4)
         (tmp-dir (uiop:merge-pathnames*
                   (make-pathname :directory
                                  (list :relative (format nil "dds-persistent-svc-~a"
                                                          (get-universal-time))))
                   (uiop:temporary-directory)))
         (key-dir (uiop:merge-pathnames*
                   (make-pathname :directory '(:relative "keys"))
                   tmp-dir)))
    (unwind-protect
         (progn
           ;; --- run 1: publisher writes N samples, service collects + persists ---
           (let* ((spec1 (dds.durability:make-service-spec
                          :domain (test-domain +td-persistent-service+)
                          :topics '(("PSquare" . "ShapeType"))
                          :store (dds.durability:make-persistent-store-factory
                                  :dir tmp-dir :key-dir key-dir)
                          :name "persistent-run1"))
                  (svc1  (dds.durability:make-durability-service spec1))
                  (pub-prefix (%make-test-prefix #xC5))
                  (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain (test-domain +td-persistent-service+)
                                                     :host "127.0.0.1" :port 0
                                                     :multicast nil)))
             (unwind-protect
                  (progn
                    (dds.durability:service-start svc1)
                    (let ((svc1-node (dds.durability:durability-service-node svc1)))
                      (setf (dds.disc:disc-node-peers pub-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port svc1-node))))
                      (setf (dds.disc:disc-node-peers svc1-node)
                            (list (cons "127.0.0.1" 0)))
                      (dds.disc:add-local-writer pub-node :topic "PSquare" :type "ShapeType"
                                                 :qos (dds.qos:make-writer-qos
                                                       :reliability :reliable
                                                       :durability :transient-local))
                      (dds.disc:enable-publisher pub-node :history-kind :keep-all)
                      (dds.disc:start-node pub-node)
                      (setf (dds.disc:disc-node-peers svc1-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port pub-node))))
                      (%await-match pub-node svc1-node :retries 300 :sleep-s 0.02)
                      (dotimes (i n) (dds.disc:publish-sample pub-node (%make-small-payload (1+ i))))
                      (loop repeat 80
                            do (%announce-both pub-node svc1-node) (sleep 0.05))
                      (%await-store-count (dds.durability:durability-service-store svc1)
                                          "PSquare" n)
                      (%check :persistent-svc-collect
                              (= n (dds.durability:store-count
                                    (dds.durability:durability-service-store svc1) "PSquare"))
                              (format nil "run1: service should collect ~d before stop, got ~d"
                                      n (dds.durability:store-count
                                         (dds.durability:durability-service-store svc1) "PSquare")))
                      (ignore-errors (dds.disc:stop-node pub-node))))
               ;; service-stop: store-close flushes + seals to disk
               (ignore-errors (dds.durability:service-stop svc1))))
           ;; DARE-at-rest through the SERVICE composition: no plaintext sample appears on disk.
           ;; (the standalone dare-persistent test scans the bare store; this proves the
           ;;  make-persistent-store-factory wiring actually seals via the service path too.)
           (let ((raw (%pst-read-all-log-bytes tmp-dir)))
             (dotimes (i n)
               (%check :persistent-svc-no-plaintext
                       (not (%pst-subseq-present-p raw (%make-small-payload (1+ i))))
                       (format nil "service-tier DARE: plaintext sample ~d must not appear on disk" (1+ i)))))
           ;; --- run 2: fresh service on same dirs simulates restart ---
           (let* ((spec2 (dds.durability:make-service-spec
                          :domain (test-domain +td-persistent-service+)
                          :topics '(("PSquare" . "ShapeType"))
                          :store (dds.durability:make-persistent-store-factory
                                  :dir tmp-dir :key-dir key-dir)
                          :name "persistent-run2"))
                  (svc2  (dds.durability:make-durability-service spec2)))
             (unwind-protect
                  (progn
                    ;; service-start: store-open re-derives prior epoch DEKs, replays logs
                    (dds.durability:service-start svc2)
                    ;; assert the reloaded store has the N records from run 1
                    (%check :persistent-svc-reload
                            (= n (dds.durability:store-count
                                  (dds.durability:durability-service-store svc2) "PSquare"))
                            (format nil "run2: reloaded store expected ~d records, got ~d"
                                    n (dds.durability:store-count
                                       (dds.durability:durability-service-store svc2) "PSquare")))
                    (let* ((lj-prefix (%make-test-prefix #xE5))
                           (lj-node (dds.disc:make-disc-node
                                     :guid-prefix lj-prefix :domain (test-domain +td-persistent-service+)
                                     :host "127.0.0.1" :port 0 :multicast nil))
                           (svc2-node (dds.durability:durability-service-node svc2)))
                      (unwind-protect
                           (progn
                             (dds.disc:add-local-reader lj-node :topic "PSquare" :type "ShapeType"
                                                        :qos (dds.qos:make-reader-qos
                                                              :reliability :reliable
                                                              :durability :transient-local))
                             (dds.disc:enable-subscriber lj-node)
                             (setf (dds.disc:disc-node-on-match lj-node)
                                   (lambda (kind remote &optional local-eid) (declare (ignore local-eid))
                                     (when (eq kind :remote-writer)
                                       (dds.disc:%reader-durability-init
                                        lj-node
                                        (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                                        (dds.qos:qos-durability
                                         (dds.rtps.discovery:endpoint-data-qos remote))))))
                             (dds.disc:start-node lj-node)
                             (setf (dds.disc:disc-node-peers lj-node)
                                   (list (cons "127.0.0.1" (dds.disc:disc-node-port svc2-node))))
                             (setf (dds.disc:disc-node-peers svc2-node)
                                   (list (cons "127.0.0.1" (dds.disc:disc-node-port lj-node))))
                             (%await-match lj-node svc2-node :retries 300 :sleep-s 0.02)
                             (%await-sample-count lj-node n :retries 1200 :sleep-s 0.005)
                             (%check :persistent-svc-latejoiner
                                     (= n (dds.disc:node-sample-count lj-node))
                                     (format nil "restart late-joiner expected ~d, got ~d"
                                             n (dds.disc:node-sample-count lj-node)))
                             ;; byte-exact: every received payload must equalp its original
                             ;; (%make-small-payload (1+i)); N zero-bufs or duplicates must fail
                             (let* ((keys (dds.disc:node-sample-sns lj-node))
                                    (payloads (sort
                                               (mapcar (lambda (k) (dds.disc:node-sample lj-node k))
                                                       keys)
                                               #'< :key (lambda (p) (aref p 4))))
                                    (expected (loop for i from 1 to n
                                                    collect (%make-small-payload i))))
                               (%check :persistent-svc-payload-exact
                                       (and (= n (length payloads))
                                            (every #'equalp payloads expected))
                                       (format nil "restart payloads not byte-exact: got ~s expected ~s"
                                               (mapcar (lambda (p) (coerce p 'list)) payloads)
                                               (mapcar (lambda (p) (coerce p 'list)) expected)))))
                        (ignore-errors (dds.disc:stop-node lj-node)))))
               (ignore-errors (dds.durability:service-stop svc2)))))
      (when (uiop:directory-exists-p tmp-dir)
        (uiop:delete-directory-tree tmp-dir :validate t))))
  t)

;;; --- SQLite backend (WP-DURABILITY-SQLITE, ADR 0049) ---
;;; The SQLite store implements the SAME fixed durable-store vtable as make-file-store, so it must
;;; pass the SAME oracle contract tests: byte-exact record round-trip, (writer-guid, sn) ascending
;;; ordering, idempotent re-put, bounded reject, RESTART-RECOVERY from the DB file, DARE-wrapped
;;; transparency, and config-selected service restart -> replay.

(defun* %sqlite-load-smoke ()
    (function () boolean)
  "Prove :sqlite loads + a put/get works in-process (the both-impls load smoke as a suite test)."
  (let ((db (sqlite:connect ":memory:")))
    (unwind-protect
         (progn
           (sqlite:execute-non-query db "create table t(a)")
           (sqlite:execute-non-query db "insert into t values(?)" 7)
           (= 7 (sqlite:execute-single db "select a from t")))
      (sqlite:disconnect db))))

(defun* run-durability-sqlite-load-test ()
    (function () t)
  "cl-sqlite loads and a put/get round-trips (the both-impls :sqlite load smoke, in-suite)."
  (%check :sqlite-load (%sqlite-load-smoke) ":sqlite loads + put/get round-trips")
  t)

(defun* %sqlite-tmp-db-path (tag)
    (function (string) pathname)
  "A fresh temp DB file path under a unique per-run directory."
  (uiop:merge-pathnames*
   (make-pathname :name "durability" :type "sqlite3")
   (uiop:merge-pathnames*
    (make-pathname :directory (list :relative (format nil "dds-sqlite-~a-~a" tag (get-universal-time))))
    (uiop:temporary-directory))))

(defun* run-durability-sqlite-store-test ()
    (function () t)
  "make-sqlite-store vtable contract: put 5 records across 2 topics, get-range byte-exact + sorted,
   idempotent re-put, topics=2, count=5, bounded reject, multi-writer byte-order; then REOPEN a fresh
   store on the same DB path and verify all 5 survive (restart recovery)."
  (let* ((db-path (%sqlite-tmp-db-path "store"))
         (tmp-dir (uiop:pathname-directory-pathname db-path))
         (g0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (g1 (let ((v (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref v 0) 1) v))
         (p (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b)))
         (s (dds.durability:make-sqlite-store :path db-path)))
    (unwind-protect
         (progn
           (dds.durability:store-open s)
           (%check :sq-put-a1 (eq t (dds.durability:store-put s "A" g0 1 nil :data (funcall p '(10 20)))) "put A/g0/1")
           (%check :sq-put-a2 (eq t (dds.durability:store-put s "A" g0 2 nil :data (funcall p '(30 40)))) "put A/g0/2")
           (%check :sq-put-a3 (eq t (dds.durability:store-put s "A" g1 1 nil :dispose (funcall p '(50)))) "put A/g1/1 dispose")
           (%check :sq-put-b1 (eq t (dds.durability:store-put s "B" g0 1 nil :data (funcall p '(1 2 3)))) "put B/g0/1 data")
           (%check :sq-put-b2 (eq t (dds.durability:store-put s "B" g1 5 nil :unregister (funcall p '(99)))) "put B/g1/5 unregister")
           (%check :sq-count-total (= 5 (dds.durability:store-count s)) "total count 5")
           (%check :sq-count-a     (= 3 (dds.durability:store-count s "A")) "topic A count 3")
           (%check :sq-count-b     (= 2 (dds.durability:store-count s "B")) "topic B count 2")
           (%check :sq-topics (equal '("A" "B") (sort (copy-list (dds.durability:store-topics s)) #'string<)) "topics A+B")
           (let ((recs-a (dds.durability:store-get-range s "A")))
             (%check :sq-a-len  (= 3 (length recs-a)) "A get-range 3 records")
             (%check :sq-a-ord0 (and (equalp g0 (dds.durability:durable-record-writer-guid (first recs-a)))
                                     (= 1 (dds.durability:durable-record-sn (first recs-a)))) "A[0] is g0/sn1")
             (%check :sq-a-ord1 (and (equalp g0 (dds.durability:durable-record-writer-guid (second recs-a)))
                                     (= 2 (dds.durability:durable-record-sn (second recs-a)))) "A[1] is g0/sn2")
             (%check :sq-a-ord2 (and (equalp g1 (dds.durability:durable-record-writer-guid (third recs-a)))
                                     (= 1 (dds.durability:durable-record-sn (third recs-a)))) "A[2] is g1/sn1")
             (%check :sq-a-kind2 (eq :dispose (dds.durability:durable-record-kind (third recs-a))) "A[2] kind dispose round-trips")
             (%check :sq-a-payload0 (equalp (funcall p '(10 20)) (dds.durability:durable-record-payload (first recs-a))) "A[0] payload byte-exact")
             (%check :sq-a-payload2 (equalp (funcall p '(50)) (dds.durability:durable-record-payload (third recs-a))) "A[2] payload byte-exact"))
           (%check :sq-reput (eq t (dds.durability:store-put s "A" g0 1 nil :data (funcall p '(99)))) "re-put A/g0/1 -> T")
           (%check :sq-reput-count (= 5 (dds.durability:store-count s)) "count still 5 after re-put")
           ;; multi-writer ordering: guid first-byte 2 must precede guid first-byte 10 (byte order, not string<)
           (let ((gw2  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
                 (gw10 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
             (setf (aref gw2 0) 2) (setf (aref gw10 0) 10)
             (dds.durability:store-put s "T" gw10 1 nil :data (funcall p '(10)))
             (dds.durability:store-put s "T" gw2  1 nil :data (funcall p '(2)))
             (let ((recs (dds.durability:store-get-range s "T")))
               (%check :sq-multi-writer-order (= 2 (aref (dds.durability:durable-record-writer-guid (first recs)) 0))
                       "byte-2 guid must precede byte-10 guid in store-get-range")))
           ;; bounded store rejects when full (idempotent re-put of an existing key still returns T)
           (let* ((bdb (%sqlite-tmp-db-path "bounded"))
                  (bs (dds.durability:make-sqlite-store :path bdb :max-samples 1)))
             (unwind-protect
                  (progn
                    (dds.durability:store-open bs)
                    (%check :sq-bounded-put (eq t (dds.durability:store-put bs "A" g0 1 nil :data (funcall p '(1)))) "bounded put1 ok")
                    (%check :sq-bounded-dup (eq t (dds.durability:store-put bs "A" g0 1 nil :data (funcall p '(1)))) "bounded re-put still T")
                    (%check :sq-bounded (eq :rejected (dds.durability:store-put bs "A" g0 2 nil :data (funcall p '(2)))) "full store rejects"))
               (ignore-errors (dds.durability:store-close bs))
               (when (uiop:directory-exists-p (uiop:pathname-directory-pathname bdb))
                 (uiop:delete-directory-tree (uiop:pathname-directory-pathname bdb) :validate t))))
           (dds.durability:store-close s)
           ;; RESTART RECOVERY: fresh store on the same DB path replays all prior rows byte-exact
           (let ((s2 (dds.durability:make-sqlite-store :path db-path)))
             (unwind-protect
                  (progn
                    (dds.durability:store-open s2)
                    (%check :sq-reopen-count  (= 7 (dds.durability:store-count s2)) "reopen: count=7 (5 + 2 multi-writer)")
                    (%check :sq-reopen-topics (equal '("A" "B" "T")
                                                     (sort (copy-list (dds.durability:store-topics s2)) #'string<))
                            "reopen: topics A+B+T")
                    (let ((recs2 (dds.durability:store-get-range s2 "A")))
                      (%check :sq-reopen-a-len (= 3 (length recs2)) "reopen A: 3 records")
                      (%check :sq-reopen-a-ord (and (= 1 (dds.durability:durable-record-sn (first recs2)))
                                                    (= 2 (dds.durability:durable-record-sn (second recs2))))
                              "reopen A ordering survives restart")
                      (%check :sq-reopen-a-payload0
                              (equalp (funcall p '(10 20)) (dds.durability:durable-record-payload (first recs2)))
                              "reopen A[0] payload byte-exact")
                      (%check :sq-reopen-a-kind2 (eq :dispose (dds.durability:durable-record-kind (third recs2)))
                              "reopen A[2] kind byte-exact"))
                    (dds.durability:store-close s2))
               (ignore-errors (dds.durability:store-close s2)))))
      (ignore-errors (dds.durability:store-close s))
      (when (uiop:directory-exists-p tmp-dir)
        (uiop:delete-directory-tree tmp-dir :validate t))))
  t)

(defun* %sqlite-read-db-bytes (dir)
    (function (pathname) (simple-array (unsigned-byte 8) (*)))
  "Concatenate every raw byte of the SQLite DB files in DIR (main + -wal/-shm sidecars) for the
   no-plaintext-on-disk assertion (mirrors %pst-read-all-log-bytes for the file store)."
  (let ((out '()))
    (dolist (path (uiop:directory-files dir))
      (let ((tp (pathname-type path)))
        (when (and (stringp tp) (search "sqlite3" tp))
          (with-open-file (s path :element-type '(unsigned-byte 8))
            (let ((v (make-array (file-length s) :element-type '(unsigned-byte 8))))
              (read-sequence v s)
              (push v out))))))
    (let* ((total (reduce #'+ out :key #'length :initial-value 0))
           (cat   (make-array total :element-type '(unsigned-byte 8)))
           (pos   0))
      (dolist (v (nreverse out) cat)
        (replace cat v :start1 pos)
        (incf pos (length v))))))

(defun* run-durability-sqlite-dare-test ()
    (function () t)
  "DARE-wrapped SQLite store: make-encrypted-store over make-sqlite-store seals payloads; put N,
   get-range byte-exact (DARE transparent), and no plaintext sample appears in the DB file."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [sqlite-dare] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-durability-sqlite-dare-test t)))
  (let* ((db-path (%sqlite-tmp-db-path "dare"))
         (tmp-dir (uiop:pathname-directory-pathname db-path))
         (n 5)
         (g0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 3))
         (kp (dds.dare:make-file-key-provider :dir tmp-dir))
         (store (dds.durability:make-encrypted-store
                 (dds.durability:make-sqlite-store :path db-path) kp :epoch-dir tmp-dir)))
    (unwind-protect
         (progn
           (dds.durability:store-open store)
           (dotimes (i n)
             (%check (intern (format nil "SQ-DARE-PUT-~d" i) :keyword)
                     (eq t (dds.durability:store-put store "Enc" g0 (1+ i) nil :data (%make-small-payload (1+ i))))
                     "encrypted put ok"))
           (%check :sq-dare-count (= n (dds.durability:store-count store "Enc")) "encrypted store count N")
           (let ((recs (dds.durability:store-get-range store "Enc")))
             (%check :sq-dare-len (= n (length recs)) "decrypted get-range N records")
             (loop for r in recs for i from 1
                   do (%check (intern (format nil "SQ-DARE-EXACT-~d" i) :keyword)
                              (equalp (%make-small-payload i) (dds.durability:durable-record-payload r))
                              "decrypted payload byte-exact")))
           ;; sync to flush the WAL into the DB file, then scan: no plaintext sample AND (3c) no
           ;; plaintext topic NAME or writer-GUID bytes on disk (the metadata is sealed too).
           (dds.durability:store-sync store)
           (let ((raw   (%sqlite-read-db-bytes tmp-dir))
                 (tname (map '(simple-array (unsigned-byte 8) (*)) #'char-code "Enc")))
             (dotimes (i n)
               (%check (intern (format nil "SQ-DARE-NO-PLAINTEXT-~d" i) :keyword)
                       (not (%pst-subseq-present-p raw (%make-small-payload (1+ i))))
                       "DARE at-rest: plaintext sample must not appear in the DB file"))
             (%check :sq-dare-no-topic-name (not (%pst-subseq-present-p raw tname))
                     "3c: the topic NAME 'Enc' must not appear in the SQLite DB bytes")
             (%check :sq-dare-no-guid (not (%pst-subseq-present-p raw g0))
                     "3c: the writer-GUID bytes must not appear in the SQLite topic/writer_guid columns or raw bytes")))
      (ignore-errors (dds.durability:store-close store))
      (when (uiop:directory-exists-p tmp-dir)
        (uiop:delete-directory-tree tmp-dir :validate t))))
  t)

;;; Config-selected SQLite service restart -> replay: identical to run-durability-persistent-service-test
;;; but the store factory is make-sqlite-store-factory (the vtable is the fixed contract both fill).
;;; Domain +td-persistent-service+ (sequential run, distinct guid prefixes avoid stale-socket confusion).

(defun* run-durability-sqlite-service-test ()
    (function () t)
  "PERSISTENT SQLite service tier: write N TL samples; service-stop (store persists to DB); fresh
   service on same dirs simulates restart (store-open replays); TL late-joiner receives all N byte-exact."
  (unless (dds.dare:dare-available-p)
    (format t "~&  [sqlite-service] SKIP — OpenSSL >= 3.5 not available~%")
    (return-from run-durability-sqlite-service-test t))
  (let* ((n 4)
         (tmp-dir (uiop:merge-pathnames*
                   (make-pathname :directory (list :relative (format nil "dds-sqlite-svc-~a" (get-universal-time))))
                   (uiop:temporary-directory)))
         (key-dir (uiop:merge-pathnames* (make-pathname :directory '(:relative "keys")) tmp-dir)))
    (unwind-protect
         (progn
           ;; --- run 1: publisher writes N samples, service collects + persists to SQLite ---
           (let* ((spec1 (dds.durability:make-service-spec
                          :domain (test-domain +td-persistent-service+)
                          :topics '(("QSquare" . "ShapeType"))
                          :store (dds.durability:make-sqlite-store-factory :dir tmp-dir :key-dir key-dir)
                          :name "sqlite-run1"))
                  (svc1  (dds.durability:make-durability-service spec1))
                  (pub-prefix (%make-test-prefix #xC7))
                  (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain (test-domain +td-persistent-service+)
                                                     :host "127.0.0.1" :port 0 :multicast nil)))
             (unwind-protect
                  (progn
                    (dds.durability:service-start svc1)
                    (let ((svc1-node (dds.durability:durability-service-node svc1)))
                      (setf (dds.disc:disc-node-peers pub-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port svc1-node))))
                      (setf (dds.disc:disc-node-peers svc1-node) (list (cons "127.0.0.1" 0)))
                      (dds.disc:add-local-writer pub-node :topic "QSquare" :type "ShapeType"
                                                 :qos (dds.qos:make-writer-qos :reliability :reliable :durability :transient-local))
                      (dds.disc:enable-publisher pub-node :history-kind :keep-all)
                      (dds.disc:start-node pub-node)
                      (setf (dds.disc:disc-node-peers svc1-node)
                            (list (cons "127.0.0.1" (dds.disc:disc-node-port pub-node))))
                      (%await-match pub-node svc1-node :retries 300 :sleep-s 0.02)
                      (dotimes (i n) (dds.disc:publish-sample pub-node (%make-small-payload (1+ i))))
                      (loop repeat 80 do (%announce-both pub-node svc1-node) (sleep 0.05))
                      (%await-store-count (dds.durability:durability-service-store svc1) "QSquare" n)
                      (%check :sqlite-svc-collect
                              (= n (dds.durability:store-count (dds.durability:durability-service-store svc1) "QSquare"))
                              (format nil "run1: service should collect ~d before stop" n))
                      (ignore-errors (dds.disc:stop-node pub-node))))
               (ignore-errors (dds.durability:service-stop svc1))))
           ;; DARE-at-rest through the SERVICE composition: no plaintext sample in the DB file.
           (let ((raw (%sqlite-read-db-bytes tmp-dir)))
             (dotimes (i n)
               (%check :sqlite-svc-no-plaintext
                       (not (%pst-subseq-present-p raw (%make-small-payload (1+ i))))
                       (format nil "sqlite service-tier DARE: plaintext sample ~d must not appear on disk" (1+ i)))))
           ;; --- run 2: fresh service on same dirs simulates restart -> store-open replays ---
           (let* ((spec2 (dds.durability:make-service-spec
                          :domain (test-domain +td-persistent-service+)
                          :topics '(("QSquare" . "ShapeType"))
                          :store (dds.durability:make-sqlite-store-factory :dir tmp-dir :key-dir key-dir)
                          :name "sqlite-run2"))
                  (svc2  (dds.durability:make-durability-service spec2)))
             (unwind-protect
                  (progn
                    (dds.durability:service-start svc2)
                    (%check :sqlite-svc-reload
                            (= n (dds.durability:store-count (dds.durability:durability-service-store svc2) "QSquare"))
                            (format nil "run2: reloaded SQLite store expected ~d records" n))
                    (let* ((lj-prefix (%make-test-prefix #xE7))
                           (lj-node (dds.disc:make-disc-node :guid-prefix lj-prefix :domain (test-domain +td-persistent-service+)
                                                             :host "127.0.0.1" :port 0 :multicast nil))
                           (svc2-node (dds.durability:durability-service-node svc2)))
                      (unwind-protect
                           (progn
                             (dds.disc:add-local-reader lj-node :topic "QSquare" :type "ShapeType"
                                                        :qos (dds.qos:make-reader-qos :reliability :reliable :durability :transient-local))
                             (dds.disc:enable-subscriber lj-node)
                             (setf (dds.disc:disc-node-on-match lj-node)
                                   (lambda (kind remote &optional local-eid) (declare (ignore local-eid))
                                     (when (eq kind :remote-writer)
                                       (dds.disc:%reader-durability-init
                                        lj-node
                                        (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                                        (dds.qos:qos-durability (dds.rtps.discovery:endpoint-data-qos remote))))))
                             (dds.disc:start-node lj-node)
                             (setf (dds.disc:disc-node-peers lj-node)
                                   (list (cons "127.0.0.1" (dds.disc:disc-node-port svc2-node))))
                             (setf (dds.disc:disc-node-peers svc2-node)
                                   (list (cons "127.0.0.1" (dds.disc:disc-node-port lj-node))))
                             (%await-match lj-node svc2-node :retries 300 :sleep-s 0.02)
                             (%await-sample-count lj-node n :retries 1200 :sleep-s 0.005)
                             (%check :sqlite-svc-latejoiner
                                     (= n (dds.disc:node-sample-count lj-node))
                                     (format nil "sqlite restart late-joiner expected ~d, got ~d"
                                             n (dds.disc:node-sample-count lj-node)))
                             (let* ((keys (dds.disc:node-sample-sns lj-node))
                                    (payloads (sort (mapcar (lambda (k) (dds.disc:node-sample lj-node k)) keys)
                                                    #'< :key (lambda (p) (aref p 4))))
                                    (expected (loop for i from 1 to n collect (%make-small-payload i))))
                               (%check :sqlite-svc-payload-exact
                                       (and (= n (length payloads)) (every #'equalp payloads expected))
                                       "sqlite restart payloads byte-exact")))
                        (ignore-errors (dds.disc:stop-node lj-node)))))
               (ignore-errors (dds.durability:service-stop svc2)))))
      (when (uiop:directory-exists-p tmp-dir)
        (uiop:delete-directory-tree tmp-dir :validate t))))
  t)

;;; --- file-store recovery test (T1 review findings 1+2) ---
;;; (a) torn tail: truncate last few bytes of 2nd frame → exactly 1 record recovered, no error.
;;; (b) mid-file corruption: flip a byte inside the 1st frame body → store-open must signal an error.

(defun* run-durability-file-recovery-test ()
    (function () t)
  "file-store replay distinguishes torn tail (recover) from mid-file corruption (error)."
  (let* ((g0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (p  (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b))))
    ;; --- (a) torn tail: 2nd frame truncated mid-write → 1 record recovered, no error ---
    (let* ((tmp-a (uiop:merge-pathnames*
                   (make-pathname :directory (list :relative
                                                   (format nil "dds-recovery-torn-~a"
                                                           (get-universal-time))))
                   (uiop:temporary-directory)))
           (s-a (dds.durability:make-file-store :dir tmp-a)))
      (unwind-protect
           (progn
             (dds.durability:store-open s-a)
             (dds.durability:store-put s-a "R" g0 1 nil :data (funcall p '(11)))
             (dds.durability:store-put s-a "R" g0 2 nil :data (funcall p '(22)))
             (dds.durability:store-close s-a)
             ;; truncate the log to drop the last 4 bytes of the 2nd frame (tears the CRC)
             (let* ((tid (dds.durability::%topic->id "R"))
                    (log-path (merge-pathnames
                               (make-pathname :directory '(:relative "topics")
                                             :name tid :type "log")
                               tmp-a))
                    (sz (with-open-file (fin log-path :element-type '(unsigned-byte 8))
                          (file-length fin))))
               (dds.durability::%truncate-file log-path (- sz 4)))
             ;; fresh store on same dir → open → exactly 1 record, no error
             (let ((s-a2 (dds.durability:make-file-store :dir tmp-a)))
               (unwind-protect
                    (progn
                      (dds.durability:store-open s-a2)
                      (%check :recovery-torn-count
                              (= 1 (dds.durability:store-count s-a2 "R"))
                              (format nil "torn tail: expected 1 record, got ~d"
                                      (dds.durability:store-count s-a2 "R")))
                      ;; put + get-range still works after recovery
                      (dds.durability:store-put s-a2 "R" g0 3 nil :data (funcall p '(33)))
                      (%check :recovery-torn-post-put
                              (= 2 (dds.durability:store-count s-a2 "R"))
                              "torn tail: put after recovery must succeed (count=2)")
                      (let ((recs (dds.durability:store-get-range s-a2 "R")))
                        (%check :recovery-torn-sn1
                                (= 1 (dds.durability:durable-record-sn (first recs)))
                                "torn tail: first record must have sn=1"))
                      (dds.durability:store-close s-a2))
                 (ignore-errors (dds.durability:store-close s-a2)))))
        (ignore-errors (dds.durability:store-close s-a))
        (when (uiop:directory-exists-p tmp-a)
          (uiop:delete-directory-tree tmp-a :validate t))))
    ;; --- (b) mid-file corruption: flip byte inside 1st frame body → store-open signals error ---
    (let* ((tmp-b (uiop:merge-pathnames*
                   (make-pathname :directory (list :relative
                                                   (format nil "dds-recovery-corrupt-~a"
                                                           (get-universal-time))))
                   (uiop:temporary-directory)))
           (s-b (dds.durability:make-file-store :dir tmp-b)))
      (unwind-protect
           (progn
             (dds.durability:store-open s-b)
             (dds.durability:store-put s-b "R" g0 1 nil :data (funcall p '(11)))
             (dds.durability:store-put s-b "R" g0 2 nil :data (funcall p '(22)))
             (dds.durability:store-close s-b)
             ;; flip a byte inside the 1st frame's PAYLOAD body → trips the trailing frame CRC
             (let* ((tid (dds.durability::%topic->id "R"))
                    (log-path (merge-pathnames
                               (make-pathname :directory '(:relative "topics")
                                             :name tid :type "log")
                               tmp-b))
                    (raw (with-open-file (fin log-path :element-type '(unsigned-byte 8))
                           (let ((v (make-array (file-length fin) :element-type '(unsigned-byte 8))))
                             (read-sequence v fin)
                             v))))
               ;; v2 no-kh frame: magic(2)+flags(1)+guid(16)+sn(8)+plen(4)+header-crc(4)=35 → offset 35
               ;; is the first PAYLOAD byte of frame 1 (header CRC is intact; the FRAME CRC catches this)
               (setf (aref raw 35) (logxor (aref raw 35) #xFF))
               (with-open-file (fout log-path :direction :output :element-type '(unsigned-byte 8)
                                              :if-exists :supersede)
                 (write-sequence raw fout)))
             ;; fresh store → open MUST signal an error (mid-file CRC mismatch on 1st frame)
             (let ((s-b2 (dds.durability:make-file-store :dir tmp-b))
                   (errored nil))
               (handler-case
                   (dds.durability:store-open s-b2)
                 (error () (setf errored t)))
               (%check :recovery-corrupt-error
                       errored
                       "mid-file corruption must cause store-open to signal an error")))
        (ignore-errors (dds.durability:store-close s-b))
        (when (uiop:directory-exists-p tmp-b)
          (uiop:delete-directory-tree tmp-b :validate t))))
    ;; --- (c) interior plen-field corruption: an inflated payload-len that overshoots the sanity
    ;;     cap MUST be :corrupt (fail loud), NOT silently truncated as a torn tail. Without the
    ;;     +frame-max-payload+ cap, an over-cap plen → :short → silent truncation of all live data. ---
    (let* ((tmp-c (uiop:merge-pathnames*
                   (make-pathname :directory (list :relative
                                                   (format nil "dds-recovery-plen-~a"
                                                           (get-universal-time))))
                   (uiop:temporary-directory)))
           (s-c (dds.durability:make-file-store :dir tmp-c)))
      (unwind-protect
           (progn
             (dds.durability:store-open s-c)
             (dds.durability:store-put s-c "R" g0 1 nil :data (funcall p '(11)))
             (dds.durability:store-put s-c "R" g0 2 nil :data (funcall p '(22)))
             (dds.durability:store-close s-c)
             ;; frame-1 plen field (no key-hash): magic(2)+flags(1)+guid(16)+sn(8)=27 → plen at 27..30.
             ;; inflate it to 0xFFFFFFFF (> +frame-max-payload+) — frame 1 is interior (frame 2 follows).
             (let* ((tid (dds.durability::%topic->id "R"))
                    (log-path (merge-pathnames
                               (make-pathname :directory '(:relative "topics")
                                             :name tid :type "log")
                               tmp-c))
                    (raw (with-open-file (fin log-path :element-type '(unsigned-byte 8))
                           (let ((v (make-array (file-length fin) :element-type '(unsigned-byte 8))))
                             (read-sequence v fin) v))))
               (dotimes (i 4) (setf (aref raw (+ 27 i)) #xFF))
               (with-open-file (fout log-path :direction :output :element-type '(unsigned-byte 8)
                                              :if-exists :supersede)
                 (write-sequence raw fout)))
             ;; fresh store → open MUST signal (over-cap plen is :corrupt, never a silent truncate)
             (let ((s-c2 (dds.durability:make-file-store :dir tmp-c))
                   (errored nil))
               (handler-case (dds.durability:store-open s-c2)
                 (error () (setf errored t)))
               (%check :recovery-plen-overcap-error
                       errored
                       "an interior frame plen above the sanity cap must fail loud (:corrupt), not silently truncate")))
        (ignore-errors (dds.durability:store-close s-c))
        (when (uiop:directory-exists-p tmp-c)
          (uiop:delete-directory-tree tmp-c :validate t))))
    t))

;;; --- compaction-on-open (Task 6, WP-DURABILITY-PERSISTENT) ---
;;; A file-store with settle records (both :dispose AND :unregister for the same
;;; key-hash) must compact them away on the next open, resulting in zero records
;;; for that instance.  A SECOND key-hash (kh2) that has only a :data record
;;; (no tombstones) must SURVIVE compaction with its 1 record intact.
;;; A new put after compaction must succeed.

(defun* run-durability-compaction-test ()
    (function () t)
  "Compaction-on-open: settled instances dropped; live-only instance survives; new put works."
  (let* ((tmp (uiop:merge-pathnames*
               (make-pathname :directory (list :relative
                                               (format nil "dds-compact-~a"
                                                       (get-universal-time))))
               (uiop:temporary-directory)))
         (g0   (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xCC))
         (kh   (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xDD))
         (kh2  (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xEE))
         (p    (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8)
                                                   :initial-contents b)))
         (topic "CompactTopic"))
    (unwind-protect
         (progn
           ;; write 3 data + dispose + unregister for kh (settled); 1 data-only for kh2 (live)
           (let ((store (dds.durability:make-file-store :dir tmp)))
             (dds.durability:store-open store)
             (dotimes (i 3)
               (dds.durability:store-put store topic g0 (1+ i) kh :data (funcall p (list (1+ i)))))
             (dds.durability:store-put store topic g0 4 kh :dispose     (funcall p '()))
             (dds.durability:store-put store topic g0 5 kh :unregister  (funcall p '()))
             ;; kh2: one live :data record only (no tombstones -> must survive compaction)
             (dds.durability:store-put store topic g0 6 kh2 :data (funcall p '(42)))
             (%check :compact-pre (= 6 (dds.durability:store-count store topic))
                     "before close: must have 6 records (5 for kh + 1 for kh2)")
             (dds.durability:store-close store))
           ;; reopen -> compaction: kh settled -> 0; kh2 live -> 1 survives
           (let ((store2 (dds.durability:make-file-store :dir tmp)))
             (unwind-protect
                  (progn
                    (dds.durability:store-open store2)
                    ;; settled kh is gone; kh2 live record survives -> total = 1
                    (%check :compact-post-total (= 1 (dds.durability:store-count store2 topic))
                            "after reopen: settled kh dropped + kh2 live -> total 1 record")
                    ;; live-record sub-case: kh2 data record must survive (count-by-keyhash proxy)
                    (let ((recs2 (dds.durability:store-get-range store2 topic)))
                      (%check :compact-live-survives
                              (and (= 1 (length recs2))
                                   (equalp kh2 (dds.durability:durable-record-key-hash (first recs2))))
                              (format nil "kh2 live record must survive compaction; got ~d records" (length recs2))))
                    ;; a new put for the settled key-hash must work after compaction
                    (%check :compact-new-put
                            (eq t (dds.durability:store-put store2 topic g0 7 kh :data (funcall p '(7))))
                            "put after compaction must succeed")
                    (%check :compact-new-count (= 2 (dds.durability:store-count store2 topic))
                            "count after new put must be 2 (kh2 live + new kh data)"))
               (ignore-errors (dds.durability:store-close store2)))))
      (ignore-errors
       (when (uiop:directory-exists-p tmp)
         (uiop:delete-directory-tree tmp :validate t))))
    t))

;;; --- compaction is order-aware: resurrected instance survives (WP-DURABILITY-PERSISTENT review) ---

(defun* run-durability-resurrection-compaction-test ()
    (function () t)
  "Compaction must be order-aware: a legally RESURRECTED instance (data → dispose → unregister →
   data again) keeps the live :data written AFTER the teardown. The order-insensitive
   set-membership form (both tombstones present ⇒ drop all) silently lost the resurrected data."
  (let* ((tmp (uiop:merge-pathnames*
               (make-pathname :directory (list :relative
                                               (format nil "dds-resurrect-~a" (get-universal-time))))
               (uiop:temporary-directory)))
         (g0  (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xCC))
         (kh  (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xFA))
         (p   (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b)))
         (topic "ResurrectTopic"))
    (unwind-protect
         (progn
           ;; data(1) → dispose(2) → unregister(3) → data(4, resurrection): LIVE at the end
           (let ((store (dds.durability:make-file-store :dir tmp)))
             (dds.durability:store-open store)
             (dds.durability:store-put store topic g0 1 kh :data       (funcall p '(1)))
             (dds.durability:store-put store topic g0 2 kh :dispose    (funcall p '()))
             (dds.durability:store-put store topic g0 3 kh :unregister (funcall p '()))
             (dds.durability:store-put store topic g0 4 kh :data       (funcall p '(44)))
             (dds.durability:store-close store))
           ;; reopen → compaction must KEEP the resurrected instance (final change is :data)
           (let ((store2 (dds.durability:make-file-store :dir tmp)))
             (unwind-protect
                  (progn
                    (dds.durability:store-open store2)
                    (let* ((recs (dds.durability:store-get-range store2 topic))
                           (live (find-if (lambda (r)
                                            (and (eq :data (dds.durability:durable-record-kind r))
                                                 (= 4 (dds.durability:durable-record-sn r))))
                                          recs)))
                      (%check :resurrect-live-survives
                              live
                              (format nil "resurrected live data (sn=4) must survive compaction; got ~d records, kinds ~s"
                                      (length recs)
                                      (mapcar #'dds.durability:durable-record-kind recs)))))
               (ignore-errors (dds.durability:store-close store2)))))
      (ignore-errors
       (when (uiop:directory-exists-p tmp)
         (uiop:delete-directory-tree tmp :validate t))))
    t))

;;; --- :sync delegation through the DARE decorator (WP-DURABILITY-PERSISTENT review) ---
;;; Regression guard for the T6 data-loss bug: a missing :sync delegation = the production
;;; PERSISTENT store's per-tick fsync silently no-ops = crash data loss. A stub inner store
;;; counts :sync calls; both the v1 and v2 encrypted-store decorators MUST forward store-sync.

(defun* %sync-stub-store (counter-box)
    (function (cons) dds.durability:durable-store)
  "A minimal durable-store whose :sync increments (CAR COUNTER-BOX); other ops are inert stubs."
  (dds.durability::%make-durable-store
   :name :sync-stub
   :put       (lambda (a b c d e f) (declare (ignore a b c d e f)) t)
   :get-range (lambda (tp) (declare (ignore tp)) '())
   :topics    (lambda () '())
   :purge     (lambda (tp) (declare (ignore tp)) t)
   :open      (lambda () t)
   :close     (lambda () t)
   :count-fn  (lambda (tp) (declare (ignore tp)) 0)
   :sync      (lambda () (incf (car counter-box)) t)))

(defun* run-durability-sync-delegation-test ()
    (function () t)
  "store-sync on the encrypted-store decorator MUST reach the inner store's :sync (the T6
   regression: a dropped :sync delegation = the DARE PERSISTENT config never fsyncs = data loss)."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [sync-delegation] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-durability-sync-delegation-test t)))
  (let* ((k1 (uiop:merge-pathnames*
              (make-pathname :directory (list :relative (format nil "dds-syncdel-k1-~a" (get-universal-time))))
              (uiop:temporary-directory)))
         (k2 (uiop:merge-pathnames*
              (make-pathname :directory (list :relative (format nil "dds-syncdel-k2-~a" (get-universal-time))))
              (uiop:temporary-directory)))
         (e2 (uiop:merge-pathnames*
              (make-pathname :directory (list :relative (format nil "dds-syncdel-e2-~a" (get-universal-time))))
              (uiop:temporary-directory))))
    (unwind-protect
         (progn
           ;; v1 (no epoch-dir): construction opens the key-provider + derives a DEK
           (let* ((box (list 0))
                  (kp  (dds.dare:make-file-key-provider :dir k1))
                  (enc (dds.durability:make-encrypted-store (%sync-stub-store box) kp)))
             (dds.durability:store-sync enc)
             (dds.durability:store-sync enc)
             (%check :sync-deleg-v1 (= 2 (car box))
                     (format nil "v1 encrypted-store must forward both store-sync calls; got ~d" (car box)))
             (ignore-errors (dds.durability:store-close enc)))
           ;; v2 (epoch-dir): constructed closed; store-sync must still forward to the inner store
           (let* ((box (list 0))
                  (kp  (dds.dare:make-file-key-provider :dir k2))
                  (enc (dds.durability:make-encrypted-store (%sync-stub-store box) kp :epoch-dir e2)))
             (dds.durability:store-sync enc)
             (%check :sync-deleg-v2 (= 1 (car box))
                     (format nil "v2 encrypted-store must forward store-sync; got ~d" (car box)))))
      (dolist (d (list k1 k2 e2))
        (when (uiop:directory-exists-p d)
          (ignore-errors (uiop:delete-directory-tree d :validate t))))))
  t)

;;; --- seed-backpressure robustness (Task 6, WP-DURABILITY-PERSISTENT) ---
;;; Pre-populate a store with 20 records before service-start; assert all 20
;;; are seeded into the replay writer's cache (:timeout is structurally impossible
;;; for TL/KEEP_ALL seeding with no reader, per the %seed-relay-from-store docstring).

(defun* run-durability-seed-backpressure-test ()
    (function () t)
  "Seed-relay backpressure robustness: 20 pre-existing records all reach a TL late-joiner.
   Validates %seed-relay-from-store handles volumes well above a typical window without
   :timeout (TL+KEEP_ALL writer with no reader has unbounded cache; :timeout is impossible).
   Domain 97 avoids collision with other test domains."
  (let* ((n     20)
         (svc-store (dds.durability:make-memory-store))
         (topic "BPSquare")
         (g0    (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xBB)))
    ;; pre-populate 20 records BEFORE service-start
    (dds.durability:store-open svc-store)
    (dotimes (i n)
      (dds.durability:store-put svc-store topic g0 (1+ i) nil :data
                                 (make-array 4 :element-type '(unsigned-byte 8)
                                               :initial-element (1+ i))))
    (%check :seed-bp-pre (= n (dds.durability:store-count svc-store topic))
            (format nil "pre-seed: store must have ~d records before service-start, got ~d"
                    n (dds.durability:store-count svc-store topic)))
    (let* ((spec (dds.durability:make-service-spec
                  :domain (test-domain +td-dispose-replay+)
                  :topics (list (cons topic "ShapeType"))
                  :store  (lambda () svc-store)
                  :name   "seed-bp-test"))
           (svc (dds.durability:make-durability-service spec :store svc-store))
           (lj-prefix (%make-test-prefix #xBB))
           (lj-node (dds.disc:make-disc-node :guid-prefix lj-prefix :domain (test-domain +td-dispose-replay+)
                                             :host "127.0.0.1" :port 0 :multicast nil)))
      (unwind-protect
           (progn
             ;; service-start calls %seed-relay-from-store with 20 records (no :timeout expected)
             (dds.durability:service-start svc)
             (let ((svc-node (dds.durability:durability-service-node svc)))
               ;; late-joiner TL reader
               (dds.disc:add-local-reader lj-node :topic topic :type "ShapeType"
                                          :qos (dds.qos:make-reader-qos
                                                :reliability :reliable
                                                :durability :transient-local))
               (dds.disc:enable-subscriber lj-node)
               (setf (dds.disc:disc-node-on-match lj-node)
                     (lambda (kind remote &optional local-eid) (declare (ignore local-eid))
                       (when (eq kind :remote-writer)
                         (dds.disc:%reader-durability-init
                          lj-node
                          (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                          (dds.qos:qos-durability (dds.rtps.discovery:endpoint-data-qos remote))))))
               (dds.disc:start-node lj-node)
               ;; wire lj <-> service
               (setf (dds.disc:disc-node-peers lj-node)
                     (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-node))))
               (setf (dds.disc:disc-node-peers svc-node)
                     (list (cons "127.0.0.1" (dds.disc:disc-node-port lj-node))))
               ;; discovery + drain
               (%await-match lj-node svc-node :retries 300 :sleep-s 0.02)
               ;; poll for all n samples
               (%await-sample-count lj-node n :retries 1200 :sleep-s 0.005)
               (%check :seed-bp-received
                       (= n (dds.disc:node-sample-count lj-node))
                       (format nil "seed-backpressure: TL late-joiner expected ~d samples, got ~d"
                               n (dds.disc:node-sample-count lj-node)))))
        (ignore-errors (dds.disc:stop-node lj-node))
        (ignore-errors (dds.durability:service-stop svc)))))
  t)

;;; --- collect-loop seen-set prune test (Task 7, WP-DURABILITY-PERSISTENT carry-forward) ---
;;; NFR-MEM: the collect-loop per-origin seen-set must stay BOUNDED by a function of the
;;; reorder window (*max-gap-range*), not by the total sample count.
;;; PURE (no threads, no network): drives %collect-seen-p / %collect-mark-seen! directly.
;;; Step 1 (failing before implementation): assert ABOVE size stays <= 1 after N in-order
;;;   samples from one origin (the watermark compacts each entry immediately on in-order traffic;
;;;   ABOVE stays empty after every mark).
;;; Step 2: assert no-double-delivery — %collect-seen-p returns T for already-delivered SNs.

(defun* run-durability-seen-prune-test ()
    (function () t)
  "PURE: collect-loop seen-set stays bounded (NFR-MEM carry-forward from Phase-2 review).
   Drives %collect-mark-seen! with N=1000 in-order samples from one origin GUID;
   after each mark, asserts the per-origin ABOVE-HT size <= 1 (compacts to 0 for in-order
   traffic — the watermark advances through every just-accepted entry).
   Also asserts no-double-delivery: re-feeding any already-delivered SN is seen-p=T."
  (let* ((origins (dds.durability::%make-collect-origins))
         (guid    (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xAA))
         (n       1000))
    ;; deliver n samples in order: watermark must advance, above stays empty
    (dotimes (i n)
      (let ((sn (1+ i)))
        ;; before delivery: must not be seen yet
        (%check :prune-pre-seen
                (not (dds.durability::%collect-seen-p origins guid sn))
                (format nil "sn ~d must not be seen before delivery" sn))
        (dds.durability::%collect-mark-seen! origins guid sn)
        ;; after delivery: watermark advance — above-set size must be <= 1
        (let ((above-size (dds.durability::%collect-origins-above-size origins)))
          (%check :prune-bounded
                  (<= above-size 1)
                  (format nil "after sn ~d: above-size ~d must be <= 1 (bounded by reorder window)"
                          sn above-size)))))
    ;; no-double-delivery: re-feed every SN in {1..n}; all must be seen
    (dotimes (i n)
      (let ((sn (1+ i)))
        (%check :prune-no-double
                (dds.durability::%collect-seen-p origins guid sn)
                (format nil "re-fed sn ~d must still be seen (no-double-delivery)" sn))))
    ;; lifecycle dedup: origins-lc uses the same %collect-seen-p/%collect-mark-seen! machinery;
    ;; the key-change refactor (car key)=writer-guid (cdr key)=sn must still dedup correctly
    (let* ((origins-lc (dds.durability::%make-collect-origins))
           (lc-guid    (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xCC)))
      (dds.durability::%collect-mark-seen! origins-lc lc-guid 42)
      (%check :prune-lc-no-double
              (dds.durability::%collect-seen-p origins-lc lc-guid 42)
              "re-fed lifecycle (lc-guid, sn=42) must still be seen (dedup preserved after key-change)"))
    ;; out-of-order: above-set bounded at *max-gap-range* even under gaps
    (let* ((origins2 (dds.durability::%make-collect-origins))
           (g2       (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xBB))
           (cap      dds.rtps.reliable:*max-gap-range*))
      ;; deliver samples at large out-of-order offsets (gaps between them)
      ;; expected: above-set can grow up to cap entries but not beyond
      (dotimes (i (+ cap 100))
        ;; skip every other SN to create gaps
        (let ((sn (* 2 (1+ i))))
          (unless (dds.durability::%collect-seen-p origins2 g2 sn)
            (dds.durability::%collect-mark-seen! origins2 g2 sn))))
      (let* ((above2 (dds.durability::%collect-origins-above-size origins2))
             ;; the shed entry is the highest SN that was pushed out (it exceeds *max-gap-range*);
             ;; re-feeding that SN must NOT be seen (shed entry is re-admissible — ADR 0024 benign dup)
             (shed-sn (* 2 (+ cap 100))))
        (%check :prune-gap-bounded
                (<= above2 (+ cap 1))
                (format nil "out-of-order scenario: above-size ~d must be <= cap+1 (~d)"
                        above2 (+ cap 1)))
        ;; shed re-admission: the highest-sn entry that was evicted must be re-admissible (not seen)
        (%check :prune-shed-readmission
                (not (dds.durability::%collect-seen-p origins2 g2 shed-sn))
                (format nil "shed sn ~d must NOT be seen — re-admissible (ADR 0024 benign dup, not silent loss)"
                        shed-sn))))
    t))

;;; --- dynamic-topic-add test (Task 8, WP-DURABILITY-PERSISTENT carry-forward, ADR 0024) ---
;;; A service starts with topic "DynA"/"ShapeType".  service-add-topic adds "DynB"/"ShapeType"
;;; to the RUNNING service (no restart).  A publisher on "DynB" writes N=3 TL samples; a TL
;;; late-joiner on "DynB" receives all 3 (proving the new disc-node is live).
;;; Assert "DynA"'s node is still present (node-count=2 after add).
;;; Idempotency: a second service-add-topic "DynB" returns T and does NOT double-add
;;; (node count stays at 2).
;;; NFR-PORT: the live-thread sub-tests (late-joiner delivery) are skipped on Clasp due to the
;;; Clasp threading gap (intermittent SIGSEGV in CLOS error-signaling on multithreaded condvar
;;; teardown — memory: clasp-threading-gap).  The idempotency + node-count structural assertions
;;; run on BOTH impls.  Domain 127 avoids collision with all prior tests.

(defun* run-durability-dynamic-topic-test ()
    (function () t)
  "Dynamic topic add: service starts with DynA; service-add-topic adds DynB live; a publisher
   on DynB writes N TL samples; TL late-joiner on DynB receives all N; DynA's node unaffected;
   idempotent second add-topic does not double the node count.  Domain 127, loopback unicast."
  (let* ((n 3)
         (svc-store (dds.durability:make-memory-store))
         (spec (dds.durability:make-service-spec
                :domain (test-domain +td-dynamic-topic+)
                :topics '(("DynA" . "ShapeType"))
                :store (lambda () svc-store)
                :name "dynamic-topic-test"))
         (svc (dds.durability:make-durability-service spec :store svc-store)))
    (unwind-protect
         (progn
           ;; start service with topic DynA (one disc-node)
           (dds.durability:service-start svc)

           ;; --- structural assertion: add DynB live; capture the returned node ---
           (multiple-value-bind (ok svc-b-node)
               (dds.durability:service-add-topic svc "DynB" "ShapeType")
             (%check :dyn-add-returns-t
                     (eq t ok)
                     "service-add-topic DynB must return T as first value")
             (%check :dyn-add-returns-node
                     (not (null svc-b-node))
                     "service-add-topic DynB must return a non-NIL node as second value")
             (%check :dyn-node-count-after-add
                     (= 2 (length (dds.durability:durability-service-nodes svc)))
                     (format nil "after service-add-topic DynB: expected 2 nodes, got ~d"
                             (length (dds.durability:durability-service-nodes svc))))

             ;; --- DynA's node still present: service's topic-name registry must contain "DynA" ---
             (%check :dyn-a-present
                     (gethash "DynA" (dds.durability:durability-service-topic-names svc))
                     "DynA's topic-name must still be in the service registry after DynB was added")

             ;; --- idempotency: second service-add-topic DynB must be a no-op ---
             (multiple-value-bind (ok2 node2)
                 (dds.durability:service-add-topic svc "DynB" "ShapeType")
               (%check :dyn-idempotent-return
                       (eq t ok2)
                       "second service-add-topic DynB must return T as first value")
               (%check :dyn-idempotent-nil-node
                       (null node2)
                       "second service-add-topic DynB must return NIL as second value (no-op)")
               (%check :dyn-node-count-idempotent
                       (= 2 (length (dds.durability:durability-service-nodes svc)))
                       (format nil "after idempotent re-add: must still have 2 nodes, got ~d"
                               (length (dds.durability:durability-service-nodes svc)))))

             ;; --- live-thread sub-test: publisher on DynB → TL late-joiner on DynB ---
             ;; NFR-PORT: skipped on Clasp (clasp-threading-gap: intermittent SIGSEGV in CLOS
             ;; error-signaling on multithreaded condvar teardown; pure structural tests above ran both impls)
             (cond
               ((eq (dds.pal:pal-impl-name) :clasp)
                (format t "~&    [dynamic-topic] Clasp: skipping live-thread sub-test (NFR-PORT gap)~%"))
               (t
                ;; svc-b-node is the node returned directly by service-add-topic (no prefix re-derivation)
                (let* ((pub-prefix (%make-test-prefix #xC7))
                       (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain (test-domain +td-dynamic-topic+)
                                                          :host "127.0.0.1" :port 0 :multicast nil)))
                  (when svc-b-node
                    (unwind-protect
                         (progn
                           ;; set up publisher on DynB
                           (dds.disc:add-local-writer pub-node :topic "DynB" :type "ShapeType"
                                                      :qos (dds.qos:make-writer-qos
                                                            :reliability :reliable
                                                            :durability :transient-local))
                           (dds.disc:enable-publisher pub-node :history-kind :keep-all)
                           (dds.disc:start-node pub-node)
                           ;; wire pub <-> svc-b-node
                           (setf (dds.disc:disc-node-peers pub-node)
                                 (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-b-node))))
                           (setf (dds.disc:disc-node-peers svc-b-node)
                                 (list (cons "127.0.0.1" (dds.disc:disc-node-port pub-node))))
                           ;; discovery + publish N samples
                           (%await-match pub-node svc-b-node :retries 300 :sleep-s 0.02)
                           (dotimes (i n) (dds.disc:publish-sample pub-node (%make-small-payload (1+ i))))
                           (loop repeat 80
                                 do (%announce-both pub-node svc-b-node) (sleep 0.05))
                           (%await-store-count svc-store "DynB" n)
                           (%check :dyn-b-store-count
                                   (= n (dds.durability:store-count svc-store "DynB"))
                                   (format nil "DynB store expected ~d, got ~d"
                                           n (dds.durability:store-count svc-store "DynB")))
                           ;; stop publisher — writer gone
                           (ignore-errors (dds.disc:stop-node pub-node))
                           (sleep 0.1)
                           ;; TL late-joiner on DynB: must receive N from the service
                           (let* ((lj-prefix (%make-test-prefix #xE8))
                                  (lj-node (dds.disc:make-disc-node :guid-prefix lj-prefix :domain (test-domain +td-dynamic-topic+)
                                                                     :host "127.0.0.1" :port 0
                                                                     :multicast nil)))
                             (unwind-protect
                                  (progn
                                    (dds.disc:add-local-reader lj-node :topic "DynB" :type "ShapeType"
                                                               :qos (dds.qos:make-reader-qos
                                                                     :reliability :reliable
                                                                     :durability :transient-local))
                                    (dds.disc:enable-subscriber lj-node)
                                    (setf (dds.disc:disc-node-on-match lj-node)
                                          (lambda (kind remote &optional local-eid) (declare (ignore local-eid))
                                            (when (eq kind :remote-writer)
                                              (dds.disc:%reader-durability-init
                                               lj-node
                                               (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                                               (dds.qos:qos-durability
                                                (dds.rtps.discovery:endpoint-data-qos remote))))))
                                    (dds.disc:start-node lj-node)
                                    (setf (dds.disc:disc-node-peers lj-node)
                                          (list (cons "127.0.0.1" (dds.disc:disc-node-port svc-b-node))))
                                    (setf (dds.disc:disc-node-peers svc-b-node)
                                          (list (cons "127.0.0.1" (dds.disc:disc-node-port lj-node))))
                                    (%await-match lj-node svc-b-node :retries 300 :sleep-s 0.02)
                                    (%await-sample-count lj-node n :retries 1200 :sleep-s 0.005)
                                    (%check :dyn-b-latejoiner-count
                                            (= n (dds.disc:node-sample-count lj-node))
                                            (format nil "DynB TL late-joiner expected ~d samples, got ~d"
                                                    n (dds.disc:node-sample-count lj-node))))
                               (ignore-errors (dds.disc:stop-node lj-node)))))
                      (ignore-errors (dds.disc:stop-node pub-node)))))))))
      (ignore-errors (dds.durability:service-stop svc))))
  t)

;;; --- dynamic-topic-add DISCOVERY-DRIVEN auto-serve test (WP-DURABILITY-DYNAMIC-TOPIC-DISCOVERY, ADR 0026 Phase-2b) ---
;;; The discovery-driven half of dynamic-topic-add: an opt-in :auto-discover service sees a SEDP writer for an
;;; UNCONFIGURED topic at RUNTIME and auto-spins a node to collect + serve it — no explicit service-add-topic call,
;;; no restart. Structural asserts (the pure filter/select core, the %service-topics relaxation, DEFAULT-OFF
;;; byte-identical, the start->stop->start lifecycle) run on BOTH impls. The live end-to-end arm (a real publisher
;;; discovered -> auto-added -> collected -> TL late-joiner replay) is SBCL-only per NFR-PORT (the clasp-threading
;;; gap), pass-skipped on Clasp exactly like run-durability-dynamic-topic-test. Domain +td-dynamic-topic-discovery+.

(defun* run-durability-dynamic-topic-discovery-test ()
    (function () t)
  "Discovery-driven auto-serve: an :auto-discover service auto-adds an unconfigured discovered WRITER topic
   (passing its filter) via the idempotent service-add-topic, with no explicit add-topic and no restart.
   Structural (both impls): the filter + selection core, the %service-topics :auto-discover relaxation,
   DEFAULT-OFF byte-identical (no discovery node/thread when off), and the start->stop->start lifecycle.
   SBCL-live: a publisher on the new topic DynC is discovered -> auto-added (nodes grow, topic-names gains DynC)
   -> collected (store-count = N) -> a TL late-joiner gets the N-sample replay; a non-matching 'Other' is NOT
   served (filter gate). RED contrast: a :auto-discover NIL service never serves DynC (pre-3c behavior)."
  ;; ============================================================================================
  ;; PART A — pure selection core (both impls, no threads): filter match, dedup, %service-topics relax
  ;; ============================================================================================
  ;; A1: %auto-discover-match-p — NIL match-all, "Dyn*" glob, function predicate, exact string, "*" all
  (%check :ad-match-nil-all
          (and (dds.durability::%auto-discover-match-p nil "Anything")
               (dds.durability::%auto-discover-match-p nil ""))
          "NIL filter must match every topic-name (match-all default under opt-in)")
  (%check :ad-match-glob
          (and (dds.durability::%auto-discover-match-p "Dyn*" "DynX")
               (dds.durability::%auto-discover-match-p "Dyn*" "DynC")
               (dds.durability::%auto-discover-match-p "Dyn*" "Dyn")
               (not (dds.durability::%auto-discover-match-p "Dyn*" "Other"))
               (not (dds.durability::%auto-discover-match-p "Dyn*" "Dy")))
          "\"Dyn*\" prefix glob must match Dyn-prefixed names and reject others")
  (%check :ad-match-star-all
          (and (dds.durability::%auto-discover-match-p "*" "Anything")
               (dds.durability::%auto-discover-match-p "*" ""))
          "\"*\" must match every name")
  (%check :ad-match-exact
          (and (dds.durability::%auto-discover-match-p "Exact" "Exact")
               (not (dds.durability::%auto-discover-match-p "Exact" "Exactly")))
          "a string with no trailing #\\* must match exactly")
  (%check :ad-match-predicate
          (let ((pred (lambda (n) (eql 0 (search "Sensor" n)))))
            (and (dds.durability::%auto-discover-match-p pred "SensorA")
                 (not (dds.durability::%auto-discover-match-p pred "Square"))))
          "a function filter must be applied as a predicate over the topic-name")
  ;; A2: %auto-discover-pending — filter gates + dedup-by-name + order preserved
  (let ((pending (dds.durability::%auto-discover-pending
                  "Dyn*"
                  '(("DynX" . "TX") ("Other" . "TO") ("DynX" . "TX2") ("DynC" . "TC") ("" . "TE")))))
    (%check :ad-pending-filter+dedup
            (equal pending '(("DynX" . "TX") ("DynC" . "TC")))
            (format nil "pending must keep only matching, de-duped by name (got ~s)" pending)))
  (let ((pending-all (dds.durability::%auto-discover-pending
                      nil '(("A" . "T") ("B" . "T") ("A" . "T2")))))
    (%check :ad-pending-nil-all
            (equal pending-all '(("A" . "T") ("B" . "T")))
            (format nil "NIL filter keeps all, de-duped by name (got ~s)" pending-all)))
  ;; A3: %service-topics relaxation — gated STRICTLY on :auto-discover
  (flet ((topics-of (spec) (dds.durability::%service-topics spec))
         (errors-p (spec) (handler-case (progn (dds.durability::%service-topics spec) nil)
                            (error () t))))
    (let ((spec-empty-on  (dds.durability:make-service-spec :domain 0 :topics '() :auto-discover t))
          (spec-pred-on   (dds.durability:make-service-spec :domain 0
                            :topics (lambda (topic type) (declare (ignore topic type)) t) :auto-discover t))
          (spec-list-on   (dds.durability:make-service-spec :domain 0
                            :topics '(("Seed" . "T")) :auto-discover t))
          (spec-empty-off (dds.durability:make-service-spec :domain 0 :topics '()))
          (spec-pred-off  (dds.durability:make-service-spec :domain 0
                            :topics (lambda (topic type) (declare (ignore topic type)) t))))
      (%check :st-empty-auto-ok
              (null (topics-of spec-empty-on))
              ":auto-discover + empty start-list must return '() (no error)")
      (%check :st-pred-auto-ok
              (null (topics-of spec-pred-on))
              ":auto-discover + predicate start-list must return '() (no error)")
      (%check :st-list-auto-kept
              (equal '(("Seed" . "T")) (topics-of spec-list-on))
              ":auto-discover + concrete list must return the list unchanged")
      (%check :st-empty-off-errors
              (errors-p spec-empty-off)
              "without :auto-discover an empty start-list must still error (byte-identical)")
      (%check :st-pred-off-errors
              (errors-p spec-pred-off)
              "without :auto-discover a predicate start-list must still error (byte-identical)")))
  ;; ============================================================================================
  ;; PART B — DEFAULT-OFF byte-identical (both impls): :auto-discover NIL -> NO discovery node / thread
  ;; ============================================================================================
  (let* ((off-store (dds.durability:make-memory-store))
         (off-spec  (dds.durability:make-service-spec
                     :domain (test-domain +td-dynamic-topic-discovery+)
                     :topics '(("OffA" . "ShapeType"))
                     :store (lambda () off-store)
                     :name "auto-discover-off"))
         (off-svc   (dds.durability:make-durability-service off-spec :store off-store)))
    (%check :off-spec-flag-nil
            (null (dds.durability:service-spec-auto-discover off-spec))
            ":auto-discover must default to NIL")
    (unwind-protect
         (progn
           (dds.durability:service-start off-svc)
           (%check :off-no-discovery-node
                   (null (dds.durability:durability-service-discovery-node off-svc))
                   "a fixed-set (:auto-discover NIL) service must have NO discovery node")
           (%check :off-alive
                   (dds.durability:service-alive-p off-svc)
                   "the fixed-set service must be alive after start")
           (%check :off-serves-fixed
                   (dds.durability:service-serves-topic-p off-svc "OffA")
                   "the fixed-set service must serve its start-list topic OffA"))
      (ignore-errors (dds.durability:service-stop off-svc))))
  ;; ============================================================================================
  ;; PART C — lifecycle (both impls): :auto-discover t + empty -> discovery node/thread up; stop tears down; restart clean
  ;; ============================================================================================
  (let* ((lc-store (dds.durability:make-memory-store))
         (lc-spec  (dds.durability:make-service-spec
                    :domain (test-domain +td-dynamic-topic-discovery+)
                    :topics '()                       ; empty start-list, permitted under :auto-discover
                    :auto-discover t
                    :store (lambda () lc-store)
                    :name "auto-discover-lifecycle"))
         (lc-svc   (dds.durability:make-durability-service lc-spec :store lc-store)))
    (unwind-protect
         (progn
           ;; start #1: discovery node + poll thread come up; alive with ZERO collect nodes
           (dds.durability:service-start lc-svc)
           (%check :lc-node-up
                   (not (null (dds.durability:durability-service-discovery-node lc-svc)))
                   ":auto-discover service-start must create a discovery node")
           (%check :lc-alive-empty
                   (dds.durability:service-alive-p lc-svc)
                   ":auto-discover service with an empty start-list must be alive (poll thread live)")
           (%check :lc-no-collect-nodes
                   (null (dds.durability:durability-service-nodes lc-svc))
                   "empty start-list -> zero collect nodes at start")
           ;; stop: tears down discovery node + poll thread (no leak)
           (dds.durability:service-stop lc-svc)
           (%check :lc-torn-down
                   (null (dds.durability:durability-service-discovery-node lc-svc))
                   "service-stop must tear down the discovery node")
           (%check :lc-not-alive
                   (not (dds.durability:service-alive-p lc-svc))
                   "service must not be alive after stop")
           ;; start #2: start->stop->start is clean
           (dds.durability:service-start lc-svc)
           (%check :lc-restart-node-up
                   (not (null (dds.durability:durability-service-discovery-node lc-svc)))
                   "restart must re-create the discovery node (start->stop->start clean)")
           (%check :lc-restart-alive
                   (dds.durability:service-alive-p lc-svc)
                   "service must be alive after restart")
           ;; --- F1: same-object restart-after-auto-add must NOT orphan a dynamically-added topic, and
           ;; must NOT leave a serves-topic-p FALSE POSITIVE (a served topic with no rebuilt collect node) ---
           (let ((dnode2 (dds.durability:durability-service-discovery-node lc-svc)))
             (%inject-discovered-writer dnode2 "DynLC" "DynLCType" #x33)
             (dds.durability::%discovery-poll-once lc-svc dnode2)
             (loop repeat 50 until (dds.durability:service-serves-topic-p lc-svc "DynLC") do (sleep 0.01))
             (%check :lc-add-served
                     (dds.durability:service-serves-topic-p lc-svc "DynLC")
                     "auto-add must serve DynLC on the running (restarted) service"))
           ;; stop: the dynamically-added DynLC must NOT survive as a stale serves-topic-p T
           (dds.durability:service-stop lc-svc)
           (%check :lc-add-cleared-on-stop
                   (not (dds.durability:service-serves-topic-p lc-svc "DynLC"))
                   "service-stop must clear a dynamically-added topic (no serves-topic-p false-positive)")
           ;; start #3 on the SAME object: nothing re-discovers DynLC yet, so it must be correctly UNSERVED
           ;; (not orphaned as a positive with no collect node — the F1 fix)
           (dds.durability:service-start lc-svc)
           (%check :lc-restart3-no-stale-positive
                   (not (dds.durability:service-serves-topic-p lc-svc "DynLC"))
                   "after restart the stale DynLC must not be a serves-topic-p false-positive")
           ;; re-discovery after restart genuinely re-serves + rebuilds a collect node (the restart is clean)
           (let ((dnode3 (dds.durability:durability-service-discovery-node lc-svc)))
             (%inject-discovered-writer dnode3 "DynLC" "DynLCType" #x33)
             (dds.durability::%discovery-poll-once lc-svc dnode3)
             (loop repeat 50 until (dds.durability:service-serves-topic-p lc-svc "DynLC") do (sleep 0.01))
             (%check :lc-restart3-reserved
                     (dds.durability:service-serves-topic-p lc-svc "DynLC")
                     "re-discovery after restart must re-serve DynLC (a collect node genuinely rebuilt)")
             (%check :lc-restart3-node-rebuilt
                     (= 1 (length (dds.durability:durability-service-nodes lc-svc)))
                     (format nil "re-serve must rebuild exactly one collect node (got ~d)"
                             (length (dds.durability:durability-service-nodes lc-svc))))))
      (ignore-errors (dds.durability:service-stop lc-svc))))
  ;; ============================================================================================
  ;; PART D — auto-add fires DETERMINISTICALLY on BOTH impls (synthetic discovered writer, no live
  ;; publisher / timing): inject writers into the discovery node, drive one poll cycle, assert
  ;; auto-add fires + nodes grow + topic-names gains the topic + the filter gates + idempotent.
  ;; This exercises exactly the service-add-topic node/thread build the API-driven test already runs
  ;; on Clasp (durability-dynamic-topic), so it is Clasp-safe.
  ;; ============================================================================================
  (let* ((inj-store (dds.durability:make-memory-store))
         (inj-spec  (dds.durability:make-service-spec
                     :domain (test-domain +td-dynamic-topic-discovery+)
                     :topics '()
                     :auto-discover t
                     :auto-discover-filter "Dyn*"
                     :store (lambda () inj-store)
                     :name "auto-discover-inject"))
         (inj-svc   (dds.durability:make-durability-service inj-spec :store inj-store)))
    (unwind-protect
         (progn
           (dds.durability:service-start inj-svc)
           (let ((dnode (dds.durability:durability-service-discovery-node inj-svc)))
             ;; inject two synthetic discovered WRITERS: DynZ (matches "Dyn*") + OtherZ (non-matching)
             (%inject-discovered-writer dnode "DynZ" "DynZType" #x11)
             (%inject-discovered-writer dnode "OtherZ" "OtherZType" #x22)
             ;; drive one deterministic poll cycle (the poll thread would do the same; both idempotent)
             (dds.durability::%discovery-poll-once inj-svc dnode)
             (loop repeat 50 until (dds.durability:service-serves-topic-p inj-svc "DynZ") do (sleep 0.01))
             (%check :inj-auto-add-fires
                     (dds.durability:service-serves-topic-p inj-svc "DynZ")
                     "auto-add must fire for a discovered matching writer (topic-names gains DynZ)")
             (%check :inj-nodes-grew
                     (= 1 (length (dds.durability:durability-service-nodes inj-svc)))
                     (format nil "auto-add must grow nodes to exactly 1 (got ~d)"
                             (length (dds.durability:durability-service-nodes inj-svc))))
             (%check :inj-filter-gates
                     (not (dds.durability:service-serves-topic-p inj-svc "OtherZ"))
                     "the filter must gate the non-matching OtherZ (never auto-served)")
             ;; idempotent: a second poll cycle must not double-add
             (dds.durability::%discovery-poll-once inj-svc dnode)
             (%check :inj-idempotent
                     (= 1 (length (dds.durability:durability-service-nodes inj-svc)))
                     "repeated poll must not double-add (idempotent-by-name)")))
      (ignore-errors (dds.durability:service-stop inj-svc))))
  ;; ============================================================================================
  ;; PART E — SBCL-live end-to-end (Clasp-skipped per NFR-PORT clasp-threading-gap)
  ;; ============================================================================================
  (cond
    ((eq (dds.pal:pal-impl-name) :clasp)
     (format t "~&    [dynamic-topic-discovery] Clasp: skipping live-thread arm (NFR-PORT gap)~%"))
    (t
     (let* ((n 3)
            (dom (test-domain +td-dynamic-topic-discovery+))
            (pub-prefix (%make-test-prefix #xD9))
            (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain dom
                                               :host "127.0.0.1" :port 0 :multicast nil)))
       (unwind-protect
            (progn
              ;; publisher with TWO writers: DynC (matches "Dyn*") + Other (non-matching); arbitrary type-names
              ;; (DynCType/OtherType, NOT ShapeType) prove opaque-bytes / no-type-registration end-to-end
              (dds.disc:add-local-writer pub-node :topic "DynC" :type "DynCType"
                                         :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                        :durability :transient-local))
              (dds.disc:add-local-writer pub-node :topic "Other" :type "OtherType"
                                         :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                        :durability :transient-local))
              (dds.disc:enable-publisher pub-node :history-kind :keep-all)
              (dds.disc:start-node pub-node)
              (let ((pub-port (dds.disc:disc-node-port pub-node)))
                ;; --- RED contrast: a :auto-discover NIL service, same domain + pub, never serves DynC ---
                (let* ((red-store (dds.durability:make-memory-store))
                       (red-spec  (dds.durability:make-service-spec
                                   :domain dom :topics '(("CtrlA" . "ShapeType"))
                                   :qos-overrides (list :peers (list (cons "127.0.0.1" pub-port)))
                                   :store (lambda () red-store) :name "auto-discover-red-control"))
                       (red-svc   (dds.durability:make-durability-service red-spec :store red-store)))
                  (unwind-protect
                       (progn
                         (dds.durability:service-start red-svc)
                         (loop repeat 60 do (dds.disc:announce-participant pub-node)
                                            (dds.disc:announce-endpoints pub-node) (sleep 0.02))
                         (%check :dd-red-dync-not-served
                                 (not (dds.durability:service-serves-topic-p red-svc "DynC"))
                                 "RED (pre-3c): a :auto-discover NIL service must NEVER auto-serve DynC"))
                    (ignore-errors (dds.durability:service-stop red-svc))))
                ;; --- GREEN: :auto-discover service, filter "Dyn*", empty start-list, pub in :peers ---
                (let* ((svc-store (dds.durability:make-memory-store))
                       (spec (dds.durability:make-service-spec
                              :domain dom
                              :topics '()
                              :auto-discover t
                              :auto-discover-filter "Dyn*"
                              :qos-overrides (list :peers (list (cons "127.0.0.1" pub-port)))
                              :store (lambda () svc-store)
                              :name "auto-discover-green"))
                       (svc (dds.durability:make-durability-service spec :store svc-store)))
                  (unwind-protect
                       (progn
                         (dds.durability:service-start svc)
                         (%check :dd-green-starts-empty
                                 (null (dds.durability:durability-service-nodes svc))
                                 "GREEN service starts with zero collect nodes (empty start-list)")
                         ;; drive discovery: pub announces until the service AUTO-ADDS DynC
                         (loop repeat 500
                               until (dds.durability:service-serves-topic-p svc "DynC")
                               do (dds.disc:announce-participant pub-node)
                                  (dds.disc:announce-endpoints pub-node)
                                  (sleep 0.02))
                         ;; --- the point: DynC auto-served (nodes grew, topic-names gained DynC) ---
                         (%check :dd-auto-serve-dync
                                 (dds.durability:service-serves-topic-p svc "DynC")
                                 "GREEN: DynC must be AUTO-SERVED from discovery (no explicit add, no restart)")
                         (%check :dd-nodes-grew
                                 (>= (length (dds.durability:durability-service-nodes svc)) 1)
                                 "auto-add must grow durability-service-nodes")
                         ;; a few more cycles so any Other SEDP + several poll ticks have surely elapsed
                         (loop repeat 40 do (dds.disc:announce-participant pub-node)
                                            (dds.disc:announce-endpoints pub-node) (sleep 0.02))
                         ;; --- FILTER gate (live): the non-matching Other is NOT served ---
                         (%check :dd-filter-blocks-other
                                 (not (dds.durability:service-serves-topic-p svc "Other"))
                                 "FILTER: the non-matching topic Other must NOT be auto-served")
                         (%check :dd-dync-still-served
                                 (dds.durability:service-serves-topic-p svc "DynC")
                                 "DynC must remain served after further poll cycles (idempotent, no drop)")
                         ;; --- collect: locate the auto-added DynC collect node (by its relay writer's topic),
                         ;; wire it bidirectionally to the pub, then publish N and drain (fast announce loop) ---
                         (let ((dync-node
                                (let ((pair (find "DynC" (dds.durability:durability-service-nodes svc)
                                                  :key (lambda (p)
                                                         (let ((w (dds.disc::disc-node-local-writers (car p))))
                                                           (and w (dds.rtps.discovery:endpoint-data-topic-name
                                                                   (first w)))))
                                                  :test #'equal)))
                                  (and pair (car pair)))))
                           (%check :dd-dync-node-found
                                   (not (null dync-node))
                                   "the auto-added DynC collect node must be locatable by its relay writer's topic")
                           (when dync-node
                             (%wire-unicast dync-node pub-node)
                             (%await-match dync-node pub-node :retries 300 :sleep-s 0.02)
                             (dotimes (i n) (dds.disc:publish-sample pub-node (%make-small-payload (1+ i))))
                             (loop repeat 120
                                   until (>= (dds.durability:store-count svc-store "DynC") n)
                                   do (%announce-both pub-node dync-node) (sleep 0.02))
                             (%check :dd-dync-collected
                                     (= n (dds.durability:store-count svc-store "DynC"))
                                     (format nil "DynC store expected ~d, got ~d"
                                             n (dds.durability:store-count svc-store "DynC")))
                             ;; --- TL late-joiner replay: stop pub, then a fresh TL reader on DynC gets all N ---
                             (ignore-errors (dds.disc:stop-node pub-node))
                             (sleep 0.1)
                             (let* ((lj-prefix (%make-test-prefix #xE9))
                                    (lj-node (dds.disc:make-disc-node :guid-prefix lj-prefix :domain dom
                                                                       :host "127.0.0.1" :port 0 :multicast nil)))
                               (unwind-protect
                                    (progn
                                      (dds.disc:add-local-reader lj-node :topic "DynC" :type "DynCType"
                                                                 :qos (dds.qos:make-reader-qos
                                                                       :reliability :reliable
                                                                       :durability :transient-local))
                                      (dds.disc:enable-subscriber lj-node)
                                      (setf (dds.disc:disc-node-on-match lj-node)
                                            (lambda (kind remote &optional local-eid)
                                              (declare (ignore local-eid))
                                              (when (eq kind :remote-writer)
                                                (dds.disc:%reader-durability-init
                                                 lj-node
                                                 (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                                                 (dds.qos:qos-durability
                                                  (dds.rtps.discovery:endpoint-data-qos remote))))))
                                      (dds.disc:start-node lj-node)
                                      (%wire-unicast lj-node dync-node)
                                      (%await-match lj-node dync-node :retries 300 :sleep-s 0.02)
                                      (%await-sample-count lj-node n :retries 1200 :sleep-s 0.005)
                                      (%check :dd-latejoiner-replay
                                              (= n (dds.disc:node-sample-count lj-node))
                                              (format nil "DynC TL late-joiner expected ~d samples, got ~d"
                                                      n (dds.disc:node-sample-count lj-node))))
                                 (ignore-errors (dds.disc:stop-node lj-node)))))))
                    (ignore-errors (dds.durability:service-stop svc))))))
         (ignore-errors (dds.disc:stop-node pub-node))))))
  t)

;;; --- logical-origin accessor test (Task 1: WP-DURABILITY-COEXIST-LIVE) ---
;;; node-sample-origin-guid/-sn surface the PID_ORIGINAL_WRITER_INFO logical origin
;;; (RTPS 2.5 §8.3.5.4) for relayed samples.  A direct sample (no OWI) falls back to
;;; the wire GUID/SN.  Two-node loopback, domain 78.

(defun* run-durability-origin-accessor-test ()
    (function () t)
  "node-sample-origin-guid/-sn surface the logical origin (RTPS 2.5 §8.3.5.4): a sample relayed with
   PID_ORIGINAL_WRITER_INFO reports the ORIGINAL writer's (GUID,SN), not the relaying wire sender; a
   direct sample (no OWI) reports the wire GUID/SN. Two-node loopback, domain 78."
  (let* ((relay-prefix (%make-test-prefix #xA1))
         (relay-node (dds.disc:make-disc-node :guid-prefix relay-prefix :domain (test-domain +td-origin-accessor+)
                                              :host "127.0.0.1" :port 0 :multicast nil))
         (rdr-prefix (%make-test-prefix #xB2))
         (rdr-node (dds.disc:make-disc-node :guid-prefix rdr-prefix :domain (test-domain +td-origin-accessor+)
                                            :host "127.0.0.1" :port 0 :multicast nil))
         (orig-guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xC3))
         (orig-sn 41))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer relay-node :topic "OSquare" :type "ShapeType"
                                      :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                     :durability :transient-local))
           (dds.disc:enable-publisher relay-node :history-kind :keep-all)
           (dds.disc:start-node relay-node)
           (dds.disc:add-local-reader rdr-node :topic "OSquare" :type "ShapeType"
                                      :qos (dds.qos:make-reader-qos :reliability :reliable
                                                                     :durability :transient-local))
           (dds.disc:enable-subscriber rdr-node)
           (dds.disc:start-node rdr-node)
           (let ((rp (dds.disc:disc-node-port relay-node))
                 (sp (dds.disc:disc-node-port rdr-node)))
             (setf (dds.disc:disc-node-peers relay-node) (list (cons "127.0.0.1" sp)))
             (setf (dds.disc:disc-node-peers rdr-node)   (list (cons "127.0.0.1" rp))))
           (loop repeat 400
                 until (and (plusp (dds.disc:disc-node-matched-count relay-node))
                            (plusp (dds.disc:disc-node-matched-count rdr-node)))
                 do (dds.disc:announce-participant relay-node) (dds.disc:announce-endpoints relay-node)
                    (dds.disc:announce-participant rdr-node)   (dds.disc:announce-endpoints rdr-node)
                    (sleep 0.02))
           ;; (1) a RELAYED sample: publish with PID_ORIGINAL_WRITER_INFO = (orig-guid, orig-sn)
           (dds.disc:publish-relay-sample relay-node (%make-small-payload 7) orig-guid orig-sn)
           (loop repeat 200
                 until (plusp (dds.disc:node-sample-count rdr-node))
                 do (dds.disc:announce-participant relay-node) (dds.disc:announce-endpoints relay-node)
                    (sleep 0.02))
           (let ((key (first (dds.disc:node-sample-sns rdr-node))))
             (%check :origin-accessor-relayed-guid
                     (equalp (dds.disc:node-sample-origin-guid rdr-node key) orig-guid)
                     "a relayed sample must report the ORIGINAL writer GUID, not the wire sender")
             (%check :origin-accessor-relayed-sn
                     (= (dds.disc:node-sample-origin-sn rdr-node key) orig-sn)
                     "a relayed sample must report the ORIGINAL writer SN")
             (%check :origin-accessor-not-wire
                     (not (equalp (dds.disc:node-sample-origin-guid rdr-node key) (car key)))
                     "the relayed origin GUID must differ from the wire sender GUID in this test")
             ;; (2) a DIRECT sample: no OWI; accessor must fall back to the wire GUID/SN and store NOTHING extra
             (dds.disc:publish-sample relay-node (%make-small-payload 8))
             (loop repeat 200
                   until (= 2 (dds.disc:node-sample-count rdr-node))
                   do (dds.disc:announce-participant relay-node) (dds.disc:announce-endpoints relay-node)
                      (sleep 0.02))
             (let ((dkey (first (set-difference (dds.disc:node-sample-sns rdr-node)
                                                (list key) :test #'equal))))
               (%check :origin-accessor-direct-guid
                       (equalp (dds.disc:node-sample-origin-guid rdr-node dkey) (car dkey))
                       "a direct sample must report the WIRE sender GUID as its origin")
               (%check :origin-accessor-direct-sn
                       (= (dds.disc:node-sample-origin-sn rdr-node dkey) (cdr dkey))
                       "a direct sample must report the WIRE SN as its origin")
               (%check :origin-accessor-direct-no-store
                       (let ((inner (gethash (car dkey)
                                             (dds.disc::disc-node-sample-origins rdr-node))))
                         (or (null inner) (null (gethash (cdr dkey) inner))))
                       "a direct sample must NOT insert an entry into sample-origins (zero-extra-alloc invariant)"))))
      (ignore-errors (dds.disc:stop-node relay-node))
      (ignore-errors (dds.disc:stop-node rdr-node))))
  t)

;;; --- collect-loop origin-convergence test (Task 2: WP-DURABILITY-COEXIST-LIVE) ---
;;; Publisher P (direct, no OWI) + foreign relay R (OWI = P's GUID) both feed the durability
;;; collect node. After the fix, the service store holds exactly ONE origin GUID == P's GUID
;;; regardless of which wire sender delivers first (RTPS 2.5 §8.3.5.4, ADR 0028).

(defun* %collect-origin-convergence-case (relay-first)
    (function (t) t)
  "One convergence case: publisher P (direct, no OWI) + foreign relay R (OWI = P's GUID) both feed the
   durability collect node N samples; RELAY-FIRST selects which writes first. The service store must end
   with exactly ONE distinct origin GUID == P's GUID (the logical origin), never R's wire GUID. Domain 79."
  (let* ((n 3)
         (svc-store (dds.durability:make-memory-store))
         (spec (dds.durability:make-service-spec
                :domain (test-domain +td-collect-origin-convergence+) :topics '(("CSquare" . "ShapeType")) :store (lambda () svc-store)
                :qos-overrides '(:collect-durability :transient) :name "collect-origin-convergence"))
         (svc (dds.durability:make-durability-service spec :store svc-store))
         (pub-node (dds.disc:make-disc-node :guid-prefix (%make-test-prefix #x1A) :domain (test-domain +td-collect-origin-convergence+)
                                            :host "127.0.0.1" :port 0 :multicast nil))
         (relay-node (dds.disc:make-disc-node :guid-prefix (%make-test-prefix #x2B) :domain (test-domain +td-collect-origin-convergence+)
                                              :host "127.0.0.1" :port 0 :multicast nil)))
    (unwind-protect
         (progn
           (dds.durability:service-start svc)
           (let* ((svc-node (dds.durability:durability-service-node svc))
                  ;; pub-guid: extract the 16-octet writer GUID from the returned endpoint-data
                  ;; (add-local-writer returns endpoint-data, not the raw GUID array)
                  (pub-ep   (dds.disc:add-local-writer pub-node :topic "CSquare" :type "ShapeType"
                                                       :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                                      :durability :transient)))
                  (pub-guid (copy-seq (dds.rtps.discovery:endpoint-data-guid pub-ep))))
             (dds.disc:enable-publisher pub-node :history-kind :keep-all)
             (dds.disc:start-node pub-node)
             (dds.disc:add-local-writer relay-node :topic "CSquare" :type "ShapeType"
                                        :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                       :durability :transient))
             (dds.disc:enable-publisher relay-node :history-kind :keep-all)
             (dds.disc:start-node relay-node)
             (let ((pp (dds.disc:disc-node-port pub-node))
                   (rp (dds.disc:disc-node-port relay-node))
                   (sp (dds.disc:disc-node-port svc-node)))
               (setf (dds.disc:disc-node-peers pub-node)   (list (cons "127.0.0.1" sp)))
               (setf (dds.disc:disc-node-peers relay-node) (list (cons "127.0.0.1" sp)))
               (setf (dds.disc:disc-node-peers svc-node)
                     (list (cons "127.0.0.1" pp) (cons "127.0.0.1" rp))))
             (loop repeat 400
                   until (>= (dds.disc:disc-node-matched-count svc-node) 2)
                   do (dds.disc:announce-participant pub-node) (dds.disc:announce-endpoints pub-node)
                      (dds.disc:announce-participant relay-node) (dds.disc:announce-endpoints relay-node)
                      (dds.disc:announce-participant svc-node) (dds.disc:announce-endpoints svc-node)
                      (sleep 0.02))
             (flet ((send-direct () (dotimes (i n) (dds.disc:publish-sample pub-node (%make-small-payload (1+ i)))))
                    (send-relay  () (dotimes (i n)
                                     (dds.disc:publish-relay-sample relay-node (%make-small-payload (1+ i))
                                                                    pub-guid (1+ i)))))
               (if relay-first (progn (send-relay) (sleep 0.2) (send-direct))
                   (progn (send-direct) (sleep 0.2) (send-relay))))
             (loop repeat 200
                   do (dds.disc:announce-participant pub-node) (dds.disc:announce-endpoints pub-node)
                      (dds.disc:announce-participant relay-node) (dds.disc:announce-endpoints relay-node)
                      (dds.disc:announce-participant svc-node) (dds.disc:announce-endpoints svc-node)
                      (sleep 0.03))
             (let ((origins (remove-duplicates
                             (mapcar #'dds.durability:durable-record-writer-guid
                                     (dds.durability:store-get-range svc-store "CSquare"))
                             :test #'equalp)))
               (%check (if relay-first :converge-relay-first :converge-direct-first)
                       (and (= 1 (length origins)) (equalp (first origins) pub-guid))
                       (format nil "store must hold exactly ONE origin == pub-guid ~a (relay-first=~a); got ~d: ~a"
                               pub-guid relay-first (length origins) origins)))))
      (ignore-errors (dds.disc:stop-node pub-node))
      (ignore-errors (dds.disc:stop-node relay-node))
      (ignore-errors (dds.durability:service-stop svc))))
  t)

(defun* run-durability-collect-origin-convergence-test ()
    (function () t)
  "The fix's deterministic proof: a durability relay collecting the SAME logical sample from a direct
   publisher AND a foreign OWI-stamping relay converges on the publisher's logical origin regardless of
   arrival order (RTPS 2.5 §8.3.5.4, ADR 0028) — the data-path symmetry of the lifecycle drain's orig-guid."
  (%collect-origin-convergence-case t)     ; relay copy arrives first (the case that diverged before the fix)
  (%collect-origin-convergence-case nil)   ; direct copy arrives first
  t)

;;; --- collect-loop stores :data under its wire key-hash (Task 2: WP-DURABILITY-KEEPLAST-COMPACTION, ADR 0029) ---
;;; A durability service (in-memory) collects a keyed sample whose writer embeds PID_KEY_HASH in its
;;; inline-QoS (RTPS 2.5 §9.6.4.8).  The service's collect-loop, having opted into capture-data-key-hash,
;;; passes node-sample-key-hash to store-put so the resulting durable-record carries the wire hash — NOT NIL.
;;; Also asserts that the two new DURABILITY_SERVICE history QoS fields (DDS 1.4 §2.2.3.5) are plumbed
;;; correctly: :keep-all (default) + depth 1 accessible via service-spec-history-kind / -depth.
;;; Domain 81, in-memory store, loopback unicast.

(defun* run-durability-collect-keyhash-store-test ()
    (function () t)
  "Durability collect-loop stores :data records under the wire PID_KEY_HASH (ADR 0029, DDS 1.4 §2.2.3.5,
   RTPS 2.5 §9.6.4.8): durable-record-key-hash equals the 16-octet hash published by the writer.
   Also asserts service-spec-history-kind / -depth plumbing (DURABILITY_SERVICE QoS fields).
   Domain 81, in-memory store, loopback unicast."
  (let* ((kh16 (make-array 16 :element-type '(unsigned-byte 8) :initial-contents
                            '(#xA1 #xA2 #xA3 #xA4 #xA5 #xA6 #xA7 #xA8
                              #xA9 #xAA #xAB #xAC #xAD #xAE #xAF #xB0)))
         (svc-store (dds.durability:make-memory-store))
         (spec (dds.durability:make-service-spec
                :domain (test-domain +td-collect-keyhash-store+)
                :topics '(("KHCollect" . "ShapeType"))
                :store (lambda () svc-store)
                :name "collect-keyhash-store-test"))
         (svc (dds.durability:make-durability-service spec :store svc-store))
         (pub-prefix (%make-test-prefix #xB1))
         (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain (test-domain +td-collect-keyhash-store+)
                                            :host "127.0.0.1" :port 0 :multicast nil)))
    ;; assert DURABILITY_SERVICE history QoS fields plumbed (DDS 1.4 §2.2.3.5)
    (%check :history-kind-default
            (eq :keep-all (dds.durability:service-spec-history-kind spec))
            "default history-kind must be :keep-all (DDS 1.4 §2.2.3.5)")
    (%check :history-depth-default
            (= 1 (dds.durability:service-spec-history-depth spec))
            "default history-depth must be 1")
    (let* ((spec2 (dds.durability:make-service-spec
                   :domain (test-domain +td-collect-keyhash-store+)
                   :topics '(("KHCollect2" . "ShapeType"))
                   :history-kind :keep-last
                   :history-depth 5
                   :name "kl5"))
           (kind2 (dds.durability:service-spec-history-kind spec2))
           (dep2  (dds.durability:service-spec-history-depth spec2)))
      (%check :history-kind-kl (eq :keep-last kind2) "explicit :keep-last must round-trip")
      (%check :history-depth-5 (= 5 dep2) "explicit depth 5 must round-trip"))
    (unwind-protect
         (progn
           (dds.durability:service-start svc)
           (let ((svc-node (dds.durability:durability-service-node svc)))
             (dds.disc:add-local-writer pub-node :topic "KHCollect" :type "ShapeType"
                                        :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                       :durability :transient-local))
             (dds.disc:enable-publisher pub-node :history-kind :keep-all)
             (dds.disc:start-node pub-node)
             (let ((pub-port (dds.disc:disc-node-port pub-node))
                   (svc-port (dds.disc:disc-node-port svc-node)))
               (setf (dds.disc:disc-node-peers pub-node)
                     (list (cons "127.0.0.1" svc-port)))
               (setf (dds.disc:disc-node-peers svc-node)
                     (list (cons "127.0.0.1" pub-port))))
             (loop repeat 400
                   until (and (plusp (dds.disc:disc-node-matched-count pub-node))
                              (plusp (dds.disc:disc-node-matched-count svc-node)))
                   do (dds.disc:announce-participant pub-node) (dds.disc:announce-endpoints pub-node)
                      (dds.disc:announce-participant svc-node) (dds.disc:announce-endpoints svc-node)
                      (sleep 0.02))
             ;; publish one keyed sample carrying PID_KEY_HASH in inline-QoS (RTPS 2.5 §9.6.4.8)
             (dds.disc:publish-sample pub-node (%make-small-payload 7) kh16)
             (loop repeat 120
                   do (dds.disc:announce-participant pub-node) (dds.disc:announce-endpoints pub-node)
                      (dds.disc:announce-participant svc-node) (dds.disc:announce-endpoints svc-node)
                      (sleep 0.05))
             (%await-store-count svc-store "KHCollect" 1 :retries 1200 :sleep-s 0.005)
             (let* ((recs (dds.durability:store-get-range svc-store "KHCollect"))
                    (rec  (first recs)))
               (%check :collect-keyhash-stored
                       (and rec
                            (eq :data (dds.durability:durable-record-kind rec))
                            (equalp (dds.durability:durable-record-key-hash rec) kh16))
                       (format nil "record must be :data kind with key-hash=kh16 (kind=~s kh=~s)"
                               (and rec (dds.durability:durable-record-kind rec))
                               (and rec (dds.durability:durable-record-key-hash rec)))))))
      (ignore-errors (dds.disc:stop-node pub-node))
      (ignore-errors (dds.durability:service-stop svc))))
  t)

;;; --- data key-hash capture test (Task 1: WP-DURABILITY-KEEPLAST-COMPACTION, ADR 0029) ---
;;; A writer publishes a keyed sample carrying PID_KEY_HASH in its inline-QoS (RTPS 2.5 §9.6.4.8).
;;; A reader with capture-data-key-hash enabled receives and stores the 16-octet hash.
;;; A second reader with the flag OFF (default) must see NIL — no hot-path allocation, byte-identical.

(defun* run-durability-data-keyhash-capture-test ()
    (function () t)
  "node-sample-key-hash surfaces the 16-octet PID_KEY_HASH (RTPS 2.5 §9.6.4.8) from a :data sample's
   inline-QoS when the receiving node has capture-data-key-hash enabled (ADR 0029). With the flag OFF
   (default) no hash is stored — the hot path stays byte-identical, mem remains 0.0000. Two loopback
   nodes on domain 80; writer publishes with a KH16 key-hash; one subscriber with capture ON, one with
   capture OFF."
  (let* ((pub-prefix (%make-test-prefix #xD1))
         (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain (test-domain +td-data-keyhash-capture+)
                                            :host "127.0.0.1" :port 0 :multicast nil))
         (rdr-on-prefix (%make-test-prefix #xE2))
         (rdr-on (dds.disc:make-disc-node :guid-prefix rdr-on-prefix :domain (test-domain +td-data-keyhash-capture+)
                                          :host "127.0.0.1" :port 0 :multicast nil
                                          :capture-data-key-hash t))
         (rdr-off-prefix (%make-test-prefix #xF3))
         (rdr-off (dds.disc:make-disc-node :guid-prefix rdr-off-prefix :domain (test-domain +td-data-keyhash-capture+)
                                           :host "127.0.0.1" :port 0 :multicast nil))
         (kh16 (make-array 16 :element-type '(unsigned-byte 8) :initial-contents
                           '(#x01 #x02 #x03 #x04 #x05 #x06 #x07 #x08
                             #x09 #x0A #x0B #x0C #x0D #x0E #x0F #x10))))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer pub-node :topic "KHSquare" :type "ShapeType"
                                      :qos (dds.qos:make-writer-qos :reliability :reliable
                                                                     :durability :transient-local))
           (dds.disc:enable-publisher pub-node :history-kind :keep-all)
           (dds.disc:start-node pub-node)
           (dds.disc:add-local-reader rdr-on :topic "KHSquare" :type "ShapeType"
                                      :qos (dds.qos:make-reader-qos :reliability :reliable
                                                                     :durability :transient-local))
           (dds.disc:enable-subscriber rdr-on)
           (dds.disc:start-node rdr-on)
           (dds.disc:add-local-reader rdr-off :topic "KHSquare" :type "ShapeType"
                                      :qos (dds.qos:make-reader-qos :reliability :reliable
                                                                     :durability :transient-local))
           (dds.disc:enable-subscriber rdr-off)
           (dds.disc:start-node rdr-off)
           (let ((pp (dds.disc:disc-node-port pub-node))
                 (on-p (dds.disc:disc-node-port rdr-on))
                 (off-p (dds.disc:disc-node-port rdr-off)))
             (setf (dds.disc:disc-node-peers pub-node)  (list (cons "127.0.0.1" on-p)
                                                               (cons "127.0.0.1" off-p)))
             (setf (dds.disc:disc-node-peers rdr-on)    (list (cons "127.0.0.1" pp)))
             (setf (dds.disc:disc-node-peers rdr-off)   (list (cons "127.0.0.1" pp))))
           (loop repeat 400
                 until (and (>= (dds.disc:disc-node-matched-count pub-node) 2)
                            (plusp (dds.disc:disc-node-matched-count rdr-on))
                            (plusp (dds.disc:disc-node-matched-count rdr-off)))
                 do (dds.disc:announce-participant pub-node) (dds.disc:announce-endpoints pub-node)
                    (dds.disc:announce-participant rdr-on)   (dds.disc:announce-endpoints rdr-on)
                    (dds.disc:announce-participant rdr-off)  (dds.disc:announce-endpoints rdr-off)
                    (sleep 0.02))
           (dds.disc:publish-sample pub-node (%make-small-payload 42) kh16)
           (loop repeat 200
                 until (and (plusp (dds.disc:node-sample-count rdr-on))
                            (plusp (dds.disc:node-sample-count rdr-off)))
                 do (dds.disc:announce-participant pub-node) (dds.disc:announce-endpoints pub-node)
                    (dds.disc:announce-participant rdr-on)   (dds.disc:announce-endpoints rdr-on)
                    (dds.disc:announce-participant rdr-off)  (dds.disc:announce-endpoints rdr-off)
                    (sleep 0.02))
           ;; capture-ON reader: key hash must equal the published KH16
           (let ((key-on (first (dds.disc:node-sample-sns rdr-on))))
             (%check :keyhash-capture-on
                     (equalp (dds.disc:node-sample-key-hash rdr-on key-on) kh16)
                     "capture-enabled reader must record the 16-octet PID_KEY_HASH from the :data sample"))
           ;; capture-OFF reader (default): node-sample-key-hash must return NIL (byte-identical, no alloc)
           (let ((key-off (first (dds.disc:node-sample-sns rdr-off))))
             (%check :keyhash-capture-off
                     (null (dds.disc:node-sample-key-hash rdr-off key-off))
                     "capture-disabled reader must return NIL for node-sample-key-hash")))
      (ignore-errors (dds.disc:stop-node pub-node))
      (ignore-errors (dds.disc:stop-node rdr-on))
      (ignore-errors (dds.disc:stop-node rdr-off))))
  t)

;;; --- in-memory store online per-instance KEEP_LAST eviction (WP-DURABILITY-KEEPLAST-COMPACTION) ---
;;; store-open policy stash drives %mem-put eviction at put time.
;;; Contract: after inserting a :data record for a non-NIL key-hash under :keep-last D,
;;; if the instance now has >D :data records, remove the lowest-SN :data record(s) until D remain.
;;; NIL-key-hash records and lifecycle (:dispose/:unregister) records are NEVER evicted.
;;; :keep-all (default) → no eviction → byte-identical to today.

(defun* run-durability-keeplast-memory-test ()
    (function () t)
  "Online per-instance KEEP_LAST eviction in the in-memory store (ADR 0029, DDS 1.4 §2.2.3.5):
   policy driven by store-open stash; :data records for non-NIL key-hash evicted to depth;
   NIL-key-hash records never evicted; distinct instances independent; :keep-all byte-identical."
  (let* ((guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xAA))
         (kh1  (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xBB))
         (kh2  (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xCC))
         (p    (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b)))
         (topic "KLMem"))
    ;; --- :keep-last 2 via store-open (the service-spec channel, WP-DURABILITY-KEEPLAST-COMPACTION) ---
    (let ((s (dds.durability:make-memory-store)))
      (dds.durability:store-open s :keep-last 2)
      ;; put 5 :data records for keyed instance kh1
      (dotimes (i 5)
        (dds.durability:store-put s topic guid (1+ i) kh1 :data (funcall p (list (1+ i)))))
      ;; assert exactly 2 remain for kh1 (the 2 highest SNs: 4 and 5)
      (let* ((recs  (dds.durability:store-get-range s topic))
             (kh1-data (remove-if-not (lambda (r)
                                        (and (equalp kh1 (dds.durability:durable-record-key-hash r))
                                             (eq :data (dds.durability:durable-record-kind r))))
                                      recs))
             (sns   (sort (mapcar #'dds.durability:durable-record-sn kh1-data) #'<)))
        (%check :klm-count2
                (= 2 (length kh1-data))
                (format nil "KEEP_LAST 2: expected 2 data records for kh1, got ~d" (length kh1-data)))
        (%check :klm-sns
                (equal '(4 5) sns)
                (format nil "KEEP_LAST 2: expected SNs (4 5), got ~s" sns))))
    ;; --- NIL-key-hash instance: all 3 records must survive (never evicted) ---
    (let ((s2 (dds.durability:make-memory-store)))
      (dds.durability:store-open s2 :keep-last 2)
      (dotimes (i 3)
        (dds.durability:store-put s2 topic guid (1+ i) nil :data (funcall p (list (1+ i)))))
      (%check :klm-nil-kh-kept
              (= 3 (dds.durability:store-count s2 topic))
              (format nil "NIL-key-hash records must never be evicted; expected 3, got ~d"
                      (dds.durability:store-count s2 topic))))
    ;; --- two distinct key-hash instances are independent ---
    (let ((s3 (dds.durability:make-memory-store)))
      (dds.durability:store-open s3 :keep-last 2)
      ;; put 3 :data records for kh1 (should evict to 2)
      (dotimes (i 3)
        (dds.durability:store-put s3 topic guid (1+ i) kh1 :data (funcall p (list (1+ i)))))
      ;; put 3 :data records for kh2 (independently evicted to 2)
      (dotimes (i 3)
        (dds.durability:store-put s3 topic guid (+ 10 i) kh2 :data (funcall p (list (+ 10 i)))))
      (let* ((recs (dds.durability:store-get-range s3 topic))
             (kh1d (remove-if-not (lambda (r) (and (equalp kh1 (dds.durability:durable-record-key-hash r))
                                                   (eq :data (dds.durability:durable-record-kind r))))
                                  recs))
             (kh2d (remove-if-not (lambda (r) (and (equalp kh2 (dds.durability:durable-record-key-hash r))
                                                   (eq :data (dds.durability:durable-record-kind r))))
                                  recs)))
        (%check :klm-indep-kh1
                (= 2 (length kh1d))
                (format nil "independent kh1: expected 2, got ~d" (length kh1d)))
        (%check :klm-indep-kh2
                (= 2 (length kh2d))
                (format nil "independent kh2: expected 2, got ~d" (length kh2d)))))
    ;; --- :keep-all (default, no store-open call) keeps all 5 ---
    (let ((s4 (dds.durability:make-memory-store)))
      (dotimes (i 5)
        (dds.durability:store-put s4 topic guid (1+ i) kh1 :data (funcall p (list (1+ i)))))
      (%check :klm-keepall
              (= 5 (dds.durability:store-count s4 topic))
              (format nil "KEEP_ALL: expected all 5 records, got ~d"
                      (dds.durability:store-count s4 topic))))
    t))

;;; --- per-instance KEEP_LAST compaction unit test (WP-DURABILITY-KEEPLAST-COMPACTION) ---
;;; One keyed instance K with 5 :data records (SN 1-5, same key-hash), a NIL-key-hash
;;; record, and a settled instance (dispose+unregister). Under :keep-last 2: K keeps
;;; only its 2 highest SNs (4,5); NIL-key-hash record kept; settled instance dropped.
;;; Under :keep-all (and no-arg default): byte-identical to settled-only result.

(defun* run-durability-keeplast-compaction-test ()
    (function () t)
  "Unit test for %compact-topic-records KEEP_LAST per-instance compaction.
   Verifies: newest-depth :data records kept per non-NIL key-hash; NIL-key-hash
   records untouched; settled instances dropped; :keep-all byte-identical to no-arg call."
  (let* ((guid  (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xAA))
         (kh    (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xBB))  ; instance K
         (kh2   (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xCC))  ; settled instance
         (p     (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b)))
         ;; 5 :data records for instance K (SN 1..5, same key-hash)
         (k1    (dds.durability::make-durable-record :topic "T" :writer-guid guid :sn 1 :key-hash kh
                                                     :kind :data    :payload (funcall p '(1))))
         (k2    (dds.durability::make-durable-record :topic "T" :writer-guid guid :sn 2 :key-hash kh
                                                     :kind :data    :payload (funcall p '(2))))
         (k3    (dds.durability::make-durable-record :topic "T" :writer-guid guid :sn 3 :key-hash kh
                                                     :kind :data    :payload (funcall p '(3))))
         (k4    (dds.durability::make-durable-record :topic "T" :writer-guid guid :sn 4 :key-hash kh
                                                     :kind :data    :payload (funcall p '(4))))
         (k5    (dds.durability::make-durable-record :topic "T" :writer-guid guid :sn 5 :key-hash kh
                                                     :kind :data    :payload (funcall p '(5))))
         ;; NIL-key-hash record (NO_KEY topic — must never be compacted)
         (nil-r (dds.durability::make-durable-record :topic "T" :writer-guid guid :sn 6 :key-hash nil
                                                     :kind :data    :payload (funcall p '(99))))
         ;; settled instance kh2: dispose + unregister (must be dropped by the settled-drop pass)
         (d2    (dds.durability::make-durable-record :topic "T" :writer-guid guid :sn 7 :key-hash kh2
                                                     :kind :dispose    :payload (funcall p '())))
         (u2    (dds.durability::make-durable-record :topic "T" :writer-guid guid :sn 8 :key-hash kh2
                                                     :kind :unregister :payload (funcall p '())))
         (recs  (list k1 k2 k3 k4 k5 nil-r d2 u2)))
    ;; --- :keep-last 2 ---
    (let* ((kept2 (dds.durability::%compact-topic-records recs :keep-last 2))
           (kh-data (remove-if-not (lambda (r)
                                     (and (equalp kh (dds.durability:durable-record-key-hash r))
                                          (eq :data (dds.durability:durable-record-kind r))))
                                   kept2))
           (sns  (sort (mapcar #'dds.durability:durable-record-sn kh-data) #'<)))
      (%check :keeplast-depth2-count
              (= 2 (length kh-data))
              (format nil "KEEP_LAST 2: instance K must have exactly 2 data records; got ~d" (length kh-data)))
      (%check :keeplast-depth2-sns
              (equal '(4 5) sns)
              (format nil "KEEP_LAST 2: instance K must keep SNs (4 5); got ~s" sns))
      ;; NIL-key-hash record must survive
      (%check :keeplast-nil-kh-kept
              (member nil-r kept2 :test #'eq)
              "KEEP_LAST: NIL-key-hash record must be kept untouched")
      ;; settled instance kh2 must be gone
      (%check :keeplast-settled-dropped
              (and (not (member d2 kept2 :test #'eq))
                   (not (member u2 kept2 :test #'eq)))
              "KEEP_LAST: settled instance must be dropped"))
    ;; --- :keep-all byte-identical to no-arg call ---
    (let* ((ka  (dds.durability::%compact-topic-records recs :keep-all))
           (df  (dds.durability::%compact-topic-records recs)))
      (%check :keeplast-keepall-identical
              (and (= (length ka) (length df))
                   (every #'eq ka df))
              (format nil "KEEP_ALL must be byte-identical to no-arg call; got ~d vs ~d records"
                      (length ka) (length df))))
    t))

;;; --- KEEP_LAST cross-restart test: compaction-on-open + DARE intact ---
;;; Write M :data records for one keyed instance to a file-backed (DARE) store.
;;; Close. Reopen via a service-spec with :keep-last D. Assert the reopened store
;;; holds exactly D records for the instance (compaction-on-open ran) AND a record
;;; can be retrieved (DARE decrypt succeeded). Domain 118.

(defun* run-durability-keeplast-cross-restart-test ()
    (function () t)
  "KEEP_LAST cross-restart: write M :data records; reopen with :keep-last D; assert
   exactly D records remain per instance; DARE envelope decrypts (ADR 0029)."
  (unless (dds.dare:dare-available-p)
    (format t "~&  [keeplast-cross-restart] SKIP — OpenSSL >= 3.5 not available~%")
    (return-from run-durability-keeplast-cross-restart-test t))
  (let* ((m       6)
         (d       2)
         (topic   "KLSquare")
         (guid    (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xD5))
         (kh      (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xE6))
         (p       (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b)))
         (tmp-dir (uiop:merge-pathnames*
                   (make-pathname :directory
                                  (list :relative (format nil "dds-kl-restart-~a" (get-universal-time))))
                   (uiop:temporary-directory)))
         (key-dir (uiop:merge-pathnames*
                   (make-pathname :directory '(:relative "keys"))
                   tmp-dir)))
    (unwind-protect
         (progn
           ;; --- write M samples to the encrypted file store ---
           (let* ((store1  (dds.durability:make-file-store
                            :dir tmp-dir
                            :history-kind :keep-last
                            :history-depth d))
                  (kp      (dds.dare:make-file-key-provider :dir key-dir))
                  (enc-st  (dds.durability:make-encrypted-store store1 kp :epoch-dir tmp-dir)))
             (dds.durability:store-open enc-st)
             (dotimes (i m)
               (dds.durability:store-put enc-st topic guid (1+ i) kh :data (funcall p (list (1+ i)))))
             (%check :kl-restart-write
                     (= m (dds.durability:store-count enc-st topic))
                     (format nil "before close: expected ~d records, got ~d"
                             m (dds.durability:store-count enc-st topic)))
             (dds.durability:store-close enc-st))
           ;; --- reopen with :keep-last D → compaction-on-open keeps only D newest ---
           (let* ((store2 (dds.durability:make-file-store
                           :dir tmp-dir
                           :history-kind :keep-last
                           :history-depth d))
                  (kp2    (dds.dare:make-file-key-provider :dir key-dir))
                  (enc-st2 (dds.durability:make-encrypted-store store2 kp2 :epoch-dir tmp-dir)))
             (unwind-protect
                  (progn
                    ;; 3c: the encrypted decorator owns compaction; the effective KEEP_LAST policy is
                    ;; supplied to store-open (exactly as service-start does), not inferred from the
                    ;; inner file-store's factory config.
                    (dds.durability:store-open enc-st2 :keep-last d)
                    (%check :kl-restart-count
                            (= d (dds.durability:store-count enc-st2 topic))
                            (format nil "after :keep-last ~d reopen: expected ~d records, got ~d"
                                    d d (dds.durability:store-count enc-st2 topic)))
                    ;; DARE decrypt check: records must be accessible (non-empty payload)
                    (let ((recs (dds.durability:store-get-range enc-st2 topic)))
                      (%check :kl-restart-dare-intact
                              (and (= d (length recs))
                                   (every (lambda (r)
                                            (plusp (length (dds.durability:durable-record-payload r))))
                                          recs))
                              (format nil "DARE decrypt: expected ~d records with non-empty payload; got ~s"
                                      d (mapcar (lambda (r)
                                                  (length (dds.durability:durable-record-payload r)))
                                                recs)))))
               (ignore-errors (dds.durability:store-close enc-st2)))))
      (ignore-errors
       (when (uiop:directory-exists-p tmp-dir)
         (uiop:delete-directory-tree tmp-dir :validate t))))
    t))

;;; --- service-spec drives store-open compaction policy (WP-DURABILITY-KEEPLAST-COMPACTION) ---
;;; store-open now accepts optional HISTORY-KIND and HISTORY-DEPTH that override the factory default.
;;; service-start passes these from the service-spec. This test verifies the end-to-end plumbing:
;;; write M samples with factory default (no policy); reopen via store-open with :keep-last D override;
;;; assert exactly D records remain (override took effect, not the factory default :keep-all).

(defun* run-durability-keeplast-service-spec-policy-test ()
    (function () t)
  "store-open history-kind/depth args drive compaction-on-open; service-start wires service-spec
   policy end-to-end (ADR 0029, DDS 1.4 §2.2.3.5):
   Part A (direct store-open): write M records with :keep-all factory; reopen with :keep-last D
   override; assert exactly D records survive (override wins over factory default).
   Part B (service-start end-to-end): write M records to a pre-seeded file store; build a
   durability-service whose spec carries :keep-last D; call service-start; assert the service
   store holds exactly D records (service-start called store-open with the spec policy,
   compaction ran, and the service-spec is the single functional source of the KEEP_LAST policy)."
  (let* ((m       5)
         (d       2)
         (topic   "KLSpecPolicy")
         (guid    (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xF1))
         (kh      (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xF2))
         (p       (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b)))
         (tmp-dir (uiop:merge-pathnames*
                   (make-pathname :directory
                                  (list :relative (format nil "dds-kl-policy-~a" (get-universal-time))))
                   (uiop:temporary-directory))))
    (unwind-protect
         (progn
           ;; Part A: write M samples to a file-store built with default :keep-all (no compaction on close)
           (let ((store1 (dds.durability:make-file-store :dir tmp-dir :history-kind :keep-all)))
             (dds.durability:store-open store1)
             (dotimes (i m)
               (dds.durability:store-put store1 topic guid (1+ i) kh :data (funcall p (list (1+ i)))))
             (%check :policy-write-all
                     (= m (dds.durability:store-count store1 topic))
                     (format nil "before close: expected ~d records, got ~d"
                             m (dds.durability:store-count store1 topic)))
             (dds.durability:store-close store1))
           ;; reopen with store-open :keep-last D override — factory is :keep-all but override wins
           (let ((store2 (dds.durability:make-file-store :dir tmp-dir :history-kind :keep-all)))
             (unwind-protect
                  (progn
                    (dds.durability:store-open store2 :keep-last d)
                    (%check :policy-override-count
                            (= d (dds.durability:store-count store2 topic))
                            (format nil "after :keep-last ~d override: expected ~d records, got ~d"
                                    d d (dds.durability:store-count store2 topic)))
                    (let* ((recs (dds.durability:store-get-range store2 topic))
                           (sns  (sort (mapcar #'dds.durability:durable-record-sn recs) #'<)))
                      (%check :policy-override-sns
                              (equal '(4 5) sns)
                              (format nil "override :keep-last ~d must retain SNs (4 5); got ~s"
                                      d sns))))
               (ignore-errors (dds.durability:store-close store2))))
           ;; verify no-arg store-open uses factory default (:keep-all = no additional compaction)
           (let ((store3 (dds.durability:make-file-store :dir tmp-dir :history-kind :keep-all)))
             (unwind-protect
                  (progn
                    (dds.durability:store-open store3)
                    ;; store3 opens the already-compacted log (2 records from previous reopen)
                    (%check :policy-factory-default
                            (= d (dds.durability:store-count store3 topic))
                            (format nil "no-arg reopen must keep ~d (already-compacted) records; got ~d"
                                    d (dds.durability:store-count store3 topic))))
               (ignore-errors (dds.durability:store-close store3)))))
      (ignore-errors
       (when (uiop:directory-exists-p tmp-dir)
         (uiop:delete-directory-tree tmp-dir :validate t))))
    ;; Part B: end-to-end service-start wiring — service-spec is the single source of compaction policy.
    ;; Pre-seed a fresh dir with M records (all :keep-all, no compaction on close); build a
    ;; durability-service with spec :keep-last D; call service-start; service-start calls store-open
    ;; with (service-spec-history-kind spec) = :keep-last and (service-spec-history-depth spec) = D;
    ;; compaction-on-open reduces the store to D records. Assert store-count = D (not M).
    (let* ((svc-topic "KLSvcPolicy")
           (svc-guid  (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xF3))
           (svc-kh    (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xF4))
           (p2        (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b)))
           (svc-dir   (uiop:merge-pathnames*
                       (make-pathname :directory
                                      (list :relative (format nil "dds-kl-svc-policy-~a" (get-universal-time))))
                       (uiop:temporary-directory))))
      (unwind-protect
           (progn
             ;; pre-seed: write M records with :keep-all factory (all M records on disk)
             (let ((seed-store (dds.durability:make-file-store :dir svc-dir :history-kind :keep-all)))
               (dds.durability:store-open seed-store)
               (dotimes (i m)
                 (dds.durability:store-put seed-store svc-topic svc-guid (1+ i) svc-kh
                                           :data (funcall p2 (list (1+ i)))))
               (%check :svc-policy-seed
                       (= m (dds.durability:store-count seed-store svc-topic))
                       (format nil "pre-seed: expected ~d records, got ~d"
                               m (dds.durability:store-count seed-store svc-topic)))
               (dds.durability:store-close seed-store))
             ;; build spec with :keep-last D — this is the policy that service-start must pass to store-open
             (let* ((spec (dds.durability:make-service-spec
                           :domain (test-domain +td-keeplast-policy+)
                           :topics (list (cons svc-topic "ShapeType"))
                           :history-kind :keep-last
                           :history-depth d
                           :store (lambda ()
                                    (dds.durability:make-file-store :dir svc-dir
                                                                     :history-kind :keep-all))
                           :name "kl-svc-policy-test"))
                    (svc (dds.durability:make-durability-service spec)))
               (unwind-protect
                    (progn
                      ;; service-start calls (store-open store :keep-last D) — driven by spec
                      (dds.durability:service-start svc)
                      ;; compaction-on-open must have run: M records → D records
                      (%check :svc-policy-after-start
                              (= d (dds.durability:store-count
                                    (dds.durability:durability-service-store svc) svc-topic))
                              (format nil "service-start :keep-last ~d must compact M=~d to D=~d; got ~d"
                                      d m d
                                      (dds.durability:store-count
                                       (dds.durability:durability-service-store svc) svc-topic)))
                      ;; SNs retained must be the D newest (4 and 5 for M=5, D=2)
                      (let* ((recs (dds.durability:store-get-range
                                    (dds.durability:durability-service-store svc) svc-topic))
                             (sns  (sort (mapcar #'dds.durability:durable-record-sn recs) #'<)))
                        (%check :svc-policy-sns
                                (equal '(4 5) sns)
                                (format nil "service-start :keep-last ~d must retain SNs (4 5); got ~s"
                                        d sns))))
                 (ignore-errors (dds.durability:service-stop svc)))))
        (ignore-errors
         (when (uiop:directory-exists-p svc-dir)
           (uiop:delete-directory-tree svc-dir :validate t)))))
    t))

(defun* run-durability-graceful-teardown-order-test ()
    (function () t)
  "The graceful teardown stops the service threads and closes the store: after the orderly stop
   (supervisor-stop -> runner-stop -> service-stop), no collect thread is alive and the store is
   closed. service-stop's join-before-close order (service.lisp) is the no-thread-mid-foreign-call
   prerequisite. Domain 82, in-memory store."
  (let* ((store (dds.durability:make-memory-store))
         (spec (dds.durability:make-service-spec
                :domain (test-domain +td-graceful-teardown+) :topics '(("GtSquare" . "ShapeType")) :store (lambda () store)
                :name "graceful-teardown"))
         (svc (dds.durability:make-durability-service spec :store store)))
    (dds.durability:service-start svc)
    (%check :gt-alive-before (dds.durability:service-alive-p svc) "service must be alive after start")
    (dds.durability:service-stop svc)
    (%check :gt-not-alive-after (not (dds.durability:service-alive-p svc))
            "after service-stop every collect thread must be joined (not alive)"))
  t)

;;; --- WP-DURABILITY-HARDENING-BATCH residual tests (ADR 0024/0025/0026/0029 §10) ---

(defun* run-durability-fsync-directory-test ()
    (function () t)
  "B2 (ADR 0026 §10.10): dds.pal:fsync-directory is callable on BOTH impls — a smoke call on a
   real temp directory returns T (open(dir,O_RDONLY)+fsync+close). Also exercised transitively by
   every file-store test (log/epochs.dat create + compaction/truncate rename now fsync the dir)."
  (let ((tmp (uiop:merge-pathnames*
              (make-pathname :directory (list :relative (format nil "dds-b2-fsyncdir-~a"
                                                                (get-universal-time))))
              (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (ensure-directories-exist tmp)
           (%check :b2-fsync-directory
                   (eq t (dds.pal:fsync-directory tmp))
                   "dds.pal:fsync-directory on a temp dir must return T (open+fsync+close)"))
      (when (uiop:directory-exists-p tmp)
        (uiop:delete-directory-tree tmp :validate t)))
    t))

(defun* run-durability-frame-version-test ()
    (function () t)
  "B3 (ADR 0026 §10.9): frame format v2 header-CRC + v1 back-compat read.
   (1) v2 round-trip: %frame-record -> %parse-frame :ok, fields byte-exact.
   (2) v1 back-compat: a legacy no-header-CRC frame still parses :ok (the reader reads both versions).
   (3) mixed-version log: a topics/<tid>.log holding a v1 frame followed by a v2 frame opens with
       BOTH records present (per-frame version dispatch).
   (4) header corruption detected: flip a header byte of an interior v2 frame -> store-open errors
       (a corrupt length/metadata is caught by the header CRC, not mis-parsed as a torn tail)."
  (let* ((g0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x5A))
         (mk (lambda (sn bytes)
               (dds.durability::make-durable-record
                :topic "R" :writer-guid g0 :sn sn :key-hash nil :kind :data
                :payload (make-array (length bytes) :element-type '(unsigned-byte 8)
                                     :initial-contents bytes))))
         (rec1 (funcall mk 1 '(11 12)))
         (rec2 (funcall mk 2 '(21 22 23))))
    ;; (1) v2 round-trip
    (let ((f2 (dds.durability::%frame-record rec1)))
      (multiple-value-bind (r next reason) (dds.durability::%parse-frame f2 0 (length f2) "R")
        (%check :b3-v2-ok (eq reason :ok) "v2 frame must parse :ok")
        (%check :b3-v2-next (= next (length f2)) "v2 parse next-pos must be frame end")
        (%check :b3-v2-sn (and r (= 1 (dds.durability:durable-record-sn r))) "v2 sn round-trips")
        (%check :b3-v2-payload (and r (equalp (dds.durability:durable-record-payload r)
                                              (dds.durability:durable-record-payload rec1)))
                "v2 payload byte-exact")))
    ;; (2) v1 back-compat read
    (let ((f1 (dds.durability::%frame-record-versioned rec1 dds.durability::+frame-version-v1+)))
      (multiple-value-bind (r next reason) (dds.durability::%parse-frame f1 0 (length f1) "R")
        (declare (ignore next))
        (%check :b3-v1-ok (eq reason :ok) "legacy v1 frame must still parse :ok (back-compat)")
        (%check :b3-v1-sn (and r (= 1 (dds.durability:durable-record-sn r))) "v1 sn round-trips")
        (%check :b3-v1-payload (and r (equalp (dds.durability:durable-record-payload r)
                                              (dds.durability:durable-record-payload rec1)))
                "v1 payload byte-exact")))
    ;; (3) mixed-version log opens with both records
    (let* ((tmp (uiop:merge-pathnames*
                 (make-pathname :directory (list :relative (format nil "dds-b3-mixed-~a"
                                                                   (get-universal-time))))
                 (uiop:temporary-directory)))
           (tid (dds.durability::%topic->id "R"))
           (log (merge-pathnames (make-pathname :directory '(:relative "topics")
                                                :name tid :type "log") tmp)))
      (unwind-protect
           (progn
             (ensure-directories-exist log)
             (dds.dare:enforce-directory-perms-0700 (uiop:ensure-directory-pathname tmp))
             (with-open-file (s log :direction :output :element-type '(unsigned-byte 8)
                                    :if-exists :supersede :if-does-not-exist :create)
               (write-sequence (dds.durability::%frame-record-versioned rec1
                                                                        dds.durability::+frame-version-v1+) s)
               (write-sequence (dds.durability::%frame-record rec2) s)) ; v2
             (let ((st (dds.durability:make-file-store :dir tmp)))
               (unwind-protect
                    (progn
                      (dds.durability:store-open st)
                      (%check :b3-mixed-count (= 2 (dds.durability:store-count st))
                              (format nil "mixed v1+v2 log must yield 2 records, got ~d"
                                      (dds.durability:store-count st))))
                 (ignore-errors (dds.durability:store-close st)))))
        (when (uiop:directory-exists-p tmp)
          (uiop:delete-directory-tree tmp :validate t))))
    ;; (4) interior v2 header-byte corruption detected as :corrupt (store-open errors)
    (let* ((tmp (uiop:merge-pathnames*
                 (make-pathname :directory (list :relative (format nil "dds-b3-hdrcorrupt-~a"
                                                                   (get-universal-time))))
                 (uiop:temporary-directory)))
           (tid (dds.durability::%topic->id "R"))
           (log (merge-pathnames (make-pathname :directory '(:relative "topics")
                                                :name tid :type "log") tmp)))
      (unwind-protect
           (progn
             (ensure-directories-exist log)
             (dds.dare:enforce-directory-perms-0700 (uiop:ensure-directory-pathname tmp))
             (with-open-file (s log :direction :output :element-type '(unsigned-byte 8)
                                    :if-exists :supersede :if-does-not-exist :create)
               (write-sequence (dds.durability::%frame-record rec1) s)   ; interior frame
               (write-sequence (dds.durability::%frame-record rec2) s))
             ;; flip a GUID byte (offset 3) inside frame 1's header -> header CRC must mismatch
             (let ((raw (with-open-file (fin log :element-type '(unsigned-byte 8))
                          (let ((v (make-array (file-length fin) :element-type '(unsigned-byte 8))))
                            (read-sequence v fin) v))))
               (setf (aref raw 3) (logxor (aref raw 3) #xFF))
               (with-open-file (fout log :direction :output :element-type '(unsigned-byte 8)
                                         :if-exists :supersede)
                 (write-sequence raw fout)))
             (let ((st (dds.durability:make-file-store :dir tmp)))
               (%check :b3-hdr-corrupt-detected
                       (handler-case (progn (dds.durability:store-open st) nil) (error () t))
                       "an interior v2 header-byte corruption must fail loud (header CRC), not truncate")))
        (when (uiop:directory-exists-p tmp)
          (uiop:delete-directory-tree tmp :validate t))))
    t))

(defun* run-durability-mac-chain-test ()
    (function () t)
  "WP-DURABILITY-MAC-LOG-CHAIN (ADR 0045): keyed running MAC chain over the durability at-rest log
   makes interior delete/reorder/substitution/insertion tamper-EVIDENT at store-open (fail-closed).
   (1) v3 round-trip: a keyed epoch store writes N, closes, reopens clean, replays N byte-exact.
   (2) v3 frame-level: %frame-record-versioned/%parse-frame verify with the oracle; NO oracle (key
       absent) and WRONG key both ⇒ :corrupt.
   (3) interior tamper (the core value): DELETE / REORDER / SUBSTITUTE-with-recomputed-CRC / INSERT
       each fail the store-open loudly; the untampered control opens clean (non-vacuous).
   (4) cross-restart: write in epoch 1, reopen (epoch 2), append; the full chain across the epoch
       boundary verifies, and tampering across the boundary is caught.
   (5) key-absent fail-closed: a v3 store opened by a bare file store (no key) or with the wrong key
       fails loud, never silently skipping verification.
   (6) honest torn tail still truncate-recovers; malicious whole-frame tail truncation is the
       DOCUMENTED deferred-anchor residual (ADR 0045 §7) — asserted here to remain undetected."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [durability-mac-chain] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-durability-mac-chain-test t)))
  (let ((g0   (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
        (dirs '())
        (pay  (lambda (i)
                (let ((v (make-array 8 :element-type '(unsigned-byte 8))))
                  (dotimes (j 8 v) (setf (aref v j) (logand (+ (* i 16) j) #xFF)))))))
    (labels ((%tmp (tag)
               (let ((d (uiop:merge-pathnames*
                         (make-pathname :directory
                                        (list :relative (format nil "dds-mlc-~a-~a-~a"
                                                                tag (get-universal-time)
                                                                (random 1000000))))
                         (uiop:temporary-directory))))
                 (push d dirs)
                 d))
             (%mk (d k)
               (dds.durability:make-encrypted-store
                (dds.durability:make-file-store :dir d)
                (dds.dare:make-file-key-provider :dir k)
                :epoch-dir d))
             (%tlog (d k)
               (merge-pathnames (make-pathname :directory '(:relative "topics")
                                               :name (%enc-topic-tid d k "T") :type "log")
                                d))
             (%read (d k)
               (with-open-file (s (%tlog d k) :element-type '(unsigned-byte 8))
                 (let ((v (make-array (file-length s) :element-type '(unsigned-byte 8))))
                   (read-sequence v s) v)))
             (%write (d k bytes)
               (with-open-file (s (%tlog d k) :direction :output :element-type '(unsigned-byte 8)
                                            :if-exists :supersede)
                 (write-sequence bytes s)))
             (%put-n (d k n)
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (dotimes (i n) (dds.durability:store-put s "T" g0 (1+ i) nil :data (funcall pay i)))
                 (dds.durability:store-close s)))
             (%open-errs-p (d k)
               (let ((s (%mk d k)))
                 (handler-case (progn (dds.durability:store-open s)
                                      (ignore-errors (dds.durability:store-close s)) nil)
                   (error () t)))))
      (unwind-protect
           (progn
             ;; (1) v3 round-trip: 4 records, reopen clean, byte-exact
             (let ((d (%tmp "rt-d")) (k (%tmp "rt-k")))
               (%put-n d k 4)
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (let ((recs (dds.durability:store-get-range s "T")))
                   (%check :mlc-rt-count (= 4 (length recs))
                           (format nil "v3 round-trip: expected 4 records, got ~d" (length recs)))
                   (%check :mlc-rt-bytes
                           (loop for r in recs for i from 0
                                 always (equalp (dds.durability:durable-record-payload r)
                                                (funcall pay i)))
                           "v3 round-trip: all payloads byte-exact after reopen+chain-verify"))
                 (dds.durability:store-close s)))
             ;; (2) v3 frame-level: verify with oracle; key-absent + wrong-key ⇒ :corrupt
             (let* ((key   (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11))
                    (wrong (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22))
                    (mac-fn   (lambda (data) (dds.dare:hmac-sha256 key data)))
                    (wrong-fn (lambda (data) (dds.dare:hmac-sha256 wrong data)))
                    (rec   (dds.durability::make-durable-record
                            :topic "T" :writer-guid g0 :sn 1 :key-hash nil :kind :data
                            :payload (funcall pay 3)))
                    (seed  (dds.durability::%chain-seed mac-fn "T")))
               (multiple-value-bind (frame mac)
                   (dds.durability::%frame-record-versioned rec dds.durability::+frame-version-v3+
                                                            seed mac-fn)
                 (multiple-value-bind (r next reason fmac)
                     (dds.durability::%parse-frame frame 0 (length frame) "T" mac-fn seed nil)
                   (declare (ignore r next))
                   (%check :mlc-v3-ok (eq reason :ok) "v3 frame must verify :ok with the oracle+seed")
                   (%check :mlc-v3-mac (equalp fmac mac) "v3 parsed frame-mac equals the written MAC"))
                 (multiple-value-bind (r next reason)
                     (dds.durability::%parse-frame frame 0 (length frame) "T")
                   (declare (ignore r next))
                   (%check :mlc-v3-key-absent (eq reason :corrupt)
                           "a v3 frame with NO oracle (key absent) must be :corrupt (fail closed)"))
                 (multiple-value-bind (r next reason)
                     (dds.durability::%parse-frame frame 0 (length frame) "T" wrong-fn
                                                   (dds.durability::%chain-seed wrong-fn "T") nil)
                   (declare (ignore r next))
                   (%check :mlc-v3-wrong-key (eq reason :corrupt)
                           "a v3 frame verified under the WRONG key must be :corrupt (fail closed)"))))
             ;; (3) interior tamper — control opens clean, each tamper fails loud
             (let ((d (%tmp "ctl-d")) (k (%tmp "ctl-k")))
               (%put-n d k 3)
               (%check :mlc-control-clean
                       (let ((s (%mk d k)))
                         (dds.durability:store-open s)
                         (prog1 (= 3 (dds.durability:store-count s "T"))
                           (dds.durability:store-close s)))
                       "non-vacuous control: the untampered v3 log opens clean with 3 records")
               (let* ((raw (%read d k)) (len (length raw)))
                 (%check :mlc-frame-uniform (zerop (mod len 3))
                         "test setup: 3 equal-size v3 frames (uniform payload)")
                 (let ((fs (truncate len 3)))
                   ;; DELETE the interior frame 1
                   (let ((dd (%tmp "del-d")) (dk (%tmp "del-k")))
                     (%put-n dd dk 3)
                     (%write dd dk (concatenate '(simple-array (unsigned-byte 8) (*))
                                             (subseq (%read dd dk) 0 fs) (subseq (%read dd dk) (* 2 fs))))
                     (%check :mlc-tamper-delete (%open-errs-p dd dk)
                             "interior record DELETE must break the chain → store-open fails loud"))
                   ;; REORDER frames 0 and 1
                   (let ((dd (%tmp "reo-d")) (dk (%tmp "reo-k")))
                     (%put-n dd dk 3)
                     (let ((r (%read dd dk)))
                       (%write dd dk (concatenate '(simple-array (unsigned-byte 8) (*))
                                               (subseq r fs (* 2 fs)) (subseq r 0 fs)
                                               (subseq r (* 2 fs)))))
                     (%check :mlc-tamper-reorder (%open-errs-p dd dk)
                             "record REORDER must break the chain → store-open fails loud"))
                   ;; SUBSTITUTE frame 1's bytes — mutate a PAYLOAD byte (offset >= fs+35, PAST the
                   ;; header-CRC coverage [fs,fs+31) and the header-CRC field), then recompute BOTH the
                   ;; header CRC and the frame CRC (the disk adversary fixes every CRC). The ONLY gate
                   ;; left is the keyed MAC — proving the MAC (not a CRC) catches the substitution.
                   (let ((dd (%tmp "sub-d")) (dk (%tmp "sub-k")))
                     (%put-n dd dk 3)
                     (let* ((b (copy-seq (%read dd dk)))
                            (hdr-off (+ fs 31))          ; frame 1's header-CRC field
                            (crc-off (- (* 2 fs) 4)))    ; frame 1's frame-CRC field
                       (setf (aref b (+ fs 35)) (logxor (aref b (+ fs 35)) #xFF))
                       (dds.durability::%put-u32-le b hdr-off (dds.durability::%crc32 b fs hdr-off))
                       (dds.durability::%put-u32-le b crc-off (dds.durability::%crc32 b fs crc-off))
                       (%write dd dk b))
                     (%check :mlc-tamper-substitute (%open-errs-p dd dk)
                             "record SUBSTITUTION (BOTH CRCs recomputed) must fail the keyed MAC → store-open fails loud"))
                   ;; INSERT a forged (duplicated) frame mid-chain
                   (let ((dd (%tmp "ins-d")) (dk (%tmp "ins-k")))
                     (%put-n dd dk 3)
                     (let ((r (%read dd dk)))
                       (%write dd dk (concatenate '(simple-array (unsigned-byte 8) (*))
                                               (subseq r 0 fs) (subseq r 0 fs) (subseq r fs))))
                     (%check :mlc-tamper-insert (%open-errs-p dd dk)
                             "record INSERTION must break the chain → store-open fails loud"))
                   ;; DOWNGRADE (C1 — the core bypass regression): rewrite EVERY v3 frame to a
                   ;; keyless-VALID v2 frame (version byte->0x02, strip the 32-byte MAC, recompute the
                   ;; header CRC over [.,+31) AND the trailing frame CRC). The whole log is byte-valid
                   ;; v2 needing no key — but the store is chain-committed (anchor present), so the
                   ;; open MUST fail loud (a non-empty chain-required log with zero v3 frames), BEFORE
                   ;; any compaction could launder the tampered set into a fresh chain (ADR 0045 §3.2).
                   (let ((dd (%tmp "dg-d")) (dk (%tmp "dg-k")))
                     (%put-n dd dk 3)
                     (let* ((raw  (%read dd dk))
                            (plen (- fs 71))           ; v3 no-kh frame = 35 hdr + plen + 32 mac + 4 crc
                            (body (+ 35 plen))          ; v2 no-kh frame prefix = header + payload
                            (frames '()))
                       (dotimes (i 3)
                         (let* ((src (* i fs))
                                (v2  (make-array (+ body 4) :element-type '(unsigned-byte 8))))
                           (replace v2 raw :start1 0 :start2 src :end2 (+ src body))
                           (setf (aref v2 1) dds.durability::+frame-version-v2+)
                           (dds.durability::%put-u32-le v2 31 (dds.durability::%crc32 v2 0 31))
                           (dds.durability::%put-u32-le v2 body (dds.durability::%crc32 v2 0 body))
                           (push v2 frames)))
                       (%write dd dk (apply #'concatenate '(simple-array (unsigned-byte 8) (*))
                                         (nreverse frames))))
                     (%check :mlc-downgrade-fails-loud (%open-errs-p dd dk)
                             "a full v3->v2 keyless downgrade of a chain-committed log MUST fail the open (C1)"))
                   ;; migration guard (no false-REJECT): a legitimately mixed log — a v2 frame followed
                   ;; by the real v3 frames (a v3 TAIL proves the chain is active) — still opens.
                   (let ((dd (%tmp "mix-d")) (dk (%tmp "mix-k")))
                     (%put-n dd dk 3)
                     (let* ((v3log  (%read dd dk))
                            (v2rec  (dds.durability::make-durable-record
                                     :topic "T" :writer-guid g0 :sn 99 :key-hash nil :kind :data
                                     :payload (funcall pay 5)))
                            (v2frame (dds.durability::%frame-record-versioned
                                      v2rec dds.durability::+frame-version-v2+)))
                       (%write dd dk (concatenate '(simple-array (unsigned-byte 8) (*)) v2frame v3log)))
                     (%check :mlc-mixed-v3-tail-opens (not (%open-errs-p dd dk))
                             "a mixed v2-prefix + v3-tail log still opens (migration not false-rejected)")))))
             ;; (4) cross-restart / epoch boundary
             (let ((d (%tmp "xr-d")) (k (%tmp "xr-k")))
               ;; run1: epoch 1, sn 1..2
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (dotimes (i 2) (dds.durability:store-put s "T" g0 (1+ i) nil :data (funcall pay i)))
                 (dds.durability:store-close s))
               ;; run2: epoch 2, append sn 3..4
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (dotimes (i 2) (dds.durability:store-put s "T" g0 (+ 3 i) nil :data (funcall pay (+ 2 i))))
                 (dds.durability:store-close s))
               ;; run3: the whole chain across the epoch boundary verifies
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (%check :mlc-xr-count (= 4 (dds.durability:store-count s "T"))
                         (format nil "cross-restart: expected 4 records across the epoch boundary, got ~d"
                                 (dds.durability:store-count s "T")))
                 (dds.durability:store-close s))
               ;; tamper an epoch-1 frame's PAYLOAD (past header-CRC coverage) + recompute BOTH CRCs →
               ;; only the keyed MAC is left → chain break caught across the epoch boundary
               (let* ((raw (%read d k)) (fs (truncate (length raw) 4)) (b (copy-seq raw))
                      (hdr-off (+ fs 31)) (crc-off (- (* 2 fs) 4)))
                 (setf (aref b (+ fs 35)) (logxor (aref b (+ fs 35)) #xFF))
                 (dds.durability::%put-u32-le b hdr-off (dds.durability::%crc32 b fs hdr-off))
                 (dds.durability::%put-u32-le b crc-off (dds.durability::%crc32 b fs crc-off))
                 (%write d k b)
                 (%check :mlc-xr-tamper (%open-errs-p d k)
                         "tampering an epoch-1 frame (both CRCs fixed) is caught across the epoch boundary → fails loud")))
             ;; (5) key-absent / wrong-key fail-closed at store-open
             (let ((d (%tmp "ka-d")) (k (%tmp "ka-k")))
               (%put-n d k 3)
               (%check :mlc-key-absent-bare
                       (let ((s (dds.durability:make-file-store :dir d)))
                         (handler-case (progn (dds.durability:store-open s)
                                              (ignore-errors (dds.durability:store-close s)) nil)
                           (error () t)))
                       "a v3 chain store opened by a bare file store (no key) must fail closed")
               (let ((k2 (%tmp "ka-wrongk")))
                 (%check :mlc-wrong-key-store (%open-errs-p d k2)
                         "a v3 chain store opened with the WRONG key must fail closed")))
             ;; (6) honest torn tail STILL truncate-recovers (the anchor tolerates it); whole-frame tail
             ;; truncation is now DETECTED by the sealed high-water tail anchor (ADR 0045 §7.1 — was the
             ;; §7 residual, now CLOSED for the file tier).
             (let ((d (%tmp "tt-d")) (k (%tmp "tt-k")))
               (%put-n d k 3)                                            ; close seals N=3, M_3
               (let ((sz (length (%read d k))))
                 (dds.durability::%truncate-file (%tlog d k) (- sz 4)))    ; tear the last frame's CRC
               (%check :mlc-torn-recover
                       (let ((s (%mk d k)))
                         (dds.durability:store-open s)                   ; must NOT error (2 complete + a
                         (prog1 (= 2 (dds.durability:store-count s "T")) ; torn partial → :torn tolerated)
                           (dds.durability:store-close s)))              ; truncate-recover to 2, re-seal N=2
                       "honest torn tail must truncate-recover to 2 records (anchor tolerates a torn partial frame)")
               ;; FLIPPED (ADR 0045 §7.1): dropping a COMPLETE valid frame down to a clean-boundary prefix
               ;; (1 < the sealed high-water N=2) now CONTRADICTS the anchor → fail-closed at open.
               (let ((fs (truncate (length (%read d k)) 2)))
                 (dds.durability::%truncate-file (%tlog d k) fs)
                 (%check :mlc-tail-truncation-detected (%open-errs-p d k)
                         "malicious whole-frame tail truncation below the sealed high-water is DETECTED (fail-closed)")))
             ;; (7) multi-topic legacy coexistence (the review regression): a DORMANT legacy-v2 topic A
             ;; (written by a bare file store, no anchor) + a born-chained v3 topic B in ONE store must
             ;; reopen CLEAN — A is grandfathered (exempt), never false-rejected — while B still
             ;; chain-verifies and a downgrade of B (non-grandfathered) still fails loud (ADR 0045 §3.2).
             (let ((d (%tmp "mt-d")) (k (%tmp "mt-k")))
               ;; topic A: a legacy v2 log (bare file store ⇒ no key, no anchor, v2 frame)
               (let ((bare (dds.durability:make-file-store :dir d)))
                 (dds.durability:store-open bare)
                 (dds.durability:store-put bare "A" g0 1 nil :data (funcall pay 0))
                 (dds.durability:store-close bare))
               ;; epoch store: migration open (anchor absent), then B put mints anchor (gf = {A})
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (dotimes (i 2) (dds.durability:store-put s "B" g0 (1+ i) nil :data (funcall pay (1+ i))))
                 (dds.durability:store-close s))
               (%check :mlc-multitopic-legacy-opens (not (%open-errs-p d k))
                       "a dormant legacy-v2 topic A coexisting with a chained v3 topic B must reopen clean (no false-REJECT)")
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (let ((recs (dds.durability:store-get-range s "B")))
                   (%check :mlc-multitopic-b-verified
                           (and (= 2 (length recs))
                                (equalp (funcall pay 1) (dds.durability:durable-record-payload (first recs))))
                           "topic B chain-verifies + decrypts alongside the dormant legacy topic"))
                 (dds.durability:store-close s))
               ;; downgrade the born-chained topic B to keyless v2 (both CRCs fixed) → still fails loud
               (let* ((blog (merge-pathnames (make-pathname :directory '(:relative "topics")
                                                            :name (%enc-topic-tid d k "B") :type "log") d))
                      (raw  (with-open-file (fin blog :element-type '(unsigned-byte 8))
                              (let ((v (make-array (file-length fin) :element-type '(unsigned-byte 8))))
                                (read-sequence v fin) v)))
                      (fs   (truncate (length raw) 2))
                      (plen (- fs 71)) (body (+ 35 plen)) (frames '()))
                 (dotimes (i 2)
                   (let* ((src (* i fs)) (v2 (make-array (+ body 4) :element-type '(unsigned-byte 8))))
                     (replace v2 raw :start1 0 :start2 src :end2 (+ src body))
                     (setf (aref v2 1) dds.durability::+frame-version-v2+)
                     (dds.durability::%put-u32-le v2 31 (dds.durability::%crc32 v2 0 31))
                     (dds.durability::%put-u32-le v2 body (dds.durability::%crc32 v2 0 body))
                     (push v2 frames)))
                 (with-open-file (fout blog :direction :output :element-type '(unsigned-byte 8)
                                            :if-exists :supersede)
                   (write-sequence (apply #'concatenate '(simple-array (unsigned-byte 8) (*))
                                          (nreverse frames)) fout))
                 (%check :mlc-multitopic-b-downgrade-fails (%open-errs-p d k)
                         "downgrading the born-chained topic B to v2 fails the open even though legacy A is grandfathered (C1 held per-topic)")))
             ;; (8) map-less grandfather (the shared-enumerator lift-regression guard): a legacy-v2
             ;; file-store topic whose topics.map is LOST must STILL be grandfathered by its RAW tid
             ;; (the log filename). The grandfather set MUST key identically to the file store's
             ;; downgrade-check lookup (by raw tid) even in the map-less fallback, where a topic NAME
             ;; degrades to the raw hex tid and a %topic->id(tid) round-trip would double-encode and
             ;; never match — a false-REJECT of a degraded store (ADR 0045 §3.2).
             (let ((d (%tmp "ml-d")) (k (%tmp "ml-k")))
               (let ((bare (dds.durability:make-file-store :dir d)))
                 (dds.durability:store-open bare)
                 (dds.durability:store-put bare "A" g0 1 nil :data (funcall pay 0))
                 (dds.durability:store-close bare))
               ;; LOSE topics.map before the mint session (topic name falls back to the raw hex tid)
               (let ((mp (merge-pathnames (make-pathname :name "topics" :type "map") d)))
                 (when (probe-file mp) (delete-file mp)))
               ;; migration open + first v3 put on B mints the anchor; A must be grandfathered by raw tid
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (dotimes (i 2) (dds.durability:store-put s "B" g0 (1+ i) nil :data (funcall pay (1+ i))))
                 (dds.durability:store-close s))
               (%check :mlc-mapless-grandfather-opens (not (%open-errs-p d k))
                       "a legacy-v2 topic with a LOST topics.map still grandfathers by RAW tid → reopens clean (lift-regression guard)")))
        (dolist (d dirs)
          (when (uiop:directory-exists-p d)
            (ignore-errors (uiop:delete-directory-tree d :validate t)))))))
  t)

(defun* run-durability-tail-anchor-test ()
    (function () t)
  "WP-DURABILITY-TAIL-ANCHOR-FILE (ADR 0045 §7.1 + §9 + §2): the sealed high-water tail anchor closes the
   whole-tail-truncation / whole-topic-drop / whole-store-rollback residuals for the FILE tier. The anchor
   commits per-topic (N = v3-count, M_N = tail chain-MAC) + the topic-SET, MAC'd under the log-MAC key into
   a SEPARATE mutable D/logmac.tail, sealed at CLEAN CLOSE, verified at OPEN by PREFIX-CONTAINMENT.
   (1) CRASH-APPEND CLEAN (the load-bearing no-false-reject): seal N, append MORE frames without re-sealing
       (skip-seal debug flag = a crash before re-seal), reopen ⇒ CLEAN (a forward extension past the
       committed prefix — a naive current-tail==anchor-tail check would false-reject here).
   (2) WHOLE-TOPIC-DROP DETECTED: seal a 2-topic store, delete a whole topic log, reopen ⇒ fail-closed
       (the sealed topic is absent — count 0 < N).
   (3) ANCHOR-TAMPER DETECTED: flip a byte in logmac.tail's own MAC (CRC recomputed so only the keyed MAC
       is left), reopen ⇒ fail-closed (the anchor's own MAC mismatch).
   (4) WHOLE-STORE-ROLLBACK DETECTED (§2): advance the anchor to N, restore an OLDER (fewer-record) log
       snapshot, reopen ⇒ fail-closed (count < N).
   (5) NEVER-CLEANLY-CLOSED opens CLEAN (documented): a store whose close skipped the seal (crash before
       the first seal ⇒ no logmac.tail) reopens clean — the anchor only protects SEALED prefixes."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [durability-tail-anchor] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-durability-tail-anchor-test t)))
  (let ((g0   (make-array 16 :element-type '(unsigned-byte 8) :initial-element 5))
        (dirs '())
        (pay  (lambda (i)
                (let ((v (make-array 8 :element-type '(unsigned-byte 8))))
                  (dotimes (j 8 v) (setf (aref v j) (logand (+ (* i 16) j) #xFF)))))))
    (labels ((%tmp (tag)
               (let ((d (uiop:merge-pathnames*
                         (make-pathname :directory
                                        (list :relative (format nil "dds-ta-~a-~a-~a"
                                                                tag (get-universal-time)
                                                                (random 1000000))))
                         (uiop:temporary-directory))))
                 (push d dirs)
                 d))
             (%mk (d k)
               (dds.durability:make-encrypted-store
                (dds.durability:make-file-store :dir d)
                (dds.dare:make-file-key-provider :dir k)
                :epoch-dir d))
             (%tlog (d k topic)
               (merge-pathnames (make-pathname :directory '(:relative "topics")
                                               :name (%enc-topic-tid d k topic) :type "log")
                                d))
             (%read-bytes (path)
               (with-open-file (s path :element-type '(unsigned-byte 8))
                 (let ((v (make-array (file-length s) :element-type '(unsigned-byte 8))))
                   (read-sequence v s) v)))
             (%write-bytes (path bytes)
               (with-open-file (s path :direction :output :element-type '(unsigned-byte 8)
                                       :if-exists :supersede :if-does-not-exist :create)
                 (write-sequence bytes s)))
             (%put-topic (s topic base n)
               (dotimes (i n) (dds.durability:store-put s topic g0 (+ base i 1) nil :data (funcall pay (+ base i)))))
             (%put-n (d k n)
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (%put-topic s "T" 0 n)
                 (dds.durability:store-close s)))
             (%open-errs-p (d k)
               (let ((s (%mk d k)))
                 (handler-case (progn (dds.durability:store-open s)
                                      (ignore-errors (dds.durability:store-close s)) nil)
                   (error () t))))
             (%tail-path (d)
               (dds.durability::%logmac-tail-path (uiop:ensure-directory-pathname d))))
      (unwind-protect
           (progn
             ;; (1) CRASH-APPEND CLEAN — the no-false-reject crux
             (let ((d (%tmp "ca-d")) (k (%tmp "ca-k")))
               (%put-n d k 5)                                       ; session1: close seals N=5, M_5
               (let ((dds.durability::*durability-debug-skip-tail-seal* t))
                 (let ((s (%mk d k)))
                   (dds.durability:store-open s)                    ; verify N=5 vs 5-frame log → CLEAN
                   (%put-topic s "T" 5 3)                           ; append SN 6,7,8 (log now 8 frames)
                   (dds.durability:store-close s)))                 ; SKIP re-seal → anchor STAYS N=5 (stale)
               (%check :ta-crash-append-clean
                       (let ((s (%mk d k)))
                         (dds.durability:store-open s)              ; verify N=5 vs 8-frame log → forward extension
                         (prog1 (= 8 (dds.durability:store-count s "T"))
                           (dds.durability:store-close s)))
                       "crash-append: appending past the sealed high-water opens CLEAN (forward extension, NO false-reject)"))
             ;; (2) WHOLE-TOPIC-DROP DETECTED
             (let ((d (%tmp "wtd-d")) (k (%tmp "wtd-k")))
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (%put-topic s "A" 0 2)
                 (%put-topic s "B" 0 2)
                 (dds.durability:store-close s))                    ; seals {A→(2,·), B→(2,·)}
               (%check :ta-2topic-control
                       (not (%open-errs-p d k))
                       "non-vacuous control: the sealed 2-topic store reopens clean")
               (delete-file (%tlog d k "A"))                        ; drop the WHOLE topic-A log
               (%check :ta-whole-topic-drop-detected (%open-errs-p d k)
                       "whole-topic drop: a sealed topic absent at open is DETECTED (fail-closed)"))
             ;; (3) ANCHOR-TAMPER DETECTED — flip a byte in logmac.tail's own MAC, fix the CRC
             (let ((d (%tmp "at-d")) (k (%tmp "at-k")))
               (%put-n d k 3)
               (let* ((tp (%tail-path d))
                      (b  (%read-bytes tp))
                      (sz (length b))
                      (mac-byte (- sz 20)))                         ; a byte inside the anchor-mac field
               (setf (aref b mac-byte) (logxor (aref b mac-byte) #xFF))
               (dds.durability::%put-u32-le b (- sz 4) (dds.durability::%crc32 b 0 (- sz 4)))
               (%write-bytes tp b))
               (%check :ta-anchor-tamper-detected (%open-errs-p d k)
                       "anchor-tamper: flipping logmac.tail's MAC (CRC fixed) is DETECTED by the keyed MAC (fail-closed)"))
             ;; (4) WHOLE-STORE-ROLLBACK DETECTED — restore an older (fewer-record) log under the newer anchor
             (let ((d (%tmp "sr-d")) (k (%tmp "sr-k")))
               (%put-n d k 3)                                       ; session1: 3 frames, seal N=3
               (let ((old-log (%read-bytes (%tlog d k "T"))))       ; snapshot the 3-frame log
                 (let ((s (%mk d k)))
                   (dds.durability:store-open s)
                   (%put-topic s "T" 3 2)                           ; append SN 4,5 → log 5 frames
                   (dds.durability:store-close s))                  ; anchor advances to N=5
                 (%write-bytes (%tlog d k "T") old-log))            ; ROLL BACK the log to the 3-frame snapshot
               (%check :ta-whole-store-rollback-detected (%open-errs-p d k)
                       "whole-store rollback: an older (fewer-record) log under the newer anchor (count<N) is DETECTED"))
             ;; (5) NEVER-CLEANLY-CLOSED opens CLEAN (documented — only running-chain protection)
             (let ((d (%tmp "nc-d")) (k (%tmp "nc-k")))
               (let ((dds.durability::*durability-debug-skip-tail-seal* t))
                 (let ((s (%mk d k)))
                   (dds.durability:store-open s)
                   (%put-topic s "T" 0 3)
                   (dds.durability:store-close s)))                 ; skip-seal ⇒ no logmac.tail ever written
               (%check :ta-never-closed-opens-clean
                       (and (not (probe-file (%tail-path d)))
                            (let ((s (%mk d k)))
                              (dds.durability:store-open s)
                              (prog1 (= 3 (dds.durability:store-count s "T"))
                                (dds.durability:store-close s))))
                       "never-cleanly-closed (no logmac.tail) opens clean — the anchor only protects sealed prefixes"))
             ;; (6) F1 REGRESSION — an AUTHORIZED reclaim-shrink of a KEEP_LAST encrypted store followed
             ;; by a crash (no clean re-seal) must reopen CLEAN, not fail-closed (BRICK). The seal counts
             ;; PHYSICAL v3 frames; the KEEP_LAST physical-reclaim path (%reclaim-deleted-topic ->
             ;; %rewrite-topic-log) atomically shrinks the on-disk log to fewer re-seeded frames mid-session;
             ;; seal-on-close-only would leave the anchor committing the pre-reclaim N. The invalidate-at-open
             ;; fix (delete logmac.tail after verify, before the sweep/puts mutate the log) makes it clean.
             (let ((d (%tmp "f1-d")) (k (%tmp "f1-k"))
                   (kh (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xAB)))
               (let ((dds.durability::*compaction-superseded-threshold* 5))
                 ;; session A: KEEP_LAST 1, 5 superseding keyed puts (pending-delete 4 < threshold 5 ⇒ NO
                 ;; reclaim); the physical log keeps all 5 frames; clean close seals N=5.
                 (let ((s (%mk d k)))
                   (dds.durability:store-open s :keep-last 1)
                   (dotimes (i 5) (dds.durability:store-put s "T" g0 (1+ i) kh :data (funcall pay i)))
                   (dds.durability:store-close s))
                 (let ((size-a (with-open-file (fin (%tlog d k "T") :element-type '(unsigned-byte 8))
                                 (file-length fin))))
                   ;; session B: reopen KEEP_LAST 1 (verify 5==5 clean, then INVALIDATE), keep putting so
                   ;; pending-delete crosses the threshold ⇒ %reclaim-deleted-topic COMMITS an on-disk shrink;
                   ;; then "crash" (skip-seal ⇒ no re-seal). The at-rest log is now SHORTER than the sealed N=5.
                   (let ((dds.durability::*durability-debug-skip-tail-seal* t))
                     (let ((s (%mk d k)))
                       (dds.durability:store-open s :keep-last 1)
                       (dotimes (i 2) (dds.durability:store-put s "T" g0 (+ 6 i) kh :data (funcall pay (+ 6 i))))
                       (dds.durability:store-close s)))
                   (let ((size-b (with-open-file (fin (%tlog d k "T") :element-type '(unsigned-byte 8))
                                   (file-length fin))))
                     (%check :ta-f1-reclaim-shrank (< size-b size-a)
                             (format nil "F1 setup non-vacuous: the authorized reclaim must SHRINK the physical log below the sealed N (~d -> ~d bytes)"
                                     size-a size-b))
                     ;; session C: reopen KEEP_LAST 1 -> must OPEN CLEAN (the anchor was invalidated at B's
                     ;; open; skip-seal ⇒ never re-sealed ⇒ absent), NOT fail-closed. Before the fix this
                     ;; reclaim-shrink+crash BRICKED the store (stale anchor N=5 vs a shorter log).
                     (%check :ta-f1-reclaim-crash-opens-clean
                             (let ((s (%mk d k)))
                               (handler-case (progn (dds.durability:store-open s :keep-last 1)
                                                    (ignore-errors (dds.durability:store-close s)) t)
                                 (error () nil)))
                             "F1: an authorized reclaim-shrink + crash reopens CLEAN (no false-reject / brick)"))))))
        (dolist (d dirs)
          (when (uiop:directory-exists-p d)
            (ignore-errors (uiop:delete-directory-tree d :validate t)))))))
  t)

(defun* run-durability-sqlite-mac-chain-test ()
    (function () t)
  "WP-SQLITE-MAC-CHAIN (ADR 0049/0045): the SQLite backend at tamper-evidence PARITY with the file
   store's v3 keyed MAC chain, tampered via DIRECT SQL on the DB (a raw sqlite:connect UPDATE/DELETE).
   (1) v3 round-trip: a MAC-chained SQLite store writes rows with MACs and reopens CLEAN, byte-exact.
   (2) interior tamper: UPDATE payload / UPDATE mac / DELETE a row / REORDER (chain_seq swap) each →
       store-open fails loud; the untampered control opens clean (non-vacuous).
   (3) downgrade (required): NULL out mac on all rows of a non-grandfathered topic → open fails loud.
   (4) NO-FALSE-REJECT (the critical case): a KEEP_LAST MAC-chained store compacts on reopen and the
       chain is RECOMPUTED over the survivors, so it reopens clean repeatedly + across epoch boundaries.
   (5) grandfather: a legacy-v2 SQLite topic (bare store, NULL mac) coexists with a born-chained topic,
       reopens clean (legacy grandfathered), and downgrading the chained topic still fails loud.
   (6) NIL-oracle regression: a bare make-sqlite-store round-trips unchanged (NULL mac column)."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [durability-sqlite-mac-chain] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-durability-sqlite-mac-chain-test t)))
  (let ((g0   (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
        (kh0  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 3))
        (dirs '())
        (pay  (lambda (i)
                (let ((v (make-array 8 :element-type '(unsigned-byte 8))))
                  (dotimes (j 8 v) (setf (aref v j) (logand (+ (* i 16) j) #xFF)))))))
    (labels ((%tmp (tag)
               (let ((d (uiop:merge-pathnames*
                         (make-pathname :directory
                                        (list :relative (format nil "dds-sqmac-~a-~a-~a"
                                                                tag (get-universal-time)
                                                                (random 1000000))))
                         (uiop:temporary-directory))))
                 (push d dirs)
                 d))
             (%dbpath (d) (uiop:merge-pathnames* "durability.sqlite3" d))
             (%mk (d k &optional (hk :keep-all) (hd 1))
               (dds.durability:make-encrypted-store
                (dds.durability:make-sqlite-store :path (%dbpath d) :history-kind hk :history-depth hd)
                (dds.dare:make-file-key-provider :dir k)
                :epoch-dir d))
             (%put-n (d k n &optional kh (hk :keep-all) (hd 1))
               (let ((s (%mk d k hk hd)))
                 (dds.durability:store-open s)
                 (dotimes (i n) (dds.durability:store-put s "T" g0 (1+ i) kh :data (funcall pay i)))
                 (dds.durability:store-close s)))
             (%open-errs-p (d k &optional (hk :keep-all) (hd 1))
               (let ((s (%mk d k hk hd)))
                 (handler-case (progn (dds.durability:store-open s hk hd)
                                      (ignore-errors (dds.durability:store-close s)) nil)
                   (error () t))))
             (%raw (d thunk)
               (let ((db (sqlite:connect (namestring (%dbpath d)))))
                 (unwind-protect (funcall thunk db) (sqlite:disconnect db)))))
      (unwind-protect
           (progn
             ;; (1) v3 round-trip
             (let ((d (%tmp "rt-d")) (k (%tmp "rt-k")))
               (%put-n d k 4)
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (let ((recs (dds.durability:store-get-range s "T")))
                   (%check :sqmac-rt-count (= 4 (length recs))
                           (format nil "v3 round-trip: expected 4 records, got ~d" (length recs)))
                   (%check :sqmac-rt-bytes
                           (loop for r in recs for i from 0
                                 always (equalp (dds.durability:durable-record-payload r) (funcall pay i)))
                           "v3 round-trip: all payloads byte-exact after reopen+chain-verify"))
                 (dds.durability:store-close s)))
             ;; (2) interior tamper — control clean, each SQL tamper fails loud
             (let ((d (%tmp "ctl-d")) (k (%tmp "ctl-k")))
               (%put-n d k 3)
               (%check :sqmac-control-clean
                       (let ((s (%mk d k)))
                         (dds.durability:store-open s)
                         (prog1 (= 3 (dds.durability:store-count s "T"))
                           (dds.durability:store-close s)))
                       "non-vacuous control: the untampered chained SQLite log opens clean with 3 rows"))
             ;; UPDATE an interior payload (row chain_seq=1) → MAC over the row mismatches
             (let ((d (%tmp "upl-d")) (k (%tmp "upl-k")))
               (%put-n d k 3)
               (%raw d (lambda (db)
                         (sqlite:execute-non-query
                          db "UPDATE record SET payload=? WHERE topic=? AND chain_seq=?"
                          (make-array 8 :element-type '(unsigned-byte 8) :initial-element #xEE) (%enc-topic-hash d k "T") 1)))
               (%check :sqmac-tamper-payload (%open-errs-p d k)
                       "interior payload UPDATE via direct SQL must fail the keyed MAC → store-open fails loud"))
             ;; UPDATE an interior mac (row chain_seq=1) → stored mac ≠ recomputed
             (let ((d (%tmp "umac-d")) (k (%tmp "umac-k")))
               (%put-n d k 3)
               (%raw d (lambda (db)
                         (sqlite:execute-non-query
                          db "UPDATE record SET mac=? WHERE topic=? AND chain_seq=?"
                          (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0) (%enc-topic-hash d k "T") 1)))
               (%check :sqmac-tamper-mac (%open-errs-p d k)
                       "interior mac UPDATE via direct SQL must fail verification → store-open fails loud"))
             ;; DELETE an interior row (chain_seq=1) → chain break over the survivors
             (let ((d (%tmp "del-d")) (k (%tmp "del-k")))
               (%put-n d k 3)
               (%raw d (lambda (db)
                         (sqlite:execute-non-query
                          db "DELETE FROM record WHERE topic=? AND chain_seq=?" (%enc-topic-hash d k "T") 1)))
               (%check :sqmac-tamper-delete (%open-errs-p d k)
                       "interior row DELETE via direct SQL must break the chain → store-open fails loud"))
             ;; REORDER rows 0 and 1 by swapping their chain_seq → running chain mismatches
             (let ((d (%tmp "reo-d")) (k (%tmp "reo-k")))
               (%put-n d k 3)
               (%raw d (lambda (db)
                         (sqlite:execute-non-query db "UPDATE record SET chain_seq=999 WHERE topic=? AND chain_seq=0" (%enc-topic-hash d k "T"))
                         (sqlite:execute-non-query db "UPDATE record SET chain_seq=0 WHERE topic=? AND chain_seq=1" (%enc-topic-hash d k "T"))
                         (sqlite:execute-non-query db "UPDATE record SET chain_seq=1 WHERE topic=? AND chain_seq=999" (%enc-topic-hash d k "T"))))
               (%check :sqmac-tamper-reorder (%open-errs-p d k)
                       "row REORDER (chain_seq swap) via direct SQL must break the chain → store-open fails loud"))
             ;; (3) downgrade (required): NULL every mac of a non-grandfathered topic
             (let ((d (%tmp "dg-d")) (k (%tmp "dg-k")))
               (%put-n d k 3)
               (%raw d (lambda (db)
                         (sqlite:execute-non-query db "UPDATE record SET mac=NULL WHERE topic=?" (%enc-topic-hash d k "T"))))
               (%check :sqmac-downgrade-fails (%open-errs-p d k)
                       "a full v3->keyless downgrade (mac NULL on a non-grandfathered topic) fails the open"))
             ;; (4) NO-FALSE-REJECT — KEEP_LAST store compacts+recomputes; reopens clean repeatedly
             (let ((d (%tmp "nfr-d")) (k (%tmp "nfr-k")))
               (let ((s (%mk d k :keep-last 1)))
                 (dds.durability:store-open s)
                 (dotimes (i 4) (dds.durability:store-put s "T" g0 (1+ i) kh0 :data (funcall pay i)))
                 (dds.durability:store-close s))
               (%check :sqmac-nfr-open1 (not (%open-errs-p d k :keep-last 1))
                       "KEEP_LAST chained store reopens clean after compaction (#1)")
               (%check :sqmac-nfr-open2 (not (%open-errs-p d k :keep-last 1))
                       "KEEP_LAST chained store reopens clean AGAIN (#2 — chain-recompute-on-compaction holds)")
               (let ((s (%mk d k :keep-last 1)))
                 (dds.durability:store-open s :keep-last 1)
                 (let ((recs (dds.durability:store-get-range s "T")))
                   (%check :sqmac-nfr-count (= 1 (length recs))
                           "KEEP_LAST kept exactly depth=1 survivor after repeated reopen")
                   (%check :sqmac-nfr-payload (and recs (equalp (funcall pay 3)
                                                                (dds.durability:durable-record-payload (first recs))))
                           "survivor payload decrypts byte-exact post-recompute"))
                 (dds.durability:store-close s)))
             ;; clean chain across an epoch boundary reopens clean
             (let ((d (%tmp "xr-d")) (k (%tmp "xr-k")))
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (dotimes (i 2) (dds.durability:store-put s "T" g0 (1+ i) nil :data (funcall pay i)))
                 (dds.durability:store-close s))
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (dotimes (i 2) (dds.durability:store-put s "T" g0 (+ 3 i) nil :data (funcall pay (+ 2 i))))
                 (dds.durability:store-close s))
               (%check :sqmac-xr-clean (not (%open-errs-p d k))
                       "clean chain across the epoch boundary reopens clean (no false-reject)")
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (%check :sqmac-xr-count (= 4 (dds.durability:store-count s "T"))
                         "4 records across the epoch boundary")
                 (dds.durability:store-close s)))
             ;; (5) grandfather: legacy-v2 topic A (bare store) + born-chained topic B
             (let ((d (%tmp "gf-d")) (k (%tmp "gf-k")))
               (let ((bare (dds.durability:make-sqlite-store :path (%dbpath d))))
                 (dds.durability:store-open bare)
                 (dds.durability:store-put bare "A" g0 1 nil :data (funcall pay 0))
                 (dds.durability:store-close bare))
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (dotimes (i 2) (dds.durability:store-put s "B" g0 (1+ i) nil :data (funcall pay (1+ i))))
                 (dds.durability:store-close s))
               (%check :sqmac-gf-opens (not (%open-errs-p d k))
                       "a legacy-v2 topic A grandfathered, coexists with chained B, reopens clean (no false-REJECT)")
               (let ((s (%mk d k)))
                 (dds.durability:store-open s)
                 (%check :sqmac-gf-b-verified (= 2 (length (dds.durability:store-get-range s "B")))
                         "born-chained topic B chain-verifies + decrypts alongside the dormant legacy topic A")
                 (dds.durability:store-close s))
               (%raw d (lambda (db)
                         (sqlite:execute-non-query db "UPDATE record SET mac=NULL WHERE topic=?" (%enc-topic-hash d k "B"))))
               (%check :sqmac-gf-b-downgrade (%open-errs-p d k)
                       "downgrading born-chained B fails the open even though legacy A is grandfathered"))
             ;; (6) NIL-oracle regression: bare store round-trips, mac column stays NULL
             (let ((d (%tmp "nil-d")))
               (let ((s (dds.durability:make-sqlite-store :path (%dbpath d))))
                 (dds.durability:store-open s)
                 (dds.durability:store-put s "T" g0 1 nil :data (funcall pay 0))
                 (dds.durability:store-put s "T" g0 2 nil :data (funcall pay 1))
                 (dds.durability:store-close s))
               (let ((s (dds.durability:make-sqlite-store :path (%dbpath d))))
                 (dds.durability:store-open s)
                 (%check :sqmac-nil-count (= 2 (dds.durability:store-count s "T"))
                         "NIL-oracle bare SQLite store round-trips unchanged")
                 (let ((recs (dds.durability:store-get-range s "T")))
                   (%check :sqmac-nil-payload (equalp (funcall pay 0)
                                                      (dds.durability:durable-record-payload (first recs)))
                           "NIL-oracle bare store payload byte-exact (no MAC layer)"))
                 (dds.durability:store-close s))
               (%raw d (lambda (db)
                         (%check :sqmac-nil-null-mac
                                 (null (sqlite:execute-single db "SELECT mac FROM record LIMIT 1"))
                                 "NIL-oracle store writes a NULL mac column (byte-behaviorally unchanged)")))))
        (dolist (d dirs)
          (when (uiop:directory-exists-p d)
            (ignore-errors (uiop:delete-directory-tree d :validate t)))))))
  t)

;;; --- SQLite online per-instance KEEP_LAST eviction (WP-DURABILITY-COMPACTION-SQLITE, Sliver 1) ---
;;; A continuously-open KEEP_LAST SQLite store must evict superseded :data rows AT PUT TIME (no
;;; close/open cycle), mirroring the memory store's %mem-evict-instance (ADR 0029, ADR 0049 §7).
;;; RED pre-Sliver-1: puts INSERT-only, on-disk row count grows to N (only on-open compaction).

(defun* run-durability-sqlite-keeplast-online-test ()
    (function () t)
  "Online per-instance KEEP_LAST eviction in the SQLite store (ADR 0049 §7, DDS 1.4 §2.2.3.5):
   (1) BOUNDED GROWTH — write N=6 :data to one instance WITHOUT closing under :keep-last 2; the on-disk
       row count converges to D=2 (the newest, SN 5+6) — the RED pre-Sliver-1 is 6 (INSERT-only).
   (2) NO DATA LOSS — the surviving D are the newest by SN, byte-exact.
   (3) two instances converge to D INDEPENDENTLY.
   (4) NIL-key-hash instance is NEVER online-evicted (keyless stream).
   (5) lifecycle (:dispose/:unregister) rows are never depth-evicted.
   (6) KEEP_ALL does NO online eviction (all N survive).
   (7) never-exceeds-D is unchanged (no eviction fires)."
  (let* ((g0   (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (kh1  (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xB1))
         (kh2  (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xC2))
         (p    (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b)))
         (dirs '()))
    (labels ((%dbp (tag) (let ((d (%sqlite-tmp-db-path tag)))
                           (push (uiop:pathname-directory-pathname d) dirs) d)))
      (unwind-protect
           (progn
             ;; (1)+(2) bounded growth to D WITHOUT reopen; survivors are newest D byte-exact
             (let ((s (dds.durability:make-sqlite-store :path (%dbp "kl-bnd"))))
               (dds.durability:store-open s :keep-last 2)
               (dotimes (i 6)
                 (dds.durability:store-put s "T" g0 (1+ i) kh1 :data (funcall p (list (1+ i)))))
               (%check :sqkl-bounded-online (= 2 (dds.durability:store-count s "T"))
                       (format nil "online KEEP_LAST 2: on-disk count must converge to 2 without reopen, got ~d"
                               (dds.durability:store-count s "T")))
               (let* ((recs (dds.durability:store-get-range s "T"))
                      (sns  (sort (mapcar #'dds.durability:durable-record-sn recs) #'<)))
                 (%check :sqkl-newest-survive (equal '(5 6) sns)
                         (format nil "online KEEP_LAST 2: survivors must be newest SNs (5 6), got ~s" sns))
                 (%check :sqkl-payload-exact
                         (equalp (funcall p '(6))
                                 (dds.durability:durable-record-payload
                                  (find 6 recs :key #'dds.durability:durable-record-sn)))
                         "surviving newest payload byte-exact"))
               (dds.durability:store-close s))
             ;; (3) two instances converge to D independently (continuously open)
             (let ((s (dds.durability:make-sqlite-store :path (%dbp "kl-2inst"))))
               (dds.durability:store-open s :keep-last 2)
               (dotimes (i 4) (dds.durability:store-put s "T" g0 (1+ i) kh1 :data (funcall p (list (1+ i)))))
               (dotimes (i 4) (dds.durability:store-put s "T" g0 (+ 10 i) kh2 :data (funcall p (list (+ 10 i)))))
               (let* ((recs (dds.durability:store-get-range s "T"))
                      (k1 (count kh1 recs :key #'dds.durability:durable-record-key-hash :test #'equalp))
                      (k2 (count kh2 recs :key #'dds.durability:durable-record-key-hash :test #'equalp)))
                 (%check :sqkl-indep (and (= 2 k1) (= 2 k2))
                         (format nil "two instances each converge to D=2 independently, got kh1=~d kh2=~d" k1 k2)))
               (dds.durability:store-close s))
             ;; (4) NIL-key-hash stream is never online-evicted
             (let ((s (dds.durability:make-sqlite-store :path (%dbp "kl-nil"))))
               (dds.durability:store-open s :keep-last 2)
               (dotimes (i 4) (dds.durability:store-put s "T" g0 (1+ i) nil :data (funcall p (list (1+ i)))))
               (%check :sqkl-nil-kept (= 4 (dds.durability:store-count s "T"))
                       (format nil "NIL-key-hash stream never online-evicted, expected 4, got ~d"
                               (dds.durability:store-count s "T")))
               (dds.durability:store-close s))
             ;; (5) lifecycle rows are never depth-evicted (kept alongside the D newest :data)
             (let ((s (dds.durability:make-sqlite-store :path (%dbp "kl-life"))))
               (dds.durability:store-open s :keep-last 1)
               (dotimes (i 3) (dds.durability:store-put s "T" g0 (1+ i) kh1 :data (funcall p (list (1+ i)))))
               (dds.durability:store-put s "T" g0 100 kh1 :dispose (funcall p '(9)))
               (let* ((recs (dds.durability:store-get-range s "T"))
                      (ndata (count :data recs :key #'dds.durability:durable-record-kind))
                      (ndisp (count :dispose recs :key #'dds.durability:durable-record-kind)))
                 (%check :sqkl-life (and (= 1 ndata) (= 1 ndisp))
                         (format nil "KEEP_LAST 1 keeps 1 :data + the :dispose lifecycle row, got data=~d dispose=~d"
                                 ndata ndisp)))
               (dds.durability:store-close s))
             ;; (6) KEEP_ALL does NO online eviction
             (let ((s (dds.durability:make-sqlite-store :path (%dbp "kl-all"))))
               (dds.durability:store-open s :keep-all)
               (dotimes (i 5) (dds.durability:store-put s "T" g0 (1+ i) kh1 :data (funcall p (list (1+ i)))))
               (%check :sqkl-keepall (= 5 (dds.durability:store-count s "T"))
                       (format nil "KEEP_ALL: no online eviction, expected 5, got ~d"
                               (dds.durability:store-count s "T")))
               (dds.durability:store-close s))
             ;; (7) never-exceeds-D: exactly D puts -> no eviction fires, all D present
             (let ((s (dds.durability:make-sqlite-store :path (%dbp "kl-under"))))
               (dds.durability:store-open s :keep-last 3)
               (dotimes (i 3) (dds.durability:store-put s "T" g0 (1+ i) kh1 :data (funcall p (list (1+ i)))))
               (%check :sqkl-under (= 3 (dds.durability:store-count s "T"))
                       (format nil "never-exceeds-D unchanged, expected 3, got ~d"
                               (dds.durability:store-count s "T")))
               (dds.durability:store-close s)))
        (dolist (d dirs)
          (when (uiop:directory-exists-p d)
            (ignore-errors (uiop:delete-directory-tree d :validate t)))))
      t)))

;;; --- SQLite online eviction preserves the MAC chain (WP-DURABILITY-COMPACTION-SQLITE, Sliver 1) ---
;;; THE load-bearing correctness test: an online DELETE that does NOT re-MAC leaves the surviving rows
;;; carrying macs chained over deleted predecessors -> a CLEAN store FALSE-REJECTS on the next open.
;;; A deterministic pure-Lisp MAC oracle (no OpenSSL) drives the exact chain machinery, so this runs on
;;; both impls unconditionally. After online eviction the store must reopen clean + return the newest D.

(defun* run-durability-sqlite-online-chain-test ()
    (function () t)
  "Online eviction re-MACs the survivors (ADR 0045; ADR 0049 §7): a KEEP_LAST MAC-chained SQLite store,
   continuously open, evicts on put AND recomputes the surviving chain, so a fresh store reopening the
   same DB VERIFIES clean (no false-reject) and get-range returns the newest D byte-exact. Without the
   re-MAC the reopen's verify would fail-closed (proving the recompute is load-bearing)."
  (let* ((g0    (make-array 16 :element-type '(unsigned-byte 8) :initial-element 5))
         (kh1   (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xD3))
         (p     (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b)))
         ;; deterministic 32-byte mock MAC oracle: folds every input byte (incl. the prev-mac prefix)
         ;; so any chain-order change alters the output — catches a missing re-MAC exactly like HMAC.
         (oracle (lambda (data)
                   (let ((out (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11)))
                     (loop for b across data for i from 0
                           do (setf (aref out (mod i 32))
                                    (logand (+ (aref out (mod i 32)) b i 1) #xFF)))
                     out)))
         (db-path (%sqlite-tmp-db-path "kl-chain"))
         (dir     (uiop:pathname-directory-pathname db-path)))
    (unwind-protect
         (progn
           ;; continuously-open chained KEEP_LAST 2 store: 6 puts to one instance -> online evict+recompute
           (let ((s (dds.durability:make-sqlite-store :path db-path)))
             (dds.durability::store-set-chain-mac-fn s oracle)
             (dds.durability:store-open s :keep-last 2)
             (dotimes (i 6)
               (dds.durability:store-put s "T" g0 (1+ i) kh1 :data (funcall p (list (1+ i)))))
             (%check :sqchain-online-bounded (= 2 (dds.durability:store-count s "T"))
                     (format nil "chained online KEEP_LAST 2: count converges to 2, got ~d"
                             (dds.durability:store-count s "T")))
             (dds.durability:store-close s))
           ;; REOPEN a fresh store on the same DB with the same oracle: verify-on-open must NOT reject
           (let ((s2 (dds.durability:make-sqlite-store :path db-path))
                 (opened-clean nil))
             (dds.durability::store-set-chain-mac-fn s2 oracle)
             (setf opened-clean
                   (handler-case (progn (dds.durability:store-open s2 :keep-last 2) t)
                     (error (c) (declare (ignore c)) nil)))
             (%check :sqchain-reopen-clean opened-clean
                     "online-evicted chained store REOPENS CLEAN — survivors were re-MAC'd (no false-reject)")
             (when opened-clean
               (let* ((recs (dds.durability:store-get-range s2 "T"))
                      (sns  (sort (mapcar #'dds.durability:durable-record-sn recs) #'<)))
                 (%check :sqchain-reopen-count (= 2 (length recs))
                         (format nil "reopen: exactly D=2 survivors, got ~d" (length recs)))
                 (%check :sqchain-reopen-sns (equal '(5 6) sns)
                         (format nil "reopen: survivors are newest SNs (5 6), got ~s" sns))
                 (%check :sqchain-reopen-payload
                         (equalp (funcall p '(5))
                                 (dds.durability:durable-record-payload
                                  (find 5 recs :key #'dds.durability:durable-record-sn)))
                         "reopen: survivor payload byte-exact post-recompute")))
             (ignore-errors (dds.durability:store-close s2))))
      (when (uiop:directory-exists-p dir)
        (ignore-errors (uiop:delete-directory-tree dir :validate t)))))
  t)

;;; --- SQLite compacting DELETE + re-MAC crash-consistency (WP-DURABILITY-COMPACTION-SQLITE review) ---
;;; The compacting DELETE(s) and the survivor chain re-MAC must commit ATOMICALLY: a crash between them
;;; leaves survivors chained over a deleted row -> a CLEAN store false-rejects on the next open (worst
;;; class). Both sites (on-open %compact-on-open + online :put evict) wrap them in one sqlite transaction
;;; so a mid-op failure rolls the DELETE back. *durability-debug-compact-fault* signals after the DELETE
;;; and before the re-MAC, inside the txn, to exercise the rollback path.

(defun* run-durability-sqlite-crash-consistency-test ()
    (function () t)
  "Crash-consistency of the SQLite compacting DELETE + chain re-MAC (ADR 0049 §10): the DELETE(s) and
   the survivor re-MAC commit in ONE transaction at BOTH the on-open and online-evict sites, so a crash
   between them rolls the DELETE back and a clean store never false-rejects on reopen.
   (A) ON-OPEN pass-1 settled compaction (production-reachable — the 3c encrypted tier opens the inner
       store :keep-all, but pass-1 dispose/unregister compaction + re-MAC still run): fault DURING the
       on-open compaction -> store-open signals -> a fresh reopen VERIFIES clean (DELETE rolled back) and
       the recovered compaction keeps exactly the live instance.
   (B) ONLINE evict-on-put: fault DURING a superseding put -> store-put signals -> a fresh reopen VERIFIES
       clean and KEEP_LAST compaction on that open yields the newest depth D."
  (let* ((g0     (make-array 16 :element-type '(unsigned-byte 8) :initial-element 9))
         (khs    (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xE1)) ; settled instance
         (khl    (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xE2)) ; live instance
         (p      (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b)))
         (oracle (lambda (data)
                   (let ((out (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22)))
                     (loop for b across data for i from 0
                           do (setf (aref out (mod i 32)) (logand (+ (aref out (mod i 32)) b i 1) #xFF)))
                     out)))
         (dirs   '()))
    (labels ((%dbp (tag) (let ((d (%sqlite-tmp-db-path tag)))
                           (push (uiop:pathname-directory-pathname d) dirs) d))
             (%mk (path) (let ((s (dds.durability:make-sqlite-store :path path)))
                           (dds.durability::store-set-chain-mac-fn s oracle) s))
             (%open-errs-p (path hk hd)
               (let ((s (%mk path)))
                 (prog1 (handler-case (progn (dds.durability:store-open s hk hd) nil) (error () t))
                   (ignore-errors (dds.durability:store-close s))))))
      (unwind-protect
           (progn
             ;; --- (A) on-open pass-1 settled compaction crash ---
             (let ((path (%dbp "crash-open")))
               ;; session 1: a settled instance (khs: data+dispose+unregister) + a live one (khl: data)
               (let ((s (%mk path)))
                 (dds.durability:store-open s :keep-all)
                 (dds.durability:store-put s "T" g0 1 khs :data (funcall p '(1)))
                 (dds.durability:store-put s "T" g0 2 khs :dispose (funcall p '(2)))
                 (dds.durability:store-put s "T" g0 3 khs :unregister (funcall p '(3)))
                 (dds.durability:store-put s "T" g0 4 khl :data (funcall p '(4)))
                 (dds.durability:store-close s))
               ;; session 2: fault DURING on-open compaction -> store-open signals, DELETE rolled back
               (let ((s (%mk path)) (errored nil))
                 (let ((dds.durability::*durability-debug-compact-fault* t))
                   (setf errored (handler-case (progn (dds.durability:store-open s :keep-all) nil)
                                   (error () t))))
                 (ignore-errors (dds.durability:store-close s))
                 (%check :sqcc-open-faulted errored
                         "on-open compaction fault must propagate (store-open signals)"))
               ;; session 3: NO fault -> reopen CLEAN (rollback preserved the chain) + recovered survivor
               (let ((s (%mk path)))
                 (%check :sqcc-open-recovers
                         (handler-case (progn (dds.durability:store-open s :keep-all) t) (error () nil))
                         "after a crash mid-compaction the store reopens CLEAN (txn rolled the DELETE back — no false-reject)")
                 (let ((recs (dds.durability:store-get-range s "T")))
                   (%check :sqcc-open-live
                           (and (= 1 (length recs))
                                (equalp khl (dds.durability:durable-record-key-hash (first recs)))
                                (equalp (funcall p '(4)) (dds.durability:durable-record-payload (first recs))))
                           (format nil "post-recovery compaction keeps exactly the live instance, got ~d recs" (length recs))))
                 (dds.durability:store-close s)))
             ;; --- (B) online evict-on-put crash ---
             (let ((path (%dbp "crash-online")))
               (let ((s (%mk path)))
                 (dds.durability:store-open s :keep-last 2)
                 (dds.durability:store-put s "T" g0 1 khl :data (funcall p '(1)))
                 (dds.durability:store-put s "T" g0 2 khl :data (funcall p '(2)))
                 ;; the 3rd put supersedes -> online evict fires; inject the fault mid-evict
                 (let ((dds.durability::*durability-debug-compact-fault* t))
                   (%check :sqcc-online-faulted
                           (handler-case (progn (dds.durability:store-put s "T" g0 3 khl :data (funcall p '(3))) nil)
                             (error () t))
                           "online evict fault must propagate (store-put signals)"))
                 (ignore-errors (dds.durability:store-close s)))
               ;; reopen NO fault: chain intact (evict rolled back; the sn3 INSERT committed) -> clean,
               ;; then KEEP_LAST compaction on open yields the newest depth D=2 (sn2, sn3)
               (%check :sqcc-online-recovers (not (%open-errs-p path :keep-last 2))
                       "after a crash mid-online-evict the store reopens CLEAN (no false-reject)")
               (let ((s (%mk path)))
                 (dds.durability:store-open s :keep-last 2)
                 (let* ((recs (dds.durability:store-get-range s "T"))
                        (sns  (sort (mapcar #'dds.durability:durable-record-sn recs) #'<)))
                   (%check :sqcc-online-depth (equal '(2 3) sns)
                           (format nil "post-recovery KEEP_LAST 2 keeps newest D=2 (2 3), got ~s" sns)))
                 (dds.durability:store-close s))))
        (dolist (d dirs)
          (when (uiop:directory-exists-p d)
            (ignore-errors (uiop:delete-directory-tree d :validate t)))))
      t)))

;;; --- Additive store-delete vtable slot (WP-DURABILITY-ENCRECLAIM-SQLITE, Sliver 3a) ---
;;; The physical-reclaim seam is an ADDITIVE vtable slot with the EXACT NIL-fallback binding of
;;; store-sync / store-set-chain-mac-fn: a backend with the :delete slot physically removes a record and
;;; returns T; a backend without it returns :UNSUPPORTED (byte-identical to pre-slot). Impl-agnostic (no
;;; DARE) so it runs on both impls unconditionally: memory + SQLite implement it, the file store does not.

(defun* run-durability-store-delete-slot-test ()
    (function () t)
  "Additive store-delete slot + NIL-fallback binding (ADR 0025 §10.3 / ADR 0029 §10): memory, SQLite AND
   the file store (the file slot lands in Sliver 3b) physically remove exactly the (topic,writer-guid,sn)
   record and return T; a bare vtable WITHOUT the :delete slot returns :UNSUPPORTED (the NIL-fallback
   binding). Per-record delete-by-PRIMARY-KEY, not evict-instance."
  (let* ((g0 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (kh (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xA5))
         (p  (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b)))
         (dirs '()))
    (labels ((%dbp (tag) (let ((d (%sqlite-tmp-db-path tag)))
                           (push (uiop:pathname-directory-pathname d) dirs) d))
             (%fdir (tag) (let ((d (%file-store-tmp-dir tag))) (push d dirs) d)))
      (unwind-protect
           (progn
             ;; (1) memory :delete removes exactly the keyed row and returns T
             (let ((s (dds.durability:make-memory-store)))
               (dds.durability:store-open s)
               (dds.durability:store-put s "T" g0 1 kh :data (funcall p '(1)))
               (dds.durability:store-put s "T" g0 2 kh :data (funcall p '(2)))
               (%check :del-mem-ret (eq t (dds.durability:store-delete s "T" g0 1))
                       "memory store-delete returns T")
               (let ((sns (sort (mapcar #'dds.durability:durable-record-sn
                                        (dds.durability:store-get-range s "T")) #'<)))
                 (%check :del-mem-row (equal '(2) sns)
                         (format nil "memory store-delete removed exactly sn1, got ~s" sns)))
               (dds.durability:store-close s))
             ;; (2) SQLite :delete removes exactly the keyed row and returns T
             (let ((s (dds.durability:make-sqlite-store :path (%dbp "del-sq"))))
               (dds.durability:store-open s)
               (dds.durability:store-put s "T" g0 1 kh :data (funcall p '(1)))
               (dds.durability:store-put s "T" g0 2 kh :data (funcall p '(2)))
               (%check :del-sq-ret (eq t (dds.durability:store-delete s "T" g0 1))
                       "sqlite store-delete returns T")
               (%check :del-sq-count (= 1 (dds.durability:store-count s "T"))
                       (format nil "sqlite store-delete removed exactly one row, got ~d"
                               (dds.durability:store-count s "T")))
               (let ((sns (sort (mapcar #'dds.durability:durable-record-sn
                                        (dds.durability:store-get-range s "T")) #'<)))
                 (%check :del-sq-row (equal '(2) sns)
                         (format nil "sqlite store-delete removed exactly sn1, got ~s" sns)))
               (dds.durability:store-close s))
             ;; (3) the file store NOW implements :delete (Sliver 3b): removes exactly the keyed row + returns T
             (let ((s (dds.durability:make-file-store :dir (%fdir "del-file"))))
               (dds.durability:store-open s)
               (dds.durability:store-put s "T" g0 1 kh :data (funcall p '(1)))
               (dds.durability:store-put s "T" g0 2 kh :data (funcall p '(2)))
               (%check :del-file-ret (eq t (dds.durability:store-delete s "T" g0 1))
                       "file store-delete returns T (Sliver 3b file :delete slot)")
               (%check :del-file-count (= 1 (dds.durability:store-count s "T"))
                       (format nil "file store-delete removed exactly one row, got ~d"
                               (dds.durability:store-count s "T")))
               (let ((sns (sort (mapcar #'dds.durability:durable-record-sn
                                        (dds.durability:store-get-range s "T")) #'<)))
                 (%check :del-file-row (equal '(2) sns)
                         (format nil "file store-delete removed exactly sn1, got ~s" sns)))
               (dds.durability:store-close s))
             ;; (4) the NIL-fallback binding itself: a vtable with NO :delete slot returns :UNSUPPORTED
             (%check :del-nofallback
                     (eq :unsupported
                         (dds.durability:store-delete (dds.durability::%make-durable-store :name :memory)
                                                      "T" g0 1))
                     "a durable-store with no :delete slot returns :UNSUPPORTED (NIL-fallback binding)"))
        (dolist (d dirs)
          (when (uiop:directory-exists-p d)
            (ignore-errors (uiop:delete-directory-tree d :validate t)))))
      t)))

;;; --- Encrypted-tier physical reclaim (WP-DURABILITY-ENCRECLAIM-SQLITE, Sliver 3a; ADR 0025 §10.3) ---
;;; The v2/epoch/3c encrypted decorator opens its inner store :keep-all + puts a NIL key-hash + a per-
;;; SAMPLE guid-surrogate, so superseded blobs were logically compacted at get-range but PHYSICALLY
;;; retained until purge (the inner physical count grew to N). Sliver 3a makes the decorator physically
;;; evict the superseded prior surrogates on put (SQLite inner store), so the inner physical count
;;; converges to D. The min-SN drop (NOT oldest-arrived) keeps the physical set == the logical newest-D
;;; view exactly, even under an out-of-order writer (no data loss).

(defun* run-durability-encrypted-physical-reclaim-test ()
    (function () t)
  "Encrypted SQLite physical reclaim (Sliver 3a): a continuously-open encrypted :keep-last D store
   physically evicts superseded prior surrogates on put so the INNER physical count converges to D
   (RED pre-3a = N).
   (1) PHYSICAL RECLAIM — N=6 one instance, no close: inner physical (store-count enc nil) = D=2 (not 6);
       logical + get-range = newest D by SN, byte-exact.
   (2) two instances each bounded to D independently.
   (3) NO DATA LOSS + min-SN — an OUT-OF-ORDER writer (SN arrival != SN order): the newest D by real SN
       survive; the last-ARRIVED (non-newest-SN) sample is the one physically dropped.
   (4) CHAIN INTACT — reopen a fresh encrypted store on the same DB: the v3 chain VERIFIES clean (no
       false-reject; the delete-txn survivor re-MAC is load-bearing) + get-range newest-D byte-exact.
   (5) CRASH lower-bar — a fault between put and delete leaks the prior blob (physical > D) but get-range
       still logically compacts (newest D) + the chain verifies + the leak self-heals on the next delete.
   (6) FALLBACK + KEEP_ALL — a KEEP_ALL encrypted store deletes nothing (physical == N); the FILE
       encrypted tier's get-range compacts to newest-D exactly like SQLite (its own physical reclaim lands in
       Sliver 3b — run-durability-file-encrypted-physical-reclaim-test covers the file on-disk bound)."
  (unless (dds.dare:dare-available-p)
    (format t "~&  [enc-physical-reclaim] SKIP — OpenSSL >= 3.5 not available~%")
    (return-from run-durability-encrypted-physical-reclaim-test t))
  (let* ((g0  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (kh1 (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xB1))
         (kh2 (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xC2))
         (dirs '()))
    (labels ((%encdir (tag)
               (let ((d (uiop:pathname-directory-pathname (%sqlite-tmp-db-path tag))))
                 (push d dirs) d))
             (%enc-build (dir)
               ;; encrypted SQLite store rooted at DIR (db + epochs.dat + logmac.anchor + keys coexist,
               ;; exactly as run-durability-sqlite-dare-test); constructed CLOSED (caller store-opens).
               (dds.durability:make-encrypted-store
                (dds.durability:make-sqlite-store
                 :path (uiop:merge-pathnames* (make-pathname :name "durability" :type "sqlite3") dir))
                (dds.dare:make-file-key-provider :dir dir)
                :epoch-dir dir))
             (%sns (recs) (sort (mapcar #'dds.durability:durable-record-sn recs) #'<))
             (%gsig (recs) (mapcar (lambda (r) (cons (aref (dds.durability:durable-record-writer-guid r) 0)
                                                     (dds.durability:durable-record-sn r)))
                                   recs)))
      (unwind-protect
           (progn
             ;; (1) PHYSICAL RECLAIM — inner physical converges to D=2 (RED pre-3a = 6)
             (let* ((dir (%encdir "enc-phys")) (s (%enc-build dir)))
               (dds.durability:store-open s :keep-last 2)
               (dotimes (i 6) (dds.durability:store-put s "Enc" g0 (1+ i) kh1 :data (%make-small-payload (1+ i))))
               (%check :encpr-physical (= 2 (dds.durability:store-count s nil))
                       (format nil "inner PHYSICAL count converges to D=2 without close (RED pre-3a=6), got ~d"
                               (dds.durability:store-count s nil)))
               (%check :encpr-logical (= 2 (dds.durability:store-count s "Enc"))
                       (format nil "logical per-topic count = D=2, got ~d" (dds.durability:store-count s "Enc")))
               (let ((recs (dds.durability:store-get-range s "Enc")))
                 (%check :encpr-newest (equal '(5 6) (%sns recs))
                         (format nil "get-range = newest D by SN (5 6), got ~s" (%sns recs)))
                 (%check :encpr-exact
                         (equalp (%make-small-payload 6)
                                 (dds.durability:durable-record-payload
                                  (find 6 recs :key #'dds.durability:durable-record-sn)))
                         "surviving newest payload decrypts byte-exact"))
               (dds.durability:store-close s))
             ;; (2) two instances each converge to D independently
             (let* ((dir (%encdir "enc-2inst")) (s (%enc-build dir)))
               (dds.durability:store-open s :keep-last 2)
               (dotimes (i 5) (dds.durability:store-put s "Enc" g0 (1+ i)  kh1 :data (%make-small-payload (1+ i))))
               (dotimes (i 5) (dds.durability:store-put s "Enc" g0 (+ 20 i) kh2 :data (%make-small-payload (+ 20 i))))
               (%check :encpr-2inst-phys (= 4 (dds.durability:store-count s nil))
                       (format nil "two instances each bounded to D=2 -> inner physical = 4, got ~d"
                               (dds.durability:store-count s nil)))
               (let* ((recs (dds.durability:store-get-range s "Enc"))
                      (k1 (count kh1 recs :key #'dds.durability:durable-record-key-hash :test #'equalp))
                      (k2 (count kh2 recs :key #'dds.durability:durable-record-key-hash :test #'equalp)))
                 (%check :encpr-2inst-indep (and (= 2 k1) (= 2 k2))
                         (format nil "each instance keeps D=2 logically, got kh1=~d kh2=~d" k1 k2)))
               (dds.durability:store-close s))
             ;; (3) NO DATA LOSS + min-SN under an OUT-OF-ORDER writer (SNs arrive 3,1,5,2,6,4)
             (let* ((dir (%encdir "enc-ooo")) (s (%enc-build dir)))
               (dds.durability:store-open s :keep-last 2)
               (dolist (sn '(3 1 5 2 6 4))
                 (dds.durability:store-put s "Enc" g0 sn kh1 :data (%make-small-payload sn)))
               (%check :encpr-ooo-phys (= 2 (dds.durability:store-count s nil))
                       (format nil "out-of-order writer: inner physical bounded to D=2, got ~d"
                               (dds.durability:store-count s nil)))
               (let ((recs (dds.durability:store-get-range s "Enc")))
                 (%check :encpr-ooo-newest (equal '(5 6) (%sns recs))
                         (format nil "min-SN drop keeps newest D by real SN (5 6) under out-of-order arrival ~
                                 (last-arrived sn4 dropped, not sn5/sn6), got ~s" (%sns recs)))
                 (%check :encpr-ooo-exact
                         (and (equalp (%make-small-payload 5)
                                      (dds.durability:durable-record-payload
                                       (find 5 recs :key #'dds.durability:durable-record-sn)))
                              (equalp (%make-small-payload 6)
                                      (dds.durability:durable-record-payload
                                       (find 6 recs :key #'dds.durability:durable-record-sn))))
                         "newest-D payloads (5,6) survive byte-exact — no newest-D sample deleted"))
               (dds.durability:store-close s))
             ;; (4) CHAIN INTACT — reopen a fresh encrypted store on the same DB, verify clean + newest-D
             (let ((dir (%encdir "enc-chain")))
               (let ((s (%enc-build dir)))
                 (dds.durability:store-open s :keep-last 2)
                 (dotimes (i 6) (dds.durability:store-put s "Enc" g0 (1+ i) kh1 :data (%make-small-payload (1+ i))))
                 (dds.durability:store-close s))
               (let* ((s2 (%enc-build dir))
                      (clean (handler-case (progn (dds.durability:store-open s2 :keep-last 2) t)
                               (error () nil))))
                 (%check :encpr-chain-clean clean
                         "reopened encrypted store VERIFIES the v3 chain clean (no false-reject — the delete-txn re-MAC is load-bearing)")
                 (when clean
                   (let ((recs (dds.durability:store-get-range s2 "Enc")))
                     (%check :encpr-chain-newest (equal '(5 6) (%sns recs))
                             (format nil "reopen: get-range = newest D (5 6), got ~s" (%sns recs)))
                     (%check :encpr-chain-exact
                             (equalp (%make-small-payload 5)
                                     (dds.durability:durable-record-payload
                                      (find 5 recs :key #'dds.durability:durable-record-sn)))
                             "reopen: survivor payload decrypts byte-exact")))
                 (ignore-errors (dds.durability:store-close s2))))
             ;; (5) CRASH lower-bar — fault between put and delete: leak, logical-correct, self-heal, clean reopen
             (let* ((dir (%encdir "enc-crash")) (s (%enc-build dir)))
               (dds.durability:store-open s :keep-last 2)
               (dds.durability:store-put s "Enc" g0 1 kh1 :data (%make-small-payload 1))
               (dds.durability:store-put s "Enc" g0 2 kh1 :data (%make-small-payload 2))
               ;; the 3rd put supersedes -> the decorator issues store-delete; inject the fault mid-delete
               (let ((dds.durability::*durability-debug-compact-fault* t))
                 (%check :encpr-crash-faulted
                         (handler-case (progn (dds.durability:store-put s "Enc" g0 3 kh1 :data (%make-small-payload 3)) nil)
                           (error () t))
                         "the store-delete fault propagates through the decorator put (crash between put and delete)"))
               (%check :encpr-crash-leak (> (dds.durability:store-count s nil) 2)
                       (format nil "crash between put and delete leaks the prior blob (physical > D), got ~d"
                               (dds.durability:store-count s nil)))
               (%check :encpr-crash-logical (equal '(2 3) (%sns (dds.durability:store-get-range s "Enc")))
                       (format nil "get-range still logically compacts to newest D (2 3) despite the leak, got ~s"
                               (%sns (dds.durability:store-get-range s "Enc"))))
               ;; self-heal: a subsequent (fault-cleared) superseding put reclaims the leak -> physical back to D
               (dds.durability:store-put s "Enc" g0 4 kh1 :data (%make-small-payload 4))
               (%check :encpr-crash-selfheal (= 2 (dds.durability:store-count s nil))
                       (format nil "the leak self-heals on the next delete -> physical back to D=2, got ~d"
                               (dds.durability:store-count s nil)))
               (%check :encpr-crash-heal-newest (equal '(3 4) (%sns (dds.durability:store-get-range s "Enc")))
                       (format nil "post-self-heal get-range = newest D (3 4), got ~s"
                               (%sns (dds.durability:store-get-range s "Enc"))))
               (dds.durability:store-close s)
               (let* ((s2 (%enc-build dir))
                      (clean (handler-case (progn (dds.durability:store-open s2 :keep-last 2) t)
                               (error () nil))))
                 (%check :encpr-crash-reopen-clean clean
                         "after the crash-fault the store reopens CLEAN (the delete rolled back -> chain intact)")
                 (ignore-errors (dds.durability:store-close s2))))
             ;; (6a) KEEP_ALL encrypted store deletes nothing (the window guard requires :keep-last)
             (let* ((dir (%encdir "enc-keepall")) (s (%enc-build dir)))
               (dds.durability:store-open s :keep-all)
               (dotimes (i 5) (dds.durability:store-put s "Enc" g0 (1+ i) kh1 :data (%make-small-payload (1+ i))))
               (%check :encpr-keepall (= 5 (dds.durability:store-count s nil))
                       (format nil "KEEP_ALL encrypted store deletes nothing (physical == N=5), got ~d"
                               (dds.durability:store-count s nil)))
               (dds.durability:store-close s))
             ;; (6b) FILE encrypted tier: get-range compacts to newest D exactly like SQLite (Sliver 3b gives
             ;; the file store its own :delete slot -> physical reclaim; dedicated on-disk-bound coverage is
             ;; run-durability-file-encrypted-physical-reclaim-test — here we only re-confirm get-range parity)
             (let* ((d-dir (uiop:pathname-directory-pathname (%sqlite-tmp-db-path "enc-file-d")))
                    (k-dir (uiop:pathname-directory-pathname (%sqlite-tmp-db-path "enc-file-k"))))
               (push d-dir dirs) (push k-dir dirs)
               (let ((s (dds.durability:make-encrypted-store
                         (dds.durability:make-file-store :dir d-dir)
                         (dds.dare:make-file-key-provider :dir k-dir)
                         :epoch-dir d-dir)))
                 (dds.durability:store-open s :keep-last 2)
                 (dotimes (i 6) (dds.durability:store-put s "Enc" g0 (1+ i) kh1 :data (%make-small-payload (1+ i))))
                 (%check :encpr-file-logical (equal '(5 6) (%sns (dds.durability:store-get-range s "Enc")))
                         (format nil "file encrypted tier: get-range compacts to newest D (5 6), got ~s"
                                 (%sns (dds.durability:store-get-range s "Enc"))))
                 (dds.durability:store-close s)))
             ;; (7) FIX 1 — multi-writer-per-instance: the SQLite and the FILE encrypted tiers agree on
             ;; get-range EXACTLY (both physically reclaim via the decorator's %win-entry< drop after 3b).
             ;; A pure-min-SN drop kept the WRONG survivor (RED: kept guidA·sn5 while the logical view keeps
             ;; guidB·sn3, max by (guid,sn)); the (guid,sn) order makes both backends' survivors identical.
             (let* ((sdir (%encdir "enc-mw-sq"))
                    (fd-d (uiop:pathname-directory-pathname (%sqlite-tmp-db-path "enc-mw-fd")))
                    (fd-k (uiop:pathname-directory-pathname (%sqlite-tmp-db-path "enc-mw-fk")))
                    (ga   (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
                    (gb   (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
                    (sq   (%enc-build sdir))
                    (fl   (dds.durability:make-encrypted-store
                           (dds.durability:make-file-store :dir fd-d)
                           (dds.dare:make-file-key-provider :dir fd-k) :epoch-dir fd-d)))
               (push fd-d dirs) (push fd-k dirs)
               (setf (aref ga 0) 1) (setf (aref gb 0) 2)     ; A.guid < B.guid
               (dolist (s (list sq fl)) (dds.durability:store-open s :keep-last 2))
               ;; one instance (same key-hash) fed by 2 writers; SN order (5,3,1,6) != (guid,sn) order
               (dolist (spec (list (list ga 5) (list gb 3) (list ga 1) (list gb 6)))
                 (dolist (s (list sq fl))
                   (dds.durability:store-put s "Enc" (first spec) (second spec) kh1
                                             :data (%make-small-payload (second spec)))))
               (let ((sq-sig (%gsig (dds.durability:store-get-range sq "Enc")))
                     (fl-sig (%gsig (dds.durability:store-get-range fl "Enc"))))
                 (%check :encpr-mw-exact (equal sq-sig fl-sig)
                         (format nil "multi-writer: SQLite physical-reclaim get-range == file physical-reclaim get-range ~
                                 EXACTLY (drop by (guid,sn), not pure SN); sqlite=~s file=~s" sq-sig fl-sig)))
               (dds.durability:store-close sq) (dds.durability:store-close fl))
             ;; (8) FIX 2 — an idempotent re-put of an already-stored (guid,sn) must NOT delete a live
             ;; newest-D row (the deterministic surrogate makes store-put a physical no-op; the window
             ;; append is dedup'd on the surrogate). RED pre-fix: the duplicate append evicts sn1.
             (let* ((dir (%encdir "enc-idem")) (s (%enc-build dir)))
               (dds.durability:store-open s :keep-last 2)
               (dds.durability:store-put s "Enc" g0 1 kh1 :data (%make-small-payload 1))
               (dds.durability:store-put s "Enc" g0 2 kh1 :data (%make-small-payload 2))
               (dds.durability:store-put s "Enc" g0 2 kh1 :data (%make-small-payload 2)) ; idempotent re-put
               (%check :encpr-idem-phys (= 2 (dds.durability:store-count s nil))
                       (format nil "idempotent re-put must not delete a live row (physical stays D=2), got ~d"
                               (dds.durability:store-count s nil)))
               (%check :encpr-idem-newest (equal '(1 2) (%sns (dds.durability:store-get-range s "Enc")))
                       (format nil "idempotent re-put must not lose sn1 (get-range stays (1 2)), got ~s"
                               (%sns (dds.durability:store-get-range s "Enc"))))
               (dds.durability:store-close s))
             ;; (9) FIX 3 — :purge clears the prior-surrogate window so a later same-instance write with a
             ;; LOWER SN than the purged entries is not mis-evicted by the stale window (bounds RAM too).
             ;; RED pre-fix: the stale window (5,6) drops the fresh sn1 as the min -> physical 0, sn1 lost.
             (let* ((dir (%encdir "enc-purge")) (s (%enc-build dir)))
               (dds.durability:store-open s :keep-last 2)
               (dds.durability:store-put s "Enc" g0 5 kh1 :data (%make-small-payload 5))
               (dds.durability:store-put s "Enc" g0 6 kh1 :data (%make-small-payload 6))
               (dds.durability:store-purge s "Enc")
               (%check :encpr-purge-empty (= 0 (dds.durability:store-count s nil))
                       (format nil "purge empties the inner store, got ~d" (dds.durability:store-count s nil)))
               (dds.durability:store-put s "Enc" g0 1 kh1 :data (%make-small-payload 1)) ; lower SN than purged 5,6
               (%check :encpr-purge-nostale (= 1 (dds.durability:store-count s nil))
                       (format nil "post-purge lower-SN write survives (window cleared), physical=~d [RED pre-fix=0]"
                               (dds.durability:store-count s nil)))
               (%check :encpr-purge-getrange (equal '(1) (%sns (dds.durability:store-get-range s "Enc")))
                       (format nil "post-purge get-range = (1), got ~s" (%sns (dds.durability:store-get-range s "Enc"))))
               (dds.durability:store-close s)))
        (dolist (d dirs)
          (when (uiop:directory-exists-p d)
            (ignore-errors (uiop:delete-directory-tree d :validate t)))))
      t)))

;;; --- File-store runtime threshold compaction (WP-DURABILITY-COMPACTION-FILE, Sliver 2) ---
;;; The APPEND-ONLY file store cannot delete-in-place, so a continuously-open KEEP_LAST log grew
;;; unboundedly between opens (only on-open compaction, ADR 0029). Sliver 2 adds RUNTIME threshold
;;; compaction: each KEEP_LAST-superseded :data put bumps an O(1) per-topic counter, and crossing
;;; *compaction-superseded-threshold* runs the EXISTING atomic %rewrite-topic-log MID-RUN (tmp+fsync+
;;; rename — crash-atomicity inherited, no new transaction machinery), bounding the on-disk log to
;;; (live-count + threshold) WITHOUT a close/open cycle.

(defun* %file-store-tmp-dir (tag)
    (function (string) pathname)
  "Fresh unique temp dir for a file-store compaction test case."
  (uiop:merge-pathnames*
   (make-pathname :directory (list :relative (format nil "dds-fscompact-~a-~a-~a"
                                                     tag (get-universal-time) (random 1000000))))
   (uiop:temporary-directory)))

(defun* %file-store-log-count (dir topic &optional oracle)
    (function (pathname string &optional (or null function)) (integer 0))
  "On-disk RAW frame count for TOPIC's append-log under DIR (BEFORE compaction) — the Sliver-2
   bounded-growth probe. Parses the log with the store's own %replay-log (ORACLE verifies a keyed v3
   chain, NIL for a bare v2 log)."
  (length (dds.durability::%replay-log
           (dds.durability::%topic-log-path dir (dds.durability::%topic->id topic))
           topic oracle nil)))

;;; --- Encrypted-tier physical reclaim, FILE backend (WP-DURABILITY-ENCRECLAIM-FILE, Sliver 3b) ---
;;; 3a made the encrypted decorator physically evict superseded surrogates on the SQLite backend. The
;;; FILE backend had no :delete slot, so store-delete returned :unsupported, the decorator skipped
;;; physical reclaim, and the encrypted file tier grew unbounded (logical-only). Sliver 3b adds the file
;;; :delete slot (append-log mark-superseded remhash + per-topic pending-delete set + threshold rewrite
;;; EXCLUDING the pending-delete surrogates, reusing the Sliver-2 atomic tmp+fsync+rename + append-fd
;;; guard), so the continuously-open encrypted file tier physically reclaims (on-disk log <= D+threshold).

(defun* %enc-file-log-count (d-dir k-dir topic)
    (function (t t string) (integer 0))
  "On-disk PHYSICAL v3-frame count for the encrypted FILE-store log of TOPIC (the Sliver-3b physical-
   reclaim probe): the log basename is %topic->id of the k_meta topic-hash (3c), and its frames are v3, so
   derive the log-MAC oracle from the persisted anchor, count via %file-store-log-count, then free the key."
  (let ((th-hex (%enc-topic-hash d-dir k-dir topic))
        (kp     (dds.dare:make-file-key-provider :dir k-dir)))
    (dds.dare:key-provider-open kp)
    (unwind-protect
         (let ((key (dds.durability::%derive-logmac-key kp (uiop:ensure-directory-pathname d-dir))))
           (unwind-protect
                (%file-store-log-count (uiop:ensure-directory-pathname d-dir) th-hex
                                       (lambda (data) (dds.dare:hmac-sha256 key data)))
             (dds.dare:free-secret-octets key)))
      (dds.dare:key-provider-close kp))))

(defun* run-durability-file-encrypted-physical-reclaim-test ()
    (function () t)
  "Encrypted FILE physical reclaim (Sliver 3b, WP-DURABILITY-ENCRECLAIM-FILE; ADR 0025 §10.3 / ADR 0029 §10):
   the encrypted decorator over a FILE inner store now physically reclaims superseded surrogates via the file
   :delete slot, so a continuously-open encrypted :keep-last D file tier bounds its ON-DISK log instead of
   growing to N.
   (1) FILE PHYSICAL RECLAIM — N=20 one instance, no close: the inner ON-DISK log frame count stays bounded
       (<= D + threshold), NOT N (RED pre-3b: file :unsupported -> decorator skips -> 20); the in-memory
       physical count converges to D; get-range = newest D by SN byte-exact.
   (2) NO DATA LOSS + CHAIN — reopen a fresh encrypted file store: the v3 chain VERIFIES clean (no
       false-reject; the reclaim rewrite re-emitted a fresh chain) + get-range = newest D byte-exact.
   (3a) CRASH (rewrite fault) — a fault in the reclaim rewrite (*durability-debug-file-rewrite-fault*)
        propagates through the decorator put; reopen finds a consistent (un-torn) log, chain verifies, no loss.
   (3b) CRASH (remhash/rewrite split) — deletes remhashed but not yet rewritten, then close+reopen: the
        superseded surrogates REAPPEAR on disk (space leak) but get-range stays logically newest-D + the chain
        verifies; sustained writes self-heal (the cross-restart sweep is 3c).
   (4) FALLBACK — a KEEP_ALL encrypted file store deletes nothing (on-disk == N).
   (5) MULTI-WRITER + IDEMPOTENT parity — the decorator window is inherited by the file backend: a multi-writer
       instance drops by (guid,sn) not pure SN; an idempotent re-put of a live row loses nothing."
  (unless (dds.dare:dare-available-p)
    (format t "~&  [file-enc-physical-reclaim] SKIP — OpenSSL >= 3.5 not available~%")
    (return-from run-durability-file-encrypted-physical-reclaim-test t))
  (let* ((g0  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (kh1 (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xB1))
         (dirs '()))
    (labels ((%dk (tag)
               ;; a fresh (data-dir . key-dir) pair for one encrypted file-store case
               (let ((d (uiop:pathname-directory-pathname (%sqlite-tmp-db-path (format nil "fenc-~a-d" tag))))
                     (k (uiop:pathname-directory-pathname (%sqlite-tmp-db-path (format nil "fenc-~a-k" tag)))))
                 (push d dirs) (push k dirs)
                 (cons d k)))
             (%build (dk)
               ;; encrypted store over a FILE inner store (data + key dirs); constructed CLOSED (caller opens)
               (dds.durability:make-encrypted-store
                (dds.durability:make-file-store :dir (car dk))
                (dds.dare:make-file-key-provider :dir (cdr dk))
                :epoch-dir (car dk)))
             (%sns (recs) (sort (mapcar #'dds.durability:durable-record-sn recs) #'<))
             (%gsig (recs) (mapcar (lambda (r) (cons (aref (dds.durability:durable-record-writer-guid r) 0)
                                                     (dds.durability:durable-record-sn r)))
                                   recs)))
      (unwind-protect
           (let ((dds.durability:*compaction-superseded-threshold* 4)
                 (d 2))
             ;; (1) FILE PHYSICAL RECLAIM — on-disk log bounded <= D+threshold, NOT N=20 (RED pre-3b = 20)
             (let* ((dk (%dk "phys")) (s (%build dk)))
               (dds.durability:store-open s :keep-last d)
               (dotimes (i 20) (dds.durability:store-put s "Enc" g0 (1+ i) kh1 :data (%make-small-payload (1+ i))))
               (let ((on-disk (%enc-file-log-count (car dk) (cdr dk) "Enc")))
                 (%check :fenc-physical-bounded (<= on-disk (+ d 4))
                         (format nil "encrypted file ON-DISK log bounded <= D+threshold=~d (physical reclaim), got ~d"
                                 (+ d 4) on-disk))
                 (%check :fenc-physical-not-n (< on-disk 20)
                         (format nil "on-disk log must be << N=20 (RED pre-3b: file :unsupported -> 20), got ~d" on-disk)))
               (%check :fenc-inmem-physical (= d (dds.durability:store-count s nil))
                       (format nil "in-memory physical index converges to D=~d (immediate remhash), got ~d"
                               d (dds.durability:store-count s nil)))
               (let ((recs (dds.durability:store-get-range s "Enc")))
                 (%check :fenc-newest (equal '(19 20) (%sns recs))
                         (format nil "get-range = newest D by SN (19 20), got ~s" (%sns recs)))
                 (%check :fenc-exact
                         (equalp (%make-small-payload 20)
                                 (dds.durability:durable-record-payload
                                  (find 20 recs :key #'dds.durability:durable-record-sn)))
                         "surviving newest payload decrypts byte-exact"))
               (dds.durability:store-close s))
             ;; (2) NO DATA LOSS + CHAIN — reopen fresh store, verify clean + newest-D byte-exact
             (let ((dk (%dk "chain")))
               (let ((s (%build dk)))
                 (dds.durability:store-open s :keep-last d)
                 (dotimes (i 20) (dds.durability:store-put s "Enc" g0 (1+ i) kh1 :data (%make-small-payload (1+ i))))
                 (dds.durability:store-close s))
               (let* ((s2 (%build dk))
                      (clean (handler-case (progn (dds.durability:store-open s2 :keep-last d) t)
                               (error () nil))))
                 (%check :fenc-chain-clean clean
                         "reopened encrypted file store VERIFIES the v3 chain clean (reclaim rewrite re-emitted a fresh chain — no false-reject)")
                 (when clean
                   (let ((recs (dds.durability:store-get-range s2 "Enc")))
                     (%check :fenc-chain-newest (equal '(19 20) (%sns recs))
                             (format nil "reopen: get-range = newest D (19 20), got ~s" (%sns recs)))
                     (%check :fenc-chain-exact
                             (equalp (%make-small-payload 20)
                                     (dds.durability:durable-record-payload
                                      (find 20 recs :key #'dds.durability:durable-record-sn)))
                             "reopen: survivor payload decrypts byte-exact")))
                 (ignore-errors (dds.durability:store-close s2))))
             ;; (3a) CRASH (rewrite fault) — a fault DURING the reclaim rewrite propagates through the
             ;; decorator put; the original log is intact (the rename is the commit point, the .tmp is
             ;; orphaned), so a fresh reopen discards the orphan, replays the un-torn log, the v3 chain
             ;; verifies, and the newest D survive (no false-reject, no loss).
             (let* ((dk (%dk "faultrw")) (s (%build dk)))
               (dds.durability:store-open s :keep-last d)
               ;; puts 1..5 (3 supersedes -> pending-delete size 3 < threshold 4, no rewrite yet)
               (dotimes (i 5) (dds.durability:store-put s "Enc" g0 (1+ i) kh1 :data (%make-small-payload (1+ i))))
               ;; the 6th put supersedes -> pending-delete reaches threshold 4 -> reclaim rewrite -> FAULT
               (let ((dds.durability::*durability-debug-file-rewrite-fault* t))
                 (%check :fenc-fault-signals
                         (handler-case (progn (dds.durability:store-put s "Enc" g0 6 kh1 :data (%make-small-payload 6)) nil)
                           (error () t))
                         "the reclaim-rewrite fault propagates through the decorator put (crash before the atomic rename)"))
               (%check :fenc-fault-logical (equal '(5 6) (%sns (dds.durability:store-get-range s "Enc")))
                       (format nil "post-fault get-range stays logically newest-D (5 6) (in-mem pruned, log intact), got ~s"
                               (%sns (dds.durability:store-get-range s "Enc"))))
               (ignore-errors (dds.durability:store-close s))
               (let* ((s2 (%build dk))
                      (clean (handler-case (progn (dds.durability:store-open s2 :keep-last d) t)
                               (error () nil))))
                 (%check :fenc-fault-reopen-clean clean
                         "after the reclaim-rewrite fault the store reopens CLEAN (original log intact, chain verifies — no torn log, no false-reject)")
                 (when clean
                   (%check :fenc-fault-no-loss (equal '(5 6) (%sns (dds.durability:store-get-range s2 "Enc")))
                           (format nil "post-fault reopen keeps the newest D (5 6) — no data loss, got ~s"
                                   (%sns (dds.durability:store-get-range s2 "Enc")))))
                 (ignore-errors (dds.durability:store-close s2))))
             ;; (3b) CRASH (remhash/rewrite split, CROSS-RESTART) — surrogates remhashed in-memory but not
             ;; yet physically rewritten (< threshold), then close+reopen: the pending-delete set is
             ;; in-memory so it is lost, the surrogates REAPPEAR in the log (a physical space leak), the
             ;; chain still verifies (the log was never torn) and get-range stays logically newest-D
             ;; (correct reads — self-healing). The cross-restart PHYSICAL reclaim of these leftovers is
             ;; Sliver 3c (the decorator's fresh post-reopen window never re-deletes them); 3b bounds only
             ;; the continuously-open case — so this asserts leak-persists + reads-correct, NOT physical reclaim.
             (let ((dk (%dk "split")))
               (let ((s (%build dk)))
                 (dds.durability:store-open s :keep-last d)
                 ;; 5 puts: 3 supersedes < threshold 4 -> NO rewrite; 3 surrogates remhashed but still on disk
                 (dotimes (i 5) (dds.durability:store-put s "Enc" g0 (1+ i) kh1 :data (%make-small-payload (1+ i))))
                 (dds.durability:store-close s))            ; close loses the in-memory pending-delete set
               (let* ((s2 (%build dk))
                      (clean (handler-case (progn (dds.durability:store-open s2 :keep-last d) t)
                               (error () nil))))
                 (%check :fenc-split-clean clean
                         "the remhash/rewrite split reopens CLEAN (the un-rewritten log is intact, chain verifies)")
                 (when clean
                   (%check :fenc-split-leak (> (%enc-file-log-count (car dk) (cdr dk) "Enc") d)
                           (format nil "the superseded surrogates REAPPEAR on disk (cross-restart space leak > D=~d; physical reclaim = 3c), got ~d"
                                   d (%enc-file-log-count (car dk) (cdr dk) "Enc")))
                   (%check :fenc-split-logical (equal '(4 5) (%sns (dds.durability:store-get-range s2 "Enc")))
                           (format nil "get-range stays logically newest-D (4 5) despite the on-disk leak (correct reads self-heal), got ~s"
                                   (%sns (dds.durability:store-get-range s2 "Enc"))))
                   ;; continued same-instance writes keep get-range correct (reads never regress on the leak)
                   (dotimes (i 4) (dds.durability:store-put s2 "Enc" g0 (+ 6 i) kh1 :data (%make-small-payload (+ 6 i))))
                   (%check :fenc-split-reads-correct (equal '(8 9) (%sns (dds.durability:store-get-range s2 "Enc")))
                           (format nil "post-leak continued writes keep get-range logically newest-D (8 9), got ~s"
                                   (%sns (dds.durability:store-get-range s2 "Enc")))))
                 (ignore-errors (dds.durability:store-close s2))))
             ;; (3c) SELF-HEAL (CONTINUOUSLY-OPEN) — a fault leaves pending-delete armed (the rewrite faulted
             ;; before the clear), so a fault-cleared same-instance put in the SAME session retries the
             ;; reclaim and it succeeds: the on-disk log drops back to bounded and get-range is newest-D.
             (let* ((dk (%dk "selfheal")) (s (%build dk)))
               (dds.durability:store-open s :keep-last d)
               (dotimes (i 5) (dds.durability:store-put s "Enc" g0 (1+ i) kh1 :data (%make-small-payload (1+ i))))
               (let ((dds.durability::*durability-debug-file-rewrite-fault* t))
                 (handler-case (dds.durability:store-put s "Enc" g0 6 kh1 :data (%make-small-payload 6))
                   (error () nil)))                          ; 6th put -> reclaim -> FAULT (swallowed)
               ;; fault cleared: the next put's store-delete finds pending-delete still armed -> retry succeeds
               (dds.durability:store-put s "Enc" g0 7 kh1 :data (%make-small-payload 7))
               (%check :fenc-selfheal-bounded (<= (%enc-file-log-count (car dk) (cdr dk) "Enc") (+ d 4))
                       (format nil "continuously-open self-heal: the post-fault put retries the reclaim -> on-disk <= D+threshold=~d, got ~d"
                               (+ d 4) (%enc-file-log-count (car dk) (cdr dk) "Enc")))
               (%check :fenc-selfheal-newest (equal '(6 7) (%sns (dds.durability:store-get-range s "Enc")))
                       (format nil "post-self-heal get-range = newest D (6 7), got ~s"
                               (%sns (dds.durability:store-get-range s "Enc"))))
               (dds.durability:store-close s))
             ;; (4) FALLBACK — KEEP_ALL encrypted file store deletes nothing (on-disk == N)
             (let* ((dk (%dk "keepall")) (s (%build dk)))
               (dds.durability:store-open s :keep-all)
               (dotimes (i 6) (dds.durability:store-put s "Enc" g0 (1+ i) kh1 :data (%make-small-payload (1+ i))))
               (%check :fenc-keepall-physical (= 6 (%enc-file-log-count (car dk) (cdr dk) "Enc"))
                       (format nil "KEEP_ALL encrypted file store deletes nothing (on-disk == N=6), got ~d"
                               (%enc-file-log-count (car dk) (cdr dk) "Enc")))
               (dds.durability:store-close s))
             ;; (5) MULTI-WRITER + IDEMPOTENT parity (the decorator window is inherited by the file backend)
             (let* ((dk (%dk "mw"))
                    (s  (%build dk))
                    (ga (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
                    (gb (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref ga 0) 1) (setf (aref gb 0) 2)     ; A.guid < B.guid, one instance, two writers
               (dds.durability:store-open s :keep-last d)
               ;; SN order (5,3,1,6) != (guid,sn) order -> the drop must be by (guid,sn), not pure SN
               (dolist (spec (list (list ga 5) (list gb 3) (list ga 1) (list gb 6)))
                 (dds.durability:store-put s "Enc" (first spec) (second spec) kh1
                                           :data (%make-small-payload (second spec))))
               (let ((sig (%gsig (dds.durability:store-get-range s "Enc"))))
                 (%check :fenc-mw-newest (equal '((2 . 3) (2 . 6)) sig)
                         (format nil "multi-writer drop is by (guid,sn) not pure SN -> survivors (B·3,B·6), got ~s" sig)))
               ;; idempotent re-put of a LIVE row (deterministic surrogate -> store-put no-op + window dedup) loses nothing
               (dds.durability:store-put s "Enc" gb 6 kh1 :data (%make-small-payload 6))
               (%check :fenc-idem (equal '((2 . 3) (2 . 6)) (%gsig (dds.durability:store-get-range s "Enc")))
                       (format nil "idempotent re-put of a live row loses nothing, got ~s"
                               (%gsig (dds.durability:store-get-range s "Enc"))))
               (dds.durability:store-close s)))
        (dolist (d dirs)
          (when (uiop:directory-exists-p d)
            (ignore-errors (uiop:delete-directory-tree d :validate t)))))
      t)))

;;; --- Encrypted-tier CROSS-RESTART physical reclaim (WP-DURABILITY-ENCRECLAIM-SWEEP, Sliver 3c; ADR 0025 §10.3) ---
;;; 3a/3b bound the CONTINUOUSLY-OPEN case (the online prior-surrogate window physically evicts superseded
;;; blobs on put). But instance-windows is IN-RAM and clrhash'd on :open (3a FIX3), so after a RESTART a
;;; prior session's newest-D survivors are unknown to the fresh window: post-restart online eviction (which
;;; tracks only this-session puts) never evicts them and they leak until the next restart — across K restarts
;;; a hammered instance accumulates ~K*D physical rows. Sliver 3c adds the decorator compaction-on-open
;;; SWEEP: decrypt each inner topic's surrogate rows (reuse the get-range decrypt), group by real key-hash,
;;; store-delete the leftovers beyond newest-D AND SEED the window with the survivors, so post-restart online
;;; eviction continues seamlessly (cross-restart physical == continuously-open). Proven RED by the test-only
;;; *durability-debug-disable-open-sweep* switch (reproduces the pre-3c leak).

(defun* run-durability-encrypted-cross-restart-sweep-test ()
    (function () t)
  "Encrypted SQLite CROSS-RESTART physical reclaim (Sliver 3c, WP-DURABILITY-ENCRECLAIM-SWEEP; ADR 0025 §10.3):
   the decorator compaction-on-open sweep reclaims a prior session's <=D leftovers AND seeds the window, so
   cross-restart physical stays ~D. Closes the encrypted-reclaim cross-restart residual (SQLite).
   (1) CROSS-RESTART BOUND — write 6, close, reopen, x K cycles: inner physical stays D=2, NOT ~K*D.
   (2) RED + SWEEP RECLAIM — sweep-disabled reproduces the pre-3c accumulation to ~K*D (physical STRICTLY
       grows across restarts); re-opening that leaked store WITH the sweep reclaims it to D (the reclaim).
   (3) WINDOW-SEEDED — after reopen+sweep, continued higher-SN writes (no close) stay D (the seed evicts the
       prior survivors); RED sweep-disabled = the continued writes leak (physical > D).
   (4) NO-LOSS + CHAIN — get-range post-sweep = newest D by real SN byte-exact; reopen-after-sweep VERIFIES
       the v3 chain clean (the sweep's store-delete re-MAC is load-bearing, no false-reject).
   (5) IDEMPOTENT — reopening an already-swept store (no new writes) reclaims nothing (physical stays D).
   (6) KEEP_ALL — a KEEP_ALL reopen runs no sweep (retains all, physical == N)."
  (unless (dds.dare:dare-available-p)
    (format t "~&  [enc-cross-restart-sweep] SKIP — OpenSSL >= 3.5 not available~%")
    (return-from run-durability-encrypted-cross-restart-sweep-test t))
  (let* ((g0  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (kh1 (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xB1))
         (dirs '()))
    (labels ((%encdir (tag)
               (let ((d (uiop:pathname-directory-pathname (%sqlite-tmp-db-path tag))))
                 (push d dirs) d))
             (%build (dir)
               (dds.durability:make-encrypted-store
                (dds.durability:make-sqlite-store
                 :path (uiop:merge-pathnames* (make-pathname :name "durability" :type "sqlite3") dir))
                (dds.dare:make-file-key-provider :dir dir)
                :epoch-dir dir))
             (%sns (recs) (sort (mapcar #'dds.durability:durable-record-sn recs) #'<))
             (%gsig (recs) (mapcar (lambda (r) (cons (aref (dds.durability:durable-record-writer-guid r) 0)
                                                     (dds.durability:durable-record-sn r)))
                                   recs))
             (%write-session (dir cyc kind)
               ;; one restart cycle: fresh decorator over DIR (cross-restart simulation), open, write 6
               ;; higher SNs to ONE instance, measure the post-writes inner PHYSICAL count, close; return it.
               (let ((s (%build dir)))
                 (if (eq kind :keep-all)
                     (dds.durability:store-open s :keep-all)
                     (dds.durability:store-open s :keep-last 2))
                 (dotimes (i 6)
                   (let ((sn (+ 1 (* cyc 6) i)))
                     (dds.durability:store-put s "Enc" g0 sn kh1 :data (%make-small-payload sn))))
                 (prog1 (dds.durability:store-count s nil)
                   (dds.durability:store-close s)))))
      (unwind-protect
           (let ((k 4))
             ;; (1) CROSS-RESTART BOUND (sweep enabled): physical stays D across K restart cycles (not K*D)
             (let ((dir (%encdir "xrs-green")) (counts '()))
               (dotimes (cyc k) (push (%write-session dir cyc :keep-last) counts))
               (setf counts (nreverse counts))
               (%check :xrs-bound (every (lambda (c) (= 2 c)) counts)
                       (format nil "cross-restart: inner physical stays D=2 across K=~d write-close-reopen cycles ~
                               (seed+sweep), got ~s [RED pre-3c accumulates ~~K*D]" k counts))
               (let ((s (%build dir)))
                 (dds.durability:store-open s :keep-last 2)
                 (%check :xrs-bound-newest (equal '(23 24) (%sns (dds.durability:store-get-range s "Enc")))
                         (format nil "post-sweep get-range = newest D of the last cycle (23 24) byte-order, got ~s"
                                 (%sns (dds.durability:store-get-range s "Enc"))))
                 (%check :xrs-bound-exact
                         (equalp (%make-small-payload 24)
                                 (dds.durability:durable-record-payload
                                  (find 24 (dds.durability:store-get-range s "Enc")
                                        :key #'dds.durability:durable-record-sn)))
                         "post-sweep survivor payload decrypts byte-exact (no data loss)")
                 (dds.durability:store-close s)))
             ;; (2) RED PROOF + SWEEP RECLAIM — sweep-disabled accumulates ~K*D; re-enabling reclaims to D
             (let ((dir (%encdir "xrs-red")) (counts '()))
               (let ((dds.durability::*durability-debug-disable-open-sweep* t))
                 (dotimes (cyc k) (push (%write-session dir cyc :keep-last) counts)))
               (setf counts (nreverse counts))
               (%check :xrs-red-grows (and (= 2 (first counts)) (apply #'< counts))
                       (format nil "RED (sweep-disabled): physical STRICTLY ACCUMULATES across restarts toward K*D=~d ~
                               (pre-3c leak), got ~s" (* 2 k) counts))
               (let ((s (%build dir)))
                 (dds.durability:store-open s :keep-last 2)   ; sweep ENABLED -> reclaim the accumulated leak
                 (%check :xrs-reclaim (= 2 (dds.durability:store-count s nil))
                         (format nil "the open-sweep RECLAIMS a leaked (pre-3c) store of ~d rows down to D=2, got ~d"
                                 (car (last counts)) (dds.durability:store-count s nil)))
                 (%check :xrs-reclaim-newest (equal '(23 24) (%sns (dds.durability:store-get-range s "Enc")))
                         (format nil "post-reclaim get-range = newest D by real SN (23 24), got ~s"
                                 (%sns (dds.durability:store-get-range s "Enc"))))
                 (dds.durability:store-close s))
               ;; (4) CHAIN + (5) IDEMPOTENT — reopen-after-sweep verifies clean; a 2nd already-swept reopen churns nothing
               (let* ((s2 (%build dir))
                      (clean (handler-case (progn (dds.durability:store-open s2 :keep-last 2) t)
                               (error () nil))))
                 (%check :xrs-chain-clean clean
                         "reopen after the sweep VERIFIES the v3 chain clean (no false-reject; the sweep's store-delete re-MAC is load-bearing)")
                 (when clean
                   (%check :xrs-idem (= 2 (dds.durability:store-count s2 nil))
                           (format nil "idempotent sweep: reopening an already-swept store reclaims nothing (physical stays D=2), got ~d"
                                   (dds.durability:store-count s2 nil))))
                 (ignore-errors (dds.durability:store-close s2))))
             ;; (3) WINDOW-SEEDED post-restart (isolate the seed): continued writes after reopen stay D
             (let ((dir (%encdir "xrs-seed")))
               (%write-session dir 0 :keep-last)              ; session 1: sns 1..6 -> physical D
               (let ((s (%build dir)))
                 (dds.durability:store-open s :keep-last 2)   ; sweep seeds the window with s5,s6
                 (dotimes (i 6)
                   (let ((sn (+ 7 i)))
                     (dds.durability:store-put s "Enc" g0 sn kh1 :data (%make-small-payload sn))))
                 (%check :xrs-seed (= 2 (dds.durability:store-count s nil))
                         (format nil "window-seeded: continued post-restart writes stay bounded to D=2 (no close), got ~d"
                                 (dds.durability:store-count s nil)))
                 (%check :xrs-seed-newest (equal '(11 12) (%sns (dds.durability:store-get-range s "Enc")))
                         (format nil "window-seeded: get-range = newest D (11 12), got ~s"
                                 (%sns (dds.durability:store-get-range s "Enc"))))
                 (dds.durability:store-close s)))
             ;; (3-RED) without the seed the continued post-restart writes LEAK the prior survivors
             (let ((dir (%encdir "xrs-seed-red")))
               (%write-session dir 0 :keep-last)
               (let ((s (%build dir))
                     (dds.durability::*durability-debug-disable-open-sweep* t))
                 (dds.durability:store-open s :keep-last 2)   ; NO sweep -> fresh window is empty
                 (dotimes (i 6)
                   (let ((sn (+ 7 i)))
                     (dds.durability:store-put s "Enc" g0 sn kh1 :data (%make-small-payload sn))))
                 (%check :xrs-seed-red (> (dds.durability:store-count s nil) 2)
                         (format nil "RED (no seed): continued post-restart writes LEAK the prior survivors (physical > D=2), got ~d"
                                 (dds.durability:store-count s nil)))
                 (dds.durability:store-close s)))
             ;; (6) KEEP_ALL reopen runs NO sweep (retains all)
             (let ((dir (%encdir "xrs-keepall")))
               (%write-session dir 0 :keep-all)               ; :keep-all session -> physical N=6
               (let ((s (%build dir)))
                 (dds.durability:store-open s :keep-all)       ; sweep guard: eff-hk :keep-all -> no sweep
                 (%check :xrs-keepall (= 6 (dds.durability:store-count s nil))
                         (format nil "KEEP_ALL reopen runs no sweep (retains all, physical == N=6), got ~d"
                                 (dds.durability:store-count s nil)))
                 (dds.durability:store-close s)))
             ;; (7) MULTI-WRITER CROSS-RESTART — ONE instance (same real key-hash) fed by TWO writer GUIDs
             ;; A<B: the open-sweep GROUPS by real key-hash and keeps the (guid,sn)-newest-D via %win-entry<
             ;; (NOT pure-SN), so the CROSS-RESTART survivors match the logical get-range view EXACTLY.
             ;; Build a >D multi-writer physical state cross-restart (session 1 writes the A samples; a
             ;; sweep-DISABLED session 2 writes the B samples — the fresh empty window never exceeds D so the
             ;; A's LEAK); a sweep-ENABLED session 3 reclaims. All-B sort ABOVE all-A (A.guid<B.guid), so
             ;; %win-entry< keeps B.3,B.6; a pure-SN sweep would WRONGLY keep A.5,B.6 (RED, as the 3a online
             ;; case proved). Locks the sweep's multi-writer grouping cross-restart (the one path not covered
             ;; by the single-writer cases above — otherwise only inherited from the shared %win-entry<).
             (let ((dir (%encdir "xrs-mw"))
                   (ga (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
                   (gb (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref ga 0) 1) (setf (aref gb 0) 2)       ; A.guid < B.guid
               (let ((s (%build dir)))                          ; session 1: A.1, A.5 -> physical D=2
                 (dds.durability:store-open s :keep-last 2)
                 (dds.durability:store-put s "Enc" ga 1 kh1 :data (%make-small-payload 1))
                 (dds.durability:store-put s "Enc" ga 5 kh1 :data (%make-small-payload 5))
                 (dds.durability:store-close s))
               (let ((s (%build dir))                           ; session 2 (sweep DISABLED): B.3, B.6 -> leak A's
                     (dds.durability::*durability-debug-disable-open-sweep* t))
                 (dds.durability:store-open s :keep-last 2)
                 (dds.durability:store-put s "Enc" gb 3 kh1 :data (%make-small-payload 3))
                 (dds.durability:store-put s "Enc" gb 6 kh1 :data (%make-small-payload 6))
                 (%check :xrs-mw-leaked (= 4 (dds.durability:store-count s nil))
                         (format nil "multi-writer >D physical state built cross-restart (A leaked, empty window), got ~d"
                                 (dds.durability:store-count s nil)))
                 (dds.durability:store-close s))
               (let ((s (%build dir)))                          ; session 3 (sweep ENABLED): reclaim to (guid,sn)-newest-D
                 (dds.durability:store-open s :keep-last 2)
                 (%check :xrs-mw-phys (= 2 (dds.durability:store-count s nil))
                         (format nil "multi-writer cross-restart sweep reclaims to physical == D=2, got ~d"
                                 (dds.durability:store-count s nil)))
                 (let ((sig (%gsig (dds.durability:store-get-range s "Enc"))))
                   (%check :xrs-mw-newest (equal sig '((2 . 3) (2 . 6)))
                           (format nil "multi-writer cross-restart sweep keeps the (guid,sn)-newest-D EXACTLY (B.3,B.6) ~
                                   via %win-entry<, NOT pure-SN (which would keep A.5,B.6 = ((1 . 5)(2 . 6))); got ~s" sig)))
                 (%check :xrs-mw-exact
                         (equalp (%make-small-payload 6)
                                 (dds.durability:durable-record-payload
                                  (find 6 (dds.durability:store-get-range s "Enc")
                                        :key #'dds.durability:durable-record-sn)))
                         "multi-writer cross-restart survivor payload (B.6) decrypts byte-exact")
                 (dds.durability:store-close s))))
        (dolist (d dirs)
          (when (uiop:directory-exists-p d)
            (ignore-errors (uiop:delete-directory-tree d :validate t)))))
      t)))

(defun* run-durability-file-encrypted-cross-restart-sweep-test ()
    (function () t)
  "Encrypted FILE CROSS-RESTART physical reclaim (Sliver 3c, WP-DURABILITY-ENCRECLAIM-SWEEP; ADR 0025 §10.3 /
   ADR 0029 §10): the decorator compaction-on-open sweep over a FILE inner store reclaims a prior session's
   <=D leftovers AND seeds the window. Measures BOTH the in-memory physical index (converges to D) and the
   ON-DISK v3 log (bounded <= D+threshold). Closes the encrypted-reclaim cross-restart residual (file).
   (1) CROSS-RESTART BOUND — write 6, close, reopen, x K cycles: in-mem physical stays D=2, NOT ~K*D; the
       on-disk log stays <= D+threshold.
   (2) RED + SWEEP RECLAIM — sweep-disabled accumulates ~K*D (in-mem strictly grows); re-opening WITH the
       sweep reclaims it (in-mem -> D, on-disk -> <= D+threshold).
   (3) WINDOW-SEEDED — after reopen+sweep, continued writes (no close) stay D; RED sweep-disabled = leak.
   (4) NO-LOSS + CHAIN — get-range post-sweep = newest D byte-exact; reopen-after-sweep verifies the chain clean.
   (5) KEEP_ALL — a KEEP_ALL reopen runs no sweep (on-disk == N)."
  (unless (dds.dare:dare-available-p)
    (format t "~&  [file-enc-cross-restart-sweep] SKIP — OpenSSL >= 3.5 not available~%")
    (return-from run-durability-file-encrypted-cross-restart-sweep-test t))
  (let* ((g0  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (kh1 (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xB1))
         (dirs '()))
    (labels ((%dk (tag)
               (let ((d (uiop:pathname-directory-pathname (%sqlite-tmp-db-path (format nil "fxrs-~a-d" tag))))
                     (k (uiop:pathname-directory-pathname (%sqlite-tmp-db-path (format nil "fxrs-~a-k" tag)))))
                 (push d dirs) (push k dirs)
                 (cons d k)))
             (%build (dk)
               (dds.durability:make-encrypted-store
                (dds.durability:make-file-store :dir (car dk))
                (dds.dare:make-file-key-provider :dir (cdr dk))
                :epoch-dir (car dk)))
             (%sns (recs) (sort (mapcar #'dds.durability:durable-record-sn recs) #'<))
             (%gsig (recs) (mapcar (lambda (r) (cons (aref (dds.durability:durable-record-writer-guid r) 0)
                                                     (dds.durability:durable-record-sn r)))
                                   recs))
             (%ondisk (dk) (%enc-file-log-count (car dk) (cdr dk) "Enc"))
             (%write-session (dk cyc kind)
               ;; one restart cycle over the FILE (d . k) dirs: fresh decorator, open, write 6 higher SNs to
               ;; ONE instance, measure the post-writes in-mem PHYSICAL index count, close; return it.
               (let ((s (%build dk)))
                 (if (eq kind :keep-all)
                     (dds.durability:store-open s :keep-all)
                     (dds.durability:store-open s :keep-last 2))
                 (dotimes (i 6)
                   (let ((sn (+ 1 (* cyc 6) i)))
                     (dds.durability:store-put s "Enc" g0 sn kh1 :data (%make-small-payload sn))))
                 (prog1 (dds.durability:store-count s nil)
                   (dds.durability:store-close s)))))
      (unwind-protect
           (let ((dds.durability:*compaction-superseded-threshold* 4)
                 (k 4) (d 2))
             ;; (1) CROSS-RESTART BOUND (sweep enabled): in-mem physical stays D; on-disk <= D+threshold
             (let ((dk (%dk "green")) (counts '()))
               (dotimes (cyc k) (push (%write-session dk cyc :keep-last) counts))
               (setf counts (nreverse counts))
               (%check :fxrs-bound (every (lambda (c) (= d c)) counts)
                       (format nil "file cross-restart: in-mem physical stays D=~d across K=~d cycles (seed+sweep), got ~s"
                               d k counts))
               (let ((s (%build dk)))
                 (dds.durability:store-open s :keep-last d)    ; final reopen -> sweep
                 (%check :fxrs-ondisk (<= (%ondisk dk) (+ d 4))
                         (format nil "file cross-restart: ON-DISK log stays <= D+threshold=~d (physical reclaim), got ~d"
                                 (+ d 4) (%ondisk dk)))
                 (%check :fxrs-bound-newest (equal '(23 24) (%sns (dds.durability:store-get-range s "Enc")))
                         (format nil "post-sweep get-range = newest D (23 24), got ~s"
                                 (%sns (dds.durability:store-get-range s "Enc"))))
                 (%check :fxrs-bound-exact
                         (equalp (%make-small-payload 24)
                                 (dds.durability:durable-record-payload
                                  (find 24 (dds.durability:store-get-range s "Enc")
                                        :key #'dds.durability:durable-record-sn)))
                         "post-sweep survivor payload decrypts byte-exact (no data loss)")
                 (dds.durability:store-close s)))
             ;; (2) RED PROOF + SWEEP RECLAIM
             (let ((dk (%dk "red")) (counts '()))
               (let ((dds.durability::*durability-debug-disable-open-sweep* t))
                 (dotimes (cyc k) (push (%write-session dk cyc :keep-last) counts)))
               (setf counts (nreverse counts))
               (%check :fxrs-red-grows (and (= d (first counts)) (apply #'< counts))
                       (format nil "RED (sweep-disabled): file in-mem physical STRICTLY ACCUMULATES across restarts toward K*D=~d, got ~s"
                               (* d k) counts))
               (let ((s (%build dk)))
                 (dds.durability:store-open s :keep-last d)    ; sweep ENABLED -> reclaim the leak
                 (%check :fxrs-reclaim (= d (dds.durability:store-count s nil))
                         (format nil "the open-sweep reclaims a leaked file store's in-mem index to D=~d, got ~d"
                                 d (dds.durability:store-count s nil)))
                 (%check :fxrs-reclaim-ondisk (<= (%ondisk dk) (+ d 4))
                         (format nil "post-reclaim ON-DISK log <= D+threshold=~d, got ~d" (+ d 4) (%ondisk dk)))
                 (%check :fxrs-reclaim-newest (equal '(23 24) (%sns (dds.durability:store-get-range s "Enc")))
                         (format nil "post-reclaim get-range = newest D (23 24), got ~s"
                                 (%sns (dds.durability:store-get-range s "Enc"))))
                 (dds.durability:store-close s))
               ;; (4) CHAIN — reopen-after-sweep verifies clean
               (let* ((s2 (%build dk))
                      (clean (handler-case (progn (dds.durability:store-open s2 :keep-last d) t)
                               (error () nil))))
                 (%check :fxrs-chain-clean clean
                         "file reopen after the sweep VERIFIES the v3 chain clean (reclaim rewrite re-emitted a fresh chain — no false-reject)")
                 (ignore-errors (dds.durability:store-close s2))))
             ;; (3) WINDOW-SEEDED post-restart (isolate the seed)
             (let ((dk (%dk "seed")))
               (%write-session dk 0 :keep-last)
               (let ((s (%build dk)))
                 (dds.durability:store-open s :keep-last d)    ; sweep seeds window with s5,s6
                 (dotimes (i 6)
                   (let ((sn (+ 7 i)))
                     (dds.durability:store-put s "Enc" g0 sn kh1 :data (%make-small-payload sn))))
                 (%check :fxrs-seed (= d (dds.durability:store-count s nil))
                         (format nil "window-seeded (file): continued post-restart writes stay bounded to D=~d, got ~d"
                                 d (dds.durability:store-count s nil)))
                 (%check :fxrs-seed-newest (equal '(11 12) (%sns (dds.durability:store-get-range s "Enc")))
                         (format nil "window-seeded (file): get-range = newest D (11 12), got ~s"
                                 (%sns (dds.durability:store-get-range s "Enc"))))
                 (dds.durability:store-close s)))
             ;; (3-RED) without the seed the continued writes leak
             (let ((dk (%dk "seed-red")))
               (%write-session dk 0 :keep-last)
               (let ((s (%build dk))
                     (dds.durability::*durability-debug-disable-open-sweep* t))
                 (dds.durability:store-open s :keep-last d)    ; NO sweep -> empty window
                 (dotimes (i 6)
                   (let ((sn (+ 7 i)))
                     (dds.durability:store-put s "Enc" g0 sn kh1 :data (%make-small-payload sn))))
                 (%check :fxrs-seed-red (> (dds.durability:store-count s nil) d)
                         (format nil "RED (no seed, file): continued post-restart writes LEAK (in-mem physical > D=~d), got ~d"
                                 d (dds.durability:store-count s nil)))
                 (dds.durability:store-close s)))
             ;; (5) KEEP_ALL reopen runs NO sweep (on-disk == N)
             (let ((dk (%dk "keepall")))
               (%write-session dk 0 :keep-all)
               (let ((s (%build dk)))
                 (dds.durability:store-open s :keep-all)        ; sweep guard: no sweep
                 (%check :fxrs-keepall (= 6 (%ondisk dk))
                         (format nil "KEEP_ALL reopen runs no sweep (file on-disk == N=6), got ~d" (%ondisk dk)))
                 (dds.durability:store-close s)))
             ;; (6) MULTI-WRITER CROSS-RESTART (file) — ONE instance (same real key-hash) fed by TWO writer
             ;; GUIDs A<B: the open-sweep GROUPS by real key-hash and keeps the (guid,sn)-newest-D via
             ;; %win-entry< (NOT pure-SN), cross-restart. Build a >D multi-writer state (session 1 A samples;
             ;; sweep-DISABLED session 2 B samples leak the A's via the empty window); sweep-ENABLED session 3
             ;; reclaims -> in-mem index == D, on-disk <= D+threshold, get-range == B.3,B.6 (RED pure-SN=A.5,B.6).
             (let ((dk (%dk "mw"))
                   (ga (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
                   (gb (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref ga 0) 1) (setf (aref gb 0) 2)       ; A.guid < B.guid
               (let ((s (%build dk)))                           ; session 1: A.1, A.5
                 (dds.durability:store-open s :keep-last d)
                 (dds.durability:store-put s "Enc" ga 1 kh1 :data (%make-small-payload 1))
                 (dds.durability:store-put s "Enc" ga 5 kh1 :data (%make-small-payload 5))
                 (dds.durability:store-close s))
               (let ((s (%build dk))                            ; session 2 (sweep DISABLED): B.3, B.6 -> leak A's
                     (dds.durability::*durability-debug-disable-open-sweep* t))
                 (dds.durability:store-open s :keep-last d)
                 (dds.durability:store-put s "Enc" gb 3 kh1 :data (%make-small-payload 3))
                 (dds.durability:store-put s "Enc" gb 6 kh1 :data (%make-small-payload 6))
                 (%check :fxrs-mw-leaked (= 4 (dds.durability:store-count s nil))
                         (format nil "file multi-writer >D state built cross-restart (A leaked), got ~d"
                                 (dds.durability:store-count s nil)))
                 (dds.durability:store-close s))
               (let ((s (%build dk)))                           ; session 3 (sweep ENABLED): reclaim
                 (dds.durability:store-open s :keep-last d)
                 (%check :fxrs-mw-phys (= d (dds.durability:store-count s nil))
                         (format nil "file multi-writer cross-restart sweep reclaims in-mem index to D=~d, got ~d"
                                 d (dds.durability:store-count s nil)))
                 (%check :fxrs-mw-ondisk (<= (%ondisk dk) (+ d 4))
                         (format nil "file multi-writer cross-restart on-disk <= D+threshold=~d, got ~d" (+ d 4) (%ondisk dk)))
                 (let ((sig (%gsig (dds.durability:store-get-range s "Enc"))))
                   (%check :fxrs-mw-newest (equal sig '((2 . 3) (2 . 6)))
                           (format nil "file multi-writer cross-restart sweep keeps the (guid,sn)-newest-D EXACTLY ~
                                   (B.3,B.6) via %win-entry<, NOT pure-SN (A.5,B.6); got ~s" sig)))
                 (%check :fxrs-mw-exact
                         (equalp (%make-small-payload 6)
                                 (dds.durability:durable-record-payload
                                  (find 6 (dds.durability:store-get-range s "Enc")
                                        :key #'dds.durability:durable-record-sn)))
                         "file multi-writer cross-restart survivor payload (B.6) decrypts byte-exact")
                 (dds.durability:store-close s))))
        (dolist (d dirs)
          (when (uiop:directory-exists-p d)
            (ignore-errors (uiop:delete-directory-tree d :validate t)))))
      t)))

(defun* run-durability-file-threshold-compaction-test ()
    (function () t)
  "Runtime threshold compaction in the FILE store (WP-DURABILITY-COMPACTION-FILE, Sliver 2, ADR 0029 §10):
   (A) BOUNDED GROWTH — a continuously-open :keep-last D file store, N=40 same-instance puts, NO close:
       the ON-DISK log record count stays BOUNDED (<= D + threshold), NOT N (RED pre-Sliver-2 = 40); the
       in-memory index is likewise bounded; the newest D by SN survive byte-exact.
   (B) BOUNDARY — writing to a rewrite boundary leaves get-range = EXACTLY the newest D byte-exact
       (a freshly-compacted read) and the on-disk log rewritten to exactly D.
   (C) BELOW THRESHOLD — fewer than the first trigger's supersedes ⇒ NO mid-run rewrite (all raw frames
       still on disk); BUT get-range + per-topic count return the LOGICAL newest-D view (exactly D),
       matching memory / SQLite / encrypted (cross-backend consistency; RED pre-fix = 5).
   (D) KEEP_ALL — no threshold compaction (on-disk grows to N).
   (E) TWO INSTANCES — the shared per-topic threshold bounds the whole topic; each instance keeps its
       newest D byte-exact (no loss)."
  (let* ((g0  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (kh1 (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xB1))
         (kh2 (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xC2))
         (p   (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b)))
         (dirs '()))
    (labels ((%d (tag) (let ((d (%file-store-tmp-dir tag))) (push d dirs) d)))
      (unwind-protect
           (let ((dds.durability:*compaction-superseded-threshold* 4)
                 (d 2))
             ;; (A) bounded growth to <= D + threshold WITHOUT reopen; newest D byte-exact
             (let* ((dir (%d "bnd"))
                    (s   (dds.durability:make-file-store :dir dir)))
               (dds.durability:store-open s :keep-last d)
               (dotimes (i 40)
                 (dds.durability:store-put s "T" g0 (1+ i) kh1 :data (funcall p (list (1+ i)))))
               (let ((on-disk (%file-store-log-count dir "T")))
                 (%check :fsc-bounded (<= on-disk (+ d 4))
                         (format nil "on-disk log must stay <= D+threshold=~d (compacts mid-run), got ~d"
                                 (+ d 4) on-disk))
                 (%check :fsc-not-unbounded (< on-disk 40)
                         (format nil "on-disk log must be << N=40 (RED pre-Sliver-2 = 40), got ~d" on-disk)))
               (%check :fsc-count-bounded (<= (dds.durability:store-count s "T") (+ d 4))
                       (format nil "in-memory index bounded to <= D+threshold, got ~d"
                               (dds.durability:store-count s "T")))
               (let* ((recs   (dds.durability:store-get-range s "T"))
                      (newest (subseq (sort (copy-list recs) #'>
                                            :key #'dds.durability:durable-record-sn)
                                      0 d))
                      (sns    (sort (mapcar #'dds.durability:durable-record-sn newest) #'<)))
                 (%check :fsc-newest-sns (equal '(39 40) sns)
                         (format nil "newest D by SN must be (39 40), got ~s" sns))
                 (%check :fsc-newest-payload
                         (equalp (funcall p '(40))
                                 (dds.durability:durable-record-payload
                                  (find 40 recs :key #'dds.durability:durable-record-sn)))
                         "newest sample payload byte-exact"))
               (dds.durability:store-close s))
             ;; (B) boundary: put 6 triggers a rewrite (D=2, threshold=4) -> get-range = exactly D
             (let* ((dir (%d "exact"))
                    (s   (dds.durability:make-file-store :dir dir)))
               (dds.durability:store-open s :keep-last d)
               (dotimes (i 6)
                 (dds.durability:store-put s "T" g0 (1+ i) kh1 :data (funcall p (list (1+ i)))))
               (let* ((recs (dds.durability:store-get-range s "T"))
                      (sns  (sort (mapcar #'dds.durability:durable-record-sn recs) #'<)))
                 (%check :fsc-boundary-exact (= d (length recs))
                         (format nil "at a rewrite boundary get-range = exactly D=~d, got ~d" d (length recs)))
                 (%check :fsc-boundary-sns (equal '(5 6) sns)
                         (format nil "boundary survivors are the newest D (5 6), got ~s" sns))
                 (%check :fsc-boundary-ondisk (= d (%file-store-log-count dir "T"))
                         (format nil "on-disk log rewritten to exactly D=~d at the boundary, got ~d"
                                 d (%file-store-log-count dir "T"))))
               (dds.durability:store-close s))
             ;; (C) below threshold: 5 puts (3 supersedes < threshold 4) -> NO rewrite, all raw on disk;
             ;; BUT get-range + per-topic count return the LOGICAL newest-D view (exactly D), matching
             ;; memory / SQLite / encrypted (the cross-backend consistency lock — RED pre-fix = 5)
             (let* ((dir (%d "under"))
                    (s   (dds.durability:make-file-store :dir dir)))
               (dds.durability:store-open s :keep-last d)
               (dotimes (i 5)
                 (dds.durability:store-put s "T" g0 (1+ i) kh1 :data (funcall p (list (1+ i)))))
               (%check :fsc-under-norewrite (= 5 (%file-store-log-count dir "T"))
                       (format nil "below-threshold store must NOT rewrite (5 raw frames on disk), got ~d"
                               (%file-store-log-count dir "T")))
               (let* ((recs (dds.durability:store-get-range s "T"))
                      (sns  (sort (mapcar #'dds.durability:durable-record-sn recs) #'<)))
                 (%check :fsc-under-logical-get-range (= d (length recs))
                         (format nil "get-range returns the LOGICAL newest-D view = exactly D=~d ~
                                      (matching memory/SQLite/encrypted; RED pre-fix = 5), got ~d"
                                 d (length recs)))
                 (%check :fsc-under-logical-sns (equal '(4 5) sns)
                         (format nil "logical view is the newest D by SN (4 5), got ~s" sns))
                 (%check :fsc-under-logical-count (= d (dds.durability:store-count s "T"))
                         (format nil "per-topic store-count returns the LOGICAL view = exactly D=~d ~
                                      (RED pre-fix = 5), got ~d" d (dds.durability:store-count s "T")))
                 (%check :fsc-under-newest-payload
                         (equalp (funcall p '(5))
                                 (dds.durability:durable-record-payload
                                  (find 5 recs :key #'dds.durability:durable-record-sn)))
                         "logical view newest payload byte-exact"))
               (dds.durability:store-close s))
             ;; (D) KEEP_ALL: no threshold compaction at all -> on-disk grows to N
             (let* ((dir (%d "all"))
                    (s   (dds.durability:make-file-store :dir dir)))
               (dds.durability:store-open s :keep-all)
               (dotimes (i 20)
                 (dds.durability:store-put s "T" g0 (1+ i) kh1 :data (funcall p (list (1+ i)))))
               (%check :fsc-keepall (= 20 (%file-store-log-count dir "T"))
                       (format nil "KEEP_ALL does NO threshold compaction (20 on disk), got ~d"
                               (%file-store-log-count dir "T")))
               (dds.durability:store-close s))
             ;; (E) two instances: shared per-topic threshold bounds the topic; each keeps its newest D
             (let* ((dir (%d "2inst"))
                    (s   (dds.durability:make-file-store :dir dir)))
               (dds.durability:store-open s :keep-last d)
               (dotimes (i 20)
                 (dds.durability:store-put s "T" g0 (1+ i) kh1 :data (funcall p (list (1+ i)))))
               (dotimes (i 20)
                 (dds.durability:store-put s "T" g0 (+ 101 i) kh2 :data (funcall p (list (mod (+ 101 i) 256)))))
               (%check :fsc-2inst-bounded (<= (%file-store-log-count dir "T") (+ (* 2 d) 4))
                       (format nil "two-instance topic bounded to <= 2D+threshold=~d, got ~d"
                               (+ (* 2 d) 4) (%file-store-log-count dir "T")))
               (let* ((recs (dds.durability:store-get-range s "T"))
                      (k1 (count kh1 recs :key #'dds.durability:durable-record-key-hash :test #'equalp))
                      (k2 (count kh2 recs :key #'dds.durability:durable-record-key-hash :test #'equalp)))
                 (%check :fsc-2inst-each-bounded (and (<= d k1 (+ d 4)) (<= d k2 (+ d 4)))
                         (format nil "each instance bounded [D, D+threshold], got kh1=~d kh2=~d" k1 k2))
                 (%check :fsc-2inst-newest
                         (and (find 20 recs :key #'dds.durability:durable-record-sn)
                              (find 120 recs :key #'dds.durability:durable-record-sn))
                         "each instance retains its newest sample (no loss)"))
               (dds.durability:store-close s)))
        (dolist (d dirs)
          (when (uiop:directory-exists-p d)
            (ignore-errors (uiop:delete-directory-tree d :validate t)))))
      t)))

(defun* run-durability-file-online-chain-test ()
    (function () t)
  "Runtime threshold compaction preserves the v3 MAC chain (Sliver 2, ADR 0045 / 0029 §10): a keyed
   KEEP_LAST file store, continuously open, threshold-compacts MID-RUN — the atomic %rewrite-topic-log
   re-emits a FRESH v3 chain over the survivors AND the running chain state is re-pointed to the new
   tail, so subsequent appends chain correctly and a fresh store REOPENING the same dir VERIFIES clean
   (no false-reject) and returns the newest D byte-exact. Also proves the append fd is re-pointed
   post-rewrite: the newest samples (appended after a mid-run rewrite) are NOT lost to a stale fd."
  (let* ((g0     (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (kh1    (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xD3))
         (p      (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b)))
         (oracle (lambda (data)
                   (let ((out (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11)))
                     (loop for b across data for i from 0
                           do (setf (aref out (mod i 32)) (logand (+ (aref out (mod i 32)) b i 1) #xFF)))
                     out)))
         (dir    (%file-store-tmp-dir "chain")))
    (unwind-protect
         (let ((dds.durability:*compaction-superseded-threshold* 4))
           ;; continuously-open keyed KEEP_LAST 2, threshold 4: 40 same-instance puts -> mid-run rewrites
           (let ((s (dds.durability:make-file-store :dir dir)))
             (dds.durability::store-set-chain-mac-fn s oracle)
             (dds.durability:store-open s :keep-last 2)
             (dotimes (i 40)
               (dds.durability:store-put s "T" g0 (1+ i) kh1 :data (funcall p (list (1+ i)))))
             (%check :fschain-bounded (<= (%file-store-log-count dir "T" oracle) 6)
                     (format nil "keyed online threshold-compact: on-disk bounded <= 6, got ~d"
                             (%file-store-log-count dir "T" oracle)))
             (dds.durability:store-close s))
           ;; reopen a FRESH keyed store on the same dir -> replay MUST verify the chain clean
           (let ((s2 (dds.durability:make-file-store :dir dir))
                 (opened-clean nil))
             (dds.durability::store-set-chain-mac-fn s2 oracle)
             (setf opened-clean
                   (handler-case (progn (dds.durability:store-open s2 :keep-last 2) t)
                     (error (c) (declare (ignore c)) nil)))
             (%check :fschain-reopen-clean opened-clean
                     "mid-run-compacted keyed store REOPENS CLEAN — the rewrite re-emitted a fresh v3 chain + re-pointed the running MAC (no false-reject)")
             (when opened-clean
               (let* ((recs (dds.durability:store-get-range s2 "T"))
                      (sns  (sort (mapcar #'dds.durability:durable-record-sn recs) #'<)))
                 (%check :fschain-reopen-count (= 2 (length recs))
                         (format nil "reopen: exactly D=2 survivors, got ~d" (length recs)))
                 (%check :fschain-reopen-sns (equal '(39 40) sns)
                         (format nil "reopen: survivors are the newest D (39 40) — newest NOT lost to a stale fd, got ~s" sns))
                 (%check :fschain-reopen-payload
                         (equalp (funcall p '(40))
                                 (dds.durability:durable-record-payload
                                  (find 40 recs :key #'dds.durability:durable-record-sn)))
                         "reopen: newest survivor payload byte-exact post mid-run rewrite")))
             (ignore-errors (dds.durability:store-close s2))))
      (when (uiop:directory-exists-p dir)
        (ignore-errors (uiop:delete-directory-tree dir :validate t)))))
  t)

(defun* run-durability-file-crash-consistency-test ()
    (function () t)
  "Crash-consistency of the mid-run atomic %rewrite-topic-log (Sliver 2, ADR 0029 §10): a fault injected
   AFTER the compacted <log>.tmp is written+fsynced but BEFORE the atomic rename (via
   *durability-debug-file-rewrite-fault*) leaves the ORIGINAL log intact (rename is the commit point) —
   so a fresh store REOPENS on a CONSISTENT log, the v3 chain VERIFIES clean, the newest D survive
   (NO data loss), and there is NO false-reject. Proves the mid-run rewrite inherits the tmp+fsync+rename
   atomicity (no new transaction machinery); the orphaned .tmp is discarded on open."
  (let* ((g0     (make-array 16 :element-type '(unsigned-byte 8) :initial-element 9))
         (kh1    (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xE2))
         (p      (lambda (b) (make-array (length b) :element-type '(unsigned-byte 8) :initial-contents b)))
         (oracle (lambda (data)
                   (let ((out (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22)))
                     (loop for b across data for i from 0
                           do (setf (aref out (mod i 32)) (logand (+ (aref out (mod i 32)) b i 1) #xFF)))
                     out)))
         (dir    (%file-store-tmp-dir "crash")))
    (unwind-protect
         (let ((dds.durability:*compaction-superseded-threshold* 4))
           ;; session 1: keyed KEEP_LAST 2; puts 1..5 (no rewrite), then put 6 triggers the mid-run
           ;; rewrite -> FAULT before the rename -> store-put signals; the original 6-frame log survives
           (let ((s (dds.durability:make-file-store :dir dir))
                 (faulted nil))
             (dds.durability::store-set-chain-mac-fn s oracle)
             (dds.durability:store-open s :keep-last 2)
             (dotimes (i 5)
               (dds.durability:store-put s "T" g0 (1+ i) kh1 :data (funcall p (list (1+ i)))))
             (let ((dds.durability::*durability-debug-file-rewrite-fault* t))
               (setf faulted
                     (handler-case
                         (progn (dds.durability:store-put s "T" g0 6 kh1 :data (funcall p '(6))) nil)
                       (error () t))))
             (%check :fscc-faulted faulted
                     "the mid-run rewrite fault must propagate (store-put signals before the rename)")
             ;; close writes topics.map so the keyed seed resolves by topic name on reopen; the log is untouched
             (ignore-errors (dds.durability:store-close s)))
           ;; session 2: fresh keyed store on the same dir -> MUST reopen clean (old log intact + chain OK)
           (let ((s2 (dds.durability:make-file-store :dir dir))
                 (opened-clean nil))
             (dds.durability::store-set-chain-mac-fn s2 oracle)
             (setf opened-clean
                   (handler-case (progn (dds.durability:store-open s2 :keep-last 2) t)
                     (error (c) (declare (ignore c)) nil)))
             (%check :fscc-reopen-clean opened-clean
                     "after a crash BEFORE the rename the store reopens CLEAN — the original log is intact, the chain verifies (no torn log, no false-reject)")
             (when opened-clean
               (let* ((recs (dds.durability:store-get-range s2 "T"))
                      (sns  (sort (mapcar #'dds.durability:durable-record-sn recs) #'<)))
                 (%check :fscc-no-loss (equal '(5 6) sns)
                         (format nil "post-crash on-open compaction keeps the newest D=2 (5 6) — no data loss, got ~s" sns))
                 (%check :fscc-payload
                         (equalp (funcall p '(6))
                                 (dds.durability:durable-record-payload
                                  (find 6 recs :key #'dds.durability:durable-record-sn)))
                         "post-crash newest payload byte-exact")))
             (ignore-errors (dds.durability:store-close s2)))
           ;; session 3: a SECOND reopen is still clean (the recovery on-open rewrite re-emitted a valid
           ;; chain of D) -> no false-reject accumulation
           (let ((s3 (dds.durability:make-file-store :dir dir)))
             (dds.durability::store-set-chain-mac-fn s3 oracle)
             (%check :fscc-reopen-again-clean
                     (handler-case (progn (dds.durability:store-open s3 :keep-last 2) t)
                       (error () nil))
                     "a second reopen is still clean (the recovery rewrite left a valid chain)")
             (ignore-errors (dds.durability:store-close s3))))
      (when (uiop:directory-exists-p dir)
        (ignore-errors (uiop:delete-directory-tree dir :validate t)))))
  t)

(defun* run-durability-store-dir-perms-test ()
    (function () t)
  "B4 (ADR 0026 §10.12): the store dir D is enforced/verified 0700, exactly like the key dir K.
   (1) a fresh store-open creates D at 0700 (drwx------). (2) loosening D to 0755 -> next store-open
   REFUSES (fail-closed). (3) *perms-mode-reader* -> nil (ls unavailable) -> store-open REFUSES."
  (let ((tmp (uiop:merge-pathnames*
              (make-pathname :directory (list :relative (format nil "dds-b4-perms-~a"
                                                                (get-universal-time))))
              (uiop:temporary-directory))))
    (unwind-protect
         (progn
           ;; (1) fresh open creates + enforces 0700
           (let ((s (dds.durability:make-file-store :dir tmp)))
             (dds.durability:store-open s)
             (let ((mode (dds.dare::%ls-mode-string (uiop:ensure-directory-pathname tmp))))
               (%check :b4-created-0700
                       (and mode (>= (length mode) 9)
                            (char= (char mode 4) #\-) (char= (char mode 5) #\-)
                            (char= (char mode 7) #\-) (char= (char mode 8) #\-))
                       (format nil "store dir D must be 0700 after creation; ls mode = ~a" mode)))
             (dds.durability:store-close s))
           ;; (2) loosen D to 0755 -> re-open must refuse (existing dir: verify-only, no re-chmod)
           (uiop:run-program (list "chmod" "755"
                                   (uiop:native-namestring (uiop:ensure-directory-pathname tmp))))
           (let ((s2 (dds.durability:make-file-store :dir tmp)))
             (%check :b4-loose-refuse
                     (handler-case (progn (dds.durability:store-open s2) nil) (error () t))
                     "store-open on a 0755 store dir must signal (fail-closed)"))
           ;; (3) restore 0700, simulate ls unavailable -> refuse (fail-closed on unverifiable)
           (uiop:run-program (list "chmod" "700"
                                   (uiop:native-namestring (uiop:ensure-directory-pathname tmp))))
           (let ((s3 (dds.durability:make-file-store :dir tmp)))
             (%check :b4-unverifiable-refuse
                     (let ((dds.dare::*perms-mode-reader* (constantly nil)))
                       (handler-case (progn (dds.durability:store-open s3) nil) (error () t)))
                     "store-open must signal when perms cannot be verified (fail-closed)")))
      (when (uiop:directory-exists-p tmp)
        (uiop:delete-directory-tree tmp :validate t)))
    t))

(defun* run-durability-process-persistent-refuse-test ()
    (function () t)
  "B1 (ADR 0026 §10.11): a :process-mode PERSISTENT spec FAILS FAST, never silently running the
   in-memory tier. %process-mode-store-conveyable-p is NIL for a persistent/file store, T for the
   in-memory store; on SBCL %start-process-service SIGNALS for a persistent :process spec (before
   any subprocess launch). The in-memory :process path stays conveyable (process-smoke covers it)."
  (let* ((mem-spec (dds.durability:make-service-spec
                    :domain 3 :topics '(("PP" . "ShapeType")) :mode :process :name "pp-mem"))
         (tmp (uiop:merge-pathnames*
               (make-pathname :directory (list :relative (format nil "dds-b1-~a"
                                                                 (get-universal-time))))
               (uiop:temporary-directory)))
         (persist-spec (dds.durability:make-service-spec
                        :domain 3 :topics '(("PP" . "ShapeType")) :mode :process
                        :store (dds.durability:make-persistent-store-factory
                                :dir tmp :key-dir (merge-pathnames "keys/" tmp))
                        :name "pp-persist")))
    (%check :b1-memory-conveyable
            (dds.durability::%process-mode-store-conveyable-p mem-spec)
            "in-memory :process store must be conveyable (T)")
    (%check :b1-persistent-not-conveyable
            (not (dds.durability::%process-mode-store-conveyable-p persist-spec))
            "persistent :process store must NOT be conveyable (NIL) — the fail-fast target")
    ;; SBCL: the subprocess path signals BEFORE launch; Clasp falls to in-thread mode (honors the
    ;; real store), so the refuse assertion is SBCL-only (NFR-PORT).
    (when (eq (dds.pal:pal-impl-name) :sbcl)
      (%check :b1-persistent-process-signals
              (handler-case (progn (dds.durability::%start-process-service persist-spec) nil)
                (error () t))
              "a :process PERSISTENT spec must signal (fail-fast), not launch a degraded subprocess"))
    t))

(defun* run-durability-origins-cap-test ()
    (function () t)
  "B5 (ADR 0024 §10.2 / ADR 0025 §10.2): the collect seen-set caps the number of DISTINCT origin
   GUIDs at *max-collect-origins*, refusing NEW origins at cap (fail-closed) rather than evicting a
   tracked origin's watermark (which would risk double-delivery on a relay replay).
   (1) below cap: distinct new origins are admitted. (2) at cap: a NEW origin is REFUSED
   (%collect-admit-p NIL) but an already-tracked origin is still admitted (no watermark lost).
   (3) re-appearing (never-evicted) origin: its old SNs stay seen-p=T — NO double delivery."
  (let* ((origins (dds.durability::%make-collect-origins))
         (cap 3)
         (mkguid (lambda (b) (make-array 16 :element-type '(unsigned-byte 8) :initial-element b))))
    (let ((dds.durability::*max-collect-origins* cap))
      ;; (1) admit cap distinct origins
      (dotimes (i cap)
        (let ((g (funcall mkguid (+ 10 i))))
          (%check :b5-below-cap-admit
                  (dds.durability::%collect-admit-p origins g)
                  (format nil "origin ~d below cap must be admitted" i))
          (dds.durability::%collect-mark-seen! origins g 1)))
      (%check :b5-at-cap-size
              (= cap (hash-table-count origins))
              (format nil "origins table must hold exactly cap=~d entries" cap))
      ;; (2) a NEW origin at cap is refused; a tracked one is still admitted
      (let ((gnew  (funcall mkguid 99))
            (gknown (funcall mkguid 10)))
        (%check :b5-new-refused-at-cap
                (not (dds.durability::%collect-admit-p origins gnew))
                "a NEW origin at cap must be REFUSED (fail-closed, no eviction)")
        (%check :b5-tracked-still-admitted
                (dds.durability::%collect-admit-p origins gknown)
                "an already-tracked origin must stay admitted at cap (watermark never evicted)")
        (%check :b5-size-unchanged
                (= cap (hash-table-count origins))
                "refusing a new origin must not grow or shrink the table"))
      ;; (3) re-appearing origin: its already-delivered SN stays seen -> no double delivery
      (let ((g0 (funcall mkguid 10)))
        (dds.durability::%collect-mark-seen! origins g0 2)
        (dds.durability::%collect-mark-seen! origins g0 3)
        (%check :b5-no-double-delivery
                (and (dds.durability::%collect-seen-p origins g0 2)
                     (dds.durability::%collect-seen-p origins g0 3))
                "a re-presented already-delivered SN must stay seen (no double delivery under cap policy)")))
    t))

;;; --- WP-DURABILITY-MICROSERVICE-1 (ADR 0050) — PAL TCP + microservice persistence backend ---

(defun* %tms-guid (b)
    (function ((unsigned-byte 8)) (simple-array (unsigned-byte 8) (16)))
  "16-byte writer GUID filled with byte B (test fixture)."
  (make-array 16 :element-type '(unsigned-byte 8) :initial-element b))

(defun* %tms-payload (n seed)
    (function ((integer 0) (unsigned-byte 8)) (simple-array (unsigned-byte 8) (*)))
  "Deterministic N-byte payload keyed by SEED (test fixture; N may be 0 for the empty-payload case)."
  (let ((v (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n v) (setf (aref v i) (logand (+ seed (* i 31)) 255)))))

(defun* %tms-rec= (r topic guid sn kh kind payload)
    (function (dds.durability:durable-record string (simple-array (unsigned-byte 8) (16)) (integer 0)
               (or null (simple-array (unsigned-byte 8) (16)))
               (member :data :dispose :unregister) (simple-array (unsigned-byte 8) (*)))
              t)
  "T iff DURABLE-RECORD R matches every field byte-exactly (topic/guid/sn/key-hash/kind/payload)."
  (and (string= (dds.durability:durable-record-topic r) topic)
       (equalp (dds.durability:durable-record-writer-guid r) guid)
       (= (dds.durability:durable-record-sn r) sn)
       (equalp (dds.durability:durable-record-key-hash r) kh)
       (eq (dds.durability:durable-record-kind r) kind)
       (equalp (dds.durability:durable-record-payload r) payload)))

(defun* run-pal-tcp-loopback-test ()
    (function () t)
  "Part A: the native TCPv4 PAL stream primitives round-trip over loopback — bind port 0, read back the
   ephemeral port, connect, send a buffer, receive it byte-exact (full-frame recv loop), close. Both impls."
  (let ((ln (dds.pal:tcp-listen "127.0.0.1" 0)))
    (unwind-protect
        (let* ((port (dds.pal:tcp-local-port ln))
               (cli (dds.pal:tcp-connect "127.0.0.1" port)))
          (%check :tcp-ephemeral-port (plusp port) "tcp-local-port returned an ephemeral port")
          (unwind-protect
              (let ((srv (dds.pal:tcp-accept ln))
                    (out (octets #xde #xad #xbe #xef #x01 #x02 #x03 #x04)))
                (unwind-protect
                    (progn
                      (dds.pal:tcp-send cli out 8)
                      (let ((in (make-array 8 :element-type '(unsigned-byte 8))))
                        (%check :tcp-recv-len (eql 8 (dds.pal:tcp-recv srv in 8)) "tcp-recv returned full length")
                        (%check :tcp-byte-exact (equalp in out) "tcp round-trip byte-exact")))
                  (dds.pal:tcp-close srv)))
            (dds.pal:tcp-close cli)))
      (dds.pal:tcp-close ln))
    t))

(defun* run-durability-microservice-test ()
    (function () t)
  "The MICROSERVICE slice (ADR 0050): a make-microservice-store client proxies the durable-store vtable
   over TCP to a make-microservice-server holding an inner memory store. Put N records (2 topics, distinct
   guids/sns/kinds/key-hashes, payloads incl. empty + 100KB) -> get-range byte-exact + (guid,sn)-ordered
   -> count(topic)+(nil) -> idempotent re-put no-op -> delete -> close -> server-stop. Both impls."
  (let* ((srv (dds.durability:make-microservice-server :port 0))
         (port (dds.durability:microservice-server-port srv)))
    (unwind-protect
        (let ((s (dds.durability:make-microservice-store :host "127.0.0.1" :port port))
              (g1 (%tms-guid 1)) (g2 (%tms-guid 2)) (g3 (%tms-guid 3))
              (kh9 (%tms-guid 9)) (kh7 (%tms-guid 7)) (kh4 (%tms-guid 4))
              (big (%tms-payload 100000 5))
              (p3 (%tms-payload 3 1)) (p50 (%tms-payload 50 2)) (empty (%tms-payload 0 0)))
          (%check :ms-open (eq t (dds.durability:store-open s)) "client store-open connects + opens")
          ;; distinct guids/sns/kinds/key-hashes; payloads incl. empty + 100KB across 2 topics
          (%check :ms-put-a2 (eq t (dds.durability:store-put s "A" g1 2 kh9 :data p3)) "put A/g1/2")
          (%check :ms-put-a1 (eq t (dds.durability:store-put s "A" g1 1 nil :data empty)) "put A/g1/1 empty")
          (%check :ms-put-a5 (eq t (dds.durability:store-put s "A" g2 5 kh7 :dispose big)) "put A/g2/5 100KB")
          (%check :ms-put-b1 (eq t (dds.durability:store-put s "B" g3 1 nil :unregister p3)) "put B/g3/1")
          (%check :ms-put-b9 (eq t (dds.durability:store-put s "B" g3 9 kh4 :data p50)) "put B/g3/9")
          ;; counts
          (%check :ms-count-a (= 3 (dds.durability:store-count s "A")) "count(A)=3")
          (%check :ms-count-b (= 2 (dds.durability:store-count s "B")) "count(B)=2")
          (%check :ms-count-all (= 5 (dds.durability:store-count s nil)) "count(nil)=5")
          ;; get-range A byte-exact + ordered by (guid,sn): (g1,1) (g1,2) (g2,5)
          (let ((ra (dds.durability:store-get-range s "A")))
            (%check :ms-a-order (equal '(1 2 5) (mapcar #'dds.durability:durable-record-sn ra))
                    "get-range(A) ordered by (guid,sn)")
            (%check :ms-a1-exact (%tms-rec= (first ra)  "A" g1 1 nil   :data    empty) "A/g1/1 byte-exact (empty)")
            (%check :ms-a2-exact (%tms-rec= (second ra) "A" g1 2 kh9   :data    p3)    "A/g1/2 byte-exact")
            (%check :ms-a5-exact (%tms-rec= (third ra)  "A" g2 5 kh7   :dispose big)   "A/g2/5 byte-exact (100KB)"))
          ;; get-range B byte-exact + ordered: (g3,1) (g3,9)
          (let ((rb (dds.durability:store-get-range s "B")))
            (%check :ms-b-order (equal '(1 9) (mapcar #'dds.durability:durable-record-sn rb))
                    "get-range(B) ordered by (guid,sn)")
            (%check :ms-b1-exact (%tms-rec= (first rb)  "B" g3 1 nil :unregister p3)  "B/g3/1 byte-exact")
            (%check :ms-b9-exact (%tms-rec= (second rb) "B" g3 9 kh4 :data       p50) "B/g3/9 byte-exact"))
          ;; topics
          (%check :ms-topics (equal '("A" "B") (sort (copy-list (dds.durability:store-topics s)) #'string<))
                  "topics list")
          ;; idempotent re-put: same (A,g1,1) with a DIFFERENT payload -> T, no double-store, ORIGINAL kept
          (%check :ms-reput-t (eq t (dds.durability:store-put s "A" g1 1 nil :data p50)) "re-put returns T")
          (%check :ms-reput-count (= 3 (dds.durability:store-count s "A")) "re-put does not double-store")
          (%check :ms-reput-orig (= 0 (length (dds.durability:durable-record-payload
                                               (first (dds.durability:store-get-range s "A")))))
                  "re-put is a no-op: the ORIGINAL (empty) payload is retained")
          ;; delete removes a single record
          (%check :ms-delete (eq t (dds.durability:store-delete s "A" g1 2)) "delete A/g1/2 returns T")
          (%check :ms-delete-count (= 2 (dds.durability:store-count s "A")) "count(A)=2 after delete")
          (%check :ms-delete-gone (null (%tms-find (dds.durability:store-get-range s "A") g1 2))
                  "deleted record no longer in get-range")
          (%check :ms-purge (eq t (dds.durability:store-purge s "B")) "purge B returns T")
          (%check :ms-purge-count (= 0 (dds.durability:store-count s "B")) "count(B)=0 after purge")
          (dds.durability:store-close s))
      (dds.durability:microservice-server-stop srv))
    t))

(defun* %tms-find (recs guid sn)
    (function (list (simple-array (unsigned-byte 8) (16)) (integer 0)) t)
  "Find the record in RECS with writer-guid GUID and sequence number SN, or NIL."
  (find-if (lambda (r) (and (equalp (dds.durability:durable-record-writer-guid r) guid)
                            (= (dds.durability:durable-record-sn r) sn)))
           recs))

(defun* run-durability-microservice-large-test ()
    (function () t)
  "Large-payload multi-segment gate (ADR 0050): a >256 KiB record round-trips byte-exact through the
   u32-length-prefixed framing, proving the full-frame tcp-recv loop reassembles a payload split across
   many TCP segments. Both impls."
  (let* ((srv (dds.durability:make-microservice-server :port 0))
         (port (dds.durability:microservice-server-port srv)))
    (unwind-protect
        (let ((s (dds.durability:make-microservice-store :host "127.0.0.1" :port port))
              (g (%tms-guid 42))
              (huge (%tms-payload 500000 17)))     ; 500 KB -> forces multi-segment delivery
          (dds.durability:store-open s)
          (%check :ms-large-put (eq t (dds.durability:store-put s "L" g 7 nil :data huge)) "put 500KB record")
          (let ((r (first (dds.durability:store-get-range s "L"))))
            (%check :ms-large-len (= 500000 (length (dds.durability:durable-record-payload r)))
                    "500KB payload length preserved")
            (%check :ms-large-exact (equalp (dds.durability:durable-record-payload r) huge)
                    "500KB payload byte-exact across TCP segmentation"))
          (dds.durability:store-close s))
      (dds.durability:microservice-server-stop srv))
    t))

(defun* run-durability-microservice-torn-test ()
    (function () t)
  "Torn-read gate (ADR 0050): the server closes mid-session; the client's next op must fail cleanly (a
   MICROSERVICE-STORE-ERROR, no hang, no crash, no garbage) — the full-frame recv returning NIL on
   peer-close surfaces as a clean signalled error. Both impls."
  (let* ((srv (dds.durability:make-microservice-server :port 0))
         (port (dds.durability:microservice-server-port srv))
         (s (dds.durability:make-microservice-store :host "127.0.0.1" :port port)))
    (dds.durability:store-open s)
    (%check :ms-torn-precheck (= 0 (dds.durability:store-count s "A")) "a normal op succeeds before the tear")
    ;; tear the connection down under the client (stop closes the served connection + the listener)
    (dds.durability:microservice-server-stop srv)
    (%check :ms-torn-clean
            (handler-case (progn (dds.durability:store-count s "A") nil)
              (error () t))
            "client op after server stop signals cleanly (no hang/crash)")
    ;; store-close is still safe (best-effort) after the tear
    (%check :ms-torn-close-safe (eq t (ignore-errors (dds.durability:store-close s)))
            "store-close is safe after a torn connection")
    t))

(defun* %tms-bad-topic-frame (bad-bytes)
    (function ((simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Build a raw microservice PURGE request whose topic field carries BAD-BYTES (a malformed-UTF-8 topic),
   bypassing the client encoder (which only emits well-formed UTF-8) — a fuzz fixture."
  (let ((b (dds.durability::%ms-buf)))
    (dds.durability::%ms-put-u16 b (length bad-bytes))
    (dds.durability::%ms-put-bytes b bad-bytes)
    (dds.durability::%ms-frame-message dds.durability::+ms-op-purge+ (dds.durability::%ms-finalize b))))

(defun* run-durability-microservice-fuzz-test ()
    (function () t)
  "Fuzz / survival gate (ADR 0050, the load-bearing network-facing fuzz posture): a malformed-UTF-8 topic
   must raise a clean MICROSERVICE-PROTOCOL-ERROR (Unicode Table 3-7 / RFC 3629 well-formedness) — never
   an uncaught TYPE-ERROR from an out-of-range code-char. (1) The bounds+well-formedness decoder rejects a
   battery of ill-formed sequences and round-trips valid ones. (2) A raw client streams malformed-topic
   frames at the server: each drops THAT connection and the SERVE THREAD SURVIVES — a SUBSEQUENT valid
   client store-open + round-trip succeeds (proving the listener kept accepting). (3) Client-symmetric: a
   malicious server sends a garbled response -> the client op signals MICROSERVICE-STORE-ERROR (not a
   TYPE-ERROR). Both impls."
  ;; (1) the decoder itself: ill-formed -> protocol-error; well-formed multibyte -> exact round-trip
  (dolist (bad (list (octets #xF7 #xBF #xBF #xBF)          ; lead > F4 (> U+10FFFF)
                     (octets #xC0 #x80)                    ; overlong 2-byte
                     (octets #xC1 #xBF)                    ; overlong 2-byte
                     (octets #xED #xA0 #x80)               ; UTF-16 surrogate U+D800
                     (octets #xE0 #x80 #x80)               ; overlong 3-byte
                     (octets #xF0 #x80 #x80 #x80)          ; overlong 4-byte
                     (octets #xF8 #x80 #x80 #x80 #x80)     ; 5-byte lead (invalid)
                     (octets #x80)                         ; standalone continuation
                     (octets #xE2 #x28 #xA1)               ; bad continuation byte
                     (octets #xF4 #x90 #x80 #x80)))        ; F4 90.. -> > U+10FFFF
    (%check :ms-fuzz-utf8-reject
            (eq :caught (handler-case (dds.durability::%ms-utf8->string bad 0 (length bad))
                          (dds.durability::microservice-protocol-error () :caught)))
            "malformed UTF-8 topic raises a clean protocol error (no TYPE-ERROR / crash)"))
  (let ((valid "AZ¿ࠀ\U0001F600"))   ; ASCII + 2/3/4-byte scalars
    (%check :ms-fuzz-utf8-roundtrip
            (string= valid (let ((u (dds.durability::%string->utf8 valid)))
                             (dds.durability::%ms-utf8->string u 0 (length u))))
            "a well-formed multibyte topic round-trips exactly through the validating decoder"))
  ;; (2) SERVER SURVIVAL: raw malformed-topic frames must not kill the listener
  (let* ((srv (dds.durability:make-microservice-server :port 0))
         (port (dds.durability:microservice-server-port srv)))
    (unwind-protect
        (progn
          (dolist (bad (list (octets #xF7 #xBF #xBF #xBF) (octets #xC0 #x80)
                             (octets #xED #xA0 #x80) (octets #xF8 #x80 #x80 #x80 #x80)
                             (octets #x80)))
            (let ((c (dds.pal:tcp-connect "127.0.0.1" port)))
              (unwind-protect
                  (let ((msg (%tms-bad-topic-frame bad))
                        (h (make-array 4 :element-type '(unsigned-byte 8))))
                    (dds.pal:tcp-send c msg (length msg))
                    (%check :ms-fuzz-server-drops (null (dds.pal:tcp-recv c h 4))
                            "server drops the malformed-topic connection (no response)"))
                (ignore-errors (dds.pal:tcp-close c)))))
          ;; the listener survived every attack -> a fresh valid client round-trips
          (let ((s (dds.durability:make-microservice-store :host "127.0.0.1" :port port)))
            (dds.durability:store-open s)
            (%check :ms-fuzz-server-survives
                    (eq t (dds.durability:store-put s "ok" (%tms-guid 1) 1 nil :data (octets 1 2 3)))
                    "SERVE THREAD SURVIVED the malformed topics: a subsequent valid client succeeds")
            (%check :ms-fuzz-server-roundtrip (= 1 (dds.durability:store-count s "ok"))
                    "post-fuzz round-trip intact")
            (dds.durability:store-close s)))
      (dds.durability:microservice-server-stop srv)))
  ;; (3) CLIENT SYMMETRIC: a garbled server response -> microservice-store-error (not TYPE-ERROR)
  (let ((ln (dds.pal:tcp-listen "127.0.0.1" 0)))
    (unwind-protect
        (let* ((port (dds.pal:tcp-local-port ln))
               (th (dds.pal:spawn
                    (lambda ()
                      (ignore-errors
                       (let ((c (dds.pal:tcp-accept ln)))
                         (dds.durability::%ms-recv-message c)          ; drain the open request
                         (let ((r (dds.durability::%ms-frame-message dds.durability::+ms-status-ok+
                                                                     (dds.durability::%ms-empty-payload))))
                           (dds.pal:tcp-send c r (length r)))          ; valid open response
                         (dds.durability::%ms-recv-message c)          ; drain the topics request
                         (let ((b (dds.durability::%ms-buf)))          ; garbled topics response
                           (dds.durability::%ms-put-u32 b 1)
                           (dds.durability::%ms-put-u16 b 4)
                           (dds.durability::%ms-put-bytes b (octets #xF7 #xBF #xBF #xBF))
                           (let ((r (dds.durability::%ms-frame-message dds.durability::+ms-status-ok+
                                                                       (dds.durability::%ms-finalize b))))
                             (dds.pal:tcp-send c r (length r))))
                         (dds.pal:tcp-close c)))))))
          (let ((s (dds.durability:make-microservice-store :host "127.0.0.1" :port port)))
            (dds.durability:store-open s)
            (%check :ms-fuzz-client-clean
                    (eq :store-err (handler-case (progn (dds.durability:store-topics s) :no-error)
                                     (dds.durability:microservice-store-error () :store-err)))
                    "a garbled server response signals microservice-store-error (not a TYPE-ERROR)")
            (ignore-errors (dds.durability:store-close s)))
          (ignore-errors (dds.pal:join th)))
      (ignore-errors (dds.pal:tcp-close ln))))
  t)

;;; --- WP-DURABILITY-MICROSERVICE-2 (ADR 0050 Slice 2; ADR 0021 cap 6 x cap 7) — DARE-wrap compose ---

(defun* %tms-tmp-dir (tag)
    (function (string) pathname)
  "A fresh unique temp directory pathname for one microservice DARE test arm (TAG + time + random)."
  (uiop:merge-pathnames*
   (make-pathname :directory (list :relative (format nil "dds-ms-~a-~a-~a" tag (get-universal-time) (random 1000000))))
   (uiop:temporary-directory)))

(defun* %tms-flatten-store (store)
    (function (dds.durability:durable-store) (simple-array (unsigned-byte 8) (*)))
  "Concatenate EVERY octet the inner STORE physically holds — per record, per topic: the topic name
   UTF-8, the writer-GUID, the sn as 8 little-endian bytes, the key-hash (if any), and the payload — into
   one octet vector so a no-plaintext scan can prove a plaintext needle is ABSENT from all the server
   actually stores (the memory-inner analogue of the 3c on-disk byte scan)."
  (let ((acc (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (flet ((push-bytes (v) (loop for x across v do (vector-push-extend x acc))))
      (dolist (topic (dds.durability:store-topics store))
        (push-bytes (map '(simple-array (unsigned-byte 8) (*)) #'char-code topic))
        (dolist (rec (dds.durability:store-get-range store topic))
          (push-bytes (dds.durability:durable-record-writer-guid rec))
          (let ((sn (dds.durability:durable-record-sn rec))
                (snb (make-array 8 :element-type '(unsigned-byte 8))))
            (dotimes (i 8) (setf (aref snb i) (ldb (byte 8 (* 8 i)) sn)))
            (push-bytes snb))
          (let ((kh (dds.durability:durable-record-key-hash rec)))
            (when kh (push-bytes kh)))
          (push-bytes (dds.durability:durable-record-payload rec)))))
    (coerce acc '(simple-array (unsigned-byte 8) (*)))))

(defun* run-durability-microservice-factory-test ()
    (function () t)
  "Slice-2 FACTORY/CONFIG (ADR 0050; runs REGARDLESS of OpenSSL — the composition is DARE-free at
   construction, per %make-epoch-encrypted-store 'Constructed CLOSED'): make-microservice-store-factory
   returns a 0-arg closure that COMPOSES make-encrypted-store OVER make-microservice-store — the returned
   store is the encrypted decorator (name :encrypted-persistent), NOT the bare :microservice inner — the
   same service-spec :store 0-arg-closure contract as make-sqlite-store-factory."
  (let* ((inner (dds.durability:make-memory-store))
         (srv   (dds.durability:make-microservice-server :port 0 :inner inner))
         (port  (dds.durability:microservice-server-port srv))
         (base  (%tms-tmp-dir "factory"))
         (kdir  (uiop:merge-pathnames* (make-pathname :directory '(:relative "keys")) base)))
    (unwind-protect
        (let ((factory (dds.durability:make-microservice-store-factory
                        :host "127.0.0.1" :port port :epoch-dir base :key-dir kdir)))
          (%check :ms-factory-fn (functionp factory)
                  "make-microservice-store-factory returns a 0-arg closure")
          (let ((store (funcall factory)))
            (%check :ms-factory-store (typep store 'dds.durability:durable-store)
                    "the closure constructs a durable-store")
            (%check :ms-factory-composed
                    (eq :encrypted-persistent (dds.durability::durable-store-name store))
                    "the composition is encrypted-store OVER microservice-store (:encrypted-persistent)")))
      (dds.durability:microservice-server-stop srv)
      (when (uiop:directory-exists-p base) (uiop:delete-directory-tree base :validate t))))
  t)

(defun* run-durability-microservice-dare-test ()
    (function () t)
  "Slice-2 DARE composition proof (ADR 0050; ADR 0021 cap 6 x cap 7): encrypted-store(microservice-store).
   (1) NO PLAINTEXT AT THE SERVER — put a record with plaintext topic \"Square\" + a distinctive
   GUID/SN/payload through the DARE-wrapped client; the remote server's inner store holds ONLY a hex
   topic-hash, a 16-byte GUID surrogate, sn=0, and sealed ciphertext — the topic name, GUID bytes, SN
   bytes, AND payload bytes are ALL ABSENT. RED contrast: a BARE microservice-store (no DARE) leaks all
   four in cleartext. (2) ROUND-TRIP THROUGH DARE — put N over 2 topics with distinct fields; get-range
   recovers the REAL topic/GUID/SN/kind/key-hash/payload byte-exact + (guid,sn)-ordered; idempotent
   re-put no-op; logical count. SKIPs if OpenSSL >= 3.5 is unavailable (the DARE-test pattern)."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [microservice-dare] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-durability-microservice-dare-test t)))
  ;; distinctive plaintext needles (multi-byte, collision-negligible)
  (let ((dguid (make-array 16 :element-type '(unsigned-byte 8)
                           :initial-contents '(#xDE #xAD #xBE #xEF #xCA #xFE #xBA #xBE
                                               #x01 #x23 #x45 #x67 #x89 #xAB #xCD #xEF)))
        (dsn   #x1122334455667788)
        (dpay  (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                    "MICROSERVICE-SLICE2-PLAINTEXT-PAYLOAD-DO-NOT-LEAK"))
        (tneedle (map '(simple-array (unsigned-byte 8) (*)) #'char-code "Square"))
        (snb (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8) (setf (aref snb i) (ldb (byte 8 (* 8 i)) dsn)))
    ;; ---- (1a) GREEN: DARE-wrapped -> the server holds only ciphertext + surrogates ----
    (let* ((inner (dds.durability:make-memory-store))
           (srv   (dds.durability:make-microservice-server :port 0 :inner inner))
           (port  (dds.durability:microservice-server-port srv))
           (base  (%tms-tmp-dir "nopt-green"))
           (kdir  (uiop:merge-pathnames* (make-pathname :directory '(:relative "keys")) base))
           (store (funcall (dds.durability:make-microservice-store-factory
                            :host "127.0.0.1" :port port :epoch-dir base :key-dir kdir))))
      (unwind-protect
          (progn
            (dds.durability:store-open store)
            (%check :ms-dare-put (eq t (dds.durability:store-put store "Square" dguid dsn nil :data dpay))
                    "DARE-wrapped put of the plaintext-topic record")
            (let ((hay (%tms-flatten-store inner)))
              (%check :ms-dare-no-topic   (not (%pst-subseq-present-p hay tneedle))
                      "server holds NO plaintext topic name \"Square\"")
              (%check :ms-dare-no-guid    (not (%pst-subseq-present-p hay dguid))
                      "server holds NO plaintext writer-GUID bytes")
              (%check :ms-dare-no-sn      (not (%pst-subseq-present-p hay snb))
                      "server holds NO plaintext SN bytes (inner sn=0, real sn sealed)")
              (%check :ms-dare-no-payload (not (%pst-subseq-present-p hay dpay))
                      "server holds NO plaintext payload bytes (sealed ciphertext only)"))
            (let ((topics (dds.durability:store-topics inner)))
              (%check :ms-dare-inner-1topic (= 1 (length topics)) "server inner holds exactly one topic")
              (%check :ms-dare-inner-hashed (not (string= "Square" (first topics)))
                      "server inner topic is a hash surrogate, not \"Square\"")
              (let ((rec (first (dds.durability:store-get-range inner (first topics)))))
                (%check :ms-dare-inner-sn0 (= 0 (dds.durability:durable-record-sn rec))
                        "server inner record sn is 0 (the real sn is sealed inside the blob)")
                (%check :ms-dare-inner-surrogate
                        (not (equalp dguid (dds.durability:durable-record-writer-guid rec)))
                        "server inner writer-GUID is a surrogate, not the real GUID"))))
        (ignore-errors (dds.durability:store-close store))
        (dds.durability:microservice-server-stop srv)
        (when (uiop:directory-exists-p base) (uiop:delete-directory-tree base :validate t))))
    ;; ---- (1b) RED: a bare microservice-store (no DARE) LEAKS all four in cleartext ----
    (let* ((inner (dds.durability:make-memory-store))
           (srv   (dds.durability:make-microservice-server :port 0 :inner inner))
           (port  (dds.durability:microservice-server-port srv))
           (store (dds.durability:make-microservice-store :host "127.0.0.1" :port port)))
      (unwind-protect
          (progn
            (dds.durability:store-open store)
            (dds.durability:store-put store "Square" dguid dsn nil :data dpay)
            (let ((hay (%tms-flatten-store inner)))
              (%check :ms-red-topic   (%pst-subseq-present-p hay tneedle)
                      "RED: a bare microservice server DOES hold the plaintext topic \"Square\"")
              (%check :ms-red-guid    (%pst-subseq-present-p hay dguid)
                      "RED: a bare microservice server DOES hold the plaintext writer-GUID")
              (%check :ms-red-sn      (%pst-subseq-present-p hay snb)
                      "RED: a bare microservice server DOES hold the plaintext SN bytes")
              (%check :ms-red-payload (%pst-subseq-present-p hay dpay)
                      "RED: a bare microservice server DOES hold the plaintext payload")))
        (ignore-errors (dds.durability:store-close store))
        (dds.durability:microservice-server-stop srv))))
  ;; ---- (2) ROUND-TRIP THROUGH DARE: encrypted(microservice) == encrypted(memory) behavior ----
  (let* ((inner (dds.durability:make-memory-store))
         (srv   (dds.durability:make-microservice-server :port 0 :inner inner))
         (port  (dds.durability:microservice-server-port srv))
         (base  (%tms-tmp-dir "rt"))
         (kdir  (uiop:merge-pathnames* (make-pathname :directory '(:relative "keys")) base))
         (store (funcall (dds.durability:make-microservice-store-factory
                          :host "127.0.0.1" :port port :epoch-dir base :key-dir kdir))))
    (unwind-protect
        (let ((g1 (%tms-guid 1)) (g2 (%tms-guid 2)) (g3 (%tms-guid 3))
              (kh9 (%tms-guid 9)) (kh7 (%tms-guid 7)) (kh4 (%tms-guid 4))
              (p3 (%tms-payload 3 1)) (p50 (%tms-payload 50 2)) (empty (%tms-payload 0 0))
              (big (%tms-payload 3000 5)))
          (dds.durability:store-open store)
          (%check :ms-rt-put-a2 (eq t (dds.durability:store-put store "Square" g1 2 kh9 :data p3)) "put Square/g1/2")
          (%check :ms-rt-put-a1 (eq t (dds.durability:store-put store "Square" g1 1 nil :data empty)) "put Square/g1/1 empty")
          (%check :ms-rt-put-a5 (eq t (dds.durability:store-put store "Square" g2 5 kh7 :dispose big)) "put Square/g2/5")
          (%check :ms-rt-put-b1 (eq t (dds.durability:store-put store "Circle" g3 1 nil :unregister p3)) "put Circle/g3/1")
          (%check :ms-rt-put-b9 (eq t (dds.durability:store-put store "Circle" g3 9 kh4 :data p50)) "put Circle/g3/9")
          (%check :ms-rt-count-a   (= 3 (dds.durability:store-count store "Square")) "count(Square)=3")
          (%check :ms-rt-count-b   (= 2 (dds.durability:store-count store "Circle")) "count(Circle)=2")
          (%check :ms-rt-count-all (= 5 (dds.durability:store-count store nil)) "count(nil)=5")
          (let ((ra (dds.durability:store-get-range store "Square")))
            (%check :ms-rt-a-order (equal '(1 2 5) (mapcar #'dds.durability:durable-record-sn ra))
                    "get-range(Square) ordered by (guid,sn) through DARE")
            (%check :ms-rt-a1 (%tms-rec= (first ra)  "Square" g1 1 nil :data    empty) "Square/g1/1 byte-exact through DARE")
            (%check :ms-rt-a2 (%tms-rec= (second ra) "Square" g1 2 kh9 :data    p3)    "Square/g1/2 byte-exact through DARE")
            (%check :ms-rt-a5 (%tms-rec= (third ra)  "Square" g2 5 kh7 :dispose big)   "Square/g2/5 byte-exact through DARE"))
          (let ((rb (dds.durability:store-get-range store "Circle")))
            (%check :ms-rt-b-order (equal '(1 9) (mapcar #'dds.durability:durable-record-sn rb))
                    "get-range(Circle) ordered by (guid,sn) through DARE")
            (%check :ms-rt-b1 (%tms-rec= (first rb)  "Circle" g3 1 nil :unregister p3)  "Circle/g3/1 byte-exact through DARE")
            (%check :ms-rt-b9 (%tms-rec= (second rb) "Circle" g3 9 kh4 :data       p50) "Circle/g3/9 byte-exact through DARE"))
          (%check :ms-rt-topics (equal '("Circle" "Square")
                                       (sort (copy-list (dds.durability:store-topics store)) #'string<))
                  "topics list through DARE")
          ;; idempotent re-put: same (Square,g1,1) with a DIFFERENT payload -> T, no double-store, original kept
          (%check :ms-rt-reput (eq t (dds.durability:store-put store "Square" g1 1 nil :data p50)) "re-put returns T")
          (%check :ms-rt-reput-count (= 3 (dds.durability:store-count store "Square")) "re-put does not double-store")
          (%check :ms-rt-reput-orig (= 0 (length (dds.durability:durable-record-payload
                                                  (first (dds.durability:store-get-range store "Square")))))
                  "re-put is a no-op: the ORIGINAL (empty) payload is retained through DARE"))
      (ignore-errors (dds.durability:store-close store))
      (dds.durability:microservice-server-stop srv)
      (when (uiop:directory-exists-p base) (uiop:delete-directory-tree base :validate t))))
  t)

;;; --- WP-DURABILITY-MICROSERVICE-3A (ADR 0050 Slice 3a) — server-owned PERSISTENT inner +
;;;     cross-restart recovery (bare + DARE-wrapped) + server-owned-lifecycle + config-env seam ---

(defun* %tms-put-2topic-fixture (s ta tb)
    (function (dds.durability:durable-store string string) t)
  "Put the shared 5-record / 2-topic cross-restart fixture through client store S: 3 records on topic TA
   (an EMPTY-payload NIL-key :data, a 3-byte :data, a 50-byte :dispose), 2 on TB (an :unregister, a :data)
   — distinct guids/sns/kinds/key-hashes/payloads. The TA/g1/1 record's payload is EMPTY (#()) so the bare
   cross-restart proves a zero-length payload round-trips as a genuine empty (not NULL/absent) through the
   PERSISTENT file + SQLite inners across a restart — no prior test exercised empty->persistent-inner (the
   Slice-1 empty is memory-inner; the DARE arm seals so the inner never sees an empty blob). Reused by the
   bare, DARE-wrapped, and multi-session arms so the recovery assertion is defined once (DRY)."
  (let ((g1 (%tms-guid 1)) (g2 (%tms-guid 2)) (g3 (%tms-guid 3))
        (kh9 (%tms-guid 9)) (kh7 (%tms-guid 7)) (kh4 (%tms-guid 4))
        (empty (%tms-payload 0 0)) (p3 (%tms-payload 3 1)) (p50 (%tms-payload 50 2)))
    (dds.durability:store-put s ta g1 1 nil :data       empty)
    (dds.durability:store-put s ta g1 2 kh9 :data       p3)
    (dds.durability:store-put s ta g2 5 kh7 :dispose    p50)
    (dds.durability:store-put s tb g3 1 nil :unregister p3)
    (dds.durability:store-put s tb g3 9 kh4 :data       p50))
  t)

(defun* %tms-verify-2topic-fixture (s ta tb label)
    (function (dds.durability:durable-store string string string) t)
  "Verify client store S recovered the shared %tms-put-2topic-fixture set byte-exact + (guid,sn)-ordered
   + counted (LABEL names the arm in the check details). The TA/g1/1 record is asserted to recover as a
   genuine EMPTY (#(), zero-length) payload — the empty->persistent-inner cross-restart regression guard."
  (let ((g1 (%tms-guid 1)) (g2 (%tms-guid 2)) (g3 (%tms-guid 3))
        (kh9 (%tms-guid 9)) (kh7 (%tms-guid 7)) (kh4 (%tms-guid 4))
        (empty (%tms-payload 0 0)) (p3 (%tms-payload 3 1)) (p50 (%tms-payload 50 2)))
    (%check :ms-xr-count-all (= 5 (dds.durability:store-count s nil))
            (format nil "~a: recovered count(nil)=5" label))
    (%check :ms-xr-count-a (= 3 (dds.durability:store-count s ta))
            (format nil "~a: recovered count(~a)=3" label ta))
    (%check :ms-xr-count-b (= 2 (dds.durability:store-count s tb))
            (format nil "~a: recovered count(~a)=2" label tb))
    (let ((ra (dds.durability:store-get-range s ta)))
      (%check :ms-xr-a-order (equal '(1 2 5) (mapcar #'dds.durability:durable-record-sn ra))
              (format nil "~a: get-range(~a) ordered by (guid,sn)" label ta))
      (%check :ms-xr-a1-empty (= 0 (length (dds.durability:durable-record-payload (first ra))))
              (format nil "~a: ~a/g1/1 recovered payload is EMPTY (zero-length, not NULL) across restart" label ta))
      (%check :ms-xr-a1 (%tms-rec= (first ra)  ta g1 1 nil :data    empty) (format nil "~a: ~a/g1/1 byte-exact (EMPTY payload)" label ta))
      (%check :ms-xr-a2 (%tms-rec= (second ra) ta g1 2 kh9 :data    p3)  (format nil "~a: ~a/g1/2 byte-exact" label ta))
      (%check :ms-xr-a5 (%tms-rec= (third ra)  ta g2 5 kh7 :dispose p50) (format nil "~a: ~a/g2/5 byte-exact (dispose)" label ta)))
    (let ((rb (dds.durability:store-get-range s tb)))
      (%check :ms-xr-b-order (equal '(1 9) (mapcar #'dds.durability:durable-record-sn rb))
              (format nil "~a: get-range(~a) ordered by (guid,sn)" label tb))
      (%check :ms-xr-b1 (%tms-rec= (first rb)  tb g3 1 nil :unregister p3)  (format nil "~a: ~a/g3/1 byte-exact (unregister)" label tb))
      (%check :ms-xr-b9 (%tms-rec= (second rb) tb g3 9 kh4 :data       p50) (format nil "~a: ~a/g3/9 byte-exact" label tb))))
  t)

(defun* %tms-bare-cross-restart-arm (label make-inner expected2)
    (function (string function (integer 0)) t)
  "One BARE (non-DARE) microservice cross-restart arm (LABEL names it): server1 (inner from MAKE-INNER) +
   a client that puts the 2-topic fixture + client-close + server1-stop (store-close inner -> fsync); then
   server2 (a FRESH inner from MAKE-INNER on the SAME persistent location) + a reconnecting client that
   recovers. EXPECTED2=5 for a persistent file/SQLite inner (full byte-exact recovery, GREEN); EXPECTED2=0
   for the RED memory inner (a fresh empty store, no shared disk). MAKE-INNER is called twice — once per
   server — so a persistent inner rebinds to the same disk while a memory inner is genuinely fresh."
  (let* ((srv1 (dds.durability:make-microservice-server :port 0 :inner (funcall make-inner)))
         (port1 (dds.durability:microservice-server-port srv1)))
    (unwind-protect
        (let ((c (dds.durability:make-microservice-store :host "127.0.0.1" :port port1)))
          (dds.durability:store-open c)
          (%tms-put-2topic-fixture c "A" "B")
          (%check :ms-xr-s1-count (= 5 (dds.durability:store-count c nil))
                  (format nil "~a: server1 collected 5 before restart" label))
          (dds.durability:store-close c))
      (dds.durability:microservice-server-stop srv1))
    ;; server2 on the SAME persistent location (a fresh inner replaying from disk)
    (let* ((srv2 (dds.durability:make-microservice-server :port 0 :inner (funcall make-inner)))
           (port2 (dds.durability:microservice-server-port srv2)))
      (unwind-protect
          (let ((c2 (dds.durability:make-microservice-store :host "127.0.0.1" :port port2)))
            (dds.durability:store-open c2)
            (if (zerop expected2)
                (%check :ms-xr-red (= 0 (dds.durability:store-count c2 nil))
                        (format nil "~a RED: recovers 0 across restart (no persistence)" label))
                (%tms-verify-2topic-fixture c2 "A" "B" label))
            (dds.durability:store-close c2))
        (dds.durability:microservice-server-stop srv2))))
  t)

(defun* run-durability-microservice-cross-restart-test ()
    (function () t)
  "BARE microservice cross-restart (ADR 0050 Slice 3a — the point of the slice): a PERSISTENT file/SQLite
   inner store SURVIVES a server restart. server1 (inner on disk D) collects the client's 5-record/2-topic
   puts + client-close + server1-stop (store-close inner -> fsync); server2 (a FRESH inner on the SAME D)
   REPLAYS from D on start; a client reconnecting to server2 + store-get-range recovers the 5 records
   byte-exact + (guid,sn)-ordered + count. Proven for BOTH a make-file-store inner AND a make-sqlite-store
   inner. RED: a make-memory-store inner (no shared disk) recovers 0 across the restart — proving the
   persistence is real, not an artefact. Both impls (no OpenSSL — bare)."
  (let ((fdir (%tms-tmp-dir "xr-file"))
        (sdir (%tms-tmp-dir "xr-sqlite")))
    (unwind-protect
        (progn
          (%tms-bare-cross-restart-arm
           "file" (lambda () (dds.durability:make-file-store :dir fdir)) 5)
          (%tms-bare-cross-restart-arm
           "sqlite" (lambda () (dds.durability:make-sqlite-store
                                :path (uiop:merge-pathnames*
                                       (make-pathname :name "durability" :type "sqlite3") sdir)))
           5)
          (%tms-bare-cross-restart-arm
           "memory" (lambda () (dds.durability:make-memory-store)) 0))
      (progn
        (when (uiop:directory-exists-p fdir) (uiop:delete-directory-tree fdir :validate t))
        (when (uiop:directory-exists-p sdir) (uiop:delete-directory-tree sdir :validate t)))))
  t)

(defun* run-durability-microservice-dare-cross-restart-test ()
    (function () t)
  "DARE-WRAPPED microservice cross-restart (ADR 0050 Slice 3a): encrypted-store(microservice-store(server
   FILE inner on disk D)) with a CLIENT-LOCAL epoch-dir/key-dir. Run 1: the DARE client seals + puts a
   distinctive record-set (sealed frames -> server1's file inner on D) + close; server1-stop fsyncs the
   OPAQUE sealed frames to D. On-disk scan: D's topic logs are CIPHERTEXT — the plaintext topic/GUID/SN/
   payload needles are ABSENT (the server never saw plaintext across the restart). Run 2: server2 (file
   inner on the SAME D) replays the opaque frames; a client with the SAME LOCAL epoch-dir/key-dir
   store-open + get-range DECRYPTS + recovers the REAL records byte-exact + (guid,sn)-ordered. SKIPs if
   OpenSSL < 3.5 (the DARE-test pattern); the bare cross-restart runs regardless. Both impls."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [microservice-dare-cross-restart] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-durability-microservice-dare-cross-restart-test t)))
  (let* ((sdir  (%tms-tmp-dir "dxr-server"))   ; the SERVER's file inner dir D (opaque sealed frames on disk)
         (cbase (%tms-tmp-dir "dxr-client"))   ; the CLIENT-LOCAL DARE state (epochs.dat + ML-KEM key)
         (kdir  (uiop:merge-pathnames* (make-pathname :directory '(:relative "keys")) cbase))
         ;; high-entropy plaintext needles (collision-negligible) present in the real record, sealed away
         (dguid (make-array 16 :element-type '(unsigned-byte 8)
                            :initial-contents '(#xDE #xAD #xBE #xEF #xCA #xFE #xBA #xBE
                                                #x01 #x23 #x45 #x67 #x89 #xAB #xCD #xEF)))
         (dsn   #x1122334455667788)
         (dpay  (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                     "MS-SLICE3A-XRESTART-PLAINTEXT-PAYLOAD-DO-NOT-LEAK"))
         (tneedle (map '(simple-array (unsigned-byte 8) (*)) #'char-code "Square"))
         (g2 (%tms-guid 2)) (kh7 (%tms-guid 7)) (g3 (%tms-guid 3)) (kh4 (%tms-guid 4))
         (p50 (%tms-payload 50 2)) (p50b (%tms-payload 50 8))
         (snb (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8) (setf (aref snb i) (ldb (byte 8 (* 8 i)) dsn)))
    (unwind-protect
        (progn
          ;; --- run 1: DARE client seals + puts to server1's file inner on D; close; server1-stop (fsync) ---
          (let* ((srv1  (dds.durability:make-microservice-server
                         :port 0 :inner (dds.durability:make-file-store :dir sdir)))
                 (port1 (dds.durability:microservice-server-port srv1)))
            (unwind-protect
                (let ((store (funcall (dds.durability:make-microservice-store-factory
                                       :host "127.0.0.1" :port port1 :epoch-dir cbase :key-dir kdir))))
                  (dds.durability:store-open store)
                  (%check :ms-dxr-put1 (eq t (dds.durability:store-put store "Square" dguid dsn nil :data dpay))
                          "run1: DARE-wrapped put of the needle record")
                  (%check :ms-dxr-put2 (eq t (dds.durability:store-put store "Square" g2 7 kh7 :data p50))
                          "run1: DARE-wrapped put Square/g2/7")
                  (%check :ms-dxr-put3 (eq t (dds.durability:store-put store "Circle" g3 9 kh4 :dispose p50b))
                          "run1: DARE-wrapped put Circle/g3/9 dispose")
                  (dds.durability:store-close store))
              (dds.durability:microservice-server-stop srv1)))
          ;; --- the on-disk frames at the server are CIPHERTEXT: no plaintext needles survive in D's logs ---
          (let ((raw (%pst-read-all-log-bytes (uiop:ensure-directory-pathname sdir))))
            (%check :ms-dxr-ondisk-bytes (plusp (length raw)) "server persisted sealed frame bytes to disk D")
            (%check :ms-dxr-no-topic (not (%pst-subseq-present-p raw tneedle))
                    "on-disk server frames hold NO plaintext topic \"Square\"")
            (%check :ms-dxr-no-guid (not (%pst-subseq-present-p raw dguid))
                    "on-disk server frames hold NO plaintext writer-GUID")
            (%check :ms-dxr-no-sn (not (%pst-subseq-present-p raw snb))
                    "on-disk server frames hold NO plaintext SN bytes (inner sn=0, real sn sealed)")
            (%check :ms-dxr-no-payload (not (%pst-subseq-present-p raw dpay))
                    "on-disk server frames hold NO plaintext payload (sealed ciphertext only)"))
          ;; --- run 2: server2 (file inner on the SAME D) replays opaque; client (SAME epoch-dir) decrypts ---
          (let* ((srv2  (dds.durability:make-microservice-server
                         :port 0 :inner (dds.durability:make-file-store :dir sdir)))
                 (port2 (dds.durability:microservice-server-port srv2)))
            (unwind-protect
                (let ((store2 (funcall (dds.durability:make-microservice-store-factory
                                        :host "127.0.0.1" :port port2 :epoch-dir cbase :key-dir kdir))))
                  (dds.durability:store-open store2)
                  (%check :ms-dxr-count (= 3 (dds.durability:store-count store2 nil))
                          "run2: recovered count(nil)=3 across the restart")
                  (let ((rs (dds.durability:store-get-range store2 "Square")))
                    (%check :ms-dxr-sq-order (equal '(7 #x1122334455667788)
                                                    (mapcar #'dds.durability:durable-record-sn rs))
                            "run2: get-range(Square) ordered by (guid,sn) — g2 before dguid")
                    (%check :ms-dxr-sq-g2 (%tms-rec= (first rs)  "Square" g2 7 kh7 :data p50)
                            "run2: Square/g2/7 byte-exact through DARE + restart")
                    (%check :ms-dxr-sq-needle (%tms-rec= (second rs) "Square" dguid dsn nil :data dpay)
                            "run2: the needle record recovers REAL topic/GUID/SN/payload byte-exact"))
                  (let ((rc (dds.durability:store-get-range store2 "Circle")))
                    (%check :ms-dxr-ci (%tms-rec= (first rc) "Circle" g3 9 kh4 :dispose p50b)
                            "run2: Circle/g3/9 byte-exact (dispose kind round-trips through DARE + restart)"))
                  (dds.durability:store-close store2))
              (dds.durability:microservice-server-stop srv2))))
      (progn
        (when (uiop:directory-exists-p sdir) (uiop:delete-directory-tree sdir :validate t))
        (when (uiop:directory-exists-p cbase) (uiop:delete-directory-tree cbase :validate t)))))
  t)

(defun* run-durability-microservice-remote-chain-test ()
    (function () t)
  "WP-DURABILITY-MICROSERVICE-3B (ADR 0050 §4.3; ADR 0045 log-MAC chain; ADR 0021 cap 6): the client-side
   v3 chain-MAC over the REMOTE microservice tier makes a malicious/compromised server's DROP / REORDER /
   TAMPER of sealed frames DETECTED fail-closed on open — file/SQLite tamper-evidence parity, with the
   server + wire protocol UNCHANGED (the 32-byte MAC + chain_seq fold into the opaque payload the DARE-blind
   server stores/returns verbatim). Arms (DARE-wrapped, so SKIP if OpenSSL < 3.5):
   (1) MALICIOUS-SERVER DETECTION: put N to a memory inner, close the session, INJECT into the server's
       inner, reopen → the on-open verify FAILS-CLOSED: interior DROP, byte TAMPER, and REORDER each a loud
       error, NOT a silent accept. RED contrast: a BARE microservice-store (no chain) opens CLEAN on the
       same drop (silent data loss) — proving the chain is what detects.
   (2) RESIDUALS (documented, ADR 0050 §4.3 / ADR 0045 §7, = file/SQLite): TAIL-TRUNCATION of a valid
       prefix + WHOLE-TOPIC-DROP each open CLEAN (undetected) — the deferred sealed-anchor residual.
   (3) CLEAN CONTROL + ROUND-TRIP: an untampered reopen SUCCEEDS non-vacuously (all recovered byte-exact,
       the mac stripped transparently, the server's inner holds the folded opaque blob).
   (4) CROSS-RESTART with the chain: a PERSISTENT file inner replays the folded frames across a server
       restart → the reconnecting client re-verifies the chain clean and recovers byte-exact.
   (5) NIL-ORACLE regression: a bare microservice-store (no oracle) round-trips unchanged (Slice 1)."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [microservice-remote-chain] SKIP — OpenSSL >= 3.5 not available: ~a~%"
              (dds.dare:dare-unavailable-reason c))
      (return-from run-durability-microservice-remote-chain-test t)))
  (let ((g0  (%tms-guid 5))
        (pay (lambda (i) (%tms-payload (+ 6 i) (logand (+ 1 i) 255)))))
    (labels
        ((%cseq-of (rec)
           (nth-value 2 (dds.durability::%ms-unfold-payload
                         (dds.durability:durable-record-payload rec))))
         (%topic-of (inner) (first (dds.durability:store-topics inner)))
         (%find-cseq (inner c)
           (find c (dds.durability:store-get-range inner (%topic-of inner)) :key #'%cseq-of))
         (%dare-arm (n inject-fn)
           ;; DARE-wrapped (chained) memory-inner arm: put N to "T"/g0/sn1..N, close the session, run
           ;; INJECT-FN on the server's inner, reopen → (values opened-clean-p recovered-count). The server +
           ;; inner survive the session close (server-owned lifecycle); the local DARE anchor persists in BASE.
           (let* ((inner (dds.durability:make-memory-store))
                  (srv   (dds.durability:make-microservice-server :port 0 :inner inner))
                  (port  (dds.durability:microservice-server-port srv))
                  (base  (%tms-tmp-dir "rchain"))
                  (kdir  (uiop:merge-pathnames* (make-pathname :directory '(:relative "keys")) base)))
             (unwind-protect
                 (progn
                   (let ((s (funcall (dds.durability:make-microservice-store-factory
                                      :host "127.0.0.1" :port port :epoch-dir base :key-dir kdir))))
                     (dds.durability:store-open s)
                     (dotimes (i n) (dds.durability:store-put s "T" g0 (1+ i) nil :data (funcall pay i)))
                     (dds.durability:store-close s))
                   (funcall inject-fn inner)
                   (let ((s2 (funcall (dds.durability:make-microservice-store-factory
                                       :host "127.0.0.1" :port port :epoch-dir base :key-dir kdir))))
                     (handler-case
                         (progn (dds.durability:store-open s2)     ; verify-on-open (fail-closed if tampered)
                                (let ((c (dds.durability:store-count s2 nil)))
                                  (ignore-errors (dds.durability:store-close s2))
                                  (values t c)))
                       (error ()
                         (ignore-errors (dds.durability:store-close s2))
                         (values nil 0)))))
               (progn
                 (dds.durability:microservice-server-stop srv)
                 (when (uiop:directory-exists-p base) (uiop:delete-directory-tree base :validate t)))))))
      ;; ---- (1) MALICIOUS-SERVER DETECTION (chained) — interior DROP / TAMPER / REORDER fail-closed ----
      (multiple-value-bind (clean cnt)
          (%dare-arm 4 (lambda (inner)
                         (let ((v (%find-cseq inner 1)))
                           (dds.durability:store-delete inner (%topic-of inner)
                                                        (dds.durability:durable-record-writer-guid v) 0))))
        (declare (ignore cnt))
        (%check :msrc-detect-drop (not clean)
                "interior DROP at a malicious server FAILS the on-open chain verify (fail-closed)"))
      (multiple-value-bind (clean cnt)
          (%dare-arm 4 (lambda (inner)
                         (let ((p (dds.durability:durable-record-payload (%find-cseq inner 1))))
                           (setf (aref p 0) (logxor (aref p 0) #xFF)))))
        (declare (ignore cnt))
        (%check :msrc-detect-tamper (not clean)
                "byte TAMPER of a stored sealed frame FAILS the on-open chain verify (fail-closed)"))
      (multiple-value-bind (clean cnt)
          (%dare-arm 4 (lambda (inner)
                         (let ((r0 (%find-cseq inner 0)) (r1 (%find-cseq inner 1)))
                           (rotatef (dds.durability:durable-record-payload r0)
                                    (dds.durability:durable-record-payload r1)))))
        (declare (ignore cnt))
        (%check :msrc-detect-reorder (not clean)
                "REORDER (payload/chain_seq swap) FAILS the on-open chain verify (fail-closed)"))
      ;; ---- (1-RED) a BARE microservice-store (no chain) does NOT detect the same drop (silent) ----
      (let* ((inner (dds.durability:make-memory-store))
             (srv   (dds.durability:make-microservice-server :port 0 :inner inner))
             (port  (dds.durability:microservice-server-port srv)))
        (unwind-protect
            (progn
              (let ((s (dds.durability:make-microservice-store :host "127.0.0.1" :port port)))
                (dds.durability:store-open s)
                (dotimes (i 4) (dds.durability:store-put s "T" (%tms-guid (1+ i)) (1+ i) nil :data (funcall pay i)))
                (dds.durability:store-close s))
              (let ((v (find 2 (dds.durability:store-get-range inner "T")
                             :key #'dds.durability:durable-record-sn)))
                (dds.durability:store-delete inner "T" (dds.durability:durable-record-writer-guid v) 2))
              (let ((s2 (dds.durability:make-microservice-store :host "127.0.0.1" :port port)))
                (dds.durability:store-open s2)
                (%check :msrc-red-bare-undetected (= 3 (dds.durability:store-count s2 nil))
                        "RED: a BARE microservice-store (no chain) opens CLEAN on the same drop — 3 of 4 silently lost (chain absent)")
                (dds.durability:store-close s2)))
          (dds.durability:microservice-server-stop srv)))
      ;; ---- (2) RESIDUALS (chained) — tail-truncation + whole-topic-drop open CLEAN (documented) ----
      (multiple-value-bind (clean cnt)
          (%dare-arm 4 (lambda (inner)
                         (let ((tail (first (sort (copy-list (dds.durability:store-get-range inner (%topic-of inner)))
                                                  #'> :key #'%cseq-of))))
                           (dds.durability:store-delete inner (%topic-of inner)
                                                        (dds.durability:durable-record-writer-guid tail) 0))))
        (%check :msrc-residual-tail-truncation (and clean (= 3 cnt))
                "documented residual (ADR 0050 §4.3): tail-truncation of a valid prefix opens CLEAN (3 of 4, undetected)"))
      (multiple-value-bind (clean cnt)
          (%dare-arm 4 (lambda (inner) (dds.durability:store-purge inner (%topic-of inner))))
        (%check :msrc-residual-whole-topic-drop (and clean (= 0 cnt))
                "documented residual (ADR 0050 §4.3): whole-topic-drop opens CLEAN (0 records, unverified)"))
      ;; ---- (3) CLEAN CONTROL (chained) — untampered reopen SUCCEEDS, non-vacuous ----
      (multiple-value-bind (clean cnt) (%dare-arm 4 (lambda (inner) (declare (ignore inner)) nil))
        (%check :msrc-clean-control (and clean (= 4 cnt))
                "non-vacuous control: an untampered chained reopen opens CLEAN with all 4 records (detection is real)"))
      ;; ---- (3-rt) ROUND-TRIP: the chain engages + get-range recovers byte-exact, mac stripped transparently ----
      (let* ((inner (dds.durability:make-memory-store))
             (srv   (dds.durability:make-microservice-server :port 0 :inner inner))
             (port  (dds.durability:microservice-server-port srv))
             (base  (%tms-tmp-dir "rchain-rt"))
             (kdir  (uiop:merge-pathnames* (make-pathname :directory '(:relative "keys")) base)))
        (unwind-protect
            (let ((g1 (%tms-guid 1)) (g2 (%tms-guid 2)) (p1 (%tms-payload 7 1)) (p2 (%tms-payload 9 2)))
              (let ((s (funcall (dds.durability:make-microservice-store-factory
                                 :host "127.0.0.1" :port port :epoch-dir base :key-dir kdir))))
                (dds.durability:store-open s)
                (dds.durability:store-put s "Square" g1 1 nil :data p1)
                (dds.durability:store-put s "Square" g1 2 nil :data p2)
                (dds.durability:store-put s "Circle" g2 1 nil :data p1)
                (dds.durability:store-close s))
              (let ((r (first (dds.durability:store-get-range inner (first (dds.durability:store-topics inner))))))
                (%check :msrc-rt-folded (> (length (dds.durability:durable-record-payload r)) 40)
                        "the server's inner holds the FOLDED opaque payload (sealed ∥ mac ∥ chain_seq, > 40 bytes)"))
              (let ((s2 (funcall (dds.durability:make-microservice-store-factory
                                  :host "127.0.0.1" :port port :epoch-dir base :key-dir kdir))))
                (dds.durability:store-open s2)                    ; re-verifies the chain clean (no error)
                (%check :msrc-rt-count (= 3 (dds.durability:store-count s2 nil)) "round-trip count(nil)=3 through the chain")
                (let ((ra (dds.durability:store-get-range s2 "Square")))
                  (%check :msrc-rt-a (and (= 2 (length ra))
                                          (%tms-rec= (first ra)  "Square" g1 1 nil :data p1)
                                          (%tms-rec= (second ra) "Square" g1 2 nil :data p2))
                          "get-range(Square) byte-exact + (guid,sn)-ordered, mac stripped transparently"))
                (let ((rc (dds.durability:store-get-range s2 "Circle")))
                  (%check :msrc-rt-c (and (= 1 (length rc)) (%tms-rec= (first rc) "Circle" g2 1 nil :data p1))
                          "get-range(Circle) byte-exact through the chain"))
                (dds.durability:store-close s2)))
          (progn
            (dds.durability:microservice-server-stop srv)
            (when (uiop:directory-exists-p base) (uiop:delete-directory-tree base :validate t)))))
      ;; ---- (4) CROSS-RESTART with the chain (PERSISTENT file inner) — verify clean + recover ----
      (let ((sdir  (%tms-tmp-dir "rchain-xr-server"))
            (cbase (%tms-tmp-dir "rchain-xr-client")))
        (unwind-protect
            (let ((kdir (uiop:merge-pathnames* (make-pathname :directory '(:relative "keys")) cbase))
                  (g1 (%tms-guid 3)) (p1 (%tms-payload 11 3)) (p2 (%tms-payload 13 4)))
              (let* ((srv1  (dds.durability:make-microservice-server
                             :port 0 :inner (dds.durability:make-file-store :dir sdir)))
                     (port1 (dds.durability:microservice-server-port srv1)))
                (unwind-protect
                    (let ((s (funcall (dds.durability:make-microservice-store-factory
                                       :host "127.0.0.1" :port port1 :epoch-dir cbase :key-dir kdir))))
                      (dds.durability:store-open s)
                      (dds.durability:store-put s "T" g1 1 nil :data p1)
                      (dds.durability:store-put s "T" g1 2 nil :data p2)
                      (dds.durability:store-close s))
                  (dds.durability:microservice-server-stop srv1)))
              (let* ((srv2  (dds.durability:make-microservice-server
                             :port 0 :inner (dds.durability:make-file-store :dir sdir)))
                     (port2 (dds.durability:microservice-server-port srv2)))
                (unwind-protect
                    (let ((s2 (funcall (dds.durability:make-microservice-store-factory
                                        :host "127.0.0.1" :port port2 :epoch-dir cbase :key-dir kdir))))
                      (dds.durability:store-open s2)               ; re-verifies the folded chain clean across restart
                      (let ((rs (dds.durability:store-get-range s2 "T")))
                        (%check :msrc-xr-recover (and (= 2 (length rs))
                                                      (%tms-rec= (first rs)  "T" g1 1 nil :data p1)
                                                      (%tms-rec= (second rs) "T" g1 2 nil :data p2))
                                "cross-restart: server2 replays folded frames → client re-verifies clean → byte-exact"))
                      (dds.durability:store-close s2))
                  (dds.durability:microservice-server-stop srv2))))
          (progn
            (when (uiop:directory-exists-p sdir) (uiop:delete-directory-tree sdir :validate t))
            (when (uiop:directory-exists-p cbase) (uiop:delete-directory-tree cbase :validate t)))))
      ;; ---- (5) NIL-ORACLE regression: a bare microservice-store round-trips unchanged ----
      (let* ((inner (dds.durability:make-memory-store))
             (srv   (dds.durability:make-microservice-server :port 0 :inner inner))
             (port  (dds.durability:microservice-server-port srv)))
        (unwind-protect
            (let ((s  (dds.durability:make-microservice-store :host "127.0.0.1" :port port))
                  (g1 (%tms-guid 8)) (p1 (%tms-payload 5 1)))
              (dds.durability:store-open s)
              (dds.durability:store-put s "T" g1 1 nil :data p1)
              (dds.durability:store-put s "T" g1 2 nil :data p1)
              (%check :msrc-nil-oracle (= 2 (dds.durability:store-count s nil))
                      "bare microservice-store round-trips (no chain, memory parity)")
              (let ((r (first (dds.durability:store-get-range s "T"))))
                (%check :msrc-nil-bytes (%tms-rec= r "T" g1 1 nil :data p1)
                        "bare store payload byte-exact (no fold)"))
              (dds.durability:store-close s))
          (dds.durability:microservice-server-stop srv)))))
  t)

(defun* run-durability-microservice-lifecycle-test ()
    (function () t)
  "SERVER-OWNED inner lifecycle (ADR 0050 Slice 3a): the inner is opened ONCE at server-start and closed
   ONLY at server-stop — a client connect/disconnect does NOT close/lose it. TWO client SESSIONS against
   ONE server: client1 opens + puts the 5-record fixture + CLOSES; client2 (a FRESH connection) opens +
   get-range SEES client1's records (the shared server-owned inner persisted across the session boundary —
   client-close is session-end, not inner-close); client2 adds one more + closes; client3 sees the
   cumulative 6. A memory inner suffices (the point is the session boundary, not disk). Both impls."
  (let* ((srv (dds.durability:make-microservice-server :port 0 :inner (dds.durability:make-memory-store)))
         (port (dds.durability:microservice-server-port srv)))
    (unwind-protect
        (progn
          (let ((c1 (dds.durability:make-microservice-store :host "127.0.0.1" :port port)))
            (dds.durability:store-open c1)
            (%tms-put-2topic-fixture c1 "A" "B")
            (%check :ms-life-c1 (= 5 (dds.durability:store-count c1 nil)) "client1 session put 5")
            (dds.durability:store-close c1))
          (let ((c2 (dds.durability:make-microservice-store :host "127.0.0.1" :port port)))
            (dds.durability:store-open c2)
            (%check :ms-life-c2-sees (= 5 (dds.durability:store-count c2 nil))
                    "client2 (new session) SEES client1's 5 records — inner not closed on client-close")
            (%tms-verify-2topic-fixture c2 "A" "B" "lifecycle-c2")
            (dds.durability:store-put c2 "A" (%tms-guid 20) 100 nil :data (%tms-payload 4 3))
            (dds.durability:store-close c2))
          (let ((c3 (dds.durability:make-microservice-store :host "127.0.0.1" :port port)))
            (dds.durability:store-open c3)
            (%check :ms-life-c3 (= 6 (dds.durability:store-count c3 nil))
                    "client3 sees the cumulative 6 (5 from c1 + 1 from c2) — one server-owned inner")
            (dds.durability:store-close c3)))
      (dds.durability:microservice-server-stop srv)))
  t)

(defun* run-durability-microservice-config-env-test ()
    (function () t)
  "CONFIG-ENV seam (ADR 0050 Slice 3a): DPERSIST_BACKEND=microservice selects the microservice backend via
   the shared backend dispatch (make-durability-store-factory) that driver-collect / driver-serve call.
   Structural (DARE-free, runs regardless of OpenSSL per the 'Constructed CLOSED' factory contract):
   \"microservice\" -> a 0-arg closure building encrypted-store OVER microservice-store (name
   :encrypted-persistent); \"file\"/\"sqlite\" still select their own factories; the microservice backend
   REQUIRES a remote port (DPERSIST_MS_PORT). Both impls."
  (let* ((base (%tms-tmp-dir "cfgenv"))
         (kdir (uiop:merge-pathnames* (make-pathname :directory '(:relative "keys")) base)))
    (unwind-protect
        (progn
          (let ((f (dds.durability:make-durability-store-factory
                    "microservice" :dir base :key-dir kdir :ms-host "127.0.0.1" :ms-port 65000)))
            (%check :ms-cfg-fn (functionp f) "DPERSIST_BACKEND=microservice -> a 0-arg store factory")
            (let ((store (funcall f)))
              (%check :ms-cfg-composed
                      (eq :encrypted-persistent (dds.durability::durable-store-name store))
                      "microservice backend builds encrypted-store OVER microservice-store (:encrypted-persistent)")))
          (%check :ms-cfg-file (functionp (dds.durability:make-durability-store-factory
                                           "file" :dir base :key-dir kdir))
                  "\"file\" backend still selects a factory")
          (%check :ms-cfg-sqlite (functionp (dds.durability:make-durability-store-factory
                                             "sqlite" :dir base :key-dir kdir))
                  "\"sqlite\" backend still selects a factory")
          (%check :ms-cfg-port-required
                  (eq :err (handler-case
                               (progn (dds.durability:make-durability-store-factory
                                       "microservice" :dir base :key-dir kdir :ms-host "127.0.0.1")
                                      :ok)
                             (error () :err)))
                  "microservice backend without a port signals (DPERSIST_MS_PORT required)"))
      (when (uiop:directory-exists-p base) (uiop:delete-directory-tree base :validate t))))
  t)
