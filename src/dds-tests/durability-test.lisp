(in-package #:dds.tests)

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
                            (lambda (kind remote)
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
                            (lambda (kind remote)
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
   drain phase and asserts: (1) every relayed DATA carries PID_ORIGINAL_WRITER_INFO; (2) its
   GUID matches the original publisher's GUID; (3) its SN is one of the originals {1..N}."
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
                            (lambda (kind remote)
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
                        ;; must have exactly N OWI entries (one per relayed DATA)
                        (%check :relay-owi-count
                                (= n (length owi-hits))
                                (format nil "expected ~d OWI PIDs in captured datagrams, got ~d"
                                        n (length owi-hits)))
                        ;; every OWI GUID must match the original publisher
                        (%check :relay-owi-guid
                                (every (lambda (pair) (equalp orig-guid (car pair))) owi-hits)
                                (format nil "OWI GUID mismatch — expected ~s, got ~s"
                                        (coerce orig-guid 'list)
                                        (mapcar (lambda (p) (coerce (car p) 'list)) owi-hits)))
                        ;; every OWI SN must be in {1..N}
                        (%check :relay-owi-sn
                                (every (lambda (pair) (<= 1 (cdr pair) n)) owi-hits)
                                (format nil "OWI SN out of range {1..~d}: ~s"
                                        n (mapcar #'cdr owi-hits)))))
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
                   (lambda (kind remote)
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
                            (lambda (kind remote)
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
                            (lambda (kind remote)
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
                            (lambda (kind remote)
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
                            (lambda (kind remote)
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
                                   (lambda (kind remote)
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
                     (lambda (kind remote)
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
                                          (lambda (kind remote)
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
                    (dds.durability:store-open enc-st2)
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
