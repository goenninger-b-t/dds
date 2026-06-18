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
  (let ((s1 (dds.durability:make-service-spec :domain 0 :topics '(("Square" . "ShapeType")) :name "shapes"))
        (s2 (dds.durability:make-service-spec :domain 0
              :topics (lambda (topic type) (declare (ignore type)) (eql 0 (search "Sensor" topic))) :name "sensors")))
    (%check :list-hit (dds.durability:service-spec-matches-p s1 "Square" "ShapeType") "list match")
    (%check :list-miss-type (not (dds.durability:service-spec-matches-p s1 "Square" "Other")) "type must match")
    (%check :list-miss-topic (not (dds.durability:service-spec-matches-p s1 "Circle" "ShapeType")) "topic must match")
    (%check :pred-hit (dds.durability:service-spec-matches-p s2 "SensorA" "X") "predicate match")
    (%check :pred-miss (not (dds.durability:service-spec-matches-p s2 "Square" "X")) "predicate miss")
    t))

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
                :domain 7
                :topics '(("Square" . "ShapeType"))
                :store (lambda () svc-store)
                :name "collect-test"))
         (svc (dds.durability:make-durability-service spec :store svc-store))
         ;; publisher node on domain 7, loopback — port 0 = OS-assigned
         (pub-prefix (%make-test-prefix #xC1))
         (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain 7
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
                :domain 17
                :topics '(("Square" . "ShapeType"))
                :store (lambda () svc-store)
                :name "transient-test"))
         (svc (dds.durability:make-durability-service spec :store svc-store))
         (pub-prefix (%make-test-prefix #xD1))
         (pub-node (dds.disc:make-disc-node :guid-prefix pub-prefix :domain 17
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
                    (lj-node (dds.disc:make-disc-node :guid-prefix lj-prefix :domain 17
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
                    (vl-node (dds.disc:make-disc-node :guid-prefix vl-prefix :domain 17
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
                      ;; let discovery + any heartbeats propagate (short window)
                      (%announce-both vl-node svc-node)
                      (sleep 0.3)
                      (loop repeat 20
                            do (%announce-both vl-node svc-node) (sleep 0.05))
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
                    :domain 27
                    :topics '(("Square" . "ShapeType"))
                    :store  (lambda () store-a)
                    :name   "runner-square"))
         (spec-b   (dds.durability:make-service-spec
                    :domain 27
                    :topics '(("Circle" . "ShapeType"))
                    :store  (lambda () store-b)
                    :name   "runner-circle"))
         (runner   (dds.durability:make-service-runner (list spec-a spec-b)))
         ;; Two publisher nodes: one per topic (one-writer-per-node invariant)
         (pub-sq-node (dds.disc:make-disc-node
                       :guid-prefix (%make-test-prefix #xF1) :domain 27
                       :host "127.0.0.1" :port 0 :multicast nil))
         (pub-ci-node (dds.disc:make-disc-node
                       :guid-prefix (%make-test-prefix #xF2) :domain 27
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
                   :domain 37
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
                   :domain 37
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
                :argv '("--domain" "7" "--topic" "Square:ShapeType" "--topic" "Circle:ShapeType")
                :env  '())))
    (%check :cfg-one-spec (= 1 (length specs)) "CLI parse must yield exactly one spec")
    (let ((s (first specs)))
      (%check :cfg-domain (= 7 (dds.durability:service-spec-domain s)) "domain must be 7")
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
                :argv '("--domain" "99")
                :env  '(("DDS_DURABILITY_DOMAIN" . "3")))))
    (%check :cfg-cli-overrides-env (= 99 (dds.durability:service-spec-domain (first specs)))
            "CLI --domain must override env DDS_DURABILITY_DOMAIN"))
  ;; --- --name round-trip: CLI --name surfaced on spec, env DDS_DURABILITY_NAME fallback ---
  (multiple-value-bind (specs-n)
      (dds.durability:parse-durability-config
       :argv '("--name" "my-service" "--domain" "3")
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
                :domain 57
                :topics '(("Square" . "ShapeType") ("Circle" . "ShapeType"))
                :mode :process
                :name "proc-smoke"))
         (argv (dds.durability::%spec->argv spec)))
    (multiple-value-bind (reparsed)
        (dds.durability:parse-durability-config :argv argv :env '())
      (let ((r (first reparsed)))
        (%check :proc-smoke-domain (= 57 (dds.durability:service-spec-domain r))
                "round-tripped spec must have domain 57")
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
                      :domain 57
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
                        :domain 57
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
                  :domain 47
                  :topics '(("LCSquare" . "ShapeType"))
                  :name "lc-runner-a"))
         (spec-b (dds.durability:make-service-spec
                  :domain 47
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
                :domain 47
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
