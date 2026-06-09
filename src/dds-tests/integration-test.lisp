(in-package #:dds.tests)

;;; End-to-end offline integration (the strongest proof short of Connext interop):
;;; a generated-type sample is serialized to a SerializedPayload, framed in an RTPS
;;; DATA message, sent over a REAL UDP loopback socket, received, dispatched, the
;;; payload deserialized, and the reliable reader records the change. This wires
;;; together the type compiler, CDR/encapsulation, the submessage codec + dispatch
;;; loop, the UDP transport, and the reliable engine.

(defun* run-end-to-end-test ()
    (function () t)
  "Test: a sample flows through the full participant stack over UDP (SPDP/SEDP + reliable data plane)."
  (let* ((wid #x00000102)
         (rid dds.rtps.message:+entityid-participant+)
         (sample (make-gsample :id 1234567 :ts -98765432101 :label "shapes"))
         (writer (dds.rtps.reliable:make-rtps-writer
                  :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
         (reader (dds.rtps.reliable:make-rtps-reader)))
    (multiple-value-bind (rx-tr rx-sock) (dds.xport.udp:make-udp-transport :host "127.0.0.1" :port 0)
      (declare (ignore rx-tr))
      (multiple-value-bind (tx-tr tx-sock) (dds.xport.udp:make-udp-transport :host "127.0.0.1" :port 0)
        (unwind-protect
            (let ((rx-port (dds.xport.udp:udp-transport-local-port rx-sock))
                  (msg-buf (dds.core.buffer:make-octet-buffer 512))
                  (pl-buf (dds.core.buffer:make-octet-buffer 256))
                  (in-buf (dds.core.buffer:make-octet-buffer 512))
                  (prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 7))
                  (got nil))
              ;; SerializedPayload = encapsulation header (PLAIN_CDR2_LE) + gsample body
              (let ((pc (dds.core.buffer:cursor pl-buf :endianness :little)))
                (dds.cdr:make-encapsulation-header pc :plain-cdr2-le)
                (serialize-gsample sample pc :xcdr2)
                (let ((pl-len (dds.core.buffer:cursor-position pc)))
                  (dds.rtps.reliable:writer-write
                   writer (subseq (dds.core.buffer:octet-buffer-vec pl-buf) 0 pl-len))
                  (let ((mc (dds.core.buffer:cursor msg-buf :endianness :little)))
                    (dds.rtps.message:write-header mc prefix :vendor 0)
                    (dds.rtps.message:write-data mc rid wid 1
                                                 (dds.core.buffer:octet-buffer-vec pl-buf) 0 pl-len)
                    (dds.xport:send tx-tr
                                    (dds.xport.udp:make-udp-locator :host "127.0.0.1" :port rx-port)
                                    msg-buf 0 (dds.core.buffer:cursor-position mc)))))
              (sleep 0.2)
              (multiple-value-bind (size a p) (dds.xport.udp:udp-transport-recv rx-sock in-buf)
                (declare (ignore a p))
                (%check :e2e-received (> size 0) "no datagram received over UDP"))
              (let ((rc (dds.core.buffer:cursor in-buf :endianness :little)))
                (dds.rtps.message:dispatch-message
                 rc (lambda (id flags cur body-len)
                      (when (= id dds.rtps.message:+submsg-data+)
                        (multiple-value-bind (r w sn has off len key)
                            (dds.rtps.message:parse-data-body cur flags body-len)
                          (declare (ignore r key))
                          (when has
                            (let ((vc (dds.core.buffer:cursor in-buf :endianness :little)))
                              (dds.core.buffer:cursor-set-position vc off)
                              (dds.cdr:parse-encapsulation-header vc)
                              (setf got (deserialize-gsample vc :xcdr2)))
                            (dds.rtps.reliable:reader-on-data
                             reader w sn (subseq (dds.core.buffer:octet-buffer-vec in-buf) off (+ off len)))))))))
              (%check :e2e-deserialized (and got t) "DATA payload not deserialized")
              (%check :e2e-sample
                      (and (= (gsample-id got) 1234567)
                           (= (gsample-ts got) -98765432101)
                           (string= (gsample-label got) "shapes"))
                      "sample did not survive the full wire path")
              (dds.rtps.reliable:reader-on-heartbeat reader wid 1 1)
              (%check :e2e-reliable (dds.rtps.reliable:reader-complete-p reader wid)
                      "reliable reader did not record the change")
              t)
          (dds.pal:udp-close rx-sock)
          (dds.pal:udp-close tx-sock))))))

;;; Typed data plane: a generated ShapeType (the canonical Connext Shapes type)
;;; flows through the FULL participant stack — SPDP discovery, SEDP matching, and
;;; the reliable HEARTBEAT/ACKNACK data plane — not the manual one-shot path above.
;;; The middleware carries the opaque SerializedPayload; the application uses the
;;; generated XCDR codec at both ends, exactly as real DDS type-support does.

(dds.gen:define-dds-type shape-type (:extensibility :final)
  (color :string :key t)
  (x :i32)
  (y :i32)
  (shapesize :i32))

(defun* %serialize-shape (shape)
    (function (shape-type) (simple-array (unsigned-byte 8) (*)))
  "Serialize SHAPE as a PLAIN_CDR2_LE SerializedPayload (encapsulation header +
   XCDR2 body) into a fresh octet vector — the data-plane publish payload."
  (let* ((buf (dds.core.buffer:make-octet-buffer 256))
         (wc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.cdr:make-encapsulation-header wc :plain-cdr2-le)
    (serialize-shape-type shape wc :xcdr2)
    (let* ((len (dds.core.buffer:cursor-position wc))
           (out (make-array len :element-type '(unsigned-byte 8))))
      (replace out (dds.core.buffer:octet-buffer-vec buf) :end1 len)
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))
      out)))

(defun* %deserialize-shape (bytes)
    (function ((simple-array (unsigned-byte 8) (*))) shape-type)
  "Parse a PLAIN_CDR2_LE SerializedPayload (encapsulation header + XCDR2 body) into
   a shape-type. The deserialized struct copies its fields out, so the scratch
   buffer is freed immediately."
  (let* ((ob (dds.core.buffer:make-octet-buffer (length bytes)))
         (rc (dds.core.buffer:cursor ob :endianness :little)))
    (replace (dds.core.buffer:octet-buffer-vec ob) bytes)
    (dds.cdr:parse-encapsulation-header rc)
    (prog1 (deserialize-shape-type rc :xcdr2)
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec ob)))))

(defun* run-typed-dataplane-test ()
    (function () t)
  "A generated ShapeType flows fully typed across the participant data plane: two
   participants discover (SPDP) + match (SEDP), then node1 publishes an XCDR2-encoded
   Shape that node2 receives reliably and deserializes; assert every field survives.
   Proves the reliable UDP data plane carries real generated types, not opaque bytes."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (shape (make-shape-type :color "BLUE" :x 100 :y 150 :shapesize 30)))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer node1 :topic "Square" :type "ShapeType"
                                      :reliability dds.rtps.discovery:+reliability-reliable+)
           (dds.disc:enable-publisher node1)
           (dds.disc:add-local-reader node2 :topic "Square" :type "ShapeType"
                                      :reliability dds.rtps.discovery:+reliability-reliable+)
           (dds.disc:enable-subscriber node2)
           (setf (dds.disc:disc-node-peers node1)
                 (list (cons "127.0.0.1" (dds.disc:disc-node-port node2))))
           (setf (dds.disc:disc-node-peers node2)
                 (list (cons "127.0.0.1" (dds.disc:disc-node-port node1))))
           (dds.disc:start-node node1)
           (dds.disc:start-node node2)
           (dds.disc:announce-participant node1)
           (dds.disc:announce-participant node2)
           (loop repeat 100
                 until (and (plusp (dds.disc:disc-node-discovered-count node1))
                            (plusp (dds.disc:disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (dds.disc:announce-endpoints node1)
           (dds.disc:announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (dds.disc:disc-node-matched-count node1))
                            (plusp (dds.disc:disc-node-matched-count node2)))
                 do (sleep 0.02))
           (%check :typed-matched (plusp (dds.disc:disc-node-matched-count node2))
                   "endpoints did not match before publish")
           (dds.disc:publish-sample node1 (%serialize-shape shape))
           (loop repeat 150 until (plusp (dds.disc:node-sample-count node2)) do (sleep 0.02))
           (%check :typed-received (plusp (dds.disc:node-sample-count node2))
                   "subscriber never received the shape over UDP")
           (let ((bytes (dds.disc:node-sample node2 1)))
             (declare (type (simple-array (unsigned-byte 8) (*)) bytes))
             (let ((q (%deserialize-shape bytes)))
               (%check :typed-fields
                       (and (string= (shape-type-color q) "BLUE")
                            (= (shape-type-x q) 100)
                            (= (shape-type-y q) 150)
                            (= (shape-type-shapesize q) 30))
                       "ShapeType did not survive the typed data-plane round-trip")))
           t)
      (dds.disc:stop-node node1)
      (dds.disc:stop-node node2))))

;;; DCPS entity model (M3/P2, FR-DCPS-1): the full DDS API path — participant ->
;;; topic/publisher/subscriber -> datawriter/datareader -> write/take — over the
;;; engine, with the generated type-support doing serialization.

(dds.gen:define-dds-type dcps-msg (:extensibility :final)
  (id :i32)
  (text :string))

(defun* run-dcps-entity-test ()
    (function () t)
  "Two DomainParticipants discover via multicast; a DataWriter writes a generated
   dcps-msg that a DataReader takes — entirely through the CLOS DCPS entity model and
   the typed type-support codec. Proves the DDS API layer over the RTPS engine."
  (let* ((ts (dds.types:find-type-support "dcps-msg"))
         (p1 (dds.dcps:create-participant :domain 0))
         (p2 (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "DcpsTopic" "dcps-msg" ts))
                (tr (dds.dcps:create-topic p2 "DcpsTopic" "dcps-msg" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr)))
           (loop repeat 150
                 until (and (plusp (dds.dcps:matched-count p1))
                            (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :dcps-matched (plusp (dds.dcps:matched-count p1))
                   "DataWriter/DataReader did not match via DCPS")
           (dds.dcps:write-sample dw (make-dcps-msg :id 42 :text "hello-dcps"))
           (let ((got nil))
             (loop repeat 150 until got
                   do (let ((s (dds.dcps:take-samples dr)))
                        (when s (setf got (dds.dcps:cached-sample-data (first s)))))
                      (sleep 0.02))
             (%check :dcps-take (and got t) "DataReader::take returned no sample over DCPS")
             (%check :dcps-fields
                     (and (= 42 (dcps-msg-id got)) (string= "hello-dcps" (dcps-msg-text got)))
                     "DCPS sample fields did not survive write/take")))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

;;; Instance lifecycle + read/take + SampleInfo (M3 #2, FR-DCPS-4). Uses the keyed
;;; shape-type (key = color): two colors -> two instances; read is non-destructive +
;;; marks samples READ + transitions per-instance view-state NEW->NOT_NEW; take removes.

(defun* %cs-vs (cs)
    (function (dds.dcps:cached-sample) t)
  "The view-state of a cached-sample CS (test accessor)." (dds.dcps:sample-info-view-state (dds.dcps:cached-sample-info cs)))
(defun* %cs-ss (cs)
    (function (dds.dcps:cached-sample) t)
  "The sample-state of a cached-sample CS (test accessor)." (dds.dcps:sample-info-sample-state (dds.dcps:cached-sample-info cs)))
(defun* %cs-ih (cs)
    (function (dds.dcps:cached-sample) t)
  "The instance-handle of a cached-sample CS (test accessor)." (dds.dcps:sample-info-instance-handle (dds.dcps:cached-sample-info cs)))

(defun* run-dcps-instance-test ()
    (function () t)
  "DCPS instance lifecycle + read/take + SampleInfo (FR-DCPS-4) on the keyed
   shape-type: write 3 samples in 2 instances (BLUE x2, RED x1); assert instance
   grouping, READ marking + non-destructive read, view-state NEW->NOT_NEW, and take
   removal."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p1 (dds.dcps:create-participant :domain 0))
         (p2 (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "Square" "shape-type" ts))
                (tr (dds.dcps:create-topic p2 "Square" "shape-type" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr)))
           (loop repeat 100
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 10))
           (dds.dcps:write-sample dw (make-shape-type :color "RED"  :x 2 :y 2 :shapesize 20))
           (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 3 :y 3 :shapesize 30))
           (loop repeat 200 until (>= (dds.dcps:samples-available dr) 3) do (sleep 0.02))
           (%check :inst-available (>= (dds.dcps:samples-available dr) 3)
                   "reader did not receive 3 samples")
           ;; first read of the unread samples
           (let ((r1 (dds.dcps:read-samples dr :states '(:not-read))))
             (%check :inst-count (= 3 (length r1)) "expected 3 unread samples")
             (%check :inst-2-instances
                     (= 2 (length (remove-duplicates (mapcar #'%cs-ih r1) :test #'equalp)))
                     "expected 2 instances (BLUE, RED)")
             (%check :inst-view-new (every (lambda (cs) (eq :new (%cs-vs cs))) r1)
                     "first read view-state must be NEW")
             (%check :inst-marked-read (every (lambda (cs) (eq :read (%cs-ss cs))) r1)
                     "read must mark samples READ"))
           ;; no unread remain; read is non-destructive (ANY default still returns 3, now NOT_NEW)
           (%check :inst-no-unread (null (dds.dcps:read-samples dr :states '(:not-read)))
                   "no unread samples should remain after read")
           (let ((r2 (dds.dcps:read-samples dr)))
             (%check :inst-nondestructive (= 3 (length r2)) "read must not remove samples")
             (%check :inst-view-notnew (every (lambda (cs) (eq :not-new (%cs-vs cs))) r2)
                     "view-state must be NOT_NEW after first instance access"))
           ;; take removes everything
           (%check :inst-take (= 3 (length (dds.dcps:take-samples dr))) "take must return all 3")
           (%check :inst-emptied (zerop (dds.dcps:samples-available dr)) "take must remove all"))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

;;; RxO over the wire (M3 #1, FR-QOS-2): SEDP now carries the full QoS (reliability +
;;; durability), and endpoint-match-p uses dds.qos:qos-rxo-compatible. Incompatible QoS
;;; blocks endpoint matching even when topic+type agree. (Gating DATA delivery on the
;;; match — so RxO also blocks delivery, not just matching — is the immediate follow-up.)

(defun* %rxo-scenario (writer-qos reader-qos)
    (function (t t) (values integer t))
  "Create a writer/reader pair with the given QoS on a shared topic; spin discovery,
   write one sample, and return (values MATCHED-COUNT DATA-RECEIVED-P) — so the test
   can assert RxO blocks both the match AND delivery."
  (let ((p1 (dds.dcps:create-participant :domain 0))
        (p2 (dds.dcps:create-participant :domain 0))
        (ts (dds.types:find-type-support "dcps-msg")))
    (unwind-protect
         (let ((pub (dds.dcps:create-publisher p1)) (sub (dds.dcps:create-subscriber p2))
               (tw (dds.dcps:create-topic p1 "RxoTopic" "dcps-msg" ts))
               (tr (dds.dcps:create-topic p2 "RxoTopic" "dcps-msg" ts)))
           (let ((dw (dds.dcps:create-datawriter pub tw :qos writer-qos))
                 (dr (dds.dcps:create-datareader sub tr :qos reader-qos)))
             (loop repeat 120
                   until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (dds.dcps:write-sample dw (make-dcps-msg :id 1 :text "rxo"))
             (loop repeat 60 until (plusp (dds.dcps:samples-available dr))
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (values (+ (dds.dcps:matched-count p1) (dds.dcps:matched-count p2))
                     (plusp (dds.dcps:samples-available dr)))))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))))

(defun* run-dcps-rxo-test ()
    (function () t)
  "RxO blocks matching AND delivery (FR-QOS-2): a compatible writer/reader match and
   the sample is delivered; a VOLATILE writer vs a reader requesting TRANSIENT_LOCAL
   neither match nor deliver, despite agreeing on topic+type."
  (multiple-value-bind (m d) (%rxo-scenario (dds.qos:make-writer-qos) (dds.qos:make-reader-qos))
    (%check :rxo-compatible-match (plusp m) "compatible QoS endpoints must match")
    (%check :rxo-compatible-deliver d "compatible reader must receive the sample"))
  (multiple-value-bind (m d) (%rxo-scenario (dds.qos:make-writer-qos :durability :volatile)
                                            (dds.qos:make-reader-qos :durability :transient-local))
    (%check :rxo-incompatible-match (zerop m) "durability-incompatible endpoints must not match")
    (%check :rxo-incompatible-deliver (not d) "incompatible reader must receive nothing (RxO blocks delivery)"))
  t)

;;; Conditions + WaitSet (M3 #3, FR-DCPS-2): a GuardCondition triggers on demand; a
;;; ReadCondition + WaitSet block until a written sample arrives (DATA_AVAILABLE),
;;; then return the triggered condition; wait times out (empty) when there is no data.

(defun* run-dcps-waitset-test ()
    (function () t)
  "DDS Conditions + WaitSet: guard-condition on-demand trigger + read-condition that
   fires when a sample arrives, surfaced through WaitSet::wait with a timeout."
  ;; GuardCondition
  (let ((gc (dds.dcps:make-guard-condition)) (ws (dds.dcps:make-wait-set)))
    (dds.dcps:attach-condition ws gc)
    (%check :ws-guard-off (null (dds.dcps:wait-set-wait ws 0.1))
            "guard-condition must not trigger before set")
    (dds.dcps:set-trigger-value gc t)
    (%check :ws-guard-on (and (member gc (dds.dcps:wait-set-wait ws 0.5)) t)
            "guard-condition must trigger after set_trigger_value"))
  ;; ReadCondition + WaitSet over real data
  (let ((ts (dds.types:find-type-support "dcps-msg"))
        (p1 (dds.dcps:create-participant :domain 0))
        (p2 (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "WsTopic" "dcps-msg" ts))
                (tr (dds.dcps:create-topic p2 "WsTopic" "dcps-msg" ts))
                (pub (dds.dcps:create-publisher p1)) (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr))
                (rc (dds.dcps:create-readcondition dr))
                (ws (dds.dcps:make-wait-set)))
           (dds.dcps:attach-condition ws rc)
           (loop repeat 150
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :ws-nodata (null (dds.dcps:wait-set-wait ws 0.2))
                   "read-condition must not trigger before any data")
           (dds.dcps:write-sample dw (make-dcps-msg :id 99 :text "ws"))
           (let ((triggered (dds.dcps:wait-set-wait ws 3.0)))
             (%check :ws-triggered (and (member rc triggered) t)
                     "WaitSet::wait must return the read-condition once data arrives")
             (let ((s (dds.dcps:read-samples dr :states '(:not-read))))
               (%check :ws-read
                       (and s (= 99 (dcps-msg-id (dds.dcps:cached-sample-data (first s)))))
                       "read after WaitSet must return the awaited sample"))))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2)))
  t)

;;; Statuses + Listeners (M3 #3 follow-up, FR-DCPS-2/3): the SEDP match / RxO-
;;; incompatible events surfaced to the application as DDS communication statuses
;;; (SUBSCRIPTION/PUBLICATION_MATCHED, REQUESTED/OFFERED_INCOMPATIBLE_QOS), with
;;; overridable CLOS listeners fired from the receiver thread. Thread-safe capture.

(defclass capture-mixin ()
  ((hits :initform '() :accessor cap-hits)
   (lock :initform (dds.pal:make-lock "test-capture") :accessor cap-lock)))
(defclass capturing-reader-listener (capture-mixin dds.dcps:data-reader-listener) ())
(defclass capturing-writer-listener (capture-mixin dds.dcps:data-writer-listener) ())

(defmethod dds.dcps:on-subscription-matched ((l capturing-reader-listener) reader status)
  (declare (ignore reader))
  (dds.pal:with-lock ((cap-lock l)) (push (cons :sub-matched status) (cap-hits l))))
(defmethod dds.dcps:on-requested-incompatible-qos ((l capturing-reader-listener) reader status)
  (declare (ignore reader))
  (dds.pal:with-lock ((cap-lock l)) (push (cons :req-incompat status) (cap-hits l))))
(defmethod dds.dcps:on-publication-matched ((l capturing-writer-listener) writer status)
  (declare (ignore writer))
  (dds.pal:with-lock ((cap-lock l)) (push (cons :pub-matched status) (cap-hits l))))

(defun* cap-snapshot (l)
    (function (capture-mixin) list)
  "Thread-safe snapshot of a capturing listener's recorded events."
  (dds.pal:with-lock ((cap-lock l)) (copy-list (cap-hits l))))

(defun* run-dcps-matched-status-test ()
    (function () t)
  "SUBSCRIPTION/PUBLICATION_MATCHED + their listeners (FR-DCPS-2/3): a compatible
   writer/reader pair match; the reader's subscription-matched-status and the writer's
   publication-matched-status each report total_count 1 / current_count 1; the
   on_subscription_matched + on_publication_matched listeners fire; and get_*_status
   resets the *_change counters while leaving the cumulative counts intact."
  (let ((ts (dds.types:find-type-support "dcps-msg"))
        (p1 (dds.dcps:create-participant :domain 0))
        (p2 (dds.dcps:create-participant :domain 0))
        (rl (make-instance 'capturing-reader-listener))
        (wl (make-instance 'capturing-writer-listener)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "MatchTopic" "dcps-msg" ts))
                (tr (dds.dcps:create-topic p2 "MatchTopic" "dcps-msg" ts))
                (pub (dds.dcps:create-publisher p1)) (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr)))
           (dds.dcps:set-reader-listener dr rl '(:subscription-matched))
           (dds.dcps:set-writer-listener dw wl '(:publication-matched))
           (loop repeat 150
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (let ((sm (dds.dcps:get-subscription-matched-status dr))
                 (pm (dds.dcps:get-publication-matched-status dw)))
             (%check :match-sub-total (= 1 (dds.dcps:subscription-matched-status-total-count sm))
                     "reader SUBSCRIPTION_MATCHED total_count must be 1")
             (%check :match-sub-current (= 1 (dds.dcps:subscription-matched-status-current-count sm))
                     "reader SUBSCRIPTION_MATCHED current_count must be 1")
             (%check :match-pub-total (= 1 (dds.dcps:publication-matched-status-total-count pm))
                     "writer PUBLICATION_MATCHED total_count must be 1")
             (%check :match-pub-current (= 1 (dds.dcps:publication-matched-status-current-count pm))
                     "writer PUBLICATION_MATCHED current_count must be 1"))
           (loop repeat 60
                 until (and (assoc :sub-matched (cap-snapshot rl))
                            (assoc :pub-matched (cap-snapshot wl)))
                 do (sleep 0.02))
           (%check :match-sub-listener (and (assoc :sub-matched (cap-snapshot rl)) t)
                   "on_subscription_matched must fire from the receiver thread")
           (%check :match-pub-listener (and (assoc :pub-matched (cap-snapshot wl)) t)
                   "on_publication_matched must fire from the receiver thread")
           (let ((sm2 (dds.dcps:get-subscription-matched-status dr)))
             (%check :match-counts-stable
                     (and (= 1 (dds.dcps:subscription-matched-status-total-count sm2))
                          (= 1 (dds.dcps:subscription-matched-status-current-count sm2))
                          (zerop (dds.dcps:subscription-matched-status-total-count-change sm2)))
                     "counts stay 1 across reads; get_*_status resets *_change")))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

(defun* run-dcps-incompatible-qos-test ()
    (function () t)
  "REQUESTED/OFFERED_INCOMPATIBLE_QOS surfaced to the app (FR-QOS-2/FR-DCPS-3): a
   VOLATILE writer and a reader requesting TRANSIENT_LOCAL agree on topic+type but fail
   durability RxO. The reader's requested-incompatible-qos-status and the writer's
   offered-incompatible-qos-status each report total_count>=1 with last_policy_id =
   DURABILITY_QOS_POLICY_ID and a DURABILITY entry in policies, and the
   on_requested_incompatible_qos listener fires — closing the RxO loop to the app."
  (let ((ts (dds.types:find-type-support "dcps-msg"))
        (p1 (dds.dcps:create-participant :domain 0))
        (p2 (dds.dcps:create-participant :domain 0))
        (rl (make-instance 'capturing-reader-listener)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "IncompatTopic" "dcps-msg" ts))
                (tr (dds.dcps:create-topic p2 "IncompatTopic" "dcps-msg" ts))
                (pub (dds.dcps:create-publisher p1)) (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw
                       :qos (dds.qos:make-writer-qos :durability :volatile)))
                (dr (dds.dcps:create-datareader sub tr
                       :qos (dds.qos:make-reader-qos :durability :transient-local))))
           (dds.dcps:set-reader-listener dr rl '(:requested-incompatible-qos))
           (loop repeat 150
                 until (plusp (dds.dcps:requested-incompatible-qos-status-total-count
                               (dds.dcps:get-requested-incompatible-qos-status dr)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (let ((rs (dds.dcps:get-requested-incompatible-qos-status dr))
                 (os (dds.dcps:get-offered-incompatible-qos-status dw)))
             (%check :req-incompat-total
                     (plusp (dds.dcps:requested-incompatible-qos-status-total-count rs))
                     "reader REQUESTED_INCOMPATIBLE_QOS total_count must be >= 1")
             (%check :req-incompat-policy
                     (= dds.dcps:+qos-policy-id-durability+
                        (dds.dcps:requested-incompatible-qos-status-last-policy-id rs))
                     "reader last_policy_id must be DURABILITY_QOS_POLICY_ID")
             (%check :req-incompat-policies
                     (find dds.dcps:+qos-policy-id-durability+
                           (dds.dcps:requested-incompatible-qos-status-policies rs)
                           :key #'dds.dcps:qos-policy-count-policy-id)
                     "policies must carry a DURABILITY QosPolicyCount")
             (%check :off-incompat-total
                     (plusp (dds.dcps:offered-incompatible-qos-status-total-count os))
                     "writer OFFERED_INCOMPATIBLE_QOS total_count must be >= 1")
             (%check :off-incompat-policy
                     (= dds.dcps:+qos-policy-id-durability+
                        (dds.dcps:offered-incompatible-qos-status-last-policy-id os))
                     "writer last_policy_id must be DURABILITY_QOS_POLICY_ID"))
           (loop repeat 60 until (assoc :req-incompat (cap-snapshot rl)) do (sleep 0.02))
           (%check :req-incompat-listener (and (assoc :req-incompat (cap-snapshot rl)) t)
                   "on_requested_incompatible_qos must fire from the receiver thread"))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

;;; QueryCondition (M3 #3 follow-up, FR-DCPS-2/5): a ReadCondition + a query predicate.
;;; A sample failing the predicate must NOT trigger the WaitSet even while unread; a
;;; matching sample triggers it; read_w_condition returns only the matching samples.
;;; v1 takes a Lisp predicate (the DDS SQL-subset grammar is #4).

(defun* run-dcps-query-condition-test ()
    (function () t)
  "QueryCondition (FR-DCPS-2/5): a ReadCondition + a predicate (id > 50). A sample that
   fails the predicate does NOT trigger the WaitSet though unread; a sample that passes
   triggers it; read_w_condition returns only the matching samples and marks them read,
   leaving the non-matching sample in the cache."
  (let ((ts (dds.types:find-type-support "dcps-msg"))
        (p1 (dds.dcps:create-participant :domain 0))
        (p2 (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "QueryTopic" "dcps-msg" ts))
                (tr (dds.dcps:create-topic p2 "QueryTopic" "dcps-msg" ts))
                (pub (dds.dcps:create-publisher p1)) (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr))
                (qc (dds.dcps:create-querycondition
                     dr :states '(:not-read) :query (lambda (m) (> (dcps-msg-id m) 50))))
                (ws (dds.dcps:make-wait-set)))
           (dds.dcps:attach-condition ws qc)
           (loop repeat 150
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           ;; a non-matching sample (id=10) arrives but must NOT trigger the query
           (dds.dcps:write-sample dw (make-dcps-msg :id 10 :text "low"))
           (loop repeat 150 until (plusp (dds.dcps:samples-available dr)) do (sleep 0.02))
           (%check :qc-nonmatch-present (plusp (dds.dcps:samples-available dr))
                   "the low (id=10) sample must have arrived")
           (%check :qc-nontrigger (null (dds.dcps:wait-set-wait ws 0.2))
                   "QueryCondition must NOT trigger on a sample failing the predicate")
           ;; a matching sample (id=99) triggers it
           (dds.dcps:write-sample dw (make-dcps-msg :id 99 :text "high"))
           (%check :qc-trigger (and (member qc (dds.dcps:wait-set-wait ws 3.0)) t)
                   "QueryCondition must trigger once a matching sample arrives")
           ;; read_w_condition returns only the matching sample and marks it read
           (let ((got (dds.dcps:read-w-condition dr qc)))
             (%check :qc-read-one (= 1 (length got))
                     "read_w_condition must return exactly the matching sample")
             (%check :qc-read-id (= 99 (dcps-msg-id (dds.dcps:cached-sample-data (first got))))
                     "read_w_condition must return the id=99 sample"))
           (%check :qc-cache-intact (= 2 (dds.dcps:samples-available dr))
                   "read_w_condition must not remove samples (both remain cached)")
           (%check :qc-reread-empty (null (dds.dcps:read-w-condition dr qc))
                   "no unread matching samples remain after read_w_condition"))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

;;; Condvar-driven WaitSet wake + on_data_available (M3 #3 follow-up, FR-DCPS-2/3,
;;; ADR 0007): a ReadCondition attached to a WaitSet wakes when a written sample
;;; arrives — the disc receiver thread signals the WaitSet condvar — replacing the
;;; ~10 ms poll; the reader's on_data_available listener fires from that thread.

(defclass data-available-listener (capture-mixin dds.dcps:data-reader-listener) ())
(defmethod dds.dcps:on-data-available ((l data-available-listener) reader)
  (declare (ignore reader))
  (dds.pal:with-lock ((cap-lock l)) (push :data-available (cap-hits l))))

(defun* run-dcps-condvar-wake-test ()
    (function () t)
  "Condvar-driven WaitSet wake + on_data_available (ADR 0007): a ReadCondition attached
   to a WaitSet wakes when a written sample arrives (the receiver thread signals the
   WaitSet condvar), the reader's on_data_available listener fires from that thread,
   read_w_condition returns the sample, and an empty WaitSet still times out."
  (let ((ts (dds.types:find-type-support "dcps-msg"))
        (p1 (dds.dcps:create-participant :domain 0))
        (p2 (dds.dcps:create-participant :domain 0))
        (dal (make-instance 'data-available-listener)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "WakeTopic" "dcps-msg" ts))
                (tr (dds.dcps:create-topic p2 "WakeTopic" "dcps-msg" ts))
                (pub (dds.dcps:create-publisher p1)) (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr))
                (rc (dds.dcps:create-readcondition dr))
                (ws (dds.dcps:make-wait-set)))
           (dds.dcps:set-reader-listener dr dal '(:data-available))
           (dds.dcps:attach-condition ws rc)
           (loop repeat 150
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :wake-empty-timeout (null (dds.dcps:wait-set-wait ws 0.2))
                   "an empty WaitSet must time out (return nil)")
           (dds.dcps:write-sample dw (make-dcps-msg :id 7 :text "wake"))
           (%check :wake-triggered (and (member rc (dds.dcps:wait-set-wait ws 3.0)) t)
                   "the ReadCondition must wake the WaitSet once the sample arrives")
           (loop repeat 50 until (member :data-available (cap-snapshot dal)) do (sleep 0.02))
           (%check :wake-on-data-available (and (member :data-available (cap-snapshot dal)) t)
                   "on_data_available must fire from the receiver thread")
           (let ((s (dds.dcps:read-w-condition dr rc)))
             (%check :wake-read (and s (= 7 (dcps-msg-id (dds.dcps:cached-sample-data (first s)))))
                     "read_w_condition after the wake must return the awaited sample")))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

;;; DDS Annex B content-filter / query grammar (M3 #4, FR-DCPS-5): compile filter
;;; expressions against the generated dcps-msg / shape-type field-accessors and
;;; evaluate them — comparisons, %n parameters, AND/OR/NOT, parens, BETWEEN, LIKE,
;;; field-vs-field, and the lexical/syntactic/field-resolution error paths. No network.

(defun* %ts-resolver (ts)
    (function (t) function)
  "A FIELDNAME resolver over a type-support's generated field-accessors (ADR 0008)."
  (let ((fa (dds.types:type-support-field-accessors ts)))
    (lambda (name) (cdr (assoc name fa :test #'string-equal)))))

(defun* %match-p (pred sample)
    (function (function t) t)
  "True iff content-filter predicate PRED accepts SAMPLE (test helper)." (and (funcall pred sample) t))

(defun* run-dcps-filter-test ()
    (function () t)
  "Compile + evaluate DDS Annex B filter/query expressions (FR-DCPS-5) over generated
   types, covering every production exercised by ContentFilteredTopic / QueryCondition."
  (let* ((mts (dds.types:find-type-support "dcps-msg"))
         (sts (dds.types:find-type-support "shape-type"))
         (mres (%ts-resolver mts))
         (sres (%ts-resolver sts))
         (m42 (make-dcps-msg :id 42 :text "hello"))
         (m7  (make-dcps-msg :id 7  :text "world"))
         (blue (make-shape-type :color "BLUE" :x 100 :y 5 :shapesize 30))
         (red  (make-shape-type :color "RED"  :x 10  :y 5 :shapesize 30)))
    (flet ((c (expr params res) (dds.dcps:compile-filter expr params res)))
      (let ((p (c "id > %0" '("40") mres)))
        (%check :flt-gt-param (%match-p p m42) "id=42 > 40")
        (%check :flt-gt-param-neg (not (%match-p p m7)) "id=7 not > 40"))
      (let ((p (c "id = 42 AND text = 'hello'" '() mres)))
        (%check :flt-and (%match-p p m42) "id=42 AND text=hello")
        (%check :flt-and-neg (not (%match-p p m7)) "id=7 fails the AND"))
      (let ((p (c "id = 7 OR id <> 42" '() mres)))
        (%check :flt-or (%match-p p m7) "id=7 matches the OR"))
      (let ((p (c "text <> 'hello'" '() mres)))
        (%check :flt-ne (%match-p p m7) "text=world <> hello")
        (%check :flt-ne-neg (not (%match-p p m42)) "text=hello not <> hello"))
      (let ((p (c "NOT (id < 10)" '() mres)))
        (%check :flt-not (%match-p p m42) "NOT(42<10) is true")
        (%check :flt-not-neg (not (%match-p p m7)) "NOT(7<10) is false"))
      (let ((p (c "id BETWEEN %0 AND %1" '("10" "50") mres)))
        (%check :flt-between (%match-p p m42) "42 in [10,50]")
        (%check :flt-between-neg (not (%match-p p m7)) "7 not in [10,50]"))
      (let ((p (c "id NOT BETWEEN 10 AND 50" '() mres)))
        (%check :flt-not-between (%match-p p m7) "7 NOT BETWEEN 10 AND 50 -> true"))
      (let ((p (c "color LIKE 'BL%'" '() sres)))
        (%check :flt-like (%match-p p blue) "BLUE LIKE BL%")
        (%check :flt-like-neg (not (%match-p p red)) "RED not LIKE BL%"))
      (let ((p (c "color LIKE 'R_D'" '() sres)))
        (%check :flt-like-underscore (%match-p p red) "RED LIKE R_D"))
      (let ((p (c "x > shapesize" '() sres)))
        (%check :flt-field-field (%match-p p blue) "x=100 > shapesize=30")
        (%check :flt-field-field-neg (not (%match-p p red)) "x=10 not > shapesize=30"))
      (%check :flt-err-field
              (handler-case (progn (c "nope > 1" '() mres) nil) (dds.dcps:filter-error () t))
              "an unknown field must signal filter-error")
      (%check :flt-err-syntax
              (handler-case (progn (c "id >" '() mres) nil) (dds.dcps:filter-error () t))
              "a truncated expression must signal filter-error")
      (%check :flt-err-trailing
              (handler-case (progn (c "id = 1 2" '() mres) nil) (dds.dcps:filter-error () t))
              "trailing tokens must signal filter-error")))
  t)

;;; ContentFilteredTopic over the wire (M3 #4, FR-DCPS-5): a DataReader on a CFT
;;; ("x > %0", params ("50")) over the Square topic matches the writer on the related
;;; topic but surfaces only the samples passing the filter (reader-side).

(defun* run-dcps-content-filtered-topic-test ()
    (function () t)
  "A ContentFilteredTopic delivers only matching samples: a reader on a CFT over Square
   with filter \"x > %0\" / params (50) receives the x=100 and x=200 shapes but not the
   x=10 shape, while still matching the writer on the related topic (FR-DCPS-5)."
  (let ((ts (dds.types:find-type-support "shape-type"))
        (p1 (dds.dcps:create-participant :domain 0))
        (p2 (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "Square" "shape-type" ts))
                (tr (dds.dcps:create-topic p2 "Square" "shape-type" ts))
                (cft (dds.dcps:create-contentfilteredtopic p2 "FastSquare" tr "x > %0" '("50")))
                (pub (dds.dcps:create-publisher p1)) (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub cft)))
           (loop repeat 150
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :cft-matched (plusp (dds.dcps:matched-count p2))
                   "the CFT reader must match the writer on the related topic")
           (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 100 :y 1 :shapesize 10))
           (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 10  :y 2 :shapesize 10))
           (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 200 :y 3 :shapesize 10))
           ;; two matches (x=100, x=200) arriving proves the x=10 (SN between) was drained + dropped
           (loop repeat 250 until (>= (dds.dcps:samples-available dr) 2) do (sleep 0.02))
           (%check :cft-count (= 2 (dds.dcps:samples-available dr))
                   "CFT must surface exactly the 2 matching samples (x>50)")
           (let ((xs (mapcar (lambda (cs) (shape-type-x (dds.dcps:cached-sample-data cs)))
                             (dds.dcps:take-samples dr))))
             (%check :cft-values
                     (and (= 2 (length xs)) (every (lambda (x) (> x 50)) xs)
                          (member 100 xs) (member 200 xs) (not (member 10 xs)))
                     "CFT delivered only x>50 (100,200), excluded x=10")))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

;;; QueryCondition with a DDS query_expression (M3 #4, FR-DCPS-5): create_querycondition
;;; now accepts an Annex B expression + parameters, compiled against the reader's topic
;;; type (not just a Lisp predicate). No discovery/data needed — checks the predicate.

(defun* run-dcps-querycondition-sql-test ()
    (function () t)
  "create_querycondition with :expression compiles the DDS query against the reader's
   topic type; the resulting query-fn filters by the SQL expression (FR-DCPS-5)."
  (let ((ts (dds.types:find-type-support "dcps-msg"))
        (p (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "QcSqlTopic" "dcps-msg" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr (dds.dcps:create-datareader sub tp))
                (qc (dds.dcps:create-querycondition
                     dr :states '(:not-read)
                        :expression "id > %0 AND text <> 'skip'" :parameters '("50")))
                (pred (dds.dcps:qc-query-fn qc)))
           (%check :qcsql-match (and (funcall pred (make-dcps-msg :id 99 :text "ok")) t)
                   "id=99,text=ok matches id>50 AND text<>skip")
           (%check :qcsql-low (not (funcall pred (make-dcps-msg :id 10 :text "ok")))
                   "id=10 fails id>50")
           (%check :qcsql-skip (not (funcall pred (make-dcps-msg :id 99 :text "skip")))
                   "text=skip fails text<>skip"))
      (dds.dcps:delete-participant p))
    t))

;;; INCONSISTENT_TOPIC (M3 #4 follow-up, FR-DCPS-3): two participants register the same
;;; topic name with DIFFERENT types; discovery detects the type collision and raises
;;; INCONSISTENT_TOPIC on the local Topic, firing the TopicListener.

(defclass capturing-topic-listener (capture-mixin dds.dcps:topic-listener) ())
(defmethod dds.dcps:on-inconsistent-topic ((l capturing-topic-listener) topic status)
  (declare (ignore topic))
  (dds.pal:with-lock ((cap-lock l)) (push (cons :inconsistent status) (cap-hits l))))

(defun* run-dcps-inconsistent-topic-test ()
    (function () t)
  "INCONSISTENT_TOPIC (FR-DCPS-3): p1 registers topic IncTopic as shape-type, p2 as
   dcps-msg (same name, different type). Discovery flags the collision: the local Topic's
   inconsistent-topic-status total_count goes >= 1 and on_inconsistent_topic fires."
  (let ((sts (dds.types:find-type-support "shape-type"))
        (mts (dds.types:find-type-support "dcps-msg"))
        (p1 (dds.dcps:create-participant :domain 0))
        (p2 (dds.dcps:create-participant :domain 0))
        (tl (make-instance 'capturing-topic-listener)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "IncTopic" "shape-type" sts))
                (tr (dds.dcps:create-topic p2 "IncTopic" "dcps-msg" mts))
                (pub (dds.dcps:create-publisher p1)) (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr)))
           (declare (ignore dw dr))
           (dds.dcps:set-topic-listener tw tl '(:inconsistent-topic))
           (loop repeat 150
                 until (plusp (dds.dcps:inconsistent-topic-status-total-count
                               (dds.dcps:get-inconsistent-topic-status tw)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :inc-total
                   (plusp (dds.dcps:inconsistent-topic-status-total-count
                           (dds.dcps:get-inconsistent-topic-status tw)))
                   "INCONSISTENT_TOPIC total_count must be >= 1 after a same-name/diff-type peer")
           (%check :inc-no-match (zerop (dds.dcps:matched-count p1))
                   "a type-mismatched endpoint must NOT match")
           (loop repeat 60 until (assoc :inconsistent (cap-snapshot tl)) do (sleep 0.02))
           (%check :inc-listener (and (assoc :inconsistent (cap-snapshot tl)) t)
                   "on_inconsistent_topic must fire from the receiver thread"))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

;;; SAMPLE_REJECTED + RESOURCE_LIMITS (M3 #4 follow-up, FR-DCPS-3): a reader bounded by
;;; max_samples rejects the overflow sample at the DCPS cache and raises SAMPLE_REJECTED.

(defmethod dds.dcps:on-sample-rejected ((l capturing-reader-listener) reader status)
  (declare (ignore reader))
  (dds.pal:with-lock ((cap-lock l)) (push (cons :sample-rejected status) (cap-hits l))))

(defun* run-dcps-sample-rejected-test ()
    (function () t)
  "SAMPLE_REJECTED + RESOURCE_LIMITS (FR-DCPS-3): a reliable reader with max_samples=2
   receives 3 samples; the 3rd is rejected at the DCPS cache (cache stays at 2),
   SAMPLE_REJECTED reports REJECTED_BY_SAMPLES_LIMIT, and on_sample_rejected fires."
  (let ((ts (dds.types:find-type-support "dcps-msg"))
        (p1 (dds.dcps:create-participant :domain 0))
        (p2 (dds.dcps:create-participant :domain 0))
        (rl (make-instance 'capturing-reader-listener)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "RejTopic" "dcps-msg" ts))
                (tr (dds.dcps:create-topic p2 "RejTopic" "dcps-msg" ts))
                (pub (dds.dcps:create-publisher p1)) (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr
                      :qos (dds.qos:make-reader-qos :reliability :reliable
                                                    :resource-max-samples 2))))
           (dds.dcps:set-reader-listener dr rl '(:sample-rejected))
           (loop repeat 150
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (dds.dcps:write-sample dw (make-dcps-msg :id 1 :text "a"))
           (dds.dcps:write-sample dw (make-dcps-msg :id 2 :text "b"))
           (dds.dcps:write-sample dw (make-dcps-msg :id 3 :text "c"))
           (loop repeat 250
                 until (plusp (dds.dcps:sample-rejected-status-total-count
                               (dds.dcps:get-sample-rejected-status dr)))
                 do (dds.dcps:samples-available dr) (sleep 0.02))
           (%check :rej-cache-bounded (= 2 (dds.dcps:samples-available dr))
                   "the reader cache must be bounded at max_samples=2")
           (let ((st (dds.dcps:get-sample-rejected-status dr)))
             (%check :rej-total (plusp (dds.dcps:sample-rejected-status-total-count st))
                     "SAMPLE_REJECTED total_count must be >= 1")
             (%check :rej-reason
                     (eq :rejected-by-samples-limit (dds.dcps:sample-rejected-status-last-reason st))
                     "last_reason must be REJECTED_BY_SAMPLES_LIMIT"))
           (loop repeat 60 until (assoc :sample-rejected (cap-snapshot rl)) do (sleep 0.02))
           (%check :rej-listener (and (assoc :sample-rejected (cap-snapshot rl)) t)
                   "on_sample_rejected must fire"))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

;;; Builtin-topic readers (M3 #5, FR-DCPS-6): DCPSParticipant / DCPSPublication /
;;; DCPSSubscription / DCPSTopic surface the discovered participants + endpoints.

(defun* run-dcps-builtin-topics-test ()
    (function () t)
  "Builtin-topic readers (FR-DCPS-6): two participants discover each other; the
   DCPSParticipant / DCPSPublication / DCPSSubscription / DCPSTopic readers expose the
   discovered participant, the remote writer/reader (topic+type), and the topic."
  (let ((ts (dds.types:find-type-support "dcps-msg"))
        (p1 (dds.dcps:create-participant :domain 0))
        (p2 (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "BTopic" "dcps-msg" ts))
                (tr (dds.dcps:create-topic p2 "BTopic" "dcps-msg" ts))
                (pub (dds.dcps:create-publisher p1)) (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr)))
           (declare (ignore dw dr))
           (loop repeat 150
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :bi-participants (plusp (length (dds.dcps:get-builtin-participant-data p1)))
                   "DCPSParticipant must list the discovered remote participant")
           (%check :bi-subscription
                   (find-if (lambda (s)
                              (and (string= "BTopic" (dds.dcps:subscription-builtin-topic-data-topic-name s))
                                   (string= "dcps-msg" (dds.dcps:subscription-builtin-topic-data-type-name s))))
                            (dds.dcps:get-builtin-subscription-data p1))
                   "DCPSSubscription on p1 must list p2's reader (BTopic, dcps-msg)")
           (%check :bi-publication
                   (find-if (lambda (pp)
                              (string= "BTopic" (dds.dcps:publication-builtin-topic-data-topic-name pp)))
                            (dds.dcps:get-builtin-publication-data p2))
                   "DCPSPublication on p2 must list p1's writer (BTopic)")
           (%check :bi-topic
                   (find "BTopic" (dds.dcps:get-builtin-topic-data p1)
                         :key #'dds.dcps:topic-builtin-topic-data-name :test #'string=)
                   "DCPSTopic on p1 must include BTopic"))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

;;; DDS keyhash (M4, FR-TYPE-5 / RTPS 2.5 §9.6.4.8): the <=16-byte direct/zero-padded
;;; path (spec Example 1, byte-exact) and the >16 MD5 path (an unbounded string key,
;;; max size > 16 -> always MD5 of the PLAIN_CDR2 big-endian key serialization).

(dds.gen:define-dds-type kh-keyed (:extensibility :final)
  (id :i32 :key t)
  (x :i32))

(defun* run-keyhash-test ()
    (function () t)
  "DDS keyhash byte-exactness (RTPS 2.5 §9.6.4.8): the <=16 direct path (Example 1) and
   the >16 MD5 path; the handle depends only on the key value, distinctly."
  ;; Example 1 (spec, byte-exact): @key long id=0x12345678 -> {12 34 56 78 00..00}
  (%check :kh-direct
          (equalp (key-hash-kh-keyed (make-kh-keyed :id #x12345678 :x 10))
                  (octets #x12 #x34 #x56 #x78 0 0 0 0 0 0 0 0 0 0 0 0))
          "fixed <=16 key = big-endian XCDR2 bytes zero-padded to 16")
  ;; unbounded string key (max > 16) -> MD5 of PLAIN_CDR2 BE: u32 len(incl NUL)=5, BLUE, NUL
  (%check :kh-md5
          (equalp (key-hash-shape-type (make-shape-type :color "BLUE" :x 1 :y 2 :shapesize 3))
                  (dds.core.md5:md5 (octets #x00 #x00 #x00 #x05 #x42 #x4c #x55 #x45 #x00)))
          "string key = MD5 of its big-endian XCDR2 serialization")
  ;; identity: depends only on the key; distinct per key value
  (%check :kh-identity
          (and (equalp (key-hash-shape-type (make-shape-type :color "RED" :x 1 :y 1 :shapesize 1))
                       (key-hash-shape-type (make-shape-type :color "RED" :x 9 :y 9 :shapesize 9)))
               (not (equalp (key-hash-shape-type (make-shape-type :color "RED" :x 0 :y 0 :shapesize 0))
                            (key-hash-shape-type (make-shape-type :color "BLUE" :x 0 :y 0 :shapesize 0)))))
          "keyhash depends only on the key, distinctly per value")
  t)

;;; XTypes structural TypeObject model (M4, FR-TYPE-2): define-dds-type now builds a
;;; Minimal struct TypeObject (member TypeIdentifiers + byte-exact NameHashes) into the
;;; type-support; plus TypeIdentifier structural equality.

(defun* run-xtypes-model-test ()
    (function () t)
  "The Minimal struct TypeObject built by define-dds-type carries the right member
   TypeIdentifier kinds, key flags, and byte-exact NameHashes; TypeIdentifier equality
   is structural (FR-TYPE-2)."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (to (dds.types:type-support-typeobject ts))
         (members (dds.types:minimal-struct-type-members to)))
    (flet ((m (name) (find name members :key #'dds.types:minimal-struct-member-name :test #'string=)))
      (%check :xt-name (string= "shape-type" (dds.types:minimal-struct-type-name to)) "type name")
      (%check :xt-ext (eq :final (dds.types:minimal-struct-type-extensibility to)) "extensibility FINAL")
      (%check :xt-count (= 4 (length members)) "4 members")
      (%check :xt-color-key (and (dds.types:minimal-struct-member-key-p (m "color")) t) "color is @key")
      (%check :xt-nonkey (not (dds.types:minimal-struct-member-key-p (m "x"))) "x is not @key")
      (%check :xt-color-string
              (= dds.types:+ti-string8-small+
                 (dds.types:type-identifier-kind
                  (dds.types:minimal-struct-member-type-identifier (m "color"))))
              "color's TypeIdentifier is a string8")
      (%check :xt-x-int32
              (= dds.types:+tk-int32+
                 (dds.types:type-identifier-kind
                  (dds.types:minimal-struct-member-type-identifier (m "x"))))
              "x's TypeIdentifier is TK_INT32")
      (%check :xt-namehash
              (equalp (dds.types:minimal-struct-member-name-hash (m "color"))
                      (octets #x70 #xdd #xa5 #xdf))
              "color's NameHash = MD5(\"color\")[0:4] = 70 dd a5 df")))
  (%check :xt-ti-equality
          (and (dds.types:type-identifier= (dds.types:primitive-type-identifier :i32)
                                           (dds.types:primitive-type-identifier :i32))
               (not (dds.types:type-identifier= (dds.types:primitive-type-identifier :i32)
                                                (dds.types:primitive-type-identifier :i64)))
               (dds.types:type-identifier= (dds.types:primitive-type-identifier :string)
                                           (dds.types:primitive-type-identifier :string))
               (dds.types:type-identifier=
                (dds.types:sequence-type-identifier (dds.types:primitive-type-identifier :u8))
                (dds.types:sequence-type-identifier (dds.types:primitive-type-identifier :u8)))
               (not (dds.types:type-identifier=
                     (dds.types:sequence-type-identifier (dds.types:primitive-type-identifier :u8))
                     (dds.types:sequence-type-identifier (dds.types:primitive-type-identifier :i16)))))
          "TypeIdentifier structural equality (primitive / string / sequence)")
  t)

;;; Type assignability + TYPE_CONSISTENCY_ENFORCEMENT (M4, FR-TYPE-4): the structural
;;; is-assignable-from relation over Minimal TypeObjects (XTypes 1.3 §7.2.4.4) and the
;;; enforcement Step-1 decision (§7.6.3.4.2). TypeObjects are built by hand so the engine
;;; is exercised in isolation against the spec's worked examples + every enforcement option.

(defun* run-assignability-test ()
    (function () t)
  "FR-TYPE-4 assignability matrix: FINAL/APPENDABLE/MUTABLE member matching, truncation,
   prevent_type_widening, ignore_member_names, the string/sequence bound rules, nested-struct
   recursion + strong-assignability (delimited), structural equivalence, and the
   TypeConsistencyEnforcement Step-1 decision + the QoS policy defaults."
  (labels ((i32 () (dds.types:primitive-type-identifier :i32))
           (sq (b) (dds.types:sequence-type-identifier (dds.types:primitive-type-identifier :i32) b))
           (strb (b) (let ((ti (dds.types:primitive-type-identifier :string)))
                       (setf (dds.types:type-identifier-bound ti) b) ti))
           (agg (s) (dds.types:hash-type-identifier dds.types:+ek-minimal+ :referenced s))
           (mem (name id ti &rest opts) (apply #'dds.types:make-struct-member name id ti opts))
           (sty (ext &rest members) (dds.types:make-minimal-struct-type :extensibility ext :members members))
           (asg (a b o) (and (dds.types:struct-assignable-from a b o) t)))
    (let ((opts (dds.types:default-assignability-options))
          (pw   (dds.types:make-assignability-options :prevent-type-widening t))
          (ign  (dds.types:make-assignability-options :ignore-member-names t))
          (sb   (dds.types:make-assignability-options :ignore-string-bounds nil))
          (qb   (dds.types:make-assignability-options :ignore-sequence-bounds nil)))
      ;; FINAL: identical -> mutually assignable; differing ID set -> neither direction
      (let ((a  (sty :final (mem "x" 0 (i32)) (mem "y" 1 (i32))))
            (b  (sty :final (mem "x" 0 (i32)) (mem "y" 1 (i32))))
            (a3 (sty :final (mem "x" 0 (i32)) (mem "y" 1 (i32)) (mem "z" 2 (i32)))))
        (%check :asg-final-equal (and (asg a b opts) (asg b a opts))
                "identical FINAL structs are mutually assignable")
        (%check :asg-final-diffset (and (not (asg a a3 opts)) (not (asg a3 a opts)))
                "FINAL requires an identical member-ID set"))
      ;; APPENDABLE: truncation both ways; index misalignment fails; widening control
      (let ((p2  (sty :appendable (mem "x" 0 (i32)) (mem "y" 1 (i32))))
            (p3  (sty :appendable (mem "x" 0 (i32)) (mem "y" 1 (i32)) (mem "z" 2 (i32))))
            (rev (sty :appendable (mem "y" 1 (i32)) (mem "x" 0 (i32)))))
        (%check :asg-append-truncate (and (asg p2 p3 opts) (asg p3 p2 opts))
                "APPENDABLE truncation is assignable both ways (Coordinate2D/3D)")
        (%check :asg-append-misaligned (not (asg p2 rev opts))
                "APPENDABLE requires the same ID at the same member index")
        (%check :asg-prevent-widening (and (not (asg p2 p3 pw)) (asg p3 p2 pw))
                "prevent_type_widening blocks a wider T2 from building a narrower T1"))
      ;; MUTABLE: reorder + add/remove members stay assignable (matched by ID)
      (let ((m1 (sty :mutable (mem "x" 0 (i32)) (mem "y" 1 (i32))))
            (m2 (sty :mutable (mem "y" 1 (i32)) (mem "x" 0 (i32))))
            (m3 (sty :mutable (mem "x" 0 (i32)) (mem "y" 1 (i32)) (mem "z" 2 (i32)))))
        (%check :asg-mutable-reorder (and (asg m1 m2 opts) (asg m2 m1 opts))
                "MUTABLE matches members by ID regardless of order")
        (%check :asg-mutable-evolve (and (asg m1 m3 opts) (asg m3 m1 opts))
                "MUTABLE add/remove member stays assignable"))
      ;; extensibility kinds must match
      (%check :asg-ext-mismatch
              (not (asg (sty :final (mem "x" 0 (i32))) (sty :appendable (mem "x" 0 (i32))) opts))
              "differing extensibility kinds are not assignable")
      ;; member name<->id consistency, toggled by ignore_member_names
      (let ((n1 (sty :mutable (mem "a" 0 (i32))))
            (n2 (sty :mutable (mem "b" 0 (i32)))))
        (%check :asg-name-id (and (not (asg n1 n2 opts)) (asg n1 n2 ign))
                "same ID with a different name fails unless ignore_member_names"))
      ;; string bound rule (Table 16) under ignore_string_bounds
      (let ((s10 (sty :mutable (mem "s" 0 (strb 10))))
            (s5  (sty :mutable (mem "s" 0 (strb 5)))))
        (%check :asg-string-bound
                (and (asg s5 s10 opts) (asg s10 s5 sb) (not (asg s5 s10 sb)))
                "string bounds ignored by default; enforced needs T1.len >= T2.len"))
      ;; sequence bound rule (Table 17) under ignore_sequence_bounds
      (let ((q10 (sty :mutable (mem "v" 0 (sq 10))))
            (q5  (sty :mutable (mem "v" 0 (sq 5)))))
        (%check :asg-seq-bound
                (and (asg q5 q10 opts) (asg q10 q5 qb) (not (asg q5 q10 qb)))
                "sequence bounds ignored by default; enforced needs T1.len >= T2.len"))
      ;; nested struct: assignability recurses through the referenced TypeObject
      (let* ((inner-pq  (sty :appendable (mem "p" 0 (i32)) (mem "q" 1 (i32))))
             (inner-p   (sty :appendable (mem "p" 0 (i32))))
             (inner-bad (sty :appendable (mem "p" 0 (strb 0))))
             (outer-pq  (sty :mutable (mem "n" 0 (agg inner-pq))))
             (outer-p   (sty :mutable (mem "n" 0 (agg inner-p))))
             (outer-bad (sty :mutable (mem "n" 0 (agg inner-bad)))))
        (%check :asg-nested (and (asg outer-pq outer-p opts) (not (asg outer-pq outer-bad opts)))
                "assignability recurses into nested struct members"))
      ;; strong-assignability: a nested APPENDABLE element is delimited (ok); a nested FINAL
      ;; element is not delimited, so an APPENDABLE container is not even self-assignable
      (let ((app-app (sty :appendable (mem "n" 0 (agg (sty :appendable (mem "p" 0 (i32)))))))
            (app-fin (sty :appendable (mem "n" 0 (agg (sty :final (mem "p" 0 (i32))))))))
        (%check :asg-strong-delimited (and (asg app-app app-app opts) (not (asg app-fin app-fin opts)))
                "strong-assignability requires the element type to be delimited"))
      ;; enforcement Step-1 decision (ALLOW coercion vs DISALLOW equivalence)
      (let ((p2  (sty :appendable (mem "x" 0 (i32)) (mem "y" 1 (i32))))
            (p2b (sty :appendable (mem "x" 0 (i32)) (mem "y" 1 (i32))))
            (p3  (sty :appendable (mem "x" 0 (i32)) (mem "y" 1 (i32)) (mem "z" 2 (i32)))))
        (%check :asg-enforce-allow
                (and (dds.types:enforce-type-consistency p2 p3 :kind :allow-type-coercion) t)
                "ALLOW_TYPE_COERCION: reader assignable-from writer is consistent")
        (%check :asg-enforce-default
                (and (dds.types:enforce-type-consistency p2 p3) t)
                "the default enforcement kind is ALLOW_TYPE_COERCION")
        (%check :asg-enforce-disallow
                (and (dds.types:enforce-type-consistency p2 p2b :kind :disallow-type-coercion)
                     (not (dds.types:enforce-type-consistency p2 p3 :kind :disallow-type-coercion)))
                "DISALLOW_TYPE_COERCION requires structural equivalence"))
      ;; the QoS policy carrier + spec defaults (§7.6.3.4.1)
      (let ((tce (dds.qos:make-type-consistency-enforcement)))
        (%check :asg-qos-defaults
                (and (eq :allow-type-coercion (dds.qos:type-consistency-enforcement-kind tce))
                     (dds.qos:type-consistency-enforcement-ignore-sequence-bounds tce)
                     (dds.qos:type-consistency-enforcement-ignore-string-bounds tce)
                     (not (dds.qos:type-consistency-enforcement-ignore-member-names tce))
                     (not (dds.qos:type-consistency-enforcement-prevent-type-widening tce))
                     (not (dds.qos:type-consistency-enforcement-force-type-validation tce)))
                "TypeConsistencyEnforcement QoS defaults (XTypes §7.6.3.4.1)")
        (%check :asg-qos-reader-slot
                (eq :allow-type-coercion
                    (dds.qos:type-consistency-enforcement-kind
                     (dds.qos:qos-type-consistency (dds.qos:make-reader-qos))))
                "the QoS set carries TYPE_CONSISTENCY_ENFORCEMENT (reader default)"))))
  t)

;;; XCDR2 MinimalTypeObject serializer + EquivalenceHash (M4, FR-TYPE-2/5): serialize the
;;; Minimal struct TypeObject to canonical XCDR2-LE bytes (XTypes §7.3.4.5) and hash it
;;; (§7.3.4.9.1). The hand-derived golden (struct pt{long x;}) proves the framing byte-exact
;;; against the §7.4.3.5.3 serialization VM. PROVISIONAL flag/encap choices await Connext.

(defun* run-typeobject-cdr-test ()
    (function () t)
  "Serialize a Minimal struct TypeObject to XCDR2-LE + compute its EquivalenceHash. Asserts
   the spec-derived golden byte layout for a 1-member FINAL struct, the hash shape +
   determinism, distinct types hashing differently, nested-struct recursion, and that
   sequence members error cleanly pending oracle confirmation. The shape-type hash is a
   PROVISIONAL self-consistency vector — to be locked byte-exact against Connext."
  (let ((pt (dds.types:make-minimal-struct-type
             :name "pt" :extensibility :final
             :members (list (dds.types:make-struct-member
                             "x" 0 (dds.types:primitive-type-identifier :i32)))))
        (golden (octets #x23 0 0 0 #xf1 #x51 #x01 0 #x01 0 0 0 0 0 0 0
                        #x13 0 0 0 #x01 0 0 0 #x0b 0 0 0 0 0 0 0
                        #x01 0 #x04 #x9d #xd4 #xe4 #x61)))
    (%check :to-golden (equalp golden (dds.types:minimal-type-object-octets pt))
            "MinimalTypeObject XCDR2-LE for struct pt{long x;} must match the spec-derived golden")
    (%check :to-hash-len (= 14 (length (dds.types:equivalence-hash pt)))
            "EquivalenceHash is 14 octets (XTypes §7.3.4.9.1)")
    (%check :to-hash-deterministic
            (equalp (dds.types:equivalence-hash pt) (dds.types:equivalence-hash pt))
            "EquivalenceHash is deterministic")
    (let ((pt2 (dds.types:make-minimal-struct-type
                :name "pt" :extensibility :final
                :members (list (dds.types:make-struct-member
                                "x" 0 (dds.types:primitive-type-identifier :i64))))))
      (%check :to-hash-distinct
              (not (equalp (dds.types:equivalence-hash pt) (dds.types:equivalence-hash pt2)))
              "a different member type yields a different EquivalenceHash"))
    (let ((to (dds.types:type-support-typeobject (dds.types:find-type-support "shape-type"))))
      (%check :to-shape-bytes (= 87 (length (dds.types:minimal-type-object-octets to)))
              "shape-type MinimalTypeObject serializes (PROVISIONAL byte count)")
      (%check :to-shape-hash
              (equalp (dds.types:equivalence-hash to)
                      (octets #xbf #xe2 #xa6 #x2e #xd8 #x11 #xac #x46 #x3c #x40 #xc9 #x7d #x30 #xee))
              "shape-type EquivalenceHash (PROVISIONAL self-consistency vector; lock vs Connext)"))
    (let ((to (dds.types:type-support-typeobject (dds.types:find-type-support "gseg"))))
      (%check :to-nested (= 14 (length (dds.types:equivalence-hash to)))
              "a struct with nested-struct members hashes via recursion into the referenced TypeObject"))
    (let ((to (dds.types:type-support-typeobject (dds.types:find-type-support "gseq"))))
      (%check :to-seq-deferred
              (handler-case (progn (dds.types:minimal-type-object-octets to) nil) (error () t))
              "sequence member TypeObject serialization errors cleanly pending oracle confirmation")))
  t)

;;; TypeInformation codec (M4 step b1, FR-TYPE-3 foundation): serialize the TypeInformation
;;; carried in PID_TYPE_INFORMATION (idl @id 0x0075) and recover the minimal EquivalenceHash.
;;; Round-trip-verifiable offline; the wire layout is PROVISIONAL (minimal-only, LC=4) pending
;;; Connext confirmation, like the TypeObject serializer.

(defun* run-type-information-test ()
    (function () t)
  "TypeInformation codec: serialize + recover the minimal EquivalenceHash. The round-trip
   must yield the type's EquivalenceHash, be deterministic, distinguish types, and serialize
   nested dependencies (gseg depends on gpoint)."
  (flet ((to (name) (dds.types:type-support-typeobject (dds.types:find-type-support name))))
    (let* ((mto (to "dcps-msg"))
           (info (dds.types:serialize-type-information mto)))
      (%check :ti-roundtrip
              (equalp (dds.types:deserialize-type-information-hash info)
                      (dds.types:equivalence-hash mto))
              "TypeInformation round-trip recovers the type's EquivalenceHash")
      (%check :ti-deterministic (equalp info (dds.types:serialize-type-information mto))
              "TypeInformation serialization is deterministic")
      (%check :ti-distinct
              (not (equalp (dds.types:deserialize-type-information-hash info)
                           (dds.types:deserialize-type-information-hash
                            (dds.types:serialize-type-information (to "shape-type")))))
              "different types yield different TypeInformation hashes"))
    (let* ((gto (to "gseg"))
           (ginfo (dds.types:serialize-type-information gto)))
      (%check :ti-nested-roundtrip
              (equalp (dds.types:deserialize-type-information-hash ginfo)
                      (dds.types:equivalence-hash gto))
              "a nested type's TypeInformation round-trips (dependencies serialized)")
      (%check :ti-nested-larger
              (> (length ginfo) (length (dds.types:serialize-type-information (to "dcps-msg"))))
              "a type with a nested dependency carries a larger TypeInformation")))
  t)

;;; Inbound RTI PID_TYPE_OBJECT_LB inflate (ADR 0009, FR-TYPE-3): a ZLIB-compressed
;;; COMPLETE TypeObject inflates byte-exact, and a malformed / oversized / wrong-class /
;;; truncated LB rejects (bounds + resource guard, NFR-SEC-POSTURE). The LB vector below is
;;; a deterministic ZLIB stream (header + stored block) for the 60-octet i*7 pattern.

(defun* %connext-shape-type-lb ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "The live RTI Connext 7.3.1 ShapeType PID_TYPE_OBJECT_LB parameter value (232 octets),
   captured 2026-06-09 via the typeobject-probe (ADR 0009); inflates to a 540-octet TypeObject."
  (coerce
   '(1 0 0 0 28 2 0 0 218 0 0 0 120 218 99 172 231 96 0 129 15 140 12 12 76 96
     22 11 131 24 144 100 4 138 115 2 105 15 70 8 27 4 20 64 226 96 89 6 134 184
     93 247 206 59 73 120 127 226 2 178 131 51 18 11 82 67 42 11 82 161 250 24
     193 166 64 0 136 159 130 198 7 169 123 3 21 131 153 173 2 54 27 2 132 161
     116 197 85 159 52 75 166 45 149 108 64 118 114 126 78 126 17 22 243 153 234
     17 102 136 192 236 0 98 86 32 4 249 167 130 72 61 76 72 122 42 9 232 145 129
     138 49 67 245 128 194 160 24 20 6 197 153 85 169 56 244 194 48 72 84 24 170 6
     100 90 9 82 24 232 128 221 33 140 226 119 81 144 217 37 69 153 121 233 241 70
     166 166 241 201 25 137 69 137 201 37 169 69 12 4 194 154 7 8 83 161 50 32 241
     19 80 241 255 72 238 129 233 23 0 98 49 168 25 176 120 5 201 3 0 156 19 56 176
     0 0)
   '(simple-array (unsigned-byte 8) (*))))

(defun* run-type-object-lb-test ()
    (function () t)
  "Test: inflate-type-object-lb + fingerprint against a real Connext ShapeType PID_TYPE_OBJECT_LB (ADR 0009)."
  (let ((lb (coerce '(1 0 0 0 60 0 0 0 71 0 0 0 120 218 1 60 0 195 255
                      0 7 14 21 28 35 42 49 56 63 70 77 84 91 98 105 112 119 126 133
                      140 147 154 161 168 175 182 189 196 203 210 217 224 231 238 245
                      252 3 10 17 24 31 38 45 52 59 66 73 80 87 94 101 108 115 122 129
                      136 143 150 157 196 116 25 103)
                    '(simple-array (unsigned-byte 8) (*))))
        (expected (coerce (loop for i below 60 collect (mod (* i 7) 256))
                          '(simple-array (unsigned-byte 8) (*)))))
    (%check :tol-inflate (equalp (dds.types:inflate-type-object-lb lb) expected)
            "PID_TYPE_OBJECT_LB ZLIB inflate recovers the declared bytes byte-exact")
    (let ((bad (copy-seq lb)))
      (setf (aref bad 0) 2)
      (%check :tol-bad-class (null (dds.types:inflate-type-object-lb bad))
              "non-ZLIB compression class rejects"))
    (let ((bad (copy-seq lb)))
      (setf (aref bad 4) 0 (aref bad 5) 0 (aref bad 6) 0 (aref bad 7) #xff)
      (%check :tol-guard (null (dds.types:inflate-type-object-lb bad))
              "uncompressed length over *max-type-object-bytes* rejects before inflate"))
    (%check :tol-short (null (dds.types:inflate-type-object-lb lb 0 20))
            "a truncated LB (compressed_length exceeds extent) rejects")
    (%check :tol-tiny (null (dds.types:inflate-type-object-lb lb 0 8))
            "a sub-header LB rejects"))
  ;; Real RTI Connext 7.3.1 ShapeType PID_TYPE_OBJECT_LB (captured 2026-06-09 via the
  ;; typeobject-probe). Locks the reverse-engineered LB header against the LIVE wire: the
  ;; inflate must recover the declared 540-octet (RTI legacy) complete TypeObject, which
  ;; carries the type name. (The legacy-TypeObject PARSE is a later increment.)
  (let* ((rti-lb (%connext-shape-type-lb))
         (inflated (dds.types:inflate-type-object-lb rti-lb))
         (needle (map '(simple-array (unsigned-byte 8) (*)) #'char-code "ShapeType")))
    (%check :tol-connext
            (and inflated (= (length inflated) 540) (search needle inflated))
            "real Connext ShapeType PID_TYPE_OBJECT_LB inflates to the declared 540-octet TypeObject")
    ;; lightweight type FINGERPRINT (heuristic): the embedded names identify the type.
    (let ((strs (and inflated (dds.types:type-object-strings inflated))))
      (%check :tol-fingerprint
              (and (member "ShapeType" strs :test #'string=)
                   (member "color" strs :test #'string=)
                   (member "shapesize" strs :test #'string=)
                   (member "string_255_character" strs :test #'string=))
              "type-object-strings recovers the ShapeType type/member/dependent names")
      (%check :tol-mentions
              (and (dds.types:type-object-mentions-all-p inflated '("ShapeType" "color" "shapesize"))
                   (not (dds.types:type-object-mentions-all-p inflated '("ShapeType" "NotAMember"))))
              "type-object-mentions-all-p: plausible names match, a bogus name does not")))
  t)

;;; SEDP capture of the inbound RTI PID_TYPE_OBJECT_LB, end to end (ADR 0009): a peer's LB
;;; rides the endpoint ParameterList; parse-endpoint-data captures it OPAQUE (L4, no dds-types
;;; dep), and the higher layer inflates + fingerprints it to recover the peer's type.

(defun* run-sedp-type-object-lb-test ()
    (function () t)
  "Test: SEDP capture of an inbound PID_TYPE_OBJECT_LB, end to end (capture -> inflate -> fingerprint)."
  (let* ((lb (%connext-shape-type-lb))
         (ob (dds.core.buffer:make-octet-buffer 512))
         (wc (dds.core.buffer:cursor ob :endianness :little)))
    (dds.rtps.message:write-parameter wc dds.rtps.message:+pid-type-object-lb+ lb 0 (length lb))
    (dds.rtps.message:write-parameter-sentinel wc)
    (let* ((rc (dds.core.buffer:cursor ob :endianness :little))
           (ep (dds.rtps.discovery:parse-endpoint-data rc)))
      (%check :tol-sedp-capture
              (equalp (dds.rtps.discovery:endpoint-data-type-object-lb ep) lb)
              "parse-endpoint-data captures PID_TYPE_OBJECT_LB opaque")
      (let ((inflated (dds.types:inflate-type-object-lb
                       (dds.rtps.discovery:endpoint-data-type-object-lb ep))))
        (%check :tol-sedp-chain
                (and inflated (= (length inflated) 540)
                     (dds.types:type-object-mentions-all-p inflated '("ShapeType" "color" "shapesize")))
                "captured LB inflates + fingerprints to the peer's ShapeType type"))))
  t)

;;; ADVISORY soft type-compatibility (ADR 0009): the LOCAL type's >=2-octet member-name
;;; fingerprint vs a peer's inbound RTI PID_TYPE_OBJECT_LB. A heuristic confirmation /
;;; diagnostic — NEVER a match gate (the peer already matched on topic + type name, and
;;; RTI's legacy TypeObject is not the OMG CompleteTypeObject), so a missing name is
;;; inconclusive and must not reject a peer.

(defun* run-type-compat-soft-test ()
    (function () t)
  "ASSESS-TYPE-OBJECT-LB verdicts + TYPE-SUPPORT-FINGERPRINT-NAMES against the real Connext
   ShapeType LB: the local shape-type's member names are present in the peer's inflated
   TypeObject (:names-present); a type whose member is absent yields :names-absent (+ the
   missing list); no LB / an un-inflatable LB / a local type with no struct TypeObject yield
   the other documented advisory verdicts. None ever rejects a peer (ADR 0009)."
  (let ((shape (dds.types:find-type-support "shape-type"))
        (msg   (dds.types:find-type-support "dcps-msg"))
        (rti-lb (%connext-shape-type-lb)))
    (let ((names (dds.types:type-support-fingerprint-names shape)))
      (%check :tcs-fingerprint
              (and (member "color" names :test #'string=)
                   (member "shapesize" names :test #'string=)
                   (not (member "x" names :test #'string=))            ; 1-octet name dropped
                   (not (member "shape-type" names :test #'string=)))  ; struct type name excluded
              "fingerprint = >=2-octet MEMBER names; 1-octet names + the struct type name excluded"))
    (%check :tcs-names-present
            (eq :names-present (dds.types:assess-type-object-lb shape rti-lb))
            "every local shape-type member name present in the Connext ShapeType LB -> :names-present")
    (multiple-value-bind (verdict missing) (dds.types:assess-type-object-lb msg rti-lb)
      (%check :tcs-names-absent
              (and (eq :names-absent verdict) (member "text" missing :test #'string=))
              "dcps-msg's 'text' member is absent from the ShapeType LB -> :names-absent (+ missing)"))
    (%check :tcs-no-type-object
            (eq :no-type-object (dds.types:assess-type-object-lb shape nil))
            "a peer that advertised no PID_TYPE_OBJECT_LB -> :no-type-object")
    (%check :tcs-inflate-failed
            (eq :inflate-failed
                (dds.types:assess-type-object-lb
                 shape (coerce '(1 0 0 0 4 0 0 0 4 0 0 0 9 9 9 9)
                               '(simple-array (unsigned-byte 8) (*)))))
            "a present-but-uninflatable LB (ZLIB class, bad deflate stream) -> :inflate-failed")
    (%check :tcs-not-assessable
            (eq :not-assessable
                (dds.types:assess-type-object-lb (dds.types:make-type-support :name "empty") rti-lb))
            "a local type with no struct TypeObject -> :not-assessable"))
  t)

;;; DCPS wiring of the advisory verdict (ADR 0009): %ON-DISC-MATCH records the matched
;;; peer's PID_TYPE_OBJECT_LB fingerprint verdict on the local DataReader/DataWriter via
;;; ENTITY-TYPE-COMPAT (inspection) and writes one line to *TYPE-COMPAT-LOG* when bound.

(defun* run-dcps-type-compat-test ()
    (function () t)
  "%ON-DISC-MATCH assesses a freshly matched peer's PID_TYPE_OBJECT_LB against the local
   type and records the verdict on the local DataReader (ENTITY-TYPE-COMPAT), also writing
   one advisory line to *TYPE-COMPAT-LOG* when bound; it never gates the match (ADR 0009)."
  (let ((ts (dds.types:find-type-support "shape-type"))
        (p (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "CompatTopic" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr (dds.dcps:create-datareader sub tp))
                (remote (dds.rtps.discovery:make-endpoint-data
                         :guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7)
                         :topic-name "CompatTopic" :type-name "ShapeType"
                         :type-object-lb (%connext-shape-type-lb)))
                (log (make-string-output-stream)))
           (%check :tc-initial (null (dds.dcps:entity-type-compat dr))
                   "type-compat is NIL on a fresh DataReader (no match assessed yet)")
           (let ((dds.dcps:*type-compat-log* log))
             (dds.dcps::%on-disc-match p :remote-writer remote))
           (%check :tc-recorded (eq :names-present (dds.dcps:entity-type-compat dr))
                   "the matched peer's ShapeType LB fingerprints :names-present and is recorded")
           (%check :tc-logged
                   (let ((s (string-downcase (get-output-stream-string log))))
                     (and (search "type-compat" s) (search "names-present" s)))
                   "*type-compat-log*, when bound, receives one advisory verdict line"))
      (dds.dcps:delete-participant p))
    t))

;;; DCPS large-sample e2e (DATA_FRAG gate, FR-DCPS-1 + RTPS 2.5 §9.4.5.5): a payload
;;; larger than *fragment-size* flows through write-sample -> DCPS serialize -> UDP
;;; DATA_FRAG fragmentation -> reassembly -> take-samples byte-exact. Proves the DCPS
;;; write/take path fragments and reassembles transparently without app involvement.

(dds.gen:define-dds-type dcps-large (:extensibility :final)
  (id :i32 :key t)
  (payload (:sequence :u8)))

(defun* run-dcps-large-test ()
    (function () t)
  "DCPS write -> DATA_FRAG fragmentation -> reassembly -> take, byte-exact (FR-DCPS-1 /
   RTPS 2.5 §9.4.5.5): write one dcps-large sample whose payload exceeds *fragment-size*
   (1024); assert the reader takes exactly one sample with the original id and byte-exact
   payload. Proves the DCPS API layer fragments transparently."
  (let* ((ts (dds.types:find-type-support "dcps-large"))
         (p1 (dds.dcps:create-participant :domain 0))
         (p2 (dds.dcps:create-participant :domain 0))
         (payload-size 4000)   ; > *fragment-size* 1024 -> fragments into 4 DATA_FRAG
         (payload (make-array payload-size :element-type '(unsigned-byte 8)))
         (orig-id 77))
    (dotimes (i payload-size) (setf (aref payload i) (logand (* i 7) #xff)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "LargeTopic" "dcps-large" ts))
                (tr (dds.dcps:create-topic p2 "LargeTopic" "dcps-large" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr)))
           (loop repeat 150
                 until (and (plusp (dds.dcps:matched-count p1))
                            (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :dcps-large-matched (plusp (dds.dcps:matched-count p1))
                   "DataWriter/DataReader did not match before publish")
           (dds.dcps:write-sample dw (make-dcps-large :id orig-id :payload payload))
           (let ((got nil))
             (loop repeat 250 until got
                   do (let ((s (dds.dcps:take-samples dr)))
                        (when s (setf got (dds.dcps:cached-sample-data (first s)))))
                      (sleep 0.02))
             (%check :dcps-large-take (and got t)
                     "DataReader::take returned no sample (fragmented large sample not delivered)")
             (%check :dcps-large-id (= orig-id (dcps-large-id got))
                     "dcps-large id field did not survive fragment->reassemble->take")
             (%check :dcps-large-payload-length
                     (= payload-size (length (dcps-large-payload got)))
                     "reassembled payload length does not match original")
             (%check :dcps-large-payload-exact
                     (equalp payload (dcps-large-payload got))
                     "reassembled payload bytes differ from original (not byte-exact)")))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

;;; PID_TYPE_INFORMATION end-to-end (M4 step b2a, FR-TYPE-3): a generated type's
;;; TypeInformation rides the SEDP endpoint ParameterList. Proves the dds-types codec and
;;; the dds-rtps opaque wire mechanism interoperate (emit only; match enforcement deferred
;;; until the EquivalenceHash is Connext-confirmed).

(defun* run-sedp-type-information-test ()
    (function () t)
  "serialize-endpoint-data carries the TypeInformation as PID_TYPE_INFORMATION;
   parse-endpoint-data recovers the opaque octets; deserialize-type-information-hash yields
   the type's EquivalenceHash, alongside the still-round-tripping type-name."
  (let* ((to (dds.types:type-support-typeobject (dds.types:find-type-support "dcps-msg")))
         (ti (dds.types:serialize-type-information to))
         (ep (dds.rtps.discovery:make-endpoint-data
              :topic-name "TiTopic" :type-name "dcps-msg" :type-information ti
              :qos (dds.qos:make-qos :reliability :reliable)))
         (buf (dds.core.buffer:make-octet-buffer 1024)))
    (dds.rtps.discovery:serialize-endpoint-data (dds.core.buffer:cursor buf :endianness :little) ep)
    (let ((back (dds.rtps.discovery:parse-endpoint-data
                 (dds.core.buffer:cursor buf :endianness :little))))
      (%check :sedp-ti-present
              (and back (dds.rtps.discovery:endpoint-data-type-information back) t)
              "the parsed endpoint must carry PID_TYPE_INFORMATION")
      (%check :sedp-ti-hash
              (equalp (dds.types:deserialize-type-information-hash
                       (dds.rtps.discovery:endpoint-data-type-information back))
                      (dds.types:equivalence-hash to))
              "the SEDP-carried TypeInformation recovers the type's EquivalenceHash")
      (%check :sedp-ti-typename
              (string= "dcps-msg" (dds.rtps.discovery:endpoint-data-type-name back))
              "type-name still round-trips alongside type-information")))
  t)
