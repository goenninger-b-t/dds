(in-package #:dds.tests)

;;; End-to-end offline integration (the strongest proof short of Connext interop):
;;; a generated-type sample is serialized to a SerializedPayload, framed in an RTPS
;;; DATA message, sent over a REAL UDP loopback socket, received, dispatched, the
;;; payload deserialized, and the reliable reader records the change. This wires
;;; together the type compiler, CDR/encapsulation, the submessage codec + dispatch
;;; loop, the UDP transport, and the reliable engine.

(declaim (ftype (function () t) run-end-to-end-test))
(defun run-end-to-end-test ()
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
                  (dds.rtps.reliable:writer-write writer pl-buf)
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
                          (declare (ignore r len key))
                          (when has
                            (let ((vc (dds.core.buffer:cursor in-buf :endianness :little)))
                              (dds.core.buffer:cursor-set-position vc off)
                              (dds.cdr:parse-encapsulation-header vc)
                              (setf got (deserialize-gsample vc :xcdr2)))
                            (dds.rtps.reliable:reader-on-data reader w sn got)))))))
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

(declaim (ftype (function (shape-type) (simple-array (unsigned-byte 8) (*))) %serialize-shape))
(defun %serialize-shape (shape)
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

(declaim (ftype (function ((simple-array (unsigned-byte 8) (*))) shape-type) %deserialize-shape))
(defun %deserialize-shape (bytes)
  "Parse a PLAIN_CDR2_LE SerializedPayload (encapsulation header + XCDR2 body) into
   a shape-type. The deserialized struct copies its fields out, so the scratch
   buffer is freed immediately."
  (let* ((ob (dds.core.buffer:make-octet-buffer (length bytes)))
         (rc (dds.core.buffer:cursor ob :endianness :little)))
    (replace (dds.core.buffer:octet-buffer-vec ob) bytes)
    (dds.cdr:parse-encapsulation-header rc)
    (prog1 (deserialize-shape-type rc :xcdr2)
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec ob)))))

(declaim (ftype (function () t) run-typed-dataplane-test))
(defun run-typed-dataplane-test ()
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

(declaim (ftype (function () t) run-dcps-entity-test))
(defun run-dcps-entity-test ()
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

(declaim (ftype (function (dds.dcps:cached-sample) t) %cs-vs))
(defun %cs-vs (cs) (dds.dcps:sample-info-view-state (dds.dcps:cached-sample-info cs)))
(declaim (ftype (function (dds.dcps:cached-sample) t) %cs-ss))
(defun %cs-ss (cs) (dds.dcps:sample-info-sample-state (dds.dcps:cached-sample-info cs)))
(declaim (ftype (function (dds.dcps:cached-sample) t) %cs-ih))
(defun %cs-ih (cs) (dds.dcps:sample-info-instance-handle (dds.dcps:cached-sample-info cs)))

(declaim (ftype (function () t) run-dcps-instance-test))
(defun run-dcps-instance-test ()
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

(declaim (ftype (function (t t) (values integer t)) %rxo-scenario))
(defun %rxo-scenario (writer-qos reader-qos)
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

(declaim (ftype (function () t) run-dcps-rxo-test))
(defun run-dcps-rxo-test ()
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

(declaim (ftype (function () t) run-dcps-waitset-test))
(defun run-dcps-waitset-test ()
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

(declaim (ftype (function (capture-mixin) list) cap-snapshot))
(defun cap-snapshot (l)
  "Thread-safe snapshot of a capturing listener's recorded events."
  (dds.pal:with-lock ((cap-lock l)) (copy-list (cap-hits l))))

(declaim (ftype (function () t) run-dcps-matched-status-test))
(defun run-dcps-matched-status-test ()
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

(declaim (ftype (function () t) run-dcps-incompatible-qos-test))
(defun run-dcps-incompatible-qos-test ()
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

(declaim (ftype (function () t) run-dcps-query-condition-test))
(defun run-dcps-query-condition-test ()
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

(declaim (ftype (function () t) run-dcps-condvar-wake-test))
(defun run-dcps-condvar-wake-test ()
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

(declaim (ftype (function (t) function) %ts-resolver))
(defun %ts-resolver (ts)
  "A FIELDNAME resolver over a type-support's generated field-accessors (ADR 0008)."
  (let ((fa (dds.types:type-support-field-accessors ts)))
    (lambda (name) (cdr (assoc name fa :test #'string-equal)))))

(declaim (ftype (function (function t) t) %match-p))
(defun %match-p (pred sample) (and (funcall pred sample) t))

(declaim (ftype (function () t) run-dcps-filter-test))
(defun run-dcps-filter-test ()
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

(declaim (ftype (function () t) run-dcps-content-filtered-topic-test))
(defun run-dcps-content-filtered-topic-test ()
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

(declaim (ftype (function () t) run-dcps-querycondition-sql-test))
(defun run-dcps-querycondition-sql-test ()
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

(declaim (ftype (function () t) run-dcps-inconsistent-topic-test))
(defun run-dcps-inconsistent-topic-test ()
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

(declaim (ftype (function () t) run-dcps-sample-rejected-test))
(defun run-dcps-sample-rejected-test ()
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
