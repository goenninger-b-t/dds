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
           (loop repeat 100
                 until (and (plusp (dds.dcps:discovered-count p1))
                            (plusp (dds.dcps:discovered-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :dcps-discovered (plusp (dds.dcps:discovered-count p1))
                   "participants did not discover via DCPS/multicast")
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
                 until (and (plusp (dds.dcps:discovered-count p1)) (plusp (dds.dcps:discovered-count p2)))
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

(declaim (ftype (function (t t) (integer 0)) %rxo-scenario))
(defun %rxo-scenario (writer-qos reader-qos)
  "Create a writer/reader pair with the given QoS on a shared topic; spin discovery
   and return the total matched-endpoint count across both participants."
  (let ((p1 (dds.dcps:create-participant :domain 0))
        (p2 (dds.dcps:create-participant :domain 0))
        (ts (dds.types:find-type-support "dcps-msg")))
    (unwind-protect
         (let ((pub (dds.dcps:create-publisher p1)) (sub (dds.dcps:create-subscriber p2))
               (tw (dds.dcps:create-topic p1 "RxoTopic" "dcps-msg" ts))
               (tr (dds.dcps:create-topic p2 "RxoTopic" "dcps-msg" ts)))
           (dds.dcps:create-datawriter pub tw :qos writer-qos)
           (dds.dcps:create-datareader sub tr :qos reader-qos)
           (loop repeat 120
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (+ (dds.dcps:matched-count p1) (dds.dcps:matched-count p2)))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))))

(declaim (ftype (function () t) run-dcps-rxo-test))
(defun run-dcps-rxo-test ()
  "RxO blocks matching (FR-QOS-2): compatible QoS endpoints match; a VOLATILE writer
   vs a reader requesting TRANSIENT_LOCAL do NOT match despite agreeing on topic+type."
  (%check :rxo-compatible
          (plusp (%rxo-scenario (dds.qos:make-writer-qos) (dds.qos:make-reader-qos)))
          "compatible QoS endpoints must match over the wire")
  (%check :rxo-incompatible-durability
          (zerop (%rxo-scenario (dds.qos:make-writer-qos :durability :volatile)
                                (dds.qos:make-reader-qos :durability :transient-local)))
          "durability-incompatible endpoints must not match (RxO blocks the match)")
  t)
