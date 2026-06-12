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
                (dds.cdr:finalize-encapsulation-options pc :plain-cdr2-le)
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
    (dds.cdr:finalize-encapsulation-options wc :plain-cdr2-le)
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
           (let ((bytes (dds.disc:node-sample-by-sn node2 1)))
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

(defun* run-dcps-dispose-test ()
    (function () t)
  "DCPS instance lifecycle S1 (writer side, DDS 1.4 §2.2.2.4.2): on the keyed shape-type a
   DataWriter register_instance returns a 16-octet handle; write the sample; then dispose the
   instance. Asserts register/dispose/unregister do not error, the handle is the type-support
   key-hash, and the dispose's no-payload DATA reaches the subscriber's engine classified :dispose
   carrying that handle (RTPS 2.5 §9.6.4.9). The reader-side instance-state transition is S2."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p1 (dds.dcps:create-participant :domain 0))
         (p2 (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "Square" "shape-type" ts))
                (tr (dds.dcps:create-topic p2 "Square" "shape-type" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr))
                (sample (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 10))
                (node2 (dds.dcps::dp-node p2)))
           (declare (ignore dr))
           (loop repeat 150
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :dcps-disp-matched (plusp (dds.dcps:matched-count p1))
                   "DataWriter/DataReader did not match via DCPS")
           (let ((handle (dds.dcps:register-instance dw sample)))
             (%check :dcps-disp-handle
                     (equalp handle (funcall (dds.types:type-support-key-hash ts) sample))
                     "register_instance handle must equal the type-support key-hash")
             (dds.dcps:write-sample dw sample)                  ; SN 1 ALIVE
             (loop repeat 100 until (plusp (dds.disc:node-sample-count node2))
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (let ((rh (dds.dcps:dispose-instance dw handle)))  ; SN 2 dispose
               (%check :dcps-disp-returns (equalp rh handle) "dispose returns the instance handle"))
             (loop repeat 150 until (plusp (dds.disc:node-lifecycle-count node2))
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (%check :dcps-disp-received (plusp (dds.disc:node-lifecycle-count node2))
                     "subscriber engine never received the dispose DATA")
             (let ((lc (dds.disc:node-lifecycle-change node2 2)))
               (%check :dcps-disp-classified
                       (and lc (eq (first lc) :dispose) (equalp (second lc) handle))
                       "dispose DATA classified :dispose with the instance handle"))
             ;; unregister must not error
             (dds.dcps:unregister-instance dw handle)))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

;;; No-key DCPS round-trip (FR-RTPS S0): a keyless type's DataWriter/DataReader come
;;; up NO_KEY (writer 0x03/id 0x103, reader 0x04/id 0x104) — selected by DCPS from the
;;; type's keyed-ness — discover, match same-kind, and deliver a sample end to end.

(dds.gen:define-dds-type nokey-rt (:extensibility :final)
  (a :i32)
  (b :i32))

(defun* run-nokey-roundtrip-test ()
    (function () t)
  "A no-key type round-trips through DCPS: create-datawriter/datareader select the
   NO_KEY endpoint kind from the keyless nokey-rt type (writer id 0x103, reader id
   0x104), the endpoints discover + match same-kind, and a sample {a=7 b=9} survives
   write/take. Proves DCPS threads the type's keyed-ness into the endpoint kind."
  (let* ((ts (dds.types:find-type-support "nokey-rt"))
         (p1 (dds.dcps:create-participant :domain 0))
         (p2 (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "NoKeyTopic" "nokey-rt" ts))
                (tr (dds.dcps:create-topic p2 "NoKeyTopic" "nokey-rt" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr)))
           (%check :nokey-writer-id
                   (= #x00000103 (dds.disc:disc-node-user-writer-id (dds.dcps::dp-node p1)))
                   "no-key DataWriter must come up with data-plane writer id 0x103")
           (%check :nokey-reader-id
                   (= #x00000104 (dds.disc:disc-node-user-reader-id (dds.dcps::dp-node p2)))
                   "no-key DataReader must come up with data-plane reader id 0x104")
           (loop repeat 150
                 until (and (plusp (dds.dcps:matched-count p1))
                            (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :nokey-matched (plusp (dds.dcps:matched-count p1))
                   "no-key DataWriter/DataReader did not match via DCPS")
           (dds.dcps:write-sample dw (make-nokey-rt :a 7 :b 9))
           (let ((got nil))
             (loop repeat 150 until got
                   do (let ((s (dds.dcps:take-samples dr)))
                        (when s (setf got (dds.dcps:cached-sample-data (first s)))))
                      (sleep 0.02))
             (%check :nokey-take (and got t) "DataReader::take returned no no-key sample")
             (%check :nokey-fields
                     (and (= 7 (nokey-rt-a got)) (= 9 (nokey-rt-b got)))
                     "no-key sample fields did not survive write/take")))
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

;;; Reader-side instance_state (instance lifecycle S2, DDS 1.4 §2.2.2.5.1.3/.4/.5): the
;;; reader maintains a per-instance state (ALIVE / NOT_ALIVE_DISPOSED / NOT_ALIVE_NO_WRITERS)
;;; from inbound data + dispose/unregister lifecycle DATA + writer-vanish, and surfaces a
;;; dispose/no-writers change as a valid_data=FALSE SampleInfo carrying the new instance_state.

(defun* %instance-rec-state (dr handle)
    (function (dds.dcps:data-reader (simple-array (unsigned-byte 8) (16))) t)
  "The reader DR's instance_state for the 16-octet HANDLE, or NIL if no record (test accessor)."
  (let ((rec (gethash handle (dds.dcps::dr-instance-recs dr))))
    (and rec (dds.dcps::instance-rec-state rec))))

(defun* %instance-rec-disp-gen (dr handle)
    (function (dds.dcps:data-reader (simple-array (unsigned-byte 8) (16))) t)
  "DR's disposed_generation_count for HANDLE, or NIL if no record (test accessor)."
  (let ((rec (gethash handle (dds.dcps::dr-instance-recs dr))))
    (and rec (dds.dcps::instance-rec-disposed-gen-count rec))))

(defun* %drain-until (dr p1 p2 pred n)
    (function (dds.dcps:data-reader dds.dcps:domain-participant dds.dcps:domain-participant
              function (integer 0)) t)
  "Drive discovery/repair cadence: spin both participants and drain DR up to N times (20ms
   apart), stopping as soon as PRED is true. Bounded — never an unbounded wait."
  (loop repeat n until (funcall pred)
        do (dds.dcps:spin p1) (dds.dcps:spin p2) (dds.dcps:samples-available dr) (sleep 0.02))
  (funcall pred))

(defun* run-dcps-instance-state-test ()
    (function () t)
  "DCPS reader-side instance_state (S2, DDS 1.4 §2.2.2.5.1.3/.4/.5): on the keyed shape-type a
   writer publishes a sample (instance ALIVE), then dispose-instance. The reader, after draining,
   has the instance NOT_ALIVE_DISPOSED, and take returns an invalid-data SampleInfo (valid_data
   FALSE) carrying instance_state NOT_ALIVE_DISPOSED + the right handle. A normal sample before the
   dispose still delivers ALIVE / valid_data TRUE / view-state NEW. A second write REVIVES the
   instance to ALIVE with disposed_generation_count bumped to 1."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p1 (dds.dcps:create-participant :domain 0))
         (p2 (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "Square" "shape-type" ts))
                (tr (dds.dcps:create-topic p2 "Square" "shape-type" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr))
                (sample (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 10))
                (handle (funcall (dds.types:type-support-key-hash ts) sample)))
           (loop repeat 150
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :is-matched (plusp (dds.dcps:matched-count p2)) "S2 endpoints did not match")
           ;; 1) ALIVE sample: a normal valid sample still delivers :alive / valid-data t / view NEW.
           (dds.dcps:write-sample dw sample)
           (%drain-until dr p1 p2 (lambda () (eq :alive (%instance-rec-state dr handle))) 150)
           (%check :is-alive (eq :alive (%instance-rec-state dr handle))
                   "instance must be ALIVE after a data sample")
           (let ((r (dds.dcps:read-samples dr)))
             (%check :is-alive-sample (= 1 (length r)) "expected the one ALIVE sample")
             (let ((info (dds.dcps:cached-sample-info (first r))))
               (%check :is-alive-valid (eq t (dds.dcps:sample-info-valid-data info))
                       "ALIVE sample must have valid_data TRUE")
               (%check :is-alive-state (eq :alive (dds.dcps:sample-info-instance-state info))
                       "ALIVE sample instance_state must be ALIVE")
               (%check :is-alive-view (eq :new (dds.dcps:sample-info-view-state info))
                       "ALIVE sample view-state must be NEW")
               (%check :is-alive-disp-gen (= 0 (dds.dcps:sample-info-disposed-generation-count info))
                       "disposed_generation_count must start at 0")))
           ;; 2) dispose -> NOT_ALIVE_DISPOSED + an invalid-data notification.
           (dds.dcps:dispose-instance dw handle)
           (%drain-until dr p1 p2 (lambda () (eq :not-alive-disposed (%instance-rec-state dr handle))) 150)
           (%check :is-disposed (eq :not-alive-disposed (%instance-rec-state dr handle))
                   "instance must be NOT_ALIVE_DISPOSED after dispose")
           (let ((inv (find-if (lambda (cs) (null (dds.dcps:sample-info-valid-data
                                                   (dds.dcps:cached-sample-info cs))))
                               (dds.dcps:take-samples dr))))
             (%check :is-disposed-sample (and inv t) "dispose must yield an invalid-data sample")
             (let ((info (dds.dcps:cached-sample-info inv)))
               (%check :is-disposed-state
                       (eq :not-alive-disposed (dds.dcps:sample-info-instance-state info))
                       "invalid-data sample instance_state must be NOT_ALIVE_DISPOSED")
               (%check :is-disposed-handle (equalp handle (dds.dcps:sample-info-instance-handle info))
                       "invalid-data sample must carry the instance handle")
               (%check :is-disposed-nodata (null (dds.dcps:cached-sample-data inv))
                       "invalid-data sample must carry no Data")))
           ;; 3) revive: a new write -> ALIVE with disposed_generation_count bumped to 1.
           (dds.dcps:write-sample dw sample)
           (%drain-until dr p1 p2 (lambda () (eq :alive (%instance-rec-state dr handle))) 150)
           (%check :is-revived (eq :alive (%instance-rec-state dr handle))
                   "a new write must revive the instance to ALIVE")
           (%check :is-revived-gen (= 1 (%instance-rec-disp-gen dr handle))
                   "disposed_generation_count must bump to 1 on NOT_ALIVE_DISPOSED->ALIVE")
           (let ((info (dds.dcps:cached-sample-info
                        (first (dds.dcps:read-samples dr :states '(:not-read))))))
             (%check :is-revived-info-gen (= 1 (dds.dcps:sample-info-disposed-generation-count info))
                     "the revived sample's SampleInfo must carry disposed_generation_count 1")))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

(defun* run-dcps-no-writers-test ()
    (function () t)
  "DCPS reader-side NOT_ALIVE_NO_WRITERS (S2, DDS 1.4 §2.2.2.5.1.3): a writer publishes a keyed
   sample (instance ALIVE, registering the writer), then unregister-instance relinquishes the
   writer's ownership; with no writers left the reader transitions the instance NOT_ALIVE_NO_WRITERS
   and surfaces an invalid-data SampleInfo carrying that state. (v1 single user writer per remote
   participant -> the unregister is the last-writer case.)"
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p1 (dds.dcps:create-participant :domain 0))
         (p2 (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "Square" "shape-type" ts))
                (tr (dds.dcps:create-topic p2 "Square" "shape-type" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr))
                (sample (make-shape-type :color "GREEN" :x 5 :y 5 :shapesize 22))
                (handle (funcall (dds.types:type-support-key-hash ts) sample)))
           (loop repeat 150
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :nw-matched (plusp (dds.dcps:matched-count p2)) "no-writers endpoints did not match")
           (dds.dcps:write-sample dw sample)
           (%drain-until dr p1 p2 (lambda () (eq :alive (%instance-rec-state dr handle))) 150)
           (%check :nw-alive (eq :alive (%instance-rec-state dr handle))
                   "instance must be ALIVE after the data sample")
           (dds.dcps:unregister-instance dw handle)
           (%drain-until dr p1 p2 (lambda () (eq :not-alive-no-writers (%instance-rec-state dr handle))) 150)
           (%check :nw-no-writers (eq :not-alive-no-writers (%instance-rec-state dr handle))
                   "instance must be NOT_ALIVE_NO_WRITERS after the last writer unregisters")
           (let ((inv (find-if (lambda (cs) (null (dds.dcps:sample-info-valid-data
                                                   (dds.dcps:cached-sample-info cs))))
                               (dds.dcps:take-samples dr))))
             (%check :nw-sample (and inv t) "unregister must yield an invalid-data sample")
             (%check :nw-state (eq :not-alive-no-writers
                                   (dds.dcps:sample-info-instance-state (dds.dcps:cached-sample-info inv)))
                     "invalid-data sample instance_state must be NOT_ALIVE_NO_WRITERS")))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

(defun* run-dcps-disposed-sticky-test ()
    (function () t)
  "DCPS reader-side DISPOSED-stickiness (S2, DDS 1.4 §2.2.2.5.1.3, service_cleanup_delay): a disposed
   instance stays NOT_ALIVE_DISPOSED until a sample revives it — an unregister of its last writer must
   NOT override it to NOT_ALIVE_NO_WRITERS (dispose dominates no-writers). A writer publishes a sample
   (ALIVE), disposes the instance (NOT_ALIVE_DISPOSED), then unregisters it; the reader stays DISPOSED
   and the unregister produces NO new invalid-data sample (no state transition, Issues 1+3)."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p1 (dds.dcps:create-participant :domain 0))
         (p2 (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "Square" "shape-type" ts))
                (tr (dds.dcps:create-topic p2 "Square" "shape-type" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr))
                (sample (make-shape-type :color "RED" :x 3 :y 3 :shapesize 14))
                (handle (funcall (dds.types:type-support-key-hash ts) sample)))
           (loop repeat 150
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :ds-matched (plusp (dds.dcps:matched-count p2)) "disposed-sticky endpoints did not match")
           (dds.dcps:write-sample dw sample)
           (%drain-until dr p1 p2 (lambda () (eq :alive (%instance-rec-state dr handle))) 150)
           (%check :ds-alive (eq :alive (%instance-rec-state dr handle)) "instance must be ALIVE first")
           (dds.dcps:dispose-instance dw handle)
           (%drain-until dr p1 p2 (lambda () (eq :not-alive-disposed (%instance-rec-state dr handle))) 150)
           (%check :ds-disposed (eq :not-alive-disposed (%instance-rec-state dr handle))
                   "instance must be NOT_ALIVE_DISPOSED after dispose")
           (dds.dcps:take-samples dr)                ; drain the dispose notification out of the cache
           ;; unregister the last writer -> must NOT flip a disposed instance to no-writers.
           (dds.dcps:unregister-instance dw handle)
           (%drain-until dr p1 p2 (lambda () nil) 60) ; bounded settle; PRED never true (no transition expected)
           (%check :ds-still-disposed (eq :not-alive-disposed (%instance-rec-state dr handle))
                   "DISPOSED must stay DISPOSED — unregister must not override it to NO_WRITERS")
           (%check :ds-no-new-sample (null (dds.dcps:take-samples dr))
                   "a no-op unregister (DISPOSED stays DISPOSED) must produce NO invalid-data sample"))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

(defun* run-dcps-writer-unmatch-test ()
    (function () t)
  "DCPS reader-side NOT_ALIVE_NO_WRITERS on writer-unmatch (S2, DDS 1.4 §2.2.2.5.1.3): a reader
   with an ALIVE instance written by a (synthetic, offline) remote writer transitions the instance
   NOT_ALIVE_NO_WRITERS when that writer's match is removed (lease expiry -> %on-disc-unmatch), and
   surfaces a valid_data=FALSE notification. Deterministic offline injection, no UDP wait — the
   writers-set is seeded via the same %reader-revive-instance path the data plane uses."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "Square" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr (dds.dcps:create-datareader sub tp))
                (handle (make-array 16 :element-type '(unsigned-byte 8) :initial-element 3))
                ;; A synthetic matched remote WRITER GUID (kind 0x02 with-key); its last 4 octets
                ;; are the EntityId the writers-set keys on.
                (wguid (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x55)))
                         (setf (aref g 12) #x00 (aref g 13) #x00 (aref g 14) #x01 (aref g 15) #x02) g))
                (wid (dds.dcps::%guid-entityid wguid))
                (rw (dds.rtps.discovery:make-endpoint-data
                     :guid wguid :topic-name "Square" :type-name "shape-type")))
           ;; Seed an ALIVE instance with WID in its writers set (mirrors a delivered data sample).
           (dds.dcps::%reader-revive-instance dr handle wid)
           (%check :wu-alive (eq :alive (%instance-rec-state dr handle))
                   "seeded instance must be ALIVE with the writer registered")
           ;; The writer's match vanishes (lease expiry) -> last writer gone -> NOT_ALIVE_NO_WRITERS.
           (dds.dcps::%on-disc-unmatch p :remote-writer rw)
           (%check :wu-no-writers (eq :not-alive-no-writers (%instance-rec-state dr handle))
                   "instance must be NOT_ALIVE_NO_WRITERS after the writer unmatches")
           (let ((inv (find-if (lambda (cs) (null (dds.dcps:sample-info-valid-data
                                                   (dds.dcps:cached-sample-info cs))))
                               (dds.dcps:take-samples dr))))
             (%check :wu-sample (and inv t) "writer-unmatch must yield an invalid-data sample")
             (%check :wu-state (eq :not-alive-no-writers
                                   (dds.dcps:sample-info-instance-state (dds.dcps:cached-sample-info inv)))
                     "invalid-data sample instance_state must be NOT_ALIVE_NO_WRITERS")))
      (dds.dcps:delete-participant p))
    t))

;;; Unified SN-ordered drain (instance lifecycle S2 corner, DDS 1.4 §2.2.2.5 / RTPS 2.5 §8.7.4):
;;; data samples and dispose/unregister lifecycle changes share ONE writer SN space, so within ONE
;;; %drain pass they MUST be applied in sequence-number order — the higher SN wins. Deterministic
;;; offline injection: stage both changes into the engine's SN maps, then drive %drain once (no UDP).

(defun* %stage-data-sn (node sn handle bytes wid)
    (function (t integer (simple-array (unsigned-byte 8) (16))
              (simple-array (unsigned-byte 8) (*)) (unsigned-byte 32)) t)
  "Stage a data sample (serialized BYTES, written by WID) at sequence number SN in NODE's composite
   (GUID, SN) maps — the same (payload + writer + source GUID) records %deliver-user-sample writes,
   minus the wire. The source GUID is a zero-prefix + WID EntityId so the drain's per-writer high-water
   keys it (a one-writer scenario; §8.3.5.4)."
  (declare (ignore handle))
  (let ((guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref guid 12) (ldb (byte 8 24) wid) (aref guid 13) (ldb (byte 8 16) wid)
          (aref guid 14) (ldb (byte 8 8) wid) (aref guid 15) (ldb (byte 8 0) wid))
    (setf (gethash sn (dds.disc::%inner-table (dds.disc::disc-node-samples node) guid)) bytes
          (gethash sn (dds.disc::%inner-table (dds.disc::disc-node-sample-writers node) guid)) wid
          (gethash sn (dds.disc::%inner-table (dds.disc::disc-node-sample-writer-guids node) guid)) guid))
  t)

(defun* %stage-lifecycle-sn (node sn kind handle wid)
    (function (t integer (member :dispose :unregister)
              (simple-array (unsigned-byte 8) (16)) (unsigned-byte 32)) t)
  "Stage a dispose/unregister lifecycle change at sequence number SN in NODE's SN map — the same
   (SN -> (kind key-hash status-flags writer-id source-guid)) record %on-user-lifecycle writes, minus
   the wire. The source GUID is a zero-prefix + WID EntityId (the owner-clear key, DDS 1.4 §2.2.3.9.2)."
  (let ((guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref guid 12) (ldb (byte 8 24) wid) (aref guid 13) (ldb (byte 8 16) wid)
          (aref guid 14) (ldb (byte 8 8) wid) (aref guid 15) (ldb (byte 8 0) wid))
    (setf (gethash sn (dds.disc::disc-node-lifecycle-changes node))
          (list kind handle 0 wid guid)))
  t)

(defun* run-dcps-drain-sn-order-test ()
    (function () t)
  "DCPS unified SN-ordered drain (S2 corner, DDS 1.4 §2.2.2.5 / RTPS 2.5 §8.7.4): within ONE %drain
   pass, a dispose at the LOWER SN followed by a revive data sample at the HIGHER SN for the SAME
   instance must end ALIVE (the revive wins because it has the higher SN) with disposed_generation_count
   1; the REVERSE (a data sample at the lower SN, then a dispose at the higher SN) must end
   NOT_ALIVE_DISPOSED. Drives %drain directly after staging both changes in the engine's SN maps —
   deterministic, no UDP, no unbounded wait."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "Square" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr (dds.dcps:create-datareader sub tp))
                (node (dds.dcps::dp-node p))
                (sample (make-shape-type :color "BLUE" :x 7 :y 7 :shapesize 18))
                (handle (funcall (dds.types:type-support-key-hash ts) sample))
                (bytes (dds.dcps::%serialize-sample ts sample))
                (wid #x00000102))
           ;; Direction A: dispose (lower SN 10) then revive (higher SN 11) in ONE drain pass -> ALIVE.
           (%stage-lifecycle-sn node 10 :dispose handle wid)
           (%stage-data-sn node 11 handle bytes wid)
           (dds.dcps::%drain dr)
           (%check :dso-a-alive (eq :alive (%instance-rec-state dr handle))
                   "dispose@10 then revive@11 in one pass must end ALIVE (higher SN wins)")
           (%check :dso-a-gen (= 1 (%instance-rec-disp-gen dr handle))
                   "the revive must bump disposed_generation_count to 1")
           ;; Direction B: a fresh instance, data (lower SN 20) then dispose (higher SN 21) -> DISPOSED.
           (let* ((sample2 (make-shape-type :color "RED" :x 9 :y 9 :shapesize 24))
                  (handle2 (funcall (dds.types:type-support-key-hash ts) sample2))
                  (bytes2 (dds.dcps::%serialize-sample ts sample2)))
             (%stage-data-sn node 20 handle2 bytes2 wid)
             (%stage-lifecycle-sn node 21 :dispose handle2 wid)
             (dds.dcps::%drain dr)
             (%check :dso-b-disposed (eq :not-alive-disposed (%instance-rec-state dr handle2))
                     "data@20 then dispose@21 in one pass must end NOT_ALIVE_DISPOSED (higher SN wins)")
             (%check :dso-b-gen (= 0 (%instance-rec-disp-gen dr handle2))
                     "no revive occurred -> disposed_generation_count stays 0")))
      (dds.dcps:delete-participant p))
    t))

;;; EXCLUSIVE reader-side OWNERSHIP arbitration (S1, DDS 1.4 §2.2.3.9.2 / §2.2.3.10): an EXCLUSIVE
;;; DataReader delivers, per instance, ONLY the samples of the OWNER = the highest-strength alive
;;; matched writer; lower-strength writers' samples are dropped. On owner loss a remaining writer
;;; takes over. SHARED readers (the default) deliver everything (no arbitration). Deterministic
;;; offline injection: seed two matched remote writers (different participant prefixes, same EntityId
;;; 0x102) into the node's matches table with EXCLUSIVE + strengths 10/20, stage their samples by
;;; FULL source GUID in the engine's SN maps, drive %drain, and assert which samples land.

(defun* %two-writer-guid (lastbyte)
    (function ((unsigned-byte 8)) (simple-array (unsigned-byte 8) (16)))
  "A synthetic remote WRITER GUID: a per-participant prefix (varied by LASTBYTE so two writers live
   on different participants) + the user-data writer EntityId 0x00000102 (RTPS 2.5 §9.3.1.2)."
  (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x40)))
    (setf (aref g 11) lastbyte
          (aref g 12) #x00 (aref g 13) #x00 (aref g 14) #x01 (aref g 15) #x02)
    g))

(defun* %seed-exclusive-match (node guid strength)
    (function (t (simple-array (unsigned-byte 8) (16)) integer) t)
  "Register a matched remote WRITER (GUID) in NODE's matches table with EXCLUSIVE ownership and
   the given STRENGTH — exactly the endpoint-data %match-remote-writer records, minus the wire,
   so matched-writer-ownership can resolve a sample's source GUID to (kind strength)."
  (let ((ep (dds.rtps.discovery:make-endpoint-data
             :guid guid :topic-name "Square" :type-name "shape-type"
             :qos (dds.qos:make-qos :ownership :exclusive :ownership-strength strength))))
    (setf (gethash (copy-seq guid) (dds.disc::disc-node-matches node)) ep))
  t)

(defun* %stage-data-sn-guid (node sn bytes guid)
    (function (t integer (simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (16))) t)
  "Stage a data sample (serialized BYTES) at sequence number SN keyed by the (GUID, SN) composite key
   built from its FULL 16-octet source GUID — the (payload + EntityId, S2 + GUID, S1) records the
   receive path writes, minus the wire (§8.3.5.4: keyed by GUID+SN so two writers do not alias)."
  (setf (gethash sn (dds.disc::%inner-table (dds.disc::disc-node-samples node) guid)) bytes
        (gethash sn (dds.disc::%inner-table (dds.disc::disc-node-sample-writers node) guid))
        (dds.dcps::%guid-entityid guid)
        (gethash sn (dds.disc::%inner-table (dds.disc::disc-node-sample-writer-guids node) guid))
        (copy-seq guid))
  t)

(defun* %own-handle-count (dr handle)
    (function (dds.dcps:data-reader (simple-array (unsigned-byte 8) (16))) (integer 0))
  "How many VALID-DATA samples for instance HANDLE the reader DR has cached (test accessor for the
   ownership arbitration result — the dropped lower-strength samples never enter the cache)."
  (count-if (lambda (cs)
              (let ((info (dds.dcps:cached-sample-info cs)))
                (and (dds.dcps:sample-info-valid-data info)
                     (equalp handle (dds.dcps:sample-info-instance-handle info)))))
            (dds.dcps::dr-cache dr)))

(defun* %ownership-scenario (reader-ownership)
    (function ((member :shared :exclusive)) (values integer integer))
  "Drive the two-writer arbitration offline for a reader with the given OWNERSHIP kind. Writer A
   (strength 10) and writer B (strength 20) both write the SAME instance; B then vanishes (unmatch);
   writer A writes again. Returns (values SAMPLES-BEFORE-VANISH SAMPLES-AFTER-TAKEOVER) — the count of
   valid-data samples cached for the instance before B vanished and the extra count A delivered after."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "Square" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr (dds.dcps:create-datareader
                     sub tp :qos (dds.qos:make-reader-qos :ownership reader-ownership)))
                (node (dds.dcps::dp-node p))
                (guid-a (%two-writer-guid #x0a))
                (guid-b (%two-writer-guid #x0b))
                (ep-b (dds.rtps.discovery:make-endpoint-data
                       :guid guid-b :topic-name "Square" :type-name "shape-type"))
                (sample (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 10))
                (handle (funcall (dds.types:type-support-key-hash ts) sample))
                (bytes (dds.dcps::%serialize-sample ts sample)))
           (%seed-exclusive-match node guid-a 10)
           (%seed-exclusive-match node guid-b 20)
           ;; Higher-strength B owns from SN 1; lower-strength A at SN 2/3 must be dropped (it never
           ;; out-ranks the owner). (Both writers known a priori — the deterministic arbitration case;
           ;; §2.2.3.9.2 also lets a first-seen lower writer own until a higher one appears, which is a
           ;; separate transient handled by the takeover assertion below.)
           (%stage-data-sn-guid node 1 bytes guid-b)
           (%stage-data-sn-guid node 2 bytes guid-a)
           (%stage-data-sn-guid node 3 bytes guid-a)
           (dds.dcps::%drain dr)
           (let ((before (%own-handle-count dr handle)))
             ;; The owner (B) vanishes: A is now the highest-strength alive writer and takes over.
             (dds.dcps::%on-disc-unmatch p :remote-writer ep-b)
             (%stage-data-sn-guid node 4 bytes guid-a)
             (dds.dcps::%drain dr)
             (values before (- (%own-handle-count dr handle) before))))
      (dds.dcps:delete-participant p))))

(defun* %first-seen-ownership-scenario ()
    (function () (values integer integer integer))
  "Drive the first-seen EXCLUSIVE ownership transient (DDS 1.4 §2.2.3.9.2: the FIRST writer of an
   instance owns it until a HIGHER-strength writer appears). Lower-strength A (10) writes the instance
   FIRST and owns it; then higher-strength B (20) writes and takes over; then A writes again and is
   dropped. Returns (values AFTER-A1 AFTER-B2 AFTER-A3) — the cumulative valid-data sample count for
   the instance after each successive drain."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "Square" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr (dds.dcps:create-datareader
                     sub tp :qos (dds.qos:make-reader-qos :ownership :exclusive)))
                (node (dds.dcps::dp-node p))
                (guid-a (%two-writer-guid #x0a))
                (guid-b (%two-writer-guid #x0b))
                (sample (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 10))
                (handle (funcall (dds.types:type-support-key-hash ts) sample))
                (bytes (dds.dcps::%serialize-sample ts sample)))
           (%seed-exclusive-match node guid-a 10)
           (%seed-exclusive-match node guid-b 20)
           (%stage-data-sn-guid node 1 bytes guid-a)   ; A (10) writes first -> owns
           (dds.dcps::%drain dr)
           (let ((after-a1 (%own-handle-count dr handle)))
             (%stage-data-sn-guid node 2 bytes guid-b) ; B (20) appears -> takes over
             (dds.dcps::%drain dr)
             (let ((after-b2 (%own-handle-count dr handle)))
               (%stage-data-sn-guid node 3 bytes guid-a) ; A again -> now dropped
               (dds.dcps::%drain dr)
               (values after-a1 after-b2 (%own-handle-count dr handle)))))
      (dds.dcps:delete-participant p))))

(defun* run-dcps-exclusive-ownership-test ()
    (function () t)
  "DCPS reader-side EXCLUSIVE OWNERSHIP arbitration + takeover (S1, DDS 1.4 §2.2.3.9.2 / §2.2.3.10):
   two writers (strength 10 and 20) write the same instance to an EXCLUSIVE reader. The reader
   delivers ONLY the strength-20 owner's samples; the strength-10 writer's samples are DROPPED (not in
   the cache). When the strength-20 owner vanishes (unmatch), the strength-10 writer takes over and its
   subsequent sample IS delivered. The first-seen transient (§2.2.3.9.2: the FIRST writer owns until a
   higher-strength writer appears) is also asserted: a lower-strength writer seen first owns and is
   delivered, a higher-strength writer then displaces it, and the lower writer's later samples drop. A
   SHARED reader (the default) delivers BOTH writers' samples (arbitration off). Deterministic offline
   injection — no UDP, no unbounded wait."
  ;; EXCLUSIVE: of the three pre-vanish samples (B@1, A@2, A@3) only B@1 (owner) is delivered.
  (multiple-value-bind (before after) (%ownership-scenario :exclusive)
    (%check :own-excl-before (= 1 before)
            "EXCLUSIVE reader must deliver ONLY the strength-20 owner's sample (2 lower-strength dropped)")
    (%check :own-excl-takeover (= 1 after)
            "after the owner vanishes the remaining writer takes over and its sample IS delivered"))
  ;; SHARED: all three pre-vanish samples are delivered (no arbitration), plus one after.
  (multiple-value-bind (before after) (%ownership-scenario :shared)
    (%check :own-shared-before (= 3 before)
            "SHARED reader must deliver BOTH writers' samples (no arbitration)")
    (%check :own-shared-after (= 1 after)
            "SHARED reader keeps delivering after the unmatch"))
  ;; FIRST-SEEN (§2.2.3.9.2): A@1 (10) owns first (1 cached); B@2 (20) displaces (2 cached); A@3 drops.
  (multiple-value-bind (after-a1 after-b2 after-a3) (%first-seen-ownership-scenario)
    (%check :own-first-seen-a1 (= 1 after-a1)
            "the first writer (lower strength) owns the instance and its sample IS delivered")
    (%check :own-first-seen-b2 (= 2 after-b2)
            "a higher-strength writer then displaces the first owner and its sample IS delivered")
    (%check :own-first-seen-a3 (= 2 after-a3)
            "the displaced lower-strength writer's later sample is DROPPED (count unchanged)"))
  t)

(defun* %pre-match-ownership-scenario ()
    (function () (values integer integer))
  "Drive the EXCLUSIVE pre-match transient (DDS 1.4 §2.2.3.9.2): a data sample is staged for an
   EXCLUSIVE reader from a writer whose SEDP match has NOT yet arrived (strength unresolved), then drained;
   the sample must be DROPPED THIS pass but LEFT PENDING (the reliable engine already ACKed it, so
   advancing the per-writer watermark would lose it permanently). The match + strength are then seeded
   and the reader drained again. Returns (values BEFORE-MATCH AFTER-MATCH) — the valid-data sample count
   for the instance before the match (must be 0) and after (must be 1: the once-pending sample now
   arbitrates and is delivered)."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "Square" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr (dds.dcps:create-datareader
                     sub tp :qos (dds.qos:make-reader-qos :ownership :exclusive)))
                (node (dds.dcps::dp-node p))
                (guid-a (%two-writer-guid #x0a))
                (sample (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 10))
                (handle (funcall (dds.types:type-support-key-hash ts) sample))
                (bytes (dds.dcps::%serialize-sample ts sample)))
           ;; Stage A's sample BEFORE seeding A's SEDP match -> strength unresolved -> :drop-unmatched.
           (%stage-data-sn-guid node 1 bytes guid-a)
           (dds.dcps::%drain dr)
           (let ((before (%own-handle-count dr handle)))
             ;; The SEDP match now arrives; the once-unmatched sample must STILL be pending and deliver.
             (%seed-exclusive-match node guid-a 10)
             (dds.dcps::%drain dr)
             (values before (%own-handle-count dr handle))))
      (dds.dcps:delete-participant p))))

(defun* run-dcps-exclusive-pre-match-test ()
    (function () t)
  "DCPS EXCLUSIVE pre-match data-loss guard (S1, DDS 1.4 §2.2.3.9.2): a sample from an
   identified-but-not-yet-SEDP-matched writer arrives at an EXCLUSIVE reader. Its strength is unresolved,
   so it is dropped THIS drain — but the per-writer drain watermark must NOT advance (the reliable engine
   already ACKed it and will never retransmit), or the sample is lost permanently once the match arrives.
   Asserts: before the match the sample is NOT delivered AND not permanently dropped; after the match
   arrives a re-drain delivers it. Deterministic offline injection — no UDP, no unbounded wait."
  (multiple-value-bind (before after) (%pre-match-ownership-scenario)
    (%check :own-pre-match-before (= 0 before)
            "an unmatched writer's sample must NOT reach an EXCLUSIVE reader's cache before the match")
    (%check :own-pre-match-after (= 1 after)
            "the once-unmatched sample must survive (watermark left pending) and deliver after the match"))
  t)

;;; EXCLUSIVE owner-clear targets the FULL source GUID, not the EntityId (S1, DDS 1.4 §2.2.3.9.2): two
;;; writers sharing EntityId 0x102 on different participants own different instances; a dispose from
;;; one must clear ONLY its own ownership, never the other's. An EntityId-only compare would
;;; cross-clear. Deterministic offline injection: seed both writers, give each its own instance, then
;;; dispose writer A's instance and assert writer B still owns its own instance.

(defun* %stage-lifecycle-sn-guid (node sn kind handle guid)
    (function (t integer (member :dispose :unregister)
              (simple-array (unsigned-byte 8) (16)) (simple-array (unsigned-byte 8) (16))) t)
  "Stage a dispose/unregister lifecycle change at SN keyed by its FULL 16-octet source GUID — the
   (SN -> (kind key-hash status-flags writer-id source-guid)) record %on-user-lifecycle writes, minus
   the wire (the owner-clear key, DDS 1.4 §2.2.3.9.2)."
  (setf (gethash sn (dds.disc::disc-node-lifecycle-changes node))
        (list kind handle 0 (dds.dcps::%guid-entityid guid) (copy-seq guid)))
  t)

(defun* %instance-rec-owner-guid (dr handle)
    (function (dds.dcps:data-reader (simple-array (unsigned-byte 8) (16))) t)
  "DR's EXCLUSIVE owner GUID for HANDLE, or NIL if unowned/no record (test accessor)."
  (let ((rec (gethash handle (dds.dcps::dr-instance-recs dr))))
    (and rec (dds.dcps::instance-rec-owner-guid rec))))

(defun* run-dcps-dispose-owner-clear-test ()
    (function () t)
  "EXCLUSIVE owner-clear uses the FULL source GUID (S1, DDS 1.4 §2.2.3.9.2): writers A and B share
   EntityId 0x102 on different participants. A owns instance-A; B owns instance-B. A disposes
   instance-A — its ownership clears, but B's ownership of instance-B MUST survive (an EntityId-only
   compare would wrongly cross-clear B). Deterministic offline injection — no UDP."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "Square" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr (dds.dcps:create-datareader
                     sub tp :qos (dds.qos:make-reader-qos :ownership :exclusive)))
                (node (dds.dcps::dp-node p))
                (guid-a (%two-writer-guid #x0a))
                (guid-b (%two-writer-guid #x0b))
                (sample-a (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 10))
                (sample-b (make-shape-type :color "RED" :x 2 :y 2 :shapesize 20))
                (handle-a (funcall (dds.types:type-support-key-hash ts) sample-a))
                (handle-b (funcall (dds.types:type-support-key-hash ts) sample-b))
                (bytes-a (dds.dcps::%serialize-sample ts sample-a))
                (bytes-b (dds.dcps::%serialize-sample ts sample-b)))
           (%seed-exclusive-match node guid-a 10)
           (%seed-exclusive-match node guid-b 10)
           ;; A writes instance-A (owns it); B writes instance-B (owns it).
           (%stage-data-sn-guid node 1 bytes-a guid-a)
           (%stage-data-sn-guid node 2 bytes-b guid-b)
           (dds.dcps::%drain dr)
           (%check :doc-a-owns (equalp guid-a (%instance-rec-owner-guid dr handle-a))
                   "writer A must own instance-A after its first sample")
           (%check :doc-b-owns (equalp guid-b (%instance-rec-owner-guid dr handle-b))
                   "writer B must own instance-B after its first sample")
           ;; A disposes instance-A: only A's ownership clears; B (same EntityId 0x102) must survive.
           (%stage-lifecycle-sn-guid node 3 :dispose handle-a guid-a)
           (dds.dcps::%drain dr)
           (%check :doc-a-cleared (null (%instance-rec-owner-guid dr handle-a))
                   "A's dispose must clear A's own ownership of instance-A")
           (%check :doc-b-survives (equalp guid-b (%instance-rec-owner-guid dr handle-b))
                   "A's dispose must NOT cross-clear B (same EntityId 0x102, different participant)"))
      (dds.dcps:delete-participant p))
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
(defmethod dds.dcps:on-liveliness-changed ((l capturing-reader-listener) reader status)
  (declare (ignore reader))
  (dds.pal:with-lock ((cap-lock l)) (push (cons :liv-changed status) (cap-hits l))))
(defmethod dds.dcps:on-liveliness-lost ((l capturing-writer-listener) writer status)
  (declare (ignore writer))
  (dds.pal:with-lock ((cap-lock l)) (push (cons :liv-lost status) (cap-hits l))))

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

;;; Enumerated type model (M4, FR-TYPE-4 S0): the in-memory MinimalEnumeratedType and its
;;; EK_MINIMAL referenced TypeIdentifier, the descriptor assignability recurses into.

(defun* run-enum-model-test ()
    (function () t)
  "minimal-enumerated-type + enumerated-type-identifier build an EK_MINIMAL TI whose
   referenced descriptor carries the literals (NameHash . value) and bit-bound."
  (let* ((lits (list (dds.types:make-enum-literal "RED" 0)
                     (dds.types:make-enum-literal "GREEN" 1)
                     (dds.types:make-enum-literal "BLUE" 2)))
         (e (dds.types:make-minimal-enumerated-type :bit-bound 32 :literals lits))
         (ti (dds.types:enumerated-type-identifier e)))
    (assert (= (dds.types:type-identifier-kind ti) dds.types:+ek-minimal+))
    (assert (dds.types:minimal-enumerated-type-p (dds.types:type-identifier-referenced ti)))
    (assert (= 3 (length (dds.types:minimal-enumerated-type-literals
                          (dds.types:type-identifier-referenced ti)))))
    (assert (= 1 (dds.types:enum-literal-value
                  (second (dds.types:minimal-enumerated-type-literals
                           (dds.types:type-identifier-referenced ti))))))
    t))

;;; Distinct 8-bit kinds (M4, FR-TYPE-4, D1): XTypes 1.3 defines THREE 8-bit kinds —
;;; TK_BYTE (0x02, octet), TK_INT8 (0x0C), TK_UINT8 (0x0D). :i8 -> TK_INT8, :u8 -> TK_UINT8,
;;; :byte/:octet -> TK_BYTE. All three are primitive (no int8/uint8 false-reject); int8 is
;;; assignable-from int8 but NOT from uint8 (distinct kinds, Table 15).

(defun* run-int8-uint8-byte-kinds-test ()
    (function () t)
  "primitive-type-identifier maps :i8 -> TK_INT8 (0x0C), :u8 -> TK_UINT8 (0x0D), :byte and
   :octet -> TK_BYTE (0x02); ti-primitive-p is T for all three; int8-vs-int8 assignability
   is T (the D1 false-reject is gone) while int8-vs-uint8 is NIL (distinct kinds, Table 15)."
  (let ((i8 (dds.types:primitive-type-identifier :i8))
        (u8 (dds.types:primitive-type-identifier :u8))
        (byte (dds.types:primitive-type-identifier :byte))
        (octet (dds.types:primitive-type-identifier :octet))
        (opts (dds.types:default-assignability-options)))
    (%check :d1-i8-kind (= (dds.types:type-identifier-kind i8) dds.types:+tk-int8+)
            ":i8 maps to TK_INT8 (0x0C)")
    (%check :d1-u8-kind (= (dds.types:type-identifier-kind u8) dds.types:+tk-uint8+)
            ":u8 maps to TK_UINT8 (0x0D)")
    (%check :d1-byte-kind (= (dds.types:type-identifier-kind byte) dds.types:+tk-byte+)
            ":byte maps to TK_BYTE (0x02)")
    (%check :d1-octet-kind (= (dds.types:type-identifier-kind octet) dds.types:+tk-byte+)
            ":octet aliases :byte -> TK_BYTE (0x02)")
    (%check :d1-i8-primitive (and (dds.types:ti-primitive-p i8) t) "TK_INT8 is a primitive")
    (%check :d1-u8-primitive (and (dds.types:ti-primitive-p u8) t) "TK_UINT8 is a primitive")
    (%check :d1-byte-primitive (and (dds.types:ti-primitive-p byte) t) "TK_BYTE is a primitive")
    (%check :d1-i8-self-assignable
            (and (dds.types:ti-assignable-from i8 (dds.types:primitive-type-identifier :i8) opts) t)
            "int8 is-assignable-from int8 (D1 false-reject removed)")
    (%check :d1-i8-not-from-u8
            (not (dds.types:ti-assignable-from i8 u8 opts))
            "int8 is NOT assignable-from uint8 (distinct kinds, Table 15)"))
  t)

;;; Enumerated assignability (M4, FR-TYPE-4 S0): the sound under-approximation of the
;;; XTypes §7.2.4.4.7 Table 18 ENUMERATION_TYPE row — reject only a provable incompatibility.

(defun* run-enum-assignability-test ()
    (function () t)
  "enum-assignable-from rejects ONLY a provable incompatibility (same literal name, different
   value); identical enums are assignable both ways; a differing-value enum is not; an
   extra-literal-on-one-side is uncertain -> assignable (fail-open)."
  (flet ((enum (&rest pairs)
           (dds.types:make-minimal-enumerated-type
            :bit-bound 32
            :literals (loop for (n v) on pairs by #'cddr collect (dds.types:make-enum-literal n v)))))
    (let ((a (enum "RED" 0 "GREEN" 1 "BLUE" 2))
          (same (enum "RED" 0 "GREEN" 1 "BLUE" 2))
          (badval (enum "RED" 0 "GREEN" 1 "BLUE" 3))
          (opts (dds.types:default-assignability-options)))
      (assert (dds.types:enum-assignable-from a same opts))
      (assert (dds.types:enum-assignable-from same a opts))
      (assert (not (dds.types:enum-assignable-from a badval opts)))
      (assert (not (dds.types:enum-assignable-from badval a opts)))
      (assert (dds.types:enum-assignable-from a (enum "RED" 0 "GREEN" 1) opts))
      t)))

;;; Plain-array model (M4, FR-TYPE-4 S1): the plain-array TypeIdentifier carrying the element
;;; TI and a single fixed dimension.

(defun* run-array-model-test ()
    (function () t)
  "array-type-identifier builds a plain-array TI carrying the element TI and the fixed size."
  (let ((ti (dds.types:array-type-identifier (dds.types:primitive-type-identifier :i32) 4)))
    (assert (dds.types:ti-array-p ti))
    (assert (= 4 (dds.types:type-identifier-bound ti)))
    (assert (= dds.types:+tk-int32+ (dds.types:type-identifier-kind
                                     (dds.types:type-identifier-element ti))))
    t))

;;; Plain-array assignability (M4, FR-TYPE-4 S1): arrays are assignable iff the element is
;;; strongly-assignable AND the fixed dimensions are identical (arrays are not resizable).

(defun* run-array-assignability-test ()
    (function () t)
  "Arrays are assignable iff element strongly-assignable AND identical fixed size (arrays are
   not resizable). A different size or element kind is a provable incompatibility."
  (let ((opts (dds.types:default-assignability-options))
        (a (dds.types:array-type-identifier (dds.types:primitive-type-identifier :i32) 4)))
    (assert (dds.types:ti-assignable-from a (dds.types:array-type-identifier (dds.types:primitive-type-identifier :i32) 4) opts))
    (assert (not (dds.types:ti-assignable-from a (dds.types:array-type-identifier (dds.types:primitive-type-identifier :i32) 5) opts)))
    (assert (not (dds.types:ti-assignable-from a (dds.types:array-type-identifier (dds.types:primitive-type-identifier :i64) 4) opts)))
    t))

;;; Union type model (M4, FR-TYPE-4 S2): the in-memory MinimalUnionType and its EK_MINIMAL
;;; referenced TypeIdentifier, the descriptor assignability recurses into.

(defun* run-union-model-test ()
    (function () t)
  "union-type-identifier builds an EK_MINIMAL TI whose referenced descriptor carries the
   discriminator TI and members (each with labels, member TI, default-p, NameHash)."
  (let* ((m0 (dds.types:make-union-member "a" '(0) (dds.types:primitive-type-identifier :i32) nil))
         (m1 (dds.types:make-union-member "b" '(1) (dds.types:primitive-type-identifier :f64) nil))
         (u (dds.types:make-minimal-union-type
             :discriminator (dds.types:primitive-type-identifier :i32) :members (list m0 m1)))
         (ti (dds.types:union-type-identifier u)))
    (assert (= (dds.types:type-identifier-kind ti) dds.types:+ek-minimal+))
    (assert (dds.types:minimal-union-type-p (dds.types:type-identifier-referenced ti)))
    (assert (equal '(0) (dds.types:union-member-labels
                         (first (dds.types:minimal-union-type-members
                                 (dds.types:type-identifier-referenced ti))))))
    t))

;;; Union assignability (M4, FR-TYPE-4 S2): the sound under-approximation of the XTypes
;;; §7.2.4.4.8 Table 19 UNION_TYPE row — reject only a provable incompatibility.

(defun* run-union-assignability-test ()
    (function () t)
  "union-assignable-from rejects only a provable incompatibility: a label present in both whose
   member types are not assignable (or discriminators not assignable). Identical unions assignable
   both ways; a changed case-0 member type is not; label-set differences are uncertain (assignable,
   fail-open)."
  (flet ((u (disc &rest ms) (dds.types:make-minimal-union-type :discriminator disc :members ms)))
    (let* ((opts (dds.types:default-assignability-options))
           (i32 (dds.types:primitive-type-identifier :i32))
           (f64 (dds.types:primitive-type-identifier :f64))
           (a (u i32 (dds.types:make-union-member "a" '(0) i32 nil)
                 (dds.types:make-union-member "b" '(1) f64 nil)))
           (same (u i32 (dds.types:make-union-member "a" '(0) i32 nil)
                    (dds.types:make-union-member "b" '(1) f64 nil)))
           (bad  (u i32 (dds.types:make-union-member "a" '(0) f64 nil)
                    (dds.types:make-union-member "b" '(1) f64 nil))))
      (assert (dds.types:union-assignable-from a same opts))
      (assert (dds.types:union-assignable-from same a opts))
      (assert (not (dds.types:union-assignable-from a bad opts)))
      (assert (not (dds.types:union-assignable-from bad a opts)))
      t)))

;;; XCDR2 MinimalTypeObject serializer + EquivalenceHash (M4, FR-TYPE-2/5): serialize the
;;; Minimal struct TypeObject to canonical XCDR2-LE bytes (XTypes §7.3.4.5) and hash it
;;; (§7.3.4.9.1). The hand-derived golden (struct pt{long x;}) proves the framing byte-exact
;;; against the §7.4.3.5.3 serialization VM. The flag/encap choices are externally confirmed
;;; for the exercised path by the Fast DDS vector test below (fastdds-type-information-vector).

(defun* run-typeobject-cdr-test ()
    (function () t)
  "Serialize a Minimal struct TypeObject to XCDR2-LE + compute its EquivalenceHash. Asserts
   the spec-derived golden byte layout for a 1-member FINAL struct, the hash shape +
   determinism, distinct types hashing differently, nested-struct recursion, and that
   sequence members error cleanly pending oracle confirmation. The shape-type hash is
   externally locked vs live Fast DDS 3.6.1 (test fastdds-type-information-vector)."
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
              "shape-type MinimalTypeObject serializes to 87 octets (= Fast DDS's typeobject_serialized_size)")
      (%check :to-shape-hash
              (equalp (dds.types:equivalence-hash to)
                      (octets #xbf #xe2 #xa6 #x2e #xd8 #x11 #xac #x46 #x3c #x40 #xc9 #x7d #x30 #xee))
              "shape-type EquivalenceHash (externally confirmed vs live Fast DDS 3.6.1, FR-IO-2 S3)"))
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
;;; Round-trip-verifiable offline; the LC=4 minimal-only emission is spec-legal and was
;;; consumed by live Fast DDS 3.6.1 (FR-IO-2 S1/S2); the parser is additionally locked
;;; against Fast DDS's own LC=5 value (fastdds-type-information-vector below).

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

;;; Live Fast DDS 3.6.1 TypeInformation vector (FR-IO-2 S3, FR-TYPE-2/3): the external
;;; oracle for the XCDR2 MinimalTypeObject serializer + EquivalenceHash. Fast DDS announced
;;; the IDENTICAL ShapeType IDL (@final, @key string color; long x; long y; long shapesize)
;;; and its SEDP PID_TYPE_INFORMATION carries EK_MINIMAL hash bfe2a62ed811ac463c40c97d30ee /
;;; typeobject_serialized_size 87 — byte-identical to ours, closing the ADR 0009 PROVISIONAL
;;; thread for the exercised path (FINAL struct + i32 + unbounded string8). Their framing is
;;; EMHEADER1 LC=5 (NEXTINT reused as the member's leading DHEADER, XTypes 1.3 §7.4.3.4.2),
;;; unlike our LC=4 emission — the parser must consume both.

(defun* %fastdds-type-information-vector ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "The live Fast DDS 3.6.1 PID_TYPE_INFORMATION parameter value (92 octets) from
   interop/fastdds/captures/s1-forward-lo0.pcap frames 236/237 (SEDP DATA, TLV
   `75 00 5c 00` at frame offset 0x110, value at 0x114..0x16f); byte-identical in
   s2-forward-lo0.pcap frame 68. Layout: DHEADER + EMHEADER1 0x50001001 (minimal,
   LC=5) + members minimal(0x1001)/complete(0x1002), each a
   TypeIdentifierWithDependencies with dependent_typeid_count -1."
  (%hex-octets
   (concatenate 'string
    "580000000110005024000000"
    "14000000f1bfe2a62ed811ac463c40c97d30ee0057000000ffffffff0400000000000000"
    "021000502400000014000000f24945808c7622315d6220054f6aad00"
    "84000000ffffffff0400000000000000")))

(defun* run-fastdds-type-information-vector-test ()
    (function () t)
  "Test: the live Fast DDS 3.6.1 PID_TYPE_INFORMATION vector (LC=5) parses to the
   EK_MINIMAL hash, and our own ShapeType serializer reproduces that hash + size 87 —
   the external EquivalenceHash confirmation (FR-IO-2 S3, FR-TYPE-2/3)."
  (let ((vec (%fastdds-type-information-vector))
        (hash (octets #xbf #xe2 #xa6 #x2e #xd8 #x11 #xac #x46 #x3c #x40 #xc9 #x7d #x30 #xee)))
    (%check :fastdds-ti-len (= 92 (length vec))
            "the locked parameter value is 92 octets (TLV length 0x005c)")
    (%check :fastdds-ti-parse
            (equalp (dds.types:deserialize-type-information-hash vec) hash)
            "our parser consumes the foreign LC=5 TypeInformation and recovers EK_MINIMAL")
    (let ((to (dds.types:type-support-typeobject (dds.types:find-type-support "shape-type"))))
      (%check :fastdds-ti-our-hash
              (equalp (dds.types:equivalence-hash to) hash)
              "our ShapeType EquivalenceHash equals Fast DDS's for the identical IDL")
      (%check :fastdds-ti-our-size
              (= 87 (length (dds.types:minimal-type-object-octets to)))
              "our serialized MinimalTypeObject size equals their typeobject_serialized_size 87")))
  t)

;;; Live Fast DDS 3.6.1 TypeLookup_Reply vector (FR-IO-2 S4, FR-TYPE-3): the first live
;;; conformant-peer getTypes exchange (the ADR 0010 CONFIRM-VS-PEER leg). Queried for our
;;; EK_MINIMAL ShapeType hash, Fast DDS exercises the §7.6.3.3.4.2 latitude: the types
;;; member carries the COMPLETE TypeObject keyed by its EK_COMPLETE TypeIdentifier, and
;;; complete_to_minimal maps that back to the queried EK_MINIMAL hash so the receiver can
;;; reconstruct the MINIMAL TypeObject.

(defun* %fastdds-typelookup-reply-vector ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "The live Fast DDS 3.6.1 TypeLookup_Reply SerializedPayload (256 octets, CDR2_LE) from
   interop/fastdds/captures/s4-ourclient-run1-lo0.pcap frame 61 (DATA on the reply writer
   {00,03,01}c3, sn 1, payload at frame offset 0x68): the getTypes answer to our query for
   the EK_MINIMAL ShapeType hash — REMOTE_EX_OK, one TypeIdentifierTypeObjectPair keyed
   EK_COMPLETE 4945808c7622315d6220054f6aad carrying the 128-octet COMPLETE TypeObject,
   plus a one-pair complete_to_minimal mapping it to EK_MINIMAL
   bfe2a62ed811ac463c40c97d30ee (XTypes 1.3 §7.6.3.3.4.2)."
  (%hex-octets
   (concatenate 'string
    "000700024742545cc3d5ed0000000000000300c3000000000100000000000000"
    "da000000d3528201d200000000000000ca000000d14a80529800000001000000"
    "f24945808c7622315d6220054f6aad0080000000f25101001200000000000000"
    "0a00000053686170655479706500000060000000040000001400000000000000"
    "2100700006000000636f6c6f7200000010000000010000000100040002000000"
    "7800000010000000020000000100040002000000790000001800000003000000"
    "010004000a000000736861706573697a6500000077658e5b2200000001000000"
    "f24945808c7622315d6220054f6aadf1bfe2a62ed811ac463c40c97d30ee0000")))

(defun* %complete-seq-typeobject-octets (ehash)
    (function ((simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Hand-laid XCDR2-LE EK_COMPLETE TypeObject for struct s { sequence<T> v; } whose
   sequence ELEMENT TypeIdentifier is EK_COMPLETE EHASH (PlainSequenceSElemDefn framing,
   xtypes-1_3_typeobject.idl §187-189) — the element-remap case the serializer cannot emit."
  (concatenate
   '(simple-array (unsigned-byte 8) (*))
   (octets 66 0 0 0              ; TypeObject DHEADER (content = 66 octets)
           #xf2 #x51 1 0         ; EK_COMPLETE + TK_STRUCTURE + struct_flags IS_FINAL
           10 0 0 0              ; header DHEADER (TK_NONE + detail = 10 octets)
           0 0 0 0               ; TK_NONE base + 2 absent annotations + pad
           2 0 0 0 #x73 0 0 0    ; type_name "s" (len 2 + chars + pad)
           42 0 0 0 1 0 0 0      ; member-seq DHEADER(42) + count 1
           34 0 0 0              ; member DHEADER(34)
           0 0 0 0 1 0           ; member id 0 + flags TRY_CONSTRUCT=DISCARD
           #x80 #xf2 1 0 0       ; TI_PLAIN_SEQ_SMALL + equiv EK_COMPLETE + flags + SBound 0
           #xf2)                 ; element TypeIdentifier discriminator EK_COMPLETE
   ehash                         ; the 14-octet element EquivalenceHash
   (octets 0 0 2 0 0 0 #x76 0))) ; pad + member name "v" (len 2 + chars)

(defun* run-fastdds-typelookup-reply-vector-test ()
    (function () t)
  "Test: the live Fast DDS 3.6.1 getTypes TypeLookup_Reply parses — including the
   complete_to_minimal member (XTypes 1.3 §7.6.3.3.4.2) — and the COMPLETE TypeObject
   reconstructs (complete-to-minimal-type-object) to a MINIMAL model that re-hashes to
   the queried EquivalenceHash and re-serializes byte-identical to our own ShapeType
   MinimalTypeObject (FR-IO-2 S4)."
  (let ((vec (%fastdds-typelookup-reply-vector))
        (chash (octets #x49 #x45 #x80 #x8c #x76 #x22 #x31 #x5d #x62 #x20 #x05 #x4f #x6a #xad))
        (mhash (octets #xbf #xe2 #xa6 #x2e #xd8 #x11 #xac #x46 #x3c #x40 #xc9 #x7d #x30 #xee)))
    (multiple-value-bind (op pairs rguid rsn rex cont c2m)
        (dds.types:parse-type-lookup-reply vec)
      (declare (ignore cont))
      (%check :s4-op (eq op :get-types) "getTypes Return discriminator")
      (%check :s4-hdr (and (= rsn 1) (eq rex :ok)
                           (equalp (subseq rguid 12 16) (octets 0 3 0 #xc3)))
              "relatedRequestId targets our TL request writer {00,03,00}c3, sn 1, REMOTE_EX_OK")
      (%check :s4-pair (and (= 1 (length pairs)) (equalp (car (first pairs)) chash))
              "one pair, keyed by the EK_COMPLETE TypeIdentifier (the §7.6.3.3.4.2 latitude)")
      (%check :s4-c2m (equalp c2m (list (cons chash mhash)))
              "complete_to_minimal maps the COMPLETE TypeIdentifier to the queried EK_MINIMAL hash")
      (let ((m (dds.types:complete-to-minimal-type-object (cdr (first pairs)) c2m)))
        (%check :s4-reconstruct (dds.types:minimal-struct-type-p m)
                "the COMPLETE TypeObject reconstructs to a MINIMAL struct model")
        (when (dds.types:minimal-struct-type-p m)
          (%check :s4-rehash (equalp (dds.types:equivalence-hash m) mhash)
                  "the reconstruction re-hashes to the queried EK_MINIMAL EquivalenceHash")
          (let ((ours (dds.types:type-support-typeobject (dds.types:find-type-support "shape-type"))))
            (%check :s4-bytes (equalp (dds.types:minimal-type-object-octets m)
                                      (dds.types:minimal-type-object-octets ours))
                    "the reconstructed MinimalTypeObject is byte-identical to our own ShapeType's")))))
    ;; truncation sweep over the CDR extent (NFR-SEC-POSTURE): the live payload ends with
    ;; 2 DATA-submessage pad octets (CDR stream = 254), so only sub-extent prefixes reject
    (%check :s4-pad-tolerated
            (eq :get-types (dds.types:parse-type-lookup-reply (subseq vec 0 254)))
            "the reply minus its submessage padding still parses (trailing-slack tolerance)")
    (%check :s4-prefixes
            (loop for end in (%truncation-offsets 254)
                  always (null (dds.types:parse-type-lookup-reply (subseq vec 0 end))))
            "every sampled proper prefix of the live reply's CDR extent rejects (NIL)")
    ;; hostile internal length (NFR-SEC-POSTURE): corrupt the COMPLETE TypeObject's
    ;; type_name length to 0xFFFFFFFF; reconstruction must drop (NIL), nothing escapes
    (let ((evil (copy-seq vec)))
      (%check :s4-hostile-site (equalp (subseq evil 96 100) (octets #x0a 0 0 0))
              "vec[96..99] is the pristine type_name length field (0a 00 00 00)")
      (fill evil #xff :start 96 :end 100)
      (multiple-value-bind (op pairs rguid rsn rex cont c2m)
          (dds.types:parse-type-lookup-reply evil)
        (declare (ignore rguid rsn rex cont))
        (%check :s4-hostile-strlen
                (and (eq op :get-types) (= 1 (length pairs))
                     (handler-case
                         (null (dds.types:complete-to-minimal-type-object
                                (cdr (first pairs)) c2m))
                       (serious-condition () nil)))
                "a 0xFFFFFFFF type_name length must drop to NIL, no condition escape")))
    ;; sequence-member ELEMENT carrying EK_COMPLETE (hand-laid): remapped via the
    ;; complete_to_minimal alist like a member-level EK_COMPLETE, :unsupported when
    ;; unmapped (fail-open) — never passed through for the hash net to catch downstream
    (let ((seqvec (%complete-seq-typeobject-octets chash)))
      (let ((m (dds.types:complete-to-minimal-type-object seqvec (list (cons chash mhash)))))
        (%check :s4-seq-element-remap
                (and (dds.types:minimal-struct-type-p m)
                     (let* ((mem (first (dds.types:minimal-struct-type-members m)))
                            (ti (dds.types:minimal-struct-member-type-identifier mem))
                            (el (dds.types:type-identifier-element ti)))
                       (and (= (dds.types:type-identifier-kind ti)
                               dds.types:+ti-plain-sequence-small+)
                            el
                            (= (dds.types:type-identifier-kind el) dds.types:+ek-minimal+)
                            (equalp (dds.types:type-identifier-hash el) mhash))))
                "a mapped EK_COMPLETE sequence ELEMENT remaps to its EK_MINIMAL hash"))
      (%check :s4-seq-element-unmapped
              (eq :unsupported (dds.types:complete-to-minimal-type-object seqvec '()))
              "an unmapped EK_COMPLETE sequence ELEMENT degrades the parse to :unsupported")))
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
           (ep (dds.rtps.discovery:parse-endpoint-data rc :writer)))
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
                 (dds.core.buffer:cursor buf :endianness :little) :writer)))
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

;;; SEDP per-role QoS defaults: an ABSENT parameter assumes its default (RTPS 2.5 §9.4.2.11.2).

(defun* %paramlist-without-pid (ep pid)
    (function (dds.rtps.discovery:endpoint-data (unsigned-byte 16)) dds.core.buffer:octet-buffer)
  "Serialize EP as a SEDP ParameterList, re-emitted with every parameter whose id equals PID removed."
  (let* ((src (dds.core.buffer:make-octet-buffer 512))
         (dst (dds.core.buffer:make-octet-buffer 512))
         (out (dds.core.buffer:cursor dst :endianness :little)))
    (dds.rtps.discovery:serialize-endpoint-data (dds.core.buffer:cursor src :endianness :little) ep)
    (dds.rtps.message:parse-parameter-list
     (dds.core.buffer:cursor src :endianness :little)
     (lambda (p c len)
       (unless (= p pid)
         (let ((v (make-array len :element-type '(unsigned-byte 8))))
           (dds.core.buffer:get-octets c v 0 len)
           (dds.rtps.message:write-parameter out p v 0 len)))))
    (dds.rtps.message:write-parameter-sentinel out)
    dst))

(defun* run-sedp-default-reliability-test ()
    (function () t)
  "An SEDP ParameterList WITHOUT PID_RELIABILITY assumes the per-role default (RTPS 2.5
   §9.4.2.11.2; DDS 1.4 §2.2.3): role :writer -> RELIABLE, role :reader -> BEST_EFFORT —
   RTI Connext elides default-valued PIDs. An explicit PID_RELIABILITY still overrides."
  (flet ((parse (buf role)
           (dds.rtps.discovery:parse-endpoint-data
            (dds.core.buffer:cursor buf :endianness :little) role))
         (ser (rel)
           (let ((buf (dds.core.buffer:make-octet-buffer 512)))
             (dds.rtps.discovery:serialize-endpoint-data
              (dds.core.buffer:cursor buf :endianness :little)
              (dds.rtps.discovery:make-endpoint-data
               :topic-name "Square" :type-name "ShapeType"
               :qos (dds.qos:make-qos :reliability rel)))
             buf)))
    (let* ((ep (dds.rtps.discovery:make-endpoint-data
                :topic-name "Square" :type-name "ShapeType"
                :qos (dds.qos:make-qos :reliability :reliable)))
           (stripped (%paramlist-without-pid ep dds.rtps.message:+pid-reliability+))
           (w (parse stripped :writer))
           (r (parse stripped :reader)))
      (%check :sedp-default-writer
              (and w (eq :reliable (dds.qos:qos-reliability (dds.rtps.discovery:endpoint-data-qos w))))
              "absent PID_RELIABILITY on a DCPSPublication must default to RELIABLE")
      (%check :sedp-default-reader
              (and r (eq :best-effort (dds.qos:qos-reliability (dds.rtps.discovery:endpoint-data-qos r))))
              "absent PID_RELIABILITY on a DCPSSubscription must default to BEST_EFFORT")
      (%check :sedp-default-topic
              (and w (string= "Square" (dds.rtps.discovery:endpoint-data-topic-name w))
                   (string= "ShapeType" (dds.rtps.discovery:endpoint-data-type-name w)))
              "topic/type names still parse from the stripped ParameterList"))
    (let ((w (parse (ser :best-effort) :writer))
          (r (parse (ser :reliable) :reader)))
      (%check :sedp-explicit-writer
              (eq :best-effort (dds.qos:qos-reliability (dds.rtps.discovery:endpoint-data-qos w)))
              "an explicit BEST_EFFORT PID_RELIABILITY overrides the writer RELIABLE default")
      (%check :sedp-explicit-reader
              (eq :reliable (dds.qos:qos-reliability (dds.rtps.discovery:endpoint-data-qos r)))
              "an explicit RELIABLE PID_RELIABILITY overrides the reader BEST_EFFORT default")))
  t)

(defun* run-endpoint-kind-test ()
    (function () t)
  "add-local-writer/reader pick the RTPS entity kind from :keyed and set the node's
   data-plane user ids: keyed (default) -> writer 0x02/id 0x102, reader 0x07/id 0x107;
   no-key -> writer 0x03/id 0x103, reader 0x04/id 0x104."
  (let ((kn (dds.disc:make-disc-node
             :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 1)
             :host "127.0.0.1" :port 0))
        (nn (dds.disc:make-disc-node
             :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 2)
             :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (let ((w (dds.disc:add-local-writer kn :topic "T" :type "X"))
                 (r (dds.disc:add-local-reader kn :topic "T" :type "X")))
             (%check :endpoint-keyed-writer-kind
                     (= #x02 (aref (dds.rtps.discovery:endpoint-data-guid w) 15))
                     "keyed writer announces entity kind 0x02 (WITH_KEY)")
             (%check :endpoint-keyed-reader-kind
                     (= #x07 (aref (dds.rtps.discovery:endpoint-data-guid r) 15))
                     "keyed reader announces entity kind 0x07 (WITH_KEY)")
             (%check :endpoint-keyed-writer-id
                     (= #x00000102 (dds.disc:disc-node-user-writer-id kn))
                     "keyed node carries data-plane writer id 0x102")
             (%check :endpoint-keyed-reader-id
                     (= #x00000107 (dds.disc:disc-node-user-reader-id kn))
                     "keyed node carries data-plane reader id 0x107"))
           (let ((w (dds.disc:add-local-writer nn :topic "T" :type "X" :keyed nil))
                 (r (dds.disc:add-local-reader nn :topic "T" :type "X" :keyed nil)))
             (%check :endpoint-nokey-writer-kind
                     (= #x03 (aref (dds.rtps.discovery:endpoint-data-guid w) 15))
                     "no-key writer announces entity kind 0x03 (NO_KEY)")
             (%check :endpoint-nokey-reader-kind
                     (= #x04 (aref (dds.rtps.discovery:endpoint-data-guid r) 15))
                     "no-key reader announces entity kind 0x04 (NO_KEY)")
             (%check :endpoint-nokey-writer-id
                     (= #x00000103 (dds.disc:disc-node-user-writer-id nn))
                     "no-key node carries data-plane writer id 0x103")
             (%check :endpoint-nokey-reader-id
                     (= #x00000104 (dds.disc:disc-node-user-reader-id nn))
                     "no-key node carries data-plane reader id 0x104")))
      (dds.disc:stop-node kn)
      (dds.disc:stop-node nn)))
  t)

;;; Keyed/no-key endpoint-kind agreement on the SEDP match path (FR-RTPS, RTPS 2.5
;;; §9.3.1.2 Table 9.1): a WITH_KEY local endpoint must NOT match a NO_KEY remote (and
;;; vice versa). The disagreement is a SILENT non-match — below type consistency, so it
;;; does NOT fire INCONSISTENT_TOPIC; only same-kind, name-agreeing endpoints match.

(defun* %remote-writer-ep (kind)
    (function ((unsigned-byte 8)) dds.rtps.discovery:endpoint-data)
  "A synthesized remote writer endpoint on (T, X) with a distinct GUID prefix and the
   given entity KIND (0x02 WITH_KEY / 0x03 NO_KEY), RELIABLE so RxO-matches a reader."
  (let ((guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 9)))
    (setf (aref guid 15) kind)
    (dds.rtps.discovery:make-endpoint-data
     :guid guid :topic-name "T" :type-name "X"
     :qos (dds.qos:make-qos :reliability :reliable))))

(defun* run-tce-disallow-default-test ()
    (function () t)
  "XTypes 1.3 §7.6.3.4.1: introspecting a remote endpoint that carries no
   TypeConsistencyEnforcementQosPolicy, the Service SHALL assume DISALLOW_TYPE_COERCION.
   %reader-side-tce returns DISALLOW for an unadvertised remote READER (we never parse a
   remote TCE), and the LOCAL reader's real policy (default ALLOW) when REMOTE is a writer."
  (let ((local (dds.rtps.discovery:make-endpoint-data
                :guid (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 1)))
                        (setf (aref g 15) #x07) g)         ; local keyed reader
                :topic-name "T" :type-name "X" :qos (dds.qos:make-qos)))
        (remote-reader (%remote-writer-ep #x04))            ; reuse the fabricator; force a reader kind below
        (remote-writer (%remote-writer-ep #x02)))
    (setf (aref (dds.rtps.discovery:endpoint-data-guid remote-reader) 15) #x04)  ; NO_KEY reader
    (%check :tce-remote-reader-disallow
            (eq :disallow-type-coercion
                (dds.qos:type-consistency-enforcement-kind
                 (dds.dcps::%reader-side-tce remote-reader local)))
            "an unadvertised remote reader's TCE must be assumed DISALLOW (§7.6.3.4.1)")
    (%check :tce-remote-writer-local-policy
            (eq :allow-type-coercion
                (dds.qos:type-consistency-enforcement-kind
                 (dds.dcps::%reader-side-tce remote-writer local)))
            "a remote writer uses the local reader's real policy (default ALLOW)")
    t))

(defun* run-keyed-match-test ()
    (function () t)
  "A keyed/no-key endpoint-kind disagreement is a silent non-match; same-kind matches;
   no INCONSISTENT_TOPIC fired (FR-RTPS, RTPS 2.5 §9.3.1.2): a keyed local reader (0x07)
   rejects a no-key remote writer (0x03); a no-key local reader (0x04) matches a no-key
   writer but rejects a keyed writer (0x02); the inconsistent table stays empty throughout."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 1)
               :host "127.0.0.1" :port 0))
        (nokey-w (%remote-writer-ep #x03))
        (keyed-w (%remote-writer-ep #x02)))
    (unwind-protect
         (progn
           (dds.disc:add-local-reader node :topic "T" :type "X")              ; keyed reader 0x07
           (dds.disc::%match-remote-writer node nokey-w)
           (%check :keyed-reader-vs-nokey-writer
                   (zerop (dds.disc:disc-node-matched-count node))
                   "a keyed local reader must not match a no-key remote writer")
           (setf (dds.disc::disc-node-local-readers node) '())
           (dds.disc:add-local-reader node :topic "T" :type "X" :keyed nil)   ; no-key reader 0x04
           (dds.disc::%match-remote-writer node nokey-w)
           (%check :nokey-reader-vs-nokey-writer
                   (= 1 (dds.disc:disc-node-matched-count node))
                   "a no-key local reader must match a no-key remote writer")
           (dds.disc::%match-remote-writer node keyed-w)
           (%check :nokey-reader-vs-keyed-writer
                   (= 1 (dds.disc:disc-node-matched-count node))
                   "a no-key local reader must not match a keyed remote writer (no new match)")
           (%check :keyed-mismatch-no-inconsistent
                   (zerop (hash-table-count (dds.disc::disc-node-inconsistent node)))
                   "an endpoint-kind disagreement must not fire INCONSISTENT_TOPIC"))
      (dds.disc:stop-node node)))
  t)

;;; Participant-lease expiry (RTPS 2.5 §8.5.3.3.2): the SPDP reader removes a
;;; discovered participant not refreshed within its leaseDuration. %lease-sweep
;;; prunes the stale participant's discovered entry + endpoints + matches +
;;; builtin-reader and fires the on-unmatch hook once per removed matched endpoint.

(defun* run-lease-sweep-test ()
    (function () t)
  "%lease-sweep prunes a participant whose last-seen + leaseDuration < now (RTPS 2.5
   §8.5.3.3.2): removes its discovered entry + endpoints + matches + builtin-reader and
   fires on-unmatch once per removed matched endpoint (direction . remote)."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x53)
               :host "127.0.0.1" :port 0))
        (unmatched '()))
    (unwind-protect
        (progn
          (setf (dds.disc:disc-node-on-unmatch node)
                (lambda (direction remote) (push (cons direction remote) unmatched)))
          (let* ((p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x71))
                 (rw (%remote-writer-ep #x02)))                 ; a remote writer endpoint
            (replace (dds.rtps.discovery:endpoint-data-guid rw) p2 :end1 12)
            (dds.disc::%record-match node rw)
            (setf (gethash (copy-seq (dds.rtps.discovery:endpoint-data-guid rw))
                           (dds.disc::disc-node-discovered-writers node)) rw)
            (setf (gethash (copy-seq p2) (dds.disc::disc-node-builtin-readers node))
                  (dds.rtps.reliable:make-rtps-reader))
            (dds.disc::%seed-discovered-stale node p2 1 5)       ; lease 1s, seen 5s ago
            (dds.disc::%lease-sweep node)
            (%check :pruned (zerop (hash-table-count (dds.disc::disc-node-discovered node)))
                    "stale participant not pruned from discovered")
            (%check :builtin-removed (zerop (hash-table-count (dds.disc::disc-node-builtin-readers node)))
                    "stale participant's builtin-reader not removed")
            (%check :ep-removed (zerop (hash-table-count (dds.disc::disc-node-discovered-writers node)))
                    "stale participant's discovered endpoint not removed")
            (%check :match-removed (zerop (hash-table-count (dds.disc::disc-node-matches node)))
                    "matched endpoint not removed")
            (%check :unmatch-fired (= 1 (length unmatched)) "on-unmatch not fired once")
            (%check :unmatch-direction (eq :remote-writer (car (first unmatched)))
                    "wrong unmatch direction")))
      (dds.disc:stop-node node))
    t))

;;; DCPS-level reaction to a participant-lease unmatch (DDS 1.4 §2.2.4.1,
;;; dds_rtf2_dcps.idl §165/§174): when the disc layer fires on-unmatch for a vanished
;;; remote endpoint, the local DataReader's SUBSCRIPTION_MATCHED / DataWriter's
;;; PUBLICATION_MATCHED current_count DECREASES (current_count_change negative),
;;; total_count stays monotonic, and the matched listener fires.

(defun* run-lease-unmatch-test ()
    (function () t)
  "A matched remote endpoint removed by participant-lease expiry decrements the local
   DataReader's SUBSCRIPTION_MATCHED current_count (change -1), leaves total_count, and
   fires on-subscription-matched; the DataWriter/PUBLICATION_MATCHED mirror holds
   (DDS 1.4 §2.2.4.1, dds_rtf2_dcps.idl §165/§174)."
  (let ((ts (dds.types:find-type-support "shape-type"))
        (p (dds.dcps:create-participant :domain 0))
        (rl (make-instance 'capturing-reader-listener))
        (wl (make-instance 'capturing-writer-listener)))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "UnmatchTopic" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (pub (dds.dcps:create-publisher p))
                (dr (dds.dcps:create-datareader sub tp))
                (dw (dds.dcps:create-datawriter pub tp))
                (rw (dds.rtps.discovery:make-endpoint-data
                     :guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7)
                     :topic-name "UnmatchTopic" :type-name "ShapeType"))
                (rr (dds.rtps.discovery:make-endpoint-data
                     :guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 9)
                     :topic-name "UnmatchTopic" :type-name "ShapeType")))
           (dds.dcps:set-reader-listener dr rl '(:subscription-matched))
           (dds.dcps:set-writer-listener dw wl '(:publication-matched))
           ;; Match a remote writer (reader's SUBSCRIPTION_MATCHED) and a remote reader
           ;; (writer's PUBLICATION_MATCHED).
           (dds.dcps::%on-disc-match p :remote-writer rw)
           (dds.dcps::%on-disc-match p :remote-reader rr)
           (let ((sm (dds.dcps:get-subscription-matched-status dr))
                 (pm (dds.dcps:get-publication-matched-status dw)))
             (%check :um-sub-matched
                     (and (= 1 (dds.dcps:subscription-matched-status-total-count sm))
                          (= 1 (dds.dcps:subscription-matched-status-current-count sm)))
                     "reader SUBSCRIPTION_MATCHED must be total 1 / current 1 after match")
             (%check :um-pub-matched
                     (and (= 1 (dds.dcps:publication-matched-status-total-count pm))
                          (= 1 (dds.dcps:publication-matched-status-current-count pm)))
                     "writer PUBLICATION_MATCHED must be total 1 / current 1 after match"))
           ;; The lease-expiry unmatch.
           (dds.dcps::%on-disc-unmatch p :remote-writer rw)
           (dds.dcps::%on-disc-unmatch p :remote-reader rr)
           ;; The matched listeners fire on unmatch, carrying the -1 change BEFORE any
           ;; get_*_status read resets it (the listener snapshot is the first observer).
           (let ((sub-hit (cdr (assoc :sub-matched (cap-snapshot rl))))
                 (pub-hit (cdr (assoc :pub-matched (cap-snapshot wl)))))
             (%check :um-sub-listener
                     (and sub-hit
                          (= -1 (dds.dcps:subscription-matched-status-current-count-change sub-hit)))
                     "on-subscription-matched must fire on unmatch with current_count_change -1")
             (%check :um-sub-listener-current
                     (and sub-hit
                          (zerop (dds.dcps:subscription-matched-status-current-count sub-hit)))
                     "the unmatch snapshot's SUBSCRIPTION_MATCHED current_count must be 0")
             (%check :um-pub-listener
                     (and pub-hit
                          (= -1 (dds.dcps:publication-matched-status-current-count-change pub-hit)))
                     "on-publication-matched must fire on unmatch with current_count_change -1")
             (%check :um-pub-listener-current
                     (and pub-hit
                          (zerop (dds.dcps:publication-matched-status-current-count pub-hit)))
                     "the unmatch snapshot's PUBLICATION_MATCHED current_count must be 0"))
           ;; Post-unmatch state read via get_*_status: current_count 0, total_count
           ;; UNCHANGED (monotonic, never decremented).
           (let ((sm (dds.dcps:get-subscription-matched-status dr))
                 (pm (dds.dcps:get-publication-matched-status dw)))
             (%check :um-sub-current-zero
                     (zerop (dds.dcps:subscription-matched-status-current-count sm))
                     "reader SUBSCRIPTION_MATCHED current_count must drop to 0 on unmatch")
             (%check :um-sub-total-unchanged
                     (= 1 (dds.dcps:subscription-matched-status-total-count sm))
                     "reader SUBSCRIPTION_MATCHED total_count must NOT be decremented (monotonic)")
             (%check :um-pub-current-zero
                     (zerop (dds.dcps:publication-matched-status-current-count pm))
                     "writer PUBLICATION_MATCHED current_count must drop to 0 on unmatch")
             (%check :um-pub-total-unchanged
                     (= 1 (dds.dcps:publication-matched-status-total-count pm))
                     "writer PUBLICATION_MATCHED total_count must NOT be decremented (monotonic)")))
      (dds.dcps:delete-participant p))
    t))

;;; Reader-side Writer Liveliness timing -> LIVELINESS_CHANGED (RTPS 2.5 §8.4.13,
;;; DDS 1.4 §2.2.4.1, dds_rtf2_dcps.idl §123-129): %liveliness-sweep, run on the announce
;;; cadence, judges each MATCHED remote writer alive/not-alive from the latest inbound
;;; liveliness assertion of its offered LIVELINESS kind vs its offered lease_duration,
;;; firing on_liveliness_changed only on an alive<->not-alive TRANSITION. The DCPS hook
;;; bumps the local DataReader's LIVELINESS_CHANGED status accordingly. Driven
;;; DETERMINISTICALLY by backdating the inbound stamp (no real-time wait).

(defun* run-liveliness-changed-test ()
    (function () t)
  "A matched remote AUTOMATIC writer whose last liveliness assertion is older than its
   offered lease_duration is swept NOT_ALIVE: %liveliness-sweep fires on_liveliness_changed
   with alive_count_change -1 / not_alive_count_change +1 and the reader's LIVELINESS_CHANGED
   reflects alive_count 0 / not_alive_count 1 / last_publication_handle = that writer's GUID.
   A subsequent FRESH assertion + sweep transitions back to ALIVE (alive_count_change +1 /
   not_alive_count_change -1). Deterministic: the stamp is backdated, never timed (RTPS 2.5
   §8.4.13 / DDS 1.4 §2.2.4.1)."
  (let ((ts (dds.types:find-type-support "shape-type"))
        (p (dds.dcps:create-participant :domain 0))
        (rl (make-instance 'capturing-reader-listener)))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "LivTopic" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr (dds.dcps:create-datareader sub tp))
                (node (dds.dcps::dp-node p))
                ;; A matched remote WRITER (0x02 kind) offering AUTOMATIC liveliness with a
                ;; finite 1s lease, so a backdated stamp can make it stale.
                (rw (dds.rtps.discovery:make-endpoint-data
                     :guid (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x71)))
                             (setf (aref g 15) #x02) g)
                     :topic-name "LivTopic" :type-name "ShapeType"
                     :qos (dds.qos:make-qos :reliability :reliable :liveliness :automatic
                                            :liveliness-lease (dds.qos:make-qos-duration 1 0))))
                (prefix (subseq (dds.rtps.discovery:endpoint-data-guid rw) 0 12)))
           (dds.dcps:set-reader-listener dr rl '(:liveliness-changed))
           (dds.disc::%record-match node rw)
           ;; Seed a STALE AUTOMATIC stamp (5s old vs a 1s lease) keyed by the writer's prefix.
           (setf (gethash (cons (copy-seq prefix) dds.rtps.discovery:+pmd-kind-automatic+)
                          (dds.disc::disc-node-remote-liveliness node))
                 (- (dds.disc::%lease-now) (* 5 internal-time-units-per-second)))
           ;; First sweep: a freshly-matched writer starts ALIVE; the stale stamp drives the
           ;; alive -> not-alive transition.
           (dds.disc::%liveliness-sweep node)
           (let ((hit (cdr (assoc :liv-changed (cap-snapshot rl)))))
             (%check :liv-not-alive-listener
                     (and hit (= -1 (dds.dcps:liveliness-changed-status-alive-count-change hit))
                          (= 1 (dds.dcps:liveliness-changed-status-not-alive-count-change hit)))
                     "on_liveliness_changed must fire with alive_count_change -1 / not_alive_count_change +1")
             (%check :liv-not-alive-handle
                     (and hit (equalp (dds.dcps:liveliness-changed-status-last-publication-handle hit)
                                      (dds.rtps.discovery:endpoint-data-guid rw)))
                     "last_publication_handle must be the not-alive writer's GUID"))
           (let ((s (dds.dcps:get-liveliness-changed-status dr)))
             (%check :liv-not-alive-counts
                     (and (zerop (dds.dcps:liveliness-changed-status-alive-count s))
                          (= 1 (dds.dcps:liveliness-changed-status-not-alive-count s)))
                     "reader LIVELINESS_CHANGED must read alive_count 0 / not_alive_count 1 once stale")
             (%check :liv-change-reset
                     (and (zerop (dds.dcps:liveliness-changed-status-alive-count-change s))
                          (zerop (dds.dcps:liveliness-changed-status-not-alive-count-change s)))
                     "get_liveliness_changed_status must reset the *_change counters"))
           ;; A re-sweep with no new stamp must NOT re-fire (no transition).
           (dds.disc::%liveliness-sweep node)
           (let ((s (dds.dcps:get-liveliness-changed-status dr)))
             (%check :liv-no-refire
                     (and (zerop (dds.dcps:liveliness-changed-status-alive-count-change s))
                          (zerop (dds.dcps:liveliness-changed-status-not-alive-count-change s)))
                     "a re-sweep without a transition must not bump the *_change counters"))
           ;; A FRESH assertion + sweep transitions back to ALIVE. The listener snapshot is
           ;; the first observer of the +1/-1 change (it resets the counters per DDS), so the
           ;; change deltas are asserted on the snapshot and the cumulative counts on get_status.
           (dds.pal:with-lock ((cap-lock rl)) (setf (cap-hits rl) '()))
           (setf (gethash (cons (copy-seq prefix) dds.rtps.discovery:+pmd-kind-automatic+)
                          (dds.disc::disc-node-remote-liveliness node))
                 (dds.disc::%lease-now))
           (dds.disc::%liveliness-sweep node)
           (let ((hit (cdr (assoc :liv-changed (cap-snapshot rl)))))
             (%check :liv-alive-again-listener
                     (and hit (= 1 (dds.dcps:liveliness-changed-status-alive-count-change hit))
                          (= -1 (dds.dcps:liveliness-changed-status-not-alive-count-change hit)))
                     "the alive-again transition must fire with alive_count_change +1 / not_alive_count_change -1"))
           (let ((s (dds.dcps:get-liveliness-changed-status dr)))
             (%check :liv-alive-again-counts
                     (and (= 1 (dds.dcps:liveliness-changed-status-alive-count s))
                          (zerop (dds.dcps:liveliness-changed-status-not-alive-count s)))
                     "a fresh assertion + sweep must transition back to ALIVE (alive_count 1 / not_alive_count 0)")))
      (dds.dcps:delete-participant p))
    t))

;;; Writer-side Writer Liveliness timing -> LIVELINESS_LOST (DDS 1.4 §2.2.3.11 / §2.2.4.1,
;;; dds_rtf2_dcps.idl §118-121): %writer-liveliness-sweep, run on the DCPS announce cadence,
;;; fires on_liveliness_lost when a local DataWriter fails to assert its OWN liveliness
;;; within its offered lease_duration. AUTOMATIC writers are kept asserted by the cadence;
;;; MANUAL writers need a write / assert_liveliness. Driven DETERMINISTICALLY by backdating
;;; the writer's last-assertion (no real-time wait).

(defun* run-liveliness-lost-test ()
    (function () t)
  "A local MANUAL_BY_TOPIC DataWriter with a short (1s) LIVELINESS lease whose self-
   assertion is backdated older than the lease is swept LIVELINESS_LOST: %writer-liveliness-
   sweep fires on_liveliness_lost with total_count 1 / total_count_change +1 and the writer's
   status reads the same. A re-sweep without a fresh assertion must NOT re-fire (one fire per
   going-lost). assert_liveliness refreshes the writer so a subsequent sweep keeps it alive;
   a later re-loss increments total_count again (monotonic). An AUTOMATIC writer is kept alive
   by the cadence and never fires while spinning. Deterministic: the stamp is backdated, never
   timed (DDS 1.4 §2.2.3.11)."
  (let ((ts (dds.types:find-type-support "shape-type"))
        (p (dds.dcps:create-participant :domain 0))
        (wl (make-instance 'capturing-writer-listener)))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "LivLostTopic" "shape-type" ts))
                (pub (dds.dcps:create-publisher p))
                (dw (dds.dcps:create-datawriter
                     pub tp :qos (dds.qos:make-writer-qos
                                  :liveliness :manual-by-topic
                                  :liveliness-lease (dds.qos:make-qos-duration 1 0))))
                (autodw (dds.dcps:create-datawriter
                         pub tp :qos (dds.qos:make-writer-qos
                                      :liveliness :automatic
                                      :liveliness-lease (dds.qos:make-qos-duration 1 0))))
                ;; A MANUAL_BY_TOPIC writer with an INFINITE lease can never go lost.
                (infdw (dds.dcps:create-datawriter
                        pub tp :qos (dds.qos:make-writer-qos
                                     :liveliness :manual-by-topic
                                     :liveliness-lease dds.qos:+duration-infinite+))))
           (dds.dcps:set-writer-listener dw wl '(:liveliness-lost))
           ;; Backdate all three writers' self-assertion to 5s ago vs a 1s lease.
           (setf (dds.dcps::dw-last-assertion dw)
                 (- (dds.disc::%lease-now) (* 5 internal-time-units-per-second)))
           (setf (dds.dcps::dw-last-assertion autodw)
                 (- (dds.disc::%lease-now) (* 5 internal-time-units-per-second)))
           ;; Backdate the infinite-lease writer far past any finite lease.
           (setf (dds.dcps::dw-last-assertion infdw)
                 (- (dds.disc::%lease-now) (* 3600 internal-time-units-per-second)))
           ;; First sweep: the MANUAL_BY_TOPIC writer is stale -> alive->not-alive; the
           ;; AUTOMATIC writer is refreshed by the cadence first, so it stays alive.
           (dds.dcps::%writer-liveliness-sweep p)
           (let ((hit (cdr (assoc :liv-lost (cap-snapshot wl)))))
             (%check :livlost-listener
                     (and hit (= 1 (dds.dcps:liveliness-lost-status-total-count hit))
                          (= 1 (dds.dcps:liveliness-lost-status-total-count-change hit)))
                     "on_liveliness_lost must fire with total_count 1 / total_count_change +1"))
           (let ((s (dds.dcps:get-liveliness-lost-status dw)))
             (%check :livlost-counts (= 1 (dds.dcps:liveliness-lost-status-total-count s))
                     "writer LIVELINESS_LOST must read total_count 1 once stale")
             (%check :livlost-change-reset
                     (zerop (dds.dcps:liveliness-lost-status-total-count-change s))
                     "get_liveliness_lost_status must reset total_count_change"))
           (%check :livlost-auto-alive
                   (and (dds.dcps::dw-alive-p autodw) t)
                   "an AUTOMATIC writer is asserted by the cadence and must NOT go lost")
           ;; An INFINITE-lease writer is never judged lost, however stale its assertion.
           (%check :livlost-infinite-alive
                   (and (dds.dcps::dw-alive-p infdw)
                        (zerop (dds.dcps:liveliness-lost-status-total-count
                                (dds.dcps:get-liveliness-lost-status infdw))))
                   "an INFINITE-lease writer must stay alive with total_count 0")
           ;; A re-sweep without a fresh assertion must NOT re-fire (one fire per going-lost).
           (dds.pal:with-lock ((cap-lock wl)) (setf (cap-hits wl) '()))
           (dds.dcps::%writer-liveliness-sweep p)
           (let ((s (dds.dcps:get-liveliness-lost-status dw)))
             (%check :livlost-no-refire
                     (and (null (assoc :liv-lost (cap-snapshot wl)))
                          (= 1 (dds.dcps:liveliness-lost-status-total-count s))
                          (zerop (dds.dcps:liveliness-lost-status-total-count-change s)))
                     "a re-sweep without a transition must not re-fire LIVELINESS_LOST"))
           ;; assert_liveliness refreshes the writer; a subsequent sweep keeps it alive.
           (dds.dcps:assert-liveliness dw)
           (dds.dcps::%writer-liveliness-sweep p)
           (let ((s (dds.dcps:get-liveliness-lost-status dw)))
             (%check :livlost-reassert-alive
                     (and (null (assoc :liv-lost (cap-snapshot wl)))
                          (= 1 (dds.dcps:liveliness-lost-status-total-count s)))
                     "assert_liveliness must keep the writer alive (no new loss, total_count unchanged)"))
           ;; A later re-loss after a re-assert increments total_count again (monotonic).
           (setf (dds.dcps::dw-last-assertion dw)
                 (- (dds.disc::%lease-now) (* 5 internal-time-units-per-second)))
           (dds.dcps::%writer-liveliness-sweep p)
           (let ((s (dds.dcps:get-liveliness-lost-status dw)))
             (%check :livlost-monotonic
                     (= 2 (dds.dcps:liveliness-lost-status-total-count s))
                     "a re-loss after a re-assert must increment total_count to 2 (monotonic)")))
      (dds.dcps:delete-participant p))
    t))

;;; TypeLookup builtin endpoints over UDP (M4 Task 3.2, FR-TYPE-3): the four
;;; XTypes 1.3 Table 61 service endpoints wired into the discovery node — a client
;;; type-lookup-query fetches a peer's TypeObject by EquivalenceHash; the peer's
;;; server core answers over the reply writer; tl-sweep expires unanswered queries.

(defun* %tl-capture ()
    (function () (values function function))
  "A thread-safe one-shot continuation capture: (values continuation result-fn).
   RESULT-FN returns (values called-p pairs okp)."
  (let ((lock (dds.pal:make-lock "tl-capture")) (called nil) (pairs nil) (okp nil))
    (values (lambda (p ok)
              (dds.pal:with-lock (lock) (setf called t pairs p okp ok)))
            (lambda ()
              (dds.pal:with-lock (lock) (values called pairs okp))))))

(defun* run-typelookup-endpoints-test ()
    (function () t)
  "Two discovery nodes on UDP loopback: B queries A's TypeLookup service for the
   registered shape-type's EquivalenceHash and gets back the byte-exact TypeObject
   (parse + re-hash equals the query); an unknown hash answers :ok with ZERO pairs
   (okp T — distinct from a timeout); a query toward an undiscovered prefix expires
   via tl-sweep with (NIL NIL); the *max-typelookup-pending* cap rejects immediately."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (ghost (make-array 12 :element-type '(unsigned-byte 8) :initial-element 9))
         (node1 (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (shape-hash (dds.types:equivalence-hash
                      (dds.types:type-support-typeobject
                       (dds.types:find-type-support "shape-type"))))
         (unknown (make-array 14 :element-type '(unsigned-byte 8) :initial-element #xEE)))
    (unwind-protect
         (progn
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
           (%check :tle-discovered
                   (and (plusp (dds.disc:disc-node-discovered-count node1))
                        (plusp (dds.disc:disc-node-discovered-count node2)))
                   "SPDP did not complete before the TypeLookup query")
           ;; known hash: B asks A; one byte-exact pair whose TypeObject re-hashes
           (multiple-value-bind (k kres) (%tl-capture)
             (%check :tle-query-sent (dds.disc:type-lookup-query node2 p1 (list shape-hash) k)
                     "type-lookup-query toward a live peer must record + send")
             (loop repeat 150 until (nth-value 0 (funcall kres)) do (sleep 0.02))
             (multiple-value-bind (called pairs okp) (funcall kres)
               (%check :tle-replied called
                       (format nil "no TypeLookup reply arrived over UDP (called=~s pairs=~s okp=~s)"
                               called pairs okp))
               (%check :tle-ok okp "the reply must be REMOTE_EX_OK")
               (%check :tle-one-pair (= 1 (length pairs))
                       "exactly one (hash . TypeObject) pair expected")
               (%check :tle-pair-hash (equalp (car (first pairs)) shape-hash)
                       "the pair must echo the queried hash")
               (let ((model (dds.types:parse-minimal-type-object (cdr (first pairs)))))
                 (%check :tle-typeobject
                         (and (typep model 'dds.types:minimal-struct-type)
                              (equalp (dds.types:equivalence-hash model) shape-hash))
                         "the fetched TypeObject must parse + re-hash to the queried hash"))))
           ;; unknown hash: :ok with ZERO pairs (okp T distinguishes from timeout-NIL)
           (multiple-value-bind (k kres) (%tl-capture)
             (dds.disc:type-lookup-query node2 p1 (list unknown) k)
             (loop repeat 150 until (nth-value 0 (funcall kres)) do (sleep 0.02))
             (multiple-value-bind (called pairs okp) (funcall kres)
               (%check :tle-unknown (and called okp (null pairs))
                       "an unknown hash answers :ok with zero pairs, not a timeout")))
           ;; undiscovered prefix: never sent, expires via tl-sweep with (NIL NIL)
           (let ((dds.disc:*typelookup-timeout* 1))
             (multiple-value-bind (k kres) (%tl-capture)
               (%check :tle-ghost-recorded (dds.disc:type-lookup-query node2 ghost (list shape-hash) k)
                       "a query toward an undiscovered prefix is recorded (awaiting expiry)")
               (loop repeat 150 until (nth-value 0 (funcall kres))
                     do (dds.disc:tl-sweep node2) (sleep 0.02))
               (multiple-value-bind (called pairs okp) (funcall kres)
                 (%check :tle-timeout (and called (null pairs) (not okp))
                         "an unanswerable query must expire to (NIL NIL) via tl-sweep"))))
           ;; pending cap: immediate (NIL NIL) continuation + NIL return
           (let ((dds.disc:*max-typelookup-pending* 0))
             (multiple-value-bind (k kres) (%tl-capture)
               (%check :tle-cap-reject
                       (null (dds.disc:type-lookup-query node2 p1 (list shape-hash) k))
                       "the pending cap must reject the query (return NIL)")
               (multiple-value-bind (called pairs okp) (funcall kres)
                 (%check :tle-cap-continuation (and called (null pairs) (not okp))
                         "the cap rejection must call the continuation with (NIL NIL) immediately"))))
           t)
      (dds.disc:stop-node node1)
      (dds.disc:stop-node node2))))

;;; TYPE-GATE on the SEDP match path (M4 Task 4.1, FR-TYPE-4 step 1): a dds-types-aware
;;; layer interposes a type-compatibility verdict BEFORE a match is recorded; :pending
;;; parks the decision (deduped by remote GUID) until resume-parked-matches re-runs it.

(defun* %tg-nodes ()
    (function () (values dds.disc:disc-node dds.disc:disc-node))
  "Two started 127.0.0.1 discovery nodes — node1 offers a RELIABLE writer, node2 a
   BEST_EFFORT reader on (Square, ShapeType) — peered and SPDP-discovered, ready for
   announce-endpoints (the run-sedp-discovery-test shape). On any failure — including
   SPDP not completing — both nodes are stopped before the error propagates."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 1))
         (p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 2))
         (node1 (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 nil)
         (donep nil))
    ;; stop node1 (and node2 if created) on any non-local exit; normal return = both live
    (unwind-protect
         (progn
           (setf node2 (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
           (dds.disc:add-local-writer node1 :topic "Square" :type "ShapeType"
                                      :reliability dds.rtps.discovery:+reliability-reliable+)
           (dds.disc:add-local-reader node2 :topic "Square" :type "ShapeType"
                                      :reliability dds.rtps.discovery:+reliability-best-effort+)
           (setf (dds.disc:disc-node-peers node1) (list (cons "127.0.0.1" (dds.disc:disc-node-port node2))))
           (setf (dds.disc:disc-node-peers node2) (list (cons "127.0.0.1" (dds.disc:disc-node-port node1))))
           (dds.disc:start-node node1)
           (dds.disc:start-node node2)
           (dds.disc:announce-participant node1)
           (dds.disc:announce-participant node2)
           (loop repeat 100
                 until (and (plusp (dds.disc:disc-node-discovered-count node1))
                            (plusp (dds.disc:disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (unless (and (plusp (dds.disc:disc-node-discovered-count node1))
                        (plusp (dds.disc:disc-node-discovered-count node2)))
             (error "SPDP did not complete in %tg-nodes"))
           (setf donep t)
           (values node1 node2))
      (unless donep
        (when node2 (dds.disc:stop-node node2))
        (dds.disc:stop-node node1)))))

(defun* run-type-gate-test ()
    (function () t)
  "The disc-node TYPE-GATE hook (FR-TYPE-4 step 1): :incompatible routes a would-be
   match to the INCONSISTENT_TOPIC path; :pending parks the decision (deduped by
   remote GUID across re-announce AND re-park on resume) until resume-parked-matches
   re-runs it with the gate's later verdict; a NIL gate matches as plain SEDP."
  ;; :incompatible -> no match recorded; the inconsistent-topic callback fires
  (multiple-value-bind (node1 node2) (%tg-nodes)
    (unwind-protect
         (let ((hits '()) (hits-lock (dds.pal:make-lock "tg-hits")))
           (setf (dds.disc:disc-node-type-gate node2)
                 (lambda (node remote local)
                   (declare (ignore node remote local)) :incompatible))
           (setf (dds.disc:disc-node-on-inconsistent-topic node2)
                 (lambda (topic) (dds.pal:with-lock (hits-lock) (push topic hits))))
           (dds.disc:announce-endpoints node1)
           (dds.disc:announce-endpoints node2)
           (loop repeat 100 until (dds.pal:with-lock (hits-lock) hits) do (sleep 0.02))
           (%check :tg-incompat-no-match (zerop (dds.disc:disc-node-matched-count node2))
                   "a gate verdict of :incompatible must not record a match")
           (%check :tg-incompat-fires
                   (member "Square" (dds.pal:with-lock (hits-lock) hits) :test #'string=)
                   "a gate verdict of :incompatible must fire on-inconsistent-topic"))
      (dds.disc:stop-node node1)
      (dds.disc:stop-node node2)))
  ;; :pending parks (deduped); NIL gate (node1) matches; resume after :compatible matches
  (multiple-value-bind (node1 node2) (%tg-nodes)
    (unwind-protect
         (let ((verdict :pending) (matches '()) (m-lock (dds.pal:make-lock "tg-m")))
           (setf (dds.disc:disc-node-type-gate node2)
                 (lambda (node remote local)
                   (declare (ignore node remote local)) verdict))
           (setf (dds.disc:disc-node-on-match node2)
                 (lambda (kind remote)
                   (declare (ignore remote))
                   (dds.pal:with-lock (m-lock) (push kind matches))))
           (dds.disc:announce-endpoints node1)
           (dds.disc:announce-endpoints node2)
           (loop repeat 100 until (plusp (dds.disc:disc-node-parked-count node2))
                 do (sleep 0.02))
           ;; NIL gate on node1: it matches node2's reader exactly as plain SEDP
           (loop repeat 100 until (plusp (dds.disc:disc-node-matched-count node1))
                 do (sleep 0.02))
           (%check :tg-nil-gate (plusp (dds.disc:disc-node-matched-count node1))
                   "a NIL gate must match exactly as the plain SEDP path")
           (%check :tg-parked (= 1 (dds.disc:disc-node-parked-count node2))
                   "a :pending verdict must park the decision exactly once")
           (%check :tg-pending-no-match (zerop (dds.disc:disc-node-matched-count node2))
                   "a :pending verdict must not record a match")
           ;; re-announce: the same remote writer must not park twice
           (dds.disc:announce-endpoints node1)
           (sleep 0.1)
           (%check :tg-park-dedupe (= 1 (dds.disc:disc-node-parked-count node2))
                   "re-announce of a parked remote must dedupe by GUID")
           ;; resume with the gate still :pending -> the entry re-parks exactly once
           (dds.disc:resume-parked-matches node2)
           (%check :tg-repark (= 1 (dds.disc:disc-node-parked-count node2))
                   "resume with a still-:pending gate must re-park the entry once")
           (%check :tg-repark-no-match (zerop (dds.disc:disc-node-matched-count node2))
                   "a re-parked decision must still not match")
           ;; flip the verdict: resume records + fires the match and drains the list
           (setf verdict :compatible)
           (dds.disc:resume-parked-matches node2)
           (%check :tg-resumed-match (plusp (dds.disc:disc-node-matched-count node2))
                   "resume with a :compatible verdict must record the match")
           (%check :tg-resumed-fired
                   (equal '(:remote-writer) (dds.pal:with-lock (m-lock) matches))
                   "the resumed match must fire on-match exactly once (:remote-writer)")
           (%check :tg-drained (zerop (dds.disc:disc-node-parked-count node2))
                   "resume must drain the parked list"))
      (dds.disc:stop-node node1)
      (dds.disc:stop-node node2)))
  t)

;;; DCPS assignability-gated matching (M4 Task 4.2, FR-TYPE-4): the DCPS layer installs
;;; an assignability gate on the disc-node TYPE-GATE hook — equal EquivalenceHashes match
;;; with zero wire traffic; differing hashes fetch the remote Minimal TypeObject via
;;; TypeLookup and decide with is-assignable-from under the reader's
;;; TYPE_CONSISTENCY_ENFORCEMENT (XTypes 1.3 §7.6.3.4.2 Step 1); a TypeLookup timeout
;;; falls back to name-based matching.

(dds.gen:define-dds-type gate-eq-type (:extensibility :final)
  (id :i32 :key t)
  (val :i32))

(dds.gen:define-dds-type gate-w-type (:extensibility :final)
  (id :i32 :key t)
  (val :i32))

(dds.gen:define-dds-type gate-r-type (:extensibility :final)
  (id :i32 :key t)
  (val :i64))   ; same member id, different primitive kind -> NOT assignable (Table 15)

(dds.gen:define-dds-type gate-cw-type (:extensibility :final)
  (id :i32 :key t)
  (count :u32))

(dds.gen:define-dds-type gate-cr-type (:extensibility :final)
  (id :i32 :key t)
  (total :u32))  ; same id, same kind, different NAME -> assignable only under ignore_member_names

;;; Legacy-TypeObject gate locals (FR-TYPE-4, ADR 0009): both mirror the live Connext
;;; C_Shape shape (color/x/y/shapesize, :final) so they correspond by name+id to the
;;; parsed legacy TypeObject; legacy-good is assignable, legacy-bad retypes x to i64
;;; (same id, different primitive kind -> NOT assignable, Table 15).
(dds.gen:define-dds-type legacy-good-type (:extensibility :final)
  (color :string :key t)
  (x :i32)
  (y :i32)
  (shapesize :i32))

(dds.gen:define-dds-type legacy-bad-type (:extensibility :final)
  (color :string :key t)
  (x :i64)   ; same id as C_Shape's x but i64 vs i32 -> NOT assignable (Table 15)
  (y :i32)
  (shapesize :i32))

(defun* %gate-queries (p)
    (function (dds.dcps:domain-participant) (integer 0))
  "The getTypes-query count of P's type-gate state (diagnostic observable)."
  (dds.dcps::type-gate-state-queries (dds.dcps::dp-type-gate-state p)))

(defun* run-dcps-type-gate-test ()
    (function () t)
  "FR-TYPE-4 gated matching end-to-end: (e) a wire-parsed (name-erased) model is
   assignable to/from its named original via the NameHash correspondence; (a) equal
   hashes match with ZERO TypeLookup queries; (b) same topic+type NAME but a
   non-assignable structure (same member id, different primitive kind) runs a
   TypeLookup query, blocks the match, and raises INCONSISTENT_TOPIC at DCPS level;
   (c) a member-NAME-only difference matches when the reader's
   TYPE_CONSISTENCY_ENFORCEMENT sets ignore_member_names; (d) an unreachable
   TypeLookup service times out to the name-based fallback and the match completes."
  ;; (e) NameHash regression: parse-minimal-type-object erases names, keeps the wire hash
  (let* ((m (dds.types:type-support-typeobject (dds.types:find-type-support "shape-type")))
         (wire (dds.types:parse-minimal-type-object (dds.types:minimal-type-object-octets m)))
         (opts (dds.types:default-assignability-options)))
    (%check :tg4-namehash
            (and (typep wire 'dds.types:minimal-struct-type)
                 (dds.types:struct-assignable-from wire m opts)
                 (dds.types:struct-assignable-from m wire opts))
            "a name-erased wire model must be assignable to/from its named original (NameHash)"))
  ;; (a) identical types both sides: match completes, zero TypeLookup queries
  (let ((ts (dds.types:find-type-support "gate-eq-type"))
        (p1 (dds.dcps:create-participant :domain 0))
        (p2 (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((t1 (dds.dcps:create-topic p1 "GateEqTopic" "gate-eq-type" ts))
                (t2 (dds.dcps:create-topic p2 "GateEqTopic" "gate-eq-type" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2)))
           (dds.dcps:create-datawriter pub t1)
           (dds.dcps:create-datareader sub t2)
           (loop repeat 150
                 until (and (plusp (dds.dcps:matched-count p1))
                            (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :tg4-eq-matched
                   (and (plusp (dds.dcps:matched-count p1))
                        (plusp (dds.dcps:matched-count p2)))
                   "identical types must match through the gate")
           (%check :tg4-eq-no-query
                   (and (zerop (%gate-queries p1)) (zerop (%gate-queries p2)))
                   "equal EquivalenceHashes must match without any TypeLookup query"))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2)))
  ;; (b) same names, non-assignable structures: query runs, no match, INCONSISTENT_TOPIC
  (let ((ts-w (dds.types:find-type-support "gate-w-type"))
        (ts-r (dds.types:find-type-support "gate-r-type"))
        (p1 (dds.dcps:create-participant :domain 0))
        (p2 (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((t1 (dds.dcps:create-topic p1 "GateBadTopic" "GateBadType" ts-w))
                (t2 (dds.dcps:create-topic p2 "GateBadTopic" "GateBadType" ts-r))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2)))
           (dds.dcps:create-datawriter pub t1)
           (dds.dcps:create-datareader sub t2)
           (loop repeat 150
                 until (plusp (dds.dcps:inconsistent-topic-status-total-count
                               (dds.dcps:get-inconsistent-topic-status t2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :tg4-bad-query (plusp (%gate-queries p2))
                   "differing hashes must run a TypeLookup query")
           (%check :tg4-bad-no-match
                   (and (zerop (dds.dcps:matched-count p1))
                        (zerop (dds.dcps:matched-count p2)))
                   "a non-assignable remote type must not match despite equal names")
           ;; the status read above reset the change counter; re-read the cumulative count
           (%check :tg4-bad-inconsistent
                   (plusp (dds.dcps:inconsistent-topic-status-total-count
                           (dds.dcps:get-inconsistent-topic-status t2)))
                   "the blocked match must surface INCONSISTENT_TOPIC on the reader-side Topic"))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2)))
  ;; (c) member-name-only difference: assignable under the reader's ignore_member_names.
  ;; Only the reader side matches: TYPE_CONSISTENCY_ENFORCEMENT is not in our SEDP
  ;; ParameterList yet, so the writer side assesses with the §7.6.3.4.1 defaults.
  (let ((ts-w (dds.types:find-type-support "gate-cw-type"))
        (ts-r (dds.types:find-type-support "gate-cr-type"))
        (p1 (dds.dcps:create-participant :domain 0))
        (p2 (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (let* ((t1 (dds.dcps:create-topic p1 "GateImnTopic" "GateImnType" ts-w))
                (t2 (dds.dcps:create-topic p2 "GateImnTopic" "GateImnType" ts-r))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2)))
           (dds.dcps:create-datawriter pub t1)
           (dds.dcps:create-datareader sub t2
            :qos (dds.qos:make-reader-qos
                  :type-consistency (dds.qos:make-type-consistency-enforcement
                                     :ignore-member-names t)))
           (loop repeat 150
                 until (plusp (dds.dcps:matched-count p2))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :tg4-imn-query (plusp (%gate-queries p2))
                   "differing hashes must run a TypeLookup query before the verdict")
           (%check :tg4-imn-matched (plusp (dds.dcps:matched-count p2))
                   "ignore_member_names on the reader must admit a name-only type difference"))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2)))
  ;; (d) timeout fallback: the remote participant IS discovered but its metatraffic
  ;; locator points at a dead port, so the getTypes goes unanswered and expires via
  ;; tl-sweep -> the gate records the name-based :compatible fallback and the match completes
  (let ((ts (dds.types:find-type-support "shape-type"))
        (p (dds.dcps:create-participant :domain 0))
        ;; a freshly released ephemeral port: discovered yet unreachable
        (dead-port (let ((dead (dds.disc:make-disc-node :host "127.0.0.1" :port 0)))
                     (prog1 (dds.disc:disc-node-port dead) (dds.disc:stop-node dead)))))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "GateTimeoutTopic" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (node (dds.dcps::dp-node p))
                (other-ti (dds.types:serialize-type-information
                           (dds.types:type-support-typeobject
                            (dds.types:find-type-support "dcps-msg"))))
                (prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 9))
                (guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 9))
                (dead-loc (dds.rtps.discovery:make-locator
                           :kind dds.rtps.discovery:+locator-kind-udpv4+ :port dead-port
                           :address (dds.rtps.discovery:make-ipv4-locator
                                     (coerce #(127 0 0 1) '(simple-array (unsigned-byte 8) (4))))))
                (remote (dds.rtps.discovery:make-endpoint-data
                         :guid guid :topic-name "GateTimeoutTopic" :type-name "shape-type"
                         :type-information other-ti :qos (dds.qos:make-writer-qos))))
           (setf (aref guid 15) #x02)   ; entityKind: user no-key writer 0x02 (RTPS 2.5 §9.3.1.2; %remote-writer-p treats 0x02/0x03 as writers)
           (dds.dcps:create-datareader sub tp)
           ;; the gate only queries a discovered participant: inject the dead one's SPDP
           (dds.disc::%record-participant
            node (dds.rtps.discovery:make-spdp-data
                  :guid-prefix prefix :version-major 2 :version-minor 5
                  :metatraffic-unicast-locators (list dead-loc)
                  :default-unicast-locators (list dead-loc)))
           (let ((dds.disc:*typelookup-timeout* 0))
             (dds.disc::%match-remote-writer node remote)   ; gate -> query -> :pending parks
             (%check :tg4-timeout-parked
                     (and (= 1 (dds.disc:disc-node-parked-count node))
                          (zerop (dds.dcps:matched-count p)))
                     "an unanswerable TypeLookup must park the match decision")
             (sleep 0.05)
             (dds.disc:tl-sweep node))   ; expiry -> fallback :compatible -> resume -> match
           (%check :tg4-timeout-match (plusp (dds.dcps:matched-count p))
                   "a TypeLookup timeout must fall back to name-based matching"))
      (dds.dcps:delete-participant p)))
  t)

;;; DCPS FAIL-OPEN legacy-TypeObject assignability gate (FR-TYPE-4, ADR 0009): a stock
;;; Connext peer advertises PID_TYPE_OBJECT_LB (0x8021) and NO PID_TYPE_INFORMATION, so
;;; the gate inflates + structurally parses the legacy TypeObject and gates ONLY on a
;;; confident minimal-struct-type — every other parse outcome (:unsupported / NIL / no
;;; local model) falls OPEN to :compatible (name-match), never rejecting. Driven through
;;; the installed gate hook directly with synthesized writer endpoint-data (the legacy
;;; rung needs no TypeLookup query — there is no TypeInformation).

;; corpus LB fixtures live in legacy-typeobject-test.lisp (loaded later); forward-declare
(declaim (ftype (function () (simple-array (unsigned-byte 8) (*)))
                %connext-c-shape-lb %lto-connext-c-union-lb %lto-connext-c-nested-lb))

(defun* %legacy-gate-remote (topic-name lb)
    (function (string (or null (simple-array (unsigned-byte 8) (*))))
              dds.rtps.discovery:endpoint-data)
  "A synthesized REMOTE writer endpoint-data (entityKind 0x02) carrying LB as its
   PID_TYPE_OBJECT_LB and NO TypeInformation — the stock-Connext-peer shape the
   fail-open legacy gate rung handles (test fixture)."
  (let ((guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 5)))
    (setf (aref guid 15) #x02)   ; entityKind: user no-key writer 0x02 (RTPS 2.5 §9.3.1.2; %remote-writer-p treats 0x02/0x03 as writers)
    (dds.rtps.discovery:make-endpoint-data
     :guid guid :topic-name topic-name :type-name "C_Shape"
     :qos (dds.qos:make-writer-qos) :type-object-lb lb)))

(defun* %legacy-gate-verdict (p topic-name type-name ts lb)
    (function (dds.dcps:domain-participant string string t
               (or null (simple-array (unsigned-byte 8) (*))))
              symbol)
  "Register a Topic binding TYPE-NAME's TS under TOPIC-NAME on P, then invoke P's
   installed type-gate directly on a synthesized stock-Connext writer (LB, no
   TypeInformation) against a local reader endpoint-data on the same topic; return the
   gate verdict (test fixture: the legacy rung needs no wire query, so the verdict is
   synchronous)."
  (dds.dcps:create-topic p topic-name type-name ts)
  (let ((remote (%legacy-gate-remote topic-name lb))
        (local (dds.rtps.discovery:make-endpoint-data
                :guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
                :topic-name topic-name :type-name type-name
                :qos (dds.qos:make-reader-qos))))
    (dds.dcps::%participant-type-gate p (dds.dcps::dp-node p) remote local)))

(defun* run-dcps-legacy-gate-test ()
    (function () t)
  "FR-TYPE-4 FAIL-OPEN legacy-TypeObject gate (ADR 0009): a stock Connext peer's
   PID_TYPE_OBJECT_LB (no TypeInformation) is inflated + structurally parsed and gated
   ONLY on a confident minimal-struct-type. (1) the live C_Shape LB vs a structurally
   COMPATIBLE local -> :compatible; (2) the same LB vs a local with a member retyped ->
   :incompatible (surfaces INCONSISTENT_TOPIC via the shared %match-remote-endpoint
   path); (3) a live C_Nested LB inflated under *lto-max-type-depth* 0 (the over-depth
   nested-struct member is unmodelable -> the parse degrades to :unsupported) ->
   :compatible (the critical fail-open assertion); (4) garbage-but-present LB (won't inflate)
   -> :compatible. A non-model parse result can NEVER reject. (Enum/array/union were the
   case-3 driver until Tasks S0.3/1.3/2.3 flipped each to a structural parse; the over-depth
   nested-struct is now the still-degrading driver.)"
  ;; (1) compatible local struct (C_Shape shape) -> assignable -> :compatible
  (let ((ts (dds.types:find-type-support "legacy-good-type"))
        (p (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (%check :lg-compatible
                 (eq :compatible
                     (%legacy-gate-verdict p "LegacyGoodTopic" "legacy-good-type" ts
                                           (%connext-c-shape-lb)))
                 "a confident C_Shape parse assignable to the local type gates :compatible")
      (dds.dcps:delete-participant p)))
  ;; (2) incompatible local struct (x retyped i64) -> NOT assignable -> :incompatible
  (let ((ts (dds.types:find-type-support "legacy-bad-type"))
        (p (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (%check :lg-incompatible
                 (eq :incompatible
                     (%legacy-gate-verdict p "LegacyBadTopic" "legacy-bad-type" ts
                                           (%connext-c-shape-lb)))
                 "a confident C_Shape parse NOT assignable to the local type gates :incompatible")
      (dds.dcps:delete-participant p)))
  ;; (3) CRITICAL fail-open: an over-depth nested-struct member degrades the C_Nested parse to
  ;; :unsupported (every captured aggregate kind now decodes; the over-depth path still degrades) ->
  ;; name-match :compatible
  (let ((ts (dds.types:find-type-support "legacy-good-type"))
        (p (dds.dcps:create-participant :domain 0))
        (dds.types:*lto-max-type-depth* 0))
    (unwind-protect
         (%check :lg-unsupported-failopen
                 (eq :compatible
                     (%legacy-gate-verdict p "LegacyNestedTopic" "legacy-good-type" ts
                                           (%lto-connext-c-nested-lb)))
                 "an :unsupported legacy-TypeObject parse falls OPEN to :compatible (name-match)")
      (dds.dcps:delete-participant p)))
  ;; (4) garbage-but-present LB (won't inflate) -> fail-open :compatible
  (let ((ts (dds.types:find-type-support "legacy-good-type"))
        (p (dds.dcps:create-participant :domain 0)))
    (unwind-protect
         (%check :lg-garbage-failopen
                 (eq :compatible
                     (%legacy-gate-verdict
                      p "LegacyJunkTopic" "legacy-good-type" ts
                      (coerce '(1 0 0 0 4 0 0 0 4 0 0 0 9 9 9 9)
                              '(simple-array (unsigned-byte 8) (*)))))
                 "a present-but-uninflatable legacy LB falls OPEN to :compatible")
      (dds.dcps:delete-participant p)))
  t)
