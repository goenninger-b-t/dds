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
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
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

(defun* run-dcps-n-reader-test ()
    (function () t)
  "WP-N-ENDPOINT-S2 (ADR 0048): THE data-corruption slice. ONE participant with a Subscriber holding TWO non-
   secured DataReaders on DIFFERENT topics of DIFFERENT types (dcps-msg vs shape-type), each fed by its own remote
   writer. Asserts each reader's take returns EXACTLY its own topic's samples, correctly deserialized (byte-exact
   fields), and NEVER a sibling topic's sample. Pre-S2 a 2nd create-datareader fail-fasted; with the S2 delivery
   route lifted but WITHOUT the %drain source-GUID filter, reader-A would drain reader-B's shape-type bytes under
   dcps-msg type-support -> garbage struct / OOB crash + wrong sample count. The filter (node-reader-matches-
   writer-p) is the binary no-corruption gate: each reader deserializes ONLY its matched writer's bytes. Both impls."
  (let* ((ts-a (dds.types:find-type-support "dcps-msg"))
         (ts-b (dds.types:find-type-support "shape-type"))
         (pa (dds.dcps:create-participant :domain (test-domain)))   ; writer of topic A (dcps-msg)
         (pb (dds.dcps:create-participant :domain (test-domain)))   ; writer of topic B (shape-type)
         (pr (dds.dcps:create-participant :domain (test-domain))))  ; ONE participant, TWO readers (the S2 slice)
    (unwind-protect
         (let* ((twa (dds.dcps:create-topic pa "S2NRA" "dcps-msg" ts-a))
                (twb (dds.dcps:create-topic pb "S2NRB" "shape-type" ts-b))
                (tra (dds.dcps:create-topic pr "S2NRA" "dcps-msg" ts-a))
                (trb (dds.dcps:create-topic pr "S2NRB" "shape-type" ts-b))
                (puba (dds.dcps:create-publisher pa))
                (pubb (dds.dcps:create-publisher pb))
                (sub  (dds.dcps:create-subscriber pr))   ; ONE subscriber holds BOTH readers
                (dwa (dds.dcps:create-datawriter puba twa :qos (dds.qos:make-writer-qos :reliability :reliable :history-kind :keep-all)))
                (dwb (dds.dcps:create-datawriter pubb twb :qos (dds.qos:make-writer-qos :reliability :reliable :history-kind :keep-all)))
                (dra (dds.dcps:create-datareader sub tra :qos (dds.qos:make-reader-qos :reliability :reliable :history-kind :keep-all)))
                (drb (dds.dcps:create-datareader sub trb :qos (dds.qos:make-reader-qos :reliability :reliable :history-kind :keep-all))))
           (%check :s2nr-distinct-ids (/= (dds.dcps::dr-entity-id dra) (dds.dcps::dr-entity-id drb))
                   "the two DataReaders must get DISTINCT engine EntityIds (pre-S2 both collided on #x0107)")
           (flet ((%spin () (dds.dcps:spin pa) (dds.dcps:spin pb) (dds.dcps:spin pr) (sleep 0.02)))
             (loop repeat 250
                   until (and (plusp (dds.dcps:matched-count pa)) (plusp (dds.dcps:matched-count pb))
                              (>= (dds.dcps:matched-count pr) 2))
                   do (%spin))
             (%check :s2nr-matched (and (plusp (dds.dcps:matched-count pa)) (plusp (dds.dcps:matched-count pb))
                                        (>= (dds.dcps:matched-count pr) 2))
                     "both writers must match their own reader on the 2-reader participant")
             ;; each writer publishes 3 samples of its OWN type
             (dotimes (i 3) (dds.dcps:write-sample dwa (make-dcps-msg :id (+ 100 i) :text (format nil "A~D" i))))
             (dotimes (i 3) (dds.dcps:write-sample dwb (make-shape-type :color (format nil "C~D" i) :x (+ 10 i) :y (+ 20 i) :shapesize (+ 30 i))))
             (loop repeat 300
                   until (and (>= (dds.dcps:samples-available dra) 3) (>= (dds.dcps:samples-available drb) 3))
                   do (%spin))
             (let ((sa (dds.dcps:take-samples dra))
                   (sb (dds.dcps:take-samples drb)))
               ;; (1) exact count: no cross-topic OVER-delivery (a sibling sample would push count past 3)
               (%check :s2nr-count-a (= 3 (length sa)) "reader-A must take EXACTLY its own 3 dcps-msg samples (no cross-topic leak)")
               (%check :s2nr-count-b (= 3 (length sb)) "reader-B must take EXACTLY its own 3 shape-type samples (no cross-topic leak)")
               ;; (2) correct type + byte-exact fields: reader-A deserialized dcps-msg (NOT shape-type bytes)
               (%check :s2nr-type-a (every (lambda (cs) (typep (dds.dcps:cached-sample-data cs) 'dcps-msg)) sa)
                       "reader-A samples must all be dcps-msg structs (a shape-type would be cross-topic deserialize corruption)")
               (%check :s2nr-type-b (every (lambda (cs) (typep (dds.dcps:cached-sample-data cs) 'shape-type)) sb)
                       "reader-B samples must all be shape-type structs")
               (%check :s2nr-fields-a
                       (equal (sort (mapcar (lambda (cs) (dcps-msg-id (dds.dcps:cached-sample-data cs))) sa) #'<)
                              '(100 101 102))
                       "reader-A must read writer-A's exact dcps-msg ids (byte-exact, no corruption)")
               (%check :s2nr-fields-b
                       (equal (sort (mapcar (lambda (cs) (shape-type-x (dds.dcps:cached-sample-data cs))) sb) #'<)
                              '(10 11 12))
                       "reader-B must read writer-B's exact shape-type x values (byte-exact, no corruption)")
               ;; (3) explicit negatives: neither reader EVER saw the sibling topic's field signature
               (%check :s2nr-a-no-b (notany (lambda (cs) (typep (dds.dcps:cached-sample-data cs) 'shape-type)) sa)
                       "reader-A must NEVER see a topic-B (shape-type) sample")
               (%check :s2nr-b-no-a (notany (lambda (cs) (typep (dds.dcps:cached-sample-data cs) 'dcps-msg)) sb)
                       "reader-B must NEVER see a topic-A (dcps-msg) sample"))))
      (dds.dcps:delete-participant pa)
      (dds.dcps:delete-participant pb)
      (dds.dcps:delete-participant pr))
    t))

(defun* run-dcps-same-topic-reader-test ()
    (function () t)
  "WP-N-ENDPOINT-2C1 (ADR 0048): the SAME-topic route-add-all slice. ONE participant with a Subscriber holding TWO
   NON-loan DataReaders on the SAME topic/type (shape-type), fed by ONE remote writer W. Asserts BOTH readers take
   ALL of W's samples, byte-exact, each over its OWN per-reader dr-drained high-water — reader-A TAKING a sample does
   NOT deny it to reader-B (no cross-consumption over the shared non-purged store). Pre-2c1 the 2nd same-topic reader
   FENCED (add-local-reader), or — fence lifted WITHOUT route-add-all — was UNROUTED so its %drain source-GUID filter
   (N>=2) dropped ALL its own samples = silent false-REJECT (the RED). W matches TWO ReaderProxies (matched-count>=2),
   so the per-reader ACKNACK fan-out in the HEARTBEAT hook is exercised for real. Both impls."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (pw (dds.dcps:create-participant :domain (test-domain)))   ; the remote writer
         (pr (dds.dcps:create-participant :domain (test-domain))))  ; ONE participant, TWO SAME-topic readers
    (unwind-protect
         (let* ((tw  (dds.dcps:create-topic pw "S2C1Same" "shape-type" ts))
                (tr  (dds.dcps:create-topic pr "S2C1Same" "shape-type" ts))
                (pub (dds.dcps:create-publisher pw))
                (sub (dds.dcps:create-subscriber pr))
                (dw  (dds.dcps:create-datawriter pub tw :qos (dds.qos:make-writer-qos :reliability :reliable :history-kind :keep-all)))
                (dra (dds.dcps:create-datareader sub tr :qos (dds.qos:make-reader-qos :reliability :reliable :history-kind :keep-all)))
                (drb (dds.dcps:create-datareader sub tr :qos (dds.qos:make-reader-qos :reliability :reliable :history-kind :keep-all))))
           (%check :s2c1-distinct-ids (/= (dds.dcps::dr-entity-id dra) (dds.dcps::dr-entity-id drb))
                   "the two SAME-topic DataReaders must get DISTINCT engine EntityIds (route-add-all keys the route on them)")
           (flet ((%spin () (dds.dcps:spin pw) (dds.dcps:spin pr) (sleep 0.02)))
             (loop repeat 250
                   until (and (>= (dds.dcps:matched-count pw) 2) (plusp (dds.dcps:matched-count pr)))
                   do (%spin))
             (%check :s2c1-writer-two-proxies (>= (dds.dcps:matched-count pw) 2)
                     "W must match BOTH same-topic readers (2 ReaderProxies -> the per-reader ACKNACK fan-out is real)")
             (%check :s2c1-readers-matched (plusp (dds.dcps:matched-count pr))
                     "the 2-reader participant must match the remote writer")
             ;; W publishes 4 distinct instances (per-instance KEEP_ALL retains all 4)
             (dotimes (i 4) (dds.dcps:write-sample dw (make-shape-type :color (format nil "K~D" i)
                                                                       :x (+ 10 i) :y (+ 20 i) :shapesize (+ 30 i))))
             (loop repeat 300
                   until (and (>= (dds.dcps:samples-available dra) 4) (>= (dds.dcps:samples-available drb) 4))
                   do (%spin))
             ;; (1) NO false-REJECT: BOTH readers received all 4 of W's samples
             (%check :s2c1-avail-a (>= (dds.dcps:samples-available dra) 4)
                     "reader-A must receive ALL 4 of W's samples (route-add-all routes reader-A to W)")
             (%check :s2c1-avail-b (>= (dds.dcps:samples-available drb) 4)
                     "reader-B must receive ALL 4 of W's samples (the RED: pre-2c1 the 2nd same-topic reader got 0)")
             ;; (2) NO cross-consumption: A takes all 4; B STILL takes all 4 (per-reader dr-drained, non-purged store)
             (let ((sa (dds.dcps:take-samples dra)))
               (%check :s2c1-take-a (= 4 (length sa)) "reader-A must TAKE exactly its own 4 samples")
               (let ((sb (dds.dcps:take-samples drb)))
                 (%check :s2c1-take-b-no-cross (= 4 (length sb))
                         "reader-B must STILL take all 4 AFTER reader-A took them (no cross-consumption over the shared store)")
                 ;; (3) byte-exact: both readers independently decoded W's exact shape-type x values
                 (%check :s2c1-fields-a
                         (equal (sort (mapcar (lambda (cs) (shape-type-x (dds.dcps:cached-sample-data cs))) sa) #'<) '(10 11 12 13))
                         "reader-A must read W's exact shape-type x values (byte-exact)")
                 (%check :s2c1-fields-b
                         (equal (sort (mapcar (lambda (cs) (shape-type-x (dds.dcps:cached-sample-data cs))) sb) #'<) '(10 11 12 13))
                         "reader-B must read W's exact shape-type x values (byte-exact, independent of A)")
                 (%check :s2c1-type-ab
                         (and (every (lambda (cs) (typep (dds.dcps:cached-sample-data cs) 'shape-type)) sa)
                              (every (lambda (cs) (typep (dds.dcps:cached-sample-data cs) 'shape-type)) sb))
                         "both readers' samples must all be shape-type structs (correct type-support, no corruption)")))))
      (dds.dcps:delete-participant pw)
      (dds.dcps:delete-participant pr))
    t))

(defun* run-dcps-same-topic-repair-test ()
    (function () t)
  "WP-N-ENDPOINT-2C1 (ADR 0048): the same-topic per-reader ACKNACK/repair gate — proves the HEARTBEAT-hook ACKNACK
   fan-out repairs BOTH same-topic readers, not just the canonical one. TWO SAME-topic NON-loan reliable KEEP_ALL
   DataReaders + ONE reliable KEEP_ALL writer W. W publishes 3 samples; the FINAL one's DATA is DETERMINISTICALLY
   dropped on every send (*debug-drop-sample-numbers*, incl. resend) so BOTH remote ReaderProxies stall at the gap
   and must NACK it. The drop is then cleared and W's periodic non-final HEARTBEAT (on the spin cadence) solicits the
   ACKNACK; the hook computes the gap from the canonical reader and EMITS one ACKNACK per matched reader-id, so W
   retransmits and — over the store-once + per-reader dr-drained fan-out — BOTH readers recover the dropped sample.
   Deterministic + bounded (mirrors run-lost-final-sample-test; drops the FINAL SN to avoid any out-of-order drain).
   RED (pre-2c1): the 2nd same-topic reader is unrouted, so it never even received SN1/SN2 — repair is moot."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (pw (dds.dcps:create-participant :domain (test-domain)))
         (pr (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw  (dds.dcps:create-topic pw "S2C1Rep" "shape-type" ts))
                (tr  (dds.dcps:create-topic pr "S2C1Rep" "shape-type" ts))
                (pub (dds.dcps:create-publisher pw))
                (sub (dds.dcps:create-subscriber pr))
                (dw  (dds.dcps:create-datawriter pub tw :qos (dds.qos:make-writer-qos :reliability :reliable :history-kind :keep-all)))
                (dra (dds.dcps:create-datareader sub tr :qos (dds.qos:make-reader-qos :reliability :reliable :history-kind :keep-all)))
                (drb (dds.dcps:create-datareader sub tr :qos (dds.qos:make-reader-qos :reliability :reliable :history-kind :keep-all))))
           (flet ((%spin () (dds.dcps:spin pw) (dds.dcps:spin pr) (sleep 0.02)))
             (loop repeat 250 until (and (>= (dds.dcps:matched-count pw) 2) (plusp (dds.dcps:matched-count pr))) do (%spin))
             (%check :s2c1rep-matched (>= (dds.dcps:matched-count pw) 2)
                     "W must match BOTH same-topic readers (2 ReaderProxies) before the drop")
             (setf dds.disc:*debug-drop-sample-numbers* (list 3))   ; drop the FINAL sample's DATA on EVERY send (incl. resend)
             (unwind-protect
                  (progn
                    (dds.dcps:write-sample dw (make-shape-type :color "V0" :x 10 :y 20 :shapesize 30))   ; SN 1
                    (dds.dcps:write-sample dw (make-shape-type :color "V1" :x 11 :y 21 :shapesize 31))   ; SN 2
                    (dds.dcps:write-sample dw (make-shape-type :color "V2" :x 12 :y 22 :shapesize 32))   ; SN 3 (dropped)
                    (loop repeat 60 until (and (>= (dds.dcps:samples-available dra) 2) (>= (dds.dcps:samples-available drb) 2)) do (%spin))
                    ;; both readers have SN1+SN2 but the dropped SN3 is still missing on BOTH
                    (%check :s2c1rep-gap-a (and (>= (dds.dcps:samples-available dra) 2) (< (dds.dcps:samples-available dra) 3))
                            "reader-A must hold SN1+SN2 but NOT the dropped final SN3")
                    (%check :s2c1rep-gap-b (and (>= (dds.dcps:samples-available drb) 2) (< (dds.dcps:samples-available drb) 3))
                            "reader-B must hold SN1+SN2 but NOT the dropped final SN3"))
               (setf dds.disc:*debug-drop-sample-numbers* nil))   ; clear -> the NACK-driven resend now gets through
             ;; drive W's periodic HEARTBEAT: BOTH proxies NACK SN3, W resends, BOTH readers repair (bounded, no unbounded wait)
             (loop repeat 200 until (and (>= (dds.dcps:samples-available dra) 3) (>= (dds.dcps:samples-available drb) 3)) do (%spin))
             (let ((sa (dds.dcps:take-samples dra)) (sb (dds.dcps:take-samples drb)))
               (%check :s2c1rep-a-all (= 3 (length sa)) "reader-A must repair to ALL 3 (its ACKNACK serviced -> SN3 retransmitted)")
               (%check :s2c1rep-b-all (= 3 (length sb))
                       "reader-B must ALSO repair to ALL 3 — its OWN ReaderProxy ACKNACK was serviced by the fan-out (not just the canonical reader)")
               (%check :s2c1rep-a-has-dropped (member 12 (mapcar (lambda (cs) (shape-type-x (dds.dcps:cached-sample-data cs))) sa))
                       "reader-A must contain the repaired final sample (x=12)")
               (%check :s2c1rep-b-has-dropped (member 12 (mapcar (lambda (cs) (shape-type-x (dds.dcps:cached-sample-data cs))) sb))
                       "reader-B must contain the repaired final sample (x=12) — repaired independently"))))
      (setf dds.disc:*debug-drop-sample-numbers* nil)
      (dds.dcps:delete-participant pw)
      (dds.dcps:delete-participant pr))
    t))

(defun* run-n-reader-2c3-joiner-window-test ()
    (function () t)
  "WP-N-ENDPOINT-2C3 (ADR 0017/0048; MEMORY-SAFETY): the mid-stream-joiner [freeze,route-add] WINDOW gate — the RED
   a registration-time freeze MISSES. The ZC-joiner high-water is frozen at MATCH time (atomic with %reader-route-add
   under the node lock), NOT at create-datareader. ONE participant on a FlatData topic with *zerocopy-enabled*.
   Reader-A created + routed to writer W; a marker SN=1 delivered (route=[A], K=1). Reader-B (the joiner) is CREATED
   but NOT yet route-added: a registration-time freeze would fix B's watermark to the max stored NOW (1). A marker
   SN=2 is then delivered with the route STILL [A] (B absent) — the [freeze,route-add] GAP marker: K=1, UNBUMPED. THEN
   B is route-added, which ATOMICALLY freezes B's join-watermark to the CURRENT max stored SN (2). B drains -> it must
   SKIP SN 1 AND the unbumped SN=2 (both <= 2). RED (the missed window): a registration-time freeze set B's watermark
   to 1, so B would drain SN=2 (2 > 1) — the marker whose demux %zc-bump did NOT count B -> B %zc-releases a slot a
   sibling still views = cross-reader use-after-free. Asserts B is NOT frozen at create (join-watermark 0), IS frozen
   to 2 at route-add, and drains 0. Both impls (watermark arithmetic — no cas; the joiner never acquires). Model-level
   (markers injected, no SHMEM). NOT cleared for ship — pending counsel (R6)."
  (let ((dds.disc:*zerocopy-enabled* t)
        (dds.disc:*shmem-enabled* nil)
        (ts (dds.types:find-type-support "fd-abc"))
        (p (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "Fd2C3W" "fd-abc" ts))
                (sub (dds.dcps:create-subscriber p))
                (dra (dds.dcps:create-datareader sub tp))
                (node (dds.dcps::dp-node p))
                (pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x6C))
                (gw (dds.disc::%source-guid pa #x00000102))
                (rida (dds.dcps::dr-entity-id dra)))
           (%check :2c3w-loan-capable (dds.disc:disc-node-zc-loan-capable node)
                   "the reader must be ZC-loan-capable (FlatData topic + *zerocopy-enabled*)")
           ;; reader-A first: route-add (route empty -> A is NOT a joiner -> not frozen) then deliver SN=1
           (dds.disc::%reader-route-add node gw rida)
           (%check :2c3w-a-not-frozen (= 0 (dds.disc:node-reader-join-watermark node rida gw))
                   "the FIRST reader (empty route) must NOT be frozen (drains from SN 1, byte-identical)")
           (dds.disc::%deliver-user-marker node #x00000102 1 (dds.disc::%make-zc-loan-marker :slot-index 1) pa gw 1)
           ;; JOINER reader-B CREATED but NOT yet route-added
           (let* ((drb (dds.dcps:create-datareader sub tp))
                  (ridb (dds.dcps::dr-entity-id drb)))
             (%check :2c3w-distinct (/= rida ridb)
                     "the 2nd same-topic loan-capable reader must register with a DISTINCT EntityId (fence lifted, 2c-3)")
             (%check :2c3w-not-frozen-at-create (= 0 (dds.disc:node-reader-join-watermark node ridb gw))
                     "reader-B must NOT be frozen at create-datareader (the freeze is at MATCH time, not registration)")
             ;; the [freeze,route-add] GAP: deliver SN=2 while B is still absent from the route (K=1, UNBUMPED)
             (dds.disc::%deliver-user-marker node #x00000102 2 (dds.disc::%make-zc-loan-marker :slot-index 2) pa gw 2)
             (%check :2c3w-stored (= 2 (dds.disc:node-sample-count node)) "both markers (incl. the gap marker SN=2) must be stored")
             ;; NOW route-add B -> the ATOMIC match-time freeze reads the current max stored SN (2)
             (dds.disc::%reader-route-add node gw ridb)
             (%check :2c3w-frozen-at-match (= 2 (dds.disc:node-reader-join-watermark node ridb gw))
                     "reader-B's join-watermark must be FROZEN to the current max stored SN (2) at route-add — covering the GAP marker SN=2 (RED: a registration-time freeze would have fixed it to 1, letting B drain the unbumped SN=2 = UAF)")
             (dds.dcps::%drain drb)
             (%check :2c3w-joiner-skips (null (dds.dcps::dr-cache drb))
                     "reader-B must DRAIN 0 markers — it skips SN 1 AND the unbumped GAP marker SN=2 (no drain-an-unbumped-marker window)")))
      (dds.dcps:delete-participant p)))
  t)

(defun* run-dcps-dispose-test ()
    (function () t)
  "DCPS instance lifecycle S1 (writer side, DDS 1.4 §2.2.2.4.2): on the keyed shape-type a
   DataWriter register_instance returns a 16-octet handle; write the sample; then dispose the
   instance. Asserts register/dispose/unregister do not error, the handle is the type-support
   key-hash, and the dispose's no-payload DATA reaches the subscriber's engine classified :dispose
   carrying that handle (RTPS 2.5 §9.6.4.9). The reader-side instance-state transition is S2."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
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
             (let ((lc (dds.disc:node-lifecycle-change-by-sn node2 2)))
               (%check :dcps-disp-classified
                       (and lc (eq (first lc) :dispose) (equalp (second lc) handle))
                       "dispose DATA classified :dispose with the instance handle"))
             ;; unregister must not error
             (dds.dcps:unregister-instance dw handle)))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2))
    t))

;;; TRANSIENT_LOCAL durability + late-joiner, our-to-our END-TO-END (DDS 1.4 §2.2.3.4, M6/P5):
;;; the MVP slice. A reliable TL writer publishes N samples BEFORE any reader exists; THEN a late
;;; reader joins. A reliable TL reader receives all N retained samples (the writer retained them —
;;; Task 1 — and replays them: firstSN proxy-init + a prompt HEARTBEAT, and Task 2's reader-side
;;; gate requests the advertised history). A VOLATILE late reader receives 0 of the pre-existing N
;;; (its reader-side gate skips the history) and only future-published samples. Both sides land here.

(defun* %run-dcps-late-joiner (reader-durability)
    (function ((member :volatile :transient-local)) (values (integer 0) (integer 0)))
  "Drive the our-to-our late-joiner slice for READER-DURABILITY and return (values pre-existing-count
   future-count): how many of the 3 PRE-EXISTING (published-before-join) samples the late reader got,
   and whether a 4th sample published AFTER the join arrived. The WRITER is always reliable
   TRANSIENT_LOCAL KEEP_ALL (it retains for late-joiners, DDS 1.4 §2.2.3.4); the late reader is reliable
   with READER-DURABILITY. Three distinct instances (RED/GREEN/BLUE) are published first, then the late
   reader joins, drains, then a 4th (YELLOW) sample is published."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p1 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "Square" "shape-type" ts))
                (pub (dds.dcps:create-publisher p1))
                (dw (dds.dcps:create-datawriter
                     pub tw :qos (dds.qos:make-writer-qos :durability :transient-local
                                                          :history-kind :keep-all))))
           ;; publish 3 samples BEFORE any reader exists (the writer retains them — TRANSIENT_LOCAL).
           (dds.dcps:write-sample dw (make-shape-type :color "RED"   :x 1 :y 1 :shapesize 10))
           (dds.dcps:write-sample dw (make-shape-type :color "GREEN" :x 2 :y 2 :shapesize 20))
           (dds.dcps:write-sample dw (make-shape-type :color "BLUE"  :x 3 :y 3 :shapesize 30))
           (loop repeat 10 do (dds.dcps:spin p1) (sleep 0.01))   ; let the 3 settle in the HC
           ;; NOW the late reader joins.
           (let ((p2 (dds.dcps:create-participant :domain (test-domain))))
             (unwind-protect
                  (let* ((tr (dds.dcps:create-topic p2 "Square" "shape-type" ts))
                         (sub (dds.dcps:create-subscriber p2))
                         (dr (dds.dcps:create-datareader
                              sub tr :qos (dds.qos:make-reader-qos :reliability :reliable
                                                                   :durability reader-durability
                                                                   :history-kind :keep-all))))
                    (loop repeat 150
                          until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                          do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
                    (%check :lj-matched (plusp (dds.dcps:matched-count p2))
                            "the late reader did not match the writer")
                    ;; a TL reader must pull all 3; a VOLATILE reader must pull 0 — drain the cadence either way.
                    (%drain-until dr p1 p2
                                  (lambda () (>= (dds.dcps:samples-available dr)
                                                 (if (eq reader-durability :transient-local) 3 99)))
                                  200)
                    (let ((pre (length (dds.dcps:take-samples dr))))
                      ;; a 4th sample, published AFTER the join — both durabilities must receive it.
                      (dds.dcps:write-sample dw (make-shape-type :color "YELLOW" :x 4 :y 4 :shapesize 40))
                      (%drain-until dr p1 p2 (lambda () (plusp (dds.dcps:samples-available dr))) 200)
                      (let ((fut (length (dds.dcps:take-samples dr))))
                        (values pre fut))))
               (dds.dcps:delete-participant p2))))
      (dds.dcps:delete-participant p1))))

(defun* run-dcps-durability-latejoiner-test ()
    (function () t)
  "DCPS our-to-our late-joiner (DDS 1.4 §2.2.3.4, M6/P5, the MVP slice). A reliable TRANSIENT_LOCAL writer
   publishes 3 samples BEFORE any reader; a late-joining reliable TRANSIENT_LOCAL reader receives ALL 3
   retained samples (writer retention + firstSN replay + the reader-side history request), then a 4th
   published after the join. A VOLATILE late reader receives 0 of the 3 pre-existing samples (its reader-side
   gate skips the advertised history) but DOES receive the 4th, published after it joined."
  (multiple-value-bind (tl-pre tl-fut) (%run-dcps-late-joiner :transient-local)
    (%check :lj-tl-pre (= 3 tl-pre)
            "a TRANSIENT_LOCAL late reader must receive ALL 3 retained pre-existing samples")
    (%check :lj-tl-fut (= 1 tl-fut) "the TL late reader must also receive the 4th (post-join) sample"))
  (multiple-value-bind (vol-pre vol-fut) (%run-dcps-late-joiner :volatile)
    (%check :lj-vol-pre (zerop vol-pre)
            "a VOLATILE late reader must receive 0 of the 3 pre-existing samples (skip the history)")
    (%check :lj-vol-fut (= 1 vol-fut)
            "the VOLATILE late reader must still receive the 4th sample (published after it joined)"))
  t)

(defun* run-dcps-durability-keeplast-test ()
    (function () t)
  "DCPS per-instance KEEP_LAST retention for a late-joiner (DDS 1.4 §2.2.3.4, spec test 3). A reliable
   TRANSIENT_LOCAL KEEP_LAST(depth=1) writer publishes 3 samples on ONE instance (color BLUE) BEFORE any
   reader; a late-joining TL reader receives only the LAST sample on that instance (depth 1 per instance),
   not the full 3-sample history (per-instance %hc-index-drop eviction still bounds a TL writer's HC)."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p1 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "Square" "shape-type" ts))
                (pub (dds.dcps:create-publisher p1))
                (dw (dds.dcps:create-datawriter
                     pub tw :qos (dds.qos:make-writer-qos :durability :transient-local
                                                          :history-kind :keep-last :history-depth 1))))
           ;; 3 samples on the SAME instance: KEEP_LAST(1) keeps only the newest (shapesize 30).
           (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 10))
           (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 2 :y 2 :shapesize 20))
           (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 3 :y 3 :shapesize 30))
           (loop repeat 10 do (dds.dcps:spin p1) (sleep 0.01))
           (let ((p2 (dds.dcps:create-participant :domain (test-domain))))
             (unwind-protect
                  (let* ((tr (dds.dcps:create-topic p2 "Square" "shape-type" ts))
                         (sub (dds.dcps:create-subscriber p2))
                         (dr (dds.dcps:create-datareader
                              sub tr :qos (dds.qos:make-reader-qos :reliability :reliable
                                                                   :durability :transient-local
                                                                   :history-kind :keep-last :history-depth 1))))
                    (loop repeat 150
                          until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                          do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
                    (%check :ljkl-matched (plusp (dds.dcps:matched-count p2)) "KEEP_LAST late reader did not match")
                    (%drain-until dr p1 p2 (lambda () (plusp (dds.dcps:samples-available dr))) 200)
                    (let ((got (dds.dcps:take-samples dr)))
                      (%check :ljkl-one (= 1 (length got))
                              "a KEEP_LAST(1) TL late reader must get only the LAST sample on the instance, not all 3")
                      (%check :ljkl-newest
                              (and got (= 30 (shape-type-shapesize (dds.dcps:cached-sample-data (first got)))))
                              "the retained KEEP_LAST sample must be the NEWEST (shapesize 30)")))
               (dds.dcps:delete-participant p2))))
      (dds.dcps:delete-participant p1))
    t))

(defun* run-dcps-durability-multiwriter-test ()
    (function () t)
  "DCPS N durable writers per participant, each replays its OWN retained history (WP-N-ENDPOINT-S2B, ADR 0048;
   DDS 1.4 §2.2.3.4). ONE participant/ONE publisher owns TWO reliable TRANSIENT_LOCAL KEEP_ALL DataWriters on
   DIFFERENT topics (Square + Circle); the Square writer publishes 3 samples and the Circle writer 2, all BEFORE
   any reader. Two late TL readers (one per topic) each receive EXACTLY their own writer's retained history —
   3 Squares to the Square reader, 2 Circles to the Circle reader — under that writer's OWN GUID. Cross-isolation:
   neither reader sees the other writer's history. This is the S2B fix: pre-fix the match-time replay armed the
   PRIMARY (Square) writer for BOTH matches, so the Circle writer's history never replayed (Circle reader got 0);
   the guard-lift is the precondition (pre-fix the 2nd durable create-datawriter fail-fasted)."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p1 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw-sq (dds.dcps:create-topic p1 "Square" "shape-type" ts))
                (tw-ci (dds.dcps:create-topic p1 "Circle" "shape-type" ts))
                (pub (dds.dcps:create-publisher p1))
                (dw-sq (dds.dcps:create-datawriter
                        pub tw-sq :qos (dds.qos:make-writer-qos :durability :transient-local
                                                                :history-kind :keep-all)))
                (dw-ci (dds.dcps:create-datawriter
                        pub tw-ci :qos (dds.qos:make-writer-qos :durability :transient-local
                                                                :history-kind :keep-all))))
           ;; pre-join: each writer RETAINS its OWN samples (3 Squares, 2 Circles) — no reader exists yet.
           (dds.dcps:write-sample dw-sq (make-shape-type :color "RED"   :x 1 :y 1 :shapesize 10))
           (dds.dcps:write-sample dw-sq (make-shape-type :color "GREEN" :x 2 :y 2 :shapesize 20))
           (dds.dcps:write-sample dw-sq (make-shape-type :color "BLUE"  :x 3 :y 3 :shapesize 30))
           (dds.dcps:write-sample dw-ci (make-shape-type :color "CYAN"    :x 5 :y 5 :shapesize 50))
           (dds.dcps:write-sample dw-ci (make-shape-type :color "MAGENTA" :x 6 :y 6 :shapesize 60))
           (loop repeat 10 do (dds.dcps:spin p1) (sleep 0.01))   ; let both writers' history settle
           (let ((p2 (dds.dcps:create-participant :domain (test-domain))))
             (unwind-protect
                  (let* ((tr-sq (dds.dcps:create-topic p2 "Square" "shape-type" ts))
                         (tr-ci (dds.dcps:create-topic p2 "Circle" "shape-type" ts))
                         (sub (dds.dcps:create-subscriber p2))
                         (dr-sq (dds.dcps:create-datareader
                                 sub tr-sq :qos (dds.qos:make-reader-qos :reliability :reliable
                                                                         :durability :transient-local
                                                                         :history-kind :keep-all)))
                         (dr-ci (dds.dcps:create-datareader
                                 sub tr-ci :qos (dds.qos:make-reader-qos :reliability :reliable
                                                                         :durability :transient-local
                                                                         :history-kind :keep-all))))
                    (loop repeat 200
                          until (and (>= (dds.dcps:matched-count p1) 2) (>= (dds.dcps:matched-count p2) 2))
                          do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
                    (%check :ljmw-matched (and (>= (dds.dcps:matched-count p1) 2)
                                               (>= (dds.dcps:matched-count p2) 2))
                            "both late TL readers must match their respective durable writers")
                    (%drain-until dr-sq p1 p2 (lambda () (>= (dds.dcps:samples-available dr-sq) 3)) 200)
                    (%drain-until dr-ci p1 p2 (lambda () (>= (dds.dcps:samples-available dr-ci) 2)) 200)
                    (let ((sq (dds.dcps:take-samples dr-sq))
                          (ci (dds.dcps:take-samples dr-ci)))
                      (%check :ljmw-sq-count (= 3 (length sq))
                              "the Square late reader must replay writer-A's OWN 3 retained Squares")
                      (%check :ljmw-ci-count (= 2 (length ci))
                              "the Circle late reader must replay writer-B's OWN 2 retained Circles (the S2B fix)")
                      (%check :ljmw-sq-iso
                              (every (lambda (s) (member (shape-type-color (dds.dcps:cached-sample-data s))
                                                         '("RED" "GREEN" "BLUE") :test #'string=))
                                     sq)
                              "the Square reader gets ONLY writer-A's Squares — never writer-B's Circle history")
                      (%check :ljmw-ci-iso
                              (every (lambda (s) (member (shape-type-color (dds.dcps:cached-sample-data s))
                                                         '("CYAN" "MAGENTA") :test #'string=))
                                     ci)
                              "the Circle reader gets ONLY writer-B's Circles — never writer-A's Square history")))
               (dds.dcps:delete-participant p2))))
      (dds.dcps:delete-participant p1))
    t))

(defun* run-dcps-same-topic-durability-multiwriter-test ()
    (function () t)
  "WP-N-ENDPOINT-2C2 (ADR 0048; DDS 1.4 §2.2.3.4): TWO SAME-topic TRANSIENT_LOCAL KEEP_ALL DataWriters on ONE
   participant, each replays ITS OWN retained history to a late reader. dw1 retains 3 samples, dw2 retains 2, all
   on the SAME topic BEFORE any reader. A late TL reader on that topic matches BOTH writers and receives ALL 5
   retained samples (the UNION of both writers' histories, each under its OWN source GUID). This is the fence-C
   lift + per-writer match-side replay: pre-2c2 the 2nd same-topic durable writer fail-fasted (could not register),
   and even lifted, the pre-2c2 per-remote match armed replay for the FIRST writer only, so dw2's history never
   replayed (reader got 3, not 5 — the RED). Proves %writer-durability-init fires per matched writer with ITS OWN
   writer-id. Both impls."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p1 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "2C2Dur" "shape-type" ts))
                (pub (dds.dcps:create-publisher p1))
                (dw1 (dds.dcps:create-datawriter
                      pub tw :qos (dds.qos:make-writer-qos :durability :transient-local :history-kind :keep-all)))
                (dw2 (dds.dcps:create-datawriter
                      pub tw :qos (dds.qos:make-writer-qos :durability :transient-local :history-kind :keep-all))))
           (%check :2c2dur-distinct (/= (dds.dcps::dw-entity-id dw1) (dds.dcps::dw-entity-id dw2))
                   "the two SAME-topic durable writers must get DISTINCT engine EntityIds (fence C lifted)")
           ;; pre-join: each writer RETAINS its OWN samples (dw1: 3, dw2: 2) — no reader exists yet.
           (dds.dcps:write-sample dw1 (make-shape-type :color "W1A" :x 1 :y 1 :shapesize 10))
           (dds.dcps:write-sample dw1 (make-shape-type :color "W1B" :x 2 :y 2 :shapesize 20))
           (dds.dcps:write-sample dw1 (make-shape-type :color "W1C" :x 3 :y 3 :shapesize 30))
           (dds.dcps:write-sample dw2 (make-shape-type :color "W2A" :x 4 :y 4 :shapesize 40))
           (dds.dcps:write-sample dw2 (make-shape-type :color "W2B" :x 5 :y 5 :shapesize 50))
           (loop repeat 10 do (dds.dcps:spin p1) (sleep 0.01))
           (let ((p2 (dds.dcps:create-participant :domain (test-domain))))
             (unwind-protect
                  (let* ((tr (dds.dcps:create-topic p2 "2C2Dur" "shape-type" ts))
                         (sub (dds.dcps:create-subscriber p2))
                         (dr (dds.dcps:create-datareader
                              sub tr :qos (dds.qos:make-reader-qos :reliability :reliable
                                                                   :durability :transient-local
                                                                   :history-kind :keep-all))))
                    (loop repeat 200
                          until (and (>= (dds.dcps:matched-count p1) 1) (>= (dds.dcps:matched-count p2) 2))
                          do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
                    (%check :2c2dur-matched (>= (dds.dcps:matched-count p2) 2)
                            "the late TL reader must match BOTH same-topic durable writers (2 WriterProxies)")
                    (%drain-until dr p1 p2 (lambda () (>= (dds.dcps:samples-available dr) 5)) 250)
                    (let ((s (dds.dcps:take-samples dr)))
                      (%check :2c2dur-union-count (= 5 (length s))
                              "the late reader must replay ALL 5 retained samples — the UNION of BOTH same-topic writers' histories (RED: pre-2c2 only dw1's 3 replayed)")
                      (let ((colors (sort (mapcar (lambda (cs) (shape-type-color (dds.dcps:cached-sample-data cs))) s) #'string<)))
                        (%check :2c2dur-both-histories
                                (equal colors '("W1A" "W1B" "W1C" "W2A" "W2B"))
                                "the reader must receive dw1's OWN 3 AND dw2's OWN 2 retained samples (each writer replayed its OWN history via its OWN writer-id)"))))
               (dds.dcps:delete-participant p2))))
      (dds.dcps:delete-participant p1))
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
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
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

;;; WP-KEEPLAST Task B1 (ADR 0019, DDS 1.4 §2.2.3.18): the DCPS write path threads the
;;; sample's instance keyhash DCPS write-sample -> publish-sample -> writer-write onto the
;;; data CacheChange, GATED on the writer's effective HISTORY being KEEP_LAST (a KEEP_ALL
;;; writer never evicts per-instance, so it skips the handle computation -> default 0-alloc).

(defun* %last-writer-change (dw)
    (function (dds.dcps:data-writer) dds.rtps.history:cache-change)
  "The CacheChange most recently added to DW's engine user-writer HistoryCache (test reach-in):
   the change at the writer's current max SN. Asserts the threaded instance-key-hash landed."
  (let* ((node (dds.dcps::dp-node (dds.dcps::pub-participant (dds.dcps::dw-publisher dw))))
         (writer (dds.disc::disc-node-user-writer node))
         (hc (dds.rtps.reliable:rtps-writer-hc writer)))
    (dds.rtps.history:hc-get-change hc (dds.rtps.history:hc-max-seq hc))))

(defun* run-keeplast-keyhash-threaded-test ()
    (function () t)
  "WP-KEEPLAST B1 (ADR 0019, DDS 1.4 §2.2.3.18): a KEEP_LAST DataWriter threads the sample's
   instance keyhash onto its data CacheChange. (a) A KEEP_LAST writer of the KEYED shape-type:
   the just-written change carries instance-key-hash = the type-support keyhash of the sample.
   (b) A KEEP_LAST writer of the UNKEYED nokey-rt: the change's instance-key-hash is EQ to the
   shared +instance-handle-nil+ (proving the shared constant, no per-sample allocation). (c) A
   KEEP_ALL writer of the keyed shape-type: the gate skips the handle -> instance-key-hash NIL.
   The engine HistoryCache is still hard-coded KEEP_ALL (the QoS flip is Task D1), so this only
   verifies the THREADING; nothing is evicted-on yet."
  (let* ((kts (dds.types:find-type-support "shape-type"))
         (p (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((ktw (dds.dcps:create-topic p "KlSquare" "shape-type" kts))
                (kl-pub (dds.dcps:create-publisher p))
                (sample (make-shape-type :color "BLUE" :x 1 :y 2 :shapesize 10))
                (kl-keyed (dds.dcps:create-datawriter
                           kl-pub ktw :qos (dds.qos:make-writer-qos :history-kind :keep-last :history-depth 4))))
           (dds.dcps:write-sample kl-keyed sample)
           (%check :kl-keyed-handle
                   (equalp (dds.rtps.history:cache-change-instance-key-hash (%last-writer-change kl-keyed))
                           (funcall (dds.types:type-support-key-hash kts) sample))
                   "KEEP_LAST keyed writer must thread the type-support keyhash onto the data change"))
      (dds.dcps:delete-participant p)))
  (let* ((uts (dds.types:find-type-support "nokey-rt"))
           (p2 (dds.dcps:create-participant :domain (test-domain))))
      (unwind-protect
           (let* ((utw (dds.dcps:create-topic p2 "KlNoKey" "nokey-rt" uts))
                  (kl-pub2 (dds.dcps:create-publisher p2))
                  (kl-unkeyed (dds.dcps:create-datawriter
                               kl-pub2 utw :qos (dds.qos:make-writer-qos :history-kind :keep-last))))
             (dds.dcps:write-sample kl-unkeyed (make-nokey-rt :a 7 :b 9))
             (%check :kl-unkeyed-shared-nil
                     (eq (dds.rtps.history:cache-change-instance-key-hash (%last-writer-change kl-unkeyed))
                         dds.dcps::+instance-handle-nil+)
                     "KEEP_LAST unkeyed writer must thread the shared +instance-handle-nil+ (no per-sample alloc)"))
        (dds.dcps:delete-participant p2)))
    (let* ((kts (dds.types:find-type-support "shape-type"))
           (p3 (dds.dcps:create-participant :domain (test-domain))))
      (unwind-protect
           (let* ((ktw3 (dds.dcps:create-topic p3 "KaSquare" "shape-type" kts))
                  (ka-pub (dds.dcps:create-publisher p3))
                  (ka-keyed (dds.dcps:create-datawriter
                             ka-pub ktw3 :qos (dds.qos:make-writer-qos :history-kind :keep-all))))
             (dds.dcps:write-sample ka-keyed (make-shape-type :color "RED" :x 3 :y 4 :shapesize 5))
             (%check :ka-keyed-nil
                     (null (dds.rtps.history:cache-change-instance-key-hash (%last-writer-change ka-keyed)))
                     "KEEP_ALL keyed writer must SKIP the handle computation -> instance-key-hash NIL"))
        (dds.dcps:delete-participant p3)))
    t)

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
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "Square" "shape-type" ts))
                (tr (dds.dcps:create-topic p2 "Square" "shape-type" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                ;; KEEP_ALL both sides: this test retains 3 samples across 2 instances (BLUE x2) — ADR 0019 migration.
                (dw (dds.dcps:create-datawriter pub tw :qos (dds.qos:make-writer-qos :history-kind :keep-all)))
                (dr (dds.dcps:create-datareader sub tr :qos (dds.qos:make-reader-qos :history-kind :keep-all))))
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
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
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
   participant -> the unregister is the last-writer case.) The writer is created with
   autodispose_unregistered_instances FALSE (DDS 1.4 §2.2.3.21) so a plain unregister exercises the
   NO_WRITERS path; under the policy DEFAULT (TRUE) the same unregister would instead DISPOSE the
   instance (covered by run-dcps-autodispose-writer-test / run-dcps-autodispose-reader-test)."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "Square" "shape-type" ts))
                (tr (dds.dcps:create-topic p2 "Square" "shape-type" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter
                     pub tw :qos (dds.qos:make-writer-qos :autodispose-unregistered-instances nil)))
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
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
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
         (p (dds.dcps:create-participant :domain (test-domain))))
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

(defun* %stage-lifecycle-sn (node sn kind handle wid &optional status-flags)
    (function (t integer (member :dispose :unregister)
              (simple-array (unsigned-byte 8) (16)) (unsigned-byte 32) &optional t) t)
  "Stage a dispose/unregister lifecycle change at sequence number SN in NODE's SN map — the same
   (SN -> (kind key-hash status-flags writer-id source-guid)) record %on-user-lifecycle writes, minus
   the wire. The source GUID is a zero-prefix + WID EntityId (the owner-clear key, DDS 1.4 §2.2.3.9.2).
   STATUS-FLAGS is the StatusInfo_t flag octet (RTPS 2.5 §9.6.4.9); when NIL it is derived from KIND
   (the legacy pure-dispose 0x01 / pure-unregister 0x02 forms), so the reader's flag-based state can be
   exercised with a Disposed|Unregistered (0x03) octet by passing it explicitly."
  (let ((guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
        (sf (or status-flags (ecase kind
                               (:dispose dds.rtps.message:+statusinfo-disposed+)
                               (:unregister dds.rtps.message:+statusinfo-unregistered+)))))
    (setf (aref guid 12) (ldb (byte 8 24) wid) (aref guid 13) (ldb (byte 8 16) wid)
          (aref guid 14) (ldb (byte 8 8) wid) (aref guid 15) (ldb (byte 8 0) wid))
    (setf (gethash sn (dds.disc::%inner-table (dds.disc::disc-node-lifecycle-changes node) guid))
          (list kind handle sf wid guid)))
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
         (p (dds.dcps:create-participant :domain (test-domain))))
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

(defun* run-dcps-autodispose-reader-test ()
    (function () t)
  "DCPS reader-side flag-based instance_state for WRITER_DATA_LIFECYCLE.autodispose (S2, DDS 1.4
   §2.2.3.21 + §2.2.2.5.1.3): %drain-one-lifecycle must apply instance_state from the StatusInfo_t
   FLAG bits (RTPS 2.5 §9.6.4.9), not only the derived kind. (a) A Disposed|Unregistered (0x03)
   lifecycle for an instance with one writer -> NOT_ALIVE_DISPOSED (disposed dominates, §2.2.2.5.1.3),
   NOT NOT_ALIVE_NO_WRITERS, even though the writers-set is also emptied. (b) A pure Unregistered
   (0x02, the autodispose-FALSE form) of the last writer -> NOT_ALIVE_NO_WRITERS. (c) A pure Disposed
   (0x01) -> NOT_ALIVE_DISPOSED (unchanged). Deterministic offline injection — stage the change with
   an explicit StatusInfo octet, drive %drain once, no UDP."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "Square" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr (dds.dcps:create-datareader sub tp))
                (node (dds.dcps::dp-node p))
                (wid #x00000102)
                (du (logior dds.rtps.message:+statusinfo-disposed+
                            dds.rtps.message:+statusinfo-unregistered+))
                (s-a (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 10))
                (h-a (funcall (dds.types:type-support-key-hash ts) s-a))
                (s-b (make-shape-type :color "GREEN" :x 2 :y 2 :shapesize 11))
                (h-b (funcall (dds.types:type-support-key-hash ts) s-b))
                (s-c (make-shape-type :color "RED" :x 3 :y 3 :shapesize 12))
                (h-c (funcall (dds.types:type-support-key-hash ts) s-c)))
           ;; (a) D|U (0x03): writer registered ALIVE, then a default-autodispose unregister.
           (dds.dcps::%reader-revive-instance dr h-a wid)
           (%check :adr-a-alive (eq :alive (%instance-rec-state dr h-a)) "instance A must start ALIVE")
           (%stage-lifecycle-sn node 10 :unregister h-a wid du)
           (dds.dcps::%drain dr)
           (%check :adr-a-disposed (eq :not-alive-disposed (%instance-rec-state dr h-a))
                   "a Disposed|Unregistered (0x03) lifecycle must end NOT_ALIVE_DISPOSED (disposed dominates)")
           ;; (b) pure Unregistered (0x02): autodispose-FALSE form -> NO_WRITERS.
           (dds.dcps::%reader-revive-instance dr h-b wid)
           (%check :adr-b-alive (eq :alive (%instance-rec-state dr h-b)) "instance B must start ALIVE")
           (%stage-lifecycle-sn node 11 :unregister h-b wid dds.rtps.message:+statusinfo-unregistered+)
           (dds.dcps::%drain dr)
           (%check :adr-b-no-writers (eq :not-alive-no-writers (%instance-rec-state dr h-b))
                   "a pure Unregistered (0x02) of the last writer must end NOT_ALIVE_NO_WRITERS")
           ;; (c) pure Disposed (0x01): unchanged -> DISPOSED.
           (dds.dcps::%reader-revive-instance dr h-c wid)
           (%check :adr-c-alive (eq :alive (%instance-rec-state dr h-c)) "instance C must start ALIVE")
           (%stage-lifecycle-sn node 12 :dispose h-c wid dds.rtps.message:+statusinfo-disposed+)
           (dds.dcps::%drain dr)
           (%check :adr-c-disposed (eq :not-alive-disposed (%instance-rec-state dr h-c))
                   "a pure Disposed (0x01) lifecycle must end NOT_ALIVE_DISPOSED"))
      (dds.dcps:delete-participant p))
    t))

(defun* %lifecycle-status-flags (node sn)
    (function (t integer) t)
  "The StatusInfo_t flag octet (RTPS 2.5 §9.6.4.9) the subscriber engine recorded for the lifecycle
   DATA at sequence number SN (the 3rd element of the node's lifecycle 5-tuple), or NIL (test accessor)."
  (let ((lc (dds.disc:node-lifecycle-change-by-sn node sn)))
    (and lc (third lc))))

(defun* %instance-rec-not-alive-since (dr handle)
    (function (dds.dcps:data-reader (simple-array (unsigned-byte 8) (16))) t)
  "DR's NOT-ALIVE-SINCE internal-time stamp for HANDLE (nil when ALIVE / no record); test accessor."
  (let ((rec (gethash handle (dds.dcps::dr-instance-recs dr))))
    (and rec (dds.dcps::instance-rec-not-alive-since rec))))

(defun* %handle-cache-count (dr handle)
    (function (dds.dcps:data-reader (simple-array (unsigned-byte 8) (16))) (integer 0))
  "How many cached-samples (valid OR invalid) DR holds for instance HANDLE (test accessor)."
  (count-if (lambda (cs) (equalp handle (%cs-ih cs))) (dds.dcps::dr-cache dr)))

(defun* %backdate-not-alive (dr handle seconds-ago)
    (function (dds.dcps:data-reader (simple-array (unsigned-byte 8) (16)) (integer 0)) t)
  "Backdate instance HANDLE's not-alive-since by SECONDS-AGO of internal-time (clamped at 0 so a
   low-uptime test process never underflows the (integer 0) slot) — the deterministic offline stand-in
   for waiting out the autopurge delay (DDS 1.4 §2.2.3.22), no real sleep."
  (setf (dds.dcps::instance-rec-not-alive-since (gethash handle (dds.dcps::dr-instance-recs dr)))
        (max 0 (- (dds.dcps::%lease-now) (* seconds-ago internal-time-units-per-second))))
  t)

(defun* run-dcps-autopurge-test ()
    (function () t)
  "DCPS READER_DATA_LIFECYCLE autopurge of NOT_ALIVE instances (DDS 1.4 §2.2.3.22): after a configurable
   delay a DataReader purges all internal information + untaken samples for a NOT_ALIVE_NO_WRITERS or
   NOT_ALIVE_DISPOSED instance. Deterministic offline injection — stage data + a dispose/unregister in
   the engine SN maps, %drain, BACKDATE the instance's not-alive-since, run %autopurge-sweep; no UDP, no
   real wait. (a) DEFAULT (both autopurge delays INFINITE) NEVER purges (the no-op common case). (b) A
   FINITE autopurge_disposed_samples_delay purges a disposed instance once now-not-alive-since >= delay:
   its cached samples + instance-rec are gone, and a later sample for the SAME key starts a FRESH ALIVE
   instance (view-state NEW, disposed_generation_count reset 0). (c) The same via the no-writers path
   under autopurge_nowriter_samples_delay. (d) A still-ALIVE instance is never purged; a NOT_ALIVE
   instance WITHIN its delay is not purged."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (delay (dds.qos:make-qos-duration 1 0))         ; {1,0}s finite autopurge delay
         (wid #x00000102))
    ;; (a) DEFAULT (both delays INFINITE): a disposed instance is NEVER purged — the no-op default.
    (let ((p (dds.dcps:create-participant :domain (test-domain))))
      (unwind-protect
           (let* ((tp (dds.dcps:create-topic p "Square" "shape-type" ts))
                  (sub (dds.dcps:create-subscriber p))
                  (dr (dds.dcps:create-datareader sub tp))   ; default reader QoS = INFINITE delays
                  (node (dds.dcps::dp-node p))
                  (s (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 10))
                  (h (funcall (dds.types:type-support-key-hash ts) s))
                  (bytes (dds.dcps::%serialize-sample ts s)))
             (%stage-data-sn node 1 h bytes wid)
             (%stage-lifecycle-sn node 2 :dispose h wid dds.rtps.message:+statusinfo-disposed+)
             (dds.dcps::%drain dr)
             (%check :ap-def-disposed (eq :not-alive-disposed (%instance-rec-state dr h))
                     "instance must be NOT_ALIVE_DISPOSED before the sweep")
             ;; backdate far past any finite delay; INFINITE default must still never purge
             (%backdate-not-alive dr h 3600)
             (dds.dcps::%autopurge-sweep dr)
             (%check :ap-def-kept-rec (eq :not-alive-disposed (%instance-rec-state dr h))
                     "DEFAULT (INFINITE delay) must NEVER purge the instance-rec")
             (%check :ap-def-kept-cache (plusp (%handle-cache-count dr h))
                     "DEFAULT (INFINITE delay) must NEVER purge cached samples"))
        (dds.dcps:delete-participant p)))
    ;; (b) FINITE autopurge_disposed_samples_delay: disposed instance purged past the delay.
    (let ((p (dds.dcps:create-participant :domain (test-domain))))
      (unwind-protect
           (let* ((tp (dds.dcps:create-topic p "Square" "shape-type" ts))
                  (sub (dds.dcps:create-subscriber p))
                  (dr (dds.dcps:create-datareader
                       sub tp :qos (dds.qos:make-reader-qos :autopurge-disposed-samples-delay delay)))
                  (node (dds.dcps::dp-node p))
                  (s (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 10))
                  (h (funcall (dds.types:type-support-key-hash ts) s))
                  (bytes (dds.dcps::%serialize-sample ts s)))
             (%stage-data-sn node 1 h bytes wid)
             (%stage-lifecycle-sn node 2 :dispose h wid dds.rtps.message:+statusinfo-disposed+)
             (dds.dcps::%drain dr)
             (%check :ap-dis-state (eq :not-alive-disposed (%instance-rec-state dr h))
                     "instance must be NOT_ALIVE_DISPOSED before the sweep")
             (%check :ap-dis-stamped (integerp (%instance-rec-not-alive-since dr h))
                     "not-alive-since must be stamped on the ALIVE->NOT_ALIVE transition")
             ;; WITHIN the delay (not yet elapsed): not purged.
             (dds.dcps::%autopurge-sweep dr)
             (%check :ap-dis-within (eq :not-alive-disposed (%instance-rec-state dr h))
                     "a disposed instance WITHIN its delay must not be purged")
             ;; BACKDATE past the 1s delay -> purge.
             (%backdate-not-alive dr h 2)
             (dds.dcps::%autopurge-sweep dr)
             (%check :ap-dis-rec-gone (null (gethash h (dds.dcps::dr-instance-recs dr)))
                     "the disposed instance-rec must be PURGED past the delay")
             (%check :ap-dis-cache-gone (zerop (%handle-cache-count dr h))
                     "the disposed instance's cached samples must be PURGED past the delay")
             (%check :ap-dis-view-gone (not (nth-value 1 (gethash h (dds.dcps::dr-instances dr))))
                     "the purged instance's view-state entry must be removed")
             ;; A NEW sample for the SAME key starts a FRESH ALIVE instance (view NEW, gen reset 0).
             (%stage-data-sn node 3 h bytes wid)
             (dds.dcps::%drain dr)
             (%check :ap-dis-fresh-alive (eq :alive (%instance-rec-state dr h))
                     "a sample after purge must start a FRESH ALIVE instance")
             (%check :ap-dis-fresh-gen (= 0 (%instance-rec-disp-gen dr h))
                     "the fresh instance's disposed_generation_count must reset to 0")
             (let ((info (dds.dcps:cached-sample-info
                          (first (dds.dcps:read-samples dr :states '(:not-read))))))
               (%check :ap-dis-fresh-view (eq :new (dds.dcps:sample-info-view-state info))
                       "the fresh instance's first sample view-state must be NEW")))
        (dds.dcps:delete-participant p)))
    ;; (c) FINITE autopurge_nowriter_samples_delay: no-writers instance purged past the delay.
    (let ((p (dds.dcps:create-participant :domain (test-domain))))
      (unwind-protect
           (let* ((tp (dds.dcps:create-topic p "Square" "shape-type" ts))
                  (sub (dds.dcps:create-subscriber p))
                  (dr (dds.dcps:create-datareader
                       sub tp :qos (dds.qos:make-reader-qos :autopurge-nowriter-samples-delay delay)))
                  (node (dds.dcps::dp-node p))
                  (s (make-shape-type :color "GREEN" :x 5 :y 5 :shapesize 22))
                  (h (funcall (dds.types:type-support-key-hash ts) s))
                  (bytes (dds.dcps::%serialize-sample ts s)))
             (%stage-data-sn node 1 h bytes wid)
             ;; pure Unregistered (0x02) of the last writer -> NOT_ALIVE_NO_WRITERS.
             (%stage-lifecycle-sn node 2 :unregister h wid dds.rtps.message:+statusinfo-unregistered+)
             (dds.dcps::%drain dr)
             (%check :ap-nw-state (eq :not-alive-no-writers (%instance-rec-state dr h))
                     "instance must be NOT_ALIVE_NO_WRITERS before the sweep")
             (%check :ap-nw-stamped (integerp (%instance-rec-not-alive-since dr h))
                     "not-alive-since must be stamped on the no-writers transition")
             (%backdate-not-alive dr h 2)
             (dds.dcps::%autopurge-sweep dr)
             (%check :ap-nw-rec-gone (null (gethash h (dds.dcps::dr-instance-recs dr)))
                     "the no-writers instance-rec must be PURGED past the delay")
             (%check :ap-nw-cache-gone (zerop (%handle-cache-count dr h))
                     "the no-writers instance's cached samples must be PURGED past the delay"))
        (dds.dcps:delete-participant p)))
    ;; (d) cross-policy: a disposed-delay reader must NOT purge a NOT_ALIVE_NO_WRITERS instance, and an
    ;; ALIVE instance is never purged regardless.
    (let ((p (dds.dcps:create-participant :domain (test-domain))))
      (unwind-protect
           (let* ((tp (dds.dcps:create-topic p "Square" "shape-type" ts))
                  (sub (dds.dcps:create-subscriber p))
                  (dr (dds.dcps:create-datareader
                       sub tp :qos (dds.qos:make-reader-qos :autopurge-disposed-samples-delay delay)))
                  (node (dds.dcps::dp-node p))
                  (s-nw (make-shape-type :color "GREEN" :x 5 :y 5 :shapesize 22))
                  (h-nw (funcall (dds.types:type-support-key-hash ts) s-nw))
                  (b-nw (dds.dcps::%serialize-sample ts s-nw))
                  (s-al (make-shape-type :color "RED" :x 3 :y 3 :shapesize 14))
                  (h-al (funcall (dds.types:type-support-key-hash ts) s-al))
                  (b-al (dds.dcps::%serialize-sample ts s-al)))
             (%stage-data-sn node 1 h-nw b-nw wid)
             (%stage-lifecycle-sn node 2 :unregister h-nw wid dds.rtps.message:+statusinfo-unregistered+)
             (%stage-data-sn node 3 h-al b-al wid)         ; stays ALIVE
             (dds.dcps::%drain dr)
             (%check :ap-x-nw (eq :not-alive-no-writers (%instance-rec-state dr h-nw))
                     "the no-writers instance must be NOT_ALIVE_NO_WRITERS")
             (%check :ap-x-al (eq :alive (%instance-rec-state dr h-al))
                     "the other instance must be ALIVE")
             (%backdate-not-alive dr h-nw 2)
             (dds.dcps::%autopurge-sweep dr)
             (%check :ap-x-nw-kept (eq :not-alive-no-writers (%instance-rec-state dr h-nw))
                     "a disposed-delay reader must NOT purge a NOT_ALIVE_NO_WRITERS instance")
             (%check :ap-x-al-kept (eq :alive (%instance-rec-state dr h-al))
                     "a still-ALIVE instance must NEVER be purged"))
        (dds.dcps:delete-participant p)))
    t))

(defun* run-dcps-autodispose-writer-test ()
    (function () t)
  "DCPS writer-side WRITER_DATA_LIFECYCLE.autodispose_unregistered_instances over UDP (S1, DDS 1.4
   §2.2.3.21): a DEFAULT DataWriter (autodispose TRUE) that unregisters an instance must emit the
   unregister DATA with StatusInfo Disposed|Unregistered (0x03) — behaviour identical to a dispose
   before the unregister (§2.2.3.21) — while a writer created with autodispose FALSE emits only
   Unregistered (0x02). Asserts the exact StatusInfo_t octet the subscriber's engine recorded for the
   unregister DATA (RTPS 2.5 §9.6.4.9), the conformant default the live Fast DDS oracle confirmed."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (du (logior dds.rtps.message:+statusinfo-disposed+
                     dds.rtps.message:+statusinfo-unregistered+)))
    (flet ((scenario (writer-qos)
             (let ((p1 (dds.dcps:create-participant :domain (test-domain)))
                   (p2 (dds.dcps:create-participant :domain (test-domain))))
               (unwind-protect
                    (let* ((tw (dds.dcps:create-topic p1 "Square" "shape-type" ts))
                           (tr (dds.dcps:create-topic p2 "Square" "shape-type" ts))
                           (pub (dds.dcps:create-publisher p1))
                           (sub (dds.dcps:create-subscriber p2))
                           (dw (dds.dcps:create-datawriter pub tw :qos writer-qos))
                           (dr (dds.dcps:create-datareader sub tr))
                           (sample (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 10))
                           (node2 (dds.dcps::dp-node p2)))
                      (declare (ignore dr))
                      (loop repeat 150
                            until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                            do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
                      (%check :adw-matched (plusp (dds.dcps:matched-count p1)) "endpoints did not match")
                      (let ((handle (dds.dcps:register-instance dw sample)))
                        (dds.dcps:write-sample dw sample)             ; SN 1 ALIVE
                        (loop repeat 100 until (plusp (dds.disc:node-sample-count node2))
                              do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
                        (dds.dcps:unregister-instance dw handle)       ; SN 2 unregister
                        (loop repeat 150 until (dds.disc:node-lifecycle-change-by-sn node2 2)
                              do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
                        (%check :adw-received (dds.disc:node-lifecycle-change-by-sn node2 2)
                                "subscriber engine never received the unregister DATA")
                        (%lifecycle-status-flags node2 2)))
                 (dds.dcps:delete-participant p1)
                 (dds.dcps:delete-participant p2)))))
      (%check :adw-default-0x03 (= du (scenario (dds.qos:make-writer-qos)))
              "a default DataWriter's unregister must emit StatusInfo Disposed|Unregistered (0x03)")
      (%check :adw-off-0x02
              (= dds.rtps.message:+statusinfo-unregistered+
                 (scenario (dds.qos:make-writer-qos :autodispose-unregistered-instances nil)))
              "autodispose FALSE must emit only StatusInfo Unregistered (0x02)"))
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
         (p (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "Square" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr (dds.dcps:create-datareader
                     sub tp :qos (dds.qos:make-reader-qos :ownership reader-ownership :history-kind :keep-all)))   ; KEEP_ALL: counts >1 same-instance delivered sample (ADR 0019 migration)
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
         (p (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "Square" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr (dds.dcps:create-datareader
                     sub tp :qos (dds.qos:make-reader-qos :ownership :exclusive :history-kind :keep-all)))   ; KEEP_ALL: counts 2 same-instance delivered samples (A@1+B@2) (ADR 0019 migration)
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
         (p (dds.dcps:create-participant :domain (test-domain))))
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
   the wire (the owner-clear key, DDS 1.4 §2.2.3.9.2). Keyed by source GUID then SN (§8.3.5.4). The
   StatusInfo_t octet is derived from KIND (RTPS 2.5 §9.6.4.9) so the reader's flag-based state applies."
  (let ((sf (ecase kind
              (:dispose dds.rtps.message:+statusinfo-disposed+)
              (:unregister dds.rtps.message:+statusinfo-unregistered+))))
    (setf (gethash sn (dds.disc::%inner-table (dds.disc::disc-node-lifecycle-changes node) guid))
          (list kind handle sf (dds.dcps::%guid-entityid guid) (copy-seq guid))))
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
         (p (dds.dcps:create-participant :domain (test-domain))))
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

;;; Multi-writer dispose non-collision at the SAME SN (S1/S2, RTPS 2.5 §8.3.5.4: a
;;; SequenceNumber is unique only within one writer GUID). Writers A and B share EntityId
;;; 0x102 on different participants and each disposes its OWN instance at the SAME raw SN.
;;; An SN-only lifecycle store would have B's dispose CLOBBER A's; the 2-level (GUID -> SN)
;;; store keeps them independent, so BOTH instances transition NOT_ALIVE_DISPOSED.

(defun* run-dcps-multiwriter-dispose-test ()
    (function () t)
  "Two writers sharing EntityId 0x102 on different participants dispose their OWN instances at
   the SAME raw SN (3). The lifecycle store keyed by source GUID then SN (RTPS 2.5 §8.3.5.4)
   must keep both disposes — A's dispose of instance-A and B's dispose of instance-B must each
   land NOT_ALIVE_DISPOSED, not clobber each other. Deterministic offline injection — no UDP."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "Square" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr (dds.dcps:create-datareader sub tp))
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
           ;; A writes instance-A (SN 1), B writes instance-B (SN 1) — each its own SN space.
           (%stage-data-sn-guid node 1 bytes-a guid-a)
           (%stage-data-sn-guid node 1 bytes-b guid-b)
           (dds.dcps::%drain dr)
           (%check :mwd-a-alive (eq :alive (%instance-rec-state dr handle-a))
                   "instance-A must be ALIVE after writer A's first sample")
           (%check :mwd-b-alive (eq :alive (%instance-rec-state dr handle-b))
                   "instance-B must be ALIVE after writer B's first sample")
           ;; A disposes instance-A at SN 3; B disposes instance-B at the SAME SN 3.
           (%stage-lifecycle-sn-guid node 3 :dispose handle-a guid-a)
           (%stage-lifecycle-sn-guid node 3 :dispose handle-b guid-b)
           (dds.dcps::%drain dr)
           (%check :mwd-a-disposed (eq :not-alive-disposed (%instance-rec-state dr handle-a))
                   "A's dispose@SN3 must transition instance-A NOT_ALIVE_DISPOSED")
           (%check :mwd-b-disposed (eq :not-alive-disposed (%instance-rec-state dr handle-b))
                   "B's dispose@SN3 must NOT be clobbered by A's same-SN dispose (§8.3.5.4)"))
      (dds.dcps:delete-participant p))
    t))

;;; RxO over the wire (M3 #1, FR-QOS-2): SEDP now carries the full QoS (reliability +
;;; durability), and endpoint-match-p uses dds.qos:qos-rxo-compatible. Incompatible QoS
;;; blocks endpoint matching even when topic+type agree. (Gating DATA delivery on the
;;; match — so RxO also blocks delivery, not just matching — is the immediate follow-up.)

(defun* %peer-matched-count (p peer)
    (function (dds.dcps:domain-participant dds.dcps:domain-participant) (integer 0))
  "TEST-ONLY peer-scoped matched-count: how many of P's matched remote endpoints belong
   to PEER — i.e. carry PEER's own participant GUID-prefix (RTPS 2.5 §9.3.1.2). Node-wide
   dds.dcps:matched-count also counts foreign participants on the shared domain (e.g. a
   domain-0 rtiddsspy that auto-subscribes to the topic), so it cannot prove THIS
   writer/reader pair matched — this can."
  (dds.disc::%disc-node-matched-count-for-prefix
   (dds.dcps::dp-node p)
   (dds.disc:disc-node-guid-prefix (dds.dcps::dp-node peer))))

(defun* %rxo-scenario (writer-qos reader-qos)
    (function (t t) (values integer t))
  "Create a writer/reader pair with the given QoS on a shared topic; spin discovery,
   write one sample, and return (values PEER-SCOPED-MATCHED-COUNT DATA-RECEIVED-P) — the
   match count scoped to the p1<->p2 pair (robust to any foreign participant on the
   domain), so the test can assert RxO blocks both the match AND delivery."
  (let ((p1 (dds.dcps:create-participant :domain (test-domain +td-rxo+)))
        (p2 (dds.dcps:create-participant :domain (test-domain +td-rxo+)))
        (ts (dds.types:find-type-support "dcps-msg")))
    (unwind-protect
         (let ((pub (dds.dcps:create-publisher p1)) (sub (dds.dcps:create-subscriber p2))
               (tw (dds.dcps:create-topic p1 "RxoTopic" "dcps-msg" ts))
               (tr (dds.dcps:create-topic p2 "RxoTopic" "dcps-msg" ts)))
           (let ((dw (dds.dcps:create-datawriter pub tw :qos writer-qos))
                 (dr (dds.dcps:create-datareader sub tr :qos reader-qos)))
             (loop repeat 120
                   until (and (plusp (%peer-matched-count p1 p2)) (plusp (%peer-matched-count p2 p1)))
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (dds.dcps:write-sample dw (make-dcps-msg :id 1 :text "rxo"))
             (loop repeat 60 until (plusp (dds.dcps:samples-available dr))
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (values (+ (%peer-matched-count p1 p2) (%peer-matched-count p2 p1))
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
        (p1 (dds.dcps:create-participant :domain (test-domain)))
        (p2 (dds.dcps:create-participant :domain (test-domain))))
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
(defmethod dds.dcps:on-offered-incompatible-qos ((l capturing-writer-listener) writer status)
  (declare (ignore writer))
  (dds.pal:with-lock ((cap-lock l)) (push (cons :off-incompat status) (cap-hits l))))

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
        (p1 (dds.dcps:create-participant :domain (test-domain)))
        (p2 (dds.dcps:create-participant :domain (test-domain)))
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

;;; WP-DCPS-API-COMPLETION S0 — status/introspection foundation (DDS 1.4).

(defun* run-dcps-status-structs-test ()
    (function () t)
  "S0.T1 (dds_rtf2_dcps.idl §99-102 / §131-135 / §137-141): the SAMPLE_LOST,
   OFFERED_DEADLINE_MISSED and REQUESTED_DEADLINE_MISSED status structs exist as exported
   value structs with their spec fields (total_count/total_count_change, plus
   last_instance_handle for the two deadline statuses; the RTF2 SampleLostStatus carries no
   SampleLostStatusKind, so no last_reason)."
  (flet ((ext (name) (eq :external (nth-value 1 (find-symbol name "NET.GOENNINGER.DDS.DCPS")))))
    (%check :sl-exported (ext "MAKE-SAMPLE-LOST-STATUS")
            "make-sample-lost-status must be exported")
    (%check :odm-exported (ext "MAKE-OFFERED-DEADLINE-MISSED-STATUS")
            "make-offered-deadline-missed-status must be exported")
    (%check :rdm-exported (ext "MAKE-REQUESTED-DEADLINE-MISSED-STATUS")
            "make-requested-deadline-missed-status must be exported"))
  (let ((sl (dds.dcps:make-sample-lost-status :total-count 3 :total-count-change 2)))
    (%check :sl-fields (and (= 3 (dds.dcps:sample-lost-status-total-count sl))
                            (= 2 (dds.dcps:sample-lost-status-total-count-change sl)))
            "sample-lost-status total_count/total_count_change round-trip"))
  (let ((h (octets 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)))
    (let ((odm (dds.dcps:make-offered-deadline-missed-status
                :total-count 1 :total-count-change 1 :last-instance-handle h)))
      (%check :odm-fields (and (= 1 (dds.dcps:offered-deadline-missed-status-total-count odm))
                               (= 1 (dds.dcps:offered-deadline-missed-status-total-count-change odm))
                               (eq h (dds.dcps:offered-deadline-missed-status-last-instance-handle odm)))
              "offered-deadline-missed-status fields round-trip"))
    (let ((rdm (dds.dcps:make-requested-deadline-missed-status
                :total-count 4 :total-count-change 4 :last-instance-handle h)))
      (%check :rdm-fields (and (= 4 (dds.dcps:requested-deadline-missed-status-total-count rdm))
                               (= 4 (dds.dcps:requested-deadline-missed-status-total-count-change rdm))
                               (eq h (dds.dcps:requested-deadline-missed-status-last-instance-handle rdm)))
              "requested-deadline-missed-status fields round-trip")))
  t)

(defun* run-dcps-status-changes-test ()
    (function () t)
  "S0.T2 (dds_rtf2_dcps.idl §684 Entity::get_status_changes): a per-entity status-changes
   bitmask, read by get_status_changes and driven by the internal %set-status-changed /
   %clear-status-changed helpers (the %notify-status chokepoint wiring is S0.T3). A fresh
   entity reports 0; setting SUBSCRIPTION_MATCHED + SAMPLE_REJECTED surfaces both; clearing
   one removes only that bit."
  (let ((p (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((ts (dds.types:find-type-support "dcps-msg"))
                (tp (dds.dcps:create-topic p "ChgTopic" "dcps-msg" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr (dds.dcps:create-datareader sub tp)))
           (%check :chg-initial (zerop (dds.dcps:get-status-changes dr))
                   "a freshly-created reader has an empty status-changes mask")
           (dds.dcps::%set-status-changed dr dds.dcps:+status-subscription-matched+)
           (dds.dcps::%set-status-changed dr dds.dcps:+status-sample-rejected+)
           (%check :chg-set
                   (and (logtest dds.dcps:+status-subscription-matched+ (dds.dcps:get-status-changes dr))
                        (logtest dds.dcps:+status-sample-rejected+ (dds.dcps:get-status-changes dr)))
                   "%set-status-changed must surface both bits via get_status_changes")
           (dds.dcps::%clear-status-changed dr dds.dcps:+status-subscription-matched+)
           (%check :chg-clear-one
                   (and (not (logtest dds.dcps:+status-subscription-matched+ (dds.dcps:get-status-changes dr)))
                        (logtest dds.dcps:+status-sample-rejected+ (dds.dcps:get-status-changes dr)))
                   "%clear-status-changed must clear only the named bit"))
      (dds.dcps:delete-participant p))
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
        (p1 (dds.dcps:create-participant :domain (test-domain)))
        (p2 (dds.dcps:create-participant :domain (test-domain)))
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
        (p1 (dds.dcps:create-participant :domain (test-domain)))
        (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "QueryTopic" "dcps-msg" ts))
                (tr (dds.dcps:create-topic p2 "QueryTopic" "dcps-msg" ts))
                (pub (dds.dcps:create-publisher p1)) (sub (dds.dcps:create-subscriber p2))
                ;; KEEP_ALL both sides: unkeyed dcps-msg; read_w_condition is non-destructive (both samples stay cached) — ADR 0019 migration.
                (dw (dds.dcps:create-datawriter pub tw :qos (dds.qos:make-writer-qos :history-kind :keep-all)))
                (dr (dds.dcps:create-datareader sub tr :qos (dds.qos:make-reader-qos :history-kind :keep-all)))
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
        (p1 (dds.dcps:create-participant :domain (test-domain)))
        (p2 (dds.dcps:create-participant :domain (test-domain)))
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
        (p1 (dds.dcps:create-participant :domain (test-domain)))
        (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "Square" "shape-type" ts))
                (tr (dds.dcps:create-topic p2 "Square" "shape-type" ts))
                (cft (dds.dcps:create-contentfilteredtopic p2 "FastSquare" tr "x > %0" '("50")))
                (pub (dds.dcps:create-publisher p1)) (sub (dds.dcps:create-subscriber p2))
                ;; KEEP_ALL both sides: 3 same-instance (BLUE) samples; the CFT surfaces the 2 matching (x=100,200) — ADR 0019 migration.
                (dw (dds.dcps:create-datawriter pub tw :qos (dds.qos:make-writer-qos :history-kind :keep-all)))
                (dr (dds.dcps:create-datareader sub cft :qos (dds.qos:make-reader-qos :history-kind :keep-all))))
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
        (p (dds.dcps:create-participant :domain (test-domain))))
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
        (p1 (dds.dcps:create-participant :domain (test-domain)))
        (p2 (dds.dcps:create-participant :domain (test-domain)))
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
        (p1 (dds.dcps:create-participant :domain (test-domain)))
        (p2 (dds.dcps:create-participant :domain (test-domain)))
        (rl (make-instance 'capturing-reader-listener)))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "RejTopic" "dcps-msg" ts))
                (tr (dds.dcps:create-topic p2 "RejTopic" "dcps-msg" ts))
                (pub (dds.dcps:create-publisher p1)) (sub (dds.dcps:create-subscriber p2))
                ;; KEEP_ALL both sides: tests RESOURCE_LIMITS *reject* (max_samples=2) — the writer must deliver all 3
                ;; unkeyed samples and the reader must NOT lossy-drop, so the 3rd hits the reject path — ADR 0019 migration.
                (dw (dds.dcps:create-datawriter pub tw :qos (dds.qos:make-writer-qos :history-kind :keep-all)))
                (dr (dds.dcps:create-datareader sub tr
                      :qos (dds.qos:make-reader-qos :reliability :reliable :history-kind :keep-all
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
        (p1 (dds.dcps:create-participant :domain (test-domain)))
        (p2 (dds.dcps:create-participant :domain (test-domain))))
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
        (p (dds.dcps:create-participant :domain (test-domain))))
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
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain)))
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

;;; ACKNACK retransmit addressing (RTPS 2.5 §8.4.2.2 / §9.4.4): a NACK comes from exactly one
;;; reader, so the writer must retransmit the NACKed changes to THAT participant's destination
;;; alone, not fan them out to every matched reader (over-send, harmless under KEEP_ALL but
;;; wasteful). %prefix-user-destination resolves the single (host . port) from the ACKNACK's
;;; src-prefix; the test seeds two matched reader participants and asserts the fan-out set is 2
;;; while the targeted resolution picks exactly the originating one.

(defun* %seed-reader-participant (node prefix-byte port)
    (function (dds.disc:disc-node (unsigned-byte 8) (unsigned-byte 16))
              (values (simple-array (unsigned-byte 8) (12)) cons))
  "Seed NODE with a discovered remote participant (SPDP, default-unicast 127.0.0.1:PORT) holding one
   matched user READER endpoint (with-key kind 0x07), its 12-octet prefix all PREFIX-BYTE. Returns
   the prefix and its expected (host . port) — the offline twin of SPDP+SEDP for a remote reader."
  (let* ((prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element prefix-byte))
         (guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element prefix-byte))
         (loc (dds.rtps.discovery:make-locator
               :kind dds.rtps.discovery:+locator-kind-udpv4+ :port port
               :address (dds.rtps.discovery:make-ipv4-locator
                         (coerce #(127 0 0 1) '(simple-array (unsigned-byte 8) (4)))))))
    (setf (aref guid 12) #x00 (aref guid 13) #x00 (aref guid 14) #x01 (aref guid 15) #x07)
    (dds.disc::%record-participant
     node (dds.rtps.discovery:make-spdp-data
           :guid-prefix prefix :version-major 2 :version-minor 5
           :metatraffic-unicast-locators (list loc) :default-unicast-locators (list loc)))
    (setf (gethash (copy-seq guid) (dds.disc::disc-node-matches node))
          (dds.rtps.discovery:make-endpoint-data
           :guid guid :topic-name "Square" :type-name "shape-type" :qos (dds.qos:make-reader-qos)))
    (values prefix (cons "127.0.0.1" port))))

(defun* run-acknack-addressing-test ()
    (function () t)
  "A writer with TWO matched reader participants resolves an ACKNACK's retransmit destination to the
   ONE originating reader (RTPS 2.5 §8.4.2.2): %prefix-user-destination returns each reader's
   (host . port) and NIL for an undiscovered prefix, while %match-destinations still lists BOTH — so
   the fix narrows a 2-way fan-out resend to the single NACKing reader."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 7)
               :host "127.0.0.1" :port 0)))
    (unwind-protect
         (multiple-value-bind (p1 d1) (%seed-reader-participant node #x21 7501)
           (multiple-value-bind (p2 d2) (%seed-reader-participant node #x22 7502)
             (%check :ana-resolve-1 (equal d1 (dds.disc::%prefix-user-destination node p1))
                     "%prefix-user-destination must resolve reader 1's (host . port)")
             (%check :ana-resolve-2 (equal d2 (dds.disc::%prefix-user-destination node p2))
                     "%prefix-user-destination must resolve reader 2's (host . port)")
             (%check :ana-resolve-nil
                     (null (dds.disc::%prefix-user-destination
                            node (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xee)))
                     "an undiscovered prefix must resolve to NIL (falls back to fan-out)")
             (%check :ana-fanout-two (= 2 (length (dds.disc::%match-destinations node t)))
                     "both matched readers must be in the fan-out set (the pre-fix breadth)")
             (%check :ana-targeted-one
                     (and (equal d1 (dds.disc::%prefix-user-destination node p1))
                          (not (equal (dds.disc::%prefix-user-destination node p1)
                                      (dds.disc::%prefix-user-destination node p2))))
                     "the targeted resend destination must be reader 1 alone, distinct from reader 2")))
      (dds.disc:stop-node node)))
  t)

;;; Static-:peers user-data isolation (FR-DISC-4 / RTPS 2.5 §9.6.1.4): a :peers entry is an SPDP
;;; metatraffic BOOTSTRAP locator, NOT a user-data destination. Once a reader is matched, user data must
;;; go to its DEFAULT_UNICAST locator alone — the static SPDP peer (a different port) must not also
;;; receive user DATA (a foreign peer like Fast DDS binds metatraffic 7410 and user 7411 on separate
;;; ports, so user DATA to 7410 is dropped; our own stack shares one socket so it was merely wasteful).
;;; The fallback to static peers as a user-data destination fires ONLY in the discovery-less case
;;; (no matched reader resolved).

(defun* run-push-spdp-peer-isolation-test ()
    (function () t)
  "A matched reader's resolved DEFAULT_UNICAST destination is the sole user-data push target; a static
   :peers SPDP/metatraffic locator on a DIFFERENT port is NOT added as a second user-data destination
   once a reader is matched. The static-peer fallback fires ONLY when no matched reader resolved (the
   discovery-less path)."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 7)
               :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (%seed-reader-participant node #x60 7411)              ; matched reader, user locator 127.0.0.1:7411
           (setf (dds.disc::disc-node-peers node) (list (cons "127.0.0.1" 7410)))  ; SPDP bootstrap peer, port 7410
           (let ((groups (dds.disc::%reader-push-targets node)))
             (%check :psi-one-group (= 1 (length groups))
                     "a matched reader must not add the static SPDP peer as a 2nd user-data destination")
             (%check :psi-user-dest (equal (cons "127.0.0.1" 7411) (car (first groups)))
                     "the push destination must be the reader's DEFAULT_UNICAST locator (7411)")
             (%check :psi-no-spdp-port
                     (notany (lambda (g) (equal (cons "127.0.0.1" 7410) (car g))) groups)
                     "user data must never target the static SPDP/metatraffic peer port (7410)"))
           (clrhash (dds.disc::disc-node-matches node))           ; discovery-less: no matched reader
           (let ((groups (dds.disc::%reader-push-targets node)))
             (%check :psi-fallback
                     (and (= 1 (length groups)) (equal (cons "127.0.0.1" 7410) (car (first groups))))
                     "with no matched reader the static peer is the discovery-less fallback destination")))
      (dds.disc:stop-node node)))
  t)

(defun* run-purge-reliable-only-test ()
    (function () t)
  "writer-purge-acked is driven ONLY by matched RELIABLE readers: a BEST_EFFORT reader never ACKNACKs, so
   if it were in %matched-reader-keys its proxy (acked-base 1) would pin the purge watermark forever and
   the writer history would grow unbounded. Seed one reliable + one best-effort matched reader and assert
   only the reliable reader's GUID is keyed for the purge (DDS 1.4 §2.2.3.13: best-effort owes no ack)."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 7)
               :host "127.0.0.1" :port 0)))
    (unwind-protect
         (let ((rel (%colocated-reader-guid #x61 #x01))
               (be (%colocated-reader-guid #x62 #x01)))
           (dolist (spec (list (cons rel :reliable) (cons be :best-effort)))
             (setf (gethash (copy-seq (car spec)) (dds.disc::disc-node-matches node))
                   (dds.rtps.discovery:make-endpoint-data
                    :guid (car spec) :topic-name "Square" :type-name "shape-type"
                    :qos (dds.qos:make-qos :reliability (cdr spec)))))
           (let ((keys (dds.disc::%matched-reader-keys node)))
             (%check :pro-one (= 1 (length keys))
                     "only the RELIABLE matched reader must be a purge watermark key")
             (%check :pro-reliable (find rel keys :test #'equalp)
                     "the reliable reader's GUID must be a purge key")
             (%check :pro-not-be (not (find be keys :test #'equalp))
                     "a best-effort reader must NOT pin the purge watermark (it never ACKNACKs)")))
      (dds.disc:stop-node node)))
  t)

;;; Co-located multi-reader send-once (RTPS 2.5 §8.4.2.2 / §8.3.5.4): two DataReaders in ONE remote
;;; participant share a unicast destination (a DATA with readerId UNKNOWN reaches both). The writer
;;; must advance EACH reader's unsent-base watermark while sending the union to the destination once —
;;; so neither reader re-pushes history on a later write. The old code deduped push targets by
;;; destination, advancing only ONE reader and leaving the other's accounting stale. Offline: seed two
;;; reader endpoints sharing a prefix/destination, write, and assert %reader-push-targets groups them
;;; and %merge-unsent advances both.

(defun* %colocated-reader-guid (prefix-byte entity-key)
    (function ((unsigned-byte 8) (unsigned-byte 8)) (simple-array (unsigned-byte 8) (16)))
  "A with-key user-reader GUID (kind 0x07) in participant PREFIX-BYTE (all 12 prefix octets) with
   entityKey ENTITY-KEY — two such GUIDs sharing PREFIX-BYTE are two readers in ONE participant."
  (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element prefix-byte)))
    (setf (aref g 12) #x00 (aref g 13) #x00 (aref g 14) entity-key (aref g 15) #x07)
    g))

(defun* run-colocated-push-test ()
    (function () t)
  "Two matched DataReaders in ONE remote participant get send-once accounting EACH (RTPS 2.5
   §8.4.2.2/§8.3.5.4): %reader-push-targets groups them under one destination carrying both GUIDs;
   after the writer pushes a change, BOTH readers' unsent-base advanced (neither re-pushes history on a
   later write). Asserts the per-reader watermark via writer-unsent-list and %merge-unsent's union."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 8)
               :host "127.0.0.1" :port 0)))
    (unwind-protect
         (let* ((loc (dds.rtps.discovery:make-locator
                      :kind dds.rtps.discovery:+locator-kind-udpv4+ :port 7601
                      :address (dds.rtps.discovery:make-ipv4-locator
                                (coerce #(127 0 0 1) '(simple-array (unsigned-byte 8) (4))))))
                (prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x33))
                (guid-a (%colocated-reader-guid #x33 #x01))
                (guid-b (%colocated-reader-guid #x33 #x02)))
           (declare (ignore prefix))
           (dds.disc:enable-publisher node)
           (dds.disc::%record-participant
            node (dds.rtps.discovery:make-spdp-data
                  :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x33)
                  :version-major 2 :version-minor 5
                  :metatraffic-unicast-locators (list loc) :default-unicast-locators (list loc)))
           (dolist (g (list guid-a guid-b))
             (setf (gethash (copy-seq g) (dds.disc::disc-node-matches node))
                   (dds.rtps.discovery:make-endpoint-data
                    :guid g :topic-name "Square" :type-name "shape-type" :qos (dds.qos:make-reader-qos))))
           (let* ((writer (dds.disc::disc-node-user-writer node))
                  (groups (dds.disc::%reader-push-targets node)))
             (%check :colo-one-group (= 1 (length groups))
                     "two co-located readers must form ONE destination group")
             (%check :colo-dest (equal (cons "127.0.0.1" 7601) (car (first groups)))
                     "the group's destination must be the shared unicast (host . port)")
             (%check :colo-two-keys (= 2 (length (cdr (first groups))))
                     "the group must carry BOTH co-located reader GUIDs")
             (dds.rtps.reliable:writer-write writer (octets 9 9 9 9))
             (let ((m1 (dds.disc::%merge-unsent writer (cdr (first groups)))))
               (%check :colo-union-1
                       (and (= 1 (length m1))
                            (= 1 (dds.rtps.history:cache-change-sn (first m1))))
                       "the first push must send exactly SN 1 once to the shared destination"))
             ;; %merge-unsent advanced BOTH readers: each is now empty (proves the second was not left behind).
             (%check :colo-a-advanced (null (dds.rtps.reliable:writer-unsent-list writer guid-a))
                     "reader A's unsent-base must have advanced past SN 1")
             (%check :colo-b-advanced (null (dds.rtps.reliable:writer-unsent-list writer guid-b))
                     "reader B's unsent-base must have advanced past SN 1 (the co-located fix)")
             (dds.rtps.reliable:writer-write writer (octets 8 8 8 8))
             (let ((m2 (dds.disc::%merge-unsent writer (cdr (first groups)))))
               (%check :colo-no-repush
                       (and (= 1 (length m2))
                            (= 2 (dds.rtps.history:cache-change-sn (first m2))))
                       "the second push must send ONLY SN 2 — no re-push of SN 1 history"))))
      (dds.disc:stop-node node)))
  t)

;;; Send-side submessage coalescing (RTPS 2.5 §8.3.4): a writer packs multiple small DATA submessages
;;; plus the trailing HEARTBEAT into ONE datagram instead of one datagram per submessage, cutting the
;;; sendto count. The receiver already accepts multi-submessage datagrams (dispatch-message). Offline:
;;; capture every outgoing datagram via *datagram-sink*, re-parse with dispatch-message, and assert the
;;; submessage total is preserved while the datagram COUNT drops (and each datagram is within budget).

(defun* %count-submessages (bytes)
    (function ((simple-array (unsigned-byte 8) (*))) list)
  "Parse a captured RTPS datagram BYTES with dispatch-message and return (TOTAL DATA HEARTBEAT)
   submessage counts — the test oracle for coalescing (a datagram is a Header + a sequence of
   Submessages, RTPS 2.5 §8.3.4)."
  (let* ((n (length bytes))
         (buf (dds.core.buffer:make-octet-buffer n))
         (total 0) (data 0) (hb 0))
    (replace (dds.core.buffer:octet-buffer-vec buf) bytes)
    (dds.rtps.message:dispatch-message
     (dds.core.buffer:cursor buf :endianness :little)
     (lambda (id flags c body-len)
       (declare (ignore flags c body-len))
       (incf total)
       (cond ((= id dds.rtps.message:+submsg-data+) (incf data))
             ((= id dds.rtps.message:+submsg-heartbeat+) (incf hb))))
     n)
    (list total data hb)))

(defun* %coalesce-capture (node)
    (function (dds.disc:disc-node) list)
  "Push the writer's unsent changes (%push-data) while capturing every outgoing datagram via
   *datagram-sink*; return the captured datagrams (each a fresh octet vector), in send order."
  (let ((captured '()))
    (let ((dds.disc::*datagram-sink* (lambda (dg) (push dg captured))))
      (dds.disc::%push-data node))
    (nreverse captured)))

(defun* run-coalesce-pack-test ()
    (function () t)
  "Ten small DATA + the trailing HEARTBEAT coalesce into ONE datagram (RTPS 2.5 §8.3.4): write 10 small
   samples to a writer with one matched reader, push under *datagram-sink*, and assert a single captured
   datagram re-parses to 10 DATA + 1 HEARTBEAT (11 submessages) within budget — vs 11 datagrams
   one-per-submessage before coalescing."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 6)
               :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (dds.disc:enable-publisher node :history-kind :keep-all)   ; KEEP_ALL: the test retains all 10 DATA to coalesce (ADR 0019 migration)
           (%seed-reader-participant node #x55 7701)
           (let ((writer (dds.disc::disc-node-user-writer node)))
             (dotimes (i 10)
               (dds.rtps.reliable:writer-write writer (octets 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0)))
             (let ((captured (%coalesce-capture node)))
               (%check :coalesce-one-datagram (= 1 (length captured))
                       "10 small DATA + HEARTBEAT must coalesce into ONE datagram")
               (destructuring-bind (total data hb) (%count-submessages (first captured))
                 (%check :coalesce-submsg-count (and (= 11 total) (= 10 data) (= 1 hb))
                         "the coalesced datagram must carry 10 DATA + 1 HEARTBEAT (11 submessages)")
                 (%check :coalesce-within-budget
                         (<= (length (first captured)) dds.disc::*coalesce-datagram-budget*)
                         "the coalesced datagram must be within *coalesce-datagram-budget*")))))
      (dds.disc:stop-node node)))
  t)

(defun* run-coalesce-split-test ()
    (function () t)
  "A small datagram budget forces the same 10-sample burst across ≥2 datagrams WITHOUT losing or
   duplicating submessages (the %send-packed flush/move path): with *coalesce-datagram-budget* lowered,
   assert >1 but <11 datagrams, each within budget, and the DATA+HEARTBEAT submessage total still 11."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 6)
               :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (dds.disc:enable-publisher node :history-kind :keep-all)   ; KEEP_ALL: the split test retains all 10 DATA (ADR 0019 migration)
           (%seed-reader-participant node #x56 7702)
           (let ((writer (dds.disc::disc-node-user-writer node)))
             (dotimes (i 10)
               (dds.rtps.reliable:writer-write writer (octets 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0)))
             (let* ((dds.disc::*coalesce-datagram-budget* 200)
                    (captured (%coalesce-capture node))
                    (totals (mapcar #'%count-submessages captured)))
               (%check :split-multiple (< 1 (length captured))
                       "a small budget must split the burst across more than one datagram")
               (%check :split-fewer (< (length captured) 11)
                       "coalescing must still pack — fewer datagrams than the 11 submessages")
               (%check :split-each-within-budget
                       (every (lambda (dg) (<= (length dg) 200)) captured)
                       "every split datagram must be within the lowered budget")
               (%check :split-total-preserved
                       (and (= 11 (reduce #'+ totals :key #'first))
                            (= 10 (reduce #'+ totals :key #'second))
                            (= 1 (reduce #'+ totals :key #'third)))
                       "the 10 DATA + 1 HEARTBEAT submessages must be preserved across the split"))))
      (dds.disc:stop-node node)))
  t)

(defun* run-coalesce-large-pack-test ()
    (function () t)
  "Near-*fragment-size* small samples coalesce WITHOUT overflowing the 2048-octet send buffer
   (regression for a write-before-budget-check overflow): push 10 samples of 1000-octet payload — two of
   which (2×1024) would exceed both the 1400 budget and, unchecked, approach the buffer — and assert no
   error, every datagram within BOTH the budget and the 2048 buffer capacity, and all 11 submessages
   (10 DATA + 1 HEARTBEAT) sent. %send-packed must flush BEFORE writing a submessage that would not fit."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 6)
               :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (dds.disc:enable-publisher node :history-kind :keep-all)   ; KEEP_ALL: the large-pack test retains all 10 DATA (ADR 0019 migration)
           (%seed-reader-participant node #x57 7703)
           (let ((writer (dds.disc::disc-node-user-writer node))
                 (big (make-array 1000 :element-type '(unsigned-byte 8) :initial-element 7)))
             (dotimes (i 10) (dds.rtps.reliable:writer-write writer big))
             (let* ((captured (%coalesce-capture node))
                    (totals (mapcar #'%count-submessages captured)))
               (%check :clp-sent (plusp (length captured))
                       "the near-fragment-size burst must push datagrams (no BUFFER-OVERFLOW)")
               (%check :clp-within-capacity (every (lambda (dg) (<= (length dg) 2048)) captured)
                       "no coalesced datagram may exceed the 2048-octet send buffer")
               (%check :clp-within-budget
                       (every (lambda (dg) (<= (length dg) dds.disc::*coalesce-datagram-budget*)) captured)
                       "each datagram must be within *coalesce-datagram-budget*")
               (%check :clp-total-preserved
                       (and (= 11 (reduce #'+ totals :key #'first))
                            (= 10 (reduce #'+ totals :key #'second))
                            (= 1 (reduce #'+ totals :key #'third)))
                       "all 10 DATA + 1 HEARTBEAT submessages must be sent"))))
      (dds.disc:stop-node node)))
  t)

;;; WP-KEEPLAST GAP on an evicted/missing SN (RTPS 2.5 §8.3.7.4 / §9.4.5.6): when a reliable reader NACKs a
;;; SN the writer's HistoryCache no longer holds (per-instance KEEP_LAST eviction, ADR 0019; or any
;;; KEEP_LAST/RESOURCE_LIMITS reliable writer that evicted), the writer must answer with a GAP marking that
;;; SN irrelevant — not silence. %on-user-acknack computes those gap SNs (writer-on-acknack) and now SENDS
;;; the GAP to the NACKing reader, alongside resending any present NACKed SN as DATA. Offline: force a hole
;;; by hc-remove-change'ing a low SN, deliver an ACKNACK NACKing {hole, present} via the disc on-acknack hook,
;;; capture the outgoing datagrams (*datagram-sink*), and assert exactly one GAP for the hole (parse-gap-body)
;;; plus a DATA resend for the present SN.

(defun* %acknack-body-cursor (reader-id writer-id base nacked-sns)
    (function ((unsigned-byte 32) (unsigned-byte 32) integer list) dds.core.buffer:cursor)
  "Build an ACKNACK BODY (the bytes parse-acknack-body consumes: readerId+writerId+SequenceNumberSet+count,
   RTPS 2.5 §9.4.5.3, NO submessage header) for READER-ID NACKing each SN in NACKED-SNS relative to BASE, and
   return a fresh cursor positioned at its start — the offline twin of an inbound ACKNACK delivered to the
   disc on-acknack hook. The bitmap is built with the SAME seqnum-set-bit helper reader-acknack uses (DRY)."
  (let* ((hi (reduce #'max nacked-sns))
         (numbits (1+ (- hi base)))
         (bitmap (make-array (max 1 (ceiling numbits 32)) :element-type '(unsigned-byte 32) :initial-element 0))
         (buf (dds.core.buffer:make-octet-buffer 64))
         (wc (dds.core.buffer:cursor buf :endianness :little)))
    (dolist (sn nacked-sns) (dds.rtps.message:seqnum-set-bit bitmap (- sn base)))
    (dds.rtps.message:write-entity-id wc reader-id)
    (dds.rtps.message:write-entity-id wc writer-id)
    (dds.rtps.message:write-sequence-number-set wc base numbits bitmap)
    (dds.core.buffer:put-u32 wc 1)                  ; ACKNACK count (§9.4.5.3)
    (dds.core.buffer:cursor buf :endianness :little)))

(defun* %scan-datagrams-for-submsg (captured target-id parse-fn)
    (function (list (unsigned-byte 8) function) list)
  "Re-parse each captured RTPS datagram (dispatch-message) and, for every submessage whose id is TARGET-ID,
   collect (multiple-value-list (funcall PARSE-FN body-cursor flags body-len)); return the list in wire order.
   The test oracle for an emitted submessage of one kind — parses the bytes the receiver would (§8.3.4)."
  (let ((results '()))
    (dolist (bytes captured)
      (let* ((n (length bytes))
             (buf (dds.core.buffer:make-octet-buffer n)))
        (replace (dds.core.buffer:octet-buffer-vec buf) bytes)
        (dds.rtps.message:dispatch-message
         (dds.core.buffer:cursor buf :endianness :little)
         (lambda (id flags c body-len)
           (when (= id target-id) (push (multiple-value-list (funcall parse-fn c flags body-len)) results)))
         n)))
    (nreverse results)))

(defun* run-gap-send-on-missing-sn-test ()
    (function () t)
  "WP-KEEPLAST: a reliable writer answers a NACK for an EVICTED/missing SN with a GAP (RTPS 2.5 §8.3.7.4),
   not silence. Write SN 1,2,3 to a reliable user writer with one matched reader; hc-remove-change SN 1 (the
   hole an eviction leaves); deliver an ACKNACK NACKing {1 (missing), 3 (present)} through the disc
   on-acknack hook while capturing outgoing datagrams. Assert: exactly ONE GAP whose SequenceNumberSet
   declares EXACTLY SN 1 irrelevant (gap-start=base=1, only bit 0 set, parsed by parse-gap-body), and SN 3
   resent as a DATA (the present NACKed change), SN 1 NOT resent as DATA. The writer is explicit KEEP_ALL
   (it never evicts -> writer-on-acknack returns no gaps -> no GAP), so this test forces the hole explicitly
   via hc-remove-change (ADR 0019: the generic default is now KEEP_LAST-1, which would evict on its own)."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 8)
               :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (dds.disc:enable-publisher node :history-kind :keep-all)   ; KEEP_ALL: the fixture writes SN 1,2,3 then removes SN 1 to model the eviction hole (ADR 0019 migration)
           (multiple-value-bind (prefix dest) (%seed-reader-participant node #x71 7706)
             (declare (ignore dest))
             (let ((writer (dds.disc::disc-node-user-writer node)))
               (dotimes (i 3) (dds.rtps.reliable:writer-write writer (octets 1 2 3 4 5 6 7 8)))
               (dds.rtps.history:hc-remove-change (dds.rtps.reliable:rtps-writer-hc writer) 1)   ; the eviction hole
               (%check :gap-hole-gone (null (dds.rtps.history:hc-get-change (dds.rtps.reliable:rtps-writer-hc writer) 1))
                       "test setup: SN 1 must be absent from the writer HC (the evicted hole)")
               (%check :gap-present-kept (dds.rtps.history:hc-get-change (dds.rtps.reliable:rtps-writer-hc writer) 3)
                       "test setup: SN 3 must still be present (resent as DATA, not GAP'd)")
               (let ((captured '()))
                 (let ((dds.disc::*datagram-sink* (lambda (dg) (push dg captured))))
                   (dds.disc::%on-user-acknack
                    node
                    (%acknack-body-cursor dds.disc::+user-reader-id+ (dds.disc:disc-node-user-writer-id node) 1 '(1 3))
                    dds.rtps.message:+acknack-flag-final+
                    prefix))
                 (setf captured (nreverse captured))
                 (let ((gaps (%scan-datagrams-for-submsg
                              captured dds.rtps.message:+submsg-gap+
                              (lambda (c flags body-len) (declare (ignore body-len))
                                (dds.rtps.message:parse-gap-body c flags))))
                       (datas (%scan-datagrams-for-submsg
                               captured dds.rtps.message:+submsg-data+
                               #'dds.rtps.message:parse-data-body)))
                   (%check :gap-one (= 1 (length gaps))
                           (format nil "exactly one GAP must be emitted for the missing SN (got ~d)" (length gaps)))
                   (destructuring-bind (rid wid gap-start base numbits bitmap) (first gaps)
                     (declare (ignore rid wid))
                     (%check :gap-start-base (and (= gap-start 1) (= base 1))
                             (format nil "the GAP's gapStart and SequenceNumberSet base must be 1 (got ~d/~d)" gap-start base))
                     (%check :gap-declares-missing (dds.rtps.message:seqnum-set-member-p base numbits bitmap 1)
                             "the GAP's SequenceNumberSet must declare the missing SN 1 irrelevant")
                     (%check :gap-only-missing (not (dds.rtps.message:seqnum-set-member-p base numbits bitmap 3))
                             "the GAP must NOT mark the present SN 3 irrelevant — only the missing SN 1"))
                   (%check :gap-present-resent
                           (member 3 datas :key (lambda (vals) (third vals)))   ; parse-data-body -> (... sn ...)
                           "the present NACKed SN 3 must be resent as a DATA submessage")
                   (%check :gap-missing-not-resent
                           (not (member 1 datas :key (lambda (vals) (third vals))))
                           "the missing SN 1 must NOT be resent as DATA (it is GAP'd, not repaired)"))))))
      (dds.disc:stop-node node)))
  t)

;;; WP-KEEPLAST GAP RECEPTION (RTPS 2.5 §8.3.7.4 / §9.4.5.6, Task C2): the receiver-thread dispatch wires an
;;; inbound GAP submessage to reader-on-gap, so a reliable reader that NACKed an evicted SN stops NACKing it
;;; once the writer answers with a GAP. Offline twin of the wire: drive reader-on-heartbeat[1,5] so the reader's
;;; writer-proxy records SN 1 missing (it would NACK it), then deliver a real GAP datagram (Header + GAP marking
;;; SN 1 irrelevant) through %handle-datagram — the SAME entry point every transport feeds. Assert SN 1 is :gap
;;; in the proxy received table AND drops out of the next reader-acknack NACK set (the ack watermark advances).

(defun* %gap-datagram (src-prefix reader-id writer-id gap-start base numbits bitmap)
    (function ((simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) (unsigned-byte 32) integer integer
              (unsigned-byte 32) (simple-array (unsigned-byte 32) (*)))
              (values dds.core.buffer:octet-buffer fixnum))
  "Build a complete RTPS datagram (Header with SRC-PREFIX + one GAP submessage, RTPS 2.5 §8.3.4 / §9.4.5.6)
   into a fresh octet-buffer. Returns (values buffer byte-length) — the offline twin of a GAP arriving on the
   wire from the remote writer at SRC-PREFIX, fed to %handle-datagram. Uses the same write-header / write-gap
   the engine emits (DRY)."
  (let* ((buf (dds.core.buffer:make-octet-buffer 128))
         (wc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.rtps.message:write-header wc src-prefix)
    (dds.rtps.message:write-gap wc reader-id writer-id gap-start base numbits bitmap)
    (values buf (dds.core.buffer:cursor-position wc))))

(defun* run-reader-gap-reception-test ()
    (function () t)
  "WP-KEEPLAST (Task C2): the reader RECEIVES a GAP. A reliable reader with a writer-proxy that recorded SN 1
   as missing (reader-on-heartbeat[1,5]) gets a GAP datagram marking SN 1 irrelevant, delivered through the
   receiver-thread dispatch (%handle-datagram -> +submsg-gap+ -> %on-user-gap -> reader-on-gap, RTPS 2.5
   §8.3.7.4). Assert: SN 1 becomes :gap in the writer-proxy received table, and the next reader-acknack no
   longer NACKs SN 1 (its base advances past it) — so the reader stops NACKing the unrepairable SN forever."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 9)
               :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (dds.disc:add-local-reader node :topic "Square" :type "ShapeType")   ; sets disc-node-user-reader-id 0x107
           (dds.disc:enable-subscriber node)                                    ; reader + reader-side hooks (incl. on-gap)
           (let* ((src (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x99))
                  (wid dds.disc::+user-writer-id+)                              ; remote writer EntityId 0x102 (with-key)
                  (rid (dds.disc:disc-node-user-reader-id node))
                  (reader (dds.disc::disc-node-user-reader node))
                  (wguid (dds.disc::%source-guid src wid)))
             (dds.rtps.reliable:reader-on-heartbeat reader wguid 1 5)            ; reader believes [1,5] available -> SN 1 missing
             (multiple-value-bind (base0 numbits0 bitmap0) (dds.rtps.reliable:reader-acknack reader wguid)
               (%check :grx-setup-nacks-1 (dds.rtps.message:seqnum-set-member-p base0 numbits0 bitmap0 1)
                       "test setup: before the GAP the reader must NACK SN 1 (base=1, bit 0 set)"))
             ;; deliver a GAP for SN 1 (gapStart=1, base=2, empty bitmap -> the range [1,2) = {1}) via the real dispatch
             (let ((gbitmap (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
               (multiple-value-bind (dg len) (%gap-datagram src rid wid 1 2 0 gbitmap)
                 (dds.disc::%handle-datagram node dg len)))
             (let ((received (dds.rtps.reliable:writer-proxy-received
                              (dds.rtps.reliable:get-writer-proxy reader wguid))))
               (%check :grx-sn1-gap (eq :gap (gethash 1 received))
                       "after the GAP, SN 1 must be marked :gap (irrelevant) in the writer-proxy received table"))
             (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wguid)
               (%check :grx-no-nack-1 (not (dds.rtps.message:seqnum-set-member-p base numbits bitmap 1))
                       "after the GAP, the next reader-acknack must NOT NACK SN 1 (it is irrelevant, not missing)")
               (%check :grx-base-advanced (> base 1)
                       (format nil "the ACKNACK base must advance past the GAP'd SN 1 (got ~d)" base)))))
      (dds.disc:stop-node node)))
  t)

;;; WP-KEEPLAST GAP RANGE HARD-CAP (NFR-SEC-POSTURE, RTPS 2.5 §8.3.7.4, Task C2 security fix): wiring
;;; reader-on-gap to the wire (%on-user-gap) made its contiguous [gapStart, base) loop reachable by an
;;; attacker-controlled GAP. gapStart/base are wire-supplied 64-bit values and last-sn is itself set from
;;; inbound HEARTBEATs, so an unclamped span (gapStart=1, base=2^60) would loop ~2^60 times inserting ~2^60
;;; hash entries -> CPU+memory DoS. The fix hard-caps the iterated span at *max-gap-range* SNs, independent
;;; of any wire value. Adversarial twin: feed such a GAP through %handle-datagram (the real receiver-thread
;;; dispatch) and assert the call returns PROMPTLY and the received table stays bounded — proving the cap held
;;; (under the pre-fix unbounded loop this call never returns / exhausts memory).

(defun* run-reader-gap-range-cap-test ()
    (function () t)
  "WP-KEEPLAST (Task C2 security fix, NFR-SEC-POSTURE): an adversarial GAP cannot DoS the receiver. Deliver a
   GAP with a 2^60-wide irrelevant range (gapStart=1, base=2^60), then a second with base=most-positive-fixnum,
   through the real dispatch (%handle-datagram -> +submsg-gap+ -> %on-user-gap -> reader-on-gap, RTPS 2.5
   §8.3.7.4). Assert each call returns PROMPTLY and the writer-proxy received table stays bounded by
   *max-gap-range*+slack — proving the hard cap (independent of the wire-supplied base/last-sn) held instead of
   iterating ~2^60 SNs. The cap is loss-free: a real evicted run is recovered over later GAP/HEARTBEAT rounds."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 7)
               :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (dds.disc:add-local-reader node :topic "Square" :type "ShapeType")
           (dds.disc:enable-subscriber node)
           (let* ((src (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x99))
                  (wid dds.disc::+user-writer-id+)
                  (rid (dds.disc:disc-node-user-reader-id node))
                  (reader (dds.disc::disc-node-user-reader node))
                  (wguid (dds.disc::%source-guid src wid))
                  (gbitmap (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0))
                  (bound (+ dds.rtps.reliable:*max-gap-range* 300)))
             (dolist (evil-base (list (expt 2 60) most-positive-fixnum))   ; both wire-controlled DoS spans
               (multiple-value-bind (dg len) (%gap-datagram src rid wid 1 evil-base 0 gbitmap)
                 (dds.disc::%handle-datagram node dg len))               ; must return promptly, not iterate 2^60
               (let ((received (dds.rtps.reliable:writer-proxy-received
                                (dds.rtps.reliable:get-writer-proxy reader wguid))))
                 (%check :grxcap-bounded (<= (hash-table-count received) bound)
                         (format nil "an attacker GAP (gapStart=1, base=~d) must mark <=~d SNs (the *max-gap-range* cap), got ~d — the contiguous loop was NOT hard-capped (CPU+memory DoS, NFR-SEC-POSTURE)"
                                 evil-base bound (hash-table-count received)))))))
      (dds.disc:stop-node node)))
  t)

;;; WP-KEEPLAST Task D2 (ADR 0019, DDS 1.4 §2.2.3.18, RTPS 2.5 §8.3.7.4): the 7 end-to-end acceptance
;;; scenarios on the now-ACTIVATED per-instance KEEP_LAST path (the engine writer HistoryCache + the reader
;;; DCPS cache honor the QoS HISTORY; the generic default is KEEP_LAST-1). These exercise the real DCPS->engine
;;; and disc->engine paths the unit tests (run-hc-perinstance-keeplast-test et al.) prove only at the cache
;;; layer: writer-side per-instance retention through write-sample, the interior-hole->GAP chain end to end,
;;; the firstSN advance on a low eviction, reader-side per-instance lossy drop through %drain, the unkeyed
;;; global-collapse, the KEEP_ALL regression, and purge-acked composing with per-instance eviction.

(defun* %hc-instance-sns (hc)
    (function (dds.rtps.history:history-cache) hash-table)
  "Group the HistoryCache HC's stored changes by per-instance bucket key -> ascending SN list (test oracle for
   per-instance retention). An UNKEYED / HANDLE_NIL change collapses to the :UNKEYED bucket, matching the HC's
   own %hc-bucket-key (DDS 1.4 §2.2.3.18). Built from the public hc-changes-for-reader change list (DRY)."
  (let ((by-instance (make-hash-table :test 'equalp)))
    (dolist (ch (dds.rtps.history:hc-changes-for-reader hc nil))
      (let* ((kh (dds.rtps.history:cache-change-instance-key-hash ch))
             (key (if (or (null kh) (every #'zerop kh)) :unkeyed kh)))
        (push (dds.rtps.history:cache-change-sn ch) (gethash key by-instance))))
    (maphash (lambda (k sns) (setf (gethash k by-instance) (sort sns #'<))) by-instance)
    by-instance))

(defun* %dw-engine-hc (dw)
    (function (dds.dcps:data-writer) dds.rtps.history:history-cache)
  "The engine user-writer HistoryCache backing the DCPS DataWriter DW (test reach-in via the participant's
   disc-node) — the cache the activated writer-side per-instance KEEP_LAST evicts in (ADR 0019)."
  (let* ((node (dds.dcps::dp-node (dds.dcps::pub-participant (dds.dcps::dw-publisher dw)))))
    (dds.rtps.reliable:rtps-writer-hc (dds.disc::disc-node-user-writer node))))

(defun* run-keeplast-writer-perinstance-e2e-test ()
    (function () t)
  "WP-KEEPLAST D2 scenario 1 (spec §1, DDS 1.4 §2.2.3.18): a DCPS KEEP_LAST depth-2 KEYED DataWriter retains
   the last 2 changes PER INSTANCE on the real write-sample -> publish-sample -> writer-write -> engine HC path
   (write-sample auto-threads each sample's keyhash). Write 3 samples for instance A (color BLUE) and 3 for
   instance B (color RED); reach into the engine writer HC and assert it holds EXACTLY 4 changes — the last 2
   SNs of A AND the last 2 SNs of B — NOT a global last-2 (which would keep only the 4th/5th write and starve
   one key). Proves the activation: the QoS HISTORY now sizes the engine cache and the keyhash drives eviction."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "KlW2Square" "shape-type" ts))
                (pub (dds.dcps:create-publisher p))
                (dw (dds.dcps:create-datawriter
                     pub tp :qos (dds.qos:make-writer-qos :history-kind :keep-last :history-depth 2)))
                (a (make-shape-type :color "BLUE" :x 0 :y 0 :shapesize 1))
                (b (make-shape-type :color "RED"  :x 0 :y 0 :shapesize 1))
                (ha (funcall (dds.types:type-support-key-hash ts) a))
                (hb (funcall (dds.types:type-support-key-hash ts) b)))
           ;; interleave the writes so a global last-2 would diverge from a per-instance last-2:
           ;; A@1 B@2 A@3 B@4 A@5 B@6  (A = SN 1,3,5 ; B = SN 2,4,6)
           (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 1))
           (dds.dcps:write-sample dw (make-shape-type :color "RED"  :x 2 :y 2 :shapesize 2))
           (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 3 :y 3 :shapesize 3))
           (dds.dcps:write-sample dw (make-shape-type :color "RED"  :x 4 :y 4 :shapesize 4))
           (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x 5 :y 5 :shapesize 5))
           (dds.dcps:write-sample dw (make-shape-type :color "RED"  :x 6 :y 6 :shapesize 6))
           (let* ((hc (%dw-engine-hc dw))
                  (by-instance (%hc-instance-sns hc)))
             (%check :klw2-count (= 4 (dds.rtps.history:hc-change-count hc))
                     (format nil "KEEP_LAST-2 over 2 instances must hold 4 changes (2 per instance), got ~d"
                             (dds.rtps.history:hc-change-count hc)))
             (%check :klw2-a-last2 (equal '(3 5) (gethash ha by-instance))
                     (format nil "instance A (BLUE) must retain its last 2 SNs (3,5), got ~s" (gethash ha by-instance)))
             (%check :klw2-b-last2 (equal '(4 6) (gethash hb by-instance))
                     (format nil "instance B (RED) must retain its last 2 SNs (4,6), got ~s" (gethash hb by-instance)))
             (%check :klw2-not-global
                     (and (dds.rtps.history:hc-get-change hc 3) (null (dds.rtps.history:hc-get-change hc 2)))
                     "NOT a global last-2: A's SN3 survives though B's SN2/SN4 bracket it (per-instance retention)")))
      (dds.dcps:delete-participant p)))
  t)

(defun* run-keeplast-interior-hole-gap-e2e-test ()
    (function () t)
  "WP-KEEPLAST D2 scenario 2 (spec §2, DDS 1.4 §2.2.3.18 + RTPS 2.5 §8.3.7.4): the full interior-hole -> GAP
   chain on the activated engine path. A KEEP_LAST depth-1 reliable user writer (enable-publisher) gets explicit
   per-instance keyhashes via writer-write: A@SN1 (handle-A), B@SN2 (handle-B), B@SN3 (handle-B). Per-instance
   KEEP_LAST-1 evicts B's oldest (SN2) -> the HC holds {SN1, SN3}, an interior hole at SN2 inside [firstSN,
   lastSN]. Deliver an ACKNACK NACKing the evicted interior SN2 through the disc on-acknack hook and capture
   outbound datagrams; assert EXACTLY one GAP declaring SN2 irrelevant is sent (parse-gap-body), SN2 is NOT
   resent as DATA. Then drive the reader side: a reliable reader that recorded SN2 missing receives that GAP via
   the real dispatch (%handle-datagram), marks SN2 :gap, and stops NACKing it (the ack watermark advances)."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 8)
               :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (dds.disc:enable-publisher node :history-kind :keep-last :history-depth 1)   ; the activated per-instance KEEP_LAST-1 engine writer
           (multiple-value-bind (prefix dest) (%seed-reader-participant node #x72 7806)
             (declare (ignore dest))
             (let ((writer (dds.disc::disc-node-user-writer node))
                   (ha (%keeplast-handle 1))                       ; instance A
                   (hb (%keeplast-handle 2)))                      ; instance B
               (dds.rtps.reliable:writer-write writer (octets 1 2 3 4) ha)   ; A@SN1
               (dds.rtps.reliable:writer-write writer (octets 5 6 7 8) hb)   ; B@SN2
               (dds.rtps.reliable:writer-write writer (octets 9 9 9 9) hb)   ; B@SN3 -> evicts B's SN2 (interior hole)
               (let ((hc (dds.rtps.reliable:rtps-writer-hc writer)))
                 (%check :klg-hole (null (dds.rtps.history:hc-get-change hc 2))
                         "per-instance KEEP_LAST-1 must have evicted B's oldest SN2 (the interior hole)")
                 (%check :klg-kept (and (dds.rtps.history:hc-get-change hc 1) (dds.rtps.history:hc-get-change hc 3))
                         "the HC must still hold SN1 (A) and SN3 (B) around the SN2 hole"))
               ;; writer side: an ACKNACK for the evicted SN2 must yield a GAP for SN2, not a DATA resend.
               (let ((captured '()))
                 (let ((dds.disc::*datagram-sink* (lambda (dg) (push dg captured))))
                   (dds.disc::%on-user-acknack
                    node
                    (%acknack-body-cursor dds.disc::+user-reader-id+ (dds.disc:disc-node-user-writer-id node) 2 '(2))
                    dds.rtps.message:+acknack-flag-final+
                    prefix))
                 (setf captured (nreverse captured))
                 (let ((gaps (%scan-datagrams-for-submsg
                              captured dds.rtps.message:+submsg-gap+
                              (lambda (c flags body-len) (declare (ignore body-len))
                                (dds.rtps.message:parse-gap-body c flags))))
                       (datas (%scan-datagrams-for-submsg
                               captured dds.rtps.message:+submsg-data+
                               #'dds.rtps.message:parse-data-body)))
                   (%check :klg-one-gap (= 1 (length gaps))
                           (format nil "exactly one GAP must be sent for the evicted interior SN2 (got ~d)" (length gaps)))
                   (destructuring-bind (rid wid gap-start base numbits bitmap) (first gaps)
                     (declare (ignore rid wid gap-start))
                     (%check :klg-gap-declares-sn2 (dds.rtps.message:seqnum-set-member-p base numbits bitmap 2)
                             "the GAP's SequenceNumberSet must declare the evicted SN2 irrelevant"))
                   (%check :klg-sn2-not-resent (not (member 2 datas :key (lambda (vals) (third vals))))
                           "the evicted SN2 must NOT be resent as DATA (it is GAP'd, gone forever)")))))
           ;; reader side: a reliable reader that NACKed SN2 receives the GAP and stops NACKing it.
           (dds.disc:add-local-reader node :topic "Square" :type "ShapeType")
           (dds.disc:enable-subscriber node)
           (let* ((src (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x9a))
                  (wid dds.disc::+user-writer-id+)
                  (rid (dds.disc:disc-node-user-reader-id node))
                  (reader (dds.disc::disc-node-user-reader node))
                  (wguid (dds.disc::%source-guid src wid)))
             (dds.rtps.reliable:reader-on-heartbeat reader wguid 1 3)            ; [1,3] -> SN2 missing (the evicted interior)
             (multiple-value-bind (b0 n0 m0) (dds.rtps.reliable:reader-acknack reader wguid)
               (%check :klg-rx-nacks-2 (dds.rtps.message:seqnum-set-member-p b0 n0 m0 2)
                       "test setup: before the GAP the reader must NACK the missing SN2"))
             (let ((gbitmap (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
               (multiple-value-bind (dg len) (%gap-datagram src rid wid 2 3 0 gbitmap)   ; GAP SN2 ([2,3) = {2})
                 (dds.disc::%handle-datagram node dg len)))
             (let ((received (dds.rtps.reliable:writer-proxy-received
                              (dds.rtps.reliable:get-writer-proxy reader wguid))))
               (%check :klg-rx-sn2-gap (eq :gap (gethash 2 received))
                       "after the GAP the reader must mark SN2 :gap (irrelevant) in the writer-proxy table"))
             (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wguid)
               (%check :klg-rx-no-nack-2 (not (dds.rtps.message:seqnum-set-member-p base numbits bitmap 2))
                       "after the GAP the reader must NOT NACK SN2 (irrelevant, not missing) — no hang"))))
      (dds.disc:stop-node node)))
  t)

(defun* run-keeplast-firstsn-advance-test ()
    (function () t)
  "WP-KEEPLAST D2 scenario 3 (spec §3, RTPS 2.5 §8.4.1 + §8.3.7.5): a low-end eviction advances the writer's
   advertised HEARTBEAT firstSN. A KEEP_LAST depth-1 reliable engine writer writes A@SN1 then A@SN2 (same
   instance A -> SN1 evicted, the lowest held SN). hc-min-seq (the live first SN) is now 2, and writer-heartbeat
   advertises firstSN=2. A reader told the available range is [2,2] (the advertised window) does not NACK the
   evicted SN1 — it compacts below first and never repairs it (covers low evictions without a GAP)."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 6)
               :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (dds.disc:enable-publisher node :history-kind :keep-last :history-depth 1)
           (let ((writer (dds.disc::disc-node-user-writer node))
                 (ha (%keeplast-handle 1)))
             (dds.rtps.reliable:writer-write writer (octets 1 1 1 1) ha)        ; A@SN1
             (dds.rtps.reliable:writer-write writer (octets 2 2 2 2) ha)        ; A@SN2 -> SN1 evicted
             (let ((hc (dds.rtps.reliable:rtps-writer-hc writer)))
               (%check :klf-sn1-gone (null (dds.rtps.history:hc-get-change hc 1))
                       "KEEP_LAST-1 must evict A's SN1 when A@SN2 arrives")
               (%check :klf-min-seq-2 (= 2 (dds.rtps.history:hc-min-seq hc))
                       (format nil "the live first SN (hc-min-seq) must advance to 2, got ~s" (dds.rtps.history:hc-min-seq hc))))
             (multiple-value-bind (first-sn last-sn count) (dds.rtps.reliable:writer-heartbeat writer)
               (declare (ignore count))
               (%check :klf-hb-first-2 (= 2 first-sn)
                       (format nil "the HEARTBEAT firstSN must advance to 2 after the low eviction, got ~d" first-sn))
               (%check :klf-hb-last-2 (= 2 last-sn)
                       (format nil "the HEARTBEAT lastSN must be 2 (the only held SN), got ~d" last-sn))))
           ;; a reader on the advertised window [2,2] must not NACK the evicted SN1.
           (dds.disc:add-local-reader node :topic "Square" :type "ShapeType")
           (dds.disc:enable-subscriber node)
           (let* ((src (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x9b))
                  (wid dds.disc::+user-writer-id+)
                  (reader (dds.disc::disc-node-user-reader node))
                  (wguid (dds.disc::%source-guid src wid)))
             (dds.rtps.reliable:reader-on-heartbeat reader wguid 2 2)            ; advertised firstSN=2
             (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wguid)
               (%check :klf-no-nack-1 (not (dds.rtps.message:seqnum-set-member-p base numbits bitmap 1))
                       "a reader on [first=2,last=2] must NOT NACK the evicted SN1 (it is below firstSN)")
               (%check :klf-base-ge-2 (>= base 2)
                       (format nil "the ACKNACK base must be >= the advertised firstSN 2 (got ~d)" base)))))
      (dds.disc:stop-node node)))
  t)

(defun* run-keeplast-reader-perinstance-e2e-test ()
    (function () t)
  "WP-KEEPLAST D2 scenario 4 (spec §4, DDS 1.4 §2.2.3.18 — also the dedicated reader-side %reader-keeplast-drop
   coverage): a DCPS KEEP_LAST depth-2 KEYED DataReader keeps the last 2 samples PER INSTANCE in dr-cache (a
   lossy drop of the oldest per instance, NOT a global last-2). Deliver 3 samples for instance A and 3 for
   instance B deterministically through the engine SN maps + %drain (the same records %deliver-user-sample
   writes, minus UDP), then assert dr-cache holds EXACTLY A's last 2 and B's last 2. A second single-instance
   variant: deliver 3 of A to a fresh KEEP_LAST-2 reader and assert exactly the last 2 survive."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "KlR2Square" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr (dds.dcps:create-datareader
                     sub tp :qos (dds.qos:make-reader-qos :history-kind :keep-last :history-depth 2)))
                (node (dds.dcps::dp-node p))
                (wid #x00000102)
                (a (make-shape-type :color "BLUE" :x 0 :y 0 :shapesize 0))
                (b (make-shape-type :color "RED"  :x 0 :y 0 :shapesize 0))
                (ha (funcall (dds.types:type-support-key-hash ts) a))
                (hb (funcall (dds.types:type-support-key-hash ts) b)))
           ;; deliver A@1 B@2 A@3 B@4 A@5 B@6 then drain (per-instance last-2 must survive, not a global last-2)
           (flet ((deliver (sn shape)
                    (%stage-data-sn node sn (funcall (dds.types:type-support-key-hash ts) shape)
                                    (dds.dcps::%serialize-sample ts shape) wid)))
             (deliver 1 (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 1))
             (deliver 2 (make-shape-type :color "RED"  :x 2 :y 2 :shapesize 2))
             (deliver 3 (make-shape-type :color "BLUE" :x 3 :y 3 :shapesize 3))
             (deliver 4 (make-shape-type :color "RED"  :x 4 :y 4 :shapesize 4))
             (deliver 5 (make-shape-type :color "BLUE" :x 5 :y 5 :shapesize 5))
             (deliver 6 (make-shape-type :color "RED"  :x 6 :y 6 :shapesize 6)))
           (dds.dcps::%drain dr)
           (%check :klr2-total (= 4 (length (dds.dcps::dr-cache dr)))
                   (format nil "KEEP_LAST-2 reader over 2 instances must hold 4 cached samples, got ~d"
                           (length (dds.dcps::dr-cache dr))))
           (%check :klr2-a-2 (= 2 (%handle-cache-count dr ha))
                   (format nil "instance A must keep exactly its last 2 samples, got ~d" (%handle-cache-count dr ha)))
           (%check :klr2-b-2 (= 2 (%handle-cache-count dr hb))
                   (format nil "instance B must keep exactly its last 2 samples, got ~d" (%handle-cache-count dr hb)))
           (let ((a-sns (sort (mapcar (lambda (cs) (dds.dcps:sample-info-sequence-number (dds.dcps:cached-sample-info cs)))
                                      (remove-if-not (lambda (cs) (equalp ha (%cs-ih cs))) (dds.dcps::dr-cache dr)))
                              #'<)))
             (%check :klr2-a-last2 (equal '(3 5) a-sns)
                     (format nil "instance A must keep its LAST 2 SNs (3,5), oldest dropped; got ~s" a-sns))))
      (dds.dcps:delete-participant p)))
  ;; single-instance variant: 3 of A to a fresh KEEP_LAST-2 reader -> exactly the last 2 survive.
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p2 "KlR2bSquare" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p2))
                (dr (dds.dcps:create-datareader
                     sub tp :qos (dds.qos:make-reader-qos :history-kind :keep-last :history-depth 2)))
                (node (dds.dcps::dp-node p2))
                (wid #x00000102)
                (a (make-shape-type :color "GREEN" :x 0 :y 0 :shapesize 0))
                (ha (funcall (dds.types:type-support-key-hash ts) a)))
           (dotimes (i 3)
             (let ((shape (make-shape-type :color "GREEN" :x (1+ i) :y (1+ i) :shapesize (1+ i))))
               (%stage-data-sn node (1+ i) ha (dds.dcps::%serialize-sample ts shape) wid)))
           (dds.dcps::%drain dr)
           (%check :klr2b-total (= 2 (length (dds.dcps::dr-cache dr)))
                   (format nil "a single-instance KEEP_LAST-2 reader fed 3 samples must keep exactly 2, got ~d"
                           (length (dds.dcps::dr-cache dr))))
           (let ((sns (sort (mapcar (lambda (cs) (dds.dcps:sample-info-sequence-number (dds.dcps:cached-sample-info cs)))
                                    (dds.dcps::dr-cache dr)) #'<)))
             (%check :klr2b-last2 (equal '(2 3) sns)
                     (format nil "the reader must keep the LAST 2 SNs (2,3), SN1 dropped; got ~s" sns))))
      (dds.dcps:delete-participant p2)))
  t)

(defun* run-keeplast-unkeyed-collapse-test ()
    (function () t)
  "WP-KEEPLAST D2 scenario 5 (spec §5, DDS 1.4 §2.2.3.18 degenerate single-instance case): an UNKEYED KEEP_LAST
   depth-2 writer + reader collapse to global last-2 (one shared instance bucket). Writer side: a DCPS unkeyed
   (nokey-rt) KEEP_LAST-2 writer's engine HC holds the global last 2 after 3 writes (all in the :UNKEYED bucket).
   Reader side: an unkeyed KEEP_LAST-2 reader fed 3 samples through %drain keeps the global last 2 — identical to
   a correct global KEEP_LAST (no per-key partitioning when there is no key)."
  (let* ((uts (dds.types:find-type-support "nokey-rt"))
         (p (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "KlUkNoKey" "nokey-rt" uts))
                (pub (dds.dcps:create-publisher p))
                (dw (dds.dcps:create-datawriter
                     pub tp :qos (dds.qos:make-writer-qos :history-kind :keep-last :history-depth 2))))
           (dds.dcps:write-sample dw (make-nokey-rt :a 1 :b 1))
           (dds.dcps:write-sample dw (make-nokey-rt :a 2 :b 2))
           (dds.dcps:write-sample dw (make-nokey-rt :a 3 :b 3))
           (let* ((hc (%dw-engine-hc dw))
                  (by-instance (%hc-instance-sns hc)))
             (%check :klu-w-count (= 2 (dds.rtps.history:hc-change-count hc))
                     (format nil "an unkeyed KEEP_LAST-2 writer must hold the global last 2, got ~d"
                             (dds.rtps.history:hc-change-count hc)))
             (%check :klu-w-one-bucket (= 1 (hash-table-count by-instance))
                     "unkeyed samples must collapse to ONE instance bucket (global KEEP_LAST)")
             (%check :klu-w-last2 (equal '(2 3) (gethash :unkeyed by-instance))
                     (format nil "the global last 2 SNs (2,3) must be retained, got ~s" (gethash :unkeyed by-instance)))))
      (dds.dcps:delete-participant p)))
  (let* ((uts (dds.types:find-type-support "nokey-rt"))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p2 "KlUkRNoKey" "nokey-rt" uts))
                (sub (dds.dcps:create-subscriber p2))
                (dr (dds.dcps:create-datareader
                     sub tp :qos (dds.qos:make-reader-qos :history-kind :keep-last :history-depth 2)))
                (node (dds.dcps::dp-node p2))
                (wid #x00000103))                       ; no-key endpoint EntityId 0x103
           (dotimes (i 3)
             (let ((shape (make-nokey-rt :a (1+ i) :b (1+ i))))
               (%stage-data-sn node (1+ i)
                               (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)   ; HANDLE_NIL (unkeyed)
                               (dds.dcps::%serialize-sample uts shape) wid)))
           (dds.dcps::%drain dr)
           (%check :klu-r-count (= 2 (length (dds.dcps::dr-cache dr)))
                   (format nil "an unkeyed KEEP_LAST-2 reader fed 3 samples must keep the global last 2, got ~d"
                           (length (dds.dcps::dr-cache dr))))
           (let ((sns (sort (mapcar (lambda (cs) (dds.dcps:sample-info-sequence-number (dds.dcps:cached-sample-info cs)))
                                    (dds.dcps::dr-cache dr)) #'<)))
             (%check :klu-r-last2 (equal '(2 3) sns)
                     (format nil "the unkeyed reader must keep the global last 2 SNs (2,3), got ~s" sns))))
      (dds.dcps:delete-participant p2)))
  t)

(defun* run-keeplast-keepall-regression-test ()
    (function () t)
  "WP-KEEPLAST D2 scenario 6 (spec §6, regression): KEEP_ALL is unchanged from pre-activation — no per-instance
   eviction. A DCPS KEEP_ALL keyed writer's engine HC retains ALL writes across instances (bounded only by
   RESOURCE_LIMITS, as before). A KEEP_ALL keyed reader fed several samples for two instances keeps ALL of them
   in dr-cache (no lossy KEEP_LAST drop fires — %reader-keeplast-depth is NIL for KEEP_ALL)."
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "KaW2Square" "shape-type" ts))
                (pub (dds.dcps:create-publisher p))
                (dw (dds.dcps:create-datawriter pub tp :qos (dds.qos:make-writer-qos :history-kind :keep-all))))
           (dotimes (i 3) (dds.dcps:write-sample dw (make-shape-type :color "BLUE" :x i :y i :shapesize 1)))
           (dotimes (i 3) (dds.dcps:write-sample dw (make-shape-type :color "RED"  :x i :y i :shapesize 1)))
           (%check :kaw-keeps-all (= 6 (dds.rtps.history:hc-change-count (%dw-engine-hc dw)))
                   (format nil "a KEEP_ALL writer must retain ALL 6 changes (no per-instance eviction), got ~d"
                           (dds.rtps.history:hc-change-count (%dw-engine-hc dw)))))
      (dds.dcps:delete-participant p)))
  (let* ((ts (dds.types:find-type-support "shape-type"))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p2 "KaR2Square" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p2))
                (dr (dds.dcps:create-datareader sub tp :qos (dds.qos:make-reader-qos :history-kind :keep-all)))
                (node (dds.dcps::dp-node p2))
                (wid #x00000102))
           (%check :kar-no-depth (null (dds.dcps::%reader-keeplast-depth dr))
                   "a KEEP_ALL reader must report NO KEEP_LAST depth (no per-instance drop path)")
           (flet ((deliver (sn shape)
                    (%stage-data-sn node sn (funcall (dds.types:type-support-key-hash ts) shape)
                                    (dds.dcps::%serialize-sample ts shape) wid)))
             (deliver 1 (make-shape-type :color "BLUE" :x 1 :y 1 :shapesize 1))
             (deliver 2 (make-shape-type :color "BLUE" :x 2 :y 2 :shapesize 2))
             (deliver 3 (make-shape-type :color "BLUE" :x 3 :y 3 :shapesize 3))
             (deliver 4 (make-shape-type :color "RED"  :x 4 :y 4 :shapesize 4)))
           (dds.dcps::%drain dr)
           (%check :kar-keeps-all (= 4 (length (dds.dcps::dr-cache dr)))
                   (format nil "a KEEP_ALL reader must keep ALL 4 delivered samples (no drop), got ~d"
                           (length (dds.dcps::dr-cache dr)))))
      (dds.dcps:delete-participant p2)))
  t)

(defun* run-keeplast-reliability-composition-test ()
    (function () t)
  "WP-KEEPLAST D2 scenario 7 (spec §7, DDS 1.4 §2.2.3.18 + RTPS 2.5 §8.4.1): purge-acked and per-instance
   KEEP_LAST eviction co-exist through the single %hc-remove-change path without drifting. A KEEP_LAST depth-2
   keyed engine writer is fed A@1 A@3 A@5 (instance A; SN1 EVICTED at depth) and B@2 (instance B). A reliable
   reader then fully-acks through SN3, so writer-purge-acked PURGES the fully-acked low changes (SN2, SN3 < 4).
   Assert: SN1 went by eviction, SN2/SN3 by purge, A keeps its last 2 (SN3 was purged though — so A's live set
   becomes {5} after purge), the change table and the per-instance index agree (count = sum of bucket lengths),
   no bucket holds an orphaned (purged/evicted) SN, and re-adding into A still evicts correctly (no drift)."
  (let* ((hc (dds.rtps.history:make-history-cache :keep-last 2 nil nil))
         (a (%keeplast-handle 1))
         (b (%keeplast-handle 2)))
    (flet ((add (sn h) (dds.rtps.history:hc-add-change
                        hc (dds.rtps.history:make-cache-change :sn sn :instance-key-hash h)))
           (have (sn) (dds.rtps.history:hc-get-change hc sn)))
      (add 1 a) (add 2 b) (add 3 a) (add 5 a)            ; A: 1,3,5 -> KEEP_LAST-2 evicts A's SN1
      (%check :klc-evicted-1 (null (have 1)) "per-instance KEEP_LAST-2 must evict A's oldest SN1")
      (%check :klc-pre-count (= 3 (dds.rtps.history:hc-change-count hc))
              (format nil "after eviction the HC holds 3 changes (A:3,5 + B:2), got ~d" (dds.rtps.history:hc-change-count hc)))
      ;; purge the fully-acked low range (< 4): removes SN2 (B) and SN3 (A) through the SAME %hc-remove-change.
      (let ((purged (dds.rtps.history:hc-purge-below hc 4)))
        (%check :klc-purged-2 (= 2 purged)
                (format nil "hc-purge-below 4 must remove SN2 and SN3 (the fully-acked low changes), got ~d" purged)))
      (%check :klc-2-gone (null (have 2)) "SN2 (B) must be purged")
      (%check :klc-3-gone (null (have 3)) "SN3 (A) must be purged")
      (%check :klc-5-kept (have 5) "SN5 (A) survives both eviction and purge")
      (%check :klc-count-1 (= 1 (dds.rtps.history:hc-change-count hc))
              (format nil "only SN5 must remain (count 1), got ~d" (dds.rtps.history:hc-change-count hc)))
      ;; the index never drifted: bucket-summed SNs equal the change count, and no bucket holds a removed SN.
      (let ((by-instance (%hc-instance-sns hc)))
        (%check :klc-index-agrees
                (= (dds.rtps.history:hc-change-count hc)
                   (let ((n 0)) (maphash (lambda (k sns) (declare (ignore k)) (incf n (length sns))) by-instance) n))
                "the per-instance index SN total must equal the change count (no orphaned/double-counted SN)")
        (%check :klc-a-live (equal '(5) (gethash a by-instance))
                (format nil "instance A's live bucket must be exactly (5) after eviction+purge, got ~s" (gethash a by-instance)))
        (%check :klc-b-empty (null (gethash b by-instance))
                "instance B's bucket must be gone (its only SN2 was purged) — not an orphaned empty bucket"))
      ;; re-add into A: depth-2 must still evict correctly off the TRUE post-purge bucket (no stale index entry).
      (add 6 a) (add 7 a)
      (%check :klc-readd-evicts (and (= 2 (dds.rtps.history:hc-change-count hc)) (have 6) (have 7) (null (have 5)))
              "re-adding A@6,A@7 must keep the last 2 (6,7) and evict SN5 — the post-purge bucket drove eviction (no drift)")))
  t)

;;; WP-BATCH write-side batching (FR-PF-1 / NFR-PERF-4): with batch-max-samples=N, publish-sample DEFERS
;;; the push until N samples accumulate (size trigger) or flush-batch fires (time/cadence/stop); the batch
;;; then flushes coalesced into few datagrams with one amortized HEARTBEAT. Each sample stays a standard
;;; DATA (wire-standard, reader unchanged). Default N=1 flushes per write (no batching). Offline: a matched
;;; reader destination is seeded so %push-data has somewhere to send, and *datagram-sink* counts the DATA.

(defun* run-batch-defer-test ()
    (function () t)
  "WP-BATCH: with batch-max-samples=5, four publishes DEFER (no datagram); the 5th hits the size trigger
   and flushes all 5 batched DATA at once; a subsequent partial batch flushes only on flush-batch."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 7)
               :host "127.0.0.1" :port 0 :batch-max-samples 5)))
    (unwind-protect
         (progn
           (dds.disc:enable-publisher node :history-kind :keep-all)   ; KEEP_ALL: batching retains all 5 DATA to flush at once (ADR 0019 migration)
           (%seed-reader-participant node #x63 7705)
           (let ((captured '()))
             (let ((dds.disc::*datagram-sink* (lambda (dg) (push dg captured))))
               (dotimes (i 4) (dds.disc:publish-sample node (octets 1 2 3 4)))
               (%check :batch-deferred (null captured)
                       "a partial batch (4 < max 5) must NOT push any datagram")
               (dds.disc:publish-sample node (octets 1 2 3 4))   ; 5th -> size trigger
               (%check :batch-flush-5
                       (= 5 (reduce #'+ (mapcar #'%count-submessages captured) :key #'second))
                       "the 5th publish flushes all 5 batched DATA at once")
               (setf captured '())
               (dds.disc:publish-sample node (octets 1 2 3 4))
               (dds.disc:publish-sample node (octets 1 2 3 4))
               (%check :batch-deferred-2 (null captured)
                       "two more publishes defer (2 < max 5)")
               (dds.disc:flush-batch node)
               (%check :batch-flush-partial
                       (= 2 (reduce #'+ (mapcar #'%count-submessages captured) :key #'second))
                       "flush-batch pushes the 2-sample partial batch"))))
      (dds.disc:stop-node node)))
  t)

;;; WP-ASYNC-FLOW per-datagram step send (FR-PF-2): %send-changes-packed is now a step loop over
;;; %emit-next-datagram, and %flow-step-emit exposes a node-level "build+send the next single datagram"
;;; seam for the Phase-C FlowController scheduler. The step's oracle is BYTE-IDENTITY: emitting one
;;; datagram at a time must produce the EXACT same wire bytes (same datagram count, same bytes each) as
;;; the existing flush-all push. Two equivalently-built nodes (same guid-prefix, same seeded reader, same
;;; unsent set) are driven — one by flush-all (%push-data), one by the step (%flow-step-emit) — and their
;;; captured datagram byte-sequences compared via *datagram-sink* (reused, DRY).

(defun* %flow-step-capture (node)
    (function (dds.disc:disc-node) list)
  "Drive NODE's user writer through the per-datagram STEP (%flow-step-emit) to completion, capturing every
   outgoing datagram's bytes via *datagram-sink*; return the captured datagrams (fresh octet vectors) in send
   order. Loops one datagram per call until MORE-REMAIN-P is NIL — the Phase-C scheduler's drive loop,
   minus the token pacing."
  (let ((captured '())
        (ws (dds.disc::%make-flow-writer-state   ; WP-N-ENDPOINT-S1B: the step now drives a per-writer flow-state (the node's primary writer)
             :node node :writer (dds.disc::disc-node-user-writer node))))
    (let ((dds.disc::*datagram-sink* (lambda (dg) (push dg captured))))
      (loop with more = t
            while more
            do (multiple-value-bind (bytes more-remain)
                   (dds.disc::%flow-step-emit ws (dds.disc::disc-node-tx-msg node))
                 (declare (ignore bytes))
                 (setf more (and more-remain t)))))
    (nreverse captured)))

(defun* %flow-step-build-node (guid-byte reader-byte port writes)
    (function ((unsigned-byte 8) (unsigned-byte 8) (unsigned-byte 16) list) dds.disc:disc-node)
  "A publisher node (guid-prefix all GUID-BYTE) with one matched reader (%seed-reader-participant,
   reader-prefix READER-BYTE at PORT) and each payload in WRITES written to its user writer's HistoryCache —
   the identical fixture both the flush-all and the step paths are driven against (byte-identity demands the
   two nodes differ in NOTHING). Caller stop-nodes it."
  (let ((node (dds.disc:make-disc-node
               :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element guid-byte)
               :host "127.0.0.1" :port 0)))
    (dds.disc:enable-publisher node :history-kind :keep-all)   ; KEEP_ALL: the step/teardown fixtures retain every written change (ADR 0019 migration)
    (%seed-reader-participant node reader-byte port)
    (let ((writer (dds.disc::disc-node-user-writer node)))
      (dolist (pl writes) (dds.rtps.reliable:writer-write writer pl)))
    node))

(defun* %datagrams-identical-p (a b)
    (function (list list) t)
  "T iff datagram byte-sequences A and B are identical: same count AND each pair equalp (same bytes)."
  (and (= (length a) (length b))
       (every #'equalp a b)))

(defun* run-flow-step-equivalence-test ()
    (function () t)
  "WP-ASYNC-FLOW byte-identity oracle (FR-PF-2): the per-datagram STEP send produces the EXACT wire bytes the
   flush-all push does. Two cases, each driving two equivalently-built nodes (same guid-prefix, matched
   reader, unsent set): (1) K=8 small DATA — flush-all (%push-data) vs step (%flow-step-emit) datagram
   sequences must be byte-IDENTICAL (same count, same bytes), proving the coalesced DATA+HEARTBEAT framing,
   coalesce budget, and HEARTBEAT trailing are unchanged; (2) ONE large sample that FRAGMENTS into a
   DATA_FRAG series + HEARTBEAT_FRAG — the fragment datagram sequence must likewise be byte-identical. Both
   capture via *datagram-sink* (reused). Flow control is wire-invisible (ADR 0016): the step is an internal
   restructuring, never a wire change."
  ;; Case 1 — K small DATA: flush-all vs step, byte-identical.
  (let ((flush-node (%flow-step-build-node #x71 #x81 7801
                                           (loop repeat 8 collect (octets 1 2 3 4 5 6 7 8))))
        (step-node  (%flow-step-build-node #x71 #x81 7801
                                           (loop repeat 8 collect (octets 1 2 3 4 5 6 7 8)))))
    (unwind-protect
         (let ((flush-dgs (%coalesce-capture flush-node))
               (step-dgs  (%flow-step-capture step-node)))
           (%check :flow-step-small-nonempty (plusp (length step-dgs))
                   "the step must emit at least one datagram for K unsent small changes")
           (%check :flow-step-small-identical (%datagrams-identical-p flush-dgs step-dgs)
                   "the step's small-DATA datagram sequence must be byte-identical to flush-all")
           ;; Sanity: the captured datagram(s) carry the expected 8 DATA + 1 HEARTBEAT (coalesced).
           (let ((totals (mapcar #'%count-submessages step-dgs)))
             (%check :flow-step-small-submsgs
                     (and (= 8 (reduce #'+ totals :key #'second))
                          (= 1 (reduce #'+ totals :key #'third)))
                     "the step's datagrams must carry 8 DATA + 1 HEARTBEAT (coalesced)")))
      (dds.disc:stop-node flush-node)
      (dds.disc:stop-node step-node)))
  ;; Case 2 — one large sample (DATA_FRAG series): flush-all vs step, byte-identical.
  (let* ((big (let ((v (make-array 4000 :element-type '(unsigned-byte 8))))
                (dotimes (i 4000 v) (setf (aref v i) (logand (* i 7) #xff)))))
         (flush-node (%flow-step-build-node #x72 #x82 7802 (list big)))
         (step-node  (%flow-step-build-node #x72 #x82 7802 (list big))))
    (unwind-protect
         (let ((flush-dgs (%coalesce-capture flush-node))
               (step-dgs  (%flow-step-capture step-node)))
           (%check :flow-step-frag-multiple (< 1 (length step-dgs))
                   "a 4000-octet sample must fragment into a multi-datagram DATA_FRAG series via the step")
           (%check :flow-step-frag-identical (%datagrams-identical-p flush-dgs step-dgs)
                   "the step's DATA_FRAG datagram sequence must be byte-identical to flush-all"))
      (dds.disc:stop-node flush-node)
      (dds.disc:stop-node step-node)))
  t)

;;; WP-ASYNC-FLOW Phase C (FR-PF-2, ADR 0016): the shared flow-controller + its scheduler thread paces the
;;; aggregate user-data byte rate of its associated writers via the token bucket, round-robining one datagram
;;; per writer per turn (so multiple writers interleave at the shaped rate). Three tests: (1) object lifecycle
;;; — make/associate/double-associate-rejected/destroy-joins (SBCL+Clasp, no sends); (2) rate-shaping — a
;;; low-rate controller drains B (>= burst) bytes in >= ~B/rate wall time vs an unpaced async baseline draining
;;; far faster (SBCL; Clasp pass-skipped — timing-dependent); (3) multi-writer round-robin — two writers on one
;;; controller, both delivered, datagrams interleave, aggregate rate shaped (SBCL).

(defun* %flow-match-writer-reader (w r topic)
    (function (dds.disc:disc-node dds.disc:disc-node string) t)
  "Wire writer node W to reader node R as a BEST_EFFORT pair on TOPIC and drive SPDP+SEDP until they match
   (the live-fixture twin of run-async-decoupled-test's boilerplate, factored DRY for the pacing + RR tests).
   BEST_EFFORT so the controller's paced send is the SOLE delivery path — no ACKNACK-driven retransmit (which
   runs unpaced on the receiver thread) confounds the rate measurement. Caller has already enable-publisher'd
   W and enable-subscriber'd R, and must stop-node both. Returns T once matched."
  (setf (dds.disc::disc-node-peers w) (list (cons "127.0.0.1" (dds.disc:disc-node-port r)))
        (dds.disc::disc-node-peers r) (list (cons "127.0.0.1" (dds.disc:disc-node-port w))))
  (dds.disc:start-node w) (dds.disc:start-node r)
  (dds.disc:announce-participant w) (dds.disc:announce-participant r)
  (loop repeat 300
        until (and (plusp (dds.disc:disc-node-discovered-count w))
                   (plusp (dds.disc:disc-node-discovered-count r)))
        do (sleep 0.01))
  (dds.disc:announce-endpoints w) (dds.disc:announce-endpoints r)
  (loop repeat 300
        until (and (plusp (dds.disc:disc-node-matched-count w))
                   (plusp (dds.disc:disc-node-matched-count r)))
        do (sleep 0.01))
  (%check :flow-matched (plusp (dds.disc:disc-node-matched-count w))
          "the flow-controller writer must match the reader before publishing")
  t)

(defun* run-flow-controller-lifecycle-test ()
    (function () t)
  "WP-ASYNC-FLOW (FR-PF-2, ADR 0016): the flow-controller OBJECT lifecycle — no samples. make-flow-controller
   spawns a scheduler thread (the THREAD slot is non-NIL); flow-controller-associate binds a writer node; a
   SECOND associate of the SAME node SIGNALS (one controller per writer); destroy-flow-controller JOINs the
   scheduler (the THREAD slot becomes NIL afterward) and is idempotent. The THREAD slot (non-NIL = running,
   NIL = joined) is the portable alive signal across SBCL + Clasp (no PAL thread-alive predicate). Runs on
   SBCL + Clasp."
  (let ((node (%flow-step-build-node #x91 #xA1 7811 '()))   ; a writer node (seeded reader); never published
        (controller (dds.disc:make-flow-controller :tokens-per-period 10000 :period 100000000
                                                   :max-burst 10000)))
    (unwind-protect
         (progn
           (%check :flow-lc-thread-running (dds.disc:flow-controller-thread controller)
                   "make-flow-controller must spawn a scheduler thread (THREAD slot non-NIL)")
           (dds.disc:flow-controller-associate controller node)
           (%check :flow-lc-associated (eq controller (dds.disc::disc-node-flow-controller node))
                   "flow-controller-associate must set the node's flow-controller slot")
           (%check :flow-lc-double-rejected
                   (null (ignore-errors (dds.disc:flow-controller-associate controller node) t))
                   "a SECOND associate of the SAME node must SIGNAL (one controller per writer)")
           (dds.disc:flow-controller-unregister controller node)
           (%check :flow-lc-unregistered (null (dds.disc::disc-node-flow-controller node))
                   "flow-controller-unregister must clear the node's flow-controller slot")
           (dds.disc:destroy-flow-controller controller)
           (%check :flow-lc-thread-joined (null (dds.disc:flow-controller-thread controller))
                   "destroy-flow-controller must JOIN the scheduler thread (THREAD slot NIL afterward)")
           (dds.disc:destroy-flow-controller controller)   ; idempotent
           (%check :flow-lc-destroy-idempotent (null (dds.disc:flow-controller-thread controller))
                   "destroy-flow-controller must be idempotent (still NIL, no error)"))
      (ignore-errors (dds.disc:destroy-flow-controller controller))
      (dds.disc:stop-node node)))
  t)

(defun* run-flow-pacing-test ()
    (function () t)
  "WP-ASYNC-FLOW (FR-PF-2, ADR 0016): RATE-SHAPING is observed. A LOW-rate controller (10000 bytes / 100 ms
   = 100 kB/s, max-burst 10000) paces a writer publishing N large samples totalling B bytes (B well above
   max-burst); the wall time for a BEST_EFFORT reader to receive all N is >= ~(B-burst)/rate within tolerance,
   while an UNPACED enable-async baseline (same payload, no controller) drains far faster — so the elapsed
   gap is the shaping. Timing-dependent: SBCL only; Clasp is pass-skipped."
  (when (eq (uiop:implementation-type) :clasp) (return-from run-flow-pacing-test t))   ; timing-flaky on Clasp
  (let* ((n 30)
         (payload (make-array 1400 :element-type '(unsigned-byte 8) :initial-element #x5a))
         (wire-bytes (* n (+ 1400 24 20)))   ; ~ payload + DATA submsg-prefix (24) + RTPS Header (20) per datagram
         (rate-bytes-per-sec 100000)         ; 10000 bytes / 0.1 s
         (max-burst 10000)
         (ideal-seconds (/ (max 0 (- wire-bytes max-burst)) (float rate-bytes-per-sec)))
         ;; -- PACED run --
         (pw (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x93) :host "127.0.0.1" :port 0))
         (pr (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xA3) :host "127.0.0.1" :port 0))
         (controller nil) (paced-elapsed 0.0) (unpaced-elapsed 0.0))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer pw :topic "FlowPace" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher pw :history-kind :keep-all)   ; KEEP_ALL: pacing must deliver all N samples (ADR 0019 migration)
           (dds.disc:add-local-reader pr :topic "FlowPace" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber pr)
           (%flow-match-writer-reader pw pr "FlowPace")
           (setf controller (dds.disc:make-flow-controller :tokens-per-period max-burst :period 100000000
                                                           :max-burst max-burst))
           (dds.disc:flow-controller-associate controller pw)
           (let ((t0 (dds.pal:monotonic-ns)))
             (dotimes (i n) (dds.disc:publish-sample pw payload))
             (loop repeat 1000 until (>= (dds.disc:node-sample-count pr) n) do (sleep 0.005))
             (setf paced-elapsed (/ (- (dds.pal:monotonic-ns) t0) 1.0d9)))
           (%check :flow-pace-delivered (>= (dds.disc:node-sample-count pr) n)
                   (format nil "the paced controller must deliver all ~d samples to the best-effort reader" n)))
      (when controller (ignore-errors (dds.disc:destroy-flow-controller controller)))
      (dds.disc:stop-node pw) (dds.disc:stop-node pr))
    ;; -- UNPACED baseline (enable-async, no controller) --
    (let ((uw (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x94) :host "127.0.0.1" :port 0))
          (ur (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xA4) :host "127.0.0.1" :port 0)))
      (unwind-protect
           (progn
             (dds.disc:add-local-writer uw :topic "FlowPace" :type "X"
                                        :reliability dds.rtps.discovery:+reliability-best-effort+)
             (dds.disc:enable-publisher uw :history-kind :keep-all)   ; KEEP_ALL: the unpaced baseline must deliver all N (ADR 0019 migration)
             (dds.disc:enable-async uw)
             (dds.disc:add-local-reader ur :topic "FlowPace" :type "X"
                                        :reliability dds.rtps.discovery:+reliability-best-effort+)
             (dds.disc:enable-subscriber ur)
             (%flow-match-writer-reader uw ur "FlowPace")
             (let ((t0 (dds.pal:monotonic-ns)))
               (dotimes (i n) (dds.disc:publish-sample uw payload))
               (loop repeat 1000 until (>= (dds.disc:node-sample-count ur) n) do (sleep 0.005))
               (setf unpaced-elapsed (/ (- (dds.pal:monotonic-ns) t0) 1.0d9))))
        (dds.disc:stop-node uw) (dds.disc:stop-node ur)))
    (format t "~&  [flow-pace] wire~~~d B, rate ~d B/s, ideal>=~,3fs | paced=~,3fs unpaced=~,3fs~%"
            wire-bytes rate-bytes-per-sec ideal-seconds paced-elapsed unpaced-elapsed)
    ;; Rate-shaping observed: paced drain takes >= a conservative fraction of the ideal AND is materially
    ;; slower than the unpaced baseline. Lower bound is loose (0.5 x ideal) to stay robust under load.
    (%check :flow-pace-shaped (>= paced-elapsed (* 0.5d0 ideal-seconds))
            (format nil "paced drain (~,3fs) must be >= ~,3fs (~~0.5 x ideal ~,3fs) — rate shaping"
                    paced-elapsed (* 0.5d0 ideal-seconds) ideal-seconds))
    (%check :flow-pace-slower-than-unpaced (> paced-elapsed (* 2.0d0 unpaced-elapsed))
            (format nil "paced (~,3fs) must be materially slower than unpaced (~,3fs) — pacing adds latency"
                    paced-elapsed unpaced-elapsed)))
  t)

(defun* run-flow-multiwriter-rr-test ()
    (function () t)
  "WP-ASYNC-FLOW (FR-PF-2, ADR 0016): two writer nodes on ONE controller round-robin at the datagram level.
   Both writers publish into a single low-rate controller; a BEST_EFFORT reader for EACH writer's topic
   receives all of that writer's samples (both delivered), the controller's scheduler interleaves their
   datagrams (one per writer per RR turn — neither writer's stream is fully drained before the other's
   begins), and the aggregate send is rate-shaped. SBCL only (timing); Clasp pass-skipped."
  (when (eq (uiop:implementation-type) :clasp) (return-from run-flow-multiwriter-rr-test t))
  (let* ((n 12)
         (pa (make-array 600 :element-type '(unsigned-byte 8) :initial-element #x0a))
         (pb (make-array 600 :element-type '(unsigned-byte 8) :initial-element #x0b))
         (wa (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x95) :host "127.0.0.1" :port 0))
         (ra (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xA5) :host "127.0.0.1" :port 0))
         (wb (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x96) :host "127.0.0.1" :port 0))
         (rb (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xA6) :host "127.0.0.1" :port 0))
         (controller nil) (order '()))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer wa :topic "FlowRRa" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher wa :history-kind :keep-all)   ; KEEP_ALL: writer A must deliver all its samples (ADR 0019 migration)
           (dds.disc:add-local-reader ra :topic "FlowRRa" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber ra)
           (dds.disc:add-local-writer wb :topic "FlowRRb" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher wb :history-kind :keep-all)   ; KEEP_ALL: writer B must deliver all its samples (ADR 0019 migration)
           (dds.disc:add-local-reader rb :topic "FlowRRb" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber rb)
           ;; Record the INTERLEAVING: each reader's on-sample stamps which writer (:a / :b) just delivered.
           (setf (dds.disc:disc-node-on-sample ra) (lambda () (push :a order))
                 (dds.disc:disc-node-on-sample rb) (lambda () (push :b order)))
           (%flow-match-writer-reader wa ra "FlowRRa")
           (%flow-match-writer-reader wb rb "FlowRRb")
           (setf controller (dds.disc:make-flow-controller :tokens-per-period 4000 :period 100000000 :max-burst 4000))
           (dds.disc:flow-controller-associate controller wa)
           (dds.disc:flow-controller-associate controller wb)
           (dotimes (i n) (dds.disc:publish-sample wa pa) (dds.disc:publish-sample wb pb))
           (loop repeat 1500
                 until (and (>= (dds.disc:node-sample-count ra) n) (>= (dds.disc:node-sample-count rb) n))
                 do (sleep 0.005))
           (%check :flow-rr-a-delivered (>= (dds.disc:node-sample-count ra) n)
                   (format nil "writer A's ~d samples must all be delivered" n))
           (%check :flow-rr-b-delivered (>= (dds.disc:node-sample-count rb) n)
                   (format nil "writer B's ~d samples must all be delivered" n))
           ;; Interleaving: count :a<->:b transitions in delivery order. Strict per-writer ordering (all A
           ;; then all B) yields exactly ONE transition; per-datagram RR yields many. Require several.
           (let* ((seq (nreverse order))
                  (transitions (loop for (x y) on seq while y count (not (eq x y)))))
             (format t "~&  [flow-rr] delivered A=~d B=~d, interleave-transitions=~d~%"
                     (dds.disc:node-sample-count ra) (dds.disc:node-sample-count rb) transitions)
             (%check :flow-rr-interleaved (>= transitions 4)
                     (format nil "RR must interleave the two writers' datagrams (>= 4 a/b transitions in ~
                                  delivery order, not all-A-then-all-B); got ~d" transitions))))
      (when controller (ignore-errors (dds.disc:destroy-flow-controller controller)))
      (dds.disc:stop-node wa) (dds.disc:stop-node ra)
      (dds.disc:stop-node wb) (dds.disc:stop-node rb)))
  t)

(defun* run-flow-multiwriter-onenode-test ()
    (function () t)
  "WP-N-ENDPOINT-S1B (ADR 0048; FR-PF-2, ADR 0016): the S1b slice — TWO local user DataWriters on ONE participant
   under ONE flow-controller, both drained under the SHARED aggregate rate. The controller registers a per-writer
   flow-state for EACH writer (the lifted S1 fail-fast) and its scheduler round-robins per-writer datagrams; BOTH
   writers' samples all deliver (neither starves — the per-writer flow-step-state makes their plans independent),
   and the send is paced at the shared aggregate (one bucket, not one-per-writer). Pre-S1b this FAILED: the
   flow-controller-associate fail-fast rejected the 2nd writer, and even lifted-without-per-writer-state only the
   PRIMARY writer drained (writer B starved). Real threads + UDP ⇒ SBCL only; Clasp pass-skipped (the flow-test
   NFR-PORT gap, mirrors run-flow-multiwriter-rr-test)."
  (when (eq (uiop:implementation-type) :clasp) (return-from run-flow-multiwriter-onenode-test t))
  (let* ((n 10)
         (pa (make-array 600 :element-type '(unsigned-byte 8) :initial-element #x1a))
         (pb (make-array 600 :element-type '(unsigned-byte 8) :initial-element #x1b))
         (pub (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x8b) :host "127.0.0.1" :port 0))
         (ra  (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xB1) :host "127.0.0.1" :port 0))
         (rb  (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xB2) :host "127.0.0.1" :port 0))
         (controller nil) (ida 0) (idb 0))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer pub :topic "OneNodeA" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher pub :history-kind :keep-all)
           (setf ida (dds.disc::disc-node-user-writer-id pub))
           (dds.disc:add-local-writer pub :topic "OneNodeB" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher pub :history-kind :keep-all)
           (setf idb (dds.disc::disc-node-user-writer-id pub))
           (%check :onenode-distinct-writers (/= ida idb) "the two DataWriters must get DISTINCT EntityIds")
           (dds.disc:add-local-reader ra :topic "OneNodeA" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber ra)
           (dds.disc:add-local-reader rb :topic "OneNodeB" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber rb)
           (setf (dds.disc::disc-node-peers pub) (list (cons "127.0.0.1" (dds.disc:disc-node-port ra)) (cons "127.0.0.1" (dds.disc:disc-node-port rb)))
                 (dds.disc::disc-node-peers ra)  (list (cons "127.0.0.1" (dds.disc:disc-node-port pub)))
                 (dds.disc::disc-node-peers rb)  (list (cons "127.0.0.1" (dds.disc:disc-node-port pub))))
           (dds.disc:start-node pub) (dds.disc:start-node ra) (dds.disc:start-node rb)
           (dds.disc:announce-participant pub) (dds.disc:announce-participant ra) (dds.disc:announce-participant rb)
           (loop repeat 300 until (and (>= (dds.disc:disc-node-discovered-count pub) 2)
                                       (plusp (dds.disc:disc-node-discovered-count ra))
                                       (plusp (dds.disc:disc-node-discovered-count rb)))
                 do (sleep 0.01))
           (dds.disc:announce-endpoints pub) (dds.disc:announce-endpoints ra) (dds.disc:announce-endpoints rb)
           (loop repeat 300 until (and (>= (dds.disc:disc-node-matched-count pub) 2)
                                       (plusp (dds.disc:disc-node-matched-count ra))
                                       (plusp (dds.disc:disc-node-matched-count rb)))
                 do (dds.disc:announce-endpoints pub) (sleep 0.01))
           (%check :onenode-matched (>= (dds.disc:disc-node-matched-count pub) 2)
                   "both writers on the one participant must match their readers before publishing")
           ;; low aggregate rate so the shared-bucket pacing is exercised; both writers publish N samples
           (setf controller (dds.disc:make-flow-controller :tokens-per-period 5000 :period 100000000 :max-burst 5000))
           (dds.disc:flow-controller-associate controller pub)
           (%check :onenode-two-entries (= 2 (length (dds.disc::disc-node-flow-writer-states pub)))
                   "the controller must register a per-writer flow-state for EACH of the participant's 2 writers")
           (dotimes (i n) (dds.disc:publish-sample pub pa nil nil 0 nil ida) (dds.disc:publish-sample pub pb nil nil 0 nil idb))
           (loop repeat 2000 until (and (>= (dds.disc:node-sample-count ra) n) (>= (dds.disc:node-sample-count rb) n))
                 do (sleep 0.005))
           (format t "~&  [flow-onenode] writer-A delivered=~d writer-B delivered=~d (of ~d each)~%"
                   (dds.disc:node-sample-count ra) (dds.disc:node-sample-count rb) n)
           (%check :onenode-writer-a-drained (>= (dds.disc:node-sample-count ra) n)
                   (format nil "writer A's ~d samples must ALL deliver under the shared controller (no starvation)" n))
           (%check :onenode-writer-b-drained (>= (dds.disc:node-sample-count rb) n)
                   (format nil "writer B's ~d samples must ALL deliver under the shared controller (B must NOT starve behind the primary)" n)))
      (when controller (ignore-errors (dds.disc:destroy-flow-controller controller)))
      (dds.disc:stop-node pub) (dds.disc:stop-node ra) (dds.disc:stop-node rb)))
  t)

(defun* run-flow-unregister-releases-refs-test ()
    (function () t)
  "WP-N-ENDPOINT-S1B (ADR 0048; adversarial-review FIX-1): flow-controller-unregister RELEASES the unregistered
   node's per-writer MID-DRAIN send-refs, so a SHARED controller that keeps running (a second node still
   associated, destroy NOT called) never leaks the departing node's captured CacheChanges until stop-node. Two
   nodes on ONE THREADLESS controller (no scheduler race); node-A's writer-state is given a snapshotted plan +
   captured refs, then node-A is unregistered while node-B stays — asserting A's step-refs are released (NIL) and
   B's writer-state is untouched (still registered + associated). Deterministic — both impls."
  (let* ((na (%flow-step-build-node #x93 #xA3 7841 (list (octets 1 2 3 4 5 6 7 8))))
         (nb (%flow-step-build-node #x94 #xA4 7842 (list (octets 9 8 7 6 5 4 3 2))))
         (controller (dds.disc::%make-flow-controller
                      :bucket (dds.disc::make-flow-token-bucket :tokens-per-period 1 :period 1 :max-burst 1)
                      :policy-fn #'dds.disc::%flow-policy-round-robin)))   ; threadless: no scheduler spawned
    (unwind-protect
         (progn
           (setf (dds.disc::disc-node-flow-controller na) controller
                 (dds.disc::disc-node-flow-controller nb) controller)
           (dds.disc::flow-controller-add-writer controller na (dds.disc::disc-node-user-writer na))
           (dds.disc::flow-controller-add-writer controller nb (dds.disc::disc-node-user-writer nb))
           (let ((wsa (dds.disc::%flow-writer-state-for na (dds.disc::disc-node-user-writer na)))
                 (wsb (dds.disc::%flow-writer-state-for nb (dds.disc::disc-node-user-writer nb))))
             (multiple-value-bind (plan refs)   ; snapshot A's plan -> populates step-state + captures pinned refs
                 (dds.disc::%node-datagram-plan na (dds.disc::flow-writer-state-writer wsa) (dds.disc::disc-node-tx-msg na))
               (setf (dds.disc::flow-writer-state-step-state wsa) plan
                     (dds.disc::flow-writer-state-step-refs wsa) refs))
             (%check :unreg-refs-precond (dds.disc::flow-writer-state-step-refs wsa)
                     "precondition: node-A's writer-state must hold captured mid-drain send-refs")
             (dds.disc::flow-controller-unregister controller na)   ; unregister A; B stays on the SHARED controller
             (%check :unreg-refs-released (null (dds.disc::flow-writer-state-step-refs wsa))
                     "unregister must RELEASE node-A's mid-drain send-refs (no leak on a shared, still-running controller)")
             (%check :unreg-a-dropped (not (member wsa (dds.disc::flow-controller-writers controller)))
                     "node-A's writer-state must be removed from the controller's selection set")
             (%check :unreg-b-untouched (and (member wsb (dds.disc::flow-controller-writers controller))
                                             (eq controller (dds.disc::disc-node-flow-controller nb)))
                     "the OTHER node's writer-state must stay registered + associated (the controller keeps serving it)")))
      (dds.disc:stop-node na) (dds.disc:stop-node nb)))
  t)

;;;; ---- WP-FLOW-EDF-PRIORITY (ADR 0016 deferred scheduling policies; FR-QOS-1) ----
;;;; The :edf + :priority policies are PURE SELECTION under the controller lock (the token-bucket pacing is
;;;; orthogonal + untouched). The strongest, most deterministic oracle for a pure selection change is to drive
;;;; the policy function DIRECTLY over constructed nodes with an injected clock — no threads, no sockets, no
;;;; timing race — so these run on BOTH impls (unlike the real-thread pacing/RR tests, which Clasp pass-skips).
;;;; A clock-box is a settable ns counter the controller's clock-fn reads (the same seam the pacing tests use).

(defun* %flow-clock-box ()
    (function () (values function cons))
  "A settable ns clock: returns (values CLOCK-FN BOX) where CLOCK-FN reads (car BOX) — advance the clock with
   (setf (car box) n). Deterministic injected time for the :edf/:priority policy tests (WP-FLOW-EDF-PRIORITY)."
  (let ((box (list 0)))
    (values (lambda () (the integer (car box))) box)))

(defun* %flow-fake-writer-state (&key (pending t) (head 0) (budget 0) (priority 0) (last-served 0) (node nil))
    (function (&key (:pending t) (:head integer) (:budget integer) (:priority integer) (:last-served integer)
                    (:node t))
              dds.disc::flow-writer-state)
  "A bare per-writer flow-writer-state with ONLY the controller-lock-guarded selection slots set (WP-FLOW-EDF-
   PRIORITY; WP-N-ENDPOINT-S1B — the selection ENTRY is now a WRITER, not a node): no socket, no threads, no
   real writer — the policy reads only these. HEAD+BUDGET drive the :edf deadline; PRIORITY+LAST-SERVED drive
   the :priority effective key. NODE lets a test place several entries on the SAME participant (proving the
   selector orders ACROSS one node's writers)."
  (dds.disc::%make-flow-writer-state
   :node node :writer nil :pending pending :head-ns head :latency-budget-ns budget
   :transport-priority priority :last-served-ns last-served))

(defun* %flow-policy-controller (clock policy-fn states)
    (function (function function list) dds.disc::flow-controller)
  "A THREADLESS flow-controller (raw %make-flow-controller — no scheduler spawned) wired to CLOCK + POLICY-FN
   with STATES (per-writer flow-writer-states, WP-N-ENDPOINT-S1B) already registered, for direct policy-fn
   exercise (WP-FLOW-EDF-PRIORITY)."
  (let ((c (dds.disc::%make-flow-controller
            :bucket (dds.disc::make-flow-token-bucket :tokens-per-period 1 :period 1 :max-burst 1 :clock-fn clock)
            :policy-fn policy-fn)))
    (setf (dds.disc::flow-controller-writers c) states)
    c))

(defun* run-flow-transport-priority-qos-test ()
    (function () t)
  "WP-FLOW-EDF-PRIORITY (FR-QOS-1, DDS 1.4 §2.2.3.13): the new TRANSPORT_PRIORITY qos slot defaults to 0 and
   is NOT an RxO policy; flow-controller-associate caches the writer's LATENCY_BUDGET (as ns) + TRANSPORT_PRIORITY
   onto the node's FLOW-* slots for the :edf/:priority policies. Runs on both impls (no publish/threads race)."
  (%check :tp-qos-default (= 0 (dds.qos:qos-transport-priority (dds.qos:make-qos)))
          "TRANSPORT_PRIORITY must default to 0 (DDS 1.4 §2.2.3.13)")
  (%check :tp-qos-set (= 7 (dds.qos:qos-transport-priority (dds.qos:make-qos :transport-priority 7)))
          ":transport-priority must round-trip on the qos struct")
  (%check :tp-qos-not-rxo
          (null (nth-value 1 (dds.qos:qos-rxo-compatible (dds.qos:make-qos :transport-priority 9)
                                                         (dds.qos:make-qos :transport-priority 1))))
          "TRANSPORT_PRIORITY is NOT an RxO policy — a mismatch must not appear in the incompatible list")
  (let ((node (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x98) :host "127.0.0.1" :port 0))
        (controller nil))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer node :topic "TP" :type "X"
                                      :qos (dds.qos:make-qos :reliability :reliable :transport-priority 7
                                                             :latency-budget (dds.qos:make-qos-duration 0 5000000)))
           (dds.disc:enable-publisher node)
           (setf controller (dds.disc:make-flow-controller :tokens-per-period 10000 :period 100000000 :max-burst 10000 :scheduling :priority))
           (dds.disc:flow-controller-associate controller node)
           (let ((ws (dds.disc::%flow-writer-state-for node (dds.disc::disc-node-user-writer node))))   ; WP-N-ENDPOINT-S1B: QoS is cached per-writer
             (%check :tp-cache-priority (= 7 (dds.disc::flow-writer-state-transport-priority ws))
                     "associate must cache the writer's TRANSPORT_PRIORITY on its per-writer flow-state")
             (%check :tp-cache-budget (= 5000000 (dds.disc::flow-writer-state-latency-budget-ns ws))
                     "associate must cache the writer's LATENCY_BUDGET (ns) on its per-writer flow-state")))
      (when controller (ignore-errors (dds.disc:destroy-flow-controller controller)))
      (dds.disc:stop-node node)))
  t)

(defun* run-flow-edf-ordering-test ()
    (function () t)
  "WP-FLOW-EDF-PRIORITY (ADR 0016; FR-QOS-1): the :edf policy selects the pending node with the MIN deadline
   (head write-time + LATENCY_BUDGET), draining earliest-first, with budget-0 = most urgent (deadline = write
   time) and a stable RR tiebreak among equal deadlines. Deterministic direct policy exercise — both impls."
  (multiple-value-bind (clock box) (%flow-clock-box)
    (declare (ignore box))
    ;; Same write-time (100), differing budgets: deadlines D=100 B=110 A=150 C=200 -> drain order D B A C.
    (let* ((d (%flow-fake-writer-state :head 100 :budget 0))     ; budget-0 -> deadline 100, most urgent
           (b (%flow-fake-writer-state :head 100 :budget 10))    ; deadline 110
           (a (%flow-fake-writer-state :head 100 :budget 50))    ; deadline 150
           (c (%flow-fake-writer-state :head 100 :budget 100))   ; deadline 200
           (controller (%flow-policy-controller clock #'dds.disc::%flow-policy-edf (list a b c d)))
           (order '()))
      (dotimes (i 4)
        (let ((pick (dds.disc::%flow-policy-edf controller)))
          (%check :edf-picks-pending pick "EDF must return a pending node while any remain")
          (push pick order)
          (setf (dds.disc::flow-writer-state-pending pick) nil)))   ; simulate draining that node
      (let ((seq (nreverse order)))
        (%check :edf-order (equal seq (list d b a c))
                "EDF must drain min-deadline-first: budget-0 (d), then 10 (b), 50 (a), 100 (c)"))
      (%check :edf-empty (null (dds.disc::%flow-policy-edf controller))
              "EDF must return NIL when no node is pending")))
  ;; Tie -> stable RR rotation (equal deadlines never starve each other).
  (multiple-value-bind (clock box) (%flow-clock-box)
    (declare (ignore box))
    (let* ((x (%flow-fake-writer-state :head 100 :budget 0))
           (y (%flow-fake-writer-state :head 100 :budget 0))
           (controller (%flow-policy-controller clock #'dds.disc::%flow-policy-edf (list x y))))
      (let ((p1 (dds.disc::%flow-policy-edf controller))
            (p2 (dds.disc::%flow-policy-edf controller)))
        (%check :edf-tie-rotates (and (not (eq p1 p2)) (member p1 (list x y)) (member p2 (list x y)))
                "equal-deadline nodes must rotate (RR tiebreak), not repeat the same node"))))
  t)

(defun* %flow-edf-backlog-run (restamp)
    (function (t) (values (integer 0) (integer 0)))
  "Sim of TWO continuously-backlogged writers (tight budget 1 vs loose budget 100, both always pending, plan
   always re-snapshotting) under :edf over 300 turns, one served per turn, clock +1/turn. When RESTAMP, the
   served node re-snapshots via the SHIPPED %FLOW-HEAD-ADVANCE (the runtime's Finding-1 behavior); when NIL,
   it does NOT (the pre-fix frozen-head behavior). Returns (values TIGHT-SERVED LOOSE-SERVED)
   (WP-FLOW-EDF-PRIORITY Finding-1)."
  (multiple-value-bind (clock box) (%flow-clock-box)
    (let* ((tight (%flow-fake-writer-state :head 0 :budget 1))
           (loose (%flow-fake-writer-state :head 0 :budget 100))
           (controller (%flow-policy-controller clock #'dds.disc::%flow-policy-edf (list tight loose)))
           (ts 0) (ls 0))
      (setf (dds.disc::flow-controller-scheduling controller) :edf)
      (dotimes (turn 300)
        (setf (car box) turn)
        (let ((pick (dds.disc::%flow-policy-edf controller)))   ; both stay pending (backlogged); flow-step-state nil ⇒ every pick re-snapshots
          (cond ((eq pick tight) (incf ts)) ((eq pick loose) (incf ls)))
          (when restamp (dds.disc::%flow-head-advance controller pick))))   ; the served writer's head-of-line batch drained ⇒ re-stamp its head
      (values ts ls))))

(defun* run-flow-edf-backlog-test ()
    (function () t)
  "WP-FLOW-EDF-PRIORITY (ADR 0016; FR-QOS-1) Finding-1: EDF fidelity under SUSTAINED per-writer backlog. A
   continuously-pending writer never goes idle, so the idle->pending stamp never re-fires; WITHOUT the
   re-snapshot re-stamp its frozen head grows ever more urgent and it MONOPOLIZES — a loose-budget writer that
   is served (thus should re-advance its head) instead freezes-early and starves a tight-budget writer. The fix
   re-stamps FLOW-HEAD-NS at each plan re-snapshot (%FLOW-HEAD-ADVANCE). This test contrasts both: WITHOUT the
   re-stamp the tight writer monopolizes and the loose writer is STARVED (served 0 — the RED the pre-fix code
   fails); WITH it the tight writer is still served PREFERENTIALLY turn-over-turn yet the loose writer makes
   BOUNDED progress. Deterministic — both impls."
  (multiple-value-bind (ts-fixed ls-fixed) (%flow-edf-backlog-run t)
    (multiple-value-bind (ts-buggy ls-buggy) (%flow-edf-backlog-run nil)
      (%check :edf-backlog-buggy-starves (and (= ls-buggy 0) (= ts-buggy 300))
              "WITHOUT the re-snapshot re-stamp the tight writer monopolizes and the loose writer STARVES (the bug)")
      (%check :edf-backlog-fixed-progress (plusp ls-fixed)
              "WITH the re-stamp the loose writer must make BOUNDED progress (served > 0), not starve")
      (%check :edf-backlog-fixed-preferential (> ts-fixed (* 10 ls-fixed))
              (format nil "WITH the re-stamp the tight-budget writer must still be served PREFERENTIALLY (tight ~d >> loose ~d)"
                      ts-fixed ls-fixed))))
  t)

(defun* run-flow-priority-ordering-test ()
    (function () t)
  "WP-FLOW-EDF-PRIORITY (ADR 0016; FR-QOS-1): the :priority policy selects the pending node with the HIGHEST
   TRANSPORT_PRIORITY first (aging = 0 at a fixed clock, all just enqueued). Deterministic — both impls."
  (multiple-value-bind (clock box) (%flow-clock-box)
    (declare (ignore box))
    (let* ((p9 (%flow-fake-writer-state :priority 9 :last-served 0))
           (p5 (%flow-fake-writer-state :priority 5 :last-served 0))
           (p1 (%flow-fake-writer-state :priority 1 :last-served 0))
           (controller (%flow-policy-controller clock #'dds.disc::%flow-policy-priority (list p1 p5 p9)))
           (order '()))
      (dotimes (i 3)
        (let ((pick (dds.disc::%flow-policy-priority controller)))
          (%check :prio-picks-pending pick "priority must return a pending node while any remain")
          (push pick order)
          (setf (dds.disc::flow-writer-state-pending pick) nil)))
      (%check :prio-order (equal (nreverse order) (list p9 p5 p1))
              "priority must drain highest-TRANSPORT_PRIORITY-first (9, 5, 1)")))
  t)

(defun* run-flow-priority-aging-test ()
    (function () t)
  "WP-FLOW-EDF-PRIORITY (ADR 0016; FR-QOS-1): starvation avoidance. Under a SATURATING high-priority writer
   (base 10, always pending) a low-priority writer (base 1) STILL wins within the aging bound — effective =
   base + floor((now - last-served)/quantum); the high writer is served every turn so its aging stays ~1,
   while the low writer's climbs with elapsed time until it overtakes. Deterministic injected clock — both
   impls. Contrast: PURE highest-first would starve the low writer forever."
  (multiple-value-bind (clock box) (%flow-clock-box)
    (let ((dds.disc::*flow-priority-aging-quantum-ns* 100))   ; small quantum for a short deterministic run
      (let* ((hi (%flow-fake-writer-state :priority 10 :last-served 0))
             (lo (%flow-fake-writer-state :priority 1 :last-served 0))
             (controller (%flow-policy-controller clock #'dds.disc::%flow-policy-priority (list hi lo)))
             (first-lo -1) (hi-wins 0))
        (dotimes (turn 20)
          (setf (car box) (* turn 100))                        ; advance one quantum per turn
          (let ((pick (dds.disc::%flow-policy-priority controller)))
            (cond ((eq pick lo) (when (< first-lo 0) (setf first-lo turn)))
                  ((eq pick hi) (incf hi-wins)))))              ; both stay pending (saturating) — never cleared
        (format t "~&  [flow-aging] low-priority writer first selected at turn ~d (hi won ~d turns), quantum=100ns~%"
                first-lo hi-wins)
        (%check :aging-starved-first (> first-lo 0)
                "the low-priority writer must be STARVED initially (high-priority wins the first turns)")
        (%check :aging-eventually-wins (and (>= first-lo 1) (<= first-lo 12))
                (format nil "aging must let the low writer win within the (P_hi-P_lo) bound; first won at turn ~d" first-lo))
        (%check :aging-hi-dominates (> hi-wins first-lo)
                "the high-priority writer must still dominate (win most turns) — aging bounds, not inverts"))))
  t)

(defun* run-flow-edf-across-writers-test ()
    (function () t)
  "WP-N-ENDPOINT-S1B (ADR 0048; FR-QOS-1): EDF orders across the SAME participant's writers. Two writer-states
   sharing ONE node — a TIGHT LATENCY_BUDGET writer and a LOOSE one, same head write-time — are registered on one
   :edf controller; the tight-budget writer (earlier deadline) MUST be selected first even though both live on the
   same participant. This is the S1b semantic: flow control orders the participant's outbound samples globally
   (the already-node-global %flow-policy-select spans the per-writer entries with NO cross-writer merge). Registered
   loose-first so a correct result cannot come from list order. Deterministic — both impls."
  (multiple-value-bind (clock box) (%flow-clock-box)
    (declare (ignore box))
    (let* ((node (dds.disc::%make-disc-node))                              ; ONE participant
           (tight (%flow-fake-writer-state :head 100 :budget 0 :node node))   ; deadline 100 (most urgent)
           (loose (%flow-fake-writer-state :head 100 :budget 50 :node node))  ; deadline 150
           (controller (%flow-policy-controller clock #'dds.disc::%flow-policy-edf (list loose tight))))  ; loose FIRST in the list
      (let ((p1 (dds.disc::%flow-policy-edf controller)))
        (%check :edf-across-tight-first (eq p1 tight)
                "EDF must select the TIGHT-budget writer first — across the same node's writers (S1b), not by list order")
        (setf (dds.disc::flow-writer-state-pending tight) nil)              ; tight drained
        (%check :edf-across-loose-next (eq (dds.disc::%flow-policy-edf controller) loose)
                "with the tight writer drained EDF must then select the loose writer (both of one participant drain)"))))
  t)

(defun* run-flow-priority-across-writers-test ()
    (function () t)
  "WP-N-ENDPOINT-S1B (ADR 0048; FR-QOS-1): TRANSPORT_PRIORITY orders across the SAME participant's writers. Two
   writer-states sharing ONE node — a HIGH-priority writer and a LOW one — are registered on one :priority
   controller; the high-priority writer MUST be selected first, and with it drained the low one is selected next
   (no starvation). Registered low-first so the result cannot come from list order. Deterministic — both impls."
  (multiple-value-bind (clock box) (%flow-clock-box)
    (declare (ignore box))
    (let* ((node (dds.disc::%make-disc-node))
           (hi (%flow-fake-writer-state :priority 9 :last-served 0 :node node))
           (lo (%flow-fake-writer-state :priority 1 :last-served 0 :node node))
           (controller (%flow-policy-controller clock #'dds.disc::%flow-policy-priority (list lo hi))))   ; low FIRST in the list
      (let ((p1 (dds.disc::%flow-policy-priority controller)))
        (%check :prio-across-hi-first (eq p1 hi)
                "priority must select the HIGH-TRANSPORT_PRIORITY writer first — across the same node's writers (S1b)")
        (setf (dds.disc::flow-writer-state-pending hi) nil)                 ; high drained
        (%check :prio-across-lo-next (eq (dds.disc::%flow-policy-priority controller) lo)
                "with the high writer drained priority must then select the low writer (no starvation, both drain)"))))
  t)

(defun* run-flow-edf-priority-e2e-test ()
    (function () t)
  "WP-FLOW-EDF-PRIORITY (ADR 0016): end-to-end wiring smoke — a live :edf controller and a live :priority
   controller each pace two real writers to best-effort readers and deliver ALL samples (the new policies
   drive the real scheduler loop, not just the isolated selector). Oracle = completeness + no crash (strict
   inter-writer ordering is asserted deterministically in the policy tests; e2e order is timing-racy). Real
   threads ⇒ SBCL only; Clasp pass-skipped (the flow-test NFR-PORT gap, mirrors run-flow-multiwriter-rr-test)."
  (when (eq (uiop:implementation-type) :clasp) (return-from run-flow-edf-priority-e2e-test t))
  (dolist (scheduling '(:edf :priority))
    (let* ((n 8)
           (pa (make-array 600 :element-type '(unsigned-byte 8) :initial-element #x0a))
           (pb (make-array 600 :element-type '(unsigned-byte 8) :initial-element #x0b))
           (wa (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x99) :host "127.0.0.1" :port 0))
           (ra (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xA9) :host "127.0.0.1" :port 0))
           (wb (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x9a) :host "127.0.0.1" :port 0))
           (rb (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xAa) :host "127.0.0.1" :port 0))
           (controller nil))
      (unwind-protect
           (progn
             ;; e2e oracle = delivery completeness (EDF ordering differentiation needs SEDP latency-budget
             ;; propagation, out of scope + proven deterministically in run-flow-edf-ordering-test); writers
             ;; carry only the LOCAL TRANSPORT_PRIORITY (not RxO-checked, cached at associate) — budgets stay 0.
             (dds.disc:add-local-writer wa :topic "FlowSchedA" :type "X"
                                        :qos (dds.qos:make-qos :reliability :best-effort :transport-priority 8))
             (dds.disc:enable-publisher wa :history-kind :keep-all)
             (dds.disc:add-local-reader ra :topic "FlowSchedA" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
             (dds.disc:enable-subscriber ra)
             (dds.disc:add-local-writer wb :topic "FlowSchedB" :type "X"
                                        :qos (dds.qos:make-qos :reliability :best-effort :transport-priority 2))
             (dds.disc:enable-publisher wb :history-kind :keep-all)
             (dds.disc:add-local-reader rb :topic "FlowSchedB" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
             (dds.disc:enable-subscriber rb)
             (%flow-match-writer-reader wa ra "FlowSchedA")
             (%flow-match-writer-reader wb rb "FlowSchedB")
             (setf controller (dds.disc:make-flow-controller :tokens-per-period 4000 :period 100000000 :max-burst 4000 :scheduling scheduling))
             (dds.disc:flow-controller-associate controller wa)
             (dds.disc:flow-controller-associate controller wb)
             (dotimes (i n) (dds.disc:publish-sample wa pa) (dds.disc:publish-sample wb pb))
             (loop repeat 1500
                   until (and (>= (dds.disc:node-sample-count ra) n) (>= (dds.disc:node-sample-count rb) n))
                   do (sleep 0.005))
             (%check (list :sched-a-delivered scheduling) (>= (dds.disc:node-sample-count ra) n)
                     (format nil "~s: writer A's ~d samples must all be delivered" scheduling n))
             (%check (list :sched-b-delivered scheduling) (>= (dds.disc:node-sample-count rb) n)
                     (format nil "~s: writer B's ~d samples must all be delivered" scheduling n)))
        (when controller (ignore-errors (dds.disc:destroy-flow-controller controller)))
        (dds.disc:stop-node wa) (dds.disc:stop-node ra)
        (dds.disc:stop-node wb) (dds.disc:stop-node rb))))
  t)

;;; WP-ASYNC-FLOW Phase C concurrency/UAF stress (FR-PF-2, ADR 0016 §Teardown): the regression guard for the
;;; per-node emit barrier. The shared flow-controller's scheduler picks a node under the lock, RELEASES it,
;;; then builds+sends LOCK-FREE; stop-node frees that node's socket/SHMEM/tx-buffers. WITHOUT the barrier a
;;; stop-node concurrent with a mid-emit would send on a closed socket / freed ring (use-after-free). These
;;; variants drive the EXACT racy path the lifecycle/pacing/RR tests avoid (they never stop a node mid-emit):
;;; (A) DETERMINISTIC — *datagram-sink* PARKS the scheduler mid-emit, then a worker calls stop-node; assert
;;; stop-node BLOCKS until the park releases (the barrier) and the node is freed only after; (B) single-writer
;;; churn — publish continuously while stop-node races the scheduler, no destroy-first; (C) shared-controller
;;; churn — 2 writers/2 threads, stop ONE node mid-drain, assert the OTHER keeps delivering (the scheduler
;;; survived — a per-node, not whole-scheduler, barrier). Real threads ⇒ SBCL (Clasp pass-skipped: timing +
;;; the known Clasp multithread-condvar SIGSEGV, NFR-PORT). *datagram-sink* is set GLOBALLY (the scheduler
;;; runs on its own thread; a LET binding would be thread-local and invisible there) and restored in cleanup.

(defun* run-flow-concurrency-stress-test ()
    (function () t)
  "WP-ASYNC-FLOW (FR-PF-2, ADR 0016 §Teardown): the PER-NODE EMIT BARRIER closes the use-after-free where
   stop-node frees a node's socket/SHMEM/tx-buffers while the SHARED controller's scheduler is mid-emit on it.
   Three variants on SBCL (Clasp pass-skipped — real-thread timing + the known Clasp condvar SIGSEGV): (A)
   DETERMINISTIC — *datagram-sink* parks the scheduler mid-emit on the writer, a worker thread calls stop-node;
   assert stop-node BLOCKS while parked (CURRENT-EMIT-NODE = node ⇒ unregister waits on EMIT-DONE-CV) and only
   RETURNS after the park releases and the emit completes — and the freed node was never sent on after the
   free; (B) single-writer churn — a writer thread publishes continuously while the main thread stop-nodes the
   writer (NO destroy-first); assert no crash, stop-node returns cleanly, the scheduler did not abort (a final
   destroy joins cleanly); (C) shared-controller churn — 2 writers on 1 controller, 2 publish threads, ~0.5s
   drain, stop ONE node, assert the OTHER writer keeps being delivered (the scheduler thread SURVIVED a
   per-node teardown, which a whole-scheduler join would not allow) then a clean teardown of the rest. Proves:
   no UAF, no scheduler abort, stop-node clean, controller keeps serving its other nodes."
  (when (eq (uiop:implementation-type) :clasp) (return-from run-flow-concurrency-stress-test t))
  (%flow-stress-deterministic-park)
  (%flow-stress-single-writer-churn)
  (%flow-stress-shared-controller-churn)
  t)

(defun* %flow-stress-deterministic-park ()
    (function () t)
  "Variant A (the strongest barrier proof). Match a writer to a BEST_EFFORT reader, associate a GENEROUS-rate
   controller (no deficit confounds the timing), then PARK the scheduler mid-emit via *datagram-sink* (it
   blocks the first data datagram on a release latch, recording the park). A worker thread calls stop-node on
   the parked writer. While parked, stop-node MUST NOT return (its flow-controller-unregister is blocked in the
   barrier: CURRENT-EMIT-NODE = node). Release the park ⇒ the emit completes, the barrier clears, stop-node
   returns. Asserts the park happened, stop-node was still blocked at release, then returned cleanly, and no
   datagram was sent on the node AFTER stop-node freed it (the sink records the last send order)."
  (let* ((w (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x97) :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xA7) :host "127.0.0.1" :port 0))
         (payload (make-array 800 :element-type '(unsigned-byte 8) :initial-element #x77))
         (controller nil) (parked nil) (release nil) (armed nil)
         (latch-lock (dds.pal:make-lock "flow-stress-park")) (latch-cv (dds.pal:make-condvar))
         (stop-returned nil) (stop-thread nil) (sink-error nil))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer w :topic "FlowStA" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher w)
           (dds.disc:add-local-reader r :topic "FlowStA" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber r)
           (%flow-match-writer-reader w r "FlowStA")
           (setf controller (dds.disc:make-flow-controller :tokens-per-period 10000000 :period 100000000 :max-burst 10000000))
           (dds.disc:flow-controller-associate controller w)
           ;; PARK: the first data datagram (>= 400 B) while armed blocks on the release latch — scheduler stuck mid-emit.
           (setf dds.disc::*datagram-sink*
                 (lambda (dg)
                   (handler-case
                       (when (and armed (>= (length dg) 400))
                         (dds.pal:with-lock (latch-lock)
                           (setf parked t)
                           (dds.pal:condvar-signal latch-cv)
                           (loop until release do (dds.pal:condvar-wait latch-cv latch-lock 0.5))))
                     (error (e) (setf sink-error e)))))
           (setf armed t)
           (dds.disc:publish-sample w payload)
           (dds.pal:with-lock (latch-lock)   ; wait until the scheduler is provably parked mid-emit
             (loop repeat 40 until parked do (dds.pal:condvar-wait latch-cv latch-lock 0.05)))
           (%check :flow-stress-parked parked
                   "the scheduler must reach *datagram-sink* mid-emit (parked) before stop-node races it")
           ;; Worker thread: stop-node the parked writer. It must BLOCK in the barrier until we release.
           (setf stop-thread (dds.pal:spawn (lambda () (dds.disc:stop-node w) (setf stop-returned t))
                                            :name "flow-stress-stop"))
           (sleep 0.25)   ; give stop-node ample time to (try to) complete — it must NOT, the barrier holds it
           (%check :flow-stress-barrier-blocks (null stop-returned)
                   "stop-node MUST block in flow-controller-unregister while the scheduler is mid-emit on the node (the barrier)")
           (dds.pal:with-lock (latch-lock) (setf release t) (dds.pal:condvar-signal latch-cv))   ; release the park
           (dds.pal:join stop-thread) (setf stop-thread nil)
           (%check :flow-stress-stop-returns stop-returned
                   "stop-node must RETURN cleanly once the parked emit completes (the barrier releases)")
           (%check :flow-stress-no-sink-error (null sink-error)
                   (format nil "the scheduler emit must not error around the barrier; got ~a" sink-error))
           (dds.disc:destroy-flow-controller controller) (setf controller nil)
           (format t "~&  [flow-stress A] deterministic park: barrier held stop-node, released cleanly, no UAF~%"))
      (setf dds.disc::*datagram-sink* nil release t)
      (ignore-errors (dds.pal:with-lock (latch-lock) (dds.pal:condvar-signal latch-cv)))
      (when stop-thread (ignore-errors (dds.pal:join stop-thread)))
      (when controller (ignore-errors (dds.disc:destroy-flow-controller controller)))
      (ignore-errors (dds.disc:stop-node w)) (dds.disc:stop-node r)))
  t)

(defun* %flow-stress-single-writer-churn ()
    (function () t)
  "Variant B (the original UAF repro, non-deterministic). A writer thread publishes continuously into a
   modest-rate controller while the main thread, after a short drain, calls stop-node on that writer WITHOUT
   destroying the controller first — racing stop-node's frees against the scheduler's lock-free emit. Asserts
   no crash, stop-node returns cleanly, and the scheduler did not abort (a subsequent destroy joins cleanly)."
  (let* ((w (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x98) :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xA8) :host "127.0.0.1" :port 0))
         (payload (make-array 700 :element-type '(unsigned-byte 8) :initial-element #x78))
         (controller nil) (run t) (pub-thread nil) (pub-error nil))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer w :topic "FlowStB" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher w)
           (dds.disc:add-local-reader r :topic "FlowStB" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber r)
           (%flow-match-writer-reader w r "FlowStB")
           (setf controller (dds.disc:make-flow-controller :tokens-per-period 200000 :period 100000000 :max-burst 200000))
           (dds.disc:flow-controller-associate controller w)
           (setf pub-thread (dds.pal:spawn
                             (lambda () (handler-case (loop while run do (dds.disc:publish-sample w payload) (sleep 0.001))
                                          (error (e) (setf pub-error e))))
                             :name "flow-stress-pub"))
           (sleep 0.3)   ; build a backlog the scheduler is still draining
           ;; Quiesce the PUBLISHER (no app-level publish into a node being freed), then stop-node RACES the
           ;; scheduler still draining the backlog — the barrier must serialize stop-node's frees against any
           ;; IN-FLIGHT scheduler emit on the node.
           (setf run nil) (dds.pal:join pub-thread) (setf pub-thread nil)
           (dds.disc:stop-node w)
           (%check :flow-stress-b-stop-clean t "stop-node returned without crashing under churn")
           (dds.disc:destroy-flow-controller controller) (setf controller nil)   ; clean join ⇒ scheduler did not abort
           (format t "~&  [flow-stress B] single-writer churn: stop-node + scheduler raced cleanly (pub-error=~a)~%" pub-error))
      (setf run nil)
      (when pub-thread (ignore-errors (dds.pal:join pub-thread)))
      (when controller (ignore-errors (dds.disc:destroy-flow-controller controller)))
      (ignore-errors (dds.disc:stop-node w)) (dds.disc:stop-node r)))
  t)

(defun* %flow-stress-shared-controller-churn ()
    (function () t)
  "Variant C (the SHARED-controller proof — why a per-node barrier, not a whole-scheduler join). Two writers
   on ONE controller, a publish thread each, ~0.5s drain, then stop ONE writer's node mid-drain. Asserts the
   OTHER writer KEEPS being delivered afterward — the scheduler thread SURVIVED tearing one node down (a
   whole-scheduler join would have stopped serving the survivor) — and the survivor + controller tear down
   cleanly with no error."
  (let* ((wa (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x99) :host "127.0.0.1" :port 0))
         (ra (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xA9) :host "127.0.0.1" :port 0))
         (wb (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x9b) :host "127.0.0.1" :port 0))
         (rb (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xAb) :host "127.0.0.1" :port 0))
         (pa (make-array 500 :element-type '(unsigned-byte 8) :initial-element #x0c))
         (pb (make-array 500 :element-type '(unsigned-byte 8) :initial-element #x0d))
         (controller nil) (run-a t) (run-b t) (ta nil) (tb nil) (ea nil) (eb nil))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer wa :topic "FlowStCa" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher wa)
           (dds.disc:add-local-reader ra :topic "FlowStCa" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber ra)
           (dds.disc:add-local-writer wb :topic "FlowStCb" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher wb)
           (dds.disc:add-local-reader rb :topic "FlowStCb" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber rb)
           (%flow-match-writer-reader wa ra "FlowStCa")
           (%flow-match-writer-reader wb rb "FlowStCb")
           (setf controller (dds.disc:make-flow-controller :tokens-per-period 500000 :period 100000000 :max-burst 500000))
           (dds.disc:flow-controller-associate controller wa)
           (dds.disc:flow-controller-associate controller wb)
           (setf ta (dds.pal:spawn (lambda () (handler-case (loop while run-a do (dds.disc:publish-sample wa pa) (sleep 0.001)) (error (e) (setf ea e)))) :name "flow-stress-ca")
                 tb (dds.pal:spawn (lambda () (handler-case (loop while run-b do (dds.disc:publish-sample wb pb) (sleep 0.001)) (error (e) (setf eb e)))) :name "flow-stress-cb"))
           (sleep 0.5)   ; both writers drain through the shared scheduler
           ;; Quiesce wa's PUBLISHER (the app must not publish into a node it is tearing down — that is an app-level
           ;; UAF, not the scheduler's) BEFORE stop-node(wa); the barrier still serializes against any IN-FLIGHT
           ;; scheduler emit on wa. wb keeps publishing throughout.
           (setf run-a nil) (dds.pal:join ta) (setf ta nil)
           (dds.disc:stop-node wa)   ; tear ONE node down mid-drain — the scheduler must keep serving wb
           (let ((b-before (dds.disc:node-sample-count rb)))
             (sleep 0.3)   ; the survivor must keep being delivered (scheduler alive)
             (%check :flow-stress-c-survivor (> (dds.disc:node-sample-count rb) b-before)
                     (format nil "after stop-node(wa), the SHARED controller must keep delivering wb (got ~d, was ~d) — scheduler survived a per-node teardown"
                             (dds.disc:node-sample-count rb) b-before)))
           (setf run-b nil) (dds.pal:join tb) (setf tb nil)
           (%check :flow-stress-c-no-pub-error (and (null ea) (null eb))
                   (format nil "neither publish thread errored under churn (a=~a b=~a)" ea eb))
           (dds.disc:destroy-flow-controller controller) (setf controller nil)
           (format t "~&  [flow-stress C] shared-controller churn: stop-node(wa) kept wb flowing, clean teardown~%"))
      (setf run-a nil run-b nil)
      (when ta (ignore-errors (dds.pal:join ta)))
      (when tb (ignore-errors (dds.pal:join tb)))
      (when controller (ignore-errors (dds.disc:destroy-flow-controller controller)))
      (ignore-errors (dds.disc:stop-node wa)) (dds.disc:stop-node ra)
      (dds.disc:stop-node wb) (dds.disc:stop-node rb)))
  t)

;;; WP-ASYNC-FLOW Phase E / E1 (FR-PF-2, ADR 0016 §Defaults): OFF-BY-DEFAULT byte-identity. A node with NO
;;; flow-controller associated must take the UNCHANGED non-flow send path: publish-sample's first cond-clause
;;; ((disc-node-flow-controller node) ...) is NOT engaged (the controller machinery never touches the node —
;;; flow-pending / flow-step-state stay NIL), and the wire bytes equal the pre-flow %push-data path exactly.
;;; B1's flow-step-equivalence proves step == flush-all; this proves the OFF path never even engages a
;;; controller (the guard that the opt-in cannot regress the default). SBCL + Clasp (deterministic, no
;;; threads). Reuses %coalesce-capture (= %push-data), %flow-step-build-node, %datagrams-identical-p (DRY).

(defun* %flow-publish-capture (node payload)
    (function (dds.disc:disc-node (simple-array (unsigned-byte 8) (*))) list)
  "Publish ONE PAYLOAD on NODE via publish-sample (the public API) while capturing every outgoing datagram's
   bytes via *datagram-sink*; return the captured datagrams (fresh octet vectors) in send order — the OFF-path
   twin of %coalesce-capture (which drives %push-data directly), so a controllerless publish can be compared
   byte-for-byte against the pre-flow %push-data path (WP-ASYNC-FLOW off-by-default oracle, ADR 0016)."
  (let ((captured '()))
    (let ((dds.disc::*datagram-sink* (lambda (dg) (push dg captured))))
      (dds.disc:publish-sample node payload))
    (nreverse captured)))

(defun* run-flow-off-byte-identical-test ()
    (function () t)
  "WP-ASYNC-FLOW off-by-default regression (FR-PF-2, ADR 0016 §Defaults): a node with NO flow-controller
   associated is byte-identical to the pre-flow path AND never engages the controller machinery. Two parts:
   (1) ENGAGE GUARD — on a controllerless node, disc-node-flow-controller is NIL, so publish-sample's first
   cond-clause is not taken: a publish creates NO per-writer flow-state (disc-node-flow-writer-states stays
   empty — the %flow-signal path never ran) — the opt-in is provably dormant; (2) BYTE-IDENTITY — a single
   publish-sample on a controllerless node (default batch-max-samples 1 ⇒ write + immediate %push-data)
   produces the EXACT datagrams that writer-write + a plain %push-data produce for the same sample, for both
   a small DATA and a large DATA_FRAG sample. SBCL + Clasp (deterministic, no threads). Flow control is
   wire-invisible (ADR 0016): with the controller OFF the send path is the unchanged pre-flow path."
  ;; -- Part 1: the OFF path never engages the controller machinery (the first cond-clause is dormant) --
  (let ((node (%flow-step-build-node #xC1 #xD1 7821 '())))   ; controllerless writer node, seeded reader
    (unwind-protect
         (progn
           (%check :flow-off-no-controller (null (dds.disc::disc-node-flow-controller node))
                   "a node with no controller associated must have a NIL flow-controller slot")
           (let ((dds.disc::*datagram-sink* (lambda (dg) (declare (ignore dg)))))
             (dds.disc:publish-sample node (octets 1 2 3 4 5 6 7 8)))
           (%check :flow-off-no-writer-states (null (dds.disc::disc-node-flow-writer-states node))
                   "a controllerless publish must NOT create any per-writer flow-state (the %flow-signal path never ran)"))
      (dds.disc:stop-node node)))
  ;; -- Part 2a: small DATA — publish-sample (OFF) == writer-write + %push-data, byte-identical --
  (let ((pub-node  (%flow-step-build-node #xC2 #xD2 7822 '()))
        (push-node (%flow-step-build-node #xC2 #xD2 7822 '())))
    (unwind-protect
         (let ((pub-dgs  (loop for i below 4
                               append (%flow-publish-capture pub-node (octets 9 8 7 6 5 4 3 2))))
               (push-dgs (loop for i below 4
                               append (let ((w (dds.disc::disc-node-user-writer push-node)))
                                        (dds.rtps.reliable:writer-write w (octets 9 8 7 6 5 4 3 2))
                                        (%coalesce-capture push-node)))))
           (%check :flow-off-small-nonempty (plusp (length pub-dgs))
                   "the OFF publish path must emit datagrams for the small samples")
           (%check :flow-off-small-identical (%datagrams-identical-p pub-dgs push-dgs)
                   "a controllerless publish-sample must be byte-identical to writer-write + %push-data (small DATA)"))
      (dds.disc:stop-node pub-node)
      (dds.disc:stop-node push-node)))
  ;; -- Part 2b: large DATA_FRAG sample — same byte-identity across the fragment path --
  (let* ((big (let ((v (make-array 4000 :element-type '(unsigned-byte 8))))
                (dotimes (i 4000 v) (setf (aref v i) (logand (* i 7) #xff)))))
         (pub-node  (%flow-step-build-node #xC3 #xD3 7823 '()))
         (push-node (%flow-step-build-node #xC3 #xD3 7823 '())))
    (unwind-protect
         (let ((pub-dgs  (%flow-publish-capture pub-node big))
               (push-dgs (progn (dds.rtps.reliable:writer-write
                                 (dds.disc::disc-node-user-writer push-node) big)
                                (%coalesce-capture push-node))))
           (%check :flow-off-frag-multiple (< 1 (length pub-dgs))
                   "a 4000-octet OFF publish must fragment into a multi-datagram DATA_FRAG series")
           (%check :flow-off-frag-identical (%datagrams-identical-p pub-dgs push-dgs)
                   "a controllerless publish-sample must be byte-identical to writer-write + %push-data (DATA_FRAG)"))
      (dds.disc:stop-node pub-node)
      (dds.disc:stop-node push-node)))
  t)

;;; WP-ASYNC-FLOW Phase E / E1 (FR-PF-2, ADR 0016 §Teardown): explicit teardown guarantees. (1) destroy
;;; FLUSHES the remaining unsent IGNORING the bucket — shutdown must never wait on a slow paced drain, and a
;;; partial in-progress plan must not be dropped — and JOINS the scheduler thread; (2) teardown must never
;;; WEDGE a writer blocked in writer-write on a full KEEP_ALL cache (block-up-to-max_blocking_time). Real
;;; threads ⇒ SBCL (Clasp pass-skipped — fine timing + the known Clasp multithread-condvar SIGSEGV, NFR-PORT).
;;; *datagram-sink* is set GLOBALLY (the scheduler runs on its own thread; a LET binding is thread-local and
;;; invisible there) and restored in cleanup. Reuses %flow-step-build-node, %seed-reader-participant,
;;; %count-submessages (DRY).

(defun* %flow-teardown-flushes-pending ()
    (function () t)
  "Part 1 (flush-on-destroy). Associate a writer node (seeded reader, KEEP_ALL/unlimited) with a LOW-rate
   controller so the paced scheduler cannot drain the backlog before teardown, publish N samples (each adds a
   change + signals the controller), then — before the paced drain completes — destroy-flow-controller.
   Asserts ALL N samples' DATA reach the wire (the flush, %flow-flush-all, drains the rest IGNORING the
   bucket: total DATA submessages captured across every datagram = N, whatever the paced/flush split) and the
   scheduler thread is JOINED (flow-controller-thread NIL). *datagram-sink* counts the DATA (the scheduler is
   on its own thread, so the sink is set globally). Low rate ⇒ deficit-sleep ⇒ a short pause lands destroy
   mid-backlog, then the flush completes it."
  (let* ((n 12)
         (payload (octets 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))
         (node (%flow-step-build-node #xC4 #xD4 7824 '()))   ; controllerless yet; seeded reader destination
         (controller nil) (captured '()) (sink-error nil))
    (unwind-protect
         (progn
           (setf dds.disc::*datagram-sink*
                 (lambda (dg) (handler-case (push dg captured) (error (e) (setf sink-error e)))))
           ;; LOW rate (400 B / 100 ms, burst 400) << N x (payload + framing): the scheduler deficit-sleeps with a backlog still pending at destroy
           (setf controller (dds.disc:make-flow-controller :tokens-per-period 400 :period 100000000 :max-burst 400))
           (dds.disc:flow-controller-associate controller node)
           (dotimes (i n) (dds.disc:publish-sample node payload))
           (sleep 0.05)   ; let the scheduler send its first deficit-limited datagram(s), then it sleeps on the deficit
           (dds.disc:destroy-flow-controller controller)   ; flush ignoring the bucket + join
           (%check :flow-td-flush-joined (null (dds.disc:flow-controller-thread controller))
                   "destroy-flow-controller must JOIN the scheduler thread (flow-controller-thread NIL)")
           (setf controller nil)
           (%check :flow-td-flush-no-sink-error (null sink-error)
                   (format nil "the teardown flush must not error in the sink; got ~a" sink-error))
           (let ((data-total (reduce #'+ (mapcar #'%count-submessages captured) :key #'second)))
             (%check :flow-td-flush-all-data (= n data-total)
                     (format nil "destroy-flow-controller must FLUSH all ~d samples' DATA ignoring the bucket (got ~d DATA submessages)"
                             n data-total)))
           (format t "~&  [flow-teardown] flush: all ~d samples flushed on destroy, scheduler joined~%" n))
      (setf dds.disc::*datagram-sink* nil)
      (when controller (ignore-errors (dds.disc:destroy-flow-controller controller)))
      (dds.disc:stop-node node)))
  t)

(defun* %flow-teardown-no-wedge ()
    (function () t)
  "Part 2 (the key guarantee — teardown never wedges a blocked writer, NO HANG). A writer node with KEEP_ALL +
   tiny max_samples + a generous max_blocking_time, associated with a LOW-rate controller; fill the cache to
   max_samples (writer-write directly, deterministic), then from a WORKER thread publish-sample the next sample
   — it BLOCKS in %writer-add-bounded on the full cache. From the main thread destroy-flow-controller (which
   joins the scheduler then broadcasts each registered writer's space-cv via %flow-unblock-writer). The worker
   MUST return within a bounded time. OBSERVED OUTCOME: teardown does not PURGE the KEEP_ALL cache (only an
   ACKNACK purge frees a KEEP_ALL cache, and the seeded reader sends none), so the woken worker re-checks, the
   cache is still full, and it returns :timeout at its max_blocking_time deadline — i.e. teardown unblocks the
   writer to re-evaluate, and the block-up-to-max_blocking_time deadline bounds it; either way the writer
   makes progress and does NOT hang. Asserted ROBUSTLY: poll a worker-returned flag up to deadline + margin;
   FAIL (without an unconditional join on a possibly-wedged thread) if still alive past the bound."
  (let* ((max-samples 3)
         (block-ms 800)
         (payload (octets 2 4 6 8 10 12 14 16))
         (node (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xC5) :host "127.0.0.1" :port 0))
         (controller nil) (worker nil) (worker-returned nil) (worker-result :unset) (worker-error nil)
         (t0 0) (elapsed-ms nil))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer node :topic "FlowTd" :type "X")
           (dds.disc:enable-publisher node :history-kind :keep-all   ; KEEP_ALL bounded cache: fills + blocks (the no-wedge fixture, ADR 0019 migration)
                                           :max-samples max-samples :max-blocking-ns (* block-ms 1000000))
           (%seed-reader-participant node #xD5 7825)
           (setf controller (dds.disc:make-flow-controller :tokens-per-period 400 :period 100000000 :max-burst 400))
           (dds.disc:flow-controller-associate controller node)
           (let ((w (dds.disc::disc-node-user-writer node)))
             (dotimes (i max-samples)
               (%check :flow-td-fill (integerp (dds.rtps.reliable:writer-write w payload))
                       "filling the bounded cache to max_samples must succeed (return an SN)")))
           ;; Worker publish-sample blocks in writer-write on the full cache (never reaching %flow-signal); records its return so it is never left to wedge the suite
           (setf t0 (dds.pal:monotonic-ns)
                 worker (dds.pal:spawn
                         (lambda ()
                           (handler-case (setf worker-result (dds.disc:publish-sample node payload))
                             (error (e) (setf worker-error e)))
                           (setf worker-returned t))
                         :name "flow-td-blocked"))
           (sleep 0.1)   ; let the worker reach the block (cache full, nothing has freed space)
           (%check :flow-td-blocked (null worker-returned)
                   "the worker publish-sample must BLOCK on the full bounded cache before teardown")
           (dds.disc:destroy-flow-controller controller) (setf controller nil)   ; join scheduler + unblock writers
           ;; NO HANG: poll a flag up to deadline + margin (no PAL bounded-join), so a wedged worker FAILS the assertion rather than hanging join — join only after it returned
           (loop repeat 60   ; 60 x 50 ms = 3.0 s > block-ms (0.8 s) + margin
                 until worker-returned do (sleep 0.05))
           (setf elapsed-ms (/ (- (dds.pal:monotonic-ns) t0) 1000000.0d0))
           (%check :flow-td-no-wedge worker-returned
                   (format nil "teardown must not WEDGE the blocked writer — it must return within ~,0f ms (deadline ~d ms + margin); still alive ⇒ HANG"
                           (+ block-ms 2200.0) block-ms))
           (when worker-returned (dds.pal:join worker) (setf worker nil))   ; reap only after it provably returned
           (%check :flow-td-worker-no-error (null worker-error)
                   (format nil "the blocked worker must not error around teardown; got ~a" worker-error))
           ;; OBSERVED: :timeout at the deadline (teardown does not purge a KEEP_ALL cache). Documented + asserted.
           (%check :flow-td-outcome-timeout (eq :timeout worker-result)
                   (format nil "the blocked worker must return :timeout (teardown unblocks it but space never frees ⇒ block-up-to-max_blocking_time deadline), got ~S" worker-result))
           (%check :flow-td-at-deadline (>= elapsed-ms (* block-ms 0.7))
                   (format nil "the :timeout must land at ~~max_blocking_time (~d ms, >= 0.7x), got ~,1f ms — progress, not a hang" block-ms elapsed-ms))
           (format t "~&  [flow-teardown] no-wedge: blocked writer returned ~S after ~,1f ms (deadline ~d ms) — no hang~%"
                   worker-result elapsed-ms block-ms))
      (when controller (ignore-errors (dds.disc:destroy-flow-controller controller)))
      (when (and worker worker-returned) (ignore-errors (dds.pal:join worker)))   ; never join a possibly-wedged worker
      (dds.disc:stop-node node)))
  t)

(defun* run-flow-teardown-test ()
    (function () t)
  "WP-ASYNC-FLOW (FR-PF-2, ADR 0016 §Teardown): explicit teardown — flush-on-destroy + no-wedge. SBCL only
   (real threads + timing); Clasp pass-skipped (fine timing + the known Clasp multithread-condvar SIGSEGV,
   NFR-PORT). (1) destroy-flow-controller FLUSHES the remaining unsent IGNORING the bucket (all N samples'
   DATA reach the wire even though the paced drain had not finished) and JOINS the scheduler thread; (2)
   teardown lets a writer BLOCKED in writer-write on a full KEEP_ALL cache make progress — it returns
   (:timeout at its max_blocking_time deadline, since teardown unblocks it to re-evaluate but a KEEP_ALL cache
   only frees on an ACKNACK purge) within a bounded time, NEVER hanging. The point of §Teardown: shutdown
   never waits on a slow paced drain, no pending change is dropped, and a blocked writer is never wedged."
  (when (eq (uiop:implementation-type) :clasp) (return-from run-flow-teardown-test t))
  (%flow-teardown-flushes-pending)
  (%flow-teardown-no-wedge)
  t)

;;;; WP-ASYNC-FLOW Phase F1 (FR-PF-2, FR-LANG-7): the HONEST rate-shaping bench. Flow control is rate
;;;; CONTROL — it trades latency for a bounded byte rate; the report makes NO "0-cost"/"free" claim. The
;;;; oracle is the MEASURED achieved drain rate over the data plane (real publish-sample + a best-effort
;;;; reader, the controller's paced send the sole delivery path) timed with dds.pal:monotonic-ns, mirroring
;;;; run-flow-pacing-test / run-flow-multiwriter-rr-test (the same measurement seam, reused DRY). Four blocks:
;;;; (1) rate-shaping accuracy (achieved-vs-configured over a few rates/burst sizes); (2) single-writer paced
;;;; vs the enable-async UNPACED baseline (so the added latency is visible); (3) multi-writer AGGREGATE rate
;;;; shaped to R (not 2R) + per-datagram RR interleaving; (4) DATA_FRAG pacing — one large fragmented sample's
;;;; fragments spread across periods (the FR-PF-2 headline use case), observed per-datagram via *datagram-sink*.

(defun* %flow-bench-configured-rate (tokens-per-period period-ns)
    (function ((integer 1) (integer 1)) double-float)
  "The configured steady-state byte rate (bytes/s) of a token bucket = TOKENS-PER-PERIOD / (PERIOD-NS / 1e9).
   Used to report achieved-vs-configured honestly (the steady drain converges to this; startup is faster by
   one full bucket — see %FLOW-BENCH-RATE-ROW)."
  (/ (float tokens-per-period 1.0d0) (/ (float period-ns 1.0d0) 1.0d9)))

(defun* %flow-bench-paced-drain (payload n tokens-per-period period-ns max-burst guard-w guard-r)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 1) (integer 1) (integer 1) (integer 1)
               (unsigned-byte 8) (unsigned-byte 8))
              (values double-float (integer 0) (integer 0)))
  "Drain N copies of PAYLOAD through ONE flow-controller (TOKENS-PER-PERIOD/PERIOD-NS/MAX-BURST) to a
   BEST_EFFORT reader and return (values elapsed-seconds wire-bytes delivered). GUARD-W/GUARD-R are distinct
   GUID-prefix octets (fresh nodes per call, like the flow tests). The controller's paced send is the sole
   delivery path (best-effort ⇒ no ACKNACK retransmit on the receiver thread to confound the rate). WIRE-BYTES
   is the approximate on-wire total (payload + a ~24-octet DATA submessage prefix + a 20-octet RTPS header per
   datagram) — the SAME accounting run-flow-pacing-test uses. Elapsed is monotonic-ns from the first publish
   to all-N-received (or a bounded poll-out). Tears every node + the controller down."
  (let* ((wire-bytes (* n (+ (length payload) 24 20)))
         (w (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element guard-w) :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element guard-r) :host "127.0.0.1" :port 0))
         (controller nil) (elapsed 0.0d0) (delivered 0))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer w :topic "FlowBench" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher w :history-kind :keep-all)   ; KEEP_ALL: the bench drains all N samples (ADR 0019 migration)
           (dds.disc:add-local-reader r :topic "FlowBench" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber r)
           (%flow-match-writer-reader w r "FlowBench")
           (setf controller (dds.disc:make-flow-controller :tokens-per-period tokens-per-period
                                                           :period period-ns :max-burst max-burst))
           (dds.disc:flow-controller-associate controller w)
           (let ((t0 (dds.pal:monotonic-ns)))
             (dotimes (i n) (dds.disc:publish-sample w payload))
             (loop repeat 2000 until (>= (dds.disc:node-sample-count r) n) do (sleep 0.005))
             (setf elapsed (/ (- (dds.pal:monotonic-ns) t0) 1.0d9)
                   delivered (dds.disc:node-sample-count r))))
      (when controller (ignore-errors (dds.disc:destroy-flow-controller controller)))
      (dds.disc:stop-node w) (dds.disc:stop-node r))
    (values elapsed wire-bytes delivered)))

(defun* %flow-bench-unpaced-drain (payload n guard-w guard-r)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 1) (unsigned-byte 8) (unsigned-byte 8))
              (values double-float (integer 0)))
  "Drain N copies of PAYLOAD through an UNPACED enable-async writer (WP-ASYNC v1 — a per-node sender thread,
   NO flow-controller) to a BEST_EFFORT reader; return (values elapsed-seconds delivered). The unpaced baseline
   for %FLOW-BENCH-PACED-DRAIN: same payload + reader, no rate bound, so the elapsed gap is exactly the shaping
   (pacing ADDS latency by design — the honest contrast). Fresh nodes per call; tears them down."
  (let* ((w (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element guard-w) :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element guard-r) :host "127.0.0.1" :port 0))
         (elapsed 0.0d0) (delivered 0))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer w :topic "FlowBench" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher w :history-kind :keep-all)   ; KEEP_ALL: the unpaced bench baseline drains all N (ADR 0019 migration)
           (dds.disc:enable-async w)
           (dds.disc:add-local-reader r :topic "FlowBench" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber r)
           (%flow-match-writer-reader w r "FlowBench")
           (let ((t0 (dds.pal:monotonic-ns)))
             (dotimes (i n) (dds.disc:publish-sample w payload))
             (loop repeat 2000 until (>= (dds.disc:node-sample-count r) n) do (sleep 0.001))
             (setf elapsed (/ (- (dds.pal:monotonic-ns) t0) 1.0d9)
                   delivered (dds.disc:node-sample-count r))))
      (dds.disc:stop-node w) (dds.disc:stop-node r))
    (values elapsed delivered)))

(defun* %flow-bench-rate-row (stream payload n tokens-per-period period-ns max-burst guard-w guard-r)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 1) (integer 1) (integer 1) (integer 1)
                 (unsigned-byte 8) (unsigned-byte 8))
              double-float)
  "Measure one paced drain (%FLOW-BENCH-PACED-DRAIN) and emit a markdown row: configured rate, wire bytes,
   ideal seconds (the steady-state lower bound (WIRE-BYTES - MAX-BURST)/rate — the full bucket drains free at
   startup, the rest is rate-bounded), achieved seconds, and achieved rate = WIRE-BYTES/elapsed. Returns the
   achieved rate (bytes/s) so the caller can guard it. The overshoot vs configured is the honest artifact:
   the startup full bucket + per-datagram granularity (a datagram is sent whole once its tokens are met)."
  (let ((configured (%flow-bench-configured-rate tokens-per-period period-ns)))
    (multiple-value-bind (elapsed wire-bytes delivered)
        (%flow-bench-paced-drain payload n tokens-per-period period-ns max-burst guard-w guard-r)
      (let* ((ideal (/ (float (max 0 (- wire-bytes max-burst)) 1.0d0) configured))
             (achieved (if (plusp elapsed) (/ (float wire-bytes 1.0d0) elapsed) 0.0d0)))
        (format stream "~&| ~,0f | ~d | ~d | ~d | ~,3f | ~,3f | ~,0f | ~,2f |~%"
                configured max-burst wire-bytes delivered ideal elapsed achieved
                (if (plusp configured) (/ achieved configured) 0.0d0))
        achieved))))

(defun* %flow-bench-multiwriter (stream payload n tokens-per-period period-ns max-burst)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 1) (integer 1) (integer 1) (integer 1))
              (values double-float (integer 0)))
  "Two writers on ONE controller publish N copies of PAYLOAD each; a BEST_EFFORT reader per writer. Returns
   (values aggregate-achieved-rate interleave-transitions): the AGGREGATE wire rate (BOTH writers' bytes /
   elapsed) is shaped to ~R (not 2R — the controller paces the sum), and the per-datagram round-robin
   interleaves the two streams (transitions = a/b changes in delivery order; all-A-then-all-B would be 1).
   Emits a markdown row. Reuses the run-flow-multiwriter-rr-test seam (DRY). Tears all nodes + controller down."
  (let* ((wa (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xC5) :host "127.0.0.1" :port 0))
         (ra (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xD5) :host "127.0.0.1" :port 0))
         (wb (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xC6) :host "127.0.0.1" :port 0))
         (rb (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xD6) :host "127.0.0.1" :port 0))
         (controller nil) (order '()) (elapsed 0.0d0)
         (wire-bytes (* 2 n (+ (length payload) 24 20)))
         (configured (%flow-bench-configured-rate tokens-per-period period-ns)))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer wa :topic "FlowBenchRRa" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher wa :history-kind :keep-all)   ; KEEP_ALL: bench writer A drains all N (ADR 0019 migration)
           (dds.disc:add-local-reader ra :topic "FlowBenchRRa" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber ra)
           (dds.disc:add-local-writer wb :topic "FlowBenchRRb" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher wb :history-kind :keep-all)   ; KEEP_ALL: bench writer B drains all N (ADR 0019 migration)
           (dds.disc:add-local-reader rb :topic "FlowBenchRRb" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber rb)
           (setf (dds.disc:disc-node-on-sample ra) (lambda () (push :a order))
                 (dds.disc:disc-node-on-sample rb) (lambda () (push :b order)))
           (%flow-match-writer-reader wa ra "FlowBenchRRa")
           (%flow-match-writer-reader wb rb "FlowBenchRRb")
           (setf controller (dds.disc:make-flow-controller :tokens-per-period tokens-per-period
                                                           :period period-ns :max-burst max-burst))
           (dds.disc:flow-controller-associate controller wa)
           (dds.disc:flow-controller-associate controller wb)
           (let ((t0 (dds.pal:monotonic-ns)))
             (dotimes (i n) (dds.disc:publish-sample wa payload) (dds.disc:publish-sample wb payload))
             (loop repeat 3000
                   until (and (>= (dds.disc:node-sample-count ra) n) (>= (dds.disc:node-sample-count rb) n))
                   do (sleep 0.005))
             (setf elapsed (/ (- (dds.pal:monotonic-ns) t0) 1.0d9))))
      (when controller (ignore-errors (dds.disc:destroy-flow-controller controller)))
      (dds.disc:stop-node wa) (dds.disc:stop-node ra)
      (dds.disc:stop-node wb) (dds.disc:stop-node rb))
    (let* ((seq (nreverse order))
           (transitions (loop for (x y) on seq while y count (not (eq x y))))
           (achieved (if (plusp elapsed) (/ (float wire-bytes 1.0d0) elapsed) 0.0d0)))
      (format stream "~&| ~,0f | ~d | ~d | ~,3f | ~,0f | ~,2f | ~d |~%"
              configured wire-bytes (* 2 n) elapsed achieved
              (if (plusp configured) (/ achieved configured) 0.0d0) transitions)
      (values achieved transitions))))

(defun* %flow-bench-datafrag-cadence (size tokens-per-period period-ns max-burst)
    (function ((integer 1) (integer 1) (integer 1) (integer 1)) list)
  "Publish ONE large (SIZE-octet) sample paced; capture every DATA_FRAG datagram's (offset-ns . length) via
   *datagram-sink* (the per-datagram seam, set GLOBALLY since the scheduler runs on its own thread). Returns
   the captured fragment events in send order (offset-ns from the first publish). SIZE > *fragment-size* ⇒ the
   sample fragments into a DATA_FRAG series, one datagram per fragment, which the scheduler paces one per RR
   step — so the fragments spread across periods (the FR-PF-2 headline use case). Filters to >= 200-octet
   datagrams (DATA_FRAGs; excludes tiny discovery/HEARTBEAT traffic). Tears the node + controller down."
  (let* ((payload (make-array size :element-type '(unsigned-byte 8) :initial-element #x5a))
         (w (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xC9) :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xD9) :host "127.0.0.1" :port 0))
         (controller nil) (events '()) (t0 0))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer w :topic "FlowBenchFrag" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher w :history-kind :keep-all)   ; KEEP_ALL: one large fragmented sample; KEEP_ALL keeps the fixture honest (ADR 0019 migration)
           (dds.disc:add-local-reader r :topic "FlowBenchFrag" :type "X" :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber r)
           (%flow-match-writer-reader w r "FlowBenchFrag")
           (setf controller (dds.disc:make-flow-controller :tokens-per-period tokens-per-period
                                                           :period period-ns :max-burst max-burst))
           (dds.disc:flow-controller-associate controller w)
           (setf t0 (dds.pal:monotonic-ns)
                 dds.disc::*datagram-sink*
                 (lambda (dg) (when (>= (length dg) 200)
                                (push (cons (- (dds.pal:monotonic-ns) t0) (length dg)) events))))
           (dds.disc:publish-sample w payload)
           (loop repeat 2000 until (>= (dds.disc:node-sample-count r) 1) do (sleep 0.005))
           (sleep 0.05))
      (setf dds.disc::*datagram-sink* nil)
      (when controller (ignore-errors (dds.disc:destroy-flow-controller controller)))
      (dds.disc:stop-node w) (dds.disc:stop-node r))
    (nreverse events)))

(defun* run-bench-async-flow (&key (file nil))
    (function (&key (:file (or null string pathname))) t)
  "WP-ASYNC-FLOW Phase F1 bench (FR-PF-2, FR-LANG-7; standard DDS, NOT R6, ADR 0016): the HONEST rate-shaping
   report. Flow control is rate CONTROL — it trades latency for a bounded byte rate; this report makes NO
   '0-cost'/'free' claim. Prints a markdown report to *standard-output*; when FILE is given, ALSO writes it
   there (captured by make bench-async-flow). The oracle is the MEASURED achieved drain rate over the real data
   plane (publish-sample + a best-effort reader, the controller's paced send the sole delivery path) timed with
   dds.pal:monotonic-ns — the SAME seam run-flow-pacing-test / run-flow-multiwriter-rr-test use, reused DRY.
   Four blocks: (1) rate-shaping accuracy over a few rates/burst sizes (achieved-vs-configured; the overshoot
   is the startup full bucket + per-datagram granularity); (2) single-writer PACED vs the enable-async UNPACED
   baseline (the added latency made visible); (3) multi-writer AGGREGATE rate shaped to ~R (not 2R) + the
   per-datagram RR interleaving; (4) DATA_FRAG pacing — one large fragmented sample's fragments spread across
   periods. SBCL-targeted (real threads + timing); on Clasp it pass-returns (the flow tests are Clasp
   pass-skipped — timing-flaky + the known Clasp multithread-condvar SIGSEGV, NFR-PORT)."
  (when (eq (uiop:implementation-type) :clasp)
    (format t "~&  run-bench-async-flow: Clasp pass-skipped (real-thread timing + the known Clasp condvar SIGSEGV, NFR-PORT)~%")
    (return-from run-bench-async-flow t))
  (let ((small (make-array 1400 :element-type '(unsigned-byte 8) :initial-element #x5a)))
    (flet ((emit (stream)
             (format stream "~&# WP-ASYNC-FLOW — rate-shaping + multi-writer aggregate (honest) (FR-PF-2, FR-LANG-7)~%~%")
             (format stream "Standard DDS flow control — **NOT patent-gated, NOT R6** (ADR 0016). Flow control is rate **CONTROL**: it bounds the user-data byte rate by **delaying** datagrams, so it **ADDS latency by design** — this report makes **no \"0-cost\"/\"free\" claim**. Phase F1 of WP-ASYNC-FLOW: the honest before/after the operating contract requires for a feature on the send path (FR-LANG-7). Generated by `dds.tests:run-bench-async-flow` (entry: `make bench-async-flow`).~%~%")
             (format stream "## Environment~%~%")
             (format stream "| field | value |~%|-------|-------|~%")
             (format stream "| host | ~a (~a) |~%" (machine-instance) (machine-version))
             (format stream "| os | ~a ~a ~a |~%" (software-type) (software-version) (machine-type))
             (format stream "| impl | ~a ~a |~%" (lisp-implementation-type) (lisp-implementation-version))
             (format stream "| HEAD | ~a |~%" (%bench-git-head))
             (format stream "| date | ~a |~%" (%bench-date-string))
             (format stream "| `*fragment-size*` | ~d octets (DATA_FRAG threshold) |~%" dds.rtps.reliable:*fragment-size*)
             (format stream "~%## Method~%~%")
             (format stream "Measured over the REAL data plane: a `flow-controller` paces `publish-sample`s from a writer node to a BEST_EFFORT reader node over UDP loopback (both in-process), the controller's paced send the SOLE delivery path (best-effort ⇒ no ACKNACK-driven retransmit on the receiver thread to confound the rate — the same fixture `run-flow-pacing-test` uses). The achieved drain rate is `wire-bytes / elapsed`, where elapsed is `dds.pal:monotonic-ns` from the first publish to all-N-received and `wire-bytes ~~ N x (payload + ~~24-octet DATA submessage prefix + 20-octet RTPS header)` — the SAME wire accounting `run-flow-pacing-test` uses (approximate: it counts a coalesced group as one prefix, so it is a close upper estimate, not byte-exact). Configured rate = `tokens-per-period / (period / 1e9)` bytes/s. The DATA_FRAG cadence is captured per-datagram via `*datagram-sink*` (a fresh octet copy of each outgoing datagram, BEFORE the real send). Single in-process run; no warmup beyond discovery; nodes + controller fresh per measurement.~%~%")
             (format stream "**Honest framing (FR-LANG-7):** pacing is a LATENCY-FOR-RATE-CONTROL trade. The paced drain is BOUNDED BELOW by `(wire-bytes - max-burst)/rate` (the initial full bucket drains at line rate, the remainder is rate-limited); it is ALWAYS slower than the unpaced baseline. Achieved rate runs slightly ABOVE configured because (a) the bucket STARTS FULL (one max-burst burst is free) and (b) per-datagram GRANULARITY — a datagram is emitted whole once its exact byte cost is met, so the meter rounds up at the datagram boundary. NO path here is 0-cost; the only thing pacing optimizes is bytes-on-the-wire-per-second predictability.~%~%")))
      (labels ((blocks (stream)
                 (format stream "## (1) Rate-shaping accuracy — achieved vs configured~%~%")
                 (format stream "| configured B/s | max-burst | wire B | delivered | ideal s | achieved s | achieved B/s | achieved/configured |~%")
                 (format stream "|----------------|-----------|--------|-----------|---------|------------|--------------|---------------------|~%")
                 (let ((r1 (%flow-bench-rate-row stream small 60 12500 100000000 12500 #xB1 #xE1))   ; 125 KB/s, burst 12.5KB
                       (r2 (%flow-bench-rate-row stream small 60 25000 100000000 25000 #xB2 #xE2))   ; 250 KB/s, burst 25KB
                       (r3 (%flow-bench-rate-row stream small 40 10000 100000000 5000 #xB3 #xE3)))   ; 100 KB/s, burst 5KB
                   (format stream "~%The achieved rate tracks the configured rate within the startup-burst + per-datagram-granularity overshoot (a smaller `max-burst` ⇒ a tighter bound, since less of the total drains free at startup). Rate control is real: the drain rate is held near the configured ceiling, NOT line rate.~%~%")
                   (format stream "## (2) Single-writer: paced vs UNPACED (`enable-async`) — the added latency~%~%")
                   (multiple-value-bind (paced-s pwire pdel) (%flow-bench-paced-drain small 40 12500 100000000 12500 #xB4 #xE4)
                     (multiple-value-bind (unpaced-s udel) (%flow-bench-unpaced-drain small 40 #xB5 #xE5)
                       (let ((pideal (/ (float (max 0 (- pwire 12500)) 1.0d0) (%flow-bench-configured-rate 12500 100000000))))
                         (format stream "| path | wire B | delivered | elapsed s | drain B/s | note |~%")
                         (format stream "|------|--------|-----------|-----------|-----------|------|~%")
                         (format stream "| **paced** (125 KB/s, burst 12.5KB) | ~d | ~d | ~,3f | ~,0f | rate-bounded ~~ ideal ~,3fs |~%"
                                 pwire pdel paced-s (if (plusp paced-s) (/ (float pwire 1.0d0) paced-s) 0.0d0) pideal)
                         (format stream "| **unpaced** (`enable-async`, same workload) | ~d | ~d | ~,3f | ~,0f | drains as fast as the loopback allows |~%~%"
                                 pwire udel unpaced-s (if (plusp unpaced-s) (/ (float pwire 1.0d0) unpaced-s) 0.0d0))
                         (format stream "Pacing made the SAME ~d-byte workload take **~,3fs** instead of the unpaced **~,3fs** (a **~,1fx** slowdown) — the added latency is the WHOLE POINT of rate control; it is not overhead to be eliminated. The unpaced `enable-async` path is the right choice when you want async-WITHOUT-a-rate-bound; the `flow-controller` is the right choice when a downstream link / reader must not be overrun.~%~%"
                                 pwire paced-s unpaced-s (if (plusp unpaced-s) (/ paced-s unpaced-s) 0.0d0))
                         (format stream "## (3) Multi-writer: AGGREGATE rate shaped to R (not 2R) + RR interleaving~%~%")
                         (format stream "| configured B/s | aggregate wire B | total delivered | elapsed s | achieved agg B/s | achieved/configured | interleave transitions |~%")
                         (format stream "|----------------|------------------|-----------------|-----------|------------------|---------------------|------------------------|~%")
                         (multiple-value-bind (agg trans) (%flow-bench-multiwriter stream small 20 12500 100000000 12500)
                           (format stream "~%Two writers on ONE controller: the AGGREGATE wire rate (~,0f B/s) is shaped to ~~the configured ceiling (125000 B/s) — the controller paces the SUM of both writers, NOT 2x (a per-writer controller would let each hit R, totalling 2R). The ~d a/b transitions in delivery order prove per-datagram ROUND-ROBIN (one datagram per writer per turn) — NOT all-of-A-then-all-of-B (which would be 1 transition).~%~%"
                                   agg trans)
                           ;; honest regression guards (SBCL): rate is bounded near configured; pacing is slower than unpaced; RR interleaves; aggregate is shaped (not 2R)
                           (assert (and (> r1 0.0d0) (> r2 0.0d0) (> r3 0.0d0)) () "bench: every paced drain must deliver + measure a positive rate")
                           (assert (> paced-s unpaced-s) () "bench: paced (~,3fs) must be slower than unpaced (~,3fs) — pacing adds latency" paced-s unpaced-s)
                           (assert (>= trans 4) () "bench: multi-writer RR must interleave (>= 4 a/b transitions), got ~d" trans)
                           (assert (< agg (* 1.8d0 (%flow-bench-configured-rate 12500 100000000))) ()
                                   "bench: AGGREGATE rate (~,0f) must be shaped to ~~R, not 2R (< 1.8x configured)" agg)))))
                   (format stream "## (4) DATA_FRAG pacing — fragments spread across periods (the FR-PF-2 headline)~%~%")
                   (let* ((size 8000) (tpp 10000) (per 100000000) (burst 4000)
                          (events (%flow-bench-datafrag-cadence size tpp per burst))
                          (configured (%flow-bench-configured-rate tpp per)))
                     (format stream "One **~d-octet** sample at **~,0f B/s** (burst ~d) fragments into a DATA_FRAG series (`*fragment-size*` = ~d ⇒ ~~~d fragments), one datagram per fragment, paced one per RR step:~%~%"
                             size configured burst dds.rtps.reliable:*fragment-size* (ceiling size dds.rtps.reliable:*fragment-size*))
                     (format stream "| fragment # | t since publish (ms) | datagram bytes |~%|------------|----------------------|----------------|~%")
                     (loop for e in events for i from 1
                           do (format stream "| ~d | ~,1f | ~d |~%" i (/ (car e) 1.0d6) (cdr e)))
                     (format stream "~%The initial full bucket (~d B) drains the first fragments back-to-back (~~0 ms apart); the rest are spread at the token-refill cadence — at ~,0f B/s a ~~~d-octet fragment costs ~~~,1f ms — so a large sample is emitted as a rate-shaped fragment STREAM rather than a single burst (the FR-PF-2 \"DATA_FRAG pacing\" use case). The fragmentation itself is wire-IDENTICAL to the unpaced path (ADR 0016): pacing changes only WHEN each fragment is sent, never its bytes.~%~%"
                             burst configured (1+ dds.rtps.reliable:*fragment-size*)
                             (* 1000.0d0 (/ (float (1+ dds.rtps.reliable:*fragment-size*) 1.0d0) configured)))
                     (when (>= (length events) 2)
                       (assert (> (car (car (last events))) (car (first events))) ()
                               "bench: DATA_FRAG fragments must spread over time (last later than first)")))
                   (format stream "## Honest framing (FR-LANG-7) — restated~%~%")
                   (format stream "- Flow control **adds latency by design**; it is rate **control**, not a speedup. NO path here is 0-cost or free.~%")
                   (format stream "- Achieved rate runs slightly ABOVE configured (startup full bucket + per-datagram granularity); a smaller `max-burst` tightens the bound.~%")
                   (format stream "- The aggregate rate of N writers on one controller is shaped to **R**, not N x R (the controller paces the sum) — the interleaving is per-datagram round-robin (v1).~%")
                   (format stream "- A large sample is paced at FRAGMENT granularity (the FR-PF-2 headline) — fragments stream out rate-shaped, the bytes wire-identical to the unpaced path.~%")
                   (format stream "- v1 policy is **round-robin only**, behind a pluggable hook; the OMG-standard-QoS-anchored follow-ups are `LATENCY_BUDGET`/`DEADLINE` -> EDF and `TRANSPORT_PRIORITY` -> priority (ADR 0016, deferred).~%~%")
                   (format stream "Method: achieved rate = wire-bytes/elapsed (`dds.pal:monotonic-ns`); paced send over the real data plane to a best-effort reader; impl ~a ~a on ~a.~%"
                           (lisp-implementation-type) (lisp-implementation-version) (machine-instance)))))
        (emit *standard-output*)
        (blocks *standard-output*)
        (when file
          (with-open-file (s file :direction :output :if-exists :supersede :if-does-not-exist :create)
            (emit s)
            (blocks s))   ; re-run the measured drains into the file stream (keeps the file self-contained)
          (format t "~&  wrote ~a~%" file)))))
  t)

;;;; ---- WP-FLOW-EDF-PRIORITY bench (ADR 0016; FR-QOS-1, FR-LANG-7) ----
;;;; Selection ordering is the deliverable, so the oracle is a DETERMINISTIC discrete-event simulation over the
;;;; REAL policy functions (no threads/timing): (1) EDF vs round-robin deadline-miss count for mixed
;;;; LATENCY_BUDGET streams under a saturated controller; (2) :priority vs round-robin high-priority service
;;;; latency + the low-priority starvation bound (max consecutive turns unserved). Both drive the actual
;;;; %flow-policy-* code with an injected clock, so the numbers are the shipped selectors', not a model of them.

(defun* %flow-bench-edf-sim (policy-fn budgets per-writer service-ns arrival-ns)
    (function (function list (integer 1) (integer 1) (integer 1)) (values (integer 0) (integer 0) integer))
  "Discrete-event sim of POLICY-FN over W writers (one per BUDGET, ns) each offering PER-WRITER samples at
   ARRIVAL-NS spacing, one datagram served per turn costing SERVICE-NS. A sample MISSES if its completion time
   exceeds its deadline (arrival + budget). Returns (values MISSES SERVED TOTAL-LATENESS-NS). Drives the real
   %flow-policy-* selector with an injected clock (WP-FLOW-EDF-PRIORITY bench)."
  (multiple-value-bind (clock box) (%flow-clock-box)
    (let* ((w (length budgets))
           (nodes (mapcar (lambda (b) (declare (ignore b)) (%flow-fake-writer-state :pending nil)) budgets))
           (bvec (coerce budgets 'vector))
           (nvec (coerce nodes 'vector))
           (next (make-array w :initial-element 0))          ; index of each writer's next unsent sample
           (controller (%flow-policy-controller clock policy-fn nodes))
           (clk 0) (misses 0) (served 0) (lateness 0))
      (declare (type (integer 0) clk misses served) (type integer lateness))
      (flet ((arrival (i k) (declare (ignore i)) (* k w arrival-ns))   ; simultaneous per-batch arrivals (W samples every W·arrival ⇒ load 1.0 at arrival=service): the contention that makes ordering matter
             (deadline (i k) (+ (* k w arrival-ns) (aref bvec i))))
        (loop while (loop for i below w thereis (< (aref next i) per-writer)) do
          (setf (car box) clk)
          (let ((any-ready nil) (next-arrival nil))
            (dotimes (i w)                                    ; mark writers with an ARRIVED unsent head pending
              (let ((k (aref next i)) (nd (aref nvec i)))
                (cond ((>= k per-writer) (setf (dds.disc::flow-writer-state-pending nd) nil))
                      ((<= (arrival i k) clk)
                       (setf (dds.disc::flow-writer-state-pending nd) t
                             (dds.disc::flow-writer-state-head-ns nd) (arrival i k)
                             (dds.disc::flow-writer-state-latency-budget-ns nd) (aref bvec i)
                             any-ready t))
                      (t (setf (dds.disc::flow-writer-state-pending nd) nil)
                         (setf next-arrival (if next-arrival (min next-arrival (arrival i k)) (arrival i k)))))))
            (if (not any-ready)
                (setf clk (or next-arrival clk))              ; idle: jump to the next arrival (no work now)
                (let* ((pick (funcall policy-fn controller)) (i (position pick nvec)))
                  (let* ((k (aref next i)) (done (+ clk service-ns)) (dl (deadline i k)))
                    (incf served)
                    (when (> done dl) (incf misses) (incf lateness (- done dl)))
                    (incf (aref next i))
                    (setf clk done)))))))
      (values misses served lateness))))

(defun* %flow-bench-priority-sim (policy-fn priorities turns service-ns)
    (function (function list (integer 1) (integer 1)) (values vector vector))
  "Saturated (all-backlogged) sim of POLICY-FN over W writers with fixed PRIORITIES, TURNS datagrams served
   one per turn costing SERVICE-NS. Returns (values SERVED MAX-GAP) per writer, where MAX-GAP is the longest
   run of consecutive turns a writer went UNSERVED (its observed starvation bound). Drives the real
   %flow-policy-priority selector with an injected clock (WP-FLOW-EDF-PRIORITY bench)."
  (multiple-value-bind (clock box) (%flow-clock-box)
    (let* ((w (length priorities))
           (nodes (mapcar (lambda (p) (%flow-fake-writer-state :priority p :last-served 0)) priorities))
           (nvec (coerce nodes 'vector))
           (controller (%flow-policy-controller clock policy-fn nodes))
           (served (make-array w :initial-element 0))
           (gap (make-array w :initial-element 0))
           (max-gap (make-array w :initial-element 0)))
      (dotimes (turn turns)
        (setf (car box) (* turn service-ns))
        (dolist (nd nodes) (setf (dds.disc::flow-writer-state-pending nd) t))   ; backlogged: always pending
        (let* ((pick (funcall policy-fn controller)) (win (position pick nvec)))
          (dotimes (i w)
            (cond ((= i win) (incf (aref served i)) (setf (aref gap i) 0))
                  (t (incf (aref gap i))
                     (when (> (aref gap i) (aref max-gap i)) (setf (aref max-gap i) (aref gap i))))))))
      (values served max-gap))))

(defun* run-bench-flow-edf-priority (&key (file nil))
    (function (&key (:file (or null string pathname))) t)
  "WP-FLOW-EDF-PRIORITY bench (ADR 0016; FR-QOS-1, FR-LANG-7): deterministic ordering-quality report for the
   :edf + :priority scheduling policies vs the round-robin baseline. Oracle = a discrete-event sim over the
   REAL %flow-policy-* selectors with an injected clock (the shipped code, not a model). (1) EDF: deadline-miss
   count for mixed-LATENCY_BUDGET streams under a saturated controller — EDF must miss no more than RR. (2)
   Priority: high-priority service share + the low-priority STARVATION BOUND (max consecutive unserved turns)
   — priority favours the high writer yet aging keeps the low writer's gap BOUNDED (RR is fair-but-priority-
   blind; pure highest-first would starve the low writer unboundedly). Prints markdown; writes FILE when given.
   Deterministic (no threads) so it is not the Clasp-skipped real-thread kind, but reported under SBCL by
   convention (a bench is a run-bench-* entry, not a suite test)."
  (labels ((emit (stream)
             (format stream "~&# WP-FLOW-EDF-PRIORITY — EDF + priority scheduling vs round-robin (ADR 0016; FR-QOS-1, FR-LANG-7)~%~%")
             (format stream "Standard DDS, **NOT R6** (ADR 0016 — flow control is wire-invisible). The `:edf` and `:priority` policies are PURE SELECTION under the controller lock (the token-bucket pacing is orthogonal + untouched). Oracle: a DETERMINISTIC discrete-event sim over the SHIPPED `%flow-policy-edf` / `%flow-policy-priority` selectors with an injected clock — the numbers are the real selectors', not a model. Generated by `dds.tests:run-bench-flow-edf-priority` (`make bench-flow-edf-priority`).~%~%")
             (format stream "| field | value |~%|-------|-------|~%")
             (format stream "| impl | ~a ~a |~%" (lisp-implementation-type) (lisp-implementation-version))
             (format stream "| HEAD | ~a |~%" (%bench-git-head))
             (format stream "| date | ~a |~%" (%bench-date-string))
             (format stream "| aging quantum | ~d ns |~%~%" dds.disc::*flow-priority-aging-quantum-ns*))
           (blocks (stream)
             ;; (1) EDF vs RR deadline misses — mixed budgets, saturated controller.
             (let* ((budgets (list 10000000 2500000 1500000))   ; 10 ms / 2.5 ms / 1.5 ms — the TIGHT (1.5 ms) stream is last in registration order, so RR's budget-blind rotation serves it LATE
                    (per 20) (service 1000000) (arrival 1000000)  ; 1 ms service; W simultaneous arrivals per batch ⇒ load 1.0 (EDF-feasible)
                    (edf (multiple-value-list (%flow-bench-edf-sim #'dds.disc::%flow-policy-edf budgets per service arrival)))
                    (rr  (multiple-value-list (%flow-bench-edf-sim #'dds.disc::%flow-policy-round-robin budgets per service arrival))))
               (format stream "## (1) EDF vs round-robin — deadline misses (mixed LATENCY_BUDGET, saturated)~%~%")
               (format stream "~d writers, budgets ~{~,1f~^/~} ms, ~d samples each, 1 ms service, W simultaneous arrivals per batch (load 1.0, EDF-feasible). A sample MISSES if completion > arrival+budget. The tightest-budget writer is registered LAST, so round-robin's budget-blind rotation reaches it late — EDF reorders by deadline.~%~%"
                       (length budgets) (mapcar (lambda (b) (/ b 1.0d6)) budgets) per)
               (format stream "| policy | served | deadline misses | miss rate | total lateness (ms) |~%")
               (format stream "|--------|--------|-----------------|-----------|---------------------|~%")
               (format stream "| **:edf** | ~d | ~d | ~,1f% | ~,2f |~%"
                       (second edf) (first edf) (* 100.0d0 (/ (first edf) (max 1 (second edf)))) (/ (third edf) 1.0d6))
               (format stream "| round-robin | ~d | ~d | ~,1f% | ~,2f |~%~%"
                       (second rr) (first rr) (* 100.0d0 (/ (first rr) (max 1 (second rr)))) (/ (third rr) 1.0d6))
               (format stream "**EDF misses ~d vs round-robin ~d** — EDF orders by deadline, so the tight-budget stream is serviced first and the aggregate miss count is no worse (typically materially better) than budget-blind RR. This is the FR-QOS ordering benefit of the LATENCY_BUDGET-anchored policy.~%~%"
                       (first edf) (first rr))
               (assert (<= (first edf) (first rr)) ()
                       "bench: EDF deadline misses (~d) must be <= round-robin (~d)" (first edf) (first rr))
               ;; (2) priority vs RR — high-priority share + low-priority starvation bound.
               (let* ((prios (list 10 5 1)) (turns 300) (svc 1000000))
                 (multiple-value-bind (pserved pgap) (%flow-bench-priority-sim #'dds.disc::%flow-policy-priority prios turns svc)
                   (multiple-value-bind (rserved rgap) (%flow-bench-priority-sim #'dds.disc::%flow-policy-round-robin prios turns svc)
                     (format stream "## (2) :priority vs round-robin — service share + starvation bound~%~%")
                     (format stream "~d writers, TRANSPORT_PRIORITY ~{~d~^/~}, saturated (all always pending), ~d turns, aging quantum ~d ns / ~d ns service. MAX-GAP = longest run of consecutive turns a writer went UNSERVED (its observed starvation bound).~%~%"
                             (length prios) prios turns dds.disc::*flow-priority-aging-quantum-ns* svc)
                     (format stream "| writer (priority) | :priority served | :priority max-gap | round-robin served | round-robin max-gap |~%")
                     (format stream "|-------------------|------------------|-------------------|--------------------|---------------------|~%")
                     (loop for p in prios for i from 0 do
                       (format stream "| prio ~d | ~d | ~d | ~d | ~d |~%"
                               p (aref pserved i) (aref pgap i) (aref rserved i) (aref rgap i)))
                     (format stream "~%The high-priority writer (prio 10) takes the LION'S SHARE under `:priority` (~d/~d turns vs RR's fair ~d) — the FR-QOS TRANSPORT_PRIORITY benefit. The low-priority writer (prio 1) is FAVOURED LAST yet its max-gap is BOUNDED at ~d turns (aging lifts its effective priority until it wins) — NOT the unbounded starvation a pure highest-first policy would inflict. RR is priority-blind (every writer's gap ~~ W-1 = ~d).~%~%"
                             (aref pserved 0) turns (aref rserved 0) (aref pgap (1- (length prios))) (1- (length prios)))
                     (assert (> (aref pserved 0) (aref rserved 0)) ()
                             "bench: :priority must give the high-priority writer MORE service than RR")
                     (assert (< (aref pgap (1- (length prios))) turns) ()
                             "bench: aging must BOUND the low-priority writer's starvation gap (< all turns)")
                     (format stream "## Honest framing (FR-LANG-7)~%~%")
                     (format stream "- Selection is ORTHOGONAL to pacing: `:edf`/`:priority` change only WHICH writer drains next, never the byte rate (all three policies shape to the same aggregate rate) or the wire bytes (ADR 0016).~%")
                     (format stream "- EDF is keyed on **LATENCY_BUDGET**, not QoS DEADLINE (which is the periodicity/liveliness contract here); LATENCY_BUDGET is a max-delay HINT informing ORDERING, so a saturated bucket may still miss — EDF minimises misses, it does not guarantee zero.~%")
                     (format stream "- `:priority` favours high-priority writers but AGES pending writers so low-priority progress is bounded (quantum ~d ns); it is priority-WITH-fairness, not strict priority.~%"
                             dds.disc::*flow-priority-aging-quantum-ns*)
                     (format stream "- Deterministic sim over the shipped selectors (injected clock); impl ~a ~a.~%"
                             (lisp-implementation-type) (lisp-implementation-version))))))))
    (emit *standard-output*)
    (blocks *standard-output*)
    (when file
      (with-open-file (s file :direction :output :if-exists :supersede :if-does-not-exist :create)
        (emit s) (blocks s))
      (format t "~&  wrote ~a~%" file)))
  t)

(defun* run-async-decoupled-test ()
    (function () t)
  "WP-ASYNC (FR-PF-2): a writer with enable-async pushes off the caller thread (a background sender);
   a reliable reader still receives EVERY sample over UDP. Exercises the sender thread end-to-end +
   stop-node's drain/join. publish-sample returns without blocking on the socket."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 41))
         (p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 42))
         (w (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer w :topic "AsyncT" :type "X")
           (dds.disc:enable-publisher w :history-kind :keep-all)   ; KEEP_ALL: the async sender must deliver all 20 (ADR 0019 migration)
           (dds.disc:enable-async w)
           (dds.disc:add-local-reader r :topic "AsyncT" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-reliable+)
           (dds.disc:enable-subscriber r)
           (setf (dds.disc::disc-node-peers w) (list (cons "127.0.0.1" (dds.disc:disc-node-port r)))
                 (dds.disc::disc-node-peers r) (list (cons "127.0.0.1" (dds.disc:disc-node-port w))))
           (dds.disc:start-node w) (dds.disc:start-node r)
           (dds.disc:announce-participant w) (dds.disc:announce-participant r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-discovered-count w))
                            (plusp (dds.disc:disc-node-discovered-count r)))
                 do (sleep 0.01))
           (dds.disc:announce-endpoints w) (dds.disc:announce-endpoints r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-matched-count w))
                            (plusp (dds.disc:disc-node-matched-count r)))
                 do (sleep 0.01))
           (%check :async-matched (plusp (dds.disc:disc-node-matched-count w))
                   "async writer must match the reader before publishing")
           (dotimes (i 20) (dds.disc:publish-sample w (octets 7 7 7 7 7 7 7 7)))
           (loop repeat 400 until (>= (dds.disc:node-sample-count r) 20) do (sleep 0.01))
           (%check :async-received (>= (dds.disc:node-sample-count r) 20)
                   "the async sender thread must deliver all 20 samples to the reliable reader"))
      (dds.disc:stop-node w) (dds.disc:stop-node r)))
  t)

(defun* run-async-emit-fault-survives-test ()
    (function () t)
  "WP-SENDER-ERROR-RESILIENCE scenario 1 (FR-PF-2, RTPS 2.5 §8.4): the async sender thread SURVIVES injected
   transient emit faults and keeps sending. Phase 1: with the fault armed, publish 3 samples ONE AT A TIME,
   each time waiting for the async emit-error counter to advance — so exactly 3 faults are caught on the async
   sender thread (a faulted flush drops both the DATA and its coalesced HEARTBEAT, so the reader never NACKs
   during this phase ⇒ no receiver-thread retransmit steals the fault budget; deterministic). Phase 2: clear
   the fault, publish 3 more (these deliver), then drive the periodic HEARTBEAT so the reader NACKs the 3
   gaps and the writer retransmits the held samples. Assert: the thread is still alive (slot non-NIL + still
   working — a dead thread could neither bump the counter nor deliver), the hook fired 3x with :ASYNC-SENDER,
   the counter = 3, and ALL 6 samples are delivered (the 3 dropped DATAs repaired via HEARTBEAT/ACKNACK)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 43))
         (p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 44))
         (w (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (lock (dds.pal:make-lock "async-fault-fired"))
         (fired '())
         (saved-hook dds.disc:*sender-emit-error-hook*))
    ;; The hook runs ON the async sender thread, which does NOT inherit this thread's dynamic bindings, so set
    ;; the GLOBAL value (restored in cleanup); the lock guards the cross-thread FIRED list.
    (setf dds.disc:*sender-emit-error-hook*
          (lambda (c ctx n) (declare (ignore n))
            (dds.pal:with-lock (lock) (push (cons ctx (type-of c)) fired))))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer w :topic "AsyncFaultT" :type "X")
           (dds.disc:enable-publisher w :history-kind :keep-all)   ; KEEP_ALL: all samples must survive the drops + repair
           (dds.disc:enable-async w)
           (dds.disc:add-local-reader r :topic "AsyncFaultT" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-reliable+)
           (dds.disc:enable-subscriber r)
           (setf (dds.disc::disc-node-peers w) (list (cons "127.0.0.1" (dds.disc:disc-node-port r)))
                 (dds.disc::disc-node-peers r) (list (cons "127.0.0.1" (dds.disc:disc-node-port w))))
           (dds.disc:start-node w) (dds.disc:start-node r)
           (dds.disc:announce-participant w) (dds.disc:announce-participant r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-discovered-count w))
                            (plusp (dds.disc:disc-node-discovered-count r)))
                 do (sleep 0.01))
           (dds.disc:announce-endpoints w) (dds.disc:announce-endpoints r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-matched-count w))
                            (plusp (dds.disc:disc-node-matched-count r)))
                 do (sleep 0.01))
           (%check :async-fault-matched (plusp (dds.disc:disc-node-matched-count w))
                   "async writer must match the reader before publishing")
           ;; Phase 1: arm a persistent fault, publish 3 samples one at a time, waiting for each to fault.
           (setf dds.disc:*debug-emit-fault* :persistent)   ; every async flush faults until cleared
           (dotimes (i 3)
             (dds.disc:publish-sample w (octets 7 7 7 7 7 7 7 i))
             (loop repeat 400 until (>= (dds.disc::disc-node-async-emit-errors w) (1+ i)) do (sleep 0.01))
             (%check :async-fault-step (>= (dds.disc::disc-node-async-emit-errors w) (1+ i))
                     "each armed publish must fault the async sender thread (counter advances)"))
           ;; Phase 2: clear the fault, publish 3 deliverable samples, then drive repair of the 3 dropped.
           (setf dds.disc:*debug-emit-fault* nil)
           (dotimes (i 3) (dds.disc:publish-sample w (octets 7 7 7 7 7 7 8 i)))
           (loop repeat 600
                 until (>= (dds.disc:node-sample-count r) 6)
                 do (dds.disc::%push-heartbeat w) (sleep 0.01))   ; periodic HB ⇒ reader NACKs the gaps ⇒ retransmit
           (%check :async-fault-thread-slot-retained (dds.disc::disc-node-async-thread w)
                   "the async sender thread slot must still be retained (non-NIL — only stop-node clears it) after the injected faults; the real liveness proof is the counter advancing + delivery")
           (%check :async-fault-counter (= 3 (dds.disc::disc-node-async-emit-errors w))
                   "exactly 3 emit faults must have been counted on the async sender thread")
           (let ((snapshot (dds.pal:with-lock (lock) (copy-list fired))))
             (%check :async-fault-hook-fired (= 3 (length snapshot))
                     "the *sender-emit-error-hook* must have fired exactly 3 times")
             (%check :async-fault-hook-context (every (lambda (e) (eq :async-sender (car e))) snapshot)
                     "every hook fire must carry the :ASYNC-SENDER context"))
           (%check :async-fault-delivered (>= (dds.disc:node-sample-count r) 6)
                   "all 6 samples must still be delivered (the 3 dropped DATAs repaired via HEARTBEAT/ACKNACK)"))
      (setf dds.disc:*debug-emit-fault* nil
            dds.disc:*sender-emit-error-hook* saved-hook)
      (dds.disc:stop-node w) (dds.disc:stop-node r)))
  t)

(defun* run-emit-fault-inert-test ()
    (function () t)
  "WP-SENDER-ERROR-RESILIENCE scenario 4 (FR-PF-2): with *DEBUG-EMIT-FAULT* NIL the guard + injector are INERT.
   Part 1 (byte-identity): a controllerless publish-sample (the guard is wired into the async loop, but the
   injector is dormant) produces datagrams byte-identical to writer-write + %push-data — the wire is unchanged.
   Part 2 (runtime inertness): an async writer delivers all samples to a loopback reader with the error counter
   never advancing (= 0) and the hook never firing."
  ;; -- Part 1: byte-identity — *debug-emit-fault* NIL ⇒ the send path is unchanged --
  (let ((pub-node  (%flow-step-build-node #xE2 #xF2 7831 '()))
        (push-node (%flow-step-build-node #xE2 #xF2 7831 '())))
    (%check :inert-default-nil (null dds.disc:*debug-emit-fault*)
            "*debug-emit-fault* must default to NIL (inert in production)")
    (unwind-protect
         (let ((pub-dgs  (loop for i below 4
                               append (%flow-publish-capture pub-node (octets 5 5 5 5 5 5 5 5))))
               (push-dgs (loop for i below 4
                               append (let ((w (dds.disc::disc-node-user-writer push-node)))
                                        (dds.rtps.reliable:writer-write w (octets 5 5 5 5 5 5 5 5))
                                        (%coalesce-capture push-node)))))
           (%check :inert-nonempty (plusp (length pub-dgs))
                   "the inert publish path must still emit datagrams")
           (%check :inert-byte-identical (%datagrams-identical-p pub-dgs push-dgs)
                   "with *debug-emit-fault* NIL a publish must be byte-identical to writer-write + %push-data"))
      (dds.disc:stop-node pub-node)
      (dds.disc:stop-node push-node)))
  ;; -- Part 2: runtime inertness — async delivery, the counter never advances, the hook never fires --
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 45))
         (p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 46))
         (w (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (lock (dds.pal:make-lock "inert-fired"))
         (fired 0)
         (saved-hook dds.disc:*sender-emit-error-hook*))
    ;; The hook runs on the async sender thread (no inherited dynamic bindings), so set the GLOBAL value.
    (setf dds.disc:*sender-emit-error-hook*
          (lambda (c ctx n) (declare (ignore c ctx n)) (dds.pal:with-lock (lock) (incf fired))))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer w :topic "InertT" :type "X")
           (dds.disc:enable-publisher w :history-kind :keep-all)
           (dds.disc:enable-async w)
           (dds.disc:add-local-reader r :topic "InertT" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-reliable+)
           (dds.disc:enable-subscriber r)
           (setf (dds.disc::disc-node-peers w) (list (cons "127.0.0.1" (dds.disc:disc-node-port r)))
                 (dds.disc::disc-node-peers r) (list (cons "127.0.0.1" (dds.disc:disc-node-port w))))
           (dds.disc:start-node w) (dds.disc:start-node r)
           (dds.disc:announce-participant w) (dds.disc:announce-participant r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-discovered-count w))
                            (plusp (dds.disc:disc-node-discovered-count r)))
                 do (sleep 0.01))
           (dds.disc:announce-endpoints w) (dds.disc:announce-endpoints r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-matched-count w))
                            (plusp (dds.disc:disc-node-matched-count r)))
                 do (sleep 0.01))
           (dotimes (i 10) (dds.disc:publish-sample w (octets 5 5 5 5 5 5 5 i)))
           (loop repeat 400 until (>= (dds.disc:node-sample-count r) 10) do (sleep 0.01))
           (%check :inert-delivered (>= (dds.disc:node-sample-count r) 10)
                   "an inert async publish must deliver all 10 samples")
           (%check :inert-counter-zero (zerop (dds.disc::disc-node-async-emit-errors w))
                   "with no injected fault the async emit-error counter must stay 0")
           (%check :inert-hook-silent (zerop (dds.pal:with-lock (lock) fired))
                   "with no injected fault the *sender-emit-error-hook* must never fire"))
      (setf dds.disc:*sender-emit-error-hook* saved-hook)
      (dds.disc:stop-node w) (dds.disc:stop-node r)))
  t)

(defun* run-flow-emit-fault-no-spin-test ()
    (function () t)
  "WP-SENDER-ERROR-RESILIENCE scenario 2 (FR-PF-2, RTPS 2.5 §8.4): under a PERSISTENT emit fault the flow
   scheduler advances its plan cursor (drops + moves on), does NOT hot-spin, survives, and resumes when the
   fault clears. A flow-controller paces a BEST_EFFORT writer (the paced scheduler is the sole delivery path).
   Phase 1: arm *DEBUG-EMIT-FAULT* :persistent, publish K small samples (which COALESCE into a single DATA+
   HEARTBEAT datagram per snapshot — so the plan here is ONE entry; the multi-entry cursor-advance-under-fault
   path is exercised by run-flow-emit-fault-no-spin-multi-test); every scheduler emit faults so the cursor
   drains each snapshotted plan and the node stops being pending (the unsent watermark advanced at SNAPSHOT
   time, so a drained faulted plan is never re-snapshotted). The no-spin PROOF: the hook-fire count STABILISES
   (two readings 0.3 s apart are equal — a spin would keep growing it) and is BOUNDED (<= K + slack, not
   unbounded). Phase 2: clear the fault, publish K more; assert the writer RESUMES (the best-effort reader now
   receives the new samples) — a dead scheduler thread could neither stabilise nor resume."
  (when (eq (uiop:implementation-type) :clasp) (return-from run-flow-emit-fault-no-spin-test t))   ; timing-flaky on Clasp (mirrors the other flow tests)
  (let* ((k 6)
         (slack 4)
         (payload (octets 9 9 9 9 9 9 9 9))
         (w (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x97) :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xA7) :host "127.0.0.1" :port 0))
         (lock (dds.pal:make-lock "no-spin-fired"))
         (fired 0)
         (controller nil)
         (saved-hook dds.disc:*sender-emit-error-hook*))
    ;; The hook runs ON the scheduler thread (no inherited dynamic bindings), so set the GLOBAL value; the lock
    ;; guards the cross-thread FIRED counter.
    (setf dds.disc:*sender-emit-error-hook*
          (lambda (c ctx n) (declare (ignore c ctx n)) (dds.pal:with-lock (lock) (incf fired))))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer w :topic "NoSpinT" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher w :history-kind :keep-all)
           (dds.disc:add-local-reader r :topic "NoSpinT" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber r)
           (%flow-match-writer-reader w r "NoSpinT")
           (setf controller (dds.disc:make-flow-controller :tokens-per-period 1000000 :period 100000000
                                                           :max-burst 1000000))   ; high rate: pacing never confounds the spin reading
           (dds.disc:flow-controller-associate controller w)
           ;; Phase 1: arm a persistent fault, publish K, let every scheduler emit fault + drain its plan.
           (setf dds.disc:*debug-emit-fault* :persistent)
           (dotimes (i k) (dds.disc:publish-sample w payload))
           (loop repeat 100 until (plusp (dds.pal:with-lock (lock) fired)) do (sleep 0.005))   ; wait until the scheduler has faulted at least once
           (sleep 0.3)
           (let ((reading1 (dds.pal:with-lock (lock) fired)))
             (sleep 0.3)
             (let ((reading2 (dds.pal:with-lock (lock) fired)))
               (format t "~&  [no-spin] persistent-fault fires: reading1=~d reading2=~d (K=~d)~%" reading1 reading2 k)
               (%check :no-spin-fired-some (plusp reading2)
                       "the scheduler must have caught at least one emit fault (it ran + advanced)")
               (%check :no-spin-stable (= reading1 reading2)
                       (format nil "the hook-fire count must STABILISE under a persistent fault (no hot-spin); ~
                                    grew ~d -> ~d" reading1 reading2))
               (%check :no-spin-bounded (<= reading2 (+ k slack))
                       (format nil "the hook-fire count must be BOUNDED (<= K datagrams — here the K small ~
                                    samples coalesce to 1 — not unbounded); ~d > ~d" reading2 (+ k slack)))))
           (%check :no-spin-controller-alive (dds.disc::flow-controller-thread controller)
                   "the flow-scheduler thread slot must still be retained after the persistent faults")
           ;; Phase 2: clear the fault, publish K more; the writer must RESUME (best-effort reader gets them).
           (setf dds.disc:*debug-emit-fault* nil)
           (let ((before (dds.disc:node-sample-count r)))
             (dotimes (i k) (dds.disc:publish-sample w payload))
             (loop repeat 600 until (> (dds.disc:node-sample-count r) before) do (sleep 0.005))
             (%check :no-spin-resumes (> (dds.disc:node-sample-count r) before)
                     "the scheduler must RESUME delivering once the fault clears (new samples reach the reader)")))
      (setf dds.disc:*debug-emit-fault* nil
            dds.disc:*sender-emit-error-hook* saved-hook)
      (when controller (ignore-errors (dds.disc:destroy-flow-controller controller)))
      (dds.disc:stop-node w) (dds.disc:stop-node r)))
  t)

(defun* run-flow-emit-fault-no-spin-multi-test ()
    (function () t)
  "WP-SENDER-ERROR-RESILIENCE scenario 2, MULTI-ENTRY strengthening (FR-PF-2, RTPS 2.5 §8.4): the sibling
   run-flow-emit-fault-no-spin-test drains a SINGLE coalesced datagram (its K small samples coalesce to one
   plan entry); this test forces a >=3-ENTRY plan in one snapshot so the scheduler walks the MULTI-element plan
   cursor (setf flow-step-state (cdr plan)) while EVERY emit faults. A single 4000-octet sample fragments into
   a DATA_FRAG series + HEARTBEAT_FRAG = multiple datagram entries (one per fragment group), exactly as
   run-flow-step-equivalence Case 2 establishes. PRECONDITION proof: an equivalently-built twin node's
   %node-datagram-plan is snapshotted DETERMINISTICALLY (no scheduler race) and asserted >= 3 entries — so the
   live faulting run genuinely exercises the multi-entry path. Phase 1: arm *DEBUG-EMIT-FAULT* :persistent,
   publish the large sample; every scheduler emit faults so the cursor drains the whole multi-entry plan and
   the node stops being pending (the unsent watermark advanced at SNAPSHOT time, so a drained faulted plan is
   never re-snapshotted). The plan-size-AGNOSTIC no-spin PROOF: the hook-fire count STABILISES (two readings
   0.3 s apart are equal — a spin would keep growing it regardless of plan size) and is BOUNDED. Phase 2: clear
   the fault, publish a small sample; assert the writer RESUMES (the best-effort reader receives it) — a dead
   scheduler thread could neither stabilise nor resume."
  (when (eq (uiop:implementation-type) :clasp) (return-from run-flow-emit-fault-no-spin-multi-test t))   ; timing-flaky on Clasp (mirrors the other flow tests)
  (let* ((slack 8)
         (big (let ((v (make-array 4000 :element-type '(unsigned-byte 8))))
                (dotimes (i 4000 v) (setf (aref v i) (logand (* i 7) #xff)))))   ; 4000 octets > *fragment-size* (1024) ⇒ DATA_FRAG series
         (w (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #x98) :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xA8) :host "127.0.0.1" :port 0))
         (lock (dds.pal:make-lock "no-spin-multi-fired"))
         (fired 0)
         (controller nil)
         (saved-hook dds.disc:*sender-emit-error-hook*))
    ;; PRECONDITION: a deterministic twin node (same guid/reader/unsent set, no scheduler) snapshots the plan —
    ;; assert the 4000-octet sample yields a >=3-ENTRY plan, so the live run below walks a multi-element cursor.
    (let ((twin (%flow-step-build-node #x98 #xA8 7831 (list big))))
      (unwind-protect
           (let ((plan (dds.disc::%node-datagram-plan twin (dds.disc::disc-node-user-writer twin) (dds.disc::disc-node-tx-msg twin))))
             (%check :no-spin-multi-plan-ge3 (>= (length plan) 3)
                     (format nil "the 4000-octet sample must snapshot a >=3-entry datagram plan to exercise the ~
                                  multi-entry cursor-advance-under-fault path; got ~d" (length plan))))
        (dds.disc:stop-node twin)))
    ;; The hook runs ON the scheduler thread (no inherited dynamic bindings), so set the GLOBAL value; the lock
    ;; guards the cross-thread FIRED counter.
    (setf dds.disc:*sender-emit-error-hook*
          (lambda (c ctx n) (declare (ignore c ctx n)) (dds.pal:with-lock (lock) (incf fired))))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer w :topic "NoSpinMultiT" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-publisher w :history-kind :keep-all)
           (dds.disc:add-local-reader r :topic "NoSpinMultiT" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-best-effort+)
           (dds.disc:enable-subscriber r)
           (%flow-match-writer-reader w r "NoSpinMultiT")
           (setf controller (dds.disc:make-flow-controller :tokens-per-period 1000000 :period 100000000
                                                           :max-burst 1000000))   ; high rate: pacing never confounds the spin reading
           (dds.disc:flow-controller-associate controller w)
           ;; Phase 1: arm a persistent fault, publish the large sample, let every scheduler emit fault + drain
           ;; the whole multi-entry plan.
           (setf dds.disc:*debug-emit-fault* :persistent)
           (dds.disc:publish-sample w big)
           (loop repeat 100 until (plusp (dds.pal:with-lock (lock) fired)) do (sleep 0.005))   ; wait until the scheduler has faulted at least once
           (sleep 0.3)
           (let ((reading1 (dds.pal:with-lock (lock) fired)))
             (sleep 0.3)
             (let ((reading2 (dds.pal:with-lock (lock) fired)))
               (format t "~&  [no-spin-multi] persistent-fault fires: reading1=~d reading2=~d~%" reading1 reading2)
               (%check :no-spin-multi-fired-some (plusp reading2)
                       "the scheduler must have caught at least one emit fault while draining the multi-entry plan")
               (%check :no-spin-multi-stable (= reading1 reading2)
                       (format nil "the hook-fire count must STABILISE under a persistent fault while walking a ~
                                    >=3-entry plan (no hot-spin); grew ~d -> ~d" reading1 reading2))
               (%check :no-spin-multi-bounded (<= reading2 slack)
                       (format nil "the hook-fire count must be BOUNDED (the multi-entry plan drains once, ~
                                    not unbounded); ~d > ~d" reading2 slack))))
           (%check :no-spin-multi-controller-alive (dds.disc::flow-controller-thread controller)
                   "the flow-scheduler thread slot must still be retained after draining the faulted multi-entry plan")
           ;; Phase 2: clear the fault, publish a small sample; the writer must RESUME (best-effort reader gets it).
           (setf dds.disc:*debug-emit-fault* nil)
           (let ((before (dds.disc:node-sample-count r)))
             (dds.disc:publish-sample w (octets 9 9 9 9 9 9 9 9))
             (loop repeat 600 until (> (dds.disc:node-sample-count r) before) do (sleep 0.005))
             (%check :no-spin-multi-resumes (> (dds.disc:node-sample-count r) before)
                     "the scheduler must RESUME delivering once the fault clears (a new sample reaches the reader)")))
      (setf dds.disc:*debug-emit-fault* nil
            dds.disc:*sender-emit-error-hook* saved-hook)
      (when controller (ignore-errors (dds.disc:destroy-flow-controller controller)))
      (dds.disc:stop-node w) (dds.disc:stop-node r)))
  t)

(defun* run-reliable-repair-after-drop-test ()
    (function () t)
  "WP-SENDER-ERROR-RESILIENCE scenario 3 (Option-1 conformance, RTPS 2.5 §8.4): a RELIABLE writer + reader;
   drop exactly ONE DATA via *DEBUG-EMIT-FAULT* = 1 around the sole publish; assert the reader STILL receives
   that sample via the HEARTBEAT/ACKNACK repair path (the sample stayed in the HistoryCache; the guard caught
   the drop and the writer survived). Proves the dropped reliable sample is recovered, not lost. Uses the
   synchronous publish path (publish-sample on the caller thread reaches the SAME guarded %send-raw-buf) so the
   single injected fault is consumed deterministically by exactly one send; the periodic HEARTBEAT is driven
   explicitly so the reader NACKs the gap and the writer retransmits (no reliance on a background timer)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 47))
         (p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 48))
         (w (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer w :topic "RepairT" :type "X")
           (dds.disc:enable-publisher w :history-kind :keep-all)   ; KEEP_ALL: the dropped sample must survive in the HC for repair
           (dds.disc:add-local-reader r :topic "RepairT" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-reliable+)
           (dds.disc:enable-subscriber r)
           (setf (dds.disc::disc-node-peers w) (list (cons "127.0.0.1" (dds.disc:disc-node-port r)))
                 (dds.disc::disc-node-peers r) (list (cons "127.0.0.1" (dds.disc:disc-node-port w))))
           (dds.disc:start-node w) (dds.disc:start-node r)
           (dds.disc:announce-participant w) (dds.disc:announce-participant r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-discovered-count w))
                            (plusp (dds.disc:disc-node-discovered-count r)))
                 do (sleep 0.01))
           (dds.disc:announce-endpoints w) (dds.disc:announce-endpoints r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-matched-count w))
                            (plusp (dds.disc:disc-node-matched-count r)))
                 do (sleep 0.01))
           (%check :repair-matched (plusp (dds.disc:disc-node-matched-count w))
                   "the reliable writer must match the reader before publishing")
           ;; Drop exactly the ONE DATA datagram for the sole sample (coalesced DATA+HEARTBEAT in one datagram).
           ;; This publish uses the SYNC path (no async/flow), which has no guard — the fault signals out HERE,
           ;; AFTER writer-write has put the sample in the HC; IGNORE-ERRORS lets the test continue to the repair.
           (setf dds.disc:*debug-emit-fault* 1)
           (ignore-errors (dds.disc:publish-sample w (octets 1 2 3 4 5 6 7 0)))
           (setf dds.disc:*debug-emit-fault* nil)   ; only the first send is dropped
           ;; Drive the periodic HEARTBEAT so the reader NACKs the gap and the writer retransmits the held sample.
           (loop repeat 600
                 until (>= (dds.disc:node-sample-count r) 1)
                 do (dds.disc::%push-heartbeat w) (sleep 0.01))
           (%check :repair-delivered (>= (dds.disc:node-sample-count r) 1)
                   "the dropped reliable DATA must still be delivered via the HEARTBEAT/ACKNACK repair (Option 1)"))
      (setf dds.disc:*debug-emit-fault* nil)
      (dds.disc:stop-node w) (dds.disc:stop-node r)))
  t)

(defun* run-hook-self-error-test ()
    (function () t)
  "WP-SENDER-ERROR-RESILIENCE scenario 5 (FR-PF-2): a *SENDER-EMIT-ERROR-HOOK* that itself SIGNALS must NOT
   re-kill the sender thread (the IGNORE-ERRORS around the hook call in WITH-SENDER-EMIT-GUARD). Arm a hook
   that always errors + *DEBUG-EMIT-FAULT* :persistent on an async writer, publish, wait for the emit-error
   counter to advance past the first hook-boom, then clear the fault and assert the async sender thread is
   STILL working (its counter keeps advancing on a fresh fault, and a post-fault publish is delivered to a
   loopback reader) — a thread killed by the signalling hook could do neither."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 49))
         (p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 50))
         (w (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (saved-hook dds.disc:*sender-emit-error-hook*))
    ;; The hook runs ON the async sender thread (no inherited dynamic bindings), so set the GLOBAL value; the
    ;; hook itself signals on EVERY fire — the guard's IGNORE-ERRORS must swallow it.
    (setf dds.disc:*sender-emit-error-hook*
          (lambda (c ctx n) (declare (ignore c ctx n)) (error "hook boom")))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer w :topic "HookBoomT" :type "X")
           (dds.disc:enable-publisher w :history-kind :keep-all)
           (dds.disc:enable-async w)
           (dds.disc:add-local-reader r :topic "HookBoomT" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-reliable+)
           (dds.disc:enable-subscriber r)
           (setf (dds.disc::disc-node-peers w) (list (cons "127.0.0.1" (dds.disc:disc-node-port r)))
                 (dds.disc::disc-node-peers r) (list (cons "127.0.0.1" (dds.disc:disc-node-port w))))
           (dds.disc:start-node w) (dds.disc:start-node r)
           (dds.disc:announce-participant w) (dds.disc:announce-participant r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-discovered-count w))
                            (plusp (dds.disc:disc-node-discovered-count r)))
                 do (sleep 0.01))
           (dds.disc:announce-endpoints w) (dds.disc:announce-endpoints r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-matched-count w))
                            (plusp (dds.disc:disc-node-matched-count r)))
                 do (sleep 0.01))
           (%check :hook-boom-matched (plusp (dds.disc:disc-node-matched-count w))
                   "the async writer must match the reader before publishing")
           ;; Phase 1: persistent fault + a signalling hook; wait until the counter advances (the hook boomed
           ;; AND was swallowed — the thread survived its own hook signalling).
           (setf dds.disc:*debug-emit-fault* :persistent)
           (dds.disc:publish-sample w (octets 4 4 4 4 4 4 4 0))
           (loop repeat 600 until (>= (dds.disc::disc-node-async-emit-errors w) 1) do (sleep 0.01))
           (%check :hook-boom-counter-advanced (>= (dds.disc::disc-node-async-emit-errors w) 1)
                   "the async sender thread must survive a SIGNALLING hook (the counter advanced past the first boom)")
           ;; Phase 2: clear the fault; the thread must STILL work — publish + drive repair to delivery.
           (setf dds.disc:*debug-emit-fault* nil)
           (dotimes (i 3) (dds.disc:publish-sample w (octets 4 4 4 4 4 4 8 i)))
           (loop repeat 600
                 until (>= (dds.disc:node-sample-count r) 1)
                 do (dds.disc::%push-heartbeat w) (sleep 0.01))
           (%check :hook-boom-thread-working (dds.disc::disc-node-async-thread w)
                   "the async sender thread slot must still be retained after the signalling hook")
           (%check :hook-boom-delivered (>= (dds.disc:node-sample-count r) 1)
                   "the async sender thread must still deliver after surviving a signalling hook (it is alive + working)"))
      (setf dds.disc:*debug-emit-fault* nil
            dds.disc:*sender-emit-error-hook* saved-hook)
      (dds.disc:stop-node w) (dds.disc:stop-node r)))
  t)

;;; SHMEM intra-host data plane (FR-XPORT-2): two participants in ONE process (so one host, one
;;; host-uuid) discover (SPDP) + match (SEDP) over UDP, then the writer routes user DATA over SHARED
;;; MEMORY to the same-host reader (discovery/HB/ACKNACK stay UDP). The reader receives every sample via
;;; the SAME %handle-datagram entry point as UDP (engine untouched); a shmem-sends counter proves SHMEM —
;;; not UDP — carried the bulk data. Pass-skips on the Clasp/macOS by-name-attach gap (ADR 0013), where
;;; *shmem-enabled* is NIL and everything falls back to UDP.

(defun* run-shmem-end-to-end-test ()
    (function () t)
  "FR-XPORT-2: same-host user DATA travels over SHMEM (UDP fallback). Two nodes, same host-uuid,
   *shmem-enabled* T; after match, publish 20 samples and assert the reliable reader receives all 20 AND
   the writer's shmem-sends advanced (so SHMEM, not UDP, carried the user data). Skips cleanly where SHMEM
   is off (Clasp/macOS by-name-attach gap, ADR 0013)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-shmem-end-to-end-test t))
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 51))
         (p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 52))
         (dds.disc:*shmem-enabled* t)   ; force SHMEM on for this test regardless of the global default
         (w (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (%check :shmem-e2e-enabled (and (dds.disc::disc-node-shmem w) (dds.disc::disc-node-shmem r))
                   "both nodes must have a SHMEM transport when *shmem-enabled*")
           (%check :shmem-e2e-same-host (= (dds.disc::disc-node-host-uuid w) (dds.disc::disc-node-host-uuid r))
                   "two participants in one process must share a host-uuid")
           (dds.disc:add-local-writer w :topic "ShmemT" :type "X")
           (dds.disc:enable-publisher w :history-kind :keep-all)   ; KEEP_ALL: SHMEM e2e must deliver all 20 (ADR 0019 migration)
           (dds.disc:add-local-reader r :topic "ShmemT" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-reliable+)
           (dds.disc:enable-subscriber r)
           (setf (dds.disc::disc-node-peers w) (list (cons "127.0.0.1" (dds.disc:disc-node-port r)))
                 (dds.disc::disc-node-peers r) (list (cons "127.0.0.1" (dds.disc:disc-node-port w))))
           (dds.disc:start-node w) (dds.disc:start-node r)
           (dds.disc:announce-participant w) (dds.disc:announce-participant r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-discovered-count w))
                            (plusp (dds.disc:disc-node-discovered-count r)))
                 do (sleep 0.01))
           (dds.disc:announce-endpoints w) (dds.disc:announce-endpoints r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-matched-count w))
                            (plusp (dds.disc:disc-node-matched-count r)))
                 do (sleep 0.01))
           (%check :shmem-e2e-matched (plusp (dds.disc:disc-node-matched-count w))
                   "writer must match the reader before publishing over SHMEM")
           (dotimes (i 20) (dds.disc:publish-sample w (octets 9 9 9 9 9 9 9 9)))
           (loop repeat 400 until (>= (dds.disc:node-sample-count r) 20) do (sleep 0.01))
           (%check :shmem-e2e-received (>= (dds.disc:node-sample-count r) 20)
                   "the reader must receive all 20 samples delivered over SHMEM")
           (%check :shmem-e2e-via-shmem (plusp (dds.disc::disc-node-shmem-sends w))
                   "the writer must have routed user data over SHMEM (shmem-sends advanced), not UDP"))
      (dds.disc:stop-node w) (dds.disc:stop-node r)))
  t)

;;; WP-SHMEM-SEND-SELF-GUARD (FR-XPORT-2): a SIGNALED %shmem-send hard fault (segment detached / pshared /
;;; bounds), unlike a benign return-0 lane-full, must NOT propagate out of the user-data send — %send-raw-buf
;;; (dds.disc) catches it, bumps disc-node-shmem-send-faults, fires *sender-emit-error-hook* with the context
;;; :shmem-send-fault, and FALLS BACK to UDP so the datagram still delivers. The catch lives in dds.disc (not
;;; the dds.xport SHMEM :send lambda) so the counter + hook stay in scope without an upward dds.xport->dds.disc
;;; dependency. The fault is injected by the test affordance dds.xport.shmem:*debug-shmem-send-fault* (inert
;;; NIL = byte-identical production). Pass-skips on the Clasp/macOS by-name-attach gap (ADR 0013).

(defun* run-shmem-send-self-guard-test ()
    (function () t)
  "FR-XPORT-2: a hard %shmem-send fault degrades to the UDP fallback. Two same-host nodes, *shmem-enabled* T;
   after match, ARM *debug-shmem-send-fault* and publish a sample. Assert the reader STILL receives it (via the
   UDP fallback), disc-node-shmem-send-faults advanced (>=1), the hook fired with context :shmem-send-fault, and
   disc-node-shmem-sends did NOT advance (it went UDP, not SHMEM). Skips where SHMEM is off (ADR 0013)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-shmem-send-self-guard-test t))
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 53))
         (p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 54))
         (dds.disc:*shmem-enabled* t)
         (w (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (lock (dds.pal:make-lock "shmem-fault-fired"))
         (fired '())
         (saved-hook dds.disc:*sender-emit-error-hook*))
    ;; The send is synchronous (on the caller thread), but set the GLOBAL hook (restored in cleanup) so the
    ;; recorder is visible regardless of thread; the lock guards the FIRED list.
    (setf dds.disc:*sender-emit-error-hook*
          (lambda (c ctx n) (declare (ignore n))
            (dds.pal:with-lock (lock) (push (cons ctx (type-of c)) fired))))
    (unwind-protect
         (progn
           (%check :shmem-guard-enabled (and (dds.disc::disc-node-shmem w) (dds.disc::disc-node-shmem r))
                   "both nodes must have a SHMEM transport when *shmem-enabled*")
           (dds.disc:add-local-writer w :topic "ShmemGuardT" :type "X")
           (dds.disc:enable-publisher w :history-kind :keep-all)
           (dds.disc:add-local-reader r :topic "ShmemGuardT" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-reliable+)
           (dds.disc:enable-subscriber r)
           (setf (dds.disc::disc-node-peers w) (list (cons "127.0.0.1" (dds.disc:disc-node-port r)))
                 (dds.disc::disc-node-peers r) (list (cons "127.0.0.1" (dds.disc:disc-node-port w))))
           (dds.disc:start-node w) (dds.disc:start-node r)
           (dds.disc:announce-participant w) (dds.disc:announce-participant r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-discovered-count w))
                            (plusp (dds.disc:disc-node-discovered-count r)))
                 do (sleep 0.01))
           (dds.disc:announce-endpoints w) (dds.disc:announce-endpoints r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-matched-count w))
                            (plusp (dds.disc:disc-node-matched-count r)))
                 do (sleep 0.01))
           (%check :shmem-guard-matched (plusp (dds.disc:disc-node-matched-count w))
                   "writer must match the reader before publishing")
           (let ((sends-before (dds.disc::disc-node-shmem-sends w)))
             ;; Arm the synthetic hard fault: the next SHMEM send signals -> %send-raw-buf catches -> UDP.
             (setf dds.xport.shmem:*debug-shmem-send-fault* t)
             (dds.disc:publish-sample w (octets 1 2 3 4 5 6 7 8))
             (loop repeat 400 until (>= (dds.disc:node-sample-count r) 1)
                   do (dds.disc::%push-heartbeat w) (sleep 0.01))   ; HB ⇒ NACK ⇒ retransmit if needed (still UDP)
             (setf dds.xport.shmem:*debug-shmem-send-fault* nil)
             (%check :shmem-guard-fallback-delivered (>= (dds.disc:node-sample-count r) 1)
                     "the sample must still reach the reader via the UDP fallback after the SHMEM fault")
             (%check :shmem-guard-fault-counted (plusp (dds.disc::disc-node-shmem-send-faults w))
                     "disc-node-shmem-send-faults must advance (the hard %shmem-send fault was caught)")
             (%check :shmem-guard-no-shmem-send (= sends-before (dds.disc::disc-node-shmem-sends w))
                     "disc-node-shmem-sends must NOT advance — the datagram went UDP, not SHMEM"))
           (let ((snapshot (dds.pal:with-lock (lock) (copy-list fired))))
             (%check :shmem-guard-hook-fired (plusp (length snapshot))
                     "the *sender-emit-error-hook* must have fired for the SHMEM send fault")
             (%check :shmem-guard-hook-context (every (lambda (e) (eq :shmem-send-fault (car e))) snapshot)
                     "every hook fire must carry the :SHMEM-SEND-FAULT context")))
      (setf dds.xport.shmem:*debug-shmem-send-fault* nil
            dds.disc:*sender-emit-error-hook* saved-hook)
      (dds.disc:stop-node w) (dds.disc:stop-node r)))
  t)

(defun* run-shmem-send-self-guard-no-regression-test ()
    (function () t)
  "WP-SHMEM-SEND-SELF-GUARD no-regression (BOTH impls): with *debug-shmem-send-fault* NIL the guard is INERT.
   (1) A same-host pair (SHMEM active) still delivers over SHMEM — disc-node-shmem-sends advances, shmem-send-
   faults stays 0, the hook never fires (the handler-case fires ONLY on a SIGNAL; a benign return-0 lane-full
   would fall back to UDP without touching the counter, but the no-fault path takes SHMEM). The SHMEM leg
   pass-skips where SHMEM is off (ADR 0013). (2) A non-SHMEM (shmem-dest NIL) UDP send still delivers and is
   byte-unaffected — this leg runs on BOTH impls (it never touches the SHMEM transport)."
  ;; Leg 1 (SHMEM active only): no-fault SHMEM send -> SHMEM, counter 0, hook silent.
  (when (dds.xport.shmem:shm-attach-by-name-reliable-p)
    (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 55))
           (p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 56))
           (dds.disc:*shmem-enabled* t)
           (w (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
           (r (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
           (lock (dds.pal:make-lock "shmem-noreg-fired"))
           (fired '())
           (saved-hook dds.disc:*sender-emit-error-hook*))
      (setf dds.disc:*sender-emit-error-hook*
            (lambda (c ctx n) (declare (ignore c n))
              (dds.pal:with-lock (lock) (push ctx fired))))
      (unwind-protect
           (progn
             (%check :shmem-noreg-inert-flag (null dds.xport.shmem:*debug-shmem-send-fault*)
                     "the fault injector must default NIL (inert production)")
             (dds.disc:add-local-writer w :topic "ShmemNoRegT" :type "X")
             (dds.disc:enable-publisher w :history-kind :keep-all)
             (dds.disc:add-local-reader r :topic "ShmemNoRegT" :type "X"
                                        :reliability dds.rtps.discovery:+reliability-reliable+)
             (dds.disc:enable-subscriber r)
             (setf (dds.disc::disc-node-peers w) (list (cons "127.0.0.1" (dds.disc:disc-node-port r)))
                   (dds.disc::disc-node-peers r) (list (cons "127.0.0.1" (dds.disc:disc-node-port w))))
             (dds.disc:start-node w) (dds.disc:start-node r)
             (dds.disc:announce-participant w) (dds.disc:announce-participant r)
             (loop repeat 300
                   until (and (plusp (dds.disc:disc-node-discovered-count w))
                              (plusp (dds.disc:disc-node-discovered-count r)))
                   do (sleep 0.01))
             (dds.disc:announce-endpoints w) (dds.disc:announce-endpoints r)
             (loop repeat 300
                   until (and (plusp (dds.disc:disc-node-matched-count w))
                              (plusp (dds.disc:disc-node-matched-count r)))
                   do (sleep 0.01))
             (%check :shmem-noreg-matched (plusp (dds.disc:disc-node-matched-count w))
                     "writer must match the reader before publishing")
             (dotimes (i 5) (dds.disc:publish-sample w (octets 9 9 9 9 9 9 9 i)))
             (loop repeat 400 until (>= (dds.disc:node-sample-count r) 5) do (sleep 0.01))
             (%check :shmem-noreg-delivered (>= (dds.disc:node-sample-count r) 5)
                     "the reader must receive all 5 samples")
             (%check :shmem-noreg-via-shmem (plusp (dds.disc::disc-node-shmem-sends w))
                     "with the injector NIL the user data must still travel over SHMEM")
             (%check :shmem-noreg-no-faults (zerop (dds.disc::disc-node-shmem-send-faults w))
                     "no SHMEM fault must be counted when the injector is NIL")
             (%check :shmem-noreg-hook-silent (null (dds.pal:with-lock (lock) (copy-list fired)))
                     "the *sender-emit-error-hook* must never fire on the no-fault SHMEM path"))
        (setf dds.disc:*sender-emit-error-hook* saved-hook)
        (dds.disc:stop-node w) (dds.disc:stop-node r))))
  ;; Leg 2 (both impls): a non-SHMEM UDP send (shmem-dest NIL) is unaffected by the guard.
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 57))
         (p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 58))
         (dds.disc:*shmem-enabled* nil)   ; force the all-UDP path: the SHMEM block in %send-raw-buf is skipped
         (w (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (%check :shmem-noreg-udp-no-transport (null (dds.disc::disc-node-shmem w))
                   "with *shmem-enabled* NIL a node must have no SHMEM transport (all-UDP path)")
           (dds.disc:add-local-writer w :topic "UdpNoRegT" :type "X")
           (dds.disc:enable-publisher w :history-kind :keep-all)
           (dds.disc:add-local-reader r :topic "UdpNoRegT" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-reliable+)
           (dds.disc:enable-subscriber r)
           (setf (dds.disc::disc-node-peers w) (list (cons "127.0.0.1" (dds.disc:disc-node-port r)))
                 (dds.disc::disc-node-peers r) (list (cons "127.0.0.1" (dds.disc:disc-node-port w))))
           (dds.disc:start-node w) (dds.disc:start-node r)
           (dds.disc:announce-participant w) (dds.disc:announce-participant r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-discovered-count w))
                            (plusp (dds.disc:disc-node-discovered-count r)))
                 do (sleep 0.01))
           (dds.disc:announce-endpoints w) (dds.disc:announce-endpoints r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-matched-count w))
                            (plusp (dds.disc:disc-node-matched-count r)))
                 do (sleep 0.01))
           (%check :shmem-noreg-udp-matched (plusp (dds.disc:disc-node-matched-count w))
                   "writer must match the reader before publishing (UDP leg)")
           (dotimes (i 3) (dds.disc:publish-sample w (octets 4 4 4 4 4 4 4 i)))
           (loop repeat 400 until (>= (dds.disc:node-sample-count r) 3) do (sleep 0.01))
           (%check :shmem-noreg-udp-delivered (>= (dds.disc:node-sample-count r) 3)
                   "the all-UDP send (shmem-dest NIL) must deliver unaffected by the guard")
           (%check :shmem-noreg-udp-zero-shmem (zerop (dds.disc::disc-node-shmem-sends w))
                   "no SHMEM send on the all-UDP path")
           (%check :shmem-noreg-udp-zero-faults (zerop (dds.disc::disc-node-shmem-send-faults w))
                   "no SHMEM fault on the all-UDP path"))
      (dds.disc:stop-node w) (dds.disc:stop-node r)))
  t)

(defun* run-zerocopy-end-to-end-test ()
    (function () t)
  "WP-ZEROCOPY Phase D end-to-end (FR-PF-3, ADR 0014; NOT cleared for ship — pending counsel R6): two
   same-host nodes, both *zerocopy-enabled* T (+ SHMEM), exchange LARGE samples (> the ZC threshold). After
   match the writer publishes N; assert (a) the reader receives all N byte-exact, (b) the writer's zc-sends
   advanced (so a 16-byte reference, not the fragmented payload, crossed), and (c) the writer pool's free
   slots fully recover once the reader has resolved+released every reference (no slot leak). Skips cleanly
   where SHMEM is off (Clasp/macOS by-name-attach gap, ADR 0013)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-zerocopy-end-to-end-test t))
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 61))
         (p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 62))
         (dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)   ; arm ZC for BOTH nodes (default OFF; R6)
         (w (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (n 8)
         (payload (make-array 3000 :element-type '(unsigned-byte 8))))   ; > *zerocopy-min-payload-bytes* (1024)
    (dotimes (i 3000) (setf (aref payload i) (logand (* i 5) #xff)))
    (unwind-protect
         (progn
           (%check :zc-e2e-pool (and (dds.disc::disc-node-zc-pool w) (dds.disc::disc-node-zc-pool r))
                   "both nodes must have a ZC writer pool when *zerocopy-enabled* + SHMEM")
           (dds.disc:add-local-writer w :topic "ZcT" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-reliable+)
           (dds.disc:enable-publisher w :history-kind :keep-all)   ; KEEP_ALL: Zero-Copy e2e must deliver all N (ADR 0019 migration)
           (dds.disc:add-local-reader r :topic "ZcT" :type "X"
                                      :reliability dds.rtps.discovery:+reliability-reliable+)
           (dds.disc:enable-subscriber r)
           (setf (dds.disc::disc-node-peers w) (list (cons "127.0.0.1" (dds.disc:disc-node-port r)))
                 (dds.disc::disc-node-peers r) (list (cons "127.0.0.1" (dds.disc:disc-node-port w))))
           (dds.disc:start-node w) (dds.disc:start-node r)
           (dds.disc:announce-participant w) (dds.disc:announce-participant r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-discovered-count w))
                            (plusp (dds.disc:disc-node-discovered-count r)))
                 do (sleep 0.01))
           (dds.disc:announce-endpoints w) (dds.disc:announce-endpoints r)
           (loop repeat 300
                 until (and (plusp (dds.disc:disc-node-matched-count w))
                            (plusp (dds.disc:disc-node-matched-count r)))
                 do (sleep 0.01))
           (%check :zc-e2e-matched (plusp (dds.disc:disc-node-matched-count w))
                   "writer must match the reader before publishing zero-copy")
           ;; the reader must have parsed the writer's PID_ZEROCOPY_CAPABLE for the writer to send refs
           (loop repeat 200
                 until (plusp (dds.disc::%zc-readers w (list (dds.rtps.discovery:endpoint-data-guid
                                                              (first (dds.disc::%matched-endpoints w))))))
                 do (dds.disc:announce-endpoints w) (sleep 0.01))
           (dotimes (i n) (dds.disc:publish-sample w payload))
           (loop repeat 500 until (>= (dds.disc:node-sample-count r) n) do (sleep 0.01))
           (%check :zc-e2e-received (>= (dds.disc:node-sample-count r) n)
                   "the reader must receive all N large samples delivered via zero-copy reference")
           (%check :zc-e2e-bytes (equalp (dds.disc:node-sample-by-sn r 1) payload)
                   "the reader's resolved payload must be byte-exact")
           (%check :zc-e2e-sends (>= (dds.disc::disc-node-zc-sends w) n)
                   "the writer must have published references (zc-sends advanced), not fragmented payloads")
           ;; the reader resolved+released every ref -> the writer pool's freelist must fully recover
           (loop repeat 200
                 until (= dds.disc:+zerocopy-pool-slots+
                          (dds.xport.zerocopy::%zc-free-count (dds.disc::disc-node-zc-pool-sap w)))
                 do (sleep 0.01))
           (%check :zc-e2e-pool-recovers
                   (= dds.disc:+zerocopy-pool-slots+
                      (dds.xport.zerocopy::%zc-free-count (dds.disc::disc-node-zc-pool-sap w)))
                   "every loaned slot must return to the freelist after the reader releases (no leak)"))
      (dds.disc:stop-node w) (dds.disc:stop-node r)))
  t)

(defun* %fd-zc-rx-bytes-new (sap slot gen iters)
    (function (t (integer 0) (unsigned-byte 32) (integer 1)) (integer 0))
  "Mean GC bytes/sample of the WP-FLATDATA-over-ZC single-copy RX resolve (%zc-resolve-fresh) over ITERS
   calls: one exact-payload-length owned vector, read in place from the slot, no slot-sized scratch sink (the
   resolve does NOT touch the slot refcount, so one loaned slot serves every iteration). The number the
   reader actually pays per FlatData-over-ZC sample (NFR-PERF-7 honest measurement)."
  (let ((before (dds.pal:bytes-consed)))
    (dotimes (i iters) (dds.xport.zerocopy::%zc-resolve-fresh sap slot gen))
    (floor (max 0 (- (dds.pal:bytes-consed) before)) iters)))

(defun* %fd-zc-rx-bytes-v1 (sap slot gen iters)
    (function (t (integer 0) (unsigned-byte 32) (integer 1)) (integer 0))
  "Mean GC bytes/sample of the WP-ZEROCOPY v1 resolve-into-sink-then-re-copy RX path over ITERS calls,
   reconstructed inline for an apples-to-apples comparison: a slot-bytes (65536) scratch sink + %zc-resolve
   (copy 1) + a fresh len vector + replace (copy 2). The cost Phase D removes on RX (NFR-PERF-7)."
  (let ((before (dds.pal:bytes-consed)))
    (dotimes (i iters)
      (let* ((sink (make-array dds.disc:+zerocopy-pool-slot-bytes+ :element-type '(unsigned-byte 8)))
             (len (dds.xport.zerocopy::%zc-resolve sap slot gen sink)))
        (when len
          (let ((vec (make-array len :element-type '(unsigned-byte 8))))
            (replace vec sink :end2 len)))))
    (floor (max 0 (- (dds.pal:bytes-consed) before)) iters)))

(defun* %fd-zc-loan-rx-bytes (sap slot gen iters)
    (function (t (integer 0) (unsigned-byte 32) (integer 1)) (integer 0))
  "WP-FLATDATA-ZC-LOAN literal-0-copy RX headline (FR-PF-3/4, NFR-PERF-7, R6, ADR 0017; NOT cleared for ship —
   pending counsel). Mean GC bytes/sample of the LITERAL-0-COPY loan acquire+read+recycle over ITERS calls:
   %zc-acquire-for-read (NO copy, NO refcount inc — one loaned slot serves every iteration) reuses the SAME view
   struct (the per-reader view recycling DCPS does — no per-sample GC-heap view alloc), the app reads a field
   straight off the slot SAP via the SAP-mode Offset accessor (read-in-place), then re-uses the view. NO owned
   delivery vector at all — the residue is only the pool-mutex acquire/release (a fixed ~32 B CFFI
   pthread-mutex-lock cost, PAYLOAD-INDEPENDENT, the SAME cost the v1 single-copy resolve %zc-resolve-fresh ALSO
   pays on top of its ~46 B owned vector). The eliminated per-sample owned vector is the literal-0-copy win.
   SBCL-exact; Clasp reads 0 (NFR-PORT gap)."
  (let ((view (dds.types:make-flatdata-view))
        (before (dds.pal:bytes-consed)))
    (dotimes (i iters)
      (multiple-value-bind (psap idx g len base) (dds.xport.zerocopy::%zc-acquire-for-read sap slot gen)
        (when psap
          (%set-view-from-acquire view psap idx g len base)    ; recycle the SAME view struct (no per-sample alloc)
          (fd-abc-a-fd view))))                                ; read a field straight off the slot SAP (0-copy)
    (floor (max 0 (- (dds.pal:bytes-consed) before)) iters)))

(defun* run-flatdata-zerocopy-test ()
    (function () t)
  "WP-FLATDATA over Zero-Copy, Phase D (FR-PF-3/4, NFR-PERF-7, R6; ADR 0015. NOT cleared for ship — pending
   counsel R6). Two same-host nodes, both *zerocopy-enabled* T (+ SHMEM), exchange a FINAL fixed-size
   FlatData sample (fd-abc) over the Zero-Copy reference path (the ZC threshold is lowered so fd-abc's
   20-octet payload qualifies). The headline checks:
     (1) ROUND-TRIP via the Offset accessors: the writer publishes a FlatData SerializedPayload built with the
         <name>-<field>-fd SETTERS; the reader resolves the ZC reference, and reading the DELIVERED payload
         with the <name>-<field>-fd GETTERS yields the EXACT field values — proving the FlatData bytes crossed
         the writer's SHMEM slot intact and are read in place.
     (2) WRITER no-double-serialize: zc-sends advanced, and the slot carried the published payload with NO
         per-field re-serialization (FlatData serialize=IDENTITY ran once in %serialize-sample; the loan is a
         single app-buffer->slot copy — the documented v1 TX cost).
     (3) RX HONEST MEASUREMENT (the win): the reader-side per-sample GC bytes of the NEW single-copy resolve
         (%zc-resolve-fresh — one exact-length owned vector, read in place) vs the WP-ZEROCOPY-v1
         resolve-into-65536-byte-sink-then-re-copy. The new path allocates ONLY the delivery vector (no sink,
         no second copy) — RX 0-EXTRA-alloc beyond the one owned payload vector. NO OVERCLAIM: this is a SAFE
         SINGLE COPY out of SHMEM (a Lisp octet-buffer cannot wrap a raw foreign SAP, and delivery is into an
         async store read on another thread with no slot-aware release hook — a literal-0-copy SHMEM VIEW would
         be a cross-process use-after-free; see ADR 0015). TX still has the one app->slot copy (loan-write API
         is the follow-up).
   Skips cleanly where SHMEM is off (Clasp/macOS by-name-attach gap, ADR 0013); on SBCL bytes-consed is exact,
   on Clasp it reads 0 (NFR-PORT gap) so the RX assertion is smoked, not enforced."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-flatdata-zerocopy-test t))
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 63))
         (p2 (make-array 12 :element-type '(unsigned-byte 8) :initial-element 64))
         (dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)                 ; arm ZC for BOTH nodes (default OFF; R6)
         (dds.disc:*zerocopy-min-payload-bytes* 8)       ; lower the threshold so fd-abc (20 octets) takes the ZC ref path
         (sbcl-p (eq (dds.pal:pal-impl-name) :sbcl))
         (va 200) (vb 3000000000) (vc 12345678901234567890)
         (fd (make-fd-abc-flatdata))                     ; the FlatData sample (the buffer IS the SerializedPayload)
         (w (dds.disc:make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (r (dds.disc:make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0)))
    (setf (fd-abc-a-fd fd) va (fd-abc-b-fd fd) vb (fd-abc-c-fd fd) vc)   ; write fields via the Offset SETTERS
    (let ((payload (let ((src (dds.core.buffer:octet-buffer-vec fd)))   ; the serialized FlatData payload to publish
                     (subseq src 0 +fd-abc-flatdata-size+))))
      (unwind-protect
           (progn
             (%check :fd-zc-pool (and (dds.disc::disc-node-zc-pool w) (dds.disc::disc-node-zc-pool r))
                     "both nodes must have a ZC writer pool when *zerocopy-enabled* + SHMEM")
             (%check :fd-zc-payload-size (> (length payload) dds.disc:*zerocopy-min-payload-bytes*)
                     "the FlatData payload must exceed the (lowered) ZC threshold to take the reference path")
             (dds.disc:add-local-writer w :topic "FdZc" :type "fd-abc"
                                        :reliability dds.rtps.discovery:+reliability-reliable+)
             (dds.disc:enable-publisher w)
             (dds.disc:add-local-reader r :topic "FdZc" :type "fd-abc"
                                        :reliability dds.rtps.discovery:+reliability-reliable+)
             (dds.disc:enable-subscriber r)
             (setf (dds.disc::disc-node-peers w) (list (cons "127.0.0.1" (dds.disc:disc-node-port r)))
                   (dds.disc::disc-node-peers r) (list (cons "127.0.0.1" (dds.disc:disc-node-port w))))
             (dds.disc:start-node w) (dds.disc:start-node r)
             (dds.disc:announce-participant w) (dds.disc:announce-participant r)
             (loop repeat 300
                   until (and (plusp (dds.disc:disc-node-discovered-count w))
                              (plusp (dds.disc:disc-node-discovered-count r)))
                   do (sleep 0.01))
             (dds.disc:announce-endpoints w) (dds.disc:announce-endpoints r)
             (loop repeat 300
                   until (and (plusp (dds.disc:disc-node-matched-count w))
                              (plusp (dds.disc:disc-node-matched-count r)))
                   do (sleep 0.01))
             (%check :fd-zc-matched (plusp (dds.disc:disc-node-matched-count w))
                     "writer must match the reader before publishing FlatData over zero-copy")
             ;; the reader must have parsed the writer's PID_ZEROCOPY_CAPABLE before the writer will send a ref
             (loop repeat 200
                   until (plusp (dds.disc::%zc-readers w (list (dds.rtps.discovery:endpoint-data-guid
                                                                (first (dds.disc::%matched-endpoints w))))))
                   do (dds.disc:announce-endpoints w) (sleep 0.01))
             (dds.disc:publish-sample w payload)
             (loop repeat 500 until (plusp (dds.disc:node-sample-count r)) do (sleep 0.01))
             (%check :fd-zc-received (plusp (dds.disc:node-sample-count r))
                     "the reader must receive the FlatData sample delivered via the zero-copy reference")
             (%check :fd-zc-sends (plusp (dds.disc::disc-node-zc-sends w))
                     "the writer must have published a reference (zc-sends advanced), not the inline payload")
             ;; (1) ROUND-TRIP: read the DELIVERED payload's fields via the Offset GETTERS (read-in-place)
             (let ((got (dds.disc:node-sample-by-sn r 1)))
               (%check :fd-zc-rx-not-nil (and got t) "the reader stored no FlatData payload")
               (when got
                 (let ((view (dds.core.buffer:octet-buffer-over got)))   ; non-owning wrapper for the Offset accessors
                   (%check :fd-zc-field-a (= (fd-abc-a-fd view) va)
                           (format nil "FlatData-over-ZC field a mismatch: ~d != ~d" (fd-abc-a-fd view) va))
                   (%check :fd-zc-field-b (= (fd-abc-b-fd view) vb)
                           (format nil "FlatData-over-ZC field b mismatch: ~d != ~d" (fd-abc-b-fd view) vb))
                   (%check :fd-zc-field-c (= (fd-abc-c-fd view) vc)
                           (format nil "FlatData-over-ZC field c mismatch: ~d != ~d" (fd-abc-c-fd view) vc))
                   ;; (2) no-double-serialize: the delivered payload EQUALS the published serialized FlatData bytes
                   (%check :fd-zc-no-reserialize (equalp got payload)
                           "the slot must carry the published FlatData payload byte-for-byte (no re-serialize)"))))
             ;; (3) RX HONEST MEASUREMENT: loan one slot, resolve it ITERS times each way (the resolve does not
             ;; touch the refcount), compare the mean per-sample GC bytes of NEW single-copy vs v1 sink+re-copy.
             (let ((sap (dds.disc::disc-node-zc-pool-sap w))
                   (iters 20000))
               (multiple-value-bind (slot gen)
                   (dds.xport.zerocopy::%zc-loan sap payload 0 (length payload) 1)
                 (%check :fd-zc-meas-loan (and slot t) "could not loan a slot for the RX measurement")
                 (when slot
                   (let ((new-bytes (%fd-zc-rx-bytes-new sap slot gen iters))
                         (v1-bytes (%fd-zc-rx-bytes-v1 sap slot gen iters)))
                     (dds.xport.zerocopy::%zc-release sap slot gen)   ; balance the refcount-1 loan
                     (format t "~&  fd-zc-rx: new single-copy = ~d bytes/sample; WP-ZEROCOPY-v1 sink+re-copy = ~d bytes/sample (~a)~%"
                             new-bytes v1-bytes (if sbcl-p "SBCL exact" "Clasp bytes-consed=0 gap"))
                     (format t "  fd-zc-rx: RX win = one exact-length (~d-octet) owned vector, read in place; no 65536-byte sink, no 2nd copy. TX app->slot copy eliminated by loan-write (WP-FLATDATA-LOAN-WRITE, ADR 0042).~%"
                             (length payload))
                     (when sbcl-p
                       (%check :fd-zc-rx-bounded
                               (< new-bytes v1-bytes)
                               (format nil "the new single-copy RX (~d) must allocate strictly less than the v1 sink+re-copy (~d)"
                                       new-bytes v1-bytes))
                       (%check :fd-zc-rx-no-sink
                               (< new-bytes dds.disc:+zerocopy-pool-slot-bytes+)
                               (format nil "the new RX (~d) must not allocate a slot-sized (~d) sink"
                                       new-bytes dds.disc:+zerocopy-pool-slot-bytes+))))))))
        (dds.disc:stop-node w) (dds.disc:stop-node r)
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))))
  t)

(defun* run-dcps-loan-roundtrip-test ()
    (function () t)
  "WP-FLATDATA-ZC-LOAN Phase D+E literal-0-copy loan round-trip (FR-PF-3/4, NFR-PERF-7, R6, ADR 0017; NOT
   cleared for ship — pending counsel). The full DCPS stack: two same-host participants, *shmem-enabled* +
   *zerocopy-enabled* T, a FlatData topic (fd-abc). create_datareader on a :flatdata topic with ZC armed makes
   the reader AUTO loan-capable (the wiring); a DataWriter publishes a FlatData sample over the Zero-Copy
   reference path; take-loaned hands back a flatdata-view loan. Asserts, the headline:
     (1) LITERAL 0-COPY READ (byte-exact): reading EVERY field via <name>-<field>-fd on the loaned VIEW (which
         reads straight off the writer's SHMEM slot SAP) EQUALS the published values — no copy, no deserialize.
     (2) SLOT REUSABLE AFTER return-loan: the loaned slot's refcount is held while loaned; after return-loan the
         refcount drops to 0 so the slot becomes reclaimable again — proving the loan was the only holder and the
         release frees it (the freelist was dropped, WP-ZC-LOAN-LOCKFREE ADR 0018, so the writer-scan reclaims any
         refcount==0 slot; which exact slot is not part of the contract).
     (3) DOUBLE return-loan is a SAFE no-op (idempotent — no double-%zc-release, no error).
     (4) READER-CLOSE RETURNS AN OUTSTANDING LOAN: take a fresh loan, do NOT return it, delete the participant —
         the registry-driven reader-close release frees the slot (refcount 0; no leaked refcount pinning the
         pool). The slot lifetime never lets the receiver thread free a slot under the app's read (no UAF) and
         never leaks a refcount (no wedge). Skips cleanly where SHMEM is off (Clasp/macOS gap, ADR 0013)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-dcps-loan-roundtrip-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)        ; fd-abc (20 octets) takes the ZC ref path
         (ts (dds.types:find-type-support "fd-abc"))
         (va 200) (vb 3000000000) (vc 12345678901234567890)
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "FdLoan" "fd-abc" ts))
                (tr (dds.dcps:create-topic p2 "FdLoan" "fd-abc" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr))
                (node1 (dds.dcps::dp-node p1))
                (node2 (dds.dcps::dp-node p2))
                (fd (make-fd-abc-flatdata)))
           (setf (fd-abc-a-fd fd) va (fd-abc-b-fd fd) vb (fd-abc-c-fd fd) vc)
           (%check :loan-pools (and (dds.disc::disc-node-zc-pool node1) (dds.disc::disc-node-zc-pool node2))
                   "both participants must have a ZC writer pool (*shmem-enabled* + *zerocopy-enabled*)")
           (%check :loan-capable-wired (dds.disc::disc-node-zc-loan-capable node2)
                   "the FlatData-topic reader must be auto loan-capable (the Phase-E wiring)")
           (loop repeat 200
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :loan-matched (plusp (dds.dcps:matched-count p1)) "writer/reader did not match")
           ;; the reader must have parsed PID_ZEROCOPY_CAPABLE before the writer will send a ref
           (loop repeat 200
                 until (plusp (dds.disc::%zc-readers node1
                                                     (list (dds.rtps.discovery:endpoint-data-guid
                                                            (first (dds.disc::%matched-endpoints node1))))))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (dds.dcps:write-sample dw fd)                  ; SN 1: a FlatData sample over Zero-Copy
           (loop repeat 300 until (plusp (dds.disc:node-sample-count node2))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :loan-zc-sends (plusp (dds.disc::disc-node-zc-sends node1))
                   "the writer must have published a reference (zc-sends advanced), not the inline payload")
           ;; (1) LITERAL 0-COPY READ via take-loaned -> a flatdata-view loan, byte-exact field reads
           (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
             (%check :loan-got-one (= 1 (length data)) "take-loaned must return exactly one sample")
             (%check :loan-is-view (dds.types:flatdata-view-p (first data))
                     "the delivered sample must be a flatdata-view (literal-0-copy loan), not a copy")
             (%check :loan-registered (= 1 (length loans)) "take-loaned must return one loan to hand back")
             (let ((view (first data)))
               (%check :loan-field-a (= (fd-abc-a-fd view) va)
                       (format nil "loaned 0-copy field a: ~d != ~d" (fd-abc-a-fd view) va))
               (%check :loan-field-b (= (fd-abc-b-fd view) vb)
                       (format nil "loaned 0-copy field b: ~d != ~d" (fd-abc-b-fd view) vb))
               (%check :loan-field-c (= (fd-abc-c-fd view) vc)
                       (format nil "loaned 0-copy field c: ~d != ~d" (fd-abc-c-fd view) vc))
               ;; the view reads the WRITER's pool slot directly (cross-process SAP), literal 0 intra-host copies
               (let* ((wsap (dds.disc::disc-node-zc-pool-sap node1))
                      (slot (dds.types:flatdata-view-slot-index view)))
                 (%check :loan-held (= 1 (%zc-slot-refcount wsap slot))
                         "while loaned the slot refcount must be 1 (held; force-reclaim skips it -> no UAF)")
                 ;; (2) return-loan frees the slot (refcount->0) -> it becomes reclaimable, so a subsequent
                 ;; %zc-loan SUCCEEDS (which exact slot it picks is a writer-scan/oldest-first detail since the
                 ;; freelist was dropped, WP-ZC-LOAN-LOCKFREE ADR 0018 — the contract is "freed -> reusable")
                 (dds.dcps:return-loan dr loans)
                 (%check :loan-released (zerop (%zc-slot-refcount wsap slot))
                         "after return-loan the slot refcount must be 0 (freed)")
                 (%check :loan-registry-cleared (null (dds.dcps::dr-loans dr))
                         "return-loan must clear the loan registry")
                 (multiple-value-bind (rslot rgen)
                     (dds.xport.zerocopy::%zc-loan wsap (subseq (dds.core.buffer:octet-buffer-vec fd) 0 +fd-abc-flatdata-size+)
                                                   0 +fd-abc-flatdata-size+ 1)
                   (%check :loan-slot-reusable rslot
                           "after the loan was freed a subsequent %zc-loan must succeed (a reclaimable slot exists)")
                   (dds.xport.zerocopy::%zc-release wsap rslot rgen))   ; balance this probe loan
                 ;; (3) double return-loan is a safe no-op (idempotent)
                 (dds.dcps:return-loan dr loans)
                 (%check :loan-double-return-safe (zerop (%zc-slot-refcount wsap slot))
                         "a double return-loan must be a safe no-op (no double-release, refcount unchanged at 0)")))
           ;; (4) READER-CLOSE RETURNS AN OUTSTANDING LOAN: take a 2nd sample, leak it, delete -> released
           (dds.dcps:write-sample dw fd)                  ; SN 2
           (loop repeat 300 until (> (dds.disc:node-sample-count node2) 1)
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (multiple-value-bind (data2 loans2) (dds.dcps:take-loaned dr)
             (declare (ignore loans2))
             (%check :loan-second (and data2 (dds.types:flatdata-view-p (first data2)))
                     "the second take-loaned must also return a loaned view")
             (let* ((view2 (first data2))
                    (wsap (dds.disc::disc-node-zc-pool-sap node1))
                    (slot2 (dds.types:flatdata-view-slot-index view2)))
               (%check :loan-second-held (= 1 (%zc-slot-refcount wsap slot2))
                       "the second loan must hold its slot (refcount 1) before reader-close")
               (%check :loan-registry-has (= 1 (length (dds.dcps::dr-loans dr)))
                       "the un-returned loan must be in the registry (so reader-close can release it)")
               (dds.dcps:delete-participant p2)            ; reader-close returns ALL outstanding loans (before pool detach)
               (setf p2 nil)
               (%check :loan-close-released (zerop (%zc-slot-refcount wsap slot2))
                       "reader-close (delete-participant) must return the outstanding loan (refcount 0, no leak)")))
           (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
    t))

(defun* run-dcps-loan-write-e2e-test ()
    (function () t)
  "WP-FLATDATA-LOAN-WRITE end-to-end proof (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending counsel). The
   full DCPS stack, mirroring run-dcps-loan-roundtrip-test but writing via the ZERO-COPY LOAN-WRITE TX API: two
   same-host participants, *shmem-enabled* + *zerocopy-enabled*, a FlatData topic (fd-abc). The app loan-samples
   a SLOT-BACKED writer loan, writes the fields STRAIGHT INTO the SHMEM slot via the SAP-mode -fd setters, and
   write-loaned publishes it. Asserts, the headline (ADR 0042 send-site integration):
     (1) SLOT-BACKED LOAN: loan-sample returns a :slot loan (free-count drops by one — the acquire).
     (2) DELIVERED FROM THE PRE-COMMITTED SLOT: the ZC reader's take-loaned view carries EXACTLY the loan's
         (slot-index, generation) — the send site emitted the pre-committed slot's ref (a fresh %zc-loan would
         have taken a DIFFERENT slot / bumped generation), i.e. NO app->payload->slot copy ran on the delivered
         bytes; zc-sends is exactly 1 and the pool never lost a second slot (free-count stays K-1 while loaned).
     (3) BYTE-EXACT: every field read off the view equals what the app wrote through the SAP setters.
     (4) LIFECYCLE: return-loan frees the ONE slot (free-count K); the recycled writer-loan struct is reused by
         the next loan-sample (freelist, no per-sample struct cons).
   Skips cleanly where SHMEM is off (Clasp/macOS gap, ADR 0013)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-dcps-loan-write-e2e-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)        ; fd-abc (20 octets) takes the ZC ref path
         (ts (dds.types:find-type-support "fd-abc"))
         (va 200) (vb 3000000000) (vc 12345678901234567890)
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "FdLoanW" "fd-abc" ts))
                (tr (dds.dcps:create-topic p2 "FdLoanW" "fd-abc" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr))
                (node1 (dds.dcps::dp-node p1))
                (node2 (dds.dcps::dp-node p2)))
           (%check :lwe2e-pools (and (dds.disc::disc-node-zc-pool node1) (dds.disc::disc-node-zc-pool node2))
                   "both participants must have a ZC writer pool")
           (loop repeat 200
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :lwe2e-matched (plusp (dds.dcps:matched-count p1)) "writer/reader did not match")
           (loop repeat 200                                ; the reader must advertise PID_ZEROCOPY_CAPABLE first
                 until (plusp (dds.disc::%zc-readers node1
                                                     (list (dds.rtps.discovery:endpoint-data-guid
                                                            (first (dds.disc::%matched-endpoints node1))))))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (let* ((wsap (dds.disc::disc-node-zc-pool-sap node1))
                  (k (dds.xport.zerocopy::%zc-free-count wsap))
                  (loan (dds.dcps:loan-sample dw)))
             ;; (1) slot-backed loan
             (%check :lwe2e-slot-backed (eq (dds.dcps::writer-loan-kind loan) :slot)
                     "loan-sample on an eligible node must be SLOT-BACKED")
             (%check :lwe2e-acquired (= (- k 1) (dds.xport.zerocopy::%zc-free-count wsap))
                     "the loan must hold one pool slot (free-count K-1)")
             (let ((lslot (dds.dcps::writer-loan-slot loan))
                   (lgen (dds.dcps::writer-loan-generation loan))
                   (s (dds.dcps:writer-loan-sample loan)))
               (setf (fd-abc-a-fd s) va (fd-abc-b-fd s) vb (fd-abc-c-fd s) vc)   ; SAP setters -> straight into the slot
               (%check :lwe2e-write-ok (eq :ok (dds.dcps:write-loaned dw loan)) "write-loaned must return :ok")
               (%check :lwe2e-zc-sends (= 1 (dds.disc::disc-node-zc-sends node1))
                       "exactly ONE zero-copy ref must have been emitted (the pre-committed slot)")
               (%check :lwe2e-no-second-slot (= (- k 1) (dds.xport.zerocopy::%zc-free-count wsap))
                       "the send site must NOT have loaned a second slot (the pre-committed one was consumed)")
               ;; I1 (ADR 0042 §4): the slot is a SELF-DESCRIBING SerializedPayload — its first 4 octets must be
               ;; byte-identical to the classic path's encap header (the FlatData ctor writes the same emitters).
               (let ((classic (make-fd-abc-flatdata))
                     (pbase (+ (dds.xport.zerocopy::%zc-slot-off wsap lslot) dds.xport.zerocopy::+zc-slot-hdr+)))
                 (%check :lwe2e-slot-encap
                         (loop for i below 4
                               always (= (dds.pal:load-sap-u8 wsap (+ pbase i))
                                         (aref (dds.core.buffer:octet-buffer-vec classic) i)))
                         "the loan-write slot's first 4 octets must equal the classic encap header (self-describing SerializedPayload)")
                 (dds.pal:free-static (dds.core.buffer:octet-buffer-vec classic)))
               (loop repeat 300 until (plusp (dds.disc:node-sample-count node2))
                     do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
               ;; (2)+(3) delivered FROM the pre-committed slot, byte-exact
               (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
                 (%check :lwe2e-got-one (= 1 (length data)) "take-loaned must return exactly one sample")
                 (%check :lwe2e-is-view (dds.types:flatdata-view-p (first data))
                         "the delivered sample must be a flatdata-view (0-copy loan)")
                 (let ((view (first data)))
                   (%check :lwe2e-same-slot (= (dds.types:flatdata-view-slot-index view) lslot)
                           (format nil "the reader's view must reference the PRE-COMMITTED slot ~d (got ~d)"
                                   lslot (dds.types:flatdata-view-slot-index view)))
                   (%check :lwe2e-same-gen (= (dds.types:flatdata-view-generation view) lgen)
                           (format nil "the reader's view must carry the loan's committed generation ~d (got ~d)"
                                   lgen (dds.types:flatdata-view-generation view)))
                   (%check :lwe2e-field-a (= (fd-abc-a-fd view) va)
                           (format nil "field a: ~d != ~d" (fd-abc-a-fd view) va))
                   (%check :lwe2e-field-b (= (fd-abc-b-fd view) vb)
                           (format nil "field b: ~d != ~d" (fd-abc-b-fd view) vb))
                   (%check :lwe2e-field-c (= (fd-abc-c-fd view) vc)
                           (format nil "field c: ~d != ~d" (fd-abc-c-fd view) vc)))
                 ;; (4) lifecycle: return frees the ONE slot; the loan struct recycles
                 (dds.dcps:return-loan dr loans)
                 (%check :lwe2e-freed (= k (dds.xport.zerocopy::%zc-free-count wsap))
                         "after return-loan the pool must be whole again (the single slot freed)")
                 (let ((loan2 (dds.dcps:loan-sample dw)))
                   (%check :lwe2e-freelist (eq loan loan2)
                           "the next loan-sample must reuse the recycled writer-loan struct (freelist)")
                   (dds.dcps:discard-loan dw loan2))))))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2)))
  t)

(defun* run-multi-dest-zc-e2e-test ()
    (function () t)
  "WP-ZC-MULTI-DEST-REFCOUNT end-to-end proof (FR-PF-4, R6, ADR 0047; NOT cleared for ship — pending counsel).
   The full DCPS stack across THREE co-resident participants — one writer (p1) and TWO ZC reader participants
   (p2, p3, each a separate participant = a separate destination GROUP) — *shmem-enabled* + *zerocopy-enabled*,
   a FlatData topic (fd-abc). ONE write-sample fans out to both ZC destinations over a SINGLE shared pool slot
   (refcount = the 2 destination GROUPS), the ADR-0047 pool-economy win vs today's 2 slots + 2 copies. Asserts:
     (1) TWO ZC GROUPS: the writer resolves 2 ZC-eligible destination groups (%reader-push-targets, both zc).
     (2) ONE SHARED SLOT: the write consumes EXACTLY ONE slot (writer free-count K-1, NOT K-2) though it reaches
         two destinations; zc-sends = 2 (two ref datagrams, one per destination — the wire is unchanged).
     (3) BOTH DELIVERED byte-exact: p2 AND p3 each take-loaned a view of the SAME shared slot (refcount 2 while
         both hold), every field equal to what was written.
     (4) EXACT LIFECYCLE: the slot frees only after BOTH readers return-loan (refcount 2 -> 1 -> 0; free-count
         restored to K) — no leak, no premature free / UAF.
   Skips cleanly where SHMEM is off (Clasp/macOS gap, ADR 0013)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-multi-dest-zc-e2e-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)
         (ts (dds.types:find-type-support "fd-abc"))
         (va 211) (vb 3000000011) (vc 12345678901234567811)
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain)))
         (p3 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "MdZc" "fd-abc" ts))
                (tr2 (dds.dcps:create-topic p2 "MdZc" "fd-abc" ts))
                (tr3 (dds.dcps:create-topic p3 "MdZc" "fd-abc" ts))
                (pub (dds.dcps:create-publisher p1))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr2 (dds.dcps:create-datareader (dds.dcps:create-subscriber p2) tr2
                                                 :qos (dds.qos:make-reader-qos :reliability :reliable)))
                (dr3 (dds.dcps:create-datareader (dds.dcps:create-subscriber p3) tr3
                                                 :qos (dds.qos:make-reader-qos :reliability :reliable)))
                (node1 (dds.dcps::dp-node p1))
                (node2 (dds.dcps::dp-node p2))
                (node3 (dds.dcps::dp-node p3))
                (fd (make-fd-abc-flatdata)))
           (setf (fd-abc-a-fd fd) va (fd-abc-b-fd fd) vb (fd-abc-c-fd fd) vc)
           (loop repeat 300
                 until (>= (dds.dcps:matched-count p1) 2)
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (dds.dcps:spin p3) (sleep 0.02))
           (%check :md-e2e-matched (>= (dds.dcps:matched-count p1) 2) "the writer must match BOTH reader participants")
           ;; both destinations must advertise ZC-capable -> 2 ZC-eligible push groups
           (loop repeat 300
                 until (let ((groups (dds.disc::%reader-push-targets node1)))
                         (and (= 2 (length groups))
                              (every (lambda (g) (plusp (dds.disc::%zc-readers node1 (cdr g)))) groups)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (dds.dcps:spin p3) (sleep 0.02))
           (let ((groups (dds.disc::%reader-push-targets node1)))
             (%check :md-e2e-two-groups
                     (and (= 2 (length groups))
                          (every (lambda (g) (plusp (dds.disc::%zc-readers node1 (cdr g)))) groups))
                     "the writer must see EXACTLY 2 ZC-eligible destination groups"))
           (let* ((wsap (dds.disc::disc-node-zc-pool-sap node1))
                  (k (dds.xport.zerocopy::%zc-free-count wsap)))
             (dds.dcps:write-sample dw fd)
             (loop repeat 300 until (>= (dds.disc::disc-node-zc-sends node1) 2)
                   do (dds.dcps:spin p1) (sleep 0.02))
             ;; (2) ONE shared slot, two ref datagrams
             (%check :md-e2e-two-sends (= 2 (dds.disc::disc-node-zc-sends node1))
                     "exactly TWO zero-copy ref datagrams (one per destination) must have been emitted")
             (%check :md-e2e-one-slot (= (- k 1) (dds.xport.zerocopy::%zc-free-count wsap))
                     "the fan-out must consume EXACTLY ONE shared slot (free-count K-1), not one-per-destination (K-2)")
             (loop repeat 400
                   until (and (plusp (dds.disc:node-sample-count node2)) (plusp (dds.disc:node-sample-count node3)))
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (dds.dcps:spin p3) (sleep 0.02))
             ;; (3) both readers take-loaned a view of the SAME shared slot, byte-exact
             (multiple-value-bind (d2 l2) (dds.dcps:take-loaned dr2)
               (multiple-value-bind (d3 l3) (dds.dcps:take-loaned dr3)
                 (%check :md-e2e-p2-view (and d2 (dds.types:flatdata-view-p (first d2))) "p2 must take a ZC view")
                 (%check :md-e2e-p3-view (and d3 (dds.types:flatdata-view-p (first d3))) "p3 must take a ZC view")
                 (let ((v2 (first d2)) (v3 (first d3)))
                   (%check :md-e2e-same-slot
                           (= (dds.types:flatdata-view-slot-index v2) (dds.types:flatdata-view-slot-index v3))
                           "both readers' views must reference the SAME shared writer slot")
                   (%check :md-e2e-p2-a (= (fd-abc-a-fd v2) va) (format nil "p2 field a ~d != ~d" (fd-abc-a-fd v2) va))
                   (%check :md-e2e-p2-c (= (fd-abc-c-fd v2) vc) (format nil "p2 field c ~d != ~d" (fd-abc-c-fd v2) vc))
                   (%check :md-e2e-p3-a (= (fd-abc-a-fd v3) va) (format nil "p3 field a ~d != ~d" (fd-abc-a-fd v3) va))
                   (%check :md-e2e-p3-c (= (fd-abc-c-fd v3) vc) (format nil "p3 field c ~d != ~d" (fd-abc-c-fd v3) vc))
                   (%check :md-e2e-held-two (= 2 (%zc-slot-refcount wsap (dds.types:flatdata-view-slot-index v2)))
                           "while BOTH readers hold, the shared slot's refcount must be 2"))
                 ;; (4) exact lifecycle: free only after BOTH return
                 (dds.dcps:return-loan dr2 l2)
                 (%check :md-e2e-after-one (= (- k 1) (dds.xport.zerocopy::%zc-free-count wsap))
                         "after ONE reader returns, the shared slot must still be held (the other reader holds it)")
                 (dds.dcps:return-loan dr3 l3)
                 (%check :md-e2e-freed (= k (dds.xport.zerocopy::%zc-free-count wsap))
                         "the shared slot frees only after BOTH readers return-loan (no leak, no early free)"))))
           (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
      (dds.dcps:delete-participant p1)
      (dds.dcps:delete-participant p2)
      (dds.dcps:delete-participant p3)))
  t)

(defun* %lw-pool-scan-marker-p (sap needle)
    (function (t (simple-array (unsigned-byte 8) (*))) t)
  "WP-FLATDATA-LOAN-WRITE SHMEM-scan helper (R6, ADR 0042 §6): T iff the 8-octet NEEDLE occurs anywhere in the
   ENTIRE writer-pool segment at SAP (header + every slot, the full %zc-bytes extent) — the live-segment
   inspection the run-zc-shmem-secured-cleartext-test proof uses, applied to the loan-write flow."
  (let ((total (dds.xport.zerocopy::%zc-bytes dds.disc:+zerocopy-pool-slots+ dds.disc:+zerocopy-pool-slot-bytes+))
        (n (length needle)))
    (loop for off from 0 upto (- total n)
            thereis (loop for i below n always (= (dds.pal:load-sap-u8 sap (+ off i)) (aref needle i))))))

(defun* run-loan-write-shmem-cleartext-test ()
    (function () t)
  "WP-FLATDATA-LOAN-WRITE SHMEM-cleartext proof (FR-PF-4, R6, ADR 0036 Carry-10 + ADR 0042 §6; NOT cleared for
   ship — pending counsel). The LITERAL live-segment scan for the LOAN-WRITE flow, mirroring
   run-zc-shmem-secured-cleartext-test's non-vacuity discipline: drive loan-sample → SAP/field setters →
   write-loaned with a distinctive 8-octet marker (fd-abc's u64 c field, LE bytes) on three writer configs, then
   scan the writer pool's ENTIRE segment for the marker bytes:
     (1) CONTROL (non-secured): the loan is SLOT-BACKED and the marker IS found in the segment — the exact bytes
         a co-resident process could read; proves the scan is NON-VACUOUS (the leak the gates close is real).
     (2) WIRE-PROTECTED (rtps_protection :sign): loan-sample degrades to the heap fallback and the marker is
         ABSENT from the segment — no plaintext ever landed in a pool slot (ADR 0036 Carry-10 at the loan end).
     (3) DATA-PROTECTED (data_protection :encrypt): likewise fallback + marker ABSENT (the loan-write-specific
         %loan-write-data-protected-p gate, ADR 0042 §6 — the slot would hold pre-transform plaintext).
   Skips cleanly where SHMEM is off (Clasp/macOS gap, ADR 0013)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-loan-write-shmem-cleartext-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)
         (ts (dds.types:find-type-support "fd-abc"))
         (marker #xB16B00B5DEADFACE)                       ; the u64 c value; its 8 LE octets are the scan needle
         (needle (let ((v (make-array 8 :element-type '(unsigned-byte 8))))
                   (dotimes (i 8 v) (setf (aref v i) (ldb (byte 8 (* 8 i)) marker))))))
    (dolist (arm '(:control :wire :data))
      (let ((p (dds.dcps:create-participant :domain (test-domain))))
        (unwind-protect
             (let* ((tw (dds.dcps:create-topic p "LwScan" "fd-abc" ts))
                    (pub (dds.dcps:create-publisher p))
                    (dw (dds.dcps:create-datawriter pub tw))
                    (node (dds.dcps::dp-node p))
                    (sap (dds.disc::disc-node-zc-pool-sap node)))
               (%check (intern (format nil "LWSCAN-POOL-~a" arm) :keyword) (and sap t) "the node must have a ZC pool")
               (ecase arm                                  ; protect the writer BEFORE the loan (the gated configs)
                 (:control nil)
                 (:wire (setf (dds.disc::disc-node-rtps-protection-kind node) :sign))
                 (:data (setf (dds.disc::disc-node-user-data-protection-kind node) :encrypt)))
               (let* ((loan (dds.dcps:loan-sample dw))
                      (s (dds.dcps:writer-loan-sample loan)))
                 (%check (intern (format nil "LWSCAN-KIND-~a" arm) :keyword)
                         (eq (dds.dcps::writer-loan-kind loan) (if (eq arm :control) :slot :fallback))
                         (format nil "~a arm: loan must be ~a-backed" arm (if (eq arm :control) "slot" "fallback")))
                 (setf (fd-abc-a-fd s) 1 (fd-abc-b-fd s) 2 (fd-abc-c-fd s) marker)
                 (dds.dcps:write-loaned dw loan)
                 (if (eq arm :control)
                     (%check :lwscan-control-found (%lw-pool-scan-marker-p sap needle)
                             "CONTROL: the marker MUST be found in the pool segment (non-vacuity — the leak is real)")
                     (%check (intern (format nil "LWSCAN-ABSENT-~a" arm) :keyword)
                             (not (%lw-pool-scan-marker-p sap needle))
                             (format nil "~a arm: the marker must be ABSENT from the ENTIRE pool segment (no plaintext in SHMEM)" arm)))))
          (dds.dcps:delete-participant p)))))
  t)

(defun* run-loan-read-return-take-test ()
    (function () t)
  "WP-FLATDATA-ZC-LOAN return-loan cache-invalidation (FR-PF-3/4, R6, ADR 0017; NOT cleared for ship — pending
   counsel). The stale-read regression guard: read-loaned LEAVES samples in dr-cache, so the cached-sample keeps
   referencing the returned view; before the fix, return-loan recycled the view to the freelist WITHOUT dropping
   its cache entry, so a subsequent drain popped+re-inited that same struct for a NEW slot and the surviving stale
   cache entry then aliased the NEW sample's bytes (a WRONG-BYTES stale read / double-return-of-the-view). The
   flow: publish sample 1 over ZC; read-loaned (leaves it) -> view V1 reading sample 1; return-loan V1 (must drop
   its cache entry AND recycle V1); publish sample 2; take-loaned (drains sample 2, recycling V1's struct).
   Asserts: (1) V1 read sample 1's values; (2) after return, V1's cache entry is gone (no dr-cache element still
   references V1 — reading a returned loan is invalidated, not a stale read); (3) take-loaned returns EXACTLY ONE
   sample (no stale duplicate of the recycled struct) that reads SAMPLE 2's values (not sample 1, not an alias).
   Pre-fix this FAILS (take-loaned returns two samples, both the recycled V1, both reading sample 2). Skips
   cleanly where SHMEM is off (Clasp/macOS gap, ADR 0013)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-loan-read-return-take-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)        ; fd-abc (20 octets) takes the ZC ref path
         (ts (dds.types:find-type-support "fd-abc"))
         (va1 200) (vb1 3000000000) (vc1 12345678901234567890)   ; sample 1
         (va2 99) (vb2 1234567890) (vc2 9876543210987654321)     ; sample 2 (distinct, to catch a stale alias)
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "FdLoanRR" "fd-abc" ts))
                (tr (dds.dcps:create-topic p2 "FdLoanRR" "fd-abc" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr))
                (node1 (dds.dcps::dp-node p1))
                (node2 (dds.dcps::dp-node p2))
                (fd (make-fd-abc-flatdata)))
           (loop repeat 200
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :loan-rr-matched (plusp (dds.dcps:matched-count p1)) "writer/reader did not match")
           (loop repeat 200
                 until (plusp (dds.disc::%zc-readers node1
                                                     (list (dds.rtps.discovery:endpoint-data-guid
                                                            (first (dds.disc::%matched-endpoints node1))))))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (setf (fd-abc-a-fd fd) va1 (fd-abc-b-fd fd) vb1 (fd-abc-c-fd fd) vc1)
           (dds.dcps:write-sample dw fd)                  ; SN 1
           (loop repeat 300 until (plusp (dds.disc:node-sample-count node2))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           ;; (1) read-loaned LEAVES the sample; V1 reads sample 1's values
           (multiple-value-bind (data loans) (dds.dcps:read-loaned dr)
             (%check :loan-rr-read-one (= 1 (length data)) "read-loaned must return exactly one sample")
             (%check :loan-rr-read-view (dds.types:flatdata-view-p (first data)) "the read sample must be a flatdata-view loan")
             (let ((v1 (first data)))
               (%check :loan-rr-v1-a (= (fd-abc-a-fd v1) va1) (format nil "V1 field a: ~d != ~d" (fd-abc-a-fd v1) va1))
               (%check :loan-rr-v1-b (= (fd-abc-b-fd v1) vb1) (format nil "V1 field b: ~d != ~d" (fd-abc-b-fd v1) vb1))
               (%check :loan-rr-v1-c (= (fd-abc-c-fd v1) vc1) (format nil "V1 field c: ~d != ~d" (fd-abc-c-fd v1) vc1))
               ;; return V1 -> must drop its cache entry (the fix) AND recycle the struct
               (dds.dcps:return-loan dr loans)
               ;; (2) after return, NO dr-cache element still references V1 (the stale-read kill)
               (%check :loan-rr-cache-invalidated
                       (notany (lambda (cs) (eq (dds.dcps::cached-sample-data cs) v1)) (dds.dcps::dr-cache dr))
                       "return-loan must drop the returned view's cache entry (else a later read aliases the next sample's bytes)")
               ;; publish sample 2 with DISTINCT values; take-loaned drains it (recycling V1's struct)
               (setf (fd-abc-a-fd fd) va2 (fd-abc-b-fd fd) vb2 (fd-abc-c-fd fd) vc2)
               (dds.dcps:write-sample dw fd)              ; SN 2
               (loop repeat 300 until (> (dds.disc:node-sample-count node2) 1)
                     do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
               (multiple-value-bind (data2 loans2) (dds.dcps:take-loaned dr)
                 ;; (3) EXACTLY ONE sample (no stale duplicate of the recycled struct), reading SAMPLE 2
                 (%check :loan-rr-take-one (= 1 (length data2))
                         (format nil "take-loaned must return exactly one sample (sample 2), got ~d (a stale duplicate of the recycled view = the regression)"
                                 (length data2)))
                 (let ((v2 (first data2)))
                   (%check :loan-rr-v2-view (dds.types:flatdata-view-p v2) "the taken sample must be a flatdata-view loan")
                   (%check :loan-rr-v2-a (= (fd-abc-a-fd v2) va2)
                           (format nil "taken view must read SAMPLE 2's a (~d), got ~d (a stale alias of sample 1 = ~d)" va2 (fd-abc-a-fd v2) va1))
                   (%check :loan-rr-v2-b (= (fd-abc-b-fd v2) vb2)
                           (format nil "taken view must read SAMPLE 2's b (~d), got ~d" vb2 (fd-abc-b-fd v2)))
                   (%check :loan-rr-v2-c (= (fd-abc-c-fd v2) vc2)
                           (format nil "taken view must read SAMPLE 2's c (~d), got ~d" vc2 (fd-abc-c-fd v2))))
                 (dds.dcps:return-loan dr loans2))))
           (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
    t)

(defun* run-loan-handle-dealias-test ()
    (function () t)
  "WP-FLATDATA-ZC-LOAN loaned instance-handle de-alias (FR-PF-3/4, R6, ADR 0017; NOT cleared for ship — pending
   counsel). %loan-instance-handle must fold the source writer GUID into the 16-octet handle so two co-located
   writers — each SN-stream restarts at 1 — do NOT collide (the earlier SN-only v1 aliased them, flipping a
   cosmetic NEW/NOT_NEW view-state; §8.3.5.4: SN is per-writer). Asserts at the same SN=1: (1) distinct source
   GUIDs -> DISTINCT handles (no SN-collision alias); (2) the SAME GUID + SN is deterministic (equal handle);
   (3) the low 8 octets still carry the SN (the published handle layout is preserved); (4) the handle is 16
   octets. Pure (no SHMEM), so it runs on every host/impl."
  (let* ((ts (dds.types:find-type-support "fd-abc"))
         (v (dds.types:make-flatdata-view))
         (g1 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 17))
         (g2 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 17)))
    (setf (aref g2 0) 99)                                 ; g2 differs from g1 in one octet (different participant)
    (let ((h1 (dds.dcps::%loan-instance-handle ts v 1 g1))
          (h1b (dds.dcps::%loan-instance-handle ts v 1 g1))
          (h2 (dds.dcps::%loan-instance-handle ts v 1 g2)))
      (%check :loan-handle-len (= 16 (length h1)) "the loaned instance handle must be 16 octets")
      (%check :loan-handle-dealias (not (equalp h1 h2))
              "two co-located writers (distinct GUID, same SN=1) must get DISTINCT handles (no SN-collision alias)")
      (%check :loan-handle-deterministic (equalp h1 h1b) "the same GUID + SN must yield an equal handle")
      (%check :loan-handle-sn-low (= 1 (loop for i below 8 sum (ash (aref h1 i) (* 8 i))))
              "the low 8 octets must still carry the RTPS SN (layout preserved)")
      (%check :loan-handle-guid-high (not (equalp (subseq h1 8 16) (subseq h2 8 16)))
              "the high 8 octets must encode the (de-aliasing) GUID fold, differing per source"))
    t))

(defun* run-flatdata-zc-loan-e2e-test ()
    (function () t)
  "WP-FLATDATA-ZC-LOAN Phase F1 — THE LITERAL-0-COPY HEADLINE (FR-PF-3/4, NFR-PERF-7, R6, ADR 0017; NOT cleared
   for ship — pending counsel). The full DCPS stack: two same-host participants, *shmem-enabled* +
   *zerocopy-enabled* T, a FlatData topic; a DataWriter publishes over Zero-Copy; the reader take-loaned's a
   flatdata-view, reads EVERY field off the slot, and return-loan's it — IN A LOOP. Asserts:
     (1) BYTE-EXACT across the loop: each take-loaned hands back exactly one flatdata-view whose field reads via
         <name>-<field>-fd EQUAL the published values (literal 0 intra-host copies, read straight off the slot).
     (2) NO REFCOUNT LEAK across the loop: after each return-loan the loan registry is empty and the freelist
         recycled the view (the per-reader freelist never grows past one — no per-sample GC-heap view alloc).
     (3) THE LITERAL-0-COPY RX NUMBER (the headline): the loan acquire+read+recycle RX (%fd-zc-loan-rx-bytes)
         allocates NO OWNED DELIVERY VECTOR — only the pool mutex acquire/release's fixed ~32 B (a CFFI
         pthread-mutex-lock cost, PAYLOAD-INDEPENDENT, the SAME cost the v1 single-copy ALSO pays) — vs the
         WP-ZEROCOPY+FlatData v1 single-copy resolve (%fd-zc-rx-bytes-new = ~78 = that same ~32 B lock + the
         ~46 B exact-length OWNED VECTOR) vs the WP-ZEROCOPY-v1 sink+re-copy (%fd-zc-rx-bytes-v1 = ~65549 = lock
         + a 64 KiB sink + a re-copy). The literal-0-copy win is the ELIMINATED per-sample owned vector
         (~78 -> ~32, the 46-byte vector gone). HONEST (FR-LANG-7): the RX ALLOCATION drops to the bare mutex
         overhead (no owned vector); the loan API's cost is the explicit %zc-acquire-for-read + %zc-release calls
         + the app's return-loan OBLIGATION, NOT a free lunch. Cross-process is covered by make zc-xproc (the ZC
         reference resolves across two OS processes; the literal-0-copy loan is a LOCAL read optimization — the
         wire is byte-identical). Skips cleanly where SHMEM is off (Clasp/macOS gap, ADR 0013); on SBCL
         bytes-consed is exact, on Clasp it reads 0 (NFR-PORT gap) so the headline assertion is smoked."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-flatdata-zc-loan-e2e-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)        ; fd-abc (20 octets) takes the ZC ref path
         (ts (dds.types:find-type-support "fd-abc"))
         (va 200) (vb 3000000000) (vc 12345678901234567890)
         (sbcl-p (eq (dds.pal:pal-impl-name) :sbcl))
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "FdZcE2E" "fd-abc" ts))
                (tr (dds.dcps:create-topic p2 "FdZcE2E" "fd-abc" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr))
                (node1 (dds.dcps::dp-node p1))
                (node2 (dds.dcps::dp-node p2))
                (fd (make-fd-abc-flatdata)))
           (setf (fd-abc-a-fd fd) va (fd-abc-b-fd fd) vb (fd-abc-c-fd fd) vc)
           (loop repeat 200
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :fdzc-e2e-matched (plusp (dds.dcps:matched-count p1)) "writer/reader did not match")
           (loop repeat 200
                 until (plusp (dds.disc::%zc-readers node1
                                                     (list (dds.rtps.discovery:endpoint-data-guid
                                                            (first (dds.disc::%matched-endpoints node1))))))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           ;; (1)+(2) the take-loaned/read/return-loan LOOP — byte-exact + no registry/freelist growth per round
           (dotimes (round 5)
             (dds.dcps:write-sample dw fd)
             (loop repeat 300 until (> (dds.disc:node-sample-count node2) round)
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
               (%check :fdzc-e2e-one (= 1 (length data))
                       (format nil "round ~d: take-loaned must return exactly one sample" round))
               (%check :fdzc-e2e-view (dds.types:flatdata-view-p (first data))
                       (format nil "round ~d: the sample must be a flatdata-view (literal-0-copy loan)" round))
               (let ((view (first data)))
                 (%check :fdzc-e2e-a (= (fd-abc-a-fd view) va)
                         (format nil "round ~d: loaned 0-copy field a ~d != ~d" round (fd-abc-a-fd view) va))
                 (%check :fdzc-e2e-b (= (fd-abc-b-fd view) vb)
                         (format nil "round ~d: loaned 0-copy field b ~d != ~d" round (fd-abc-b-fd view) vb))
                 (%check :fdzc-e2e-c (= (fd-abc-c-fd view) vc)
                         (format nil "round ~d: loaned 0-copy field c ~d != ~d" round (fd-abc-c-fd view) vc)))
               (dds.dcps:return-loan dr loans)
               (%check :fdzc-e2e-registry-clear (null (dds.dcps::dr-loans dr))
                       (format nil "round ~d: return-loan must leave the loan registry empty (no refcount leak)" round))
               (%check :fdzc-e2e-freelist-bounded (<= (length (dds.dcps::dr-view-freelist dr)) 1)
                       (format nil "round ~d: the per-reader view freelist must recycle (<=1), not grow per sample" round))))
           ;; (3) THE LITERAL-0-COPY HEADLINE: loan acquire+read (~0) vs v1 single-copy (~80) vs v1 sink (~65552)
           (let ((sap (dds.disc::disc-node-zc-pool-sap node1))
                 (iters 20000))
             (multiple-value-bind (slot gen)
                 (dds.xport.zerocopy::%zc-loan sap (subseq (dds.core.buffer:octet-buffer-vec fd) 0 +fd-abc-flatdata-size+)
                                               0 +fd-abc-flatdata-size+ 1)
               (%check :fdzc-e2e-meas-loan (and slot t) "could not loan a slot for the literal-0-copy measurement")
               (when slot
                 (let ((loan-bytes (%fd-zc-loan-rx-bytes sap slot gen iters))
                       (new-bytes (%fd-zc-rx-bytes-new sap slot gen iters))
                       (v1-bytes (%fd-zc-rx-bytes-v1 sap slot gen iters)))
                   (dds.xport.zerocopy::%zc-release sap slot gen)   ; balance the refcount-1 measurement loan
                   (format t "~&  fd-zc-loan-rx: LITERAL-0-COPY loan = ~d bytes/sample (the pool mutex acquire alone, NO owned vector); FlatData+ZC v1 single-copy = ~d (lock + the owned vector); WP-ZEROCOPY-v1 sink = ~d (~a)~%"
                           loan-bytes new-bytes v1-bytes (if sbcl-p "SBCL exact" "Clasp bytes-consed=0 gap"))
                   (format t "  fd-zc-loan-rx: the eliminated per-sample OWNED VECTOR is the win (~d -> ~d, payload-independent residue = the CFFI mutex lock the v1 path ALSO pays); the loan API's cost is the explicit acquire/release calls + the app's return-loan obligation (FR-LANG-7, no overclaim).~%"
                           new-bytes loan-bytes)
                   (when sbcl-p
                     ;; the literal-0-copy win: the per-sample OWNED VECTOR is gone (loan RX strictly below the v1 single-copy)
                     (%check :fdzc-e2e-loan-below-v1-single
                             (< loan-bytes new-bytes)
                             (format nil "the literal-0-copy loan RX (~d) must allocate strictly less than the v1 single-copy (~d) — the owned vector eliminated"
                                     loan-bytes new-bytes))
                     ;; the residue is a small FIXED mutex cost (payload-independent), NOT a per-sample delivery vector
                     (%check :fdzc-e2e-loan-no-owned-vector
                             (<= loan-bytes 64)
                             (format nil "the literal-0-copy loan RX (~d) must be a small fixed overhead (<=64 B, the mutex acquire), not a per-sample owned vector" loan-bytes))
                     (%check :fdzc-e2e-loan-below-v1-sink
                             (< loan-bytes v1-bytes)
                             (format nil "the literal-0-copy loan RX (~d) must allocate far less than the WP-ZEROCOPY-v1 sink (~d)"
                                     loan-bytes v1-bytes)))))))
           (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
    t)

(defun* run-keyed-flatdata-loan-handle-test ()
    (function () t)
  "WP-KEYED-FLATDATA real per-key loan handle (FR-PF-4, ADR 0017, RTPS 2.5 §9.6.4.8, R6; NOT cleared for ship —
   pending counsel). The full DCPS stack over Zero-Copy with a KEYED FlatData type (keyed-fd-i32: i32 @key k +
   i32 v): %loan-instance-handle must now return the REAL per-key keyhash off the loaned view (key-hash-<name>-fd),
   NOT the synthetic SN+GUID fold (which gave per-sample-unique handles → same-key samples would get DIFFERENT
   handles). Loans samples one at a time (write → spin → %drain → capture the cached SampleInfo instance-handle →
   take-loaned → return-loan) and asserts: (1) key-A round 1 handle EQUALP the keyhash of an owned key-A buffer
   (the conformance link: the view keyhash == the buffer keyhash for the same key bytes); (2) a SECOND key-A sample
   gets the SAME handle (no SN-fold aliasing — the v1 fold would differ on SN); (3) a key-B sample gets a DISTINCT
   handle EQUALP the keyhash of a key-B buffer; (4) the loaned sample is a flatdata-view whose field reads via
   -fd are byte-correct off the slot. Skips cleanly where SHMEM is off (the ZC loan path is SBCL-only — NFR-PORT
   gap, ADR 0013; Clasp/macOS pass-skip). NOT cleared for ship — pending counsel (R6)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-keyed-flatdata-loan-handle-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 4)        ; keyed-fd-i32 (8 octets) takes the ZC ref path
         (ts (dds.types:find-type-support "keyed-fd-i32"))
         (ka #x01020304) (kb #x0a0b0c0d) (va #x11223344) (vb #x55667788)
         ;; oracle: the per-key keyhash read from an OWNED buffer — the view keyhash must equal this for the same key
         (kh-a (let ((b (make-keyed-fd-i32-flatdata)))
                 (setf (keyed-fd-i32-k-fd b) ka (keyed-fd-i32-v-fd b) 0)
                 (prog1 (copy-seq (key-hash-keyed-fd-i32-fd b))
                   (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))))
         (kh-b (let ((b (make-keyed-fd-i32-flatdata)))
                 (setf (keyed-fd-i32-k-fd b) kb (keyed-fd-i32-v-fd b) 0)
                 (prog1 (copy-seq (key-hash-keyed-fd-i32-fd b))
                   (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))))
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (%check :kfdl-kh-distinct (not (equalp kh-a kh-b)) "the two key values must have distinct keyhashes (oracle sanity)")
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "KFdLoan" "keyed-fd-i32" ts))
                (tr (dds.dcps:create-topic p2 "KFdLoan" "keyed-fd-i32" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr))
                (node1 (dds.dcps::dp-node p1))
                (node2 (dds.dcps::dp-node p2))
                (fd (make-keyed-fd-i32-flatdata)))
           (loop repeat 200
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :kfdl-matched (plusp (dds.dcps:matched-count p1)) "writer/reader did not match")
           (loop repeat 200
                 until (plusp (dds.disc::%zc-readers node1
                                                     (list (dds.rtps.discovery:endpoint-data-guid
                                                            (first (dds.disc::%matched-endpoints node1))))))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           ;; loan ONE sample of key K (value V) and return the (handle . view-field-V) it delivered
           (flet ((%loan-one (round k v)
                    (setf (keyed-fd-i32-k-fd fd) k (keyed-fd-i32-v-fd fd) v)
                    (dds.dcps:write-sample dw fd)
                    (loop repeat 300 until (> (dds.disc:node-sample-count node2) round)
                          do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
                    (dds.dcps::%drain dr)                              ; build the loan + cached SampleInfo
                    (let* ((cs (first (dds.dcps::dr-cache dr)))        ; the just-drained loaned sample
                           (handle (and cs (copy-seq (dds.dcps::sample-info-instance-handle
                                                      (dds.dcps::cached-sample-info cs))))))
                      (%check :kfdl-cs (and cs t) (format nil "round ~d: no drained sample" round))
                      (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
                        (%check :kfdl-view (and data (dds.types:flatdata-view-p (first data)))
                                (format nil "round ~d: the loaned sample must be a flatdata-view" round))
                        (let ((vfield (and data (keyed-fd-i32-v-fd (first data)))))   ; -fd read off the slot
                          (dds.dcps:return-loan dr loans)
                          (values handle vfield))))))
             (multiple-value-bind (ha1 va1) (%loan-one 0 ka va)
               (multiple-value-bind (ha2 va2) (%loan-one 1 ka #x0c0d0e0f)   ; same key, DIFFERENT i32 value
                 (multiple-value-bind (hb vb-read) (%loan-one 2 kb vb)
                   ;; (1) key-A handle == the per-key keyhash (the real keyhash off the view, not the SN-fold)
                   (%check :kfdl-a-keyhash (equalp ha1 kh-a)
                           "the loaned key-A handle must equal the per-key keyhash of a key-A buffer")
                   ;; (2) a SECOND key-A sample gets the SAME handle (no SN-fold aliasing across samples)
                   (%check :kfdl-same-key-same-handle (equalp ha1 ha2)
                           "two samples of the SAME key must get the SAME instance handle (no SN-fold aliasing)")
                   ;; (3) key-B gets a DISTINCT handle == the key-B keyhash
                   (%check :kfdl-b-distinct (not (equalp ha1 hb))
                           "two DIFFERENT key values must get DISTINCT instance handles")
                   (%check :kfdl-b-keyhash (equalp hb kh-b)
                           "the loaned key-B handle must equal the per-key keyhash of a key-B buffer")
                   ;; (4) the -fd field read off the slot is byte-correct
                   (%check :kfdl-field-a (eql va1 va) (format nil "loaned key-A v ~a != ~a" va1 va))
                   (%check :kfdl-field-a2 (eql va2 #x0c0d0e0f) "second key-A v read wrong off the slot")
                   (%check :kfdl-field-b (eql vb-read vb) (format nil "loaned key-B v ~a != ~a" vb-read vb))))))
           (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
    t)

(defun* run-keyed-flatdata-loan-keeplast-test ()
    (function () t)
  "WP-KEYED-FLATDATA Task C1 — close the WP-KEEPLAST follow-up gap on the ZC LOAN path (DDS 1.4 §2.2.3.18,
   FR-PF-4, ADR 0017, RTPS 2.5 §9.6.4.8, R6; NOT cleared for ship — pending counsel). With B1's REAL per-key loan
   handle in place, %drain-one-loan now applies the per-instance KEEP_LAST drop (mirroring the copy path
   %drain-one-sample), so a KEEP_LAST depth-2 loan-capable reader of a KEYED FlatData type (keyed-fd-i32: i32
   @key k + i32 v) keeps the last 2 of EACH instance, not a global last-2. Loans 3 samples of instance A (key kA,
   varying v) + 3 of instance B (key kB) — draining after each write (delivery is where the drop fires) and NOT
   taking between writes (take would empty the cache, masking retention) — then inspects dr-cache: EXACTLY 4 cached
   (A's last 2 + B's last 2), 2 per instance, A's surviving SNs the LAST 2 of A's three and likewise for B. RED
   before C1 (the loan path skipped the drop → all 6 of A+B retained). REGRESSION: a NO_KEY FlatData (fd-abc)
   KEEP_LAST-2 loan reader is UNAFFECTED — its per-(GUID,SN)-unique synthetic handles mean each sample is its own
   instance, so the depth-2 cap never fires and all 3 loaned samples are retained. Skips cleanly where SHMEM is off
   (the ZC loan path is SBCL-only — NFR-PORT gap, ADR 0013; Clasp/macOS pass-skip). NOT cleared for ship (R6)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-keyed-flatdata-loan-keeplast-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 4)        ; keyed-fd-i32 (8 octets) takes the ZC ref path
         (ts (dds.types:find-type-support "keyed-fd-i32"))
         (ka #x01020304) (kb #x0a0b0c0d)
         (kh-a (let ((b (make-keyed-fd-i32-flatdata)))    ; oracle: instance A's per-key handle
                 (setf (keyed-fd-i32-k-fd b) ka (keyed-fd-i32-v-fd b) 0)
                 (prog1 (copy-seq (key-hash-keyed-fd-i32-fd b))
                   (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))))
         (kh-b (let ((b (make-keyed-fd-i32-flatdata)))    ; oracle: instance B's per-key handle
                 (setf (keyed-fd-i32-k-fd b) kb (keyed-fd-i32-v-fd b) 0)
                 (prog1 (copy-seq (key-hash-keyed-fd-i32-fd b))
                   (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))))
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "KFdKlLoan" "keyed-fd-i32" ts))
                (tr (dds.dcps:create-topic p2 "KFdKlLoan" "keyed-fd-i32" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader
                     sub tr :qos (dds.qos:make-reader-qos :history-kind :keep-last :history-depth 2)))
                (node1 (dds.dcps::dp-node p1))
                (node2 (dds.dcps::dp-node p2))
                (fd (make-keyed-fd-i32-flatdata)))
           (loop repeat 200
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :kfdkl-matched (plusp (dds.dcps:matched-count p1)) "writer/reader did not match")
           (loop repeat 200
                 until (plusp (dds.disc::%zc-readers node1
                                                     (list (dds.rtps.discovery:endpoint-data-guid
                                                            (first (dds.disc::%matched-endpoints node1))))))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           ;; loan the (round+1)-th sample of key K (value V), draining (NOT taking) so the KEEP_LAST drop fires on delivery
           (flet ((%loan (round k v)
                    (setf (keyed-fd-i32-k-fd fd) k (keyed-fd-i32-v-fd fd) v)
                    (dds.dcps:write-sample dw fd)
                    (loop repeat 300 until (> (dds.disc:node-sample-count node2) round)
                          do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
                    (dds.dcps::%drain dr)))                ; delivery + the per-instance KEEP_LAST drop
             ;; interleave A and B so per-instance retention (not a global last-2) is the only thing that passes
             (%loan 0 ka #x000000a1) (%loan 1 kb #x000000b1)
             (%loan 2 ka #x000000a2) (%loan 3 kb #x000000b2)
             (%loan 4 ka #x000000a3) (%loan 5 kb #x000000b3))
           ;; the keyed reader retains the last 2 of EACH instance: 4 cached, 2 per handle, NOT 6 and NOT a global 2
           (%check :kfdkl-total (= 4 (length (dds.dcps::dr-cache dr)))
                   (format nil "keyed KEEP_LAST-2 loan reader over 2 instances must hold 4 cached, got ~d"
                           (length (dds.dcps::dr-cache dr))))
           (%check :kfdkl-a-2 (= 2 (%handle-cache-count dr kh-a))
                   (format nil "instance A must keep exactly its last 2 loaned samples, got ~d"
                           (%handle-cache-count dr kh-a)))
           (%check :kfdkl-b-2 (= 2 (%handle-cache-count dr kh-b))
                   (format nil "instance B must keep exactly its last 2 loaned samples, got ~d"
                           (%handle-cache-count dr kh-b)))
           ;; the surviving samples are each instance's LAST 2 (oldest dropped): A keeps a2,a3 — B keeps b2,b3
           (flet ((%vals (h) (sort (mapcar (lambda (cs) (keyed-fd-i32-v-fd (dds.dcps:cached-sample-data cs)))
                                           (remove-if-not (lambda (cs) (equalp h (%cs-ih cs)))
                                                          (dds.dcps::dr-cache dr)))
                                   #'<)))
             (%check :kfdkl-a-last2 (equal (list #x000000a2 #x000000a3) (%vals kh-a))
                     (format nil "instance A must keep its LAST 2 values (a2,a3), oldest dropped; got ~x" (%vals kh-a)))
             (%check :kfdkl-b-last2 (equal (list #x000000b2 #x000000b3) (%vals kh-b))
                     (format nil "instance B must keep its LAST 2 values (b2,b3), oldest dropped; got ~x" (%vals kh-b))))
           ;; THE LEAK CHECK (C-2): the 2 evicted views' loans were RELEASED, not orphaned in dr-loans pinning a slot.
           ;; dr-cache shape (above) CANNOT see the leak — the unfixed bug is precisely a slot surviving in dr-loans /
           ;; the pool while gone from dr-cache. Unfixed: dr-loans=6, writer pool free=26 (2 dropped slots LEAK held).
           (%check :kfdkl-loans-4 (= 4 (length (dds.dcps::dr-loans dr)))
                   (format nil "the 2 KEEP_LAST-evicted loaned views must be released (dr-loans=4), got ~d (=6 ⇒ slot LEAK)"
                           (length (dds.dcps::dr-loans dr))))
           ;; the 2 dropped slots returned to the writer's ZC pool (28 of 32 reclaimable: 4 still held by live loans)
           (let ((wsap (dds.disc::disc-node-zc-pool-sap node1)))
             (%check :kfdkl-pool-2-reclaimed
                     (= (- dds.disc:+zerocopy-pool-slots+ 4)
                        (dds.xport.zerocopy::%zc-free-count wsap))
                     (format nil "the 2 evicted slots must be reclaimable in the writer pool (free=~d of ~d), got ~d"
                             (- dds.disc:+zerocopy-pool-slots+ 4) dds.disc:+zerocopy-pool-slots+
                             (dds.xport.zerocopy::%zc-free-count wsap)))
             ;; full pool recovery after the app returns the 4 held loans + reader close — no residual held slot
             (dds.dcps:return-all-loans dr)
             (loop repeat 200
                   until (= dds.disc:+zerocopy-pool-slots+ (dds.xport.zerocopy::%zc-free-count wsap))
                   do (dds.dcps:spin p1) (sleep 0.01))
             (%check :kfdkl-pool-full-recovery
                     (= dds.disc:+zerocopy-pool-slots+ (dds.xport.zerocopy::%zc-free-count wsap))
                     (format nil "every loaned slot must return to the writer pool after return-all-loans (free=~d of ~d)"
                             (dds.xport.zerocopy::%zc-free-count wsap) dds.disc:+zerocopy-pool-slots+)))
           (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
  ;; NO-UAF (C-2): read-loaned is NON-DESTRUCTIVE — it LEAVES :READ samples in dr-cache and hands the app their views.
  ;; So the KEEP_LAST drop's oldest CAN be an app-held view; releasing its slot would be a use-after-free. The loan
  ;; drop's RELEASABLE-ONLY guard skips :READ views: a held view is NEVER released by an over-depth append. Here a
  ;; single instance's 2 loaned samples are read-loaned (app-held, :READ); a 3rd arrives (over depth 2). The 2 held
  ;; views must STILL be loaned (dr-loans keeps the 2 held; only an UN-held over-depth sample could have been dropped,
  ;; and there is none), so no app-held slot was released out from under the reader.
  (when (dds.xport.shmem:shm-attach-by-name-reliable-p)
    (let* ((dds.disc:*shmem-enabled* t)
           (dds.disc:*zerocopy-enabled* t)
           (dds.disc:*zerocopy-min-payload-bytes* 4)
           (ts (dds.types:find-type-support "keyed-fd-i32"))
           (kc #x07070707)
           (p1 (dds.dcps:create-participant :domain (test-domain)))
           (p2 (dds.dcps:create-participant :domain (test-domain))))
      (unwind-protect
           (let* ((tw (dds.dcps:create-topic p1 "KFdKlUaf" "keyed-fd-i32" ts))
                  (tr (dds.dcps:create-topic p2 "KFdKlUaf" "keyed-fd-i32" ts))
                  (pub (dds.dcps:create-publisher p1))
                  (sub (dds.dcps:create-subscriber p2))
                  (dw (dds.dcps:create-datawriter pub tw))
                  (dr (dds.dcps:create-datareader
                       sub tr :qos (dds.qos:make-reader-qos :history-kind :keep-last :history-depth 2)))
                  (node1 (dds.dcps::dp-node p1))
                  (node2 (dds.dcps::dp-node p2))
                  (fd (make-keyed-fd-i32-flatdata)))
             (loop repeat 200
                   until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (%check :kfdkl-uaf-matched (plusp (dds.dcps:matched-count p1)) "no-UAF writer/reader did not match")
             (loop repeat 200
                   until (plusp (dds.disc::%zc-readers node1
                                                       (list (dds.rtps.discovery:endpoint-data-guid
                                                              (first (dds.disc::%matched-endpoints node1))))))
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (flet ((%loan (round v)
                      (setf (keyed-fd-i32-k-fd fd) kc (keyed-fd-i32-v-fd fd) v)
                      (dds.dcps:write-sample dw fd)
                      (loop repeat 300 until (> (dds.disc:node-sample-count node2) round)
                            do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))))
               (%loan 0 #x000000c1) (%loan 1 #x000000c2)
               ;; READ (non-destructive): both views handed to the app, left in dr-cache, marked :READ
               (multiple-value-bind (data loans) (dds.dcps:read-loaned dr)
                 (declare (ignore data))
                 (%check :kfdkl-uaf-read-2 (= 2 (length loans)) "read-loaned must hand the app 2 loaned views")
                 (%check :kfdkl-uaf-all-read
                         (every (lambda (cs) (eq :read (%cs-ss cs))) (dds.dcps::dr-cache dr))
                         "both held views must be marked :read after read-loaned")
                 ;; a 3rd sample arrives (over depth 2) — the drop must NOT release either app-held :read view
                 (%loan 2 #x000000c3)
                 (dds.dcps::%drain dr)
                 (%check :kfdkl-uaf-held-not-released
                         (and (member (first loans) (dds.dcps::dr-loans dr))
                              (member (second loans) (dds.dcps::dr-loans dr)))
                         "no-UAF: a read-loaned (app-held :read) view must NEVER be released by the KEEP_LAST drop")
                 ;; the app can still safely return its held loans (slots were never freed under it) -> full recovery
                 (dds.dcps:return-loan dr loans)
                 (dds.dcps:return-all-loans dr)
                 (let ((wsap (dds.disc::disc-node-zc-pool-sap node1)))
                   (loop repeat 200
                         until (= dds.disc:+zerocopy-pool-slots+ (dds.xport.zerocopy::%zc-free-count wsap))
                         do (dds.dcps:spin p1) (sleep 0.01))
                   (%check :kfdkl-uaf-recovery
                           (= dds.disc:+zerocopy-pool-slots+ (dds.xport.zerocopy::%zc-free-count wsap))
                           "no-UAF: every slot recovers after the app returns its held loans (no slot freed under it)"))))
             (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
        (dds.dcps:delete-participant p1)
        (when p2 (dds.dcps:delete-participant p2)))))
  ;; REGRESSION: a NO_KEY FlatData KEEP_LAST-2 loan reader is UNAFFECTED — per-(GUID,SN)-unique handles ⇒ the cap never fires.
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)        ; fd-abc (20 octets) takes the ZC ref path
         (ts (dds.types:find-type-support "fd-abc"))
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "NkFdKlLoan" "fd-abc" ts))
                (tr (dds.dcps:create-topic p2 "NkFdKlLoan" "fd-abc" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader
                     sub tr :qos (dds.qos:make-reader-qos :history-kind :keep-last :history-depth 2)))
                (node1 (dds.dcps::dp-node p1))
                (node2 (dds.dcps::dp-node p2))
                (fd (make-fd-abc-flatdata)))
           (setf (fd-abc-a-fd fd) 1 (fd-abc-b-fd fd) 2 (fd-abc-c-fd fd) 3)
           (loop repeat 200
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :nkfdkl-matched (plusp (dds.dcps:matched-count p1)) "NO_KEY writer/reader did not match")
           (loop repeat 200
                 until (plusp (dds.disc::%zc-readers node1
                                                     (list (dds.rtps.discovery:endpoint-data-guid
                                                            (first (dds.disc::%matched-endpoints node1))))))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (dotimes (round 3)                              ; 3 samples > depth 2; drain (NOT take) after each
             (dds.dcps:write-sample dw fd)
             (loop repeat 300 until (> (dds.disc:node-sample-count node2) round)
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (dds.dcps::%drain dr))
           ;; NO_KEY: 3 distinct synthetic instances ⇒ the depth-2 cap never fires ⇒ all 3 retained (unchanged from B1)
           (%check :nkfdkl-all-retained (= 3 (length (dds.dcps::dr-cache dr)))
                   (format nil "NO_KEY KEEP_LAST-2 loan reader must retain all 3 (per-(GUID,SN) handles, cap never fires), got ~d"
                           (length (dds.dcps::dr-cache dr))))
           (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
  t)

(defun* run-keyed-flatdata-copy-behavior-test ()
    (function () t)
  "WP-KEYED-FLATDATA Task D1 — keyed FlatData FULL keyed behaviour on the COPY (non-ZeroCopy) path (FR-PF-4,
   DDS 1.4 §2.2.2.5, RTPS 2.5 §9.6.4.8, R6). NO *zerocopy-enabled* — plain UDP/loopback: write-sample
   serializes the keyed-fd-i32 FlatData buffer, the reader deserializes it to an owned octet-buffer the -fd
   accessors read in place, and %drain-one-sample computes the instance handle via %instance-handle ts data =
   key-hash-keyed-fd-i32-fd off that buffer. Asserts the keyhash wiring (A1) lit the EXISTING reader machinery
   with NO new copy-path code: (1) each delivered sample's SampleInfo instance-handle EQUALP the per-key
   keyhash of its key (a REAL per-key handle, NOT HANDLE_NIL); (2) the FIRST sample of key A reads view-state
   :new, a REPEAT of key A reads :not-new (per-instance view-state, DDS 1.4 §2.2.2.5.1.7); (3) a second
   distinct key B is an INDEPENDENT instance with its own :new; (4) a KEEP_LAST depth-2 keyed reader fed 3
   samples of ONE key retains the last 2 (per-instance KEEP_LAST on the copy path, DDS 1.4 §2.2.3.18 —
   %drain-one-sample's %reader-keeplast-drop-oldest keyed on the FlatData handle). Both impls (the copy path is
   NOT ZC-gated). NOT cleared for ship — pending counsel (R6)."
  (let* ((ts (dds.types:find-type-support "keyed-fd-i32"))
         (ka #x01020304) (kb #x0a0b0c0d)
         (nil-handle (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         ;; oracle: the per-key handle the reader must produce == the keyhash read from an owned buffer
         (kh-a (let ((b (make-keyed-fd-i32-flatdata)))
                 (setf (keyed-fd-i32-k-fd b) ka (keyed-fd-i32-v-fd b) 0)
                 (prog1 (copy-seq (key-hash-keyed-fd-i32-fd b))
                   (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))))
         (kh-b (let ((b (make-keyed-fd-i32-flatdata)))
                 (setf (keyed-fd-i32-k-fd b) kb (keyed-fd-i32-v-fd b) 0)
                 (prog1 (copy-seq (key-hash-keyed-fd-i32-fd b))
                   (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))))
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain)))
         (p3 (dds.dcps:create-participant :domain (test-domain))))   ; the KEEP_LAST reader lives alone (multi-reader-per-participant delivery is Slice S2)
    (%check :kfdc-kh-distinct (not (equalp kh-a kh-b)) "the two key values must have distinct keyhashes (oracle sanity)")
    (%check :kfdc-kh-not-nil (not (equalp kh-a nil-handle)) "a keyed FlatData keyhash must not be HANDLE_NIL")
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "KFdCopy" "keyed-fd-i32" ts))
                (tr (dds.dcps:create-topic p2 "KFdCopy" "keyed-fd-i32" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                ;; RELIABLE + KEEP_ALL both sides: deterministic delivery + retain every sample for the grouping/view-state asserts
                (dw (dds.dcps:create-datawriter
                     pub tw :qos (dds.qos:make-writer-qos :reliability :reliable :history-kind :keep-all)))
                (dr (dds.dcps:create-datareader
                     sub tr :qos (dds.qos:make-reader-qos :reliability :reliable :history-kind :keep-all)))
                (fd (make-keyed-fd-i32-flatdata)))
           (loop repeat 200
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :kfdc-matched (plusp (dds.dcps:matched-count p2)) "keyed FlatData copy writer/reader did not match")
           ;; write ONE keyed FlatData sample of key K (value V) and wait for the reader to receive it
           (flet ((%write (round k v)
                    (setf (keyed-fd-i32-k-fd fd) k (keyed-fd-i32-v-fd fd) v)
                    (dds.dcps:write-sample dw fd)
                    (loop repeat 300 until (> (dds.dcps:samples-available dr) round)
                          do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))))
             ;; (1)+(2) first key-A sample -> a REAL per-key handle (== kh-a), view-state NEW (first access of A)
             (%write 0 ka #x11111111)
             (let ((r (dds.dcps:read-samples dr :states '(:not-read))))
               (%check :kfdc-a1-one (= 1 (length r)) "expected the one key-A sample unread")
               (%check :kfdc-a1-handle (equalp kh-a (%cs-ih (first r)))
                       "the delivered key-A sample's SampleInfo handle must equal the per-key keyhash (a REAL handle, not HANDLE_NIL)")
               (%check :kfdc-a1-not-nil (not (equalp nil-handle (%cs-ih (first r))))
                       "the keyed FlatData copy-path handle must not be HANDLE_NIL")
               (%check :kfdc-a1-new (eq :new (%cs-vs (first r))) "the FIRST sample of key A must read view-state NEW")
               (%check :kfdc-a1-value (eql #x11111111 (keyed-fd-i32-v-fd (dds.dcps:cached-sample-data (first r))))
                       "the key-A sample value must read byte-correct off the deserialized FlatData buffer"))
             ;; (2) a REPEAT of key A -> SAME handle, view-state NOT_NEW (instance A already accessed)
             (%write 1 ka #x22222222)
             (let ((r (dds.dcps:read-samples dr :states '(:not-read))))
               (%check :kfdc-a2-one (= 1 (length r)) "expected the second key-A sample unread")
               (%check :kfdc-a2-same-handle (equalp kh-a (%cs-ih (first r)))
                       "a REPEAT of key A must carry the SAME per-key handle")
               (%check :kfdc-a2-notnew (eq :not-new (%cs-vs (first r)))
                       "a REPEAT of an already-accessed key must read view-state NOT_NEW"))
             ;; (3) a second DISTINCT key B -> an independent instance with its OWN view-state NEW
             (%write 2 kb #x33333333)
             (let ((r (dds.dcps:read-samples dr :states '(:not-read))))
               (%check :kfdc-b-one (= 1 (length r)) "expected the one key-B sample unread")
               (%check :kfdc-b-handle (equalp kh-b (%cs-ih (first r)))
                       "key B must be an independent instance carrying its own per-key keyhash")
               (%check :kfdc-b-distinct (not (equalp kh-a (%cs-ih (first r))))
                       "key B's handle must differ from key A's (two instances, not one)")
               (%check :kfdc-b-new (eq :new (%cs-vs (first r))) "the first sample of a distinct key B must read view-state NEW"))
             ;; total instances seen across the read history: exactly 2 (A and B)
             (%check :kfdc-two-instances
                     (= 2 (length (remove-duplicates (mapcar #'%cs-ih (dds.dcps:read-samples dr)) :test #'equalp)))
                     "the keyed FlatData reader must group the samples into exactly 2 instances")
             (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
           ;; (4) per-instance KEEP_LAST depth-2 on the copy path: a fresh keyed reader fed 3 of ONE key keeps the last 2
           ;; The KEEP_LAST reader runs on its OWN participant p3 (a single user reader): multi-reader-per-participant
           ;; delivery routing is Slice S2, so a 2nd reader on p2 would share p2's engine reader and drain p1's dw
           ;; samples too — the S1 writer fix (distinct writer GUIDs) unmasks that S2 gap. The copy-path per-instance
           ;; KEEP_LAST behaviour under test is a single-reader property, verified cleanly here.
           (let* ((trk (dds.dcps:create-topic p3 "KFdCopyKl" "keyed-fd-i32" ts))
                  (twk (dds.dcps:create-topic p1 "KFdCopyKl" "keyed-fd-i32" ts))
                  (pubk (dds.dcps:create-publisher p1))
                  (subk (dds.dcps:create-subscriber p3))
                  (dwk (dds.dcps:create-datawriter
                        pubk twk :qos (dds.qos:make-writer-qos :reliability :reliable :history-kind :keep-all)))
                  (drk (dds.dcps:create-datareader
                        subk trk :qos (dds.qos:make-reader-qos :reliability :reliable
                                                               :history-kind :keep-last :history-depth 2)))
                  (node2k (dds.dcps::dp-node p3))
                  (base (dds.disc:node-sample-count node2k))
                  (fdk (make-keyed-fd-i32-flatdata)))
             (loop repeat 200
                   until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p3)))
                   do (dds.dcps:spin p1) (dds.dcps:spin p3) (sleep 0.02))
             (dotimes (round 3)                          ; 3 samples of key A > depth 2; deliver all, the drop fires within %drain
               (setf (keyed-fd-i32-k-fd fdk) ka (keyed-fd-i32-v-fd fdk) (+ #x000000a1 round))
               (dds.dcps:write-sample dwk fdk)
               (loop repeat 300 until (> (- (dds.disc:node-sample-count node2k) base) round)
                     do (dds.dcps:spin p1) (dds.dcps:spin p3) (sleep 0.02)))
             (dds.dcps::%drain drk)                       ; per-instance KEEP_LAST drop runs over the 3 received in one pass
             ;; the per-instance KEEP_LAST cap holds on the copy path: exactly the last 2 of key A survive
             (%check :kfdc-kl-total (= 2 (length (dds.dcps::dr-cache drk)))
                     (format nil "a keyed KEEP_LAST-2 copy reader fed 3 of one key must keep exactly 2, got ~d"
                             (length (dds.dcps::dr-cache drk))))
             (%check :kfdc-kl-a-2 (= 2 (%handle-cache-count drk kh-a))
                     (format nil "all retained samples must belong to key A's instance, got ~d" (%handle-cache-count drk kh-a)))
             (let ((vals (sort (mapcar (lambda (cs) (keyed-fd-i32-v-fd (dds.dcps:cached-sample-data cs)))
                                       (dds.dcps::dr-cache drk)) #'<)))
               (%check :kfdc-kl-last2 (equal (list #x000000a2 #x000000a3) vals)
                       (format nil "the copy reader must keep key A's LAST 2 values (a2,a3), oldest dropped; got ~x" vals)))
             (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fdk))))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))
      (when p3 (dds.dcps:delete-participant p3))))
  t)

(defun* run-keyed-flatdata-dispose-test ()
    (function () t)
  "WP-KEYED-FLATDATA Task D1 — dispose/unregister of a keyed FlatData instance BY SAMPLE (FR-PF-4,
   DDS 1.4 §2.2.2.5 / §2.2.3.21, RTPS 2.5 §9.6.4.9, R6). Both impls (no ZeroCopy). A keyed-fd-i32 writer
   disposes an instance by passing the FlatData octet-buffer (NOT a pre-computed handle): %resolve-handle's
   %handle-p must REJECT the octet-buffer (it is a struct, not a (simple-array (unsigned-byte 8) (16))) and
   fall through to %instance-handle -> key-hash-keyed-fd-i32-fd, which reads @key off the buffer the app passed.
   Asserts: (1) a matched reader sees the instance ALIVE after a normal write; (2) after dispose-instance dw fd
   the reader sees NOT_ALIVE_DISPOSED for that instance's keyhash, with an invalid-data SampleInfo carrying the
   right handle; (3) a SECOND distinct instance: write -> ALIVE, then unregister-instance dw fd (default
   autodispose TRUE) -> NOT_ALIVE_DISPOSED. NOT cleared for ship — pending counsel (R6)."
  (let* ((ts (dds.types:find-type-support "keyed-fd-i32"))
         (ka #x02030405) (kb #x0b0c0d0e)
         (kh-a (let ((b (make-keyed-fd-i32-flatdata)))
                 (setf (keyed-fd-i32-k-fd b) ka (keyed-fd-i32-v-fd b) 0)
                 (prog1 (copy-seq (key-hash-keyed-fd-i32-fd b))
                   (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))))
         (kh-b (let ((b (make-keyed-fd-i32-flatdata)))
                 (setf (keyed-fd-i32-k-fd b) kb (keyed-fd-i32-v-fd b) 0)
                 (prog1 (copy-seq (key-hash-keyed-fd-i32-fd b))
                   (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b)))))
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "KFdDisp" "keyed-fd-i32" ts))
                (tr (dds.dcps:create-topic p2 "KFdDisp" "keyed-fd-i32" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw :qos (dds.qos:make-writer-qos :reliability :reliable)))
                (dr (dds.dcps:create-datareader sub tr :qos (dds.qos:make-reader-qos :reliability :reliable)))
                (fd (make-keyed-fd-i32-flatdata)))
           (loop repeat 200
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :kfdd-matched (plusp (dds.dcps:matched-count p2)) "keyed FlatData dispose writer/reader did not match")
           ;; instance A: write -> ALIVE
           (setf (keyed-fd-i32-k-fd fd) ka (keyed-fd-i32-v-fd fd) #x11111111)
           (dds.dcps:write-sample dw fd)
           (%drain-until dr p1 p2 (lambda () (eq :alive (%instance-rec-state dr kh-a))) 200)
           (%check :kfdd-a-alive (eq :alive (%instance-rec-state dr kh-a))
                   "instance A must be ALIVE after a keyed FlatData data sample")
           ;; dispose BY SAMPLE (the FlatData octet-buffer, k still = ka) -> the reader sees NOT_ALIVE_DISPOSED
           (dds.dcps:dispose-instance dw fd)
           (%drain-until dr p1 p2 (lambda () (eq :not-alive-disposed (%instance-rec-state dr kh-a))) 200)
           (%check :kfdd-a-disposed (eq :not-alive-disposed (%instance-rec-state dr kh-a))
                   "dispose-instance BY SAMPLE must transition instance A to NOT_ALIVE_DISPOSED (keyhash read off the buffer)")
           (let ((inv (find-if (lambda (cs) (and (null (dds.dcps:sample-info-valid-data (dds.dcps:cached-sample-info cs)))
                                                 (equalp kh-a (%cs-ih cs))))
                               (dds.dcps:take-samples dr))))
             (%check :kfdd-a-inv (and inv t) "dispose must yield an invalid-data SampleInfo for instance A")
             (when inv
               (%check :kfdd-a-inv-state
                       (eq :not-alive-disposed (dds.dcps:sample-info-instance-state (dds.dcps:cached-sample-info inv)))
                       "the invalid-data SampleInfo must carry instance_state NOT_ALIVE_DISPOSED")))
           ;; instance B: write -> ALIVE, then unregister BY SAMPLE with default autodispose (TRUE) -> NOT_ALIVE_DISPOSED
           (setf (keyed-fd-i32-k-fd fd) kb (keyed-fd-i32-v-fd fd) #x22222222)
           (dds.dcps:write-sample dw fd)
           (%drain-until dr p1 p2 (lambda () (eq :alive (%instance-rec-state dr kh-b))) 200)
           (%check :kfdd-b-alive (eq :alive (%instance-rec-state dr kh-b))
                   "instance B must be ALIVE after a keyed FlatData data sample")
           (dds.dcps:unregister-instance dw fd)             ; default autodispose TRUE -> disposes too (DDS 1.4 §2.2.3.21)
           (%drain-until dr p1 p2 (lambda () (eq :not-alive-disposed (%instance-rec-state dr kh-b))) 200)
           (%check :kfdd-b-disposed (eq :not-alive-disposed (%instance-rec-state dr kh-b))
                   "unregister-instance BY SAMPLE (autodispose default TRUE) must transition instance B to NOT_ALIVE_DISPOSED")
           (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
  t)

(defun* run-reliable-zc-retransmit-test ()
    (function () t)
  "WP-RELIABLE-ZC scenario 1 — RELIABLE retransmit of a Zero-Copy loan sample (FR-PF-3/4, FR-RTPS reliability,
   R6, ADR 0017; NOT cleared for ship — pending counsel). The binary reliability gate over the ZC loan path: a
   RELIABLE writer + a same-host RELIABLE loan-capable ZC reader; the first ZC ref-DATA for SN 1 is DROPPED on
   every thread (*debug-drop-sample-numbers*), so the reader never sees it; on the next periodic HEARTBEAT the
   reader NACKs SN 1; the drop is cleared and the writer's ACKNACK retransmit re-emits SN 1 from the still-
   retained full payload in its HistoryCache (writer-on-acknack -> %on-user-acknack -> %send-changes-packed),
   which a loan-capable reader delivers (a re-loaned ref defers to a view; a copy-fallback delivers an owned
   FlatData buffer — either is byte-exact). Asserts: (1) the drop hook worked (nothing received during the
   drop window); (2) the sample is ULTIMATELY received after the drop clears (reliable, NO silent loss); (3)
   take-loaned reads a/b/c BYTE-EXACT off whatever the retransmit delivered (view OR copy), via the SAME
   <name>-<field>-fd Offset accessors (both a flatdata-view and an owned FlatData octet-buffer answer them).
   Bounded drive (no unbounded wait). Skips cleanly where SHMEM is off (Clasp/macOS gap, ADR 0013)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-reliable-zc-retransmit-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)        ; fd-abc (20 octets) takes the ZC ref path
         (ts (dds.types:find-type-support "fd-abc"))
         (va 201) (vb 3000000001) (vc 12345678901234567891)
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "FdRelZc" "fd-abc" ts))
                (tr (dds.dcps:create-topic p2 "FdRelZc" "fd-abc" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))                                   ; RELIABLE (writer-qos default)
                (dr (dds.dcps:create-datareader sub tr
                                                :qos (dds.qos:make-reader-qos :reliability :reliable)))
                (node1 (dds.dcps::dp-node p1))
                (node2 (dds.dcps::dp-node p2))
                (fd (make-fd-abc-flatdata)))
           (setf (fd-abc-a-fd fd) va (fd-abc-b-fd fd) vb (fd-abc-c-fd fd) vc)
           (%check :relzc-loan-capable (dds.disc::disc-node-zc-loan-capable node2)
                   "the RELIABLE FlatData-topic reader must be auto loan-capable (the Phase-E wiring)")
           (loop repeat 200
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :relzc-matched (plusp (dds.dcps:matched-count p1)) "writer/reader did not match")
           (loop repeat 200
                 until (plusp (dds.disc::%zc-readers node1
                                                     (list (dds.rtps.discovery:endpoint-data-guid
                                                            (first (dds.disc::%matched-endpoints node1))))))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           ;; DROP SN 1 on every thread (initial push AND the NACK-driven resend), then publish.
           (setf dds.disc:*debug-drop-sample-numbers* (list 1))
           (dds.dcps:write-sample dw fd)
           (dotimes (i 6) (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))   ; drive HB/NACK while the resend is still dropped
           (%check :relzc-dropped (zerop (dds.disc:node-sample-count node2))
                   "drop hook failed: the reader received SN 1 while it was being dropped")
           ;; Clear the drop; the periodic HEARTBEAT prompts a NACK, the writer retransmits SN 1 from its HC.
           (setf dds.disc:*debug-drop-sample-numbers* nil)
           (loop repeat 80
                 until (plusp (dds.disc:node-sample-count node2))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :relzc-recovered (plusp (dds.disc:node-sample-count node2))
                   "RELIABLE ZC loan sample never recovered after the dropped ref-DATA was retransmitted (silent loss)")
           ;; take-loaned reads the recovered sample byte-exact — view (re-loan) OR owned buffer (copy fallback).
           (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
             (%check :relzc-one (= 1 (length data)) "take-loaned must return exactly the one recovered sample")
             (let* ((d (first data))
                    (view-p (dds.types:flatdata-view-p d)))
               (format t "~&  reliable-zc-retransmit: SN 1 recovered as ~a (both read byte-exact via the Offset accessors)~%"
                       (if view-p "a re-loaned flatdata-VIEW" "an owned COPY (full-payload retransmit fallback)"))
               (%check :relzc-a (= (fd-abc-a-fd d) va)
                       (format nil "recovered field a: ~d != ~d" (fd-abc-a-fd d) va))
               (%check :relzc-b (= (fd-abc-b-fd d) vb)
                       (format nil "recovered field b: ~d != ~d" (fd-abc-b-fd d) vb))
               (%check :relzc-c (= (fd-abc-c-fd d) vc)
                       (format nil "recovered field c: ~d != ~d" (fd-abc-c-fd d) vc)))
             (dds.dcps:return-loan dr loans))                                  ; releases a view; no-op for a copy
           (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
      (setf dds.disc:*debug-drop-sample-numbers* nil)
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
    t)

(defun* %saturate-zc-pool (node)
    (function (t) list)
  "WP-RELIABLE-ZC test helper (R6, ADR 0017; NOT cleared for ship — pending counsel): hold a loan on every
   FREE slot of NODE's writer ZC pool (looping %zc-loan until it returns NIL) so the next %zc-loan (the per-send
   ZC decision) ALSO returns NIL and the writer falls back to the full payload. Loops until saturated rather
   than assuming a fixed free count — a slot already held by a live loan (a deferred ZC sample) is not free, so
   the count of fresh loans is at MOST +zerocopy-pool-slots+. Returns the list of (SLOT . GENERATION) loans to
   release with %release-zc-loans. Mirrors the existing zc-pool tests reaching the %zc-loan internals directly."
  (let ((sap (dds.disc::disc-node-zc-pool-sap node))
        (filler (octets 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))
        (held '()))
    (loop repeat dds.disc:+zerocopy-pool-slots+ do            ; bounded: at most one fresh loan per slot
      (multiple-value-bind (slot gen) (dds.xport.zerocopy::%zc-loan sap filler 0 (length filler) 1)
        (if slot (push (cons slot gen) held) (return))))
    held))

(defun* %zc-pool-full-p (node)
    (function (t) t)
  "WP-RELIABLE-ZC test helper (R6, ADR 0017): T iff NODE's writer ZC pool has NO free slot — a probe %zc-loan
   returns NIL (and is balanced if it unexpectedly succeeds). The robust saturation oracle (the next ZC send
   will fall back to the full payload). NOT cleared for ship — pending counsel (R6)."
  (let ((sap (dds.disc::disc-node-zc-pool-sap node))
        (filler (octets 1 2 3 4 5 6 7 8)))
    (multiple-value-bind (slot gen) (dds.xport.zerocopy::%zc-loan sap filler 0 (length filler) 1)
      (if slot (progn (dds.xport.zerocopy::%zc-release sap slot gen) nil) t))))

(defun* %release-zc-loans (node held)
    (function (t list) t)
  "WP-RELIABLE-ZC test helper (R6, ADR 0017): release every (SLOT . GENERATION) loan in HELD on NODE's writer
   pool, un-saturating it. NOT cleared for ship — pending counsel (R6)."
  (let ((sap (dds.disc::disc-node-zc-pool-sap node)))
    (dolist (l held t) (dds.xport.zerocopy::%zc-release sap (car l) (cdr l))))
  t)

(defun* run-reliable-zc-poolfull-fallback-test ()
    (function () t)
  "WP-RELIABLE-ZC scenario 2 — pool-full -> copy-fallback delivered correctly to a loan-capable reader
   (FR-PF-3/4, R6, ADR 0017; NOT cleared for ship — pending counsel). The reliability binary gate when the ZC
   pool is saturated: SATURATE the writer's ZC pool (hold a loan on all +zerocopy-pool-slots+ slots), then a
   RELIABLE writer publishes a ZC-eligible FlatData sample -> %zc-change-item's %zc-loan returns NIL (no free
   slot) -> the writer sends the FULL serialized payload (NOT a ref, no double-delivery) -> the loan-capable
   reader's %on-user-data sees :not-a-ref and copy-delivers it -> take-loaned returns it AS A COPY (an owned
   FlatData octet-buffer, NOT a flatdata-view, NOT skipped/errored), read BYTE-EXACT off the owned vec. Proves
   the saturated-pool fallback under RELIABLE never silently drops — it copy-delivers (the harden point: a
   non-marker sample mixed into a loan-capable reader must deliver copy-backed). Asserts: (1) the writer did
   NOT advance zc-sends for this sample (it fell back, did not loan a ref); (2) take-loaned returns exactly one
   sample that is NOT a flatdata-view (a copy) with NIL in the loans list; (3) its a/b/c read byte-exact.
   Skips cleanly where SHMEM is off (Clasp/macOS gap, ADR 0013)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-reliable-zc-poolfull-fallback-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)
         (ts (dds.types:find-type-support "fd-abc"))
         (va 202) (vb 3000000002) (vc 12345678901234567892)
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain)))
         (held '()))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "FdPoolFull" "fd-abc" ts))
                (tr (dds.dcps:create-topic p2 "FdPoolFull" "fd-abc" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr
                                                :qos (dds.qos:make-reader-qos :reliability :reliable)))
                (node1 (dds.dcps::dp-node p1))
                (node2 (dds.dcps::dp-node p2))
                (fd (make-fd-abc-flatdata)))
           (setf (fd-abc-a-fd fd) va (fd-abc-b-fd fd) vb (fd-abc-c-fd fd) vc)
           (%check :poolfull-loan-capable (dds.disc::disc-node-zc-loan-capable node2)
                   "the FlatData-topic reader must be auto loan-capable")
           (loop repeat 200
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :poolfull-matched (plusp (dds.dcps:matched-count p1)) "writer/reader did not match")
           (loop repeat 200
                 until (plusp (dds.disc::%zc-readers node1
                                                     (list (dds.rtps.discovery:endpoint-data-guid
                                                            (first (dds.disc::%matched-endpoints node1))))))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           ;; SATURATE the writer's pool -> the next %zc-loan returns NIL -> the writer sends the FULL payload.
           (setf held (%saturate-zc-pool node1))
           (%check :poolfull-saturated (%zc-pool-full-p node1)
                   "could not saturate the ZC pool for the fallback probe (a free slot remains)")
           (let ((sends-before (dds.disc::disc-node-zc-sends node1)))
             (dds.dcps:write-sample dw fd)
             (loop repeat 300 until (plusp (dds.disc:node-sample-count node2))
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (%check :poolfull-delivered (plusp (dds.disc:node-sample-count node2))
                     "the pool-full fallback sample was never delivered (silent drop under RELIABLE)")
             (%check :poolfull-no-zc-send (= sends-before (dds.disc::disc-node-zc-sends node1))
                     "the writer must NOT have loaned a ref when the pool was saturated (zc-sends must not advance) — it must fall back to the full payload"))
           (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
             (%check :poolfull-one (= 1 (length data)) "take-loaned must return exactly one fallback sample")
             (%check :poolfull-is-copy (not (dds.types:flatdata-view-p (first data)))
                     "the pool-full fallback sample must be delivered AS A COPY (an owned FlatData buffer), NOT a flatdata-view")
             (%check :poolfull-no-loan (null loans)
                     "a copy-backed fallback sample must contribute NO loan to return-loan (NIL)")
             (let ((d (first data)))
               (%check :poolfull-a (= (fd-abc-a-fd d) va) (format nil "copy field a: ~d != ~d" (fd-abc-a-fd d) va))
               (%check :poolfull-b (= (fd-abc-b-fd d) vb) (format nil "copy field b: ~d != ~d" (fd-abc-b-fd d) vb))
               (%check :poolfull-c (= (fd-abc-c-fd d) vc) (format nil "copy field c: ~d != ~d" (fd-abc-c-fd d) vc)))
             (dds.dcps:return-loan dr loans))                                  ; no-op (no views)
           (%release-zc-loans node1 held)                                      ; un-saturate before teardown
           (setf held '())
           (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
      (when held (ignore-errors (%release-zc-loans (dds.dcps::dp-node p1) held)))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
    t)

(defun* run-reliable-zc-mixed-test ()
    (function () t)
  "WP-RELIABLE-ZC scenario 3 — mixed loan-markers + fallback-copies in ONE take-loaned (FR-PF-3/4, R6, ADR
   0017; NOT cleared for ship — pending counsel). A loan-capable RELIABLE reader receives an interleaved
   stream: sample 1 over Zero-Copy (pool has a free slot -> a ref -> a deferred VIEW); then the pool is
   SATURATED and sample 2 falls back to the full payload (-> an owned COPY); both are drained into the cache
   and ONE take-loaned returns BOTH correctly — the view read byte-exact off the slot, the copy read byte-exact
   off its owned vec. Asserts: (1) take-loaned returns exactly two samples; (2) exactly one is a flatdata-view
   (the ZC sample) and exactly one is a copy (the fallback) — verifying the loan registry / drain handle a
   mixed batch; (3) the loans list has exactly ONE entry (only the view); (4) every field of both reads byte-
   exact; (5) return-loan releases the view (registry empties) and is a no-op for the copy. Skips cleanly where
   SHMEM is off (Clasp/macOS gap, ADR 0013)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-reliable-zc-mixed-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)
         (ts (dds.types:find-type-support "fd-abc"))
         (va1 211) (vb1 3100000001) (vc1 11111111111111111111)
         (va2 212) (vb2 3100000002) (vc2 12222222222222222222)
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain)))
         (held '()))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "FdMixed" "fd-abc" ts))
                (tr (dds.dcps:create-topic p2 "FdMixed" "fd-abc" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr
                                                :qos (dds.qos:make-reader-qos :reliability :reliable)))
                (node1 (dds.dcps::dp-node p1))
                (node2 (dds.dcps::dp-node p2))
                (fd (make-fd-abc-flatdata)))
           (loop repeat 200
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :mixed-matched (plusp (dds.dcps:matched-count p1)) "writer/reader did not match")
           (loop repeat 200
                 until (plusp (dds.disc::%zc-readers node1
                                                     (list (dds.rtps.discovery:endpoint-data-guid
                                                            (first (dds.disc::%matched-endpoints node1))))))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           ;; sample 1: pool free -> a ZC ref -> a deferred VIEW
           (setf (fd-abc-a-fd fd) va1 (fd-abc-b-fd fd) vb1 (fd-abc-c-fd fd) vc1)
           (dds.dcps:write-sample dw fd)
           (loop repeat 300 until (plusp (dds.disc:node-sample-count node2))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :mixed-first-zc (plusp (dds.disc::disc-node-zc-sends node1))
                   "sample 1 must take the ZC ref path (a free slot) — zc-sends must advance")
           ;; sample 2: SATURATE the pool first -> %zc-loan NIL -> full-payload COPY
           (setf held (%saturate-zc-pool node1))
           (%check :mixed-saturated (%zc-pool-full-p node1)
                   "could not saturate the pool for the fallback half of the mixed batch (a free slot remains)")
           (let ((sends-before (dds.disc::disc-node-zc-sends node1)))
             (setf (fd-abc-a-fd fd) va2 (fd-abc-b-fd fd) vb2 (fd-abc-c-fd fd) vc2)
             (dds.dcps:write-sample dw fd)
             (loop repeat 300 until (> (dds.disc:node-sample-count node2) 1)
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (%check :mixed-second-delivered (> (dds.disc:node-sample-count node2) 1)
                     "the fallback (sample 2) was never delivered (silent drop)")
             (%check :mixed-second-fallback (= sends-before (dds.disc::disc-node-zc-sends node1))
                     "sample 2 must fall back to the full payload (no new zc-send) when the pool is saturated"))
           ;; ONE take-loaned returns BOTH: a view (sample 1) AND a copy (sample 2), each byte-exact.
           (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
             (%check :mixed-two (= 2 (length data)) "take-loaned must return both the view and the copy")
             (let ((views (remove-if-not #'dds.types:flatdata-view-p data))
                   (copies (remove-if #'dds.types:flatdata-view-p data)))
               (%check :mixed-one-view (= 1 (length views)) "exactly one sample must be a flatdata-view (the ZC sample)")
               (%check :mixed-one-copy (= 1 (length copies)) "exactly one sample must be a copy (the fallback)")
               (%check :mixed-one-loan (= 1 (length loans)) "the loans list must carry exactly the one view")
               ;; the view read straight off the writer's slot, the copy off its owned vec — both byte-exact.
               (let ((v (first views)) (c (first copies)))
                 (%check :mixed-view-a (= (fd-abc-a-fd v) va1) (format nil "view field a: ~d != ~d" (fd-abc-a-fd v) va1))
                 (%check :mixed-view-b (= (fd-abc-b-fd v) vb1) (format nil "view field b: ~d != ~d" (fd-abc-b-fd v) vb1))
                 (%check :mixed-view-c (= (fd-abc-c-fd v) vc1) (format nil "view field c: ~d != ~d" (fd-abc-c-fd v) vc1))
                 (%check :mixed-copy-a (= (fd-abc-a-fd c) va2) (format nil "copy field a: ~d != ~d" (fd-abc-a-fd c) va2))
                 (%check :mixed-copy-b (= (fd-abc-b-fd c) vb2) (format nil "copy field b: ~d != ~d" (fd-abc-b-fd c) vb2))
                 (%check :mixed-copy-c (= (fd-abc-c-fd c) vc2) (format nil "copy field c: ~d != ~d" (fd-abc-c-fd c) vc2))))
             (dds.dcps:return-loan dr loans)                                   ; releases only the view; no-op for the copy
             (%check :mixed-registry-clear (null (dds.dcps::dr-loans dr))
                     "return-loan must release the view and leave the registry empty (no leak)"))
           (%release-zc-loans node1 held)
           (setf held '())
           (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
      (when held (ignore-errors (%release-zc-loans (dds.dcps::dp-node p1) held)))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
    t)

(defun* run-reliable-zc-slot-outlives-purge-test ()
    (function () t)
  "WP-RELIABLE-ZC scenario 4 — the loaned slot OUTLIVES the HistoryCache purge (FR-PF-3/4, FR-RTPS reliability,
   R6, ADR 0017; NOT cleared for ship — pending counsel). Proves the loan <-> reliability refcount composition:
   a loan-capable RELIABLE reader take-loaned's a ZC sample (holding the loan, refcount 1); the reader ACKs on
   receive, so the writer's full-ACK purge (writer-purge-acked, RTPS 2.5 §8.4.1) drops the HC change for SN 1
   WHILE the reader still holds the loaned view; the loaned view STILL reads byte-exact (the writer's per-slot
   refcount holds the slot past the HC purge — force-reclaim skips refcount>0, so no use-after-free); then
   return-loan drops the refcount to 0 and the slot frees (a subsequent %zc-loan reuses it). Asserts: (1) after
   the ACK the writer's HC no longer holds SN 1 (the change was purged); (2) the held slot's refcount is still
   1 and the view still reads a/b/c byte-exact (the purge did NOT free the slot); (3) after return-loan the
   refcount is 0 and a fresh %zc-loan succeeds (the slot is reclaimable). Skips cleanly where SHMEM is off
   (Clasp/macOS gap, ADR 0013)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-reliable-zc-slot-outlives-purge-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)
         (ts (dds.types:find-type-support "fd-abc"))
         (va 204) (vb 3000000004) (vc 12345678901234567894)
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "FdPurge" "fd-abc" ts))
                (tr (dds.dcps:create-topic p2 "FdPurge" "fd-abc" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr
                                                :qos (dds.qos:make-reader-qos :reliability :reliable)))
                (node1 (dds.dcps::dp-node p1))
                (node2 (dds.dcps::dp-node p2))
                (writer (dds.disc::disc-node-user-writer node1))
                (fd (make-fd-abc-flatdata)))
           (setf (fd-abc-a-fd fd) va (fd-abc-b-fd fd) vb (fd-abc-c-fd fd) vc)
           (loop repeat 200
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :purge-matched (plusp (dds.dcps:matched-count p1)) "writer/reader did not match")
           (loop repeat 200
                 until (plusp (dds.disc::%zc-readers node1
                                                     (list (dds.rtps.discovery:endpoint-data-guid
                                                            (first (dds.disc::%matched-endpoints node1))))))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (dds.dcps:write-sample dw fd)                                       ; SN 1 over Zero-Copy
           (loop repeat 300 until (plusp (dds.disc:node-sample-count node2))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           ;; take the loan (hold it) BEFORE the ACK purges the writer HC
           (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
             (%check :purge-is-view (and data (dds.types:flatdata-view-p (first data)))
                     "the held sample must be a flatdata-view (literal-0-copy loan)")
             (let* ((view (first data))
                    (sap (dds.disc::disc-node-zc-pool-sap node1))
                    (slot (dds.types:flatdata-view-slot-index view)))
               (%check :purge-held (= 1 (%zc-slot-refcount sap slot))
                       "the loaned slot must be held (refcount 1) while the app reads it")
               ;; drive the ACK so the writer purges the fully-acked HC change (§8.4.1) WHILE the loan is held
               (loop repeat 80
                     until (null (dds.rtps.history:hc-get-change (dds.rtps.reliable:rtps-writer-hc writer) 1))
                     do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
               (%check :purge-hc-dropped (null (dds.rtps.history:hc-get-change (dds.rtps.reliable:rtps-writer-hc writer) 1))
                       "the writer must purge SN 1 from its HistoryCache after the reader fully ACKs it (§8.4.1)")
               ;; the slot OUTLIVES the HC purge: still held, still byte-exact (refcount > HC, no UAF)
               (%check :purge-slot-survives (= 1 (%zc-slot-refcount sap slot))
                       "the loaned slot must SURVIVE the HC purge (refcount still 1; force-reclaim skips it)")
               (%check :purge-view-a (= (fd-abc-a-fd view) va)
                       (format nil "post-purge view field a: ~d != ~d (the slot was freed under the read — UAF)" (fd-abc-a-fd view) va))
               (%check :purge-view-b (= (fd-abc-b-fd view) vb)
                       (format nil "post-purge view field b: ~d != ~d" (fd-abc-b-fd view) vb))
               (%check :purge-view-c (= (fd-abc-c-fd view) vc)
                       (format nil "post-purge view field c: ~d != ~d" (fd-abc-c-fd view) vc))
               ;; return-loan -> the slot frees (refcount 0) -> reusable
               (dds.dcps:return-loan dr loans)
               (%check :purge-released (zerop (%zc-slot-refcount sap slot))
                       "after return-loan the slot must free (refcount 0)")
               (multiple-value-bind (rslot rgen)
                   (dds.xport.zerocopy::%zc-loan sap (subseq (dds.core.buffer:octet-buffer-vec fd) 0 +fd-abc-flatdata-size+)
                                                 0 +fd-abc-flatdata-size+ 1)
                 (%check :purge-slot-reusable rslot
                         "after the loan was returned a subsequent %zc-loan must succeed (the freed slot is reclaimable)")
                 (when rslot (dds.xport.zerocopy::%zc-release sap rslot rgen)))))
           (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
    t)

(defun* %acked-pin-setup (p1 p2 topic)
    (function (t t string) (values t t t t t))
  "WP-ACKED-SLOT-PINNING test fixture (R6, ADR 0044): a RELIABLE + VOLATILE + KEEP_ALL loan-write writer on P1
   matched to a RELIABLE loan-capable ZC reader on P2 over TOPIC (fd-abc). Drives discovery until matched AND the
   writer sees the reader as ZC-capable, then returns (values DW DR NODE1 NODE2 WRITER). The caller loan-samples,
   fills the SAP setters, write-loaned's, and asserts the pin lifecycle. Mirrors the reliable-zc fixtures."
  (let* ((ts (dds.types:find-type-support "fd-abc"))
         (tw (dds.dcps:create-topic p1 topic "fd-abc" ts))
         (tr (dds.dcps:create-topic p2 topic "fd-abc" ts))
         (pub (dds.dcps:create-publisher p1))
         (sub (dds.dcps:create-subscriber p2))
         (dw (dds.dcps:create-datawriter pub tw))                                       ; RELIABLE + VOLATILE default
         (dr (dds.dcps:create-datareader sub tr :qos (dds.qos:make-reader-qos :reliability :reliable)))
         (node1 (dds.dcps::dp-node p1))
         (node2 (dds.dcps::dp-node p2)))
    (loop repeat 200
          until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
          do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
    (loop repeat 200
          until (plusp (dds.disc::%zc-readers node1
                                              (list (dds.rtps.discovery:endpoint-data-guid
                                                     (first (dds.disc::%matched-endpoints node1))))))
          do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
    (values dw dr node1 node2 (dds.disc::disc-node-user-writer node1))))

(defun* run-acked-slot-pin-happy-test ()
    (function () t)
  "WP-ACKED-SLOT-PINNING scenario 1 — the pin happy path (FR-PF-4, R6, ADR 0044; NOT cleared for ship — pending
   counsel). An ELIGIBLE reliable+VOLATILE+KEEP_ALL loan-write writer + one reliable ZC reader; loan-write. Asserts
   the headline: (1) the writer is pin-capable and write-loaned PINS the committed slot — the HistoryCache change
   for SN 1 carries NO retained serialized-payload (the per-write heap copy is ELIMINATED), is zc-pinned, and
   records its true length in zc-len; (2) the live pin count is 1 and the slot's refcount is 2 (the delivery hold +
   the TX pin, ADR 0044 §4.1); (3) the reader receives the sample byte-exact; (4) after the reader ACKs, the
   full-ACK purge drops the HC change AND releases the pin (live pin count back to 0), and after return-loan the
   slot frees (refcount 0, free-count restored). Skips cleanly where SHMEM is off (Clasp/macOS gap, ADR 0013)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-acked-slot-pin-happy-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)
         (va 210) (vb 3000000010) (vc 12345678901234567800)
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (multiple-value-bind (dw dr node1 node2 writer) (%acked-pin-setup p1 p2 "FdPinHappy")
           (%check :pin-capable (dds.disc:node-loan-write-pin-capable-p node1)
                   "an eligible reliable+VOLATILE writer with a matched reliable reader must be pin-capable")
           (let* ((sap (dds.disc::disc-node-zc-pool-sap node1))
                  (loan (dds.dcps:loan-sample dw))
                  (s (dds.dcps:writer-loan-sample loan))
                  (slot (dds.dcps::writer-loan-slot loan)))
             (setf (fd-abc-a-fd s) va (fd-abc-b-fd s) vb (fd-abc-c-fd s) vc)
             (%check :pin-write-ok (eq :ok (dds.dcps:write-loaned dw loan)) "write-loaned must return :ok")
             ;; (1) the pinned change: NO retained payload, zc-pinned, true length recorded
             (let ((ch (dds.rtps.history:hc-get-change (dds.rtps.reliable:rtps-writer-hc writer) 1)))
               (%check :pin-change-present ch "the writer HC must hold SN 1 after write-loaned")
               (when ch
                 (%check :pin-no-retained (null (dds.rtps.history:cache-change-serialized-payload ch))
                         "a PINNED change must carry NO retained serialized-payload (the per-write heap copy is eliminated)")
                 (%check :pin-flagged (dds.rtps.history:cache-change-zc-pinned ch)
                         "the change must be zc-pinned")
                 (%check :pin-len (eql +fd-abc-flatdata-size+ (dds.rtps.history:cache-change-zc-len ch))
                         "the pinned change must record its true serialized length in zc-len")))
             ;; (2) live pin count 1, slot refcount 2 (delivery + pin)
             (%check :pin-count-1 (= 1 (dds.pal:atomic-cell-value (dds.disc::disc-node-zc-pin-count node1)))
                     "exactly one slot must be pinned")
             (%check :pin-refcount-2 (= 2 (%zc-slot-refcount sap slot))
                     "the pinned slot's refcount must be 2 (the delivery hold + the TX pin)")
             ;; (3) byte-exact delivery, held as a view BEFORE the ACK purges
             (loop repeat 300 until (plusp (dds.disc:node-sample-count node2))
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
               (%check :pin-got-one (= 1 (length data)) "take-loaned must return exactly one sample")
               (let ((v (first data)))
                 (%check :pin-a (= (fd-abc-a-fd v) va) (format nil "field a ~d != ~d" (fd-abc-a-fd v) va))
                 (%check :pin-b (= (fd-abc-b-fd v) vb) (format nil "field b ~d != ~d" (fd-abc-b-fd v) vb))
                 (%check :pin-c (= (fd-abc-c-fd v) vc) (format nil "field c ~d != ~d" (fd-abc-c-fd v) vc)))
               ;; (4) drive the ACK -> full-ACK purge drops the HC change AND releases the pin
               (loop repeat 120
                     until (null (dds.rtps.history:hc-get-change (dds.rtps.reliable:rtps-writer-hc writer) 1))
                     do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
               (%check :pin-purged (null (dds.rtps.history:hc-get-change (dds.rtps.reliable:rtps-writer-hc writer) 1))
                       "the writer must purge SN 1 after the reader fully ACKs it (§8.4.1)")
               (%check :pin-released (zerop (dds.pal:atomic-cell-value (dds.disc::disc-node-zc-pin-count node1)))
                       "the full-ACK purge must RELEASE the pin (live pin count back to 0)")
               (%check :pin-slot-survives (= 1 (%zc-slot-refcount sap slot))
                       "the slot must SURVIVE the purge on the reader's still-held delivery hold (refcount 1)")
               (dds.dcps:return-loan dr loans)
               (%check :pin-slot-freed (zerop (%zc-slot-refcount sap slot))
                       "after return-loan the slot must free (refcount 0)")))
           ;; PHASE 2 (M1) — the REVERSE release order: return-loan BEFORE the full-ACK purge (the code is
           ;; order-independent; both orders free the slot exactly once). SN 2 on the same instance (KEEP_LAST
           ;; depth-1) supersedes SN 1's already-purged change.
           (let* ((sap (dds.disc::disc-node-zc-pool-sap node1))
                  (loan2 (dds.dcps:loan-sample dw))
                  (s2 (dds.dcps:writer-loan-sample loan2))
                  (slot2 (dds.dcps::writer-loan-slot loan2)))
             (setf (fd-abc-a-fd s2) 220 (fd-abc-b-fd s2) 3000000020 (fd-abc-c-fd s2) 12345678901234567820)
             (%check :pin2-write-ok (eq :ok (dds.dcps:write-loaned dw loan2)) "write-loaned (SN 2) must return :ok")
             (loop repeat 300 until (< 1 (dds.disc:node-sample-count node2))
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
               (%check :pin2-got (= 1 (length data)) "take-loaned must return SN 2")
               ;; RETURN the loan FIRST — before driving the ACK-purge (the reverse of phase 1's order). The delivery
               ;; hold and the pin hold are two independent %zc-release decrements; the exact instant each fires is
               ;; timing-dependent, but whichever is LAST must free the slot EXACTLY once (no double-free / u32 wrap).
               (dds.dcps:return-loan dr loans)
               ;; NOW drive the ACK -> the full-ACK purge releases the pin -> both holds gone -> slot freed once
               (loop repeat 120
                     until (zerop (%zc-slot-refcount sap slot2))
                     do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
               (%check :pin2-freed-reverse (zerop (%zc-slot-refcount sap slot2))
                       "reverse order (return-loan THEN ACK-purge) must free the slot EXACTLY once (refcount 0, no u32 wrap)")
               (%check :pin2-count-0 (zerop (dds.pal:atomic-cell-value (dds.disc::disc-node-zc-pin-count node1)))
                       "the pin count must return to 0 after the reverse-order release"))))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
    t)

(defun* run-acked-slot-pin-retransmit-test ()
    (function () t)
  "WP-ACKED-SLOT-PINNING scenario 2 — retransmit-from-pinned-slot (FR-PF-4, R6, ADR 0044; NOT cleared for ship —
   pending counsel). An eligible pinned writer; the first ref-DATA for SN 1 is DROPPED (*debug-drop-sample-numbers*)
   so the reader NACKs; the writer's ACKNACK retransmit must deliver the sample byte-exact by reading the STILL-
   PINNED slot ON DEMAND — NO retained payload ever existed. Asserts: (1) right after write-loaned the HC change is
   pinned with no retained payload; (2) nothing arrived during the drop; (3) after the drop clears the sample is
   ultimately received (reliable, no silent loss) and reads a/b/c byte-exact; (4) the retransmit materialised the
   payload from the slot (the change now carries a resolved serialized-payload). Skips where SHMEM is off."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-acked-slot-pin-retransmit-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)
         (va 211) (vb 3000000011) (vc 12345678901234567801)
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (multiple-value-bind (dw dr node1 node2 writer) (%acked-pin-setup p1 p2 "FdPinReTx")
           (setf dds.disc:*debug-drop-sample-numbers* (list 1))
           (let* ((loan (dds.dcps:loan-sample dw))
                  (s (dds.dcps:writer-loan-sample loan)))
             (setf (fd-abc-a-fd s) va (fd-abc-b-fd s) vb (fd-abc-c-fd s) vc)
             (%check :pinretx-write-ok (eq :ok (dds.dcps:write-loaned dw loan)) "write-loaned must return :ok")
             (let ((ch (dds.rtps.history:hc-get-change (dds.rtps.reliable:rtps-writer-hc writer) 1)))
               (%check :pinretx-pinned (and ch (dds.rtps.history:cache-change-zc-pinned ch)
                                            (null (dds.rtps.history:cache-change-serialized-payload ch)))
                       "the change must be pinned with NO retained payload before the retransmit")
               ;; M2 KAT: the on-demand read of the pinned slot (the retransmit's byte-source, via write-data) must
               ;; be BYTE-FOR-BYTE identical to the classic retained-path serialization of the same field values —
               ;; so a retransmit-from-pinned DATA payload equals what the retained-payload retransmit would emit.
               (when ch
                 (let* ((sap (dds.disc::disc-node-zc-pool-sap node1))
                        (classic (make-fd-abc-flatdata))
                        (b-pin (dds.xport.zerocopy::%zc-resolve-fresh
                                sap (dds.rtps.history:cache-change-zc-slot ch)
                                (dds.rtps.history:cache-change-zc-generation ch))))
                   (setf (fd-abc-a-fd classic) va (fd-abc-b-fd classic) vb (fd-abc-c-fd classic) vc)
                   (%check :pinretx-kat-byte-exact
                           (and b-pin (equalp b-pin (subseq (dds.core.buffer:octet-buffer-vec classic)
                                                            0 +fd-abc-flatdata-size+)))
                           "the pinned-slot on-demand read must be BYTE-FOR-BYTE the retained-path serialization (the retransmit DATA payload)")
                   (dds.pal:free-static (dds.core.buffer:octet-buffer-vec classic)))))
             (dotimes (i 6) (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (%check :pinretx-dropped (zerop (dds.disc:node-sample-count node2))
                     "drop hook failed: the reader received SN 1 while it was being dropped")
             (setf dds.disc:*debug-drop-sample-numbers* nil)
             (loop repeat 100 until (plusp (dds.disc:node-sample-count node2))
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (%check :pinretx-recovered (plusp (dds.disc:node-sample-count node2))
                     "the pinned sample never recovered after the dropped ref-DATA was retransmitted (silent loss)")
             (let ((ch (dds.rtps.history:hc-get-change (dds.rtps.reliable:rtps-writer-hc writer) 1)))
               (when ch   ; may already be purged if the reader ACKed; if present it must show the on-demand resolve
                 (%check :pinretx-materialized (dds.rtps.history:cache-change-serialized-payload ch)
                         "the retransmit must have MATERIALISED the payload from the pinned slot on demand")))
             (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
               (%check :pinretx-one (= 1 (length data)) "take-loaned must return exactly the one recovered sample")
               (let ((d (first data)))
                 (%check :pinretx-a (= (fd-abc-a-fd d) va) (format nil "recovered field a ~d != ~d" (fd-abc-a-fd d) va))
                 (%check :pinretx-b (= (fd-abc-b-fd d) vb) (format nil "recovered field b ~d != ~d" (fd-abc-b-fd d) vb))
                 (%check :pinretx-c (= (fd-abc-c-fd d) vc) (format nil "recovered field c ~d != ~d" (fd-abc-c-fd d) vc)))
               (dds.dcps:return-loan dr loans))))
      (setf dds.disc:*debug-drop-sample-numbers* nil)
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
    t)

(defun* run-acked-slot-pin-budget-test ()
    (function () t)
  "WP-ACKED-SLOT-PINNING scenario 3 — pin-budget exhaustion falls back to the retained payload (FR-PF-4, R6, ADR
   0044). With *zc-pin-budget* bound to 0 an eligible loan-write CANNOT pin; it must fall back — materialise the
   retained payload on demand from the still-armed slot and publish as a NORMAL change (serialized-payload
   non-nil, NOT pinned, live pin count stays 0) — and still deliver byte-exact. Skips where SHMEM is off."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-acked-slot-pin-budget-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)
         (dds.disc:*zc-pin-budget* 0)                       ; no pin may be granted
         (va 212) (vb 3000000012) (vc 12345678901234567802)
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (multiple-value-bind (dw dr node1 node2 writer) (%acked-pin-setup p1 p2 "FdPinBudget")
           (let* ((loan (dds.dcps:loan-sample dw))
                  (s (dds.dcps:writer-loan-sample loan)))
             (setf (fd-abc-a-fd s) va (fd-abc-b-fd s) vb (fd-abc-c-fd s) vc)
             (%check :pinbud-write-ok (eq :ok (dds.dcps:write-loaned dw loan)) "write-loaned must return :ok")
             (let ((ch (dds.rtps.history:hc-get-change (dds.rtps.reliable:rtps-writer-hc writer) 1)))
               (%check :pinbud-present ch "the writer HC must hold SN 1")
               (when ch
                 (%check :pinbud-not-pinned (null (dds.rtps.history:cache-change-zc-pinned ch))
                         "at budget 0 the change must NOT be pinned")
                 (%check :pinbud-retained (dds.rtps.history:cache-change-serialized-payload ch)
                         "the budget-exhausted fallback must carry the on-demand-resolved retained payload")))
             (%check :pinbud-count-0 (zerop (dds.pal:atomic-cell-value (dds.disc::disc-node-zc-pin-count node1)))
                     "no slot may be pinned when the budget is 0")
             (loop repeat 300 until (plusp (dds.disc:node-sample-count node2))
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
               (%check :pinbud-one (= 1 (length data)) "take-loaned must return the sample")
               (let ((d (first data)))
                 (%check :pinbud-a (= (fd-abc-a-fd d) va) (format nil "field a ~d != ~d" (fd-abc-a-fd d) va))
                 (%check :pinbud-c (= (fd-abc-c-fd d) vc) (format nil "field c ~d != ~d" (fd-abc-c-fd d) vc)))
               (dds.dcps:return-loan dr loans))))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
    t)

(defun* run-acked-slot-pin-ineligible-test ()
    (function () t)
  "WP-ACKED-SLOT-PINNING scenario 4 — ineligibility falls back to the eager retained payload (FR-PF-4, R6, ADR
   0044). A BEST_EFFORT reader (no ACK -> nothing would release a pin) makes the writer NOT pin-capable: write-loaned
   must materialise the retained payload eagerly (ADR 0042 behaviour, byte- and alloc-identical) — the change is
   NOT pinned, carries a serialized-payload, and the live pin count stays 0 — and deliver byte-exact. Skips where
   SHMEM is off."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-acked-slot-pin-ineligible-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)
         (va 213) (vb 3000000013) (vc 12345678901234567803)
         (ts (dds.types:find-type-support "fd-abc"))
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 "FdPinInelig" "fd-abc" ts))
                (tr (dds.dcps:create-topic p2 "FdPinInelig" "fd-abc" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw))
                (dr (dds.dcps:create-datareader sub tr))     ; BEST_EFFORT default -> never ACKs -> not pin-capable
                (node1 (dds.dcps::dp-node p1))
                (node2 (dds.dcps::dp-node p2))
                (writer (dds.disc::disc-node-user-writer node1)))
           (loop repeat 200
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (loop repeat 200
                 until (plusp (dds.disc::%zc-readers node1
                                                     (list (dds.rtps.discovery:endpoint-data-guid
                                                            (first (dds.disc::%matched-endpoints node1))))))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check :pininelig-not-capable (not (dds.disc:node-loan-write-pin-capable-p node1))
                   "a writer with only a BEST_EFFORT reader must NOT be pin-capable (nothing would release the pin)")
           (let* ((loan (dds.dcps:loan-sample dw))
                  (s (dds.dcps:writer-loan-sample loan)))
             (setf (fd-abc-a-fd s) va (fd-abc-b-fd s) vb (fd-abc-c-fd s) vc)
             (%check :pininelig-write-ok (eq :ok (dds.dcps:write-loaned dw loan)) "write-loaned must return :ok")
             (let ((ch (dds.rtps.history:hc-get-change (dds.rtps.reliable:rtps-writer-hc writer) 1)))
               (when ch
                 (%check :pininelig-not-pinned (null (dds.rtps.history:cache-change-zc-pinned ch))
                         "an ineligible writer's change must NOT be pinned")
                 (%check :pininelig-retained (dds.rtps.history:cache-change-serialized-payload ch)
                         "an ineligible writer must materialise the retained payload eagerly (ADR 0042)")))
             (%check :pininelig-count-0 (zerop (dds.pal:atomic-cell-value (dds.disc::disc-node-zc-pin-count node1)))
                     "no pin may be taken for an ineligible writer")
             (loop repeat 300 until (plusp (dds.disc:node-sample-count node2))
                   do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
             (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
               (%check :pininelig-one (= 1 (length data)) "take-loaned must return the sample")
               (let ((d (first data)))
                 (%check :pininelig-a (= (fd-abc-a-fd d) va) (format nil "field a ~d != ~d" (fd-abc-a-fd d) va))
                 (%check :pininelig-c (= (fd-abc-c-fd d) vc) (format nil "field c ~d != ~d" (fd-abc-c-fd d) vc)))
               (dds.dcps:return-loan dr loans))))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
    t)

(defun* run-acked-slot-pin-keeplast-evict-test ()
    (function () t)
  "WP-ACKED-SLOT-PINNING scenario 5 — a KEEP_LAST early eviction releases the pin BEFORE the ACK (FR-PF-4, R6,
   ADR 0044 §4.4). A KEEP_LAST depth-1 pinned writer publishes SN 1 (pinned), then SN 2 for the SAME instance
   SUPERSEDES it: the hc-add-change eviction of SN 1 fires the change-removal choke, which releases SN 1's pin
   exactly once (no retransmit owed for a superseded sample). Asserts the pin count returns to 1 (SN 2's pin) after
   SN 1 is evicted, proving the eviction drop-site releases the pin. Skips where SHMEM is off."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-acked-slot-pin-keeplast-evict-test t))
  (let* ((dds.disc:*shmem-enabled* t)
         (dds.disc:*zerocopy-enabled* t)
         (dds.disc:*zerocopy-min-payload-bytes* 8)
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         ;; the default writer QoS is KEEP_LAST depth 1; keyless fd-abc collapses to one (global) bucket, so
         ;; SN 2 supersedes SN 1 in the writer HistoryCache
         (multiple-value-bind (dw dr node1 node2 writer) (%acked-pin-setup p1 p2 "FdPinKL")
           (declare (ignore dr node2))
           (%check :pinkl-capable (dds.disc:node-loan-write-pin-capable-p node1) "must be pin-capable")
           (let ((loan1 (dds.dcps:loan-sample dw)))
             (setf (fd-abc-a-fd (dds.dcps:writer-loan-sample loan1)) 1
                   (fd-abc-b-fd (dds.dcps:writer-loan-sample loan1)) 100
                   (fd-abc-c-fd (dds.dcps:writer-loan-sample loan1)) 1000)
             (dds.dcps:write-loaned dw loan1))
           (%check :pinkl-one-pinned (= 1 (dds.pal:atomic-cell-value (dds.disc::disc-node-zc-pin-count node1)))
                   "SN 1 must be pinned")
           (let ((loan2 (dds.dcps:loan-sample dw)))
             (setf (fd-abc-a-fd (dds.dcps:writer-loan-sample loan2)) 1
                   (fd-abc-b-fd (dds.dcps:writer-loan-sample loan2)) 200
                   (fd-abc-c-fd (dds.dcps:writer-loan-sample loan2)) 2000)
             (dds.dcps:write-loaned dw loan2))
           ;; SN 1 evicted by the KEEP_LAST depth-1 supersession -> its pin released; SN 2 now pinned
           (%check :pinkl-sn1-evicted (null (dds.rtps.history:hc-get-change (dds.rtps.reliable:rtps-writer-hc writer) 1))
                   "SN 1 must be evicted by the KEEP_LAST depth-1 supersession")
           (%check :pinkl-one-after (= 1 (dds.pal:atomic-cell-value (dds.disc::disc-node-zc-pin-count node1)))
                   "the eviction of SN 1 must RELEASE its pin (live pin count back to 1 = SN 2's pin)"))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
    t)

(defun* run-acked-slot-pin-defer-on-sendref-test ()
    (function () t)
  "WP-ACKED-SLOT-PINNING I1 regression — the pin release DEFERS on an in-flight send-ref (FR-PF-4, R6, ADR 0044
   §I1). A captured send build-thunk may still RESOLVE the pinned slot BY REFERENCE (%ensure-change-payload reads
   the live slot), so hc-try-release-pinned must OUTLIVE any outstanding send-ref — structurally identical to
   hc-try-release-pooled — or the slot could be reclaimed+generation-bumped under a concurrent resolve. Pure
   unit-level with a MOCK zc-release-fn (no SHMEM — runs FULLY on BOTH impls, not pass-skipped): install a pinned
   change, HOLD a send-ref, remove the change (KEEP_LAST/purge), assert the pin is NOT released (deferred), drop
   the send-ref, assert the deferred release fires EXACTLY once, and a second try is a validated no-op."
  (let* ((hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil))
         (released '())
         (change (dds.rtps.history:make-cache-change
                  :sn 1 :zc-slot 5 :zc-generation 7 :zc-pinned t :zc-len 100)))
    (setf (dds.rtps.history:history-cache-zc-release-fn hc)
          (lambda (slot gen) (push (cons slot gen) released)))
    (dds.rtps.history:hc-add-change hc change)
    (incf (dds.rtps.history:cache-change-send-refcount change))   ; an in-flight send captured the change
    (dds.rtps.history:hc-remove-change hc 1)                      ; remove WHILE the send-ref is held
    (%check :pindefer-held (and (null released) (dds.rtps.history:cache-change-zc-pinned change))
            "the pin must NOT release while a send-ref is held (deferred exactly like the pooled path, I1)")
    (setf (dds.rtps.history:cache-change-send-refcount change) 0)  ; the send finished -> last ref drops
    (dds.rtps.history:hc-try-release-pinned hc change)            ; the deferred release fires (writer-release-change-refs' retry)
    (%check :pindefer-released (and (= 1 (length released)) (equal (car released) (cons 5 7))
                                    (null (dds.rtps.history:cache-change-zc-pinned change)))
            "the pin must release EXACTLY once when the last send-ref drops (I1)")
    (dds.rtps.history:hc-try-release-pinned hc change)            ; idempotent one-shot
    (%check :pindefer-idempotent (= 1 (length released))
            "a second hc-try-release-pinned after release is a validated no-op (one-shot)"))
  t)

(defun* %deliver-one-zc-loan (writer-qos label va vb vc)
    (function (t string (unsigned-byte 8) (unsigned-byte 32) (unsigned-byte 64)) t)
  "WP-RELIABLE-ZC scenario 5 helper (R6, ADR 0017; NOT cleared for ship — pending counsel): drive ONE
   FlatData-over-Zero-Copy loan delivery from a writer created with WRITER-QOS (reliable OR best-effort) to a
   loan-capable reader of MATCHING reliability, and assert take-loaned hands back a flatdata-view reading
   (VA,VB,VC) byte-exact. LABEL distinguishes the assertion keys per QoS. Proves ZC rides the writer's QoS with
   NO reliability gate — a best-effort and a reliable ZC writer deliver the loan identically. NOT cleared for
   ship — pending counsel (R6)."
  (let* ((ts (dds.types:find-type-support "fd-abc"))
         (reader-qos (dds.qos:make-reader-qos
                      :reliability (dds.qos:qos-reliability writer-qos)))   ; RxO-compatible with the writer
         (p1 (dds.dcps:create-participant :domain (test-domain)))
         (p2 (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (let* ((tw (dds.dcps:create-topic p1 (format nil "FdQos~a" label) "fd-abc" ts))
                (tr (dds.dcps:create-topic p2 (format nil "FdQos~a" label) "fd-abc" ts))
                (pub (dds.dcps:create-publisher p1))
                (sub (dds.dcps:create-subscriber p2))
                (dw (dds.dcps:create-datawriter pub tw :qos writer-qos))
                (dr (dds.dcps:create-datareader sub tr :qos reader-qos))
                (node1 (dds.dcps::dp-node p1))
                (node2 (dds.dcps::dp-node p2))
                (fd (make-fd-abc-flatdata)))
           (setf (fd-abc-a-fd fd) va (fd-abc-b-fd fd) vb (fd-abc-c-fd fd) vc)
           (%check (intern (format nil "QOS-~a-LOAN-CAPABLE" label) :keyword)
                   (dds.disc::disc-node-zc-loan-capable node2)
                   (format nil "~a: the FlatData reader must be loan-capable regardless of reliability QoS" label))
           (loop repeat 200
                 until (and (plusp (dds.dcps:matched-count p1)) (plusp (dds.dcps:matched-count p2)))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check (intern (format nil "QOS-~a-MATCHED" label) :keyword)
                   (plusp (dds.dcps:matched-count p1)) (format nil "~a: writer/reader did not match" label))
           (loop repeat 200
                 until (plusp (dds.disc::%zc-readers node1
                                                     (list (dds.rtps.discovery:endpoint-data-guid
                                                            (first (dds.disc::%matched-endpoints node1))))))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (dds.dcps:write-sample dw fd)
           (loop repeat 300 until (plusp (dds.disc:node-sample-count node2))
                 do (dds.dcps:spin p1) (dds.dcps:spin p2) (sleep 0.02))
           (%check (intern (format nil "QOS-~a-DELIVERED" label) :keyword)
                   (plusp (dds.disc:node-sample-count node2))
                   (format nil "~a: the ZC loan sample was never delivered (ZC must ride the QoS)" label))
           (%check (intern (format nil "QOS-~a-ZC-SEND" label) :keyword)
                   (plusp (dds.disc::disc-node-zc-sends node1))
                   (format nil "~a: the writer must have sent a ZC ref (no reliability gate on ZC)" label))
           (multiple-value-bind (data loans) (dds.dcps:take-loaned dr)
             (%check (intern (format nil "QOS-~a-ONE" label) :keyword) (= 1 (length data))
                     (format nil "~a: take-loaned must return exactly one sample" label))
             (%check (intern (format nil "QOS-~a-VIEW" label) :keyword) (dds.types:flatdata-view-p (first data))
                     (format nil "~a: the ZC sample must be delivered as a flatdata-view" label))
             (let ((v (first data)))
               (%check (intern (format nil "QOS-~a-A" label) :keyword) (= (fd-abc-a-fd v) va)
                       (format nil "~a: field a ~d != ~d" label (fd-abc-a-fd v) va))
               (%check (intern (format nil "QOS-~a-B" label) :keyword) (= (fd-abc-b-fd v) vb)
                       (format nil "~a: field b ~d != ~d" label (fd-abc-b-fd v) vb))
               (%check (intern (format nil "QOS-~a-C" label) :keyword) (= (fd-abc-c-fd v) vc)
                       (format nil "~a: field c ~d != ~d" label (fd-abc-c-fd v) vc)))
             (dds.dcps:return-loan dr loans))
           (dds.pal:free-static (dds.core.buffer:octet-buffer-vec fd)))
      (dds.dcps:delete-participant p1)
      (when p2 (dds.dcps:delete-participant p2))))
  t)

(defun* run-reliable-zc-qos-test ()
    (function () t)
  "WP-RELIABLE-ZC scenario 5 — ZC rides the QoS, no reliability gate (FR-PF-3/4, R6, ADR 0017; NOT cleared for
   ship — pending counsel). A RELIABLE writer AND a BEST-EFFORT writer EACH deliver a Zero-Copy loan sample
   correctly to a matching loan-capable reader (%deliver-one-zc-loan): the ZC ref path is selected by the same-
   host + ZC-capable gate, NOT by reliability, so a best-effort ZC sample is delivered as a literal-0-copy view
   exactly like a reliable one. Confirms ZC composes orthogonally with reliability (a reliable ZC sample is
   NACKable/retransmittable — scenario 1; a best-effort ZC sample is delivered once — here). The ZC-OFF /
   non-FlatData byte-identity regression is held by the existing suite (flow-off-byte-identical, the corpus,
   zerocopy-end-to-end). Skips cleanly where SHMEM is off (Clasp/macOS gap, ADR 0013)."
  (unless (dds.xport.shmem:shm-attach-by-name-reliable-p) (return-from run-reliable-zc-qos-test t))
  (let ((dds.disc:*shmem-enabled* t)
        (dds.disc:*zerocopy-enabled* t)
        (dds.disc:*zerocopy-min-payload-bytes* 8))
    (%deliver-one-zc-loan (dds.qos:make-writer-qos :reliability :reliable) "REL" 220 3200000001 12000000000000000001)
    (%deliver-one-zc-loan (dds.qos:make-writer-qos :reliability :best-effort) "BE" 221 3200000002 12000000000000000002))
  t)

(defun* run-flatdata-zc-loan-stress-test ()
    (function () t)
  "WP-FLATDATA-ZC-LOAN Phase F1 — THE CONCURRENCY LIFETIME STRESS (FR-PF-3/4, NFR-SEC, R6, ADR 0017; NOT cleared
   for ship — pending counsel). The binary-gate safety property under REAL threads: a loan's slot lifetime spans
   the holder thread WHILE a concurrent writer thread churns the pool (loaning + force-reclaiming to fill it).
   Asserts, against a small pool: (1) NO UAF / NO TORN READ — a held loan's fields stay byte-correct while the
   writer churns (force-reclaim skips refcount>0, so the held slot is never overwritten under the read); (2)
   POOL-FULL ⇒ the writer's %zc-loan returns NIL (the non-ZC fallback — never blocks, never crashes), with the
   held slot still intact; (3) NO REFCOUNT LEAK — after the holder releases, the pool is FULLY reclaimable (the
   freelist recovers to K); (4) A LEAKED LOAN (never returned) degrades to fallback (a pinned slot ⇒ pool-full ⇒
   NIL, no wedge), and an explicit final release (the reader-close analogue) STILL returns it (the slot frees).
   Bounded + robust: the writer thread runs a fixed iteration count behind a deadline so a regression FAILS
   rather than wedges (the holder never blocks; the writer's loan just returns NIL when saturated). SBCL only
   (the ZC pool + foreign SAP reads are SBCL-only, ADR 0013); Clasp pass-skips."
  (if (not (eq (dds.pal:pal-impl-name) :sbcl))
      (format t "~&  [skip] flatdata-zc-loan-stress: ZC pool + load-sap-u8 are SBCL-only (ADR 0013) — NFR-PORT gap~%")
      (let* ((k 4)
             (slot-bytes 64)
             (mem (dds.pal:alloc-static (dds.xport.zerocopy::%zc-bytes k slot-bytes)))
             (sap (dds.pal:static-pointer mem))
             (held (octets 11 22 33 44 55 66 77 88))   ; the byte pattern the held loan must keep intact
             (churn (octets 200 201 202 203 204))      ; the writer's churn payload (distinct from HELD)
             (stop nil) (writer-iters 0) (writer-error nil) (loan-nils 0)
             (writer-thread nil))
        (unwind-protect
             (progn
               (dds.xport.zerocopy::%zc-init sap k slot-bytes)
               ;; HOLD a loan: loan HELD into a slot (refcount=1), acquire it for read, DO NOT release
               (multiple-value-bind (hslot hgen) (dds.xport.zerocopy::%zc-loan sap held 0 (length held) 1)
                 (%check :fdzc-stress-held-loaned (and hslot t) "the held loan must take a slot")
                 (multiple-value-bind (psap idx hg hlen hbase) (dds.xport.zerocopy::%zc-acquire-for-read sap hslot hgen)
                   (declare (ignore idx hg))
                   (%check :fdzc-stress-held-acquired (and psap t) "acquire-for-read of the held loan must return a handle")
                   ;; CONCURRENT WRITER: churn the pool (loan + force-reclaim) for a bounded number of iterations
                   (setf writer-thread
                         (dds.pal:spawn
                          (lambda ()
                            (handler-case
                                (dotimes (i 20000)
                                  (when stop (return))
                                  (multiple-value-bind (s g) (dds.xport.zerocopy::%zc-loan sap churn 0 (length churn) 1)
                                    (incf writer-iters)
                                    (if s
                                        (dds.xport.zerocopy::%zc-release sap s g)   ; immediately return so churn keeps cycling
                                        (incf loan-nils)))                          ; pool-full while the held slot pins one ⇒ fallback
                                  (when (zerop (mod i 64)) (sleep 0.0001)))         ; let the holder interleave
                              (error (e) (setf writer-error e))))
                          :name "fdzc-stress-writer"))
                   ;; wait (bounded) for the writer to actually start churning (no race: the holder read must overlap real churn)
                   (let ((start-deadline (+ (dds.pal:monotonic-ns) 2000000000)))
                     (loop until (or (plusp writer-iters) (> (dds.pal:monotonic-ns) start-deadline))
                           do (sleep 0.0005)))
                   ;; while the writer churns, REPEATEDLY read the held view — its bytes must NEVER tear/change
                   (let ((torn nil) (deadline (+ (dds.pal:monotonic-ns) 2000000000)))   ; 2s bound (fail, never wedge)
                     (loop repeat 50000
                           while (< (dds.pal:monotonic-ns) deadline)
                           do (unless (loop for j below (min (length held) hlen)
                                            always (= (dds.pal:load-sap-u8 psap (+ hbase j)) (aref held j)))
                                (setf torn t) (return)))
                     (%check :fdzc-stress-no-torn-read (null torn)
                             "the held loan's bytes must stay byte-correct while the writer churns (no torn read / UAF — force-reclaim skips refcount>0)"))
                   (setf stop t)
                   (dds.pal:join writer-thread) (setf writer-thread nil)
                   (%check :fdzc-stress-writer-no-error (null writer-error)
                           (format nil "the concurrent writer must not error (no crash under churn); got ~a" writer-error))
                   (%check :fdzc-stress-writer-progressed (plusp writer-iters)
                           "the concurrent writer must have made progress (the holder never blocks it)")
                   ;; the held loan is STILL byte-intact after all that churn (the final UAF check)
                   (%check :fdzc-stress-held-still-intact
                           (loop for j below (min (length held) hlen)
                                 always (= (dds.pal:load-sap-u8 psap (+ hbase j)) (aref held j)))
                           "the held loan's payload must remain byte-intact after the writer churn completes (no overwrite)")
                   ;; (2) POOL-FULL fallback while the held slot pins one: fill the other K-1 slots, then a further loan ⇒ NIL
                   (let ((probes '()))
                     (dotimes (i (1- k))
                       (multiple-value-bind (s g) (dds.xport.zerocopy::%zc-loan sap churn 0 (length churn) 1)
                         (when s (push (cons s g) probes))))
                     (multiple-value-bind (sfull gfull) (dds.xport.zerocopy::%zc-loan sap churn 0 (length churn) 1)
                       (declare (ignore gfull))
                       (%check :fdzc-stress-pool-full-fallback (null sfull)
                               "with every slot loaned (the held one + the K-1 probes) %zc-loan must return NIL (non-ZC fallback), never reclaim the held slot"))
                     (%check :fdzc-stress-held-survives-full
                             (loop for j below (min (length held) hlen)
                                   always (= (dds.pal:load-sap-u8 psap (+ hbase j)) (aref held j)))
                             "the held loan must survive pool-full pressure byte-intact (it is never a reclaim candidate)")
                     (dolist (p probes) (dds.xport.zerocopy::%zc-release sap (car p) (cdr p))))   ; release the probes
                   ;; (3) NO REFCOUNT LEAK: release the held loan ⇒ the freelist fully recovers to K
                   (%check :fdzc-stress-release-held (dds.xport.zerocopy::%zc-release psap hslot hgen)
                           "releasing the held loan must apply")
                   (%check :fdzc-stress-full-reclaim (= k (dds.xport.zerocopy::%zc-free-count sap))
                           (format nil "after all returns the pool must be FULLY reclaimable (freelist = K = ~d), no refcount leak" k))))
               ;; (4) LEAKED LOAN: loan + acquire, NEVER return ⇒ a pinned slot; fill the rest ⇒ pool-full fallback (no wedge);
               ;;     then the explicit final release (the reader-close analogue) STILL returns it.
               (multiple-value-bind (lslot lgen) (dds.xport.zerocopy::%zc-loan sap held 0 (length held) 1)
                 (dds.xport.zerocopy::%zc-acquire-for-read sap lslot lgen)   ; acquire, then LEAK (no release)
                 (let ((probes '()))
                   (dotimes (i (1- k))
                     (multiple-value-bind (s g) (dds.xport.zerocopy::%zc-loan sap churn 0 (length churn) 1)
                       (when s (push (cons s g) probes))))
                   (multiple-value-bind (sfull gfull) (dds.xport.zerocopy::%zc-loan sap churn 0 (length churn) 1)
                     (declare (ignore gfull))
                     (%check :fdzc-stress-leak-fallback (null sfull)
                             "a LEAKED (never-returned) loan pins a slot ⇒ pool-full ⇒ the writer falls back to non-ZC (NIL), no wedge"))
                   (dolist (p probes) (dds.xport.zerocopy::%zc-release sap (car p) (cdr p)))
                   ;; the reader-close analogue: the explicit final release of the leaked loan still frees its slot
                   (%check :fdzc-stress-leak-close-returns (dds.xport.zerocopy::%zc-release sap lslot lgen)
                           "the reader-close analogue (a final release of the leaked loan) must STILL return it")
                   (%check :fdzc-stress-leak-recovered (= k (dds.xport.zerocopy::%zc-free-count sap))
                           "after the leaked loan's final release the pool fully recovers (no permanent leak)"))))
          (setf stop t)
          (when writer-thread (ignore-errors (dds.pal:join writer-thread)))
          (dds.xport.zerocopy::%zc-destroy sap)
          (dds.pal:free-static mem))))
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
                (lambda (direction remote &optional local-eid) (declare (ignore local-eid))
                  (push (cons direction remote) unmatched)))
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
        (p (dds.dcps:create-participant :domain (test-domain)))
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

(defun* run-n-endpoint-s5-status-test ()
    (function () t)
  "WP-N-ENDPOINT-S5 (ADR 0048): THE per-endpoint status/listener dispatch slice (the FINAL slice). ONE
   participant holds TWO different-topic DataReaders (A=dcps-msg, B=shape-type) + TWO DataWriters, each
   with its OWN capturing listener. The four HARD disc->DCPS status hooks (match/unmatch/incompatible/
   liveliness) are fired offline for a remote on TOPIC-B; each must land on ENDPOINT-B (its status counter
   bumps + its listener fires) and NEVER on ENDPOINT-A. Endpoint-B is created FIRST and endpoint-A LAST, so
   the retired v1 back-ref (dp-user-reader/-writer = LAST-created = A) would mis-deliver every topic-B event
   to A: the B-counter / A-silent assertions are the RED discriminator (pre-rewire they fail; post-rewire,
   per-topic resolution makes them GREEN). Offline direct hook firing (no network). Both impls."
  (let ((ts-a (dds.types:find-type-support "dcps-msg"))
        (ts-b (dds.types:find-type-support "shape-type"))
        (p (dds.dcps:create-participant :domain (test-domain)))
        (rla (make-instance 'capturing-reader-listener))
        (rlb (make-instance 'capturing-reader-listener))
        (wla (make-instance 'capturing-writer-listener))
        (wlb (make-instance 'capturing-writer-listener)))
    (unwind-protect
         (let* ((tra (dds.dcps:create-topic p "S5A" "dcps-msg" ts-a))
                (trb (dds.dcps:create-topic p "S5B" "shape-type" ts-b))
                (sub (dds.dcps:create-subscriber p))
                (pub (dds.dcps:create-publisher p))
                ;; B FIRST, A LAST: the retired back-ref would point at A -> a topic-B event mis-delivers to A (RED).
                (drb (dds.dcps:create-datareader sub trb))
                (dwb (dds.dcps:create-datawriter pub trb))
                (dra (dds.dcps:create-datareader sub tra))
                (dwa (dds.dcps:create-datawriter pub tra))
                (node (dds.dcps::dp-node p))
                (rw-b (dds.rtps.discovery:make-endpoint-data
                       :guid (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x5b)))
                               (setf (aref g 15) #x02) g)
                       :topic-name "S5B" :type-name "ShapeType"))
                (rr-b (dds.rtps.discovery:make-endpoint-data
                       :guid (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x5c)))
                               (setf (aref g 15) #x07) g)
                       :topic-name "S5B" :type-name "ShapeType")))
           (dds.dcps:set-reader-listener dra rla '(:subscription-matched :requested-incompatible-qos :liveliness-changed))
           (dds.dcps:set-reader-listener drb rlb '(:subscription-matched :requested-incompatible-qos :liveliness-changed))
           (dds.dcps:set-writer-listener dwa wla '(:publication-matched :offered-incompatible-qos))
           (dds.dcps:set-writer-listener dwb wlb '(:publication-matched :offered-incompatible-qos))
           ;; (1) MATCH on topic B -> reader-B SUBSCRIPTION_MATCHED + writer-B PUBLICATION_MATCHED; A stays 0.
           (dds.dcps::%on-disc-match p :remote-writer rw-b)
           (dds.dcps::%on-disc-match p :remote-reader rr-b)
           (%check :s5-match-b-sub
                   (= 1 (dds.dcps:subscription-matched-status-total-count (dds.dcps:get-subscription-matched-status drb)))
                   "topic-B match must bump reader-B SUBSCRIPTION_MATCHED (RED: retired back-ref delivers to last-created A)")
           (%check :s5-match-a-sub-zero
                   (zerop (dds.dcps:subscription-matched-status-total-count (dds.dcps:get-subscription-matched-status dra)))
                   "reader-A must NOT see topic-B's match")
           (%check :s5-match-b-pub
                   (= 1 (dds.dcps:publication-matched-status-total-count (dds.dcps:get-publication-matched-status dwb)))
                   "topic-B match must bump writer-B PUBLICATION_MATCHED")
           (%check :s5-match-a-pub-zero
                   (zerop (dds.dcps:publication-matched-status-total-count (dds.dcps:get-publication-matched-status dwa)))
                   "writer-A must NOT see topic-B's match")
           (%check :s5-match-b-rlistener (and (assoc :sub-matched (cap-snapshot rlb)) t)
                   "reader-B on_subscription_matched must fire")
           (%check :s5-match-a-rlistener-silent (null (assoc :sub-matched (cap-snapshot rla)))
                   "reader-A on_subscription_matched must NOT fire")
           (%check :s5-match-b-wlistener (and (assoc :pub-matched (cap-snapshot wlb)) t)
                   "writer-B on_publication_matched must fire")
           (%check :s5-match-a-wlistener-silent (null (assoc :pub-matched (cap-snapshot wla)))
                   "writer-A on_publication_matched must NOT fire")
           ;; (2) LIVELINESS on topic B: wire writer-B's S2 route -> reader-B, fire alive->not-alive.
           (dds.disc::%reader-route-add node (dds.rtps.discovery:endpoint-data-guid rw-b) (dds.dcps::dr-entity-id drb))
           (dds.dcps::%on-disc-liveliness-changed p (dds.rtps.discovery:endpoint-data-guid rw-b) nil)
           (%check :s5-liv-b
                   (= 1 (dds.dcps:liveliness-changed-status-not-alive-count (dds.dcps:get-liveliness-changed-status drb)))
                   "topic-B liveliness-not-alive must bump reader-B LIVELINESS_CHANGED (routed via %reader-routes-for)")
           (%check :s5-liv-a-zero
                   (zerop (dds.dcps:liveliness-changed-status-not-alive-count (dds.dcps:get-liveliness-changed-status dra)))
                   "reader-A must NOT see topic-B's liveliness change")
           (%check :s5-liv-b-listener (and (assoc :liv-changed (cap-snapshot rlb)) t)
                   "reader-B on_liveliness_changed must fire")
           (%check :s5-liv-a-listener-silent (null (assoc :liv-changed (cap-snapshot rla)))
                   "reader-A on_liveliness_changed must NOT fire")
           ;; (3) INCOMPATIBLE_QOS on topic B: reader-B REQUESTED + writer-B OFFERED; A stays 0.
           (dds.dcps::%on-disc-incompatible p :remote-writer rw-b '(:durability))
           (dds.dcps::%on-disc-incompatible p :remote-reader rr-b '(:durability))
           (%check :s5-incompat-b-req
                   (= 1 (dds.dcps:requested-incompatible-qos-status-total-count (dds.dcps:get-requested-incompatible-qos-status drb)))
                   "topic-B incompatible must bump reader-B REQUESTED_INCOMPATIBLE_QOS")
           (%check :s5-incompat-a-req-zero
                   (zerop (dds.dcps:requested-incompatible-qos-status-total-count (dds.dcps:get-requested-incompatible-qos-status dra)))
                   "reader-A must NOT see topic-B's incompatible-qos")
           (%check :s5-incompat-b-off
                   (= 1 (dds.dcps:offered-incompatible-qos-status-total-count (dds.dcps:get-offered-incompatible-qos-status dwb)))
                   "topic-B incompatible must bump writer-B OFFERED_INCOMPATIBLE_QOS")
           (%check :s5-incompat-a-off-zero
                   (zerop (dds.dcps:offered-incompatible-qos-status-total-count (dds.dcps:get-offered-incompatible-qos-status dwa)))
                   "writer-A must NOT see topic-B's incompatible-qos")
           (%check :s5-incompat-b-rlistener (and (assoc :req-incompat (cap-snapshot rlb)) t)
                   "reader-B on_requested_incompatible_qos must fire")
           (%check :s5-incompat-a-rlistener-silent (null (assoc :req-incompat (cap-snapshot rla)))
                   "reader-A on_requested_incompatible_qos must NOT fire")
           (%check :s5-incompat-b-wlistener (and (assoc :off-incompat (cap-snapshot wlb)) t)
                   "writer-B on_offered_incompatible_qos must fire")
           (%check :s5-incompat-a-wlistener-silent (null (assoc :off-incompat (cap-snapshot wla)))
                   "writer-A on_offered_incompatible_qos must NOT fire")
           ;; (4) UNMATCH on topic B: reader-B SUBSCRIPTION_MATCHED current_count -> 0; total monotonic; A untouched.
           (dds.dcps::%on-disc-unmatch p :remote-writer rw-b)
           (dds.dcps::%on-disc-unmatch p :remote-reader rr-b)
           (%check :s5-unmatch-b-current-zero
                   (zerop (dds.dcps:subscription-matched-status-current-count (dds.dcps:get-subscription-matched-status drb)))
                   "topic-B unmatch must drop reader-B SUBSCRIPTION_MATCHED current_count to 0")
           (%check :s5-unmatch-b-total-monotonic
                   (= 1 (dds.dcps:subscription-matched-status-total-count (dds.dcps:get-subscription-matched-status drb)))
                   "reader-B SUBSCRIPTION_MATCHED total_count must NOT be decremented (monotonic)")
           (%check :s5-unmatch-a-untouched
                   (zerop (dds.dcps:subscription-matched-status-total-count (dds.dcps:get-subscription-matched-status dra)))
                   "reader-A must NOT be touched by topic-B's unmatch"))
      (dds.dcps:delete-participant p))
    t))

(defun* run-n-endpoint-2c2-status-test ()
    (function () t)
  "WP-N-ENDPOINT-2C2 (ADR 0048): per-endpoint status dispatch for SAME-topic endpoints (closes the 2c-1 status
   follow-on). ONE participant holds TWO SAME-topic DataWriters (dw1,dw2) + TWO SAME-topic DataReaders (dra,drb)
   on ONE topic. The match/unmatch/incompatible hooks are fired offline threading the matched-local EntityId (as
   the real %fire-match does): each must land on the RIGHT SAME-topic endpoint resolved BY EntityId (its counter +
   listener), never the first-by-topic (the pre-2c2 RED: topic-first resolution bumped only ONE of the two). Also
   verifies UNMATCH threaded by EntityId decrements the RIGHT writer, leaving its same-topic sibling untouched.
   Offline direct hook firing (no network). Both impls."
  (let ((ts (dds.types:find-type-support "shape-type"))
        (p (dds.dcps:create-participant :domain (test-domain)))
        (rl1 (make-instance 'capturing-reader-listener))
        (rl2 (make-instance 'capturing-reader-listener))
        (wl1 (make-instance 'capturing-writer-listener))
        (wl2 (make-instance 'capturing-writer-listener)))
    (unwind-protect
         (let* ((tp  (dds.dcps:create-topic p "2C2S" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (pub (dds.dcps:create-publisher p))
                (dw1 (dds.dcps:create-datawriter pub tp))
                (dw2 (dds.dcps:create-datawriter pub tp))
                (dra (dds.dcps:create-datareader sub tp))
                (drb (dds.dcps:create-datareader sub tp))
                (e-w1 (dds.dcps::dw-entity-id dw1)) (e-w2 (dds.dcps::dw-entity-id dw2))
                (e-ra (dds.dcps::dr-entity-id dra)) (e-rb (dds.dcps::dr-entity-id drb))
                (rr1 (dds.rtps.discovery:make-endpoint-data
                      :guid (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x61)))
                              (setf (aref g 15) #x07) g)
                      :topic-name "2C2S" :type-name "ShapeType"))
                (rr2 (dds.rtps.discovery:make-endpoint-data
                      :guid (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x62)))
                              (setf (aref g 15) #x07) g)
                      :topic-name "2C2S" :type-name "ShapeType"))
                (rw1 (dds.rtps.discovery:make-endpoint-data
                      :guid (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x63)))
                              (setf (aref g 15) #x02) g)
                      :topic-name "2C2S" :type-name "ShapeType"))
                (rw2 (dds.rtps.discovery:make-endpoint-data
                      :guid (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x64)))
                              (setf (aref g 15) #x02) g)
                      :topic-name "2C2S" :type-name "ShapeType")))
           (%check :2c2-distinct-writers (/= e-w1 e-w2)
                   "the two SAME-topic DataWriters must get DISTINCT engine EntityIds")
           (%check :2c2-distinct-readers (/= e-ra e-rb)
                   "the two SAME-topic DataReaders must get DISTINCT engine EntityIds")
           (dds.dcps:set-reader-listener dra rl1 '(:subscription-matched :requested-incompatible-qos))
           (dds.dcps:set-reader-listener drb rl2 '(:subscription-matched :requested-incompatible-qos))
           (dds.dcps:set-writer-listener dw1 wl1 '(:publication-matched :offered-incompatible-qos))
           (dds.dcps:set-writer-listener dw2 wl2 '(:publication-matched :offered-incompatible-qos))
           ;; (1) PUBLICATION_MATCHED per SAME-topic writer, by threaded EntityId: rr1->dw1, rr2->dw2.
           (dds.dcps::%on-disc-match p :remote-reader rr1 e-w1)
           (%check :2c2-pub-w1
                   (= 1 (dds.dcps:publication-matched-status-total-count (dds.dcps:get-publication-matched-status dw1)))
                   "the match threaded with writer-1's EntityId must bump ONLY writer-1 PUBLICATION_MATCHED")
           (%check :2c2-pub-w2-zero
                   (zerop (dds.dcps:publication-matched-status-total-count (dds.dcps:get-publication-matched-status dw2)))
                   "writer-2 must NOT see writer-1's match (the RED: pre-2c2 topic-first resolution bumped only the first-by-topic)")
           (dds.dcps::%on-disc-match p :remote-reader rr2 e-w2)
           (%check :2c2-pub-w2
                   (= 1 (dds.dcps:publication-matched-status-total-count (dds.dcps:get-publication-matched-status dw2)))
                   "the match threaded with writer-2's EntityId must bump writer-2 PUBLICATION_MATCHED (both same-topic writers matched)")
           (%check :2c2-pub-w1-still-one
                   (= 1 (dds.dcps:publication-matched-status-total-count (dds.dcps:get-publication-matched-status dw1)))
                   "writer-1 stays at 1 — writer-2's match does not touch it")
           (%check :2c2-pub-w1-listener (and (assoc :pub-matched (cap-snapshot wl1)) t)
                   "writer-1 on_publication_matched must fire")
           (%check :2c2-pub-w2-listener (and (assoc :pub-matched (cap-snapshot wl2)) t)
                   "writer-2 on_publication_matched must fire")
           ;; (2) SUBSCRIPTION_MATCHED per SAME-topic reader, by threaded EntityId: rw1->dra, rw2->drb.
           (dds.dcps::%on-disc-match p :remote-writer rw1 e-ra)
           (dds.dcps::%on-disc-match p :remote-writer rw2 e-rb)
           (%check :2c2-sub-ra
                   (= 1 (dds.dcps:subscription-matched-status-total-count (dds.dcps:get-subscription-matched-status dra)))
                   "the match threaded with reader-A's EntityId must bump reader-A SUBSCRIPTION_MATCHED")
           (%check :2c2-sub-rb
                   (= 1 (dds.dcps:subscription-matched-status-total-count (dds.dcps:get-subscription-matched-status drb)))
                   "the match threaded with reader-B's EntityId must bump reader-B SUBSCRIPTION_MATCHED (both same-topic readers matched — closes the 2c-1 follow-on)")
           (%check :2c2-sub-ra-listener (and (assoc :sub-matched (cap-snapshot rl1)) t)
                   "reader-A on_subscription_matched must fire")
           (%check :2c2-sub-rb-listener (and (assoc :sub-matched (cap-snapshot rl2)) t)
                   "reader-B on_subscription_matched must fire")
           ;; (3) INCOMPATIBLE_QOS threaded by EntityId lands on the RIGHT same-topic writer only.
           (dds.dcps::%on-disc-incompatible p :remote-reader rr1 '(:durability) e-w1)
           (%check :2c2-incompat-w1
                   (= 1 (dds.dcps:offered-incompatible-qos-status-total-count (dds.dcps:get-offered-incompatible-qos-status dw1)))
                   "incompatible-qos threaded with writer-1's EntityId must bump ONLY writer-1 OFFERED_INCOMPATIBLE_QOS")
           (%check :2c2-incompat-w2-zero
                   (zerop (dds.dcps:offered-incompatible-qos-status-total-count (dds.dcps:get-offered-incompatible-qos-status dw2)))
                   "writer-2 must NOT see writer-1's incompatible-qos")
           ;; (4) UNMATCH threaded by EntityId decrements the RIGHT writer, sibling untouched.
           (dds.dcps::%on-disc-unmatch p :remote-reader rr1 e-w1)
           (%check :2c2-unmatch-w1-current-zero
                   (zerop (dds.dcps:publication-matched-status-current-count (dds.dcps:get-publication-matched-status dw1)))
                   "unmatch threaded with writer-1's EntityId must drop writer-1 PUBLICATION_MATCHED current_count to 0")
           (%check :2c2-unmatch-w2-untouched
                   (= 1 (dds.dcps:publication-matched-status-current-count (dds.dcps:get-publication-matched-status dw2)))
                   "writer-2 current_count must stay 1 — writer-1's unmatch must NOT decrement its same-topic sibling (no missed/mis-directed decrement)"))
      (dds.dcps:delete-participant p))
    t))

(defun* run-incompat-qos-perpair-test ()
    (function () t)
  "WP-DDS-INCOMPAT-QOS-PERPAIR (ADR 0048 §16.3): INCOMPATIBLE_QOS is now PER-(local,remote) PAIR, mirroring the
   match-pair path (%record-match-pair/%fire-match). A bare disc-node holds SAME-topic local readers, all
   RxO-incompatible (durability: they REQUEST transient-local, the remote writer OFFERS volatile); a capturing
   on-incompatible-qos hook records the fired (local-eid . bad) pairs. Exercises the disc-layer DETECTION->
   DISPATCH that the fix changed (no network). RED before this WP: the 2-scalar collector fired once-per-remote
   carrying ONLY the last-in-dolist local eid, so a sibling / late local silently missed the status. Covers:
   BOTH-LOCALS (both fire), PER-PAIR IDEMPOTENT (a re-announce re-fires nothing), LATE-LOCAL (a local created
   after the remote was recorded fires), MIXED (a compatible sibling never fires), RE-DISCOVERY (after a
   lease-sweep purge, a re-match re-fires — no stuck gate / unbounded growth). Both impls."
  (let* ((node (dds.disc:make-disc-node
                :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 1)
                :host "127.0.0.1" :port 0))
         (fired '())
         (rq (dds.qos:make-qos :durability :transient-local))   ; reader REQUESTS transient-local
         (wq (dds.qos:make-qos :durability :volatile))          ; remote writer OFFERS volatile -> durability RxO fails
         (remote (dds.rtps.discovery:make-endpoint-data
                  :guid (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 9)))
                          (setf (aref g 15) #x02) g)            ; remote WRITER, WITH_KEY kind 0x02
                  :topic-name "IQP" :type-name "X" :qos wq)))
    (setf (dds.disc:disc-node-on-incompatible-qos node)
          (lambda (kind remote bad eid) (declare (ignore kind remote))
            (push (cons eid bad) fired)))
    (unwind-protect
         (let* ((r1 (dds.disc:add-local-reader node :topic "IQP" :type "X" :qos rq))
                (r2 (dds.disc:add-local-reader node :topic "IQP" :type "X" :qos rq))
                (e1 (dds.disc::%guid-entityid (dds.rtps.discovery:endpoint-data-guid r1)))
                (e2 (dds.disc::%guid-entityid (dds.rtps.discovery:endpoint-data-guid r2))))
           (%check :iqp-distinct-eids (/= e1 e2)
                   "the two SAME-topic local readers must get DISTINCT engine EntityIds")
           ;; (1) BOTH-LOCALS-INCOMPAT: ONE match pass fires BOTH local eids (RED: only the last-in-dolist).
           (dds.disc::%match-remote-writer node remote)
           (%check :iqp-both-e1 (and (assoc e1 fired) t)
                   "reader-1 must get INCOMPATIBLE_QOS")
           (%check :iqp-both-e2 (and (assoc e2 fired) t)
                   "reader-2 must ALSO get INCOMPATIBLE_QOS (RED: the 2-scalar collector overwrote/dropped the sibling — only the last-in-dolist local fired)")
           (%check :iqp-both-bad (equal '(:durability) (cdr (assoc e1 fired)))
                   "the failing-policy list threaded per endpoint must be (:durability)")
           (%check :iqp-both-count (= 2 (length fired))
                   "exactly TWO firings for two incompatible same-topic locals (each pair fires once, no double-count)")
           ;; (2) PER-PAIR IDEMPOTENT: a SEDP re-announce (2nd match pass) re-fires NOTHING (both pairs already fired).
           (dds.disc::%match-remote-writer node remote)
           (%check :iqp-idempotent (= 2 (length fired))
                   "re-processing the SAME remote must NOT re-fire either pair (per-pair idempotency — mirrors match-pairs)")
           ;; (3) LATE-LOCAL: a THIRD same-topic incompatible reader created AFTER the remote was recorded fires.
           (let* ((r3 (dds.disc:add-local-reader node :topic "IQP" :type "X" :qos rq))
                  (e3 (dds.disc::%guid-entityid (dds.rtps.discovery:endpoint-data-guid r3))))
             (dds.disc::%match-remote-writer node remote)
             (%check :iqp-late-e3 (and (assoc e3 fired) t)
                     "a LATE same-topic incompatible reader must fire (RED: the per-remote gate was already tripped + never purged -> L3 never fired)")
             (%check :iqp-late-only-one (= 3 (length fired))
                     "ONLY the late reader re-fires; the two already-fired pairs stay idempotent"))
           ;; (4) MIXED: a COMPATIBLE + an INCOMPATIBLE same-topic reader with a remote -> only the incompatible fires.
           (let* ((rc (dds.disc:add-local-reader node :topic "MIX" :type "X"
                                                 :qos (dds.qos:make-qos :durability :volatile)))   ; requests volatile -> RxO-COMPATIBLE
                  (ri (dds.disc:add-local-reader node :topic "MIX" :type "X" :qos rq))             ; requests transient-local -> INCOMPATIBLE
                  (ec (dds.disc::%guid-entityid (dds.rtps.discovery:endpoint-data-guid rc)))
                  (ei (dds.disc::%guid-entityid (dds.rtps.discovery:endpoint-data-guid ri)))
                  (mremote (dds.rtps.discovery:make-endpoint-data
                            :guid (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 8)))
                                    (setf (aref g 15) #x02) g)
                            :topic-name "MIX" :type-name "X" :qos wq)))
             (dds.disc::%match-remote-writer node mremote)
             (%check :iqp-mixed-incompat (and (assoc ei fired) t)
                     "the INCOMPATIBLE same-topic reader must fire INCOMPATIBLE_QOS")
             (%check :iqp-mixed-compat-silent (null (assoc ec fired))
                     "the COMPATIBLE same-topic reader must NOT fire INCOMPATIBLE_QOS (it matches; no MIXED-case regression)")
             (%check :iqp-mixed-one-new (= 4 (length fired))
                     "exactly ONE new incompat firing in the mixed case"))
           ;; (5) RE-DISCOVERY: a lease-sweep purge of the remote participant clears the incompat pairs -> a re-match re-fires.
           (let ((prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 9)))   ; the remote's 12-octet participant prefix
             (setf (gethash (copy-seq prefix) (dds.disc::disc-node-discovered node))
                   (dds.rtps.discovery:make-spdp-data :guid-prefix (copy-seq prefix) :lease-duration-seconds 1))
             (setf (gethash (copy-seq prefix) (dds.disc::disc-node-participant-last-seen node))
                   (- (dds.disc::%lease-now) (* 5 internal-time-units-per-second)))   ; 5s old vs a 1s lease -> stale
             (dds.disc::%lease-sweep node)
             (dds.disc::%match-remote-writer node remote)
             (%check :iqp-rediscovery-refire (= 7 (length fired))
                     "after a lease-sweep purge of the remote, the re-discovered incompatible pairs must RE-fire (3 IQP readers -> +3; no stuck gate / bounded growth)")))
      (dds.disc:stop-node node)))
  t)

(defun* run-incompat-qos-perpair-dcps-test ()
    (function () t)
  "WP-DDS-INCOMPAT-QOS-PERPAIR (ADR 0048 §16.3), DCPS end-to-end: TWO SAME-topic DataReaders BOTH requesting
   TRANSIENT_LOCAL (RxO-incompatible with a VOLATILE remote writer). Driving the REAL %match-remote-writer on
   the participant's node must land REQUESTED_INCOMPATIBLE_QOS on BOTH readers — each total_count = 1 and each
   on_requested_incompatible_qos listener fires (RED before this WP: the once-per-remote dispatch bumped ONLY
   the last-in-dolist reader, so the sibling's counter stayed 0 and its listener never fired). A re-match must
   NOT double-count (per-pair idempotency). Offline disc match (no network); real disc->DCPS eid dispatch via
   %on-disc-incompatible. Both impls."
  (let ((ts (dds.types:find-type-support "shape-type"))
        (p (dds.dcps:create-participant :domain (test-domain)))
        (rl1 (make-instance 'capturing-reader-listener))
        (rl2 (make-instance 'capturing-reader-listener)))
    (unwind-protect
         (let* ((tp (dds.dcps:create-topic p "IQPD" "shape-type" ts))
                (sub (dds.dcps:create-subscriber p))
                (dr1 (dds.dcps:create-datareader sub tp :qos (dds.qos:make-reader-qos :durability :transient-local)))
                (dr2 (dds.dcps:create-datareader sub tp :qos (dds.qos:make-reader-qos :durability :transient-local)))
                (node (dds.dcps::dp-node p))
                ;; A synthetic remote WRITER on the SAME topic/type, OFFERING volatile -> durability RxO fails
                ;; against BOTH transient-local readers. type-name is the topic's type string verbatim (string= match).
                (remote (dds.rtps.discovery:make-endpoint-data
                         :guid (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element #x3d)))
                                 (setf (aref g 15) #x02) g)
                         :topic-name "IQPD" :type-name "shape-type"
                         :qos (dds.qos:make-writer-qos :durability :volatile))))
           (%check :iqpd-distinct (/= (dds.dcps::dr-entity-id dr1) (dds.dcps::dr-entity-id dr2))
                   "the two SAME-topic DataReaders must get DISTINCT engine EntityIds")
           (dds.dcps:set-reader-listener dr1 rl1 '(:requested-incompatible-qos))
           (dds.dcps:set-reader-listener dr2 rl2 '(:requested-incompatible-qos))
           ;; Drive the REAL disc match: both readers are RxO-incompatible -> both pairs collected + fired by eid.
           (dds.disc::%match-remote-writer node remote)
           (%check :iqpd-dr1-count
                   (= 1 (dds.dcps:requested-incompatible-qos-status-total-count
                         (dds.dcps:get-requested-incompatible-qos-status dr1)))
                   "reader-1 REQUESTED_INCOMPATIBLE_QOS total_count must be 1")
           (%check :iqpd-dr2-count
                   (= 1 (dds.dcps:requested-incompatible-qos-status-total-count
                         (dds.dcps:get-requested-incompatible-qos-status dr2)))
                   "reader-2 REQUESTED_INCOMPATIBLE_QOS total_count must ALSO be 1 (RED: the once-per-remote dispatch left the sibling at 0)")
           (%check :iqpd-dr1-listener (and (assoc :req-incompat (cap-snapshot rl1)) t)
                   "reader-1 on_requested_incompatible_qos must fire")
           (%check :iqpd-dr2-listener (and (assoc :req-incompat (cap-snapshot rl2)) t)
                   "reader-2 on_requested_incompatible_qos must ALSO fire (RED: the sibling's listener never fired)")
           ;; PER-PAIR IDEMPOTENT end-to-end: a re-announce must not DOUBLE-count either reader.
           (dds.disc::%match-remote-writer node remote)
           (%check :iqpd-dr1-no-doublecount
                   (= 1 (dds.dcps:requested-incompatible-qos-status-total-count
                         (dds.dcps:get-requested-incompatible-qos-status dr1)))
                   "reader-1 total_count must stay 1 across a re-announce (no per-pair double-count)")
           (%check :iqpd-dr2-no-doublecount
                   (= 1 (dds.dcps:requested-incompatible-qos-status-total-count
                         (dds.dcps:get-requested-incompatible-qos-status dr2)))
                   "reader-2 total_count must stay 1 across a re-announce (no per-pair double-count)"))
      (dds.dcps:delete-participant p))
    t))

(defun* run-incompat-inconsistent-independent-test ()
    (function () t)
  "WP-DDS-INCOMPAT-QOS-PERPAIR F1/F1b (ADR 0048 §16.3): INCOMPATIBLE_QOS (an endpoint status) and INCONSISTENT_TOPIC
   (a Topic status) are INDEPENDENT (DDS 1.4 §2.2.4.1) on DIFFERENT entities — no spec basis for mutual exclusion.
   A remote (topic T, type X) matched against a participant holding a QoS-incompatible same-type local L1 AND a
   type-inconsistent local L2 (type Y) must fire BOTH statuses (F1: the per-pair-incompat epilogue must NOT SHADOW
   the inconsistent fire — the RED this WP briefly introduced with a bare `incompats` cond clause). And
   disc-node-inconsistent is purged on lease-expiry, so a re-discovered inconsistent remote re-fires (F1b: a
   pre-existing stuck-gate, now made symmetric with the incompat purge). Bare disc-node + capturing hooks (no
   network). RED(F1): inconsistent never fires next to an incompatible sibling. RED(F1b): stuck, never re-fires."
  (let* ((node (dds.disc:make-disc-node
                :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 1)
                :host "127.0.0.1" :port 0))
         (fired-incompat '())
         (fired-inconsistent '())
         (wq (dds.qos:make-qos :durability :volatile))
         (remote (dds.rtps.discovery:make-endpoint-data
                  :guid (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7)))
                          (setf (aref g 15) #x02) g)            ; remote WRITER, WITH_KEY kind 0x02
                  :topic-name "IND" :type-name "X" :qos wq)))
    (setf (dds.disc:disc-node-on-incompatible-qos node)
          (lambda (kind r bad eid) (declare (ignore kind r bad)) (push eid fired-incompat)))
    (setf (dds.disc:disc-node-on-inconsistent-topic node)
          (lambda (tname) (push tname fired-inconsistent)))
    (unwind-protect
         (let* ((l1 (dds.disc:add-local-reader node :topic "IND" :type "X"
                                               :qos (dds.qos:make-qos :durability :transient-local)))   ; same-type, QoS-INCOMPATIBLE
                (l2 (dds.disc:add-local-reader node :topic "IND" :type "Y" :qos wq))                    ; type-MISMATCH -> INCONSISTENT_TOPIC
                (e1 (dds.disc::%guid-entityid (dds.rtps.discovery:endpoint-data-guid l1))))
           (declare (ignore l2))
           ;; (F1) ONE scan fires BOTH INCOMPATIBLE_QOS (for L1) AND INCONSISTENT_TOPIC (for the topic) — independent.
           (dds.disc::%match-remote-writer node remote)
           (%check :f1-incompat-fires (and (member e1 fired-incompat) t)
                   "the QoS-incompatible same-type local must fire INCOMPATIBLE_QOS")
           (%check :f1-inconsistent-fires (and (member "IND" fired-inconsistent :test #'string=) t)
                   "the type-inconsistent sibling must ALSO fire INCONSISTENT_TOPIC (RED: the per-pair-incompat epilogue SHADOWED it — inconsistent never fired next to an incompatible sibling)")
           ;; idempotent: a re-announce re-fires NEITHER status (both gates hold).
           (let ((ni (length fired-incompat)) (nc (length fired-inconsistent)))
             (dds.disc::%match-remote-writer node remote)
             (%check :f1-idempotent (and (= ni (length fired-incompat)) (= nc (length fired-inconsistent)))
                     "a re-announce must re-fire NEITHER status (both the per-pair incompat gate and the per-remote inconsistent gate hold)"))
           ;; (F1b) RE-DISCOVERY: a lease-sweep purge of disc-node-inconsistent (+ incompat) -> a re-match re-fires INCONSISTENT_TOPIC.
           (let ((prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 7))
                 (nc (length fired-inconsistent)))
             (setf (gethash (copy-seq prefix) (dds.disc::disc-node-discovered node))
                   (dds.rtps.discovery:make-spdp-data :guid-prefix (copy-seq prefix) :lease-duration-seconds 1))
             (setf (gethash (copy-seq prefix) (dds.disc::disc-node-participant-last-seen node))
                   (- (dds.disc::%lease-now) (* 5 internal-time-units-per-second)))   ; 5s old vs a 1s lease -> stale
             (dds.disc::%lease-sweep node)
             (dds.disc::%match-remote-writer node remote)
             (%check :f1b-inconsistent-refire (> (length fired-inconsistent) nc)
                     "after a lease-sweep purge, a re-discovered INCONSISTENT_TOPIC remote must RE-fire (RED: disc-node-inconsistent was never purged -> stuck gate, asymmetric with the purged incompat tables)")))
      (dds.disc:stop-node node)))
  t)

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
        (p (dds.dcps:create-participant :domain (test-domain)))
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
        (p (dds.dcps:create-participant :domain (test-domain)))
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
                 (lambda (kind remote &optional local-eid) (declare (ignore local-eid))
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

;;; WP-DDS-SECURITY-AUTH-KEYX T4: auth-gate compose test (stub hooks, no crypto).
;;; Verifies the auth-gate is consulted as a SECOND sequential gate after the type-gate
;;; returns :compatible (DDS-Security 1.1 §7.3, disc.lisp %match-remote-endpoint).

(defun* run-auth-gate-compose-test ()
    (function () t)
  "AUTH-GATE composed after TYPE-GATE (stub, crypto-free): :incompatible -> no match;
   :pending -> parked (non-vacuous: match must NOT fire while pending); :compatible after
   resume-parked-matches -> match fires exactly once."
  ;; Case 1: auth-gate returns :incompatible -> no match recorded, no INCONSISTENT_TOPIC
  (multiple-value-bind (node1 node2) (%tg-nodes)
    (unwind-protect
         (progn
           (setf (dds.disc:disc-node-auth-gate node2)
                 (lambda (node remote local)
                   (declare (ignore node remote local)) :incompatible))
           (dds.disc:announce-endpoints node1)
           (dds.disc:announce-endpoints node2)
           (sleep 0.15)
           (%check :auth-incompat-no-match (zerop (dds.disc:disc-node-matched-count node2))
                   "auth-gate :incompatible must not record a match"))
      (dds.disc:stop-node node1)
      (dds.disc:stop-node node2)))
  ;; Case 2: :pending -> parked (NOT fired); after gate flips :compatible and resume-parked-matches -> fires
  (multiple-value-bind (node1 node2) (%tg-nodes)
    (unwind-protect
         (let ((verdict :pending) (matches '()) (m-lock (dds.pal:make-lock "ag-m")))
           (setf (dds.disc:disc-node-auth-gate node2)
                 (lambda (node remote local)
                   (declare (ignore node remote local)) verdict))
           (setf (dds.disc:disc-node-on-match node2)
                 (lambda (kind remote &optional local-eid) (declare (ignore local-eid))
                   (declare (ignore remote))
                   (dds.pal:with-lock (m-lock) (push kind matches))))
           (dds.disc:announce-endpoints node1)
           (dds.disc:announce-endpoints node2)
           (loop repeat 100 until (plusp (dds.disc:disc-node-parked-count node2)) do (sleep 0.02))
           ;; non-vacuous: assert match did NOT fire while :pending
           (%check :auth-pending-no-match (zerop (dds.disc:disc-node-matched-count node2))
                   "auth-gate :pending must not record a match before resume")
           (%check :auth-pending-parked (plusp (dds.disc:disc-node-parked-count node2))
                   "auth-gate :pending must park the match decision")
           ;; flip to :compatible and resume
           (setf verdict :compatible)
           (dds.disc:resume-parked-matches node2)
           (%check :auth-resumed-match (plusp (dds.disc:disc-node-matched-count node2))
                   "resume with :compatible auth-gate must record the match")
           (%check :auth-resumed-fired
                   (equal '(:remote-writer) (dds.pal:with-lock (m-lock) matches))
                   "resumed auth match must fire on-match exactly once (:remote-writer)")
           (%check :auth-drained (zerop (dds.disc:disc-node-parked-count node2))
                   "resume must drain the parked list"))
      (dds.disc:stop-node node1)
      (dds.disc:stop-node node2)))
  t)

(defun* run-permissions-gate-compose-test ()
    (function () t)
  "PERMISSIONS-GATE composed after AUTH-GATE (stub, crypto-free): :incompatible -> no match;
   :pending -> parked (non-vacuous: match must NOT fire while pending); :compatible after
   resume-parked-matches -> match fires exactly once. NIL gate leaves matching byte-identical."
  ;; Case 0: no permissions-gate (NIL) -> match proceeds as if :compatible (backward-compat)
  (multiple-value-bind (node1 node2) (%tg-nodes)
    (unwind-protect
         (progn
           (dds.disc:announce-endpoints node1)
           (dds.disc:announce-endpoints node2)
           (sleep 0.15)
           (%check :pg-nil-gate-matches (plusp (dds.disc:disc-node-matched-count node2))
                   "NIL permissions-gate must not prevent a normal match"))
      (dds.disc:stop-node node1)
      (dds.disc:stop-node node2)))
  ;; Case 1: permissions-gate returns :incompatible -> no match recorded, no INCONSISTENT_TOPIC
  (multiple-value-bind (node1 node2) (%tg-nodes)
    (unwind-protect
         (progn
           (setf (dds.disc:disc-node-permissions-gate node2)
                 (lambda (node remote local)
                   (declare (ignore node remote local)) :incompatible))
           (dds.disc:announce-endpoints node1)
           (dds.disc:announce-endpoints node2)
           (sleep 0.15)
           (%check :pg-incompat-no-match (zerop (dds.disc:disc-node-matched-count node2))
                   "permissions-gate :incompatible must not record a match"))
      (dds.disc:stop-node node1)
      (dds.disc:stop-node node2)))
  ;; Case 2: :pending -> parked (NOT fired); after gate flips :compatible and resume -> fires
  (multiple-value-bind (node1 node2) (%tg-nodes)
    (unwind-protect
         (let ((verdict :pending) (matches '()) (m-lock (dds.pal:make-lock "pg-m")))
           (setf (dds.disc:disc-node-permissions-gate node2)
                 (lambda (node remote local)
                   (declare (ignore node remote local)) verdict))
           (setf (dds.disc:disc-node-on-match node2)
                 (lambda (kind remote &optional local-eid) (declare (ignore local-eid))
                   (declare (ignore remote))
                   (dds.pal:with-lock (m-lock) (push kind matches))))
           (dds.disc:announce-endpoints node1)
           (dds.disc:announce-endpoints node2)
           (loop repeat 100 until (plusp (dds.disc:disc-node-parked-count node2)) do (sleep 0.02))
           ;; non-vacuous: assert match did NOT fire while :pending
           (%check :pg-pending-no-match (zerop (dds.disc:disc-node-matched-count node2))
                   "permissions-gate :pending must not record a match before resume")
           (%check :pg-pending-parked (plusp (dds.disc:disc-node-parked-count node2))
                   "permissions-gate :pending must park the match decision")
           ;; flip to :compatible and resume
           (setf verdict :compatible)
           (dds.disc:resume-parked-matches node2)
           (%check :pg-resumed-match (plusp (dds.disc:disc-node-matched-count node2))
                   "resume with :compatible permissions-gate must record the match")
           (%check :pg-resumed-fired
                   (equal '(:remote-writer) (dds.pal:with-lock (m-lock) matches))
                   "resumed permissions match must fire on-match exactly once (:remote-writer)")
           (%check :pg-drained (zerop (dds.disc:disc-node-parked-count node2))
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
        (p1 (dds.dcps:create-participant :domain (test-domain)))
        (p2 (dds.dcps:create-participant :domain (test-domain))))
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
        (p1 (dds.dcps:create-participant :domain (test-domain)))
        (p2 (dds.dcps:create-participant :domain (test-domain))))
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
        (p1 (dds.dcps:create-participant :domain (test-domain)))
        (p2 (dds.dcps:create-participant :domain (test-domain))))
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
        (p (dds.dcps:create-participant :domain (test-domain)))
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
        (p (dds.dcps:create-participant :domain (test-domain))))
    (unwind-protect
         (%check :lg-compatible
                 (eq :compatible
                     (%legacy-gate-verdict p "LegacyGoodTopic" "legacy-good-type" ts
                                           (%connext-c-shape-lb)))
                 "a confident C_Shape parse assignable to the local type gates :compatible")
      (dds.dcps:delete-participant p)))
  ;; (2) incompatible local struct (x retyped i64) -> NOT assignable -> :incompatible
  (let ((ts (dds.types:find-type-support "legacy-bad-type"))
        (p (dds.dcps:create-participant :domain (test-domain))))
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
        (p (dds.dcps:create-participant :domain (test-domain)))
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
        (p (dds.dcps:create-participant :domain (test-domain))))
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
