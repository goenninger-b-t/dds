;;;; L5/L6 bridge — user data plane over UDP (FR-RTPS-*, FR-DDS-*). Wires the
;;;; value-level reliable writer/reader state machines (dds.rtps.reliable) to the
;;;; UDP transport: a publisher serializes a sample into a DATA submessage and
;;;; sends it plus a HEARTBEAT to its peers; the subscriber stores the DATA and
;;;; answers the HEARTBEAT with an ACKNACK; the publisher retransmits any NACKed
;;;; change. For v1 the user/metatraffic share one socket (routing is by
;;;; EntityId), peers double as the data destination, and the SerializedPayload is
;;;; opaque bytes (a generated-type codec is the follow-up). The reliable handshake
;;;; runs in the receiver thread, so its sends use the node's separate rx-tx-msg
;;;; buffer (publish runs on the caller thread and uses tx-msg) — no shared buffer
;;;; across threads. This file is NOT a measured hot path (per-sample heap copies
;;;; here are a documented v1 concern; the gated hot-path files are untouched).

(in-package #:dds.disc)

;; User-defined EntityIds: entityKey[3] << 8 | entityKind (RTPS 2.5 §9.3.1.2).
;; ShapeType is keyed (color), so the endpoints are WITH-KEY kinds (0x02 / 0x07) —
;; a no-key writer on a keyed topic is what RTI is fed otherwise.
(defconstant +user-writer-id+ #x00000102)   ; key 000001, kind 02 (user writer WITH key)
(defconstant +user-reader-id+ #x00000107)   ; key 000001, kind 07 (user reader WITH key)
;; These MUST equal the EntityIds that add-local-writer/add-local-reader announce via
;; SEDP (key 1, kinds 0x02/0x07): a peer matches the announced endpoint and routes its
;; HEARTBEAT/ACKNACK by that EntityId, so the data-plane endpoint must carry the same id.

(defun* %send-msg-buf (node buf build-fn host port)
    (function (disc-node dds.core.buffer:octet-buffer function string (unsigned-byte 16)) t)
  "Build an RTPS message (Header + whatever BUILD-FN writes on the cursor) into BUF
   and send it to HOST:PORT. BUF selects the thread's scratch message buffer."
  (let ((mc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
    (funcall build-fn mc)
    (dds.xport:send (disc-node-transport node)
                    (dds.xport.udp:make-udp-locator :host host :port port)
                    buf 0 (dds.core.buffer:cursor-position mc))))

(defun* %usable-destination (p)
    (function (dds.rtps.discovery:spdp-data) t)
  "A sendable (host . port) for user traffic to participant P, selected from its
   advertised locator LISTS: a routable UDPv4 default-unicast locator (host+port
   from that locator); else — if every default-unicast locator is non-routable — a
   routable metatraffic ADDRESS paired with a default-unicast PORT (same host, user
   port). NIL if none is usable. Foreign stacks (RTI) advertise several locators
   including 0.0.0.0 placeholders; this picks one that can actually be reached."
  (let* ((dlocs (dds.rtps.discovery:spdp-data-default-unicast-locators p))
         (mlocs (dds.rtps.discovery:spdp-data-metatraffic-unicast-locators p))
         (d (dds.rtps.discovery:usable-udpv4-locator dlocs))
         (m (dds.rtps.discovery:usable-udpv4-locator mlocs)))
    (cond
      (d (cons (dds.rtps.discovery:locator-ipv4-string d)
               (%locator-port (dds.rtps.discovery:locator-port d))))
      ((and m dlocs)
       (cons (dds.rtps.discovery:locator-ipv4-string m)
             (%locator-port (dds.rtps.discovery:locator-port (first dlocs)))))
      (t nil))))

(defun* %reader-guid-p (guid)
    (function ((simple-array (unsigned-byte 8) (16))) t)
  "T iff the GUID's entity kind is a user reader (0x04 no-key / 0x07 with-key)."
  (let ((k (aref guid 15))) (or (= k #x04) (= k #x07))))

(defun* %writer-guid-p (guid)
    (function ((simple-array (unsigned-byte 8) (16))) t)
  "T iff the GUID's entity kind is a user writer (0x02 with-key / 0x03 no-key)."
  (let ((k (aref guid 15))) (or (= k #x02) (= k #x03))))

(defun* %endpoint-keyed-p (guid)
    (function ((simple-array (unsigned-byte 8) (16))) t)
  "T iff the endpoint GUID's entity kind is a WITH_KEY user endpoint: writer 0x02 or
   reader 0x07 (vs NO_KEY writer 0x03 / reader 0x04) — RTPS 2.5 §9.3.1.2 Table 9.1."
  (let ((k (aref guid 15))) (or (= k #x02) (= k #x07))))

(defun* %user-writer-entityid-p (entity-id)
    (function ((unsigned-byte 32)) t)
  "T iff ENTITY-ID's kind is an application-defined writer (0x02 with-key / 0x03 no-key) —
   a user-data writer, not a builtin (kind 0xc2). Lets the reader ACKNACK ANY matched
   remote writer's HEARTBEAT, not only a writer sharing this stack's local EntityId
   convention (a peer such as RTI Connext picks its own writer EntityIds)."
  (let ((k (logand entity-id #xff))) (or (= k #x02) (= k #x03))))

(defun* %matched-endpoints (node)
    (function (disc-node) list)
  "Snapshot of the remote endpoints matched to one of NODE's local endpoints."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for v being the hash-values of (disc-node-matches node) collect v)))

(defun* %match-destinations (node want-readers)
    (function (disc-node t) list)
  "User-traffic (host . port) destinations gated on MATCHING: the union of static
   PEERS and the participants holding a matched remote endpoint of the wanted kind —
   readers (WANT-READERS t) for a writer's DATA/HEARTBEAT, writers (nil) for a
   reader's ACKNACK. RxO-incompatible / topic-mismatched peers never match, so they
   receive nothing (FR-QOS-2: RxO now blocks delivery, not just the match)."
  (let ((dests (copy-list (disc-node-peers node)))
        (parts (%discovered-participants node)))
    (dolist (remote (%matched-endpoints node) dests)
      (let ((guid (dds.rtps.discovery:endpoint-data-guid remote)))
        (when (if want-readers (%reader-guid-p guid) (%writer-guid-p guid))
          (let ((spdp (find (subseq guid 0 12) parts
                            :key #'dds.rtps.discovery:spdp-data-guid-prefix :test #'equalp)))
            (when spdp
              (let ((hp (%usable-destination spdp)))
                (when (and hp (plusp (cdr hp)))
                  (pushnew hp dests :test #'equal))))))))))

(defparameter *debug-drop-fragment-numbers* nil
  "Debug-only fragment-loss injection (default NIL = off): a list of 1-based fragment
   numbers that %SEND-SAMPLE silently SKIPS when fragmenting a sample into DATA_FRAGs
   (both the initial push and sample-level ACKNACK retransmits). NACK_FRAG-driven
   resends (%ON-USER-NACK-FRAG) are NOT filtered, so the only recovery path for a
   dropped fragment is the peer's NACK_FRAG — proving fragment-level reliability
   against a live peer (RTPS 2.5 §8.3.8.12 NackFrag). Never set in production.")

(defun* %send-sample (node buf sn pl host port)
    (function (disc-node dds.core.buffer:octet-buffer integer (simple-array (unsigned-byte 8) (*)) string (unsigned-byte 16)) t)
  "Send sample (SN, PL) to HOST:PORT: one DATA submessage if PL fits *fragment-size*, else a
   series of DATA_FRAG submessages (packing as many fragments as fit the datagram) followed by
   a HEARTBEAT_FRAG. Uses BUF (tx-msg or rx-tx-msg) as the scratch message buffer. A submessage
   containing a fragment named in *DEBUG-DROP-FRAGMENT-NUMBERS* is skipped (loss injection)."
  (let ((size (length pl)))
    (if (<= size dds.rtps.reliable:*fragment-size*)
        (%send-msg-buf node buf
                       (lambda (mc) (dds.rtps.message:write-data
                                     mc dds.rtps.message:+entityid-unknown+ (disc-node-user-writer-id node) sn pl 0 size))
                       host port)
        (let ((budget (- (dds.core.buffer:octet-buffer-capacity buf) 64)))
          (dolist (desc (dds.rtps.reliable:writer-frag-plan size dds.rtps.reliable:*fragment-size* budget))
            (destructuring-bind (fstart fcount off len) desc
              (unless (and *debug-drop-fragment-numbers*
                           (loop for f from fstart below (+ fstart fcount)
                                   thereis (member f *debug-drop-fragment-numbers*)))
                (%send-msg-buf node buf
                               (lambda (mc) (dds.rtps.message:write-data-frag
                                             mc dds.rtps.message:+entityid-unknown+ (disc-node-user-writer-id node) sn size
                                             fstart fcount dds.rtps.reliable:*fragment-size* pl off len))
                               host port))))
          (multiple-value-bind (lastfrag cnt)
              (dds.rtps.reliable:writer-frag-heartbeat (disc-node-user-writer node) sn)
            (when lastfrag
              (%send-msg-buf node buf
                             (lambda (mc) (dds.rtps.message:write-heartbeat-frag
                                           mc dds.rtps.message:+entityid-unknown+ (disc-node-user-writer-id node) sn lastfrag cnt))
                             host port)))))))

(defun* %push-data (node)
    (function (disc-node) t)
  "Writer side: send every change not yet acked by the reader as a DATA (or DATA_FRAG series
   for large samples) submessage, followed by a HEARTBEAT, to each peer (caller thread; uses tx-msg)."
  (let ((writer (disc-node-user-writer node)))
    (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat writer)
      (let ((datas (dds.rtps.reliable:writer-data-list writer (disc-node-user-reader-id node))))
        (dolist (peer (%match-destinations node t))   ; DATA + HEARTBEAT -> matched readers
          (dolist (d datas)
            (%send-sample node (disc-node-tx-msg node) (car d) (cdr d) (car peer) (cdr peer)))
          (%send-msg-buf node (disc-node-tx-msg node)
                         (lambda (mc)
                           (dds.rtps.message:write-heartbeat
                            mc dds.rtps.message:+entityid-unknown+ (disc-node-user-writer-id node) first last count :final nil))
                         (car peer) (cdr peer)))))))

(defun* publish-sample (node payload)
    (function (disc-node (simple-array (unsigned-byte 8) (*))) (eql t))
  "Publish PAYLOAD (an opaque SerializedPayload) on the node's user writer: add it
   to the writer HistoryCache, then push DATA + HEARTBEAT to peers (FR-RTPS-8)."
  (dds.rtps.reliable:writer-write (disc-node-user-writer node) payload)
  (%push-data node)
  t)

(defun* %deliver-user-sample (node writer-id sn vec)
    (function (disc-node (unsigned-byte 32) integer (simple-array (unsigned-byte 8) (*))) t)
  "Feed a complete user sample VEC (SN from WRITER-ID) to the reliable reader, record it by SN,
   then fire ON-SAMPLE outside the node lock (DATA_AVAILABLE + WaitSet wake)."
  (dds.rtps.reliable:reader-on-data (disc-node-user-reader node) writer-id sn vec)
  (dds.pal:with-lock ((disc-node-lock node)) (setf (gethash sn (disc-node-samples node)) vec))
  (when (disc-node-on-sample node) (funcall (disc-node-on-sample node)))
  t)

(defun* %on-user-data (node writer-id sn buf poff plen)
    (function (disc-node (unsigned-byte 32) integer dds.core.buffer:octet-buffer (integer 0) (integer 0)) t)
  "Reader side: copy the [poff,plen) SerializedPayload out of the receive buffer and deliver it
   (dedup/reorder, store by SN, fire ON-SAMPLE outside the node lock — no lock-order inversion)."
  (let ((vec (make-array plen :element-type '(unsigned-byte 8))))
    (replace vec (dds.core.buffer:octet-buffer-vec buf) :start2 poff :end2 (+ poff plen))
    (%deliver-user-sample node writer-id sn vec)))

(defun* %on-user-heartbeat (node c flags)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8)) t)
  "Reader side: apply the HEARTBEAT's available range, then answer with an ACKNACK
   (acking received SNs, NACKing the rest) to each peer (uses rx-tx-msg)."
  (multiple-value-bind (rid wid first last count finalp livep)
      (dds.rtps.message:parse-heartbeat-body c flags)
    (declare (ignore rid count finalp livep))
    (when (and (disc-node-user-reader node) (%user-writer-entityid-p wid))
      (let ((reader (disc-node-user-reader node)))
        (dds.rtps.reliable:reader-on-heartbeat reader wid first last)
        (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wid)
          (let ((cnt (incf (disc-node-ack-count node))))
            (dolist (peer (%match-destinations node nil))   ; ACKNACK -> matched writers
              (%send-msg-buf node (disc-node-rx-tx-msg node)
                             (lambda (mc)
                               ;; writerEntityId = the REMOTE writer's id (WID), so the peer
                               ;; routes the ACKNACK to its writer (not our local convention).
                               (dds.rtps.message:write-acknack
                                mc (disc-node-user-reader-id node) wid base numbits bitmap cnt :final t))
                             (car peer) (cdr peer))))))))
  t)

(defun* %on-user-acknack (node c flags)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8)) t)
  "Writer side: on an ACKNACK, retransmit each NACKed change as a DATA submessage
   to each peer (uses rx-tx-msg). GAPs are not needed (KEEP_ALL never drops)."
  (multiple-value-bind (rid wid base numbits bitmap count finalp)
      (dds.rtps.message:parse-acknack-body c flags)
    (declare (ignore rid count finalp))
    (when (= wid (disc-node-user-writer-id node))
      (incf (disc-node-acks-in node))   ; a matched reader (incl. RTI) acked our writer
      (multiple-value-bind (resends gaps)
          (dds.rtps.reliable:writer-on-acknack (disc-node-user-writer node)
                                               (disc-node-user-reader-id node) base numbits bitmap)
        (declare (ignore gaps))
        (dolist (peer (%match-destinations node t))   ; retransmit DATA(_FRAG) -> matched readers
          (dolist (d resends)
            (%send-sample node (disc-node-rx-tx-msg node) (car d) (cdr d) (car peer) (cdr peer)))))))
  t)

(defun* %on-user-data-frag (node c flags body-len buf)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8) (integer 0) dds.core.buffer:octet-buffer) t)
  "Reader side: accept a DATA_FRAG, reassemble; on the final fragment deliver the complete sample."
  (multiple-value-bind (rdr wtr sn ssize fstart frags fsize poff plen keyp)
      (dds.rtps.message:parse-data-frag-body c flags body-len)
    (declare (ignore rdr keyp))
    (when (and (disc-node-user-reader node) (%user-writer-entityid-p wtr))
      (let ((region (make-array plen :element-type '(unsigned-byte 8))))
        (replace region (dds.core.buffer:octet-buffer-vec buf) :start2 poff :end2 (+ poff plen))
        (let ((done (dds.rtps.reliable:reader-on-data-frag
                     (disc-node-user-reader node) wtr sn fstart frags fsize ssize region)))
          (when done (%deliver-user-sample node wtr sn done))))))
  t)

(defun* %on-user-heartbeat-frag (node c flags)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8)) t)
  "Reader side: on a HEARTBEAT_FRAG, NACK_FRAG the still-missing fragments to matched writers."
  (multiple-value-bind (rid wid sn lastfrag count) (dds.rtps.message:parse-heartbeat-frag-body c flags)
    (declare (ignore rid lastfrag count))
    (when (and (disc-node-user-reader node) (%user-writer-entityid-p wid))
      (multiple-value-bind (base numbits bitmap)
          (dds.rtps.reliable:reader-frag-acknack (disc-node-user-reader node) wid sn)
        (when base
          (let ((cnt (incf (disc-node-ack-count node))))
            (dolist (peer (%match-destinations node nil))
              (%send-msg-buf node (disc-node-rx-tx-msg node)
                             (lambda (mc) (dds.rtps.message:write-nack-frag
                                           mc (disc-node-user-reader-id node) wid sn base numbits bitmap cnt))
                             (car peer) (cdr peer))))))))
  t)

(defun* %on-user-nack-frag (node c flags)
    (function (disc-node dds.core.buffer:cursor (unsigned-byte 8)) t)
  "Writer side: on a NACK_FRAG, resend exactly the named fragments as DATA_FRAGs to matched readers."
  (multiple-value-bind (rid wid sn base numbits bitmap count) (dds.rtps.message:parse-nack-frag-body c flags)
    (declare (ignore rid count))
    (when (= wid (disc-node-user-writer-id node))
      (let ((descs (dds.rtps.reliable:writer-on-nack-frag (disc-node-user-writer node) sn base numbits bitmap))
            (pl (dds.rtps.reliable:writer-sample-payload (disc-node-user-writer node) sn)))
        (when (and descs pl)
          (let ((size (length pl)))
            (dolist (peer (%match-destinations node t))
              (dolist (desc descs)
                (destructuring-bind (fstart fcount off len) desc
                  (%send-msg-buf node (disc-node-rx-tx-msg node)
                                 (lambda (mc) (dds.rtps.message:write-data-frag
                                               mc dds.rtps.message:+entityid-unknown+ (disc-node-user-writer-id node) sn size
                                               fstart fcount dds.rtps.reliable:*fragment-size* pl off len))
                                 (car peer) (cdr peer)))))))))
    t))

(defun* enable-publisher (node)
    (function (disc-node) disc-node)
  "Give NODE a reliable user writer (KEEP_ALL) and install the writer-side data-
   plane hooks (retransmit on ACKNACK; resend named fragments on NACK_FRAG). Call after add-local-writer."
  (setf (disc-node-user-writer node)
        (dds.rtps.reliable:make-rtps-writer
         :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
  (setf (disc-node-on-acknack node) (lambda (c flags) (%on-user-acknack node c flags)))
  (setf (disc-node-on-nack-frag node) (lambda (c flags) (%on-user-nack-frag node c flags)))
  node)

(defun* enable-subscriber (node)
    (function (disc-node) disc-node)
  "Give NODE a reliable user reader and install the reader-side data-plane hooks (store DATA,
   ACKNACK on HEARTBEAT, reassemble DATA_FRAG, NACK_FRAG on HEARTBEAT_FRAG). Call after add-local-reader."
  (setf (disc-node-user-reader node) (dds.rtps.reliable:make-rtps-reader))
  (setf (disc-node-on-data node)
        (lambda (wid sn buf poff plen) (%on-user-data node wid sn buf poff plen)))
  (setf (disc-node-on-heartbeat node)
        (lambda (c flags) (%on-user-heartbeat node c flags)))
  (setf (disc-node-on-data-frag node)
        (lambda (c flags body-len buf) (%on-user-data-frag node c flags body-len buf)))
  (setf (disc-node-on-heartbeat-frag node)
        (lambda (c flags) (%on-user-heartbeat-frag node c flags)))
  node)

(defun* node-sample-count (node)
    (function (disc-node) (integer 0))
  "Number of distinct user samples the subscriber has received."
  (dds.pal:with-lock ((disc-node-lock node))
    (hash-table-count (disc-node-samples node))))

(defun* node-sample (node sn)
    (function (disc-node integer) t)
  "The received payload for sequence number SN, or NIL."
  (dds.pal:with-lock ((disc-node-lock node))
    (gethash sn (disc-node-samples node))))

(defun* node-sample-sns (node)
    (function (disc-node) list)
  "Sequence numbers of the user samples received so far (unordered). Lets a
   subscriber drain new samples without assuming SNs start at 1 (Connext may not)."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for k being the hash-keys of (disc-node-samples node) collect k)))

(defun* node-discovered-participants (node)
    (function (disc-node) list)
  "Snapshot of the SPDP data for every participant NODE has discovered (diagnostic)."
  (%discovered-participants node))

(defun* resolved-destination (p)
    (function (dds.rtps.discovery:spdp-data) t)
  "The (host . port) this stack would send user data to for participant P (its
   resolved routable locator), or NIL — exactly what the data plane uses. Diagnostic."
  (%usable-destination p))

(defun* node-acks-in (node)
    (function (disc-node) integer)
  "Count of ACKNACKs received for this node's user writer — i.e. how many times a
   matched reader (incl. a foreign one like RTI) acknowledged our data. >0 proves a
   remote reliable reader is actually receiving our samples. Diagnostic."
  (disc-node-acks-in node))

(defun* run-dataplane-test ()
    (function () (eql t))
  "Full stack over UDP: two participants discover (SPDP) and match (SEDP), then the
   publisher sends a user sample the subscriber receives reliably (DATA + HEARTBEAT
   -> ACKNACK). Asserts the exact payload bytes arrive within a bounded wait. The
   reliable protocol makes this robust to UDP reorder/loss (FR-RTPS-8)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (payload (make-array 8 :element-type '(unsigned-byte 8)
                              :initial-contents '(#xDE #xAD #xBE #xEF #x01 #x02 #x03 #x04))))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-publisher node1)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-subscriber node2)
           (setf (disc-node-peers node1) (list (cons "127.0.0.1" (disc-node-port node2))))
           (setf (disc-node-peers node2) (list (cons "127.0.0.1" (disc-node-port node1))))
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node1))
                            (plusp (disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (and (plusp (disc-node-matched-count node1))
                        (plusp (disc-node-matched-count node2)))
                   () "endpoints did not match before publish")
           (publish-sample node1 payload)
           (loop repeat 150 until (plusp (node-sample-count node2)) do (sleep 0.02))
           (assert (plusp (node-sample-count node2)) ()
                   "subscriber never received the sample over UDP")
           (assert (equalp (node-sample node2 1) payload) ()
                   "subscriber received the wrong payload bytes")
           t)
      (stop-node node1)
      (stop-node node2))))

(defun* run-large-dataplane-test ()
    (function () (eql t))
  "Full stack over UDP with a sample LARGER than *fragment-size*: two participants discover
   (SPDP) and match (SEDP), then the publisher sends a 4000-octet user sample. The writer
   fragments it into DATA_FRAG submessages + a HEARTBEAT_FRAG; the subscriber reassembles it
   and delivers a byte-exact copy. Proves send-side fragmentation + receive-side reassembly +
   NACK_FRAG recovery over real UDP loopback (RTPS 2.5 §9.4.5.5)."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0))
         (payload (make-array 4000 :element-type '(unsigned-byte 8))))
    (dotimes (i 4000) (setf (aref payload i) (logand (* i 7) #xff)))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-publisher node1)
           (add-local-reader node2 :topic "Square" :type "ShapeType"
                                   :reliability dds.rtps.discovery:+reliability-reliable+)
           (enable-subscriber node2)
           (setf (disc-node-peers node1) (list (cons "127.0.0.1" (disc-node-port node2))))
           (setf (disc-node-peers node2) (list (cons "127.0.0.1" (disc-node-port node1))))
           (start-node node1)
           (start-node node2)
           (announce-participant node1)
           (announce-participant node2)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node1))
                            (plusp (disc-node-discovered-count node2)))
                 do (sleep 0.02))
           (announce-endpoints node1)
           (announce-endpoints node2)
           (loop repeat 100
                 until (and (plusp (disc-node-matched-count node1))
                            (plusp (disc-node-matched-count node2)))
                 do (sleep 0.02))
           (assert (and (plusp (disc-node-matched-count node1))
                        (plusp (disc-node-matched-count node2)))
                   () "endpoints did not match before publish")
           (publish-sample node1 payload)
           (loop repeat 150 until (plusp (node-sample-count node2)) do (sleep 0.02))
           (assert (plusp (node-sample-count node2)) ()
                   "subscriber never received the fragmented sample over UDP")
           (assert (equalp (node-sample node2 1) payload) ()
                   "subscriber received the wrong reassembled payload bytes")
           t)
      (stop-node node1)
      (stop-node node2))))

(defun* run-locator-filter-test ()
    (function () (eql t))
  "Locator-list selection + foreign-participant robustness (regression for the
   EHOSTUNREACH crash vs RTI DDSSpy, which advertises several locators incl.
   0.0.0.0): %usable-destination (1) picks a routable default-unicast locator,
   skipping a 0.0.0.0 entry; (2) falls back to a routable metatraffic ADDRESS + a
   default-unicast PORT when every default-unicast locator is non-routable; (3)
   yields NIL when nothing is routable; (4) a UDP send to 0.0.0.0 is non-fatal."
  (flet ((loc (a b c d port)
           (dds.rtps.discovery:make-locator
            :kind dds.rtps.discovery:+locator-kind-udpv4+ :port port
            :address (dds.rtps.discovery:make-ipv4-locator
                      (make-array 4 :element-type '(unsigned-byte 8)
                                  :initial-contents (list a b c d)))))
         (sd (du mt)
           (dds.rtps.discovery:make-spdp-data :default-unicast-locators du
                                              :metatraffic-unicast-locators mt)))
    (assert (equal (%usable-destination (sd (list (loc 0 0 0 0 7411) (loc 192 168 1 7 7411)) '()))
                   '("192.168.1.7" . 7411))
            () "must pick the routable default-unicast locator, skipping 0.0.0.0")
    (assert (equal (%usable-destination (sd (list (loc 0 0 0 0 7411)) (list (loc 192 168 1 7 7410))))
                   '("192.168.1.7" . 7411))
            () "must fall back to metatraffic address + default-unicast port")
    (assert (null (%usable-destination (sd (list (loc 0 0 0 0 7411)) (list (loc 0 0 0 0 7410)))))
            () "all-0.0.0.0 must yield NIL, not a bad destination")
    (multiple-value-bind (tr sock) (dds.xport.udp:make-udp-transport :host "127.0.0.1" :port 0)
      (unwind-protect
           (let ((buf (dds.core.buffer:make-octet-buffer 16)))
             (dds.xport:send tr (dds.xport.udp:make-udp-locator :host "0.0.0.0" :port 7411) buf 0 1)
             (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf)))
        (dds.pal:udp-close sock)))
    t))
