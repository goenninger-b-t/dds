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
(defconstant +user-reader-id+ #x00000207)   ; key 000002, kind 07 (user reader WITH key)

(declaim (ftype (function (disc-node dds.core.buffer:octet-buffer function string (unsigned-byte 16)) t) %send-msg-buf))
(defun %send-msg-buf (node buf build-fn host port)
  "Build an RTPS message (Header + whatever BUILD-FN writes on the cursor) into BUF
   and send it to HOST:PORT. BUF selects the thread's scratch message buffer."
  (let ((mc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
    (funcall build-fn mc)
    (dds.xport:send (disc-node-transport node)
                    (dds.xport.udp:make-udp-locator :host host :port port)
                    buf 0 (dds.core.buffer:cursor-position mc))))

(declaim (ftype (function (dds.rtps.discovery:spdp-data) t) %usable-destination))
(defun %usable-destination (p)
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

(declaim (ftype (function ((simple-array (unsigned-byte 8) (16))) t) %reader-guid-p))
(defun %reader-guid-p (guid)
  "T iff the GUID's entity kind is a user reader (0x04 no-key / 0x07 with-key)."
  (let ((k (aref guid 15))) (or (= k #x04) (= k #x07))))

(declaim (ftype (function ((simple-array (unsigned-byte 8) (16))) t) %writer-guid-p))
(defun %writer-guid-p (guid)
  "T iff the GUID's entity kind is a user writer (0x02 with-key / 0x03 no-key)."
  (let ((k (aref guid 15))) (or (= k #x02) (= k #x03))))

(declaim (ftype (function (disc-node) list) %matched-endpoints))
(defun %matched-endpoints (node)
  "Snapshot of the remote endpoints matched to one of NODE's local endpoints."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for v being the hash-values of (disc-node-matches node) collect v)))

(declaim (ftype (function (disc-node t) list) %match-destinations))
(defun %match-destinations (node want-readers)
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

(declaim (ftype (function (disc-node) t) %push-data))
(defun %push-data (node)
  "Writer side: send every change not yet acked by the reader as a DATA submessage,
   followed by a HEARTBEAT, to each peer (caller thread; uses tx-msg)."
  (let ((writer (disc-node-user-writer node)))
    (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat writer)
      (let ((datas (dds.rtps.reliable:writer-data-list writer +user-reader-id+)))
        (dolist (peer (%match-destinations node t))   ; DATA + HEARTBEAT -> matched readers
          (dolist (d datas)
            (let ((sn (car d)) (pl (cdr d)))
              (declare (type (simple-array (unsigned-byte 8) (*)) pl))
              (%send-msg-buf node (disc-node-tx-msg node)
                             (lambda (mc)
                               (dds.rtps.message:write-data
                                mc dds.rtps.message:+entityid-unknown+ +user-writer-id+ sn pl 0 (length pl)))
                             (car peer) (cdr peer))))
          (%send-msg-buf node (disc-node-tx-msg node)
                         (lambda (mc)
                           (dds.rtps.message:write-heartbeat
                            mc dds.rtps.message:+entityid-unknown+ +user-writer-id+ first last count :final nil))
                         (car peer) (cdr peer)))))))

(declaim (ftype (function (disc-node (simple-array (unsigned-byte 8) (*))) (eql t)) publish-sample))
(defun publish-sample (node payload)
  "Publish PAYLOAD (an opaque SerializedPayload) on the node's user writer: add it
   to the writer HistoryCache, then push DATA + HEARTBEAT to peers (FR-RTPS-8)."
  (dds.rtps.reliable:writer-write (disc-node-user-writer node) payload)
  (%push-data node)
  t)

(declaim (ftype (function (disc-node (unsigned-byte 32) integer dds.core.buffer:octet-buffer (integer 0) (integer 0)) t) %on-user-data))
(defun %on-user-data (node writer-id sn buf poff plen)
  "Reader side: copy the [poff,plen) SerializedPayload out of the receive buffer,
   feed it to the reliable reader (dedup/reorder), and record it by SN."
  (let ((vec (make-array plen :element-type '(unsigned-byte 8))))
    (replace vec (dds.core.buffer:octet-buffer-vec buf) :start2 poff :end2 (+ poff plen))
    (dds.rtps.reliable:reader-on-data (disc-node-user-reader node) writer-id sn vec)
    (dds.pal:with-lock ((disc-node-lock node))
      (setf (gethash sn (disc-node-samples node)) vec))
    t))

(declaim (ftype (function (disc-node dds.core.buffer:cursor (unsigned-byte 8)) t) %on-user-heartbeat))
(defun %on-user-heartbeat (node c flags)
  "Reader side: apply the HEARTBEAT's available range, then answer with an ACKNACK
   (acking received SNs, NACKing the rest) to each peer (uses rx-tx-msg)."
  (multiple-value-bind (rid wid first last count finalp livep)
      (dds.rtps.message:parse-heartbeat-body c flags)
    (declare (ignore rid count finalp livep))
    (when (= wid +user-writer-id+)
      (let ((reader (disc-node-user-reader node)))
        (dds.rtps.reliable:reader-on-heartbeat reader wid first last)
        (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wid)
          (let ((cnt (incf (disc-node-ack-count node))))
            (dolist (peer (%match-destinations node nil))   ; ACKNACK -> matched writers
              (%send-msg-buf node (disc-node-rx-tx-msg node)
                             (lambda (mc)
                               (dds.rtps.message:write-acknack
                                mc +user-reader-id+ +user-writer-id+ base numbits bitmap cnt :final t))
                             (car peer) (cdr peer))))))))
  t)

(declaim (ftype (function (disc-node dds.core.buffer:cursor (unsigned-byte 8)) t) %on-user-acknack))
(defun %on-user-acknack (node c flags)
  "Writer side: on an ACKNACK, retransmit each NACKed change as a DATA submessage
   to each peer (uses rx-tx-msg). GAPs are not needed (KEEP_ALL never drops)."
  (multiple-value-bind (rid wid base numbits bitmap count finalp)
      (dds.rtps.message:parse-acknack-body c flags)
    (declare (ignore rid count finalp))
    (when (= wid +user-writer-id+)
      (incf (disc-node-acks-in node))   ; a matched reader (incl. RTI) acked our writer
      (multiple-value-bind (resends gaps)
          (dds.rtps.reliable:writer-on-acknack (disc-node-user-writer node)
                                               +user-reader-id+ base numbits bitmap)
        (declare (ignore gaps))
        (dolist (peer (%match-destinations node t))   ; retransmit DATA -> matched readers
          (dolist (d resends)
            (let ((sn (car d)) (pl (cdr d)))
              (declare (type (simple-array (unsigned-byte 8) (*)) pl))
              (%send-msg-buf node (disc-node-rx-tx-msg node)
                             (lambda (mc)
                               (dds.rtps.message:write-data
                                mc dds.rtps.message:+entityid-unknown+ +user-writer-id+ sn pl 0 (length pl)))
                             (car peer) (cdr peer))))))))
  t)

(declaim (ftype (function (disc-node) disc-node) enable-publisher))
(defun enable-publisher (node)
  "Give NODE a reliable user writer (KEEP_ALL) and install the writer-side data-
   plane hook (retransmit on ACKNACK). Call after add-local-writer."
  (setf (disc-node-user-writer node)
        (dds.rtps.reliable:make-rtps-writer
         :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
  (setf (disc-node-on-acknack node) (lambda (c flags) (%on-user-acknack node c flags)))
  node)

(declaim (ftype (function (disc-node) disc-node) enable-subscriber))
(defun enable-subscriber (node)
  "Give NODE a reliable user reader and install the reader-side data-plane hooks
   (store DATA, ACKNACK on HEARTBEAT). Call after add-local-reader."
  (setf (disc-node-user-reader node) (dds.rtps.reliable:make-rtps-reader))
  (setf (disc-node-on-data node)
        (lambda (wid sn buf poff plen) (%on-user-data node wid sn buf poff plen)))
  (setf (disc-node-on-heartbeat node)
        (lambda (c flags) (%on-user-heartbeat node c flags)))
  node)

(declaim (ftype (function (disc-node) (integer 0)) node-sample-count))
(defun node-sample-count (node)
  "Number of distinct user samples the subscriber has received."
  (dds.pal:with-lock ((disc-node-lock node))
    (hash-table-count (disc-node-samples node))))

(declaim (ftype (function (disc-node integer) t) node-sample))
(defun node-sample (node sn)
  "The received payload for sequence number SN, or NIL."
  (dds.pal:with-lock ((disc-node-lock node))
    (gethash sn (disc-node-samples node))))

(declaim (ftype (function (disc-node) list) node-sample-sns))
(defun node-sample-sns (node)
  "Sequence numbers of the user samples received so far (unordered). Lets a
   subscriber drain new samples without assuming SNs start at 1 (Connext may not)."
  (dds.pal:with-lock ((disc-node-lock node))
    (loop for k being the hash-keys of (disc-node-samples node) collect k)))

(declaim (ftype (function (disc-node) list) node-discovered-participants))
(defun node-discovered-participants (node)
  "Snapshot of the SPDP data for every participant NODE has discovered (diagnostic)."
  (%discovered-participants node))

(declaim (ftype (function (dds.rtps.discovery:spdp-data) t) resolved-destination))
(defun resolved-destination (p)
  "The (host . port) this stack would send user data to for participant P (its
   resolved routable locator), or NIL — exactly what the data plane uses. Diagnostic."
  (%usable-destination p))

(declaim (ftype (function (disc-node) integer) node-acks-in))
(defun node-acks-in (node)
  "Count of ACKNACKs received for this node's user writer — i.e. how many times a
   matched reader (incl. a foreign one like RTI) acknowledged our data. >0 proves a
   remote reliable reader is actually receiving our samples. Diagnostic."
  (disc-node-acks-in node))

(declaim (ftype (function () (eql t)) run-dataplane-test))
(defun run-dataplane-test ()
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

(declaim (ftype (function () (eql t)) run-locator-filter-test))
(defun run-locator-filter-test ()
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
