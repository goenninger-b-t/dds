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
(defconstant +user-writer-id+ #x00000103)   ; key 000001, kind 03 (user writer, no key)
(defconstant +user-reader-id+ #x00000204)   ; key 000002, kind 04 (user reader, with key)

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

(declaim (ftype (function (disc-node) list) %data-destinations))
(defun %data-destinations (node)
  "Where to send user DATA/HEARTBEAT: the union of static PEERS and each discovered
   participant's default-unicast (user-traffic) locator, deduped by (host . port).
   Discovery-driven routing is what makes the data plane work against a foreign
   participant (e.g. Connext), not just hand-wired peers."
  (let ((dests (copy-list (disc-node-peers node))))
    (dolist (p (%discovered-participants node) dests)
      (let ((host (%locator-ipv4-string (dds.rtps.discovery:spdp-data-default-unicast-address p)))
            (port (%locator-port (dds.rtps.discovery:spdp-data-default-unicast-port p))))
        (when (plusp port)
          (pushnew (cons host port) dests :test #'equal))))))

(declaim (ftype (function (disc-node) t) %push-data))
(defun %push-data (node)
  "Writer side: send every change not yet acked by the reader as a DATA submessage,
   followed by a HEARTBEAT, to each peer (caller thread; uses tx-msg)."
  (let ((writer (disc-node-user-writer node)))
    (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat writer)
      (let ((datas (dds.rtps.reliable:writer-data-list writer +user-reader-id+)))
        (dolist (peer (%data-destinations node))
          (dolist (d datas)
            (let ((sn (car d)) (pl (cdr d)))
              (declare (type (simple-array (unsigned-byte 8) (*)) pl))
              (%send-msg-buf node (disc-node-tx-msg node)
                             (lambda (mc)
                               (dds.rtps.message:write-data
                                mc +user-reader-id+ +user-writer-id+ sn pl 0 (length pl)))
                             (car peer) (cdr peer))))
          (%send-msg-buf node (disc-node-tx-msg node)
                         (lambda (mc)
                           (dds.rtps.message:write-heartbeat
                            mc +user-reader-id+ +user-writer-id+ first last count :final nil))
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
            (dolist (peer (%data-destinations node))
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
      (multiple-value-bind (resends gaps)
          (dds.rtps.reliable:writer-on-acknack (disc-node-user-writer node)
                                               +user-reader-id+ base numbits bitmap)
        (declare (ignore gaps))
        (dolist (peer (%data-destinations node))
          (dolist (d resends)
            (let ((sn (car d)) (pl (cdr d)))
              (declare (type (simple-array (unsigned-byte 8) (*)) pl))
              (%send-msg-buf node (disc-node-rx-tx-msg node)
                             (lambda (mc)
                               (dds.rtps.message:write-data
                                mc +user-reader-id+ +user-writer-id+ sn pl 0 (length pl)))
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
