;;;; L5 — Writer Liveliness Protocol builtin endpoints over the discovery node
;;;; (RTPS 2.5 §8.4.13). Wires the ParticipantMessageData wire codec (dds.rtps.discovery
;;;; serialize-/parse-participant-message) onto the two §9.6.2.2 P2P builtin endpoints:
;;;; the BuiltinParticipantMessageWriter (0x000200c2) periodically asserts this
;;;; participant's liveliness on the announce cadence (§8.4.13.5), and the
;;;; BuiltinParticipantMessageReader (0x000200c7) records each inbound assertion as a
;;;; per-remote liveliness stamp. Control-plane: per-assertion heap allocation is
;;;; acceptable (not a measured hot path), mirroring typelookup-endpoints.lisp.
;;;;
;;;; Reliability (§8.4.13.3): the BuiltinParticipantMessageWriter shall be RELIABLE. We
;;;; send each assertion as a DATA submessage followed by a HEARTBEAT for the PM writer
;;;; so a reliable peer can NACK a lost sample — but we keep NO per-reply resend store:
;;;; a missed assertion is re-sent on the very next announce cadence (the assertion is
;;;; periodic + idempotent — the DDS key is participantGuidPrefix+kind, §8.4.13.5), so
;;;; the next sample supersedes the lost one. The peer is not broken by this: it still
;;;; sees periodic DATA + HEARTBEAT for the writer. A full ACKNACK-driven resend store
;;;; (the TL/SEDP discipline) is a noted refinement, not required for liveliness.

(in-package #:dds.disc)

(defun* %local-liveliness-kinds (node)
    (function (disc-node) list)
  "The set of ParticipantMessageData kinds this participant must assert, derived from
   its local writers' LIVELINESS QoS (RTPS 2.5 §8.4.13.5): +pmd-kind-automatic+ if any
   local writer is :automatic, +pmd-kind-manual-by-participant+ if any is
   :manual-by-participant. MANUAL_BY_TOPIC is NOT carried by this protocol (§8.4.13.5;
   handled by §8.7.2.2.3) and contributes no kind here. Empty when no local writer uses
   a protocol-carried liveliness kind, in which case nothing is asserted."
  (let ((auto nil) (manual nil))
    (dolist (w (disc-node-local-writers node))
      (case (dds.qos:qos-liveliness (dds.rtps.discovery:endpoint-data-qos w))
        (:automatic (setf auto t))
        (:manual-by-participant (setf manual t))))
    (nconc (when auto (list dds.rtps.discovery:+pmd-kind-automatic+))
           (when manual (list dds.rtps.discovery:+pmd-kind-manual-by-participant+)))))

(defun* %pm-serialized-payload (node kind)
    (function (disc-node (unsigned-byte 32)) (simple-array (unsigned-byte 8) (*)))
  "Build the SerializedPayload for a ParticipantMessageData assertion of KIND: a
   4-octet PLAIN_CDR_LE encapsulation header (RTPS 2.5 §10.2; the codec writes the
   sequence length little-endian to mirror PLAIN_CDR, see serialize-participant-message)
   followed by the bare struct (participantGuidPrefix = this node's prefix, kind = KIND,
   empty data). DATA is empty: a liveliness assertion carries no payload (§8.4.13.5)."
  (let* ((hdr (dds.core.buffer:make-octet-buffer 4))
         (hc (dds.core.buffer:cursor hdr :endianness :little)))
    (dds.cdr:make-encapsulation-header hc :plain-cdr-le)
    (let* ((body (dds.rtps.discovery:serialize-participant-message
                  (dds.rtps.discovery:make-participant-message
                   :guid-prefix (disc-node-guid-prefix node) :kind kind)))
           (out (make-array (+ 4 (length body)) :element-type '(unsigned-byte 8))))
      (replace out (dds.core.buffer:octet-buffer-vec hdr) :start1 0 :end1 4)
      (replace out body :start1 4)
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec hdr))
      out)))

(defun* %send-pm-assertion (node kind host port)
    (function (disc-node (unsigned-byte 32) string (unsigned-byte 16)) t)
  "Send one ParticipantMessageData assertion of KIND from the
   BuiltinParticipantMessageWriter to HOST:PORT: a DATA submessage (PM writer -> PM
   reader, next pm-writer-sn) followed by a non-final HEARTBEAT for the PM writer
   (RTPS 2.5 §8.4.13.3 RELIABLE). SN is allocated under the node lock; the send happens
   outside it. Per-assertion buffers (announce thread): a per-call message buffer so the
   reused tx-msg is untouched, and the per-call SerializedPayload."
  (let* ((octets (%pm-serialized-payload node kind))
         (sn (dds.pal:with-lock ((disc-node-lock node))
               (let ((sn (disc-node-pm-writer-sn node)))
                 (incf (disc-node-pm-writer-sn node))
                 sn)))
         ;; RTPS header(20) + DATA(4 + 20 fixed + payload) + HEARTBEAT(4 + 28) -> generous slack
         (buf (dds.core.buffer:make-octet-buffer (+ 128 (length octets)))))
    (unwind-protect
         (%send-msg-buf node buf
                        (lambda (mc)
                          (dds.rtps.message:write-data
                           mc dds.rtps.discovery:+entityid-p2p-participant-message-reader+
                           dds.rtps.discovery:+entityid-p2p-participant-message-writer+
                           sn octets 0 (length octets))
                          ;; count = SN: monotonic per PM writer; non-final solicits an ACKNACK
                          (dds.rtps.message:write-heartbeat
                           mc dds.rtps.discovery:+entityid-p2p-participant-message-reader+
                           dds.rtps.discovery:+entityid-p2p-participant-message-writer+
                           sn sn sn :final nil :liveliness nil))
                        host port)
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))))
  t)

(defun* assert-participant-liveliness (node)
    (function (disc-node) (eql t))
  "Assert NODE's Writer Liveliness on the announce cadence (RTPS 2.5 §8.4.13.5): for
   each liveliness kind its local writers require (%local-liveliness-kinds — one
   AUTOMATIC instance if any local writer is :automatic, one MANUAL_BY_PARTICIPANT
   instance if any is :manual-by-participant; the two are distinct DDS-key instances),
   write one ParticipantMessageData sample to every discovered participant's metatraffic
   unicast locator via the BuiltinParticipantMessageWriter. Returns T (no-op when the
   node has no protocol-carried-liveliness local writer or no discovered peer).

   CADENCE: v1 uses the announce cadence as the assertion rate (announce-participant
   drives this). §8.4.13.5 requires the assertion rate be FASTER than the smallest
   AUTOMATIC/MANUAL lease among the writers — which holds for the default leases (the
   harness re-announces well inside any practical lease). A finer per-lease assertion
   timer (one timer per distinct lease duration) is a noted refinement; it is not needed
   while the cadence already beats the lease."
  (let ((kinds (%local-liveliness-kinds node)))
    (when kinds
      (dolist (p (%discovered-participants node))
        (let ((loc (dds.rtps.discovery:usable-udpv4-locator
                    (dds.rtps.discovery:spdp-data-metatraffic-unicast-locators p))))
          (when loc
            (let ((host (dds.rtps.discovery:locator-ipv4-string loc))
                  (port (%locator-port (dds.rtps.discovery:locator-port loc))))
              (when (plusp port)
                (dolist (kind kinds)
                  (%send-pm-assertion node kind host port)))))))))
  t)

(defun* %on-participant-message (node prefix wtr sn buf poff plen)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) integer dds.core.buffer:octet-buffer (integer 0) (integer 0)) t)
  "Receiver thread: a DATA from a remote BuiltinParticipantMessageWriter. Bounds-check +
   copy the SerializedPayload, strip its encapsulation header, parse the bare
   ParticipantMessageData, and record a per-remote liveliness stamp keyed by
   (sender-prefix . kind) -> %lease-now (RTPS 2.5 §8.4.13.5). PREFIX is the datagram's
   source GUID prefix (anti-spoof: the stamp is keyed by the SENDER, not by the
   message's self-reported participantGuidPrefix). WTR/SN are accepted for dispatch
   symmetry; the PM reader is treated BEST_EFFORT-tolerant here (no ACKNACK), since the
   assertion is periodic + idempotent and the next cadence re-sends any loss."
  (declare (ignore wtr sn))
  (when (and (plusp plen)
             (<= (+ poff plen) (dds.core.buffer:octet-buffer-capacity buf)))
    (let ((octets (make-array plen :element-type '(unsigned-byte 8))))
      (replace octets (dds.core.buffer:octet-buffer-vec buf) :start2 poff :end2 (+ poff plen))
      ;; strip the 4-octet SerializedPayload encapsulation header (§10.2) before the codec
      (when (>= plen 4)
        (let ((pm (dds.rtps.discovery:parse-participant-message (subseq octets 4))))
          (when pm
            (dds.pal:with-lock ((disc-node-lock node))
              (setf (gethash (cons (copy-seq prefix)
                                   (dds.rtps.discovery:participant-message-kind pm))
                             (disc-node-remote-liveliness node))
                    (%lease-now))))))))
  t)

(defun* disc-node-remote-liveliness-stamp (node prefix kind)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32)) (or null integer))
  "The internal-real-time stamp of the last liveliness assertion of KIND received from
   participant PREFIX (RTPS 2.5 §8.4.13.5), or NIL if none recorded. Lock-guarded."
  (dds.pal:with-lock ((disc-node-lock node))
    (gethash (cons prefix kind) (disc-node-remote-liveliness node))))

(defun* run-participant-liveliness-test ()
    (function () (eql t))
  "Writer Liveliness Protocol over UDP (RTPS 2.5 §8.4.13.5): two participants on
   127.0.0.1 first discover each other via SPDP; node1 carries a local AUTOMATIC
   DataWriter, so its announce cadence asserts AUTOMATIC liveliness via the
   BuiltinParticipantMessageWriter; node2's BuiltinParticipantMessageReader records an
   AUTOMATIC liveliness stamp for node1's prefix. Assert node2 holds a fresh AUTOMATIC
   stamp for node1 after spinning."
  (let* ((p1 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(1 1 1 1 1 1 1 1 1 1 1 1)))
         (p2 (make-array 12 :element-type '(unsigned-byte 8)
                         :initial-contents '(2 2 2 2 2 2 2 2 2 2 2 2)))
         (node1 (make-disc-node :guid-prefix p1 :host "127.0.0.1" :port 0))
         (node2 (make-disc-node :guid-prefix p2 :host "127.0.0.1" :port 0)))
    (unwind-protect
         (progn
           (add-local-writer node1 :topic "Square" :type "ShapeType"
                                   :qos (dds.qos:make-qos :reliability :reliable
                                                          :liveliness :automatic))
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
           (assert (and (plusp (disc-node-discovered-count node1))
                        (plusp (disc-node-discovered-count node2)))
                   () "SPDP did not complete before the liveliness assertion")
           ;; re-announce so the assertion fires now that node1 has discovered node2
           (loop repeat 100
                 until (disc-node-remote-liveliness-stamp
                        node2 p1 dds.rtps.discovery:+pmd-kind-automatic+)
                 do (announce-participant node1) (sleep 0.02))
           (assert (disc-node-remote-liveliness-stamp
                    node2 p1 dds.rtps.discovery:+pmd-kind-automatic+)
                   () "node2 did not record an AUTOMATIC liveliness stamp for node1")
           t)
      (stop-node node1)
      (stop-node node2))))
