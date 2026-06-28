;;;; L5 — ParticipantStatelessMessage builtin endpoints (DDS-Security 1.1 §7.4.3 / §8.7).
;;;; Wires T2's ParticipantGenericMessage codec onto two best-effort builtin endpoints:
;;;; ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_WRITER (0x000201C3) for sending and
;;;; ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_READER (0x000201C4) for receiving.
;;;; No HEARTBEAT / ACKNACK (best-effort, §7.4.3). Used exclusively for the DDS-Security §8.7
;;;; three-message authentication handshake between two security-aware participants.
;;;; Default-OFF: a node without identity-token-octets / on-stateless-message is unaffected.
;;;; Control-plane only — per-message heap allocation is intentional (no hot-path concern).

(in-package #:dds.disc)

(defun* %psm-encapsulate (envelope-octets)
    (function ((simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Prefix ENVELOPE-OCTETS (a CDR-LE ParticipantGenericMessage blob) with the 4-octet PLAIN_CDR_LE
   SerializedPayload encapsulation header (RTPS 2.5 §10.2). The ParticipantStatelessMessage rides a
   regular builtin DataWriter, so its SerializedPayload MUST carry the encapsulation header like every
   other DATA — corroborated against Fast DDS SecurityManager.cpp:933-938 (addOctet 0, DEFAULT_ENCAPSULATION,
   addUInt16 0 before the ParticipantGenericMessage; read back at :1462-1470). Control-plane; per-message alloc fine."
  (let* ((hdr (dds.core.buffer:make-octet-buffer 4))
         (hc  (dds.core.buffer:cursor hdr :endianness :little))
         (out (make-array (+ 4 (length envelope-octets)) :element-type '(unsigned-byte 8))))
    (dds.cdr:make-encapsulation-header hc :plain-cdr-le)
    (replace out (dds.core.buffer:octet-buffer-vec hdr) :start1 0 :end1 4)
    (replace out envelope-octets :start1 4)
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec hdr))
    out))

(defun* %send-stateless-message (node dest-prefix envelope-octets)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*))) t)
  "Send ENVELOPE-OCTETS (a T2 ParticipantGenericMessage blob) as a best-effort DATA submessage
   with writerId = +entityid-participant-stateless-writer+ and readerId =
   +entityid-participant-stateless-reader+ (DDS-Security 1.1 §7.4.3, best-effort — no HEARTBEAT).
   The SerializedPayload is the §10.2 PLAIN_CDR_LE encapsulation header (%psm-encapsulate) + the
   CDR-LE envelope, matching a conformant peer (Fast DDS prepends/strips this header). Destination:
   DEST-PREFIX's metatraffic unicast locator (looked up under the node lock via %remote-metatraffic).
   No-op if the remote is not yet discovered or has no usable locator. Uses the rx-tx-msg scratch
   buffer (called from the receiver thread during handshake callback)."
  (let ((hp (%remote-metatraffic node dest-prefix)))
    (when hp
      (let ((payload (%psm-encapsulate envelope-octets)))
        (%send-msg-buf node (disc-node-rx-tx-msg node)
                       (lambda (mc)
                         ;; writer-SN 0: best-effort PSM, no reliable-channel SN discipline (DDS-Security 1.1 §7.4.3)
                         (dds.rtps.message:write-data
                          mc dds.rtps.discovery:+entityid-participant-stateless-reader+
                          dds.rtps.discovery:+entityid-participant-stateless-writer+
                          0 payload 0 (length payload)))
                       (car hp) (cdr hp)))))
  t)

(defun* %on-stateless-message (node src-prefix wtr sn buf poff plen)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) integer
               dds.core.buffer:octet-buffer (integer 0) (integer 0)) t)
  "Receiver thread: a DATA from a remote ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_WRITER.
   Bounds-check the SerializedPayload extent, copy it out of the shared receive buffer, and
   deliver the RAW ParticipantGenericMessage envelope octets (§7.4.4) to
   disc-node-on-stateless-message if the hook is set: (funcall hook node src-prefix envelope).
   dds-disc stays crypto/format-agnostic — the manager (dds-dcps) does parse-generic-message,
   reads message_class_id, and dispatches handshake vs crypto-token (an auth-message and a
   crypto-token message arrive on the SAME stateless endpoint with DIFFERENT DataHolders, so a
   pre-parse to a handshake-token here would silently drop crypto-token messages). FAIL-CLOSED:
   only the buffer-extent bounds-check happens here; an empty/out-of-range payload is dropped —
   the receiver thread MUST NOT crash or signal. WTR/SN accepted for dispatch-signature
   symmetry with %on-participant-message."
  (declare (ignore wtr sn))
  (block %on-psm ; explicit block so (return-from %on-psm t) is a clean early exit
    ;; Require the 4-octet §10.2 encapsulation header + at least an empty body (fail-closed on a runt).
    (unless (and (>= plen 4)
                 (<= (+ poff plen) (dds.core.buffer:octet-buffer-capacity buf)))
      (return-from %on-psm t))
    (let ((hook (disc-node-on-stateless-message node)))
      (unless hook (return-from %on-psm t))
      ;; Strip the PLAIN_CDR_LE SerializedPayload encapsulation header (§10.2, %psm-encapsulate's
      ;; counterpart; Fast DDS SecurityManager.cpp:1462-1470 reads it back) before delivering the bare
      ;; ParticipantGenericMessage envelope. Copy out of the shared receive buffer under no lock; the
      ;; manager (dds-dcps) parses/dispatches handshake vs crypto-token.
      (let ((octets (make-array (- plen 4) :element-type '(unsigned-byte 8))))
        (replace octets (dds.core.buffer:octet-buffer-vec buf) :start2 (+ poff 4) :end2 (+ poff plen))
        (funcall hook node src-prefix octets))))
  t)
