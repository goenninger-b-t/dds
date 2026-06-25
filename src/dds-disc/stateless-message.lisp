;;;; L5 — ParticipantStatelessMessage builtin endpoints (DDS-Security 1.1 §7.4.3 / §8.7).
;;;; Wires T2's ParticipantGenericMessage codec onto two best-effort builtin endpoints:
;;;; ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_WRITER (0x000201C3) for sending and
;;;; ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_READER (0x000201C4) for receiving.
;;;; No HEARTBEAT / ACKNACK (best-effort, §7.4.3). Used exclusively for the DDS-Security §8.7
;;;; three-message authentication handshake between two security-aware participants.
;;;; Default-OFF: a node without identity-token-octets / on-stateless-message is unaffected.
;;;; Control-plane only — per-message heap allocation is intentional (no hot-path concern).

(in-package #:dds.disc)

(defun* %send-stateless-message (node dest-prefix envelope-octets)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*))) t)
  "Send ENVELOPE-OCTETS (a T2 ParticipantGenericMessage blob) as a best-effort DATA submessage
   with writerId = +entityid-participant-stateless-writer+ and readerId =
   +entityid-participant-stateless-reader+ (DDS-Security 1.1 §7.4.3, best-effort — no HEARTBEAT).
   The envelope is sent as the SerializedPayload body directly (no encapsulation header added here:
   the PSM DATA SerializedPayload *is* the CDR-LE envelope, §7.4.4). Destination: DEST-PREFIX's
   metatraffic unicast locator (looked up under the node lock via %remote-metatraffic). No-op if
   the remote is not yet discovered or has no usable locator. Uses the rx-tx-msg scratch buffer
   (called from the receiver thread during handshake callback)."
  (let ((hp (%remote-metatraffic node dest-prefix)))
    (when hp
      (%send-msg-buf node (disc-node-rx-tx-msg node)
                     (lambda (mc)
                       ;; writer-SN 0: best-effort PSM, no reliable-channel SN discipline (DDS-Security 1.1 §7.4.3)
                       (dds.rtps.message:write-data
                        mc dds.rtps.discovery:+entityid-participant-stateless-reader+
                        dds.rtps.discovery:+entityid-participant-stateless-writer+
                        0 envelope-octets 0 (length envelope-octets)))
                     (car hp) (cdr hp))))
  t)

(defun* %on-stateless-message (node src-prefix wtr sn buf poff plen)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) integer
               dds.core.buffer:octet-buffer (integer 0) (integer 0)) t)
  "Receiver thread: a DATA from a remote ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_WRITER.
   Bounds-check + copy the SerializedPayload, parse it as a ParticipantGenericMessage (T2 codec,
   §7.4.4), extract + parse the first DataHolder as a handshake-token, and invoke
   disc-node-on-stateless-message if the hook is set. FAIL-CLOSED: any malformed/truncated/
   missing message or token is silently dropped — the receiver thread MUST NOT crash or signal.
   WTR/SN accepted for dispatch-signature symmetry with %on-participant-message."
  (declare (ignore wtr sn))
  (block %on-psm ; explicit block so (return-from %on-psm t) is a clean early exit
    (unless (and (plusp plen)
                 (<= (+ poff plen) (dds.core.buffer:octet-buffer-capacity buf)))
      (return-from %on-psm t))
    (let ((hook (disc-node-on-stateless-message node)))
      (unless hook (return-from %on-psm t))
      ;; copy payload out of the shared receive buffer before releasing the buffer lock
      (let ((octets (make-array plen :element-type '(unsigned-byte 8))))
        (replace octets (dds.core.buffer:octet-buffer-vec buf) :start2 poff :end2 (+ poff plen))
        ;; parse-generic-message returns NIL source-guid on any malformed input (fail-closed §7.4.4)
        (multiple-value-bind (src-guid _sn rel-guid _rel-sn _dest-part _dest-ep _src-ep class-id dh-list)
            (dds.security:parse-generic-message octets)
          (declare (ignore _sn rel-guid _rel-sn _dest-part _dest-ep _src-ep class-id))
          (unless src-guid (return-from %on-psm t))
          ;; require exactly one DataHolder (the auth token, §8.7.2.4 message format)
          (unless dh-list (return-from %on-psm t))
          ;; dataholder->handshake-token returns NIL on any malformed DataHolder (fail-closed)
          (let ((token (dds.security:dataholder->handshake-token (car dh-list))))
            (unless token (return-from %on-psm t))
            ;; all parsing succeeded: invoke the hook outside the node lock (user code)
            (funcall hook node src-prefix token)))))
    t))
