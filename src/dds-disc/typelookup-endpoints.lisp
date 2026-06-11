;;;; L5 — TypeLookup service builtin endpoints over the discovery node (M4,
;;;; FR-TYPE-3). Wires the pure server core (dds.types:type-lookup-respond) plus a
;;;; getTypes client (type-lookup-query) onto the four XTypes 1.3 Table 61 builtin
;;;; endpoints, sharing the node's metatraffic socket: requests and replies travel
;;;; as DATA submessages routed by writerId, with the same per-remote reliable
;;;; builtin bookkeeping SEDP uses (final ACKNACK answering a HEARTBEAT) plus a
;;;; bounded resend store for the reply writer (ACKNACK-driven retransmit; the
;;;; §7.6.3.3.3 service QoS is RELIABLE/KEEP_ALL/VOLATILE). Control-plane: per-query
;;;; heap allocation is acceptable here (not a measured hot path). NO Connext
;;;; oracle exists for this protocol (ADR 0010); byte-level choices are
;;;; CONFIRM-VS-PEER in dds-types/typelookup.lisp.

(in-package #:dds.disc)

;;; XTypes 1.3 Table 61: TypeLookup service builtin EntityIds.
(defconstant +entityid-tl-req-writer+ #x000300c3
  "ENTITYID_TL_SVC_REQ_WRITER = {{00,03,00},c3}: the TypeLookupService
   RequestDataWriter builtin EntityId (XTypes 1.3 §7.6.3.3.3 Table 61).")
(defconstant +entityid-tl-req-reader+ #x000300c4
  "ENTITYID_TL_SVC_REQ_READER = {{00,03,00},c4}: the TypeLookupService
   RequestDataReader builtin EntityId (XTypes 1.3 §7.6.3.3.3 Table 61).")
(defconstant +entityid-tl-reply-writer+ #x000301c3
  "ENTITYID_TL_SVC_REPLY_WRITER = {{00,03,01},c3}: the TypeLookupService
   ReplyDataWriter builtin EntityId (XTypes 1.3 §7.6.3.3.3 Table 61).")
(defconstant +entityid-tl-reply-reader+ #x000301c4
  "ENTITYID_TL_SVC_REPLY_READER = {{00,03,01},c4}: the TypeLookupService
   ReplyDataReader builtin EntityId (XTypes 1.3 §7.6.3.3.3 Table 61).")

(defparameter *typelookup-timeout* 3
  "Seconds to wait for a TypeLookup reply before a pending entry expires (its
   continuation is called with NIL). Read per query (XTypes 1.3 §7.6.3.3.3 QoS
   gives the service RELIABLE/VOLATILE semantics; the timeout is our local policy).")

(defparameter *max-typelookup-pending* 64
  "Cap on in-flight TypeLookup client requests per node (NFR-SEC-POSTURE).")

(defconstant +tl-sent-bound+ 16
  "Max (sn . reply-octets) entries retained in the reply writer's resend store.
   The service endpoints are VOLATILE (XTypes 1.3 §7.6.3.3.3), so a reply only
   needs to survive until the requester acknowledges it — a small bound suffices
   and doubles as a resource-exhaustion guard (NFR-SEC-POSTURE).")

(defstruct* (tl-pending-entry (:constructor %make-tl-pending-entry))
  "One in-flight TypeLookup getTypes request: the queried HASHES, the target
   participant PREFIX (%on-tl-reply matches it against the reply's sender prefix,
   anti-spoof), the CONTINUATION called once with (pairs okp) — okp T for a
   REMOTE_EX_OK reply (PAIRS possibly empty), NIL on timeout/guard/non-OK — and the
   internal-real-time DEADLINE after which tl-sweep expires the entry."
  (hashes '() :type list)
  (prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)
          :type (simple-array (unsigned-byte 8) (12)))
  (continuation nil :type (or null function))
  (deadline 0 :type integer))

(defun* %tl-writer-p (entity-id)
    (function ((unsigned-byte 32)) t)
  "T iff ENTITY-ID is a TypeLookup service builtin writer (XTypes 1.3 Table 61)."
  (or (= entity-id +entityid-tl-req-writer+)
      (= entity-id +entityid-tl-reply-writer+)))

(defun* %tl-reader-id-for (writer-id)
    (function ((unsigned-byte 32)) (or null (unsigned-byte 32)))
  "The local TypeLookup reader EntityId matching a remote TL builtin writer
   WRITER-ID, or NIL if WRITER-ID is not a TL service writer (XTypes 1.3 Table 61)."
  (cond ((= writer-id +entityid-tl-req-writer+) +entityid-tl-req-reader+)
        ((= writer-id +entityid-tl-reply-writer+) +entityid-tl-reply-reader+)
        (t nil)))

(defun* %tl-writer-guid (node)
    (function (disc-node) (simple-array (unsigned-byte 8) (16)))
  "This node's TypeLookup RequestDataWriter GUID_t: 12-octet participant prefix +
   ENTITYID_TL_SVC_REQ_WRITER {{00,03,00},c3} (XTypes 1.3 Table 61; RTPS 2.5 §9.3.1.2)."
  (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace g (disc-node-guid-prefix node) :start1 0 :end1 12)
    (setf (aref g 12) #x00 (aref g 13) #x03 (aref g 14) #x00 (aref g 15) #xc3)
    g))

(defun* %tl-instance-name (prefix)
    (function ((simple-array (unsigned-byte 8) (12))) string)
  "The service instanceName for a request toward participant PREFIX:
   \"dds.builtin.TOS.\" + the lowercase-hex GUID (XTypes 1.3 §7.6.3.3.4). NOTE:
   §7.6.3.3.4 self-contradicts on the hex length (16 chars stated vs a 15-char
   example); we send the 24-char prefix hex. CONFIRM-VS-PEER (ADR 0010)."
  (format nil "dds.builtin.TOS.~(~{~2,'0x~}~)" (coerce prefix 'list)))

(defun* %tl-now ()
    (function () integer)
  "The TypeLookup deadline clock: internal real time (same clock the DCPS WaitSet
   deadline path uses), in internal-time-units-per-second ticks."
  (get-internal-real-time))

(defun* %send-tl-reply (node prefix octets)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*))) t)
  "Send reply OCTETS to participant PREFIX's metatraffic locator as one RTPS message:
   DATA (reply writer -> reply reader, next tl-reply-sn) + a HEARTBEAT for the reply
   writer so a reliable requester can NACK a lost reply. SN allocation + the resend
   store push happen under the node lock; the send happens OUTSIDE it (receiver
   thread -> rx-tx-msg buffer, the %send-acknack discipline)."
  (let ((hp (%remote-metatraffic node prefix)))
    (when hp
      (multiple-value-bind (sn first last)
          (dds.pal:with-lock ((disc-node-lock node))
            (let ((sn (disc-node-tl-reply-sn node)))
              (incf (disc-node-tl-reply-sn node))
              (push (cons sn octets) (disc-node-tl-sent node))
              ;; trim the (newest-first) resend store to the VOLATILE bound
              (let ((tail (nthcdr (1- +tl-sent-bound+) (disc-node-tl-sent node))))
                (when tail (setf (cdr tail) nil)))
              (values sn (car (first (last (disc-node-tl-sent node)))) sn)))
        (%send-msg-buf node (disc-node-rx-tx-msg node)
                       (lambda (mc)
                         (dds.rtps.message:write-data
                          mc +entityid-tl-reply-reader+ +entityid-tl-reply-writer+
                          sn octets 0 (length octets))
                         ;; count = SN: monotonic per reply writer (one HB per reply)
                         (dds.rtps.message:write-heartbeat
                          mc +entityid-tl-reply-reader+ +entityid-tl-reply-writer+
                          first last sn :final nil))
                       (car hp) (cdr hp)))))
  t)

(defun* %on-tl-reply (node prefix octets)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*))) t)
  "Client inbound: parse a TypeLookup_Reply and correlate it by DDS-RPC GUID + SN
   (anti-spoof): its relatedRequestId GUID must equal our RequestDataWriter GUID
   (%tl-writer-guid) AND the sender PREFIX must equal the pending entry's recorded
   target prefix; the relatedRequestId SN selects the entry in tl-pending.
   Unknown/late/mismatched replies drop without consuming the entry. A matched
   entry is removed under the node lock and its continuation is called OUTSIDE the
   lock with (pairs okp) — okp T iff REMOTE_EX_OK."
  ;; 6th value (the getDeps continuation token) intentionally dropped: this client issues getTypes only
  (multiple-value-bind (op result rguid rsn rex) (dds.types:parse-type-lookup-reply octets)
    (when (and rsn (equalp rguid (%tl-writer-guid node)))
      (let ((entry (dds.pal:with-lock ((disc-node-lock node))
                     (let ((e (gethash rsn (disc-node-tl-pending node))))
                       (when (and e (equalp prefix (tl-pending-entry-prefix e)))
                         (remhash rsn (disc-node-tl-pending node))
                         e)))))
        (when (and entry (tl-pending-entry-continuation entry))
          (let ((okp (and (eq rex :ok) (member op '(:get-types :get-deps)) t)))
            ;; continuation fires OUTSIDE the node lock (file lock discipline)
            (funcall (tl-pending-entry-continuation entry) (and okp result) okp))))))
  t)

(defun* %on-tl-data (node prefix wtr sn buf poff plen)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) integer dds.core.buffer:octet-buffer (integer 0) (integer 0)) t)
  "Receiver thread: a DATA from a remote TL builtin writer WTR. Record it on the
   per-remote reliable builtin reader (so our final ACKNACK advances), bounds-check
   + copy the SerializedPayload, then serve a request (reply via the pure server
   core) or correlate a reply. A duplicate request yields a duplicate reply; the
   requester's SN correlation drops the extra (idempotent)."
  (%builtin-on-data node prefix wtr sn)
  (when (and (plusp plen)
             (<= (+ poff plen) (dds.core.buffer:octet-buffer-capacity buf)))
    (let ((octets (make-array plen :element-type '(unsigned-byte 8))))
      (replace octets (dds.core.buffer:octet-buffer-vec buf) :start2 poff :end2 (+ poff plen))
      ;; explicit per-writer dispatch: a future third TL EntityId must not silently route here
      (cond ((= wtr +entityid-tl-req-writer+)
             (let ((reply (dds.types:type-lookup-respond octets)))
               (when reply (%send-tl-reply node prefix reply))))
            ((= wtr +entityid-tl-reply-writer+)
             (%on-tl-reply node prefix octets)))))
  t)

(defun* %on-tl-acknack (node prefix c flags)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) dds.core.buffer:cursor (unsigned-byte 8)) t)
  "Receiver thread: parse an ACKNACK; when it targets our TypeLookup reply writer,
   resend each NACKed SN still in the tl-sent store as a DATA to PREFIX's metatraffic
   locator and return T (handled). NIL for any other writer (caller falls through)."
  (multiple-value-bind (rid wid base numbits bitmap count finalp)
      (dds.rtps.message:parse-acknack-body c flags)
    (declare (ignore rid count finalp))
    (when (and wid (= wid +entityid-tl-reply-writer+))
      (let ((resends (dds.pal:with-lock ((disc-node-lock node))
                       (loop for d in (disc-node-tl-sent node)
                             when (dds.rtps.message:seqnum-set-member-p
                                   base numbits bitmap (car d))
                               collect d)))
            (hp (%remote-metatraffic node prefix)))
        (when hp
          (dolist (d resends)
            (%send-msg-buf node (disc-node-rx-tx-msg node)
                           (lambda (mc)
                             (dds.rtps.message:write-data
                              mc +entityid-tl-reply-reader+ +entityid-tl-reply-writer+
                              (car d) (cdr d) 0 (length (cdr d))))
                           (car hp) (cdr hp)))))
      t)))

(defun* type-lookup-query (node prefix hashes continuation)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) list (or null function)) t)
  "Ask participant PREFIX's TypeLookup service for the TypeObjects of HASHES (a list
   of 14-octet EquivalenceHashes) via a getTypes TypeLookup_Request (XTypes 1.3
   §7.6.3.3.3) sent to its metatraffic locator. CONTINUATION is called exactly once,
   OUTSIDE the node lock, with (pairs okp): okp T and the (hash . typeobject-octets)
   alist on a REMOTE_EX_OK reply (possibly empty — none of the hashes were known),
   or (NIL NIL) on a non-OK reply, on expiry after *TYPELOOKUP-TIMEOUT* seconds (via
   tl-sweep), or immediately when *MAX-TYPELOOKUP-PENDING* requests are already in
   flight. Returns T if the request was recorded (sent now, or awaiting expiry if
   PREFIX has no known metatraffic locator), NIL on the pending-cap rejection."
  (let ((sn nil))
    (dds.pal:with-lock ((disc-node-lock node))
      (unless (>= (hash-table-count (disc-node-tl-pending node)) *max-typelookup-pending*)
        (setf sn (disc-node-tl-req-sn node))
        (incf (disc-node-tl-req-sn node))
        (setf (gethash sn (disc-node-tl-pending node))
              (%make-tl-pending-entry
               :hashes hashes :prefix (copy-seq prefix) :continuation continuation
               :deadline (+ (%tl-now)
                            (round (* *typelookup-timeout*
                                      internal-time-units-per-second)))))))
    (cond
      ((null sn)
       ;; cap rejection fires OUTSIDE the node lock (file lock discipline)
       (when continuation (funcall continuation nil nil))
       nil)
      (t
       (let ((req (dds.types:serialize-type-lookup-request
                   :writer-guid (%tl-writer-guid node) :sn sn
                   :instance-name (%tl-instance-name prefix)
                   :operation :get-types :type-ids hashes))
             (hp (%remote-metatraffic node prefix)))
         (when hp
           ;; per-call buffer: queries fire from ANY thread (the type-gate uses the receiver thread), so the announce thread's tx-msg would race
           (let ((buf (dds.core.buffer:make-octet-buffer (+ 64 (length req)))))
             (unwind-protect
                  (%send-msg-buf node buf
                                 (lambda (mc)
                                   (dds.rtps.message:write-data
                                    mc +entityid-tl-req-reader+ +entityid-tl-req-writer+
                                    sn req 0 (length req)))
                                 (car hp) (cdr hp))
               (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))))))
       t))))

(defun* tl-sweep (node)
    (function (disc-node) (eql t))
  "Expire every pending TypeLookup request whose deadline has passed: remove it
   under the node lock, then call its continuation OUTSIDE the lock with (NIL NIL).
   Driven from the periodic announce loop (announce-endpoints)."
  (let ((now (%tl-now)) (expired '()))
    (dds.pal:with-lock ((disc-node-lock node))
      (let ((sns '()))
        (loop for sn being the hash-keys of (disc-node-tl-pending node)
                using (hash-value e)
              when (> now (tl-pending-entry-deadline e))
                do (push sn sns) (push e expired))
        (dolist (sn sns) (remhash sn (disc-node-tl-pending node)))))
    (dolist (e expired)
      (when (tl-pending-entry-continuation e)
        ;; expiry continuations fire OUTSIDE the node lock (file lock discipline)
        (funcall (tl-pending-entry-continuation e) nil nil))))
  t)
