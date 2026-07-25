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
   while the cadence already beats the lease.

   T11 (DDS-Security 1.1 §8.4.1.6): when this participant protects liveliness
   (%secure-pm-active-p — governance liveliness_protection_kind != NONE) EVERY assertion
   instead rides the secure BuiltinParticipantMessageSecureWriter (0xff0200c2),
   submessage-protected, to the :authenticated peers ONLY (%announce-secure-liveliness),
   and the plain WLP below is SUPPRESSED — a confidential liveliness assertion must never
   ride plain (mirrors the secure SEDP off-plain partition). NONE (the default) keeps the
   plain WLP path, byte-identical."
  (if (%secure-pm-active-p node)
      (%announce-secure-liveliness node)   ; T11: secure WLP over 0xff0200 (off plain); no-op until a peer is :keyed
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
                      (%send-pm-assertion node kind host port))))))))))
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

(defun* %liveliness-kind-for (qos-kind)
    (function (symbol) (or null (unsigned-byte 32)))
  "The ParticipantMessageData kind that carries a matched writer's LIVELINESS QoS kind
   over this protocol (RTPS 2.5 §8.4.13.5): :automatic -> +pmd-kind-automatic+,
   :manual-by-participant -> +pmd-kind-manual-by-participant+. :manual-by-topic is NOT
   carried here (§8.7.2.2.3) and answers NIL (no protocol stamp gates it)."
  (case qos-kind
    (:automatic dds.rtps.discovery:+pmd-kind-automatic+)
    (:manual-by-participant dds.rtps.discovery:+pmd-kind-manual-by-participant+)
    (t nil)))

(defun* %lease-seconds (duration)
    (function (dds.qos:qos-duration) integer)
  "A matched writer's offered LIVELINESS lease_duration as whole seconds (the granularity
   %lease-stale-p compares against), rounding the sub-second nanosec part up so a fresh
   assertion within the lease is never prematurely judged stale (RTPS 2.5 §8.4.13)."
  (+ (dds.qos:qos-duration-sec duration)
     (if (plusp (dds.qos:qos-duration-nanosec duration)) 1 0)))

(defun* %fire-liveliness-changed (node guid alive-p)
    (function (disc-node (simple-array (unsigned-byte 8) (16)) t) t)
  "Invoke the ON-LIVELINESS-CHANGED hook (if installed) OUTSIDE the node lock for a
   matched remote writer GUID whose liveliness crossed alive<->not-alive (RTPS 2.5
   §8.4.13 / DDS 1.4 §2.2.4.1). ALIVE-P is the NEW state."
  (when (disc-node-on-liveliness-changed node)
    (funcall (disc-node-on-liveliness-changed node) guid alive-p))
  t)

(defun* %matched-writer-alive-p (node remote now)
    (function (disc-node dds.rtps.discovery:endpoint-data (integer 0)) t)
  "Whether matched remote writer REMOTE is currently asserting liveliness (RTPS 2.5
   §8.4.13): T iff a liveliness assertion of REMOTE's offered LIVELINESS kind has been
   received from its participant within REMOTE's offered lease_duration. A writer with an
   infinite lease, or a MANUAL_BY_TOPIC writer (not carried by this protocol), is treated
   as always alive (no protocol stamp can mark it stale). CALLER HOLDS the node lock."
  (let* ((qos (dds.rtps.discovery:endpoint-data-qos remote))
         (kind (%liveliness-kind-for (dds.qos:qos-liveliness qos))))
    (if (null kind)
        ;; MANUAL_BY_TOPIC: the PM protocol does not carry it, but the writer DOES assert by writing
        ;; (§8.4.13), and %deliver-user-sample stamps each inbound sample. Age that stamp against the
        ;; offered lease exactly as the PM path does. Previously this returned T unconditionally, which
        ;; made such a writer immortal: it could never be reported not-alive, so LIVELINESS_CHANGED was
        ;; inert for the one kind whose liveliness a reader can actually observe directly.
        (let ((lease (%lease-seconds (dds.qos:qos-liveliness-lease qos)))
              (stamp (gethash (dds.rtps.discovery:endpoint-data-guid remote)
                              (disc-node-writer-data-stamp node))))
          (cond ((>= lease #x7fffffff) t)   ; infinite lease -> always alive, as for the PM kinds
                ;; No sample yet: a freshly matched writer has not had a chance to assert, and calling
                ;; it not-alive here would fire a spurious NOT_ALIVE on every match. Alive until it
                ;; has actually been given the chance and missed it.
                ((null stamp) t)
                (t (not (%lease-stale-p stamp lease now)))))
        (let ((lease (%lease-seconds (dds.qos:qos-liveliness-lease qos)))
              (prefix (subseq (dds.rtps.discovery:endpoint-data-guid remote) 0 12))
              (stamp nil))
          (setf stamp (gethash (cons prefix kind) (disc-node-remote-liveliness node)))
          (cond ((>= lease #x7fffffff) t)        ; infinite lease -> always alive
                ((null stamp) nil)               ; never asserted -> not alive
                (t (not (%lease-stale-p stamp lease now))))))))

(defun* %liveliness-sweep (node)
    (function (disc-node) (eql t))
  "Reader-side Writer Liveliness timing (RTPS 2.5 §8.4.13, DDS 1.4 §2.2.4.1): on the
   announce cadence, for every MATCHED remote WRITER decide alive vs not-alive from the
   latest inbound liveliness assertion of the writer's offered LIVELINESS kind against
   that writer's offered lease_duration (%matched-writer-alive-p). Fire ON-LIVELINESS-
   CHANGED only on a TRANSITION (LIVELINESS-STATE flips), so the DCPS LIVELINESS_CHANGED
   status counts each alive<->not-alive crossing once, never every sweep. Transitions are
   collected under the node lock and the hook fired OUTSIDE it (a listener must never
   deadlock the receiver). Idempotent between transitions."
  (let ((transitions '()))
    (dds.pal:with-lock ((disc-node-lock node))
      (let ((now (%lease-now)) (seen '()))
        (maphash
         (lambda (guid remote)
           (when (%writer-guid-p guid)
             (push guid seen)
             (let* ((alive (%matched-writer-alive-p node remote now))
                    (prev (multiple-value-bind (v present)
                              (gethash guid (disc-node-liveliness-state node))
                            (if present v t))))   ; a freshly matched writer starts ALIVE
               (unless (eq alive prev)
                 (push (cons (copy-seq guid) alive) transitions))
               (setf (gethash (copy-seq guid) (disc-node-liveliness-state node)) alive))))
         (disc-node-matches node))
        ;; Drop liveliness-state for writers no longer matched (lease-swept) so a
        ;; re-match restarts at ALIVE rather than inheriting a stale NOT_ALIVE flag.
        (let ((stale '()))
          (maphash (lambda (guid v)
                     (declare (ignore v))
                     (unless (member guid seen :test #'equalp) (push guid stale)))
                   (disc-node-liveliness-state node))
          (dolist (guid stale)
            (remhash guid (disc-node-liveliness-state node))
            ;; Drop the MANUAL_BY_TOPIC data stamp with it, for the same reason and one more: a
            ;; re-matched writer must not inherit a stale assertion and be judged alive on evidence
            ;; from its previous incarnation, and without this the table grows without bound against a
            ;; peer that churns endpoints.
            (remhash guid (disc-node-writer-data-stamp node))))))
    (dolist (tr transitions) (%fire-liveliness-changed node (car tr) (cdr tr)))
    t))

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
