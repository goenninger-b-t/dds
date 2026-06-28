;;;; L5 — Secure SEDP builtin endpoints (DDS-Security 1.1 §7.4.5 / §8.4.1.6 / §9.4.1.2.3;
;;;; M7/P6 Slice 4 T9). When the effective governance protects discovery
;;;; (discovery_protection_kind != NONE) AND a topic's rule sets enable_discovery_protection,
;;;; that topic's DiscoveredWriterData / DiscoveredReaderData flows ONLY over the SECURE SEDP
;;;; builtin endpoints (EntityIds 0xff0003c2/c7 publications, 0xff0004c2/c7 subscriptions),
;;;; submessage-PROTECTED (ENCRYPT) with the matched-remote EntityCrypto, and is NEVER announced
;;;; over plain SEDP — so a peer that is not :keyed (cannot decode) never learns the protected
;;;; endpoint. This mirrors the plain SEDP announce/parse/match path (disc.lisp), wrapping each
;;;; SEDP DATA submessage in the T2 submessage-protection codec before send and recovering it
;;;; before the existing parse + RxO/gate-ladder match.
;;;;
;;;; CROSS-LAYER INSTALL (the T7/T8 pattern). dds-dcps (which owns the crypto-manager + governance)
;;;; depends on dds-disc, not the reverse, so the disc layer cannot import them. Instead dds-dcps
;;;; INSTALLS three closures onto the disc-node (all NIL = security OFF, byte-identical plain SEDP):
;;;;   SECURE-SEDP-ENCODE-KM  (entity-id -> local secure-SEDP EntityCrypto §9.5.2 KM | nil) — the
;;;;     crypto-manager's cm-encode-entity-km; the ENCODE source for a protected announce.
;;;;   SECURE-SEDP-DECODE-KM  (4-octet transformation_key_id -> remote secure-SEDP EntityCrypto | nil)
;;;;     — the crypto-manager's cm-decode-entity-km-by-key-id; BOTH the inbound discriminator AND the
;;;;     DECODE source.
;;;;   DISCOVERY-PROTECTED-TOPIC-P (topic-name -> boolean) — governance topic-discovery-protected-p;
;;;;     routes a topic off plain SEDP onto the secure endpoints; being non-NIL marks secure discovery
;;;;     active so %node-spdp-data advertises BuiltinEndpointSet bits 16-19.
;;;;
;;;; SEC_PREFIX DISAMBIGUATION (the T7 carry). T7 routed EVERY SEC_PREFIX (0x31) bracket to the PVMS
;;;; handler. Now secure-SEDP submessages ALSO arrive as SEC_PREFIX brackets, so %on-secure-submessage
;;;; disambiguates by the wire §9.5.3.3.1 CryptoHeader transformation_key_id: if the secure-SEDP DECODE
;;;; resolver maps it to a remote EntityCrypto -> the secure-SEDP receive path; else -> the PVMS handler
;;;; (whose §9.5.3.1 bootstrap KM has an all-zero sender_key_id that never lands in the EntityCrypto index,
;;;; so a PVMS bracket always falls through here). Each handler then verifies the RECOVERED inner writerId
;;;; (secure-SEDP pub/sub writer vs PVMS writer) and fails CLOSED on any mismatch.
;;;;
;;;; SECURITY POSTURE (NFR-SEC-POSTURE / operating contract §4). Inbound is FAIL-CLOSED: a missing KM,
;;;; an undecryptable / malformed / truncated / tampered bracket, a wrong-EntityId inner DATA, or an
;;;; unparseable endpoint-data -> a silent DROP (no match on unverified data, never a signal out of the
;;;; receiver thread, never plaintext on failure). Every field is bounds-checked (the T2 codec + the
;;;; inner header reads). Each EntityCrypto KM is INDEPENDENT per endpoint (unlike the symmetric PVMS
;;;; bootstrap KM), so the default +fixed-session-id+ is safe — there is no shared-key nonce-reuse hazard.
;;;;
;;;; Control-plane only (discovery): per-announce heap allocation is intentional, mirroring
;;;; stateless-message.lisp / volatile-secure.lisp (the steady-state user-data hot path is untouched).

(in-package #:dds.disc)

;;; --- inbound: SEC_PREFIX bracket discriminator + receive ---

(defun* %secure-bracket-key-id (bracket)
    (function ((simple-array (unsigned-byte 8) (*))) (or null (simple-array (unsigned-byte 8) (4))))
  "The 4-octet §9.5.3.3.1 CryptoHeader transformation_key_id of a SEC_PREFIX bracket BRACKET, at offset
   [8,12): the 4-octet SEC_PREFIX SubmessageHeader (RTPS 2.5 §9.4.5.1) + the CryptoHeader's
   transformation_kind[4] then transformation_key_id[4] (the same offset T8's %pvms-wire-session-id pins
   for session_id at [12,16)). Returns a FRESH 4-octet copy, or NIL when BRACKET is too short to hold it
   — a fail-closed bounds-check before any trust in wire data (NFR-SEC-POSTURE, even at (safety 0))."
  (when (>= (length bracket) 12)
    (subseq bracket 8 12)))

(defun* %on-secure-builtin (node src-prefix bracket km my-receiver-key-id my-receiver-key)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*))
               dds.security:key-material
               (or null (simple-array (unsigned-byte 8) (*)))
               (or null (simple-array (unsigned-byte 8) (*)))) t)
  "Receiver thread: a secure BUILTIN SEC_PREFIX...SEC_POSTFIX bracket from remote SRC-PREFIX, whose
   transformation_key_id already resolved to the remote secure-builtin-writer EntityCrypto KM. Recover the
   plaintext DATA submessage (the T2/T3 codec decode-datawriter-submessage, DDS-Security 1.1 §8.5.1.7) and ROUTE
   by the recovered INNER writerId (T9 + T11), each path verifying its own writerId, fail-closed on a mismatch:
     publications 0xff0003c2  -> a DiscoveredWriterData: parse-endpoint-data, record, %match-remote-writer (T9);
     subscriptions 0xff0004c2 -> a DiscoveredReaderData: parse-endpoint-data, record, %match-remote-reader (T9);
     participant-message 0xff0200c2 -> a ParticipantMessageData liveliness assertion: the EXISTING WLP handler
       %on-participant-message, keyed by the datagram SRC-PREFIX (anti-spoof — the stamp is keyed by the verified
       SENDER, not the message's self-reported guid) (T11);
     SPDP 0xff0101c2 -> a re-announced ParticipantBuiltinTopicData: parse-spdp-data, %record-participant (T11);
     any other inner writerId -> DROP (fail-closed).
   ORIGIN AUTH (§9.5.3.3.4.3, T-ORIGINAUTH): when MY-RECEIVER-KEY-ID is non-NIL (the local receiving READER
   EntityCrypto carries a receiver-specific key — origin-auth in effect for this tier), decode-datawriter-submessage
   ALSO verifies THIS receiver's entry in the CryptoFooter receiver_specific_macs under MY-RECEIVER-KEY and fails
   closed (no plaintext) if it is absent or mismatched — even when the common_mac is valid. Both NIL = no origin-auth
   (the common_mac alone governs; byte-identical to the non-origin-auth path). FAIL-CLOSED (NFR-SEC-POSTURE): an
   undecryptable/malformed/truncated/tampered bracket, a wrong/absent inner writerId, a missing/forged receiver-MAC,
   or an unparseable inner data -> a silent DROP (no match/assert/record on unverified data — a tampered liveliness
   assertion never asserts liveliness, a forged secure SPDP never registers a participant — no signal out, no
   plaintext on failure). The SEDP match hooks fire OUTSIDE the node lock (the recorded-endpoint write is the only
   locked region — mirrors %handle-datagram)."
  (block %on-builtin
    (let ((plain (dds.security:decode-datawriter-submessage
                  km bracket :my-receiver-key-id my-receiver-key-id :my-receiver-key my-receiver-key)))
      (unless (and plain (>= (length plain) 4)) (return-from %on-builtin t))   ; auth/parse fail -> drop
      ;; PLAIN is a complete DATA submessage (header + body) built with write-data (E=1 LE).
      (let ((cur (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over plain) :endianness :little)))
        (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header cur)
          (unless (and id (= id dds.rtps.message:+submsg-data+)) (return-from %on-builtin t))
          (dds.core.buffer:cursor-set-endianness cur (if le :little :big))
          (multiple-value-bind (rdr wid sn has-payload poff plen)
              (dds.rtps.message:parse-data-body cur flags octets)
            (declare (ignore rdr))
            (unless (and has-payload (plusp plen)) (return-from %on-builtin t))
            (cond
              ;; secure SEDP (T9): the payload is the PL_CDR ParameterList (encap header + endpoint-data), like plain SEDP.
              ((or (= wid dds.rtps.discovery:+entityid-sedp-pub-secure-writer+)
                   (= wid dds.rtps.discovery:+entityid-sedp-sub-secure-writer+))
               (let ((role (if (= wid dds.rtps.discovery:+entityid-sedp-pub-secure-writer+) :writer :reader))
                     (pc (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over plain) :endianness :little)))
                 (dds.core.buffer:cursor-set-position pc poff)
                 (dds.cdr:parse-encapsulation-header pc)
                 (let ((ep (dds.rtps.discovery:parse-endpoint-data pc role)))
                   (when ep
                     (if (eq role :writer)
                         (progn
                           (dds.pal:with-lock ((disc-node-lock node))
                             (%record-discovered (disc-node-discovered-writers node) ep))
                           (%match-remote-writer node ep))
                         (progn
                           (dds.pal:with-lock ((disc-node-lock node))
                             (%record-discovered (disc-node-discovered-readers node) ep))
                           (%match-remote-reader node ep)))))))
              ;; secure participant-message (T11): hand the inner DATA to the EXISTING WLP handler (keyed by SRC-PREFIX).
              ((= wid dds.rtps.discovery:+entityid-participant-message-secure-writer+)
               (%on-participant-message node src-prefix wid sn
                                        (dds.core.buffer:octet-buffer-over plain) poff plen))
              ;; secure SPDP re-announce (T11): the payload is the PL_CDR SPDP ParameterList (encap header + spdp-data).
              ((= wid dds.rtps.discovery:+entityid-spdp-secure-writer+)
               (let ((pc (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over plain) :endianness :little)))
                 (dds.core.buffer:cursor-set-position pc poff)
                 (dds.cdr:parse-encapsulation-header pc)
                 (let ((spdp (dds.rtps.discovery:parse-spdp-data pc)))
                   (when spdp (%record-participant node spdp)))))
              (t nil)))))))   ; not a secure builtin writer -> drop (fail-closed)
  t)

(defun* %on-secure-submessage (node src-prefix bracket)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*))) t)
  "Receiver-thread DISPATCH for ONE inbound SEC_PREFIX...SEC_POSTFIX submessage-protection bracket from
   SRC-PREFIX (DDS-Security 1.1 §8.5.1.7). The SAME submessage id (0x31) carries the reliable PVMS crypto-token
   exchange (T7), the secure SEDP DiscoveredWriter/ReaderData (T9), AND the secure participant-message (liveliness)
   + secure SPDP re-announce (T11), so disambiguate by the wire §9.5.3.3.1 CryptoHeader transformation_key_id
   (%secure-bracket-key-id): if the installed secure-builtin DECODE resolver maps it to a remote EntityCrypto ->
   %on-secure-builtin (which decodes then routes by the recovered inner writerId to SEDP-match / liveliness /
   record-participant, each verifying its own writerId); else -> %on-volatile-secure (PVMS, which resolves its
   §9.5.3.1 bootstrap KM by SRC-PREFIX — that KM's sender_key_id is all-zeros and never lands in the EntityCrypto
   index, so a PVMS bracket always falls through here). Security OFF / pre-keyed (no resolver, or a key_id it does
   not know) -> the bracket goes to PVMS, exactly as before T9. Fail-closed throughout: each downstream handler
   drops an undecryptable/wrong-writerId bracket.
   ORIGIN AUTH (T-ORIGINAUTH): when the secure-builtin path is taken, also resolve the LOCAL receiving READER's
   receiver descriptor (key_id . key) for this bracket's channel via SECURE-SEDP-DECODE-RECEIVER-KM — which maps the
   wire key_id -> the remote sender's entity-id -> the matching local reader's receiver key, covering EVERY secure
   builtin tier (SEDP/PM/SPDP), NIL when origin-auth is not in effect — and pass it to %on-secure-builtin so the
   receiver-specific MAC is verified (§9.5.3.3.4.3). NIL -> no origin-auth verification (the common_mac alone governs)."
  (let* ((resolver (disc-node-secure-sedp-decode-km node))
         (recvres  (disc-node-secure-sedp-decode-receiver-km node))
         (key-id   (%secure-bracket-key-id bracket))
         (km       (and resolver key-id (funcall resolver key-id))))
    (if km
        (let ((rd (and recvres key-id (funcall recvres key-id))))   ; (key_id . key) | nil
          (%on-secure-builtin node src-prefix bracket km (car rd) (cdr rd)))
        (%on-volatile-secure node src-prefix bracket)))
  t)

;;; --- outbound: build + protect + announce a secure SEDP endpoint ---

(defun* %build-secure-data-submessage (reader-id writer-id sn payload pstart plen)
    (function ((unsigned-byte 32) (unsigned-byte 32) integer (simple-array (unsigned-byte 8) (*))
               (integer 0) (integer 0))
              (simple-array (unsigned-byte 8) (*)))
  "Wrap the SerializedPayload PAYLOAD[PSTART,PSTART+PLEN) in a PLAINTEXT DATA submessage (RTPS 2.5 §9.4.5.4)
   with READER-ID/WRITER-ID and writerSN SN (E=1 little-endian) — the PLAIN-SUBMESSAGE region the T2 submessage
   codec then protects. Returned as a fresh exact-length octet vector. The shared DATA-wrapping tail of EVERY
   secure builtin announce (secure SEDP / participant-message / SPDP — DRY, T11); the off-heap scratch buffer
   (control-plane) is freed before return."
  (let* ((dbuf (dds.core.buffer:make-octet-buffer (+ 64 plen)))
         (dc   (dds.core.buffer:cursor dbuf :endianness :little)))
    (unwind-protect
         (progn
           (dds.rtps.message:write-data dc reader-id writer-id sn payload pstart plen)
           (subseq (dds.core.buffer:octet-buffer-vec dbuf) 0 (dds.core.buffer:cursor-position dc)))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec dbuf)))))

(defun* %build-secure-sedp-data (reader-id writer-id sn ep)
    (function ((unsigned-byte 32) (unsigned-byte 32) integer dds.rtps.discovery:endpoint-data)
              (simple-array (unsigned-byte 8) (*)))
  "Build the PLAINTEXT secure SEDP DATA submessage (RTPS 2.5 §9.4.5.4) carrying EP's DiscoveredWriter/
   ReaderData: a PL_CDR_LE SerializedPayload (encapsulation header + serialize-endpoint-data, IDENTICAL to
   the plain SEDP %send-paramlist payload) wrapped (%build-secure-data-submessage) in a DATA submessage with
   the SECURE SEDP reader/writer EntityIds READER-ID/WRITER-ID and writerSN SN. Returned as a fresh exact-length
   octet vector — the PLAIN-SUBMESSAGE region the T2 submessage codec then protects. The off-heap payload scratch
   buffer (control-plane) is freed before return."
  (let* ((ti  (dds.rtps.discovery:endpoint-data-type-information ep))
         (cap (+ 256 (* 2 (+ (length (dds.rtps.discovery:endpoint-data-topic-name ep))
                             (length (dds.rtps.discovery:endpoint-data-type-name ep))))
                 (if ti (length ti) 0)))
         (plbuf (dds.core.buffer:make-octet-buffer cap))
         (pc    (dds.core.buffer:cursor plbuf :endianness :little)))
    (unwind-protect
         (progn
           (dds.cdr:make-encapsulation-header pc :pl-cdr-le)
           (dds.rtps.discovery:serialize-endpoint-data pc ep)
           (%build-secure-data-submessage reader-id writer-id sn
                                          (dds.core.buffer:octet-buffer-vec plbuf) 0
                                          (dds.core.buffer:cursor-position pc)))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec plbuf)))))

(defun* %send-secure-bracket (node km kind plain receivers host port)
    (function (disc-node dds.security:key-material (member :sign :encrypt)
               (simple-array (unsigned-byte 8) (*)) list string (unsigned-byte 16)) t)
  "Submessage-PROTECT one PLAINTEXT DATA submessage PLAIN under the LOCAL secure-builtin EntityCrypto KM per the
   governance-EFFECTIVE KIND (the T2/T3 codec encode-datawriter-submessage, DDS-Security 1.1 §8.5.1.7) and send
   the SEC_PREFIX ... SEC_POSTFIX bracket as ONE datagram to HOST:PORT. :encrypt -> SEC_PREFIX ‖ CryptoHeader ‖
   SEC_BODY[ciphertext] ‖ SEC_POSTFIX (the plaintext is HIDDEN, §9.4.1.2.3 ENCRYPT); :sign -> SEC_PREFIX ‖
   CryptoHeader ‖ the DATA submessage VERBATIM ‖ SEC_POSTFIX[GMAC] (authenticated-but-VISIBLE, §9.4.1.2.3 SIGN).
   KIND is the node's installed governance-EFFECTIVE base kind (HONORING the directive, never a hardcoded
   ENCRYPT). RECEIVERS is the origin-authentication receiver list (§9.5.3.3.4.3, T-ORIGINAUTH); EMPTY (the
   default for a non-origin-auth kind) emits no receiver-specific MAC (plain SIGN/ENCRYPT, byte-identical).
   Default session_id is safe (each EntityCrypto KM is INDEPENDENT per endpoint — no symmetric-key nonce hazard,
   unlike PVMS). The shared PROTECT+SEND tail of every secure builtin announce (SEDP / participant-message /
   SPDP — DRY, T11). A no-op (still T) if the codec returns NIL. Fresh per-call buffer (control-plane), freed."
  (let ((secured (dds.security:encode-datawriter-submessage km kind plain :receivers receivers)))
    (when secured
      (let ((buf (dds.core.buffer:make-octet-buffer (+ 64 (length secured)))))
        (unwind-protect
             (%send-msg-buf node buf
                            (lambda (mc) (dds.core.buffer:put-octets mc secured 0 (length secured)))
                            host port)
          (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))))))
  t)

(defun* %send-secure-endpoint (node km kind reader-id writer-id ep sn host port receivers)
    (function (disc-node dds.security:key-material (member :sign :encrypt) (unsigned-byte 32) (unsigned-byte 32)
               dds.rtps.discovery:endpoint-data integer string (unsigned-byte 16) list) t)
  "Announce ONE local endpoint EP over the SECURE SEDP writer WRITER-ID to HOST:PORT: build the plaintext
   SEDP DATA submessage (%build-secure-sedp-data) with the STABLE per-writer SN, then submessage-PROTECT + send
   it (%send-secure-bracket) under the LOCAL secure-SEDP EntityCrypto KM per the governance-EFFECTIVE KIND
   (RECEIVERS = the matched-remote READER's origin-auth descriptors, §9.5.3.3.4.3 / T-ORIGINAUTH). Re-announcing
   an endpoint RESENDS the same SN (a retransmission), like plain SEDP %send-endpoint, so a reliable peer never
   gaps. A no-op (still T) if the codec returns NIL."
  (%send-secure-bracket node km kind (%build-secure-sedp-data reader-id writer-id sn ep) receivers host port))

(defun* %secure-endpoints-for (node protp accessor)
    (function (disc-node function function) list)
  "The discovery-PROTECTED local endpoints (those whose topic name PROTP marks protected) drawn from
   (ACCESSOR NODE) (disc-node-local-writers or -readers), in stable ADD-ORDER (reverse of the push list) so
   each endpoint's 1-based index in the returned list is its FIXED per-writer SN (RTPS 2.5 §8.5.4 — a
   protected endpoint resends a stable SN). The complement (unprotected endpoints) is what announce-endpoints
   sends over PLAIN SEDP, so the two partitions are disjoint and a protected topic is never announced plainly."
  (remove-if-not (lambda (ep) (funcall protp (dds.rtps.discovery:endpoint-data-topic-name ep)))
                 (reverse (funcall accessor node))))

(defun* %announce-secure-endpoints (node)
    (function (disc-node) (eql t))
  "Announce NODE's discovery-PROTECTED local publications/subscriptions over the SECURE SEDP endpoints to
   every :authenticated peer (DDS-Security 1.1 §7.4.5 / §8.4.1.6; T9). For each protected local writer/reader
   (selected by the installed DISCOVERY-PROTECTED-TOPIC-P), submessage-PROTECT its DiscoveredWriter/ReaderData
   under the LOCAL secure-SEDP-writer EntityCrypto (SECURE-SEDP-ENCODE-KM) per the installed governance base
   kind SECURE-SEDP-PROTECTION-KIND (:sign authenticated-but-visible | :encrypt confidential — HONORING the
   §9.4.1.2.3 discovery_protection_kind, never a hardcoded ENCRYPT) and send it over the secure
   publications (0xff0003c2) / subscriptions (0xff0004c2) writer to each authenticated peer's metatraffic
   locator. A no-op (still T) when secure discovery is not active (no encode-KM or no protected-topic
   predicate installed), when the local EntityCrypto is not yet registered, or when there are no protected
   endpoints / no authenticated peers — so security OFF is byte-identical (nothing sent over secure SEDP).
   Fanned over %pvms-authenticated-prefixes (the secure peers — the same set PVMS drives); a peer that is not
   yet :keyed cannot decode and drops it (fail-closed), and the next announce cadence re-delivers (reliable
   re-announce, like plain SEDP). The protected endpoints are NOT also sent over plain SEDP (announce-endpoints
   sends only the unprotected complement plainly)."
  (let ((enc   (disc-node-secure-sedp-encode-km node))
        (recv  (disc-node-secure-sedp-encode-receivers node))   ; T-ORIGINAUTH: per-peer receiver descriptors | nil
        (protp (disc-node-discovery-protected-topic-p node))
        (kind  (disc-node-secure-sedp-protection-kind node)))   ; governance-EFFECTIVE base kind (SIGN | ENCRYPT)
    (when (and enc protp)
      (let ((sec-writers (%secure-endpoints-for node protp #'disc-node-local-writers))
            (sec-readers  (%secure-endpoints-for node protp #'disc-node-local-readers))
            (wkm (funcall enc dds.rtps.discovery:+entityid-sedp-pub-secure-writer+))
            (rkm (funcall enc dds.rtps.discovery:+entityid-sedp-sub-secure-writer+)))
        (when (or (and sec-writers wkm) (and sec-readers rkm))
          (dolist (prefix (%pvms-authenticated-prefixes node))
            (let ((hp (%remote-metatraffic node prefix)))
              (when hp
                ;; T-ORIGINAUTH: the matched-remote READER's receiver descriptors are PER-PEER + per-channel
                ;; (the pub-secure-writer announces to the peer's pub-secure-reader; sub to sub) — resolve once
                ;; per (peer, channel), shared by every endpoint in the channel's loop. NIL when not origin-auth.
                (when wkm
                  (let ((wreceivers (and recv (funcall recv
                                                       dds.rtps.discovery:+entityid-sedp-pub-secure-writer+
                                                       prefix))))
                    (loop for w in sec-writers for wsn from 1 do
                      (%send-secure-endpoint node wkm kind
                                             dds.rtps.discovery:+entityid-sedp-pub-secure-reader+
                                             dds.rtps.discovery:+entityid-sedp-pub-secure-writer+
                                             w wsn (car hp) (cdr hp) wreceivers))))
                (when rkm
                  (let ((rreceivers (and recv (funcall recv
                                                       dds.rtps.discovery:+entityid-sedp-sub-secure-writer+
                                                       prefix))))
                    (loop for r in sec-readers for rsn from 1 do
                      (%send-secure-endpoint node rkm kind
                                             dds.rtps.discovery:+entityid-sedp-sub-secure-reader+
                                             dds.rtps.discovery:+entityid-sedp-sub-secure-writer+
                                             r rsn (car hp) (cdr hp) rreceivers)))))))))))
  t)

;;; --- T11: secure participant-message (Writer Liveliness Protocol) over 0xff0200 ---

(defun* %announce-secure-liveliness (node)
    (function (disc-node) (eql t))
  "Assert this participant's Writer Liveliness over the SECURE BuiltinParticipantMessageSecureWriter (0xff0200c2)
   to every :authenticated peer (DDS-Security 1.1 §8.4.1.6 / §7.4.5; T11) — the secure analogue of
   assert-participant-liveliness's plain path, called BY it when liveliness is protected (%secure-pm-active-p).
   For each liveliness kind the local writers require (%local-liveliness-kinds), build the ParticipantMessageData
   SerializedPayload (%pm-serialized-payload, the SAME bytes as plain WLP) wrapped in a secure-PM DATA submessage
   and submessage-PROTECT + send it (%send-secure-bracket) under the LOCAL secure-PM-writer EntityCrypto
   (SECURE-SEDP-ENCODE-KM — the GENERIC secure-builtin resolver) per the governance-EFFECTIVE base kind
   SECURE-PM-PROTECTION-KIND (:sign authenticated-but-visible | :encrypt confidential — HONORING the
   liveliness_protection_kind directive, never a hardcoded ENCRYPT). ORIGIN AUTH (§9.5.3.3.4.3, T-ORIGINAUTH):
   when a *_WITH_ORIGIN_AUTHENTICATION liveliness kind is in effect, SECURE-SEDP-ENCODE-RECEIVERS yields the
   matched-remote secure-PM READER's receiver descriptors for encode :receivers, so a per-receiver MAC is emitted;
   NIL otherwise (plain SIGN/ENCRYPT). A no-op (still T) when secure WLP is not active (no encode resolver, kind
   NONE, no protocol-carried-liveliness local writer, or no :authenticated peer) — so security OFF is byte-identical
   (nothing over secure PM). The secure-PM writer's SN space (SECURE-PM-WRITER-SN, distinct EntityId) is allocated
   under the node lock; the assertion is periodic + idempotent (keyed by sender+kind), so a missed one is re-sent on
   the next cadence (no per-reply resend store — mirrors secure SEDP)."
  (let ((enc   (disc-node-secure-sedp-encode-km node))
        (recv  (disc-node-secure-sedp-encode-receivers node))
        (kind  (disc-node-secure-pm-protection-kind node))
        (kinds (%local-liveliness-kinds node)))
    (when (and enc (not (eq kind :none)) kinds)
      (let ((wkm      (funcall enc dds.rtps.discovery:+entityid-participant-message-secure-writer+))
            (prefixes (%pvms-authenticated-prefixes node)))
        (when (and wkm prefixes)
          (dolist (k kinds)
            ;; one SN per kind per cadence (shared across peers — the secure-PM writer's own SN space)
            (let ((sn (dds.pal:with-lock ((disc-node-lock node))
                        (let ((s (disc-node-secure-pm-writer-sn node)))
                          (incf (disc-node-secure-pm-writer-sn node))
                          s))))
              (dolist (prefix prefixes)
                (let ((hp (%remote-metatraffic node prefix)))
                  (when hp
                    (let ((octets    (%pm-serialized-payload node k))
                          (receivers (and recv (funcall recv
                                                        dds.rtps.discovery:+entityid-participant-message-secure-writer+
                                                        prefix))))
                      (%send-secure-bracket
                       node wkm kind
                       (%build-secure-data-submessage
                        dds.rtps.discovery:+entityid-participant-message-secure-reader+
                        dds.rtps.discovery:+entityid-participant-message-secure-writer+
                        sn octets 0 (length octets))
                       receivers (car hp) (cdr hp))))))))))))
  t)

;;; --- T11: secure SPDP re-announce over 0xff0101 (protected ParticipantBuiltinTopicData; plain SPDP bootstraps) ---

(defun* %spdp-serialized-payload (node)
    (function (disc-node) (simple-array (unsigned-byte 8) (*)))
  "Build the SerializedPayload for the secure SPDP re-announce: a PL_CDR_LE encapsulation header + the
   SPDPdiscoveredParticipantData ParameterList (serialize-spdp-data over %node-spdp-data), IDENTICAL to the plain
   SPDP %send-paramlist payload — so %on-secure-builtin's SPDP branch parses it with the SAME
   parse-encapsulation-header + parse-spdp-data. Returned as a fresh exact-length octet vector; the off-heap
   scratch buffer (control-plane) is freed before return."
  (let* ((data (%node-spdp-data node))
         (tok  (dds.rtps.discovery:spdp-data-identity-token-octets data))
         (cap  (+ 1024 (if tok (* 2 (length tok)) 0)))
         (buf  (dds.core.buffer:make-octet-buffer cap))
         (pc   (dds.core.buffer:cursor buf :endianness :little)))
    (unwind-protect
         (progn
           (dds.cdr:make-encapsulation-header pc :pl-cdr-le)
           (dds.rtps.discovery:serialize-spdp-data pc data)
           (subseq (dds.core.buffer:octet-buffer-vec buf) 0 (dds.core.buffer:cursor-position pc)))
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf)))))

(defun* %announce-secure-spdp (node)
    (function (disc-node) (eql t))
  "Re-announce this participant's ParticipantBuiltinTopicData over the SECURE SPDPbuiltinParticipantSecureWriter
   (0xff0101c2) to every :authenticated peer (DDS-Security 1.1 §7.4.5 / §7.4.6.1; T11), submessage-PROTECTED. The
   PLAIN SPDP keeps bootstrapping (announce-participant always sends it — it carries the Identity/Permissions
   tokens a peer authenticates with); THIS is the additional protected re-announce over the secure channel AFTER
   keying. It rides the DISCOVERY protection tier (bits 26/27 are DISC_BUILTIN_ENDPOINT_PARTICIPANT_SECURE_*): gated
   on DISCOVERY-PROTECTED-TOPIC-P being non-NIL (= discovery protection active) and protected per
   SECURE-SEDP-PROTECTION-KIND (:sign | :encrypt, the governance discovery_protection_kind base — same as secure
   SEDP, HONORED not hardcoded), encoded under the LOCAL secure-SPDP-writer EntityCrypto (SECURE-SEDP-ENCODE-KM,
   the GENERIC secure-builtin resolver). ORIGIN AUTH (§9.5.3.3.4.3): SECURE-SEDP-ENCODE-RECEIVERS yields the
   matched-remote secure-SPDP READER's receiver descriptors when an *_WITH_ORIGIN_AUTHENTICATION discovery kind is
   in effect; NIL otherwise. A no-op (still T) when secure discovery is not active (no encode resolver / no
   protected-topic predicate), the local EntityCrypto is not yet registered, or there is no :authenticated peer —
   so security OFF is byte-identical (nothing over secure SPDP; the plain SPDP is unchanged). One SN per cadence
   (SECURE-SPDP-SN, the secure-SPDP writer's own space) under the node lock, shared across peers (mirrors plain
   SPDP's one sn per announce)."
  (let ((enc   (disc-node-secure-sedp-encode-km node))
        (recv  (disc-node-secure-sedp-encode-receivers node))
        (protp (disc-node-discovery-protected-topic-p node))   ; non-NIL = secure discovery active
        (kind  (disc-node-secure-sedp-protection-kind node)))
    (when (and enc protp)
      (let ((wkm (funcall enc dds.rtps.discovery:+entityid-spdp-secure-writer+)))
        (when wkm
          (let ((octets (%spdp-serialized-payload node))
                (sn     (dds.pal:with-lock ((disc-node-lock node))
                          (incf (disc-node-secure-spdp-sn node)))))
            (dolist (prefix (%pvms-authenticated-prefixes node))
              (let ((hp (%remote-metatraffic node prefix)))
                (when hp
                  (let ((receivers (and recv (funcall recv
                                                      dds.rtps.discovery:+entityid-spdp-secure-writer+
                                                      prefix))))
                    (%send-secure-bracket
                     node wkm kind
                     (%build-secure-data-submessage
                      dds.rtps.discovery:+entityid-spdp-secure-reader+
                      dds.rtps.discovery:+entityid-spdp-secure-writer+
                      sn octets 0 (length octets))
                     receivers (car hp) (cdr hp)))))))))))
  t)

;;; --- test (deterministic disc-level round-trip + confidentiality + plain-omission + non-secure control) ---

(defun* %secure-sedp-test-km (kid-byte fill)
    (function ((unsigned-byte 8) (unsigned-byte 8)) dds.security:key-material)
  "Test helper: a deterministic §9.5.2 AES256-GCM EntityCrypto KeyMaterial with a distinct NON-ZERO 4-octet
   sender_key_id (all = KID-BYTE) and 32-octet master_salt / master_sender_key derived from FILL — no random,
   no auth handshake (the full crypto-manager exchange is exercised by the dds-dcps e2e). Distinct KID-BYTEs
   give distinct transformation_key_ids so the decode resolver maps each remote KM unambiguously. Test-only."
  (dds.security:make-key-material
   :transformation-kind (copy-seq dds.security:+transformation-kind-aes256-gcm+)
   :master-salt         (make-array 32 :element-type '(unsigned-byte 8) :initial-element fill)
   :sender-key-id       (make-array 4 :element-type '(unsigned-byte 8) :initial-element kid-byte)
   :master-sender-key   (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element (logand (logxor fill #x5a) #xff))))

(defun* %datagram-secure-bracket-p (dg)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "T iff datagram DG's FIRST submessage (at offset 20, right after the 20-octet RTPS Header — 'RTPS'(4) +
   version(2) + vendorId(2) + guidPrefix(12), §9.4.4) is a SEC_PREFIX (0x31): a submessage-protection bracket
   on the wire. Used by the secure-SEDP round-trip test to prove a protected announce was emitted as a
   SEC_PREFIX bracket (not plaintext DATA)."
  (and (> (length dg) 20) (= (aref dg 20) dds.security:+submessage-sec-prefix+)))

(defun* %run-secure-sedp-roundtrip (kind)
    (function ((member :sign :encrypt)) (eql t))
  "Secure SEDP DiscoveredWriter/ReaderData round-trip at the disc layer under governance discovery protection
   KIND (:sign | :encrypt) (DDS-Security 1.1 §7.4.5 / §9.4.1.2.3; M7/P6 Slice 4 T9 + review) — deterministic,
   no auth handshake (manually-installed EntityCrypto KMs stand in for the dds-dcps crypto-manager; the full
   :keyed e2e is run-secure-discovery-protected-test / -sign-test). Three nodes discover over SPDP: A (writer)
   + B (reader) install the secure-SEDP closures + KIND for a PROTECTED topic and a (dummy) PVMS bootstrap KM
   for each other (so each is in the other's :authenticated set); C is a PLAIN control node (no secure closures)
   with a reader on the SAME protected topic. Asserts:
     (1) B MATCHES A's protected writer (and A matches B's protected reader) — A's writer is NOT on plain SEDP
         (omitted), so the ONLY path is the submessage-protected secure SEDP endpoint;
     (2) on-wire posture HONORS KIND: a SEC_PREFIX bracket WAS emitted (non-vacuous) AND — for :encrypt — the
         protected topic name NEVER appears in CLEARTEXT in any datagram A emits (confidentiality); for :sign
         the topic name IS visible but ONLY inside a SEC_PREFIX bracket (authenticated-but-visible, never plain
         SEDP), and it MUST appear at least once (proving we SIGNed, not silently ENCRYPTed — the review defect);
     (3) NON-VACUOUS control: the PLAIN peer C NEVER matches A's protected writer — a protected endpoint is
         invisible over plain SEDP to a peer that cannot decode the secure SEDP.
   Bounded; no unbounded wait. Requires the AES-GCM primitive (same as the volatile-secure tests)."
  (let* ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 51))
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 52))
         (pc (make-array 12 :element-type '(unsigned-byte 8) :initial-element 53))
         (node-a (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
         (node-b (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (node-c (make-disc-node :guid-prefix pc :host "127.0.0.1" :port 0))
         (topic "SecretSquare")
         (km-a-pub (%secure-sedp-test-km 1 #x11))   ; A's secure-SEDP publications-writer EntityCrypto
         (km-b-sub (%secure-sedp-test-km 2 #x22))   ; B's secure-SEDP subscriptions-writer EntityCrypto
         (topic-bytes (map '(simple-array (unsigned-byte 8) (*)) #'char-code topic))
         (captured '())
         (lk (dds.pal:make-lock "secure-sedp-test")))
    (unwind-protect
         (progn
           ;; install on A + B exactly what the dds-dcps crypto-manager/access-control install at :keyed
           (flet ((arm (node enc-eid enc-km dec-km)
                    (setf (disc-node-discovery-protected-topic-p node) (lambda (tn) (string= tn topic)))
                    (setf (disc-node-secure-sedp-protection-kind node) kind)   ; honor the governance kind
                    (setf (disc-node-secure-sedp-encode-km node)
                          (lambda (eid) (when (= eid enc-eid) enc-km)))
                    (setf (disc-node-secure-sedp-decode-km node)
                          (lambda (kid) (when (equalp kid (dds.security:key-material-sender-key-id dec-km)) dec-km)))))
             (arm node-a dds.rtps.discovery:+entityid-sedp-pub-secure-writer+ km-a-pub km-b-sub)
             (arm node-b dds.rtps.discovery:+entityid-sedp-sub-secure-writer+ km-b-sub km-a-pub))
           (add-local-writer node-a :topic topic :type "ShapeType" :reliability dds.rtps.discovery:+reliability-reliable+)
           (add-local-reader  node-b :topic topic :type "ShapeType" :reliability dds.rtps.discovery:+reliability-reliable+)
           (add-local-reader  node-c :topic topic :type "ShapeType" :reliability dds.rtps.discovery:+reliability-reliable+)
           (setf (disc-node-peers node-a) (list (cons "127.0.0.1" (disc-node-port node-b))
                                                (cons "127.0.0.1" (disc-node-port node-c))))
           (setf (disc-node-peers node-b) (list (cons "127.0.0.1" (disc-node-port node-a))))
           (setf (disc-node-peers node-c) (list (cons "127.0.0.1" (disc-node-port node-a))))
           (start-node node-a) (start-node node-b) (start-node node-c)
           (loop repeat 100
                 until (and (>= (disc-node-discovered-count node-a) 2)
                            (plusp (disc-node-discovered-count node-b))
                            (plusp (disc-node-discovered-count node-c)))
                 do (announce-participant node-a) (announce-participant node-b) (announce-participant node-c)
                    (sleep 0.02))
           (assert (>= (disc-node-discovered-count node-a) 2) () "secure-SEDP test: SPDP discovery incomplete")
           ;; (0) A advertises the secure SEDP BuiltinEndpointSet bits 16-19 (discovery protected); the plain C does NOT
           (let ((ep-a (dds.rtps.discovery:spdp-data-builtin-endpoint-set (%node-spdp-data node-a)))
                 (ep-c (dds.rtps.discovery:spdp-data-builtin-endpoint-set (%node-spdp-data node-c))))
             (assert (and (logtest ep-a dds.rtps.discovery:+be-sedp-pub-secure-writer+)
                          (logtest ep-a dds.rtps.discovery:+be-sedp-pub-secure-reader+)
                          (logtest ep-a dds.rtps.discovery:+be-sedp-sub-secure-writer+)
                          (logtest ep-a dds.rtps.discovery:+be-sedp-sub-secure-reader+)) ()
                     "A must OR BuiltinEndpointSet bits 16-19 into SPDP when discovery is protected")
             (assert (not (logtest ep-c dds.rtps.discovery:+be-sedp-pub-secure-writer+)) ()
                     "a plain (no discovery-protection) node must NOT advertise the secure SEDP bits (byte-identical)"))
           ;; mark A<->B :authenticated (dummy bootstrap KM puts each in the other's PVMS authenticated set,
           ;; the fan-out set %announce-secure-endpoints uses); C is NOT authenticated (the control).
           (set-pvms-bootstrap-km node-a pb (dds.security:make-key-material))
           (set-pvms-bootstrap-km node-b pa (dds.security:make-key-material))
           ;; capture every datagram A emits (confidentiality + plain-omission proof)
           (let ((*datagram-sink* (lambda (dg) (dds.pal:with-lock (lk) (push dg captured)))))
             (loop repeat 80
                   until (and (plusp (disc-node-matched-count node-a)) (plusp (disc-node-matched-count node-b)))
                   do (announce-endpoints node-a) (announce-endpoints node-b) (announce-endpoints node-c)
                      (announce-participant node-a) (sleep 0.02)))
           ;; (1) B matched A's protected writer over secure SEDP (A's writer is omitted from plain SEDP)
           (assert (plusp (disc-node-matched-count node-b)) ()
                   "secure SEDP failed: B did not match A's discovery-protected writer (the only path is secure SEDP)")
           (assert (member topic (disc-node-matched-topics node-b) :test #'string=) ()
                   "B matched the wrong topic (expected the protected ~a)" topic)
           (assert (plusp (disc-node-matched-count node-a)) ()
                   "secure SEDP failed: A did not match B's discovery-protected reader over secure SEDP")
           ;; (2) on-wire posture HONORS KIND: a SEC_PREFIX bracket WAS emitted; ENCRYPT hides the topic name
           ;;     (never cleartext), SIGN leaves it VISIBLE but ONLY inside a SEC_PREFIX bracket (never plain SEDP)
           ;;     and it MUST appear (proving SIGN, not a silent ENCRYPT — the review defect).
           (let ((sec-seen nil) (topic-in-bracket nil))
             (dds.pal:with-lock (lk)
               (dolist (dg captured)
                 (let ((bracketp (%datagram-secure-bracket-p dg))
                       (has-topic (search topic-bytes dg)))
                   (when bracketp (setf sec-seen t))
                   (ecase kind
                     (:encrypt
                      (assert (not has-topic) ()
                              "confidentiality breach: ENCRYPT secure SEDP leaked the protected topic name in CLEARTEXT"))
                     (:sign
                      (when has-topic
                        (assert bracketp ()
                                "SIGN secure SEDP put the protected topic on PLAIN SEDP (it must ride inside a SEC_PREFIX bracket)")
                        (setf topic-in-bracket t)))))))
             (assert sec-seen () "non-vacuous: no SEC_PREFIX bracket was emitted for the protected topic")
             (when (eq kind :sign)
               (assert topic-in-bracket ()
                       "SIGN secure SEDP never exposed the protected topic in cleartext — ENCRYPT was used instead of honoring SIGN")))
           ;; (3) NON-VACUOUS control: the plain peer C never matched A's protected writer
           (loop repeat 25 do (announce-endpoints node-a) (announce-endpoints node-c) (sleep 0.02))
           (assert (zerop (disc-node-matched-count node-c)) ()
                   "control breach: a plain (non-secure) peer matched a discovery-protected endpoint (~d) — it must be invisible over plain SEDP"
                   (disc-node-matched-count node-c))
           t)
      (stop-node node-a) (stop-node node-b) (stop-node node-c))))

(defun* run-secure-sedp-roundtrip-test ()
    (function () (eql t))
  "Secure SEDP round-trip under discovery_protection_kind = ENCRYPT (the confidential tier): the protected
   topic name is NEVER on the wire in cleartext. Delegates to %run-secure-sedp-roundtrip; see its contract."
  (%run-secure-sedp-roundtrip :encrypt))

(defun* run-secure-sedp-sign-roundtrip-test ()
    (function () (eql t))
  "Secure SEDP round-trip under discovery_protection_kind = SIGN (the authenticated-but-visible tier; the T9
   review conformance fix): the protected topic's DiscoveredWriter/ReaderData flows SIGNED over secure SEDP —
   a SEC_PREFIX bracket is emitted and the topic name IS visible (only inside the bracket, never plain SEDP),
   proving the announce HONORS SIGN instead of hardcoding ENCRYPT. Delegates to %run-secure-sedp-roundtrip."
  (%run-secure-sedp-roundtrip :sign))

;;; --- T-ORIGINAUTH: secure-SEDP origin-authentication wiring (the receiver-specific-MAC resolvers) ---

(defun* %run-secure-sedp-origin-auth (tamper-p)
    (function (t) (eql t))
  "Secure SEDP origin-authentication WIRING round-trip (DDS-Security 1.1 §9.5.3.3.4.3, discovery_protection_kind
   = ENCRYPT_WITH_ORIGIN_AUTHENTICATION; M7/P6 Slice 4 T-ORIGINAUTH) — deterministic, no auth handshake
   (manually-installed EntityCrypto KMs + receiver descriptors stand in for the dds-dcps crypto-manager; the
   full :keyed e2e is run-secure-discovery-origin-auth-test). Exercises the REAL announce/dispatch wiring: the
   installed SECURE-SEDP-ENCODE-RECEIVERS closure feeds encode-datawriter-submessage's :receivers and the
   SECURE-SEDP-DECODE-RECEIVER-KM closure feeds decode-datawriter-submessage's my-receiver-key. A (writer)
   announces a protected topic to B (reader) over the secure SEDP pub endpoint, computing a receiver-specific
   MAC under B-pub-reader's receiver key (rid . KGOOD); B verifies with its local receiver key.
   TAMPER-P NIL  -> B's receiver key is KGOOD -> the receiver-MAC verifies -> B MATCHES A's protected writer.
   TAMPER-P T    -> B's receiver key is the WRONG KBAD (same key_id) -> the receiver-MAC FAILS -> B NEVER
     matches, EVEN THOUGH the common_mac is valid (same sender KM) — proving origin-auth gates BEYOND the
     common_mac (the non-vacuous control). Bounded; requires the AES-GCM primitive (like the other secure tests)."
  (let* ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 71))
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 72))
         (node-a (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
         (node-b (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (topic "OriginSquare")
         (km-a-pub (%secure-sedp-test-km 1 #x11))   ; A's secure-SEDP publications-writer EntityCrypto (the sender)
         (km-b-sub (%secure-sedp-test-km 2 #x22))   ; B's secure-SEDP subscriptions-writer EntityCrypto
         (rid   (make-array 4 :element-type '(unsigned-byte 8) :initial-element #x5a))   ; B-pub-reader receiver_specific_key_id
         (kgood (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x3c))  ; B-pub-reader master_receiver_specific_key
         (kbad  (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x99))) ; a WRONG receiver key (SAME key_id)
    (unwind-protect
         (progn
           (flet ((arm (node enc-eid enc-km dec-km recv-key)
                    (setf (disc-node-discovery-protected-topic-p node) (lambda (tn) (string= tn topic)))
                    (setf (disc-node-secure-sedp-protection-kind node) :encrypt)   ; base kind of ENCRYPT_WITH_ORIGIN_AUTH
                    (setf (disc-node-secure-sedp-origin-auth node) t)
                    (setf (disc-node-secure-sedp-encode-km node)
                          (lambda (eid) (when (= eid enc-eid) enc-km)))
                    (setf (disc-node-secure-sedp-decode-km node)
                          (lambda (kid) (when (equalp kid (dds.security:key-material-sender-key-id dec-km)) dec-km)))
                    ;; encode-receivers: the matched-remote B-pub-reader descriptor for a pub-secure-writer announce
                    (setf (disc-node-secure-sedp-encode-receivers node)
                          (lambda (weid prefix)
                            (declare (ignore prefix))
                            (when (= weid dds.rtps.discovery:+entityid-sedp-pub-secure-writer+)
                              (list (cons rid kgood)))))
                    ;; decode-receiver: the LOCAL pub-reader's receiver descriptor (KGOOD = correct, KBAD = tampered)
                    (setf (disc-node-secure-sedp-decode-receiver-km node)
                          (lambda (kid) (declare (ignore kid)) (cons rid recv-key)))))
             ;; A always ENCODES the receiver-MAC under KGOOD; B VERIFIES with KGOOD (match) or KBAD (no match).
             (arm node-a dds.rtps.discovery:+entityid-sedp-pub-secure-writer+ km-a-pub km-b-sub kgood)
             (arm node-b dds.rtps.discovery:+entityid-sedp-sub-secure-writer+ km-b-sub km-a-pub
                  (if tamper-p kbad kgood)))
           (add-local-writer node-a :topic topic :type "ShapeType"
                             :reliability dds.rtps.discovery:+reliability-reliable+)
           (add-local-reader  node-b :topic topic :type "ShapeType"
                              :reliability dds.rtps.discovery:+reliability-reliable+)
           (setf (disc-node-peers node-a) (list (cons "127.0.0.1" (disc-node-port node-b))))
           (setf (disc-node-peers node-b) (list (cons "127.0.0.1" (disc-node-port node-a))))
           (start-node node-a) (start-node node-b)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node-a))
                            (plusp (disc-node-discovered-count node-b)))
                 do (announce-participant node-a) (announce-participant node-b) (sleep 0.02))
           ;; mark A<->B :authenticated (the fan-out set %announce-secure-endpoints uses)
           (set-pvms-bootstrap-km node-a pb (dds.security:make-key-material))
           (set-pvms-bootstrap-km node-b pa (dds.security:make-key-material))
           (loop repeat 80
                 until (plusp (disc-node-matched-count node-b))
                 do (announce-endpoints node-a) (announce-endpoints node-b)
                    (announce-participant node-a) (sleep 0.02))
           (if tamper-p
               (progn
                 (loop repeat 25 do (announce-endpoints node-a) (sleep 0.02))
                 (assert (zerop (disc-node-matched-count node-b)) ()
                         "origin-auth breach: B matched A's protected writer with the WRONG receiver-specific key (~d) — the receiver-MAC must gate BEYOND the common_mac (§9.5.3.3.4.3)"
                         (disc-node-matched-count node-b)))
               (assert (plusp (disc-node-matched-count node-b)) ()
                       "origin-auth secure SEDP: B did not match A's discovery-protected writer with the CORRECT receiver-specific key (the receiver-MAC must verify)"))
           t)
      (stop-node node-a) (stop-node node-b))))

(defun* run-secure-sedp-origin-auth-roundtrip-test ()
    (function () (eql t))
  "Secure SEDP origin-authentication round-trip under discovery_protection_kind = ENCRYPT_WITH_ORIGIN_AUTHENTICATION
   (DDS-Security 1.1 §9.5.3.3.4.3; T-ORIGINAUTH): with the CORRECT matched receiver-specific key, A's protected
   DiscoveredWriterData carries a receiver-specific MAC that B verifies, and B MATCHES A's protected writer over
   the secure SEDP endpoint. Proves the origin-auth resolvers (encode :receivers / decode my-receiver-key) are
   wired through the real announce/dispatch path. Delegates to %run-secure-sedp-origin-auth."
  (%run-secure-sedp-origin-auth nil))

(defun* run-secure-sedp-origin-auth-tamper-test ()
    (function () (eql t))
  "Secure SEDP origin-authentication NON-VACUOUS control (T-ORIGINAUTH): a peer holding the WRONG
   receiver-specific key (same key_id, different key bytes) does NOT match A's protected writer, EVEN THOUGH the
   common_mac is valid (same sender KM) — proving the receiver-specific MAC gates BEYOND the common_mac
   (§9.5.3.3.4.3, fail-closed). Delegates to %run-secure-sedp-origin-auth with TAMPER-P = T."
  (%run-secure-sedp-origin-auth t))

;;; --- T10: whole-RTPS-message protection (rtps_protection) engagement on the live disc data path ---

(defun* %rtps-build-user-datagram (node buf sn payload)
    (function (disc-node dds.core.buffer:octet-buffer integer (simple-array (unsigned-byte 8) (*))) (integer 0))
  "Build a plain user-writer DATA datagram (20-octet RTPS Header §9.4.4 + one DATA submessage §9.4.5.4: writerId
   = NODE's user writer EntityId, sequence SN, serializedPayload PAYLOAD) into BUF and return its octet length —
   the plaintext input the T10 send-path wrap (%send-raw-buf -> %maybe-wrap-srtps) protects. Test helper."
  (let ((mc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
    (dds.rtps.message:write-data mc dds.rtps.message:+entityid-unknown+ (disc-node-user-writer-id node)
                                 sn payload 0 (length payload))
    (dds.core.buffer:cursor-position mc)))

(defun* %rtps-feed-datagram (node dg)
    (function (disc-node (simple-array (unsigned-byte 8) (*))) t)
  "Feed a captured datagram DG into NODE's %handle-datagram over a FRESH buffer (a copy, so the in-place SRTPS
   decode never mutates DG — DG can be re-fed with different keys), as if the receiver thread had read it.
   Test helper (run-rtps-protection-test)."
  (let ((buf (dds.core.buffer:make-octet-buffer (max 64 (length dg)))))
    (replace (dds.core.buffer:octet-buffer-vec buf) dg)
    (%handle-datagram node buf (length dg))))

(defun* run-rtps-protection-test ()
    (function () (eql t))
  "WP-DDS-SECURITY-SECURE-DISCOVERY T10: whole-RTPS-message protection (rtps_protection_kind, DDS-Security 1.1
   §8.5.1.10-.12) engagement on the live disc data path — deterministic, no auth handshake (manually-installed
   ParticipantCrypto KMs + the rtps-protection-encode/decode closures stand in for the dds-dcps crypto-manager;
   the full :keyed participant e2e is run-secure-discovery-protected-test, whose Square sample now traverses this
   wrap+unwrap path). A is the sender; B the receiver holding A's ParticipantCrypto. Asserts:
     (1) EXEMPTION: a NIL-dest-prefix send (the SPDP/PSM bootstrap analogue) stays PLAIN (first submessage DATA),
         even with the encode resolver installed — the wrap is gated on a per-destination prefix.
     (2) ENGAGEMENT: a send to the :keyed B (dest-prefix = B's GUID-prefix) is SRTPS-wrapped on the wire (first
         submessage SRTPS_PREFIX 0x33) and the user payload never appears in cleartext (ENCRYPT).
     (3) DECODE+DISPATCH: B (correct ParticipantCrypto) decodes the SRTPS datagram and delivers the inner user
         DATA byte-exact through %handle-datagram's re-dispatch.
     (4) NON-VACUOUS: a receiver WITHOUT A's ParticipantCrypto (wrong KM) does NOT decode -> fail-closed drop.
     (5) ORIGIN-AUTH (§9.5.3.3.4.3): with :receivers, the CORRECT receiver key decodes+delivers; the WRONG
         receiver key (same key_id) fails-closed (drops) even though the common_mac is valid.
   Requires the AES-GCM primitive (like the other secure tests); skips gracefully if absent. Both impls."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [rtps-protection] SKIP — AES-GCM not available: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-rtps-protection-test t)))
  (let* ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 81))
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 82))
         (node-a (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
         (node-b (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (km-a     (%secure-sedp-test-km 7 #x33))   ; A's ParticipantCrypto (AES256-GCM); B holds the SAME (received A's token)
         (km-wrong (%secure-sedp-test-km 8 #x44))   ; a DIFFERENT ParticipantCrypto — the non-vacuous wrong-key control
         (rid   (make-array 4  :element-type '(unsigned-byte 8) :initial-element #x5a))   ; A's ParticipantCrypto receiver_specific_key_id
         (kgood (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x3c))   ; the matching receiver key
         (kbad  (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x99))   ; a WRONG receiver key (SAME id)
         (payload (map '(simple-array (unsigned-byte 8) (*)) #'char-code "RTPSDATA"))
         (host "127.0.0.1") (port 7) (cap nil))
    (unwind-protect
         (progn
           ;; (1) EXEMPTION — encode resolver installed, but NIL dest-prefix -> never wrapped (SPDP/PSM analogue)
           (setf (disc-node-rtps-protection-kind node-a) :encrypt
                 (disc-node-rtps-protection-encode node-a)
                 (lambda (dp) (declare (ignore dp)) (values km-a :encrypt '())))
           (let ((buf (disc-node-tx-msg node-a)) (*datagram-sink* (lambda (dg) (setf cap dg))))
             (%send-raw-buf node-a buf (%rtps-build-user-datagram node-a buf 1 payload) host port nil nil))
           (assert (and (> (length cap) 20) (= (aref cap 20) dds.rtps.message:+submsg-data+)) ()
                   "T10 exemption: a NIL-dest-prefix send (SPDP/PSM analogue) must stay PLAIN (first submessage DATA 0x15)")
           ;; (2) ENGAGEMENT — dest-prefix = B's prefix -> SRTPS-wrapped + confidential
           (let ((buf (disc-node-tx-msg node-a)) (*datagram-sink* (lambda (dg) (setf cap dg))))
             (%send-raw-buf node-a buf (%rtps-build-user-datagram node-a buf 1 payload) host port nil pb))
           (assert (and (> (length cap) 20) (= (aref cap 20) dds.security:+submessage-srtps-prefix+)) ()
                   "T10 engagement: a :keyed-dest send must be SRTPS-wrapped (first submessage SRTPS_PREFIX 0x33)")
           (assert (not (search payload cap)) ()
                   "T10 ENCRYPT: the user payload must NOT appear in cleartext in the wrapped datagram")
           ;; (3) DECODE+DISPATCH at B (correct ParticipantCrypto) -> byte-exact delivery
           (let ((got nil))
             (setf (disc-node-rtps-protection-decode node-b) (lambda (sp) (declare (ignore sp)) (values km-a nil nil))
                   (disc-node-on-data node-b)
                   (lambda (w sn b poff plen sp og os kh) (declare (ignore w sn sp og os kh))
                     (setf got (subseq (dds.core.buffer:octet-buffer-vec b) poff (+ poff plen)))))
             (%rtps-feed-datagram node-b cap)
             (assert (and got (equalp got payload)) ()
                     "T10 decode: B must recover + dispatch the inner user DATA byte-exact from the SRTPS datagram"))
           ;; (4) NON-VACUOUS — wrong ParticipantCrypto -> fail-closed drop (on-data never fires)
           (let ((fired nil))
             (setf (disc-node-rtps-protection-decode node-b) (lambda (sp) (declare (ignore sp)) (values km-wrong nil nil))
                   (disc-node-on-data node-b) (lambda (&rest r) (declare (ignore r)) (setf fired t)))
             (%rtps-feed-datagram node-b cap)
             (assert (null fired) ()
                     "T10 fail-closed: a peer WITHOUT A's ParticipantCrypto must NOT decode the SRTPS datagram"))
           ;; (5) ORIGIN-AUTH — right receiver key delivers; wrong key (same id) drops though common_mac valid
           (setf (disc-node-rtps-protection-encode node-a)
                 (lambda (dp) (declare (ignore dp)) (values km-a :encrypt (list (cons rid kgood)))))
           (let ((buf (disc-node-tx-msg node-a)) (oa nil))
             (let ((*datagram-sink* (lambda (dg) (setf oa dg))))
               (%send-raw-buf node-a buf (%rtps-build-user-datagram node-a buf 2 payload) host port nil pb))
             (let ((got nil))
               (setf (disc-node-rtps-protection-decode node-b) (lambda (sp) (declare (ignore sp)) (values km-a rid kgood))
                     (disc-node-on-data node-b)
                     (lambda (w sn b poff plen sp og os kh) (declare (ignore w sn sp og os kh))
                       (setf got (subseq (dds.core.buffer:octet-buffer-vec b) poff (+ poff plen)))))
               (%rtps-feed-datagram node-b oa)
               (assert (and got (equalp got payload)) ()
                       "T10 origin-auth: the CORRECT receiver key must decode + deliver the inner DATA"))
             (let ((fired nil))
               (setf (disc-node-rtps-protection-decode node-b) (lambda (sp) (declare (ignore sp)) (values km-a rid kbad))
                     (disc-node-on-data node-b) (lambda (&rest r) (declare (ignore r)) (setf fired t)))
               (%rtps-feed-datagram node-b oa)
               (assert (null fired) ()
                       "T10 origin-auth: a WRONG receiver key (same key_id) must fail-closed though the common_mac is valid")))
           t)
      (stop-node node-a) (stop-node node-b))))

(defun* run-rtps-protection-enforce-test ()
    (function () (eql t))
  "WP-DDS-SECURITY-SECURE-DISCOVERY T10 review: RECEIVE-side rtps_protection ENFORCEMENT (DDS-Security 1.1
   §8.5.1.10-.12 / §9.4.1.2.3) — the complement of the send-side SRTPS wrap (run-rtps-protection-test). B is the
   receiver: its governance REQUIRES rtps_protection (kind ENCRYPT) and it is :keyed with peer A (B holds A's
   ParticipantCrypto, so A's source prefix resolves through the decode resolver). A legitimate keyed-rtps A ALWAYS
   SRTPS-wraps user data, so a PLAIN user-DATA claiming to come from A is FORGED — anyone can spoof A's source
   GUID-prefix on a plain datagram, no key needed (the review defect). Asserts, feeding datagrams straight into
   %handle-datagram (deterministic, no UDP / no handshake; both impls):
     (1) ENFORCEMENT: a forged PLAIN user-DATA spoofing A's source prefix + a USER writerId is DROPPED — B's
         user-data hook never fires (the cleartext injection is rejected before any user reader).
     (2) NON-VACUOUS (source not keyed): the SAME plain user-DATA from an UNKEYED stranger prefix IS delivered —
         the drop is gated on the source being :keyed, not a blanket reject.
     (3) NON-VACUOUS (governance NONE): with rtps_protection = NONE the SAME forged user-DATA from A IS delivered —
         proving the drop is specifically the rtps_protection enforcement (security-OFF is byte-identical), not
         some other gate.
     (4) NO FALSE-REJECT: a PLAIN BUILTIN-metatraffic (SPDP) datagram spoofing A's prefix is STILL processed (B
         records A) — metatraffic is intentionally plain in this slice (the T12 carry); the drop discriminates by
         writerId (builtin EntityId kind 0xc? vs user 0x02/0x03), never dropping metatraffic."
  (let* ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 91))   ; the :keyed peer A a forger spoofs
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 92))   ; node-b: the receiver under enforcement
         (px (make-array 12 :element-type '(unsigned-byte 8) :initial-element 93))   ; an UNKEYED stranger prefix (control)
         (node-a (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))   ; builds a VALID SPDP announce + owns the spoofed prefix
         (node-b (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (km-a   (%secure-sedp-test-km 7 #x33))                  ; A's ParticipantCrypto, held by B -> A is :keyed at B
         (uwid   (disc-node-user-writer-id node-a))              ; A's user-data writer EntityId (kind 0x02 -> a user writer)
         (payload (map '(simple-array (unsigned-byte 8) (*)) #'char-code "FORGEDXX")))
    (flet ((feed (dg)   ; dispatch DG (a fresh heap vector) into B's %handle-datagram, as the receiver thread would
             (%handle-datagram node-b (dds.core.buffer:octet-buffer-over dg) (length dg)))
           (user-dg (src-prefix)   ; a PLAIN user-DATA datagram (user writerId) spoofing SRC-PREFIX
             (let* ((vec (make-array 256 :element-type '(unsigned-byte 8)))
                    (mc  (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over vec) :endianness :little)))
               (dds.rtps.message:write-header mc src-prefix)
               (dds.rtps.message:write-data mc dds.rtps.message:+entityid-unknown+ uwid 1 payload 0 (length payload))
               (subseq vec 0 (dds.core.buffer:cursor-position mc))))
           (spdp-dg (src-prefix spdp)   ; a PLAIN builtin SPDP DATA datagram (metatraffic) spoofing SRC-PREFIX
             (let* ((pvec (make-array 512 :element-type '(unsigned-byte 8)))
                    (ppc  (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over pvec) :endianness :little)))
               (dds.cdr:make-encapsulation-header ppc :pl-cdr-le)
               (dds.rtps.discovery:serialize-spdp-data ppc spdp)
               (let* ((plen (dds.core.buffer:cursor-position ppc))
                      (vec  (make-array 640 :element-type '(unsigned-byte 8)))
                      (mc   (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over vec) :endianness :little)))
                 (dds.rtps.message:write-header mc src-prefix)
                 (dds.rtps.message:write-data mc dds.rtps.discovery:+entityid-spdp-reader+
                                              dds.rtps.discovery:+entityid-spdp-writer+ 1 pvec 0 plen)
                 (subseq vec 0 (dds.core.buffer:cursor-position mc))))))
      (unwind-protect
           (let ((spdp-a (%node-spdp-data node-a)))
             ;; ARM B: governance REQUIRES rtps_protection (ENCRYPT) AND peer A (pa) is :keyed (its ParticipantCrypto
             ;; resolves through the decode resolver); any other source (px) is NOT keyed (resolver returns NIL).
             (setf (disc-node-rtps-protection-kind node-b) :encrypt
                   (disc-node-rtps-protection-decode node-b)
                   (lambda (sp) (when (equalp sp pa) (values km-a nil nil))))
             ;; (1) ENFORCEMENT — a forged PLAIN user-DATA spoofing the :keyed peer A's source prefix -> DROPPED
             (let ((got nil))
               (setf (disc-node-on-data node-b) (lambda (&rest r) (declare (ignore r)) (setf got t)))
               (feed (user-dg pa))
               (assert (null got) ()
                       "T10 enforce: a PLAIN user-DATA spoofing a :keyed-rtps peer's source prefix must be DROPPED (cleartext injection)"))
             ;; (2) NON-VACUOUS (source not keyed) — the SAME plain user-DATA from an UNKEYED stranger px -> DELIVERED
             (let ((got nil))
               (setf (disc-node-on-data node-b) (lambda (&rest r) (declare (ignore r)) (setf got t)))
               (feed (user-dg px))
               (assert got ()
                       "T10 enforce non-vacuous: a PLAIN user-DATA from a NOT-keyed source must be DELIVERED (the drop is keyed-gated, not blanket)"))
             ;; (3) NON-VACUOUS (governance NONE) — with rtps_protection NONE the SAME forged user-DATA from A -> DELIVERED
             (let ((got nil))
               (setf (disc-node-rtps-protection-kind node-b) :none
                     (disc-node-on-data node-b) (lambda (&rest r) (declare (ignore r)) (setf got t)))
               (feed (user-dg pa))
               (assert got ()
                       "T10 enforce non-vacuous: with rtps_protection NONE the same plain user-DATA must be DELIVERED (proves the drop IS the rtps_protection enforcement)")
               (setf (disc-node-rtps-protection-kind node-b) :encrypt))   ; restore enforce mode for (4)
             ;; (4) NO FALSE-REJECT — a PLAIN BUILTIN metatraffic (SPDP) datagram spoofing A's prefix is STILL processed
             (feed (spdp-dg pa spdp-a))
             (assert (member pa (disc-node-discovered-prefixes node-b) :test #'equalp) ()
                     "T10 enforce false-REJECT: plain BUILTIN metatraffic (SPDP) from a :keyed-rtps peer must STILL be processed (metatraffic is intentionally plain in this slice)")
             t)
        (stop-node node-a) (stop-node node-b)))))

(defun* %rtps-build-submsg-datagram (src-prefix writer)
    (function ((simple-array (unsigned-byte 8) (12)) function) (simple-array (unsigned-byte 8) (*)))
  "Build a PLAIN RTPS datagram into a fresh heap vector: the 20-octet RTPS Header (§9.4.4) for source
   participant SRC-PREFIX, then ONE submessage emitted by the WRITER closure (called with the message cursor).
   Returns the exact-length octet vector. Test helper for the receive-side rtps_protection enforcement tests —
   forges an arbitrary plain submessage (HEARTBEAT / ACKNACK / GAP / *_FRAG / SPDP) spoofing any source
   GUID-prefix, no key needed (the threat the enforcement closes)."
  (let* ((vec (make-array 1024 :element-type '(unsigned-byte 8)))
         (mc  (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over vec) :endianness :little)))
    (dds.rtps.message:write-header mc src-prefix)
    (funcall writer mc)
    (subseq vec 0 (dds.core.buffer:cursor-position mc))))

(defun* run-rtps-protection-enforce-reliability-test ()
    (function () (eql t))
  "WP-DDS-SECURITY-SECURE-DISCOVERY T10 review fix-2: RECEIVE-side rtps_protection ENFORCEMENT extended to the
   USER-plane RELIABILITY-CONTROL submessages (DDS-Security 1.1 §8.5.1.10) — the complement of
   run-rtps-protection-enforce-test (which covered DATA / DATA_FRAG). B requires rtps_protection (kind ENCRYPT)
   and is :keyed with peer A (B holds A's ParticipantCrypto, so A's source prefix resolves through the decode
   resolver). A legitimate keyed-rtps A ALWAYS SRTPS-wraps user traffic, so a PLAIN user-plane reliability
   submessage claiming to come from A is FORGED — anyone can spoof A's source GUID-prefix on a plain datagram,
   no key needed (the review defect: forged GAP suppresses samples, forged ACKNACK purges unacked history,
   forged HEARTBEAT corrupts the reader-proxy / reflects a NACK storm). Feeding datagrams straight into
   %handle-datagram (deterministic, no UDP / no handshake; both impls), with each user reliability hook installed
   as a SPY (the SOLE path from a datagram to user reliable state, so spy-not-fired == state untouched), for EACH
   of HEARTBEAT / ACKNACK / GAP / HEARTBEAT_FRAG / NACK_FRAG (a USER reader/writer EntityId):
     (1) ENFORCEMENT: a forged PLAIN submessage spoofing the :keyed peer A's source prefix is DROPPED — its user
         handler never fires (no GAP-marking, no acked-base advance / HistoryCache purge, no reader-proxy change).
     (2) NON-VACUOUS (source not keyed): the SAME submessage from an UNKEYED stranger prefix IS delivered (its
         handler fires) — the drop is keyed-gated, not a blanket reject.
     (3) NON-VACUOUS (governance NONE): with rtps_protection = NONE the SAME forged submessage from A IS delivered
         — proving the drop is specifically the rtps_protection enforcement (security-OFF byte-identical).
   Then NO FALSE-REJECT of BUILTIN reliability: a PLAIN builtin SEDP HEARTBEAT from the keyed peer A is STILL
   processed (routed to %on-builtin-heartbeat — the BID clause, BEFORE the gated user fall-through — advancing the
   ack counter) and NEVER reaches the user heartbeat spy, proving builtin metatraffic reliability stays exempt."
  (let* ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 91))   ; the :keyed peer A a forger spoofs
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 92))   ; node-b: the receiver under enforcement
         (px (make-array 12 :element-type '(unsigned-byte 8) :initial-element 93))   ; an UNKEYED stranger prefix (control)
         (node-a (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))   ; owns the spoofed prefix + a valid SPDP announce
         (node-b (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (km-a   (%secure-sedp-test-km 7 #x33))                  ; A's ParticipantCrypto, held by B -> A is :keyed at B
         (uwid   (disc-node-user-writer-id node-a))              ; a USER writer EntityId (kind 0x02) for the forged submessages
         (rrid   dds.rtps.message:+entityid-unknown+)            ; the forged submessage's source reader id (irrelevant to the gate)
         (bm     (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0))   ; empty SequenceNumberSet bitmap (numBits 0)
         (fired  nil))
    (flet ((feed (dg)   ; dispatch DG (a fresh heap vector) into B's %handle-datagram, as the receiver thread would
             (%handle-datagram node-b (dds.core.buffer:octet-buffer-over dg) (length dg)))
           (spy (&rest r) (declare (ignore r)) (setf fired t)))   ; a hook spy: the gated user fall-through was reached
      (let ((hb-dg  (lambda (sp) (%rtps-build-submsg-datagram sp (lambda (mc) (dds.rtps.message:write-heartbeat mc rrid uwid 1 1 1 :final t)))))
            (an-dg  (lambda (sp) (%rtps-build-submsg-datagram sp (lambda (mc) (dds.rtps.message:write-acknack mc rrid uwid 1 0 bm 1 :final t)))))
            (gap-dg (lambda (sp) (%rtps-build-submsg-datagram sp (lambda (mc) (dds.rtps.message:write-gap mc rrid uwid 1 3 0 bm)))))
            (hbf-dg (lambda (sp) (%rtps-build-submsg-datagram sp (lambda (mc) (dds.rtps.message:write-heartbeat-frag mc rrid uwid 1 1 1)))))
            (nf-dg  (lambda (sp) (%rtps-build-submsg-datagram sp (lambda (mc) (dds.rtps.message:write-nack-frag mc rrid uwid 1 1 0 bm 1))))))
        (unwind-protect
             (progn
               ;; ARM B: governance REQUIRES rtps_protection (ENCRYPT) AND peer A (pa) is :keyed (its
               ;; ParticipantCrypto resolves); any other source (px) is NOT keyed (resolver -> NIL). Install the
               ;; 5 user reliability hooks as SPYs — the sole datagram->user-reliable-state path, so a spy that
               ;; does not fire proves the state was untouched (no real handler, no UDP, fully deterministic).
               (setf (disc-node-rtps-protection-decode node-b)
                     (lambda (sp) (when (equalp sp pa) (values km-a nil nil)))
                     (disc-node-on-heartbeat node-b)      #'spy
                     (disc-node-on-acknack node-b)        #'spy
                     (disc-node-on-gap node-b)            #'spy
                     (disc-node-on-heartbeat-frag node-b) #'spy
                     (disc-node-on-nack-frag node-b)      #'spy)
               (flet ((check (label builder)
                        ;; (1) forged from the :keyed peer A under ENCRYPT -> DROPPED (spy must NOT fire)
                        (setf (disc-node-rtps-protection-kind node-b) :encrypt fired nil)
                        (feed (funcall builder pa))
                        (assert (null fired) ()
                                "T10 enforce ~a: a forged PLAIN ~a from a :keyed-rtps peer must be DROPPED (no user reliable-state mutation)" label label)
                        ;; (2) non-vacuous (source not keyed): the SAME submessage from an UNKEYED px -> DELIVERED
                        (setf fired nil)
                        (feed (funcall builder px))
                        (assert fired ()
                                "T10 enforce ~a non-vacuous: a PLAIN ~a from a NOT-keyed source must be DELIVERED (the drop is keyed-gated, not blanket)" label label)
                        ;; (3) non-vacuous (governance NONE): the SAME forged submessage from A -> DELIVERED
                        (setf (disc-node-rtps-protection-kind node-b) :none fired nil)
                        (feed (funcall builder pa))
                        (assert fired ()
                                "T10 enforce ~a non-vacuous: with rtps_protection NONE the same PLAIN ~a must be DELIVERED (proves the drop IS the rtps_protection enforcement)" label label)
                        (setf (disc-node-rtps-protection-kind node-b) :encrypt)))   ; restore enforce mode for the next submessage
                 (check "HEARTBEAT"      hb-dg)
                 (check "ACKNACK"        an-dg)
                 (check "GAP"            gap-dg)
                 (check "HEARTBEAT_FRAG" hbf-dg)
                 (check "NACK_FRAG"      nf-dg))
               ;; NO FALSE-REJECT — a PLAIN BUILTIN SEDP HEARTBEAT from the keyed peer A is STILL processed (the
               ;; BID clause -> %on-builtin-heartbeat, BEFORE the gated user fall-through). Discover A first (so
               ;; %remote-metatraffic resolves A's metatraffic locator), then a builtin HEARTBEAT advances the ack
               ;; counter AND never reaches the user heartbeat spy.
               (feed (%rtps-build-submsg-datagram                   ; A's SPDP -> B records A (builtin DATA, exempt)
                      pa (lambda (mc)
                           (let* ((pvec (make-array 512 :element-type '(unsigned-byte 8)))
                                  (ppc  (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over pvec) :endianness :little)))
                             (dds.cdr:make-encapsulation-header ppc :pl-cdr-le)
                             (dds.rtps.discovery:serialize-spdp-data ppc (%node-spdp-data node-a))
                             (dds.rtps.message:write-data mc dds.rtps.discovery:+entityid-spdp-reader+
                                                          dds.rtps.discovery:+entityid-spdp-writer+ 1 pvec 0
                                                          (dds.core.buffer:cursor-position ppc))))))
               (assert (member pa (disc-node-discovered-prefixes node-b) :test #'equalp) ()
                       "T10 enforce false-REJECT setup: plain BUILTIN SPDP from a :keyed-rtps peer must STILL record A")
               (setf fired nil)
               (let ((ac0 (disc-node-ack-count node-b)))
                 (feed (%rtps-build-submsg-datagram                 ; builtin SEDP HEARTBEAT (wid = SEDP publications writer)
                        pa (lambda (mc) (dds.rtps.message:write-heartbeat
                                         mc dds.rtps.discovery:+entityid-spdp-reader+
                                         dds.rtps.discovery:+entityid-sedp-pub-writer+ 1 1 1 :final t))))
                 (assert (null fired) ()
                         "T10 enforce false-REJECT: a BUILTIN SEDP HEARTBEAT must NOT reach the gated user heartbeat fall-through")
                 (assert (> (disc-node-ack-count node-b) ac0) ()
                         "T10 enforce false-REJECT: a PLAIN BUILTIN SEDP HEARTBEAT from a :keyed-rtps peer must STILL be processed (no false-REJECT of builtin reliability)"))
               t)
          (stop-node node-a) (stop-node node-b))))))

;;; --- T11 tests: secure participant-message (liveliness) + secure SPDP re-announce ---

(defun* %run-secure-pm (kind origin-auth-p tamper-p)
    (function ((member :sign :encrypt) t t) (eql t))
  "Secure participant-message (Writer Liveliness Protocol) round-trip at the disc layer under
   liveliness_protection_kind = KIND (DDS-Security 1.1 §8.4.1.6 / §9.4.1.2.3; T11 + T-ORIGINAUTH) — deterministic,
   no auth handshake (manually-installed EntityCrypto KMs stand in for the dds-dcps crypto-manager). A carries an
   AUTOMATIC-liveliness writer, so its announce cadence asserts liveliness; with secure-pm-protection-kind = KIND
   it routes EVERY assertion over the secure BuiltinParticipantMessageSecureWriter (0xff0200c2), submessage-PROTECT
   under A's secure-PM EntityCrypto; B's dispatcher decodes (the inner writerId routes to the EXISTING WLP handler)
   and records a per-A AUTOMATIC liveliness stamp. ORIGIN-AUTH-P installs the receiver-MAC resolvers (encode
   :receivers / decode my-receiver-key, §9.5.3.3.4.3); TAMPER-P then gives B the WRONG receiver key (same key_id).
   Asserts: a SEC_PREFIX bracket WAS emitted (non-vacuous — the secure WLP path, not plain); TAMPER-P NIL -> B
   DETECTS A's liveliness; TAMPER-P T -> B NEVER detects it (the receiver-MAC gates BEYOND the valid common_mac).
   Bounded; requires the AES-GCM primitive (skips gracefully if absent). Both impls."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [secure-pm] SKIP — AES-GCM not available: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from %run-secure-pm t)))
  (let* ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 61))
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 62))
         (node-a (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
         (node-b (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (km-a-pm (%secure-sedp-test-km 1 #x11))   ; A's secure-PM-writer EntityCrypto (the sender)
         (km-b-pm (%secure-sedp-test-km 2 #x22))   ; B's secure-PM-writer EntityCrypto (unused — B only receives)
         (rid   (make-array 4  :element-type '(unsigned-byte 8) :initial-element #x5a))   ; B-pm-reader receiver_specific_key_id
         (kgood (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x3c))   ; the correct receiver key
         (kbad  (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x99))   ; a WRONG receiver key (same id)
         (sec-seen nil)
         (lk (dds.pal:make-lock "secure-pm-test")))
    (unwind-protect
         (progn
           ;; security-OFF control: an unarmed node advertises NO secure participant-message bits 20/21
           (assert (not (logtest (dds.rtps.discovery:spdp-data-builtin-endpoint-set (%node-spdp-data node-a))
                                 dds.rtps.discovery:+be-participant-message-secure-writer+)) ()
                   "a node with no liveliness protection must NOT advertise the secure PM bits 20/21 (security-OFF byte-identical)")
           (flet ((arm (node enc-km dec-km recv-key)
                    (setf (disc-node-secure-pm-protection-kind node) kind)
                    (setf (disc-node-secure-pm-origin-auth node) (and origin-auth-p t))
                    (setf (disc-node-secure-sedp-encode-km node)
                          (lambda (eid) (when (= eid dds.rtps.discovery:+entityid-participant-message-secure-writer+) enc-km)))
                    (setf (disc-node-secure-sedp-decode-km node)
                          (lambda (kid) (when (equalp kid (dds.security:key-material-sender-key-id dec-km)) dec-km)))
                    (when origin-auth-p
                      (setf (disc-node-secure-sedp-encode-receivers node)
                            (lambda (weid prefix)
                              (declare (ignore prefix))
                              (when (= weid dds.rtps.discovery:+entityid-participant-message-secure-writer+)
                                (list (cons rid kgood)))))
                      (setf (disc-node-secure-sedp-decode-receiver-km node)
                            (lambda (kid) (declare (ignore kid)) (cons rid recv-key))))))
             ;; A always ENCODES the receiver-MAC under KGOOD; B VERIFIES with KGOOD (match) or KBAD (tamper).
             (arm node-a km-a-pm km-b-pm kgood)
             (arm node-b km-b-pm km-a-pm (if tamper-p kbad kgood)))
           ;; with liveliness protection active, A DOES advertise the secure PM bits 20/21
           (assert (logtest (dds.rtps.discovery:spdp-data-builtin-endpoint-set (%node-spdp-data node-a))
                            dds.rtps.discovery:+be-participant-message-secure-writer+) ()
                   "A must OR BuiltinEndpointSet bits 20/21 into SPDP when liveliness protection is active")
           (add-local-writer node-a :topic "Square" :type "ShapeType"
                             :qos (dds.qos:make-qos :reliability :reliable :liveliness :automatic))
           (setf (disc-node-peers node-a) (list (cons "127.0.0.1" (disc-node-port node-b))))
           (setf (disc-node-peers node-b) (list (cons "127.0.0.1" (disc-node-port node-a))))
           (start-node node-a) (start-node node-b)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node-a))
                            (plusp (disc-node-discovered-count node-b)))
                 do (announce-participant node-a) (announce-participant node-b) (sleep 0.02))
           (assert (and (plusp (disc-node-discovered-count node-a))
                        (plusp (disc-node-discovered-count node-b)))
                   () "secure-PM test: SPDP discovery incomplete")
           ;; mark A<->B :authenticated (the fan-out set %announce-secure-liveliness uses)
           (set-pvms-bootstrap-km node-a pb (dds.security:make-key-material))
           (set-pvms-bootstrap-km node-b pa (dds.security:make-key-material))
           (let ((*datagram-sink* (lambda (dg)
                                    (dds.pal:with-lock (lk)
                                      (when (%datagram-secure-bracket-p dg) (setf sec-seen t))))))
             (loop repeat 80
                   until (and sec-seen
                              (if tamper-p nil
                                  (disc-node-remote-liveliness-stamp node-b pa dds.rtps.discovery:+pmd-kind-automatic+)))
                   do (announce-participant node-a) (sleep 0.02)))
           (assert sec-seen () "secure PM: no SEC_PREFIX bracket emitted (the secure WLP path was not taken)")
           (if tamper-p
               (assert (null (disc-node-remote-liveliness-stamp node-b pa dds.rtps.discovery:+pmd-kind-automatic+)) ()
                       "origin-auth breach: B asserted A's liveliness with the WRONG receiver key — the receiver-MAC must gate BEYOND the common_mac (§9.5.3.3.4.3)")
               (assert (disc-node-remote-liveliness-stamp node-b pa dds.rtps.discovery:+pmd-kind-automatic+) ()
                       "secure PM: B did not detect A's liveliness over the secure participant-message endpoint (0xff0200)"))
           t)
      (stop-node node-a) (stop-node node-b))))

(defun* run-secure-participant-message-test ()
    (function () (eql t))
  "Secure WLP round-trip under liveliness_protection_kind = SIGN (authenticated-but-visible): A asserts its
   AUTOMATIC liveliness over the secure BuiltinParticipantMessageSecureWriter (0xff0200c2) submessage-protected,
   B detects it; a SEC_PREFIX bracket is emitted (the secure path, not plain). Delegates to %run-secure-pm."
  (%run-secure-pm :sign nil nil))

(defun* run-secure-pm-origin-auth-roundtrip-test ()
    (function () (eql t))
  "Secure WLP origin-authentication round-trip under liveliness_protection_kind = ENCRYPT_WITH_ORIGIN_AUTHENTICATION
   (§9.5.3.3.4.3): with the CORRECT matched receiver-specific key, A's liveliness assertion carries a
   receiver-specific MAC that B verifies, and B detects A's liveliness. Delegates to %run-secure-pm."
  (%run-secure-pm :encrypt t nil))

(defun* run-secure-pm-origin-auth-tamper-test ()
    (function () (eql t))
  "Secure WLP origin-authentication NON-VACUOUS control (§9.5.3.3.4.3): a peer holding the WRONG receiver-specific
   key (same key_id) does NOT detect A's liveliness, EVEN THOUGH the common_mac is valid — proving the
   receiver-specific MAC gates BEYOND the common_mac (fail-closed). Delegates to %run-secure-pm with TAMPER-P = T."
  (%run-secure-pm :encrypt t t))

(defun* run-secure-participant-message-tamper-test ()
    (function () (eql t))
  "Secure WLP TAMPER control (NFR-SEC-POSTURE; T11): a TAMPERED secure participant-message assertion is DROPPED —
   it never asserts liveliness. A (SIGN secure PM) emits a protected assertion; capture it, then feed it into two
   FRESH armed receivers (deterministic, straight into %handle-datagram — no UDP race): the CLEAN datagram records
   A's liveliness (non-vacuous — the path works), a copy with ONE flipped octet in the protected region fails the
   MAC and is DROPPED (no stamp). Requires the AES-GCM primitive (skips gracefully if absent). Both impls."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [secure-pm-tamper] SKIP — AES-GCM not available: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-secure-participant-message-tamper-test t)))
  (let* ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 63))
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 64))
         (node-a (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
         (node-b (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (km-a-pm (%secure-sedp-test-km 1 #x11))
         (km-b-pm (%secure-sedp-test-km 2 #x22))
         (captured '())
         (lk (dds.pal:make-lock "secure-pm-tamper-test")))
    (unwind-protect
         (progn
           (flet ((arm (node enc-km dec-km)
                    (setf (disc-node-secure-pm-protection-kind node) :sign)
                    (setf (disc-node-secure-sedp-encode-km node)
                          (lambda (eid) (when (= eid dds.rtps.discovery:+entityid-participant-message-secure-writer+) enc-km)))
                    (setf (disc-node-secure-sedp-decode-km node)
                          (lambda (kid) (when (equalp kid (dds.security:key-material-sender-key-id dec-km)) dec-km)))))
             (arm node-a km-a-pm km-b-pm)
             (arm node-b km-b-pm km-a-pm))
           (add-local-writer node-a :topic "Square" :type "ShapeType"
                             :qos (dds.qos:make-qos :reliability :reliable :liveliness :automatic))
           (setf (disc-node-peers node-a) (list (cons "127.0.0.1" (disc-node-port node-b))))
           (setf (disc-node-peers node-b) (list (cons "127.0.0.1" (disc-node-port node-a))))
           (start-node node-a) (start-node node-b)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node-a))
                            (plusp (disc-node-discovered-count node-b)))
                 do (announce-participant node-a) (announce-participant node-b) (sleep 0.02))
           (set-pvms-bootstrap-km node-a pb (dds.security:make-key-material))
           (set-pvms-bootstrap-km node-b pa (dds.security:make-key-material))
           (let ((*datagram-sink* (lambda (dg)
                                    (dds.pal:with-lock (lk)
                                      (when (%datagram-secure-bracket-p dg) (push (copy-seq dg) captured))))))
             (loop repeat 80 until captured
                   do (announce-participant node-a) (sleep 0.02)))
           (assert captured () "secure-PM tamper: no secure participant-message bracket was captured")
           (let ((dg (first captured)))
             ;; (1) NON-VACUOUS: a FRESH armed receiver decodes the CLEAN datagram and records A's liveliness.
             (let ((b1 (make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 99)
                                       :host "127.0.0.1" :port 0)))
               (setf (disc-node-secure-sedp-decode-km b1)
                     (lambda (kid) (when (equalp kid (dds.security:key-material-sender-key-id km-a-pm)) km-a-pm)))
               (%handle-datagram b1 (dds.core.buffer:octet-buffer-over (copy-seq dg)) (length dg))
               (assert (disc-node-remote-liveliness-stamp b1 pa dds.rtps.discovery:+pmd-kind-automatic+) ()
                       "secure-PM tamper non-vacuous: a CLEAN secure assertion must record liveliness (the path works)"))
             ;; (2) a TAMPERED datagram (one flipped octet in the protected region) FAILS the MAC -> DROPPED, no stamp.
             (let ((b2 (make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 98)
                                       :host "127.0.0.1" :port 0))
                   (bad (copy-seq dg)))
               (setf (aref bad (1- (length bad))) (logxor (aref bad (1- (length bad))) #xff))
               (setf (disc-node-secure-sedp-decode-km b2)
                     (lambda (kid) (when (equalp kid (dds.security:key-material-sender-key-id km-a-pm)) km-a-pm)))
               (%handle-datagram b2 (dds.core.buffer:octet-buffer-over bad) (length bad))
               (assert (null (disc-node-remote-liveliness-stamp b2 pa dds.rtps.discovery:+pmd-kind-automatic+)) ()
                       "secure-PM tamper: a tampered assertion must be DROPPED (no liveliness on unverified data)")))
           t)
      (stop-node node-a) (stop-node node-b))))

(defun* run-secure-spdp-reannounce-test ()
    (function () (eql t))
  "Secure SPDP re-announce round-trip at the disc layer (DDS-Security 1.1 §7.4.5 / §7.4.6.1; T11) — deterministic,
   no auth handshake. With discovery protection active, A re-announces its ParticipantBuiltinTopicData over the
   secure SPDPbuiltinParticipantSecureWriter (0xff0101c2) submessage-protected, IN ADDITION to the unchanged plain
   SPDP bootstrap. Asserts:
     (0) security-OFF byte-identical: a PLAIN node does NOT advertise the secure SPDP bits 26/27; an armed node DOES;
     (1) plain SPDP STILL bootstraps (B discovers A over plain SPDP — unchanged);
     (2) NON-VACUOUS: a SEC_PREFIX bracket (the protected re-announce) is emitted post-keying;
     (3) DECODE+RECORD: feeding a captured secure-SPDP bracket into a FRESH peer that has seen NO plain SPDP
         registers A from the protected re-announce ALONE (the secure SPDP decode + %record-participant path).
   Requires the AES-GCM primitive (skips gracefully if absent). Both impls."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [secure-spdp] SKIP — AES-GCM not available: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-secure-spdp-reannounce-test t)))
  (let* ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 65))
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 66))
         (node-a (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
         (node-b (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (km-a-spdp (%secure-sedp-test-km 3 #x33))   ; A's secure-SPDP-writer EntityCrypto (the sender)
         (km-b-spdp (%secure-sedp-test-km 4 #x44))   ; B's secure-SPDP-writer EntityCrypto (unused — A is the re-announcer)
         (captured '())
         (lk (dds.pal:make-lock "secure-spdp-test")))
    (unwind-protect
         (progn
           ;; (0) security-OFF control: a plain node (no discovery protection) advertises NO secure SPDP bits 26/27
           (assert (not (logtest (dds.rtps.discovery:spdp-data-builtin-endpoint-set (%node-spdp-data node-b))
                                 dds.rtps.discovery:+be-participant-secure-announcer+)) ()
                   "a plain node must NOT advertise the secure SPDP bits 26/27 (security-OFF byte-identical)")
           (flet ((arm (node enc-km dec-km)
                    ;; non-NIL discovery-protected-topic-p marks secure discovery active (gates secure SPDP); no
                    ;; per-topic protection needed (A has no local endpoints -> no secure SEDP brackets to confuse).
                    (setf (disc-node-discovery-protected-topic-p node) (lambda (tn) (declare (ignore tn)) nil))
                    (setf (disc-node-secure-sedp-protection-kind node) :encrypt)
                    (setf (disc-node-secure-sedp-encode-km node)
                          (lambda (eid) (when (= eid dds.rtps.discovery:+entityid-spdp-secure-writer+) enc-km)))
                    (setf (disc-node-secure-sedp-decode-km node)
                          (lambda (kid) (when (equalp kid (dds.security:key-material-sender-key-id dec-km)) dec-km)))))
             (arm node-a km-a-spdp km-b-spdp)
             (arm node-b km-b-spdp km-a-spdp))
           ;; (0b) with discovery protection active, A DOES advertise the secure SPDP bits 26/27
           (assert (logtest (dds.rtps.discovery:spdp-data-builtin-endpoint-set (%node-spdp-data node-a))
                            dds.rtps.discovery:+be-participant-secure-announcer+) ()
                   "A must OR BuiltinEndpointSet bits 26/27 into SPDP when discovery protection is active")
           (setf (disc-node-peers node-a) (list (cons "127.0.0.1" (disc-node-port node-b))))
           (setf (disc-node-peers node-b) (list (cons "127.0.0.1" (disc-node-port node-a))))
           (start-node node-a) (start-node node-b)
           (loop repeat 100
                 until (and (plusp (disc-node-discovered-count node-a))
                            (plusp (disc-node-discovered-count node-b)))
                 do (announce-participant node-a) (announce-participant node-b) (sleep 0.02))
           ;; (1) plain SPDP bootstrap unchanged: B discovered A over plain SPDP
           (assert (member pa (disc-node-discovered-prefixes node-b) :test #'equalp) ()
                   "secure SPDP: plain SPDP bootstrap must still register A (the bootstrap channel is unchanged)")
           (set-pvms-bootstrap-km node-a pb (dds.security:make-key-material))
           (set-pvms-bootstrap-km node-b pa (dds.security:make-key-material))
           ;; (2) capture A's protected re-announce (the only SEC_PREFIX brackets A emits — A has no local endpoints)
           (let ((*datagram-sink* (lambda (dg)
                                    (dds.pal:with-lock (lk)
                                      (when (%datagram-secure-bracket-p dg) (push (copy-seq dg) captured))))))
             (loop repeat 80 until captured
                   do (announce-participant node-a) (sleep 0.02)))
           (assert captured () "secure SPDP: no SEC_PREFIX re-announce bracket was emitted post-keying")
           ;; (3) isolate the secure SPDP decode+record: a FRESH peer with NO plain SPDP registers A from the bracket
           (let ((b2 (make-disc-node :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 88)
                                     :host "127.0.0.1" :port 0))
                 (dg (first captured)))
             (setf (disc-node-secure-sedp-decode-km b2)
                   (lambda (kid) (when (equalp kid (dds.security:key-material-sender-key-id km-a-spdp)) km-a-spdp)))
             (%handle-datagram b2 (dds.core.buffer:octet-buffer-over (copy-seq dg)) (length dg))
             (assert (member pa (disc-node-discovered-prefixes b2) :test #'equalp) ()
                     "secure SPDP: a FRESH peer (no plain SPDP) must register A from the protected re-announce ALONE"))
           t)
      (stop-node node-a) (stop-node node-b))))
