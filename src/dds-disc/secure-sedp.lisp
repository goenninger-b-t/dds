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

(defun* %secure-bracket-key-id-into (out bracket bracket-len)
    (function ((simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*)) fixnum)
              (or null (simple-array (unsigned-byte 8) (*))))
  "Copy the 4-octet §9.5.3.3.1 CryptoHeader transformation_key_id of the SEC_PREFIX bracket in BRACKET[0,BRACKET-LEN)
   — at offset [8,12): the 4-octet SEC_PREFIX SubmessageHeader (RTPS 2.5 §9.4.5.1) + the CryptoHeader's
   transformation_kind[4] then transformation_key_id[4] (the same offset T8's %pvms-wire-session-id pins for
   session_id at [12,16)) — INTO the caller-provided OUT (which MUST be EXACTLY 4 octets so the equalp-keyed key_id
   resolvers hash the whole vector, not stale trailing octets) and return OUT, or NIL when BRACKET-LEN is too short to
   hold it (a fail-closed bounds-check before any trust in wire data; NFR-SEC-POSTURE, even at (safety 0)). The
   zero-alloc twin of the pre-T5 %secure-bracket-key-id (which subseq'd a fresh 4-octet copy per bracket): the caller
   (%on-secure-submessage) passes a per-thread 4-octet buffer borrowed from the KEY-ID-RX pool (%with-key-id-rx-scratch)
   so the RECEIVE key-id lookup conses nothing per bracket (WP-DDS-SECURITY-ZEROALLOC-AEAD T5 / ZA-2). The equalp-keyed
   key_id resolvers (cm-*-by-key-id) hash + compare OUT without retaining it, so a reused pooled OUT is safe. BRACKET-LEN
   (not (length BRACKET)) is authoritative — BRACKET may be a longer POOLED buffer whose octets past BRACKET-LEN are
   stale from a prior bracket."
  (when (>= bracket-len 12)
    (replace out bracket :start1 0 :end1 4 :start2 8 :end2 12)
    out))

(defun* %secure-reader-eid-for-writer (writer-eid)
    (function ((unsigned-byte 32)) (or null (unsigned-byte 32)))
  "Map a secure BUILTIN WRITER entity-id to its matched READER entity-id (the §9.3.2 builtin pair, low byte
   0xC2 writer -> 0xC7 reader): publications 0xff0003c2 -> 0xff0003c7; subscriptions 0xff0004c2 -> 0xff0004c7;
   participant-message 0xff0200c2 -> 0xff0200c7; SPDP 0xff0101c2 -> 0xff0101c7. NIL for any non-secure-builtin
   writer (fail-closed — a HEARTBEAT for an unrecognized writer is dropped). The LOCAL receiving reader for an
   inbound HEARTBEAT (its EntityCrypto encodes our ACKNACK) AND the destination reader of an outbound HEARTBEAT.
   The disc-layer twin of dds.dcps::%secure-sedp-reader-for-writer (clean-room, identical §9.3.2 pairing)."
  (when (or (= writer-eid dds.rtps.discovery:+entityid-sedp-pub-secure-writer+)
            (= writer-eid dds.rtps.discovery:+entityid-sedp-sub-secure-writer+)
            (= writer-eid dds.rtps.discovery:+entityid-participant-message-secure-writer+)
            (= writer-eid dds.rtps.discovery:+entityid-spdp-secure-writer+))
    (logior (logand writer-eid #xffffff00) #xc7)))

;; T9pull: the secure-SEDP reliability HEARTBEAT/ACKNACK handlers, defined after the announce helpers they
;; reuse (%send-secure-bracket / %send-secure-endpoint / %secure-endpoints-for); forward-declared here because
;; %on-secure-builtin (below) demuxes to them.
(declaim (ftype (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) integer integer) t)
                %on-secure-builtin-heartbeat)
         (ftype (function (disc-node (simple-array (unsigned-byte 8) (12)) dds.core.buffer:cursor (unsigned-byte 8)) t)
                %on-secure-builtin-acknack))

(defun* %on-secure-builtin (node src-prefix bracket km my-receiver-key-id my-receiver-key)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*))
               dds.security:key-material
               (or null (simple-array (unsigned-byte 8) (*)))
               (or null (simple-array (unsigned-byte 8) (*)))) t)
  "Receiver thread: a secure BUILTIN SEC_PREFIX...SEC_POSTFIX bracket from remote SRC-PREFIX, whose
   transformation_key_id already resolved to the remote secure-builtin EntityCrypto KM. Recover the plaintext
   submessage (the T2/T3 codec decode-datawriter-submessage decodes ANY §8.5 bracket — DataWriter or DataReader
   share one transform, DDS-Security 1.1 §8.5.1.7/.8) then DEMUX by the inner submessage id (T9pull, mirroring
   %on-volatile-secure): a HEARTBEAT -> %on-secure-builtin-heartbeat (apply range + send the protected ACKNACK,
   the NACK-pull that delivers a reliable Fast DDS writer's DiscoveredWriter/ReaderData); an ACKNACK ->
   %on-secure-builtin-acknack (resend the NACKed protected SEDP DATA, the repair); a DATA -> ROUTE by the
   recovered INNER writerId (T9 + T11), each path verifying its own writerId, fail-closed on a mismatch:
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
      ;; PLAIN is a complete RTPS submessage (header + body): DATA | HEARTBEAT | ACKNACK (a submessage-protected
      ;; endpoint protects ALL its submessages — Fast DDS add_data/add_heartbeat/add_acknack encode_*_submessage,
      ;; T9pull). DEMUX by the inner submessage id, mirroring %on-volatile-secure (PVMS).
      (let ((cur (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over plain) :endianness :little)))
        (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header cur)
          (unless id (return-from %on-builtin t))
          (dds.core.buffer:cursor-set-endianness cur (if le :little :big))
          (cond
            ;; inner DATA — a DiscoveredWriter/ReaderData (SEDP), liveliness (PM), or SPDP re-announce
            ((= id dds.rtps.message:+submsg-data+)
             (multiple-value-bind (rdr wid sn has-payload poff plen)
                 (dds.rtps.message:parse-data-body cur flags octets)
               (declare (ignore rdr))
               (unless (and has-payload (plusp plen)) (return-from %on-builtin t))
               ;; reliable accounting: record the received SN under the per-remote builtin reader keyed by the
               ;; secure writer-id, so the HEARTBEAT-driven ACKNACK advances past it (terminates the NACK-pull;
               ;; matches the plain-SEDP %builtin-on-data). The endpoint-data delivery is the explicit parse below.
               (when sn (%builtin-on-data node src-prefix wid sn))
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
                 (t nil))))   ; not a secure builtin writer -> drop (fail-closed)
            ;; inner HEARTBEAT (T9pull) — a reliable secure-builtin writer solicits an ACKNACK; answer it
            ;; submessage-protected (the NACK-pull that delivers Fast DDS's DiscoveredWriter/ReaderData).
            ((= id dds.rtps.message:+submsg-heartbeat+)
             (multiple-value-bind (rid wid first last hcount hfinal hlive)
                 (dds.rtps.message:parse-heartbeat-body cur flags)
               (declare (ignore rid hcount hfinal hlive))
               ;; fail-closed: a truncated inner HEARTBEAT (parse -> NIL) is dropped, not signaled (NFR-SEC-POSTURE)
               (when (and wid first last)
                 (%on-secure-builtin-heartbeat node src-prefix wid first last))))
            ;; inner ACKNACK (T9pull) — the remote's reliable secure-builtin reader NACKs; resend the protected DATA.
            ((= id dds.rtps.message:+submsg-acknack+)
             (%on-secure-builtin-acknack node src-prefix cur flags))
            (t nil))))))   ; unknown inner id -> drop (fail-closed)
  t)

(defun* %on-secure-submessage (node src-prefix bracket bracket-len enforce-rtps)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*)) fixnum t) t)
  "Receiver-thread DISPATCH for ONE inbound SEC_PREFIX...SEC_POSTFIX submessage-protection bracket in
   BRACKET[0,BRACKET-LEN) from SRC-PREFIX (DDS-Security 1.1 §8.5.1.7) — BRACKET may be a longer POOLED buffer
   (WP-DDS-SECURITY-ZEROALLOC-AEAD T5 / ZA-2: %handle-datagram copies the bracket into a per-thread BRACKET-RX pool
   buffer), so BRACKET-LEN — not (length BRACKET) — bounds it. The SAME submessage id (0x31) carries the reliable PVMS crypto-token
   exchange (T7), the secure SEDP DiscoveredWriter/ReaderData (T9), AND the secure participant-message (liveliness)
   + secure SPDP re-announce (T11), so disambiguate by the wire §9.5.3.3.1 CryptoHeader transformation_key_id
   (%secure-bracket-key-id-into): if the installed secure-builtin DECODE resolver maps it to a remote EntityCrypto ->
   %on-secure-builtin (which decodes then routes by the recovered inner writerId to SEDP-match / liveliness /
   record-participant, each verifying its own writerId); else -> %on-volatile-secure (PVMS, which resolves its
   §9.5.3.1 bootstrap KM by SRC-PREFIX — that KM's sender_key_id is all-zeros and never lands in the EntityCrypto
   index, so a PVMS bracket always falls through here). Security OFF / pre-keyed (no resolver, or a key_id it does
   not know) -> the bracket goes to PVMS, exactly as before T9. Fail-closed throughout: each downstream handler
   drops an undecryptable/wrong-writerId bracket.
   ENFORCE-RTPS (T10 review fix-1, computed once by %handle-datagram = rtps_protection REQUIRED from this :keyed
   source AND this datagram arrived NOT SRTPS-wrapped) gates the USER-bracket route ONLY: a BARE user
   metadata_protection bracket arriving WITHOUT the mandated outer whole-RTPS (SRTPS) wrap (§8.5.1.10-.12) is a
   forgeable un-wrapped injection -> DROPPED fail-closed, mirroring the sibling plain-user-DATA/HEARTBEAT/ACKNACK/
   GAP enforcement. The LEGITIMATE path re-dispatches post-SRTPS-decode with rtps-unwrapped=t, so ENFORCE-RTPS is
   NIL there and the inner user bracket IS delivered. BUILTIN secure brackets (secure-SEDP/PVMS/SPDP) are NEVER
   enforce-gated — metatraffic is intentionally plain this slice (the T12 carry), so they stay exempt (no false-REJECT).
   ORIGIN AUTH (T-ORIGINAUTH): when the secure-builtin path is taken, also resolve the LOCAL receiving READER's
   receiver descriptor (key_id . key) for this bracket's channel via SECURE-SEDP-DECODE-RECEIVER-KM — which maps the
   wire key_id -> the remote sender's entity-id -> the matching local reader's receiver key, covering EVERY secure
   builtin tier (SEDP/PM/SPDP), NIL when origin-auth is not in effect — and pass it to %on-secure-builtin so the
   receiver-specific MAC is verified (§9.5.3.3.4.3). NIL -> no origin-auth verification (the common_mac alone governs).
   ZERO-ALLOC (WP-DDS-SECURITY-ZEROALLOC-AEAD T5 / ZA-2): the wire key_id is read into a per-thread 4-octet buffer
   borrowed from the KEY-ID-RX pool (%with-key-id-rx-scratch; a dynamic-extent stack array does NOT stack-allocate for a
   specialized (unsigned-byte 8) array on this SBCL) via %secure-bracket-key-id-into — no per-bracket subseq — and the
   equalp-keyed resolvers hash/compare it without retaining, so the USER metadata_protection route (BRACKET + BRACKET-LEN
   passed BY OFFSET to %on-user-secure-submessage, which decodes into a pooled SECURE-RX buffer) conses ~0 GC-heap
   B/bracket. Runtime key_id-pool EXHAUSTION -> the borrow is NIL -> a fail-closed drop; a not-carved pool (arena
   exhausted) -> a heap 4-array fallback (byte-identical). The BUILTIN secure-SEDP / PVMS routes are the allocating
   control-plane (discovery, not the per-sample data path): they take an exact-length (subseq BRACKET 0 BRACKET-LEN),
   preserving their prior exact-vector input — the pre-T5 per-bracket alloc simply moves here from %handle-datagram's
   make-array, net-neutral on the control plane and REMOVED from the user data plane."
  (flet ((dispatch (kid-buf)
           (let* ((key-id   (%secure-bracket-key-id-into kid-buf bracket bracket-len))
                  (user-fn  (disc-node-user-submessage-decode node))
                  (ukm      (and user-fn key-id (funcall user-fn key-id))))
             (if ukm
                 ;; Slice 5: a USER-endpoint bracket (metadata_protection, §8.5.1.7-.9) — its key_id resolved to a remote
                 ;; USER EntityCrypto (not a secure builtin). T10 review fix-1: DROP a BARE (non-SRTPS-wrapped) user
                 ;; bracket when rtps_protection is REQUIRED from this :keyed source (ENFORCE-RTPS) — the forgeable
                 ;; un-wrapped framing the §8.5.1.10-.12 enforcement closes; ENFORCE-RTPS is NIL on the legitimate
                 ;; post-SRTPS re-dispatch (rtps-unwrapped=t), so a properly wrapped bracket IS decoded + re-dispatched.
                 ;; ZA-2: BRACKET + BRACKET-LEN BY OFFSET (no subseq) — the zero-alloc data-plane receive.
                 (unless enforce-rtps
                   (%on-user-secure-submessage node src-prefix bracket bracket-len ukm))
                 (let* ((resolver (disc-node-secure-sedp-decode-km node))
                        (recvres  (disc-node-secure-sedp-decode-receiver-km node))
                        (km       (and resolver key-id (funcall resolver key-id))))
                   ;; BUILTIN secure-SEDP / PVMS control-plane (allocating): an exact-length (subseq BRACKET 0 BRACKET-LEN)
                   ;; preserves the pre-T5 exact-vector input (the make-array moves here from %handle-datagram, net-neutral).
                   (if km
                       (let ((rd (and recvres key-id (funcall recvres key-id))))   ; (key_id . key) | nil
                         (%on-secure-builtin node src-prefix (subseq bracket 0 bracket-len) km (car rd) (cdr rd)))
                       (%on-volatile-secure node src-prefix (subseq bracket 0 bracket-len))))))
           t))
    ;; ZA-2: borrow the per-thread key_id scratch (alloc-free); a not-carved pool (arena exhausted) -> a heap 4-array
    ;; fallback (byte-identical, self-heals). DISPATCH is called directly (no heap closure), so the common path conses 0.
    (let ((pool (%ensure-key-id-rx-pool node)))
      (if pool
          (%with-key-id-rx-scratch (kb node) (dispatch (dds.core.buffer:octet-buffer-vec kb)))
          (dispatch (make-array 4 :element-type '(unsigned-byte 8))))))
  t)

(defun* %on-user-secure-submessage (node src-prefix bracket bracket-len km)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (*))
               fixnum dds.security:key-material) t)
  "Receiver thread: a USER-endpoint SEC_PREFIX … SEC_POSTFIX submessage-protection bracket in BRACKET[0,BRACKET-LEN)
   (BRACKET may be a longer POOLED buffer — WP-DDS-SECURITY-ZEROALLOC-AEAD T5 — so BRACKET-LEN bounds it) from SRC-PREFIX whose
   transformation_key_id resolved (USER-SUBMESSAGE-DECODE) to the remote user EntityCrypto KM (DDS-Security 1.1
   §8.5.1.7-.9, metadata_protection). Recover the plaintext user submessage (decode-datawriter-submessage-into decodes
   ANY §8.5 bracket — DataWriter or DataReader share one transform) and RE-DISPATCH it through the normal user data
   path: synthesize a one-submessage datagram carrying SRC-PREFIX's RTPS Header (so %source-prefix keys the sender
   correctly, §9.4.4) followed by the recovered submessage, and feed it to %handle-datagram with RTPS-UNWRAPPED set —
   the bracket's AEAD already authenticated it, so the plain-user-DATA rtps_protection enforcement must NOT re-drop it.
   So a recovered DATA reaches the user reader (its payload data_protection-decoded by the crypto-transform on-data
   path), a HEARTBEAT/ACKNACK/GAP drives the user reliable engine — IDENTICAL to a plain user submessage, only the wire
   framing differed.
   ZERO-ALLOC (WP-DDS-SECURITY-ZEROALLOC-AEAD T4 / ZA-2): the synthetic datagram is built in a REUSED per-node RX buffer
   borrowed from the SECURE-RX pool (%with-secure-rx-scratch over %ensure-secure-rx-pool — the SAME pool the SRTPS
   unwrap uses, which by then has RELEASED its borrow: the SRTPS re-dispatch happens OUTSIDE its %with-secure-rx-scratch
   scope, so at most ONE RX buffer is held per receiver thread here), dropping the pre-ZA-2 per-call
   (make-octet-buffer (+ 20 (length plain))). decode-datawriter-submessage-into writes the ENCRYPT plaintext straight
   into the RX buffer at offset 20 (leaving room for the 20-octet header); SIGN moves the verbatim submessage into
   [20,…) in place. CONCURRENCY: each receiver thread (unicast / multicast / SHMEM) gets a DISTINCT RX buffer, so the
   decode->re-dispatch window never races (the T3(ZA-2) RX-pool fix). LIFETIME: the RX buffer is held across the
   recursive %handle-datagram and released after — SAFE because the inner dispatch consumes the datagram SYNCHRONOUSLY
   (the inner data_protection DATA copies its payload into its OWN distinct ZA-1 decode loan; the on-data hook copies
   the payload region before returning — the very invariant the pre-ZA-2 code already relied on when it free-static'd
   its buffer right after %handle-datagram), and the recovered submessage is a plain DATA/HEARTBEAT/ACKNACK/GAP, never
   another SEC_PREFIX, so there is no further RX-pool borrow to nest. FAIL-CLOSED (NFR-SEC-POSTURE): an undecryptable /
   malformed / truncated / tampered bracket, or a recovered datagram that would not fit the RX buffer -> a silent DROP
   (no synthetic dispatch, no signal out, no plaintext on failure). If the RX pool could not be carved (arena exhausted)
   the recover DEGRADES to the allocating decode-datawriter-submessage (correct, byte-identical), self-healing when the
   arena frees."
  (let ((pool (%ensure-secure-rx-pool node)))
    (if pool
        ;; ZA-2: decode the bracket INTO a distinct reused RX buffer at offset 20, prepend the RTPS Header, re-dispatch.
        (%with-secure-rx-scratch (rx node)
          (handler-case
              (let ((vec (dds.core.buffer:octet-buffer-vec rx))
                    (cap (dds.core.buffer:octet-buffer-capacity rx)))
                (multiple-value-bind (data-len mode data-off postfix-off)
                    (dds.security:decode-datawriter-submessage-into rx 20 km bracket 0 bracket-len)
                  (declare (ignore postfix-off))
                  (when (and data-len (>= data-len 4) (<= (+ 20 data-len) cap))
                    (ecase mode
                      (:encrypt nil)   ; plaintext already written into rx[20,20+data-len) by decode-into
                      (:sign (replace vec bracket :start1 20 :end1 (+ 20 data-len)   ; verbatim region -> [20,…) in place
                                      :start2 data-off :end2 (+ data-off data-len))))
                    (let ((mc (dds.core.buffer:cursor rx :endianness :little)))
                      (dds.rtps.message:write-header mc src-prefix))   ; 20-octet RTPS Header w/ SRC prefix at [0,20)
                    (%handle-datagram node rx (+ 20 data-len) t))))   ; t = rtps-unwrapped (AEAD already authenticated)
            (error () nil)))   ; decode / bounds failure -> fail-closed drop
        ;; RX pool carve failed (arena exhausted): allocating fallback — correct + byte-identical, self-heals. An
        ;; exact-length (subseq BRACKET 0 BRACKET-LEN) since BRACKET may be a longer pooled buffer (T5).
        (let ((plain (dds.security:decode-datawriter-submessage km (subseq bracket 0 bracket-len))))
          (when (and plain (>= (length plain) 4))
            (let ((buf (dds.core.buffer:make-octet-buffer (+ 20 (length plain)))))
              (unwind-protect
                   (let ((mc (dds.core.buffer:cursor buf :endianness :little)))
                     (dds.rtps.message:write-header mc src-prefix)
                     (dds.core.buffer:put-octets mc plain 0 (length plain))
                     (%handle-datagram node buf (dds.core.buffer:cursor-position mc) t))
                (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))))))))
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

(defconstant +secure-metatraffic-buffer-slack+ 160
  "Octet slack the fresh per-call secure-metatraffic send buffer reserves ABOVE the submessage-protected bracket
   length so the OUTER T10 whole-RTPS-message (rtps_protection) SRTPS wrap can be applied IN PLACE (§8.5.1.10-.12).
   %maybe-wrap-srtps overwrites [20,…) of BUF, growing it by the RTPS Header(20) + the §9.5.3.3.5 source-binding
   INFO_SRC prepended to the plaintext (24) + the max SRTPS ENCRYPT overhead = SRTPS_PREFIX(4+CryptoHeader 20 = 24)
   + SEC_BODY(4 hdr + 4 CryptoContent-len + ≤3 pad = ≤11) + SRTPS_POSTFIX(4 hdr + common_mac 16 + count 4 = 24),
   plus the *_WITH_ORIGIN_AUTHENTICATION receiver-MAC footer (≤ +20) — ≤ ~123 octets total; 160 is that worst
   case + margin. NOT a wire constant (a local buffer-size policy). The
   pre-Phase-4 slack was 64, which fit an UNWRAPPED bracket only — too small once secure metatraffic is SRTPS-
   wrapped, so %maybe-wrap-srtps silently fail-closed-DROPPED the datagram (the datagram never reached a keyed
   Connext peer, matched=0). §8.5.1.10-.12.")

(defun* %send-secure-bracket (node km kind plain receivers host port dest-prefix &key reader)
    (function (disc-node dds.security:key-material (member :sign :encrypt)
               (simple-array (unsigned-byte 8) (*)) list string (unsigned-byte 16)
               (or null (simple-array (unsigned-byte 8) (12)))
               &key (:reader t)) t)
  "Submessage-PROTECT one PLAINTEXT submessage PLAIN under the LOCAL secure-builtin EntityCrypto KM per the
   governance-EFFECTIVE KIND (the T2/T3 codec, DDS-Security 1.1 §8.5.1.7/.8) and send the SEC_PREFIX ...
   SEC_POSTFIX bracket as ONE datagram to HOST:PORT. :encrypt -> SEC_PREFIX ‖ CryptoHeader ‖
   SEC_BODY[ciphertext] ‖ SEC_POSTFIX (the plaintext is HIDDEN, §9.4.1.2.3 ENCRYPT); :sign -> SEC_PREFIX ‖
   CryptoHeader ‖ the submessage VERBATIM ‖ SEC_POSTFIX[GMAC] (authenticated-but-VISIBLE, §9.4.1.2.3 SIGN).
   READER selects the §8.5 transform: NIL (default) -> encode-datawriter-submessage (DATA / HEARTBEAT, a
   writer submessage); T -> encode-datareader-submessage (ACKNACK, a reader submessage) — the two delegate to
   ONE engine (byte-identical wire), the split is only which §8.5 codec the receiver pairs for decode.
   KIND is the node's installed governance-EFFECTIVE base kind (HONORING the directive, never a hardcoded
   ENCRYPT). RECEIVERS is the origin-authentication receiver list (§9.5.3.3.4.3, T-ORIGINAUTH); EMPTY (the
   default for a non-origin-auth kind) emits no receiver-specific MAC (plain SIGN/ENCRYPT, byte-identical).
   Default session_id is safe (each EntityCrypto KM is INDEPENDENT per endpoint — no symmetric-key nonce hazard,
   unlike PVMS). The shared PROTECT+SEND tail of every secure builtin submessage (SEDP DATA / participant-message
   / SPDP / the secure-SEDP reliability HEARTBEAT+ACKNACK — DRY, T11). A no-op (still T) if the codec returns
   NIL. Fresh per-call buffer (control-plane), freed.
   DEST-PREFIX (the 12-octet destination-participant GUID-prefix) threads to %send-msg-buf -> %send-raw-buf so
   T10 whole-RTPS-message protection (rtps_protection, DDS-Security 1.1 §8.5.1.10-.12 / §9.4.1.2.3) SRTPS-wraps
   the WHOLE datagram when DEST-PREFIX is :keyed under a non-NONE governance rtps_protection_kind — the secure
   metatraffic (secure-SEDP / secure-PM / secure-SPDP) is then DOUBLY protected (inner submessage-protection +
   outer whole-RTPS), which a strict rtps_protection=ENCRYPT peer (live RTI Connext) REQUIRES: it DROPS a
   non-SRTPS metatraffic datagram from a keyed participant ('received unencoded rtps message. Unacceptable due
   to is_rtps_*_protected = true'). NIL / not-keyed / rtps_protection NONE -> %maybe-wrap-srtps no-ops
   (byte-identical plain), so DEST-PREFIX is safe to thread unconditionally; the inner SEC_* bracket carries no
   user-plane submessage id, so the metadata_protection walk (%maybe-wrap-user-submessages) is a verbatim no-op."
  (let ((secured (if reader
                     (dds.security:encode-datareader-submessage km kind plain :receivers receivers)
                     (dds.security:encode-datawriter-submessage km kind plain :receivers receivers))))
    (when secured
      (let ((buf (dds.core.buffer:make-octet-buffer (+ +secure-metatraffic-buffer-slack+ (length secured)))))
        (unwind-protect
             (%send-msg-buf node buf
                            (lambda (mc) (dds.core.buffer:put-octets mc secured 0 (length secured)))
                            host port dest-prefix)
          (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))))))
  t)

(defun* %send-secure-endpoint (node km kind reader-id writer-id ep sn host port receivers dest-prefix)
    (function (disc-node dds.security:key-material (member :sign :encrypt) (unsigned-byte 32) (unsigned-byte 32)
               dds.rtps.discovery:endpoint-data integer string (unsigned-byte 16) list
               (or null (simple-array (unsigned-byte 8) (12)))) t)
  "Announce ONE local endpoint EP over the SECURE SEDP writer WRITER-ID to HOST:PORT: build the plaintext
   SEDP DATA submessage (%build-secure-sedp-data) with the STABLE per-writer SN, then submessage-PROTECT + send
   it (%send-secure-bracket) under the LOCAL secure-SEDP EntityCrypto KM per the governance-EFFECTIVE KIND
   (RECEIVERS = the matched-remote READER's origin-auth descriptors, §9.5.3.3.4.3 / T-ORIGINAUTH). Re-announcing
   an endpoint RESENDS the same SN (a retransmission), like plain SEDP %send-endpoint, so a reliable peer never
   gaps. DEST-PREFIX (the destination-participant GUID-prefix) threads to %send-secure-bracket for the outer
   T10 whole-RTPS-message (rtps_protection) SRTPS wrap on this secure-SEDP DATA when the peer is :keyed under a
   non-NONE rtps_protection_kind (§8.5.1.10-.12) — required by a strict rtps_protection=ENCRYPT peer. A no-op
   (still T) if the codec returns NIL."
  (%send-secure-bracket node km kind (%build-secure-sedp-data reader-id writer-id sn ep) receivers host port
                        dest-prefix))

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
                                             w wsn (car hp) (cdr hp) wreceivers prefix))))
                (when rkm
                  (let ((rreceivers (and recv (funcall recv
                                                       dds.rtps.discovery:+entityid-sedp-sub-secure-writer+
                                                       prefix))))
                    (loop for r in sec-readers for rsn from 1 do
                      (%send-secure-endpoint node rkm kind
                                             dds.rtps.discovery:+entityid-sedp-sub-secure-reader+
                                             dds.rtps.discovery:+entityid-sedp-sub-secure-writer+
                                             r rsn (car hp) (cdr hp) rreceivers prefix)))))))))))
  t)

;;; --- T9pull: secure-SEDP RELIABILITY (HEARTBEAT/ACKNACK over the protected builtin endpoints) ---
;;; A reliable secure-SEDP/PM writer (Fast DDS RTPSMessageGroup add_heartbeat/add_acknack ->
;;; encode_writer/reader_submessage when is_submessage_protected) drives its matched reader via
;;; submessage-PROTECTED HEARTBEAT/ACKNACK, never a clear one (MessageReceiver drops a clear submessage on a
;;; protected endpoint: was_decoded || !is_submessage_protected). %on-secure-builtin demuxes them here.
;;; Corroborated CLEAN-ROOM vs Fast DDS (docs/provenance.md); RTI never read. The our-to-our secure SEDP also
;;; push-announces (announce-endpoints cadence), so these branches only ADD repair (a lost DATA is re-pulled)
;;; and the cross-vendor pull — they never replace the push, and a fully-received reader ACKs (numBits 0 ->
;;; no resend), so our-to-our stays green.

(defun* %on-secure-builtin-heartbeat (node src-prefix wid first last)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) integer integer) t)
  "Receiver thread: an inner HEARTBEAT [FIRST,LAST] (decoded from a protected secure-builtin bracket) from
   remote SRC-PREFIX's secure-builtin writer WID. Apply the range to the per-remote builtin reader (keyed by
   WID, reusing %builtin-acknack-values + the plain-SEDP builtin-readers — the SNs were recorded by the DATA
   branch's %builtin-on-data) and send the computed ACKNACK submessage-PROTECTED (the governance KIND) under
   OUR matched LOCAL receiving reader's EntityCrypto (%secure-reader-eid-for-writer WID -> secure-sedp-encode-km),
   encoded as a DataReader submessage (:reader t), to SRC-PREFIX's metatraffic locator (RTPS 2.5 §8.3.7.1;
   DDS-Security 1.1 §8.5.1.8/.9 — the ACKNACK rides protected, a CLEAR one is dropped by a conformant secure
   writer). The NACK-pull that delivers a reliable Fast DDS writer's DiscoveredWriter/ReaderData (it sends only
   HEARTBEATs to an unacked late-joining reader-proxy, waiting for the ACKNACK before pushing DATA). The matched
   remote WRITER holds no receiver-specific key (§9.5.3.3.4.3 — only readers mint one), so receivers = EMPTY
   (common_mac only). A no-op (still T) when WID is not a secure builtin writer, our local reader EntityCrypto is
   not yet registered, or SRC-PREFIX has no resolved metatraffic locator (fail-closed, NFR-SEC-POSTURE)."
  (let* ((reader-eid (%secure-reader-eid-for-writer wid))
         (enc        (disc-node-secure-sedp-encode-km node))
         (km         (and enc reader-eid (funcall enc reader-eid)))   ; LOCAL receiving reader's EntityCrypto
         (hp         (%remote-metatraffic node src-prefix))
         (kind       (disc-node-secure-sedp-protection-kind node)))
    (when (and km hp)
      (multiple-value-bind (base numbits bitmap count)
          (%builtin-acknack-values node src-prefix wid first last)
        (%send-secure-bracket node km kind
                              (%build-plain-acknack-sm reader-eid wid base numbits bitmap count)
                              '() (car hp) (cdr hp) src-prefix :reader t))))
  t)

(defun* %on-secure-builtin-acknack (node src-prefix c flags)
    (function (disc-node (simple-array (unsigned-byte 8) (12)) dds.core.buffer:cursor (unsigned-byte 8)) t)
  "Receiver thread: parse the inner ACKNACK (decoded from a protected secure-builtin bracket; CURSOR at the
   ACKNACK body) from remote SRC-PREFIX's secure-SEDP reader. When it targets OUR secure-SEDP publications
   (0xff0003c2) or subscriptions (0xff0004c2) writer, RESEND each NACKed DiscoveredWriter/ReaderData (the SN
   is the endpoint's stable 1-based add-order index, %secure-endpoints-for) as a freshly-protected secure-SEDP
   DATA to SRC-PREFIX (%send-secure-endpoint, the SAME protect path the announce uses, with the matched-remote
   reader's origin-auth receivers). The repair for a dropped secure-SEDP DATA and the response to Fast DDS's
   initial pull (its reader NACKs 1..N off our HEARTBEAT). NIL/no-op for any other writer or when not keyed /
   no locator (fail-closed). NACKed SNs are read base+bit exactly as dds.rtps.reliable:writer-on-acknack does."
  (multiple-value-bind (rid wid base numbits bitmap count finalp)
      (dds.rtps.message:parse-acknack-body c flags)
    (declare (ignore rid count finalp))
    (let ((pub-p (and wid (= wid dds.rtps.discovery:+entityid-sedp-pub-secure-writer+)))
          (sub-p (and wid (= wid dds.rtps.discovery:+entityid-sedp-sub-secure-writer+))))
      (when (or pub-p sub-p)
        (let* ((enc   (disc-node-secure-sedp-encode-km node))
               (km    (and enc (funcall enc wid)))    ; LOCAL secure-SEDP writer's EntityCrypto
               (hp    (%remote-metatraffic node src-prefix))
               (protp (disc-node-discovery-protected-topic-p node))
               (kind  (disc-node-secure-sedp-protection-kind node))
               (recv  (disc-node-secure-sedp-encode-receivers node)))
          (when (and km hp protp base)
            (let* ((reader-id (if pub-p dds.rtps.discovery:+entityid-sedp-pub-secure-reader+
                                  dds.rtps.discovery:+entityid-sedp-sub-secure-reader+))
                   (eps       (%secure-endpoints-for node protp
                                                     (if pub-p #'disc-node-local-writers #'disc-node-local-readers)))
                   (n         (length eps))
                   (receivers (and recv (funcall recv wid src-prefix))))
              (dotimes (i numbits)
                (when (dds.rtps.message:seqnum-set-bit-p bitmap i)
                  (let ((sn (+ base i)))
                    (when (<= 1 sn n)
                      (%send-secure-endpoint node km kind reader-id wid (nth (1- sn) eps) sn
                                             (car hp) (cdr hp) receivers src-prefix)))))))))))
  t)

(defun* %send-secure-builtin-heartbeats (node)
    (function (disc-node) (eql t))
  "Announce thread: emit a NON-FINAL secure-SEDP HEARTBEAT [1,N] from each protected local secure-SEDP writer
   (publications 0xff0003c2 over the local writers, subscriptions 0xff0004c2 over the local readers; N = that
   channel's discovery-PROTECTED endpoint count) to every :keyed peer, submessage-PROTECTED under the LOCAL
   secure-SEDP-writer EntityCrypto per the governance KIND with the matched-remote reader's origin-auth receivers
   — the periodic re-solicit (RTPS 2.5 §8.4.2.2) that makes a reliable Fast DDS secure-SEDP reader NACK-pull OUR
   DiscoveredWriter/ReaderData (without it Fast DDS never matches us). The destination reader is
   %secure-reader-eid-for-writer (the peer's matched secure-SEDP reader). A no-op (still T) when secure discovery
   is not active (no encode-KM / no protected-topic predicate), the local EntityCrypto is not registered, the
   channel has NO protected endpoints, or there are no :keyed peers — so security OFF is byte-identical. Fanned
   over %pvms-authenticated-prefixes (the :keyed peers, like %announce-secure-endpoints / PVMS); a not-yet-keyed
   or PLAIN peer is never in that set (the non-vacuous-control invariant). Fresh per-call buffers (control-plane)."
  (let ((enc   (disc-node-secure-sedp-encode-km node))
        (recv  (disc-node-secure-sedp-encode-receivers node))
        (protp (disc-node-discovery-protected-topic-p node))
        (kind  (disc-node-secure-sedp-protection-kind node)))
    (when (and enc protp)
      (dolist (ch (list (cons dds.rtps.discovery:+entityid-sedp-pub-secure-writer+ #'disc-node-local-writers)
                        (cons dds.rtps.discovery:+entityid-sedp-sub-secure-writer+ #'disc-node-local-readers)))
        (let* ((wid        (car ch))
               (km         (funcall enc wid))
               (n          (length (%secure-endpoints-for node protp (cdr ch))))
               (reader-eid (%secure-reader-eid-for-writer wid)))
          (when (and km reader-eid (plusp n))
            (dolist (prefix (%pvms-authenticated-prefixes node))
              (let ((hp (%remote-metatraffic node prefix)))
                (when hp
                  (let ((receivers (and recv (funcall recv wid prefix))))
                    (%send-secure-bracket node km kind
                                          (%build-plain-heartbeat-sm reader-eid wid 1 n
                                                                     (incf (disc-node-ack-count node)))
                                          receivers (car hp) (cdr hp) prefix))))))))))
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
                       receivers (car hp) (cdr hp) prefix)))))))))))
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
                     receivers (car hp) (cdr hp) prefix))))))))))
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

(defvar *za2-rx-ctx* nil
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T3(ZA-2) concurrency-test scratch: per-receiver-thread cons
   (EXPECTED-PAYLOAD . MISMATCH-COUNT) the shared node-b ON-DATA hook checks each SRTPS re-dispatch delivery
   against, to prove concurrent receiver threads never contaminate each other's RX decode sink. Bound per thread
   inside run-rtps-protection-zeroalloc-test; NIL (ignored) otherwise. Test-internal, not an API symbol.")

(defun* run-rtps-protection-zeroalloc-test ()
    (function () (eql t))
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T3 (ZA-2) + T3(ZA-2) review: the whole-RTPS (rtps_protection / SRTPS) dataplane is
   ZERO-ALLOC and CONCURRENCY-SAFE — the SEND wrap borrows a per-node send-scratch pool + encode-rtps-message-into (no
   per-datagram plain-region subseq, no →octets); the RX unwrap borrows a DISTINCT buffer per decode from a per-node RX
   pool (SECURE-RX-POOL) and opens ENCRYPT plaintext into it via decode-rtps-message-into, so the concurrent unicast /
   multicast / SHMEM receiver threads never share a decode sink. A is the sender; B the receiver holding A's
   ParticipantCrypto. Asserts (ENCRYPT):
     (a) ROUND-TRIP: a pooled-send SRTPS datagram (first submessage SRTPS_PREFIX 0x33, payload confidential) unwraps
         through the pooled RX path and delivers the inner user DATA byte-EXACT — exercising BOTH rewired paths; the
         send-scratch pool + SECURE-RX-POOL are carved (lazy) after the first wrap/unwrap.
     (b) ZERO-ALLOC (send): a steady-state SRTPS wrap over the reused tx-msg + pooled scratch conses ~0 GC-heap
         B/datagram (SBCL-exact via dds.pal:bytes-consed; Clasp reports 0 -> skip, NFR-PORT), vs the pre-rewire
         subseq+encode-rtps-message path. The check is written to FAIL if the new wrap still allocates.
     (c) EXHAUSTION: with the send-scratch pool fully drained, %maybe-wrap-srtps returns NIL (fail-closed drop,
         RESOURCE_LIMITS backpressure) — never a GC fallback.
     (d) CONCURRENCY (the review fix): N receiver threads each feeding their OWN distinct SRTPS-ENCRYPT datagram
         through %handle-datagram recover ITS OWN plaintext — zero cross-thread contamination (this arm FAILS on the
         pre-fix single shared RX buffer, verified RED before the fix). Plus a deterministic distinctness check: two
         concurrent RX-pool borrows return distinct buffers.
     (f) ZERO-ALLOC (RX): a steady-state pooled RX borrow + decode-rtps-message-into conses ~0 GC-heap B/datagram
         (SBCL-exact; Clasp skip, NFR-PORT) — the pooled RX borrow adds no allocation over the pre-review single buffer.
   Requires AES-GCM; skips gracefully if absent. Both impls (Clasp first)."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [rtps-protection-zeroalloc] SKIP — AES-GCM not available: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-rtps-protection-zeroalloc-test t)))
  (let* ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 71))
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 72))
         (node-a (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
         (node-b (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (km-a (%secure-sedp-test-km 7 #x33))   ; A's ParticipantCrypto; B holds the SAME
         (payload (map '(simple-array (unsigned-byte 8) (*)) #'char-code "ZEROALLOC-SRTPS!"))
         (host "127.0.0.1") (port 7) (srtps-dg nil))
    (unwind-protect
         (progn
           (setf (disc-node-rtps-protection-kind node-a) :encrypt
                 (disc-node-rtps-protection-encode node-a)
                 (lambda (dp) (declare (ignore dp)) (values km-a :encrypt '())))
           ;; (a) ROUND-TRIP through the pooled send + pooled-RX path
           (let ((cap nil))
             (let ((buf (disc-node-tx-msg node-a)) (*datagram-sink* (lambda (dg) (setf cap dg))))
               (%send-raw-buf node-a buf (%rtps-build-user-datagram node-a buf 1 payload) host port nil pb))
             (assert (and (> (length cap) 20) (= (aref cap 20) dds.security:+submessage-srtps-prefix+)) ()
                     "ZA-2 round-trip: the pooled send must produce an SRTPS datagram (first submessage SRTPS_PREFIX 0x33)")
             (assert (not (search payload cap)) ()
                     "ZA-2 round-trip: ENCRYPT must hide the user payload on the wire")
             (assert (disc-node-send-scratch-pool node-a) ()
                     "ZA-2: the per-node send-scratch pool must be carved (lazy) after the first wrap")
             (let ((got nil))
               (setf (disc-node-rtps-protection-decode node-b) (lambda (sp) (declare (ignore sp)) (values km-a nil nil))
                     (disc-node-on-data node-b)
                     (lambda (w sn b poff plen sp og os kh) (declare (ignore w sn sp og os kh))
                       (setf got (subseq (dds.core.buffer:octet-buffer-vec b) poff (+ poff plen)))))
               (%rtps-feed-datagram node-b cap)
               (assert (and got (equalp got payload)) ()
                       "ZA-2 round-trip: B must recover the inner user DATA byte-exact through the reused-RX decode-rtps-message-into path")
               (assert (disc-node-secure-rx-pool node-b) ()
                       "ZA-2: the per-node RX decode pool (SECURE-RX-POOL) must be carved (lazy) after the first unwrap")
               (setf srtps-dg cap)))   ; keep a clean SRTPS datagram for the RX arms (cap is a fresh subseq; decode never mutates it)
           ;; (a2) DISTINCTNESS (deterministic, T3(ZA-2) review): two concurrent RX-pool borrows return DISTINCT buffers,
           ;; so receiver threads decoding at once never share a sink — the mechanism that closes the race.
           (let* ((pool (%ensure-secure-rx-pool node-b))
                  (b1 (dds.core.arena:pool-acquire pool))
                  (b2 (dds.core.arena:pool-acquire pool)))
             (unwind-protect
                  (assert (and b1 b2 (not (eq b1 b2))) ()
                          "ZA-2 distinctness: the RX pool must hand two concurrent borrows DISTINCT buffers (no shared decode sink)")
               (when b2 (dds.core.arena:pool-release pool b2))
               (when b1 (dds.core.arena:pool-release pool b1))))
           ;; (b) ZERO-ALLOC bytes-consed: before (subseq+encode-rtps-message) vs after (%maybe-wrap-srtps), reused buffers
           (let* ((buf (disc-node-tx-msg node-a))
                  (vec (dds.core.buffer:octet-buffer-vec buf))
                  (plen (%rtps-build-user-datagram node-a buf 1 payload))
                  (plain-copy (subseq vec 0 plen))   ; the plaintext datagram to restore before each wrap
                  (iters 4000))
             (dds.security:encode-rtps-message km-a :encrypt (subseq vec 20 plen))   ; warm the old path
             (replace vec plain-copy :end2 plen) (%maybe-wrap-srtps node-a buf plen pb)   ; warm the new path
             (let ((old-b (let ((before (dds.pal:bytes-consed)))
                            (dotimes (i iters)
                              (dds.security:encode-rtps-message km-a :encrypt (subseq vec 20 plen)))   ; the pre-rewire allocating path
                            (- (dds.pal:bytes-consed) before)))
                   (new-b (let ((before (dds.pal:bytes-consed)))
                            (dotimes (i iters)
                              (replace vec plain-copy :end2 plen)       ; restore the plaintext (into the reused buf; 0 cons)
                              (%maybe-wrap-srtps node-a buf plen pb))   ; the pooled zero-alloc wrap
                            (- (dds.pal:bytes-consed) before))))
               (let ((old-per (/ (float old-b) iters)) (new-per (/ (float new-b) iters)))
                 (format t "~&  [rtps-protection-zeroalloc] SRTPS wrap bytes/datagram: before(subseq+encode-rtps-message)=~,2f  after(pooled -into)=~,2f (~d iters)~%"
                         old-per new-per iters)
                 (if (zerop (dds.pal:bytes-consed))
                     (format t "  [skip] dds.pal:bytes-consed is 0 on this impl (Clasp NFR-PORT gap) — SRTPS wrap alloc not measurable~%")
                     (progn
                       (assert (< new-per 1.0) ()
                               "ZA-2: the pooled SRTPS wrap must cons ~~0 GC-heap B/datagram; got ~,2f (would FAIL on the pre-rewire subseq+encode-rtps-message path, ~,2f)" new-per old-per)
                       (assert (< new-per (* 0.25 old-per)) ()
                               "ZA-2: the pooled wrap (~,2f B) must cons far less than the old subseq+encode path (~,2f B)" new-per old-per))))))
           ;; (c) EXHAUSTION -> fail-closed NIL (never a GC fallback)
           (let* ((buf (disc-node-tx-msg node-a))
                  (pool (disc-node-send-scratch-pool node-a))
                  (plen (%rtps-build-user-datagram node-a buf 1 payload))   ; buf holds a fresh plaintext datagram
                  (held '()))
             (loop for b = (dds.core.arena:pool-acquire pool) while b do (push b held))   ; drain the pool
             (unwind-protect
                  (assert (null (%maybe-wrap-srtps node-a buf plen pb)) ()
                          "ZA-2 exhaustion: %maybe-wrap-srtps must return NIL (fail-closed drop) when the send-scratch pool is exhausted — never a GC fallback")
               (dolist (b held) (dds.core.arena:pool-release pool b))))
           ;; (d) CONCURRENCY — NO CROSS-CONTAMINATION across the receiver threads that share node-b's RX decode sink
           ;; (T3(ZA-2) review). NTHREADS threads each feed their OWN distinct (same-length) SRTPS-ENCRYPT datagram
           ;; through %handle-datagram in a tight loop; the shared ON-DATA checks every re-dispatch delivery equals
           ;; THAT thread's payload. On a single shared RX buffer the decode->copy-back window races (thread A copies
           ;; B's just-decoded plaintext into A's datagram -> wrong-sample delivery); a distinct buffer per decode
           ;; (the RX pool) closes it. The 0-mismatch assertion FAILS on the pre-fix single-buffer code.
           (let* ((nthreads 4) (iters 3000)
                  (payloads (loop for k below nthreads
                                  collect (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                                               (format nil "ZA2-CONCUR-T~d!!" k))))   ; distinct, all 16 octets
                  (dgs (loop for p in payloads
                             collect (let ((buf (disc-node-tx-msg node-a)) (out nil))
                                       (let ((*datagram-sink* (lambda (dg) (setf out dg))))
                                         (%send-raw-buf node-a buf (%rtps-build-user-datagram node-a buf 3 p) host port nil pb))
                                       out)))
                  (clock (dds.pal:make-lock "za2-concur")) (total-mismatch 0))
             (setf (disc-node-rtps-protection-decode node-b) (lambda (sp) (declare (ignore sp)) (values km-a nil nil))
                   (disc-node-on-data node-b)
                   (lambda (w sn b poff plen sp og os kh) (declare (ignore w sn sp og os kh))
                     (when *za2-rx-ctx*
                       (let ((exp (car *za2-rx-ctx*)))   ; in-place compare, no per-delivery cons
                         (unless (and (= plen (length exp))
                                      (null (mismatch exp (dds.core.buffer:octet-buffer-vec b) :start2 poff :end2 (+ poff plen))))
                           (incf (cdr *za2-rx-ctx*)))))))
             (%rtps-feed-datagram node-b (first dgs))   ; carve node-b's RX sink before the fan-out
             (let ((threads (loop for p in payloads for dg in dgs
                                  collect (dds.pal:spawn
                                           (let ((mp p) (mdg dg))
                                             (lambda ()
                                               (let ((*za2-rx-ctx* (cons mp 0)))
                                                 (dotimes (i iters) (%rtps-feed-datagram node-b mdg))
                                                 (dds.pal:with-lock (clock) (incf total-mismatch (cdr *za2-rx-ctx*))))))
                                           :name "za2-concur"))))
               (dolist (th threads) (dds.pal:join th)))
             (assert (zerop total-mismatch) ()
                     "ZA-2 concurrency: ~d cross-thread RX-buffer contaminations over ~d threads x ~d SRTPS-ENCRYPT decodes — concurrent receiver threads must NOT share a mutable decode sink" total-mismatch nthreads iters))
           ;; (f) ZERO-ALLOC (RX): a steady-state pooled RX borrow + decode-rtps-message-into over the reused SRTPS
           ;; ciphertext conses ~0 GC-heap B/datagram — the pooled borrow (O(1) index ops under the RX lock) adds no
           ;; allocation over the pre-review single reused buffer. SBCL-exact; Clasp bytes-consed=0 -> skip (NFR-PORT).
           (when srtps-dg
             (%ensure-secure-rx-pool node-b)
             (let ((slen (- (length srtps-dg) 20)) (iters 4000))
               (%with-secure-rx-scratch (rx node-b)                       ; warm
                 (dds.security:decode-rtps-message-into rx 0 km-a srtps-dg 20 slen))
               (let ((rx-b (let ((before (dds.pal:bytes-consed)))
                             (dotimes (i iters)
                               (%with-secure-rx-scratch (rx node-b)
                                 (dds.security:decode-rtps-message-into rx 0 km-a srtps-dg 20 slen)))
                             (- (dds.pal:bytes-consed) before))))
                 (let ((rx-per (/ (float rx-b) iters)))
                   (format t "~&  [rtps-protection-zeroalloc] SRTPS RX unwrap (pooled borrow + decode-rtps-message-into) bytes/datagram: ~,2f (~d iters)~%" rx-per iters)
                   (if (zerop (dds.pal:bytes-consed))
                       (format t "  [skip] dds.pal:bytes-consed is 0 on this impl (Clasp NFR-PORT gap) — SRTPS RX alloc not measurable~%")
                       (assert (< rx-per 1.0) ()
                               "ZA-2: the pooled SRTPS RX unwrap must cons ~~0 GC-heap B/datagram; got ~,2f" rx-per))))))
           t)
      (stop-node node-a) (stop-node node-b))))

(defun* run-user-submessage-protection-test ()
    (function () (eql t))
  "WP-DDS-SECURITY-FASTDDS-INTEROP (Slice 5): user-DATA submessage protection (metadata_protection_kind,
   DDS-Security 1.1 §8.5.1.7-.9) on the live disc data path — deterministic, no auth handshake (a manually-installed
   user EntityCrypto KM + the user-submessage-encode/decode closures stand in for the dds-dcps crypto-manager; the
   full :keyed participant e2e + the live Fast DDS cross-vendor run exercise the integrated path). A is the sender,
   B the receiver holding A's user-writer EntityCrypto. Asserts:
     (1) EXEMPTION: with the encode resolver installed but USER-SUBMESSAGE-PROTECTION-KIND :none, a send stays PLAIN
         (first submessage DATA 0x15) — gated on the kind, byte-identical to the non-secure path.
     (2) ENGAGEMENT: kind :encrypt -> the user DATA submessage is wrapped (first submessage SEC_PREFIX 0x31) and the
         payload never appears in cleartext (ENCRYPT).
     (3) 4-ALIGNMENT: the wrapped submessage stream is a 4-octet multiple — the §8.3.4 pad lives in the SEC_BODY
         CryptoContent container (NOT the plaintext), so a conformant receiver's body_align lands on the SEC_POSTFIX.
     (4) DECODE+DISPATCH: B (correct user EntityCrypto, resolved by transformation_key_id) decodes the bracket and
         delivers the inner user DATA through %on-user-secure-submessage -> %handle-datagram re-dispatch; the sent
         payload is recovered byte-EXACT (no trailing pad — the SEC_BODY carries the alignment, T10 review fix-2).
     (5) NON-VACUOUS: a receiver WITHOUT A's user EntityCrypto (wrong KM, same key_id) does NOT decode -> fail-closed.
   Requires the AES-GCM primitive; skips gracefully if absent. Both impls."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [user-submsg] SKIP — AES-GCM not available: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-user-submessage-protection-test t)))
  (let* ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 91))
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 92))
         (node-a (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
         (node-b (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (km       (%secure-sedp-test-km #x71 #x35))   ; A's user-writer EntityCrypto; B holds the SAME (received A's token)
         (km-wrong (%secure-sedp-test-km #x71 #x46))   ; SAME key_id, DIFFERENT key bytes — the non-vacuous wrong-key control
         (kid      (dds.security:key-material-sender-key-id km))
         ;; 13 octets -> DATA octetsToNextHeader 20+13=33 (NOT a 4-multiple): the SEC_BODY CryptoContent container
         ;; carries the §8.3.4 4-align pad after the ciphertext (the plaintext is NOT padded), exercising it.
         (payload (map '(simple-array (unsigned-byte 8) (*)) #'char-code "USERMETADATA!"))
         (host "127.0.0.1") (port 7) (cap nil))
    (unwind-protect
         (progn
           ;; (1) EXEMPTION — encode resolver installed, kind :none -> never wrapped (byte-identical plain path)
           (setf (disc-node-user-submessage-protection-kind node-a) :none
                 (disc-node-user-submessage-encode node-a)
                 (lambda (writer-p) (declare (ignore writer-p))
                   (unless (eq (disc-node-user-submessage-protection-kind node-a) :none)
                     (values km (disc-node-user-submessage-protection-kind node-a)))))
           (let ((buf (disc-node-tx-msg node-a)) (*datagram-sink* (lambda (dg) (setf cap dg))))
             (%send-raw-buf node-a buf (%rtps-build-user-datagram node-a buf 1 payload) host port nil pb))
           (assert (and (> (length cap) 20) (= (aref cap 20) dds.rtps.message:+submsg-data+)) ()
                   "user-submsg exemption: kind :none must stay PLAIN (first submessage DATA 0x15)")
           ;; (2) ENGAGEMENT — kind :encrypt -> SEC_PREFIX-wrapped + confidential
           (setf (disc-node-user-submessage-protection-kind node-a) :encrypt)
           (let ((buf (disc-node-tx-msg node-a)) (*datagram-sink* (lambda (dg) (setf cap dg))))
             (%send-raw-buf node-a buf (%rtps-build-user-datagram node-a buf 1 payload) host port nil pb))
           (assert (and (> (length cap) 20) (= (aref cap 20) dds.security:+submessage-sec-prefix+)) ()
                   "user-submsg engagement: kind :encrypt must wrap the user DATA (first submessage SEC_PREFIX 0x31)")
           (assert (not (search payload cap)) ()
                   "user-submsg ENCRYPT: the user payload must NOT appear in cleartext in the wrapped datagram")
           ;; (3) 4-ALIGNMENT — the wrapped submessage stream (after the 20-octet RTPS header) is a 4-multiple: the
           ;; SEC_BODY CryptoContent container carries the §8.3.4 pad, so a conformant peer's body_align lands on
           ;; the SEC_POSTFIX (the plaintext is NOT padded — Fast DDS serialize_SecureDataBody).
           (assert (zerop (mod (- (length cap) 20) 4)) ()
                   "user-submsg 4-align: the wrapped submessage stream must be a 4-octet multiple (got ~d)" (- (length cap) 20))
           ;; (4) DECODE+DISPATCH at B (correct user EntityCrypto, resolved by key_id) -> payload byte-EXACT (no pad)
           (let ((got nil))
             (setf (disc-node-user-submessage-decode node-b) (lambda (k) (when (equalp k kid) km))
                   (disc-node-on-data node-b)
                   (lambda (w sn b poff plen sp og os kh) (declare (ignore w sn sp og os kh))
                     (setf got (subseq (dds.core.buffer:octet-buffer-vec b) poff (+ poff plen)))))
             (%rtps-feed-datagram node-b cap)
             (assert (and got (equalp got payload)) ()
                     "user-submsg decode: B must recover + dispatch the inner user DATA payload byte-EXACT (no trailing pad)"))
           ;; (5) NON-VACUOUS — wrong user EntityCrypto (same key_id) -> fail-closed drop (on-data never fires)
           (let ((fired nil))
             (setf (disc-node-user-submessage-decode node-b) (lambda (k) (when (equalp k kid) km-wrong))
                   (disc-node-on-data node-b) (lambda (&rest r) (declare (ignore r)) (setf fired t)))
             (%rtps-feed-datagram node-b cap)
             (assert (null fired) ()
                     "user-submsg fail-closed: a peer WITHOUT A's user EntityCrypto must NOT decode the bracket"))
           t)
      (stop-node node-a) (stop-node node-b))))

(defun* run-user-submessage-data-protection-test ()
    (function () (eql t))
  "WP-DDS-SECURITY-FASTDDS-INTEROP (Slice 5): the TWO-TIER user-DATA case — both metadata_protection (the
   §8.5.1.7-.9 SEC_PREFIX submessage wrap) AND data_protection (the §9.5.3.3 serialized-payload SecuredPayload)
   ENCRYPT on a user DATA whose CDR plaintext length is NOT a 4-multiple. Both tiers Fast-DDS-faithful:
     - data_protection self-4-aligns the SecuredPayload (T11reverse cross-vendor fix): the §9.5.3.3.3
       SecureDataTag pads the receiver_specific_macs_count to a 4-byte boundary vs the SecuredPayload start
       (Fast DDS serialize_SecureDataTag), so a non-4-aligned ciphertext still yields a 4-aligned SecuredPayload.
       Omitting the pad made Fast DDS decode_serialized_payload mis-read the tag length ('Error in fastcdr
       trying to deserialize SecureDataTag length') -> the cross-vendor ours2fast user-DATA drop this closes.
     - metadata_protection keeps the 4-align pad inside the SEC_BODY CryptoContent, not the plaintext (Fast DDS
       serialize_SecureDataBody, L1677-1700: octetsToNextHeader=(N+4+3)&~3, cnt_length=N true, pad after the
       ciphertext), so the recovered inner DATA's octetsToNextHeader reflects the TRUE payload length and the
       inner SecuredPayload round-trips (the T10 silent-drop fix).
   A is the sender (data_protection km-payload + metadata_protection km-meta, distinct key_ids); B holds
   km-meta (its user EntityCrypto) and decodes the inner SecuredPayload with km-payload. Deterministic, no
   handshake (manual KMs, like run-user-submessage-protection-test). Asserts:
     (0) data_protection 4-aligns the SecuredPayload (the §9.5.3.3.3 tag pad) from a non-4-aligned plaintext.
     (1) the recovered inner DATA payload region is BYTE-EXACT the §9.5.3.3 SecuredPayload — no spurious
         trailing 4-align pad (the SEC_BODY carries the metadata pad, not the plaintext).
     (2) NON-VACUOUS two-tier round-trip: decode-serialized-payload(km-payload, recovered) = the original
         non-4-aligned plaintext.
   Requires the AES-GCM primitive; skips gracefully if absent. Both impls (Clasp first)."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [user-submsg-data-protection] SKIP — AES-GCM not available: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-user-submessage-data-protection-test t)))
  (let* ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 95))
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 96))
         (node-a (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
         (node-b (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (km-meta    (%secure-sedp-test-km #x74 #x38))   ; A's user-writer EntityCrypto (metadata_protection); B holds it
         (km-payload (dds.security:make-test-key-material))   ; the data_protection (serialized-payload) KM
         (kid        (dds.security:key-material-sender-key-id km-meta))
         ;; 13-octet CDR plaintext (NOT a 4-multiple) -> the §9.5.3.3.3 SecureDataTag pads to a 4-aligned
         ;; SecuredPayload (20 hdr + 4 ct_len + 13 ct + 3 pad + 16 mac + 4 rsm_count = 60): the conformant
         ;; two-tier shape Fast DDS decode_serialized_payload expects (a non-4-aligned SecuredPayload is the
         ;; pre-fix non-conformance this closes).
         (plaintext  (map '(simple-array (unsigned-byte 8) (*)) #'char-code "TWO-TIER-DATA"))
         (secured    (dds.security:encode-serialized-payload km-payload plaintext))   ; data_protection tier
         (host "127.0.0.1") (port 7) (cap nil) (got nil))
    ;; (0) the plaintext is non-4-aligned (so the §9.5.3.3.3 tag pad is non-empty) AND data_protection
    ;;     self-4-aligns the SecuredPayload (the conformant invariant Fast DDS decode_serialized_payload needs).
    (assert (plusp (mod (length plaintext) 4)) ()
            "user-submsg two-tier setup: the plaintext must be NON-4-aligned to exercise the §9.5.3.3.3 tag pad (got ~d)" (length plaintext))
    (assert (zerop (mod (length secured) 4)) ()
            "user-submsg two-tier: data_protection must 4-align the SecuredPayload (the §9.5.3.3.3 SecureDataTag pad, Fast DDS-conformant; got ~d)" (length secured))
    (unwind-protect
         (progn
           ;; A wraps the (data_protection-encoded) DATA submessage under metadata_protection ENCRYPT.
           (setf (disc-node-user-submessage-protection-kind node-a) :encrypt
                 (disc-node-user-submessage-encode node-a)
                 (lambda (writer-p) (declare (ignore writer-p)) (values km-meta :encrypt)))
           (let ((buf (disc-node-tx-msg node-a)) (*datagram-sink* (lambda (dg) (setf cap dg))))
             (%send-raw-buf node-a buf (%rtps-build-user-datagram node-a buf 1 secured) host port nil pb))
           (assert (and (> (length cap) 20) (= (aref cap 20) dds.security:+submessage-sec-prefix+)) ()
                   "user-submsg two-tier: the DATA submessage must be metadata_protection-wrapped (SEC_PREFIX 0x31)")
           (assert (zerop (mod (- (length cap) 20) 4)) ()
                   "user-submsg two-tier 4-align: the wrapped submessage stream must stay a 4-octet multiple (SEC_BODY carries the pad)")
           ;; B decodes the bracket (km-meta) + re-dispatches; capture the recovered inner DATA payload region.
           (setf (disc-node-user-submessage-decode node-b) (lambda (k) (when (equalp k kid) km-meta))
                 (disc-node-on-data node-b)
                 (lambda (w sn b poff plen sp og os kh) (declare (ignore w sn sp og os kh))
                   (setf got (subseq (dds.core.buffer:octet-buffer-vec b) poff (+ poff plen)))))
           (%rtps-feed-datagram node-b cap)
           ;; (1) the recovered DATA payload is byte-exact the SecuredPayload (no trailing 4-align pad).
           (assert (and got (equalp got secured)) ()
                   "user-submsg two-tier: the recovered inner DATA payload must be the EXACT SecuredPayload (no trailing pad); got ~d vs ~d octets"
                   (and got (length got)) (length secured))
           ;; (2) NON-VACUOUS: the inner data_protection SecuredPayload decodes to the original plaintext
           ;;     (pre-fix the trailing pad made this NIL — the silent drop this fix closes).
           (let ((recovered (dds.security:decode-serialized-payload km-payload got)))
             (assert (and recovered (equalp recovered plaintext)) ()
                     "user-submsg two-tier: metadata_protection + data_protection + non-4-aligned payload must round-trip byte-exact (was silently dropped)"))
           t)
      (stop-node node-a) (stop-node node-b))))

(defun* %rtps-build-multi-user-datagram (node buf sns payloads)
    (function (disc-node dds.core.buffer:octet-buffer list list) (integer 0))
  "Build a plain datagram (20-octet RTPS Header §9.4.4 + one user-writer DATA submessage §9.4.5.4 per (SN, PAYLOAD)
   pair drawn 1:1 from SNS/PAYLOADS) into BUF and return its length — the MULTI-submessage plaintext input the
   metadata_protection send wrap protects bracket-by-bracket. Test helper (run-user-submessage-protection-zeroalloc-test)."
  (let ((mc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.rtps.message:write-header mc (disc-node-guid-prefix node))
    (loop for sn in sns for pl in payloads do
      (dds.rtps.message:write-data mc dds.rtps.message:+entityid-unknown+ (disc-node-user-writer-id node)
                                   sn pl 0 (length pl)))
    (dds.core.buffer:cursor-position mc)))

(defun* run-user-submessage-protection-zeroalloc-test ()
    (function () (eql t))
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T4 (ZA-2): the metadata_protection (DDS-Security 1.1 §8.5.1.7-.9) user-submessage
   dataplane is ZERO-ALLOC on BOTH the SEND multi-bracket wrap AND the RECEIVE re-dispatch. The SEND wrap borrows a
   per-node submessage-scratch pool + the encode-datawriter/datareader-submessage-into cores (dropping the pre-ZA-2
   per-datagram (make-octet-buffer (+ len 8192)) AND the per-submessage subseq, walking [20,LEN) BY OFFSET); the RECEIVE
   re-dispatch decodes the bracket via decode-datawriter-submessage-into into a REUSED per-node SECURE-RX buffer
   (dropping the pre-ZA-2 per-call make-octet-buffer + decode-datawriter-submessage →octets subseq). A is the sender; B
   the receiver holding A's user-writer EntityCrypto (resolved by transformation_key_id). Deterministic, no auth
   handshake (manual KMs, like run-user-submessage-protection-test). Asserts (both impls, Clasp first):
     (a) ENCRYPT + SIGN ROUND-TRIP byte-exact through the pooled send + reused-RX re-dispatch (a single DATA) — the
         payload is recovered byte-EXACT for BOTH modes (the -into cores are byte-identical to the allocating pair).
     (b) MULTI-SUBMESSAGE: a datagram of THREE user DATA submessages is wrapped bracket-by-bracket + each recovered
         byte-EXACT in order (the multi-bracket walk — the pre-ZA-2 per-submessage subseq path replaced by BY-OFFSET).
     (c) BYTES-CONSED: the pooled SEND wrap AND the pooled RX decode-into each cons ~0 GC-heap B/datagram (SBCL-exact
         via dds.pal:bytes-consed; Clasp reports 0 -> skip, NFR-PORT), FAR below the pre-rewire allocating path
         (subseq + encode/decode-datawriter-submessage) — the < 1.0 assertion WOULD FAIL on the pre-rewire +8192/subseq code.
     (d) EXHAUSTION: with the submessage-scratch pool drained, the SEND wrap returns NIL (fail-closed drop) — never a
         GC fallback (RESOURCE_LIMITS backpressure; NFR-MEM).
   Requires the AES-GCM primitive; skips gracefully if absent."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [user-submsg-zeroalloc] SKIP — AES-GCM not available: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-user-submessage-protection-zeroalloc-test t)))
  (let* ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 87))
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 88))
         (node-a (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
         (node-b (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (km-meta (%secure-sedp-test-km #x7a #x3c))   ; A's user-writer EntityCrypto; B holds the SAME (received A's token)
         (kid     (dds.security:key-material-sender-key-id km-meta))
         (payload (map '(simple-array (unsigned-byte 8) (*)) #'char-code "ZA2-USER-SUBMSG"))   ; 15 octets (non-4-aligned)
         (host "127.0.0.1") (port 7))
    (unwind-protect
         (progn
           ;; B decodes A's user brackets (key_id -> km-meta); no rtps_protection required -> the bare bracket IS delivered.
           (setf (disc-node-user-submessage-decode node-b) (lambda (k) (when (equalp k kid) km-meta)))
           ;; (a) ENCRYPT + SIGN round-trip byte-exact through the pooled send + reused-RX re-dispatch.
           (dolist (kind '(:encrypt :sign))
             (setf (disc-node-user-submessage-protection-kind node-a) kind
                   (disc-node-user-submessage-encode node-a)
                   (let ((k kind)) (lambda (writer-p) (declare (ignore writer-p)) (values km-meta k))))
             (let ((cap nil) (got nil))
               (let ((buf (disc-node-tx-msg node-a)) (*datagram-sink* (lambda (dg) (setf cap dg))))
                 (%send-raw-buf node-a buf (%rtps-build-user-datagram node-a buf 1 payload) host port nil pb))
               (assert (and (> (length cap) 20) (= (aref cap 20) dds.security:+submessage-sec-prefix+)) ()
                       "ZA-2 user-submsg ~(~a~): the pooled send must emit a SEC_PREFIX bracket (0x31)" kind)
               (setf (disc-node-on-data node-b)
                     (lambda (w sn b poff plen sp og os kh) (declare (ignore w sn sp og os kh))
                       (setf got (subseq (dds.core.buffer:octet-buffer-vec b) poff (+ poff plen)))))
               (%rtps-feed-datagram node-b cap)
               (assert (and got (equalp got payload)) ()
                       "ZA-2 user-submsg ~(~a~): the pooled send + reused-RX re-dispatch must recover the payload byte-EXACT" kind)))
           ;; (b) MULTI-SUBMESSAGE: three DATA submessages in one datagram, each wrapped + recovered byte-exact in order.
           (setf (disc-node-user-submessage-protection-kind node-a) :encrypt
                 (disc-node-user-submessage-encode node-a)
                 (lambda (writer-p) (declare (ignore writer-p)) (values km-meta :encrypt)))
           (let* ((pls (list (map '(simple-array (unsigned-byte 8) (*)) #'char-code "MULTI-ONE")
                             (map '(simple-array (unsigned-byte 8) (*)) #'char-code "MULTI-TWO!!")
                             (map '(simple-array (unsigned-byte 8) (*)) #'char-code "MULTI-THREE")))
                  (cap nil) (recovered '()))
             (let ((buf (disc-node-tx-msg node-a)) (*datagram-sink* (lambda (dg) (setf cap dg))))
               (%send-raw-buf node-a buf (%rtps-build-multi-user-datagram node-a buf '(11 12 13) pls) host port nil pb))
             (assert (and (> (length cap) 20) (= (aref cap 20) dds.security:+submessage-sec-prefix+)) ()
                     "ZA-2 user-submsg multi: the pooled send must wrap the first DATA as a SEC_PREFIX bracket")
             (setf (disc-node-on-data node-b)
                   (lambda (w sn b poff plen sp og os kh) (declare (ignore w sn sp og os kh))
                     (push (subseq (dds.core.buffer:octet-buffer-vec b) poff (+ poff plen)) recovered)))
             (%rtps-feed-datagram node-b cap)
             (setf recovered (nreverse recovered))
             (assert (= (length recovered) 3) ()
                     "ZA-2 user-submsg multi: all THREE wrapped DATA submessages must be recovered (got ~d)" (length recovered))
             (assert (every #'equalp recovered pls) ()
                     "ZA-2 user-submsg multi: each recovered DATA payload must be byte-EXACT + in order"))
           ;; (c) BYTES-CONSED: pooled SEND wrap + pooled RX decode-into each ~0, vs the allocating subseq+encode/decode.
           (setf (disc-node-user-submessage-protection-kind node-a) :encrypt
                 (disc-node-user-submessage-encode node-a)
                 (lambda (writer-p) (declare (ignore writer-p)) (values km-meta :encrypt)))
           (%ensure-submsg-scratch-pool node-a) (%ensure-secure-rx-pool node-b)   ; warm the lazy carves (off the measure)
           (let* ((buf (disc-node-tx-msg node-a))
                  (vec (dds.core.buffer:octet-buffer-vec buf))
                  (plen (%rtps-build-user-datagram node-a buf 1 payload))
                  (plain-copy (subseq vec 0 plen))         ; the plaintext datagram, restored before each measured wrap
                  (bracket nil) (iters 4000))
             ;; capture ONE wrapped bracket (the RX decode input) — the SEC_PREFIX...SEC_POSTFIX rest of the wrapped datagram
             (let ((newlen (%maybe-wrap-user-submessages node-a buf plen)))
               (setf bracket (subseq vec 20 newlen)))
             (replace vec plain-copy :end2 plen)           ; restore plaintext (the wrap mutated BUF in place)
             (dds.security:encode-datawriter-submessage km-meta :encrypt (subseq vec 20 plen))   ; warm the old send path
             (let ((send-old (let ((before (dds.pal:bytes-consed)))
                               (dotimes (i iters)
                                 (dds.security:encode-datawriter-submessage km-meta :encrypt (subseq vec 20 plen)))   ; pre-rewire: subseq + →octets
                               (- (dds.pal:bytes-consed) before)))
                   (send-new (let ((before (dds.pal:bytes-consed)))
                               (dotimes (i iters)
                                 (replace vec plain-copy :end2 plen)   ; restore plaintext into the reused buf (0 cons)
                                 (%maybe-wrap-user-submessages node-a buf plen))   ; the pooled zero-alloc wrap
                               (- (dds.pal:bytes-consed) before)))
                   (slen (length bracket)))
               (dds.security:decode-datawriter-submessage km-meta bracket)   ; warm the old RX path
               (%with-secure-rx-scratch (rx node-b)                          ; warm the new RX path
                 (dds.security:decode-datawriter-submessage-into rx 20 km-meta bracket 0 slen))
               (let ((rx-old (let ((before (dds.pal:bytes-consed)))
                               (dotimes (i iters)
                                 (dds.security:decode-datawriter-submessage km-meta bracket))   ; pre-rewire: make-octet-buffer + →octets subseq
                               (- (dds.pal:bytes-consed) before)))
                     (rx-new (let ((before (dds.pal:bytes-consed)))
                               (dotimes (i iters)
                                 (%with-secure-rx-scratch (rx node-b)
                                   (dds.security:decode-datawriter-submessage-into rx 20 km-meta bracket 0 slen)))   ; pooled borrow + into-decode
                               (- (dds.pal:bytes-consed) before))))
                 (let ((so (/ (float send-old) iters)) (sn (/ (float send-new) iters))
                       (ro (/ (float rx-old) iters)) (rn (/ (float rx-new) iters)))
                   (format t "~&  [user-submsg-zeroalloc] SEND wrap bytes/datagram: before(subseq+encode-datawriter-submessage)=~,2f  after(pooled -into)=~,2f (~d iters)~%" so sn iters)
                   (format t "  [user-submsg-zeroalloc] RX decode bytes/bracket: before(decode-datawriter-submessage)=~,2f  after(pooled decode-into)=~,2f~%" ro rn)
                   (if (zerop (dds.pal:bytes-consed))
                       (format t "  [skip] dds.pal:bytes-consed is 0 on this impl (Clasp NFR-PORT gap) — metadata_protection alloc not measurable~%")
                       (progn
                         (assert (< sn 1.0) ()
                                 "ZA-2: the pooled metadata_protection SEND wrap must cons ~~0 GC-heap B/datagram; got ~,2f (would FAIL on the pre-rewire +8192/subseq path, ~,2f)" sn so)
                         (assert (< sn (* 0.25 so)) ()
                                 "ZA-2: the pooled SEND wrap (~,2f B) must cons far less than the old subseq+encode path (~,2f B)" sn so)
                         (assert (< rn 1.0) ()
                                 "ZA-2: the pooled metadata_protection RX decode must cons ~~0 GC-heap B/bracket; got ~,2f (would FAIL on the pre-rewire decode+subseq path, ~,2f)" rn ro)
                         (assert (< rn (* 0.25 ro)) ()
                                 "ZA-2: the pooled RX decode (~,2f B) must cons far less than the old decode-datawriter-submessage path (~,2f B)" rn ro))))))
             (replace vec plain-copy :end2 plen))          ; leave BUF holding the plaintext datagram
           ;; (d) EXHAUSTION -> fail-closed NIL (never a GC fallback)
           (let* ((buf (disc-node-tx-msg node-a))
                  (plen (%rtps-build-user-datagram node-a buf 1 payload))
                  (pool (%ensure-submsg-scratch-pool node-a))
                  (held '()))
             (loop for b = (dds.core.arena:pool-acquire pool) while b do (push b held))   ; drain the pool
             (unwind-protect
                  (assert (null (%maybe-wrap-user-submessages node-a buf plen)) ()
                          "ZA-2 exhaustion: %maybe-wrap-user-submessages must return NIL (fail-closed drop) when the submessage-scratch pool is exhausted — never a GC fallback")
               (dolist (b held) (dds.core.arena:pool-release pool b))))
           t)
      (stop-node node-a) (stop-node node-b))))

(defun* run-secured-dataplane-mem-test ()
    (function () (eql t))
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5 (ZA-2): the LIVE `make mem` proof that BOTH secured dataplane tiers — the
   submessage metadata_protection (DDS-Security 1.1 §8.5.1.7-.9) AND the whole-RTPS rtps_protection (§8.5.1.10-.12) —
   are ZERO GC-alloc/sample on SEND and RECEIVE, over reused buffers (steady state), and that pool EXHAUSTION
   fail-closes (drops) rather than falling back to the GC heap. Four DETERMINISTIC bytes-consed/sample arms measure the
   security TRANSFORM in isolation over reused input/output buffers + the per-node pools (the ZA-1 %secured-wrapper-
   cycle-bps style — no cross-node framing / GC-boundary noise, so the result is an EXACT 0.0000 on SBCL), each
   reported as `plain=.. secured=.. -> delta=.. B/sample`:
     (a) metadata_protection SEND    — %maybe-wrap-user-submessages, resolver OFF (byte-identical no-op) vs ON (pooled
                                        multi-bracket wrap over the submsg-scratch pool).
     (b) metadata_protection RECEIVE — the T5 pooled bracket EXTRACTION (%with-bracket-rx-scratch, replacing the pre-T5
                                        per-bracket make-array) + the zero-alloc key_id read (%secure-bracket-key-id-into
                                        into a STACK buffer, replacing the pre-T5 subseq) + the key_id resolve + the
                                        decode INTO a DISTINCT secure-rx buffer (decode-datawriter-submessage-into) — the
                                        exact security receive transform %handle-datagram + %on-user-secure-submessage run
                                        (the re-dispatch that then delivers the recovered PLAIN submessage IS the
                                        non-secured baseline, so it is excluded here — it conses no more than receiving
                                        that plain submessage always did).
     (c) rtps_protection SEND        — %maybe-wrap-srtps, resolver OFF vs ON (pooled SRTPS wrap over the send-scratch pool).
     (d) rtps_protection RECEIVE     — the SRTPS unwrap: decode-rtps-message-into into a pooled secure-rx buffer + the
                                        in-place copy-back (the exact transform %handle-datagram runs).
   SBCL asserts each delta is < 1.0 B/sample (dds.pal:bytes-consed is exact); Clasp bytes-consed is 0 (NFR-PORT gap) so
   the arms run the SAME code paths (smoke) and only report 0.0000. EXHAUSTION (both send + receive): with the submsg-
   scratch / send-scratch pool drained the SEND wrap returns NIL (fail-closed drop, RESOURCE_LIMITS backpressure — never
   a GC fallback), and with the bracket-rx pool drained a metadata datagram is DROPPED (its on-data hook never fires — a
   make-array GC fallback would have delivered it) then DELIVERED once the pool is released (non-vacuous). Deterministic,
   no auth handshake (manual KMs). Requires the AES-GCM primitive; skips gracefully if absent. Wired into make mem."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [secured-dataplane-mem] SKIP — AES-GCM not available: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-secured-dataplane-mem-test t)))
  (let* ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 71))
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 72))
         (node-a (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
         (node-b (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (km-meta (%secure-sedp-test-km #x5a #x2c))       ; A's user EntityCrypto (metadata_protection); B holds the same
         (km-rtps (%secure-sedp-test-km #x5b #x2d))       ; A's ParticipantCrypto (rtps_protection / SRTPS)
         (meta-kid (dds.security:key-material-sender-key-id km-meta))
         (payload (map '(simple-array (unsigned-byte 8) (*)) #'char-code "ZA2-MEM-DATAPLANE"))   ; 17 octets (non-4-aligned)
         (iters 20000)
         (sbcl (eq (dds.pal:pal-impl-name) :sbcl)))
    (labels ((bps (thunk)
               (declare (type function thunk))
               (funcall thunk)                            ; warm (lazy carve already forced separately) off the measured window
               (let ((before (dds.pal:bytes-consed)))
                 (dotimes (i iters) (funcall thunk))
                 (/ (float (- (dds.pal:bytes-consed) before) 1.0d0) iters)))
             (report-arm (label plain secured)
               (format t "~&  mem[~a]: plain=~,4f secured=~,4f -> delta=~,4f B/sample (~a)~%"
                       label plain secured (- secured plain) (dds.pal:pal-impl-name))
               (when sbcl
                 (assert (< (abs (- secured plain)) 1.0) ()
                         "ZA-2 T5 ~a: enabling the tier must add ~~0 GC-heap B/sample over the non-secured baseline; got delta ~,4f (plain ~,4f, secured ~,4f)"
                         label (- secured plain) plain secured))))
      (unwind-protect
           (progn
             ;; ---- (a) metadata_protection SEND: resolver OFF (no-op) vs ON (pooled wrap), over the reused tx buffer ----
             (setf (disc-node-user-submessage-protection-kind node-a) :encrypt)
             (%ensure-submsg-scratch-pool node-a)         ; force the lazy carve off the measured window
             (let* ((buf (disc-node-tx-msg node-a))
                    (vec (dds.core.buffer:octet-buffer-vec buf))
                    (plen (%rtps-build-user-datagram node-a buf 1 payload))
                    (plain-copy (subseq vec 0 plen)))
               (setf (disc-node-user-submessage-encode node-a) nil)   ; plain baseline: no resolver -> byte-identical no-op
               (let ((base (bps (lambda () (replace vec plain-copy :end2 plen)
                                   (%maybe-wrap-user-submessages node-a buf plen)))))
                 (setf (disc-node-user-submessage-encode node-a)
                       (lambda (wp) (declare (ignore wp)) (values km-meta :encrypt)))   ; created ONCE, off the measured window
                 (let ((sec (bps (lambda () (replace vec plain-copy :end2 plen)
                                    (%maybe-wrap-user-submessages node-a buf plen)))))
                   (report-arm "meta-send " base sec)))
               (replace vec plain-copy :end2 plen))       ; leave BUF holding the plaintext datagram
             ;; ---- (c) rtps_protection SEND: resolver OFF vs ON (pooled SRTPS wrap), over the reused tx buffer ----
             (setf (disc-node-rtps-protection-kind node-a) :encrypt)
             (%ensure-send-scratch-pool node-a)
             (let* ((buf (disc-node-tx-msg node-a))
                    (vec (dds.core.buffer:octet-buffer-vec buf))
                    (plen (%rtps-build-user-datagram node-a buf 2 payload))
                    (plain-copy (subseq vec 0 plen)))
               (setf (disc-node-rtps-protection-encode node-a) nil)   ; plain baseline
               (let ((base (bps (lambda () (replace vec plain-copy :end2 plen)
                                   (%maybe-wrap-srtps node-a buf plen pb)))))
                 (setf (disc-node-rtps-protection-encode node-a)
                       (lambda (dp) (declare (ignore dp)) (values km-rtps :encrypt '())))
                 (let ((sec (bps (lambda () (replace vec plain-copy :end2 plen)
                                    (%maybe-wrap-srtps node-a buf plen pb)))))
                   (report-arm "rtps-send " base sec)))
               (replace vec plain-copy :end2 plen))
             ;; ---- (b) metadata_protection RECEIVE: pooled bracket extract + stack key_id + resolve + distinct-pool decode ----
             (setf (disc-node-user-submessage-protection-kind node-a) :encrypt
                   (disc-node-user-submessage-encode node-a)
                   (lambda (wp) (declare (ignore wp)) (values km-meta :encrypt))
                   (disc-node-user-submessage-decode node-b) (lambda (k) (when (equalp k meta-kid) km-meta)))
             (let* ((buf (disc-node-tx-msg node-a))
                    (vec (dds.core.buffer:octet-buffer-vec buf))
                    (plen (%rtps-build-user-datagram node-a buf 3 payload))
                    (newlen (%maybe-wrap-user-submessages node-a buf plen))   ; vec[0,newlen) = RTPS header + SEC_PREFIX bracket
                    (dgbuf (dds.core.buffer:make-octet-buffer (max 64 newlen)))
                    (dgvec (dds.core.buffer:octet-buffer-vec dgbuf))
                    (start 20) (size newlen) (blen (- newlen 20))
                    (user-fn (disc-node-user-submessage-decode node-b)))
               (replace dgvec vec :end2 newlen)           ; the received datagram (reused; RX bracket extraction never mutates it)
               (%ensure-bracket-rx-pool node-b) (%ensure-key-id-rx-pool node-b) (%ensure-secure-rx-pool node-b)   ; force the lazy carves off the measured window
               (let ((sec (bps (lambda ()
                                  (%with-bracket-rx-scratch (br node-b)          ; pooled bracket INPUT (T5, replaces make-array)
                                    (replace (dds.core.buffer:octet-buffer-vec br) dgvec :start2 start :end2 size)
                                    (%with-key-id-rx-scratch (kb node-b)         ; pooled key_id scratch (T5, replaces subseq)
                                      (%secure-bracket-key-id-into (dds.core.buffer:octet-buffer-vec kb)
                                                                   (dds.core.buffer:octet-buffer-vec br) blen)
                                      (let ((km (funcall user-fn (dds.core.buffer:octet-buffer-vec kb))))   ; resolve (equalp, no retain)
                                        (%with-secure-rx-scratch (rx node-b)     ; DISTINCT decode OUTPUT pool
                                          (dds.security:decode-datawriter-submessage-into
                                           rx 20 km (dds.core.buffer:octet-buffer-vec br) 0 blen)))))))))
                 (report-arm "meta-recv " 0.0d0 sec))
               (dds.pal:free-static dgvec))
             ;; ---- (d) rtps_protection RECEIVE: SRTPS unwrap into a pooled secure-rx buffer + in-place copy-back ----
             (setf (disc-node-rtps-protection-kind node-a) :encrypt
                   (disc-node-rtps-protection-encode node-a)
                   (lambda (dp) (declare (ignore dp)) (values km-rtps :encrypt '())))
             (let* ((buf (disc-node-tx-msg node-a))
                    (vec (dds.core.buffer:octet-buffer-vec buf))
                    (plen (%rtps-build-user-datagram node-a buf 4 payload))
                    (wlen (%maybe-wrap-srtps node-a buf plen pb))   ; vec[0,wlen) = the SRTPS datagram
                    (srtps-copy (subseq vec 0 wlen))
                    (dgbuf (dds.core.buffer:make-octet-buffer (max 64 wlen)))
                    (dgvec (dds.core.buffer:octet-buffer-vec dgbuf))
                    (cap (dds.core.buffer:octet-buffer-capacity dgbuf))
                    (size wlen))
               (%ensure-secure-rx-pool node-b)
               (let ((sec (bps (lambda ()
                                  (replace dgvec srtps-copy :end2 size)    ; restore (the SRTPS decode mutates [20,) in place)
                                  (%with-secure-rx-scratch (rx node-b)
                                    (multiple-value-bind (data-len mode data-off postfix-off)
                                        (dds.security:decode-rtps-message-into rx 0 km-rtps dgvec 20 (- size 20))
                                      (declare (ignore postfix-off))
                                      (when (and data-len (<= (+ 20 data-len) cap))
                                        (ecase mode
                                          (:encrypt (replace dgvec (dds.core.buffer:octet-buffer-vec rx)
                                                             :start1 20 :end1 (+ 20 data-len) :end2 data-len))
                                          (:sign (replace dgvec dgvec :start1 20 :start2 data-off
                                                          :end2 (+ data-off data-len)))))))))))
                 (report-arm "rtps-recv " 0.0d0 sec))
               (dds.pal:free-static dgvec))
             ;; ---- (e/f) ORIGIN AUTHENTICATION (§9.5.3.3.4.3, *_WITH_ORIGIN_AUTHENTICATION rtps tier): the
             ;; receiver-specific-MAC encode + decode is 0 B/sample OVER the common (empty-receivers) tier — the
             ;; WP-SECURITY-ORIGIN-AUTH-ZEROALLOC LIVE-PATH proof. These arms drive the REAL memoized receiver-
             ;; descriptor resolver (dds.security:km-receiver-descriptor{-list} — the EXACT call the installed
             ;; cm-rtps-encode-receivers / cm-rtps-decode-receiver make) INSIDE the measured window, not a pre-built
             ;; stub list, so they measure the LIVE origin-auth datagram path (resolver + transform) and prove the
             ;; resolver-list residual is closed. km-oa is an origin-auth ParticipantCrypto carrying the receiver
             ;; key; its descriptor list is memoized on the KM, so the one-time cold-cache build is forced OFF the
             ;; window and the reported 0.0000 is warmed steady-state (the %km-session-key-at convention). SEND
             ;; baseline = the common rtps wrap (empty receivers); secured = the SAME wrap DRIVING the resolver ->
             ;; the delta is the %put-receiver-macs-into cost (cached receiver session key + GMAC-into) + the
             ;; resolver (memoized -> 0 B). RECV baseline = decode-rtps-message-into WITHOUT the gate; secured = the
             ;; SAME decode RESOLVING my-receiver-key via the memoized resolver WITH the gate (%verify-receiver-mac-
             ;; into, in-place GMAC verify). Both over reused buffers + warmed caches -> an EXACT 0.0000 on SBCL (Clasp smokes).
             (let* ((oa-kid (map '(simple-array (unsigned-byte 8) (*)) #'identity #(#xab #xcd #x12 #x34)))
                    (oa-mk  (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x5e))
                    (km-oa  (dds.security:make-key-material                 ; origin-auth KM = the resolver's descriptor source
                             :receiver-specific-key-id oa-kid :master-receiver-specific-key oa-mk)))
               (dds.security:km-receiver-descriptor-list km-oa)            ; force the one-time cold-cache build off the window
               ;; (e) origin-auth SEND: common wrap vs receiver-MAC wrap DRIVING the live resolver, over the reused tx buffer.
               (setf (disc-node-rtps-protection-kind node-a) :encrypt)
               (%ensure-send-scratch-pool node-a)
               (let* ((buf (disc-node-tx-msg node-a))
                      (vec (dds.core.buffer:octet-buffer-vec buf))
                      (plen (%rtps-build-user-datagram node-a buf 6 payload))
                      (plain-copy (subseq vec 0 plen)))
                 (setf (disc-node-rtps-protection-encode node-a)
                       (lambda (dp) (declare (ignore dp)) (values km-rtps :encrypt '())))   ; baseline: common tier
                 (let ((base (bps (lambda () (replace vec plain-copy :end2 plen)
                                     (%maybe-wrap-srtps node-a buf plen pb)))))
                   (setf (disc-node-rtps-protection-encode node-a)
                         (lambda (dp) (declare (ignore dp))
                           (values km-rtps :encrypt (dds.security:km-receiver-descriptor-list km-oa))))   ; LIVE resolver
                   (let ((sec (bps (lambda () (replace vec plain-copy :end2 plen)
                                      (%maybe-wrap-srtps node-a buf plen pb)))))
                     (report-arm "oauth-send" base sec)))
                 (replace vec plain-copy :end2 plen))
               ;; (f) origin-auth RECV: decode the receiver-MAC SRTPS datagram WITHOUT (baseline) vs WITH the gate,
               ;; RESOLVING my-receiver-key via the live memoized resolver per datagram (cm-rtps-decode-receiver's call).
               (setf (disc-node-rtps-protection-encode node-a)
                     (lambda (dp) (declare (ignore dp))
                       (values km-rtps :encrypt (dds.security:km-receiver-descriptor-list km-oa))))
               (let* ((buf (disc-node-tx-msg node-a))
                      (vec (dds.core.buffer:octet-buffer-vec buf))
                      (plen (%rtps-build-user-datagram node-a buf 7 payload))
                      (wlen (%maybe-wrap-srtps node-a buf plen pb))   ; vec[0,wlen) = the origin-auth SRTPS datagram
                      (srtps-copy (subseq vec 0 wlen))
                      (dgbuf (dds.core.buffer:make-octet-buffer (max 64 wlen)))
                      (dgvec (dds.core.buffer:octet-buffer-vec dgbuf))
                      (size wlen))
                 (%ensure-secure-rx-pool node-b)
                 (let ((base (bps (lambda ()
                                     (replace dgvec srtps-copy :end2 size)
                                     (%with-secure-rx-scratch (rx node-b)
                                       (dds.security:decode-rtps-message-into rx 0 km-rtps dgvec 20 (- size 20)))))))
                   (let ((sec (bps (lambda ()
                                      (replace dgvec srtps-copy :end2 size)
                                      (%with-secure-rx-scratch (rx node-b)
                                        (let ((rd (dds.security:km-receiver-descriptor km-oa)))   ; LIVE decode resolver
                                          (dds.security:decode-rtps-message-into rx 0 km-rtps dgvec 20 (- size 20)
                                                                                 :my-receiver-key-id (car rd)
                                                                                 :my-receiver-key (cdr rd))))))))
                     (report-arm "oauth-recv" base sec)))
                 (dds.pal:free-static dgvec)))
             ;; ---- EXHAUSTION -> fail-closed drop, NEVER a GC fallback (send AND receive) ----
             ;; SEND (submsg-scratch): drain -> the required metadata wrap fails-closed NIL.
             (setf (disc-node-user-submessage-protection-kind node-a) :encrypt
                   (disc-node-user-submessage-encode node-a)
                   (lambda (wp) (declare (ignore wp)) (values km-meta :encrypt)))
             (let* ((buf (disc-node-tx-msg node-a))
                    (plen (%rtps-build-user-datagram node-a buf 5 payload))
                    (pool (%ensure-submsg-scratch-pool node-a)) (held '()))
               (loop for b = (dds.core.arena:pool-acquire pool) while b do (push b held))
               (unwind-protect
                    (assert (null (%maybe-wrap-user-submessages node-a buf plen)) ()
                            "ZA-2 T5 send exhaustion: %maybe-wrap-user-submessages must fail-closed NIL when the submsg-scratch pool is drained (never a GC fallback)")
                 (dolist (b held) (dds.core.arena:pool-release pool b))))
             ;; SEND (send-scratch / SRTPS): drain -> the required SRTPS wrap fails-closed NIL.
             (setf (disc-node-rtps-protection-kind node-a) :encrypt
                   (disc-node-rtps-protection-encode node-a)
                   (lambda (dp) (declare (ignore dp)) (values km-rtps :encrypt '())))
             (let* ((buf (disc-node-tx-msg node-a))
                    (plen (%rtps-build-user-datagram node-a buf 6 payload))
                    (pool (%ensure-send-scratch-pool node-a)) (held '()))
               (loop for b = (dds.core.arena:pool-acquire pool) while b do (push b held))
               (unwind-protect
                    (assert (null (%maybe-wrap-srtps node-a buf plen pb)) ()
                            "ZA-2 T5 send exhaustion: %maybe-wrap-srtps must fail-closed NIL when the send-scratch pool is drained (never a GC fallback)")
                 (dolist (b held) (dds.core.arena:pool-release pool b))))
             ;; RECEIVE (bracket-rx): drain -> a metadata datagram is DROPPED (on-data never fires); released -> delivered.
             (setf (disc-node-user-submessage-protection-kind node-a) :encrypt
                   (disc-node-user-submessage-encode node-a)
                   (lambda (wp) (declare (ignore wp)) (values km-meta :encrypt))
                   (disc-node-user-submessage-decode node-b) (lambda (k) (when (equalp k meta-kid) km-meta))
                   (disc-node-rtps-protection-kind node-b) :none)   ; no rtps_protection enforcement on B (deliver the bare bracket)
             (let* ((buf (disc-node-tx-msg node-a))
                    (vec (dds.core.buffer:octet-buffer-vec buf))
                    (plen (%rtps-build-user-datagram node-a buf 7 payload))
                    (newlen (%maybe-wrap-user-submessages node-a buf plen))
                    (dg (subseq vec 0 newlen))
                    (pool (%ensure-bracket-rx-pool node-b)) (held '()) (got nil))
               (setf (disc-node-on-data node-b) (lambda (&rest r) (declare (ignore r)) (setf got t)))
               (loop for b = (dds.core.arena:pool-acquire pool) while b do (push b held))
               (unwind-protect
                    (progn
                      (%rtps-feed-datagram node-b dg)
                      (assert (null got) ()
                              "ZA-2 T5 receive exhaustion: a metadata bracket must be DROPPED when the bracket-rx pool is drained (a make-array GC fallback would fire on-data)"))
                 (dolist (b held) (dds.core.arena:pool-release pool b)))
               (setf got nil)
               (%rtps-feed-datagram node-b dg)
               (assert got ()
                       "ZA-2 T5 receive exhaustion non-vacuous: after releasing the bracket-rx pool the SAME datagram must be DELIVERED (on-data fires)"))
             (format t "~&  [secured-dataplane-mem] exhaustion: metadata + SRTPS SEND fail-closed NIL; bracket-rx RECEIVE drop-then-deliver — no GC fallback~%")
             t)
        (stop-node node-a) (stop-node node-b)))))

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

(defun* run-rtps-protection-enforce-user-bracket-test ()
    (function () (eql t))
  "WP-DDS-SECURITY-FASTDDS-INTEROP (Slice 5, T10 review fix-1): RECEIVE-side rtps_protection ENFORCEMENT on a
   BARE user metadata_protection bracket (DDS-Security 1.1 §8.5.1.10-.12) — the gap the other enforce tests
   (run-rtps-protection-enforce-test / -reliability-test, which cover plain DATA/HEARTBEAT/ACKNACK/GAP/*_FRAG)
   did NOT close: a SEC_PREFIX user bracket arriving WITHOUT the mandated outer SRTPS wrap. A legitimate
   keyed-rtps peer ALWAYS SRTPS-wraps user traffic, so a bare user bracket claiming to come from the :keyed peer
   A is forgeable framing — the AEAD authenticates the inner submessage, but the bracket bypassed the required
   whole-RTPS protection — and MUST be dropped. B requires rtps_protection (ENCRYPT) and is :keyed with A (holds
   A's ParticipantCrypto km-rtps + A's user EntityCrypto km-meta). A is the sender. Feeding datagrams straight
   into %handle-datagram (deterministic, no UDP / no handshake; both impls). Asserts:
     (1) ENFORCEMENT: a BARE user bracket (metadata_protection only, no SRTPS) from the :keyed A is DROPPED —
         B's user-data hook never fires (the un-wrapped injection is rejected before any user reader).
     (2) NON-VACUOUS (governance NONE): with rtps_protection = NONE the SAME bare bracket IS delivered —
         proving the drop is specifically the rtps_protection enforcement (not the bracket decode failing).
     (3) LEGITIMATE PATH: the SAME user bracket delivered INSIDE the proper SRTPS wrap IS delivered byte-exact
         (outer SRTPS decode -> re-dispatch rtps-unwrapped=t -> ENFORCE-RTPS NIL -> user bracket decoded), so
         the fix drops ONLY the bare bracket, never the conformant wrapped one (no false-REJECT).
   Requires the AES-GCM primitive; skips gracefully if absent. Both impls (Clasp first)."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (format t "~&  [rtps-enforce-user-bracket] SKIP — AES-GCM not available: ~a~%" (dds.dare:dare-unavailable-reason c))
      (return-from run-rtps-protection-enforce-user-bracket-test t)))
  (let* ((pa (make-array 12 :element-type '(unsigned-byte 8) :initial-element 97))   ; the :keyed peer A
         (pb (make-array 12 :element-type '(unsigned-byte 8) :initial-element 98))   ; node-b: receiver under enforcement
         (node-a (make-disc-node :guid-prefix pa :host "127.0.0.1" :port 0))
         (node-b (make-disc-node :guid-prefix pb :host "127.0.0.1" :port 0))
         (km-meta (%secure-sedp-test-km #x77 #x39))   ; A's user-writer EntityCrypto (metadata_protection)
         (km-rtps (%secure-sedp-test-km #x78 #x3a))   ; A's ParticipantCrypto (rtps_protection / SRTPS)
         (meta-kid (dds.security:key-material-sender-key-id km-meta))
         (payload (map '(simple-array (unsigned-byte 8) (*)) #'char-code "BARE-DROP"))   ; 9 octets (non-4-aligned)
         (host "127.0.0.1") (port 7) (cap-bare nil) (cap-srtps nil) (got nil))
    (unwind-protect
         (progn
           ;; A: user metadata_protection ENCRYPT (km-meta) on the user DATA submessage.
           (setf (disc-node-user-submessage-protection-kind node-a) :encrypt
                 (disc-node-user-submessage-encode node-a)
                 (lambda (writer-p) (declare (ignore writer-p)) (values km-meta :encrypt)))
           ;; Build the BARE user bracket: metadata wrap only (NO rtps-protection-encode -> %maybe-wrap-srtps no-op).
           (let ((buf (disc-node-tx-msg node-a)) (*datagram-sink* (lambda (dg) (setf cap-bare dg))))
             (%send-raw-buf node-a buf (%rtps-build-user-datagram node-a buf 1 payload) host port nil pb))
           (assert (and (> (length cap-bare) 20) (= (aref cap-bare 20) dds.security:+submessage-sec-prefix+)) ()
                   "enforce-user-bracket setup: the bare datagram must be a SEC_PREFIX user bracket (0x31), not SRTPS")
           ;; Build the SRTPS-WRAPPED user bracket: metadata wrap THEN whole-RTPS wrap (km-rtps).
           (setf (disc-node-rtps-protection-encode node-a)
                 (lambda (dp) (declare (ignore dp)) (values km-rtps :encrypt '())))
           (let ((buf (disc-node-tx-msg node-a)) (*datagram-sink* (lambda (dg) (setf cap-srtps dg))))
             (%send-raw-buf node-a buf (%rtps-build-user-datagram node-a buf 2 payload) host port nil pb))
           (assert (and (> (length cap-srtps) 20) (= (aref cap-srtps 20) dds.security:+submessage-srtps-prefix+)) ()
                   "enforce-user-bracket setup: the wrapped datagram must be SRTPS (0x33) carrying the inner bracket")
           ;; B: rtps_protection REQUIRED + :keyed with A (km-rtps) + holds A's user EntityCrypto (km-meta).
           (setf (disc-node-rtps-protection-kind node-b) :encrypt
                 (disc-node-rtps-protection-decode node-b)
                 (lambda (sp) (when (equalp sp pa) (values km-rtps nil nil)))
                 (disc-node-user-submessage-decode node-b) (lambda (k) (when (equalp k meta-kid) km-meta))
                 (disc-node-on-data node-b)
                 (lambda (w sn b poff plen sp og os kh) (declare (ignore w sn sp og os kh))
                   (setf got (subseq (dds.core.buffer:octet-buffer-vec b) poff (+ poff plen)))))
           ;; (1) ENFORCEMENT — a BARE user bracket from the :keyed A is DROPPED (no on-data dispatch).
           (setf got nil)
           (%rtps-feed-datagram node-b cap-bare)
           (assert (null got) ()
                   "T10 enforce-user-bracket: a BARE user metadata_protection bracket (no outer SRTPS) from a :keyed-rtps peer must be DROPPED")
           ;; (2) NON-VACUOUS (governance NONE) — the SAME bare bracket IS delivered with rtps_protection NONE.
           (setf got nil (disc-node-rtps-protection-kind node-b) :none)
           (%rtps-feed-datagram node-b cap-bare)
           (assert (and got (equalp got payload)) ()
                   "T10 enforce-user-bracket non-vacuous: with rtps_protection NONE the same bare bracket must be DELIVERED (proves the drop IS the enforcement)")
           (setf (disc-node-rtps-protection-kind node-b) :encrypt)   ; restore enforce mode
           ;; (3) LEGITIMATE PATH — the SAME bracket inside the proper SRTPS wrap IS delivered byte-exact.
           (setf got nil)
           (%rtps-feed-datagram node-b cap-srtps)
           (assert (and got (equalp got payload)) ()
                   "T10 enforce-user-bracket: the SAME user bracket delivered inside the proper SRTPS wrap must be DELIVERED byte-exact (no false-REJECT)")
           t)
      (stop-node node-a) (stop-node node-b))))

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
