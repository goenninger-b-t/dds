;;;; DDS-Security 1.1 §8.5 Cryptographic plugin — the CryptoKeyFactory / CryptoKeyExchange
;;;; KEY-MANAGEMENT HUB (M7/P6 WP-DDS-SECURITY-SECURE-DISCOVERY Slice 4 T6). The
;;;; Cryptographic-plugin analogue of auth-manager.lisp (Authentication): it owns the
;;;; ParticipantCrypto + EntityCrypto §9.5.2 KeyMaterial registries and exposes the key
;;;; RESOLVERS the §9.5.3.3 secured data path consumes (encode keyed by the LOCAL crypto,
;;;; decode keyed by the wire-visible discriminator the receiver already holds: the source
;;;; GUID-prefix for participant-level rtps_protection, the CryptoHeader transformation_key_id
;;;; or the inner endpoint GUID for entity-level submessage/serialized-payload protection).
;;;;
;;;; Lives in the DCPS layer (mirrors auth-manager / type-gate): it needs dds-security (the
;;;; KeyMaterial + generate-key-material + crypto-keys) and reuses auth-manager's %GUID-FROM-PREFIX
;;;; (same package). T8 wires this into the §8.7 auth state machine (CryptoToken exchange + :keyed
;;;; promotion); T9/T11 consume the entity resolvers for the secure SEDP builtin endpoints; T10
;;;; consumes the participant resolvers at send / %handle-datagram for whole-RTPS protection.
;;;;
;;;; Control-plane: registries are written at discovery/keying, read on the data path. ALL five
;;;; registries are guarded by the SINGLE manager LOCK — register_matched_remote_entity updates the
;;;; (prefix.entity) map AND the transformation_key_id index together, so one lock keeps those two
;;;; atomic w.r.t. resolvers with NO two-lock ordering hazard; every critical section is an O(1)
;;;; gethash/sethash and the lock is never held across a callback. The RESOLVED key-material is used
;;;; on the hot path (T10), so the resolvers are O(1) and allocate nothing per call (the GUID/prefix/
;;;; key-id keys are supplied by the caller). Every resolver fails CLOSED: NIL on a miss, and the
;;;; data path drops the sample/datagram on NIL (no plaintext fallback for a secured participant).
;;;;
;;;; Spec: OMG DDS-Security 1.1 §8.5 (Cryptographic plugin: CryptoKeyFactory register_local_*/
;;;; register_matched_remote_*, CryptoKeyExchange), §9.5.2 (KeyMaterial — CryptoTransformKeyMaterial),
;;;; §9.5.3.3 (encode/decode session-key derivation keyed by the KeyMaterial). RTPS 2.5 §9.3.1.2
;;;; (GUID_t = GuidPrefix_t(12) + EntityId_t(4)).

(in-package #:dds.dcps)

;;; --- the key-management hub ---

(defstruct* crypto-manager
  "DDS-Security 1.1 §8.5 CryptoKeyFactory/CryptoKeyExchange key-management hub: the ParticipantCrypto
   + EntityCrypto §9.5.2 KeyMaterial registries plus the key resolvers the §9.5.3.3 data path uses.
   PARTICIPANT-CRYPTO    : the LOCAL participant's KeyMaterial for rtps_protection (encode source); NIL
                           until CM-REGISTER-LOCAL-PARTICIPANT (one per participant).
   REMOTE-PARTICIPANT-CRYPTO : EQUALP hash 12-octet GUID-prefix -> KeyMaterial; the rtps_protection
                           DECODE source, resolved by the datagram's source GUID-prefix (readable from
                           the RTPS header before the inner parse — the T10 discriminator).
   LOCAL-ENTITY-CRYPTO   : EQL hash EntityId(ub32) -> KeyMaterial; one per local secure builtin/user
                           endpoint, the submessage/serialized-payload ENCODE source.
   REMOTE-ENTITY-CRYPTO  : EQUALP hash 16-octet GUID -> KeyMaterial; the entity DECODE source keyed by
                           the inner endpoint GUID (GUID = prefix||entity-id; realizes the brief's
                           (prefix . entity-id) pair as the concatenated GUID so the data path resolves
                           with the remote GUID it already built — no per-sample allocation).
   KEY-ID-INDEX          : EQUALP hash 4-octet transformation_key_id -> KeyMaterial; the O(1) entity
                           DECODE index keyed by the CryptoHeader transformation_key_id (= the remote
                           sender's sender_key_id, §9.5.2 Table 65 — the T9/T11 discriminator). Cross-peer
                           key_id collisions, if any, are disambiguated by REMOTE-ENTITY-CRYPTO (the
                           authoritative GUID-keyed map); this index is the wire-discriminator fast path.
   REMOTE-KEY-ID-ENTITY  : EQUALP hash 4-octet transformation_key_id -> the remote sender's 32-bit EntityId
                           (T-ORIGINAUTH). The origin-auth secure-SEDP DECODE maps a bracket's wire key_id to
                           the remote secure-SEDP-WRITER entity-id, hence (via the fixed writer->reader pairing)
                           to the LOCAL receiving READER whose receiver-specific key verifies the per-receiver MAC
                           (§9.5.3.3.4.3). The value is the BUILTIN secure-SEDP writer entity-id (the same across
                           peers), so a cross-peer key_id collision still maps to the same channel; a true
                           mis-map fails closed (the receiver-MAC under the wrong reader key just won't verify).
   ALL-KMS               : an EQ set (hash-table) of EVERY §9.5.2 KeyMaterial this manager has minted or
                           registered — the teardown roster CM-TEARDOWN walks to zeroize+free each KM's secret
                           slots at quiesced participant teardown (ADR-0034). It holds even KMs replaced/orphaned
                           by re-keying (they are never freed mid-run — the only free is at teardown — so a live
                           data-path resolver never uses freed key bytes), and the EQ keying dedups so no KM is
                           double-freed. Written under LOCK on every register (%CM-TRACK-KM).
   LOCK                  : the single mutex guarding all five registries + ALL-KMS (no two-lock ordering
                           hazard; O(1) critical sections; never held across a callback).
   OWNER-MS              : back-reference to this participant's AUTH-MANAGER-STATE (T8). The crypto-manager
                           mediates the §7.2 :authenticated->:keyed promotion, which flips the AUTH-REMOTE
                           state under the auth-manager LOCK; OWNER-MS gives cm-on-crypto-token that lock +
                           the AUTH-REMOTE table without a third lock-ordering hazard (set once at install,
                           read-only after; typed T to avoid a crypto-manager<->auth-manager-state cycle)."
  (participant-crypto nil :type (or null dds.security:key-material))
  (remote-participant-crypto (make-hash-table :test 'equalp) :type hash-table)
  (local-entity-crypto (make-hash-table :test 'eql) :type hash-table)
  (remote-entity-crypto (make-hash-table :test 'equalp) :type hash-table)
  (key-id-index (make-hash-table :test 'equalp) :type hash-table)
  (remote-key-id-entity (make-hash-table :test 'equalp) :type hash-table)
  (all-kms (make-hash-table :test 'eq) :type hash-table)
  (lock (dds.pal:make-lock "crypto-manager") :type t)
  (owner-ms nil :type t))

(defun* %cm-track-km (cm km)
    (function (crypto-manager (or null dds.security:key-material)) (or null dds.security:key-material))
  "Record KM in CM's ALL-KMS teardown roster (caller holds the manager LOCK) and return KM. Guarantees
   CM-TEARDOWN wipes EVERY minted/registered KeyMaterial — including any later replaced/orphaned by re-keying
   — with NO mid-run free (the sole free is at quiesced participant teardown), so no live data-path resolver
   ever touches freed key bytes (ADR-0034 secret hygiene). A NIL KM is ignored."
  (when km (setf (gethash km (crypto-manager-all-kms cm)) t))
  km)

;;; --- GUID helpers (reuse auth-manager %GUID-FROM-PREFIX for prefix+entity-id -> GUID) ---

(defun* %cm-entity-id-from-guid (guid)
    (function ((simple-array (unsigned-byte 8) (16))) (unsigned-byte 32))
  "Extract the 32-bit EntityId (octets 12-15, big-endian) from a 16-octet GUID_t
   (GUID_t = GuidPrefix_t(12) + EntityId_t(4), RTPS 2.5 §9.3.1.2) — the LOCAL-ENTITY-CRYPTO key
   the encode resolver derives from the writer GUID the dataplane supplies."
  (logior (ash (aref guid 12) 24) (ash (aref guid 13) 16)
          (ash (aref guid 14) 8) (aref guid 15)))

;;; --- §8.5 CryptoKeyFactory: register_local_* / register_matched_remote_* ---

(defun* cm-register-local-participant (cm &key (origin-auth nil) (kind :encrypt))
    (function (crypto-manager &key (:origin-auth t) (:kind (member :sign :encrypt))) dds.security:key-material)
  "§8.5 register_local_participant: get-or-create the LOCAL participant's §9.5.2 KeyMaterial (the
   rtps_protection ParticipantCrypto encode source). Idempotent — returns the existing KeyMaterial if
   already registered, else mints one (GENERATE-KEY-MATERIAL; ORIGIN-AUTH adds the receiver-specific
   fields for rtps_protection WITH_ORIGIN_AUTHENTICATION). KIND (:encrypt default | :sign) sets the
   KeyMaterial's advertised transformation_kind — it MUST equal the wire CryptoHeader kind the whole-RTPS
   SRTPS wrap carries (rtps_protection_kind of the tier: SIGN advertises AES256-GMAC, ENCRYPT AES256-GCM),
   because a conformant remote resolves the ParticipantCrypto by sender_key_id then transforms per the
   advertised kind — a SIGN participant that advertised GCM makes the remote GCM-decrypt a GMAC datagram
   (Connext 'RTI_Security_Cryptography_decode: DecryptFinal failed'), §9.5.2 Table 65 / §8.5.1.10-.12.
   Under the manager lock (mirrors auth-manager's get-or-create-under-lock; the leaf GENERATE-KEY-MATERIAL
   never re-enters the manager). Returns the KM."
  (dds.pal:with-lock ((crypto-manager-lock cm))
    (or (crypto-manager-participant-crypto cm)
        (setf (crypto-manager-participant-crypto cm)
              (%cm-track-km cm (dds.security:generate-key-material :origin-auth origin-auth :kind kind))))))

(defun* cm-register-matched-remote-participant (cm prefix km)
    (function (crypto-manager (simple-array (unsigned-byte 8) (12)) dds.security:key-material) (eql t))
  "§8.5 register_matched_remote_participant: install the REMOTE participant's §9.5.2 KeyMaterial KM
   under its 12-octet GUID PREFIX (the rtps_protection decode source, resolved by the datagram's source
   GUID-prefix). PREFIX is copied as the stored key (the caller may reuse its buffer). Under the lock."
  (dds.pal:with-lock ((crypto-manager-lock cm))
    (%cm-track-km cm km)
    (setf (gethash (copy-seq prefix) (crypto-manager-remote-participant-crypto cm)) km))
  t)

(defun* cm-register-local-entity (cm entity-id &key (origin-auth nil) (kind :encrypt))
    (function (crypto-manager (unsigned-byte 32) &key (:origin-auth t) (:kind (member :sign :encrypt)))
              dds.security:key-material)
  "§8.5 register_local_datawriter/datareader: get-or-create the LOCAL endpoint's §9.5.2 KeyMaterial for
   ENTITY-ID (the submessage/serialized-payload EntityCrypto encode source). Idempotent per ENTITY-ID;
   ORIGIN-AUTH adds the receiver-specific fields. KIND (:encrypt default | :sign) sets the KeyMaterial's
   advertised transformation_kind — it MUST equal the wire CryptoHeader kind this endpoint's submessages carry
   (governance protection_kind of the tier: a SIGN endpoint advertises AES256-GMAC, an ENCRYPT one AES256-GCM),
   because a conformant remote (Fast DDS find_key) matches a stored token KeyMaterial to an inbound submessage on
   transformation_kind AND sender_key_id together — a SIGN endpoint that advertised GCM is rejected 'Key material
   not found'. Under the lock. Returns the KeyMaterial."
  (dds.pal:with-lock ((crypto-manager-lock cm))
    (or (gethash entity-id (crypto-manager-local-entity-crypto cm))
        (setf (gethash entity-id (crypto-manager-local-entity-crypto cm))
              (%cm-track-km cm (dds.security:generate-key-material :origin-auth origin-auth :kind kind))))))

(defun* cm-register-matched-remote-entity (cm prefix entity-id km)
    (function (crypto-manager (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32)
               dds.security:key-material) (eql t))
  "§8.5 register_matched_remote_datawriter/datareader: install the REMOTE endpoint's §9.5.2 KeyMaterial
   KM under BOTH (a) the 16-octet GUID built from PREFIX+ENTITY-ID (decode by the inner endpoint GUID
   the data path already holds) AND (b) KM's 4-octet sender_key_id in the O(1) transformation_key_id
   index (decode by the CryptoHeader transformation_key_id, §9.5.2 Table 65) AND (c) that key-id ->
   ENTITY-ID in the REMOTE-KEY-ID-ENTITY map (T-ORIGINAUTH — the secure-SEDP origin-auth decode maps the wire
   key_id to the remote writer's entity-id, hence to the local receiving reader's receiver key). All three
   writes are atomic w.r.t. the resolvers under the single manager lock (no two-lock ordering hazard). PREFIX
   (via the built GUID) and the key-id are copied as the stored keys."
  (dds.pal:with-lock ((crypto-manager-lock cm))
    (%cm-track-km cm km)
    (let ((guid (%guid-from-prefix prefix entity-id))
          (kid  (copy-seq (dds.security:key-material-sender-key-id km))))
      (setf (gethash guid (crypto-manager-remote-entity-crypto cm)) km
            (gethash kid (crypto-manager-key-id-index cm)) km
            (gethash kid (crypto-manager-remote-key-id-entity cm)) entity-id)))
  t)

;;; --- direct key resolvers (O(1), under the lock, fail-closed) ---

(defun* cm-encode-participant-km (cm)
    (function (crypto-manager) (or null dds.security:key-material))
  "Resolve the LOCAL participant KeyMaterial for rtps_protection ENCODE (§8.5; T10 send path). NIL if
   no local participant is registered (the caller fails closed). O(1), under the lock."
  (dds.pal:with-lock ((crypto-manager-lock cm))
    (crypto-manager-participant-crypto cm)))

(defun* cm-decode-participant-km (cm prefix)
    (function (crypto-manager (simple-array (unsigned-byte 8) (12))) (or null dds.security:key-material))
  "Resolve the REMOTE participant KeyMaterial for rtps_protection DECODE (§8.5; T10 %handle-datagram),
   keyed by the datagram's 12-octet source GUID-prefix (readable before the inner parse). NIL on an
   unknown prefix (fail-closed). O(1), under the lock."
  (dds.pal:with-lock ((crypto-manager-lock cm))
    (gethash prefix (crypto-manager-remote-participant-crypto cm))))

(defun* cm-encode-entity-km (cm entity-id)
    (function (crypto-manager (unsigned-byte 32)) (or null dds.security:key-material))
  "Resolve the LOCAL endpoint KeyMaterial for ENTITY-ID (submessage/serialized-payload ENCODE; T9/T11).
   NIL if the entity is not registered (fail-closed). O(1), under the lock."
  (dds.pal:with-lock ((crypto-manager-lock cm))
    (gethash entity-id (crypto-manager-local-entity-crypto cm))))

(defun* cm-decode-entity-km (cm guid)
    (function (crypto-manager (simple-array (unsigned-byte 8) (16))) (or null dds.security:key-material))
  "Resolve the REMOTE endpoint KeyMaterial by the 16-octet inner endpoint GUID (the decode discriminator
   the data path already holds; GUID = prefix||entity-id, §9.5.2). NIL on an unknown GUID (fail-closed).
   O(1), under the lock — allocates nothing (the caller supplies the GUID)."
  (dds.pal:with-lock ((crypto-manager-lock cm))
    (gethash guid (crypto-manager-remote-entity-crypto cm))))

(defun* cm-decode-entity-km-by-key-id (cm key-id)
    (function (crypto-manager (simple-array (unsigned-byte 8) (*))) (or null dds.security:key-material))
  "Resolve the REMOTE endpoint KeyMaterial by the 4-octet CryptoHeader transformation_key_id (= the
   remote sender's sender_key_id, §9.5.2 Table 65) via the O(1) index (T9/T11 secure-SEDP decode). NIL
   on an unknown key-id (fail-closed). Cross-peer key_id collisions, if any, are disambiguated by the
   GUID-keyed CM-DECODE-ENTITY-KM map; this index is the wire-discriminator fast path. Under the lock."
  (dds.pal:with-lock ((crypto-manager-lock cm))
    (gethash key-id (crypto-manager-key-id-index cm))))

(defun* %secure-builtin-entity-id-p (entity-id)
    (function ((unsigned-byte 32)) boolean)
  "T iff ENTITY-ID is one of the DDS-Security 1.1 §7.4.5 secure BUILTIN endpoint entity-ids (secure SEDP pub/sub,
   secure participant-message, secure SPDP — the 0xC2 writer / 0xC7 reader of each), NIL for a USER endpoint. The
   discriminator that routes an inbound SEC_PREFIX bracket whose key_id maps to a builtin entity to %on-secure-builtin
   vs a USER bracket to user submessage re-dispatch; ENTITY-ID is the remote sender's entity-id REMOTE-KEY-ID-ENTITY records."
  (and (member entity-id
               (list dds.rtps.discovery:+entityid-sedp-pub-secure-writer+
                     dds.rtps.discovery:+entityid-sedp-pub-secure-reader+
                     dds.rtps.discovery:+entityid-sedp-sub-secure-writer+
                     dds.rtps.discovery:+entityid-sedp-sub-secure-reader+
                     dds.rtps.discovery:+entityid-participant-message-secure-writer+
                     dds.rtps.discovery:+entityid-participant-message-secure-reader+
                     dds.rtps.discovery:+entityid-spdp-secure-writer+
                     dds.rtps.discovery:+entityid-spdp-secure-reader+))
       t))

(defun* cm-remote-entity-for-key-id (cm key-id)
    (function (crypto-manager (simple-array (unsigned-byte 8) (*))) (or null (unsigned-byte 32)))
  "The remote sender's entity-id that CryptoHeader transformation_key_id KEY-ID was registered under
   (REMOTE-KEY-ID-ENTITY, written ATOMICALLY with the KM by register-remote-entity, §9.5.2 Table 65) — the
   EXPECTED inner-submessage source endpoint for the ADR-0040 anti-substitution cross-check in %on-secure-builtin
   (a writer-sourced inner DATA/HEARTBEAT whose writerId != this entity was keyed under one endpoint but claims
   another -> DROP). NIL (skip the cross-check, no false-REJECT) on an unknown key-id. O(1) under the lock."
  (dds.pal:with-lock ((crypto-manager-lock cm))
    (gethash key-id (crypto-manager-remote-key-id-entity cm))))

(defun* cm-user-entity-km-by-key-id (cm key-id)
    (function (crypto-manager (simple-array (unsigned-byte 8) (*))) (or null dds.security:key-material))
  "Resolve the REMOTE USER endpoint KeyMaterial by the 4-octet CryptoHeader transformation_key_id, returning the
   KM ONLY when KEY-ID maps to a remote USER endpoint (not a secure builtin) — the secure-submessage dispatcher
   routes a USER bracket here (metadata_protection, §8.5.1.7-.9) and a builtin bracket to %on-secure-builtin. Maps
   KEY-ID -> the remote sender's entity-id (REMOTE-KEY-ID-ENTITY): a secure-builtin entity-id
   (%secure-builtin-entity-id-p) -> NIL (defer to the builtin path); any other -> the EntityCrypto KM
   (CM-DECODE-ENTITY-KM-BY-KEY-ID). Fail-closed NIL on an unknown key-id. O(1) under the lock for the eid lookup."
  (let ((eid (dds.pal:with-lock ((crypto-manager-lock cm))
               (gethash key-id (crypto-manager-remote-key-id-entity cm)))))
    (when (and eid (not (%secure-builtin-entity-id-p eid)))
      (cm-decode-entity-km-by-key-id cm key-id))))

;;; --- T-ORIGINAUTH: secure-SEDP origin-authentication receiver-key resolvers (§9.5.3.3.4.3) ---

;;; The origin-auth predicate + the receiver DESCRIPTOR construction now live with the KM struct in dds.security
;;; (%km-origin-auth-p / km-receiver-descriptor{-list}); the descriptor list is MEMOIZED on the key-material there,
;;; so the live per-datagram resolvers below cons ZERO GC-heap bytes and re-keying (a new KM) invalidates for free.

(defun* %cm-entity-origin-auth (node entity-id)
    (function (dds.disc:disc-node (unsigned-byte 32)) boolean)
  "Whether the LOCAL secure-builtin EntityCrypto for ENTITY-ID must be minted WITH a receiver-specific key
   (§9.5.3.3.4.3) — i.e. ENTITY-ID is an origin-auth-capable secure builtin RECEIVING reader AND its governance
   TIER directs an *_WITH_ORIGIN_AUTHENTICATION kind. The reader endpoints are the ones that hold their OWN
   receiver key (the matched WRITERS encode under the remote reader's key, never their own), so a non-reader
   answers NIL. The tier flag is per-protection-class: the secure-SEDP readers (pub/sub) AND the secure-SPDP
   reader ride the DISCOVERY tier (disc-node-secure-sedp-origin-auth — SPDP re-announce is discovery traffic);
   the secure participant-message reader rides the LIVELINESS tier (disc-node-secure-pm-origin-auth). Any other
   entity (writers, user endpoints) -> NIL (no own receiver key here)."
  (cond ((or (= entity-id dds.rtps.discovery:+entityid-sedp-pub-secure-reader+)
             (= entity-id dds.rtps.discovery:+entityid-sedp-sub-secure-reader+)
             (= entity-id dds.rtps.discovery:+entityid-spdp-secure-reader+))
         (dds.disc:disc-node-secure-sedp-origin-auth node))
        ((= entity-id dds.rtps.discovery:+entityid-participant-message-secure-reader+)
         (dds.disc:disc-node-secure-pm-origin-auth node))
        (t nil)))

(defun* %cm-entity-protection-kind (node entity-id)
    (function (dds.disc:disc-node (unsigned-byte 32)) (member :sign :encrypt))
  "The §9.5.2 transformation_kind a LOCAL EntityCrypto for ENTITY-ID must ADVERTISE = the governance protection
   kind of its tier mapped to a CryptoTransformKind (:sign -> AES256-GMAC, :encrypt/:none -> AES256-GCM). A
   conformant peer's find_key (Fast DDS) matches a stored token KeyMaterial to an inbound submessage on this kind
   AND the sender_key_id, so a SIGN tier MUST advertise GMAC or it is rejected 'Key material not found'. secure-SEDP
   / secure-SPDP readers+writers ride disc-node-secure-sedp-protection-kind; secure participant-message (liveliness)
   readers+writers ride disc-node-secure-pm-protection-kind; the user writer/reader's EntityCrypto serves BOTH the
   metadata_protection (submessage, §8.5.1.7-.9) AND the data_protection (payload/SecuredPayload, §9.4.1.2.4) tiers, so
   its kind is driven by the DATA_PROTECTION tier when that is engaged (non-NONE) — a data=SIGN topic MUST advertise
   AES256-GMAC so its SecuredPayload rides VISIBLE+authenticated (encode-serialized-payload GMAC sub-tier), a
   data=ENCRYPT topic AES256-GCM so the payload stays HIDDEN (confidentiality is authoritative — never emit a visible
   GMAC payload for an ENCRYPT topic); data=NONE/unset falls back to the submessage tier
   (disc-node-user-submessage-protection-kind). anything else -> :encrypt. A :none tier maps to :encrypt (inert — that
   tier emits no protected submessage, so its EntityCrypto kind is never matched against a wire submessage). SINGLE-KM
   LIMITATION: one EntityCrypto km cannot advertise two kinds, so a topic_rule that sets data_protection AND
   metadata_protection to DIFFERENT non-NONE kinds on the user endpoint is unrepresentable here (Fast DDS uses separate
   EntityKeyMaterials — the payload 'last' key vs the submessage 'first'). The payload kind wins, which is
   confidentiality-PRESERVING ONLY for data=ENCRYPT + metadata=SIGN (the SIGN submessage rides the stronger GCM); the
   REVERSE, data=SIGN + metadata=ENCRYPT, would DOWNGRADE the ENCRYPT-mandated user submessage onto the visible GMAC
   kind. That contradictory mixed-kind governance is now FAIL-CLOSED REJECTED at %install-access-control
   (governance-mixed-nonnone-kind-conflict, create-participant), so it can never reach this derivation; same-kind and
   any-NONE combos are unaffected. ADR-0040."
  (flet ((nz (k) (if (eq k :sign) :sign :encrypt)))   ; :none/:encrypt -> :encrypt; :sign -> :sign
    (cond
      ((or (= entity-id dds.rtps.discovery:+entityid-sedp-pub-secure-writer+)
           (= entity-id dds.rtps.discovery:+entityid-sedp-pub-secure-reader+)
           (= entity-id dds.rtps.discovery:+entityid-sedp-sub-secure-writer+)
           (= entity-id dds.rtps.discovery:+entityid-sedp-sub-secure-reader+)
           (= entity-id dds.rtps.discovery:+entityid-spdp-secure-writer+)
           (= entity-id dds.rtps.discovery:+entityid-spdp-secure-reader+))
       (nz (dds.disc:disc-node-secure-sedp-protection-kind node)))
      ((or (= entity-id dds.rtps.discovery:+entityid-participant-message-secure-writer+)
           (= entity-id dds.rtps.discovery:+entityid-participant-message-secure-reader+))
       (nz (dds.disc:disc-node-secure-pm-protection-kind node)))
      ((or (= entity-id (dds.disc:disc-node-user-writer-id node))
           (= entity-id (dds.disc:disc-node-user-reader-id node)))
       ;; payload tier is authoritative when engaged (non-NONE), else the submessage tier (unchanged for data=NONE)
       (if (member (dds.disc:disc-node-user-data-protection-kind node) '(:sign :encrypt))
           (nz (dds.disc:disc-node-user-data-protection-kind node))
           (nz (dds.disc:disc-node-user-submessage-protection-kind node))))
      (t :encrypt))))

(defun* %secure-sedp-reader-for-writer (writer-entity-id)
    (function ((unsigned-byte 32)) (or null (unsigned-byte 32)))
  "Map a secure BUILTIN WRITER entity-id to the corresponding RECEIVING reader entity-id (the matched builtin
   pair, DDS-Security §7.4.5 / RTPS 2.5 §9.3.2). Covers ALL the origin-auth-capable secure builtin tiers, not
   just SEDP (the name is historical, T9): publications writer 0xff0003c2 -> reader 0xff0003c7; subscriptions
   0xff0004c2 -> 0xff0004c7 (secure SEDP, T9); participant-message 0xff0200c2 -> 0xff0200c7 (secure WLP, T11);
   SPDP 0xff0101c2 -> 0xff0101c7 (secure SPDP re-announce, T11). NIL for any non-secure-builtin-writer entity-id.
   Used by BOTH the ENCODE resolver (local writer -> matched-remote reader's receiver key) and the DECODE
   resolver (remote writer -> local reader's receiver key) — the writer->reader pairing is identical in both
   directions, so the origin-auth receiver-MAC wiring is one shared mechanism across every secure builtin tier.
   Delegates the gate + §9.3.1.2/§9.3.2 pairing to the shared dds.rtps.discovery helpers (ADR-0037 carry 1 DRY —
   ONE source below both dds.dcps + dds.disc; identical to dds.disc::%secure-reader-eid-for-writer)."
  (when (dds.rtps.discovery:secure-builtin-writer-eid-p writer-entity-id)
    (dds.rtps.discovery:builtin-complementary-eid writer-entity-id)))

(defun* cm-secure-sedp-encode-receivers (cm writer-entity-id remote-prefix)
    (function (crypto-manager (unsigned-byte 32) (simple-array (unsigned-byte 8) (12))) list)
  "Origin-auth ENCODE resolver (§9.5.3.3.4.3, T-ORIGINAUTH): for a local secure-SEDP WRITER-ENTITY-ID announcing
   to REMOTE-PREFIX, the list of matched-remote RECEIVER descriptors ((receiver_specific_key_id .
   master_receiver_specific_key)) for encode-datawriter-submessage's :receivers. The matched remote of a
   secure-SEDP writer is the peer's corresponding secure-SEDP READER (%secure-sedp-reader-for-writer): resolve
   THAT remote reader's EntityCrypto (cm-decode-entity-km by GUID = REMOTE-PREFIX+reader-eid) and return its
   receiver descriptor. NIL (empty -> plain SIGN/ENCRYPT) when WRITER-ENTITY-ID is not a secure-SEDP writer, the
   remote reader is not yet keyed, or it carries no receiver key (origin-auth off). Control-plane (announce)."
  (let ((reader-eid (%secure-sedp-reader-for-writer writer-entity-id)))
    (when reader-eid
      (let ((rkm (cm-decode-entity-km cm (%guid-from-prefix remote-prefix reader-eid))))
        (and rkm (dds.security:km-receiver-descriptor-list rkm))))))

(defun* cm-secure-sedp-decode-receiver (cm key-id)
    (function (crypto-manager (simple-array (unsigned-byte 8) (*))) (or null cons))
  "Origin-auth DECODE resolver (§9.5.3.3.4.3, T-ORIGINAUTH): for an inbound secure-SEDP bracket whose
   CryptoHeader transformation_key_id is KEY-ID, the LOCAL receiving READER's receiver descriptor
   (receiver_specific_key_id . master_receiver_specific_key) for decode-datawriter-submessage's
   my-receiver-key-id/my-receiver-key. Maps KEY-ID -> the remote sender's entity-id (REMOTE-KEY-ID-ENTITY) ->
   the corresponding LOCAL receiving reader (%secure-sedp-reader-for-writer) -> that local reader's EntityCrypto
   (cm-encode-entity-km) -> its receiver descriptor. NIL (no origin-auth verification — the common_mac alone
   governs) when KEY-ID is unknown, maps to a non-secure-SEDP-writer entity, or the local reader carries no
   receiver key (origin-auth off). Takes the lock ONLY for the key-id lookup (released before the leaf resolvers
   re-acquire it — no nested lock)."
  (let ((remote-eid (dds.pal:with-lock ((crypto-manager-lock cm))
                       (gethash key-id (crypto-manager-remote-key-id-entity cm)))))
    (when remote-eid
      (let ((reader-eid (%secure-sedp-reader-for-writer remote-eid)))
        (when reader-eid
          (let ((lkm (cm-encode-entity-km cm reader-eid)))
            (and lkm (dds.security:km-receiver-descriptor lkm))))))))

;;; --- T10: whole-RTPS-message-protection (rtps_protection) origin-auth receiver-key resolvers (§9.5.3.3.4.3) ---
;;; The PARTICIPANT-level analogue of cm-secure-sedp-encode-receivers / cm-secure-sedp-decode-receiver (the entity
;;; level, T-ORIGINAUTH): identical receiver-generated key model (§9.5.3.3.4.3) — A MACs under each remote B's
;;; ParticipantCrypto receiver key (learned from B's ParticipantCryptoToken); B verifies with its OWN. rtps_protection
;;; is per-PAIR (a datagram targets exactly one remote participant), so the encode :receivers list is just that one
;;; remote's descriptor and the decode my-receiver-key is the LOCAL participant's own.

(defun* cm-rtps-encode-receivers (cm dest-prefix)
    (function (crypto-manager (simple-array (unsigned-byte 8) (12))) list)
  "Origin-auth ENCODE resolver for whole-RTPS-message protection (§9.5.3.3.4.3, T10): the list of receiver
   descriptors ((receiver_specific_key_id . master_receiver_specific_key)) encode-rtps-message's :receivers needs
   to MAC a datagram bound for the remote participant DEST-PREFIX — namely THAT remote's ParticipantCrypto receiver
   descriptor (resolved from the remote ParticipantCrypto KM it sent in its ParticipantCryptoToken,
   cm-decode-participant-km). NIL (empty -> plain SIGN/ENCRYPT) when the remote is not yet keyed or carries no
   receiver key (origin-auth off). The descriptor list is MEMOIZED on the remote's KM (km-receiver-descriptor-list),
   so this resolves per datagram but conses ZERO GC-heap bytes on the hit path (re-keying mints a new KM -> fresh
   cache). Mirrors cm-secure-sedp-encode-receivers at the participant level."
  (let ((rkm (cm-decode-participant-km cm dest-prefix)))
    (and rkm (dds.security:km-receiver-descriptor-list rkm))))

(defun* cm-rtps-decode-receiver (cm)
    (function (crypto-manager) (or null cons))
  "Origin-auth DECODE resolver for whole-RTPS-message protection (§9.5.3.3.4.3, T10): the LOCAL participant's own
   receiver descriptor (receiver_specific_key_id . master_receiver_specific_key) for decode-rtps-message's
   my-receiver-key-id / my-receiver-key — resolved from the LOCAL ParticipantCrypto (cm-encode-participant-km),
   which was minted WITH a receiver-specific key iff governance directs an *_WITH_ORIGIN_AUTHENTICATION rtps tier.
   NIL (no origin-auth verification — the common_mac alone governs) when no local participant crypto or no receiver
   key. Mirrors cm-secure-sedp-decode-receiver at the participant level (no key_id lookup needed — there is exactly
   one local ParticipantCrypto, so the receiver is unambiguous). The descriptor is the CAR of the KM's MEMOIZED
   descriptor list (km-receiver-descriptor) — zero GC-heap alloc per datagram on the hit path."
  (let ((lkm (cm-encode-participant-km cm)))
    (and lkm (dds.security:km-receiver-descriptor lkm))))

;;; --- §9.5.3.3 dataplane CRYPTO-KEYS resolvers (the disc-node CRYPTO-TRANSFORM shape, ADR 0031) ---

(defun* %cm-entity-crypto-keys (cm)
    (function (crypto-manager) dds.security:crypto-keys)
  "Build the dataplane CRYPTO-KEYS (dds.security:crypto-keys) for the §9.5.3.3 serialized-payload /
   submessage EntityCrypto path: ENCODE-KEY-FN resolves the LOCAL endpoint KM by the EntityId extracted
   from the 16-octet local writer GUID (CM-ENCODE-ENTITY-KM); DECODE-KEY-FN resolves the REMOTE endpoint
   KM by the 16-octet remote writer GUID (CM-DECODE-ENTITY-KM). Both read the live registries under the
   manager lock (later-keyed remotes are visible) and return NIL on a miss (the data path fails closed).
   The closures allocate nothing per call (the GUIDs are supplied by the caller). Shared by
   CM-ENCODE-KEYS and CM-DECODE-KEYS — the one struct carries both directions, which is what the
   dataplane disc-node CRYPTO-TRANSFORM installs and invokes (encode-key-fn on send, decode-key-fn on
   receive)."
  (dds.security:make-crypto-keys
   :encode-key-fn (lambda (local-guid)
                    (cm-encode-entity-km cm (%cm-entity-id-from-guid local-guid)))
   :decode-key-fn (lambda (remote-guid)
                    (cm-decode-entity-km cm remote-guid))))

(defun* cm-encode-keys (cm)
    (function (crypto-manager) dds.security:crypto-keys)
  "The §8.5 EntityCrypto resolver for the ENCODE direction, as a dds.security:crypto-keys (the shape the
   dataplane disc-node CRYPTO-TRANSFORM installs; ADR 0031). The returned struct carries BOTH closures,
   so the same value also serves decode (see CM-DECODE-KEYS — they return the identical complete
   resolver). ENCODE-KEY-FN: local 16-octet writer GUID -> local endpoint KM by EntityId. Built per call
   (control-plane install), so closure allocation is off the hot path."
  (%cm-entity-crypto-keys cm))

(defun* cm-decode-keys (cm)
    (function (crypto-manager) dds.security:crypto-keys)
  "The §8.5 EntityCrypto resolver for the DECODE direction, as a dds.security:crypto-keys — the identical
   complete resolver to CM-ENCODE-KEYS (the two-closure struct serves both directions; the dataplane
   installs one). DECODE-KEY-FN: remote 16-octet writer GUID -> remote endpoint KM (CM-DECODE-ENTITY-KM);
   the CryptoHeader transformation_key_id fast path is the separate CM-DECODE-ENTITY-KM-BY-KEY-ID
   (the crypto-keys closure resolves by the inner GUID, which the receiver already holds). Built per call."
  (%cm-entity-crypto-keys cm))

;;; === T8 (WP-DDS-SECURITY-SECURE-DISCOVERY): §8.5.2 crypto-token exchange over PVMS + :keyed promotion ===
;;; The §7.2 :authenticated->:keyed edge, MEDIATED by the crypto-manager (design 2026-06-27 §6.4/§7.2): at
;;; :authenticated register local ParticipantCrypto + builtin EntityCrypto, derive+install the §9.5.3.1 PVMS
;;; bootstrap KM from the SharedSecret, exchange per-class crypto tokens over the reliable PVMS endpoint
;;; (tokens ride PLAINTEXT inside the PVMS-protected submessage — §6.5; KEYX's KxKey-wrap over best-effort
;;; PSM is RETIRED), install the remote's tokens, and promote to :keyed once Participant + the core builtin
;;; tokens are all in. T9/T10/T11 consume the installed registries (secure SEDP / rtps_protection).

(defun* %cm-local-token-entities (node)
    (function (dds.disc:disc-node) list)
  "The (entity-id . token-class) list of LOCAL endpoints whose §8.5.2 EntityCrypto T8/T11 registers + exchanges:
   the secure-SEDP builtin publications/subscriptions writer+reader (T9), the secure participant-message
   (liveliness) writer+reader + the secure SPDP re-announce writer+reader (T11), PLUS the node's USER
   writer/reader — the KEYX per-writer KeyMaterial, MIGRATED here off best-effort PSM `participant_crypto_tokens`
   onto reliable PVMS `datawriter/datareader_crypto_tokens` landing in the crypto-manager EntityCrypto registry
   (T8 reconciliation #2, design §6.4). Registering the PM/SPDP secure EntityCryptos here is what lets the GENERIC
   secure-builtin resolvers (cm-encode-entity-km / cm-decode-entity-km-by-key-id) resolve those tiers exactly like
   secure SEDP — no tier-specific resolver. Writers -> +gm-datawriter-crypto-tokens+; readers ->
   +gm-datareader-crypto-tokens+ (DDS-Security 1.1 §9.5.2.2)."
  (list (cons dds.rtps.discovery:+entityid-sedp-pub-secure-writer+ dds.security:+gm-datawriter-crypto-tokens+)
        (cons dds.rtps.discovery:+entityid-sedp-pub-secure-reader+ dds.security:+gm-datareader-crypto-tokens+)
        (cons dds.rtps.discovery:+entityid-sedp-sub-secure-writer+ dds.security:+gm-datawriter-crypto-tokens+)
        (cons dds.rtps.discovery:+entityid-sedp-sub-secure-reader+ dds.security:+gm-datareader-crypto-tokens+)
        (cons dds.rtps.discovery:+entityid-participant-message-secure-writer+ dds.security:+gm-datawriter-crypto-tokens+)
        (cons dds.rtps.discovery:+entityid-participant-message-secure-reader+ dds.security:+gm-datareader-crypto-tokens+)
        (cons dds.rtps.discovery:+entityid-spdp-secure-writer+ dds.security:+gm-datawriter-crypto-tokens+)
        (cons dds.rtps.discovery:+entityid-spdp-secure-reader+ dds.security:+gm-datareader-crypto-tokens+)
        (cons (dds.disc:disc-node-user-writer-id node) dds.security:+gm-datawriter-crypto-tokens+)
        (cons (dds.disc:disc-node-user-reader-id node) dds.security:+gm-datareader-crypto-tokens+)))

(defun* %cm-token-dest-entity-id (node local-eid)
    (function (dds.disc:disc-node (unsigned-byte 32)) (unsigned-byte 32))
  "The REMOTE matched-complementary endpoint EntityId for a LOCAL endpoint LOCAL-EID — the §8.5.2.2/.3 DW/DR
   crypto-token destination_endpoint_key (DDS-Security 1.1 §7.4.4): a DataWriter's tokens are destined for the
   matched DataReader and vice-versa. The builtin secure endpoints pair deterministically by the §9.3.2 key-kind
   low byte (writer 0xC2 <-> reader 0xC7 within the SAME builtin: secure SEDP 0xff0003/0xff0004, secure SPDP
   0xff0101, secure PM 0xff0200); the USER endpoints pair the node's own writer-id <-> reader-id. Fast DDS
   REQUIRES this key non-unknown for a DW/DR token (SecurityManager.cpp process_participant_volatile_message_secure
   rejects destination_endpoint_key == GUID_unknown at 1830/1907 and APPLIES the token via reader_handles_/
   writer_handles_.find(destination_endpoint_key) at 1924/1848)."
  (cond
    ((= local-eid (dds.disc:disc-node-user-writer-id node)) (dds.disc:disc-node-user-reader-id node))
    ((= local-eid (dds.disc:disc-node-user-reader-id node)) (dds.disc:disc-node-user-writer-id node))
    ;; ADR-0037 carry 1 DRY: the builtin writer<->reader §9.3.1.2/§9.3.2 low-byte pairing, one shared source
    (t (dds.rtps.discovery:builtin-complementary-eid local-eid))))

(defun* cm-make-crypto-token-message (cm class km src-guid dest-prefix dest-endpoint-guid)
    (function (crypto-manager string dds.security:key-material
               (simple-array (unsigned-byte 8) (16)) (simple-array (unsigned-byte 8) (12))
               (simple-array (unsigned-byte 8) (16)))
              (simple-array (unsigned-byte 8) (*)))
  "Build a §7.4.4 ParticipantGenericMessage (message_class_id = CLASS) wrapping KM as ONE plaintext
   CryptoToken DataHolder (serialize-crypto-token-plain; §8.5.2 — the token rides plaintext, the PVMS
   submessage ENCRYPT is the confidentiality boundary, T8 HARD CONSTRAINT #2). SRC-GUID is the 16-octet
   SOURCE ENTITY GUID (the participant GUID for a participant token, the endpoint GUID for a DW/DR token);
   it is written into source_endpoint_key so the receiver keys the remote EntityCrypto by the exact entity
   (the §7.4.4 wire carries the per-entity identity the builtin-EntityCrypto model needs, design §6.2).
   DEST-ENDPOINT-GUID is the 16-octet destination_endpoint_key — GUID_unknown (all-zero) for a PARTICIPANT
   token (participant-level), the MATCHED REMOTE endpoint GUID for a DW/DR token (the remote DataReader for our
   DataWriter's tokens, the remote DataWriter for our DataReader's tokens, §8.5.2.2/.3). DEST-PREFIX ->
   destination_participant_key (prefix + ENTITYID_PARTICIPANT). Returns the CDR-LE envelope octets
   %send-volatile-secure protects + sends. Inverse: cm-parse-crypto-token-message."
  (declare (ignore cm))
  (let* ((zero16 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
         (partp (string= class dds.security:+gm-participant-crypto-tokens+))
         (src-prefix (subseq src-guid 0 12))
         (part-guid (%guid-from-prefix src-prefix dds.rtps.message:+entityid-participant+))
         (dest-guid (%guid-from-prefix dest-prefix dds.rtps.message:+entityid-participant+)))
    (dds.security:make-generic-message
     :source-guid           part-guid
     :sequence-number       0
     :related-guid          zero16
     :related-sn            0
     :dest-participant-guid dest-guid
     ;; §8.5.2.1/.2/.3 + Fast DDS SM process_participant_volatile_message_secure: a PARTICIPANT token is
     ;; participant-level -> BOTH endpoint keys = GUID_unknown (rejected otherwise, SM:1739-1749); a DW/DR token
     ;; carries the SOURCE endpoint GUID + the matched-remote DESTINATION endpoint GUID (rejected if either is
     ;; GUID_unknown, SM:1830/1835/1907/1912; the token is APPLIED via *_handles_.find(dest) at 1848/1924).
     :dest-endpoint-guid    (if partp zero16 dest-endpoint-guid)
     :source-endpoint-guid  (if partp zero16 src-guid)
     :message-class-id      class
     :dataholders           (list (dds.security:serialize-crypto-token-plain km)))))

(defun* cm-parse-crypto-token-message (cm octets)
    (function (crypto-manager (simple-array (unsigned-byte 8) (*)))
              (values (or string null) (or dds.security:key-material null)
                      (or (simple-array (unsigned-byte 8) (16)) null)))
  "Parse a §7.4.4 ParticipantGenericMessage carrying ONE plaintext CryptoToken DataHolder. Returns
   (values CLASS KM SOURCE-ENDPOINT-GUID) on success — CLASS the message_class_id, KM the §9.5.2 key
   material, SOURCE-ENDPOINT-GUID the 16-octet source_endpoint_key identifying the source entity (NIL
   third value for a participant token's all-zero/participant guid is harmless — cm-on-crypto-token only
   uses it for DW/DR). Returns (values NIL NIL NIL) on any malformed/truncated/wrong-class/multi-DataHolder
   input (fail-closed; NFR-SEC-POSTURE). A two-value (multiple-value-bind (class km) ...) caller still works
   (the third value is additive). Inverse: cm-make-crypto-token-message."
  (declare (ignore cm))
  (block %p
    (multiple-value-bind (src-guid sn rel-guid rel-sn dest-part dest-ep src-ep class-id dh-list)
        (dds.security:parse-generic-message octets)
      (declare (ignore src-guid sn rel-guid rel-sn dest-part dest-ep))
      (unless class-id (return-from %p (values nil nil nil)))
      (unless (or (string= class-id dds.security:+gm-participant-crypto-tokens+)
                  (string= class-id dds.security:+gm-datawriter-crypto-tokens+)
                  (string= class-id dds.security:+gm-datareader-crypto-tokens+))
        (return-from %p (values nil nil nil)))
      (unless (= (length dh-list) 1) (return-from %p (values nil nil nil)))
      (let ((km (dds.security:parse-crypto-token-plain (car dh-list))))
        (if km (values class-id km src-ep) (values nil nil nil))))))

(defun* %cm-remote-keyed-ready-p (cm node prefix)
    (function (crypto-manager dds.disc:disc-node (simple-array (unsigned-byte 8) (12))) t)
  "T iff remote PREFIX's PARTICIPANT-level crypto is established — the §7.2 :authenticated->:keyed
   precondition. Requires ONLY PREFIX's ParticipantCrypto: the participant-level KeyMaterial Fast DDS
   exchanges unconditionally at participant_authorized (SecurityManager.cpp exchange_participant_crypto,
   NOT gated on rtps_protection). The ENDPOINT-level secure-builtin EntityCryptos (secure SEDP 0xff0003/
   0xff0004, secure SPDP 0xff0101, secure PM 0xff0200) are NOT a keying precondition: a conformant peer
   exchanges them in a SECOND phase that FOLLOWS the participant secure-match (Fast DDS PDPSimple.cpp
   assignRemoteEndpoints with notify_secure -> EDPSimple.cpp secure-endpoint pairing, gated on the secure
   SPDP reader having matched the remote secure SPDP writer — i.e. AFTER :keyed, not before). Requiring the
   secure-SEDP tokens here would DEADLOCK against that two-phase peer (we would never key, so the matches
   that drive the secure channel stay parked, so the peer never reaches phase two). So keying gates on the
   ParticipantCrypto alone (identical for PLAIN and PROTECTED discovery); the secure-SEDP/PM EntityCryptos
   install lazily as those endpoints match (the secure-SEDP receive path resolves each by transformation_key_id
   on arrival, NFR-SEC-POSTURE fail-closed until present). Reads the registry directly."
  (declare (ignore node))
  (and (cm-decode-participant-km cm prefix) t))

(defun* %cm-try-promote (cm node prefix)
    (function (crypto-manager dds.disc:disc-node (simple-array (unsigned-byte 8) (12))) (eql t))
  "Promote remote PREFIX to :keyed iff it is currently :authenticated AND crypto is established
   (%cm-remote-keyed-ready-p) — the §7.2 edge. Flips the AUTH-REMOTE state under the auth-manager LOCK
   (via OWNER-MS), then OUTSIDE the lock installs the crypto-manager CRYPTO-KEYS resolver on the node's
   CRYPTO-TRANSFORM (so user-data encode/decode resolve via the §8.5 EntityCrypto registries — the KEYX
   resolver MIGRATED onto the crypto-manager) and resumes the parked matches (resume takes the node lock;
   never held under the manager lock). Idempotent: a no-op once already :keyed, or until the tokens are in."
  (let ((ms (crypto-manager-owner-ms cm)) (flip nil))
    (when (and ms (%cm-remote-keyed-ready-p cm node prefix))
      (dds.pal:with-lock ((auth-manager-state-lock ms))
        (let ((ar (gethash prefix (dds.disc:disc-node-auth-state node))))
          (when (and ar (eq (auth-remote-state ar) :authenticated))
            (setf (auth-remote-state ar) :keyed flip t))))
      (when flip
        (setf (dds.disc:disc-node-crypto-transform node) (cm-decode-keys cm))
        (dds.disc:resume-parked-matches node)))
    t))

(defun* cm-on-authenticated (cm node remote-prefix)
    (function (crypto-manager dds.disc:disc-node (simple-array (unsigned-byte 8) (12))) (eql t))
  "Drive the §8.5.2 crypto-token exchange for a newly-:authenticated remote REMOTE-PREFIX (design §7.2;
   called by the auth manager OUTSIDE its lock). Steps: (1) derive the §9.5.3.1 PVMS bootstrap KM from the
   handshake SharedSecret + challenges and install it (set-pvms-bootstrap-km) — fail-closed: no shared
   secret -> no keying; (2) register LOCAL ParticipantCrypto + builtin/user EntityCrypto (idempotent);
   (3) send our Participant + per-entity tokens to REMOTE-PREFIX over reliable PVMS (cm-make-crypto-token-
   message -> %send-volatile-secure; plaintext token inside the PVMS ENCRYPT); (4) try to promote (the
   remote may have authenticated first, so its tokens may already be installed). Returns T. The SharedSecret
   read is under the auth-manager lock (the handle lives in AUTH-REMOTE); the bytes are copied into the
   bootstrap KM, then the lock is dropped before any PVMS send (never hold a lock across a network send)."
  (let* ((ms (crypto-manager-owner-ms cm))
         (local-prefix (dds.disc:disc-node-guid-prefix node))
         (bootstrap
           (and ms
                (dds.pal:with-lock ((auth-manager-state-lock ms))
                  (let ((ar (gethash remote-prefix (dds.disc:disc-node-auth-state node))))
                    (when ar
                      (let ((h (auth-remote-handle ar)))
                        (when (and h (eq (dds.security:handshake-handle-state h) :authenticated))
                          (let ((ss (dds.security:handshake-shared-secret h)))
                            (when ss
                              (dds.disc:%pvms-derive-bootstrap-km
                               (dds.security:shared-secret-bytes ss)
                               (dds.security:shared-secret-handle-challenge1-bytes ss)
                               (dds.security:shared-secret-handle-challenge2-bytes ss))))))))))))
    (unless bootstrap (return-from cm-on-authenticated t))   ; no SharedSecret -> fail-closed, no keying
    (dds.disc:set-pvms-bootstrap-km node remote-prefix bootstrap)
    ;; register LOCAL crypto (idempotent across remotes: one KM per local participant/entity, design §6.2).
    ;; T-ORIGINAUTH / T11: each secure-builtin RECEIVING reader is minted WITH a receiver-specific key
    ;; (§9.5.3.3.4.3) iff ITS governance tier directs an origin-auth kind (%cm-entity-origin-auth: the secure-SEDP
    ;; + secure-SPDP readers ride the discovery tier SECURE-SEDP-ORIGIN-AUTH; the secure participant-message reader
    ;; rides the liveliness tier SECURE-PM-ORIGIN-AUTH). The receiver key is exchanged in that reader's crypto
    ;; token and consumed by the receiver-specific-MAC resolvers. Writers + user endpoints stay non-origin-auth
    ;; here (writers encode under the matched reader's key; user-data origin-auth is a later tier).
    ;; T10: the LOCAL ParticipantCrypto carries a receiver-specific key iff governance directs an origin-auth RTPS
    ;; tier (the node RTPS-PROTECTION-ORIGIN-AUTH flag, set from governance rtps_protection_kind by
    ;; %install-access-control) — so a remote A can MAC an rtps-protected datagram under THIS participant's receiver
    ;; key and this participant verifies it with its own (cm-rtps-decode-receiver). NONE/non-origin-auth -> no
    ;; receiver key -> plain SRTPS, byte-identical.
    ;; The advertised ParticipantCrypto kind MUST equal the wire SRTPS CryptoHeader kind (rtps_protection_kind):
    ;; SIGN -> AES256-GMAC, else AES256-GCM. Without this a SIGN participant advertised GCM (the default) but emitted
    ;; a GMAC SRTPS wrap -> the remote finds the key by sender_key_id but transforms as GCM -> DecryptFinal (§9.5.2).
    (cm-register-local-participant cm :origin-auth (dds.disc:disc-node-rtps-protection-origin-auth node)
                                      :kind (if (eq (dds.disc:disc-node-rtps-protection-kind node) :sign) :sign :encrypt))
    (dolist (e (%cm-local-token-entities node))
      (cm-register-local-entity cm (car e) :origin-auth (%cm-entity-origin-auth node (car e))
                                           :kind (%cm-entity-protection-kind node (car e))))
    ;; send our ParticipantCryptoToken, then one DatawriterCryptoToken/DatareaderCryptoToken per local entity
    (let ((zero16 (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
          (part-km (cm-encode-participant-km cm)))
      (when part-km
        (dds.disc:%send-volatile-secure
         node remote-prefix
         (cm-make-crypto-token-message
          cm dds.security:+gm-participant-crypto-tokens+ part-km
          (%guid-from-prefix local-prefix dds.rtps.message:+entityid-participant+) remote-prefix zero16)))
      ;; §8.5.2.2/.3: each DW/DR token's destination_endpoint_key is the MATCHED REMOTE complementary endpoint
      ;; GUID = remote-prefix + %cm-token-dest-entity-id (writer<->reader); GUID_unknown is rejected by Fast DDS.
      (dolist (e (%cm-local-token-entities node))
        (let ((km (cm-encode-entity-km cm (car e))))
          (when km
            (dds.disc:%send-volatile-secure
             node remote-prefix
             (cm-make-crypto-token-message
              cm (cdr e) km (%guid-from-prefix local-prefix (car e)) remote-prefix
              (%guid-from-prefix remote-prefix (%cm-token-dest-entity-id node (car e)))))))))
    (%cm-try-promote cm node remote-prefix)
    ;; §7.3/§8.5: an all-NONE governance never reaches :keyed via a peer that (conformantly) exchanges NO
    ;; participant crypto token when rtps_protection=NONE (e.g. RTI Connext, whose PVMS writer stays empty at
    ;; GOV=none). Resume the parked user-endpoint matches now that the remote is :authenticated — the auth +
    ;; permissions gates match at :authenticated on §8.7 auth + §8.4 permissions (§8.4.2.9). Keying-required
    ;; governance leaves this untouched (the match resumes at :keyed via %cm-try-promote, as before).
    (unless (dds.disc:disc-node-crypto-keying-required-p node)
      (dds.disc:resume-parked-matches node)))
  t)

(defun* cm-on-endpoint-match (cm node remote-guid local-is-writer-p)
    (function (crypto-manager dds.disc:disc-node (simple-array (unsigned-byte 8) (16)) t) (eql t))
  "Re-exchange the USER endpoint's §8.5.2.2/.3 DW/DR CryptoToken at MATCH time, now that the ACTUAL matched-remote
   user-endpoint GUID REMOTE-GUID is known (learned from the secure-SEDP — or plain-SEDP — Discovered{Writer,
   Reader}Data, design §7.2 / DDS-Security 1.1 §7.4.4). LOCAL-IS-WRITER-P selects which local user endpoint
   matched: T = our user WRITER matched a remote READER (send our DatawriterCryptoToken, source = our writer
   GUID); NIL = our user READER matched a remote WRITER (send our DatareaderCryptoToken, source = our reader
   GUID). The token's destination_endpoint_key is REMOTE-GUID itself — the matched-remote endpoint GUID, NOT the
   symmetric-assumed our-own-id cm-on-authenticated sent at auth time (correct ONLY our-to-our; a cross-vendor
   peer's user entity-ids are its own, so Fast DDS process_participant_volatile_message_secure rejects a wrong
   destination_endpoint_key as 'Key material not found' and applies a correct one via reader/writer_handles_.find,
   SM:1848/1924). Sent over the reliable PVMS (%send-volatile-secure). Gated on the remote being KEYED (its
   ParticipantCrypto present) — a user match via secure SEDP is post-keying; fail-closed no-op otherwise. For
   our-to-our the real GUID EQUALS the auth-time guess, so this is an idempotent duplicate (cm-register-matched-
   remote-entity + %cm-try-promote are idempotent) — no regression. A no-op (still T) when the local user
   EntityCrypto is not registered (security off / not keyed)."
  (let* ((remote-prefix (subseq remote-guid 0 12))
         (local-prefix  (dds.disc:disc-node-guid-prefix node)))
    (when (cm-decode-participant-km cm remote-prefix)            ; remote keyed (PVMS up) — else fail-closed no-op
      (let* ((local-eid (if local-is-writer-p (dds.disc:disc-node-user-writer-id node)
                            (dds.disc:disc-node-user-reader-id node)))
             (class     (if local-is-writer-p dds.security:+gm-datawriter-crypto-tokens+
                           dds.security:+gm-datareader-crypto-tokens+))
             (km        (cm-encode-entity-km cm local-eid)))
        (when km
          (dds.disc:%send-volatile-secure
           node remote-prefix
           (cm-make-crypto-token-message
            cm class km (%guid-from-prefix local-prefix local-eid) remote-prefix remote-guid))))))
  t)

(defun* %cm-user-token-at-match (p remote-guid local-is-writer-p)
    (function (domain-participant (simple-array (unsigned-byte 8) (16)) t) (eql t))
  "DCPS on-match -> §8.5.2 user-token re-exchange bridge: resolve P's crypto-manager (NIL = security OFF / no
   handshake -> no-op) and re-send the matched USER endpoint's DW/DR CryptoToken keyed to the matched-remote
   REMOTE-GUID (cm-on-endpoint-match — the destination_endpoint_key fix). LOCAL-IS-WRITER-P: T our user writer
   matched a remote reader, NIL our user reader matched a remote writer. Called from %on-disc-match (fired once
   per newly-matched user endpoint, %fire-match dedups). Fail-soft no-op when no auth/crypto manager."
  (let ((ms (dp-auth-state p)))
    (when ms
      (let ((cm (auth-manager-state-crypto-manager ms)))
        (when cm (cm-on-endpoint-match cm (dp-node p) remote-guid local-is-writer-p)))))
  t)

(defun* cm-on-crypto-token (cm node src-prefix class km &optional entity-guid)
    (function (crypto-manager dds.disc:disc-node (simple-array (unsigned-byte 8) (12)) string
               dds.security:key-material
               &optional (or null (simple-array (unsigned-byte 8) (16))))
              (eql t))
  "Install ONE received remote crypto token (CLASS, KM) from SRC-PREFIX into the right §8.5 registry, then
   try to promote to :keyed (design §7.2). participant_crypto_tokens -> ParticipantCrypto (by SRC-PREFIX);
   datawriter/datareader_crypto_tokens -> EntityCrypto (by ENTITY-GUID = the source_endpoint_key the token
   carried — keyed both by the 16-octet GUID AND by KM's transformation_key_id for the T9/T11 O(1) decode).
   A DW/DR token with a NIL ENTITY-GUID is unidentifiable -> dropped (fail-closed). An unknown CLASS ->
   dropped, no promote. After the install, %cm-try-promote flips :keyed once Participant + the core builtin
   tokens are all present. Returns T (the receiver hook ignores the value; never signals out, NFR-SEC-POSTURE)."
  (cond
    ((string= class dds.security:+gm-participant-crypto-tokens+)
     (cm-register-matched-remote-participant cm src-prefix km))
    ((or (string= class dds.security:+gm-datawriter-crypto-tokens+)
         (string= class dds.security:+gm-datareader-crypto-tokens+))
     (when entity-guid
       (cm-register-matched-remote-entity cm src-prefix (%cm-entity-id-from-guid entity-guid) km)))
    (t (return-from cm-on-crypto-token t)))
  (%cm-try-promote cm node src-prefix)
  t)

(defun* %am-on-volatile-secure (p node src-prefix payload)
    (function (domain-participant dds.disc:disc-node (simple-array (unsigned-byte 8) (12))
               (simple-array (unsigned-byte 8) (*)))
              (eql t))
  "ON-VOLATILE-SECURE receiver hook (receiver thread, OUTSIDE the node lock): a recovered crypto-token
   ParticipantGenericMessage PAYLOAD from SRC-PREFIX (already PVMS-decrypted + reliability-deduped by
   dds-disc). Parse it (cm-parse-crypto-token-message) and dispatch to the crypto-manager
   (cm-on-crypto-token). Fail-closed: no manager / a malformed-or-unknown token -> silent drop, never a
   signal out of the receiver thread, never a promotion on bad input (NFR-SEC-POSTURE)."
  (let ((ms (dp-auth-state p)))
    (when ms
      (let ((cm (auth-manager-state-crypto-manager ms)))
        (when cm
          (multiple-value-bind (class km entity-guid) (cm-parse-crypto-token-message cm payload)
            (when (and class km)
              (cm-on-crypto-token cm node src-prefix class km entity-guid)))))))
  t)

(defun* %install-crypto-manager (p ms node)
    (function (domain-participant auth-manager-state dds.disc:disc-node) crypto-manager)
  "Create P's §8.5 crypto-manager (OWNER-MS = MS, the back-reference for the :keyed promotion), store it in
   MS, and enable the reliable PVMS builtin endpoint (T7) with the ON-VOLATILE-SECURE hook routed to the
   crypto-token dispatcher (%am-on-volatile-secure -> cm-parse -> cm-on-crypto-token). Called by
   %install-auth-manager for a security-enabled participant (BEFORE start-node, so the PVMS reader exists
   before the receiver thread). Returns the crypto-manager."
  (let ((cm (make-crypto-manager :owner-ms ms)))
    (setf (auth-manager-state-crypto-manager ms) cm)
    (dds.disc:enable-volatile-secure
     node :on-volatile-secure (lambda (n src-prefix payload) (%am-on-volatile-secure p n src-prefix payload)))
    ;; T9: install the §8.5 secure-SEDP EntityCrypto resolvers on the disc-node (the disc layer stays
    ;; crypto-free; it calls these CLOSURES, never the crypto-manager). ENCODE-KM resolves the LOCAL
    ;; secure-SEDP-writer KM by EntityId for a protected announce (cm-encode-entity-km); DECODE-KM resolves
    ;; the REMOTE secure-SEDP-writer KM by the wire CryptoHeader transformation_key_id — BOTH the inbound
    ;; SEC_PREFIX discriminator (secure SEDP vs PVMS) AND the decode source (cm-decode-entity-km-by-key-id,
    ;; the T6 carry: by key_id, NOT a GUID closure, since ENCRYPT hides the inner GUID until decrypt). Both
    ;; read the live registries (later-keyed remotes become visible) and fail closed (NIL on a miss).
    (setf (dds.disc:disc-node-secure-sedp-encode-km node)
          (lambda (entity-id) (cm-encode-entity-km cm entity-id)))
    (setf (dds.disc:disc-node-secure-sedp-decode-km node)
          (lambda (key-id) (cm-decode-entity-km-by-key-id cm key-id)))
    ;; T-ORIGINAUTH: the secure-SEDP origin-auth receiver-key resolvers (§9.5.3.3.4.3). ENCODE-RECEIVERS maps a
    ;; local secure-SEDP writer + a remote prefix to the matched-remote READER's receiver descriptors (for
    ;; encode-datawriter-submessage :receivers); DECODE-RECEIVER-KM maps an inbound bracket's transformation_key_id
    ;; to the LOCAL receiving reader's receiver descriptor (for decode my-receiver-key). Both return NIL when
    ;; origin-auth is not in effect (no receiver key minted) -> plain SIGN/ENCRYPT, byte-identical.
    (setf (dds.disc:disc-node-secure-sedp-encode-receivers node)
          (lambda (writer-entity-id remote-prefix)
            (cm-secure-sedp-encode-receivers cm writer-entity-id remote-prefix)))
    (setf (dds.disc:disc-node-secure-sedp-decode-receiver-km node)
          (lambda (key-id) (cm-secure-sedp-decode-receiver cm key-id)))
    ;; ADR-0040 carry (submessage-substitution defense, §8.5.1.9 / §9.5.2 Table 65): map an inbound secure-builtin
    ;; bracket's transformation_key_id -> the EXPECTED remote sender entity-id it was registered under, so
    ;; %on-secure-builtin drops a writer-sourced inner DATA/HEARTBEAT whose writerId claims a DIFFERENT endpoint.
    ;; NIL on an unknown key_id -> no cross-check (no false-REJECT); security OFF leaves it NIL -> byte-identical.
    (setf (dds.disc:disc-node-secure-sedp-decode-sender-entity node)
          (lambda (key-id) (cm-remote-entity-for-key-id cm key-id)))
    ;; T10: whole-RTPS-message protection (rtps_protection_kind, §8.5.1.10-.12). RTPS-PROTECTION-ENCODE wraps a
    ;; USER-DATA datagram bound for a :keyed destination — gated on governance rtps_protection != NONE
    ;; (RTPS-PROTECTION-KIND, set by %install-access-control) AND the dest having sent its ParticipantCrypto
    ;; (cm-decode-participant-km non-NIL = the dest is :keyed); it returns (values LOCAL-ParticipantCrypto KIND
    ;; receivers) so the sender MACs the common_mac under its OWN key + (origin-auth) a per-receiver MAC under the
    ;; dest's receiver key. RTPS-PROTECTION-DECODE resolves an inbound SRTPS datagram's REMOTE ParticipantCrypto by
    ;; the source GUID-prefix (NIL if not keyed -> fail-closed drop) + the LOCAL participant's receiver descriptor
    ;; (origin-auth verify). Both NIL until keying; security OFF leaves them NIL -> byte-identical plain path.
    (setf (dds.disc:disc-node-rtps-protection-encode node)
          (lambda (dest-prefix)
            (let ((kind (dds.disc:disc-node-rtps-protection-kind node)))
              (when (and (not (eq kind :none)) (cm-decode-participant-km cm dest-prefix))
                (let ((local (cm-encode-participant-km cm)))
                  (when local
                    (values local kind (cm-rtps-encode-receivers cm dest-prefix))))))))
    (setf (dds.disc:disc-node-rtps-protection-decode node)
          (lambda (src-prefix)
            (let ((km (cm-decode-participant-km cm src-prefix)))
              (when km
                (let ((rd (cm-rtps-decode-receiver cm)))   ; (key_id . key) | nil (origin-auth)
                  (values km (car rd) (cdr rd)))))))
    ;; Slice 5 (WP-DDS-SECURITY-FASTDDS-INTEROP): user-DATA submessage protection (metadata_protection,
    ;; §8.5.1.7-.9). USER-SUBMESSAGE-ENCODE (writer-p -> (values LOCAL-user-EntityCrypto-KM kind) | NIL): the SEND
    ;; wrap resolver — NIL when the node's metadata_protection kind is NONE or the local user EntityCrypto is not yet
    ;; registered (pre-keying), so %maybe-wrap-user-submessages passes the submessage through plain (byte-identical).
    ;; USER-SUBMESSAGE-DECODE (key-id -> REMOTE user EntityCrypto KM | NIL): the RECEIVE resolver — NIL when key-id is
    ;; a secure builtin (a builtin bracket still routes to %on-secure-builtin) or unknown. metadata_protection NONE
    ;; leaves the encode resolver returning NIL -> the user submessage path is byte-identical to the plain stack.
    (setf (dds.disc:disc-node-user-submessage-encode node)
          (lambda (writer-p)
            (let ((kind (dds.disc:disc-node-user-submessage-protection-kind node)))
              (unless (eq kind :none)
                (let ((km (cm-encode-entity-km cm (if writer-p (dds.disc:disc-node-user-writer-id node)
                                                      (dds.disc:disc-node-user-reader-id node)))))
                  (when km (values km kind)))))))
    (setf (dds.disc:disc-node-user-submessage-decode node)
          (lambda (key-id) (cm-user-entity-km-by-key-id cm key-id)))
    ;; ADR-0034 MINOR-4: when a remote participant leases out (%lease-sweep), drop its KeyMaterials from the active
    ;; crypto registries (unresolve + prompt secret-wipe; the foreign free stays at the quiesced teardown). NIL peer /
    ;; GOV=none -> cm-forget-remote-participant returns 0 (no-op). Security OFF leaves the hook NIL -> byte-identical.
    (setf (dds.disc:disc-node-on-participant-lost node)
          (lambda (prefix) (cm-forget-remote-participant cm prefix) nil))
    cm))

;;; --- participant-lost: drop a lost remote's KeyMaterials from the active registries (ADR-0034 MINOR-4) ---

(defun* cm-forget-remote-participant (cm prefix)
    (function (crypto-manager (simple-array (unsigned-byte 8) (12))) (integer 0))
  "ADR-0034 MINOR-4 (remote-KM drop-on-unmatch): when the REMOTE participant PREFIX is LOST/unmatched
   (fired from %lease-sweep via disc-node-on-participant-lost), DROP its §9.5.2 KeyMaterials from the ACTIVE
   lookup registries — remote-participant-crypto (12-octet prefix), remote-entity-crypto (every prefix+entity
   GUID), key-id-index + remote-key-id-entity (by each dropped KM's sender_key_id) — so a lost peer's keys become
   UNRESOLVABLE (a subsequent decode fails closed) and a peer-CHURNING participant's data-path lookup tables stay
   BOUNDED. Each dropped KM's SECRETS are WIPED IN PLACE (dds.security:wipe-key-material-secrets: fill-0, NO free)
   for prompt hygiene. The KM handle is KEPT in ALL-KMS so its foreign buffers are freed EXACTLY ONCE at the
   QUIESCED participant teardown (cm-teardown, after the receiver thread is joined): freeing here would UAF a
   concurrent in-flight decode (a lease-expired peer's delayed/replayed datagram resolved before the drop) — the
   no-mid-run-free invariant. Under the manager lock; idempotent (a re-discovered peer re-registers). Returns the
   count of KMs dropped (0 = the peer had no registered crypto — GOV=none / never keyed).
   Contract: do not drive %lease-sweep / announce on a participant concurrently with its own delete-participant
   (use-after-delete API misuse) — the real receiver-thread axis is closed by the stop-node join-before-free."
  (dds.pal:with-lock ((crypto-manager-lock cm))
    (let ((victims '()))
      (let ((pkm (gethash prefix (crypto-manager-remote-participant-crypto cm))))
        (when pkm (pushnew pkm victims) (remhash prefix (crypto-manager-remote-participant-crypto cm))))
      (let ((dead-guids '()))
        (maphash (lambda (guid km)
                   (when (loop for i below 12 always (= (aref guid i) (aref prefix i)))
                     (pushnew km victims) (push guid dead-guids)))
                 (crypto-manager-remote-entity-crypto cm))
        (dolist (g dead-guids) (remhash g (crypto-manager-remote-entity-crypto cm))))
      (dolist (km victims)
        (let ((kid (dds.security:key-material-sender-key-id km)))
          (when kid
            (remhash kid (crypto-manager-key-id-index cm))
            (remhash kid (crypto-manager-remote-key-id-entity cm))))
        ;; prompt secret wipe (no free — the buffers stay alive for the single quiesced-teardown free; ALL-KMS keeps the handle)
        (dds.security:wipe-key-material-secrets km))
      (length victims))))

;;; --- teardown: zeroize + free every KeyMaterial secret (ADR-0034 secret hygiene) ---

(defun* cm-teardown (cm)
    (function (crypto-manager) (eql t))
  "Zeroize + free the SECRET slots of EVERY §9.5.2 KeyMaterial this crypto-manager owns — the
   participant-teardown secret-hygiene choke (ADR-0034; operating contract NFR-MEM / CNSA-2.0 data-at-rest).
   Walks ALL-KMS (every minted/registered KM, including any replaced by re-keying) running
   dds.security:zeroize-key-material on each (idempotent; the EQ set dedups so no KM is double-freed), then
   clears ALL-KMS + the five registries + the two indices so a post-teardown resolver hands out NIL
   (fail-closed). MUST run only when the data path is QUIESCED (delete-participant, after dds.disc:stop-node
   has joined the receiver thread): the secret buffers are freed here. Under the manager lock; idempotent."
  (dds.pal:with-lock ((crypto-manager-lock cm))
    (maphash (lambda (km present) (declare (ignore present)) (dds.security:zeroize-key-material km))
             (crypto-manager-all-kms cm))
    (clrhash (crypto-manager-all-kms cm))
    (setf (crypto-manager-participant-crypto cm) nil)
    (clrhash (crypto-manager-remote-participant-crypto cm))
    (clrhash (crypto-manager-local-entity-crypto cm))
    (clrhash (crypto-manager-remote-entity-crypto cm))
    (clrhash (crypto-manager-key-id-index cm))
    (clrhash (crypto-manager-remote-key-id-entity cm)))
  t)

(defun* %participant-crypto-teardown (auth-state)
    (function (t) (eql t))
  "delete-participant secret-hygiene entry (ADR-0034): zeroize+free every KeyMaterial owned by the
   participant whose DP-AUTH-STATE is AUTH-STATE (an auth-manager-state, or NIL when security is OFF). NIL —
   or a manager with no crypto-manager — is a no-op; otherwise runs CM-TEARDOWN. MUST be called only after
   dds.disc:stop-node has quiesced the data path. Idempotent. Returns T."
  (when auth-state
    (let ((cm (auth-manager-state-crypto-manager auth-state)))
      (when cm (cm-teardown cm))))
  t)
