(defpackage #:net.goenninger.dds.security
  (:nicknames #:dds.security)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "DDS.SECURITY — DDS-Security 1.1 Cryptographic plugin, Slice 1 (serialized-payload protection,
    §9.5.3.3) + Slice 2a Auth (§8.7 Authentication plugin T1: PKI identity load/validate +
    IdentityToken). Crypto primitives reused from DDS.DARE (OpenSSL >= 3.5); no hand-rolled
    crypto, no copied wire constants (every field cited from the §-clause + spike docs).")
  (:export
   #:+transformation-kind-aes256-gcm+
   #:+transformation-kind-aes256-gmac+
   ;; Slice 4 (WP-DDS-SECURITY-SECURE-DISCOVERY T2): §8.5.1.7-.9 submessage protection
   ;; (crypto/submessage.lisp) — SEC_PREFIX/SEC_BODY/SEC_POSTFIX SIGN+ENCRYPT; consumed by T3
   ;; (origin-auth), T4 (whole-RTPS protection reuses the shared AEAD core) and T9 (secure SEDP).
   #:encode-datawriter-submessage
   #:decode-datawriter-submessage
   #:encode-datareader-submessage
   #:decode-datareader-submessage
   ;; Slice 2 / ZA-2 (WP-DDS-SECURITY-ZEROALLOC-AEAD T4): zero-alloc into-buffer submessage tier for the live
   ;; dataplane — wrap/unwrap ONE user submessage bracket (SEC_PREFIX 0x31 / SEC_POSTFIX 0x32) through a
   ;; caller-owned STATIC buffer by raw offset (no per-submessage subseq / →octets); the shared
   ;; %encode/%decode-secured-region-into cores, byte-identical wire. Consumed by dds.disc (send multi-bracket
   ;; wrap + the receive re-dispatch).
   #:encode-datawriter-submessage-into
   #:decode-datawriter-submessage-into
   #:encode-datareader-submessage-into
   #:decode-datareader-submessage-into
   ;; Slice 4 (WP-DDS-SECURITY-SECURE-DISCOVERY T4): §8.5.1.10-.12 whole-RTPS-message protection
   ;; (crypto/rtps-message.lisp) — SRTPS_PREFIX/SEC_BODY/SRTPS_POSTFIX SIGN+ENCRYPT+origin-auth over the
   ;; shared %encode/%decode-secured-region engine; ParticipantCrypto-keyed. Consumed by T10 (send /
   ;; %handle-datagram). The whole submessage STREAM is the protected unit (SIGN walks it to SRTPS_POSTFIX).
   #:encode-rtps-message
   #:decode-rtps-message
   ;; Slice 2 / ZA-2 (WP-DDS-SECURITY-ZEROALLOC-AEAD T3): zero-alloc into-buffer whole-RTPS tier for the live
   ;; dataplane — wrap/unwrap SRTPS through a caller-owned STATIC buffer by raw offset (no per-datagram subseq /
   ;; →octets); the shared %encode/%decode-secured-region-into cores, byte-identical wire. Consumed by dds.disc.
   #:encode-rtps-message-into
   #:decode-rtps-message-into
   ;; Slice 4 (WP-DDS-SECURITY-SECURE-DISCOVERY T3): origin authentication (§9.5.3.3.4.3) —
   ;; receiver-specific session-key KDF + per-receiver GMAC; encode emits receiver_specific_macs (the
   ;; encode :receivers key), decode verifies its own (the decode :my-receiver-key-id/:my-receiver-key
   ;; keys). Consumed by T4 (whole-RTPS protection) / T6 / T8.
   #:derive-receiver-specific-session-key
   #:compute-receiver-specific-mac
   ;; Slice 4 (WP-DDS-SECURITY-SECURE-DISCOVERY T0): §8.5 crypto-plugin + §9.4.1.2 governance constants
   ;; (crypto/constants.lisp). Secure builtin EntityIds + §7.4.6.1 bits live in dds.rtps.discovery;
   ;; crypto-token message_class_ids are the +gm-*-crypto-tokens+ in keyexchange.lisp (DRY, not re-pinned).
   #:+submessage-sec-body+ #:+submessage-sec-prefix+ #:+submessage-sec-postfix+
   #:+submessage-srtps-prefix+ #:+submessage-srtps-postfix+
   #:+kdf-label-session-receiver-key+
   #:+protection-kinds+ #:+basic-protection-kinds+ #:+protection-kind-xsd-strings+
   ;; Slice 4 (WP-DDS-SECURITY-SECURE-DISCOVERY T1): §7.3.7 shared CryptoHeader/Content/Footer wire
   ;; codec (crypto/crypto-header.lisp) reused by submessage- (T2) / RTPS-message- (T4) protection +
   ;; the Slice-1 serialized-payload tier; +max-receiver-specific-macs+ is the parse-side count cap.
   #:+max-receiver-specific-macs+
   #:serialize-crypto-header #:parse-crypto-header
   #:serialize-crypto-content #:parse-crypto-content
   #:serialize-crypto-footer #:parse-crypto-footer
   #:secured-payload-malformed
   #:secured-payload-malformed-reason
   #:serialize-secured-payload
   #:parse-secured-payload
   #:derive-session-key
   ;; KeyMaterial struct + constructor (§9.5.2 Table 65)
   #:key-material
   #:make-key-material
   #:key-material-transformation-kind
   #:key-material-master-salt
   #:key-material-sender-key-id
   #:key-material-master-sender-key
   #:key-material-iv-counter
   #:key-material-iv-counter-lock
   ;; §9.5.3.3.1 tier predicate: ENCRYPT (AES256-GCM) vs SIGN (AES256-GMAC) — the ZC/SHMEM overlay eligibility gate
   #:key-material-encrypt-p
   ;; ADR-0034 secret hygiene: foreign/static KeyMaterial master secrets + zeroize-on-teardown choke + fail-closed guard
   #:zeroize-key-material
   #:wipe-key-material-secrets
   #:key-material-zeroized
   #:key-material-zeroized-error
   #:make-test-key-material
   ;; T6: per-writer key resolver (§9.5.3.3.4.4/4.5 dynamic key lookup, replaces pre-shared km)
   #:crypto-keys
   #:make-crypto-keys
   #:crypto-keys-encode-key-fn
   #:crypto-keys-decode-key-fn
   ;; Transform ops (§9.5.3.3.4.4/4.5) — allocating entries + the zero-alloc into-buffer codec core
   #:encode-serialized-payload
   #:decode-serialized-payload
   #:encode-serialized-payload-into #:secured-payload-length
   #:decode-serialized-payload-into
   ;; Auth T1: PKI identity (§8.7 / §9.3) — DDS-Security 1.1 Authentication plugin
   #:+test-pki-root+
   #:+test-ac-pki-root+
   #:+test-ssd-pki-root+
   #:identity-handle
   #:identity-handle-p
   #:identity-handle-cert
   #:identity-handle-pkey
   #:identity-handle-ca-store
   #:identity-handle-token-octets
   #:identity-handle-guid
   #:validate-local-identity
   #:identity-token
   #:validate-remote-identity
   #:free-identity-handle
   ;; Auth T2: handshake state machine + ECDH-P256 suite (WP-DDS-SECURITY-AUTH-2A T2)
   #:auth-suite
   #:auth-suite-p
   #:auth-suite-kagree-algo-str
   #:auth-suite-dsign-algo-str
   #:+suite-ecdh+
   ;; Auth T3: FFDH-2048 + RSA-PSS suite + §9.3.2 selection (WP-DDS-SECURITY-AUTH-2A T3)
   #:+suite-ffdh+
   #:select-auth-suite
   ;; WP-DDS-SECURITY-AUTH-KEYX T5: identity-derived §9.3.2 suite selection (encapsulates %cert-algo->kind NIL)
   #:select-suite-for-identities
   #:handshake-token
   #:handshake-token-p
   #:handshake-handle
   #:handshake-handle-p
   #:handshake-handle-state
   #:handshake-handle-peer-subject
   #:handshake-handle-shared-secret
   #:shared-secret-handle
   #:shared-secret-handle-p
   #:shared-secret-handle-challenge1-bytes
   #:shared-secret-handle-challenge2-bytes
   #:begin-handshake-request
   #:begin-handshake-reply
   #:process-handshake
   #:handshake-shared-secret
   #:shared-secret-bytes
   #:free-shared-secret-handle
   #:free-handshake-handle
   ;; T2: §9.3.4 DataHolder + §7.4.4 ParticipantGenericMessage wire codec (WP-DDS-SECURITY-AUTH-2BI T2)
   #:+auth-message-class-id+
   ;; §8.7.2.3 AuthRequestMessageToken sub-protocol (challenge-binding / anti-replay) — full-participant
   ;; (RTI Connext) interop; §8.7.2.3-optional, absence tolerated (WP-DDS-SECURITY-CONNEXT-INTEROP Slice 5b)
   #:+auth-request-message-class-id+
   #:+auth-request-class-id+
   #:+prop-future-challenge+
   #:generate-future-challenge
   #:handshake-token->dataholder
   #:dataholder->handshake-token
   #:make-generic-message
   #:parse-generic-message
   ;; KeyMaterial §9.5.2 Table 65: two additional receiver-specific key fields (T3)
   #:key-material-receiver-specific-key-id
   #:key-material-master-receiver-specific-key
   ;; §9.5.3.3.4.3 memoized origin-auth receiver descriptor (zero-alloc per-datagram resolver, WP-SECURITY-ORIGIN-AUTH-ZEROALLOC)
   #:km-receiver-descriptor
   #:km-receiver-descriptor-list
   ;; WP-DDS-SECURITY-AUTH-KEYX T2: §9.5.3 KxKey/KxSalt derivation from the SharedSecret
   #:kx-key-handle
   #:kx-key-handle-p
   #:derive-kx-key
   #:derive-kx-salt
   #:kx-key-bytes
   #:free-kx-key
   ;; WP-DDS-SECURITY-AUTH-KEYX T3: §9.5.2 KeyMaterial generation + KxKey CryptoToken codec
   #:+crypto-token-class-id+
   #:+crypto-token-keymat-prop+
   #:+gm-participant-crypto-tokens+
   #:+gm-datawriter-crypto-tokens+
   #:+gm-datareader-crypto-tokens+
   #:generate-writer-key-material
   ;; T6 (WP-DDS-SECURITY-SECURE-DISCOVERY): generic §8.5 CryptoKeyFactory KeyMaterial generator
   #:generate-key-material
   #:serialize-crypto-token
   #:parse-crypto-token
   #:make-crypto-token-message
   #:parse-crypto-token-message
   ;; T8 (WP-DDS-SECURITY-SECURE-DISCOVERY): plaintext CryptoToken DataHolder (§8.5.2, rides inside PVMS)
   #:serialize-crypto-token-plain
   #:parse-crypto-token-plain
   ;; T2: AccessControl Governance/Permissions data model + parser + matcher (WP-DDS-SECURITY-ACCESS-CONTROL)
   ;; T5 (WP-DDS-SECURITY-SECURE-DISCOVERY): protection-kind model
   #:topic-rule #:make-topic-rule #:topic-rule-p
   #:topic-rule-topic-expr
   #:topic-rule-enable-read-ac #:topic-rule-enable-write-ac
   #:topic-rule-enable-discovery-protection #:topic-rule-enable-liveliness-protection
   #:topic-rule-metadata-protection-kind #:topic-rule-data-protection-kind
   #:governance
   #:make-governance
   #:governance-p
   #:governance-allow-unauthenticated
   #:governance-enable-join-ac
   #:governance-discovery-protection-kind
   #:governance-liveliness-protection-kind
   #:governance-rtps-protection-kind
   #:governance-topic-rules
   #:parse-governance
   #:governance-topic-rule
   #:governance-discovery-protection
   #:governance-liveliness-protection
   #:governance-rtps-protection
   #:governance-any-protection-p
   #:protection-kind-base
   #:topic-discovery-protected-p
   #:topic-metadata-protection
   #:topic-data-protection
   #:governance-effective-data-protection
   #:governance-effective-metadata-protection
   #:governance-mixed-nonnone-kind-conflict
   #:permissions
   #:make-permissions
   #:permissions-p
   #:permissions-subject-name
   #:permissions-not-before
   #:permissions-not-after
   #:permissions-default
   #:permissions-rules
   #:parse-permissions
   #:permissions-grant-for
   #:permissions-allow-publish-p
   #:permissions-allow-subscribe-p
   ;; T3: AccessControl plugin — validate + check predicates (WP-DDS-SECURITY-ACCESS-CONTROL)
   #:access-handle
   #:make-access-handle
   #:access-handle-p
   #:access-handle-governance
   #:access-handle-permissions
   #:access-handle-grants
   #:access-handle-ca-store
   #:access-handle-subject
   #:validate-local-permissions
   #:free-access-handle
   #:validate-remote-permissions
   #:check-create-participant
   #:check-create-datawriter
   #:check-create-datareader
   #:check-remote-datawriter
   #:check-remote-datareader))
