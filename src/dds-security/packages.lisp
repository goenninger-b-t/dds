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
   #:make-test-key-material
   ;; T6: per-writer key resolver (§9.5.3.3.4.4/4.5 dynamic key lookup, replaces pre-shared km)
   #:crypto-keys
   #:make-crypto-keys
   #:crypto-keys-encode-key-fn
   #:crypto-keys-decode-key-fn
   ;; Transform ops (§9.5.3.3.4.4/4.5)
   #:encode-serialized-payload
   #:decode-serialized-payload
   ;; Auth T1: PKI identity (§8.7 / §9.3) — DDS-Security 1.1 Authentication plugin
   #:+test-pki-root+
   #:+test-ac-pki-root+
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
   #:handshake-token->dataholder
   #:dataholder->handshake-token
   #:make-generic-message
   #:parse-generic-message
   ;; KeyMaterial §9.5.2 Table 65: two additional receiver-specific key fields (T3)
   #:key-material-receiver-specific-key-id
   #:key-material-master-receiver-specific-key
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
   #:serialize-crypto-token
   #:parse-crypto-token
   #:make-crypto-token-message
   #:parse-crypto-token-message
   ;; T2: AccessControl Governance/Permissions data model + parser + matcher (WP-DDS-SECURITY-ACCESS-CONTROL)
   #:governance
   #:make-governance
   #:governance-p
   #:governance-allow-unauthenticated
   #:governance-enable-join-ac
   #:governance-topic-rules
   #:parse-governance
   #:governance-topic-rule
   #:permissions
   #:make-permissions
   #:permissions-p
   #:permissions-subject-name
   #:permissions-not-before
   #:permissions-not-after
   #:permissions-default
   #:permissions-rules
   #:parse-permissions
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
