(in-package #:dds.security)

;;;; DDS-Security 1.1 secure-discovery crypto-plugin wire constants (Slice 4 / WP-DDS-SECURITY-
;;;; SECURE-DISCOVERY). The §8.5 Cryptographic-plugin constants the submessage/RTPS-message
;;;; protection codecs (crypto-header.lisp, submessage.lisp, rtps-message.lisp — T1/T2/T4) and the
;;;; governance protection-kind model (T5) import. NO logic; pure pinned constants.
;;;;
;;;; Clean-room (the operating contract §4): every value is pinned from its OMG DDS-Security 1.1 /
;;;; DDSI-RTPS 2.5 §-clause and dual-corroborated — read directly from the Fast DDS Apache-2.0 source
;;;; (reading only, no code copied) and cross-checked against the vendor-neutral Wireshark/tshark
;;;; 4.6.6 RTPS dissector. Provenance + the pinned-values table: spike
;;;; docs/superpowers/spikes/2026-06-27-dds-security-secure-discovery.md; docs/provenance.md.
;;;;
;;;; DRY — related secure-discovery constants pinned ELSEWHERE (single source of truth, not
;;;; re-typed here; import from their home package/file):
;;;;   * Secure builtin EntityIds (secure SEDP pub/sub, secure participant-message, secure SPDP) +
;;;;     PVMS/PSM EntityIds + the §7.4.6.1 BuiltinEndpointSet security bits 16-27:
;;;;       dds.rtps.discovery (src/dds-rtps/discovery.lisp) — kept with the other builtin EntityIds.
;;;;   * Crypto-token GenericMessage message_class_ids ("dds.sec.{participant,datawriter,datareader}_
;;;;     crypto_tokens"): +gm-participant-crypto-tokens+ / +gm-datawriter-crypto-tokens+ /
;;;;     +gm-datareader-crypto-tokens+ (src/dds-security/auth/keyexchange.lisp, §7.4.4 / §9.5.2.2).
;;;;   * Session-key KDF id_string "SessionKey": +session-key-id-string+ (src/dds-security/crypto.lisp,
;;;;     §9.5.3.3.4.2). Receiver-specific-key KDF id_string is NEW and pinned below.
;;;;   * CryptoTransformKind octet[4] for AES256-GCM {0,0,0,4}: +transformation-kind-aes256-gcm+
;;;;     (src/dds-security/crypto.lisp, §9.5.3.3.1 Table 69).

;;; --- Secure RTPS SubmessageKind octets (DDS-Security 1.1 §7.3.7 — DDS-Security extends the DDSI-RTPS
;;; 2.5 SubmessageKind set with the 0x30-0x34 security submessages). Same 1-octet submessageId space as
;;; the dds.rtps +submsg-*+ family
;;; (src/dds-rtps/message.lisp, e.g. +submsg-data+ #x15); kept in the crypto plugin so the codec does
;;; not pull a dds-security -> dds-rtps dependency. Corroboration: Fast DDS
;;; src/cpp/rtps/security/cryptography/CryptoTypes.h lines 31-41 (SEC_PREFIX 0x31 ... SecureBody 0x30);
;;; Wireshark packet-rtps.c SUBMESSAGE_SEC_* (vendor-neutral, tshark 4.6.6).

(defconstant +submessage-sec-body+ #x30
  "SEC_BODY SubmessageKind = 0x30: carries CryptoContent (DDS-Security 1.1 §7.3.7; Fast DDS CryptoTypes.h).")
(defconstant +submessage-sec-prefix+ #x31
  "SEC_PREFIX SubmessageKind = 0x31: carries the CryptoHeader before a protected submessage (§7.3.7; Fast DDS).")
(defconstant +submessage-sec-postfix+ #x32
  "SEC_POSTFIX SubmessageKind = 0x32: carries the CryptoFooter after a protected submessage (§7.3.7; Fast DDS).")
(defconstant +submessage-srtps-prefix+ #x33
  "SRTPS_PREFIX SubmessageKind = 0x33: CryptoHeader for whole-RTPS-message protection (§7.3.7; Fast DDS).")
(defconstant +submessage-srtps-postfix+ #x34
  "SRTPS_POSTFIX SubmessageKind = 0x34: CryptoFooter for whole-RTPS-message protection (§7.3.7; Fast DDS).")

;;; --- Receiver-specific session-key KDF id_string (DDS-Security 1.1 §9.5.3.3.4.3; origin-auth).
;;; receiver_session_key = HMAC-SHA256(master_receiver_specific_key, "SessionReceiverKey" || master_salt
;;; || session_id); the per-receiver GMAC is computed under it (§9.5.3.3.4.3). NO trailing counter
;;; (Fast-DDS/Cyclone-aligned; T-RECONCILE — see docs/provenance.md). The session-key id_string
;;; ("SessionKey") is +session-key-id-string+ in crypto.lisp (reused). Corroboration: Fast DDS
;;; src/cpp/security/cryptography/AESGCMGMAC_Transform.cpp line 1481 (const char receiver_seq[] = "SessionReceiverKey").

(defconstant +kdf-label-session-receiver-key+
    (if (boundp '+kdf-label-session-receiver-key+)
        (symbol-value '+kdf-label-session-receiver-key+)
        "SessionReceiverKey")
  "DDS-Security 1.1 §9.5.3.3.4.3 receiver-specific session-key KDF id_string (ASCII, 18 octets).
   Used for origin authentication's receiver-specific GMAC key derivation; the session-key id_string
   counterpart is +session-key-id-string+ (\"SessionKey\", crypto.lisp). Corroborated against Fast DDS
   AESGCMGMAC_Transform.cpp. The boundp-guard makes a reload a no-op (defconstant same-value rule).")

;;; --- Governance ProtectionKind model (DDS-Security 1.1 §9.4.1.2 / Annex B dds_governance.xsd).
;;; ProtectionKind (5 values) gates the domain-rule kinds discovery_protection_kind /
;;; liveliness_protection_kind / rtps_protection_kind; BasicProtectionKind (3 values, no origin-auth)
;;; gates the per-topic metadata_protection_kind / data_protection_kind. The "on-wire encoding" is the
;;; XSD enumeration token carried in the signed Governance XML (there is no separate RTPS-wire enum;
;;; the local plugin maps the token to the protection it applies). Corroboration: Fast DDS
;;; src/cpp/security/accesscontrol/GovernanceParser.cpp lines 48-52 (ProtectionKind*_str string table).

(defconstant +protection-kinds+
    (if (boundp '+protection-kinds+)
        (symbol-value '+protection-kinds+)
        '(:none :sign :encrypt :sign-with-origin-auth :encrypt-with-origin-auth))
  "DDS-Security 1.1 §9.4.1.2 ProtectionKind — the 5 domain-rule protection kinds, in XSD order.
   :sign/:encrypt-with-origin-auth additionally emit receiver-specific MACs (§8.5.1.9). Boundp-guarded
   (a list is not EQL-comparable across reloads, so defconstant's same-value rule needs the guard).")

(defconstant +basic-protection-kinds+
    (if (boundp '+basic-protection-kinds+)
        (symbol-value '+basic-protection-kinds+)
        '(:none :sign :encrypt))
  "DDS-Security 1.1 §9.4.1.2 BasicProtectionKind — the 3 per-topic protection kinds (no origin-auth),
   used by metadata_protection_kind / data_protection_kind. A subset of +protection-kinds+. Boundp-guarded.")

(defconstant +protection-kind-xsd-strings+
    (if (boundp '+protection-kind-xsd-strings+)
        (symbol-value '+protection-kind-xsd-strings+)
        '((:none . "NONE")
          (:sign . "SIGN")
          (:encrypt . "ENCRYPT")
          (:sign-with-origin-auth . "SIGN_WITH_ORIGIN_AUTHENTICATION")
          (:encrypt-with-origin-auth . "ENCRYPT_WITH_ORIGIN_AUTHENTICATION")))
  "DDS-Security 1.1 §9.4.1.2 / dds_governance.xsd ProtectionKind keyword <-> on-wire XSD token alist.
   The governance parser (T5) maps each Governance-XML token to its keyword via reverse lookup (`rassoc`
   with `string=`); an unknown token MUST fail-closed (false-REJECT guard). Corroborated against Fast
   DDS GovernanceParser.cpp (lines 48-52). Boundp-guarded.")
