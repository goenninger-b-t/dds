(in-package #:dds.security)

;;;; DDS-Security 1.1 §8.5.1.10-.12 / §9.5.3.3.4 whole-RTPS-message protection (Slice 4 /
;;;; WP-DDS-SECURITY-SECURE-DISCOVERY T4): protect the ENTIRE submessage stream of a datagram
;;;; (everything AFTER the 20-octet RTPS Header) as
;;;;   SRTPS_PREFIX (0x33) ‖ <protected body> ‖ SRTPS_POSTFIX (0x34)
;;;; keyed by the per-participant ParticipantCrypto KeyMaterial (DDS-Security 1.1 §8.5.1.10/.11; the
;;;; rtps_protection_kind governance setting selects whether a participant applies it). The CALLER keeps
;;;; / re-prepends the 20-octet RTPS Header — the transform operates only on the submessage stream.
;;;;
;;;; This is the SAME AES-GCM-GMAC mechanism as the §8.5.1.7-.9 submessage tier (T2, crypto/submessage.lisp);
;;;; per the operating contract §10 (DRY, no copy-paste) BOTH tiers run on the SHARED engine
;;;; %encode-secured-region / %decode-secured-region. Only three things differ for the RTPS tier:
;;;;   (a) the bracket submessage ids are +submessage-srtps-prefix+ (0x33) / +submessage-srtps-postfix+
;;;;       (0x34) (T0-pinned, crypto/constants.lisp) instead of SEC_PREFIX/SEC_POSTFIX;
;;;;   (b) the protected unit is the whole submessage STREAM, not one submessage — so on SIGN decode the
;;;;       verbatim body is located by WALKING the stream to the trailing SRTPS_POSTFIX (sign-walk-p T,
;;;;       %walk-verbatim-body) rather than reading one embedded submessage;
;;;;   (c) the key is the ParticipantCrypto KeyMaterial (the caller resolves it; same key-material struct).
;;;;
;;;; FRAMING (identical to the submessage tier, only the kinds change; §9.5.3.3.4.3/.4):
;;;;   :encrypt  CryptoHeader.transformation_kind = AES256_GCM {0,0,0,4}; a SEC_BODY (0x30) carrying the
;;;;             length-prefixed CryptoContent = ciphertext (the encrypted submessage stream) sits between
;;;;             SRTPS_PREFIX and SRTPS_POSTFIX; AAD = EMPTY; common_mac = the GCM tag.
;;;;   :sign     CryptoHeader.transformation_kind = AES256_GMAC {0,0,0,3}; NO SEC_BODY — the ORIGINAL
;;;;             submessage stream sits VERBATIM between SRTPS_PREFIX and SRTPS_POSTFIX (§9.5.3.3.4.3);
;;;;             AAD = that stream; common_mac = the GMAC over it (no cipher).
;;;; ORIGIN AUTH (§9.5.3.3.4.3): the encode :receivers list and the decode :my-receiver-key-id /
;;;; :my-receiver-key keys behave exactly as in T3's submessage tier (the shared engine emits / verifies
;;;; the CryptoFooter receiver_specific_macs).
;;;;
;;;; Clean-room (the operating contract §4 — the wire is the oracle): the SRTPS layout AND the SIGN
;;;; decode-locate (walk the submessage stream to the trailing SRTPS_POSTFIX) are corroborated CLEAN-ROOM
;;;; (read-only, no code copied) against eProsima Fast DDS (Apache-2.0)
;;;; AESGCMGMAC_Transform.cpp encode_rtps_message / decode_rtps_message; see docs/provenance.md (M7/P6 T4).
;;;; NO RTI Connext source/headers/generated code consulted.
;;;;
;;;; SECURITY POSTURE (NFR-SEC-POSTURE): decode is FAIL-CLOSED and bounds-checked even at (safety 0) — the
;;;; SRTPS_PREFIX -> {SEC_BODY (ENCRYPT) | verbatim stream (SIGN)} -> SRTPS_POSTFIX bracket (kinds, order,
;;;; lengths within extent, a hostile body/stream length can't read past the buffer) is validated and every
;;;; field is check-room'd against the buffer extent BEFORE use; any malformed / truncated / re-ordered /
;;;; unknown-kind / GCM-or-GMAC-auth-fail / receiver-MAC-fail input yields NIL, never an OOB read, never a
;;;; signal to the caller, never plaintext on a failure. HOT PATH (per datagram): the encode scratch is
;;;; off-heap (the shared %encode-secured-region draws it from dds.pal:alloc-static; NFR-MEM).

(defun* encode-rtps-message (km kind submessages-octets &key (receivers '()))
    (function (key-material (member :sign :encrypt) (simple-array (unsigned-byte 8) (*))
               &key (:receivers list))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Protect the whole submessage stream SUBMESSAGES-OCTETS (everything AFTER the 20-octet RTPS Header) of a
   datagram under the ParticipantCrypto KeyMaterial KM per KIND (:sign | :encrypt), per DDS-Security 1.1
   §8.5.1.10-.12 / §9.5.3.3.4; return the SRTPS_PREFIX(0x33) ‖ <body> ‖ SRTPS_POSTFIX(0x34) octets (the
   CALLER prepends / keeps the RTPS Header), or NIL.
     :encrypt hides the stream — a SEC_BODY(0x30) carries the ciphertext (empty AAD; §9.5.3.3.4.4).
     :sign leaves the ORIGINAL stream VERBATIM between SRTPS_PREFIX and SRTPS_POSTFIX with NO SEC_BODY
       (§9.5.3.3.4.3) and a GMAC common_mac (stream-as-AAD).
   RECEIVERS enables origin authentication (§9.5.3.3.4.3): a list of
   (receiver-key-id . master-receiver-specific-key) conses (4- and 32-octet vectors); for each, a
   receiver-specific GMAC over the common_mac is emitted into the CryptoFooter receiver_specific_macs.
   EMPTY RECEIVERS (the default) is plain SIGN/ENCRYPT (rsm_count 0). Same crypto mechanism as
   encode-datawriter-submessage (T2/T3) over the shared %encode-secured-region engine — only the bracket
   submessage ids (SRTPS_PREFIX/SRTPS_POSTFIX) and the protected unit (the whole stream) differ (DRY).
   Inverse: decode-rtps-message. Consumed by the send / %handle-datagram paths at T10."
  (%encode-secured-region km kind submessages-octets receivers
                          +submessage-srtps-prefix+ +submessage-srtps-postfix+))

(defun* decode-rtps-message (km srtps-octets &key (my-receiver-key-id nil) (my-receiver-key nil))
    (function (key-material (simple-array (unsigned-byte 8) (*))
               &key (:my-receiver-key-id (or (simple-array (unsigned-byte 8) (*)) null))
                    (:my-receiver-key (or (simple-array (unsigned-byte 8) (*)) null)))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Recover the original submessage stream from SRTPS-OCTETS — the SRTPS_PREFIX(0x33) ... SRTPS_POSTFIX(0x34)
   bracket from encode-rtps-message (SEC_BODY ciphertext for ENCRYPT, the original stream verbatim for SIGN,
   §9.5.3.3.4.3) — under the ParticipantCrypto KeyMaterial KM, or NIL on any failure (fail-closed;
   DDS-Security 1.1 §8.5.1.12). SRTPS-OCTETS starts at SRTPS_PREFIX (the RTPS Header is handled by the
   caller). The wire CryptoHeader.transformation_kind selects the framing: {0,0,0,4} (GCM) opens a SEC_BODY
   ciphertext under EMPTY AAD; {0,0,0,3} (GMAC) verifies a GMAC over the verbatim stream, located by WALKING
   the submessage stream to the trailing SRTPS_POSTFIX (§8.5.1.12, corroborated against Fast DDS
   decode_rtps_message; see docs/provenance.md).
   For origin authentication (§9.5.3.3.4.3), pass MY-RECEIVER-KEY-ID (this receiver's 4-octet
   receiver_specific_key_id) and MY-RECEIVER-KEY (its 32-octet master_receiver_specific_key): the decoder
   then ALSO verifies this receiver's entry in the CryptoFooter receiver_specific_macs and fails-closed
   (NIL) if it is absent or does not match, even when the common_mac is valid. Both NIL (the default, the
   §8.5.1.12 2-arg contract T10 calls) = origin-auth not expected — the common_mac alone governs. Delegates
   to the shared %decode-secured-region engine (sign-walk-p T). Inverse: encode-rtps-message."
  (%decode-secured-region km srtps-octets my-receiver-key-id my-receiver-key
                          +submessage-srtps-prefix+ +submessage-srtps-postfix+ t))
