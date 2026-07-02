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

;;;; ZERO-ALLOC (Slice 2 / ZA-2 T3): the into-buffer whole-RTPS tier for the live dataplane. The allocating
;;;; encode/decode-rtps-message above stay unchanged (the WITH_ORIGIN_AUTHENTICATION receiver-MAC gate + the
;;;; deferred allocating fallback ride them); the -into entries below let the dds.disc send/receive paths wrap /
;;;; unwrap SRTPS through a caller-owned STATIC buffer BY RAW OFFSET (no per-datagram subseq / →octets), reusing
;;;; the SAME %encode/%decode-secured-region-into cores as the submessage tier (DRY). Byte-identical wire.

(defun* encode-rtps-message-into (out-buf out-off km kind plain plain-off plain-len &key (receivers '()))
    (function (dds.core.buffer:octet-buffer fixnum key-material (member :sign :encrypt)
               (simple-array (unsigned-byte 8) (*)) fixnum fixnum &key (:receivers list))
              fixnum)
  "Protect the submessage stream PLAIN[PLAIN-OFF..+PLAIN-LEN] (everything AFTER the 20-octet RTPS Header) under
   the ParticipantCrypto KeyMaterial KM per KIND (:sign | :encrypt) directly INTO the caller's STATIC octet-buffer
   OUT-BUF starting at OUT-OFF, and return the total SRTPS_PREFIX(0x33) ‖ <body> ‖ SRTPS_POSTFIX(0x34) bracket
   length — the zero-alloc, into-buffer twin of encode-rtps-message (which allocates a fresh →octets vector). The
   thin whole-RTPS delegation to the shared %encode-secured-region-into core with the SRTPS bracket ids; BYTE-
   IDENTICAL to encode-rtps-message by construction (same core), so the T4 byte-exact corpus covers it. Works BY
   OFFSET for BOTH kinds (the SIGN GMAC AAD is bounded to PLAIN[PLAIN-OFF..+PLAIN-LEN]). Common path (RECEIVERS
   empty) conses ~0 GC-heap B/call; RECEIVERS non-empty (origin authentication, §9.5.3.3.4.3) is the core's
   deferred allocating fallback (still written into OUT-BUF). OUT-BUF must hold OUT-OFF + the bracket length, else
   BUFFER-OVERFLOW (an O(1) extent check BEFORE any write, safety-0-safe; NFR-SEC-POSTURE — the caller fail-closes
   / drops on overflow). Consumed by dds.disc %maybe-wrap-srtps over a per-node send-scratch pool. Inverse:
   decode-rtps-message-into."
  (%encode-secured-region-into out-buf out-off km kind plain plain-off plain-len receivers
                               +submessage-srtps-prefix+ +submessage-srtps-postfix+))

(defun* decode-rtps-message-into (pt-out pt-off km secured secured-off secured-len)
    (function (dds.core.buffer:octet-buffer fixnum key-material
               (simple-array (unsigned-byte 8) (*)) fixnum fixnum)
              (values (or fixnum null) (or (member :sign :encrypt) null) (or fixnum null) (or fixnum null)))
  "Recover the protected submessage stream from an SRTPS_PREFIX ... SRTPS_POSTFIX bracket in
   SECURED[SECURED-OFF..+SECURED-LEN] under KM BY RAW OFFSET; return (values DATA-LEN MODE DATA-OFF POSTFIX-OFF),
   or a single NIL on ANY failure (fail-closed; NFR-SEC-POSTURE) — the zero-alloc, into-buffer twin of
   decode-rtps-message (which allocates the recovered vector). The thin whole-RTPS delegation to the shared
   %decode-secured-region-into core (SIGN-WALK-P T — the whole-RTPS SIGN body is located by WALKING the submessage
   stream to the trailing SRTPS_POSTFIX). The core validates the bracket + verifies the common_mac before any AEAD
   open. ENCRYPT: aes-256-gcm-open-into writes the recovered stream into PT-OUT[PT-OFF..+DATA-LEN] (zero GC-heap
   alloc); DATA-OFF is the ciphertext offset in SECURED. SIGN: NO copy into PT-OUT — DATA-OFF is the verbatim-region
   offset in SECURED (the caller moves it in place); DATA-LEN its length. POSTFIX-OFF is the SRTPS_POSTFIX offset.
   ORIGIN AUTHENTICATION (§9.5.3.3.4.3) is NOT verified here (the -into core does the common_mac only) — the
   WITH_ORIGIN_AUTHENTICATION tier stays on the allocating decode-rtps-message (its receiver-MAC gate); dds.disc
   %handle-datagram routes origin-auth there and the common tier through here. Consumed over a reused per-node RX
   buffer. Inverse: encode-rtps-message-into."
  (%decode-secured-region-into pt-out pt-off km secured secured-off secured-len t))
