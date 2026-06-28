(in-package #:dds.security)

;;;; DDS-Security 1.1 §7.3.7 shared cryptographic-transformation wire codec (Slice 4 / WP-DDS-
;;;; SECURITY-SECURE-DISCOVERY T1): the CryptoHeader / CryptoContent / CryptoFooter elements reused by
;;;; submessage protection (SEC_PREFIX/SEC_BODY/SEC_POSTFIX, T2), whole-RTPS-message protection
;;;; (SRTPS_PREFIX/SRTPS_POSTFIX, T4), and the Slice-1 serialized-payload tier (crypto.lisp delegates
;;;; here). The §7.3.7 elements map onto the §9.5.3.3 SecuredPayload structs of the builtin AES-GCM-GMAC
;;;; plugin one-to-one:
;;;;   * CryptoHeader  = transform_identifier{transformation_kind octet[4], transformation_key_id
;;;;       octet[4]} ‖ plugin_crypto_header_extra{session_id octet[4], init_vector_suffix octet[8]}
;;;;       = the 20-octet §9.5.3.3.1 SecureDataHeader.
;;;;   * CryptoContent = the §9.5.3.3.4.4 crypto_content: a uint32-length-prefixed sequence<octet>.
;;;;   * CryptoFooter  = common_mac octet[16] ‖ receiver_specific_macs (uint32 count ‖
;;;;       {receiver_mac_key_id octet[4], receiver_mac octet[16]}*) = the §9.5.3.3.3 SecureDataTag.
;;;;
;;;; Clean-room (the operating contract §4): every field width / layout is pinned from its OMG DDS-
;;;; Security 1.1 §-clause (cited per symbol below) and dual-corroborated (Fast DDS Apache-2.0 source,
;;;; reading only; Wireshark/tshark 4.6.6 RTPS dissector), per the T0 spike
;;;; docs/superpowers/spikes/2026-06-27-dds-security-secure-discovery.md and docs/provenance.md. No
;;;; value is typed from memory. Bounds-checked, fail-closed: every parse path check-room's against the
;;;; buffer extent BEFORE each read and caps the receiver-MAC count BEFORE allocating, returning NIL on
;;;; any shortfall — never an OOB read or an unbounded allocation, even at (safety 0) (NFR-SEC-POSTURE).
;;;;
;;;; ENDIANNESS (the operating contract §4 — the wire is the oracle): the CryptoContent length
;;;; (§9.5.3.3.4.4) and the CryptoFooter receiver_specific_macs_count (§9.5.3.3.3) are serialized
;;;; BIG-ENDIAN, independent of the surrounding RTPS submessage's E-flag endianness — the %put-u32-be /
;;;; %get-u32-be helpers force it. Corroborated CLEAN-ROOM (read-only, no code copied) against Fast DDS
;;;; (Apache-2.0; Cdr::Endianness::BIG_ENDIANNESS) AND Eclipse Cyclone DDS (ddsrt_toBE4u/ddsrt_fromBE4u);
;;;; see docs/provenance.md (M7/P6 T-RECONCILE). All other crypto-wire fields are opaque octet arrays.
;;;;
;;;; DRY: the §9.5.3.3 wire-element WIDTH constants live HERE (the lowest-level wire-layout file, loaded
;;;; before its consumers in dds-security.asd) as the single source of truth; crypto.lisp, transform.lisp
;;;; and the T2/T4 tiers reference them by name (same DDS.SECURITY package). The CryptoTransformKind
;;;; VALUE (+transformation-kind-aes256-gcm+), the rsm=0 tag total (+secure-data-tag-len+) and the
;;;; payload-protection count literal stay in crypto.lisp where the serialized-payload tier owns them.

;;; --- §9.5.3.3 wire-element field widths (single source of truth; consumed across DDS.SECURITY) ---

(defconstant +transformation-kind-len+ 4 "CryptoTransformKind width: octet[4] (§9.5.3.3.1).")
(defconstant +transformation-key-id-len+ 4 "CryptoTransformKeyId width: octet[4] (§9.5.3.3.1; opaque, spike §8.2).")
(defconstant +session-id-len+ 4 "SecureDataHeader.session_id width: octet[4] (§9.5.3.3.1; spike §2.2).")
(defconstant +init-vector-suffix-len+ 8 "SecureDataHeader.init_vector_suffix width: octet[8] (§9.5.3.3.1; spike §2.2).")
(defconstant +secure-data-header-len+ 20
  "SecureDataHeader total width = kind(4)+key_id(4)+session_id(4)+iv_suffix(8) (§9.5.3.3.1; spike §2.2).")
(defconstant +crypto-content-length-len+ 4
  "crypto_content sequence<octet> length-prefix width: uint32 (§9.5.3.3.4.4; spike §2.3). Serialized
   BIG-ENDIAN on the wire (Fast-DDS/Cyclone-aligned; see %put-u32-be) — the width is endian-independent.")
(defconstant +common-mac-len+ 16
  "SecureDataTag.common_mac width = AES-GCM 128-bit tag, 16 octets (§9.5.3.3.3; spike §2.4/§5).")
(defconstant +receiver-specific-macs-count-len+ 4
  "SecureDataTag.receiver_specific_macs_count width: uint32 (§9.5.3.3.3; spike §2.4). Serialized
   BIG-ENDIAN on the wire (Fast-DDS/Cyclone-aligned; see %put-u32-be) — the width is endian-independent.")

;;; --- receiver-specific-MAC count cap (parse-side resource-exhaustion guard; NOT a wire constant) ---

(defconstant +max-receiver-specific-macs+ 65535
  "Maximum receiver_specific_macs entries PARSE-CRYPTO-FOOTER will accept from one CryptoFooter before
   rejecting it (-> NIL). A parse-side resource-exhaustion guard (the operating contract §4 /
   NFR-SEC-POSTURE), NOT an OMG wire constant: the receiver_specific_macs_count field is a uint32
   (§9.5.3.3.3), so a hostile or corrupt footer could declare up to 2^32-1 entries; this caps the
   value BEFORE any per-entry allocation. 65535 exceeds every realistic DDS domain's per-writer
   matched-reader / per-participant origin-auth count by orders of magnitude (so it never false-REJECTs
   a legitimate deployment), while the buffer-extent check-room remains the primary bound.")

;;; --- big-endian uint32 helper: the AES-GCM-GMAC CryptoContent length + CryptoFooter count (§9.5.3.3.3/.4.4) ---

(defun* %put-u32-be (cursor value)
    (function (dds.core.buffer:cursor (integer 0)) (integer 0))
  "Write VALUE as a big-endian uint32 at CURSOR, INDEPENDENT of the cursor's stream endianness, and return
   VALUE. The DDS-Security 1.1 builtin AES-GCM-GMAC plugin serializes the CryptoContent length
   (§9.5.3.3.4.4) and the CryptoFooter receiver_specific_macs_count (§9.5.3.3.3) BIG-ENDIAN regardless of
   the surrounding RTPS submessage's E-flag endianness. Corroborated CLEAN-ROOM (read-only, no code copied):
   Fast DDS (Apache-2.0) AESGCMGMAC_Transform.cpp forces Cdr::Endianness::BIG_ENDIANNESS on exactly these
   two fields (serialize_SecureDataBody cnt_length; serialize_SecureDataTag count); Eclipse Cyclone DDS uses
   ddsrt_toBE4u for both. See docs/provenance.md (M7/P6 T-RECONCILE). Saves/sets/restores the cursor
   endianness around the shared put-u32 (DRY), leaving the rest of the stream's endianness untouched."
  (let ((saved (dds.core.buffer:cursor-endianness cursor)))
    (dds.core.buffer:cursor-set-endianness cursor :big)
    (unwind-protect (dds.core.buffer:put-u32 cursor value)
      (dds.core.buffer:cursor-set-endianness cursor saved))))

(defun* %get-u32-be (cursor)
    (function (dds.core.buffer:cursor) (integer 0))
  "Read a big-endian uint32 at CURSOR, INDEPENDENT of the cursor's stream endianness — the inverse of
   %put-u32-be. The AES-GCM-GMAC CryptoContent length (§9.5.3.3.4.4) and CryptoFooter count (§9.5.3.3.3)
   are always big-endian on the wire (Fast DDS BIG_ENDIANNESS / Cyclone ddsrt_fromBE4u; see %put-u32-be +
   docs/provenance.md). The caller check-room's BEFORE the call, so the fail-closed bounds discipline is
   preserved. Saves/sets/restores the cursor endianness around the shared get-u32 (DRY)."
  (let ((saved (dds.core.buffer:cursor-endianness cursor)))
    (dds.core.buffer:cursor-set-endianness cursor :big)
    (unwind-protect (dds.core.buffer:get-u32 cursor)
      (dds.core.buffer:cursor-set-endianness cursor saved))))

;;; --- CryptoHeader (§7.3.7 / §9.5.3.3.1 SecureDataHeader) ---

(defun* serialize-crypto-header (cursor kind key-id session-id iv-suffix)
    (function (dds.core.buffer:cursor
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              fixnum)
  "Write the 20-byte DDS-Security 1.1 §7.3.7 CryptoHeader at CURSOR; return the octet count (20).
   Layout: transformation_kind(4) ‖ transformation_key_id(4) ‖ session_id(4) ‖ init_vector_suffix(8)
   — identical to the §9.5.3.3.1 SecureDataHeader, so the serialized-payload tier reuses this codec.
   KIND/KEY-ID/SESSION-ID must be 4 octets and IV-SUFFIX 8 octets (caller precondition; the API
   boundary validates — e.g. SERIALIZE-SECURED-PAYLOAD's %require-len). Advances CURSOR by 20."
  (dds.core.buffer:put-octets cursor kind 0 +transformation-kind-len+)
  (dds.core.buffer:put-octets cursor key-id 0 +transformation-key-id-len+)
  (dds.core.buffer:put-octets cursor session-id 0 +session-id-len+)
  (dds.core.buffer:put-octets cursor iv-suffix 0 +init-vector-suffix-len+)
  +secure-data-header-len+)

(defun* parse-crypto-header (cursor)
    (function (dds.core.buffer:cursor)
              (values (or (simple-array (unsigned-byte 8) (*)) null)
                      (or (simple-array (unsigned-byte 8) (*)) null)
                      (or (simple-array (unsigned-byte 8) (*)) null)
                      (or (simple-array (unsigned-byte 8) (*)) null)))
  "Parse a §7.3.7 CryptoHeader at CURSOR; return (values KIND KEY-ID SESSION-ID IV-SUFFIX) — each a
   fresh octet vector — or NIL on any shortfall. check-room guards the full 20 octets before any read;
   fewer than 20 remaining -> NIL, never an OOB read or partial parse (NFR-SEC-POSTURE), even at
   (safety 0). Advances CURSOR by 20 on success."
  (handler-case
      (progn
        (dds.core.buffer:check-room cursor +secure-data-header-len+)
        (let ((kind       (make-array +transformation-kind-len+ :element-type '(unsigned-byte 8)))
              (key-id     (make-array +transformation-key-id-len+ :element-type '(unsigned-byte 8)))
              (session-id (make-array +session-id-len+ :element-type '(unsigned-byte 8)))
              (iv-suffix  (make-array +init-vector-suffix-len+ :element-type '(unsigned-byte 8))))
          (dds.core.buffer:get-octets cursor kind 0 +transformation-kind-len+)
          (dds.core.buffer:get-octets cursor key-id 0 +transformation-key-id-len+)
          (dds.core.buffer:get-octets cursor session-id 0 +session-id-len+)
          (dds.core.buffer:get-octets cursor iv-suffix 0 +init-vector-suffix-len+)
          (values kind key-id session-id iv-suffix)))
    (dds.core.buffer:buffer-overflow () nil)))

;;; --- CryptoContent (§7.3.7 / §9.5.3.3.4.4 crypto_content) ---

(defun* serialize-crypto-content (cursor ciphertext)
    (function (dds.core.buffer:cursor (simple-array (unsigned-byte 8) (*)))
              fixnum)
  "Write the §7.3.7 CryptoContent at CURSOR — a uint32 length prefix (BIG-ENDIAN, §9.5.3.3.4.4; forced
   independent of the cursor's stream endianness via %put-u32-be, Fast-DDS/Cyclone-aligned) followed by
   the CIPHERTEXT octets — and return the octet count (4 + |CIPHERTEXT|). This is the §9.5.3.3.4.4
   crypto_content encoding. Advances CURSOR by 4 + |CIPHERTEXT|."
  (let ((n (length ciphertext)))
    (%put-u32-be cursor n)
    (dds.core.buffer:put-octets cursor ciphertext 0 n)
    (+ +crypto-content-length-len+ n)))

(defun* parse-crypto-content (cursor)
    (function (dds.core.buffer:cursor)
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Parse a §7.3.7 CryptoContent at CURSOR; return the ciphertext octets, or NIL on any shortfall.
   The uint32 length is BIG-ENDIAN (§9.5.3.3.4.4; read via %get-u32-be, independent of cursor endianness,
   Fast-DDS/Cyclone-aligned) and is bounds-checked against the buffer extent (check-room) BEFORE the result
   is allocated, so a hostile / over-declared length yields NIL rather than a large allocation or an OOB
   read (NFR-SEC-POSTURE), even at (safety 0). Advances CURSOR by 4 + length on success."
  (handler-case
      (progn
        (dds.core.buffer:check-room cursor +crypto-content-length-len+)
        (let ((n (%get-u32-be cursor)))
          (dds.core.buffer:check-room cursor n)
          (let ((ciphertext (make-array n :element-type '(unsigned-byte 8))))
            (dds.core.buffer:get-octets cursor ciphertext 0 n)
            ciphertext)))
    (dds.core.buffer:buffer-overflow () nil)))

;;; --- CryptoFooter (§7.3.7 / §9.5.3.3.3 SecureDataTag) ---

(defun* serialize-crypto-footer (cursor common-mac receiver-macs)
    (function (dds.core.buffer:cursor (simple-array (unsigned-byte 8) (*)) list)
              fixnum)
  "Write the §7.3.7 CryptoFooter at CURSOR; return the octet count. Layout:
   common_mac(16) ‖ receiver_specific_macs_count(uint32 BIG-ENDIAN) ‖ {receiver_mac_key_id(4) ‖ receiver_mac(16)}*
   — the §9.5.3.3.3 SecureDataTag. The count is BIG-ENDIAN (§9.5.3.3.3; via %put-u32-be, independent of
   cursor endianness, Fast-DDS/Cyclone-aligned); the key_id/mac fields are opaque octet arrays. RECEIVER-MACS
   is a list of (key_id . mac) conses (each key_id 4 octets, each mac 16 octets, caller precondition); an
   empty list writes count 0 (the Slice-1 serialized-payload tag). COMMON-MAC must be 16 octets. Advances
   CURSOR by 16 + 4 + 20*count."
  (let ((count (length receiver-macs)))
    (dds.core.buffer:put-octets cursor common-mac 0 +common-mac-len+)
    (%put-u32-be cursor count)
    (dolist (entry receiver-macs)
      (dds.core.buffer:put-octets cursor (car entry) 0 +transformation-key-id-len+)
      (dds.core.buffer:put-octets cursor (cdr entry) 0 +common-mac-len+))
    (+ +common-mac-len+ +receiver-specific-macs-count-len+
       (* count (+ +transformation-key-id-len+ +common-mac-len+)))))

(defun* parse-crypto-footer (cursor)
    (function (dds.core.buffer:cursor)
              (values (or (simple-array (unsigned-byte 8) (*)) null) list))
  "Parse a §7.3.7 CryptoFooter at CURSOR; return (values COMMON-MAC RECEIVER-MACS) — COMMON-MAC a
   16-octet vector and RECEIVER-MACS a list of (key_id . mac) conses (each in wire order, possibly
   empty) — or NIL (first value) on any shortfall. The receiver_specific_macs_count is read BIG-ENDIAN
   (§9.5.3.3.3; via %get-u32-be, independent of cursor endianness, Fast-DDS/Cyclone-aligned), then
   REJECTED (-> NIL) if it exceeds +max-receiver-specific-macs+ BEFORE any per-entry allocation, and
   the full entry extent is check-room'd before reading; a truncated or hostile footer yields NIL,
   never an OOB read or an unbounded allocation (NFR-SEC-POSTURE), even at (safety 0). A valid empty
   footer returns a non-NIL COMMON-MAC with RECEIVER-MACS = NIL, so COMMON-MAC discriminates success
   from shortfall. Advances CURSOR past the footer on success."
  (handler-case
      (progn
        (dds.core.buffer:check-room cursor +common-mac-len+)
        (let ((common-mac (make-array +common-mac-len+ :element-type '(unsigned-byte 8))))
          (dds.core.buffer:get-octets cursor common-mac 0 +common-mac-len+)
          (dds.core.buffer:check-room cursor +receiver-specific-macs-count-len+)
          (let ((count (%get-u32-be cursor)))
            (when (> count +max-receiver-specific-macs+)
              (return-from parse-crypto-footer nil))
            (dds.core.buffer:check-room cursor (* count (+ +transformation-key-id-len+ +common-mac-len+)))
            (let ((macs '()))
              (dotimes (i count)
                (let ((kid (make-array +transformation-key-id-len+ :element-type '(unsigned-byte 8)))
                      (mac (make-array +common-mac-len+ :element-type '(unsigned-byte 8))))
                  (dds.core.buffer:get-octets cursor kid 0 +transformation-key-id-len+)
                  (dds.core.buffer:get-octets cursor mac 0 +common-mac-len+)
                  (push (cons kid mac) macs)))
              (values common-mac (nreverse macs))))))
    (dds.core.buffer:buffer-overflow () nil)))
