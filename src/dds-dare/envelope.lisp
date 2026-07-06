(in-package #:dds.dare)

;;; Task 4: KEM-DEM envelope — HKDF-SHA384 DEK derivation + AES-256-GCM seal/open.
;;; Wire format: version(1)=#x01 ∥ nonce(12) ∥ ciphertext ∥ tag(16).
;;; AAD binds topic + writer-guid + sequence-number + kind so relabeling is detected.
;;; Fail-closed: open-payload returns NIL (never plaintext) on any auth/parse failure.
;;; Bounds check in open-payload is mandatory even at (safety 0) — the operating contract §4.

(defconstant +envelope-version+ #x01
  "DARE envelope version byte (CNSA-2.0, v1). Fixed prefix of every sealed blob.")

(defconstant +envelope-version-v2+ #x02
  "DARE envelope version byte (v2, epoch-aware cross-restart key-epoch). ADR 0025 §5.")

(defconstant +envelope-epoch-len+ 4
  "Byte width of the epoch-id field in a v2 envelope (32-bit LE unsigned integer).")

(defconstant +envelope-v2-header-len+ 17
  "Version(1) + epoch-id(4) + nonce(12) bytes that precede ciphertext in a v2 sealed blob.")

(defconstant +envelope-header-len+ 13
  "Version(1) + nonce(12) bytes that precede the ciphertext in a sealed blob.")

(defconstant +envelope-min-sealed-len+ (+ +envelope-header-len+ +aes-gcm-tag-len+)
  "Minimum valid sealed-blob length: 1 version + 12 nonce + 16 tag = 29 bytes (ct may be 0).")

(defconstant +dek-info-str+
  (if (boundp '+dek-info-str+) (symbol-value '+dek-info-str+) "dds-dare/dek/v1")
  "HKDF-SHA384 info label for DEK derivation (ASCII, pinned; change = new version byte).
   The boundp guard keeps the value pinned to \"dds-dare/dek/v1\" while making the string
   constant reload-safe (DEFCONSTANT-UNEQL on recompile — strings are not self-eql), identically
   on SBCL and Clasp with no reader conditional.")

(defvar *dek-info-octets* nil
  "Cached octet vector for +dek-info-str+, built lazily on first use.")

(defun* %dek-info ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "Return (and cache) the HKDF info octet vector for DEK derivation."
  (or *dek-info-octets*
      (setf *dek-info-octets* (%ascii +dek-info-str+))))

(defconstant +logmac-info-str+
  (if (boundp '+logmac-info-str+) (symbol-value '+logmac-info-str+) "dds-dare/logmac/v1")
  "HKDF-SHA384 info label for durability log-MAC-key derivation (ASCII, pinned; change = new
   format version). Distinct domain separator from +dek-info-str+ so the log-MAC key is
   cryptographically independent of every DEK (ADR 0045 §4.3). Same reload-safe boundp guard
   as +dek-info-str+ (DEFCONSTANT-UNEQL — strings are not self-eql — identical SBCL/Clasp).")

(defvar *logmac-info-octets* nil
  "Cached octet vector for +logmac-info-str+, built lazily on first use.")

(defun* %logmac-info ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "Return (and cache) the HKDF info octet vector for log-MAC-key derivation."
  (or *logmac-info-octets*
      (setf *logmac-info-octets* (%ascii +logmac-info-str+))))

(defun* derive-log-mac-key (shared-secret)
    (function ((simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Derive a 32-byte durability log-MAC (HMAC-SHA-256) key from a cross-restart-STABLE ML-KEM
   shared secret via HKDF-SHA384 (ADR 0045 §4.3). Computes
   HKDF(SHA-384, ikm=SHARED-SECRET, salt=∅, info=ASCII(+logmac-info-str+), L=32).
   The stable secret is obtained by decapsulating a persisted anchor ciphertext — ML-KEM
   decapsulation is deterministic in (private-key, ciphertext) (FIPS-203), so a fixed anchor
   yields the same key on every restart while the key stays secret (only the private key
   decapsulates it). Mirrors DERIVE-DEK but with a distinct info label so the log-MAC key is
   independent of the DEK. The key is a foreign-backed secret buffer (static-vector, design
   spec §6) that never transits a GC-heap array; the caller (the encrypted-store) holds it for
   the store lifetime and MUST release it with FREE-SECRET-OCTETS on close."
  (%hkdf-sha384-into shared-secret
                     (make-array 0 :element-type '(unsigned-byte 8))
                     (%logmac-info)
                     32
                     t))

(defconstant +metakey-info-str+
  (if (boundp '+metakey-info-str+) (symbol-value '+metakey-info-str+) "dds-dare/meta/v1")
  "HKDF-SHA384 info label for the durability at-rest METADATA-sealing key k_meta derivation (ASCII,
   pinned; change = new format version). Distinct domain separator from +dek-info-str+ AND
   +logmac-info-str+ so k_meta is cryptographically independent of every DEK and of the log-MAC key
   (ADR 0025 §10 item 3c). Same reload-safe boundp guard as +dek-info-str+ (DEFCONSTANT-UNEQL —
   strings are not self-eql — identical SBCL/Clasp).")

(defvar *metakey-info-octets* nil
  "Cached octet vector for +metakey-info-str+, built lazily on first use.")

(defun* %metakey-info ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "Return (and cache) the HKDF info octet vector for k_meta derivation."
  (or *metakey-info-octets*
      (setf *metakey-info-octets* (%ascii +metakey-info-str+))))

(defun* derive-meta-key (shared-secret)
    (function ((simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Derive a 32-byte durability METADATA-sealing key k_meta (an HMAC-SHA-256 key AND an AES-256 key)
   from a cross-restart-STABLE ML-KEM shared secret via HKDF-SHA384 (ADR 0025 §10 item 3c). Computes
   HKDF(SHA-384, ikm=SHARED-SECRET, salt=∅, info=ASCII(+metakey-info-str+), L=32). The stable secret
   is obtained by decapsulating the SAME persisted log-MAC anchor ciphertext used for the log-MAC key
   — ML-KEM decapsulation is deterministic in (private-key, ciphertext) (FIPS-203), so a fixed anchor
   yields the same k_meta on every restart, letting a fresh process re-derive it and re-locate/decrypt
   the sealed metadata. A SIBLING of DERIVE-LOG-MAC-KEY with a distinct info label so k_meta is
   independent of the log-MAC key (zero new key-management surface). The key is a foreign-backed secret
   buffer (static-vector, design spec §6) that never transits a GC-heap array; the caller (the
   encrypted-store) holds it for the store lifetime and MUST release it with FREE-SECRET-OCTETS on close."
  (%hkdf-sha384-into shared-secret
                     (make-array 0 :element-type '(unsigned-byte 8))
                     (%metakey-info)
                     32
                     t))

(defun* derive-dek (shared-secret)
    (function ((simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Derive a 32-byte AES-256 Data-Encryption Key from ML-KEM shared secret via HKDF-SHA384.
   Computes HKDF(SHA-384, ikm=SHARED-SECRET, salt=#(), info=ASCII(+dek-info-str+), L=32).
   Per RFC 5869 §2 / NIST SP 800-56C Rev 2; info string is the pinned DARE KDF domain separator.
   The DEK is a foreign-backed secret buffer (static-vector) that never transits a GC-heap array
   (design spec §6); the caller (the encrypted-store) holds it for the store lifetime and MUST
   release it with FREE-SECRET-OCTETS on close."
  (%hkdf-sha384-into shared-secret
                     (make-array 0 :element-type '(unsigned-byte 8))
                     (%dek-info)
                     32
                     t))

(defun* seal-payload (dek nonce aad plaintext)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Seal PLAINTEXT with AES-256-GCM using DEK (32 B) and NONCE (12 B), authenticated with AAD.
   Returns a sealed blob: version(1)=#x01 ∥ nonce(12) ∥ ciphertext ∥ tag(16).
   Caller is responsible for nonce uniqueness (counter or random managed outside this fn)."
  (multiple-value-bind (ct tag)
      (aes-256-gcm-seal dek nonce aad plaintext)
    (let* ((pt-len  (length plaintext))
           (out-len (+ 1 +aes-gcm-nonce-len+ pt-len +aes-gcm-tag-len+))
           (out     (make-array out-len :element-type '(unsigned-byte 8))))
      (setf (aref out 0) +envelope-version+)
      (dotimes (i +aes-gcm-nonce-len+)
        (setf (aref out (+ 1 i)) (aref nonce i)))
      (dotimes (i pt-len)
        (setf (aref out (+ +envelope-header-len+ i)) (aref ct i)))
      (dotimes (i +aes-gcm-tag-len+)
        (setf (aref out (+ +envelope-header-len+ pt-len i)) (aref tag i)))
      out)))

(defun* open-payload (dek sealed aad)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Unseal a DARE blob produced by SEAL-PAYLOAD using DEK and AAD.
   Bounds-checked (the operating contract §4 — mandatory even at (safety 0)):
     returns NIL if (length SEALED) < 29 or version byte /= #x01.
   Splits nonce(12) / ciphertext / tag(16), calls AES-256-GCM-OPEN.
   Returns plaintext on auth success, NIL on any failure (fail-closed). NEVER returns
   plaintext if the authentication tag does not verify."
  (let ((sealed-len (length sealed)))
    ;; bounds check first — mandatory, no error signaled
    (when (< sealed-len +envelope-min-sealed-len+)
      (return-from open-payload nil))
    (unless (= (aref sealed 0) +envelope-version+)
      (return-from open-payload nil))
    (let* ((ct-len  (- sealed-len +envelope-header-len+ +aes-gcm-tag-len+))
           (nonce   (make-array +aes-gcm-nonce-len+ :element-type '(unsigned-byte 8)))
           (ct      (make-array ct-len :element-type '(unsigned-byte 8)))
           (tag     (make-array +aes-gcm-tag-len+ :element-type '(unsigned-byte 8))))
      (dotimes (i +aes-gcm-nonce-len+)
        (setf (aref nonce i) (aref sealed (+ 1 i))))
      (dotimes (i ct-len)
        (setf (aref ct i) (aref sealed (+ +envelope-header-len+ i))))
      (dotimes (i +aes-gcm-tag-len+)
        (setf (aref tag i) (aref sealed (+ +envelope-header-len+ ct-len i))))
      ;; aes-256-gcm-open returns plaintext or NIL (fail-closed)
      (aes-256-gcm-open dek nonce aad ct tag))))

(defun* %epoch-id->4-bytes-le (epoch-id)
    (function ((unsigned-byte 32)) (simple-array (unsigned-byte 8) (*)))
  "Encode EPOCH-ID as 4 bytes little-endian (32-bit unsigned)."
  (let ((v (make-array +envelope-epoch-len+ :element-type '(unsigned-byte 8))))
    (dotimes (i +envelope-epoch-len+ v)
      (setf (aref v i) (ldb (byte 8 (* 8 i)) epoch-id)))))

(defun* %append-epoch-aad-bytes (aad epoch-bytes)
    (function ((simple-array (unsigned-byte 8) (*)) (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Return AAD ∥ EPOCH-BYTES (4 LE) — inner form that reuses already-computed epoch bytes."
  (let* ((aad-len (length aad))
         (out     (make-array (+ aad-len +envelope-epoch-len+) :element-type '(unsigned-byte 8))))
    (dotimes (i aad-len)
      (setf (aref out i) (aref aad i)))
    (dotimes (i +envelope-epoch-len+)
      (setf (aref out (+ aad-len i)) (aref epoch-bytes i)))
    out))

(defun* %append-epoch-aad (aad epoch-id)
    (function ((simple-array (unsigned-byte 8) (*)) (unsigned-byte 32))
              (simple-array (unsigned-byte 8) (*)))
  "Return AAD ∥ epoch-id(4 LE) — the full GCM additional data for v2 (binds epoch into AEAD)."
  (%append-epoch-aad-bytes aad (%epoch-id->4-bytes-le epoch-id)))

(defun* seal-payload-v2 (dek epoch-id nonce aad plaintext)
    (function ((simple-array (unsigned-byte 8) (*))
               (unsigned-byte 32)
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Seal PLAINTEXT under DEK/NONCE with epoch EPOCH-ID bound into the AEAD via AAD ∥ epoch-id(4 LE).
   Wire format: version(1)=#x02 ∥ epoch-id(4 LE) ∥ nonce(12) ∥ ciphertext ∥ tag(16). ADR 0025 §5."
  (let* ((eb      (%epoch-id->4-bytes-le epoch-id))  ; computed once; reused for header + AAD
         (gcm-aad (%append-epoch-aad-bytes aad eb)))
    (multiple-value-bind (ct tag)
        (aes-256-gcm-seal dek nonce gcm-aad plaintext)
      (let* ((pt-len  (length plaintext))
             (out-len (+ 1 +envelope-epoch-len+ +aes-gcm-nonce-len+ pt-len +aes-gcm-tag-len+))
             (out     (make-array out-len :element-type '(unsigned-byte 8))))
        (setf (aref out 0) +envelope-version-v2+)
        (dotimes (i +envelope-epoch-len+)
          (setf (aref out (+ 1 i)) (aref eb i)))
        (dotimes (i +aes-gcm-nonce-len+)
          (setf (aref out (+ 1 +envelope-epoch-len+ i)) (aref nonce i)))
        (dotimes (i pt-len)
          (setf (aref out (+ +envelope-v2-header-len+ i)) (aref ct i)))
        (dotimes (i +aes-gcm-tag-len+)
          (setf (aref out (+ +envelope-v2-header-len+ pt-len i)) (aref tag i)))
        out))))

(defun* open-payload-v2 (dek-lookup sealed aad)
    (function ((function ((unsigned-byte 32))
                         (or null (simple-array (unsigned-byte 8) (*))))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Unseal a v2 DARE blob produced by SEAL-PAYLOAD-V2. DEK-LOOKUP is called with the epoch-id
   and must return the DEK (32-byte octet vector) or NIL (unknown epoch -> fail-closed).
   Bounds-checked (the operating contract §4 — mandatory even at (safety 0)):
     returns NIL if (length SEALED) < 33 or version byte /= #x02.
   Reads epoch-id(4 LE), calls DEK-LOOKUP; NIL DEK -> NIL. Slices nonce/ct/tag,
   rebuilds AAD ∥ epoch-id, calls AES-256-GCM-OPEN. Returns plaintext or NIL (fail-closed)."
  (let ((sealed-len (length sealed)))
    ;; bounds check: minimum = 1 + 4 + 12 + 16 = 33
    (when (< sealed-len (+ +envelope-v2-header-len+ +aes-gcm-tag-len+))
      (return-from open-payload-v2 nil))
    (unless (= (aref sealed 0) +envelope-version-v2+)
      (return-from open-payload-v2 nil))
    (let* ((epoch-id (logior (aref sealed 1)
                             (ash (aref sealed 2) 8)
                             (ash (aref sealed 3) 16)
                             (ash (aref sealed 4) 24)))
           (dek      (funcall dek-lookup epoch-id)))
      (unless dek
        (return-from open-payload-v2 nil))
      (let* ((ct-len  (- sealed-len +envelope-v2-header-len+ +aes-gcm-tag-len+))
             (nonce   (make-array +aes-gcm-nonce-len+ :element-type '(unsigned-byte 8)))
             (ct      (make-array ct-len :element-type '(unsigned-byte 8)))
             (tag     (make-array +aes-gcm-tag-len+ :element-type '(unsigned-byte 8)))
             (gcm-aad (%append-epoch-aad aad epoch-id)))
        (dotimes (i +aes-gcm-nonce-len+)
          (setf (aref nonce i) (aref sealed (+ 1 +envelope-epoch-len+ i))))
        (dotimes (i ct-len)
          (setf (aref ct i) (aref sealed (+ +envelope-v2-header-len+ i))))
        (dotimes (i +aes-gcm-tag-len+)
          (setf (aref tag i) (aref sealed (+ +envelope-v2-header-len+ ct-len i))))
        (aes-256-gcm-open dek nonce gcm-aad ct tag)))))

(defun* %sn->8-bytes-le (sn)
    (function ((integer 0)) (simple-array (unsigned-byte 8) (*)))
  "Encode non-negative integer SN as 8 bytes little-endian (unsigned 64-bit)."
  (let ((v (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8 v)
      (setf (aref v i) (ldb (byte 8 (* 8 i)) sn)))))

(defun* %kind-byte (kind)
    (function (symbol) (unsigned-byte 8))
  "Map DARE record KIND keyword to a single byte: :data=0, :dispose=1, :unregister=2."
  (ecase kind
    (:data       0)
    (:dispose    1)
    (:unregister 2)))

(defun* make-record-aad (topic writer-guid sn kind)
    (function (string
               (simple-array (unsigned-byte 8) (*))
               (integer 0)
               symbol)
              (simple-array (unsigned-byte 8) (*)))
  "Build the AEAD Additional Authenticated Data for a DDS record.
   Returns UTF-8(TOPIC) ∥ WRITER-GUID(16) ∥ SN-as-8-bytes-LE ∥ KIND-byte.
   TOPIC is ASCII/UTF-8 string; WRITER-GUID is 16 octets (RTPS GUID §8.2.4.1).
   SN is a non-negative integer (DDS SequenceNumber §2.2.3.4).
   KIND ∈ {:data :dispose :unregister} → byte 0/1/2, bound into AAD to prevent relabeling.
   A change to any field causes AES-256-GCM authentication to fail in OPEN-PAYLOAD."
  (let* ((topic-bytes (%ascii topic))
         (topic-len   (length topic-bytes))
         (sn-bytes    (%sn->8-bytes-le sn))
         (out-len     (+ topic-len 16 8 1))
         (out         (make-array out-len :element-type '(unsigned-byte 8))))
    (dotimes (i topic-len)
      (setf (aref out i) (aref topic-bytes i)))
    (dotimes (i 16)
      (setf (aref out (+ topic-len i)) (aref writer-guid i)))
    (dotimes (i 8)
      (setf (aref out (+ topic-len 16 i)) (aref sn-bytes i)))
    (setf (aref out (+ topic-len 16 8)) (%kind-byte kind))
    out))
