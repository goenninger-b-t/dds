(in-package #:dds.dare)

;;; Task 4: KEM-DEM envelope — HKDF-SHA384 DEK derivation + AES-256-GCM seal/open.
;;; Wire format: version(1)=#x01 ∥ nonce(12) ∥ ciphertext ∥ tag(16).
;;; AAD binds topic + writer-guid + sequence-number + kind so relabeling is detected.
;;; Fail-closed: open-payload returns NIL (never plaintext) on any auth/parse failure.
;;; Bounds check in open-payload is mandatory even at (safety 0) — the operating contract §4.

(defconstant +envelope-version+ #x01
  "DARE envelope version byte (CNSA-2.0, v1). Fixed prefix of every sealed blob.")

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
