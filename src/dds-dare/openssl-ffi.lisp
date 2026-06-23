(in-package #:dds.dare)

;;; OpenSSL libcrypto CFFI bindings for DDS.DARE (Task 1: SHA-384, HKDF-SHA384).
;;;
;;; Host: OpenSSL 3.6.2 7 Apr 2026, dylib = /opt/homebrew/opt/openssl@3/lib/libcrypto.dylib
;;; OPENSSLDIR: /opt/homebrew/etc/openssl@3
;;;
;;; Pinned signatures (verified against installed headers, /opt/homebrew/opt/openssl@3/include/openssl/):
;;;
;;;   EVP_Q_digest(OSSL_LIB_CTX *libctx, const char *name, const char *propq,
;;;                const void *data, size_t datalen,
;;;                unsigned char *md, size_t *mdlen)  -> int (1=ok, <=0 error)
;;;     Source: evp.h line 744 (OpenSSL 3.6.2)
;;;
;;;   EVP_Q_mac(OSSL_LIB_CTX *libctx, const char *name, const char *propq,
;;;             const char *subalg, const OSSL_PARAM *params,
;;;             const void *key, size_t keylen,
;;;             const unsigned char *data, size_t datalen,
;;;             unsigned char *out, size_t outsize, size_t *outlen) -> uchar* (NULL=error)
;;;     One-shot MAC (analogue of EVP_Q_digest); HMAC-SHA256 = name "HMAC", subalg "SHA256".
;;;     Source: evp.h line 1271 (OpenSSL 3.6.2)
;;;
;;;   EVP_KDF_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
;;;                 const char *properties) -> EVP_KDF* (NULL on error)
;;;   EVP_KDF_free(EVP_KDF *kdf)  -> void
;;;   EVP_KDF_CTX_new(EVP_KDF *kdf) -> EVP_KDF_CTX* (NULL on error)
;;;   EVP_KDF_CTX_free(EVP_KDF_CTX *ctx) -> void
;;;   EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen,
;;;                  const OSSL_PARAM params[]) -> int (1=ok, <=0 error)
;;;     Source: kdf.h lines 29-45 (OpenSSL 3.6.2)
;;;
;;;   OpenSSL_version_num(void) -> unsigned long
;;;     Encoding: (major<<28)|(minor<<20)|(patch<<4)|status; release=0xf.
;;;     3.6.2 release -> 0x3060002f (confirmed via `python3 -c "print(hex((3<<28)|(6<<20)|(2<<4)|0xf))"`)
;;;     Source: crypto.h line 181 (OpenSSL 3.6.2)
;;;
;;;   EVP_KEM_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
;;;                 const char *properties) -> EVP_KEM* (NULL on error)
;;;   EVP_KEM_free(EVP_KEM *wrap) -> void
;;;     Source: evp.h lines 1994-1997 (OpenSSL 3.6.2)
;;;
;;; OSSL_PARAM struct layout (verified via C offsetof on arm64-macOS, sizeof=40):
;;;   +0  key          : const char*  (8 bytes)
;;;   +8  data_type    : unsigned int (4 bytes) + 4 bytes padding
;;;   +16 data         : void*        (8 bytes)
;;;   +24 data_size    : size_t       (8 bytes)
;;;   +32 return_size  : size_t       (8 bytes)
;;; OSSL_PARAM data type constants (core.h §95–160):
;;;   OSSL_PARAM_UTF8_STRING = 4, OSSL_PARAM_OCTET_STRING = 5
;;; OSSL_PARAM_END sentinel: key=NULL, all zeros.

;;; --- impl-agnostic libcrypto path resolution ---
;;; On macOS, Clasp loads /usr/lib/libcrypto.46.dylib (LibreSSL 2.0.0 = 0x20000000) at
;;; startup via its own dependencies. CFFI name-based foreign-funcall then resolves to
;;; that already-resident symbol rather than the homebrew OpenSSL 3.x we need.
;;; Fix: resolve and load the real OpenSSL dylib path at load time, store its handle,
;;; and dispatch ALL OpenSSL calls through cffi:foreign-symbol-pointer on that handle.
;;; Candidate paths in preference order (DDS_DARE_LIBCRYPTO env override first):
;;;   1. $DDS_DARE_LIBCRYPTO            — explicit host override
;;;   2. /opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib  (homebrew arm64 realpath)
;;;   3. /usr/local/opt/openssl@3/lib/libcrypto.3.dylib     (homebrew x86_64 realpath)
;;;   4. /opt/homebrew/lib/libcrypto.3.dylib                (homebrew generic)
;;;   5. libcrypto.so.3 / libcrypto.so   — Linux loader fallback (no probe-file needed)

(defvar *libcrypto* nil
  "The explicitly-loaded OpenSSL >= 3.5 libcrypto handle (CFFI foreign-library object or NIL).
   Resolved at load time from DDS_DARE_LIBCRYPTO env or known homebrew/system paths.
   All DARE foreign calls dispatch through this handle via %ossl-sym.")

(defun* %resolve-libcrypto-path ()
    (function () (or string null))
  "Return the best available libcrypto path: env override, then homebrew realpaths.
   Returns NIL for Linux names that need the loader (caller passes them as strings directly)."
  (let ((env (uiop:getenv "DDS_DARE_LIBCRYPTO")))
    (when (and env (probe-file env))
      (return-from %resolve-libcrypto-path env)))
  (dolist (candidate '("/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib"
                       "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib"
                       "/opt/homebrew/lib/libcrypto.3.dylib"))
    (when (probe-file candidate)
      (return-from %resolve-libcrypto-path candidate)))
  nil)

(defun* %load-libcrypto ()
    (function () t)
  "Load the real OpenSSL >= 3.5 libcrypto, returning the CFFI foreign-library object or NIL.
   Uses %resolve-libcrypto-path for absolute-path candidates (macOS homebrew),
   then falls back to the string names libcrypto.so.3 / libcrypto.so for Linux."
  (let ((path (%resolve-libcrypto-path)))
    (when path
      (return-from %load-libcrypto
        (cffi:load-foreign-library path))))
  (dolist (name '("libcrypto.so.3" "libcrypto.so"))
    (handler-case
        (return-from %load-libcrypto (cffi:load-foreign-library name))
      (cffi:load-foreign-library-error () nil)))
  nil)

(eval-when (:load-toplevel :execute)
  (setf *libcrypto* (%load-libcrypto)))

(defmacro %ossl-sym (name)
  "Return the function pointer for OpenSSL symbol NAME from *LIBCRYPTO*."
  `(cffi:foreign-symbol-pointer ,name :library *libcrypto*))

;;; --- version gate ---

(define-condition dare-unavailable (error)
  ((reason :initarg :reason :reader dare-unavailable-reason))
  (:report (lambda (c s) (format s "DDS.DARE unavailable: ~a" (dare-unavailable-reason c))))
  (:documentation
   "Signalled by DARE-AVAILABLE-P when libcrypto is not loaded, OpenSSL is below 3.5,
    or ML-KEM-1024 is not fetchable from the default provider."))

(defun* dare-available-p ()
    (function () boolean)
  "Return T iff libcrypto is loaded, OpenSSL_version_num >= 3.5.0, and ML-KEM-1024 is
   fetchable from the default provider (FIPS 203, CNSA 2.0 requirement).
   Signals DARE-UNAVAILABLE if the library is absent or the version check fails.
   Note: ML-KEM availability check fully exercised here; Task 3 adds the full
   wrap/unwrap API on top of the gate this function establishes."
  (handler-case
      (progn
        (unless *libcrypto*
          (error 'dare-unavailable :reason "libcrypto not loaded (no suitable path found)"))
        (let* ((ver-ptr (%ossl-sym "OpenSSL_version_num"))
               (ver (if ver-ptr
                        (cffi:foreign-funcall-pointer ver-ptr nil :unsigned-long)
                        (error 'dare-unavailable :reason "OpenSSL_version_num symbol not found"))))
          ;; 3.5.0 dev threshold = 0x30500000; any release of 3.5+ is >= 0x3050000f
          (unless (>= ver #x30500000)
            (error 'dare-unavailable
                   :reason (format nil "OpenSSL version 0x~8,'0x < 3.5.0 (0x30500000)" ver)))
          (let* ((kem-fetch-ptr (%ossl-sym "EVP_KEM_fetch"))
                 (kem (if kem-fetch-ptr
                          (cffi:foreign-funcall-pointer kem-fetch-ptr nil
                                                        :pointer (cffi:null-pointer)
                                                        :string "ML-KEM-1024"
                                                        :pointer (cffi:null-pointer)
                                                        :pointer)
                          (error 'dare-unavailable :reason "EVP_KEM_fetch symbol not found"))))
            (if (cffi:null-pointer-p kem)
                (error 'dare-unavailable :reason "ML-KEM-1024 not fetchable from default provider")
                (progn
                  (cffi:foreign-funcall-pointer (%ossl-sym "EVP_KEM_free") nil
                                                :pointer kem :void)
                  t)))))
    (cffi:load-foreign-library-error (e)
      (error 'dare-unavailable :reason (format nil "libcrypto load failed: ~a" e)))))

;;; --- internal helpers ---

(defun* %ascii (s)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Convert ASCII string S to an octet vector (test helper; no Unicode support needed)."
  (let* ((n (length s))
         (v (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n v)
      (setf (aref v i) (char-code (char s i))))))

;;; OSSL_PARAM builder — constructs a flat foreign array of OSSL_PARAM structs.
;;; Each slot is 40 bytes (verified via C offsetof on this host).
;;; Layout per slot: key(8) data_type(4) pad(4) data(8) data_size(8) return_size(8).

(defconstant +ossl-param-size+ 40)
(defconstant +ossl-param-data-type-utf8-string+ 4)   ; core.h line 117
(defconstant +ossl-param-data-type-octet-string+ 5)  ; core.h line 123

(defun* %set-ossl-param-slot (base idx key-ptr data-type data-ptr data-size)
    (function (cffi:foreign-pointer fixnum cffi:foreign-pointer fixnum cffi:foreign-pointer fixnum) t)
  "Write one OSSL_PARAM slot at BASE + IDX*40 bytes (arm64-macOS verified layout)."
  (let ((p (cffi:inc-pointer base (* idx +ossl-param-size+))))
    (setf (cffi:mem-ref p :pointer 0)  key-ptr)
    (setf (cffi:mem-ref p :uint32 8)   data-type)
    (setf (cffi:mem-ref p :pointer 16) data-ptr)
    (setf (cffi:mem-ref p :size 24)    data-size)
    (setf (cffi:mem-ref p :size 32)    0))
  t)

(defun* %set-ossl-param-end (base idx)
    (function (cffi:foreign-pointer fixnum) t)
  "Write the OSSL_PARAM_END sentinel (all-zero 40-byte slot) at BASE + IDX*40."
  (let ((p (cffi:inc-pointer base (* idx +ossl-param-size+))))
    (dotimes (i +ossl-param-size+)
      (setf (cffi:mem-ref p :uint8 i) 0)))
  t)

;;; EVP_CIPHER bindings for AES-256-GCM (Task 2).
;;;
;;; Pinned signatures (verified against /opt/homebrew/opt/openssl@3/include/openssl/evp.h):
;;;
;;;   EVP_CIPHER_CTX_new(void) -> EVP_CIPHER_CTX*        (evp.h line 921)
;;;   EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c) -> void     (evp.h line 923)
;;;   EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type,
;;;                        int arg, void *ptr) -> int     (evp.h line 926)
;;;   EVP_aes_256_gcm(void) -> const EVP_CIPHER*         (evp.h line 1104)
;;;   EVP_EncryptInit_ex(EVP_CIPHER_CTX*, const EVP_CIPHER*,
;;;                       ENGINE*, const uchar* key,
;;;                       const uchar* iv) -> int (1=ok) (evp.h line 780)
;;;   EVP_EncryptUpdate(EVP_CIPHER_CTX*, uchar* out, int* outl,
;;;                      const uchar* in, int inl) -> int (evp.h line 788)
;;;   EVP_EncryptFinal_ex(EVP_CIPHER_CTX*, uchar* out,
;;;                        int* outl) -> int              (evp.h line 790)
;;;   EVP_DecryptInit_ex(EVP_CIPHER_CTX*, const EVP_CIPHER*,
;;;                       ENGINE*, const uchar* key,
;;;                       const uchar* iv) -> int (1=ok) (evp.h line 797)
;;;   EVP_DecryptUpdate(EVP_CIPHER_CTX*, uchar* out, int* outl,
;;;                      const uchar* in, int inl) -> int (evp.h line 805)
;;;   EVP_DecryptFinal_ex(EVP_CIPHER_CTX*, uchar* out,
;;;                        int* outl) -> int (<=0=auth fail) (evp.h line 809)
;;;
;;; GCM ctrl constants (evp.h lines 388–394, via AEAD aliases):
;;;   EVP_CTRL_GCM_SET_IVLEN = EVP_CTRL_AEAD_SET_IVLEN = 0x9
;;;   EVP_CTRL_GCM_GET_TAG   = EVP_CTRL_AEAD_GET_TAG   = 0x10
;;;   EVP_CTRL_GCM_SET_TAG   = EVP_CTRL_AEAD_SET_TAG   = 0x11

(defconstant +gcm-ctrl-set-ivlen+ #x09  "EVP_CTRL_GCM_SET_IVLEN (evp.h, via AEAD_SET_IVLEN=0x9).")
(defconstant +gcm-ctrl-get-tag+   #x10  "EVP_CTRL_GCM_GET_TAG (evp.h, via AEAD_GET_TAG=0x10).")
(defconstant +gcm-ctrl-set-tag+   #x11  "EVP_CTRL_GCM_SET_TAG (evp.h, via AEAD_SET_TAG=0x11).")
(defconstant +aes-256-gcm-key-len+  32  "AES-256 key length in octets (FIPS 197 §5).")
(defconstant +aes-gcm-nonce-len+    12  "GCM standard 96-bit (12-byte) nonce (SP 800-38D §5.2.1.1).")
(defconstant +aes-gcm-tag-len+      16  "GCM authentication tag length in octets (128-bit, SP 800-38D §5.2.1.2).")

;;; EVP_PKEY KEM bindings for ML-KEM-1024 (Task 3).
;;;
;;; Pinned signatures (verified against /opt/homebrew/opt/openssl@3/include/openssl/evp.h,
;;; OpenSSL 3.6.2 7 Apr 2026; man pages EVP_PKEY_encapsulate(3), EVP_PKEY_decapsulate(3),
;;; EVP_PKEY-ML-KEM(7), EVP_KEM-ML-KEM-1024(7)):
;;;
;;;   EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx, const char *name,
;;;                               const char *propquery) -> EVP_PKEY_CTX*  (evp.h line 1887)
;;;   EVP_PKEY_CTX_new_from_pkey(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
;;;                               const char *propquery) -> EVP_PKEY_CTX*  (evp.h line 1890)
;;;   EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx) -> void                         (evp.h line 1893)
;;;   EVP_PKEY_free(EVP_PKEY *pkey) -> void                                 (evp.h line 1440)
;;;   EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx) -> int (1=ok)                (evp.h line 2119)
;;;   EVP_PKEY_generate(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey) -> int (1=ok) (evp.h line 2121)
;;;   EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey,
;;;                                unsigned char *pub, size_t *len) -> int  (evp.h line 1937)
;;;     For ML-KEM-1024: len = 1568 (ek, FIPS-203 Table 2, confirmed via C oracle)
;;;   EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey,
;;;                                 unsigned char *priv, size_t *len) -> int (evp.h line 1935)
;;;     For ML-KEM-1024: len = 3168 (dk, FIPS-203 Table 2, confirmed via C oracle)
;;;   EVP_PKEY_new_raw_public_key_ex(OSSL_LIB_CTX *libctx, const char *keytype,
;;;                                   const char *propq,
;;;                                   const unsigned char *key, size_t keylen)
;;;                                   -> EVP_PKEY*                         (evp.h line 1929)
;;;   EVP_PKEY_new_raw_private_key_ex(OSSL_LIB_CTX *libctx, const char *keytype,
;;;                                    const char *propq,
;;;                                    const unsigned char *key, size_t keylen)
;;;                                    -> EVP_PKEY*                        (evp.h line 1922)
;;;   EVP_PKEY_encapsulate_init(EVP_PKEY_CTX *ctx,
;;;                              const OSSL_PARAM params[]) -> int (1=ok)  (evp.h line 2064)
;;;   EVP_PKEY_encapsulate(EVP_PKEY_CTX *ctx,
;;;                         unsigned char *wrappedkey, size_t *wrappedkeylen,
;;;                         unsigned char *genkey, size_t *genkeylen) -> int (evp.h line 2067)
;;;     wrappedkey = ML-KEM ciphertext c (1568 bytes); genkey = shared secret K (32 bytes).
;;;     NULL/NULL first call queries sizes; non-NULL second call fills buffers.
;;;   EVP_PKEY_decapsulate_init(EVP_PKEY_CTX *ctx,
;;;                              const OSSL_PARAM params[]) -> int (1=ok)  (evp.h line 2070)
;;;   EVP_PKEY_decapsulate(EVP_PKEY_CTX *ctx,
;;;                         unsigned char *unwrapped, size_t *unwrappedlen,
;;;                         const unsigned char *wrapped, size_t wrappedlen) -> int (evp.h line 2073)
;;;     unwrapped = shared secret K; wrapped = ML-KEM ciphertext c.
;;;
;;; ML-KEM-1024 sizes (FIPS-203 Aug 2024, Table 2; confirmed via C oracle on OpenSSL 3.6.2):
;;;   Public key ek: 1568 bytes   Private key dk: 3168 bytes
;;;   Ciphertext c:  1568 bytes   Shared secret K: 32 bytes

(defconstant +ml-kem-1024-pub-len+   1568 "ML-KEM-1024 public key (ek) size in octets (FIPS-203 Table 2).")
(defconstant +ml-kem-1024-priv-len+  3168 "ML-KEM-1024 private key (dk) size in octets (FIPS-203 Table 2).")
(defconstant +ml-kem-1024-ct-len+    1568 "ML-KEM-1024 ciphertext (c) size in octets (FIPS-203 Table 2).")
(defconstant +ml-kem-1024-ss-len+      32 "ML-KEM-1024 shared secret (K) size in octets (FIPS-203 Table 2).")
