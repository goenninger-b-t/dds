(in-package #:dds.dare)

;;; SHA-384 and HKDF-SHA384 primitives — OpenSSL EVP high-level API via CFFI.
;;; Foreign buffers zeroized before free (establishes the DARE secret-material pattern).

(defconstant +sha384-digest-len+ 48 "SHA-384 output length in octets (FIPS 180-4 §6.5).")

;;; OSSL_KDF_PARAM_* string constants (core_names.h, OpenSSL 3.6.2):
;;;   OSSL_KDF_PARAM_DIGEST = "digest"  (core_names.h line 281 -> OSSL_ALG_PARAM_DIGEST line 128)
;;;   OSSL_KDF_PARAM_KEY    = "key"     (core_names.h line 294)
;;;   OSSL_KDF_PARAM_SALT   = "salt"    (core_names.h line 304)
;;;   OSSL_KDF_PARAM_INFO   = "info"    (core_names.h line 289)

(defun* sha-384 (octets)
    (function ((simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (48)))
  "Return the SHA-384 digest of OCTETS as a fresh 48-byte vector.
   Uses EVP_Q_digest(NULL,'SHA-384',NULL,...) (OpenSSL evp.h, verified against 3.6.2 headers).
   Digest output buffer is zeroized before deallocation."
  (let* ((n (length octets))
         (out (make-array +sha384-digest-len+ :element-type '(unsigned-byte 8))))
    (cffi:with-foreign-pointer (in-ptr (max 1 n))
      (dotimes (i n)
        (setf (cffi:mem-aref in-ptr :uint8 i) (aref octets i)))
      (cffi:with-foreign-pointer (md-ptr +sha384-digest-len+)
        (cffi:with-foreign-pointer (mdlen-ptr (cffi:foreign-type-size :size))
          (setf (cffi:mem-ref mdlen-ptr :size) +sha384-digest-len+)
          (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_Q_digest") nil
                                          :pointer (cffi:null-pointer)
                                          :string "SHA-384"
                                          :pointer (cffi:null-pointer)
                                          :pointer in-ptr
                                          :size n
                                          :pointer md-ptr
                                          :pointer mdlen-ptr
                                          :int)))
            (unless (= rc 1)
              (dotimes (i +sha384-digest-len+)
                (setf (cffi:mem-aref md-ptr :uint8 i) 0))
              (error "EVP_Q_digest(SHA-384) failed (rc=~a)" rc))
            (dotimes (i +sha384-digest-len+)
              (setf (aref out i) (cffi:mem-aref md-ptr :uint8 i)))
            (dotimes (i +sha384-digest-len+)
              (setf (cffi:mem-aref md-ptr :uint8 i) 0))))))
    out))

;;; HKDF-SHA384 internal workhorse — holds all foreign state live while EVP_KDF_derive runs.

(defun* %hkdf-sha384-derive (ikm-ptr ikm-n salt-ptr salt-n info-ptr info-n out-ptr out-len)
    (function (cffi:foreign-pointer fixnum
               cffi:foreign-pointer fixnum
               cffi:foreign-pointer fixnum
               cffi:foreign-pointer fixnum)
              t)
  "Drive EVP_KDF_fetch+CTX+derive for HKDF-SHA384 given pre-filled foreign input buffers.
   OUT-PTR must be OUT-LEN bytes of foreign memory; filled on return. Errors signal."
  (cffi:with-foreign-pointer (params (* 5 +ossl-param-size+))
    (cffi:with-foreign-string (p-digest "digest")
      (cffi:with-foreign-string (v-sha384 "SHA-384")
        (cffi:with-foreign-string (p-key "key")
          (cffi:with-foreign-string (p-salt "salt")
            (cffi:with-foreign-string (p-info "info")
              (%set-ossl-param-slot params 0 p-digest
                                    +ossl-param-data-type-utf8-string+
                                    v-sha384 8)
              (%set-ossl-param-slot params 1 p-key
                                    +ossl-param-data-type-octet-string+
                                    ikm-ptr ikm-n)
              (%set-ossl-param-slot params 2 p-salt
                                    +ossl-param-data-type-octet-string+
                                    salt-ptr salt-n)
              (%set-ossl-param-slot params 3 p-info
                                    +ossl-param-data-type-octet-string+
                                    info-ptr info-n)
              (%set-ossl-param-end params 4)
              (let ((kdf (cffi:foreign-funcall-pointer (%ossl-sym "EVP_KDF_fetch") nil
                                               :pointer (cffi:null-pointer)
                                               :string "HKDF"
                                               :pointer (cffi:null-pointer)
                                               :pointer)))
                (when (cffi:null-pointer-p kdf)
                  (error "EVP_KDF_fetch(HKDF) returned NULL"))
                (let ((ctx (cffi:foreign-funcall-pointer (%ossl-sym "EVP_KDF_CTX_new") nil
                                               :pointer kdf :pointer)))
                  (cffi:foreign-funcall-pointer (%ossl-sym "EVP_KDF_free") nil
                                               :pointer kdf :void)
                  (when (cffi:null-pointer-p ctx)
                    (error "EVP_KDF_CTX_new failed"))
                  (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_KDF_derive") nil
                                                  :pointer ctx
                                                  :pointer out-ptr
                                                  :size out-len
                                                  :pointer params
                                                  :int)))
                    (cffi:foreign-funcall-pointer (%ossl-sym "EVP_KDF_CTX_free") nil
                                               :pointer ctx :void)
                    (unless (= rc 1)
                      (dotimes (i out-len)
                        (setf (cffi:mem-aref out-ptr :uint8 i) 0))
                      (error "EVP_KDF_derive(HKDF-SHA384) failed (rc=~a)" rc))))
                t))))))))

;;; AES-256-GCM AEAD seal/open (Task 2) — EVP_CIPHER via handle-based CFFI.
;;; Verified against NIST SP 800-38D (Nov 2007) Appendix B, Test Case 16 (256-bit key).

(defun* aes-256-gcm-seal (key nonce aad plaintext)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (values (simple-array (unsigned-byte 8) (*))
                      (simple-array (unsigned-byte 8) (*))))
  "AES-256-GCM authenticated encryption (FIPS 197 + NIST SP 800-38D).
   KEY 32 octets, NONCE 12 octets, AAD and PLAINTEXT arbitrary octet vectors.
   Returns (values CIPHERTEXT TAG): CIPHERTEXT = (length PLAINTEXT) octets, TAG 16 octets.
   Key buffer is zeroized before return. Signals on any EVP error."
  (let* ((pt-len (length plaintext))
         (aad-len (length aad))
         (ciphertext (make-array pt-len :element-type '(unsigned-byte 8)))
         (tag        (make-array +aes-gcm-tag-len+ :element-type '(unsigned-byte 8))))
    (cffi:with-foreign-pointer (key-ptr +aes-256-gcm-key-len+)
      (cffi:with-foreign-pointer (nonce-ptr +aes-gcm-nonce-len+)
        (cffi:with-foreign-pointer (aad-ptr (max 1 aad-len))
          (cffi:with-foreign-pointer (pt-ptr (max 1 pt-len))
            (cffi:with-foreign-pointer (ct-ptr (max 1 pt-len))
              (cffi:with-foreign-pointer (tag-ptr +aes-gcm-tag-len+)
                (cffi:with-foreign-pointer (outl-ptr (cffi:foreign-type-size :int))
                  (dotimes (i +aes-256-gcm-key-len+)
                    (setf (cffi:mem-aref key-ptr :uint8 i) (aref key i)))
                  (dotimes (i +aes-gcm-nonce-len+)
                    (setf (cffi:mem-aref nonce-ptr :uint8 i) (aref nonce i)))
                  (dotimes (i aad-len)
                    (setf (cffi:mem-aref aad-ptr :uint8 i) (aref aad i)))
                  (dotimes (i pt-len)
                    (setf (cffi:mem-aref pt-ptr :uint8 i) (aref plaintext i)))
                  (let ((ctx (cffi:foreign-funcall-pointer
                              (%ossl-sym "EVP_CIPHER_CTX_new") nil :pointer)))
                    (when (cffi:null-pointer-p ctx)
                      (dotimes (i +aes-256-gcm-key-len+)
                        (setf (cffi:mem-aref key-ptr :uint8 i) 0))
                      (error "EVP_CIPHER_CTX_new returned NULL"))
                    (unwind-protect
                         (progn
                           ;; init cipher, no key/iv yet
                           (let ((rc (cffi:foreign-funcall-pointer
                                      (%ossl-sym "EVP_EncryptInit_ex") nil
                                      :pointer ctx
                                      :pointer (cffi:foreign-funcall-pointer
                                                (%ossl-sym "EVP_aes_256_gcm") nil :pointer)
                                      :pointer (cffi:null-pointer)
                                      :pointer (cffi:null-pointer)
                                      :pointer (cffi:null-pointer)
                                      :int)))
                             (unless (= rc 1)
                               (error "EVP_EncryptInit_ex(EVP_aes_256_gcm) failed (rc=~a)" rc)))
                           ;; set 12-byte nonce length
                           (let ((rc (cffi:foreign-funcall-pointer
                                      (%ossl-sym "EVP_CIPHER_CTX_ctrl") nil
                                      :pointer ctx :int +gcm-ctrl-set-ivlen+
                                      :int +aes-gcm-nonce-len+
                                      :pointer (cffi:null-pointer) :int)))
                             (unless (= rc 1)
                               (error "EVP_CIPHER_CTX_ctrl(SET_IVLEN) failed (rc=~a)" rc)))
                           ;; init key and nonce
                           (let ((rc (cffi:foreign-funcall-pointer
                                      (%ossl-sym "EVP_EncryptInit_ex") nil
                                      :pointer ctx
                                      :pointer (cffi:null-pointer)
                                      :pointer (cffi:null-pointer)
                                      :pointer key-ptr
                                      :pointer nonce-ptr
                                      :int)))
                             (unless (= rc 1)
                               (error "EVP_EncryptInit_ex(key,nonce) failed (rc=~a)" rc)))
                           ;; feed AAD (outl is discarded for AAD)
                           (when (> aad-len 0)
                             (let ((rc (cffi:foreign-funcall-pointer
                                        (%ossl-sym "EVP_EncryptUpdate") nil
                                        :pointer ctx
                                        :pointer (cffi:null-pointer) :pointer outl-ptr
                                        :pointer aad-ptr :int aad-len
                                        :int)))
                               (unless (= rc 1)
                                 (error "EVP_EncryptUpdate(AAD) failed (rc=~a)" rc))))
                           ;; encrypt plaintext
                           (when (> pt-len 0)
                             (let ((rc (cffi:foreign-funcall-pointer
                                        (%ossl-sym "EVP_EncryptUpdate") nil
                                        :pointer ctx
                                        :pointer ct-ptr :pointer outl-ptr
                                        :pointer pt-ptr :int pt-len
                                        :int)))
                               (unless (= rc 1)
                                 (error "EVP_EncryptUpdate(PT) failed (rc=~a)" rc))))
                           ;; finalize (GCM final produces no additional output)
                           (let ((rc (cffi:foreign-funcall-pointer
                                      (%ossl-sym "EVP_EncryptFinal_ex") nil
                                      :pointer ctx :pointer ct-ptr :pointer outl-ptr
                                      :int)))
                             (unless (= rc 1)
                               (error "EVP_EncryptFinal_ex failed (rc=~a)" rc)))
                           ;; extract 16-byte tag
                           (let ((rc (cffi:foreign-funcall-pointer
                                      (%ossl-sym "EVP_CIPHER_CTX_ctrl") nil
                                      :pointer ctx :int +gcm-ctrl-get-tag+
                                      :int +aes-gcm-tag-len+
                                      :pointer tag-ptr :int)))
                             (unless (= rc 1)
                               (error "EVP_CIPHER_CTX_ctrl(GET_TAG) failed (rc=~a)" rc)))
                           ;; copy results out before zeroizing key
                           (dotimes (i pt-len)
                             (setf (aref ciphertext i) (cffi:mem-aref ct-ptr :uint8 i)))
                           (dotimes (i +aes-gcm-tag-len+)
                             (setf (aref tag i) (cffi:mem-aref tag-ptr :uint8 i))))
                      ;; always: zeroize key buffer, free ctx
                      (dotimes (i +aes-256-gcm-key-len+)
                        (setf (cffi:mem-aref key-ptr :uint8 i) 0))
                      (cffi:foreign-funcall-pointer
                       (%ossl-sym "EVP_CIPHER_CTX_free") nil :pointer ctx :void))))))))
    (values ciphertext tag)))))

(defun* aes-256-gcm-open (key nonce aad ciphertext tag)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (or (simple-array (unsigned-byte 8) (*)) null))
  "AES-256-GCM authenticated decryption (FIPS 197 + NIST SP 800-38D).
   KEY 32 octets, NONCE 12 octets, AAD/CIPHERTEXT/TAG octet vectors.
   Returns the plaintext octet vector on success, or NIL if authentication fails (fail-closed).
   Key buffer zeroized before return. NEVER returns plaintext on auth failure."
  (let* ((ct-len  (length ciphertext))
         (aad-len (length aad))
         (plaintext (make-array ct-len :element-type '(unsigned-byte 8))))
    (cffi:with-foreign-pointer (key-ptr +aes-256-gcm-key-len+)
      (cffi:with-foreign-pointer (nonce-ptr +aes-gcm-nonce-len+)
        (cffi:with-foreign-pointer (aad-ptr (max 1 aad-len))
          (cffi:with-foreign-pointer (ct-ptr (max 1 ct-len))
            (cffi:with-foreign-pointer (pt-ptr (max 1 ct-len))
              (cffi:with-foreign-pointer (tag-ptr +aes-gcm-tag-len+)
                (cffi:with-foreign-pointer (outl-ptr (cffi:foreign-type-size :int))
                  (dotimes (i +aes-256-gcm-key-len+)
                    (setf (cffi:mem-aref key-ptr :uint8 i) (aref key i)))
                  (dotimes (i +aes-gcm-nonce-len+)
                    (setf (cffi:mem-aref nonce-ptr :uint8 i) (aref nonce i)))
                  (dotimes (i aad-len)
                    (setf (cffi:mem-aref aad-ptr :uint8 i) (aref aad i)))
                  (dotimes (i ct-len)
                    (setf (cffi:mem-aref ct-ptr :uint8 i) (aref ciphertext i)))
                  (dotimes (i +aes-gcm-tag-len+)
                    (setf (cffi:mem-aref tag-ptr :uint8 i) (aref tag i)))
                  (let ((ctx (cffi:foreign-funcall-pointer
                              (%ossl-sym "EVP_CIPHER_CTX_new") nil :pointer))
                        (auth-ok nil))
                    (when (cffi:null-pointer-p ctx)
                      (dotimes (i +aes-256-gcm-key-len+)
                        (setf (cffi:mem-aref key-ptr :uint8 i) 0))
                      (error "EVP_CIPHER_CTX_new returned NULL"))
                    (unwind-protect
                         (progn
                           (let ((rc (cffi:foreign-funcall-pointer
                                      (%ossl-sym "EVP_DecryptInit_ex") nil
                                      :pointer ctx
                                      :pointer (cffi:foreign-funcall-pointer
                                                (%ossl-sym "EVP_aes_256_gcm") nil :pointer)
                                      :pointer (cffi:null-pointer)
                                      :pointer (cffi:null-pointer)
                                      :pointer (cffi:null-pointer)
                                      :int)))
                             (unless (= rc 1)
                               (error "EVP_DecryptInit_ex(EVP_aes_256_gcm) failed (rc=~a)" rc)))
                           (let ((rc (cffi:foreign-funcall-pointer
                                      (%ossl-sym "EVP_CIPHER_CTX_ctrl") nil
                                      :pointer ctx :int +gcm-ctrl-set-ivlen+
                                      :int +aes-gcm-nonce-len+
                                      :pointer (cffi:null-pointer) :int)))
                             (unless (= rc 1)
                               (error "EVP_CIPHER_CTX_ctrl(SET_IVLEN) failed (rc=~a)" rc)))
                           (let ((rc (cffi:foreign-funcall-pointer
                                      (%ossl-sym "EVP_DecryptInit_ex") nil
                                      :pointer ctx
                                      :pointer (cffi:null-pointer)
                                      :pointer (cffi:null-pointer)
                                      :pointer key-ptr
                                      :pointer nonce-ptr
                                      :int)))
                             (unless (= rc 1)
                               (error "EVP_DecryptInit_ex(key,nonce) failed (rc=~a)" rc)))
                           ;; set expected tag BEFORE Final
                           (let ((rc (cffi:foreign-funcall-pointer
                                      (%ossl-sym "EVP_CIPHER_CTX_ctrl") nil
                                      :pointer ctx :int +gcm-ctrl-set-tag+
                                      :int +aes-gcm-tag-len+
                                      :pointer tag-ptr :int)))
                             (unless (= rc 1)
                               (error "EVP_CIPHER_CTX_ctrl(SET_TAG) failed (rc=~a)" rc)))
                           ;; feed AAD
                           (when (> aad-len 0)
                             (let ((rc (cffi:foreign-funcall-pointer
                                        (%ossl-sym "EVP_DecryptUpdate") nil
                                        :pointer ctx
                                        :pointer (cffi:null-pointer) :pointer outl-ptr
                                        :pointer aad-ptr :int aad-len
                                        :int)))
                               (unless (= rc 1)
                                 (error "EVP_DecryptUpdate(AAD) failed (rc=~a)" rc))))
                           ;; decrypt ciphertext
                           (when (> ct-len 0)
                             (let ((rc (cffi:foreign-funcall-pointer
                                        (%ossl-sym "EVP_DecryptUpdate") nil
                                        :pointer ctx
                                        :pointer pt-ptr :pointer outl-ptr
                                        :pointer ct-ptr :int ct-len
                                        :int)))
                               (unless (= rc 1)
                                 (error "EVP_DecryptUpdate(CT) failed (rc=~a)" rc))))
                           ;; final — returns <=0 on auth failure
                           (let ((rc (cffi:foreign-funcall-pointer
                                      (%ossl-sym "EVP_DecryptFinal_ex") nil
                                      :pointer ctx :pointer pt-ptr :pointer outl-ptr
                                      :int)))
                             (setf auth-ok (> rc 0)))
                           ;; copy plaintext only on auth success
                           (when auth-ok
                             (dotimes (i ct-len)
                               (setf (aref plaintext i) (cffi:mem-aref pt-ptr :uint8 i)))))
                      ;; always: zeroize key + pt foreign buffer, free ctx
                      (dotimes (i +aes-256-gcm-key-len+)
                        (setf (cffi:mem-aref key-ptr :uint8 i) 0))
                      (dotimes (i ct-len)
                        (setf (cffi:mem-aref pt-ptr :uint8 i) 0))
                      (cffi:foreign-funcall-pointer
                       (%ossl-sym "EVP_CIPHER_CTX_free") nil :pointer ctx :void))
                    (if auth-ok plaintext nil)))))))))))

;;; HKDF-SHA384 — EVP_KDF "HKDF" provider, extract-then-expand (RFC 5869 §2 / SP 800-56C).

(defun* %hkdf-sha384-into (ikm salt info out-len secret)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (integer 1 #x1ffff)
               t)
              (simple-array (unsigned-byte 8) (*)))
  "HKDF-SHA384 with output copied into a fresh octet vector — the single shared EVP_KDF path.
   Marshals IKM/SALT/INFO into foreign buffers, drives %HKDF-SHA384-DERIVE, then copies the
   foreign output into the result and zeroizes the foreign output buffer.
   When SECRET is non-NIL the result is a foreign-backed secret static-vector (caller MUST free
   via FREE-SECRET-OCTETS); when NIL it is a plain heap vector.
   DRY note: both HKDF-SHA384 (heap) and DERIVE-DEK (secret) call this — the EVP dance is here
   once and the DEK never transits a GC-heap array (design spec §6)."
  (let ((result (if secret
                    (%make-secret-octets out-len)
                    (make-array out-len :element-type '(unsigned-byte 8))))
        (ikm-n  (length ikm))
        (salt-n (length salt))
        (info-n (length info)))
    (cffi:with-foreign-pointer (ikm-ptr (max 1 ikm-n))
      (cffi:with-foreign-pointer (salt-ptr (max 1 salt-n))
        (cffi:with-foreign-pointer (info-ptr (max 1 info-n))
          (cffi:with-foreign-pointer (out-ptr out-len)
            (dotimes (i ikm-n)
              (setf (cffi:mem-aref ikm-ptr :uint8 i) (aref ikm i)))
            (dotimes (i salt-n)
              (setf (cffi:mem-aref salt-ptr :uint8 i) (aref salt i)))
            (dotimes (i info-n)
              (setf (cffi:mem-aref info-ptr :uint8 i) (aref info i)))
            (%hkdf-sha384-derive ikm-ptr ikm-n salt-ptr salt-n info-ptr info-n out-ptr out-len)
            (dotimes (i out-len)
              (setf (aref result i) (cffi:mem-aref out-ptr :uint8 i)))
            (dotimes (i out-len)
              (setf (cffi:mem-aref out-ptr :uint8 i) 0))))))
    result))

(defun* hkdf-sha384 (ikm salt info out-len)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (integer 1 #x1ffff))
              (simple-array (unsigned-byte 8) (*)))
  "HKDF extract-then-expand with SHA-384 (RFC 5869 §2, NIST SP 800-56C Rev 2).
   IKM, SALT, and INFO are octet vectors; OUT-LEN is the requested output byte count (1..131071).
   Uses OpenSSL EVP_KDF 'HKDF' provider (kdf.h, verified against 3.6.2 headers).
   Returns a plain heap octet vector (a general primitive; its KAT outputs are public test
   vectors). The foreign output buffer is zeroized before deallocation."
  (%hkdf-sha384-into ikm salt info out-len nil))

;;; ML-KEM-1024 KEM — EVP_PKEY-based KEM API (FIPS-203, OpenSSL >= 3.5).
;;;
;;; Key-encoding choice: raw octet vectors via EVP_PKEY_get_raw_public_key /
;;;   EVP_PKEY_get_raw_private_key (confirmed working for ML-KEM in OpenSSL 3.6.2 via C oracle).
;;;   Import uses EVP_PKEY_new_raw_public_key_ex / EVP_PKEY_new_raw_private_key_ex.
;;;   These return the FIPS-203 ek (1568 B) / dk (3168 B) raw encoding — simplest serializable form.
;;;
;;; DRY note: The EVP_PKEY ctx lifecycle (new_from_name/pkey -> init -> free) differs enough
;;;   from the EVP_CIPHER and EVP_KDF flows that no shared wrapper reduces them without forcing
;;;   it; the three KEM functions each hold their own ctx open for the full operation and close
;;;   it in unwind-protect, matching the established DARE pattern. The foreign-buffer marshal/
;;;   zeroize is factored into the inline dotimes loops as in Tasks 1-2 (no copy-paste reduction
;;;   is available without a macro that would obscure the security-critical zeroize paths).

(defun* %evp-pkey-ctx-from-pkey (pkey)
    (function (cffi:foreign-pointer) cffi:foreign-pointer)
  "Create an EVP_PKEY_CTX from an existing EVP_PKEY handle via EVP_PKEY_CTX_new_from_pkey.
   Returns the context pointer (caller must free with EVP_PKEY_CTX_free).
   Errors signal on NULL return."
  (let ((ctx (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_CTX_new_from_pkey") nil
                                            :pointer (cffi:null-pointer)
                                            :pointer pkey
                                            :pointer (cffi:null-pointer)
                                            :pointer)))
    (when (cffi:null-pointer-p ctx)
      (error "EVP_PKEY_CTX_new_from_pkey returned NULL"))
    ctx))

(defun* %evp-pkey-ctx-free (ctx)
    (function (cffi:foreign-pointer) t)
  "Free an EVP_PKEY_CTX via EVP_PKEY_CTX_free (evp.h line 1893)."
  (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_CTX_free") nil :pointer ctx :void)
  t)

(defun* %evp-pkey-free (pkey)
    (function (cffi:foreign-pointer) t)
  "Free an EVP_PKEY via EVP_PKEY_free (evp.h line 1440)."
  (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_free") nil :pointer pkey :void)
  t)

(defun* %foreign->octets (ptr n)
    (function (cffi:foreign-pointer fixnum) (simple-array (unsigned-byte 8) (*)))
  "Copy N bytes from foreign PTR into a fresh Lisp octet vector."
  (let ((v (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n v)
      (setf (aref v i) (cffi:mem-aref ptr :uint8 i)))))

(defun* %zeroize-foreign (ptr n)
    (function (cffi:foreign-pointer fixnum) t)
  "Overwrite N bytes at foreign PTR with zeros (secret-material wipe)."
  (dotimes (i n t)
    (setf (cffi:mem-aref ptr :uint8 i) 0)))

(defun* %make-secret-octets (n)
    (function (fixnum) (simple-array (unsigned-byte 8) (*)))
  "Allocate an N-byte foreign-backed secret buffer, zero-initialised, via the PAL (impl-agnostic).
   The backing memory is pinned/foreign so it can be reliably wiped (design spec §6 — a
   GC-moved heap array cannot). Caller MUST release it via FREE-SECRET-OCTETS at end-of-life."
  (let ((v (dds.pal:alloc-static n)))
    (fill v 0)
    v))

(defun* %foreign->secret (ptr n)
    (function (cffi:foreign-pointer fixnum) (simple-array (unsigned-byte 8) (*)))
  "Copy N bytes from foreign PTR into a fresh foreign-backed secret buffer (static-vector).
   Like %FOREIGN->OCTETS but the destination is non-moving so it can be reliably zeroized
   (design spec §6). Caller MUST release the result via FREE-SECRET-OCTETS."
  (let ((v (%make-secret-octets n)))
    (dotimes (i n v)
      (setf (aref v i) (cffi:mem-aref ptr :uint8 i)))))

(defun* free-secret-octets (v)
    (function ((or null (simple-array (unsigned-byte 8) (*)))) null)
  "Zeroize then release a foreign-backed secret buffer returned by %MAKE-SECRET-OCTETS /
   %FOREIGN->SECRET (the ML-KEM private key, shared secret, or DEK; design spec §6).
   The (fill V 0) reliably wipes because the storage is pinned/foreign. Release is via the PAL
   FREE-STATIC: SBCL frees; Clasp recycles into a lock-guarded pool (never the buggy
   interior-pointer GC_FREE of clasp#1793) and re-zeros on reuse. Returns NIL so callers can
   write (setf slot (free-secret-octets slot)). Idempotent: a NIL argument is a no-op."
  (when v
    (fill v 0)
    (dds.pal:free-static v))
  nil)

(defun* ml-kem-1024-keygen ()
    (function () (values (simple-array (unsigned-byte 8) (*))
                         (simple-array (unsigned-byte 8) (*))))
  "Generate an ML-KEM-1024 key pair (FIPS-203 §7.1 / Algorithm 16).
   Returns (values PUBLIC-KEY PRIVATE-KEY) as raw octet vectors:
     PUBLIC-KEY  = 1568 bytes (ek, FIPS-203 Table 2)
     PRIVATE-KEY = 3168 bytes (dk, FIPS-203 Table 2)
   Uses EVP_PKEY_CTX_new_from_name + EVP_PKEY_keygen_init + EVP_PKEY_generate
   + EVP_PKEY_get_raw_public_key/private_key (OpenSSL 3.6.2 evp.h, verified).
   The OpenSSL private-key work buffer is zeroized before deallocation; the returned
   PRIVATE-KEY is a foreign-backed secret buffer (static-vector, design spec §6) the caller
   MUST release with FREE-SECRET-OCTETS. PUBLIC-KEY is a plain heap vector (not secret)."
  (let ((kctx (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_CTX_new_from_name") nil
                                             :pointer (cffi:null-pointer)
                                             :string "ML-KEM-1024"
                                             :pointer (cffi:null-pointer)
                                             :pointer)))
    (when (cffi:null-pointer-p kctx)
      (error "EVP_PKEY_CTX_new_from_name(ML-KEM-1024) returned NULL"))
    (unwind-protect
         (progn
           (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_keygen_init") nil
                                                    :pointer kctx :int)))
             (unless (= rc 1)
               (error "EVP_PKEY_keygen_init(ML-KEM-1024) failed (rc=~a)" rc)))
           (cffi:with-foreign-pointer (ppkey (cffi:foreign-type-size :pointer))
             (setf (cffi:mem-ref ppkey :pointer) (cffi:null-pointer))
             (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_generate") nil
                                                      :pointer kctx
                                                      :pointer ppkey
                                                      :int)))
               (unless (= rc 1)
                 (error "EVP_PKEY_generate(ML-KEM-1024) failed (rc=~a)" rc)))
             (let ((pkey (cffi:mem-ref ppkey :pointer)))
               (unwind-protect
                    (cffi:with-foreign-pointer (pub-ptr +ml-kem-1024-pub-len+)
                      (cffi:with-foreign-pointer (priv-ptr +ml-kem-1024-priv-len+)
                        (cffi:with-foreign-pointer (pub-len-ptr (cffi:foreign-type-size :size))
                          (cffi:with-foreign-pointer (priv-len-ptr (cffi:foreign-type-size :size))
                            (setf (cffi:mem-ref pub-len-ptr :size) +ml-kem-1024-pub-len+)
                            (setf (cffi:mem-ref priv-len-ptr :size) +ml-kem-1024-priv-len+)
                            (let ((rc (cffi:foreign-funcall-pointer
                                       (%ossl-sym "EVP_PKEY_get_raw_public_key") nil
                                       :pointer pkey
                                       :pointer pub-ptr
                                       :pointer pub-len-ptr
                                       :int)))
                              (unless (= rc 1)
                                (error "EVP_PKEY_get_raw_public_key(ML-KEM-1024) failed (rc=~a)" rc)))
                            (let ((rc (cffi:foreign-funcall-pointer
                                       (%ossl-sym "EVP_PKEY_get_raw_private_key") nil
                                       :pointer pkey
                                       :pointer priv-ptr
                                       :pointer priv-len-ptr
                                       :int)))
                              (unless (= rc 1)
                                (%zeroize-foreign priv-ptr +ml-kem-1024-priv-len+)
                                (error "EVP_PKEY_get_raw_private_key(ML-KEM-1024) failed (rc=~a)" rc)))
                            (let ((pub  (%foreign->octets pub-ptr  +ml-kem-1024-pub-len+))
                                  (priv (%foreign->secret priv-ptr +ml-kem-1024-priv-len+)))
                              (%zeroize-foreign priv-ptr +ml-kem-1024-priv-len+)
                              (values pub priv))))))
                 (%evp-pkey-free pkey)))))
      (%evp-pkey-ctx-free kctx))))

(defun* ml-kem-1024-encapsulate (public-key)
    (function ((simple-array (unsigned-byte 8) (*)))
              (values (simple-array (unsigned-byte 8) (*))
                      (simple-array (unsigned-byte 8) (*))))
  "ML-KEM-1024 key encapsulation (FIPS-203 §7.2 / Algorithm 17).
   PUBLIC-KEY must be 1568 octets (ek, raw FIPS-203 encoding).
   Returns (values KEM-CIPHERTEXT SHARED-SECRET):
     KEM-CIPHERTEXT = 1568 bytes (c, FIPS-203 Table 2)
     SHARED-SECRET  = 32 bytes (K, FIPS-203 Table 2)
   Uses EVP_PKEY_new_raw_public_key_ex + EVP_PKEY_CTX_new_from_pkey +
   EVP_PKEY_encapsulate_init + EVP_PKEY_encapsulate (OpenSSL 3.6.2 evp.h, verified).
   The OpenSSL shared-secret work buffer is zeroized before deallocation; the returned
   SHARED-SECRET is a foreign-backed secret buffer (static-vector, design spec §6) the caller
   MUST release with FREE-SECRET-OCTETS. KEM-CIPHERTEXT is a plain heap vector (not secret)."
  (cffi:with-foreign-pointer (pub-ptr +ml-kem-1024-pub-len+)
    (dotimes (i +ml-kem-1024-pub-len+)
      (setf (cffi:mem-aref pub-ptr :uint8 i) (aref public-key i)))
    (let ((pkey (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_new_raw_public_key_ex") nil
                                               :pointer (cffi:null-pointer)
                                               :string "ML-KEM-1024"
                                               :pointer (cffi:null-pointer)
                                               :pointer pub-ptr
                                               :size +ml-kem-1024-pub-len+
                                               :pointer)))
      (when (cffi:null-pointer-p pkey)
        (error "EVP_PKEY_new_raw_public_key_ex(ML-KEM-1024) returned NULL"))
      (unwind-protect
           (let ((ctx (%evp-pkey-ctx-from-pkey pkey)))
             (unwind-protect
                  (progn
                    (let ((rc (cffi:foreign-funcall-pointer
                               (%ossl-sym "EVP_PKEY_encapsulate_init") nil
                               :pointer ctx
                               :pointer (cffi:null-pointer)
                               :int)))
                      (unless (= rc 1)
                        (error "EVP_PKEY_encapsulate_init(ML-KEM-1024) failed (rc=~a)" rc)))
                    (cffi:with-foreign-pointer (ct-ptr +ml-kem-1024-ct-len+)
                      (cffi:with-foreign-pointer (ss-ptr +ml-kem-1024-ss-len+)
                        (cffi:with-foreign-pointer (ct-len-ptr (cffi:foreign-type-size :size))
                          (cffi:with-foreign-pointer (ss-len-ptr (cffi:foreign-type-size :size))
                            (setf (cffi:mem-ref ct-len-ptr :size) +ml-kem-1024-ct-len+)
                            (setf (cffi:mem-ref ss-len-ptr :size) +ml-kem-1024-ss-len+)
                            (let ((rc (cffi:foreign-funcall-pointer
                                       (%ossl-sym "EVP_PKEY_encapsulate") nil
                                       :pointer ctx
                                       :pointer ct-ptr :pointer ct-len-ptr
                                       :pointer ss-ptr :pointer ss-len-ptr
                                       :int)))
                              (unless (= rc 1)
                                (%zeroize-foreign ss-ptr +ml-kem-1024-ss-len+)
                                (error "EVP_PKEY_encapsulate(ML-KEM-1024) failed (rc=~a)" rc)))
                            (let ((ct (%foreign->octets ct-ptr +ml-kem-1024-ct-len+))
                                  (ss (%foreign->secret ss-ptr +ml-kem-1024-ss-len+)))
                              (%zeroize-foreign ss-ptr +ml-kem-1024-ss-len+)
                              (values ct ss)))))))
               (%evp-pkey-ctx-free ctx)))
        (%evp-pkey-free pkey)))))

(defun* ml-kem-1024-decapsulate (private-key kem-ciphertext)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "ML-KEM-1024 key decapsulation (FIPS-203 §7.3 / Algorithm 18).
   PRIVATE-KEY must be 3168 octets (dk, raw FIPS-203 encoding).
   KEM-CIPHERTEXT must be 1568 octets (c, FIPS-203 Table 2).
   Returns SHARED-SECRET (32 octets, K).
   ML-KEM implicit rejection (FIPS-203 §7.3): always returns rc=1; on key mismatch
   the returned K differs from the encapsulator's K (not an error condition).
   Uses EVP_PKEY_new_raw_private_key_ex + EVP_PKEY_CTX_new_from_pkey +
   EVP_PKEY_decapsulate_init + EVP_PKEY_decapsulate (OpenSSL 3.6.2 evp.h, verified).
   The OpenSSL private-key and shared-secret work buffers are zeroized before deallocation;
   the returned SHARED-SECRET is a foreign-backed secret buffer (static-vector, design spec §6)
   the caller MUST release with FREE-SECRET-OCTETS."
  (cffi:with-foreign-pointer (priv-ptr +ml-kem-1024-priv-len+)
    (cffi:with-foreign-pointer (ct-ptr +ml-kem-1024-ct-len+)
      (cffi:with-foreign-pointer (ss-ptr +ml-kem-1024-ss-len+)
        (dotimes (i +ml-kem-1024-priv-len+)
          (setf (cffi:mem-aref priv-ptr :uint8 i) (aref private-key i)))
        (dotimes (i +ml-kem-1024-ct-len+)
          (setf (cffi:mem-aref ct-ptr :uint8 i) (aref kem-ciphertext i)))
        (let ((pkey (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_new_raw_private_key_ex") nil
                                                   :pointer (cffi:null-pointer)
                                                   :string "ML-KEM-1024"
                                                   :pointer (cffi:null-pointer)
                                                   :pointer priv-ptr
                                                   :size +ml-kem-1024-priv-len+
                                                   :pointer)))
          (%zeroize-foreign priv-ptr +ml-kem-1024-priv-len+)
          (when (cffi:null-pointer-p pkey)
            (error "EVP_PKEY_new_raw_private_key_ex(ML-KEM-1024) returned NULL"))
          (unwind-protect
               (let ((ctx (%evp-pkey-ctx-from-pkey pkey)))
                 (unwind-protect
                      (progn
                        (let ((rc (cffi:foreign-funcall-pointer
                                   (%ossl-sym "EVP_PKEY_decapsulate_init") nil
                                   :pointer ctx
                                   :pointer (cffi:null-pointer)
                                   :int)))
                          (unless (= rc 1)
                            (error "EVP_PKEY_decapsulate_init(ML-KEM-1024) failed (rc=~a)" rc)))
                        (cffi:with-foreign-pointer (ss-len-ptr (cffi:foreign-type-size :size))
                          (setf (cffi:mem-ref ss-len-ptr :size) +ml-kem-1024-ss-len+)
                          (let ((rc (cffi:foreign-funcall-pointer
                                     (%ossl-sym "EVP_PKEY_decapsulate") nil
                                     :pointer ctx
                                     :pointer ss-ptr :pointer ss-len-ptr
                                     :pointer ct-ptr :size +ml-kem-1024-ct-len+
                                     :int)))
                            (unless (= rc 1)
                              (%zeroize-foreign ss-ptr +ml-kem-1024-ss-len+)
                              (error "EVP_PKEY_decapsulate(ML-KEM-1024) failed (rc=~a)" rc)))
                          (let ((ss (%foreign->secret ss-ptr +ml-kem-1024-ss-len+)))
                            (%zeroize-foreign ss-ptr +ml-kem-1024-ss-len+)
                            ss)))
                   (%evp-pkey-ctx-free ctx)))
            (%evp-pkey-free pkey)))))))
