(in-package #:dds.dare)

;;; SHA-384 and HKDF-SHA384 primitives — OpenSSL EVP high-level API via CFFI.
;;; Foreign buffers zeroized before free (establishes the DARE secret-material pattern).

(defconstant +sha384-digest-len+ 48 "SHA-384 output length in octets (FIPS 180-4 §6.5).")
(defconstant +hmac-sha256-mac-len+ 32 "HMAC-SHA-256 output length in octets (FIPS 198-1, hash=SHA-256 FIPS 180-4 §6.2).")

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

;;; HMAC-SHA256 one-shot — EVP_Q_mac(name="HMAC", subalg="SHA256"), the DDS-Security session-key MAC.

(defun* hmac-sha256 (key data)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (32)))
  "Return HMAC-SHA-256(KEY, DATA) as a fresh 32-byte vector (FIPS 198-1, hash SHA-256).
   Uses one-shot EVP_Q_mac(NULL,'HMAC',NULL,'SHA256',NULL,...) (OpenSSL evp.h, verified vs 3.6.2).
   The foreign key buffer is zeroized before deallocation. Signals on any EVP error.
   This is the session-key MAC primitive for DDS-Security 1.1 §9.5.3.3.4.2 (NOT HKDF-SHA384)."
  (let* ((key-n  (length key))
         (data-n (length data))
         (out    (make-array +hmac-sha256-mac-len+ :element-type '(unsigned-byte 8))))
    (cffi:with-foreign-pointer (key-ptr (max 1 key-n))
      (cffi:with-foreign-pointer (data-ptr (max 1 data-n))
        (cffi:with-foreign-pointer (out-ptr +hmac-sha256-mac-len+)
          (cffi:with-foreign-pointer (outlen-ptr (cffi:foreign-type-size :size))
            (dotimes (i key-n)
              (setf (cffi:mem-aref key-ptr :uint8 i) (aref key i)))
            (dotimes (i data-n)
              (setf (cffi:mem-aref data-ptr :uint8 i) (aref data i)))
            (setf (cffi:mem-ref outlen-ptr :size) +hmac-sha256-mac-len+)
            (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_Q_mac") nil
                                            :pointer (cffi:null-pointer)
                                            :string "HMAC"
                                            :pointer (cffi:null-pointer)
                                            :string "SHA256"
                                            :pointer (cffi:null-pointer)
                                            :pointer key-ptr
                                            :size key-n
                                            :pointer data-ptr
                                            :size data-n
                                            :pointer out-ptr
                                            :size +hmac-sha256-mac-len+
                                            :pointer outlen-ptr
                                            :pointer)))
              (dotimes (i key-n)
                (setf (cffi:mem-aref key-ptr :uint8 i) 0))
              (when (cffi:null-pointer-p rc)
                (error "EVP_Q_mac(HMAC-SHA256) returned NULL"))
              (dotimes (i +hmac-sha256-mac-len+)
                (setf (aref out i) (cffi:mem-aref out-ptr :uint8 i))))))))
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
                                      :pointer *%aes-256-gcm-cipher*
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
                                      :pointer *%aes-256-gcm-cipher*
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

;;; AES-256-GCM AEAD into-buffer variants — write CT/tag/PT directly through the caller's
;;; static-vector SAP (dds.pal:static-pointer), zero GC-heap output allocation. The EVP call
;;; sequence is identical to aes-256-gcm-seal/open, so the output is byte-for-byte identical
;;; (NIST SP 800-38D Appendix B Test Case 16, asserted by the dare-aes-gcm-kat into-buffer arm).

(defun* aes-256-gcm-seal-into (out ct-off tag-off key nonce-vec nonce-off aad pt pt-off pt-len
                               &optional (aad-off 0) (aad-len (length aad)))
    (function ((simple-array (unsigned-byte 8) (*))
               fixnum
               fixnum
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               fixnum
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               fixnum
               fixnum
               &optional fixnum fixnum)
              (eql t))
  "AES-256-GCM authenticated encryption into a caller's static buffer (FIPS 197 + NIST SP 800-38D).
   Writes PT-LEN ciphertext octets into OUT[CT-OFF..] and the 16-byte tag into OUT[TAG-OFF..]
   directly through OUT's GC-stable static SAP (no make-array; zero GC-heap output allocation).
   NONCE = NONCE-VEC[NONCE-OFF..+12]; PLAINTEXT = PT[PT-OFF..+PT-LEN]; AAD = AAD[AAD-OFF..+AAD-LEN]
   (optional; default aad-off=0, aad-len=(length aad), i.e. the whole vector — backward-compatible,
   so every existing caller is byte-identical). PT-LEN=0 (SIGN/GMAC, DDS-Security §9.5.3.3.4.3): no
   ciphertext bytes written; only the 16-byte GMAC tag at OUT[TAG-OFF..] over the AAD sub-range — the
   symmetric mate of AES-256-GCM-OPEN-INTO's aad-off/aad-len, letting a caller GMAC a region of a larger
   buffer BY OFFSET (no subseq; the whole-RTPS SIGN wrap authenticates exactly the verbatim submessage
   stream, not the surrounding buffer). AAD may alias OUT's backing memory (the SIGN verbatim region in
   the same buffer): EVP_EncryptUpdate(AAD) runs before GET_TAG writes the tag, so aad-ptr / out-SAP
   aliasing is safe regardless of offset overlap.
   OUT MUST be an ALLOC-STATIC-backed vector with room for CT-OFF+PT-LEN and TAG-OFF+16 octets.
   Same EVP_Encrypt* sequence as AES-256-GCM-SEAL so the output is byte-identical (NIST SP 800-38D
   Appendix B TC16). Key buffer is zeroized before return. Returns T. Signals on any EVP error.
   Zero-alloc (~0 GC-heap B/call on SBCL): the plaintext is staged into OUT[CT-OFF..] and encrypted
   IN PLACE (EVP in==out via dds.pal:static-sap+, an inline non-boxing SAP into OUT), so no per-call
   ciphertext/plaintext SAP is boxed; the AAD is pinned and offset via cffi:inc-pointer (no copy, 0 cons);
   NULL args use the cached *%NULL-PTR*; the only scratch is the constant-size key/nonce/outl buffers."
  (let ()
    (declare (type fixnum aad-off aad-len))
    ;; O(1) AAD-region bounds (safety-0-safe; NFR-SEC-POSTURE) — mirror aes-256-gcm-open-into
    (unless (<= (+ aad-off aad-len) (length aad))
      (error "aes-256-gcm-seal-into: AAD region [~d,+~d) out of bounds (vector length ~d)"
             aad-off aad-len (length aad)))
    ;; O(1) output-extent bounds: unconditional, safety-0-safe (the operating contract §4)
    (unless (<= (+ ct-off pt-len) (dds.pal:static-length out))
      (error "aes-256-gcm-seal-into: OUT too small for CT region (need ~d, have ~d)"
             (+ ct-off pt-len) (dds.pal:static-length out)))
    (unless (<= (+ tag-off +aes-gcm-tag-len+) (dds.pal:static-length out))
      (error "aes-256-gcm-seal-into: OUT too small for TAG region (need ~d, have ~d)"
             (+ tag-off +aes-gcm-tag-len+) (dds.pal:static-length out)))
    ;; stage plaintext into OUT's CT region for in-place GCM (EVP in==out; static-vector aref, 0 cons)
    (dotimes (i pt-len)
      (setf (aref out (+ ct-off i)) (aref pt (+ pt-off i))))
    (cffi:with-foreign-pointer (key-ptr +aes-256-gcm-key-len+)
      (cffi:with-foreign-pointer (nonce-ptr +aes-gcm-nonce-len+)
        (cffi:with-foreign-object (outl-ptr :int)
          ;; AAD is read-only: pin the caller's vector and pass its SAP in place (no copy, no variable-size scratch, 0 cons)
          (cffi:with-pointer-to-vector-data (aad-ptr aad)
            (dotimes (i +aes-256-gcm-key-len+)
              (setf (cffi:mem-aref key-ptr :uint8 i) (aref key i)))
            (dotimes (i +aes-gcm-nonce-len+)
              (setf (cffi:mem-aref nonce-ptr :uint8 i) (aref nonce-vec (+ nonce-off i))))
            (let* ((sealed nil)
                   (ctx (cffi:foreign-funcall-pointer
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
                                :pointer *%aes-256-gcm-cipher*
                                :pointer *%null-ptr*
                                :pointer *%null-ptr*
                                :pointer *%null-ptr*
                                :int)))
                       (unless (= rc 1)
                         (error "EVP_EncryptInit_ex(EVP_aes_256_gcm) failed (rc=~a)" rc)))
                     ;; set 12-byte nonce length
                     (let ((rc (cffi:foreign-funcall-pointer
                                (%ossl-sym "EVP_CIPHER_CTX_ctrl") nil
                                :pointer ctx :int +gcm-ctrl-set-ivlen+
                                :int +aes-gcm-nonce-len+
                                :pointer *%null-ptr* :int)))
                       (unless (= rc 1)
                         (error "EVP_CIPHER_CTX_ctrl(SET_IVLEN) failed (rc=~a)" rc)))
                     ;; init key and nonce
                     (let ((rc (cffi:foreign-funcall-pointer
                                (%ossl-sym "EVP_EncryptInit_ex") nil
                                :pointer ctx
                                :pointer *%null-ptr*
                                :pointer *%null-ptr*
                                :pointer key-ptr
                                :pointer nonce-ptr
                                :int)))
                       (unless (= rc 1)
                         (error "EVP_EncryptInit_ex(key,nonce) failed (rc=~a)" rc)))
                     ;; feed AAD sub-range [aad-off, aad-off+aad-len) via cffi:inc-pointer offset (outl discarded for AAD)
                     (when (> aad-len 0)
                       (let ((rc (cffi:foreign-funcall-pointer
                                  (%ossl-sym "EVP_EncryptUpdate") nil
                                  :pointer ctx
                                  :pointer *%null-ptr* :pointer outl-ptr
                                  :pointer (cffi:inc-pointer aad-ptr aad-off) :int aad-len
                                  :int)))
                         (unless (= rc 1)
                           (error "EVP_EncryptUpdate(AAD) failed (rc=~a)" rc))))
                     ;; encrypt plaintext in place at OUT[CT-OFF] (EVP in==out via inline non-boxing SAP)
                     (when (> pt-len 0)
                       (let ((rc (cffi:foreign-funcall-pointer
                                  (%ossl-sym "EVP_EncryptUpdate") nil
                                  :pointer ctx
                                  :pointer (dds.pal:static-sap+ out ct-off) :pointer outl-ptr
                                  :pointer (dds.pal:static-sap+ out ct-off) :int pt-len
                                  :int)))
                         (unless (= rc 1)
                           (error "EVP_EncryptUpdate(PT) failed (rc=~a)" rc))))
                     ;; finalize (GCM final produces no additional output)
                     (let ((rc (cffi:foreign-funcall-pointer
                                (%ossl-sym "EVP_EncryptFinal_ex") nil
                                :pointer ctx :pointer (dds.pal:static-sap+ out ct-off) :pointer outl-ptr
                                :int)))
                       (unless (= rc 1)
                         (error "EVP_EncryptFinal_ex failed (rc=~a)" rc)))
                     ;; extract 16-byte tag directly into OUT's SAP at TAG-OFF
                     (let ((rc (cffi:foreign-funcall-pointer
                                (%ossl-sym "EVP_CIPHER_CTX_ctrl") nil
                                :pointer ctx :int +gcm-ctrl-get-tag+
                                :int +aes-gcm-tag-len+
                                :pointer (dds.pal:static-sap+ out tag-off) :int)))
                       (unless (= rc 1)
                         (error "EVP_CIPHER_CTX_ctrl(GET_TAG) failed (rc=~a)" rc)))
                     (setf sealed t))   ; tag written: encryption complete, OUT holds ciphertext
                ;; always: zeroize key, free ctx; on error-path only: wipe staged plaintext (defense-in-depth)
                (unless sealed
                  (dotimes (i pt-len)   ; mirror decode-side fail-closed wipe (operating contract §4)
                    (setf (aref out (+ ct-off i)) 0)))
                (dotimes (i +aes-256-gcm-key-len+)
                  (setf (cffi:mem-aref key-ptr :uint8 i) 0))
                (cffi:foreign-funcall-pointer
                 (%ossl-sym "EVP_CIPHER_CTX_free") nil :pointer ctx :void)))))))
    t))

(defun* aes-256-gcm-open-into (pt-out pt-off key nonce-vec nonce-off aad ct-vec ct-off ct-len tag-vec tag-off
                               &optional (aad-off 0) (aad-len (length aad)))
    (function ((simple-array (unsigned-byte 8) (*))
               fixnum
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               fixnum
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               fixnum
               fixnum
               (simple-array (unsigned-byte 8) (*))
               fixnum
               &optional fixnum fixnum)
              (or (eql t) null))
  "AES-256-GCM authenticated decryption into a caller's static buffer (FIPS 197 + NIST SP 800-38D).
   On auth success writes CT-LEN plaintext octets into PT-OUT[PT-OFF..] directly through PT-OUT's
   GC-stable static SAP and returns T; on authentication failure returns NIL and zeroizes the
   CT-LEN-octet output region so NO readable plaintext remains (fail-closed, SP 800-38D §7.2).
   NONCE = NONCE-VEC[NONCE-OFF..+12]; CIPHERTEXT = CT-VEC[CT-OFF..+CT-LEN]; TAG = TAG-VEC[TAG-OFF..+16].
   AAD = AAD[AAD-OFF..+AAD-LEN] (optional; default aad-off=0, aad-len=(length aad), backward-compatible).
   CT-LEN=0 (SIGN/GMAC verify, DDS-Security §9.5.3.3.4.3): no plaintext bytes are written;
   EVP_DecryptFinal_ex authenticates the AAD-only GHASH against TAG-VEC[TAG-OFF..+16], returning T
   on match and NIL on mismatch (fail-closed; no-op output wipe since CT-LEN=0).
   PT-OUT MUST be an ALLOC-STATIC-backed vector with room for PT-OFF+CT-LEN octets.
   Same EVP_Decrypt* sequence as AES-256-GCM-OPEN so the plaintext is byte-identical. Key buffer is
   zeroized before return; NEVER leaves plaintext readable on auth failure (NIST SP 800-38D §7.2).
   On the EVP_CIPHER_CTX_new OOM branch PT-OUT is left UNTOUCHED — the ciphertext is staged only AFTER the
   context allocation succeeds, so a failed open never leaves staged bytes in PT-OUT (ADR 0038 residual f).
   Zero-alloc (~0 GC-heap B/call on SBCL): the ciphertext is staged into PT-OUT[PT-OFF..] and decrypted
   IN PLACE (EVP in==out via dds.pal:static-sap+, an inline non-boxing SAP into PT-OUT), so no per-call
   ciphertext/plaintext SAP is boxed; NULL args use the cached *%NULL-PTR*; the fail-closed wipe zeroes
   the PT-OUT region through its static-vector aref (0 cons); scratch is the constant-size
   key/nonce/tag/outl buffers; AAD is pinned and offset via cffi:inc-pointer (no copy, 0 cons)."
  (declare (type fixnum aad-off aad-len))
  (let ()
    ;; O(1) output-extent bounds: unconditional, safety-0-safe (the operating contract §4)
    (unless (<= (+ pt-off ct-len) (dds.pal:static-length pt-out))
      (error "aes-256-gcm-open-into: PT-OUT too small for plaintext region (need ~d, have ~d)"
             (+ pt-off ct-len) (dds.pal:static-length pt-out)))
    (unless (<= (+ aad-off aad-len) (length aad))
      (error "aes-256-gcm-open-into: AAD region [~d,+~d) out of bounds (vector length ~d)"
             aad-off aad-len (length aad)))
    (cffi:with-foreign-pointer (key-ptr +aes-256-gcm-key-len+)
      (cffi:with-foreign-pointer (nonce-ptr +aes-gcm-nonce-len+)
        (cffi:with-foreign-pointer (tag-ptr +aes-gcm-tag-len+)
          (cffi:with-foreign-object (outl-ptr :int)
            ;; AAD is read-only: pin caller's vector, advance SAP to aad-off via cffi:inc-pointer (0 cons)
            (cffi:with-pointer-to-vector-data (aad-ptr aad)
              (dotimes (i +aes-256-gcm-key-len+)
                (setf (cffi:mem-aref key-ptr :uint8 i) (aref key i)))
              (dotimes (i +aes-gcm-nonce-len+)
                (setf (cffi:mem-aref nonce-ptr :uint8 i) (aref nonce-vec (+ nonce-off i))))
              (dotimes (i +aes-gcm-tag-len+)
                (setf (cffi:mem-aref tag-ptr :uint8 i) (aref tag-vec (+ tag-off i))))
              (let ((ctx (cffi:foreign-funcall-pointer
                          (%ossl-sym "EVP_CIPHER_CTX_new") nil :pointer))
                    (auth-ok nil))
                (when (cffi:null-pointer-p ctx)
                  (dotimes (i +aes-256-gcm-key-len+)
                    (setf (cffi:mem-aref key-ptr :uint8 i) 0))
                  (error "EVP_CIPHER_CTX_new returned NULL"))
                ;; stage AFTER the CTX-NULL check (ADR 0038 residual f): on OOM PT-OUT is never written -> holds no ciphertext
                (dotimes (i ct-len)
                  (setf (aref pt-out (+ pt-off i)) (aref ct-vec (+ ct-off i))))
                (unwind-protect
                     (progn
                       (let ((rc (cffi:foreign-funcall-pointer
                                  (%ossl-sym "EVP_DecryptInit_ex") nil
                                  :pointer ctx
                                  :pointer *%aes-256-gcm-cipher*
                                  :pointer *%null-ptr*
                                  :pointer *%null-ptr*
                                  :pointer *%null-ptr*
                                  :int)))
                         (unless (= rc 1)
                           (error "EVP_DecryptInit_ex(EVP_aes_256_gcm) failed (rc=~a)" rc)))
                       (let ((rc (cffi:foreign-funcall-pointer
                                  (%ossl-sym "EVP_CIPHER_CTX_ctrl") nil
                                  :pointer ctx :int +gcm-ctrl-set-ivlen+
                                  :int +aes-gcm-nonce-len+
                                  :pointer *%null-ptr* :int)))
                         (unless (= rc 1)
                           (error "EVP_CIPHER_CTX_ctrl(SET_IVLEN) failed (rc=~a)" rc)))
                       (let ((rc (cffi:foreign-funcall-pointer
                                  (%ossl-sym "EVP_DecryptInit_ex") nil
                                  :pointer ctx
                                  :pointer *%null-ptr*
                                  :pointer *%null-ptr*
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
                       ;; feed AAD sub-range [aad-off, aad-off+aad-len) via cffi:inc-pointer offset
                       (when (> aad-len 0)
                         (let ((rc (cffi:foreign-funcall-pointer
                                    (%ossl-sym "EVP_DecryptUpdate") nil
                                    :pointer ctx
                                    :pointer *%null-ptr* :pointer outl-ptr
                                    :pointer (cffi:inc-pointer aad-ptr aad-off) :int aad-len
                                    :int)))
                           (unless (= rc 1)
                             (error "EVP_DecryptUpdate(AAD) failed (rc=~a)" rc))))
                       ;; decrypt ciphertext in place at PT-OUT[PT-OFF] (EVP in==out via inline non-boxing SAP)
                       (when (> ct-len 0)
                         (let ((rc (cffi:foreign-funcall-pointer
                                    (%ossl-sym "EVP_DecryptUpdate") nil
                                    :pointer ctx
                                    :pointer (dds.pal:static-sap+ pt-out pt-off) :pointer outl-ptr
                                    :pointer (dds.pal:static-sap+ pt-out pt-off) :int ct-len
                                    :int)))
                           (unless (= rc 1)
                             (error "EVP_DecryptUpdate(CT) failed (rc=~a)" rc))))
                       ;; final — returns <=0 on auth failure
                       (let ((rc (cffi:foreign-funcall-pointer
                                  (%ossl-sym "EVP_DecryptFinal_ex") nil
                                  :pointer ctx :pointer (dds.pal:static-sap+ pt-out pt-off) :pointer outl-ptr
                                  :int)))
                         (setf auth-ok (> rc 0))))
                  ;; always: zeroize key; fail-closed: wipe written PT region unless auth-ok; free ctx
                  (dotimes (i +aes-256-gcm-key-len+)
                    (setf (cffi:mem-aref key-ptr :uint8 i) 0))
                  (unless auth-ok
                    (dotimes (i ct-len)
                      (setf (aref pt-out (+ pt-off i)) 0)))
                  (cffi:foreign-funcall-pointer
                   (%ossl-sym "EVP_CIPHER_CTX_free") nil :pointer ctx :void))
                (if auth-ok t nil)))))))))

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

(defun* octets->secret (vec)
    (function ((simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Copy VEC's octets into a fresh foreign-backed secret buffer (static-vector), so the long-lived copy can
   be reliably zeroized (design spec §6) — the Lisp-vector companion to %FOREIGN->SECRET. SOURCE VEC is left
   untouched (the caller owns it). Caller MUST release the result via FREE-SECRET-OCTETS. Used by the
   DDS-Security KeyMaterial secret slots + derived-session-key caches (ADR-0034 secret hygiene)."
  (let* ((n (length vec))
         (v (%make-secret-octets n)))
    (dotimes (i n v)
      (setf (aref v i) (aref vec i)))))

;;; RAND_bytes wrapper — exported for DDS-Security nonce generation (not a secret; plain heap vector).
;;; RAND_bytes(unsigned char *buf, int num) -> int (1=ok); rand.h (OpenSSL 3.6.2).

(defun* random-bytes (n)
    (function ((unsigned-byte 32)) (simple-array (unsigned-byte 8) (*)))
  "Generate N cryptographically random bytes via RAND_bytes (rand.h, OpenSSL 3.6.2).
   Returns a plain heap octet vector. Nonces are not secret. Signals on RAND_bytes failure."
  (cffi:with-foreign-pointer (buf n)
    (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "RAND_bytes") nil
                                             :pointer buf :int n :int)))
      (unless (= rc 1)
        (error "RAND_bytes(~a) failed (rc=~a)" n rc))
      (%foreign->octets buf n))))

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

;;; SHA-256 one-shot digest — EVP_Q_digest(NULL,"SHA-256",NULL,...) (evp.h line 744, OpenSSL 3.6.2).
;;; DDS-Security 1.1 §9.3.2 uses SHA-256 for hash_c1, hash_c2, and SharedSecret derivation.

(defconstant +sha256-digest-len+ 32 "SHA-256 output length in octets (FIPS 180-4 §6.2).")

(defun* sha-256 (octets)
    (function ((simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (32)))
  "Return SHA-256(OCTETS) as a fresh 32-byte heap vector via EVP_Q_digest (evp.h line 744).
   Source: FIPS 180-4 §6.2. KAT: SHA-256('') = e3b0c44...b855 (NIST FIPS 180-4 §6.2 test vector)."
  (let* ((n (length octets))
         (out (make-array +sha256-digest-len+ :element-type '(unsigned-byte 8))))
    (cffi:with-foreign-pointer (in-ptr (max 1 n))
      (dotimes (i n)
        (setf (cffi:mem-aref in-ptr :uint8 i) (aref octets i)))
      (cffi:with-foreign-pointer (md-ptr +sha256-digest-len+)
        (cffi:with-foreign-pointer (mdlen-ptr (cffi:foreign-type-size :size))
          (setf (cffi:mem-ref mdlen-ptr :size) +sha256-digest-len+)
          (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_Q_digest") nil
                                          :pointer (cffi:null-pointer)
                                          :string "SHA-256"
                                          :pointer (cffi:null-pointer)
                                          :pointer in-ptr
                                          :size n
                                          :pointer md-ptr
                                          :pointer mdlen-ptr
                                          :int)))
            (unless (= rc 1)
              (dotimes (i +sha256-digest-len+)
                (setf (cffi:mem-aref md-ptr :uint8 i) 0))
              (error "EVP_Q_digest(SHA-256) failed (rc=~a)" rc))
            (dotimes (i +sha256-digest-len+)
              (setf (aref out i) (cffi:mem-aref md-ptr :uint8 i)))
            (dotimes (i +sha256-digest-len+)
              (setf (cffi:mem-aref md-ptr :uint8 i) 0))))))
    out))

;;; x509-to-der: DER-encode an X509* handle via i2d_X509 (x509.h line 743, OpenSSL 3.6.2).
;;; i2d_X509(X509 *a, unsigned char **pp) -> int (bytes written, <0=error).
;;; With pp pointing to a NULL pointer, OpenSSL allocates the DER buffer; caller must CRYPTO_free it.
;;; SubjectPublicKeyInfo DER (via i2d_PUBKEY) used for dh1/dh2 in DDS-Security §9.3.2.1.

(defun* x509-to-der (cert)
    (function (cffi:foreign-pointer) (or (simple-array (unsigned-byte 8) (*)) null))
  "DER-encode X509* CERT via i2d_X509 (x509.h, OpenSSL 3.6.2). Returns fresh heap vector or NIL."
  (cffi:with-foreign-pointer (pp (cffi:foreign-type-size :pointer))
    (setf (cffi:mem-ref pp :pointer) (cffi:null-pointer))
    (let ((derlen (cffi:foreign-funcall-pointer (%ossl-sym "i2d_X509") nil
                                                 :pointer cert :pointer pp :int)))
      (when (< derlen 0) (return-from x509-to-der nil))
      (let ((der-ptr (cffi:mem-ref pp :pointer)))
        (unwind-protect
             (let ((v (make-array derlen :element-type '(unsigned-byte 8))))
               (dotimes (i derlen v)
                 (setf (aref v i) (cffi:mem-aref der-ptr :uint8 i))))
          (cffi:foreign-funcall-pointer (%ossl-sym "CRYPTO_free") nil
                                        :pointer der-ptr
                                        :pointer (cffi:null-pointer)
                                        :int 0
                                        :void))))))

;;; EC P-256 key import from raw scalar + uncompressed point (for KATs and externally-supplied keys).
;;;
;;; EVP_PKEY_fromdata_init(ctx) -> int (evp.h line 2078, OpenSSL 3.6.2).
;;; EVP_PKEY_fromdata(ctx, **ppkey, selection, params) -> int (evp.h line 2079, OpenSSL 3.6.2).
;;; selection constants (evp.h line 106–113, core_dispatch.h line 640–651):
;;;   EVP_PKEY_PUBLIC_KEY = 0x86 (ALL_PARAMS|PUBLIC_KEY), EVP_PKEY_KEYPAIR = 0x87 (+PRIVATE_KEY).
;;; OSSL_PARAM for EC key import (core_names.h):
;;;   "group" (UTF8_STRING, "prime256v1"), "priv" (UNSIGNED_INTEGER, BN in LE byte order),
;;;   "pub"   (OCTET_STRING, uncompressed point 0x04||X||Y, 65 bytes).
;;; CRITICAL: OpenSSL OSSL_PARAM BN (type UNSIGNED_INTEGER=2) is stored in little-endian byte order
;;;   on LE hosts (BN_bn2nativepad; OpenSSL crypto/params.c). Standard EC scalars are big-endian, so
;;;   the caller must reverse the scalar bytes before providing them as the UNSIGNED_INTEGER buffer.
;;; The public point (OCTET_STRING "pub") is passed as-is (no endian conversion needed).

(defconstant +evp-pkey-public-key+  #x86 "EVP_PKEY selection: public key + domain parameters (evp.h line 110).")
(defconstant +evp-pkey-keypair+     #x87 "EVP_PKEY selection: keypair (public + private + params) (evp.h line 112).")

(defun* ec-p256-import-private (scalar-octets point-octets)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              cffi:foreign-pointer)
  "Import a P-256 private key (KEYPAIR) from SCALAR-OCTETS (32 BE bytes, the scalar d) and
   POINT-OCTETS (65 bytes, uncompressed 0x04||X||Y). Returns EVP_PKEY* (caller MUST release
   via PKEY-FREE). The scalar is reversed to little-endian before passing to the UNSIGNED_INTEGER
   OSSL_PARAM (OpenSSL BN native byte order on LE hosts; core_dispatch.h + crypto/params.c).
   Uses EVP_PKEY_fromdata(KEYPAIR=0x87) (evp.h line 2079, OpenSSL 3.6.2). Signals on failure."
  (assert (= (length scalar-octets) 32))
  (assert (and (= (length point-octets) 65) (= (aref point-octets 0) #x04)))
  (cffi:with-foreign-pointer (scalar-le 32)
    (cffi:with-foreign-pointer (pub-ptr 65)
      (dotimes (i 32)
        (setf (cffi:mem-aref scalar-le :uint8 i) (aref scalar-octets (- 31 i))))
      (dotimes (i 65)
        (setf (cffi:mem-aref pub-ptr :uint8 i) (aref point-octets i)))
      (cffi:with-foreign-pointer (params (* 4 +ossl-param-size+))
        (cffi:with-foreign-string (p-group "group")
          (cffi:with-foreign-string (v-p256  "prime256v1")
            (cffi:with-foreign-string (p-priv  "priv")
              (cffi:with-foreign-string (p-pub   "pub")
                (%set-ossl-param-slot params 0 p-group +ossl-param-data-type-utf8-string+ v-p256 10)
                (%set-ossl-param-slot params 1 p-priv  +ossl-param-data-type-unsigned-integer+ scalar-le 32)
                (%set-ossl-param-slot params 2 p-pub   +ossl-param-data-type-octet-string+ pub-ptr 65)
                (%set-ossl-param-end  params 3)
                (let ((kctx (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_CTX_new_from_name") nil
                                                           :pointer (cffi:null-pointer)
                                                           :string "EC"
                                                           :pointer (cffi:null-pointer)
                                                           :pointer)))
                  (when (cffi:null-pointer-p kctx)
                    (error "EVP_PKEY_CTX_new_from_name(EC) returned NULL"))
                  (unwind-protect
                       (progn
                         (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_fromdata_init") nil
                                                                  :pointer kctx :int)))
                           (unless (= rc 1)
                             (error "EVP_PKEY_fromdata_init failed (rc=~a)" rc)))
                         (cffi:with-foreign-pointer (ppkey (cffi:foreign-type-size :pointer))
                           (setf (cffi:mem-ref ppkey :pointer) (cffi:null-pointer))
                           (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_fromdata") nil
                                                                    :pointer kctx
                                                                    :pointer ppkey
                                                                    :int +evp-pkey-keypair+
                                                                    :pointer params
                                                                    :int)))
                             (unless (= rc 1)
                               (%zeroize-foreign scalar-le 32)
                               (error "EVP_PKEY_fromdata(EC KEYPAIR) failed (rc=~a)" rc))
                             (%zeroize-foreign scalar-le 32)
                             (cffi:mem-ref ppkey :pointer))))
                    (%evp-pkey-ctx-free kctx)))))))))))

(defun* ec-p256-import-public (point-octets)
    (function ((simple-array (unsigned-byte 8) (*))) cffi:foreign-pointer)
  "Import a P-256 public key from POINT-OCTETS (65 bytes, uncompressed 0x04||X||Y).
   Returns EVP_PKEY* (caller MUST release via PKEY-FREE).
   Uses EVP_PKEY_fromdata(PUBLIC_KEY=0x86) with OSSL_PARAM 'pub' (OCTET_STRING).
   (evp.h line 2079, core_names.h, OpenSSL 3.6.2). Signals on failure."
  (assert (and (= (length point-octets) 65) (= (aref point-octets 0) #x04)))
  (cffi:with-foreign-pointer (pub-ptr 65)
    (dotimes (i 65)
      (setf (cffi:mem-aref pub-ptr :uint8 i) (aref point-octets i)))
    (cffi:with-foreign-pointer (params (* 3 +ossl-param-size+))
      (cffi:with-foreign-string (p-group "group")
        (cffi:with-foreign-string (v-p256  "prime256v1")
          (cffi:with-foreign-string (p-pub   "pub")
            (%set-ossl-param-slot params 0 p-group +ossl-param-data-type-utf8-string+ v-p256 10)
            (%set-ossl-param-slot params 1 p-pub   +ossl-param-data-type-octet-string+ pub-ptr 65)
            (%set-ossl-param-end  params 2)
            (let ((kctx (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_CTX_new_from_name") nil
                                                       :pointer (cffi:null-pointer)
                                                       :string "EC"
                                                       :pointer (cffi:null-pointer)
                                                       :pointer)))
              (when (cffi:null-pointer-p kctx)
                (error "EVP_PKEY_CTX_new_from_name(EC) returned NULL"))
              (unwind-protect
                   (progn
                     (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_fromdata_init") nil
                                                              :pointer kctx :int)))
                       (unless (= rc 1)
                         (error "EVP_PKEY_fromdata_init failed (rc=~a)" rc)))
                     (cffi:with-foreign-pointer (ppkey (cffi:foreign-type-size :pointer))
                       (setf (cffi:mem-ref ppkey :pointer) (cffi:null-pointer))
                       (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_fromdata") nil
                                                                :pointer kctx
                                                                :pointer ppkey
                                                                :int +evp-pkey-public-key+
                                                                :pointer params
                                                                :int)))
                         (unless (= rc 1)
                           (error "EVP_PKEY_fromdata(EC PUBLIC_KEY) failed (rc=~a)" rc))
                         (cffi:mem-ref ppkey :pointer))))
                (%evp-pkey-ctx-free kctx)))))))))

;;; EC P-256 ephemeral key generation for ECDH (DDS-Security 1.1 §9.3 ECDH+prime256v1-CEUM).
;;;
;;; OpenSSL 3.x OSSL_PARAM approach (EVP_PKEY_CTX_new_from_name + keygen_init +
;;;   EVP_PKEY_CTX_set_params(group="prime256v1") + EVP_PKEY_generate); evp.h, OpenSSL 3.6.2.
;;; dh1/dh2 wire format = the RAW UNCOMPRESSED EC point (0x04||X||Y), read via
;;;   EVP_PKEY_get_octet_string_param "pub" (default point format = uncompressed). This is the form
;;;   Fast DDS emits + parses for the EC suite (store_dh_public_key EC_POINT_point2oct(conv_form) /
;;;   generate_dh_peer_key o2i_ECPublicKey, PKIDH.cpp; DDS-Security 1.1 §9.3.2.1). NOT
;;;   SubjectPublicKeyInfo DER — Fast DDS rejects SPKI with "Cannot deserialize public key"
;;;   (PKIDH.cpp:858); WP-DDS-SECURITY-FASTDDS-INTEROP T4 cross-vendor fix.
;;; OSSL_PARAM "group" = OSSL_PKEY_PARAM_GROUP_NAME (core_names.h); data_size = strlen (no NUL).
;;; OSSL_PARAM "pub" = OSSL_PKEY_PARAM_PUB_KEY (core_names.h); EVP_PKEY_get_octet_string_param
;;;   (evp.h, OpenSSL >= 3.0) — NULL buf queries the required length, then fetches the point octets.

(defun* %evp-pkey-ec-pub-point (pkey)
    (function (cffi:foreign-pointer) (simple-array (unsigned-byte 8) (*)))
  "Return the raw uncompressed EC public point (0x04||X||Y) of EVP_PKEY* PKEY via the 'pub'
   octet-string param (default point format = uncompressed). The DDS-Security 1.1 §9.3.2.1 dh1/dh2
   EC wire form Fast DDS emits (EC_POINT_point2oct) + reads (o2i_ECPublicKey, PKIDH.cpp). Two-call
   EVP_PKEY_get_octet_string_param: NULL buf queries the length, then fetches. Does NOT free PKEY.
   Signals on failure."
  (cffi:with-foreign-pointer (outlen (cffi:foreign-type-size :size))
    (setf (cffi:mem-ref outlen :size) 0)
    (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_get_octet_string_param") nil
                                             :pointer pkey :string "pub"
                                             :pointer (cffi:null-pointer) :size 0
                                             :pointer outlen :int)))
      (unless (= rc 1) (error "EVP_PKEY_get_octet_string_param(pub size) failed (rc=~a)" rc)))
    (let ((plen (cffi:mem-ref outlen :size)))
      (cffi:with-foreign-pointer (pub-ptr plen)
        (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_get_octet_string_param") nil
                                                 :pointer pkey :string "pub"
                                                 :pointer pub-ptr :size plen
                                                 :pointer outlen :int)))
          (unless (= rc 1) (error "EVP_PKEY_get_octet_string_param(pub) failed (rc=~a)" rc)))
        (%foreign->octets pub-ptr (cffi:mem-ref outlen :size))))))

(defun* ecdh-gen-keypair ()
    (function () (values (simple-array (unsigned-byte 8) (*)) cffi:foreign-pointer))
  "Generate ephemeral EC P-256 key pair (DDS-Security 1.1 §9.3 ECDH+prime256v1-CEUM).
   Returns (values PUB-POINT PRIV-PKEY): PUB-POINT = the raw uncompressed EC point 0x04||X||Y
   (dh1/dh2 wire format Fast DDS emits/parses for the EC suite, §9.3.2.1; NOT SubjectPublicKeyInfo
   DER); PRIV-PKEY = EVP_PKEY* (caller MUST release via PKEY-FREE)."
  (let ((kctx (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_CTX_new_from_name") nil
                                             :pointer (cffi:null-pointer)
                                             :string "EC"
                                             :pointer (cffi:null-pointer)
                                             :pointer)))
    (when (cffi:null-pointer-p kctx)
      (error "EVP_PKEY_CTX_new_from_name(EC) returned NULL"))
    (unwind-protect
         (progn
           (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_keygen_init") nil
                                                    :pointer kctx :int)))
             (unless (= rc 1)
               (error "EVP_PKEY_keygen_init(EC) failed (rc=~a)" rc)))
           (cffi:with-foreign-pointer (params (* 2 +ossl-param-size+))
             (cffi:with-foreign-string (p-group "group")
               (cffi:with-foreign-string (v-p256 "prime256v1")
                 (%set-ossl-param-slot params 0 p-group
                                       +ossl-param-data-type-utf8-string+
                                       v-p256 (length "prime256v1"))
                 (%set-ossl-param-end params 1)
                 (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_CTX_set_params") nil
                                                          :pointer kctx :pointer params :int)))
                   (unless (= rc 1)
                     (error "EVP_PKEY_CTX_set_params(group=prime256v1) failed (rc=~a)" rc)))))
             (cffi:with-foreign-pointer (ppkey (cffi:foreign-type-size :pointer))
               (setf (cffi:mem-ref ppkey :pointer) (cffi:null-pointer))
               (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_generate") nil
                                                        :pointer kctx :pointer ppkey :int)))
                 (unless (= rc 1)
                   (error "EVP_PKEY_generate(EC P-256) failed (rc=~a)" rc)))
               (let ((pkey (cffi:mem-ref ppkey :pointer)))
                 ;; dh1/dh2 = raw uncompressed EC point 0x04||X||Y (Fast DDS o2i_ECPublicKey form,
                 ;; §9.3.2.1); free pkey if the point extraction signals.
                 (handler-case (values (%evp-pkey-ec-pub-point pkey) pkey)
                   (error (e) (%evp-pkey-free pkey) (error e)))))))
      (%evp-pkey-ctx-free kctx))))

;;; ECDH key agreement — EVP_PKEY_derive_init + EVP_PKEY_derive_set_peer + EVP_PKEY_derive.
;;; d2i_PUBKEY(EVP_PKEY **a, const unsigned char **pp, long length) -> EVP_PKEY* (x509.h).
;;; EVP_PKEY_derive_init(ctx) -> int (evp.h line 2127); _set_peer(ctx,peer) (evp.h line 2128).
;;; EVP_PKEY_derive(ctx, key, *keylen) -> int (evp.h line 2131); NULL key queries size.

(defun* %ecdh-import-peer-pub (peer-pub-octets)
    (function ((simple-array (unsigned-byte 8) (*))) cffi:foreign-pointer)
  "Import a peer ECDH public key as EVP_PKEY* (caller frees via %EVP-PKEY-FREE). Decode-tolerant:
   a 65-byte uncompressed EC point (0x04||X||Y — the DDS-Security 1.1 §9.3.2.1 dh1/dh2 EC wire form
   Fast DDS emits/parses, PKIDH.cpp store_dh_public_key/generate_dh_peer_key) is imported via
   EC-P256-IMPORT-PUBLIC; any other input is treated as SubjectPublicKeyInfo DER via d2i_PUBKEY (the
   RFC 5903 KAT form). Signals on malformed input. WP-DDS-SECURITY-FASTDDS-INTEROP T4 cross-vendor fix."
  (if (and (= (length peer-pub-octets) 65) (= (aref peer-pub-octets 0) #x04))
      (ec-p256-import-public peer-pub-octets)
      (let ((peer-n (length peer-pub-octets)))
        (cffi:with-foreign-pointer (peer-ptr peer-n)
          (dotimes (i peer-n)
            (setf (cffi:mem-aref peer-ptr :uint8 i) (aref peer-pub-octets i)))
          (cffi:with-foreign-pointer (pp (cffi:foreign-type-size :pointer))
            (setf (cffi:mem-ref pp :pointer) peer-ptr)
            (let ((peer-pkey (cffi:foreign-funcall-pointer (%ossl-sym "d2i_PUBKEY") nil
                                                            :pointer (cffi:null-pointer)
                                                            :pointer pp
                                                            :long peer-n
                                                            :pointer)))
              (when (cffi:null-pointer-p peer-pkey)
                (error "d2i_PUBKEY failed (malformed peer SubjectPublicKeyInfo DER)"))
              peer-pkey))))))

(defun* ecdh-compute (priv-handle peer-pub-octets)
    (function (cffi:foreign-pointer (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "ECDH key agreement: raw x-coordinate from PRIV-HANDLE (EVP_PKEY*) + PEER-PUB-OCTETS (the peer
   ephemeral EC public key). Decode-tolerant on PEER-PUB-OCTETS (see %ECDH-IMPORT-PEER-PUB): the
   65-byte uncompressed EC point 0x04||X||Y (the §9.3.2.1 dh1/dh2 wire form Fast DDS emits) OR
   SubjectPublicKeyInfo DER (RFC 5903 KAT). Returns the 32-byte raw ECDH agreed value; the derive
   buffer is zeroized. Caller must SHA-256(result) for DDS-Security 1.1 §9.3.3."
  (let ((peer-pkey (%ecdh-import-peer-pub peer-pub-octets)))
    (unwind-protect
         (let ((ctx (%evp-pkey-ctx-from-pkey priv-handle)))
           (unwind-protect
                (progn
                  (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_derive_init") nil
                                                           :pointer ctx :int)))
                    (unless (= rc 1)
                      (error "EVP_PKEY_derive_init failed (rc=~a)" rc)))
                  (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_derive_set_peer") nil
                                                           :pointer ctx :pointer peer-pkey :int)))
                    (unless (= rc 1)
                      (error "EVP_PKEY_derive_set_peer failed (rc=~a)" rc)))
                  (cffi:with-foreign-pointer (keylen-ptr (cffi:foreign-type-size :size))
                    (setf (cffi:mem-ref keylen-ptr :size) 0)
                    (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_derive") nil
                                                             :pointer ctx
                                                             :pointer (cffi:null-pointer)
                                                             :pointer keylen-ptr
                                                             :int)))
                      (unless (= rc 1)
                        (error "EVP_PKEY_derive(size-query) failed (rc=~a)" rc)))
                    (let ((klen (cffi:mem-ref keylen-ptr :size)))
                      (cffi:with-foreign-pointer (key-ptr klen)
                        (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_derive") nil
                                                                 :pointer ctx
                                                                 :pointer key-ptr
                                                                 :pointer keylen-ptr
                                                                 :int)))
                          (unless (= rc 1)
                            (%zeroize-foreign key-ptr klen)
                            (error "EVP_PKEY_derive failed (rc=~a)" rc)))
                        (let ((result (%foreign->octets key-ptr klen)))
                          (%zeroize-foreign key-ptr klen)
                          result)))))
             (%evp-pkey-ctx-free ctx)))
      (%evp-pkey-free peer-pkey))))

;;; ECDSA-SHA256 sign/verify via EVP_DigestSign/Verify API (evp.h, OpenSSL 3.6.2).
;;; EVP_MD_CTX_new / EVP_MD_CTX_free (evp.h); EVP_sha256() -> const EVP_MD* (evp.h).
;;; EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) -> int (evp.h).
;;; EVP_DigestSignUpdate(ctx, data, len) -> int (evp.h).
;;; EVP_DigestSignFinal(ctx, sig, &siglen) -> int (1=ok) (evp.h); NULL sig queries size.
;;; EVP_DigestVerifyFinal(ctx, sig, siglen) -> int (1=ok, 0=fail, <0=error) (evp.h).

(defun* ecdsa-sign (priv-handle data)
    (function (cffi:foreign-pointer (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "ECDSA-SHA256 sign: DER-encoded signature over DATA using PRIV-HANDLE (EVP_PKEY*).
   Uses EVP_DigestSignInit(SHA256)+Update+Final (evp.h, OpenSSL 3.6.2). Returns heap octet vector."
  (let* ((data-n (length data))
         (md-ctx (cffi:foreign-funcall-pointer (%ossl-sym "EVP_MD_CTX_new") nil :pointer)))
    (when (cffi:null-pointer-p md-ctx)
      (error "EVP_MD_CTX_new returned NULL"))
    (unwind-protect
         (progn
           (let ((sha256 (cffi:foreign-funcall-pointer (%ossl-sym "EVP_sha256") nil :pointer)))
             (when (cffi:null-pointer-p sha256)
               (error "EVP_sha256 returned NULL"))
             (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_DigestSignInit") nil
                                                      :pointer md-ctx
                                                      :pointer (cffi:null-pointer)
                                                      :pointer sha256
                                                      :pointer (cffi:null-pointer)
                                                      :pointer priv-handle
                                                      :int)))
               (unless (= rc 1)
                 (error "EVP_DigestSignInit failed (rc=~a)" rc))))
           (cffi:with-foreign-pointer (data-ptr (max 1 data-n))
             (dotimes (i data-n)
               (setf (cffi:mem-aref data-ptr :uint8 i) (aref data i)))
             (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_DigestSignUpdate") nil
                                                      :pointer md-ctx
                                                      :pointer data-ptr
                                                      :size data-n
                                                      :int)))
               (unless (= rc 1)
                 (error "EVP_DigestSignUpdate failed (rc=~a)" rc))))
           (cffi:with-foreign-pointer (siglen-ptr (cffi:foreign-type-size :size))
             (setf (cffi:mem-ref siglen-ptr :size) 0)
             (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_DigestSignFinal") nil
                                                      :pointer md-ctx
                                                      :pointer (cffi:null-pointer)
                                                      :pointer siglen-ptr
                                                      :int)))
               (unless (= rc 1)
                 (error "EVP_DigestSignFinal(size-query) failed (rc=~a)" rc)))
             (let ((max-siglen (cffi:mem-ref siglen-ptr :size)))
               (cffi:with-foreign-pointer (sig-ptr max-siglen)
                 (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_DigestSignFinal") nil
                                                          :pointer md-ctx
                                                          :pointer sig-ptr
                                                          :pointer siglen-ptr
                                                          :int)))
                   (unless (= rc 1)
                     (error "EVP_DigestSignFinal failed (rc=~a)" rc)))
                 ;; Re-read siglen-ptr: actual written length may be less than max-siglen
                 (let ((actual-siglen (cffi:mem-ref siglen-ptr :size)))
                   (%foreign->octets sig-ptr actual-siglen))))))
      (cffi:foreign-funcall-pointer (%ossl-sym "EVP_MD_CTX_free") nil :pointer md-ctx :void))))

(defun* ecdsa-verify (pub-handle data sig)
    (function (cffi:foreign-pointer
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              boolean)
  "ECDSA-SHA256 verify: T if SIG is valid over DATA under PUB-HANDLE (EVP_PKEY*).
   Uses EVP_DigestVerifyInit(SHA256)+Update+Final (evp.h, OpenSSL 3.6.2). Fail-closed: NIL on error."
  (let* ((data-n (length data))
         (sig-n  (length sig))
         (md-ctx (cffi:foreign-funcall-pointer (%ossl-sym "EVP_MD_CTX_new") nil :pointer)))
    (when (cffi:null-pointer-p md-ctx)
      (return-from ecdsa-verify nil))
    (unwind-protect
         (handler-case
             (progn
               (let ((sha256 (cffi:foreign-funcall-pointer (%ossl-sym "EVP_sha256") nil :pointer)))
                 (when (cffi:null-pointer-p sha256) (return-from ecdsa-verify nil))
                 (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_DigestVerifyInit") nil
                                                          :pointer md-ctx
                                                          :pointer (cffi:null-pointer)
                                                          :pointer sha256
                                                          :pointer (cffi:null-pointer)
                                                          :pointer pub-handle
                                                          :int)))
                   (unless (= rc 1) (return-from ecdsa-verify nil))))
               (cffi:with-foreign-pointer (data-ptr (max 1 data-n))
                 (dotimes (i data-n)
                   (setf (cffi:mem-aref data-ptr :uint8 i) (aref data i)))
                 (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_DigestVerifyUpdate") nil
                                                          :pointer md-ctx
                                                          :pointer data-ptr
                                                          :size data-n
                                                          :int)))
                   (unless (= rc 1) (return-from ecdsa-verify nil))))
               (cffi:with-foreign-pointer (sig-ptr (max 1 sig-n))
                 (dotimes (i sig-n)
                   (setf (cffi:mem-aref sig-ptr :uint8 i) (aref sig i)))
                 (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_DigestVerifyFinal") nil
                                                          :pointer md-ctx
                                                          :pointer sig-ptr
                                                          :size sig-n
                                                          :int)))
                   (= rc 1))))
           (error () nil))
      (cffi:foreign-funcall-pointer (%ossl-sym "EVP_MD_CTX_free") nil :pointer md-ctx :void))))

;;; FFDH MODP-2048 (DH+MODP-2048-256) key generation and key agreement.
;;;
;;; OpenSSL approach: EVP_PKEY_CTX_new_from_name(NULL,"DH",NULL) + fromdata(KEY_PARAMETERS) to
;;; import p/g, then EVP_PKEY_CTX_new(tmpl,NULL) + keygen to produce a private key + public value.
;;; Agreement: EVP_PKEY_derive (raw DH output, 256 bytes for 2048-bit group). Caller SHA-256s it.
;;;
;;; Wire encoding of dh1/dh2: SubjectPublicKeyInfo DER via i2d_PUBKEY (same as ECDH — see Fast DDS
;;; PKIDH.cpp which uses i2d_PUBKEY for both ECDH and FFDH). On import, d2i_PUBKEY recovers the key.
;;;
;;; OSSL_PARAM names for DH (verified against /opt/homebrew/opt/openssl@3/include/openssl/core_names.h
;;; OpenSSL 3.6.2 7 Apr 2026):
;;;   OSSL_PKEY_PARAM_FFC_P = "p"  (core_names.h)
;;;   OSSL_PKEY_PARAM_FFC_G = "g"  (core_names.h)
;;; EVP_PKEY_KEY_PARAMETERS selection = 0x01 (evp.h line 104).
;;; BN parameters use OSSL_PARAM_UNSIGNED_INTEGER = 2 (core.h line 107, OpenSSL 3.6.2).

(defconstant +evp-pkey-key-parameters+ 1
  "EVP_PKEY selection flag: domain parameters only (evp.h line 104, OpenSSL 3.6.2).")
;;; OSSL_PARAM_UNSIGNED_INTEGER = 2 (core.h line 103, OpenSSL 3.6.2) — same as existing
;;; +ossl-param-data-type-unsigned-integer+ = 2 defined in openssl-ffi.lisp.
;;; Alias used here for clarity in the DH/RSA fromdata context.

(defun* %dh-build-params-pkey (p-octets g-octets)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (or cffi:foreign-pointer null))
  "Import MODP-2048 (p,g) parameters via EVP_PKEY_fromdata(KEY_PARAMETERS,'DH') from big-endian BN.
   Returns an EVP_PKEY* parameter template or NIL on failure (caller must release via %EVP-PKEY-FREE)."
  (let* ((p-n (length p-octets))
         (g-n (length g-octets)))
    (cffi:with-foreign-pointer (p-ptr p-n)
      (cffi:with-foreign-pointer (g-ptr g-n)
        (dotimes (i p-n)
          (setf (cffi:mem-aref p-ptr :uint8 i) (aref p-octets i)))
        (dotimes (i g-n)
          (setf (cffi:mem-aref g-ptr :uint8 i) (aref g-octets i)))
        (cffi:with-foreign-pointer (params (* 3 +ossl-param-size+))
          (cffi:with-foreign-string (pname "p")
            (cffi:with-foreign-string (gname "g")
              (%set-ossl-param-slot params 0 pname +ossl-param-data-type-unsigned-integer+ p-ptr p-n)
              (%set-ossl-param-slot params 1 gname +ossl-param-data-type-unsigned-integer+ g-ptr g-n)
              (%set-ossl-param-end  params 2)
              (let ((kctx (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_CTX_new_from_name") nil
                                                         :pointer (cffi:null-pointer)
                                                         :string "DH"
                                                         :pointer (cffi:null-pointer)
                                                         :pointer)))
                (when (cffi:null-pointer-p kctx)
                  (return-from %dh-build-params-pkey nil))
                (unwind-protect
                     (progn
                       (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_fromdata_init") nil
                                                                :pointer kctx :int)))
                         (unless (= rc 1)
                           (return-from %dh-build-params-pkey nil)))
                       (cffi:with-foreign-pointer (ppkey (cffi:foreign-type-size :pointer))
                         (setf (cffi:mem-ref ppkey :pointer) (cffi:null-pointer))
                         (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_fromdata") nil
                                                                  :pointer kctx
                                                                  :pointer ppkey
                                                                  :int +evp-pkey-key-parameters+
                                                                  :pointer params
                                                                  :int)))
                           (if (= rc 1)
                               (cffi:mem-ref ppkey :pointer)
                               nil))))
                  (%evp-pkey-ctx-free kctx))))))))))

(defun* ffdh-gen-keypair (p-octets g-octets)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (values (simple-array (unsigned-byte 8) (*)) cffi:foreign-pointer))
  "Generate ephemeral FFDH key pair over the group defined by P-OCTETS and G-OCTETS (big-endian BN).
   Returns (values PUB-DER PRIV-PKEY): PUB-DER = SubjectPublicKeyInfo DER (dh1/dh2 wire encoding,
   per Fast DDS PKIDH.cpp i2d_PUBKEY); PRIV-PKEY = EVP_PKEY* (caller MUST release via PKEY-FREE).
   Designed for DH+MODP-2048-256 (DDS-Security 1.1 §9.3, RFC 3526 §3 Group 14)."
  (let ((tmpl (%dh-build-params-pkey p-octets g-octets)))
    (unless tmpl (error "ffdh-gen-keypair: failed to build DH parameter template"))
    (unwind-protect
         (let ((gctx (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_CTX_new") nil
                                                    :pointer tmpl
                                                    :pointer (cffi:null-pointer)
                                                    :pointer)))
           (when (cffi:null-pointer-p gctx)
             (error "ffdh-gen-keypair: EVP_PKEY_CTX_new returned NULL"))
           (unwind-protect
                (progn
                  (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_keygen_init") nil
                                                           :pointer gctx :int)))
                    (unless (= rc 1)
                      (error "ffdh-gen-keypair: EVP_PKEY_keygen_init failed (rc=~a)" rc)))
                  (cffi:with-foreign-pointer (ppkey (cffi:foreign-type-size :pointer))
                    (setf (cffi:mem-ref ppkey :pointer) (cffi:null-pointer))
                    (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_keygen") nil
                                                             :pointer gctx :pointer ppkey :int)))
                      (unless (= rc 1)
                        (error "ffdh-gen-keypair: EVP_PKEY_keygen failed (rc=~a)" rc)))
                    (let ((pkey (cffi:mem-ref ppkey :pointer)))
                      (cffi:with-foreign-pointer (pp (cffi:foreign-type-size :pointer))
                        (setf (cffi:mem-ref pp :pointer) (cffi:null-pointer))
                        (let ((derlen (cffi:foreign-funcall-pointer (%ossl-sym "i2d_PUBKEY") nil
                                                                     :pointer pkey :pointer pp :int)))
                          (when (< derlen 0)
                            (%evp-pkey-free pkey)
                            (error "ffdh-gen-keypair: i2d_PUBKEY failed (rc=~a)" derlen))
                          (let ((der-ptr (cffi:mem-ref pp :pointer)))
                            (unwind-protect
                                 (let ((pub (%foreign->octets der-ptr derlen)))
                                   (values pub pkey))
                              (cffi:foreign-funcall-pointer (%ossl-sym "CRYPTO_free") nil
                                                            :pointer der-ptr
                                                            :pointer (cffi:null-pointer)
                                                            :int 0
                                                            :void))))))))
             (%evp-pkey-ctx-free gctx)))
      (%evp-pkey-free tmpl))))

(defun* ffdh-compute (priv-handle peer-pub-octets)
    (function (cffi:foreign-pointer (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "FFDH key agreement: raw DH agreed value from PRIV-HANDLE (EVP_PKEY*) + PEER-PUB-OCTETS (SPKI DER).
   PEER-PUB-OCTETS is SubjectPublicKeyInfo DER (dh2 from wire); imported via d2i_PUBKEY (x509.h).
   Returns the raw DH output (256 bytes for MODP-2048). Caller MUST SHA-256 it per DDS-Security §9.3.3.
   Wire encoding: SubjectPublicKeyInfo DER (i2d_PUBKEY), consistent with ECDH dh1/dh2 encoding."
  (let ((peer-n (length peer-pub-octets)))
    (cffi:with-foreign-pointer (peer-ptr peer-n)
      (dotimes (i peer-n)
        (setf (cffi:mem-aref peer-ptr :uint8 i) (aref peer-pub-octets i)))
      (cffi:with-foreign-pointer (pp (cffi:foreign-type-size :pointer))
        (setf (cffi:mem-ref pp :pointer) peer-ptr)
        (let ((peer-pkey (cffi:foreign-funcall-pointer (%ossl-sym "d2i_PUBKEY") nil
                                                        :pointer (cffi:null-pointer)
                                                        :pointer pp
                                                        :long peer-n
                                                        :pointer)))
          (when (cffi:null-pointer-p peer-pkey)
            (error "ffdh-compute: d2i_PUBKEY failed (malformed DH SubjectPublicKeyInfo DER)"))
          (unwind-protect
               (let ((ctx (%evp-pkey-ctx-from-pkey priv-handle)))
                 (unwind-protect
                      (progn
                        (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_derive_init") nil
                                                                 :pointer ctx :int)))
                          (unless (= rc 1)
                            (error "ffdh-compute: EVP_PKEY_derive_init failed (rc=~a)" rc)))
                        (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_derive_set_peer") nil
                                                                 :pointer ctx :pointer peer-pkey :int)))
                          (unless (= rc 1)
                            (error "ffdh-compute: EVP_PKEY_derive_set_peer failed (rc=~a)" rc)))
                        (cffi:with-foreign-pointer (keylen-ptr (cffi:foreign-type-size :size))
                          (setf (cffi:mem-ref keylen-ptr :size) 0)
                          (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_derive") nil
                                                                   :pointer ctx
                                                                   :pointer (cffi:null-pointer)
                                                                   :pointer keylen-ptr
                                                                   :int)))
                            (unless (= rc 1)
                              (error "ffdh-compute: EVP_PKEY_derive(size-query) failed (rc=~a)" rc)))
                          (let ((klen (cffi:mem-ref keylen-ptr :size)))
                            (cffi:with-foreign-pointer (key-ptr klen)
                              (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_derive") nil
                                                                       :pointer ctx
                                                                       :pointer key-ptr
                                                                       :pointer keylen-ptr
                                                                       :int)))
                                (unless (= rc 1)
                                  (%zeroize-foreign key-ptr klen)
                                  (error "ffdh-compute: EVP_PKEY_derive failed (rc=~a)" rc)))
                              (let ((result (%foreign->octets key-ptr klen)))
                                (%zeroize-foreign key-ptr klen)
                                result)))))
                   (%evp-pkey-ctx-free ctx)))
            (%evp-pkey-free peer-pkey)))))))

;;; RSA-PSS-SHA256 sign/verify via EVP_DigestSignInit_ex / EVP_DigestVerifyInit_ex (OpenSSL 3.x).
;;;
;;; Signatures verified against /opt/homebrew/opt/openssl@3/include/openssl/evp.h (OpenSSL 3.6.2):
;;;   EVP_DigestSignInit_ex(ctx, **pctx, mdname, libctx, props, pkey,
;;;                         const OSSL_PARAM params[]) -> int (evp.h)
;;;   EVP_DigestVerifyInit_ex(ctx, **pctx, mdname, libctx, props, pkey,
;;;                           const OSSL_PARAM params[]) -> int (evp.h)
;;;   EVP_DigestSignUpdate / EVP_DigestVerifyUpdate: same as ECDSA (reused).
;;;   EVP_DigestSignFinal / EVP_DigestVerifyFinal: same as ECDSA (reused).
;;;
;;; PSS params passed via OSSL_PARAM array (verified against core_names.h, OpenSSL 3.6.2):
;;;   OSSL_PKEY_PARAM_PAD_MODE    = "pad-mode"      value = "pss" (OSSL_PKEY_RSA_PAD_MODE_PSS)
;;;   OSSL_PKEY_PARAM_MGF1_DIGEST = "mgf1-digest"   value = "SHA256"
;;;   OSSL_PKEY_PARAM_RSA_PSS_SALTLEN = "saltlen"   value = 32 (integer; hash length; §9.3 / Fast DDS)
;;;
;;; The saltlen=32 (digest length) matches Fast DDS usage of RSA_PSS_SALTLEN_DIGEST; the OMG spec
;;; cites MGF1-SHA256 but does not mandate a specific salt length (Fast DDS spike §10 item 6).
;;; Using saltlen=32 (= SHA-256 output length) for interoperability with Fast DDS.
;;;
;;; Wycheproof KAT source: https://raw.githubusercontent.com/google/wycheproof/master/testvectors_v1/
;;;   rsa_pss_2048_sha256_mgf1_32_test.json (fetched 2026-06-24)
;;;   tcId=1: msg="" (empty), sig=4f01e0c1..., result=valid
;;;   tcId=62: msg=313233343030, sig=67d1d1c0..., result=invalid

(defconstant +rsa-pss-salt-len+ 32
  "RSASSA-PSS salt length = SHA-256 digest length (32 bytes) per Fast DDS and DDS-Security 1.1 §9.3.")

(defun* rsa-pss-sign (priv-handle data)
    (function (cffi:foreign-pointer (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "RSASSA-PSS-SHA256 sign: signature over DATA using PRIV-HANDLE (EVP_PKEY*).
   Uses EVP_DigestSignInit_ex(SHA256, pad-mode=pss, mgf1-digest=SHA256, saltlen=32)
   + Update + Final (evp.h, OpenSSL 3.6.2; core_names.h param names verified).
   Returns raw RSA signature octet vector (256 bytes for RSA-2048). Signals on error.
   Source: DDS-Security 1.1 §9.3 RSASSA-PSS-SHA256; Fast DDS PKIDH.cpp RSA_PSS_SALTLEN_DIGEST."
  (let* ((data-n (length data))
         (md-ctx (cffi:foreign-funcall-pointer (%ossl-sym "EVP_MD_CTX_new") nil :pointer)))
    (when (cffi:null-pointer-p md-ctx)
      (error "rsa-pss-sign: EVP_MD_CTX_new returned NULL"))
    (unwind-protect
         (progn
           (cffi:with-foreign-pointer (saltlen-ptr (cffi:foreign-type-size :int))
             (setf (cffi:mem-ref saltlen-ptr :int) +rsa-pss-salt-len+)
             (cffi:with-foreign-pointer (params-buf (* 4 +ossl-param-size+))
               (cffi:with-foreign-string (v-pss "pss")
                 (cffi:with-foreign-string (v-sha256 "SHA256")
                   (cffi:with-foreign-string (k-padmode "pad-mode")
                     (cffi:with-foreign-string (k-mgf1 "mgf1-digest")
                       (cffi:with-foreign-string (k-saltlen "saltlen")
                         (%set-ossl-param-slot params-buf 0 k-padmode
                                               +ossl-param-data-type-utf8-string+
                                               v-pss (length "pss"))
                         (%set-ossl-param-slot params-buf 1 k-mgf1
                                               +ossl-param-data-type-utf8-string+
                                               v-sha256 (length "SHA256"))
                         (%set-ossl-param-slot params-buf 2 k-saltlen
                                               +ossl-param-data-type-integer+
                                               saltlen-ptr (cffi:foreign-type-size :int))
                         (%set-ossl-param-end params-buf 3)
                         (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_DigestSignInit_ex") nil
                                                                  :pointer md-ctx
                                                                  :pointer (cffi:null-pointer)
                                                                  :string "SHA256"
                                                                  :pointer (cffi:null-pointer)
                                                                  :pointer (cffi:null-pointer)
                                                                  :pointer priv-handle
                                                                  :pointer params-buf
                                                                  :int)))
                           (unless (= rc 1)
                             (error "rsa-pss-sign: EVP_DigestSignInit_ex failed (rc=~a)" rc))))))))))
           (cffi:with-foreign-pointer (data-ptr (max 1 data-n))
             (dotimes (i data-n)
               (setf (cffi:mem-aref data-ptr :uint8 i) (aref data i)))
             (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_DigestSignUpdate") nil
                                                      :pointer md-ctx
                                                      :pointer data-ptr
                                                      :size data-n
                                                      :int)))
               (unless (= rc 1)
                 (error "rsa-pss-sign: EVP_DigestSignUpdate failed (rc=~a)" rc))))
           (cffi:with-foreign-pointer (siglen-ptr (cffi:foreign-type-size :size))
             (setf (cffi:mem-ref siglen-ptr :size) 0)
             (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_DigestSignFinal") nil
                                                      :pointer md-ctx
                                                      :pointer (cffi:null-pointer)
                                                      :pointer siglen-ptr
                                                      :int)))
               (unless (= rc 1)
                 (error "rsa-pss-sign: EVP_DigestSignFinal(size-query) failed (rc=~a)" rc)))
             (let ((max-siglen (cffi:mem-ref siglen-ptr :size)))
               (cffi:with-foreign-pointer (sig-ptr max-siglen)
                 (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_DigestSignFinal") nil
                                                          :pointer md-ctx
                                                          :pointer sig-ptr
                                                          :pointer siglen-ptr
                                                          :int)))
                   (unless (= rc 1)
                     (error "rsa-pss-sign: EVP_DigestSignFinal failed (rc=~a)" rc)))
                 (let ((actual-siglen (cffi:mem-ref siglen-ptr :size)))
                   (%foreign->octets sig-ptr actual-siglen))))))
      (cffi:foreign-funcall-pointer (%ossl-sym "EVP_MD_CTX_free") nil :pointer md-ctx :void))))

(defun* rsa-pss-verify (pub-handle data sig)
    (function (cffi:foreign-pointer
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              boolean)
  "RSASSA-PSS-SHA256 verify: T if SIG is valid over DATA under PUB-HANDLE (EVP_PKEY*).
   Uses EVP_DigestVerifyInit_ex(SHA256, pad-mode=pss, mgf1-digest=SHA256, saltlen=32)
   + Update + Final (evp.h, OpenSSL 3.6.2; core_names.h param names verified).
   Fail-closed: returns NIL on any error or verification failure (never signals).
   Source: DDS-Security 1.1 §9.3 RSASSA-PSS-SHA256; Fast DDS PKIDH.cpp RSA_PSS_SALTLEN_DIGEST.
   KAT: Wycheproof rsa_pss_2048_sha256_mgf1_32_test.json tcId=1 (valid) + tcId=62 (invalid);
        fetched from raw.githubusercontent.com/google/wycheproof/master/testvectors_v1/ 2026-06-24."
  (let* ((data-n (length data))
         (sig-n  (length sig))
         (md-ctx (cffi:foreign-funcall-pointer (%ossl-sym "EVP_MD_CTX_new") nil :pointer)))
    (when (cffi:null-pointer-p md-ctx)
      (return-from rsa-pss-verify nil))
    (unwind-protect
         (handler-case
             (progn
               (cffi:with-foreign-pointer (saltlen-ptr (cffi:foreign-type-size :int))
                 (setf (cffi:mem-ref saltlen-ptr :int) +rsa-pss-salt-len+)
                 (cffi:with-foreign-pointer (params-buf (* 4 +ossl-param-size+))
                   (cffi:with-foreign-string (v-pss "pss")
                     (cffi:with-foreign-string (v-sha256 "SHA256")
                       (cffi:with-foreign-string (k-padmode "pad-mode")
                         (cffi:with-foreign-string (k-mgf1 "mgf1-digest")
                           (cffi:with-foreign-string (k-saltlen "saltlen")
                             (%set-ossl-param-slot params-buf 0 k-padmode
                                                   +ossl-param-data-type-utf8-string+
                                                   v-pss (length "pss"))
                             (%set-ossl-param-slot params-buf 1 k-mgf1
                                                   +ossl-param-data-type-utf8-string+
                                                   v-sha256 (length "SHA256"))
                             (%set-ossl-param-slot params-buf 2 k-saltlen
                                                   +ossl-param-data-type-integer+
                                                   saltlen-ptr (cffi:foreign-type-size :int))
                             (%set-ossl-param-end params-buf 3)
                             (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_DigestVerifyInit_ex") nil
                                                                      :pointer md-ctx
                                                                      :pointer (cffi:null-pointer)
                                                                      :string "SHA256"
                                                                      :pointer (cffi:null-pointer)
                                                                      :pointer (cffi:null-pointer)
                                                                      :pointer pub-handle
                                                                      :pointer params-buf
                                                                      :int)))
                               (unless (= rc 1) (return-from rsa-pss-verify nil))))))))))
               (cffi:with-foreign-pointer (data-ptr (max 1 data-n))
                 (dotimes (i data-n)
                   (setf (cffi:mem-aref data-ptr :uint8 i) (aref data i)))
                 (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "EVP_DigestVerifyUpdate") nil
                                                          :pointer md-ctx
                                                          :pointer data-ptr
                                                          :size data-n
                                                          :int)))
                   (unless (= rc 1) (return-from rsa-pss-verify nil))))
               (cffi:with-foreign-pointer (sig-ptr (max 1 sig-n))
                 (dotimes (i sig-n)
                   (setf (cffi:mem-aref sig-ptr :uint8 i) (aref sig i)))
                 (= 1 (cffi:foreign-funcall-pointer (%ossl-sym "EVP_DigestVerifyFinal") nil
                                                     :pointer md-ctx
                                                     :pointer sig-ptr
                                                     :size sig-n
                                                     :int))))
           (error () nil))
      (cffi:foreign-funcall-pointer (%ossl-sym "EVP_MD_CTX_free") nil :pointer md-ctx :void))))

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
