(in-package #:dds.security)

;;; DDS-Security 1.1 §8.7.2.4 three-message PKI-DH handshake state machine.
;;; Messages: HandshakeRequestMessageToken -> HandshakeReplyMessageToken -> HandshakeFinalMessageToken.
;;; Token format: internal tagged binary (not CDR DataHolder wire format — in-process transport only).
;;; CDR BIG-ENDIAN BinaryPropertySeq used for hash_c1/hash_c2 + signature inputs (§9.3.2.2/§9.3.2.3).

;;; --- CDR big-endian helpers for BinaryPropertySeq (hash and signature inputs) ---
;;; Per Fast DDS PKIDH.cpp: signature inputs + hash inputs use big-endian CDR BinaryPropertySeq.
;;; BinaryProperty CDR layout (big-endian):
;;;   name: uint32-BE(strlen+1) || ascii-bytes || NUL || pad-to-4-bytes
;;;   value: uint32-BE(count) || bytes (octet sequence, no post-pad)
;;;   propagate: 1 byte (=1) || 3 pad bytes
;;; BinaryPropertySeq: uint32-BE(count) || BinaryProperty* (§9.3.2.2/§9.3.2.3)

(defun* %cdr-u32-be (v)
    (function ((unsigned-byte 32)) (simple-array (unsigned-byte 8) (4)))
  "Encode V as 4-byte big-endian uint32."
  (make-array 4 :element-type '(unsigned-byte 8)
                :initial-contents (list (ldb (byte 8 24) v)
                                        (ldb (byte 8 16) v)
                                        (ldb (byte 8  8) v)
                                        (ldb (byte 8  0) v))))

(defun* %cdr-string-be (s)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Encode string S as CDR BE string: uint32-BE(strlen+1) || ascii-bytes || NUL || pad-to-4."
  (let* ((bytes (map '(simple-array (unsigned-byte 8) (*)) #'char-code s))
         (n (length bytes))
         (total (1+ n))
         (pad (mod (- 4 (mod total 4)) 4))
         (out (make-array (+ 4 total pad) :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref out 0) (ldb (byte 8 24) total)
          (aref out 1) (ldb (byte 8 16) total)
          (aref out 2) (ldb (byte 8  8) total)
          (aref out 3) (ldb (byte 8  0) total))
    (dotimes (i n)
      (setf (aref out (+ 4 i)) (aref bytes i)))
    out))

(defun* %cdr-octet-seq-be (value-octets)
    (function ((simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Encode VALUE-OCTETS as CDR BE octet-sequence: uint32-BE(count) || bytes."
  (let* ((n (length value-octets))
         (out (make-array (+ 4 n) :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref out 0) (ldb (byte 8 24) n)
          (aref out 1) (ldb (byte 8 16) n)
          (aref out 2) (ldb (byte 8  8) n)
          (aref out 3) (ldb (byte 8  0) n))
    (dotimes (i n)
      (setf (aref out (+ 4 i)) (aref value-octets i)))
    out))

(defun* %cdr-binary-property-be (name value-octets)
    (function (string (simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Serialize CDR BE BinaryProperty: name(string-BE) + value(octet-seq-BE) + propagate(1)+3pad."
  (%concat-octets (%cdr-string-be name)
                  (%cdr-octet-seq-be value-octets)
                  (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(1 0 0 0))))

(defun* %build-cdr-binary-property-seq-be (property-pairs)
    (function (list) (simple-array (unsigned-byte 8) (*)))
  "Serialize PROPERTY-PAIRS ((name-string . value-octets)*) as CDR BE BinaryPropertySeq.
   Layout: uint32-BE(count) | BinaryProperty* — used for hash_c1/hash_c2 and sig inputs (§9.3.2)."
  (let ((count (length property-pairs)))
    (apply #'%concat-octets
           (%cdr-u32-be count)
           (mapcar (lambda (pair) (%cdr-binary-property-be (car pair) (cdr pair)))
                   property-pairs))))

;;; --- Internal token tagged format (in-process only; NOT CDR DataHolder wire format) ---
;;; Magic: #xD0 #xDD #x53 #x70 | uint32-LE(class-id-len) | class-id-bytes
;;; | uint32-LE(prop-count) | foreach: uint32-LE(name-len) | name-bytes | uint32-LE(val-len) | val-bytes

(defconstant +token-magic-0+ #xD0)
(defconstant +token-magic-1+ #xDD)
(defconstant +token-magic-2+ #x53)
(defconstant +token-magic-3+ #x70)

(defstruct* (handshake-token (:constructor %make-handshake-token))
  "Internal DDS-Security HandshakeMessageToken (§8.7.2.4 / §9.3.2), in-process only.
   class-id: token class_id string (§9.3.1 table). binary-props: (name . octets) alist in wire order."
  (class-id "" :type string)
  (binary-props '() :type list))

(defun* %serialize-token (tok)
    (function (handshake-token) (simple-array (unsigned-byte 8) (*)))
  "Serialize a handshake-token to the internal tagged octet format (in-process only)."
  (let* ((cid-bytes (map '(simple-array (unsigned-byte 8) (*)) #'char-code
                          (handshake-token-class-id tok)))
         (props (handshake-token-binary-props tok))
         (cid-n (length cid-bytes))
         (count (length props))
         (magic (make-array 4 :element-type '(unsigned-byte 8)
                               :initial-contents (list +token-magic-0+ +token-magic-1+
                                                       +token-magic-2+ +token-magic-3+)))
         ;; parts accumulates in forward output order; collect as list, apply %concat-octets
         (parts (list magic (%cdr-u32-le cid-n) cid-bytes (%cdr-u32-le count))))
    (dolist (pair props)
      (let* ((name-bytes (map '(simple-array (unsigned-byte 8) (*)) #'char-code (car pair)))
             (val-bytes  (cdr pair)))
        ;; append in forward order: name-len name-bytes val-len val-bytes
        (setf parts (nconc parts
                           (list (%cdr-u32-le (length name-bytes))
                                 name-bytes
                                 (%cdr-u32-le (length val-bytes))
                                 val-bytes)))))
    (apply #'%concat-octets parts)))

(defun* %parse-token (octets)
    (function ((simple-array (unsigned-byte 8) (*))) (or handshake-token null))
  "Parse a handshake-token from the internal tagged format. Returns NIL on malformed input.
   Bounds-checks every length before trusting wire data (NFR-SEC-POSTURE; fail-closed)."
  (handler-case
      (let ((n (length octets))
            (pos 0))
        (labels ((ensure (need)
                   (when (> (+ pos need) n) (error "truncated")))
                 (read-u32-le ()
                   (ensure 4)
                   (let ((v (logior (aref octets pos)
                                    (ash (aref octets (+ pos 1))  8)
                                    (ash (aref octets (+ pos 2)) 16)
                                    (ash (aref octets (+ pos 3)) 24))))
                     (incf pos 4)
                     v))
                 (read-bytes (len)
                   (ensure len)
                   (let ((v (make-array len :element-type '(unsigned-byte 8))))
                     (dotimes (i len)
                       (setf (aref v i) (aref octets (+ pos i))))
                     (incf pos len)
                     v)))
          (ensure 4)
          (unless (and (= (aref octets 0) +token-magic-0+)
                       (= (aref octets 1) +token-magic-1+)
                       (= (aref octets 2) +token-magic-2+)
                       (= (aref octets 3) +token-magic-3+))
            (error "bad magic"))
          (incf pos 4)
          (let* ((cid-n   (read-u32-le))
                 (dummy1  (when (> cid-n 65536) (error "class-id too long")))
                 (cid-v   (read-bytes cid-n))
                 (class-id (map 'string #'code-char cid-v))
                 (count   (read-u32-le))
                 (dummy2  (when (> count 256) (error "too many props")))
                 (props   nil))
            (declare (ignore dummy1 dummy2))
            (dotimes (i count)
              (declare (ignore i))
              (let* ((name-n  (read-u32-le))
                     (dummy3  (when (> name-n 65536) (error "name too long")))
                     (name-v  (read-bytes name-n))
                     (name    (map 'string #'code-char name-v))
                     (val-n   (read-u32-le))
                     (dummy4  (when (> val-n #x1000000) (error "value too long")))
                     (val     (read-bytes val-n)))
                (declare (ignore dummy3 dummy4))
                (push (cons name val) props)))
            (%make-handshake-token :class-id class-id
                                   :binary-props (nreverse props)))))
    (error () nil)))

(defun* %token-get (tok name)
    (function (handshake-token string) (or (simple-array (unsigned-byte 8) (*)) null))
  "Lookup binary property NAME in TOK; return its value octets or NIL if not present."
  (let ((pair (find name (handshake-token-binary-props tok) :key #'car :test #'string=)))
    (if pair (cdr pair) nil)))

;;; --- random nonce generation (delegates to dds.dare:random-bytes) ---

(defun* %random-bytes (n)
    (function ((unsigned-byte 32)) (simple-array (unsigned-byte 8) (*)))
  "Generate N cryptographically random bytes via dds.dare:random-bytes (RAND_bytes, OpenSSL 3.6.2)."
  (dds.dare:random-bytes n))

;;; --- SharedSecretHandle ---

(defstruct* (shared-secret-handle (:constructor %make-shared-secret-handle))
  "DDS-Security §9.3.3 SharedSecretHandle: SHA-256(ECDH-agreed-value) + challenges.
   secret-bytes: foreign-backed 32-byte secret (MUST free via FREE-SHARED-SECRET-HANDLE).
   challenge1/challenge2 are plain heap vectors (nonces are not secret)."
  (secret-bytes     (make-array 32 :element-type '(unsigned-byte 8))
                    :type (simple-array (unsigned-byte 8) (32)))
  (challenge1-bytes (make-array 32 :element-type '(unsigned-byte 8))
                    :type (simple-array (unsigned-byte 8) (32)))
  (challenge2-bytes (make-array 32 :element-type '(unsigned-byte 8))
                    :type (simple-array (unsigned-byte 8) (32))))

(defun* shared-secret-bytes (handle)
    (function (shared-secret-handle) (simple-array (unsigned-byte 8) (32)))
  "Return the 32-byte SharedSecret from HANDLE (SHA-256(ECDH-agreed-value), §9.3.3)."
  (shared-secret-handle-secret-bytes handle))

(defun* free-shared-secret-handle (handle)
    (function ((or shared-secret-handle null)) t)
  "Zeroize and free the foreign-backed secret in HANDLE. Idempotent: NIL is a no-op."
  (when handle
    (dds.dare:free-secret-octets (shared-secret-handle-secret-bytes handle)))
  t)

;;; --- hash_c computation (DDS-Security 1.1 §9.3.2) ---

(defun* %ascii->octets (s)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Convert ASCII string S to raw octets (for c.dsign_algo / c.kagree_algo binary property values)."
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code s))

(defun* %compute-hash-c (suite cert-der perm-octets pdata dsign-algo-str kagree-algo-str)
    (function (auth-suite
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               string string)
              (simple-array (unsigned-byte 8) (32)))
  "Compute hash_c1 or hash_c2: SHA-256(CDR-BE-BinaryPropertySeq(c.id,c.perm,c.pdata,c.dsign,c.kagree)).
   Per DDS-Security 1.1 §9.3.2.1 — all 5 c.* properties in this exact order."
  (let* ((hash-fn (auth-suite-hash suite))
         (seq (%build-cdr-binary-property-seq-be
               (list (cons +prop-c-id+          cert-der)
                     (cons +prop-c-perm+         perm-octets)
                     (cons +prop-c-pdata+        pdata)
                     (cons +prop-c-dsign-algo+   (%ascii->octets dsign-algo-str))
                     (cons +prop-c-kagree-algo+  (%ascii->octets kagree-algo-str))))))
    (let ((result (funcall hash-fn seq)))
      (make-array 32 :element-type '(unsigned-byte 8)
                     :initial-contents (coerce result 'list)))))

;;; --- SharedSecret derivation (DDS-Security 1.1 §9.3.3) ---

(defun* %derive-shared-secret (suite priv-handle peer-pub-octets challenge1 challenge2)
    (function (auth-suite cffi:foreign-pointer
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (32))
               (simple-array (unsigned-byte 8) (32)))
              shared-secret-handle)
  "Compute SharedSecret = SHA-256(ECDH-agreed-value) into a foreign-backed buffer (§9.3.3).
   Zeroizes the raw ECDH output before returning. Returns a fresh shared-secret-handle."
  (let* ((raw    (funcall (auth-suite-kagree-compute suite) priv-handle peer-pub-octets))
         (sha-fn (auth-suite-hash suite))
         (hashed (funcall sha-fn raw))
         (secret (dds.pal:alloc-static 32)))
    (dotimes (i 32)
      (setf (aref secret i) (aref hashed i)))
    (fill raw 0)
    (fill hashed 0)
    (%make-shared-secret-handle :secret-bytes secret
                                :challenge1-bytes challenge1
                                :challenge2-bytes challenge2)))

;;; --- stub c.pdata (Slice 2a: 4-byte CDR stub; full PBDTD in Slice 2b) ---

(defconstant +pdata-stub+
    (if (boundp '+pdata-stub+)
        (symbol-value '+pdata-stub+)
        #(0 0 0 0))
  "Stub 4-byte CDR ParticipantBuiltinTopicData for Slice 2a (§9.3.2.1; full PBDTD is Slice 2b).")

;;; --- handshake-handle ---

(defstruct* (handshake-handle (:constructor %make-handshake-handle))
  "State for an in-flight DDS-Security §8.7.2.4 three-message PKI-DH handshake.
   role: :requester (local GUID < remote) or :replier (§8.7.2.4 GUID ordering).
   suite: auth-suite vtable. local-id: local identity-handle.
   remote-pub-key: EVP_PKEY* from peer cert (stored after cert verify; released in free-handshake-handle).
   state: :init | :awaiting-reply | :awaiting-final | :authenticated | :rejected.
   my-dh-priv: EVP_PKEY* ephemeral private (released on free or after use).
   my-dh-pub: SubjectPublicKeyInfo DER of ephemeral public key (dh1 or dh2 wire value).
   my-challenge: 32-byte random nonce. peer-dh-pub: peer ephemeral DH octets. peer-challenge: peer nonce.
   hash-c-local/hash-c-peer: SHA-256 of own / peer c.* BinaryPropertySeq (§9.3.2).
   c-cert-der/c-perm/c-pdata: own c.* values stored for inclusion in signature inputs.
   shared-secret: set after successful authentication; NIL until then."
  (role          :requester :type (member :requester :replier))
  (suite         +suite-ecdh+ :type auth-suite)
  (local-id      nil :type (or identity-handle null))
  (remote-pub-key (cffi:null-pointer) :type cffi:foreign-pointer)
  (state         :init :type (member :init :awaiting-reply :awaiting-final :authenticated :rejected))
  (my-dh-priv    (cffi:null-pointer) :type cffi:foreign-pointer)
  (my-dh-pub     (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*)))
  (my-challenge  (make-array 32 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (32)))
  (peer-dh-pub   (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*)))
  (peer-challenge (make-array 32 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (32)))
  (hash-c-local  (make-array 32 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (32)))
  (hash-c-peer   (make-array 32 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (32)))
  (shared-secret nil :type (or shared-secret-handle null))
  (c-cert-der    (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*)))
  (c-perm        (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*)))
  (c-pdata       (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*))))

(defun* handshake-shared-secret (handle)
    (function (handshake-handle) (or shared-secret-handle null))
  "Return the SharedSecretHandle from HANDLE (§9.3.3), or NIL if not yet authenticated."
  (handshake-handle-shared-secret handle))

(defun* free-handshake-handle (handle)
    (function ((or handshake-handle null)) t)
  "Release all foreign resources owned by HANDLE (dh-priv, remote-pub-key, shared-secret).
   Idempotent: NIL is a no-op. Null pointer slots are skipped safely."
  (when handle
    (let ((priv (handshake-handle-my-dh-priv handle))
          (rpub (handshake-handle-remote-pub-key handle)))
      (unless (cffi:null-pointer-p priv) (dds.dare:pkey-free priv))
      (unless (cffi:null-pointer-p rpub) (dds.dare:pkey-free rpub))
      (when (handshake-handle-shared-secret handle)
        (free-shared-secret-handle (handshake-handle-shared-secret handle))))
    (setf (handshake-handle-my-dh-priv handle) (cffi:null-pointer)
          (handshake-handle-remote-pub-key handle) (cffi:null-pointer)
          (handshake-handle-shared-secret handle) nil))
  t)

;;; --- public API ---

(defun* begin-handshake-request (local remote suite)
    (function (identity-handle identity-handle auth-suite)
              (values (simple-array (unsigned-byte 8) (*)) handshake-handle))
  "Initiate DDS-Security §8.7.2.4 handshake as the requester (local GUID < remote GUID).
   LOCAL: local identity-handle. REMOTE: remote identity-handle (CA used for reply verification).
   SUITE: auth-suite vtable (use +suite-ecdh+ for EC P-256 / ECDSA-SHA256 / SHA-256).
   Returns (values REQUEST-TOKEN-OCTETS HANDSHAKE-HANDLE) — HANDLE state = :awaiting-reply."
  (declare (ignore remote))
  (let* ((cert-der    (dds.dare:x509-to-der (identity-handle-cert local)))
         (challenge1  (%random-bytes +challenge-len+))
         (dsign-str   (auth-suite-dsign-algo-str suite))
         (kagree-str  (auth-suite-kagree-algo-str suite))
         (perm-octets (make-array 0 :element-type '(unsigned-byte 8)))
         (pdata       (coerce +pdata-stub+ '(simple-array (unsigned-byte 8) (*))))
         (hash-c1     (%compute-hash-c suite cert-der perm-octets pdata dsign-str kagree-str)))
    (multiple-value-bind (my-dh-pub my-dh-priv)
        (funcall (auth-suite-kagree-gen suite))
      (let* ((token (%make-handshake-token
                     :class-id +handshake-request-class-id+
                     :binary-props (list (cons +prop-c-id+          cert-der)
                                         (cons +prop-c-perm+         perm-octets)
                                         (cons +prop-c-pdata+        pdata)
                                         (cons +prop-c-dsign-algo+   (%ascii->octets dsign-str))
                                         (cons +prop-c-kagree-algo+  (%ascii->octets kagree-str))
                                         (cons +prop-hash-c1+        hash-c1)
                                         (cons +prop-dh1+            my-dh-pub)
                                         (cons +prop-challenge1+     challenge1))))
             (handle (%make-handshake-handle
                      :role :requester
                      :suite suite
                      :local-id local
                      :state :awaiting-reply
                      :my-dh-priv my-dh-priv
                      :my-dh-pub my-dh-pub
                      :my-challenge challenge1
                      :hash-c-local hash-c1
                      :c-cert-der cert-der
                      :c-perm perm-octets
                      :c-pdata pdata)))
        (values (%serialize-token token) handle)))))

(defun* begin-handshake-reply (local remote request-token-octets suite)
    (function (identity-handle identity-handle
               (simple-array (unsigned-byte 8) (*))
               auth-suite)
              (values (or (simple-array (unsigned-byte 8) (*)) null)
                      (or handshake-handle null)))
  "Process HandshakeRequestMessageToken as the replier (DDS-Security 1.1 §8.7.2.4 / §9.3.2.2).
   LOCAL: local identity. REMOTE: remote identity (CA trust store for peer cert verification).
   REQUEST-TOKEN-OCTETS: the requester's HandshakeRequestMessageToken (internal tagged format).
   SUITE: auth-suite vtable. Returns (values REPLY-TOKEN-OCTETS HANDLE) or (values NIL NIL) on failure.
   Verifies peer cert chain, recomputes hash_c1, generates own ephemeral key + Sign2."
  (declare (ignore remote))
  (let ((req-tok (%parse-token request-token-octets)))
    (unless req-tok (return-from begin-handshake-reply (values nil nil)))
    (unless (string= (handshake-token-class-id req-tok) +handshake-request-class-id+)
      (return-from begin-handshake-reply (values nil nil)))
    (let* ((peer-cert-der    (%token-get req-tok +prop-c-id+))
           (peer-perm        (or (%token-get req-tok +prop-c-perm+)
                                 (make-array 0 :element-type '(unsigned-byte 8))))
           (peer-pdata       (or (%token-get req-tok +prop-c-pdata+)
                                 (make-array 0 :element-type '(unsigned-byte 8))))
           (peer-dsign-octs  (or (%token-get req-tok +prop-c-dsign-algo+)
                                 (make-array 0 :element-type '(unsigned-byte 8))))
           (peer-kagree-octs (or (%token-get req-tok +prop-c-kagree-algo+)
                                 (make-array 0 :element-type '(unsigned-byte 8))))
           (hash-c1-claimed  (%token-get req-tok +prop-hash-c1+))
           (dh1              (%token-get req-tok +prop-dh1+))
           (challenge1       (%token-get req-tok +prop-challenge1+)))
      (unless (and peer-cert-der hash-c1-claimed dh1 challenge1)
        (return-from begin-handshake-reply (values nil nil)))
      (let ((peer-cert (dds.dare:x509-load-cert-der peer-cert-der)))
        (unless peer-cert (return-from begin-handshake-reply (values nil nil)))
        (unwind-protect
             (progn
               (unless (dds.dare:x509-verify-chain (identity-handle-ca-store local) peer-cert)
                 (return-from begin-handshake-reply (values nil nil)))
               (let* ((peer-dsign-str  (map 'string #'code-char peer-dsign-octs))
                      (peer-kagree-str (map 'string #'code-char peer-kagree-octs))
                      (hash-c1-recomputed (%compute-hash-c suite peer-cert-der peer-perm peer-pdata
                                                            peer-dsign-str peer-kagree-str)))
                 (unless (equalp hash-c1-claimed hash-c1-recomputed)
                   (return-from begin-handshake-reply (values nil nil)))
                 (multiple-value-bind (my-dh-pub my-dh-priv)
                     (funcall (auth-suite-kagree-gen suite))
                   (let* ((challenge2  (%random-bytes +challenge-len+))
                          (my-cert-der (dds.dare:x509-to-der (identity-handle-cert local)))
                          (my-perm     (make-array 0 :element-type '(unsigned-byte 8)))
                          (my-pdata    (coerce +pdata-stub+ '(simple-array (unsigned-byte 8) (*))))
                          (dsign-str   (auth-suite-dsign-algo-str suite))
                          (kagree-str  (auth-suite-kagree-algo-str suite))
                          (hash-c2     (%compute-hash-c suite my-cert-der my-perm my-pdata
                                                        dsign-str kagree-str))
                          ;; Sign2 = ECDSA-SHA256 over CDR-BE BinaryPropertySeq(hash_c2,challenge2,dh2,challenge1,dh1,hash_c1)
                          (sig-input   (%build-cdr-binary-property-seq-be
                                        (list (cons +prop-hash-c2+   hash-c2)
                                              (cons +prop-challenge2+ challenge2)
                                              (cons +prop-dh2+        my-dh-pub)
                                              (cons +prop-challenge1+ challenge1)
                                              (cons +prop-dh1+        dh1)
                                              (cons +prop-hash-c1+    hash-c1-claimed))))
                          (sign2       (funcall (auth-suite-dsign-sign suite)
                                                (identity-handle-pkey local) sig-input)))
                     ;; peer-pub-key acquired after sign2; free on any error unless stored in handle
                     (let ((peer-pub-key  nil)
                           (peer-pk-stored nil))
                       (unwind-protect
                            (progn
                              (setf peer-pub-key (dds.dare:x509-public-key peer-cert))
                              (let* ((reply-tok (%make-handshake-token
                                                 :class-id +handshake-reply-class-id+
                                                 :binary-props (list
                                                                (cons +prop-c-id+          my-cert-der)
                                                                (cons +prop-c-perm+         my-perm)
                                                                (cons +prop-c-pdata+        my-pdata)
                                                                (cons +prop-c-dsign-algo+   (%ascii->octets dsign-str))
                                                                (cons +prop-c-kagree-algo+  (%ascii->octets kagree-str))
                                                                (cons +prop-hash-c2+        hash-c2)
                                                                (cons +prop-dh2+            my-dh-pub)
                                                                (cons +prop-hash-c1+        hash-c1-claimed)
                                                                (cons +prop-dh1+            dh1)
                                                                (cons +prop-challenge1+     challenge1)
                                                                (cons +prop-challenge2+     challenge2)
                                                                (cons +prop-signature+      sign2))))
                                     (rep-handle (%make-handshake-handle
                                                  :role :replier
                                                  :suite suite
                                                  :local-id local
                                                  :remote-pub-key peer-pub-key
                                                  :state :awaiting-final
                                                  :my-dh-priv my-dh-priv
                                                  :my-dh-pub my-dh-pub
                                                  :my-challenge challenge2
                                                  :peer-dh-pub dh1
                                                  :peer-challenge challenge1
                                                  :hash-c-local hash-c2
                                                  :hash-c-peer hash-c1-recomputed
                                                  :c-cert-der my-cert-der
                                                  :c-perm my-perm
                                                  :c-pdata my-pdata)))
                                (setf peer-pk-stored t)
                                (values (%serialize-token reply-tok) rep-handle)))
                         ;; free peer-pub-key only if not transferred to the handle
                         (unless peer-pk-stored
                           (when peer-pub-key (dds.dare:pkey-free peer-pub-key)))))))))
          (dds.dare:x509-free peer-cert))))))

(defun* process-handshake (handle incoming-token-octets)
    (function (handshake-handle (simple-array (unsigned-byte 8) (*)))
              (values (or (simple-array (unsigned-byte 8) (*)) null)
                      (member :continue :authenticated :rejected)))
  "Drive the DDS-Security §8.7.2.4 handshake state machine for subsequent steps.
   Requester (:awaiting-reply): validates Reply, produces Final token; state -> :authenticated.
   Replier (:awaiting-final): validates Final; state -> :authenticated. No further token returned.
   Returns (values next-token-or-nil status): status in {:continue, :authenticated, :rejected}."
  (ecase (handshake-handle-state handle)
    (:awaiting-reply  (%process-reply  handle incoming-token-octets))
    (:awaiting-final  (%process-final  handle incoming-token-octets))
    (:authenticated   (values nil :authenticated))
    (:rejected        (values nil :rejected))
    (:init            (values nil :rejected))))

(defun* %process-reply (handle reply-octets)
    (function (handshake-handle (simple-array (unsigned-byte 8) (*)))
              (values (or (simple-array (unsigned-byte 8) (*)) null)
                      (member :continue :authenticated :rejected)))
  "Process replier's Reply token for the requester (§9.3.2.2 / §9.3.2.3).
   Verifies peer cert, hash_c2, and Sign2; derives SharedSecret; generates Final token."
  (flet ((reject ()
           (setf (handshake-handle-state handle) :rejected)
           (return-from %process-reply (values nil :rejected))))
    (let ((reply-tok (%parse-token reply-octets)))
      (unless reply-tok (reject))
      (unless (string= (handshake-token-class-id reply-tok) +handshake-reply-class-id+) (reject))
      (let* ((suite          (handshake-handle-suite handle))
             (peer-cert-der  (%token-get reply-tok +prop-c-id+))
             (peer-perm      (or (%token-get reply-tok +prop-c-perm+)
                                 (make-array 0 :element-type '(unsigned-byte 8))))
             (peer-pdata     (or (%token-get reply-tok +prop-c-pdata+)
                                 (make-array 0 :element-type '(unsigned-byte 8))))
             (peer-dsign-o   (or (%token-get reply-tok +prop-c-dsign-algo+)
                                 (make-array 0 :element-type '(unsigned-byte 8))))
             (peer-kagree-o  (or (%token-get reply-tok +prop-c-kagree-algo+)
                                 (make-array 0 :element-type '(unsigned-byte 8))))
             (hash-c2        (%token-get reply-tok +prop-hash-c2+))
             (dh2            (%token-get reply-tok +prop-dh2+))
             (hash-c1-echo   (%token-get reply-tok +prop-hash-c1+))
             (dh1-echo       (%token-get reply-tok +prop-dh1+))
             (ch1-echo       (%token-get reply-tok +prop-challenge1+))
             (challenge2     (%token-get reply-tok +prop-challenge2+))
             (sign2          (%token-get reply-tok +prop-signature+)))
        (unless (and peer-cert-der hash-c2 dh2 hash-c1-echo dh1-echo ch1-echo challenge2 sign2)
          (reject))
        (unless (equalp hash-c1-echo (handshake-handle-hash-c-local handle)) (reject))
        (unless (equalp dh1-echo     (handshake-handle-my-dh-pub handle))    (reject))
        (unless (equalp ch1-echo     (handshake-handle-my-challenge handle))  (reject))
        (let ((peer-cert (dds.dare:x509-load-cert-der peer-cert-der)))
          (unless peer-cert (reject))
          (unwind-protect
               (progn
                 (unless (dds.dare:x509-verify-chain
                          (identity-handle-ca-store (handshake-handle-local-id handle)) peer-cert)
                   (reject))
                 (let* ((peer-dsign-str  (map 'string #'code-char peer-dsign-o))
                        (peer-kagree-str (map 'string #'code-char peer-kagree-o))
                        (hash-c2-recomputed (%compute-hash-c suite peer-cert-der peer-perm peer-pdata
                                                              peer-dsign-str peer-kagree-str)))
                   (unless (equalp hash-c2 hash-c2-recomputed) (reject))
                   (let ((peer-pub     nil)
                         (peer-stored  nil))
                     (unwind-protect
                          (progn
                            (setf peer-pub (dds.dare:x509-public-key peer-cert))
                            (let ((sig-input (%build-cdr-binary-property-seq-be
                                              (list (cons +prop-hash-c2+   hash-c2)
                                                    (cons +prop-challenge2+ challenge2)
                                                    (cons +prop-dh2+        dh2)
                                                    (cons +prop-challenge1+ (handshake-handle-my-challenge handle))
                                                    (cons +prop-dh1+        (handshake-handle-my-dh-pub handle))
                                                    (cons +prop-hash-c1+    (handshake-handle-hash-c-local handle))))))
                              (unless (funcall (auth-suite-dsign-verify suite) peer-pub sig-input sign2)
                                (reject)))
                            (let* ((ss         (%derive-shared-secret suite
                                                                       (handshake-handle-my-dh-priv handle)
                                                                       dh2
                                                                       (handshake-handle-my-challenge handle)
                                                                       challenge2))
                                   (sig1-input (%build-cdr-binary-property-seq-be
                                                (list (cons +prop-hash-c1+   (handshake-handle-hash-c-local handle))
                                                      (cons +prop-challenge1+ (handshake-handle-my-challenge handle))
                                                      (cons +prop-dh1+        (handshake-handle-my-dh-pub handle))
                                                      (cons +prop-challenge2+ challenge2)
                                                      (cons +prop-dh2+        dh2)
                                                      (cons +prop-hash-c2+    hash-c2-recomputed))))
                                   (sign1      (funcall (auth-suite-dsign-sign suite)
                                                        (identity-handle-pkey (handshake-handle-local-id handle))
                                                        sig1-input))
                                   (final-tok  (%make-handshake-token
                                                :class-id +handshake-final-class-id+
                                                :binary-props (list
                                                               (cons +prop-hash-c1+   (handshake-handle-hash-c-local handle))
                                                               (cons +prop-hash-c2+   hash-c2-recomputed)
                                                               (cons +prop-dh1+       (handshake-handle-my-dh-pub handle))
                                                               (cons +prop-dh2+       dh2)
                                                               (cons +prop-challenge1+ (handshake-handle-my-challenge handle))
                                                               (cons +prop-challenge2+ challenge2)
                                                               (cons +prop-signature+  sign1)))))
                              (setf (handshake-handle-peer-dh-pub    handle) dh2
                                    (handshake-handle-peer-challenge  handle) challenge2
                                    (handshake-handle-hash-c-peer     handle) hash-c2-recomputed
                                    (handshake-handle-remote-pub-key  handle) peer-pub
                                    (handshake-handle-shared-secret   handle) ss
                                    (handshake-handle-state           handle) :authenticated)
                              (setf peer-stored t)
                              ;; :continue while our state is :authenticated: replier must still process Final (§8.7.2.4 step 3)
                              (values (%serialize-token final-tok) :continue)))
                       (unless peer-stored
                         (when peer-pub (dds.dare:pkey-free peer-pub)))))))
            (dds.dare:x509-free peer-cert)))))))

(defun* %process-final (handle final-octets)
    (function (handshake-handle (simple-array (unsigned-byte 8) (*)))
              (values (or (simple-array (unsigned-byte 8) (*)) null)
                      (member :continue :authenticated :rejected)))
  "Process requester's Final token for the replier (§9.3.2.3 / §8.7.2.4).
   Verifies all echoes and Sign1; derives SharedSecret; transitions to :authenticated."
  (flet ((reject ()
           (setf (handshake-handle-state handle) :rejected)
           (return-from %process-final (values nil :rejected))))
    (let ((final-tok (%parse-token final-octets)))
      (unless final-tok (reject))
      (unless (string= (handshake-token-class-id final-tok) +handshake-final-class-id+) (reject))
      (let* ((suite        (handshake-handle-suite handle))
             (hash-c1-echo (%token-get final-tok +prop-hash-c1+))
             (hash-c2-echo (%token-get final-tok +prop-hash-c2+))
             (dh1-echo     (%token-get final-tok +prop-dh1+))
             (dh2-echo     (%token-get final-tok +prop-dh2+))
             (ch1-echo     (%token-get final-tok +prop-challenge1+))
             (ch2-echo     (%token-get final-tok +prop-challenge2+))
             (sign1        (%token-get final-tok +prop-signature+)))
        (unless (and hash-c1-echo hash-c2-echo dh1-echo dh2-echo ch1-echo ch2-echo sign1) (reject))
        ;; replier: hash-c-peer = hash_c1 (requester's); hash-c-local = hash_c2 (our own)
        (unless (equalp hash-c1-echo (handshake-handle-hash-c-peer  handle)) (reject))
        (unless (equalp hash-c2-echo (handshake-handle-hash-c-local handle)) (reject))
        (unless (equalp dh1-echo     (handshake-handle-peer-dh-pub  handle)) (reject))
        (unless (equalp dh2-echo     (handshake-handle-my-dh-pub    handle)) (reject))
        (unless (equalp ch1-echo     (handshake-handle-peer-challenge handle)) (reject))
        (unless (equalp ch2-echo     (handshake-handle-my-challenge   handle)) (reject))
        ;; Sign1 was over CDR-BE BinaryPropertySeq(hash_c1,challenge1,dh1,challenge2,dh2,hash_c2)
        (let ((sig1-input (%build-cdr-binary-property-seq-be
                           (list (cons +prop-hash-c1+   hash-c1-echo)
                                 (cons +prop-challenge1+ ch1-echo)
                                 (cons +prop-dh1+        dh1-echo)
                                 (cons +prop-challenge2+ ch2-echo)
                                 (cons +prop-dh2+        dh2-echo)
                                 (cons +prop-hash-c2+    hash-c2-echo)))))
          (unless (funcall (auth-suite-dsign-verify suite)
                            (handshake-handle-remote-pub-key handle)
                            sig1-input sign1)
            (reject))
          (let ((ss (%derive-shared-secret suite
                                           (handshake-handle-my-dh-priv handle)
                                           dh1-echo
                                           ch1-echo
                                           (handshake-handle-my-challenge handle))))
            (setf (handshake-handle-shared-secret handle) ss
                  (handshake-handle-state handle) :authenticated)
            (values nil :authenticated)))))))
