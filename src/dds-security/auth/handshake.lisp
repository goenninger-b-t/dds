(in-package #:dds.security)

;;; DDS-Security 1.1 §8.7.2.4 three-message PKI-DH handshake state machine.
;;; Messages: HandshakeRequestMessageToken -> HandshakeReplyMessageToken -> HandshakeFinalMessageToken.
;;; Token format: internal tagged binary (not CDR DataHolder wire format — in-process transport only).
;;; CDR BIG-ENDIAN BinaryPropertySeq used for hash_c1/hash_c2 + signature inputs (§9.3.2.2/§9.3.2.3).

;;; --- CDR big-endian helpers for BinaryPropertySeq (hash and signature inputs) ---
;;; Per Fast DDS PKIDH.cpp: signature inputs + hash inputs use big-endian CDR BinaryPropertySeq.
;;; BinaryProperty CDR layout (big-endian) — name+value ONLY (no propagate byte, T1):
;;;   name: uint32-BE(strlen+1) || ascii-bytes || NUL || pad-to-4-bytes
;;;   value: uint32-BE(count) || bytes || pad-to-4 (the octet value is 4-padded for EVERY property
;;;          EXCEPT the LAST in the sequence — Fast DDS add_final_padding, CDRMessage.cpp
;;;          addBinaryProperty/addOctetVector with the seq-level add_final_padding=false; T4)
;;;   propagate: NOT serialized (§7.2.2 LOCAL include/exclude filter; never in the hash/sig input)
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

(defun* %cdr-octet-seq-be (value-octets pad)
    (function ((simple-array (unsigned-byte 8) (*)) t) (simple-array (unsigned-byte 8) (*)))
  "Encode VALUE-OCTETS as CDR BE octet-sequence: uint32-BE(count) || bytes || (zero pad to a 4-byte
   multiple of the VALUE length when PAD). Fast DDS CDRMessage::addOctetVector applies this final
   padding (add_final_padding) to every BinaryProperty value except the LAST in the hashed/signed
   BinaryPropertySeq (the seq-level add_final_padding=false; PKIDH.cpp begin_handshake_*/process_*
   + CDRMessage.cpp). WP-DDS-SECURITY-FASTDDS-INTEROP T4 cross-vendor fix (was always unpadded)."
  (let* ((n    (length value-octets))
         (padn (if pad (mod (- 4 (mod n 4)) 4) 0))
         (out  (make-array (+ 4 n padn) :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref out 0) (ldb (byte 8 24) n)
          (aref out 1) (ldb (byte 8 16) n)
          (aref out 2) (ldb (byte 8  8) n)
          (aref out 3) (ldb (byte 8  0) n))
    (dotimes (i n)
      (setf (aref out (+ 4 i)) (aref value-octets i)))
    out))

(defun* %cdr-binary-property-be (name value-octets pad-value)
    (function (string (simple-array (unsigned-byte 8) (*)) t) (simple-array (unsigned-byte 8) (*)))
  "Serialize CDR BE §9.3.4 BinaryProperty: name(string-BE) + value(octet-seq-BE, 4-padded when
   PAD-VALUE) — name+value ONLY. The propagate flag is NEVER serialized (§7.2.2 LOCAL include/exclude
   filter). PAD-VALUE mirrors Fast DDS add_final_padding: every property value is 4-padded except the
   LAST in the sequence (T1 dropped propagate; T4 added the value padding to match Fast DDS)."
  (%concat-octets (%cdr-string-be name)
                  (%cdr-octet-seq-be value-octets pad-value)))

(defun* %build-cdr-binary-property-seq-be (property-pairs)
    (function (list) (simple-array (unsigned-byte 8) (*)))
  "Serialize PROPERTY-PAIRS ((name-string . value-octets)*) as CDR BE BinaryPropertySeq.
   Layout: uint32-BE(count) | BinaryProperty* — used for hash_c1/hash_c2 and the Sign inputs (§9.3.2).
   Each property's octet value is zero-padded to a 4-byte multiple EXCEPT the LAST property, matching
   Fast DDS CDRMessage::addBinaryPropertySeq(..., add_final_padding=false) (PKIDH.cpp begin_handshake_
   request/reply + process_handshake_*; CDRMessage.cpp addBinaryProperty/addOctetVector). T4 fix."
  (let ((count (length property-pairs)))
    (apply #'%concat-octets
           (%cdr-u32-be count)
           (loop for cell on property-pairs
                 collect (%cdr-binary-property-be (car (car cell)) (cdr (car cell))
                                                  (not (null (cdr cell))))))))

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

(defun* %class-id-role-match-p (class-id canonical)
    (function ((or string null) string) boolean)
  "T iff CLASS-ID names the same DDS:Auth:PKI-DH plugin FAMILY + message ROLE as the CANONICAL
   handshake class_id constant (+handshake-{request,reply,final}-class-id+), TOLERATING the plugin
   VERSION between them (§9.3.1 / §9.3.2.1 / §8.7.2.4). Ours emits version 1.0, live RTI Connext 7.3.1
   emits 1.2 (e.g. \"DDS:Auth:PKI-DH:1.2+Reply\"): the plugin family + the message role are the interop
   contract; the version is the plugin revision. Both the family prefix (up to and incl. the last ':')
   and the role suffix (from the last '+') are DERIVED from CANONICAL — no version literal is hard-coded,
   the match keys off the already-pinned + corpus-locked constants. Fail-closed: NIL for a different
   plugin family or an unrecognized role. The class_id is NEVER a trust boundary — trust is the §8.7.2.4
   peer cert-chain verify + Sign, unchanged."
  (when class-id
    (let ((colon (position #\: canonical :from-end t))
          (plus  (position #\+ canonical :from-end t)))
      (and colon plus
           (uiop:string-prefix-p (subseq canonical 0 (1+ colon)) class-id)
           (uiop:string-suffix-p class-id (subseq canonical plus))
           t))))

(defun* %algo-name-match-p (peer-algo-str suite-algo-str)
    (function (string string) boolean)
  "T iff the peer's advertised c.dsign_algo / c.kagree_algo NAME equals the selected suite's algo string
   (§9.3.2), TOLERATING a trailing C-string NUL terminator on the peer octets: live RTI Connext 7.3.1
   null-terminates its algo binary-property values (e.g. \"ECDSA-SHA256\\0\"), ours does not. The algo NAME
   is the interop contract; the NUL is a serialization artifact. Fail-closed — a genuinely different
   algorithm still mismatches. The verbatim (NUL-included) octets remain the hash_c/Sign input, so the
   cryptographic binding is UNCHANGED; only this NAME cross-check is NUL-tolerant."
  (and (string= (string-right-trim '(#\Nul) peer-algo-str) suite-algo-str) t))

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

(defun* generate-future-challenge ()
    (function () (simple-array (unsigned-byte 8) (32)))
  "Mint a fresh 32-octet (256-bit) §8.7.2.3 future_challenge nonce for the AuthRequestMessageToken
   sub-protocol (RAND_bytes). The auth manager mints ONE per remote at discovery and reuses it (stable):
   it is both the nonce sent in our AuthRequestMessageToken and — as the requester's challenge1 / replier's
   challenge2 — the precommitted handshake challenge the peer binds to byte-for-byte (§8.7.2.4 / §8.7.2.5)."
  (let ((n (%random-bytes +challenge-len+))
        (out (make-array 32 :element-type '(unsigned-byte 8))))
    (replace out n :end2 (min 32 (length n)))
    out))

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

(defun* %compute-hash-c (suite cert-bytes perm-octets pdata dsign-algo-str kagree-algo-str)
    (function (auth-suite
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               string string)
              (simple-array (unsigned-byte 8) (32)))
  "Compute hash_c1 or hash_c2: SHA-256(CDR-BE-BinaryPropertySeq(c.id,c.perm,c.pdata,c.dsign,c.kagree)).
   Per DDS-Security 1.1 §9.3.2.1 — all 5 c.* properties in this exact order. CERT-BYTES here carries the
   c.id BYTES exactly as placed on the wire (the PEM certificate per §9.3.2.1); both sides hash the
   identical transmitted c.id bytes, so the recompute matches cross-vendor regardless of encoding."
  (let* ((hash-fn (auth-suite-hash suite))
         (seq (%build-cdr-binary-property-seq-be
               (list (cons +prop-c-id+          cert-bytes)
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

;;; --- c.pdata = ParticipantBuiltinTopicData ParameterList (§9.3.2.1) ---

(defun* %build-c-pdata (guid)
    (function ((simple-array (unsigned-byte 8) (16))) (simple-array (unsigned-byte 8) (*)))
  "Serialize c.pdata: a ParticipantBuiltinTopicData as a BIG-ENDIAN RTPS ParameterList (NO
   encapsulation header) carrying PID_PARTICIPANT_GUID = the 16-octet participant GUID, then
   PID_SENTINEL (DDS-Security 1.1 §9.3.2.1). A conformant replier reads PID_PARTICIPANT_GUID from
   c.pdata as a big-endian ParameterList scanned from offset 0 — corroborated against Fast DDS
   PKIDH::begin_handshake_reply + ParameterList::read_guid_from_cdr_msg, and the producer side
   PDP::get_participant_proxy_data_serialized(BIGEND) which emits write_encapsulation=false. The
   u16 PID and u16 length are big-endian; the GUID octets are MSB-first (RTPS 2.5 §9.3.1.2 / §9.6.2.2).
   Replaces the Slice-2a 4-byte stub so the replier's c.pdata participant_key check passes (T2)."
  (let ((out (make-array 24 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref out 0) (ldb (byte 8 8) +pid-participant-guid+)
          (aref out 1) (ldb (byte 8 0) +pid-participant-guid+)
          (aref out 2) 0
          (aref out 3) 16)
    (dotimes (i 16) (setf (aref out (+ 4 i)) (aref guid i)))
    (setf (aref out 20) (ldb (byte 8 8) +pid-sentinel+)
          (aref out 21) (ldb (byte 8 0) +pid-sentinel+)
          (aref out 22) 0
          (aref out 23) 0)
    out))

;;; --- handshake-handle ---

(defstruct* (handshake-handle (:constructor %make-handshake-handle))
  "State for an in-flight DDS-Security §8.7.2.4 three-message PKI-DH handshake.
   role: :requester (local GUID < remote) or :replier (§8.7.2.4 GUID ordering).
   suite: auth-suite vtable. local-id: local identity-handle.
   remote-pub-key: EVP_PKEY* from peer cert (stored after cert verify; released in free-handshake-handle).
   peer-subject: the VALIDATED peer-cert subject name (x509-subject-name of the chain-verified c.id cert; §8.7.2.5 — the unforgeable authorization identity; NIL until the peer cert is validated).
   state: :init | :awaiting-reply | :awaiting-final | :authenticated | :rejected.
   my-dh-priv: EVP_PKEY* ephemeral private (released on free or after use).
   my-dh-pub: SubjectPublicKeyInfo DER of ephemeral public key (dh1 or dh2 wire value).
   my-challenge: 32-byte random nonce. peer-dh-pub: peer ephemeral DH octets. peer-challenge: peer nonce.
   hash-c-local/hash-c-peer: SHA-256 of own / peer c.* BinaryPropertySeq (§9.3.2).
   c-cert-bytes/c-perm/c-pdata: own c.* values (c.id = the PEM certificate bytes per §9.3.2.1,
   c.perm, c.pdata) retained for reference; the §8.7.2.4 Sign inputs use hash_c/challenge/dh only.
   shared-secret: set after successful authentication; NIL until then."
  (role          :requester :type (member :requester :replier))
  (suite         +suite-ecdh+ :type auth-suite)
  (local-id      nil :type (or identity-handle null))
  (remote-pub-key (cffi:null-pointer) :type cffi:foreign-pointer)
  (peer-subject  nil :type (or null string))
  (state         :init :type (member :init :awaiting-reply :awaiting-final :authenticated :rejected))
  (my-dh-priv    (cffi:null-pointer) :type cffi:foreign-pointer)
  (my-dh-pub     (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*)))
  (my-challenge  (make-array 32 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (32)))
  (peer-dh-pub   (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*)))
  (peer-challenge (make-array 32 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (32)))
  (hash-c-local  (make-array 32 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (32)))
  (hash-c-peer   (make-array 32 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (32)))
  (shared-secret nil :type (or shared-secret-handle null))
  (c-cert-bytes  (make-array 0 :element-type '(unsigned-byte 8)) :type (simple-array (unsigned-byte 8) (*)))
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

(defun* %c-id-pem-octets (cert)
    (function (cffi:foreign-pointer) (simple-array (unsigned-byte 8) (*)))
  "The c.id binary-property value for CERT: the X.509 identity certificate as a PEM string with a
   trailing NUL terminator (§9.3.2.1). Live RTI Connext 7.3.1's
   RTI_Security_Authentication_copyCertificateFromTokenToIdentityHandle REQUIRES the c.id PEM to be a
   NUL-terminated C-string and REJECTS a non-terminated cert as 'malformed'; ours previously emitted the
   raw PEM (no NUL). The single NUL is folded into hash_c UNIFORMLY (these exact octets are BOTH the c.id
   property AND the hash_c input, so both ends recompute the identical hash over the transmitted bytes),
   and OpenSSL PEM_read ignores any trailing byte after END CERTIFICATE, so a spec-literal peer (Fast DDS /
   ours) still loads it — an encode-side form BOTH vendors accept, NOT a weakening (the certificate content
   is unchanged; the trailing NUL is only a C-string terminator)."
  (let* ((pem (dds.dare:x509-to-pem cert))
         (out (make-array (1+ (length pem)) :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace out pem)
    out))

(defun* begin-handshake-request (local remote suite
                                 &optional (perm-octets (make-array 0 :element-type '(unsigned-byte 8)))
                                           (challenge1-nonce nil))
    (function (identity-handle identity-handle auth-suite
               &optional (simple-array (unsigned-byte 8) (*))
                         (or null (simple-array (unsigned-byte 8) (*))))
              (values (simple-array (unsigned-byte 8) (*)) handshake-handle))
  "Initiate DDS-Security §8.7.2.4 handshake as the requester (local GUID < remote GUID).
   LOCAL: local identity-handle. REMOTE: remote identity-handle (CA used for reply verification).
   SUITE: auth-suite vtable (use +suite-ecdh+ for EC P-256 / ECDSA-SHA256 / SHA-256).
   PERM-OCTETS (optional, default empty): the local participant's signed Permissions credential placed
   in the c.perm binary_property (§9.3.2.1) — the S/MIME multipart/signed §9.4.1.1 document a conformant
   replier reads via validate_remote_permissions (Fast DDS SMIME_read_PKCS7). Empty (the default) emits an
   empty c.perm for the shared-document model / auth-only flows; it is ALSO folded into hash_c1 either way,
   so both ends recompute the identical hash over the transmitted bytes (WP-DDS-SECURITY-FASTDDS-INTEROP T6).
   CHALLENGE1-NONCE (optional, default NIL): the §8.7.2.3 future_challenge this participant precommitted in
   its AuthRequestMessageToken — when non-NIL it becomes challenge1 VERBATIM (the anti-replay binding a full
   RTI Connext replier enforces, §8.7.2.4); NIL falls back to a fresh random challenge1 (the §8.7.2.3-optional
   path for a peer that requires no auth_request, e.g. Fast DDS / ours↔ours without the sub-protocol).
   Returns (values REQUEST-TOKEN-OCTETS HANDSHAKE-HANDLE) — HANDLE state = :awaiting-reply."
  (declare (ignore remote))
  (let* ((cert-pem    (%c-id-pem-octets (identity-handle-cert local)))
         (challenge1  (or challenge1-nonce (%random-bytes +challenge-len+)))
         (dsign-str   (auth-suite-dsign-algo-str suite))
         (kagree-str  (auth-suite-kagree-algo-str suite))
         (pdata       (%build-c-pdata (identity-handle-guid local)))
         (hash-c1     (%compute-hash-c suite cert-pem perm-octets pdata dsign-str kagree-str)))
    (multiple-value-bind (my-dh-pub my-dh-priv)
        (funcall (auth-suite-kagree-gen suite))
      (let* ((token (%make-handshake-token
                     :class-id +handshake-request-class-id+
                     :binary-props (list (cons +prop-c-id+          cert-pem)
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
                      :c-cert-bytes cert-pem
                      :c-perm perm-octets
                      :c-pdata pdata)))
        (values (%serialize-token token) handle)))))

(defun* begin-handshake-reply (local remote request-token-octets suite
                               &optional (perm-octets (make-array 0 :element-type '(unsigned-byte 8)))
                                         (expected-challenge1 nil)
                                         (challenge2-nonce nil))
    (function (identity-handle identity-handle
               (simple-array (unsigned-byte 8) (*))
               auth-suite
               &optional (simple-array (unsigned-byte 8) (*))
                         (or null (simple-array (unsigned-byte 8) (*)))
                         (or null (simple-array (unsigned-byte 8) (*))))
              (values (or (simple-array (unsigned-byte 8) (*)) null)
                      (or handshake-handle null)))
  "Process HandshakeRequestMessageToken as the replier (DDS-Security 1.1 §8.7.2.4 / §9.3.2.2).
   LOCAL: local identity. REMOTE: remote identity (CA trust store for peer cert verification).
   REQUEST-TOKEN-OCTETS: the requester's HandshakeRequestMessageToken (internal tagged format).
   SUITE: auth-suite vtable.
   PERM-OCTETS (optional, default empty): the local participant's signed Permissions credential placed in
   the reply's c.perm binary_property (§9.3.2.1) — the S/MIME §9.4.1.1 document the requester's
   validate_remote_permissions reads (Fast DDS SMIME_read_PKCS7). It is also folded into hash_c2, so the
   requester recomputes the identical hash over the transmitted bytes (WP-DDS-SECURITY-FASTDDS-INTEROP T6).
   EXPECTED-CHALLENGE1 (optional, default NIL): the requester's §8.7.2.3 future_challenge, received in its
   AuthRequestMessageToken. When non-NIL the request's challenge1 MUST equal it byte-for-byte or the reply is
   REJECTED (values NIL NIL) — the §8.7.2.5 replier-side anti-replay binding. NIL SKIPS the check (the peer
   sent no auth_request; §8.7.2.3-optional, absence must not false-reject — matches OpenDDS's conditional).
   CHALLENGE2-NONCE (optional, default NIL): the replier's OWN §8.7.2.3 future_challenge — when non-NIL it
   becomes challenge2 VERBATIM (so a full requester can bind to it, §8.7.2.4); NIL = fresh random challenge2.
   Returns (values REPLY-TOKEN-OCTETS HANDLE) or (values NIL NIL) on failure.
   Verifies peer cert chain, recomputes hash_c1, generates own ephemeral key + Sign2."
  (declare (ignore remote))
  (let ((req-tok (%parse-token request-token-octets)))
    (unless req-tok (return-from begin-handshake-reply (values nil nil)))
    (unless (%class-id-role-match-p (handshake-token-class-id req-tok) +handshake-request-class-id+)
      (return-from begin-handshake-reply (values nil nil)))
    (let* ((peer-cert-bytes  (%token-get req-tok +prop-c-id+))
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
      (unless (and peer-cert-bytes hash-c1-claimed dh1 challenge1)
        (return-from begin-handshake-reply (values nil nil)))
      ;; §8.7.2.5 anti-replay binding: when the requester precommitted a future_challenge (via its
      ;; AuthRequestMessageToken), its challenge1 MUST equal it byte-for-byte; a mismatch is a replayed /
      ;; forged request -> fail-closed. NIL EXPECTED-CHALLENGE1 = no auth_request seen (§8.7.2.3-optional).
      (when (and expected-challenge1 (not (equalp challenge1 expected-challenge1)))
        (return-from begin-handshake-reply (values nil nil)))
      (let ((peer-cert (dds.dare:x509-load-cert-auto peer-cert-bytes)))
        (unless peer-cert (return-from begin-handshake-reply (values nil nil)))
        (unwind-protect
             (progn
               (unless (dds.dare:x509-verify-chain (identity-handle-ca-store local) peer-cert)
                 (return-from begin-handshake-reply (values nil nil)))
               (let* ((peer-dsign-str     (map 'string #'code-char peer-dsign-octs))
                      (peer-kagree-str    (map 'string #'code-char peer-kagree-octs))
                      (hash-c1-recomputed (%compute-hash-c suite peer-cert-bytes peer-perm peer-pdata
                                                            peer-dsign-str peer-kagree-str)))
                 ;; §9.3.2 algo-vs-suite cross-check: peer advertised algos must match selected suite (NUL-tolerant)
                 (unless (and (%algo-name-match-p peer-dsign-str  (auth-suite-dsign-algo-str suite))
                              (%algo-name-match-p peer-kagree-str (auth-suite-kagree-algo-str suite)))
                   (return-from begin-handshake-reply (values nil nil)))
                 (unless (equalp hash-c1-claimed hash-c1-recomputed)
                   (return-from begin-handshake-reply (values nil nil)))
                 (multiple-value-bind (my-dh-pub my-dh-priv)
                     (funcall (auth-suite-kagree-gen suite))
                   (let* ((challenge2  (or challenge2-nonce (%random-bytes +challenge-len+)))
                          (my-cert-pem (%c-id-pem-octets (identity-handle-cert local)))
                          (my-perm     perm-octets)
                          (my-pdata    (%build-c-pdata (identity-handle-guid local)))
                          (dsign-str   (auth-suite-dsign-algo-str suite))
                          (kagree-str  (auth-suite-kagree-algo-str suite))
                          (hash-c2     (%compute-hash-c suite my-cert-pem my-perm my-pdata
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
                                                                (cons +prop-c-id+          my-cert-pem)
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
                                                  ;; §8.7.2.5: bind the unforgeable authorization identity to the chain-verified peer cert
                                                  :peer-subject (dds.dare:x509-subject-name peer-cert)
                                                  :state :awaiting-final
                                                  :my-dh-priv my-dh-priv
                                                  :my-dh-pub my-dh-pub
                                                  :my-challenge challenge2
                                                  :peer-dh-pub dh1
                                                  :peer-challenge challenge1
                                                  :hash-c-local hash-c2
                                                  :hash-c-peer hash-c1-recomputed
                                                  :c-cert-bytes my-cert-pem
                                                  :c-perm my-perm
                                                  :c-pdata my-pdata)))
                                (setf peer-pk-stored t)
                                (values (%serialize-token reply-tok) rep-handle)))
                         ;; free peer-pub-key only if not transferred to the handle
                         (unless peer-pk-stored
                           (when peer-pub-key (dds.dare:pkey-free peer-pub-key)))))))))
          (dds.dare:x509-free peer-cert))))))

(defun* process-handshake (handle incoming-token-octets &optional (expected-challenge2 nil))
    (function (handshake-handle (simple-array (unsigned-byte 8) (*))
               &optional (or null (simple-array (unsigned-byte 8) (*))))
              (values (or (simple-array (unsigned-byte 8) (*)) null)
                      (member :continue :authenticated :rejected)))
  "Drive the DDS-Security §8.7.2.4 handshake state machine for subsequent steps.
   Requester (:awaiting-reply): validates Reply, produces Final token; state -> :authenticated.
   Replier (:awaiting-final): validates Final; state -> :authenticated. No further token returned.
   EXPECTED-CHALLENGE2 (optional, default NIL): the replier's §8.7.2.3 future_challenge (from its
   AuthRequestMessageToken) — when non-NIL the Reply's challenge2 MUST equal it byte-for-byte or the step
   is REJECTED (§8.7.2.5 requester-side binding); NIL SKIPS the check (no auth_request seen; §8.7.2.3-optional).
   Only consulted in the :awaiting-reply (requester) step; ignored for the replier's :awaiting-final step.
   Returns (values next-token-or-nil status): status in {:continue, :authenticated, :rejected}."
  (ecase (handshake-handle-state handle)
    (:awaiting-reply  (%process-reply  handle incoming-token-octets expected-challenge2))
    (:awaiting-final  (%process-final  handle incoming-token-octets))
    (:authenticated   (values nil :authenticated))
    (:rejected        (values nil :rejected))
    (:init            (values nil :rejected))))

(defun* %process-reply (handle reply-octets &optional (expected-challenge2 nil))
    (function (handshake-handle (simple-array (unsigned-byte 8) (*))
               &optional (or null (simple-array (unsigned-byte 8) (*))))
              (values (or (simple-array (unsigned-byte 8) (*)) null)
                      (member :continue :authenticated :rejected)))
  "Process replier's Reply token for the requester (§9.3.2.2 / §9.3.2.3).
   Verifies peer cert, hash_c2, and Sign2; derives SharedSecret; generates Final token.
   EXPECTED-CHALLENGE2 (optional): when non-NIL, the Reply's challenge2 MUST equal the replier's
   precommitted §8.7.2.3 future_challenge byte-for-byte or the step is REJECTED (§8.7.2.5); NIL skips it."
  (flet ((reject ()
           (setf (handshake-handle-state handle) :rejected)
           (return-from %process-reply (values nil :rejected))))
    (let ((reply-tok (%parse-token reply-octets)))
      (unless reply-tok (reject))
      (unless (%class-id-role-match-p (handshake-token-class-id reply-tok) +handshake-reply-class-id+) (reject))
      (let* ((suite          (handshake-handle-suite handle))
             (peer-cert-bytes (%token-get reply-tok +prop-c-id+))
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
        (unless (and peer-cert-bytes dh2 challenge2 sign2)
          (reject))
        ;; §8.7.2.5 requester-side binding: when the replier precommitted a future_challenge (its
        ;; AuthRequestMessageToken), the Reply's challenge2 MUST equal it byte-for-byte -> fail-closed on
        ;; mismatch. NIL EXPECTED-CHALLENGE2 = no auth_request seen (§8.7.2.3-optional; matches OpenDDS).
        (when (and expected-challenge2 (not (equalp challenge2 expected-challenge2))) (reject))
        (when (and hash-c1-echo (not (equalp hash-c1-echo (handshake-handle-hash-c-local handle)))) (reject))
        (when (and dh1-echo     (not (equalp dh1-echo (handshake-handle-my-dh-pub handle))))         (reject))
        (when (and ch1-echo     (not (equalp ch1-echo (handshake-handle-my-challenge handle))))       (reject))
        (let ((peer-cert (dds.dare:x509-load-cert-auto peer-cert-bytes)))
          (unless peer-cert (reject))
          (unwind-protect
               (progn
                 (unless (dds.dare:x509-verify-chain
                          (identity-handle-ca-store (handshake-handle-local-id handle)) peer-cert)
                   (reject))
                 (let* ((peer-dsign-str     (map 'string #'code-char peer-dsign-o))
                        (peer-kagree-str    (map 'string #'code-char peer-kagree-o))
                        (hash-c2-recomputed (%compute-hash-c suite peer-cert-bytes peer-perm peer-pdata
                                                              peer-dsign-str peer-kagree-str)))
                   ;; §9.3.2 algo-vs-suite cross-check: peer advertised algos must match selected suite (NUL-tolerant)
                   (unless (and (%algo-name-match-p peer-dsign-str  (auth-suite-dsign-algo-str suite))
                                (%algo-name-match-p peer-kagree-str (auth-suite-kagree-algo-str suite)))
                     (reject))
                   (when (and hash-c2 (not (equalp hash-c2 hash-c2-recomputed))) (reject))
                   (let ((peer-pub     nil)
                         (peer-stored  nil))
                     (unwind-protect
                          (progn
                            (setf peer-pub (dds.dare:x509-public-key peer-cert))
                            (let ((sig-input (%build-cdr-binary-property-seq-be
                                              (list (cons +prop-hash-c2+   hash-c2-recomputed)
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
                                    ;; §8.7.2.5: bind the unforgeable authorization identity to the chain-verified peer cert
                                    (handshake-handle-peer-subject    handle) (dds.dare:x509-subject-name peer-cert)
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
      (unless (%class-id-role-match-p (handshake-token-class-id final-tok) +handshake-final-class-id+) (reject))
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
