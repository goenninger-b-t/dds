(in-package #:dds.security)

;;; DDS-Security 1.1 §8.7 Authentication plugin — PKI identity load, validation, and IdentityToken.
;;; T1 of WP-DDS-SECURITY-AUTH-2A (M7/P6 Slice 2a).
;;;
;;; Spec citations:
;;;   §8.7.2.2  IdentityToken — 4 string Properties: dds.cert.sn, dds.cert.algo, dds.ca.sn, dds.ca.algo
;;;   §9.3.1    class_id "DDS:Auth:PKI-DH:1.0" + IdentityToken layout
;;;   §8.7.2.4  Lexicographic GUID ordering decides :requester/:replier role in handshake
;;;
;;; IdentityToken serialization: CDR LE DataHolder (class_id:string + Properties:sequence +
;;;   BinaryProperties:empty-sequence). Endianness = little-endian (DDS data-path default;
;;;   NEEDS-VERIFICATION item #4 in the spike applies only to the BinaryPropertySeq fed to hash_c1
;;;   — the IdentityToken itself goes into DataHolder properties which are plain CDR string fields,
;;;   not the special BinaryPropertySeq for handshake hashes). Choice made: LE for IdentityToken
;;;   serialization; recorded here per the operating contract §4.
;;;
;;; Crypto: all X.509 ops via dds.dare X.509 FFI (OpenSSL >= 3.5 handle-based); no hand-rolled crypto.
;;; Private key stays as EVP_PKEY foreign handle (never extracted to GC heap bytes).

;;; --- IdentityToken CDR serialization helpers ---

(defun* %cdr-string-le (s)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Encode string S as CDR LE string: uint32-LE(len+1) || ASCII-bytes || NUL || pad-to-4."
  (let* ((bytes (map '(simple-array (unsigned-byte 8) (*)) #'char-code s))
         (n     (length bytes))
         (total (1+ n))
         (pad   (mod (- 4 (mod total 4)) 4))
         (out   (make-array (+ 4 total pad) :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref out 0) (ldb (byte 8  0) total)
          (aref out 1) (ldb (byte 8  8) total)
          (aref out 2) (ldb (byte 8 16) total)
          (aref out 3) (ldb (byte 8 24) total))
    (dotimes (i n)
      (setf (aref out (+ 4 i)) (aref bytes i)))
    out))

(defun* %cdr-u32-le (v)
    (function ((unsigned-byte 32)) (simple-array (unsigned-byte 8) (4)))
  "Encode V as a 4-byte little-endian uint32."
  (make-array 4 :element-type '(unsigned-byte 8)
                :initial-contents (list (ldb (byte 8  0) v)
                                        (ldb (byte 8  8) v)
                                        (ldb (byte 8 16) v)
                                        (ldb (byte 8 24) v))))

(defun* %concat-octets (&rest vecs)
    (function (&rest (simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)))
  "Concatenate octet vectors into a single fresh vector."
  (let* ((total (reduce #'+ vecs :key #'length :initial-value 0))
         (out   (make-array total :element-type '(unsigned-byte 8)))
         (pos   0))
    (dolist (v vecs out)
      (dotimes (i (length v))
        (setf (aref out pos) (aref v i))
        (incf pos)))))

(defun* %cdr-property-le (name value)
    (function (string string) (simple-array (unsigned-byte 8) (*)))
  "Encode a DDS-Security Property (name:string, value:string, propagate:boolean=true) in CDR LE.
   propagate is 1 byte (true=1) + 3 pad bytes to restore 4-byte alignment (DDS-Security §7.2)."
  (%concat-octets (%cdr-string-le name)
                  (%cdr-string-le value)
                  (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(1 0 0 0))))

;;; --- IdentityToken computation (§8.7.2.2 / §9.3.1) ---

(defun* %build-identity-token (cert-sn cert-algo ca-sn ca-algo)
    (function (string string string string) (simple-array (unsigned-byte 8) (*)))
  "Serialize a DDS-Security IdentityToken as a CDR LE DataHolder (§8.7.2.2 / §9.3.1).
   Layout: class_id:string + properties:seq<Property>(4) + binary_properties:seq(0).
   Property names are the T0-pinned constants from constants.lisp."
  (%concat-octets
   (%cdr-string-le +auth-plugin-class-id+)
   (%cdr-u32-le 4)
   (%cdr-property-le +id-token-prop-cert-sn+   cert-sn)
   (%cdr-property-le +id-token-prop-cert-algo+ cert-algo)
   (%cdr-property-le +id-token-prop-ca-sn+     ca-sn)
   (%cdr-property-le +id-token-prop-ca-algo+   ca-algo)
   (%cdr-u32-le 0)))

(defun* %cert-algo-string (pkey)
    (function (cffi:foreign-pointer) (or string null))
  "Return the IdentityToken algo string for the public key: +TOKEN-ALGO-EC+ or +TOKEN-ALGO-RSA+.
   Returns NIL on unrecognized key type so the caller's (unless … nil) guard fails closed (§8.7.2.2)."
  (case (dds.dare:pkey-kind pkey)
    (:ec  +token-algo-ec+)
    (:rsa +token-algo-rsa+)
    (t    nil)))

;;; --- identity-handle struct ---

(defstruct* (identity-handle (:constructor %make-identity-handle))
  "PKI identity handle for DDS-Security 1.1 §8.7 Authentication plugin.
   Holds: cert = X509* foreign cert handle; pkey = EVP_PKEY* private-key foreign handle;
   ca-store = X509_STORE* trust-store handle; token-octets = CDR LE IdentityToken octet vector
   (§8.7.2.2 / §9.3.1); guid = 16-octet participant GUID (§8.7.2.4 GUID ordering).
   All foreign handles MUST be released via FREE-IDENTITY-HANDLE."
  (cert        (cffi:null-pointer) :type cffi:foreign-pointer)
  (pkey        (cffi:null-pointer) :type cffi:foreign-pointer)
  (ca-store    (cffi:null-pointer) :type cffi:foreign-pointer)
  (token-octets (make-array 0 :element-type '(unsigned-byte 8))
                :type (simple-array (unsigned-byte 8) (*)))
  (guid        (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
               :type (simple-array (unsigned-byte 8) (16))))

;;; --- public API ---

(defun* validate-local-identity (ca-pem cert-pem key-pem guid)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*)))
              (values (or identity-handle null) (or string null)))
  "Load and validate a local DDS participant identity from PEM octet vectors.
   CA-PEM: Identity CA certificate PEM octets.
   CERT-PEM: Participant identity certificate PEM octets.
   KEY-PEM: Participant private key PEM octets.
   GUID: 16-octet participant GUID (used for the §8.7.2.4 role decision in validate-remote-identity).
   Returns (values IDENTITY-HANDLE NIL) on success, (values NIL reason-string) on failure.
   All foreign handles are owned by the returned identity-handle; caller MUST call
   FREE-IDENTITY-HANDLE when done (DDS-Security 1.1 §8.7.2 / §9.3.1)."
  (handler-case (dds.dare:dare-available-p)
    (dds.dare:dare-unavailable (c)
      (return-from validate-local-identity
        (values nil (format nil "OpenSSL unavailable: ~a" (dds.dare:dare-unavailable-reason c))))))
  (let ((ca-store nil) (cert nil) (pkey nil))
    (handler-case
        (progn
          (setf ca-store (dds.dare:x509-load-ca ca-pem))
          (unless ca-store
            (return-from validate-local-identity (values nil "failed to load CA into trust store")))
          (setf cert (dds.dare:x509-load-cert cert-pem))
          (unless cert
            (dds.dare:x509-ca-free ca-store)
            (return-from validate-local-identity (values nil "failed to load participant certificate")))
          ;; chain verify
          (unless (dds.dare:x509-verify-chain ca-store cert)
            (dds.dare:x509-free cert)
            (dds.dare:x509-ca-free ca-store)
            (return-from validate-local-identity (values nil "certificate chain verification failed")))
          (setf pkey (dds.dare:pkey-load-private key-pem))
          (unless pkey
            (dds.dare:x509-free cert)
            (dds.dare:x509-ca-free ca-store)
            (return-from validate-local-identity (values nil "failed to load private key")))
          ;; build IdentityToken — temporaries freed on every exit (success/early-return/signal)
          (let ((pub-key nil) (ca-cert nil) (ca-pub-key nil))
            (unwind-protect
                 (progn
                   (setf pub-key  (dds.dare:x509-public-key cert))
                   (setf ca-cert  (dds.dare:x509-load-cert ca-pem))
                   (when ca-cert
                     (setf ca-pub-key (dds.dare:x509-public-key ca-cert)))
                   (let* ((cert-sn   (dds.dare:x509-subject-name cert))
                          (cert-algo (%cert-algo-string pub-key))
                          (ca-sn     (when ca-cert (dds.dare:x509-subject-name ca-cert)))
                          (ca-algo   (when ca-pub-key (%cert-algo-string ca-pub-key))))
                     (unless (and cert-sn ca-sn cert-algo ca-algo)
                       (dds.dare:pkey-free pkey)
                       (dds.dare:x509-free cert)
                       (dds.dare:x509-ca-free ca-store)
                       (return-from validate-local-identity
                         (values nil "failed to extract cert/CA subject names")))
                     (let ((token (%build-identity-token cert-sn cert-algo ca-sn ca-algo)))
                       (values (%make-identity-handle :cert cert :pkey pkey :ca-store ca-store
                                                      :token-octets token :guid guid)
                               nil))))
              ;; cleanup: free the three temporaries on every exit path
              (when pub-key    (dds.dare:pkey-free pub-key))
              (when ca-pub-key (dds.dare:pkey-free ca-pub-key))
              (when ca-cert    (dds.dare:x509-free ca-cert)))))
      (error (e)
        (when pkey      (dds.dare:pkey-free pkey))
        (when cert      (dds.dare:x509-free cert))
        (when ca-store  (dds.dare:x509-ca-free ca-store))
        (values nil (format nil "validate-local-identity error: ~a" e))))))

(defun* identity-token (handle)
    (function (identity-handle) (simple-array (unsigned-byte 8) (*)))
  "Return the CDR LE IdentityToken octet vector from HANDLE (§8.7.2.2 / §9.3.1).
   The returned vector is the same object stored in the handle; do not mutate it."
  (identity-handle-token-octets handle))

(defun* free-identity-handle (handle)
    (function ((or identity-handle null)) t)
  "Release all foreign resources held by HANDLE (cert, pkey, ca-store).
   Idempotent: NIL argument is a no-op. Call exactly once at end-of-life."
  (when handle
    (dds.dare:pkey-free      (identity-handle-pkey     handle))
    (dds.dare:x509-free      (identity-handle-cert     handle))
    (dds.dare:x509-ca-free   (identity-handle-ca-store handle)))
  t)

;;; --- remote identity validation (§8.7.2.4) ---

(defun* %guid-lexicographic< (a b)
    (function ((simple-array (unsigned-byte 8) (16))
               (simple-array (unsigned-byte 8) (16)))
              boolean)
  "Return T if 16-byte GUID A is lexicographically less than B (§8.7.2.4 role ordering).
   Compares octets left-to-right; the first differing byte decides."
  (dotimes (i 16 nil)
    (let ((ai (aref a i)) (bi (aref b i)))
      (when (< ai bi) (return t))
      (when (> ai bi) (return nil)))))

(defun* %parse-remote-token-strings (token-octets)
    (function ((simple-array (unsigned-byte 8) (*)))
              (values (or string null) (or string null) (or string null) (or string null)))
  "Parse a CDR LE IdentityToken octet vector (§8.7.2.2) and extract the 4 property values.
   Returns (values cert-sn cert-algo ca-sn ca-algo) or (values NIL NIL NIL NIL) on malformed input.
   Bounds-checks every length before trusting wire data (NFR-SEC-POSTURE)."
  (handler-case
      (let ((n (length token-octets))
            (pos 0))
        ;; labels (not flet) so read-cdr-string can call read-u32
        (labels ((read-u32 ()
                   (when (> (+ pos 4) n) (error "truncated"))
                   (let ((v (logior (aref token-octets pos)
                                    (ash (aref token-octets (+ pos 1))  8)
                                    (ash (aref token-octets (+ pos 2)) 16)
                                    (ash (aref token-octets (+ pos 3)) 24))))
                     (incf pos 4)
                     v))
                 (read-cdr-string ()
                   ;; uint32-LE(len) || bytes(len including NUL) || pad-to-4
                   (let* ((len (read-u32))
                          (pad (mod (- 4 (mod len 4)) 4)))
                     (when (> len 65536) (error "string too long"))
                     (when (> (+ pos len pad) n) (error "truncated string"))
                     (let* ((str-len (max 0 (1- len)))
                            (s (make-string str-len)))
                       (dotimes (i str-len)
                         (setf (char s i) (code-char (aref token-octets (+ pos i)))))
                       (incf pos (+ len pad))
                       s)))
                 (read-cdr-property ()
                   ;; name:string, value:string, propagate:bool(1)+3pad
                   (let* ((name  (read-cdr-string))
                          (value (read-cdr-string)))
                     (when (> (+ pos 4) n) (error "truncated propagate field"))
                     (incf pos 4)         ; propagate byte + 3 pad
                     (values name value))))
          ;; skip class_id string
          (read-cdr-string)
          ;; read property count
          (let ((count (read-u32)))
            (when (> count 256) (error "too many properties"))
            ;; read up to 4 properties; extract by name
            (let ((cert-sn nil) (cert-algo nil) (ca-sn nil) (ca-algo nil))
              (dotimes (i count)
                (multiple-value-bind (name value) (read-cdr-property)
                  (cond ((string= name +id-token-prop-cert-sn+)   (setf cert-sn   value))
                        ((string= name +id-token-prop-cert-algo+) (setf cert-algo value))
                        ((string= name +id-token-prop-ca-sn+)     (setf ca-sn     value))
                        ((string= name +id-token-prop-ca-algo+)   (setf ca-algo   value)))))
              (values cert-sn cert-algo ca-sn ca-algo)))))
    (error () (values nil nil nil nil))))

(defun* validate-remote-identity (local remote-identity-token)
    (function (identity-handle (simple-array (unsigned-byte 8) (*)))
              (values (member :ok :rejected) (member :requester :replier) (or string null)))
  "Validate a remote participant's IdentityToken against the local identity (§8.7.2.4).
   LOCAL: the local participant's identity-handle.
   REMOTE-IDENTITY-TOKEN: the remote IdentityToken CDR octets (received on the wire).
   Returns (values VERDICT ROLE REASON):
     VERDICT: :OK if the token is well-formed and non-empty; :REJECTED otherwise.
     ROLE: :REQUESTER if local GUID < remote (derived) GUID, :REPLIER otherwise (§8.7.2.4).
     REASON: NIL on :OK, or a diagnostic string on :REJECTED.
   Bounds-checks all wire parsing (NFR-SEC-POSTURE; fail-closed)."
  ;; parse remote token
  (multiple-value-bind (remote-cert-sn remote-cert-algo remote-ca-sn remote-ca-algo)
      (%parse-remote-token-strings remote-identity-token)
    (unless (and remote-cert-sn remote-cert-algo remote-ca-sn remote-ca-algo)
      (return-from validate-remote-identity
        (values :rejected :requester "remote IdentityToken is malformed or missing required properties")))
    ;; derive a pseudo-GUID for the remote from the cert-sn hash (deterministic ordering)
    ;; We do NOT have the remote participant's real GUID over-wire at this point in T1.
    ;; The §8.7.2.4 GUID ordering operates on the actual RTPS participant GUIDs.
    ;; For T1 the token contains no GUID; the handshake tokens carry it. We use a
    ;; SHA-like hash of the remote cert-sn as a stable stand-in for the test-harness role
    ;; decision, making the local-vs-remote ordering deterministic for same-cert-sn cases.
    ;; NOTE: In T2 (handshake) the real GUID arrives in the ParticipantStatelessMessage.
    (let* ((local-guid   (identity-handle-guid local))
           (remote-bytes (map '(simple-array (unsigned-byte 8) (*)) #'char-code remote-cert-sn))
           ;; derive 16 fake remote-GUID bytes from cert-sn (stable ordering, not crypto)
           (remote-guid  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
      (dotimes (i (min 16 (length remote-bytes)))
        (setf (aref remote-guid i) (aref remote-bytes i)))
      (let ((role (if (%guid-lexicographic< local-guid remote-guid)
                      :requester
                      :replier)))
        (values :ok role nil)))))
