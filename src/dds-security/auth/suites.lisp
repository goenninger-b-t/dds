(in-package #:dds.security)

;;; DDS-Security 1.1 §9.3 auth-suite vtable: kagree + dsign + hash primitives.
;;; +suite-ecdh+ wires ECDH+prime256v1-CEUM / ECDSA-SHA256 / SHA-256 from dds.dare (§9.3.2).

(defstruct* (auth-suite (:constructor %make-auth-suite))
  "Authentication suite vtable for DDS-Security 1.1 §9.3 key agreement + signing primitives.
   kagree-algo-str: kagree_algo wire string (§9.3.2.1).
   dsign-algo-str: dsign_algo wire string (§9.3.2.1).
   kagree-gen: () -> (values pub-octets priv-handle) — ephemeral key pair.
   kagree-compute: (priv-handle peer-pub-octets) -> shared-raw-octets — raw ECDH agreed value.
   dsign-sign: (priv-handle data) -> sig-octets — produce DER-encoded signature.
   dsign-verify: (pub-handle data sig) -> boolean — verify DER-encoded signature.
   hash: (octets) -> digest-octets — hash for hash_c1/hash_c2/SharedSecret (§9.3.2)."
  (kagree-algo-str "" :type string)
  (dsign-algo-str  "" :type string)
  (kagree-gen      (lambda () (error 'contract-violation :detail "cipher-suite: kagree-gen not populated")) :type function)   ; NOCOND(CONTRACT): unpopulated vtable slot — fires only if an unbuilt suite is used
  (kagree-compute  (lambda (h p) (declare (ignore h p)) (error 'contract-violation :detail "cipher-suite: kagree-compute not populated")) :type function)   ; NOCOND(CONTRACT): unpopulated vtable slot
  (dsign-sign      (lambda (h d) (declare (ignore h d)) (error 'contract-violation :detail "cipher-suite: dsign-sign not populated")) :type function)   ; NOCOND(CONTRACT): unpopulated vtable slot
  (dsign-verify    (lambda (h d s) (declare (ignore h d s)) (error 'contract-violation :detail "cipher-suite: dsign-verify not populated")) :type function)   ; NOCOND(CONTRACT): unpopulated vtable slot
  (hash            (lambda (o) (declare (ignore o)) (error 'contract-violation :detail "cipher-suite: hash not populated")) :type function))   ; NOCOND(CONTRACT): unpopulated vtable slot

(defparameter +suite-ecdh+
    (%make-auth-suite
     :kagree-algo-str +kagree-algo-ecdh+
     :dsign-algo-str  +dsign-algo-ecdsa+
     :kagree-gen      #'dds.dare:ecdh-gen-keypair
     :kagree-compute  #'dds.dare:ecdh-compute
     :dsign-sign      #'dds.dare:ecdsa-sign
     :dsign-verify    #'dds.dare:ecdsa-verify
     :hash            #'dds.dare:sha-256)
  "Auth suite: EC P-256 ECDH+prime256v1-CEUM + ECDSA-SHA256 + SHA-256 (DDS-Security 1.1 §9.3).")

(defun* %ffdh-gen-keypair-wrapper ()
    (function () (values (simple-array (unsigned-byte 8) (*)) cffi:foreign-pointer))
  "Wrap dds.dare:ffdh-gen-keypair with the MODP-2048 p/g constants (§9.3 / RFC 3526 §3)."
  (dds.dare:ffdh-gen-keypair +modp-2048-p+ +modp-2048-g+))

(defparameter +suite-ffdh+
    (%make-auth-suite
     :kagree-algo-str +kagree-algo-ffdh+
     :dsign-algo-str  +dsign-algo-rsa+
     :kagree-gen      #'%ffdh-gen-keypair-wrapper
     :kagree-compute  #'dds.dare:ffdh-compute
     :dsign-sign      #'dds.dare:rsa-pss-sign
     :dsign-verify    #'dds.dare:rsa-pss-verify
     :hash            #'dds.dare:sha-256)
  "Auth suite: DH+MODP-2048-256 + RSASSA-PSS-SHA256 + SHA-256 (DDS-Security 1.1 §9.3 / RFC 3526 §3).")

(defun* %cert-algo->kind (algo-string)
    (function (string) (or (member :ec :rsa) null))
  "Map a dds.cert.algo IdentityToken string to a cert kind keyword (§8.7.2.2 / §9.3.1).
   +token-algo-ec+ (\"EC-prime256v1\") -> :EC; +token-algo-rsa+ (\"RSA-2048\") -> :RSA; else NIL."
  (cond
    ((string= algo-string +token-algo-ec+)  :ec)
    ((string= algo-string +token-algo-rsa+) :rsa)
    (t nil)))

(defun* select-auth-suite (local-cert-kind remote-cert-kind)
    (function ((member :ec :rsa) (member :ec :rsa)) (or auth-suite null))
  "Select the §9.3.2 auth suite from the local and remote identity certificate key kinds.
   Both :EC  -> +suite-ecdh+  (ECDH+prime256v1-CEUM / ECDSA-SHA256).
   Both :RSA -> +suite-ffdh+  (DH+MODP-2048-256 / RSASSA-PSS-SHA256).
   Mismatched pair -> NIL (no common suite; handshake MUST reject per DDS-Security 1.1 §9.3.2).
   Source: DDS-Security 1.1 §9.3.2 (cert key type -> kagree_algo / dsign_algo mapping)."
  (cond
    ((and (eq local-cert-kind :ec)  (eq remote-cert-kind :ec))  +suite-ecdh+)
    ((and (eq local-cert-kind :rsa) (eq remote-cert-kind :rsa)) +suite-ffdh+)
    (t nil)))

(defun* select-suite-for-identities (local-identity remote-id-token-octets)
    (function (identity-handle (simple-array (unsigned-byte 8) (*))) (or auth-suite null))
  "Select the §9.3.2 auth suite for a discovered remote from the local identity and the
   remote IdentityToken octets, deriving both certificate kinds via %CERT-ALGO->KIND on
   their advertised dds.cert.algo property (§8.7.2.2 / §9.3.2.1). The remote's dds.cert.algo
   is an OPTIONAL advertisement hint: when the remote OMITS it (a §9.3.2.1-conformant empty
   IdentityToken — live RTI Connext 7.3.1) the requester proposes the suite for its OWN cert
   kind (EFFECTIVE-REMOTE := LOCAL-KIND); the §8.7.2.4 handshake (c.id chain-verify + Sign +
   c.kagree_algo/c.dsign_algo) then enforces the real algo match FAIL-CLOSED, so a genuine
   EC/RSA mismatch is refused there. An EXPLICITLY-advertised mismatched algo still yields NIL
   (REJECT), unchanged. Returns NIL — REJECT — when the LOCAL algo is unsupported/unparseable
   or the effective kinds yield no common suite; else the selected AUTH-SUITE (DDS-Security 1.1 §9.3.2)."
  (let* ((local-kind  (%cert-algo->kind
                       (or (nth-value 1 (%parse-remote-token-strings
                                         (identity-handle-token-octets local-identity)))
                           "")))
         (remote-kind (%cert-algo->kind
                       (or (nth-value 1 (%parse-remote-token-strings remote-id-token-octets))
                           "")))
         ;; §9.3.2.1: dds.cert.algo optional -> when the remote omits it, propose our own kind (handshake enforces)
         (effective-remote (or remote-kind local-kind)))
    (if (and local-kind effective-remote)
        (select-auth-suite local-kind effective-remote)
        nil)))
