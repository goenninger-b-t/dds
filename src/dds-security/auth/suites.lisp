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
  (kagree-gen      (lambda () (error "no kagree-gen")) :type function)
  (kagree-compute  (lambda (h p) (declare (ignore h p)) (error "no kagree-compute")) :type function)
  (dsign-sign      (lambda (h d) (declare (ignore h d)) (error "no dsign-sign")) :type function)
  (dsign-verify    (lambda (h d s) (declare (ignore h d s)) (error "no dsign-verify")) :type function)
  (hash            (lambda (o) (declare (ignore o)) (error "no hash")) :type function))

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
