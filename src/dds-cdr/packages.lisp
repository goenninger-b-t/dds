;;;; L2 — CDR codec. dds.cdr is a HOT-PATH package: defstruct + monomorphic
;;;; functions only, no CLOS (hotpath-purity-gate).

(defpackage #:net.goenninger.dds.cdr
  (:nicknames #:dds.cdr)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "XCDR1 + XCDR2 codec substrate (IMPLEMENTATION-PLAN §7.2). The codec is NOT
    generic-function based: generated per-type functions (serialize-T /
    deserialize-T / serialized-size-T / key-hash-T) call concrete buffer ops.
    Encapsulation representation IDs are filled from [XTYPES]/[RTPS] tables and
    verified byte-exact (FR-CDR-3) — never hardcoded from memory.")
  (:export #:+representation-ids+ #:extensibility-kind #:+zc-encapsulation-id+
           #:representation-id #:representation-id-value #:representation-id-name
           #:flatdata-rx-rep-plan
           #:make-encapsulation-header #:parse-encapsulation-header #:encapsulation-id-for
           #:finalize-encapsulation-options
           #:encode-zc-reference #:parse-zc-reference #:+zc-ref-overlay-secured+
           #:cdr-not-implemented
           ;; XCDR primitive + composite codec (FR-CDR-1/2)
           #:cdr-mode #:cdr-align #:cdr-size-align
           #:cdr-put-u8 #:cdr-get-u8 #:cdr-put-u16 #:cdr-get-u16
           #:cdr-put-u32 #:cdr-get-u32 #:cdr-put-u64 #:cdr-get-u64
           #:cdr-put-f32 #:cdr-get-f32 #:cdr-put-f64 #:cdr-get-f64
           #:cdr-put-i8 #:cdr-get-i8 #:cdr-put-i16 #:cdr-get-i16
           #:cdr-put-i32 #:cdr-get-i32 #:cdr-put-i64 #:cdr-get-i64
           #:cdr-put-bool #:cdr-get-bool #:cdr-put-enum #:cdr-get-enum
           #:cdr-put-string #:cdr-get-string #:utf8-octet-length #:string-to-utf8-octets #:+utf8-max-code-point+
           #:cdr-put-sequence #:cdr-get-sequence #:cdr-get-sequence-typed
           #:cdr-put-octet-sequence #:cdr-get-octet-sequence
           ;; XCDR2 framing (FR-CDR-2, XTypes 1.3 §7.4.3.4)
           #:cdr-put-dheader #:cdr-get-dheader
           #:emheader1-encode #:emheader1-decode #:lc-for-length #:lc-member-extent
           #:+flag-impl-extension+ #:+flag-must-understand+
           #:+pid-extended+ #:+pid-extended-mu+ #:+pid-list-end+ #:+pid-list-end-mu+ #:+pid-ignore+
           #:+pid-sentinel-rtps+ #:+emheader-mu-flag+
           #:pl-pid-encode #:pl-pid-decode #:pl-end-of-list-p))

(in-package #:dds.cdr)

;;; ADR 0114: CDR-MODE is defined HERE, in the first-loaded file, and not beside its users in
;;; primitives.lisp — because cdr.lisp is compiled BEFORE primitives.lisp and declaims an ftype that
;;; mentions it. A type referenced before its DEFTYPE is a deferred style-warning on SBCL and Clasp and a
;;; HARD ERROR on AllegroCL, which reported it as "(FUNCTION ((UNSIGNED-BYTE 16)) (:DEFAULT)) is not a
;;; valid type specifier" and blocked 12 of the 18 systems from loading. The forward reference was always
;;; a latent defect; only a third implementation made it fatal.
(deftype cdr-mode ()
  "The XCDR encoding version an operation is running under: :XCDR1 (PLAIN_CDR) or :XCDR2 (PLAIN_CDR2).
   Threaded explicitly through every codec entry point rather than held in a special, so a serializer and
   its deserializer cannot disagree about the encoding at a distance."
  '(member :xcdr1 :xcdr2))
