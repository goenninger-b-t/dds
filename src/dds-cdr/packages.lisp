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
           #:make-encapsulation-header #:parse-encapsulation-header
           #:finalize-encapsulation-options
           #:encode-zc-reference #:parse-zc-reference #:+zc-ref-overlay-secured+
           #:cdr-not-implemented
           ;; XCDR primitive + composite codec (FR-CDR-1/2)
           #:cdr-mode #:cdr-align #:cdr-size-align
           #:cdr-put-u8 #:cdr-get-u8 #:cdr-put-u16 #:cdr-get-u16
           #:cdr-put-u32 #:cdr-get-u32 #:cdr-put-u64 #:cdr-get-u64
           #:cdr-put-i8 #:cdr-get-i8 #:cdr-put-i16 #:cdr-get-i16
           #:cdr-put-i32 #:cdr-get-i32 #:cdr-put-i64 #:cdr-get-i64
           #:cdr-put-bool #:cdr-get-bool #:cdr-put-enum #:cdr-get-enum
           #:cdr-put-string #:cdr-get-string
           #:cdr-put-sequence #:cdr-get-sequence
           ;; XCDR2 framing (FR-CDR-2, XTypes 1.3 §7.4.3.4)
           #:cdr-put-dheader #:cdr-get-dheader
           #:emheader1-encode #:emheader1-decode #:lc-for-length))
