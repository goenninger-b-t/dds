;;;; L1 — Core runtime packages. dds.core.buffer is a HOT-PATH package
;;;; (hotpath-purity-gate): defstruct + monomorphic functions only, no CLOS.

(defpackage #:net.goenninger.dds.core.buffer
  (:nicknames #:dds.core.buffer)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "Off-heap octet buffers + cursors (IMPLEMENTATION-PLAN §7.1). HOT PATH:
    no defclass/defgeneric/defmethod, no per-sample allocation. Every op is
    bounds-checked at the boundary (NFR-SEC-POSTURE). Alignment is relative to a
    settable origin (default 0); the codec sets it past the encapsulation header
    per RTPS 2.5 §10.2.")
  (:export #:octet-buffer #:make-octet-buffer #:octet-buffer-over #:octet-buffer-vec
           #:octet-buffer-capacity #:buffer-sap
           #:cursor #:cursor-reuse #:cursor-buffer #:cursor-position #:cursor-endianness
           #:cursor-origin #:cursor-set-origin #:cursor-set-endianness #:cursor-set-position
           #:cursor-reset #:align
           #:put-u8 #:get-u8 #:put-u16 #:get-u16 #:put-u32 #:get-u32
           #:put-u64 #:get-u64 #:put-octets #:get-octets
           #:check-room #:buffer-overflow))

(defpackage #:net.goenninger.dds.core.md5
  (:nicknames #:dds.core.md5)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "MD5 (RFC 1321), vendored clean-room. Content/identity hash for the XTypes
    EquivalenceHash/NameHash (FR-TYPE-2) + the DDS keyhash >16-byte case (FR-TYPE-5).
    NOT a DDS-Security primitive (FR-SEC-2 requires vetted native crypto).")
  (:export #:md5))

(defpackage #:net.goenninger.dds.core.arena
  (:nicknames #:dds.core.arena)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "Static, startup-allocated, non-GC'd arena + fixed-capacity pools
    (IMPLEMENTATION-PLAN §7.7, REQUIREMENTS NFR-MEM). The home of
    *static-arena-bytes*, read ONCE at init-arena; later rebinding is a no-op
    until teardown. pool-acquire returning NIL is the exhaustion signal — the
    engine maps it to RESOURCE_LIMITS, NEVER a GC-heap fallback.")
  (:export #:*static-arena-bytes* #:*static-arena-growth-bytes* #:*static-arena-max-bytes*
           #:arena-growths #:arena-max-bytes
           #:arena #:init-arena #:teardown-arena
           #:*process-arena* #:process-arena #:make-sub-arena
           #:arena-byte-budget #:arena-bytes-used #:arena-reserved #:arena-pools
           #:arena-initialized-p #:arena-report
           #:buffer-pool #:make-buffer-pool #:pool-acquire #:pool-release
           #:carve-buffer
           #:pool-high-water #:pool-capacity #:pool-in-use
           ))
