;;;; L4 — RTPS engine. dds.rtps.history is a HOT-PATH package: the CacheChange
;;;; struct and its add/get ops are defstruct + monomorphic functions, no CLOS
;;;; (hotpath-purity-gate).

(defpackage #:net.goenninger.dds.rtps.history
  (:nicknames #:dds.rtps.history)
  (:use #:common-lisp)
  (:documentation
   "HistoryCache protocol (IMPLEMENTATION-PLAN §7.4). A CacheChange is a pooled
    struct; the cache honours HISTORY (KEEP_LAST/KEEP_ALL), RESOURCE_LIMITS, and
    LIFESPAN. M0 freezes the shape and protocol; the state machine lands in M2.")
  (:export #:cache-change #:make-cache-change #:cache-change-p
           #:cache-change-kind #:cache-change-writer-guid #:cache-change-sn
           #:cache-change-instance-key-hash #:cache-change-serialized-payload
           #:cache-change-source-timestamp #:cache-change-inline-qos
           #:history-cache #:make-history-cache
           #:hc-add-change #:hc-remove-change #:hc-get-change
           #:hc-min-seq #:hc-max-seq #:hc-changes-for-reader
           #:history-not-implemented))

;;;; dds.rtps.message is a HOT-PATH package: the submessage parser is the network
;;;; attack surface — defstruct + monomorphic functions, no CLOS, every parser
;;;; bounds-checked before trusting wire data (NFR-SEC-POSTURE).

(defpackage #:net.goenninger.dds.rtps.message
  (:nicknames #:dds.rtps.message)
  (:use #:common-lisp)
  (:documentation
   "RTPS Message Header + Submessage framing + GUID/EntityId codec (RTPS 2.5
    §9.4.4/§9.4.5/§9.3.1.2). All wire constants are pinned from the in-repo spec
    (docs/specs/rtps-2_5.pdf), never memorized.")
  (:export #:+protocol-id+ #:+protocol-version-major+ #:+protocol-version-minor+
           #:+vendor-id-unknown+ #:*vendor-id*
           #:+submsg-pad+ #:+submsg-acknack+ #:+submsg-heartbeat+ #:+submsg-gap+
           #:+submsg-info-ts+ #:+submsg-info-src+ #:+submsg-info-reply-ip4+
           #:+submsg-info-dst+ #:+submsg-info-reply+ #:+submsg-nack-frag+
           #:+submsg-heartbeat-frag+ #:+submsg-data+ #:+submsg-data-frag+
           #:+flag-endianness+ #:+entityid-unknown+ #:+entityid-participant+
           #:write-header #:parse-header
           #:write-submessage-header #:parse-submessage-header
           #:write-entity-id #:read-entity-id
           #:+sequence-number-unknown+ #:+seqnum-set-max-bits+
           #:write-sequence-number #:read-sequence-number
           #:write-sequence-number-set #:read-sequence-number-set
           #:seqnum-set-bit #:seqnum-set-member-p))
