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
