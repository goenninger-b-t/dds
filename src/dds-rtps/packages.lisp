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
           #:history-cache #:make-history-cache #:hc-change-count
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
           #:seqnum-set-bit #:seqnum-set-bit-p #:seqnum-set-member-p
           #:+heartbeat-flag-final+ #:+heartbeat-flag-liveliness+ #:+heartbeat-flag-group-info+
           #:+acknack-flag-final+ #:+gap-flag-group-info+ #:+gap-flag-filtered+
           #:write-heartbeat #:parse-heartbeat-body
           #:write-acknack #:parse-acknack-body
           #:write-gap #:parse-gap-body
           #:+data-flag-inline-qos+ #:+data-flag-data+ #:+data-flag-key+
           #:+data-flag-non-standard+
           #:write-data #:parse-data-body
           #:+pid-pad+ #:+pid-sentinel+ #:+pid-participant-lease-duration+
           #:+pid-topic-name+ #:+pid-type-name+ #:+pid-protocol-version+
           #:+pid-vendorid+ #:+pid-reliability+ #:+pid-default-unicast-locator+
           #:+pid-metatraffic-unicast-locator+ #:+pid-participant-guid+
           #:+pid-builtin-endpoint-set+ #:+pid-endpoint-guid+ #:+pid-key-hash+
           #:write-parameter #:write-parameter-sentinel #:parse-parameter-list
           #:spdp-multicast-port #:spdp-unicast-port
           #:user-multicast-port #:user-unicast-port
           #:dispatch-message))

;;;; dds.rtps.reliable — the stateful reliable writer/reader protocol logic
;;;; (RTPS 2.5 §8.4). Value-level state machines over the HistoryCache; the
;;;; byte/transport wiring is a later increment. CLOS-free.

(defpackage #:net.goenninger.dds.rtps.reliable
  (:nicknames #:dds.rtps.reliable)
  (:use #:common-lisp)
  (:documentation
   "Stateful reliable RTPS writer + reader (RTPS 2.5 §8.4.2/§8.4.10): ReaderProxy/
    WriterProxy, changes-for-reader, HEARTBEAT/ACKNACK/GAP-driven retransmit and
    reordering. Verified by a lossy/reorder/dup fault-injection suite (NFR-TEST).")
  (:export #:rtps-writer #:make-rtps-writer #:writer-write #:writer-heartbeat
           #:writer-data-list #:writer-on-acknack #:get-reader-proxy
           #:reader-proxy #:reader-proxy-acked-base
           #:rtps-reader #:make-rtps-reader #:reader-on-data #:reader-on-heartbeat
           #:reader-acknack #:reader-on-gap #:reader-complete-p
           #:get-writer-proxy #:writer-proxy #:writer-proxy-received))
