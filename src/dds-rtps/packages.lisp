;;;; L4 — RTPS engine. dds.rtps.history is a HOT-PATH package: the CacheChange
;;;; struct and its add/get ops are defstruct + monomorphic functions, no CLOS
;;;; (hotpath-purity-gate).

(defpackage #:net.goenninger.dds.rtps.history
  (:nicknames #:dds.rtps.history)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "HistoryCache protocol (IMPLEMENTATION-PLAN §7.4). A CacheChange is a pooled
    struct; the cache honours HISTORY (KEEP_LAST/KEEP_ALL), RESOURCE_LIMITS, and
    LIFESPAN. M0 freezes the shape and protocol; the state machine lands in M2.")
  (:export #:cache-change #:make-cache-change #:cache-change-p
           #:cache-change-kind #:cache-change-writer-guid #:cache-change-sn
           #:cache-change-instance-key-hash #:cache-change-serialized-payload
           #:cache-change-status-info
           #:cache-change-source-timestamp #:cache-change-inline-qos
           #:history-cache #:make-history-cache #:hc-change-count #:hc-kind #:hc-max-samples
           #:hc-add-change #:hc-remove-change #:hc-purge-below #:hc-get-change
           #:hc-min-seq #:hc-max-seq #:hc-changes-for-reader
           #:history-not-implemented))

;;;; dds.rtps.message is a HOT-PATH package: the submessage parser is the network
;;;; attack surface — defstruct + monomorphic functions, no CLOS, every parser
;;;; bounds-checked before trusting wire data (NFR-SEC-POSTURE).

(defpackage #:net.goenninger.dds.rtps.message
  (:nicknames #:dds.rtps.message)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "RTPS Message Header + Submessage framing + GUID/EntityId codec (RTPS 2.5
    §9.4.4/§9.4.5/§9.3.1.2). All wire constants are pinned from the in-repo spec
    (docs/specs/rtps-2_5.pdf), never memorized.")
  (:export #:+protocol-id+ #:+protocol-version-major+ #:+protocol-version-minor+
           #:+vendor-id-unknown+ #:+vendor-id-dev-provisional+ #:*vendor-id*
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
           #:write-fragment-number-set #:read-fragment-number-set
           #:fragnum-set-bit #:fragnum-set-member-p
           #:+heartbeat-flag-final+ #:+heartbeat-flag-liveliness+ #:+heartbeat-flag-group-info+
           #:+acknack-flag-final+ #:+gap-flag-group-info+ #:+gap-flag-filtered+
           #:write-heartbeat #:parse-heartbeat-body
           #:write-acknack #:parse-acknack-body
           #:write-gap #:parse-gap-body
           #:write-heartbeat-frag #:parse-heartbeat-frag-body
           #:write-nack-frag #:parse-nack-frag-body
           #:+data-flag-inline-qos+ #:+data-flag-data+ #:+data-flag-key+
           #:+data-flag-non-standard+
           #:+statusinfo-disposed+ #:+statusinfo-unregistered+ #:+statusinfo-filtered+
           #:status-info->kind #:write-status-info-inline-qos
           #:parse-inline-qos-key-status #:write-data-dispose
           #:write-data #:parse-data-body
           #:write-data-frag #:parse-data-frag-body
           #:+data-frag-flag-key+ #:+data-frag-flag-inline-qos+
           #:+pid-pad+ #:+pid-sentinel+ #:+pid-participant-lease-duration+
           #:+pid-topic-name+ #:+pid-type-name+ #:+pid-protocol-version+
           #:+pid-vendorid+ #:+pid-reliability+ #:+pid-durability+ #:+pid-liveliness+
           #:+pid-ownership+ #:+pid-ownership-strength+
           #:+pid-default-unicast-locator+
           #:+pid-metatraffic-unicast-locator+ #:+pid-participant-guid+
           #:+pid-builtin-endpoint-set+ #:+pid-endpoint-guid+ #:+pid-key-hash+
           #:+pid-status-info+
           #:+pid-type-information+ #:+pid-type-object-lb+ #:+pid-shmem-host-uuid+
           #:+pid-zerocopy-capable+
           #:write-parameter #:write-parameter-sentinel #:parse-parameter-list
           #:spdp-multicast-port #:spdp-unicast-port
           #:user-multicast-port #:user-unicast-port
           #:dispatch-message))

;;;; dds.rtps.reliable — the stateful reliable writer/reader protocol logic
;;;; (RTPS 2.5 §8.4). Value-level state machines over the HistoryCache; the
;;;; byte/transport wiring is a later increment. CLOS-free.

(defpackage #:net.goenninger.dds.rtps.reliable
  (:nicknames #:dds.rtps.reliable)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "Stateful reliable RTPS writer + reader (RTPS 2.5 §8.4.2/§8.4.10): ReaderProxy/
    WriterProxy, changes-for-reader, HEARTBEAT/ACKNACK/GAP-driven retransmit and
    reordering. Verified by a lossy/reorder/dup fault-injection suite (NFR-TEST).")
  (:export #:rtps-writer #:make-rtps-writer #:rtps-writer-hc #:writer-write #:writer-heartbeat
           #:writer-lifecycle-change #:rtps-writer-max-blocking-ns #:%writer-signal-space
           #:writer-data-list #:writer-unsent-list #:writer-on-acknack #:writer-purge-acked #:get-reader-proxy
           #:reader-proxy #:reader-proxy-acked-base
           #:rtps-reader #:make-rtps-reader #:reader-on-data #:reader-on-heartbeat
           #:reader-acknack #:reader-on-gap #:reader-complete-p
           #:get-writer-proxy #:writer-proxy #:writer-proxy-received #:writer-proxy-last-sn #:writer-proxy-first-sn
           #:*fragment-size* #:*max-reassembly-bytes* #:*max-reassembly-fragments*
           #:reader-on-data-frag #:reader-frag-acknack
           #:writer-frag-plan #:writer-frag-plan-for
           #:writer-frag-heartbeat #:writer-on-nack-frag #:writer-sample-payload))

;;;; dds.rtps.discovery — SPDP Locator_t codec + SPDPdiscoveredParticipantData
;;;; build/parse (RTPS 2.5 §8.5.3 / §9.6.2). Wire constants pinned from the in-repo
;;;; spec (docs/specs/rtps-2_5.pdf), never memorized. CLOS-free: defstruct +
;;;; monomorphic functions; every parser bounds-checked (NFR-SEC-POSTURE).

(defpackage #:net.goenninger.dds.rtps.discovery
  (:nicknames #:dds.rtps.discovery)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "Simple Participant Discovery Protocol (SPDP): the Locator_t codec (RTPS 2.5
    §9.3.2.4) and SPDPdiscoveredParticipantData ParameterList build/parse (§8.5.3/
    §9.6.2). PID values from §9.6.2.2; Duration/Locator layouts from §9.3.2.")
  (:export #:+locator-kind-udpv4+ #:+locator-kind-shmem+ #:+locator-bytes+
           #:make-shmem-locator-wire #:shmem-locator-wire-lane-count
           #:+entityid-spdp-writer+ #:+entityid-spdp-reader+
           #:+entityid-sedp-pub-writer+ #:+entityid-sedp-pub-reader+
           #:+entityid-sedp-sub-writer+ #:+entityid-sedp-sub-reader+
           #:+be-tl-request-writer+ #:+be-tl-request-reader+
           #:+be-tl-reply-writer+ #:+be-tl-reply-reader+
           #:+entityid-p2p-participant-message-writer+ #:+entityid-p2p-participant-message-reader+
           #:+pmd-kind-unknown+ #:+pmd-kind-automatic+ #:+pmd-kind-manual-by-participant+
           #:+be-participant-message-writer+ #:+be-participant-message-reader+
           #:participant-message #:make-participant-message #:participant-message-p
           #:participant-message-guid-prefix #:participant-message-kind #:participant-message-data
           #:serialize-participant-message #:parse-participant-message
           #:+builtin-endpoint-set-default+
           #:write-locator #:read-locator #:make-ipv4-locator
           #:locator #:make-locator #:locator-p
           #:locator-kind #:locator-port #:locator-address
           #:locator-ipv4-string #:locator-usable-udpv4-p #:usable-udpv4-locator
           #:spdp-data #:make-spdp-data #:spdp-data-p
           #:spdp-data-guid-prefix #:spdp-data-version-major #:spdp-data-version-minor
           #:spdp-data-vendor-id
           #:spdp-data-default-unicast-locators #:spdp-data-metatraffic-unicast-locators
           #:spdp-data-lease-duration-seconds #:spdp-data-builtin-endpoint-set
           #:spdp-data-host-uuid
           #:serialize-spdp-data #:parse-spdp-data
           #:run-discovery-test
           #:+reliability-best-effort+ #:+reliability-reliable+
           #:endpoint-data #:make-endpoint-data #:endpoint-data-p
           #:endpoint-data-guid #:endpoint-data-topic-name
           #:endpoint-data-type-name #:endpoint-data-qos
           #:endpoint-data-type-information #:endpoint-data-type-object-lb
           #:endpoint-data-zerocopy-capable
           #:serialize-endpoint-data #:parse-endpoint-data #:endpoint-match-p
           #:run-sedp-test))
