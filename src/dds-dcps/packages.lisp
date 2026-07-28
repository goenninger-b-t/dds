;;;; L6 — DCPS entity package. QoS now lives in dds-qos (L3, foundational) so the
;;;; discovery matcher can share it.

(defpackage #:net.goenninger.dds.dcps
  (:nicknames #:dds.dcps)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "DDS 1.4 DCPS entity model (M3/P2, FR-DCPS-1) — CLOS, control-plane. Entities
    (DomainParticipant, Publisher/Subscriber, Topic, DataWriter/DataReader) over the
    RTPS engine (dds.disc), with typed write/take through the generated type-support.
    v1: one writer + one reader per participant (the engine's single user endpoint);
    discovery is caller-driven via SPIN. Multi-endpoint, instance lifecycle +
    SampleInfo, conditions/WaitSets, and content-filter are later increments.")
  (:export #:entity #:domain-participant #:publisher #:subscriber
           #:topic #:data-writer #:data-reader
           #:entity-qos #:entity-enabled-p #:entity-type-compat #:*type-compat-log*
           #:*max-typeobject-cache-entries* #:*typelookup-max-depth*
           #:create-participant #:delete-participant
           #:create-publisher #:create-subscriber #:create-topic
           #:create-datawriter #:create-datareader
           ;; WP-DCPS-API-COMPLETION S2.T1: DomainParticipantFactory singleton (DDS 1.4 §2.2.2.2.2)
           #:domain-participant-factory #:get-participant-factory #:get-instance
           #:lookup-participant
           #:participant-factory-autoenable-p #:set-participant-factory-autoenable
           ;; WP-DCPS-API-COMPLETION S2.T2: parent->children containment registry (DDS 1.4 §2.2.2)
           #:participant-publishers #:participant-subscribers #:participant-topics
           ;; participant identity accessors (public surface for identity-stamping, ADR 0082 §3)
           #:participant-guid-prefix #:participant-advertise-address
           #:publisher-datawriters #:subscriber-datareaders
           ;; WP-DCPS-API-COMPLETION S2.T3: enable() + disabled-entity semantics (DDS 1.4 §2.2.2.1.1.7)
           #:enable #:entity-autoenable-created-entities
           #:+retcode-not-enabled+ #:+retcode-precondition-not-met+
           ;; WP-DCPS-API-COMPLETION S2.T4/T5: child delete_* + delete_contained_entities (DDS 1.4 §2.2.2)
           #:delete-datawriter #:delete-datareader #:delete-publisher #:delete-subscriber
           #:delete-topic #:delete-contained-entities
           #:write-sample #:read-samples #:take-samples #:samples-available
           #:read-instance #:take-instance #:read-next-instance #:take-next-instance
           #:read-next-sample #:take-next-sample
           ;; WP-FLATDATA-ZC-LOAN literal-0-copy loan API (FR-PF-3/4, R6, ADR 0017)
           #:take-loaned #:read-loaned #:return-loan #:return-all-loans
           ;; ADR 0093 slice 1: the RX copy path's wrapper pooling A/B lever (NFR-MEM). Returning a taken
           ;; sample via return-loan recycles its wrapper; NIL restores a fresh wrapper pair per sample.
           #:*rx-wrapper-pool-enabled*
           ;; ADR 0090 A3b: application acknowledgment (VENDOR EXTENSION — DDS 1.4 and RTPS 2.5 define
           ;; none). Effective only under ACKNOWLEDGMENT_KIND :APPLICATION-EXPLICIT.
           #:acknowledge-sample #:acknowledge-all
           ;; WP-FLATDATA-LOAN-WRITE zero-copy TX loan API (FR-PF-4, R6, ADR 0042)
           #:loan-sample #:write-loaned #:discard-loan #:writer-loan #:writer-loan-p
           #:writer-loan-sample #:discard-all-loans
           #:register-instance #:dispose-instance #:unregister-instance
           #:lookup-instance #:get-key-value #:+instance-handle-nil+
           #:write-w-timestamp #:dispose-w-timestamp #:unregister-instance-w-timestamp #:writedispose
           #:+retcode-ok+ #:+retcode-timeout+ #:+retcode-bad-parameter+
           ;; WP-DCPS-API-COMPLETION S1.T3: get_qos/set_qos + IMMUTABLE/INCONSISTENT return codes
           #:get-qos #:set-qos
           #:+retcode-immutable-policy+ #:+retcode-inconsistent-policy+
           ;; WP-DCPS-API-COMPLETION S1.T4: default-QoS getters/setters (DDS 1.4 §2.2.2)
           #:get-default-datawriter-qos #:set-default-datawriter-qos
           #:get-default-datareader-qos #:set-default-datareader-qos
           #:get-default-topic-qos #:set-default-topic-qos
           #:get-default-publisher-qos #:set-default-publisher-qos
           #:get-default-subscriber-qos #:set-default-subscriber-qos
           #:get-default-participant-qos #:set-default-participant-qos
           #:sample-info #:make-sample-info
           #:sample-info-sample-state #:sample-info-view-state #:sample-info-instance-state
           ;; the DDS state masks (dds_rtf2_dcps.idl §294-320): ANY_SAMPLE/VIEW/INSTANCE_STATE
           #:+any-sample-states+ #:+any-view-states+ #:+any-instance-states+
           #:rc-view-states #:rc-instance-states
           #:sample-info-source-timestamp #:sample-info-instance-handle
           #:sample-info-publication-handle #:sample-info-valid-data
           #:sample-info-disposed-generation-count #:sample-info-no-writers-generation-count
           #:sample-info-sample-rank #:sample-info-generation-rank
           #:sample-info-absolute-generation-rank #:sample-info-sequence-number
           #:cached-sample #:cached-sample-data #:cached-sample-info
           #:spin #:discovered-count #:matched-count
           ;; WP-DCPS-API-COMPLETION S0.T2: per-entity status-changes bitmask + StatusKind bits
           #:get-status-changes
           #:+status-inconsistent-topic+ #:+status-offered-deadline-missed+
           #:+status-requested-deadline-missed+ #:+status-offered-incompatible-qos+
           #:+status-requested-incompatible-qos+ #:+status-sample-lost+
           #:+status-sample-rejected+ #:+status-data-on-readers+ #:+status-data-available+
           #:+status-liveliness-lost+ #:+status-liveliness-changed+
           #:+status-publication-matched+ #:+status-subscription-matched+
           #:wait-condition #:guard-condition #:read-condition #:query-condition
           #:status-condition #:wait-set
           #:make-guard-condition #:set-trigger-value #:create-readcondition
           #:create-querycondition #:qc-query-fn #:read-w-condition #:take-w-condition
           #:make-status-condition #:make-wait-set
           ;; WP-DCPS-API-COMPLETION S0.T4: entity-owned StatusCondition + enabled-statuses
           #:get-statuscondition #:set-enabled-statuses #:get-enabled-statuses
           #:attach-condition #:detach-condition #:wait-set-wait #:condition-trigger-value
           ;; Communication statuses (FR-DCPS-3)
           #:subscription-matched-status #:publication-matched-status
           #:requested-incompatible-qos-status #:offered-incompatible-qos-status
           #:qos-policy-count #:make-qos-policy-count
           #:qos-policy-count-policy-id #:qos-policy-count-count
           #:subscription-matched-status-total-count #:subscription-matched-status-total-count-change
           #:subscription-matched-status-current-count #:subscription-matched-status-current-count-change
           #:subscription-matched-status-last-publication-handle
           #:publication-matched-status-total-count #:publication-matched-status-total-count-change
           #:publication-matched-status-current-count #:publication-matched-status-current-count-change
           #:publication-matched-status-last-subscription-handle
           #:requested-incompatible-qos-status-total-count
           #:requested-incompatible-qos-status-total-count-change
           #:requested-incompatible-qos-status-last-policy-id
           #:requested-incompatible-qos-status-policies
           #:offered-incompatible-qos-status-total-count
           #:offered-incompatible-qos-status-total-count-change
           #:offered-incompatible-qos-status-last-policy-id
           #:offered-incompatible-qos-status-policies
           #:rxo-policy-id
           #:+qos-policy-id-durability+ #:+qos-policy-id-reliability+
           #:+qos-policy-id-deadline+ #:+qos-policy-id-latency-budget+
           #:+qos-policy-id-ownership+ #:+qos-policy-id-liveliness+
           #:+qos-policy-id-destination-order+ #:+qos-policy-id-presentation+
           #:+qos-policy-id-data-representation+
           #:+qos-policy-id-invalid+
           #:+qos-policy-id-time-based-filter+ #:+qos-policy-id-history+
           #:+qos-policy-id-resource-limits+ #:+qos-policy-id-type-consistency+
           ;; WP-DCPS-API-COMPLETION S1.T1/T2: QoS immutability table + consistency validator
           #:qos-policy-immutable-p
           #:get-subscription-matched-status #:get-unaddressable-peer-status
           #:unaddressable-peer-status #:unaddressable-peer-status-total-count #:unaddressable-peer-status-last-guid
           #:unaddressable-peer-status-last-locator-kinds #:unaddressable-peer-status-last-locator-names #:+status-unaddressable-peer+ #:get-publication-matched-status
           #:get-requested-incompatible-qos-status #:get-offered-incompatible-qos-status
           #:inconsistent-topic-status #:inconsistent-topic-status-total-count
           #:inconsistent-topic-status-total-count-change
           #:get-inconsistent-topic-status #:set-topic-listener
           #:sample-rejected-status #:sample-rejected-reason
           #:sample-rejected-status-total-count #:sample-rejected-status-total-count-change
           #:sample-rejected-status-last-reason #:sample-rejected-status-last-instance-handle
           #:get-sample-rejected-status
           #:liveliness-changed-status
           #:liveliness-changed-status-alive-count #:liveliness-changed-status-not-alive-count
           #:liveliness-changed-status-alive-count-change
           #:liveliness-changed-status-not-alive-count-change
           #:liveliness-changed-status-last-publication-handle
           #:get-liveliness-changed-status
           #:liveliness-lost-status
           #:liveliness-lost-status-total-count #:liveliness-lost-status-total-count-change
           #:get-liveliness-lost-status #:assert-liveliness
           #:get-offered-deadline-missed-status #:get-requested-deadline-missed-status
           #:get-sample-lost-status
           ;; WP-DCPS-API-COMPLETION S0.T1: SAMPLE_LOST + OFFERED/REQUESTED_DEADLINE_MISSED
           #:sample-lost-status #:make-sample-lost-status #:copy-sample-lost-status
           #:sample-lost-status-total-count #:sample-lost-status-total-count-change
           #:offered-deadline-missed-status #:make-offered-deadline-missed-status
           #:copy-offered-deadline-missed-status
           #:offered-deadline-missed-status-total-count
           #:offered-deadline-missed-status-total-count-change
           #:offered-deadline-missed-status-last-instance-handle
           #:requested-deadline-missed-status #:make-requested-deadline-missed-status
           #:copy-requested-deadline-missed-status
           #:requested-deadline-missed-status-total-count
           #:requested-deadline-missed-status-total-count-change
           #:requested-deadline-missed-status-last-instance-handle
           #:durability-finalize
           ;; Listeners (FR-DCPS-2)
           #:listener #:data-reader-listener #:data-writer-listener #:topic-listener
           ;; WP-DCPS-API-COMPLETION S3.T1: the 3 missing listener interfaces (DDS 1.4 §2.2.4.1)
           #:publisher-listener #:subscriber-listener #:domain-participant-listener
           #:on-data-on-readers
           #:on-data-available #:on-subscription-matched #:on-requested-incompatible-qos
           #:on-requested-deadline-missed #:on-sample-rejected #:on-sample-lost
           #:on-liveliness-changed
           #:on-publication-matched #:on-offered-incompatible-qos
           #:on-offered-deadline-missed #:on-liveliness-lost
           #:on-inconsistent-topic #:on-unaddressable-peer
           ;; ADR 0089: VENDOR-EXTENSION listener operations (not DDS 1.4) — Connext-compatible
           ;; notifications riding the same status machinery.
           #:on-reliable-writer-cache-changed #:on-reliable-reader-activity-changed
           #:get-reliable-writer-cache-changed-status #:get-reliable-reader-activity-changed-status
           #:+status-reliable-writer-cache-changed+ #:+status-reliable-reader-activity-changed+
           ;; ADR 0090 A3c: APPLICATION_ACKNOWLEDGMENT (bit 28 — 27 is RESERVED, see statuses.lisp).
           ;; The only callback that reports "the application has processed it" rather than "it arrived".
           #:on-application-acknowledgment #:get-application-acknowledgment-status
           #:+status-application-acknowledgment+
           #:application-acknowledgment-status #:make-application-acknowledgment-status
           #:application-acknowledgment-status-total-count
           #:application-acknowledgment-status-total-count-change
           #:application-acknowledgment-status-last-subscription-handle
           #:application-acknowledgment-status-last-sequence-number
           #:application-acknowledgment-status-app-unacked-sample-count
           #:on-application-acknowledgment-overdue #:get-application-acknowledgment-overdue-status
           #:+status-application-acknowledgment-overdue+
           #:application-acknowledgment-overdue-status
           #:application-acknowledgment-overdue-status-total-count
           #:application-acknowledgment-overdue-status-total-count-change
           #:application-acknowledgment-overdue-status-last-subscription-handle
           #:application-acknowledgment-overdue-status-oldest-unacknowledged-sequence-number
           #:application-acknowledgment-overdue-status-app-unacked-sample-count
           #:reliable-writer-cache-changed-status
           #:reliable-writer-cache-changed-status-empty-count
           #:reliable-writer-cache-changed-status-empty-count-change
           #:reliable-writer-cache-changed-status-full-count
           #:reliable-writer-cache-changed-status-full-count-change
           #:reliable-writer-cache-changed-status-low-watermark-count
           #:reliable-writer-cache-changed-status-low-watermark-count-change
           #:reliable-writer-cache-changed-status-high-watermark-count
           #:reliable-writer-cache-changed-status-high-watermark-count-change
           #:reliable-writer-cache-changed-status-unacked-sample-count
           #:reliable-writer-cache-changed-status-unacked-sample-peak
           #:reliable-writer-cache-changed-status-replaced-unacked-sample-count
           #:reliable-reader-activity-changed-status
           #:reliable-reader-activity-changed-status-active-count
           #:reliable-reader-activity-changed-status-active-count-change
           #:reliable-reader-activity-changed-status-inactive-count
           #:reliable-reader-activity-changed-status-inactive-count-change
           #:reliable-reader-activity-changed-status-last-instance-handle
           #:set-reader-listener #:set-writer-listener
           ;; WP-DCPS-API-COMPLETION S3.T1: uniform set_listener/get_listener on all six kinds
           #:set-listener #:get-listener
           ;; WP-DCPS-API-COMPLETION S3.T3: on_data_on_readers + get_datareaders/notify_datareaders
           #:get-datareaders #:notify-datareaders
           ;; Content-filter / query SQL-subset grammar (FR-DCPS-5)
           #:compile-filter #:lex-filter
           #:filter-status #:filter-status-code #:filter-status-detail
           #:content-filtered-topic #:create-contentfilteredtopic
           #:set-cft-expression-parameters
           #:cft-name #:cft-related-topic #:cft-expression #:cft-parameters
           ;; Builtin topics (FR-DCPS-6)
           #:participant-builtin-topic-data #:participant-builtin-topic-data-key
           #:publication-builtin-topic-data #:subscription-builtin-topic-data
           #:topic-builtin-topic-data
           #:publication-builtin-topic-data-key #:publication-builtin-topic-data-participant-key
           #:publication-builtin-topic-data-topic-name #:publication-builtin-topic-data-type-name
           #:publication-builtin-topic-data-reliability #:publication-builtin-topic-data-durability
           #:subscription-builtin-topic-data-key #:subscription-builtin-topic-data-participant-key
           #:subscription-builtin-topic-data-topic-name #:subscription-builtin-topic-data-type-name
           #:subscription-builtin-topic-data-reliability #:subscription-builtin-topic-data-durability
           #:topic-builtin-topic-data-name #:topic-builtin-topic-data-type-name
           #:get-builtin-participant-data #:get-builtin-publication-data
           #:get-builtin-subscription-data #:get-builtin-topic-data
           #:get-matched-subscriptions #:get-matched-publications
           #:get-matched-subscription-data #:get-matched-publication-data))
