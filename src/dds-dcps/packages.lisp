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
           #:write-sample #:read-samples #:take-samples #:samples-available
           ;; WP-FLATDATA-ZC-LOAN literal-0-copy loan API (FR-PF-3/4, R6, ADR 0017)
           #:take-loaned #:read-loaned #:return-loan #:return-all-loans
           ;; WP-FLATDATA-LOAN-WRITE zero-copy TX loan API (FR-PF-4, R6, ADR 0042)
           #:loan-sample #:write-loaned #:discard-loan #:writer-loan #:writer-loan-p
           #:writer-loan-sample #:discard-all-loans
           #:register-instance #:dispose-instance #:unregister-instance
           #:+retcode-ok+ #:+retcode-timeout+
           #:sample-info #:make-sample-info
           #:sample-info-sample-state #:sample-info-view-state #:sample-info-instance-state
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
           #:+qos-policy-id-time-based-filter+ #:+qos-policy-id-history+
           #:+qos-policy-id-resource-limits+ #:+qos-policy-id-type-consistency+
           ;; WP-DCPS-API-COMPLETION S1.T1/T2: QoS immutability table + consistency validator
           #:qos-policy-immutable-p
           #:get-subscription-matched-status #:get-publication-matched-status
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
           #:on-data-available #:on-subscription-matched #:on-requested-incompatible-qos
           #:on-requested-deadline-missed #:on-sample-rejected #:on-sample-lost
           #:on-liveliness-changed
           #:on-publication-matched #:on-offered-incompatible-qos
           #:on-offered-deadline-missed #:on-liveliness-lost
           #:on-inconsistent-topic
           #:set-reader-listener #:set-writer-listener
           ;; Content-filter / query SQL-subset grammar (FR-DCPS-5)
           #:compile-filter #:lex-filter #:filter-error #:filter-error-detail
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
           #:get-builtin-subscription-data #:get-builtin-topic-data))
