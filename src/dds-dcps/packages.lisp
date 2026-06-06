;;;; L6 — DCPS entity package. QoS now lives in dds-qos (L3, foundational) so the
;;;; discovery matcher can share it.

(defpackage #:net.goenninger.dds.dcps
  (:nicknames #:dds.dcps)
  (:use #:common-lisp)
  (:documentation
   "DDS 1.4 DCPS entity model (M3/P2, FR-DCPS-1) — CLOS, control-plane. Entities
    (DomainParticipant, Publisher/Subscriber, Topic, DataWriter/DataReader) over the
    RTPS engine (dds.disc), with typed write/take through the generated type-support.
    v1: one writer + one reader per participant (the engine's single user endpoint);
    discovery is caller-driven via SPIN. Multi-endpoint, instance lifecycle +
    SampleInfo, conditions/WaitSets, and content-filter are later increments.")
  (:export #:entity #:domain-participant #:publisher #:subscriber
           #:topic #:data-writer #:data-reader
           #:entity-qos #:entity-enabled-p
           #:create-participant #:delete-participant
           #:create-publisher #:create-subscriber #:create-topic
           #:create-datawriter #:create-datareader
           #:write-sample #:read-samples #:take-samples #:samples-available
           #:sample-info #:make-sample-info
           #:sample-info-sample-state #:sample-info-view-state #:sample-info-instance-state
           #:sample-info-source-timestamp #:sample-info-instance-handle
           #:sample-info-publication-handle #:sample-info-valid-data
           #:sample-info-disposed-generation-count #:sample-info-no-writers-generation-count
           #:sample-info-sample-rank #:sample-info-generation-rank
           #:sample-info-absolute-generation-rank #:sample-info-sequence-number
           #:cached-sample #:cached-sample-data #:cached-sample-info
           #:spin #:discovered-count #:matched-count
           #:wait-condition #:guard-condition #:read-condition #:query-condition
           #:status-condition #:wait-set
           #:make-guard-condition #:set-trigger-value #:create-readcondition
           #:create-querycondition #:qc-query-fn #:read-w-condition #:take-w-condition
           #:make-status-condition #:make-wait-set
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
           #:get-subscription-matched-status #:get-publication-matched-status
           #:get-requested-incompatible-qos-status #:get-offered-incompatible-qos-status
           #:inconsistent-topic-status #:inconsistent-topic-status-total-count
           #:inconsistent-topic-status-total-count-change
           #:get-inconsistent-topic-status #:set-topic-listener
           #:sample-rejected-status #:sample-rejected-reason
           #:sample-rejected-status-total-count #:sample-rejected-status-total-count-change
           #:sample-rejected-status-last-reason #:sample-rejected-status-last-instance-handle
           #:get-sample-rejected-status
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
           #:cft-name #:cft-related-topic #:cft-expression #:cft-parameters))
