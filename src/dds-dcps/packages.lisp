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
           #:wait-condition #:guard-condition #:read-condition #:status-condition #:wait-set
           #:make-guard-condition #:set-trigger-value #:create-readcondition
           #:make-status-condition #:make-wait-set
           #:attach-condition #:detach-condition #:wait-set-wait #:condition-trigger-value))
