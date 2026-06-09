;;;; L5 — Discovery-over-UDP package. A minimal RTPS participant that announces
;;;; SPDP to its unicast peers and records discovered participants. The builtin
;;;; EntityIds + SPDP ParameterList codecs live in DDS.RTPS.DISCOVERY; this layer
;;;; only wires them to the DDS.XPORT UDP transport + receiver thread. SPDP only
;;;; for this increment; SEDP/multicast are later increments. CLOS-free hot path
;;;; is not a concern here (discovery is control-plane, not per-sample).

(defpackage #:net.goenninger.dds.disc
  (:nicknames #:dds.disc)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "Simple Participant Discovery over UDP (FR-DISC-1/4): make-disc-node opens a
    metatraffic UDPv4 socket; start-node spawns a receiver thread; announce-
    participant sends SPDPdiscoveredParticipantData to the configured unicast
    peers; inbound SPDP records the remote participant keyed by GUID prefix.")
  (:export #:disc-node #:disc-node-p #:make-disc-node
           #:disc-node-guid-prefix #:disc-node-peers #:disc-node-port
           #:disc-node-discovered-count #:disc-node-discovered-prefixes
           #:disc-node-matched-count #:disc-node-matched-topics
           #:disc-node-on-match #:disc-node-on-incompatible-qos #:disc-node-on-sample
           #:disc-node-on-inconsistent-topic
           #:add-local-writer #:add-local-reader
           #:start-node #:stop-node
           #:announce-participant #:announce-endpoints
           #:enable-publisher #:enable-subscriber
           #:publish-sample #:node-sample-count #:node-sample #:node-sample-sns
           #:node-discovered-participants #:resolved-destination #:node-acks-in
           #:disc-node-discovered-writers-list #:disc-node-discovered-readers-list
           #:run-spdp-discovery-test #:run-sedp-discovery-test
           #:run-mcast-discovery-test #:run-dataplane-test
           #:run-locator-filter-test))
