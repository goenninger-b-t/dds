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
           #:disc-node-matched-count #:disc-node-matched-topics #:disc-node-matched-endpoints-for
           #:disc-node-on-match #:disc-node-on-unmatch
           #:disc-node-on-participant-lost
           #:disc-node-on-liveliness-changed #:%liveliness-sweep
           #:disc-node-on-lifecycle-event
           #:disc-node-on-incompatible-qos #:disc-node-on-sample #:disc-node-on-sample-lost
           #:disc-node-on-inconsistent-topic
           #:disc-node-type-gate #:resume-parked-matches #:disc-node-parked-count
           #:add-local-writer #:add-local-reader
           #:remove-local-writer #:remove-local-reader
           #:disc-node-user-writer-id #:disc-node-user-reader-id
           ;; WP-N-ENDPOINT-S3 (ADR 0048): per-endpoint enumeration + protection-kind resolvers (crypto-manager consumers)
           #:%all-user-writer-ids #:%all-user-reader-ids #:%user-endpoint-kinds #:%local-user-writer-id-for-topic
           #:start-node #:stop-node
           #:announce-participant #:announce-endpoints
           #:enable-publisher #:enable-subscriber
           #:%writer-durability-init #:%reader-durability-init #:finalize-writer-durability
           #:publish-sample #:publish-relay-sample #:publish-relay-lifecycle #:flush-batch #:disc-node-batch-max-samples #:enable-async
           #:flow-token-bucket #:flow-token-bucket-p #:make-flow-token-bucket
           #:flow-token-bucket-tokens #:flow-token-bucket-max-burst
           #:flow-controller #:flow-controller-p #:make-flow-controller #:destroy-flow-controller
           #:flow-controller-associate #:flow-controller-unregister #:flow-controller-remove-writer #:flow-controller-thread
           #:*shmem-enabled* #:*zerocopy-enabled* #:disc-node-shmem #:disc-node-shmem-sends #:disc-node-shmem-send-faults #:disc-node-host-uuid
           #:disc-node-zc-sends #:+zerocopy-pool-slots+ #:+zerocopy-pool-slot-bytes+ #:*zerocopy-min-payload-bytes*
           ;; WP-DDS-SECURITY-ZEROALLOC-AEAD T5a: data_protection encode-pool sizing knobs + the per-node arena slot
           #:*secured-payload-max-bytes* #:*secured-pool-capacity* #:*secured-pool-headroom* #:disc-node-payload-arena
           ;; WP-RESIDUAL-FIXES-BATCH-A / ADR 0031 lim.1: reliable-reader decode-failure retransmit-suppression knobs
           #:*decode-fail-suppress-threshold* #:*decode-fail-track-limit*
           ;; WP-DDS-SECURITY-ZEROALLOC-AEAD T3 (ZA-2): whole-RTPS (rtps_protection / SRTPS) send-scratch pool capacity knob
           #:*srtps-send-scratch-capacity*
           ;; WP-DDS-SECURITY-ZEROALLOC-AEAD T5b: data_protection DECODE loan (zero-alloc secured receive via the loan registry)
           #:set-secured-loan-capable #:disc-node-secured-loan-capable #:disc-node-decode-pool #:disc-node-decode-pool-rejects
           #:secured-loan-handle #:secured-loan-handle-p #:secured-loan-handle-len
           #:secured-loan-handle-buffer #:secured-loan-handle-guid #:secured-loan-handle-sn #:secured-loan-bytes
           #:node-take-loaned #:node-return-loan #:node-return-all-loans #:node-secured-reader-p
           ;; WP-FLATDATA-ZC-LOAN (FR-PF-3/4, R6, ADR 0017): loan-capable flag + the unresolved ZC-ref marker
           #:set-zc-loan-capable #:disc-node-zc-loan-capable
           ;; WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042): TX loan-write pool API
           #:node-loan-write-eligible-p #:node-loan-write-acquire #:node-loan-write-abort #:node-loan-write-commit
           ;; WP-ACKED-SLOT-PINNING (FR-PF-4, R6, ADR 0044): pin-until-ack budget + capability gate
           #:*zc-pin-budget* #:node-loan-write-pin-capable-p #:disc-node-zc-pin-count
           #:zc-loan-marker #:zc-loan-marker-p #:zc-loan-marker-pool-sap
           #:zc-loan-marker-slot-index #:zc-loan-marker-generation #:zc-loan-marker-len
           #:node-sample-count #:node-sample #:node-sample-sns
           #:node-sample-writer #:node-sample-writer-guid #:node-sample-origin-guid #:node-sample-origin-sn #:node-sample-key-hash #:node-sample-key-sn #:node-sample-by-sn #:matched-writer-ownership
           #:node-reader-join-watermark
           #:node-user-reader-count #:node-reader-matches-writer-p
           #:dispose-instance #:unregister-instance
           #:node-lifecycle-change #:node-lifecycle-change-by-sn #:node-lifecycle-count #:node-lifecycle-sns
           #:*datagram-sink*
           #:*debug-drop-fragment-numbers*
           #:*debug-drop-sample-numbers*
           ;; WP-SENDER-ERROR-RESILIENCE (FR-PF-2): the sender-thread emit guard + its observability + test affordance
           #:*sender-emit-error-hook* #:with-sender-emit-guard #:*debug-emit-fault* #:sender-emit-test-fault
           #:node-discovered-participants #:resolved-destination #:node-acks-in
           #:+entityid-tl-req-writer+ #:+entityid-tl-req-reader+
           #:+entityid-tl-reply-writer+ #:+entityid-tl-reply-reader+
           #:*typelookup-timeout* #:*max-typelookup-pending*
           #:type-lookup-query #:tl-sweep
           #:assert-participant-liveliness #:disc-node-remote-liveliness-stamp
           #:disc-node-discovered-writers-list #:disc-node-discovered-readers-list
           #:run-spdp-discovery-test #:run-sedp-discovery-test
           #:run-mcast-discovery-test #:run-dataplane-test #:run-n-writer-dataplane-test #:run-n-same-topic-writer-dataplane-test #:run-n-writer-frag-heartbeat-test #:run-n-reader-dataplane-test
           #:run-n-reader-s4-decode-tier-test #:run-n-reader-s4-zc-marker-test
           #:run-n-reader-2c3-zc-uaf-test #:run-n-reader-2c3-secured-purge-defer-test #:run-n-reader-2c3-watermark-purge-test
           #:run-n-reader-2c3-zc-refcount-leak-test
           #:run-large-dataplane-test #:run-participant-liveliness-test
           #:run-locator-filter-test #:run-lost-final-sample-test
           #:run-dispose-dataplane-test #:run-dispose-repair-test
           ;; ADR 0031: DDS-Security 1.1 §9.5.3.3 Slice-1 serialized-payload protection slot
           #:disc-node-crypto-transform
           ;; Slice 2b-i: IdentityToken octets for SPDP PID_IDENTITY_TOKEN + PSM endpoint-set bits
           #:disc-node-identity-token-octets
           ;; Slice 2b-i: ParticipantStatelessMessage builtin endpoints (DDS-Security 1.1 §7.4.3)
           #:disc-node-on-stateless-message
           #:%send-stateless-message
           #:%on-stateless-message
           ;; Slice 4 (T7): reliable ParticipantVolatileMessageSecure builtin endpoint (DDS-Security 1.1 §7.4.5 / §9.5.3.1)
           #:enable-volatile-secure
           #:disc-node-on-volatile-secure
           #:%pvms-derive-bootstrap-km
           #:set-pvms-bootstrap-km
           #:%send-volatile-secure
           #:%on-volatile-secure
           #:%pvms-push-heartbeat
           #:%pvms-push-heartbeats-all
           #:%pvms-role-session-id
           #:*pvms-debug-drop-sns*
           #:run-volatile-secure-reliable-test
           #:run-pvms-peer-loss-prune-test
           #:run-volatile-secure-fail-closed-test
           #:run-volatile-secure-purge-bound-test
           #:run-volatile-secure-session-id-on-wire-test
           ;; Slice 4 (T9): secure SEDP builtin endpoints (DDS-Security 1.1 §7.4.5 / §8.4.1.6 / §9.4.1.2.3)
           #:disc-node-secure-sedp-encode-km
           #:disc-node-secure-sedp-decode-km
           #:disc-node-discovery-protected-topic-p
           #:disc-node-secure-sedp-protection-kind
           #:disc-node-secure-sedp-origin-auth
           #:disc-node-secure-sedp-encode-receivers
           #:disc-node-secure-sedp-decode-receiver-km
           #:disc-node-secure-sedp-decode-sender-entity
           ;; Slice 4 (T11): secure participant-message (liveliness) + secure SPDP re-announce
           #:disc-node-secure-pm-protection-kind
           #:disc-node-secure-pm-origin-auth
           #:run-secure-participant-message-test
           #:run-secure-participant-message-tamper-test
           #:run-secure-pm-origin-auth-roundtrip-test
           #:run-secure-pm-origin-auth-tamper-test
           #:run-secure-spdp-reannounce-test
           ;; DDS-Security 1.1 §7.3/§8.5: keying is a match precondition only when governance mandates protection
           #:disc-node-crypto-keying-required-p
           #:disc-node-rtps-protection-kind
           #:disc-node-rtps-protection-origin-auth
           #:disc-node-rtps-protection-encode
           #:disc-node-rtps-protection-decode
           ;; Slice 5 (WP-DDS-SECURITY-FASTDDS-INTEROP): USER-DATA submessage protection (metadata_protection)
           #:disc-node-user-submessage-protection-kind
           #:disc-node-user-data-protection-kind
           ;; ADR 0046: per-role protection kinds (writer's / reader's own topic kind — the cross-role downgrade fix)
           #:disc-node-user-writer-data-protection-kind
           #:disc-node-user-writer-submessage-protection-kind
           #:disc-node-user-reader-data-protection-kind
           #:disc-node-user-reader-submessage-protection-kind
           #:disc-node-topic-data-protection-resolver
           #:disc-node-topic-metadata-protection-resolver
           #:disc-node-user-submessage-encode
           #:disc-node-user-submessage-decode
           #:run-user-submessage-protection-test
           #:run-user-submessage-data-protection-test
           #:run-secure-builtin-sender-crosscheck-test
           #:run-secure-builtin-acknack-count-test
           #:run-user-submessage-protection-zeroalloc-test
           #:run-secured-dataplane-mem-test
           #:run-secure-sedp-roundtrip-test
           #:run-secure-sedp-sign-roundtrip-test
           #:run-secure-sedp-origin-auth-roundtrip-test
           #:run-secure-sedp-origin-auth-tamper-test
           #:run-rtps-protection-test
           #:run-rtps-protection-zeroalloc-test
           #:run-rtps-protection-enforce-test
           #:run-rtps-protection-enforce-reliability-test
           #:run-rtps-protection-enforce-user-bracket-test
           #:run-zc-shmem-secured-cleartext-test
           #:run-zc-shmem-secured-overlay-test
           ;; WP-DDS-SECURITY-AUTH-KEYX T4: auth extension points (DDS-Security 1.1 §7.3/7.4.3.2)
           #:disc-node-on-participant-discovered
           #:disc-node-auth-gate
           #:disc-node-auth-state
           ;; WP-DDS-SECURITY-ACCESS-CONTROL T4: access-control gate (DDS-Security 1.1 §8.4)
           #:disc-node-permissions-gate))
