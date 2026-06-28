;;;; L5 — Discovery wired over UDP. Ties the RTPS message framing + SPDP codecs
;;;; (dds-rtps) to the native UDPv4 transport + receiver thread (dds-xport): a
;;;; participant announces SPDPdiscoveredParticipantData to its unicast peers and
;;;; records the participants it discovers from inbound SPDP (FR-DISC-1/4).
(defsystem "dds-disc"
  :description "DDS.DISC — SPDP participant discovery wired over the UDP transport."
  :depends-on ("dds-pal" "dds-core" "dds-cdr" "dds-qos" "dds-types" "dds-rtps" "dds-xport" "dds-security")
  :pathname "src/dds-disc"
  :serial t
  :components ((:file "packages")
               (:file "disc")
               (:file "dataplane")
               (:file "flow-control")
               (:file "typelookup-endpoints")
               (:file "participant-message")
               (:file "stateless-message")
               (:file "volatile-secure")
               (:file "secure-sedp"))
  :in-order-to ((test-op (test-op "dds-tests"))))
