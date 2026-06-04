;;;; L0 — Platform Abstraction Layer. Per-impl code confined here (NFR-BUILD).
(defsystem "dds-pal"
  :description "DDS.PAL — frozen L0 platform abstraction contract + per-impl backends."
  :depends-on ("static-vectors" "bordeaux-threads" "cffi")
  :pathname "src/dds-pal"
  :serial t
  :components ((:file "pal-contract")
               (:file "pal-clasp" :if-feature :clasp)
               (:file "pal-sbcl"  :if-feature :sbcl)
               (:file "pal-net"))
  :in-order-to ((test-op (test-op "dds-tests"))))
