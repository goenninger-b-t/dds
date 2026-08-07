;;;; L0 — Platform Abstraction Layer. Per-impl code confined here (NFR-BUILD).
(defsystem "dds-pal"
  :description "DDS.PAL — frozen L0 platform abstraction contract + per-impl backends."
  :depends-on ("dds-lang" "static-vectors" "bordeaux-threads" "cffi")
  :pathname "src/dds-pal"
  :serial t
  :components ((:file "pal-contract")
               (:file "pal-clasp"   :if-feature :clasp)
               (:file "pal-sbcl"    :if-feature :sbcl)
               ;; ADR 0004 follow-through: the Allegro backend exists but is INCOMPLETE (4 of the 40
               ;; per-impl symbols). Wired now so the file is built and type-checked on Allegro rather
               ;; than rotting unloaded; :dds-pal does not yet load there. See pal-allegro.lisp's header.
               (:file "pal-allegro" :if-feature :allegro)
               (:file "pal-net"))
  :in-order-to ((test-op (test-op "dds-tests"))))
