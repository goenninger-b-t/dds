;;;; L0 — Platform Abstraction Layer. Per-impl code confined here (NFR-BUILD).
(defsystem "dds-pal"
  :description "DDS.PAL — frozen L0 platform abstraction contract + per-impl backends."
  :depends-on ("dds-lang" "static-vectors" "bordeaux-threads" "cffi")
  :pathname "src/dds-pal"
  :serial t
  ;; Two backends, one per target (ADR 0118 withdrew Clasp). pal-allegro completes the per-impl PAL
  ;; contract (ADR 0113) and pal-net's socket layer runs on AllegroCL's SOCKET module (ADR 0114).
  :components ((:file "pal-contract")
               (:file "pal-sbcl"    :if-feature :sbcl)
               (:file "pal-allegro" :if-feature :allegro)
               (:file "pal-net")
               ;; ADR 0121: EXIT-PROCESS and the shutdown-hook chain. Last, because it registers the PAL's own
               ;; hook over the shm registry in pal-net and calls each backend's %HARD-EXIT.
               (:file "pal-exit"))
  :in-order-to ((test-op (test-op "dds-tests"))))
