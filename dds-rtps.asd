;;;; L4 — RTPS engine (M0: frozen HistoryCache protocol + CacheChange shape).
(defsystem "dds-rtps"
  :description "DDS.RTPS — submessage codec + reliable engine + HistoryCache (M0 contracts)."
  :depends-on ("dds-cdr" "dds-types")
  :pathname "src/dds-rtps"
  :serial t
  :components ((:file "packages")
               (:file "history")
               (:file "message")
               (:file "reliable"))
  :in-order-to ((test-op (test-op "dds-tests"))))
