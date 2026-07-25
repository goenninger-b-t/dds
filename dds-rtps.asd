;;;; L4 — RTPS engine (M0: frozen HistoryCache protocol + CacheChange shape).
(defsystem "dds-rtps"
  :description "DDS.RTPS — submessage codec + reliable engine + HistoryCache (M0 contracts)."
  :depends-on ("dds-pal" "dds-cdr" "dds-types" "dds-qos")
  :pathname "src/dds-rtps"
  :serial t
  :components ((:file "packages")
               (:file "history")
               (:file "message")
               (:file "reliable")
               (:file "discovery"))
  :in-order-to ((test-op (test-op "dds-tests"))))
