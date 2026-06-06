;;;; L1 — Core runtime: static arena, off-heap buffers, cursors.
(defsystem "dds-core"
  :description "DDS.CORE — static arena (*static-arena-bytes*), off-heap buffers + cursors."
  :depends-on ("dds-pal")
  :pathname "src/dds-core"
  :serial t
  :components ((:file "packages")
               (:file "buffer")
               (:file "arena")
               (:file "md5"))
  :in-order-to ((test-op (test-op "dds-tests"))))
