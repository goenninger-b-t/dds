;;;; L7 — Transport record + M0 loopback mock.
(defsystem "dds-xport"
  :description "DDS.XPORT — pluggable transport record + synchronous loopback mock."
  :depends-on ("dds-core")
  :pathname "src/dds-xport"
  :serial t
  :components ((:file "packages")
               (:file "transport")
               (:file "udp")
               (:file "shmem")
               (:file "rti-shmem")
               (:file "zerocopy-pool"))
  :in-order-to ((test-op (test-op "dds-tests"))))
