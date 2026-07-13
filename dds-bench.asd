;;;; WP-PERFTEST (M5/P4) — the performance harness that gates NFR-PERF. Drives the
;;;; participant data plane (dds-disc) over UDP loopback to measure one-way PING/PONG
;;;; latency percentiles, throughput, and bytes-consed-per-sample (NFR-PERF-8). Mirrors
;;;; the RTI Perftest latency/throughput scenarios. xperf.lisp adds the CROSS-STACK parity
;;;; harness (WP-CONFORMANCE-AND-PARITY WP-1): a DCPS-layer, cross-PROCESS echo ping-pong whose
;;;; responder is interchangeable (ours / Connext / Fast DDS), which is what turns these absolute
;;;; numbers into the NFR-PERF "within Nx of Connext" RATIOS the requirements actually specify. Not a unit test (long runs) — a `make bench` harness + a tiny smoke.
;;;; keeplast-bench adds the WP-KEEPLAST writer-side per-instance KEEP_LAST machinery cost
;;;; (HistoryCache add path, KEEP_LAST vs KEEP_ALL delta; `make bench-keeplast`, FR-LANG-7).
(defsystem "dds-bench"
  :description "DDS.BENCH — perftest harness: latency/throughput/allocation (NFR-PERF, FR-LANG-7)."
  :depends-on ("dds-pal" "dds-core" "dds-disc" "dds-rtps" "dds-qos" "dds-types" "dds-gen" "dds-dcps")
  :pathname "src/dds-bench"
  :serial t
  :components ((:file "packages")
               (:file "perftest")
               (:file "keeplast-bench")
               (:file "xperf")
               (:file "corpus")))
