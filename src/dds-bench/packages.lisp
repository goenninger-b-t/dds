;;;; dds.bench — WP-PERFTEST harness package (M5/P4). Exposes the latency, throughput,
;;;; and allocation measurements plus run-bench (the make bench entry) and a smoke run.

(defpackage #:net.goenninger.dds.bench
  (:nicknames #:dds.bench)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "Performance harness for the participant data plane (NFR-PERF / FR-LANG-7): one-way
    PING/PONG latency percentiles, throughput (samples/s + Mbps), and bytes-consed per
    sample (NFR-PERF-8 oracle). run-bench prints a markdown report; run-bench-smoke is a
    tiny suite-friendly self-check.")
  (:export #:run-latency #:run-throughput #:run-bench #:run-bench-smoke))
