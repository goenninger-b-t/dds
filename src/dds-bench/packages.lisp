;;;; dds.bench — WP-PERFTEST harness package (M5/P4). Exposes the latency, throughput,
;;;; and allocation measurements plus run-bench (the make bench entry) and a smoke run.

(defpackage #:net.goenninger.dds.bench
  (:nicknames #:dds.bench)
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation
   "Performance harness for the participant data plane (NFR-PERF / FR-LANG-7): one-way
    PING/PONG latency percentiles, throughput (samples/s + Mbps), and bytes-consed per
    sample (NFR-PERF-8 oracle). run-bench prints a markdown report; run-bench-shmem prints the
    SHMEM-vs-UDP comparison (WP-SHMEM); run-bench-zerocopy prints the large-sample
    ZC-vs-SHMEM-vs-UDP comparison (WP-ZEROCOPY/FR-PF-3, NOT cleared for ship — counsel R6);
    run-bench-smoke / run-bench-shmem-smoke / run-bench-zerocopy-smoke are tiny suite-friendly
    self-checks.")
  (:export ;; WP-CONFORMANCE-AND-PARITY WP-1: the cross-stack (ours / Connext / Fast DDS) parity harness
           #:run-echo-responder #:run-echo-pinger #:corpus-capture #:corpus-verify #:*corpus-dir* #:run-echo-ladder
           #:mutable-corpus-capture #:run-mutable-publisher #:run-mutable-subscriber
           #:mem-per-sample
           #:perf-data #:make-perf-data
           #:run-latency #:run-throughput #:run-bench #:run-bench-shmem #:run-bench-zerocopy
           #:run-bench-smoke #:run-bench-shmem-smoke #:run-bench-zerocopy-smoke
           #:run-keeplast-bench #:run-keeplast-bench-smoke))
