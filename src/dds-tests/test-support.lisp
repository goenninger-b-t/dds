(in-package #:dds.tests)

;;; Configurable test DDS domain (owner directive): every test's DDS domain derives from
;;; ONE knob, dds.tests:*test-domain*, so the whole suite can be shifted off any domain a
;;; foreign participant occupies (e.g. an rtiddsspy -domainId 0). Default base is 42 (never
;;; the shared well-known domain 0). Per-isolation-group NAMED offset constants (+td-*+)
;;; reproduce the inter-test domain isolation the old absolute literals provided, with no
;;; absolute domain value anywhere in the suite (the operating contract, owner directive).

(defun* test-domain-from-env ()
    (function () (or null (integer 0 232)))
  "Parse env var DDS_TEST_DOMAIN as a DDS domain id; NIL if unset, non-integer, or out of
   the valid 0..232 range (DDSI-RTPS 2.5 §9.6.1.1 default port mapping PB=7400/DG=250 keeps
   every UDP port <= 65535 only for domain id <= 232). uiop:getenv is the impl-agnostic
   accessor already used in production (no reader conditional in test code)."
  (let ((v (uiop:getenv "DDS_TEST_DOMAIN")))
    (when (and v (plusp (length v)))
      (let ((n (ignore-errors (parse-integer v))))
        (when (and (integerp n) (<= 0 n 232)) n)))))

(defparameter *test-domain* (or (test-domain-from-env) 42)
  "The configurable BASE DDS domain id for the whole test suite. Read once from env var
   DDS_TEST_DOMAIN at load (default 42 — deliberately non-zero, off the shared well-known
   domain 0). Rebind it, or set DDS_TEST_DOMAIN, to shift every test onto a different domain
   (e.g. to avoid a foreign participant already on the default). Given the current maximum
   +td-*+ offset (37) and the DDS domain-id ceiling (232), valid bases are 0..195.")

(defun* test-domain (&optional (offset 0))
    (function (&optional (integer 0)) (integer 0 232))
  "The DDS domain id for a test: (+ *test-domain* OFFSET). OFFSET is 0 for the shared base
   (tests that historically ran together on one domain) or a per-isolation-group +td-*+
   constant (tests that historically used distinct absolute domains). Asserts the result is
   a valid DDS domain id (0..232, DDSI-RTPS 2.5 §9.6.1.1) so a misconfigured base fails
   loudly at the offending call site rather than producing an unroutable domain."
  (let ((d (+ *test-domain* offset)))
    (assert (<= 0 d 232) (d)
            "test-domain ~d out of the valid DDS domain-id range 0..232 (base *test-domain*=~d, ~
             offset=~d); lower DDS_TEST_DOMAIN (valid base 0..195)." d *test-domain* offset)
    d))

;;; Per-isolation-group offset constants. Each distinct historical absolute domain literal
;;; maps to ONE offset here (same literal -> same offset everywhere, so the exact inter-test
;;; domain equivalence classes — both the sharing AND the distinctness — are preserved with
;;; zero behavioral change). Offsets are small relative values; the actual domain is
;;; (+ *test-domain* offset). The parenthetical notes the historical absolute domain each
;;; constant replaces and its representative test(s).

;;; integration-test
(defconstant +td-rxo+ 1
  "RxO integration test isolation offset (historical absolute domain 42, the prior
   +rxo-test-domain+): a non-zero domain distinct from the shared base so the RxO pair does
   not share a multicast group with a foreign domain-0 participant (RTPS 2.5 §9.6.1.1).")

;;; durability-test
(defconstant +td-collect+ 2
  "durability collect-tier isolation offset (historical domain 7; also the access-control
   manager test, which historically shared domain 7).")
(defconstant +td-transient+ 3
  "durability transient-relay isolation offset (historical domain 17).")
(defconstant +td-runner+ 4
  "durability multi-service runner isolation offset (historical domain 27).")
(defconstant +td-supervisor+ 5
  "durability supervisor isolation offset (historical domain 37).")
(defconstant +td-runner-lifecycle+ 6
  "durability runner-lifecycle isolation offset (historical domain 47).")
(defconstant +td-writer-rep+ 7
  "durability writer-representation isolation offset (historical domain 57; also the
   process-smoke %spec->argv round-trip fixture, which historically shared domain 57).")
(defconstant +td-relay-emit+ 8
  "durability relay-emit isolation offset (historical domain 67).")
(defconstant +td-no-double-delivery+ 9
  "durability no-double-delivery isolation offset (historical domain 77; also the
   auth-secured-refuses-plain test, which historically shared domain 77).")
(defconstant +td-origin-accessor+ 10
  "durability original-writer-info accessor isolation offset (historical domain 78; also the
   auth-plain-byte-identical test, which historically shared domain 78).")
(defconstant +td-collect-origin-convergence+ 11
  "durability collect origin-convergence isolation offset (historical domain 79).")
(defconstant +td-data-keyhash-capture+ 12
  "durability DATA key-hash capture isolation offset (historical domain 80).")
(defconstant +td-collect-keyhash-store+ 13
  "durability collect key-hash store isolation offset (historical domain 81).")
(defconstant +td-graceful-teardown+ 14
  "durability graceful-teardown-order isolation offset (historical domain 82).")
(defconstant +td-multitopic+ 15
  "durability multitopic isolation offset (historical domain 87; also the access-control
   local-deny test, which historically shared domain 87).")
(defconstant +td-dispose-replay+ 16
  "durability dispose-replay isolation offset (historical domain 97; also the
   seed-backpressure test, which historically shared domain 97).")
(defconstant +td-dare-transparency+ 17
  "DARE service-transparency isolation offset (historical domain 107).")
(defconstant +td-persistent-service+ 18
  "durability persistent-service isolation offset (historical domain 117).")
(defconstant +td-keeplast-policy+ 19
  "durability keep-last service-spec policy isolation offset (historical domain 119).")
(defconstant +td-dynamic-topic+ 20
  "durability dynamic-topic-add isolation offset (historical domain 127).")
(defconstant +td-relay-tier+ 21
  "durability relay-tier QoS-override isolation offset (historical domain 137).")
(defconstant +td-collect-tier+ 22
  "durability collect-tier QoS-override isolation offset (historical domain 138).")
(defconstant +td-cfg-domain+ 23
  "durability config-parser CLI/spec domain fixture offset (historical parser fixtures 7/99/57).")
(defconstant +td-cfg-env-domain+ 24
  "durability config-parser ENV domain fixture offset (historical parser fixture 3); distinct
   from +td-cfg-domain+ so the CLI-overrides-env precedence check keeps CLI /= env.")

;;; gen-test (bench harnesses)
(defconstant +td-bench-publish-delta+ 25
  "secured live publish-delta bench isolation offset (historical domain 70).")
(defconstant +td-bench-receive+ 26
  "secured live receive bench isolation offset (historical domain 71).")
(defconstant +td-bench-wrapper-cycle+ 27
  "secured wrapper-cycle bench isolation offset (historical domain 73).")
(defconstant +td-mem-secure+ 28
  "secure mem-test isolation offset (historical domain 99).")

;;; security-test / security-auth-test / security-access-control-test
(defconstant +td-encrypted-pubsub+ 29
  "security encrypted pub/sub isolation offset (historical domain 83).")
(defconstant +td-encrypted-fragmented+ 30
  "security encrypted-fragmented isolation offset (historical domain 84).")
(defconstant +td-ac-allow+ 31
  "access-control ALLOW-pair isolation offset (historical domain 85); distinct from
   +td-ac-deny+ so the allow/deny test's two pairs do not cross-discover.")
(defconstant +td-ac-deny+ 32
  "access-control DENY-pair isolation offset (historical domain 86); distinct from
   +td-ac-allow+ so the allow/deny test's two pairs do not cross-discover.")
(defconstant +td-secure-discovery+ 33
  "secure-discovery e2e isolation offset (historical domain 88; also the access-control
   default-off test, which historically shared domain 88).")
(defconstant +td-secured-decode-loan-alloc+ 34
  "secured decode-loan alloc isolation offset (historical domain 91).")
(defconstant +td-secured-decode-loan-dup+ 35
  "secured decode-loan dup isolation offset (historical domain 92).")
(defconstant +td-secured-zeroalloc-encode+ 36
  "secured zero-alloc ENCODE-pool-exhaustion isolation offset (historical domain 93);
   distinct from +td-secured-zeroalloc-decode+ (the same test's two independent parts).")
(defconstant +td-secured-zeroalloc-decode+ 37
  "secured zero-alloc DECODE-pool-exhaustion isolation offset (historical domain 94);
   distinct from +td-secured-zeroalloc-encode+ (the same test's two independent parts).")
(defconstant +td-secured-submsg-exhaust+ 38
  "metadata_protection submessage-scratch EXHAUSTION pass-through isolation offset (ZA-2 review):
   on pool exhaustion the send wrap must pass a no-protectable-submessage datagram THROUGH (LEN),
   not drop it, while still fail-closed dropping a datagram carrying a protectable submessage.")
(defconstant +td-secured-store-growth+ 39
  "WP-SECURED-STORE-GROWTH leak-proof test isolation offset: streaming many secured samples must not
   grow the parallel per-(guid,sn) store tables unbounded (purged on loan release) nor the arena-carve-fail
   bare-vector store unbounded (bounded high-water, fail-closed RESOURCE_LIMITS at the cap).")
(defconstant +td-decode-fail-suppress+ 40
  "WP-RESIDUAL-FIXES-BATCH-A / ADR 0031 lim.1 isolation offset: the reliable-reader decode-failure
   retransmit-suppression — a missing-KM failure NEVER suppresses (self-heals when the key arrives), while a
   persistent KM-present tag failure suppresses the SN after a bounded count without wedging later SNs.")
(defconstant +td-dcps-secured-take-loan+ 41
  "WP-DCPS-SECURED-TAKE-LOAN (ADR 0038 residual (i)) isolation offset: a secured DCPS reader take/read-loaned a
   secured sample via the zero-decode-buffer-alloc loan; the loan lifecycle is leak-free + byte-exact + idempotent.")
(defconstant +td-dynamic-topic-discovery+ 42
  "durability dynamic-topic-add DISCOVERY-DRIVEN auto-serve isolation offset (WP-DURABILITY-DYNAMIC-TOPIC-DISCOVERY,
   ADR 0026 Phase-2b); distinct from +td-dynamic-topic+ (the API-driven variant) so the two never cross-discover.")
(defconstant +td-log-pipeline+ 43
  "logging-service end-to-end pipeline isolation offset (ADR 0082 §5/§6): make-logger -> DDS -> make-log-collector
   -> file sink, an in-process LogEvent round-trip on its own domain so it never cross-discovers another test.")
(defconstant +td-log-macros+ 44
  "logging-service macro-API isolation offset (ADR 0082 §5, FR-LOG-3/4): the per-severity macros + with-trace-scope
   over a logger->collector round-trip (threshold gating, compile-time function capture), on its own domain.")
(defconstant +td-log-service+ 45
  "logging-service runnable-service isolation offset (ADR 0082 §6/§7, FR-LOG-7): log-service-main (block nil) builds
   a collector whose file sink drains a logger's LogEvents, on its own domain so it never cross-discovers a test.")
(defconstant +td-log-async+ 46
  "logging-service async-ring isolation offset (ADR 0082 §5/§6, FR-LOG-5/6): an async (:async t) logger's worker
   thread drains the bounded ring into a collector, on its own domain so it never cross-discovers a test.")
(defconstant +td-log-runner+ 47
  "logging-service multi-service-runner isolation offset (ADR 0082 §6/§7, FR-LOG-7): the runner runs TWO collectors,
   one on this domain and one on this+1 (offset 48, unused elsewhere), each fed by its own logger — proving
   concurrent multi-collector operation + per-domain isolation on their own domains.")
(defconstant +td-log-supervisor+ 49
  "logging-service OTP-supervisor isolation offset (ADR 0082 §6/§7, FR-LOG-7): one collector whose drain thread is
   killed via the *log-runner-fault* hook, so the supervisor's restart + restart-intensity-shed paths are exercised
   on its own domain (48 is taken by the runner test's second collector).")
(defconstant +td-app-ack+ 50
  "APP-ACK emission isolation offset (ADR 0090 A3b): THREE participants — the acknowledged writer, a DECOY
   writer on the same topic in a DIFFERENT participant, and the reader — on their own domain. The decoy is
   the whole point of the test, and it only proves anything if no foreign participant shares the domain:
   the assertion is that the reader's APP_ACK reaches the writer it names and NOTHING ELSE.")

(defun* record-synthetic-match (node src wid &rest reader-eids)
    (function (t (simple-array (unsigned-byte 8) (12)) (unsigned-byte 32) &rest (unsigned-byte 32)) t)
  "Record the synthetic remote writer (SRC prefix + WID EntityId) as MATCHED on NODE — the setup a test
   needs before injecting a sample with %deliver-user-sample against a DCPS participant.

   WHY IT EXISTS. Those tests used to inject without matching anything, and the sample still reached the
   reader through the WP-N-ENDPOINT-S2 primary-reader fallback. That fallback is exactly what made an RxO
   refusal ADVISORY — a DataReader could refuse a writer, raise REQUESTED_INCOMPATIBLE_QOS, and read its
   data anyway (measured against live Connext: interop/connext/appack/captures/a2live-results.txt, leg 3).
   It now applies only to a node that does no matching at all, so a DCPS-driven injection has to say what
   it means: this writer is matched.

   Only the GUID is consulted — %record-match keys the match table by the 16-octet GUID alone — so no
   topic or type name is invented here. IDEMPOTENT (%record-match returns NIL on a re-record), so calling
   it before every injection is safe."
  (let ((guid (dds.disc::%source-guid src wid)))
    (dds.disc::%record-match
     node (dds.rtps.discovery:make-endpoint-data :guid guid :role :writer))
    ;; BOTH, because production does BOTH: %match-remote-endpoint route-adds every RxO-compatible local
    ;; reader for a remote writer IMMEDIATELY BEFORE recording the match. Recording only the match leaves
    ;; MATCHED-BUT-UNROUTED, a state that cannot occur in production and that %reader-routes-for now
    ;; refuses and counts (disc-node-unrouted-match-drops). READER-EIDS may be empty for a test that only
    ;; needs the match recorded (a HEARTBEAT gate, a lease sweep) and never expects delivery.
    (dolist (eid reader-eids)
      (dds.disc::%reader-route-add node guid eid)))
  t)

(defconstant +td-rx-consumers+ 51
  "ADR 0093 slice 2 isolation offset: ONE writer plus TWO co-located SAME-topic readers, and the assertion is
   about the SIZE OF THE SHARED RECEIVE STORE after each reader drains. Any foreign participant on the domain
   would put its own samples in that store and the count would stop meaning what the test says it means.")

(defconstant +td-reader-cache-race+ 53
  "ADR 0093 slice 3 isolation offset: TWO application threads taking from ONE DataReader while a writer
   publishes. The assertion is that the union of what the two threads take is EXACTLY what was written, so
   a foreign participant's samples on the domain would break the count.")

(defconstant +td-rx-data-pool+ 54
  "ADR 0093 slice 4 isolation offset: the pooled deserialized-sample path. The assertion is that an
   instance's retained get_key_value key sample survives later deliveries decoding into pooled structs, so
   a foreign participant's samples on the domain would muddy which struct came from where.")

(defconstant +td-take-into+ 55
  "ADR 0105 slice 1 isolation offset: TAKE-INTO / READ-INTO. The assertions count EXACTLY how many samples
   one call wrote and which wrapper the reader recycled, so a foreign participant's sample on the domain
   would change both.")

(defconstant +td-take-into-poison+ 56
  "ADR 0105 Task 4 isolation offset: the SampleInfo poison arm. It takes ONE sample into a sentinel-filled
   destination and asserts no sentinel survives; a second, foreign sample would be written over the first
   and the surviving-sentinel set would stop meaning what the test says it means. Distinct from
   +td-take-into+ so the two into tests never share a domain (the standing order).")

(defconstant +td-take-into-truncate+ 57
  "ADR 0105 slice 1 isolation offset: the destination-length bound. The arm writes EXACTLY one more sample
   than the destination has slots and asserts the surplus stayed cached, so one foreign sample on the
   domain would change the count on both sides of the bound and the arm would stop testing the bound.")

(defconstant +td-take-into-exposed+ 58
  "ADR 0105 §4.1 isolation offset: the READ-LOANED-then-TAKE-INTO hazard. The arm holds one specific
   struct across further deliveries and asserts its fields never change, so a foreign sample decoded into
   a pooled struct on this domain is indistinguishable from the defect being tested.")

(defconstant +td-take-into-listener+ 59
  "ADR 0105 §8 isolation offset: TAKE-INTO called from an ON_DATA_AVAILABLE listener. The arm counts
   listener entries against listener exits, and a foreign participant's traffic fires the same listener.")

(defconstant +td-view-state-snapshot+ 60
  "DDS 1.4 §2.2.2.5.1.4 isolation offset: the view-state SNAPSHOT ordering. Every arm asserts the exact
   view_state of the exact samples ONE access call returned for ONE instance, so a foreign participant's
   sample arriving mid-arm would add an instance whose first access falls in a different call and the
   NEW/NOT_NEW pattern being asserted would stop describing what the test says it does.")

(defconstant +td-lifecycle-drained-identity+ 61
  "ADR 0105 Task 6 isolation offset: the lifecycle drained-set key identity. The arm drains exactly two
   dispose changes in two SEPARATE passes and then asserts a third pass delivers NOTHING, so any foreign
   participant's dispose on the domain would put a genuine third change in the store and the
   no-resurrection assertion would fail for a reason that is not the defect.")
