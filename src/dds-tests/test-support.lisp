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

(defconstant +td-cache-spine-unlink+ 62
  "ADR 0105 Task 6a isolation offset: the in-place DR-CACHE spine unlink. The arm pins the exact residue and
   ORDER of a three-sample cache after taking the head, the middle and the tail one at a time, so a foreign
   participant's sample landing in that cache changes both the count and the order being asserted.")

(defconstant +td-lifecycle-drained-identity+ 61
  "ADR 0105 Task 6 isolation offset: the lifecycle drained-set key identity. The arm drains exactly two
   dispose changes in two SEPARATE passes and then asserts a third pass delivers NOTHING, so any foreign
   participant's dispose on the domain would put a genuine third change in the store and the
   no-resurrection assertion would fail for a reason that is not the defect.")

(defconstant +td-writer-handle-intern+ 63
  "ADR 0106 isolation offset: the writer's interned instance handle. The arm asserts EQ identity of the
   handles a writer hands out across writes and a finite offered DEADLINE arming per instance, so a foreign
   participant's traffic on the domain would add instances the EQ and per-instance assertions do not expect.")

(defconstant +td-writer-handle-race+ 64
  "ADR 0106 review finding 1 isolation offset: CONCURRENT writes on one DataWriter. The arm asserts that
   every instance's key holder matches its own key after N threads write M instances each, so a foreign
   participant's traffic would add instances the per-instance assertions do not expect.")

(defconstant +td-exit-process+ 65
  "ADR 0121 isolation offset: the durability-service SUBPROCESS that the exit-process test SIGTERMs. The
   child runs a real participant, so a foreign participant on the domain would only add discovery traffic,
   but a sibling test's participant on the same domain could match its endpoints and delay its teardown.")

;;; ================================================================================================
;;; ONE SKIP CHANNEL (ADR 0122, WP-0.10 step 1; step 2 enforcement: ADR 0128)
;;;
;;; A test that returns early, or skips one arm, because the host lacks a capability reports it HERE and
;;; nowhere else: (note-skip SITE CAPABILITY REASON). Every event is recorded against the test that is
;;; running (*CURRENT-TEST*), nothing is deduplicated, and CAPABILITY must come from the closed vocabulary
;;; *SKIP-CAPABILITIES*. RUN-ALL-TESTS turns the events into a per-test FULL / PARTIAL / SKIPPED / FAILED
;;; classification and a per-capability table. A bare "[skip]" or "SKIP" print in a test is banned by
;;; `make gate-skip-lint`; it is how about 100 tests reported "ok" on this host while doing nothing.
;;;
;;; Nothing in this file changes an exit code: the accounting is printed and the run ends as before. Step 2
;;; (ADR 0128) enforces OUTSIDE the Lisp: `make test` hands the run's log to scripts/test-baseline.py gate,
;;; which fails on any skip event (any capability) the ADR 0120 skip baseline does not list, unless
;;; DDS_TEST_ALLOW_SKIP names its capability (then exit 3, NOT A GATE RUN). `make fuzz`, `make mem` and
;;; `make corpus` (RUN-WITH-SKIP-REPORT) are judged by scripts/test-baseline.py entry (ADR 0128 section 3):
;;; a skip of a capability the Lisp's skip baseline excuses for no test fails them.
;;; ================================================================================================

(defparameter *skip-capabilities*
  '(:openssl-pqc :libcrypto :alloc-counter :zc-sap-primitives :shm-attach-by-name :subprocess-mode
    :rx-store-pool :static-vector-p :carve-refusal :verified-elsewhere)
  "The CLOSED vocabulary of capabilities a test may report as missing (ADR 0122 §2.2). Each names one host
   or implementation fact, not a test:
     :OPENSSL-PQC        a libcrypto is loaded but it is older than OpenSSL 3.5.0 or cannot fetch ML-KEM-1024
                         (DDS.DARE:DARE-AVAILABLE-P's third value);
     :LIBCRYPTO          no libcrypto could be loaded at all;
     :ALLOC-COUNTER      DDS.PAL:BYTES-CONSED does not move, so an allocation assertion cannot be measured
                         (AllegroCL: the constant 0);
     :ZC-SAP-PRIMITIVES  the Zero-Copy / FlatData SAP primitives (cas-sap-u32, load-/store-sap-u8) are not
                         cleared for this implementation (today gated on pal-impl-name :SBCL, WP-1.15);
     :SHM-ATTACH-BY-NAME a POSIX shm segment cannot be reliably re-opened by name
                         (DDS.XPORT.SHMEM:SHM-ATTACH-BY-NAME-RELIABLE-P is NIL);
     :SUBPROCESS-MODE    the durability service's subprocess execution mode is not available on this
                         implementation (dds-durability/runner.lisp gates it on pal-impl-name :SBCL);
     :RX-STORE-POOL      DDS.DISC:*RX-STORE-POOL-ENABLED* is NIL, so the pooled receive-store arm is off;
     :STATIC-VECTOR-P    DDS.PAL:STATIC-VECTOR-P cannot tell a GC-heap array from a static one on this
                         implementation (AllegroCL), so a 'this key is NOT foreign-static' check is vacuous;
     :CARVE-REFUSAL      the host GRANTS an absurd (2^48-octet) static carve (overcommit), so an arm that
                         needs the carve to fail cannot reach its failure path;
     :VERIFIED-ELSEWHERE a gate does not check an artefact itself because another gate does (today: a
                         `make corpus` vector named in DDS.BENCH::*CORPUS-VERIFIED-ELSEWHERE*, which
                         dds-bench cannot verify because it does not load the system the vector's type
                         lives in). Counted as a skip of THIS gate, so a deferral is never silent.
   The first seven are the plan's vocabulary; the last three are the ADR 0122 §2.2 extensions, each justified
   there by a site no other capability describes. NOTE-SKIP rejects any other keyword. Extending the list
   requires a justification in ADR 0122.")

(defvar *current-test* nil
  "The name (a string) of the test RUN-ALL-TESTS is running, or NIL outside a suite run. Set with SETF, not
   bound with LET, by the runner around each test: tests run one at a time, and a skip noted from a thread
   the test spawned must still be charged to that test (a LET binding is invisible in other threads).")

(defstruct (skip-event (:constructor %make-skip-event (test site capability reason scope)))
  "One reported skip (ADR 0122): TEST is *CURRENT-TEST* when it was noted (or NIL), SITE names what did not
   run, CAPABILITY is a member of *SKIP-CAPABILITIES*, REASON is the printed explanation, and SCOPE is :TEST
   (the test returned without running) or :ARM (one arm of a test that otherwise ran)."
  (test nil) (site "" ) (capability nil :type keyword) (reason "") (scope :test :type keyword))

(defvar *skip-events-lock* (dds.pal:make-lock "dds-test-skip-events")
  "Guards *SKIP-EVENTS*: a skip may be noted from a thread the test spawned.")

(defvar *skip-events* '()
  "Every SKIP-EVENT noted since the last RESET-SKIP-EVENTS, newest first. Read it with SKIP-EVENTS.")

(defun* note-skip (site capability reason &key (scope :test))
    (function (t keyword t &key (:scope keyword)) (eql t))
  "Report that SITE did not run because CAPABILITY is missing, for REASON: print one line and record a
   SKIP-EVENT against *CURRENT-TEST*. CAPABILITY must be a member of *SKIP-CAPABILITIES* and SCOPE one of
   :TEST (the whole test returns without running: the default) or :ARM (one arm skipped, the rest ran);
   anything else signals an ERROR, which fails the calling test, because an unclassified skip is exactly the
   invisible coverage hole this channel exists to close. Every call is recorded: two calls are two events.
   Returns T, so a pass-skip guard can return its value. ADR 0122."
  (unless (member capability *skip-capabilities*)
    (error "note-skip ~a: capability ~s is not in the closed ADR 0122 vocabulary ~s"
           site capability *skip-capabilities*))
  (unless (member scope '(:test :arm))
    (error "note-skip ~a: scope ~s must be :TEST or :ARM" site scope))
  (let ((ev (%make-skip-event *current-test* (princ-to-string site) capability (princ-to-string reason) scope)))
    (dds.pal:with-lock (*skip-events-lock*) (push ev *skip-events*))
    (format t "~&  [skip] ~a (~(~a~), ~(~a~)): ~a~%" site capability scope reason))
  t)

(defun* note-dare-skip (site reason &key (scope :test))
    (function (t t &key (:scope keyword)) (eql t))
  "NOTE-SKIP for a DARE / DDS-Security site, with the capability taken from DDS.DARE:DARE-AVAILABLE-P's third
   value: :LIBCRYPTO when no libcrypto loaded, :OPENSSL-PQC when the loaded one is older than 3.5 or lacks
   ML-KEM-1024. Called only after DARE-AVAILABLE-P returned NIL; should it now return T (it cannot change
   within a run), the skip is still recorded, under :OPENSSL-PQC, rather than dropped."
  (note-skip site (or (nth-value 2 (dds.dare:dare-available-p)) :openssl-pqc) reason :scope scope))

(defun* %skip-hook (site capability reason scope)
    (function (t keyword t keyword) (eql t))
  "The DDS.PAL:*TEST-SKIP-HOOK* this harness installs: production-file test bodies report through
   DDS.PAL:NOTE-TEST-SKIP, which lands here, in the same registry as every other skip."
  (note-skip site capability reason :scope scope))

(setf dds.pal:*test-skip-hook* #'%skip-hook)

(defun* skip-events ()
    (function () list)
  "A fresh list of every SKIP-EVENT noted since the last RESET-SKIP-EVENTS, oldest first."
  (dds.pal:with-lock (*skip-events-lock*) (reverse *skip-events*)))

(defun* reset-skip-events ()
    (function () (eql t))
  "Forget every noted SKIP-EVENT. RUN-ALL-TESTS calls it before the first test."
  (dds.pal:with-lock (*skip-events-lock*) (setf *skip-events* '()))
  t)

(defun* classify-test (name failed-p events)
    (function (t t list) keyword)
  "The ADR 0122 coverage class of test NAME: :FAILED if FAILED-P; else :SKIPPED if any of EVENTS charged to
   NAME has scope :TEST; else :PARTIAL if any is charged to NAME at all; else :FULL."
  (let ((mine (remove-if-not (lambda (e) (equal (skip-event-test e) name)) events)))
    (cond (failed-p :failed)
          ((find :test mine :key #'skip-event-scope) :skipped)
          (mine :partial)
          (t :full))))

(defun* print-skip-report (results events &optional (stream *standard-output*))
    (function (list list &optional t) (eql t))
  "Print the ADR 0122 accounting to STREAM. RESULTS is a list of (NAME . FAILED-P), one per test run, in run
   order; EVENTS is the SKIP-EVENTS list. Prints the FULL / PARTIAL / SKIPPED / FAILED counts, then one row
   per capability of *SKIP-CAPABILITIES* (events, distinct tests, and the tests by name), then any event noted
   outside a test. Report-only: it returns T and decides nothing; `make test` judges this report from the
   run's log against the ADR 0120 skip baseline (scripts/test-baseline.py gate, ADR 0128)."
  (let ((counts (list :full 0 :partial 0 :skipped 0 :failed 0)))
    (dolist (r results)
      (incf (getf counts (classify-test (car r) (cdr r) events))))
    (format stream "~&coverage: ~d FULL, ~d PARTIAL, ~d SKIPPED, ~d FAILED of ~d test(s); ~d skip event(s).~%"
            (getf counts :full) (getf counts :partial) (getf counts :skipped) (getf counts :failed)
            (length results) (length events))
    (format stream "~&skips by capability (ADR 0122; every event counted, no dedup):~%")
    (format stream "  ~20a ~7@a ~6@a ~5@a~%" "capability" "events" "tests" "arms")
    (dolist (cap *skip-capabilities*)
      (let* ((evs (remove-if-not (lambda (e) (eq (skip-event-capability e) cap)) events))
             (tests (remove-duplicates (mapcar #'skip-event-test evs) :test #'equal :from-end t)))
        (format stream "  ~20a ~7d ~6d ~5d~%" (string-downcase (symbol-name cap)) (length evs) (length tests)
                (count :arm evs :key #'skip-event-scope))))
    ;; then, per capability that fired, the tests it was charged to (xN = N events in that test)
    (dolist (cap *skip-capabilities*)
      (let* ((evs (remove-if-not (lambda (e) (eq (skip-event-capability e) cap)) events))
             (tests (remove-duplicates (mapcar #'skip-event-test evs) :test #'equal :from-end t)))
        (when evs
          (format stream "~&  ~(~a~):~{~<~%   ~1,110:; ~a~>~^,~}~%" cap
                  (mapcar (lambda (tn)
                            (let ((n (count tn evs :key #'skip-event-test :test #'equal)))
                              (if (> n 1) (format nil "~a x~d" (or tn "<no test>") n) (or tn "<no test>"))))
                          tests)))))
    (let ((stray (remove-if #'skip-event-test events)))
      (when stray
        (format stream "~&  ~d skip event(s) noted outside a running test:~{ ~a~^,~}~%"
                (length stray) (mapcar #'skip-event-site stray)))))
  t)

(defvar *preflight-sink* nil
  "Holds the probe allocation of CAPABILITY-PREFLIGHT so the compiler cannot elide it.")

(defun* %libcrypto-mapped-paths ()
    (function () list)
  "The distinct libcrypto files in /proc/self/maps: the libcrypto the dynamic loader actually mapped into this
   process, which is the answer to 'which OpenSSL did this run use' that a load name like libcrypto.so.3 does
   not give. NIL where /proc/self/maps cannot be read. The same rule the loader applies
   (DDS.PAL:MAPPED-OBJECT-PATHS, ADR 0123): a file counts when its basename contains \"libcrypto\"."
  (values (dds.pal:mapped-object-paths "libcrypto")))

(defun* %libcrypto-preflight-failure ()
    (function () (or null string))
  "NIL when the libcrypto this run uses can be trusted, else the reason the run must not start (ADR 0123).
   Two things fail it: the loader REJECTED a libcrypto (DDS.DARE:LIBCRYPTO-STATUS is neither :OK nor :ABSENT —
   e.g. DDS_DARE_LIBCRYPTO names a missing file), or /proc/self/maps shows more than one libcrypto file NOW,
   at suite start, whatever got mapped after the loader's own check. A skip is not the answer to either: a
   run against the wrong library, or against two of them, is not a test of the library it reports."
  (multiple-value-bind (status path detail) (dds.dare:libcrypto-status)
    (let ((mapped (%libcrypto-mapped-paths)))
      (cond ((not (member status '(:ok :absent)))
             (format nil "libcrypto REJECTED by the loader: ~(~a~)~@[ (~a)~]~@[: ~a~]" status path detail))
            ((> (length mapped) 1)
             (format nil "~d libcrypto mappings (must be 1): ~{~a~^, ~}" (length mapped) mapped))
            (t nil)))))

(defun* assert-libcrypto-preflight (&optional (stream *standard-output*))
    (function (&optional t) (eql t))
  "Fail closed before any test runs when %LIBCRYPTO-PREFLIGHT-FAILURE names a reason (ADR 0123): print it and
   signal TEST-FAILURE, so `make test`, `make fuzz`, `make mem` and `make corpus` exit non-zero whatever the
   skip mode. Returns T when the libcrypto is trustworthy."
  (let ((why (%libcrypto-preflight-failure)))
    (when why
      (format stream "~&⛔ LIBCRYPTO PREFLIGHT FAILED (ADR 0123): ~a~%   No test was run.~%" why)
      (error 'test-failure :name :libcrypto-preflight :detail why)))
  t)

(defun* %openssl-version-text ()
    (function () (values (or null integer) (or null string)))
  "(VALUES VERSION-NUM VERSION-TEXT) of the loaded libcrypto, or NILs when none is loaded. VERSION-TEXT is
   OpenSSL_version(OPENSSL_VERSION); OPENSSL_VERSION is 0, read from /usr/include/openssl/crypto.h:153
   (OpenSSL 3.0.13 headers on the reference host; the selector is unchanged in 3.5's crypto.h)."
  (if (null dds.dare::*libcrypto*)
      (values nil nil)
      (let ((num-ptr (dds.dare::%ossl-sym-or-nil "OpenSSL_version_num"))
            (txt-ptr (dds.dare::%ossl-sym-or-nil "OpenSSL_version")))
        (values (and num-ptr (cffi:foreign-funcall-pointer num-ptr nil :unsigned-long))
                (and txt-ptr (cffi:foreign-funcall-pointer txt-ptr nil :int 0 :string))))))

(defun* %shm-attach-probe ()
    (function () (values t t))
  "Create a 4096-octet POSIX shm segment, write a marker, attach it again BY NAME and read the marker back.
   (VALUES WORKS-P DETAIL): WORKS-P is T iff the by-name attach saw the marker; DETAIL is the attach status or
   the condition, for the preflight line. A failed SHM-CREATE reports its own status (e.g. :SHM-OPEN-FAILED)
   rather than the type error that touching its NIL segment would raise; the name is still unlinked, since
   SHM-CREATE's :FTRUNCATE-FAILED / :MMAP-FAILED paths close the fd but leave the name behind."
  (let ((name (format nil "/dds-preflight-~a-~a" (dds.pal:process-id) (random 1000000))) (size 4096))
    (handler-case
        (multiple-value-bind (seg create-status) (dds.pal:shm-create name size)
          (if (null seg)
              (progn (dds.pal:shm-destroy name) (values nil create-status))
              (unwind-protect
                   (progn
                     (setf (cffi:mem-ref (dds.pal:shm-sap seg) :uint32 0) #xCAFEF00D)
                     (multiple-value-bind (seg2 status) (dds.pal:shm-attach name size)
                       (if status
                           (values nil status)
                           (unwind-protect
                                (values (= #xCAFEF00D (cffi:mem-ref (dds.pal:shm-sap seg2) :uint32 0)) :attached)
                             (dds.pal:shm-detach seg2)))))
                (dds.pal:shm-detach seg)
                (dds.pal:shm-destroy name))))
      (error (e) (values nil (princ-to-string e))))))

(defun* capability-preflight (&optional (stream *standard-output*))
    (function (&optional t) (eql t))
  "Print, before the first test, what this host and implementation actually provide for every capability in
   *SKIP-CAPABILITIES* (ADR 0122): the OpenSSL version and the libcrypto path the loader mapped, whether
   DDS.PAL:BYTES-CONSED moves across a known allocation, whether a shm segment can be attached by name (a
   live probe, next to the PAL's declared answer), and the gates the remaining capabilities use. It decides
   nothing and returns T; its job is that a run's skip table can be read against the facts that caused it."
  (format stream "~&preflight (ADR 0122): ~a ~a on ~a~%"
          (lisp-implementation-type) (lisp-implementation-version) (dds.pal:pal-impl-name))
  (multiple-value-bind (ok reason cap) (dds.dare:dare-available-p)
    (multiple-value-bind (num text) (ignore-errors (%openssl-version-text))
      (format stream "  openssl:            ~:[UNAVAILABLE (~(~a~)): ~a~;available~2*~]; version ~a~@[ (0x~8,'0x)~]~%"
              ok cap reason (or text "n/a") num))
    (multiple-value-bind (status path detail pinned) (dds.dare:libcrypto-status)
      (format stream "  libcrypto loaded:   ~(~a~) ~a~:[ (unpinned search)~; (pinned by DDS_DARE_LIBCRYPTO)~]~@[ — ~a~]~%"
              status (or path "none") pinned detail))
    (let ((mapped (%libcrypto-mapped-paths)))
      (format stream "  libcrypto mappings: ~d~@[: ~{~a~^, ~}~]~%" (length mapped) mapped)))
  (let* ((before (dds.pal:bytes-consed))
         (_ (setf *preflight-sink* (make-list 4096)))
         (delta (- (dds.pal:bytes-consed) before)))
    (declare (ignore _))
    (setf *preflight-sink* nil)
    (format stream "  alloc-counter:      ~:[DOES NOT MOVE~;moves~] (bytes-consed delta ~d across a 4096-cons list)~%"
            (plusp delta) delta))
  (multiple-value-bind (works detail) (%shm-attach-probe)
    (format stream "  shm-attach-by-name: live probe ~:[FAILED~;works~] (~a); PAL declares reliable-p = ~a~%"
            works detail (dds.xport.shmem:shm-attach-by-name-reliable-p)))
  (format stream "  zc-sap-primitives:  ~:[gated OFF~;enabled~] (tests gate on pal-impl-name :SBCL until WP-1.15)~%"
          (eq (dds.pal:pal-impl-name) :sbcl))
  (format stream "  subprocess-mode:    ~:[gated OFF~;enabled~] (dds-durability runner gates on pal-impl-name :SBCL)~%"
          (eq (dds.pal:pal-impl-name) :sbcl))
  (format stream "  rx-store-pool:      dds.disc:*rx-store-pool-enabled* = ~a~%" dds.disc:*rx-store-pool-enabled*)
  t)

(defun* note-bench-skip (stream site capability reason)
    (function (t t keyword t) (eql t))
  "A bench harness's skip (ADR 0122): record it through NOTE-SKIP (scope :ARM — the bench still writes the
   rest of its report) and, when STREAM is a report file rather than *STANDARD-OUTPUT*, also write the same
   fact into the report, so the published numbers carry their own gap. Returns T."
  (note-skip site capability reason :scope :arm)
  (unless (eq stream *standard-output*)
    (format stream "(~a not measured: capability ~(~a~) missing — ~a; ADR 0122)~%~%" site capability reason))
  t)

(defun* run-with-skip-report (name thunk)
    (function (string function) t)
  "Run THUNK as the single test NAME outside RUN-ALL-TESTS, with the ADR 0122 skip accounting: print the
   capability preflight, refuse to start when the libcrypto preflight fails (ASSERT-LIBCRYPTO-PREFLIGHT,
   ADR 0123), charge every NOTE-SKIP to NAME, and print the FULL / PARTIAL / SKIPPED / FAILED line
   and the per-capability table afterwards, whether THUNK returns or signals. Returns THUNK's values; a
   condition THUNK signals propagates unchanged after the report, so the caller's exit code is exactly what it
   was without the report. Used by `make fuzz`, `make mem` and `make corpus`, whose make targets then judge
   the printed accounting with scripts/test-baseline.py entry (ADR 0128 section 3); the Lisp never consults
   a baseline."
  (capability-preflight)
  (assert-libcrypto-preflight)
  (reset-skip-events)
  (setf *current-test* name)
  (let ((ok nil))
    (unwind-protect
         (multiple-value-prog1 (funcall thunk) (setf ok t))
      (setf *current-test* nil)
      (print-skip-report (list (cons name (not ok))) (skip-events)))))
