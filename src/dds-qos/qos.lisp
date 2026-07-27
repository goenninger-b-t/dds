;;;; DDS 1.4 QoS policy model + Requested/Offered (RxO) matching (M3/P2, FR-QOS-1/2).
;;;; RxO compatibility per DDS 1.4 §2.2.3 (the standard table): for the kind-ordered
;;;; policies the OFFERED (writer) value must be >= the REQUESTED (reader) value; for
;;;; the duration policies OFFERED <= REQUESTED; OWNERSHIP kinds must be equal. A
;;;; failing policy yields OFFERED/REQUESTED_INCOMPATIBLE_QOS and blocks the match.
;;;; PARTITION is NOT an incompatible-QoS policy — a partition mismatch silently
;;;; prevents matching (no status), handled separately by partition-match-p.

(in-package #:dds.qos)

;;; ---- Duration_t with a total order (DURATION_INFINITE = the maximum) ----

(defstruct* (qos-duration (:constructor make-qos-duration (&optional (sec 0) (nanosec 0))))
  "DDS Duration_t: SEC + NANOSEC. DURATION_INFINITE is {0x7fffffff, 0x7fffffff}."
  (sec 0 :type (integer 0))
  (nanosec 0 :type (integer 0)))

(defparameter +duration-zero+ (make-qos-duration 0 0)
  "The zero Duration_t {0, 0}; the minimum of the Duration_t total order.")
(defparameter +duration-infinite+ (make-qos-duration #x7fffffff #x7fffffff)
  "DURATION_INFINITE {0x7fffffff, 0x7fffffff}; the maximum of the Duration_t total order.")

(defun* duration<= (a b)
    (function (qos-duration qos-duration) t)
  "Total order on Duration_t: A <= B (DURATION_INFINITE compares as the maximum,
   since 0x7fffffff is the largest second value)."
  (let ((as (qos-duration-sec a)) (bs (qos-duration-sec b)))
    (or (< as bs) (and (= as bs) (<= (qos-duration-nanosec a) (qos-duration-nanosec b))))))

;;; ---- DCPS Duration_t {sec,nanosec} <-> RTPS-wire Duration_t {seconds,fraction} ----
;;; The DCPS PSM Duration_t carries nanoseconds (dds_rtf2_dcps.idl: DURATION_INFINITE_NSEC
;;; = 0x7fffffff), but the RTPS-wire Duration_t carries a fraction in units of sec/2^32
;;; with DURATION_INFINITE {seconds 0x7fffffff, fraction 0xffffffff} (DDSI-RTPS 2.5 §9.3.2,
;;; struct Duration_t). Any Duration_t emitted into an RTPS Parameter (e.g. PID_LIVELINESS
;;; lease_duration) MUST convert nanosec->fraction; emitting the raw nanosec makes an
;;; INFINITE lease read as a finite ~0.5 s on conformant peers.

(defun* duration-nanosec->wire-fraction (nanosec)
    (function ((integer 0)) (unsigned-byte 32))
  "Convert a DCPS Duration_t nanosec field to the RTPS-wire fraction (sec/2^32),
   mapping the DCPS infinite sentinel 0x7fffffff to the RTPS infinite fraction
   0xffffffff (DDSI-RTPS 2.5 §9.3.2 struct Duration_t)."
  (if (= nanosec #x7fffffff)
      #xffffffff
      (min #xffffffff (floor (* nanosec #x100000000) 1000000000))))

(defun* wire-fraction->duration-nanosec (fraction)
    (function ((unsigned-byte 32)) (integer 0))
  "Convert an RTPS-wire Duration_t fraction (sec/2^32) back to a DCPS Duration_t
   nanosec field, mapping the RTPS infinite fraction 0xffffffff to the DCPS infinite
   nanosec 0x7fffffff (DDSI-RTPS 2.5 §9.3.2; dds_rtf2_dcps.idl DURATION_INFINITE_NSEC)."
  (if (= fraction #xffffffff)
      #x7fffffff
      (floor (* fraction 1000000000) #x100000000)))

(defun* duration-infinite-p (dur)
    (function (qos-duration) boolean)
  "T iff DUR is DURATION_INFINITE (sec 0x7fffffff; dds_rtf2_dcps.idl DURATION_INFINITE_SEC) — the
   sentinel every duration-consuming path tests before converting to a real time value."
  (>= (qos-duration-sec dur) #x7fffffff))

(defun* duration->seconds (dur)
    (function (qos-duration) double-float)
  "DUR as a double-float count of SECONDS (sec + nanosec/1e9), for the control-plane paths that need a
   real timeout (the discovery announce cadence, the participant lease). DURATION_INFINITE maps to
   MOST-POSITIVE-DOUBLE-FLOAT (an effectively unreachable deadline), so a caller never has to special-case
   the sentinel. NOT a hot-path function (no per-sample use)."
  (if (duration-infinite-p dur)
      most-positive-double-float
      (+ (coerce (qos-duration-sec dur) 'double-float)
         (/ (coerce (qos-duration-nanosec dur) 'double-float) 1.0d9))))

;;; ---- Ordinal ranks for the kind-ordered policies (offered >= requested) ----

(defun* reliability-rank (k)
    (function (symbol) (integer 0))
  "RxO strength rank of a RELIABILITY kind (:best-effort 1 < :reliable 2); offered must rank >= requested." (ecase k (:best-effort 1) (:reliable 2)))

(defun* durability-rank (k)
    (function (symbol) (integer 0))
  "RxO strength rank of a DURABILITY kind (:volatile 0 < :transient-local 1 < :transient 2 < :persistent 3)."
  (ecase k (:volatile 0) (:transient-local 1) (:transient 2) (:persistent 3)))

(defun* liveliness-rank (k)
    (function (symbol) (integer 0))
  "RxO strength rank of a LIVELINESS kind (:automatic 0 < :manual-by-participant 1 < :manual-by-topic 2)."
  (ecase k (:automatic 0) (:manual-by-participant 1) (:manual-by-topic 2)))

(defun* destination-order-rank (k)
    (function (symbol) (integer 0))
  "RxO strength rank of a DESTINATION_ORDER kind (:by-reception-timestamp 0 < :by-source-timestamp 1)."
  (ecase k (:by-reception-timestamp 0) (:by-source-timestamp 1)))

(defun* presentation-rank (k)
    (function (symbol) (integer 0))
  "RxO strength rank of a PRESENTATION access_scope (:instance 0 < :topic 1 < :group 2)." (ecase k (:instance 0) (:topic 1) (:group 2)))

;;; ---- TYPE_CONSISTENCY_ENFORCEMENT (XTypes 1.3 §7.6.3.4): reader-only, NOT an RxO
;;;      policy (so it is absent from qos-rxo-compatible); defaults per §7.6.3.4.1. ----

(defstruct* (type-consistency-enforcement
            (:constructor make-type-consistency-enforcement)
            (:copier copy-type-consistency-enforcement))
  "DDS XTypes TYPE_CONSISTENCY_ENFORCEMENT QoS policy (XTypes 1.3 §7.6.3.4, policy id 24).
   Applies to DataReaders only; it has NO request/offered (RxO) semantics and is immutable
   after enable, so it is deliberately absent from qos-rxo-compatible. KIND selects coercion
   vs equivalence; the four flags modulate ALLOW_TYPE_COERCION assignability; force-type-
   validation requires type info to be present in order to match. Defaults per §7.6.3.4.1:
   ALLOW_TYPE_COERCION, bounds ignored, names enforced, widening permitted, validation off."
  (kind :allow-type-coercion :type (member :allow-type-coercion :disallow-type-coercion))
  (ignore-sequence-bounds t :type boolean)
  (ignore-string-bounds t :type boolean)
  (ignore-member-names nil :type boolean)
  (prevent-type-widening nil :type boolean)
  (force-type-validation nil :type boolean))

;;; ---- The QoS set (the RxO-relevant + commonly-held policies; full 22+2 set is
;;;      filled in as the entity model lands). Defaults per DDS 1.4 §2.2.3. ----

(defstruct* (qos (:constructor make-qos) (:copier copy-qos))
  "The DDS QoS set: the RxO-relevant + commonly-held policies (the full 22+2 set is
   filled in as the entity model lands). Slot defaults follow DDS 1.4 §2.2.3.

   DISCOVERY_CONFIG (DISCOVERY-ANNOUNCE-PERIOD + DISCOVERY-LEASE-DURATION) is a VENDOR EXTENSION —
   DDS 1.4 standardizes no discovery-cadence policy, so this mirrors what every vendor supplies as an
   extension. Both are PARTICIPANT-scoped (ignored on a Publisher/Subscriber/Topic/DataWriter/DataReader
   QoS), have NO request/offered semantics (absent from qos-rxo-compatible), are never advertised in SEDP,
   and are CHANGEABLE after enable (set_qos re-applies them live; they carry no OMG QosPolicyId_t, so an
   inconsistency reports +qos-policy-id-invalid+ rather than an invented id).

   DISCOVERY-ANNOUNCE-PERIOD is the cadence at which an AUTONOMOUS participant's background announcer
   re-sends SPDP + SEDP and runs the lease/liveliness/autopurge sweeps. Default {1, 0} = 1 s: DELIBERATELY
   more frequent than the RTPS 2.5 §9.6.2.4 default announcement rate (SPDPbuiltinParticipantWriter.
   resendPeriod = {30, 0}), trading a little metatraffic for prompt discovery; a peer never requires a
   FASTER cadence than the lease we announce, so announcing more often is always interop-safe.

   DISCOVERY-LEASE-DURATION is the leaseDuration this participant ANNOUNCES in its SPDP
   (PID_PARTICIPANT_LEASE_DURATION): how long a peer keeps us alive after our last announcement before
   pruning us as stale (RTPS 2.5 §8.5.3.3.2). Default {100, 0} = the spec default (RTPS 2.5 Table 9.18).
   It MUST exceed the announce period (else peers age us out between our own announcements) — enforced by
   the DCPS consistency validator (INCONSISTENT_POLICY).

   WRITER-CACHE-LOW-WATERMARK / WRITER-CACHE-HIGH-WATERMARK are a second VENDOR EXTENSION (ADR 0089),
   DATAWRITER-scoped, measured in UNACKNOWLEDGED SAMPLES, and NIL (disabled) by default. They are the two
   thresholds that define a BACKPRESSURE EPISODE for the vendor RELIABLE_WRITER_CACHE_CHANGED status: the
   send window rising to HIGH opens one, and its falling back to LOW closes it. Like DISCOVERY_CONFIG they
   have NO request/offered semantics (absent from qos-rxo-compatible), are never advertised in SEDP, carry
   no OMG QosPolicyId_t, and are ignored on every entity except a DataWriter. When BOTH are set LOW MUST be
   strictly below HIGH — equal thresholds leave no hysteresis band, so one sample sitting on the boundary
   satisfies both tests at once; enforced by the DCPS consistency validator (INCONSISTENT_POLICY).

   THE DEFAULT IS DISABLED, WHICH IS A DELIBERATE DIVERGENCE FROM RTI CONNEXT, whose corresponding
   DataWriterProtocol fields default to {0, 1}. Connext can afford that default because there the pair
   primarily drives an INTERNAL mode — the switch to fast_heartbeat_period — and the status change is a
   by-product costing two counter increments. Here the pair drives an APPLICATION CALLBACK. At {0, 1} a
   reliable exchange with one sample in flight crosses HIGH on every write and LOW on every acknowledgement:
   two listener invocations per sample, on the write and receiver threads. That is not a cost problem to be
   optimised away, it is the wrong semantics — a status whose purpose is to announce backpressure must be
   SILENT when there is none. Adopting the numeric default while omitting the mechanism it was chosen for
   would be parity in appearance only.

   So: disabled by default, and the status then reports the FULL transition (an absolute condition needing
   no episode) and keeps its levels — unacked count, peak, replaced-unacked — continuously readable through
   get-reliable-writer-cache-changed-status at no cost. Set HIGH to a depth at which YOUR writer is in
   trouble to be told when it gets there, and LOW below it to be told when it recovers.

   ACKNOWLEDGMENT-KIND is a third VENDOR EXTENSION (ADR 0090), and the only one of the three that IS
   RxO-checked. DDS 1.4 defines no application acknowledgment at all — an exhaustive search of RTPS 2.5
   finds nothing, and the DCPS IDL has only wait_for_acknowledgments, which is protocol-level — so this
   mirrors RTI's DDS_ReliabilityQosPolicy.acknowledgment_kind. Effective only when RELIABILITY is
   :RELIABLE; on a best-effort endpoint there are no acknowledgments to speak of and it is ignored.

     :PROTOCOL (default)     acknowledged by the RTPS protocol — today's behaviour, unchanged.
     :APPLICATION-AUTO       acknowledged when the subscribing application ACCESSES it (read/take).
     :APPLICATION-EXPLICIT   acknowledged only on an explicit acknowledge-sample / acknowledge-all.

   ⚠️ RxO IS BY EQUALITY, NOT BY RANK, and that is the safety-critical part of this policy. Every other
   ordered policy has a 'a stronger offer satisfies a weaker request' direction. This one has NO safe
   direction, because both mismatches fail and they fail in OPPOSITE ways. A writer offering :PROTOCOL to
   a reader requesting an APPLICATION kind purges on protocol acks alone, so the reader believes it holds
   an end-to-end guarantee it does not have — SILENT DATA LOSS. A writer offering an APPLICATION kind to a
   :PROTOCOL reader waits for acknowledgments that reader will never send, so its history grows until
   RESOURCE_LIMITS blocks or rejects — A SILENT STALL. Neither is recoverable at runtime and neither
   announces itself, so a mismatch is refused at match time and reported as INCOMPATIBLE_QOS — the one
   outcome an operator can actually see and act on (the ADR 0057 lesson: matched-but-undeliverable is the
   worst state to leave a system in). OWNERSHIP is checked by equality for the same structural reason."
  (reliability :best-effort :type (member :best-effort :reliable))
  (reliability-max-blocking (make-qos-duration 0 100000000) :type qos-duration) ; 100 ms
  (durability :volatile :type (member :volatile :transient-local :transient :persistent))
  (deadline +duration-infinite+ :type qos-duration)
  (latency-budget +duration-zero+ :type qos-duration)
  (ownership :shared :type (member :shared :exclusive))
  (ownership-strength 0 :type integer)
  ;; TRANSPORT_PRIORITY (DDS 1.4 §2.2.3.13): a hint on the relative importance of a DataWriter's data;
  ;; the `value` field is a `long` (int32) with default 0. Writer-local, NOT an RxO policy (no request/
  ;; offered semantics — absent from qos-rxo-compatible); here it anchors the async flow-controller's
  ;; :priority scheduling (highest-first, ADR 0016). Not propagated in SEDP (sender-local scheduling only).
  (transport-priority 0 :type (signed-byte 32))
  (liveliness :automatic :type (member :automatic :manual-by-participant :manual-by-topic))
  (liveliness-lease +duration-infinite+ :type qos-duration)
  (destination-order :by-reception-timestamp
                     :type (member :by-reception-timestamp :by-source-timestamp))
  (presentation-scope :instance :type (member :instance :topic :group))
  (presentation-coherent nil :type boolean)
  (presentation-ordered nil :type boolean)
  ;; DataWriter: the OFFERED representation is (first data-representation);
  ;; DataReader: data-representation is the SET of accepted representations.
  (data-representation (list :xcdr1) :type list)
  (partition '() :type list)                ; list of partition-name strings
  ;; held (non-RxO) policies
  (history-kind :keep-last :type (member :keep-last :keep-all))
  (history-depth 1 :type (integer 1))
  (lifespan +duration-infinite+ :type qos-duration)
  ;; WRITER_DATA_LIFECYCLE (DDS 1.4 §2.2.3.21): writer-local, NOT advertised in SEDP, NOT RxO-checked.
  ;; autodispose_unregistered_instances default TRUE -> an unregister also disposes the instance.
  (autodispose-unregistered-instances t :type boolean)
  ;; READER_DATA_LIFECYCLE (DDS 1.4 §2.2.3.22): reader-local, NOT advertised in SEDP, NOT RxO-checked.
  ;; Both default INFINITE -> a NOT_ALIVE instance is never autopurged (the no-op default).
  (autopurge-nowriter-samples-delay +duration-infinite+ :type qos-duration)
  (autopurge-disposed-samples-delay +duration-infinite+ :type qos-duration)
  ;; RESOURCE_LIMITS (not an RxO policy). LENGTH_UNLIMITED = -1 is the DDS default.
  (resource-max-samples -1 :type integer)
  (resource-max-instances -1 :type integer)
  (resource-max-samples-per-instance -1 :type integer)
  ;; TYPE_CONSISTENCY_ENFORCEMENT (XTypes, reader-only, not RxO; see FR-TYPE-4).
  (type-consistency (make-type-consistency-enforcement) :type type-consistency-enforcement)
  ;; DISCOVERY_CONFIG (VENDOR EXTENSION, participant-scoped, not RxO, not in SEDP) — see the struct docstring.
  (discovery-announce-period (make-qos-duration 1 0) :type qos-duration)
  (discovery-lease-duration (make-qos-duration 100 0) :type qos-duration)
  ;; RELIABLE_WRITER_CACHE watermarks (VENDOR EXTENSION, writer-scoped, not RxO, not in SEDP) — see above.
  (writer-cache-low-watermark nil :type (or null (integer 0)))
  (writer-cache-high-watermark nil :type (or null (integer 1)))
  ;; ACKNOWLEDGMENT_KIND (VENDOR EXTENSION, ADR 0090) — RxO-checked by EQUALITY; see the docstring.
  (acknowledgment-kind :protocol
                       :type (member :protocol :application-auto :application-explicit)))

(defun* make-writer-qos (&rest args)
    (function (&rest t) qos)
  "QoS with DataWriter defaults: RELIABILITY -> RELIABLE; DATA_REPRESENTATION -> (:xcdr2) — the
   OFFERED representation the writer's TX serializes/sends (XTypes 1.3 §7.6.3.1.1). ARGS override:
   ARGS precede the defaults so a caller's keyword is the LEFTMOST (and thus winning, HyperSpec 3.4.1.4)."
  (apply #'make-qos (append args (list :reliability :reliable :data-representation (list :xcdr2)))))

(defun* make-reader-qos (&rest args)
    (function (&rest t) qos)
  "QoS with DataReader defaults: RELIABILITY -> BEST_EFFORT; DATA_REPRESENTATION -> (:xcdr2 :xcdr1) — the
   ACCEPTED set; the reader reads both (XCDR2 native + XCDR1 via the struct codec/FlatData transcode) and
   prefers XCDR2 (XTypes 1.3 §7.6.3.1.1). ARGS override: ARGS precede the defaults so a caller's keyword is
   the LEFTMOST (and thus winning, HyperSpec 3.4.1.4)."
  (apply #'make-qos (append args (list :reliability :best-effort :data-representation (list :xcdr2 :xcdr1)))))

;;; ---- RxO compatibility (FR-QOS-2) ----

(defun* qos-rxo-compatible (offered requested)
    (function (qos qos) (values boolean list))
  "RxO compatibility of an OFFERED (writer) QoS against a REQUESTED (reader) QoS,
   DDS 1.4 §2.2.3. Returns (values COMPATIBLE-P INCOMPATIBLE), where INCOMPATIBLE is
   the ordered list of policy keywords that fail — i.e. the policies that would raise
   OFFERED/REQUESTED_INCOMPATIBLE_QOS and block the endpoint match (FR-QOS-2)."
  (let ((bad '()))
    (when (< (reliability-rank (qos-reliability offered))
             (reliability-rank (qos-reliability requested)))
      (push :reliability bad))
    (when (< (durability-rank (qos-durability offered))
             (durability-rank (qos-durability requested)))
      (push :durability bad))
    (unless (duration<= (qos-deadline offered) (qos-deadline requested))
      (push :deadline bad))
    (unless (duration<= (qos-latency-budget offered) (qos-latency-budget requested))
      (push :latency-budget bad))
    (unless (eq (qos-ownership offered) (qos-ownership requested))
      (push :ownership bad))
    ;; ACKNOWLEDGMENT_KIND (VENDOR EXTENSION, ADR 0090): equality, and only between RELIABLE endpoints.
    ;; Gated on reliability because the policy is meaningless without acknowledgments — a BEST_EFFORT pair
    ;; acknowledges nothing whatever either side asked for, so refusing that match would block endpoints
    ;; that cannot possibly disagree. Equality rather than rank: see the qos docstring — BOTH mismatch
    ;; directions fail, one as silent data loss and the other as a silent stall.
    (when (and (eq (qos-reliability offered) :reliable)
               (eq (qos-reliability requested) :reliable)
               (not (eq (qos-acknowledgment-kind offered) (qos-acknowledgment-kind requested))))
      (push :acknowledgment-kind bad))
    (when (or (< (liveliness-rank (qos-liveliness offered))
                 (liveliness-rank (qos-liveliness requested)))
              (not (duration<= (qos-liveliness-lease offered) (qos-liveliness-lease requested))))
      (push :liveliness bad))
    (when (< (destination-order-rank (qos-destination-order offered))
             (destination-order-rank (qos-destination-order requested)))
      (push :destination-order bad))
    (when (or (< (presentation-rank (qos-presentation-scope offered))
                 (presentation-rank (qos-presentation-scope requested)))
              (and (qos-presentation-coherent requested) (not (qos-presentation-coherent offered)))
              (and (qos-presentation-ordered requested) (not (qos-presentation-ordered offered))))
      (push :presentation bad))
    (unless (member (first (qos-data-representation offered)) (qos-data-representation requested))
      (push :data-representation bad))
    (values (null bad) (nreverse bad))))

(defun* partition-match-p (a b)
    (function (qos qos) t)
  "Partitions overlap (DDS 1.4 §2.2.3 PARTITION). An empty partition list denotes the
   default partition, which matches another empty list. (Wildcard/fnmatch names are a
   later increment; v1 does exact name matching.) NOT part of RxO incompatibility."
  (let ((pa (or (qos-partition a) '(""))) (pb (or (qos-partition b) '(""))))
    (and (some (lambda (x) (member x pb :test #'string=)) pa) t)))

;;; ---- RxO truth-table test (FR-QOS-2) ----

(defun* %assert-rxo (label expect-bad got-bad)
    (function (t t t) t)
  "Assert the RxO incompatible-list GOT-BAD equals the EXPECT-BAD set (order-free)."
  (assert (and (= (length expect-bad) (length got-bad))   ; NOCOND(TEST): test-assertion helper reached ONLY from run-qos-rxo-test; the assert IS the test failure mechanism
               (every (lambda (p) (member p got-bad)) expect-bad))
          () "RxO[~a]: expected incompatible ~a, got ~a" label expect-bad got-bad)
  t)

(defun* run-qos-rxo-test ()
    (function () (eql t))
  "Exercise the DDS 1.4 §2.2.3 RxO truth table (FR-QOS-2): each kind-ordered policy
   (reliability/durability/liveliness/destination-order/presentation), each duration
   policy (deadline/latency-budget), ownership equality, and data-representation set
   membership — both the compatible and the incompatible direction."
  (flet ((bad (offered requested) (nth-value 1 (qos-rxo-compatible offered requested)))
         (d (ms) (make-qos-duration 0 (* ms 1000000))))
    ;; default writer (RELIABLE) + default reader (BEST_EFFORT) -> compatible
    (%assert-rxo :defaults '() (bad (make-writer-qos) (make-reader-qos)))
    ;; reliability: best-effort offered vs reliable requested -> incompatible
    (%assert-rxo :reliability '(:reliability)
                 (bad (make-qos :reliability :best-effort) (make-qos :reliability :reliable)))
    (%assert-rxo :reliability-ok '()
                 (bad (make-qos :reliability :reliable) (make-qos :reliability :best-effort)))
    ;; durability: volatile offered vs transient-local requested -> incompatible
    (%assert-rxo :durability '(:durability)
                 (bad (make-qos :durability :volatile) (make-qos :durability :transient-local)))
    (%assert-rxo :durability-ok '()
                 (bad (make-qos :durability :transient) (make-qos :durability :transient-local)))
    ;; deadline: offered 30ms must be <= requested 20ms -> incompatible
    (%assert-rxo :deadline '(:deadline)
                 (bad (make-qos :deadline (d 30)) (make-qos :deadline (d 20))))
    (%assert-rxo :deadline-ok '()
                 (bad (make-qos :deadline (d 10)) (make-qos :deadline (d 20))))
    ;; latency-budget: offered <= requested
    (%assert-rxo :latency '(:latency-budget)
                 (bad (make-qos :latency-budget (d 30)) (make-qos :latency-budget (d 20))))
    ;; ownership: kinds must be equal
    (%assert-rxo :ownership '(:ownership)
                 (bad (make-qos :ownership :shared) (make-qos :ownership :exclusive)))
    ;; liveliness: automatic offered vs manual-by-topic requested -> incompatible
    (%assert-rxo :liveliness '(:liveliness)
                 (bad (make-qos :liveliness :automatic) (make-qos :liveliness :manual-by-topic)))
    ;; destination-order: by-reception offered vs by-source requested -> incompatible
    (%assert-rxo :dest-order '(:destination-order)
                 (bad (make-qos :destination-order :by-reception-timestamp)
                      (make-qos :destination-order :by-source-timestamp)))
    ;; presentation: instance offered vs group requested -> incompatible
    (%assert-rxo :presentation '(:presentation)
                 (bad (make-qos :presentation-scope :instance)
                      (make-qos :presentation-scope :group)))
    ;; data-representation: xcdr2 offered, reader accepts only xcdr1 -> incompatible
    (%assert-rxo :data-rep '(:data-representation)
                 (bad (make-qos :data-representation '(:xcdr2))
                      (make-qos :data-representation '(:xcdr1))))
    (%assert-rxo :data-rep-ok '()
                 (bad (make-qos :data-representation '(:xcdr1))
                      (make-qos :data-representation '(:xcdr1 :xcdr2))))
    ;; multiple simultaneous incompatibilities are all reported
    (%assert-rxo :multi '(:reliability :ownership)
                 (bad (make-qos :reliability :best-effort :ownership :shared)
                      (make-qos :reliability :reliable :ownership :exclusive)))
    ;; PARTITION is not an RxO incompatibility but gates matching separately
    (assert (partition-match-p (make-qos) (make-qos)) () "default (empty) partitions must match")
    (assert (partition-match-p (make-qos :partition '("A" "B")) (make-qos :partition '("B")))
            () "overlapping partitions must match")
    (assert (not (partition-match-p (make-qos :partition '("A")) (make-qos :partition '("B"))))
            () "disjoint partitions must not match"))
  t)

;;; ---- DATA_REPRESENTATION RxO matrix + role-aware-default advertising (XTypes 1.3 §7.6.3.1.1) ----

(defun* run-data-representation-rxo-test ()
    (function () (eql t))
  "Lock the DATA_REPRESENTATION RxO matrix (XTypes 1.3 §7.6.3.1.1; the rule is
   offered-first ∈ reader-set) AND assert the truthful role-aware advertising defaults:
   make-reader-qos accepts (:xcdr2 :xcdr1) (XCDR2 native + XCDR1 via the struct codec/
   FlatData transcode, XCDR2 preferred), make-writer-qos offers (:xcdr2) (what TX sends).
   A failing data-representation policy is the policy-id-23 OFFERED/REQUESTED_INCOMPATIBLE_QOS."
  (flet ((bad (offered requested) (nth-value 1 (qos-rxo-compatible offered requested))))
    ;; (a) explicit-value matrix: a reader accepting both reps matches either single-rep writer.
    (%assert-rxo :rep-reader-both-vs-xcdr1 '()
                 (bad (make-qos :data-representation '(:xcdr1))
                      (make-qos :data-representation '(:xcdr2 :xcdr1))))
    (%assert-rxo :rep-reader-both-vs-xcdr2 '()
                 (bad (make-qos :data-representation '(:xcdr2))
                      (make-qos :data-representation '(:xcdr2 :xcdr1))))
    ;; an XCDR1-only reader does NOT accept an XCDR2-only writer -> incompatible (policy-id 23).
    (%assert-rxo :rep-xcdr1-reader-vs-xcdr2-writer '(:data-representation)
                 (bad (make-qos :data-representation '(:xcdr2))
                      (make-qos :data-representation '(:xcdr1))))
    ;; (b) role-aware DEFAULTS advertise the truth: reader accepts (:xcdr2 :xcdr1), writer offers (:xcdr2).
    (assert (equal (qos-data-representation (make-reader-qos)) '(:xcdr2 :xcdr1)) ()
            "make-reader-qos must default data-representation to (:xcdr2 :xcdr1)")
    (assert (equal (qos-data-representation (make-writer-qos)) '(:xcdr2)) ()
            "make-writer-qos must default data-representation to (:xcdr2)")
    ;; the default writer (offers :xcdr2) matches the default reader (accepts :xcdr2) -> our own pub/sub match.
    (%assert-rxo :rep-default-writer-vs-default-reader '()
                 (bad (make-writer-qos) (make-reader-qos)))
    ;; the default :xcdr2 writer vs an explicit XCDR1-only reader -> a TRUE incompatibility (step 2 resolves it).
    (%assert-rxo :rep-default-writer-vs-xcdr1-reader '(:data-representation)
                 (bad (make-writer-qos) (make-reader-qos :data-representation '(:xcdr1)))))
  t)
