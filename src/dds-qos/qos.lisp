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
   filled in as the entity model lands). Slot defaults follow DDS 1.4 §2.2.3."
  (reliability :best-effort :type (member :best-effort :reliable))
  (reliability-max-blocking (make-qos-duration 0 100000000) :type qos-duration) ; 100 ms
  (durability :volatile :type (member :volatile :transient-local :transient :persistent))
  (deadline +duration-infinite+ :type qos-duration)
  (latency-budget +duration-zero+ :type qos-duration)
  (ownership :shared :type (member :shared :exclusive))
  (ownership-strength 0 :type integer)
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
  ;; RESOURCE_LIMITS (not an RxO policy). LENGTH_UNLIMITED = -1 is the DDS default.
  (resource-max-samples -1 :type integer)
  (resource-max-instances -1 :type integer)
  (resource-max-samples-per-instance -1 :type integer)
  ;; TYPE_CONSISTENCY_ENFORCEMENT (XTypes, reader-only, not RxO; see FR-TYPE-4).
  (type-consistency (make-type-consistency-enforcement) :type type-consistency-enforcement))

(defun* make-writer-qos (&rest args)
    (function (&rest t) qos)
  "QoS with DataWriter defaults (RELIABILITY defaults to RELIABLE). ARGS override."
  (apply #'make-qos :reliability :reliable args))

(defun* make-reader-qos (&rest args)
    (function (&rest t) qos)
  "QoS with DataReader defaults (RELIABILITY defaults to BEST_EFFORT). ARGS override."
  (apply #'make-qos :reliability :best-effort args))

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
  (assert (and (= (length expect-bad) (length got-bad))
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
