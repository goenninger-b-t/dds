;;;; DDS 1.4 QoS-management validation (WP-DCPS-API-COMPLETION S1): the per-policy
;;;; immutability table (§2.2.3 "changeable" column, drives IMMUTABLE_POLICY on a
;;;; post-enable mutation) and the cross-policy consistency validator (§2.2.3.18/§2.2.3.19,
;;;; drives INCONSISTENT_POLICY). Control-plane, CLOS-free; shared by set_qos on every entity.
;;;; No wire constant invented from memory — every policy id is pinned in statuses.lisp.

(in-package #:dds.dcps)

;;; ---- S1.T1: the immutability table (DDS 1.4 §2.2.3 per-policy "changeable" column) ----
;;; Each entry is (POLICY-KEYWORD POLICY-ID SAME-P) where SAME-P is (function (qos qos) boolean)
;;; returning T iff the two QoS sets carry an UNCHANGED value for that policy. A policy is
;;; immutable-after-enable iff it appears here; every absent policy (USER_DATA, DEADLINE,
;;; LATENCY_BUDGET, OWNERSHIP_STRENGTH, TRANSPORT_PRIORITY, LIFESPAN, PARTITION, the DATA_LIFECYCLE
;;; policies, ENTITY_FACTORY) is changeable and never raises IMMUTABLE_POLICY.

(defun* %duration-eq (a b)
    (function (dds.qos:qos-duration dds.qos:qos-duration) boolean)
  "Field equality of two DDS Duration_t (sec + nanosec), used to diff a duration-valued
   immutable policy (LIVELINESS lease_duration) between two QoS sets."
  (and (= (dds.qos:qos-duration-sec a) (dds.qos:qos-duration-sec b))
       (= (dds.qos:qos-duration-nanosec a) (dds.qos:qos-duration-nanosec b))))

(defparameter *qos-immutability-table*
  (list
   (list :reliability +qos-policy-id-reliability+
         (lambda (a b) (eq (dds.qos:qos-reliability a) (dds.qos:qos-reliability b))))
   (list :durability +qos-policy-id-durability+
         (lambda (a b) (eq (dds.qos:qos-durability a) (dds.qos:qos-durability b))))
   (list :presentation +qos-policy-id-presentation+
         (lambda (a b) (and (eq (dds.qos:qos-presentation-scope a) (dds.qos:qos-presentation-scope b))
                            (eq (dds.qos:qos-presentation-coherent a) (dds.qos:qos-presentation-coherent b))
                            (eq (dds.qos:qos-presentation-ordered a) (dds.qos:qos-presentation-ordered b)))))
   (list :ownership +qos-policy-id-ownership+
         (lambda (a b) (eq (dds.qos:qos-ownership a) (dds.qos:qos-ownership b))))
   (list :liveliness +qos-policy-id-liveliness+
         (lambda (a b) (and (eq (dds.qos:qos-liveliness a) (dds.qos:qos-liveliness b))
                            (%duration-eq (dds.qos:qos-liveliness-lease a) (dds.qos:qos-liveliness-lease b)))))
   (list :destination-order +qos-policy-id-destination-order+
         (lambda (a b) (eq (dds.qos:qos-destination-order a) (dds.qos:qos-destination-order b))))
   (list :history +qos-policy-id-history+
         (lambda (a b) (and (eq (dds.qos:qos-history-kind a) (dds.qos:qos-history-kind b))
                            (= (dds.qos:qos-history-depth a) (dds.qos:qos-history-depth b)))))
   (list :resource-limits +qos-policy-id-resource-limits+
         (lambda (a b) (and (= (dds.qos:qos-resource-max-samples a) (dds.qos:qos-resource-max-samples b))
                            (= (dds.qos:qos-resource-max-instances a) (dds.qos:qos-resource-max-instances b))
                            (= (dds.qos:qos-resource-max-samples-per-instance a)
                               (dds.qos:qos-resource-max-samples-per-instance b)))))
   (list :data-representation +qos-policy-id-data-representation+
         (lambda (a b) (equal (dds.qos:qos-data-representation a) (dds.qos:qos-data-representation b))))
   (list :type-consistency +qos-policy-id-type-consistency+
         (lambda (a b) (equalp (dds.qos:qos-type-consistency a) (dds.qos:qos-type-consistency b)))))
  "The DDS 1.4 §2.2.3 QoS-policy immutability table: the policies whose 'changeable' column is
   No (immutable once the entity is enabled). Entries are (POLICY-KEYWORD POLICY-ID SAME-P);
   SAME-P diffs the policy value between two QoS sets so set_qos on an enabled entity can raise
   IMMUTABLE_POLICY citing the first changed policy's id. Pinned per policy: RELIABILITY (kind),
   DURABILITY (kind), PRESENTATION, OWNERSHIP (kind), LIVELINESS (kind + lease_duration),
   DESTINATION_ORDER, HISTORY, RESOURCE_LIMITS (§2.2.3); DATA_REPRESENTATION and
   TYPE_CONSISTENCY_ENFORCEMENT (XTypes 1.3 §7.6.3.1.1 / §7.6.3.4, both immutable).")

(defun* qos-policy-immutable-p (policy)
    (function (keyword) boolean)
  "T iff the QoS POLICY keyword is immutable-after-enable per the DDS 1.4 §2.2.3 per-policy
   'changeable' column (i.e. mutating it via set_qos on an enabled entity yields
   IMMUTABLE_POLICY). NIL for any changeable policy. See *qos-immutability-table*."
  (and (assoc policy *qos-immutability-table*) t))

(defun* %qos-immutable-violation (old new)
    (function (dds.qos:qos dds.qos:qos) integer)
  "The DDS QosPolicyId_t of the FIRST immutable policy (DDS 1.4 §2.2.3) whose value differs
   between the currently-effective OLD QoS and the proposed NEW QoS, or +qos-policy-id-invalid+
   (0) when every immutable policy is unchanged. Drives IMMUTABLE_POLICY in set_qos on an
   enabled entity; changeable policies are ignored (never a violation)."
  (dolist (entry *qos-immutability-table* +qos-policy-id-invalid+)
    (unless (funcall (the function (third entry)) old new)
      (return (the integer (second entry))))))

;;; ---- S1.T2: the cross-policy consistency validator (INCONSISTENT_POLICY) ----

(defun* %resource-limit-bounded-p (n)
    (function (integer) boolean)
  "T iff a RESOURCE_LIMITS limit N is an active finite bound (>= 0), i.e. NOT the DDS
   LENGTH_UNLIMITED sentinel -1 (dds_rtf2_dcps.idl LENGTH_UNLIMITED). An unlimited limit
   imposes no consistency constraint."
  (>= n 0))

(defun* %discovery-config-consistent-p (qos)
    (function (dds.qos:qos) boolean)
  "T iff QOS's DISCOVERY_CONFIG (vendor extension, WP-DCPS-API-COMPLETION S7) is self-consistent: the
   announce period is FINITE and POSITIVE (a cadence of zero or DURATION_INFINITE announces nothing), and
   — when the announced leaseDuration is finite — it is STRICTLY SHORTER than that lease. An announce
   period at or above the lease is self-defeating: peers would age this participant out (RTPS 2.5
   §8.5.3.3.2) between its own announcements, so it flaps in and out of every peer's discovery set. This
   raises INCONSISTENT_POLICY citing +qos-policy-id-invalid+ — the policy is a vendor extension with no OMG
   QosPolicyId_t, and an id is never invented (see the qos struct docstring)."
  (let ((period (dds.qos:qos-discovery-announce-period qos))
        (lease (dds.qos:qos-discovery-lease-duration qos)))
    (and (not (dds.qos:duration-infinite-p period))
         (plusp (dds.qos:duration->seconds period))
         (or (dds.qos:duration-infinite-p lease)
             (< (dds.qos:duration->seconds period) (dds.qos:duration->seconds lease))))))

(defun* %qos-consistent-p (qos)
    (function (dds.qos:qos) (values boolean integer))
  "Validate the DDS 1.4 cross-policy consistency rules that raise INCONSISTENT_POLICY,
   returning (values OK-P FAILING-POLICY-ID). The rules (a LENGTH_UNLIMITED -1 limit disables
   its bound): §2.2.3.19 RESOURCE_LIMITS.max_samples >= max_samples_per_instance (else the
   RESOURCE_LIMITS id); §2.2.3.18 HISTORY (KEEP_LAST) depth <= RESOURCE_LIMITS.max_samples_per_
   instance (else the HISTORY id). A consistent QoS yields (values T +qos-policy-id-invalid+). Also
   enforced: the DISCOVERY_CONFIG vendor extension (announce period finite, positive, and shorter than the
   announced lease — %discovery-config-consistent-p), reporting +qos-policy-id-invalid+ as it carries no
   OMG policy id.
   Policies the stack does not yet model (TIME_BASED_FILTER minimum_separation vs DEADLINE) are
   not checked here — recorded as a follow-on, not silently claimed."
  (let ((max-samples (dds.qos:qos-resource-max-samples qos))
        (mspi (dds.qos:qos-resource-max-samples-per-instance qos)))
    (when (and (%resource-limit-bounded-p max-samples)
               (%resource-limit-bounded-p mspi)
               (> mspi max-samples))
      (return-from %qos-consistent-p (values nil +qos-policy-id-resource-limits+)))
    (when (and (eq :keep-last (dds.qos:qos-history-kind qos))
               (%resource-limit-bounded-p mspi)
               (> (dds.qos:qos-history-depth qos) mspi))
      (return-from %qos-consistent-p (values nil +qos-policy-id-history+)))
    (unless (%discovery-config-consistent-p qos)
      (return-from %qos-consistent-p (values nil +qos-policy-id-invalid+)))
    (values t +qos-policy-id-invalid+)))
