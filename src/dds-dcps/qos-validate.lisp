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
