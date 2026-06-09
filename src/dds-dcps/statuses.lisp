;;;; DDS 1.4 communication statuses (M3 #3, FR-DCPS-3). Control-plane defstructs —
;;;; CLOS is not required here and a value struct matches the IDL one-to-one. The
;;;; StatusKind bit constants and the status struct fields are pinned from
;;;; docs/specs/dds_rtf2_dcps.idl (§77-180); the QosPolicyId_t constants from §363-385
;;;; of the same file, with DATA_REPRESENTATION_QOS_POLICY_ID from
;;;; docs/specs/xtypes-1_3-discovery-builtin-topic.idl §177 (NOT memorized). v1
;;;; populates MATCHED + INCOMPATIBLE_QOS (the RxO loop surfaced to the application);
;;;; the remaining statuses get struct scaffolding for later increments.

(in-package #:dds.dcps)

;;; ---- StatusKind bits (dds_rtf2_dcps.idl §80-92) ----

(defconstant +status-inconsistent-topic+         (ash 1 0))
(defconstant +status-offered-deadline-missed+    (ash 1 1))
(defconstant +status-requested-deadline-missed+  (ash 1 2))
(defconstant +status-offered-incompatible-qos+   (ash 1 5))
(defconstant +status-requested-incompatible-qos+ (ash 1 6))
(defconstant +status-sample-lost+                (ash 1 7))
(defconstant +status-sample-rejected+            (ash 1 8))
(defconstant +status-data-on-readers+            (ash 1 9))
(defconstant +status-data-available+             (ash 1 10))
(defconstant +status-liveliness-lost+            (ash 1 11))
(defconstant +status-liveliness-changed+         (ash 1 12))
(defconstant +status-publication-matched+        (ash 1 13))
(defconstant +status-subscription-matched+       (ash 1 14))

;;; ---- QosPolicyId_t (dds_rtf2_dcps.idl §363-385; DATA_REPRESENTATION from
;;;      xtypes-1_3-discovery-builtin-topic.idl §177) ----

(defconstant +qos-policy-id-invalid+ 0)
(defconstant +qos-policy-id-durability+ 2
  "DDS QosPolicyId_t for DURABILITY (dds_rtf2_dcps.idl §363-385).")
(defconstant +qos-policy-id-presentation+ 3
  "DDS QosPolicyId_t for PRESENTATION (dds_rtf2_dcps.idl §363-385).")
(defconstant +qos-policy-id-deadline+ 4
  "DDS QosPolicyId_t for DEADLINE (dds_rtf2_dcps.idl §363-385).")
(defconstant +qos-policy-id-latency-budget+ 5
  "DDS QosPolicyId_t for LATENCY_BUDGET (dds_rtf2_dcps.idl §363-385).")
(defconstant +qos-policy-id-ownership+ 6
  "DDS QosPolicyId_t for OWNERSHIP (dds_rtf2_dcps.idl §363-385).")
(defconstant +qos-policy-id-liveliness+ 8
  "DDS QosPolicyId_t for LIVELINESS (dds_rtf2_dcps.idl §363-385).")
(defconstant +qos-policy-id-reliability+ 11
  "DDS QosPolicyId_t for RELIABILITY (dds_rtf2_dcps.idl §363-385).")
(defconstant +qos-policy-id-destination-order+ 12
  "DDS QosPolicyId_t for DESTINATION_ORDER (dds_rtf2_dcps.idl §363-385).")
(defconstant +qos-policy-id-data-representation+ 23
  "DDS QosPolicyId_t for DATA_REPRESENTATION (xtypes-1_3-discovery-builtin-topic.idl §177).")

(defparameter *rxo-keyword->policy-id*
  (list (cons :reliability +qos-policy-id-reliability+)
        (cons :durability +qos-policy-id-durability+)
        (cons :deadline +qos-policy-id-deadline+)
        (cons :latency-budget +qos-policy-id-latency-budget+)
        (cons :ownership +qos-policy-id-ownership+)
        (cons :liveliness +qos-policy-id-liveliness+)
        (cons :destination-order +qos-policy-id-destination-order+)
        (cons :presentation +qos-policy-id-presentation+)
        (cons :data-representation +qos-policy-id-data-representation+))
  "Maps an RxO incompatible-policy keyword (dds.qos:qos-rxo-compatible's second value)
   to its DDS QosPolicyId_t for the (OFFERED|REQUESTED)_INCOMPATIBLE_QOS status.")

(defun* rxo-policy-id (keyword)
    (function (keyword) integer)
  "The DDS QosPolicyId_t for an RxO failing-policy KEYWORD, or +qos-policy-id-invalid+."
  (or (cdr (assoc keyword *rxo-keyword->policy-id*)) +qos-policy-id-invalid+))

;;; ---- Status structs (one-to-one with the IDL §94-180) ----

(defstruct* (subscription-matched-status (:constructor make-subscription-matched-status)
                                        (:copier copy-subscription-matched-status))
  "DataReader SUBSCRIPTION_MATCHED status (dds_rtf2_dcps.idl §174)."
  (total-count 0 :type integer)
  (total-count-change 0 :type integer)
  (current-count 0 :type integer)
  (current-count-change 0 :type integer)
  (last-publication-handle nil :type t))

(defstruct* (publication-matched-status (:constructor make-publication-matched-status)
                                       (:copier copy-publication-matched-status))
  "DataWriter PUBLICATION_MATCHED status (dds_rtf2_dcps.idl §165)."
  (total-count 0 :type integer)
  (total-count-change 0 :type integer)
  (current-count 0 :type integer)
  (current-count-change 0 :type integer)
  (last-subscription-handle nil :type t))

(deftype sample-rejected-reason ()
  "DDS SampleRejectedStatusKind (dds_rtf2_dcps.idl §104)."
  '(member :not-rejected :rejected-by-instances-limit
    :rejected-by-samples-limit :rejected-by-samples-per-instance-limit))

(defstruct* (sample-rejected-status (:constructor make-sample-rejected-status)
                                   (:copier copy-sample-rejected-status))
  "DataReader SAMPLE_REJECTED status (dds_rtf2_dcps.idl §111): a sample was rejected
   because a RESOURCE_LIMITS bound would have been exceeded."
  (total-count 0 :type integer)
  (total-count-change 0 :type integer)
  (last-reason :not-rejected :type sample-rejected-reason)
  (last-instance-handle nil :type t))

(defstruct* (inconsistent-topic-status (:constructor make-inconsistent-topic-status)
                                      (:copier copy-inconsistent-topic-status))
  "Topic INCONSISTENT_TOPIC status (dds_rtf2_dcps.idl §94): a remote topic of the same
   name but a different type was discovered."
  (total-count 0 :type integer)
  (total-count-change 0 :type integer))

(defstruct* (qos-policy-count (:constructor make-qos-policy-count (policy-id count))
                             (:copier copy-qos-policy-count))
  "DDS QosPolicyCount (dds_rtf2_dcps.idl §143): a policy id + how many times it failed."
  (policy-id 0 :type integer)
  (count 0 :type integer))

(defstruct* (requested-incompatible-qos-status
            (:constructor make-requested-incompatible-qos-status)
            (:copier copy-requested-incompatible-qos-status))
  "DataReader REQUESTED_INCOMPATIBLE_QOS status (dds_rtf2_dcps.idl §157)."
  (total-count 0 :type integer)
  (total-count-change 0 :type integer)
  (last-policy-id 0 :type integer)
  (policies '() :type list))

(defstruct* (offered-incompatible-qos-status
            (:constructor make-offered-incompatible-qos-status)
            (:copier copy-offered-incompatible-qos-status))
  "DataWriter OFFERED_INCOMPATIBLE_QOS status (dds_rtf2_dcps.idl §150)."
  (total-count 0 :type integer)
  (total-count-change 0 :type integer)
  (last-policy-id 0 :type integer)
  (policies '() :type list))

(defun* bump-policy-count (policies policy-id)
    (function (list integer) list)
  "Increment the QosPolicyCount for POLICY-ID in POLICIES (a QosPolicyCountSeq),
   appending {policy-id, 1} when absent. Returns the (possibly extended) list."
  (let ((pc (find policy-id policies :key #'qos-policy-count-policy-id)))
    (if pc
        (progn (incf (qos-policy-count-count pc)) policies)
        (append policies (list (make-qos-policy-count policy-id 1))))))
