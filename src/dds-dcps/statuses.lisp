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

(defconstant +status-inconsistent-topic+         (ash 1 0)
  "DDS StatusKind bit INCONSISTENT_TOPIC_STATUS (dds_rtf2_dcps.idl §80).")
(defconstant +status-offered-deadline-missed+    (ash 1 1)
  "DDS StatusKind bit OFFERED_DEADLINE_MISSED_STATUS (dds_rtf2_dcps.idl §81).")
(defconstant +status-requested-deadline-missed+  (ash 1 2)
  "DDS StatusKind bit REQUESTED_DEADLINE_MISSED_STATUS (dds_rtf2_dcps.idl §82).")
(defconstant +status-offered-incompatible-qos+   (ash 1 5)
  "DDS StatusKind bit OFFERED_INCOMPATIBLE_QOS_STATUS (dds_rtf2_dcps.idl §83).")
(defconstant +status-requested-incompatible-qos+ (ash 1 6)
  "DDS StatusKind bit REQUESTED_INCOMPATIBLE_QOS_STATUS (dds_rtf2_dcps.idl §84).")
(defconstant +status-sample-lost+                (ash 1 7)
  "DDS StatusKind bit SAMPLE_LOST_STATUS (dds_rtf2_dcps.idl §85).")
(defconstant +status-sample-rejected+            (ash 1 8)
  "DDS StatusKind bit SAMPLE_REJECTED_STATUS (dds_rtf2_dcps.idl §86).")
(defconstant +status-data-on-readers+            (ash 1 9)
  "DDS StatusKind bit DATA_ON_READERS_STATUS (dds_rtf2_dcps.idl §87).")
(defconstant +status-data-available+             (ash 1 10)
  "DDS StatusKind bit DATA_AVAILABLE_STATUS (dds_rtf2_dcps.idl §88).")
(defconstant +status-liveliness-lost+            (ash 1 11)
  "DDS StatusKind bit LIVELINESS_LOST_STATUS (dds_rtf2_dcps.idl §89).")
(defconstant +status-liveliness-changed+         (ash 1 12)
  "DDS StatusKind bit LIVELINESS_CHANGED_STATUS (dds_rtf2_dcps.idl §90).")
(defconstant +status-publication-matched+        (ash 1 13)
  "DDS StatusKind bit PUBLICATION_MATCHED_STATUS (dds_rtf2_dcps.idl §91).")
(defconstant +status-subscription-matched+       (ash 1 14)
  "DDS StatusKind bit SUBSCRIPTION_MATCHED_STATUS (dds_rtf2_dcps.idl §92).")

(defparameter *status-kind->bit*
  (list (cons :inconsistent-topic +status-inconsistent-topic+)
        (cons :offered-deadline-missed +status-offered-deadline-missed+)
        (cons :requested-deadline-missed +status-requested-deadline-missed+)
        (cons :offered-incompatible-qos +status-offered-incompatible-qos+)
        (cons :requested-incompatible-qos +status-requested-incompatible-qos+)
        (cons :sample-lost +status-sample-lost+)
        (cons :sample-rejected +status-sample-rejected+)
        (cons :data-on-readers +status-data-on-readers+)
        (cons :data-available +status-data-available+)
        (cons :liveliness-lost +status-liveliness-lost+)
        (cons :liveliness-changed +status-liveliness-changed+)
        (cons :publication-matched +status-publication-matched+)
        (cons :subscription-matched +status-subscription-matched+))
  "Maps a DDS communication-status keyword to its StatusKind bit (dds_rtf2_dcps.idl §80-92),
   shared by %notify-status callers and the StatusCondition trigger predicate.")

;;; ---- The DDS state masks (dds_rtf2_dcps.idl §294-320: SampleStateKind / ViewStateKind /
;;;      InstanceStateKind + the ANY_*_STATE masks). The IDL models each mask as a bitmask over the
;;;      *_KIND bits; here a mask is the keyword LIST of the kinds it admits — a caller writes
;;;      '(:not-read) and MEMBER is the mask test. Same expressive power, no bit arithmetic. ----

(defparameter +any-sample-states+ '(:read :not-read)
  "ANY_SAMPLE_STATE (dds_rtf2_dcps.idl §300 = 0xffff): every SampleStateKind — READ_SAMPLE_STATE +
   NOT_READ_SAMPLE_STATE (§295-296). The default sample_states mask of read/take + get_datareaders;
   selects a sample whether or not the application has already accessed it.")

(defparameter +any-view-states+ '(:new :not-new)
  "ANY_VIEW_STATE (dds_rtf2_dcps.idl §309 = 0xffff): every ViewStateKind — NEW_VIEW_STATE +
   NOT_NEW_VIEW_STATE (§304-305). The default view_states mask; selects a sample whether or not its
   INSTANCE has been accessed before (the view state is a property of the instance as seen by the
   reader, DDS 1.4 §2.2.2.5.1.4).")

(defparameter +any-instance-states+ '(:alive :not-alive-disposed :not-alive-no-writers)
  "ANY_INSTANCE_STATE (dds_rtf2_dcps.idl §319 = 0xffff): every InstanceStateKind —
   ALIVE_INSTANCE_STATE + NOT_ALIVE_DISPOSED_INSTANCE_STATE + NOT_ALIVE_NO_WRITERS_INSTANCE_STATE
   (§313-315). The default instance_states mask; selects a sample whatever the liveness of its instance.
   NOT_ALIVE_INSTANCE_STATE (§320 = 0x006, the two NOT_ALIVE kinds together) is written here as the
   two-element list '(:not-alive-disposed :not-alive-no-writers).")

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
(defconstant +qos-policy-id-time-based-filter+ 9
  "DDS QosPolicyId_t for TIME_BASED_FILTER (dds_rtf2_dcps.idl §363-385).")
(defconstant +qos-policy-id-destination-order+ 12
  "DDS QosPolicyId_t for DESTINATION_ORDER (dds_rtf2_dcps.idl §363-385).")
(defconstant +qos-policy-id-history+ 13
  "DDS QosPolicyId_t for HISTORY (dds_rtf2_dcps.idl §363-385).")
(defconstant +qos-policy-id-resource-limits+ 14
  "DDS QosPolicyId_t for RESOURCE_LIMITS (dds_rtf2_dcps.idl §363-385).")
(defconstant +qos-policy-id-data-representation+ 23
  "DDS QosPolicyId_t for DATA_REPRESENTATION (xtypes-1_3-discovery-builtin-topic.idl §177).")
(defconstant +qos-policy-id-type-consistency+ 24
  "DDS QosPolicyId_t for TYPE_CONSISTENCY_ENFORCEMENT (xtypes-1_3-discovery-builtin-topic.idl §191).")

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
  (last-publication-handle nil :type (or null (array (unsigned-byte 8) (*)))))

(defstruct* (publication-matched-status (:constructor make-publication-matched-status)
                                       (:copier copy-publication-matched-status))
  "DataWriter PUBLICATION_MATCHED status (dds_rtf2_dcps.idl §165)."
  (total-count 0 :type integer)
  (total-count-change 0 :type integer)
  (current-count 0 :type integer)
  (current-count-change 0 :type integer)
  (last-subscription-handle nil :type (or null (array (unsigned-byte 8) (*)))))

(defstruct* (liveliness-changed-status (:constructor make-liveliness-changed-status)
                                      (:copier copy-liveliness-changed-status))
  "DataReader LIVELINESS_CHANGED status (dds_rtf2_dcps.idl §123-129): how many matched
   DataWriters are currently asserting their liveliness (ALIVE) vs have let it lapse
   (NOT_ALIVE) within their offered LIVELINESS lease_duration (RTPS 2.5 §8.4.13). On a
   matched writer going not-alive alive_count decreases + not_alive_count increases (and
   the reverse on it becoming alive again); the *_change fields accumulate the delta since
   the last read; last_publication_handle is the most recently transitioned writer's GUID."
  (alive-count 0 :type integer)
  (not-alive-count 0 :type integer)
  (alive-count-change 0 :type integer)
  (not-alive-count-change 0 :type integer)
  (last-publication-handle nil :type (or null (array (unsigned-byte 8) (*)))))

(defstruct* (liveliness-lost-status (:constructor make-liveliness-lost-status)
                                   (:copier copy-liveliness-lost-status))
  "DataWriter LIVELINESS_LOST status (dds_rtf2_dcps.idl §118-121): the local writer
   failed to assert its own liveliness within its offered LIVELINESS lease_duration
   (DDS 1.4 §2.2.3.11). total_count is the cumulative number of times the writer became
   not-alive (monotonic, never decremented); total_count_change accumulates the delta
   since the status was last read."
  (total-count 0 :type integer)
  (total-count-change 0 :type integer))

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
  (last-instance-handle nil :type (or null (array (unsigned-byte 8) (*)))))

(defconstant +status-unaddressable-peer+          (ash 1 24)
  "VENDOR-EXTENSION StatusKind bit UNADDRESSABLE_PEER — NOT an OMG status. DDS 1.4 defines no status for
   'a remote endpoint matched on topic/type/QoS but cannot be addressed', so this stack defines one rather
   than report the condition unusably. Deliberately placed at bit 24, far above the OMG range (bits 0-14,
   dds_rtf2_dcps.idl §80-92), so a future standard StatusKind can never collide with it. Owner directive
   2026-07-22: anything that MATCHES must be ADDRESSABLE; if it is not, that is an ERROR and must be
   announced through the normal status machinery — bitmask + StatusCondition + listener + get_*_status.")

(defstruct* (unaddressable-peer-status (:constructor make-unaddressable-peer-status)
                                       (:copier copy-unaddressable-peer-status))
  "DomainParticipant UNADDRESSABLE_PEER status (VENDOR EXTENSION, see +status-unaddressable-peer+): a
   remote endpoint was topic/type/QoS compatible but its participant advertises no user-data locator this
   implementation can send to, so the match was REFUSED rather than recorded and silently never delivered.
   LAST-GUID is the refused remote endpoint's 16-octet GUID; LAST-LOCATOR-KINDS are the Locator_t kinds it
   did offer, which is what tells an operator what to change (typically: enable UDPv4 on the peer — RTPS
   2.5 §7.5 makes UDP/IP the one PSM every implementation must support, and defines no other)."
  (total-count 0 :type integer)
  (total-count-change 0 :type integer)
  (last-guid nil :type t)
  (last-locator-kinds '() :type list))

(defstruct* (inconsistent-topic-status (:constructor make-inconsistent-topic-status)
                                      (:copier copy-inconsistent-topic-status))
  "Topic INCONSISTENT_TOPIC status (dds_rtf2_dcps.idl §94): a remote topic of the same
   name but a different type was discovered."
  (total-count 0 :type integer)
  (total-count-change 0 :type integer))

(defstruct* (sample-lost-status (:constructor make-sample-lost-status)
                               (:copier copy-sample-lost-status))
  "DataReader SAMPLE_LOST status (dds_rtf2_dcps.idl §99-102): total_count is the cumulative
   number of samples that were lost (never made available to the DataReader), never
   decremented; total_count_change accumulates the delta since the status was last read. The
   RTF2 SampleLostStatus carries no SampleLostStatusKind, so there is no last_reason field."
  (total-count 0 :type integer)
  (total-count-change 0 :type integer))

(defstruct* (offered-deadline-missed-status (:constructor make-offered-deadline-missed-status)
                                           (:copier copy-offered-deadline-missed-status))
  "DataWriter OFFERED_DEADLINE_MISSED status (dds_rtf2_dcps.idl §131-135): the local writer
   failed to write a sample for an instance within its offered DEADLINE period. total_count is
   the cumulative number of missed deadlines (monotonic); total_count_change accumulates the
   delta since the status was last read; last_instance_handle is the most recently missed
   instance's 16-octet handle."
  (total-count 0 :type integer)
  (total-count-change 0 :type integer)
  (last-instance-handle nil :type (or null (array (unsigned-byte 8) (*)))))

(defstruct* (requested-deadline-missed-status (:constructor make-requested-deadline-missed-status)
                                             (:copier copy-requested-deadline-missed-status))
  "DataReader REQUESTED_DEADLINE_MISSED status (dds_rtf2_dcps.idl §137-141): no sample was
   received for an instance within the reader's requested DEADLINE period. total_count is the
   cumulative number of missed deadlines (monotonic); total_count_change accumulates the delta
   since the status was last read; last_instance_handle is the most recently missed instance's
   16-octet handle."
  (total-count 0 :type integer)
  (total-count-change 0 :type integer)
  (last-instance-handle nil :type (or null (array (unsigned-byte 8) (*)))))

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
