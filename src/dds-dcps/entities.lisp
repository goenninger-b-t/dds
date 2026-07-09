;;;; DDS 1.4 DCPS entity model (M3/P2, FR-DCPS-1). CLOS — this is control-plane, so
;;;; CLOS is the preferred default (FR-LANG-0); none of this is on the hot path. The
;;;; entities are a thin, typed facade over the existing RTPS engine (dds.disc): a
;;;; DomainParticipant owns a multicast disc-node; each DataWriter/DataReader binds to its
;;;; own distinct engine EntityId (WP-N-ENDPOINT S1/S2), and the disc->DCPS status/listener
;;;; hooks resolve the endpoint an event is about per-topic / per-route (WP-N-ENDPOINT-S5) — N
;;;; writers + N readers per participant on distinct topics (same-topic multi-endpoint deferred).
;;;; write/take serialize/deserialize through the generated type-support (dds.types).

(in-package #:dds.dcps)

(defun* %lease-now ()
    (function () (integer 0))
  "The monotonic DCPS liveliness clock — the same internal-real-time source the engine's
   lease/liveliness bookkeeping uses (dds.disc::%lease-now), shared so a DataWriter's self-
   assertion stamp is comparable across the DCPS/disc boundary (DDS 1.4 §2.2.3.11)."
  (dds.disc::%lease-now))

;;; ---- Entity hierarchy (CLOS inheritance is the DDS idiom) ----

(defclass entity ()
  ((qos :initarg :qos :initform nil :accessor entity-qos)
   (enabled :initarg :enabled :initform nil :accessor entity-enabled-p)
   (autoenable-created-entities :initarg :autoenable :initform t
                                :accessor entity-autoenable-created-entities)
   (type-compat :initform nil :accessor entity-type-compat)
   (status-changes :initform 0 :type (unsigned-byte 32) :accessor %entity-status-changes)
   (status-condition :initform nil :accessor %entity-owned-status-condition))
  (:documentation "Base DDS Entity: carries the QoS and the enabled flag shared by all
   DCPS entities (DomainParticipant, Publisher/Subscriber, Topic, DataWriter/DataReader).
   TYPE-COMPAT holds the ADVISORY type-object fingerprint verdict for the most recently
   matched remote endpoint (ADR 0009; DataReader/DataWriter only, NIL on other entities and
   until a first match) — a heuristic signal, never a match gate; see ENTITY-TYPE-COMPAT.
   STATUS-CHANGES is the DDS 1.4 StatusMask (dds_rtf2_dcps.idl §684) of communication
   statuses changed since last read, maintained by %notify-status and read by
   get_status_changes (guarded by the entity's status lock; DataReader/DataWriter/Topic).
   STATUS-CONDITION is the entity's lazily-created, entity-owned StatusCondition (S0.T4;
   dds_rtf2_dcps.idl §682), NIL until get_statuscondition is first called.
   AUTOENABLE-CREATED-ENTITIES is this entity's ENTITY_FACTORY autoenable_created_entities policy
   (DDS 1.4 §2.2.3.23, S2.T3): T (the spec default) auto-enables each CHILD this entity creates at
   create time, NIL creates the child disabled until enable() is called (a local policy, never on
   the wire). ENABLED is the DDS enabled state (§2.2.2.1.1.7) formalized by enable()/S2."))

(defclass domain-participant (entity)
  ((domain :initarg :domain :reader dp-domain)
   (node :initarg :node :accessor dp-node)
   (children :initform '() :accessor dp-children)
   (default-topic-qos :initform nil :accessor dp-default-topic-qos)          ; DDS 1.4 §2.2.2.2 get/set_default_topic_qos
   (default-publisher-qos :initform nil :accessor dp-default-publisher-qos)  ; DDS 1.4 §2.2.2.2 get/set_default_publisher_qos
   (default-subscriber-qos :initform nil :accessor dp-default-subscriber-qos) ; DDS 1.4 §2.2.2.2 get/set_default_subscriber_qos
   (type-gate-state :initform nil :accessor dp-type-gate-state)   ; FR-TYPE-4 gate (type-gate.lisp)
   (auth-state :initform nil :accessor dp-auth-state)   ; DDS-Security 1.1 §8.7 auth manager (auth-manager.lisp)
   (access-state :initform nil :accessor dp-access-state))   ; DDS-Security 1.1 §8.4 AccessControl manager (access-control.lisp)
  (:documentation "DDS DomainParticipant: owns a multicast disc-node for its domain and
   its contained entities. Holds N DataReaders + N DataWriters (on distinct topics) across its
   Subscribers/Publishers; the disc->DCPS status/listener hooks resolve the endpoint an event is
   about per-topic / per-route (WP-N-ENDPOINT-S5), not via a participant-wide back-ref.
   TYPE-GATE-STATE carries the FR-TYPE-4 assignability gate's TypeObject/verdict caches.
   AUTH-STATE carries the DDS-Security §8.7 authentication manager's local identity +
   per-remote handshake/key state (NIL = security OFF; see auth-manager.lisp).
   ACCESS-STATE holds the DDS-Security §8.4 AccessControl access-handle (validated Governance +
   shared Permissions) driving the permissions-gate (NIL = access-control OFF; see access-control.lisp)."))

(defclass publisher (entity)
  ((participant :initarg :participant :reader pub-participant)
   (writers :initform '() :accessor pub-writers)
   (default-datawriter-qos :initform nil :accessor pub-default-datawriter-qos)) ; DDS 1.4 §2.2.2.4.1 get/set_default_datawriter_qos
  (:documentation "DDS Publisher: a factory/container for DataWriters in its participant."))

(defclass subscriber (entity)
  ((participant :initarg :participant :reader sub-participant)
   (readers :initform '() :accessor sub-readers)
   (default-datareader-qos :initform nil :accessor sub-default-datareader-qos)) ; DDS 1.4 §2.2.2.5.1 get/set_default_datareader_qos
  (:documentation "DDS Subscriber: a factory/container for DataReaders in its participant."))

(defclass topic (entity)
  ((name :initarg :name :reader topic-name)
   (type-name :initarg :type-name :reader topic-type-name)
   (type-support :initarg :type-support :reader topic-type-support)
   (participant :initarg :participant :reader topic-participant)
   (inconsistent-status :initform (make-inconsistent-topic-status) :accessor topic-inconsistent-status)
   (listener :initform nil :accessor topic-listener-obj)
   (listener-mask :initform '() :accessor topic-listener-mask)
   (status-lock :initform (dds.pal:make-lock "topic-status") :accessor topic-status-lock))
  (:documentation "DDS Topic: a named type binding (name + type-name + type-support)
   within a participant, carrying its INCONSISTENT_TOPIC status and optional listener."))

(defclass data-writer (entity)
  ((topic :initarg :topic :reader dw-topic)
   (publisher :initarg :publisher :reader dw-publisher)
   (entity-id :initform 0 :accessor dw-entity-id) ; WP-N-ENDPOINT-S1 (ADR 0048): this writer's DISTINCT engine EntityId (RTPS 2.5 §9.3.1.2), captured at create-datawriter; write-sample threads it to publish-sample so the sample enters THIS writer's HistoryCache (not the aliased primary)
   (disc-endpoint :initform nil :accessor dw-disc-endpoint) ; WP-DCPS-API-COMPLETION S2.T4: this writer's SEDP endpoint-data (from add-local-writer), so delete_datawriter can remove-local-writer it from discovery

   (pub-matched :initform (make-publication-matched-status) :accessor dw-pub-matched)
   (off-incompat :initform (make-offered-incompatible-qos-status) :accessor dw-off-incompat)
   (liv-lost :initform (make-liveliness-lost-status) :accessor dw-liv-lost)
   (last-assertion :initform (%lease-now) :accessor dw-last-assertion) ; last self-assertion stamp (DDS 1.4 §2.2.3.11)
   (alive :initform t :accessor dw-alive-p)                            ; LIVELINESS_LOST loss-transition flag
   (listener :initform nil :accessor dw-listener)
   (listener-mask :initform '() :accessor dw-listener-mask)
   (instances :initform (make-hash-table :test 'equalp) :accessor dw-instances) ; 16-octet handle -> :alive (DDS 1.4 §2.2.2.4.2)
   (loans :initform '() :accessor dw-loans)                ; WP-FLATDATA-LOAN-WRITE (R6, ADR 0042): outstanding writer-loans (writer-close safety sweep)
   (loan-freelist :initform '() :accessor dw-loan-freelist) ; WP-FLATDATA-LOAN-WRITE: recycled writer-loan structs (the struct+view recycle; the registry cell + retained payload are the documented v1 per-write cost)
   (loan-encap :initform nil :accessor dw-loan-encap)      ; WP-FLATDATA-LOAN-WRITE (ADR 0042): the type's 4-octet encap header+options, cached once from the FlatData ctor (%loan-encap-header) — written into every slot-backed loan's slot
   (status-lock :initform (dds.pal:make-lock "dw-status") :accessor dw-status-lock))
  (:documentation "DDS DataWriter: publishes typed samples on a Topic, carrying its
   PUBLICATION_MATCHED, OFFERED_INCOMPATIBLE_QOS and LIVELINESS_LOST statuses and optional
   listener. LAST-ASSERTION is the internal-real-time stamp of the most recent self-
   assertion (a write or assert_liveliness, or the announce cadence for an AUTOMATIC
   writer); ALIVE is the loss-transition flag so LIVELINESS_LOST fires once per going-lost."))

(defclass data-reader (entity)
  ((topic :initarg :topic :reader dr-topic)
   (subscriber :initarg :subscriber :reader dr-subscriber)
   (entity-id :initform 0 :accessor dr-entity-id) ; WP-N-ENDPOINT-S2 (ADR 0048): this reader's DISTINCT engine EntityId (RTPS 2.5 §9.3.1.2), captured at create-datareader; %drain's source-GUID filter keeps only samples whose remote writer is matched to THIS reader-id (node-reader-matches-writer-p) -> no cross-topic deserialize
   (disc-endpoint :initform nil :accessor dr-disc-endpoint) ; WP-DCPS-API-COMPLETION S2.T4: this reader's SEDP endpoint-data (from add-local-reader), so delete_datareader can remove-local-reader it from discovery

   (cache :initform '() :accessor dr-cache)                       ; list of cached-sample
   (instances :initform (make-hash-table :test 'equalp) :accessor dr-instances) ; handle -> accessed-p
   (instance-recs :initform (make-hash-table :test 'equalp) :accessor dr-instance-recs) ; handle -> instance-rec (DDS 1.4 §2.2.2.5.1.3)
   (drained :initform (make-hash-table :test 'equalp) :accessor dr-drained) ; 16-octet source GUID -> highest engine SN drained for that writer (§8.3.5.4: SN is per-writer)
   (lifecycle-drained :initform '() :accessor dr-lifecycle-drained) ; engine lifecycle (GUID . SN) composite keys already consumed (user thread)
   (sub-matched :initform (make-subscription-matched-status) :accessor dr-sub-matched)
   (req-incompat :initform (make-requested-incompatible-qos-status) :accessor dr-req-incompat)
   (sample-rejected :initform (make-sample-rejected-status) :accessor dr-sample-rejected)
   (liv-changed :initform (make-liveliness-changed-status) :accessor dr-liv-changed)
   (listener :initform nil :accessor dr-listener)
   (listener-mask :initform '() :accessor dr-listener-mask)
   (conditions :initform '() :accessor dr-conditions)      ; read/query/status conditions bound here
   (filter :initform nil :accessor dr-filter)              ; ContentFilteredTopic predicate, or nil
   (loans :initform '() :accessor dr-loans)                ; WP-FLATDATA-ZC-LOAN (R6, ADR 0017): outstanding loaned flatdata-views (the loan registry) — return-loan / reader-close release them
   (view-freelist :initform '() :accessor dr-view-freelist) ; WP-FLATDATA-ZC-LOAN: recycled flatdata-view structs (no per-sample GC-heap alloc; NFR-MEM)
   (secured-loans :initform '() :accessor dr-secured-loans) ; WP-DCPS-SECURED-TAKE-LOAN (ADR 0038 (i)): outstanding secured decode-loan handles — SEPARATE registry from dr-loans (the type-clean two-registry discipline); return-loan / reader-close node-return-loan them
   (secured-scratch :initform nil :accessor dr-secured-scratch) ; WP-DCPS-SECURED-TAKE-LOAN: reusable octet-buffer wrapper (repointed per drain) for the in-place [0,len) secured-plaintext deserialize — created once, zero per-sample cons (NFR-MEM)
   (status-lock :initform (dds.pal:make-lock "dr-status") :accessor dr-status-lock))
  (:documentation "DDS DataReader: receives typed samples on a Topic into a read/take
   cache with per-instance SampleInfo, carrying its SUBSCRIPTION_MATCHED,
   REQUESTED_INCOMPATIBLE_QOS and SAMPLE_REJECTED statuses, conditions and listener."))

;; Defined in conditions.lisp (loaded after this file); forward-declared so the data-
;; arrival hook below can wake the reader's WaitSets without a compile-time warning.
(declaim (ftype (function (data-reader) t) %notify-reader-conditions))

;; Defined in type-gate.lisp (loaded after this file); forward-declared so
;; create-participant can install the FR-TYPE-4 assignability gate.
(declaim (ftype (function (domain-participant) domain-participant) %install-type-gate))

;; Defined in auth-manager.lisp (loaded after this file); forward-declared so
;; create-participant can install the DDS-Security §8.7 auth manager when an identity is configured.
(declaim (ftype (function (domain-participant dds.security:identity-handle
                           &optional (or null (simple-array (unsigned-byte 8) (*))))
                          domain-participant)
                %install-auth-manager))

;; Defined in access-control.lisp (loaded after this file); forward-declared so create-participant
;; can install the DDS-Security §8.4 AccessControl manager when governance + permissions are configured.
(declaim (ftype (function (domain-participant dds.security:access-handle) domain-participant)
                %install-access-control))
(declaim (ftype (function (domain-participant (simple-array (unsigned-byte 8) (16)) t
                          &optional (or null (unsigned-byte 32)))
                         (eql t))
                %cm-user-token-at-match))

;; WP-FLATDATA-ZC-LOAN (R6, ADR 0017): forward-declared so create-datareader / delete-participant (defined
;; above their bodies in this file) reach the loan helpers without a compile-time undefined-function warning.
(declaim (ftype (function (t) (or null (integer 0))) %flatdata-size))
(declaim (ftype (function (domain-participant) list) %participant-readers))
(declaim (ftype (function (data-reader) t) return-all-loans))
;; ADR-0034: crypto-manager.lisp (loaded after this file) — the delete-participant KeyMaterial-secret-wipe entry.
(declaim (ftype (function (t) (eql t)) %participant-crypto-teardown))

;; conditions.lisp (loaded after this file): forward-declared so %notify-status /
;; %trigger-status-condition (S0.T3/T4) reach the WaitSet wake helpers without a warning.
(declaim (ftype (function (t) t) %notify-condition))

;;; ---- WP-DCPS-API-COMPLETION S0: per-entity status-changes bitmask + introspection ----

(defun* %entity-status-lock (entity)
    (function (entity) t)
  "The lock guarding ENTITY's communication-status structs + its status-changes bitmask.
   DataReader/DataWriter/Topic each own one; other entities have none (no communication
   status fires on them), returning NIL."
  (typecase entity
    (data-reader (dr-status-lock entity))
    (data-writer (dw-status-lock entity))
    (topic (topic-status-lock entity))
    (t nil)))

(defun* %set-status-changed (entity bit)
    (function (entity (unsigned-byte 32)) t)
  "Set BIT in ENTITY's status-changes bitmask (DDS 1.4 StatusMask, dds_rtf2_dcps.idl §684).
   CALLER HOLDS the entity's status lock (%entity-status-lock)."
  (setf (%entity-status-changes entity) (logior (%entity-status-changes entity) bit))
  t)

(defun* %clear-status-changed (entity bit)
    (function (entity (unsigned-byte 32)) t)
  "Clear BIT in ENTITY's status-changes bitmask (the read-communication-status reset, DDS
   1.4 §2.2.2.1.9). CALLER HOLDS the entity's status lock (%entity-status-lock)."
  (setf (%entity-status-changes entity) (logandc2 (%entity-status-changes entity) bit))
  t)

(defun* get-status-changes (entity)
    (function (entity) (unsigned-byte 32))
  "DDS Entity::get_status_changes (dds_rtf2_dcps.idl §684): the StatusMask of communication
   statuses that have changed on ENTITY since the app last read them. A status bit is set by
   %notify-status when the status fires and cleared when the app reads that status via its
   get_<status>_status getter (§2.2.2.1.9) — for DATA_AVAILABLE/DATA_ON_READERS the reset is
   the read/take path. Read under the entity's status lock when it has one."
  (let ((lk (%entity-status-lock entity)))
    (if lk (dds.pal:with-lock (lk) (%entity-status-changes entity))
        (%entity-status-changes entity))))

(defun* %trigger-status-condition (entity)
    (function (entity) (eql t))
  "Wake the WaitSets that must re-evaluate ENTITY's conditions after a status change (DDS 1.4
   §2.2.4.1). A DataReader wakes its read/query/status conditions via the existing reader-
   condition path (which includes its entity-owned StatusCondition, registered on the reader).
   A DataWriter/Topic wakes its entity-owned StatusCondition, if one has been created (S0.T4).
   This is the single StatusCondition-trigger seam every status flows through; S3 hangs
   listener-hierarchy propagation off %notify-status, not here."
  (if (typep entity 'data-reader)
      (%notify-reader-conditions entity)
      (let ((sc (%entity-owned-status-condition entity)))
        (when sc (%notify-condition sc))))
  t)

(defun* %notify-status (entity status-bit apply-fn)
    (function (entity (unsigned-byte 32) function) (eql t))
  "The single communication-status notification chokepoint (DDS 1.4 §2.2.4.1). Under ENTITY's
   status lock it runs APPLY-FN — the status-specific update, which mutates the status struct
   and returns (values CHANGED-P FIRE), where FIRE is a zero-arg thunk closing over a snapshot
   to invoke the (already mask-gated) listener callback, or NIL when no listener is masked.
   When CHANGED-P, %notify-status sets STATUS-BIT in the status-changes bitmask (so
   get_status_changes reflects it) under the same lock; then, OUTSIDE the lock, it fires the
   listener (behavior-preserving: the exact prior on_<status> callback under the exact prior
   mask gate) and triggers ENTITY's StatusCondition / reader WaitSets. Bit-set + condition
   trigger are additive; the listener call is unchanged. S3 (listener-hierarchy propagation)
   and S4 (deadline / SAMPLE_LOST firing) reuse THIS chokepoint — there is no parallel path."
  (let ((changed nil) (fire nil) (lk (%entity-status-lock entity)))
    (dds.pal:with-lock (lk)
      (multiple-value-setq (changed fire) (funcall apply-fn))
      (when changed (%set-status-changed entity status-bit)))
    (when fire (funcall fire))
    (when changed (%trigger-status-condition entity)))
  t)

(defun* %field-resolver (ts)
    (function (t) function)
  "A content-filter FIELDNAME resolver over a type-support's field-accessors (ADR 0008):
   maps a field name (case-insensitively) to its unary accessor, or NIL."
  (let ((fa (dds.types:type-support-field-accessors ts)))
    (lambda (name) (cdr (assoc name fa :test #'string-equal)))))

;; A TopicDescription's content-filter predicate: NIL for a plain Topic; the compiled
;; predicate for a ContentFilteredTopic (the method is added in filter.lisp).
(defgeneric td-filter-predicate (topic-description)
  (:method ((td t)) nil))

;;; ---- SampleInfo + cached samples (FR-DCPS-4) ----

(defstruct* (sample-info (:constructor make-sample-info))
  "DDS 1.4 SampleInfo (dds_rtf2_dcps.idl §SampleInfo). v1 populates the three states +
   valid-data + instance-handle; source/publication handle, generation counts and the
   ranks default to 0/nil and are filled in by later increments. State kinds are kept
   as keywords (READ/NOT_READ, NEW/NOT_NEW, ALIVE/NOT_ALIVE_DISPOSED/_NO_WRITERS).
   sequence-number is a vendor extension (the RTPS writer SN)."
  (sample-state :not-read :type (member :read :not-read))
  (view-state :new :type (member :new :not-new))
  (instance-state :alive :type (member :alive :not-alive-disposed :not-alive-no-writers))
  (source-timestamp nil :type (or null integer))
  (instance-handle nil :type (or null (array (unsigned-byte 8) (*))))
  (publication-handle nil :type (or null (array (unsigned-byte 8) (*))))
  (disposed-generation-count 0 :type integer)
  (no-writers-generation-count 0 :type integer)
  (sample-rank 0 :type integer)
  (generation-rank 0 :type integer)
  (absolute-generation-rank 0 :type integer)
  (valid-data t :type boolean)
  (sequence-number 0 :type integer))

(defstruct* (cached-sample (:constructor make-cached-sample))
  "A read/take result element: the deserialized DATA + its SAMPLE-INFO. LOAN, when non-NIL, is the loan object
   whose lifetime backs this entry, for a type-dispatched return: a dds.disc:secured-loan-handle for a secured
   zero-decode-buffer-alloc loan (WP-DCPS-SECURED-TAKE-LOAN, ADR 0038 (i)) — DATA is then the INDEPENDENT
   deserialized struct and LOAN pins the pooled decode buffer until return-loan releases it. NIL for a copy-backed
   sample and for a FlatData ZC loan (whose view is DATA itself, dispatched by flatdata-view-p, ADR 0017)."
  (data nil :type t)
  (loan nil :type t)
  (info nil :type (or null sample-info)))

(defstruct* (instance-rec (:constructor make-instance-rec))
  "The reader's per-instance lifecycle record (DDS 1.4 §2.2.2.5.1.3/.5): STATE is the
   instance_state (ALIVE / NOT_ALIVE_DISPOSED / NOT_ALIVE_NO_WRITERS); DISPOSED-GEN-COUNT
   and NO-WRITERS-GEN-COUNT are the per-instance generation counters (incremented on the
   NOT_ALIVE_DISPOSED->ALIVE and NOT_ALIVE_NO_WRITERS->ALIVE transitions respectively);
   WRITERS is the set of matched remote writer EntityIds (RTPS 2.5 §9.3.1.2) currently
   keeping the instance alive — emptying it transitions the instance NOT_ALIVE_NO_WRITERS.
   OWNER-GUID/OWNER-STRENGTH track the EXCLUSIVE-ownership owner of the instance (DDS 1.4
   §2.2.3.9.2): the 16-octet GUID + strength of the highest-strength alive writer whose
   samples are currently delivered. OWNER-GUID NIL = no current owner (lazily reclaimed by
   the next sample). Unused on SHARED readers (arbitration off).
   NOT-ALIVE-SINCE is the internal-time stamp (%lease-now) of the most recent ALIVE->NOT_ALIVE
   transition, or NIL while ALIVE — the READER_DATA_LIFECYCLE autopurge clock (DDS 1.4 §2.2.3.22)."
  (state :alive :type (member :alive :not-alive-disposed :not-alive-no-writers))
  (disposed-gen-count 0 :type integer)
  (no-writers-gen-count 0 :type integer)
  (writers '() :type list)
  (owner-guid nil :type (or null (simple-array (unsigned-byte 8) (16))))
  (owner-strength 0 :type integer)
  (not-alive-since nil :type (or null (integer 0))))

;;; ---- type-support serialization helpers (PLAIN_CDR(2)_LE SerializedPayload) ----

(defun* %rep->codec (rep)
    (function (symbol) (values dds.cdr:cdr-mode (member :plain-cdr2-le :plain-cdr-le)))
  "Map a writer's OFFERED data-representation keyword (DDS-XTypes 1.3 §7.6.3.1.1) to the
   (values CODEC-MODE ENCAP-REP) the TX SerializedPayload uses: :xcdr2 -> (:xcdr2 :plain-cdr2-le),
   :xcdr1 -> (:xcdr1 :plain-cdr-le). CODEC-MODE drives the generated serializer's alignment cap
   (FR-CDR-2); ENCAP-REP names the +representation-ids+ encapsulation id (§7.6.3.1.2 Table 60) the
   4-octet header carries (XCDR2-LE 0x0007 / XCDR1-LE 0x0001). The XML / BE representations are out
   of scope on TX (we send LE); a NIL (absent) rep maps to the :xcdr2 default (back-compat), and any
   other unmapped rep (e.g. :xml) SIGNALS via the ecase — a FINAL PLAIN-encapsulated writer sends only
   XCDR1/XCDR2-LE."
  (ecase rep
    ((:xcdr2 nil) (values :xcdr2 :plain-cdr2-le))
    (:xcdr1       (values :xcdr1 :plain-cdr-le))))

(defun* %writer-tx-rep (dw)
    (function (data-writer) symbol)
  "DW's OFFERED data-representation = (first (qos-data-representation writer-qos)) — the single rep TX
   serializes/sends in (DDS-XTypes 1.3 §7.6.3.1.1; WP-DATA-REPRESENTATION step 2). Defaults to :xcdr2
   (the make-writer-qos default, byte-identical existing wire) when the QoS is absent / not a dds.qos:qos
   / has an empty data-representation list."
  (let ((qos (entity-qos dw)))
    (or (and (typep qos 'dds.qos:qos) (first (dds.qos:qos-data-representation qos))) :xcdr2)))

(defun* %serialize-sample (ts sample &optional (rep :xcdr2))
    (function (t t &optional symbol) (simple-array (unsigned-byte 8) (*)))
  "Serialize SAMPLE via type-support TS as a SerializedPayload in the writer's OFFERED representation
   REP (DDS-XTypes 1.3 §7.6.3.1.1; WP-DATA-REPRESENTATION step 2): :xcdr2 -> PLAIN_CDR2_LE (0x0007,
   the default — byte-identical existing wire), :xcdr1 -> PLAIN_CDR_LE (0x0001). The encapsulation id
   and the codec alignment mode are both rep-derived (%rep->codec); REP applies ONLY to the user-data
   payload, NEVER to the keyhash (always XCDR2-BE, RTPS 2.5 §9.6.4.8) or discovery. For a FlatData type
   the :xcdr2 path stays the 0-copy identity serialize; an :xcdr1 FlatData write TX-transcodes via the
   flatdata-builder (decode XCDR2 -> struct -> re-encode XCDR1) — R6, off the measured hot path."
  (multiple-value-bind (mode encap) (%rep->codec rep)
    (let ((fd-tx (dds.types:type-support-flatdata-builder ts)))
      ;; FlatData + non-XCDR2 offered rep: the identity serializer copies XCDR2 bytes, so transcode (R6).
      (when (and fd-tx (not (eq mode :xcdr2)))
        (return-from %serialize-sample (funcall fd-tx ts sample mode encap))))
    (let* ((ssz-fn (dds.types:type-support-serialized-size ts))
           (body-size (if ssz-fn (funcall ssz-fn sample mode) 2044))
           (cap (+ 4 body-size 8))   ; 4 encap + body + 8 slack for alignment
           (buf (dds.core.buffer:make-octet-buffer cap))
           (wc (dds.core.buffer:cursor buf :endianness :little)))
      (dds.cdr:make-encapsulation-header wc encap)
      (funcall (dds.types:type-support-serialize ts) sample wc mode)
      (dds.cdr:finalize-encapsulation-options wc encap)
      (let* ((len (dds.core.buffer:cursor-position wc))
             (out (make-array len :element-type '(unsigned-byte 8))))
        (replace out (dds.core.buffer:octet-buffer-vec buf) :end1 len)
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))
        out))))

(defun* %encap->codec (encap)
    (function (symbol) (values dds.cdr:cdr-mode (member :little :big)))
  "Map a parsed SerializedPayload encapsulation id (a +representation-ids+ key, DDS-XTypes 1.3
   §7.6.3.1.2 Table 60) to the (values CODEC-MODE ENDIANNESS) the struct codec decodes the body in:
   PLAIN_CDR_LE -> (:xcdr1 :little), PLAIN_CDR_BE -> (:xcdr1 :big), PLAIN_CDR2_LE -> (:xcdr2 :little),
   PLAIN_CDR2_BE -> (:xcdr2 :big). The inverse of %rep->codec for RX: a reader accepting (:xcdr2 :xcdr1)
   reads whichever representation a peer wrote (WP-DATA-REPRESENTATION; the 8-vs-4 alignment + endianness
   come from the wire, not a hardcoded :xcdr2). A NIL (absent) encap maps to the XCDR2-LE default
   (back-compat); a known-but-unmapped encap (PL_CDR / DELIMITED / XML) is unexpected for a
   PLAIN-encapsulated FINAL type and SIGNALS via the ecase — the correct conservative reject (such a body
   is not decodable here; truly-unknown ids are already rejected upstream by parse-encapsulation-header)."
  (ecase encap
    (:plain-cdr-le   (values :xcdr1 :little))
    (:plain-cdr-be   (values :xcdr1 :big))
    ((:plain-cdr2-le nil) (values :xcdr2 :little))
    (:plain-cdr2-be  (values :xcdr2 :big))))

(defun* %deserialize-payload (ts ob)
    (function (t dds.core.buffer:octet-buffer) t)
  "Deserialize a SerializedPayload (encap header + body) already RESIDENT in octet-buffer OB into a sample via TS,
   WITHOUT allocating or freeing OB — the buffer is caller-owned (a scratch buffer for %deserialize-sample, or the
   pooled secured-decode buffer read IN PLACE for the WP-DCPS-SECURED-TAKE-LOAN loan). The parsed encapsulation
   keyword selects the codec mode (XCDR1/XCDR2, the 8-vs-4 alignment) AND the cursor endianness (LE/BE) via
   %encap->codec, so a reader accepting (:xcdr2 :xcdr1) reads either rep a peer sent (DDS-XTypes 1.3 §7.6.3.1.2;
   WP-DATA-REPRESENTATION). A FlatData type's :deserialize self-dispatches on the rep id and ignores the passed
   mode (its own RX-transcode). Bounds-checked against OB's capacity (NFR-SEC-POSTURE): the caller sizes OB to the
   exact payload extent so a wire-supplied length can never over-read past it."
  (let ((rc (dds.core.buffer:cursor ob :endianness :little)))
    (let ((encap (dds.cdr:parse-encapsulation-header rc)))
      (multiple-value-bind (mode endian) (%encap->codec encap)
        (dds.core.buffer:cursor-set-endianness rc endian)
        (funcall (dds.types:type-support-deserialize ts) rc mode)))))

(defun* %deserialize-sample (ts bytes)
    (function (t (simple-array (unsigned-byte 8) (*))) t)
  "Deserialize a SerializedPayload (encap header + body) into a sample via TS. Copies BYTES into a fresh scratch
   octet-buffer (sized exactly), decodes it in place via %deserialize-payload, then frees the scratch — the
   allocating deserialize path (the copy-backed and non-secured samples). See %deserialize-payload for the
   representation-selection contract."
  (let ((ob (dds.core.buffer:make-octet-buffer (length bytes))))
    (replace (dds.core.buffer:octet-buffer-vec ob) bytes)
    (prog1 (%deserialize-payload ts ob)
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec ob)))))

;;; ---- DomainParticipantFactory + participant lifecycle ----

(defvar *participant-counter* 0
  "Process-local counter for GUID-prefix uniqueness (single creation thread assumed).")

(defun* %make-guid-prefix ()
    (function () (simple-array (unsigned-byte 8) (12)))
  "A unique-enough 12-octet GUID prefix per participant: vendor marker + a process
   counter + the wall clock. Without this every participant defaults to the all-zero
   prefix and the self-check makes them ignore each other's SPDP. Demo-grade."
  (let ((p (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0))
        (clk (get-universal-time))
        (n (incf *participant-counter*)))
    (setf (aref p 0) #x47 (aref p 1) #x42 (aref p 2) (logand n #xff))
    (loop for i from 3 below 12 do (setf (aref p i) (logand (ash clk (* -8 (- i 3))) #xff)))
    p))

(defun* %participant-guid-prefix (identity)
    (function (dds.security:identity-handle) (simple-array (unsigned-byte 8) (12)))
  "The 12-octet GUID prefix for a SECURITY-ENABLED participant: the DDS-Security 1.1 §9.3.2.1
   authenticated prefix stored in IDENTITY (validate-local-identity derived octets 0-5 from the
   identity certificate's subject-name SHA-256; octets 6-11 carry the candidate GUID's uniqueness).
   A conformant peer re-derives + validates these 48 bits before replying to our HandshakeRequest, so
   a security-enabled participant MUST announce this prefix (not the demo %make-guid-prefix). A fresh
   typed 12-octet copy for make-disc-node."
  (let ((g (dds.security:identity-handle-guid identity))
        (p (make-array 12 :element-type '(unsigned-byte 8))))
    (dotimes (i 12 p) (setf (aref p i) (aref g i)))))

(defun* %validate-access-config (identity permissions-ca governance permissions)
    (function ((or dds.security:identity-handle null)
               (or (simple-array (unsigned-byte 8) (*)) null)
               (or (simple-array (unsigned-byte 8) (*)) null)
               (or (simple-array (unsigned-byte 8) (*)) null))
              (or dds.security:access-handle null))
  "DDS-Security 1.1 §8.4: validate a participant's AccessControl configuration, returning the
   ACCESS-HANDLE to install, or NIL when AccessControl is OFF (any of IDENTITY / PERMISSIONS-CA /
   GOVERNANCE / PERMISSIONS absent — AC requires an authenticated identity plus both signed §9.4
   documents). When all are supplied: CMS-verify the signed Governance + Permissions against the
   Permissions CA and bind the LOCAL grant by the identity cert's subject name
   (validate-local-permissions), then gate check_create_participant (§8.4.2.3). Fail-closed: an
   invalid/denied config SIGNALS a clear error (the participant does not join), freeing the handle on a
   check_create_participant denial. Validated up-front (before the engine opens) so the error path
   leaks no node. The *_WITH_ORIGIN_AUTHENTICATION discovery tier (receiver-specific MACs for the builtin
   secure-SEDP endpoints, §9.5.3.3.4.3) is now WIRED (T-ORIGINAUTH), so it is accepted here — its origin-auth
   flag is carried to the disc-node by %install-access-control (no longer refused)."
  (when (and identity permissions-ca governance permissions)
    (let ((subject (dds.dare:x509-subject-name (dds.security:identity-handle-cert identity))))
      (unless subject
        (error "create-participant: could not extract subject name from the identity certificate"))
      (let ((ah (dds.security:validate-local-permissions permissions-ca governance permissions subject)))
        (unless ah
          (error "create-participant: AccessControl validate-local-permissions failed (bad Permissions CA / Governance / Permissions signature, or subject ~s not granted)"
                 subject))
        (unless (dds.security:check-create-participant ah)
          (dds.security:free-access-handle ah)
          (error "create-participant: AccessControl check_create_participant denied subject ~s" subject))
        ;; T-ORIGINAUTH: the *_WITH_ORIGIN_AUTHENTICATION secure-discovery tier (receiver-specific MACs,
        ;; DDS-Security 1.1 §9.5.3.3.4.3) is now WIRED for the builtin secure-SEDP endpoints (origin-auth
        ;; EntityCrypto registration + receiver-key exchange + per-receiver MACs), so it is no longer refused
        ;; here — %install-access-control reads protection-kind-base's origin-auth flag onto the disc-node.
        ah))))

(defvar *default-participant-qos* nil
  "The DDS DomainParticipantFactory's default DomainParticipant QoS (DDS 1.4 §2.2.2.2.2
   get/set_default_participant_qos). Provisional module-level home until WP-DCPS-API-COMPLETION
   S2 introduces the DomainParticipantFactory singleton that formally owns it; NIL selects the
   built-in policy defaults. Read/written by get/set_default_participant_qos and applied by
   create_participant when no explicit :qos is supplied.")

;;; ---- WP-DCPS-API-COMPLETION S2.T1: the DomainParticipantFactory singleton (DDS 1.4 §2.2.2.2.2) ----

(defclass domain-participant-factory ()
  ((participants :initform '() :accessor dpf-participants)
   (autoenable :initform t :accessor dpf-autoenable)
   (lock :initform (dds.pal:make-lock "dpf") :accessor dpf-lock))
  (:documentation "DDS 1.4 DomainParticipantFactory (§2.2.2.2.2): the process-wide singleton
   entry point that creates, looks up and deletes DomainParticipants and holds the factory-scope
   defaults. PARTICIPANTS is the live registry (create_participant registers, delete_participant
   unregisters), read by lookup_participant. AUTOENABLE is the factory's ENTITY_FACTORY
   autoenable_created_entities policy (§2.2.3.23) — TRUE (the spec default) auto-enables each
   participant at create_participant, FALSE creates it disabled until enable() is called. The
   DomainParticipantFactory is NOT itself a DDS Entity (§2.2.2.2.2), so it carries no QoS/status/
   listener beyond ENTITY_FACTORY. The default participant QoS lives in *default-participant-qos*
   (S1), which this factory logically owns. LOCK guards the registry against concurrent creates."))

(defvar *participant-factory* nil
  "The lazily-created DomainParticipantFactory process singleton (DDS 1.4 §2.2.2.2.2
   get_instance). NIL until the first get-participant-factory / get-instance call.")

(defvar *participant-factory-init-lock* (dds.pal:make-lock "dpf-singleton")
  "The lock guarding the one-time lazy construction of *participant-factory* so two threads
   racing the first get_instance still observe a SINGLE factory (DDS 1.4 §2.2.2.2.2).")

(defun* get-participant-factory ()
    (function () domain-participant-factory)
  "DomainParticipantFactory::get_instance (DDS 1.4 §2.2.2.2.2) — return the process-wide
   DomainParticipantFactory singleton, constructing it on first use. Every call returns the SAME
   object (double-checked under *participant-factory-init-lock*)."
  (or *participant-factory*
      (dds.pal:with-lock (*participant-factory-init-lock*)
        (or *participant-factory*
            (setf *participant-factory* (make-instance 'domain-participant-factory))))))

(defun* get-instance ()
    (function () domain-participant-factory)
  "DomainParticipantFactory::get_instance (DDS 1.4 §2.2.2.2.2) — the spec-named alias for
   get-participant-factory; returns the one process-wide factory singleton."
  (get-participant-factory))

(defun* participant-factory-autoenable-p (factory)
    (function (domain-participant-factory) boolean)
  "The factory's ENTITY_FACTORY autoenable_created_entities policy (DDS 1.4 §2.2.3.23): T (the
   spec default) means create_participant auto-enables the new participant; NIL creates it
   disabled until enable() is called."
  (and (dpf-autoenable factory) t))

(defun* set-participant-factory-autoenable (factory enable)
    (function (domain-participant-factory t) (member :ok))
  "Set the factory's ENTITY_FACTORY autoenable_created_entities policy (DDS 1.4 §2.2.3.23;
   DomainParticipantFactory::set_qos with only ENTITY_FACTORY) — ENABLE non-NIL auto-enables
   participants at create_participant, NIL creates them disabled. ENTITY_FACTORY is mutable, so
   this always succeeds (:ok); it governs only participants created AFTER the call."
  (setf (dpf-autoenable factory) (and enable t))
  +retcode-ok+)

(defun* %factory-register-participant (factory p)
    (function (domain-participant-factory domain-participant) domain-participant)
  "Register participant P in FACTORY's live registry (DDS 1.4 §2.2.2.2.2 create_participant),
   lock-guarded; returns P."
  (dds.pal:with-lock ((dpf-lock factory))
    (push p (dpf-participants factory)))
  p)

(defun* %factory-unregister-participant (factory p)
    (function (domain-participant-factory domain-participant) (eql t))
  "Remove participant P from FACTORY's registry (DDS 1.4 §2.2.2.2.2 delete_participant),
   lock-guarded + idempotent."
  (dds.pal:with-lock ((dpf-lock factory))
    (setf (dpf-participants factory) (remove p (dpf-participants factory))))
  t)

(defun* lookup-participant (factory domain)
    (function (domain-participant-factory (integer 0)) (or null domain-participant))
  "DomainParticipantFactory::lookup_participant (DDS 1.4 §2.2.2.2.2) — return one of FACTORY's
   registered participants bound to DOMAIN, or NIL if none. Lock-guarded snapshot of the registry."
  (dds.pal:with-lock ((dpf-lock factory))
    (find domain (dpf-participants factory) :key #'dp-domain :test #'=)))

(defun* create-participant (&key (domain 0) (qos nil) (advertise-address "127.0.0.1") (peers nil)
                                 (port 0)
                                 (identity nil) (permissions-ca nil) (governance nil) (permissions nil))
    (function (&key (:domain (integer 0)) (:qos t) (:advertise-address string) (:peers list)
                    (:port (unsigned-byte 16))
                    (:identity t)
                    (:permissions-ca (or (simple-array (unsigned-byte 8) (*)) null))
                    (:governance (or (simple-array (unsigned-byte 8) (*)) null))
                    (:permissions (or (simple-array (unsigned-byte 8) (*)) null)))
              domain-participant)
  "DomainParticipantFactory::create_participant — open the RTPS engine (a multicast
   disc-node) for DOMAIN, install the match/incompatible-QoS hooks that surface DDS
   statuses to the application, start the receiver, and return an enabled participant.
   PEERS is an optional ((host . port) ...) list of unicast SPDP announce targets
   (FR-DISC-4) layered on top of multicast — e.g. ((\"127.0.0.1\" . 7410)) reaches a
   same-host peer over loopback when the macOS application firewall silently drops
   LAN-sourced UDP for an unapproved peer binary.
   PORT (default 0 = ephemeral) binds the metatraffic unicast socket to a FIXED port and
   advertises it, so a foreign peer can list us in its initialPeers and unicast SPDP back
   over loopback (the cross-vendor secure-discovery interop reachability pattern, FR-DISC-4).
   IDENTITY (DDS-Security 1.1 §8.7): an optional dds.security:identity-handle from
   validate-local-identity. When supplied the participant is SECURITY-ENABLED — the node
   announces the DDS-Security 1.1 §9.3.2.1 authenticated GUID (derived from the identity
   certificate's subject-name, not the demo prefix), advertises its IdentityToken + PSM bits in
   SPDP, and the auth manager is installed, so the
   participant authenticates every discovered security-enabled peer over the §7.4.3 PSM wire,
   exchanges §9.5.2 key material, and STRICTLY refuses unauthenticated peers (the conformant
   default). NIL (default) = security OFF, byte-identical plain participant.
   PERMISSIONS-CA / GOVERNANCE / PERMISSIONS (DDS-Security 1.1 §8.4 AccessControl): optional octet
   vectors — the Permissions CA certificate (PEM) plus the S/MIME-signed Governance and Permissions
   documents (§9.4). When ALL THREE are supplied AND an IDENTITY is configured, the participant is
   ACCESS-CONTROLLED: validate-local-permissions CMS-verifies both documents against the Permissions CA,
   binds the LOCAL grant by the identity cert's subject name, gates check_create_participant, installs the
   permissions-gate (composed after the auth-gate), and the participant matches a remote endpoint only
   when the remote's validated handshake-cert subject is granted the topic. A failed validation or a denied
   check_create_participant SIGNALS an error (fail-closed). NIL (default) = access-control OFF,
   byte-identical."
  ;; DDS-Security §8.4: validate the AccessControl config BEFORE opening the engine so an invalid or
  ;; denied config fails closed with no node leak; the resulting handle is installed once the node exists.
  (let ((access-handle (%validate-access-config identity permissions-ca governance permissions))
        (installed nil))   ; T once the participant is fully constructed and will be returned
    (unwind-protect
        (let* ((node (dds.disc:make-disc-node :domain domain :multicast t
                                              :advertise-address advertise-address
                                              :peers peers :port port
                                              ;; §9.3.2.1: a security-enabled participant announces the
                                              ;; authenticated GUID derived from its identity cert (so a
                                              ;; conformant peer accepts our handshake); plain = demo prefix.
                                              :guid-prefix (if identity
                                                               (%participant-guid-prefix identity)
                                                               (%make-guid-prefix))
                                              :identity-token-octets
                                              (when identity (dds.security:identity-token identity))))
               (p (make-instance 'domain-participant :domain domain :node node
                                 :enabled (%child-created-enabled-p (get-participant-factory))   ; S2.T3: factory ENTITY_FACTORY autoenable
                                 :qos (or qos (when (typep *default-participant-qos* 'dds.qos:qos)
                                                (dds.qos:copy-qos *default-participant-qos*))))))
          ;; Install hooks BEFORE the receiver thread starts so no early SEDP match is lost.
          (setf (dds.disc:disc-node-on-match node)
                (lambda (kind remote local-eid) (%on-disc-match p kind remote local-eid)))
          (setf (dds.disc:disc-node-on-unmatch node)
                (lambda (direction remote local-eid) (%on-disc-unmatch p direction remote local-eid)))
          (setf (dds.disc:disc-node-on-liveliness-changed node)
                (lambda (guid alive-p) (%on-disc-liveliness-changed p guid alive-p)))
          (setf (dds.disc:disc-node-on-lifecycle-event node)
                (lambda (wid sn kind kh sf) (%on-disc-lifecycle p wid sn kind kh sf)))
          (setf (dds.disc:disc-node-on-incompatible-qos node)
                (lambda (kind remote bad local-eid) (%on-disc-incompatible p kind remote bad local-eid)))
          (setf (dds.disc:disc-node-on-sample node)
                (lambda () (%on-participant-sample p)))
          (setf (dds.disc:disc-node-on-inconsistent-topic node)
                (lambda (topic-name) (%on-disc-inconsistent-topic p topic-name)))
          (%install-type-gate p)   ; FR-TYPE-4 assignability gate (type-gate.lisp)
          (when identity           ; DDS-Security §8.7 auth manager — only for a security-enabled participant
            ;; pass the configured signed Permissions octets so the handshake emits c.perm (§9.3.2.1, T6)
            (%install-auth-manager p identity permissions))
          (when access-handle      ; DDS-Security §8.4 AccessControl manager — validated above, install the gate
            (%install-access-control p access-handle))
          (dds.disc:start-node node)
          (setf installed t)   ; construction complete; p owns the access-handle via dp-access-state
          (%factory-register-participant (get-participant-factory) p)   ; S2.T1: the free-fn is the factory shim (DDS 1.4 §2.2.2.2.2)
          p)
      ;; Free the access-handle on a non-local exit ONLY if not yet installed (install transfers ownership).
      (when (and access-handle (not installed))
        (dds.security:free-access-handle access-handle)))))

(defun* delete-participant (p)
    (function (domain-participant) (eql t))
  "Delete the participant and its contained entities; stop the engine. WP-FLATDATA-ZC-LOAN (R6, ADR 0017):
   return EVERY outstanding loan on each contained DataReader FIRST — BEFORE stop-node detaches the reader-side
   ZC pool mapping — so no held refcount pins the writer's pool (no leak) and the final %zc-release runs while
   the views' SAP is still mapped (no use-after-free at teardown). A no-op for readers with no loans (the common
   case: ZC off / non-FlatData)."
  (dolist (dr (%participant-readers p)) (return-all-loans dr))
  (%factory-unregister-participant (get-participant-factory) p)   ; S2.T1: the free-fn is the factory delete_participant shim (DDS 1.4 §2.2.2.2.2)
  (dds.disc:stop-node (dp-node p))
  ;; ADR-0034 secret hygiene: zeroize + free every §9.5.2 KeyMaterial secret this participant holds in its
  ;; crypto-manager. AFTER stop-node (the receiver thread is joined -> the data path is quiesced -> the secret
  ;; buffers are safe to free). Null-safe (security OFF -> no-op) + idempotent.
  (%participant-crypto-teardown (dp-auth-state p))
  ;; DDS-Security §8.4: release the participant-owned AccessControl handle (its Permissions-CA X509_STORE*);
  ;; create-participant created it internally, so the participant owns it. Null-safe + idempotent.
  (let ((ah (dp-access-state p)))
    (when ah
      (dds.security:free-access-handle ah)
      (setf (dp-access-state p) nil)))
  (setf (entity-enabled-p p) nil)
  t)

(defun* discovered-count (p)
    (function (domain-participant) (integer 0))
  "Number of remote participants P has discovered."
  (dds.disc:disc-node-discovered-count (dp-node p)))

(defun* matched-count (p)
    (function (domain-participant) (integer 0))
  "Number of remote endpoints matched against P's local endpoints."
  (dds.disc:disc-node-matched-count (dp-node p)))

(defun* spin (p)
    (function (domain-participant) (eql t))
  "Drive one discovery announcement cycle (SPDP + SEDP) for P. Discovery is
   caller-driven in v1 — an automatic background announcer with isolated send buffers
   is a follow-up (the engine's announce buffers are not yet thread-isolated)."
  (dds.disc:announce-participant (dp-node p))
  (dds.disc:announce-endpoints (dp-node p))
  (%writer-liveliness-sweep p)   ; writer-side LIVELINESS_LOST on the DCPS cadence (DDS 1.4 §2.2.3.11)
  (dolist (dr (%participant-readers p)) (%autopurge-sweep dr))   ; READER_DATA_LIFECYCLE autopurge (DDS 1.4 §2.2.3.22)
  t)

;;; ---- Publisher / Subscriber / Topic ----

(defun* %parent-default-qos (stored)
    (function (t) (or null dds.qos:qos))
  "An independent COPY of a STORED parent default QoS if one is set, else NIL — for the create_*
   paths (Publisher/Subscriber/Topic) whose entities carry no role-default QoS (NIL when unset)."
  (when (typep stored 'dds.qos:qos) (dds.qos:copy-qos stored)))

(defun* %default-qos-for-create (stored fallback)
    (function (t dds.qos:qos) dds.qos:qos)
  "The effective QoS a create_* applies to a new child when the caller gave no explicit QoS: an
   independent COPY of the parent's STORED default if set, else FALLBACK (the role default). The
   copy keeps each child's QoS independent of the shared default."
  (if (typep stored 'dds.qos:qos) (dds.qos:copy-qos stored) fallback))

(defun* create-publisher (p)
    (function (domain-participant) publisher)
  "DomainParticipant::create_publisher — create an enabled Publisher in P, adopting the
   participant's default Publisher QoS (DDS 1.4 §2.2.2.2.2) when one has been set."
  (let ((pub (make-instance 'publisher :participant p :enabled (%child-created-enabled-p p)
                                       :qos (%parent-default-qos (dp-default-publisher-qos p)))))
    (push pub (dp-children p))
    pub))

(defun* create-subscriber (p)
    (function (domain-participant) subscriber)
  "DomainParticipant::create_subscriber — create an enabled Subscriber in P, adopting the
   participant's default Subscriber QoS (DDS 1.4 §2.2.2.2.2) when one has been set."
  (let ((sub (make-instance 'subscriber :participant p :enabled (%child-created-enabled-p p)
                                        :qos (%parent-default-qos (dp-default-subscriber-qos p)))))
    (push sub (dp-children p))
    sub))

(defun* create-topic (p name type-name type-support)
    (function (domain-participant string string t) topic)
  "DomainParticipant::create_topic, adopting the participant's default Topic QoS (DDS 1.4
   §2.2.2.2.2) when one has been set. TYPE-SUPPORT is a registered dds.types type-support (the
   generated codec bundle) used by write/take."
  (let ((tp (make-instance 'topic :name name :type-name type-name
                                  :type-support type-support :participant p
                                  :enabled (%child-created-enabled-p p)
                                  :qos (%parent-default-qos (dp-default-topic-qos p)))))
    (push tp (dp-children p))
    tp))

;;; ---- WP-DCPS-API-COMPLETION S2.T2: the parent->children containment registry (DDS 1.4 §2.2.2) ----

(defun* participant-publishers (p)
    (function (domain-participant) list)
  "The Publishers contained in participant P (DDS 1.4 §2.2.2.2.1) — the Publisher children of P's
   containment tree, filtered from the mixed child list. A fresh list; mutating it does not affect P."
  (remove-if-not (lambda (c) (typep c 'publisher)) (dp-children p)))

(defun* participant-subscribers (p)
    (function (domain-participant) list)
  "The Subscribers contained in participant P (DDS 1.4 §2.2.2.2.1). A fresh list."
  (remove-if-not (lambda (c) (typep c 'subscriber)) (dp-children p)))

(defun* participant-topics (p)
    (function (domain-participant) list)
  "The Topics contained in participant P (DDS 1.4 §2.2.2.2.1). A fresh list."
  (remove-if-not (lambda (c) (typep c 'topic)) (dp-children p)))

(defun* publisher-datawriters (pub)
    (function (publisher) list)
  "The DataWriters contained in Publisher PUB (DDS 1.4 §2.2.2.4.1). A fresh list."
  (copy-list (pub-writers pub)))

(defun* subscriber-datareaders (sub)
    (function (subscriber) list)
  "The DataReaders contained in Subscriber SUB (DDS 1.4 §2.2.2.5.1). A fresh list."
  (copy-list (sub-readers sub)))

;;; ---- DataWriter / DataReader ----

(defun* %topic-type-information (topic)
    (function (t) (or null (simple-array (unsigned-byte 8) (*))))
  "Opaque serialized XTypes TypeInformation for TOPIC's type-support (PID_TYPE_INFORMATION),
   or NIL if unavailable or not yet serializable (e.g. a type with sequence members, whose
   TypeObject serializer is oracle-deferred, or a ContentFilteredTopic)."
  (handler-case
      (let ((ts (topic-type-support topic)))
        (and ts (dds.types:serialize-type-information (dds.types:type-support-typeobject ts))))
    (error () nil)))

(defun* %topic-keyed-p (topic)
    (function (t) boolean)
  "Whether TOPIC's type is keyed (selects WITH_KEY vs NO_KEY endpoint kinds);
   defaults to T (back-compat) when the type-support is absent. TOPIC may be a
   Topic or a ContentFilteredTopic (both answer topic-type-support)."
  (let ((ts (topic-type-support topic)))
    (if ts (dds.types:type-support-keyed-p ts) t)))

(defun* %set-user-metadata-protection (node ah topic-name role)
    (function (dds.disc:disc-node t string (member :writer :reader)) t)
  "DDS-Security 1.1 §9.4.1.2.4 (ADR 0046): set ROLE's (the WRITER's or the READER's) OWN metadata_protection +
   data_protection kind from the access-handle AH's governance for TOPIC-NAME, into the PER-ROLE disc-node fields —
   so a writer and a reader on DIFFERENT topics keep INDEPENDENT kinds (the cross-role false-ACCEPT downgrade fix).
   The shared user-{data,submessage}-protection-kind slots are kept at the MONOTONIC MAX over both roles for the
   participant-scope consumers only. A NIL AH (no AccessControl) or no governance leaves every slot at its default
   (:none submessage / :unset data) -> the user path stays plain, byte-identical. Called when the user writer/reader
   is created (it knows the topic name) AFTER add-local-{writer,reader}; both agree on ROLE's fields (idempotent)."
  (when ah
    (let ((gov (dds.security:access-handle-governance ah)))
      (when gov
        (let ((mk (dds.security:topic-metadata-protection gov topic-name))
              (dk (dds.security:topic-data-protection gov topic-name)))
          (ecase role
            (:writer (setf (dds.disc:disc-node-user-writer-submessage-protection-kind node) mk
                           (dds.disc:disc-node-user-writer-data-protection-kind node) dk))
            (:reader (setf (dds.disc:disc-node-user-reader-submessage-protection-kind node) mk
                           (dds.disc:disc-node-user-reader-data-protection-kind node) dk)))
          ;; §9.4.1.2.4: keep the participant-scope shared slots at the most-protective MAX over both roles (fail-closed)
          (setf (dds.disc:disc-node-user-submessage-protection-kind node)
                (dds.disc::%protection-kind-max (dds.disc:disc-node-user-writer-submessage-protection-kind node)
                                               (dds.disc:disc-node-user-reader-submessage-protection-kind node))
                (dds.disc:disc-node-user-data-protection-kind node)
                (dds.disc::%protection-kind-max (dds.disc:disc-node-user-writer-data-protection-kind node)
                                               (dds.disc:disc-node-user-reader-data-protection-kind node)))))))
  t)

(defun* create-datawriter (pub topic &key (qos nil qos-supplied-p))
    (function (publisher topic &key (:qos t)) data-writer)
  "Publisher::create_datawriter — register a local writer in the engine on the
   topic's name/type with the QoS reliability (v1: the single user writer); the
   endpoint kind (WITH_KEY/NO_KEY) is selected from the topic type's keyed-ness.
   When no explicit :qos is supplied, the Publisher's default DataWriter QoS applies
   (DDS 1.4 §2.2.2.4.1, set_default_datawriter_qos), falling back to the role default.
   DDS-Security §8.4.2.4: when the participant is access-controlled, check_create_datawriter must
   grant publish on the topic (local Permissions + Governance write-AC toggle) or the writer is
   refused (fail-closed SIGNAL). No access-state (default) = unchecked, byte-identical."
  (let ((node (dp-node (pub-participant pub)))
        (ah (dp-access-state (pub-participant pub)))
        (qos (if qos-supplied-p qos
                 (%default-qos-for-create (pub-default-datawriter-qos pub) (dds.qos:make-writer-qos)))))
    (when (and ah (not (dds.security:check-create-datawriter ah (topic-name topic))))
      (error "create-datawriter: AccessControl check_create_datawriter denied publish on topic ~s"
             (topic-name topic)))
    (let ((ep (dds.disc:add-local-writer node :topic (topic-name topic) :type (topic-type-name topic)
                                         :keyed (%topic-keyed-p topic)
                                         :qos qos :type-information (%topic-type-information topic))))
    (%set-user-metadata-protection node ah (topic-name topic) :writer)   ; ADR 0046 §9.4.1.2.4: the WRITER's own protection tiers
    (dds.disc:enable-publisher node :history-kind (dds.qos:qos-history-kind qos)
                                    :history-depth (dds.qos:qos-history-depth qos))
    ;; WP-N-ENDPOINT-S1 (ADR 0048): capture THIS writer's distinct EntityId (add-local-writer set it, enable-publisher
    ;; just registered the engine writer under it) so write-sample routes into this writer's own HistoryCache.
    (let ((dw (make-instance 'data-writer :topic topic :publisher pub :qos qos
                                          :enabled (%child-created-enabled-p pub))))
      (setf (dw-entity-id dw) (dds.disc:disc-node-user-writer-id node))
      (setf (dw-disc-endpoint dw) ep)   ; S2.T4: retain the SEDP endpoint so delete_datawriter can remove it
      (push dw (pub-writers pub))
      dw))))

(defun* create-datareader (sub topic &key (qos nil qos-supplied-p))
    (function (subscriber t &key (:qos t)) data-reader)
  "Subscriber::create_datareader — register a local reader in the engine on the
   topic's name/type with the QoS reliability (v1: the single user reader). TOPIC may
   be a Topic or a ContentFilteredTopic; in the latter case the reader applies the
   filter predicate reader-side (only matching samples reach read/take). The
   endpoint kind (WITH_KEY/NO_KEY) is selected from the topic type's keyed-ness.
   When no explicit :qos is supplied, the Subscriber's default DataReader QoS applies
   (DDS 1.4 §2.2.2.5.1, set_default_datareader_qos), falling back to the role default.
   DDS-Security §8.4.2.5: when the participant is access-controlled, check_create_datareader must
   grant subscribe on the topic (local Permissions + Governance read-AC toggle) or the reader is
   refused (fail-closed SIGNAL). No access-state (default) = unchecked, byte-identical."
  (let ((node (dp-node (sub-participant sub)))
        (ah (dp-access-state (sub-participant sub)))
        (qos (if qos-supplied-p qos
                 (%default-qos-for-create (sub-default-datareader-qos sub) (dds.qos:make-reader-qos)))))
    (when (and ah (not (dds.security:check-create-datareader ah (topic-name topic))))
      (error "create-datareader: AccessControl check_create_datareader denied subscribe on topic ~s"
             (topic-name topic)))
    (let ((ep (dds.disc:add-local-reader node :topic (topic-name topic) :type (topic-type-name topic)
                                         :keyed (%topic-keyed-p topic)
                                         :qos qos :type-information (%topic-type-information topic))))
    (%set-user-metadata-protection node ah (topic-name topic) :reader)   ; ADR 0046 §9.4.1.2.4: the READER's own protection tiers
    (dds.disc:enable-subscriber node)
    ;; WP-FLATDATA-ZC-LOAN wiring (FR-PF-3/4, R6, ADR 0017): a :flatdata-topic reader, with ZC armed, is
    ;; loan-capable — the receiver thread defers ZC resolution (holds the slot) and the loan API owns the slot
    ;; lifetime. Gated on the TYPE being FlatData AND *zerocopy-enabled*; off either way -> NIL -> byte-unchanged.
    (when (and dds.disc:*zerocopy-enabled* (%flatdata-size (topic-type-support topic)))
      (dds.disc:set-zc-loan-capable node t))
    ;; WP-DCPS-SECURED-TAKE-LOAN (ADR 0038 residual (i)): a SECURED reader (its topic's data_protection is non-NONE,
    ;; node-secured-reader-p) opts into the zero-decode-buffer-alloc secured LOAN path — the receiver decodes each
    ;; SecuredPayload into a pooled buffer and take/read-loaned deserialize it in place, no per-sample decrypt
    ;; vector. A plain reader -> NIL -> the allocating decode path stays byte-identical.
    (when (dds.disc:node-secured-reader-p node)
      (dds.disc:set-secured-loan-capable node t))
    (let ((dr (make-instance 'data-reader :topic topic :subscriber sub :qos qos
                                          :enabled (%child-created-enabled-p sub))))
      (setf (dr-filter dr) (td-filter-predicate topic))   ; nil for a plain Topic
      ;; WP-N-ENDPOINT-S2 (ADR 0048): capture THIS reader's distinct EntityId (add-local-reader set it, enable-
      ;; subscriber registered the engine reader under it) so %drain's source-GUID filter routes delivery per reader.
      (setf (dr-entity-id dr) (dds.disc:disc-node-user-reader-id node))
      (setf (dr-disc-endpoint dr) ep)   ; S2.T4: retain the SEDP endpoint so delete_datareader can remove it
      ;; WP-N-ENDPOINT-2C3 (ADR 0017/0048): the mid-stream ZC-joiner high-water is frozen at MATCH time (atomic
      ;; with %reader-route-add under the node lock), NOT here at registration — a registration-time freeze leaves
      ;; the [freeze,route-add] window open (a marker delivered in the gap is unbumped for this reader yet would be
      ;; drained+released = UAF). See disc.lisp %reader-route-add + node-reader-join-watermark.
      (push dr (sub-readers sub))
      dr))))

(defun* %participant-writers (p)
    (function (domain-participant) list)
  "Every local DataWriter contained in participant P (across all its Publishers)."
  (let ((ws '()))
    (dolist (c (dp-children p) ws)
      (when (typep c 'publisher) (setf ws (append (pub-writers c) ws))))))

(defun* %writer-liveliness-kind (dw)
    (function (data-writer) symbol)
  "DW's offered LIVELINESS kind (DDS 1.4 §2.2.3.11), defaulting to :automatic when the
   QoS is absent or not a dds.qos:qos."
  (let ((qos (entity-qos dw)))
    (if (typep qos 'dds.qos:qos) (dds.qos:qos-liveliness qos) :automatic)))

(defun* %assert-writer-liveliness (dw)
    (function (data-writer) (eql t))
  "Stamp DW's self-assertion timestamp to now and clear its lost flag (DDS 1.4 §2.2.3.11):
   a write or DataWriter::assert_liveliness asserts the writer's liveliness, refreshing its
   lease so the next LIVELINESS_LOST sweep does not judge it not-alive; re-asserting a
   previously-lost writer transitions it back to alive so a LATER loss fires LIVELINESS_LOST
   again (total_count is never decremented — re-asserting does not undo a past loss).
   Lock-guarded."
  (dds.pal:with-lock ((dw-status-lock dw))
    (setf (dw-last-assertion dw) (%lease-now)
          (dw-alive-p dw) t))
  t)

(defun* assert-liveliness (dw)
    (function (data-writer) (eql t))
  "DataWriter::assert_liveliness (DDS 1.4 §2.2.2.4.2.2 / §2.2.3.11) — manually assert this
   writer's liveliness. Kind-aware (DDS 1.4 §2.2.3.11): MANUAL_BY_TOPIC asserts only THIS
   writer; MANUAL_BY_PARTICIPANT asserts EVERY MANUAL_BY_PARTICIPANT writer of the same
   participant (an assertion on any participant entity asserts them all); AUTOMATIC is
   asserted by the infrastructure (the announce cadence) so calling here merely refreshes
   this writer harmlessly. Stamps the affected writers' last-assertion to now."
  (case (%writer-liveliness-kind dw)
    (:manual-by-participant
     (let ((p (pub-participant (dw-publisher dw))))
       (dolist (w (%participant-writers p))
         (when (eq (%writer-liveliness-kind w) :manual-by-participant)
           (%assert-writer-liveliness w)))))
    (t (%assert-writer-liveliness dw)))
  t)

(defun* durability-finalize (dw)
    (function (data-writer) (eql t))
  "Declare that NO MORE LATE-JOINERS are expected for this DataWriter, releasing its retained
   TRANSIENT_LOCAL history — a NON-STANDARD, OPT-IN extension ADDED ON TOP of the conformant default
   (DDS 1.4 §2.2.3.4), never replacing it. By default a TRANSIENT_LOCAL writer RETAINS its acked samples
   for the writer's lifetime (the conformant default; DDS leaves per-writer TRANSIENT/PERSISTENT lifetime
   to the durability SERVICE — out of scope for this WP, that is the follow-on service milestone). Calling
   durability-finalize sets a per-writer flag so the writer reverts to the VOLATILE-style full-ACK purge:
   the retained late-joiner history is RELEASED once all current matched readers ACK it, and any sample
   published afterwards behaves VOLATILE (purged on full-ACK, not retained). A subsequent TRANSIENT_LOCAL
   late-joiner therefore receives NOTHING of the pre-finalize history. The control is MONOTONIC — once
   finalized the writer stays finalized (no un-finalize in v1); a repeat call is idempotent. A no-op (still
   returns T) for a VOLATILE writer (it already purges on full-ACK) and when there is no engine writer yet —
   the disc bridge (dds.disc:finalize-writer-durability) guards on (when w ...), so the no-op arises from the
   absence of an engine writer, NOT from an explicit enabled check. Forwards to the engine via that bridge."
  (dds.disc:finalize-writer-durability (dp-node (pub-participant (dw-publisher dw))) (dw-entity-id dw)))

(defparameter +retcode-ok+ :ok
  "DDS 1.4 ReturnCode_t RETCODE_OK (§2.2.4.4): the operation succeeded. Represented as the keyword :ok.")

(defparameter +retcode-timeout+ :timeout
  "DDS 1.4 ReturnCode_t RETCODE_TIMEOUT (§2.2.4.4): the operation did not complete within the configured
   time. Returned by write/dispose/unregister when RELIABILITY.max_blocking_time elapsed on a full bounded
   (KEEP_ALL + RESOURCE_LIMITS max_samples) HistoryCache — DDS-standard block-up-to-max_blocking_time
   backpressure (WP-ASYNC-FLOW, FR-PF-2/FR-QOS, ADR 0016 §Backpressure). Represented as the keyword
   :timeout, the same sentinel the engine (dds.disc:publish-sample) surfaces.")

(defparameter +retcode-not-enabled+ :not-enabled
  "DDS 1.4 ReturnCode_t RETCODE_NOT_ENABLED (§2.2.4.4): an operation outside the NOT_ENABLED-safe
   set (§2.2.2.1.1.7 — set_qos, get_qos, enable, get_statuscondition, set_listener) was called on a
   still-disabled entity. Represented as the keyword :not-enabled; the operation had no effect.")

(defparameter +retcode-precondition-not-met+ :precondition-not-met
  "DDS 1.4 ReturnCode_t RETCODE_PRECONDITION_NOT_MET (§2.2.4.4): a precondition for the operation
   was not met — enable() on an entity whose factory-parent is still disabled (§2.2.2.1.1.7), or
   delete_* of a container that still holds contained entities / a Topic still referenced by an
   endpoint (§2.2.2.2.1.5). Represented as the keyword :precondition-not-met; nothing was deleted.")

(defparameter +retcode-immutable-policy+ :immutable-policy
  "DDS 1.4 ReturnCode_t RETCODE_IMMUTABLE_POLICY (§2.2.4.4): set_qos on an ENABLED entity tried
   to change a policy the DDS 1.4 §2.2.3 'changeable' column marks immutable-after-enable.
   Represented as the keyword :immutable-policy; the QoS is left unchanged.")

(defparameter +retcode-inconsistent-policy+ :inconsistent-policy
  "DDS 1.4 ReturnCode_t RETCODE_INCONSISTENT_POLICY (§2.2.4.4): set_qos was given a QoS whose
   policies are mutually inconsistent (the §2.2.3.18/§2.2.3.19 cross-policy rules; see
   %qos-consistent-p). Represented as the keyword :inconsistent-policy; the QoS is left unchanged.")

(defun* get-qos (entity)
    (function (entity) dds.qos:qos)
  "Entity::get_qos (DDS 1.4 §2.2.4.1) — return a COPY of ENTITY's effective QoS set so the
   caller cannot mutate the stored policies in place. An entity created without an explicit QoS
   (a Publisher/Subscriber/DomainParticipant/Topic in this v1) reports a fresh default QoS."
  (let ((q (entity-qos entity)))
    (if (typep q 'dds.qos:qos) (dds.qos:copy-qos q) (dds.qos:make-qos))))

(defun* set-qos (entity qos)
    (function (entity dds.qos:qos) (member :ok :immutable-policy :inconsistent-policy))
  "Entity::set_qos (DDS 1.4 §2.2.4.1) — install QOS as ENTITY's effective QoS, returning the
   DDS ReturnCode_t. First the §2.2.3.18/§2.2.3.19 consistency rules run (-> :inconsistent-policy
   on failure, QoS unchanged); then, if ENTITY is already enabled, the §2.2.3 immutability table
   rejects any change to an immutable-after-enable policy (-> :immutable-policy, QoS unchanged).
   Otherwise QOS is stored and :ok returned. (Enabled state uses the provisional entity-enabled-p;
   WP-DCPS-API-COMPLETION S2 formalizes enable().)"
  (multiple-value-bind (okp failing-id) (%qos-consistent-p qos)
    (declare (ignore failing-id))
    (unless okp (return-from set-qos +retcode-inconsistent-policy+)))
  (when (entity-enabled-p entity)
    (let ((old (get-qos entity)))   ; normalize an absent stored QoS to the effective default, as get_qos does
      (when (/= +qos-policy-id-invalid+ (%qos-immutable-violation old qos))
        (return-from set-qos +retcode-immutable-policy+))))
  (setf (entity-qos entity) qos)
  +retcode-ok+)

;;; ---- WP-DCPS-API-COMPLETION S2.T3: enable() + disabled-entity semantics (DDS 1.4 §2.2.2.1.1.7) ----

(defun* %entity-factory-parent-enabled-p (entity)
    (function (entity) boolean)
  "Whether ENTITY's factory-parent (the entity that created it) is itself enabled (DDS 1.4
   §2.2.2.1.1.7): a DomainParticipant's factory-parent is the DomainParticipantFactory (always
   enabled -> T); a Publisher/Subscriber/Topic's is its DomainParticipant; a DataWriter's is its
   Publisher; a DataReader's is its Subscriber. An entity can only transition to enabled once its
   factory-parent is enabled."
  (typecase entity
    (domain-participant t)
    (publisher (entity-enabled-p (pub-participant entity)))
    (subscriber (entity-enabled-p (sub-participant entity)))
    (topic (entity-enabled-p (topic-participant entity)))
    (data-writer (entity-enabled-p (dw-publisher entity)))
    (data-reader (entity-enabled-p (dr-subscriber entity)))
    (t t)))

(defun* enable (entity)
    (function (entity) (member :ok :precondition-not-met))
  "Entity::enable (DDS 1.4 §2.2.2.1.1.7) — transition ENTITY to the enabled state. Idempotent: an
   already-enabled entity returns :ok with no effect. An entity whose factory-parent is still
   disabled cannot be enabled and returns :precondition-not-met (the parent must be enabled first).
   Enabling is monotonic (there is no disable in DDS). Once enabled, the entity's operations leave
   the NOT_ENABLED-safe set and its QoS immutable-after-enable policies are frozen (set_qos, S1)."
  (when (entity-enabled-p entity) (return-from enable +retcode-ok+))
  (unless (%entity-factory-parent-enabled-p entity)
    (return-from enable +retcode-precondition-not-met+))
  (setf (entity-enabled-p entity) t)
  +retcode-ok+)

(defun* %child-created-enabled-p (parent)
    (function (t) boolean)
  "Whether a child created under PARENT is created ENABLED (DDS 1.4 §2.2.2.1.1.7 + §2.2.3.23): TRUE
   iff PARENT's ENTITY_FACTORY autoenable_created_entities is set AND PARENT is itself enabled — a
   child of a DISABLED factory-parent is ALWAYS created disabled (it cannot be enabled before its
   parent). The DomainParticipantFactory is always enabled, so a participant's create-enabled state
   is just the factory's autoenable flag. At the default (autoenable T, parent enabled) this is T —
   byte-identical to the pre-S2.T3 always-enabled create paths. Consulted by every create_*."
  (typecase parent
    (domain-participant-factory (participant-factory-autoenable-p parent))
    (entity (and (entity-autoenable-created-entities parent) (entity-enabled-p parent) t))
    (t t)))

;;; ---- S1.T4: default-QoS getters/setters (DDS 1.4 §2.2.2), applied at create_* ----

(defun* %default-qos-or (stored fallback-fn)
    (function (t function) dds.qos:qos)
  "Return an independent COPY of the STORED default QoS if one is set, else a fresh default
   from FALLBACK-FN. Backs every get_default_*_qos so callers never alias the stored default."
  (if (typep stored 'dds.qos:qos) (dds.qos:copy-qos stored) (funcall fallback-fn)))

(defun* %store-default-qos (qos)
    (function (dds.qos:qos) (member :ok :inconsistent-policy))
  "Validate QOS for set_default_*_qos (DDS 1.4 §2.2.3 consistency): :ok if consistent (the caller
   then stores it), else :inconsistent-policy (nothing stored)."
  (multiple-value-bind (okp failing-id) (%qos-consistent-p qos)
    (declare (ignore failing-id))
    (if okp +retcode-ok+ +retcode-inconsistent-policy+)))

(defun* get-default-datawriter-qos (pub)
    (function (publisher) dds.qos:qos)
  "Publisher::get_default_datawriter_qos (DDS 1.4 §2.2.2.4.1.21): the QoS create_datawriter uses
   when no explicit QoS is supplied; a fresh DataWriter default until set."
  (%default-qos-or (pub-default-datawriter-qos pub) #'dds.qos:make-writer-qos))

(defun* set-default-datawriter-qos (pub qos)
    (function (publisher dds.qos:qos) (member :ok :inconsistent-policy))
  "Publisher::set_default_datawriter_qos (DDS 1.4 §2.2.2.4.1.22): install QOS as the default for
   subsequently-created DataWriters; :inconsistent-policy (nothing stored) if QOS is inconsistent."
  (let ((rc (%store-default-qos qos)))
    (when (eq +retcode-ok+ rc) (setf (pub-default-datawriter-qos pub) qos))
    rc))

(defun* get-default-datareader-qos (sub)
    (function (subscriber) dds.qos:qos)
  "Subscriber::get_default_datareader_qos (DDS 1.4 §2.2.2.5.1.22): the QoS create_datareader uses
   when no explicit QoS is supplied; a fresh DataReader default until set."
  (%default-qos-or (sub-default-datareader-qos sub) #'dds.qos:make-reader-qos))

(defun* set-default-datareader-qos (sub qos)
    (function (subscriber dds.qos:qos) (member :ok :inconsistent-policy))
  "Subscriber::set_default_datareader_qos (DDS 1.4 §2.2.2.5.1.23): install QOS as the default for
   subsequently-created DataReaders; :inconsistent-policy (nothing stored) if QOS is inconsistent."
  (let ((rc (%store-default-qos qos)))
    (when (eq +retcode-ok+ rc) (setf (sub-default-datareader-qos sub) qos))
    rc))

(defun* get-default-topic-qos (p)
    (function (domain-participant) dds.qos:qos)
  "DomainParticipant::get_default_topic_qos (DDS 1.4 §2.2.2.2.2): the QoS create_topic uses when
   no explicit QoS is supplied; a fresh default until set."
  (%default-qos-or (dp-default-topic-qos p) #'dds.qos:make-qos))

(defun* set-default-topic-qos (p qos)
    (function (domain-participant dds.qos:qos) (member :ok :inconsistent-policy))
  "DomainParticipant::set_default_topic_qos (DDS 1.4 §2.2.2.2.2): install QOS as the default for
   subsequently-created Topics; :inconsistent-policy (nothing stored) if QOS is inconsistent."
  (let ((rc (%store-default-qos qos)))
    (when (eq +retcode-ok+ rc) (setf (dp-default-topic-qos p) qos))
    rc))

(defun* get-default-publisher-qos (p)
    (function (domain-participant) dds.qos:qos)
  "DomainParticipant::get_default_publisher_qos (DDS 1.4 §2.2.2.2.2): the QoS create_publisher
   uses when no explicit QoS is supplied; a fresh default until set."
  (%default-qos-or (dp-default-publisher-qos p) #'dds.qos:make-qos))

(defun* set-default-publisher-qos (p qos)
    (function (domain-participant dds.qos:qos) (member :ok :inconsistent-policy))
  "DomainParticipant::set_default_publisher_qos (DDS 1.4 §2.2.2.2.2): install QOS as the default
   for subsequently-created Publishers; :inconsistent-policy (nothing stored) if inconsistent."
  (let ((rc (%store-default-qos qos)))
    (when (eq +retcode-ok+ rc) (setf (dp-default-publisher-qos p) qos))
    rc))

(defun* get-default-subscriber-qos (p)
    (function (domain-participant) dds.qos:qos)
  "DomainParticipant::get_default_subscriber_qos (DDS 1.4 §2.2.2.2.2): the QoS create_subscriber
   uses when no explicit QoS is supplied; a fresh default until set."
  (%default-qos-or (dp-default-subscriber-qos p) #'dds.qos:make-qos))

(defun* set-default-subscriber-qos (p qos)
    (function (domain-participant dds.qos:qos) (member :ok :inconsistent-policy))
  "DomainParticipant::set_default_subscriber_qos (DDS 1.4 §2.2.2.2.2): install QOS as the default
   for subsequently-created Subscribers; :inconsistent-policy (nothing stored) if inconsistent."
  (let ((rc (%store-default-qos qos)))
    (when (eq +retcode-ok+ rc) (setf (dp-default-subscriber-qos p) qos))
    rc))

(defun* get-default-participant-qos ()
    (function () dds.qos:qos)
  "DomainParticipantFactory::get_default_participant_qos (DDS 1.4 §2.2.2.2.2): the QoS
   create_participant uses when no explicit QoS is supplied; a fresh default until set. Reads the
   provisional *default-participant-qos* (S2 moves this onto the DomainParticipantFactory)."
  (%default-qos-or *default-participant-qos* #'dds.qos:make-qos))

(defun* set-default-participant-qos (qos)
    (function (dds.qos:qos) (member :ok :inconsistent-policy))
  "DomainParticipantFactory::set_default_participant_qos (DDS 1.4 §2.2.2.2.2): install QOS as the
   default for subsequently-created DomainParticipants; :inconsistent-policy (nothing stored) if
   inconsistent. Writes the provisional *default-participant-qos* (S2 formalizes on the factory)."
  (let ((rc (%store-default-qos qos)))
    (when (eq +retcode-ok+ rc) (setf *default-participant-qos* qos))
    rc))

(defun* %writer-keeplast-p (dw)
    (function (data-writer) boolean)
  "T iff DW's effective HISTORY QoS kind is KEEP_LAST (DDS 1.4 §2.2.3.18); defaults to T (the
   policy default :keep-last, DDS 1.4 §2.2.3 default QoS table) when the QoS is absent/not a qos."
  (let ((qos (entity-qos dw)))
    (if (typep qos 'dds.qos:qos) (eq :keep-last (dds.qos:qos-history-kind qos)) t)))

(defun* %write-key-hash (dw sample)
    (function (data-writer t) (or null (simple-array (unsigned-byte 8) (16))))
  "The instance handle to thread onto SAMPLE's data CacheChange (WP-KEEPLAST, ADR 0019,
   DDS 1.4 §2.2.3.18): computed via the topic type-support ONLY when DW is KEEP_LAST (a
   KEEP_ALL writer never evicts per-instance, so it needs no handle), else NIL. For an unkeyed
   type %instance-handle returns the SHARED +instance-handle-nil+ (eq, no allocation); a keyed
   type allocates a fresh keyhash. NIL on a KEEP_ALL writer keeps the default path 0-alloc."
  (when (%writer-keeplast-p dw)
    (%instance-handle (topic-type-support (dw-topic dw)) sample)))

(defun* write-sample (dw sample)
    (function (data-writer t) (member :ok :timeout :not-enabled))
  "DataWriter::write — serialize SAMPLE via the topic type-support and publish it reliably over the engine
   to all matched/discovered readers. Returns the DDS ReturnCode_t +RETCODE-OK+ (:ok) normally, or
   +RETCODE-TIMEOUT+ (:timeout) if the writer's HistoryCache was full and RELIABILITY.max_blocking_time
   elapsed without freeing a slot (WP-ASYNC-FLOW backpressure, ADR 0016 §Backpressure; only a writer whose
   engine cache is bounded — finite max_samples + max_blocking_time — can return :timeout, so the default
   path is byte-identical). On :timeout the sample was NOT published and liveliness is NOT asserted (the
   write did not occur). A write otherwise asserts the writer's liveliness (DDS 1.4 §2.2.3.11), stamping the
   writer (and, for MANUAL_BY_PARTICIPANT, every such writer of the participant) via assert_liveliness.
   WP-KEEPLAST (ADR 0019, DDS 1.4 §2.2.3.18): for a KEEP_LAST writer the sample's instance handle is
   threaded onto the data CacheChange (publish-sample -> writer-write) for per-instance eviction; a KEEP_ALL
   writer threads NIL, keeping the default path 0-alloc (the handle is computed only when KEEP_LAST needs it).
   WP-DATA-REPRESENTATION step 2 (DDS-XTypes 1.3 §7.6.3.1.1): the sample is serialized in DW's OFFERED
   representation (%writer-tx-rep = the first of its data-representation QoS) — :xcdr2 (default, PLAIN_CDR2_LE,
   byte-identical existing wire) or :xcdr1 (PLAIN_CDR_LE), so an XCDR1-offering writer can serve an XCDR1-only
   reader; the rep applies to the payload only, never to the keyhash (always XCDR2-BE, RTPS 2.5 §9.6.4.8).
   A DISABLED DataWriter refuses the write with +RETCODE-NOT-ENABLED+ (:not-enabled), the write outside
   the NOT_ENABLED-safe set on a disabled entity (DDS 1.4 §2.2.2.1.1.7, S2.T3)."
  (unless (entity-enabled-p dw) (return-from write-sample +retcode-not-enabled+))
  (let ((node (dp-node (pub-participant (dw-publisher dw)))))
    (when (eq :timeout (dds.disc:publish-sample
                        node (%serialize-sample (topic-type-support (dw-topic dw)) sample
                                                (%writer-tx-rep dw))
                        (%write-key-hash dw sample) nil 0 nil
                        (dw-entity-id dw)))   ; WP-N-ENDPOINT-S1: publish into THIS writer's own HistoryCache
      (return-from write-sample +retcode-timeout+))   ; full bounded cache, max_blocking_time elapsed
    (assert-liveliness dw)
    +retcode-ok+))

;;;; ---- WP-FLATDATA-LOAN-WRITE zero-copy TX loan API (FR-PF-4, R6, ADR 0042) ----
;;;; NOT cleared for ship — pending counsel (R6); see ADR 0042.

(defstruct* (writer-loan (:constructor %make-writer-loan))
  "WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending counsel). A writer-side loaned
   FlatData sample — the TX dual of the reader's flatdata-view loan. KIND :slot = SLOT-BACKED (SAMPLE is a
   flatdata-view over a live writer-pool slot the app fills straight through the <name>-<field>-fd setters;
   POOL-SAP/SLOT/GENERATION/PAYLOAD-BASE/SIZE are the loan handle); KIND :fallback = a heap/foreign FlatData
   octet-buffer (make-<name>-flatdata) when the node is not ZC-loan-eligible (no pool / too-small type /
   wire-protected / pool saturated / non-SBCL) — same API, graceful degradation, no error. DONE latches the
   terminal state (:written / :discarded) so write-loaned / discard-loan are idempotent (a double call, or a
   write-after-discard, is a validated no-op). Recycled through the DataWriter's loan freelist (no per-sample
   GC-heap struct cons; NFR-MEM). NOT cleared for ship — pending counsel (R6)."
  (kind :fallback :type (member :slot :fallback))
  (sample nil :type t)                       ; the flatdata-view (slot) or octet-buffer (fallback) the app writes
  (view nil :type t)                         ; the recycled flatdata-view (slot kind); NIL for fallback
  (pool-sap nil :type t) (slot 0 :type (integer 0)) (generation 0 :type (unsigned-byte 32))
  (payload-base 0 :type (integer 0)) (size 0 :type (integer 0))
  (done nil :type (or null (member :written :discarded))))

(defun* %loan-encap-header (ts)
    (function (t) (simple-array (unsigned-byte 8) (4)))
  "WP-FLATDATA-LOAN-WRITE (R6, ADR 0042 §4): the type's 4-octet XCDR2-LE encapsulation header + finalized
   OPTIONS, sourced by funcalling the type's OWN FlatData constructor (make-<name>-flatdata — the SAME
   dds.cdr:make-encapsulation-header/finalize-encapsulation-options emitters %serialize-sample uses; NEVER
   hardcoded representation bytes) and copying its first 4 octets. Per-TYPE constant (a FINAL FlatData size is
   fixed, so the OPTIONS trailing-pad bits are too); cached once per DataWriter (dw-loan-encap) and written into
   every slot-backed loan's slot at loan-sample so the slot bytes are a SELF-DESCRIBING SerializedPayload —
   byte-identical in [base,base+4) to what %zc-loan copies in on the classic write-sample path. NOT cleared for
   ship — pending counsel (R6)."
  (let ((buf (funcall (dds.types:type-support-flatdata-ctor ts))))
    (unwind-protect
         (subseq (dds.core.buffer:octet-buffer-vec buf) 0 4)
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf)))))

(defun* loan-sample (dw)
    (function (data-writer) (or writer-loan (eql :not-enabled)))
  "DataWriter loan-write — WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending counsel).
   Return a writer-side loaned FlatData sample the app fills via the existing <name>-<field>-fd setters, then
   publishes with write-loaned (or abandons with discard-loan). When the FULL ZC-TX eligibility holds — the topic
   type is FlatData, its +<name>-flatdata-size+ clears *zerocopy-min-payload-bytes*, the node has a writer pool,
   the writer is NOT wire-protected (secured) NOR data_protection-transformed (ADR 0042 §6), and the impl
   supports foreign-SAP writes (SBCL; ZC is SBCL-only, ADR 0013) — the loan is SLOT-BACKED: a pool slot is
   acquired (dds.disc:node-loan-write-acquire), the type's 4-octet encap header + OPTIONS are written into the
   slot head (%loan-encap-header — the slot IS a self-describing SerializedPayload, byte-identical to the
   classic path's), and the sample is a flatdata-view over the slot's XCDR2 body, so the app's setters write
   STRAIGHT INTO the shared-memory slot (no app→buffer copy). Otherwise it degrades GRACEFULLY to a
   make-<name>-flatdata octet-buffer — same API, no error, byte-identical downstream. SECURITY (ADR 0036
   Carry-10 + ADR 0042 §6, fail-closed at the loan end): a wire-protected OR payload-transforming writer NEVER
   gets a slot-backed loan — its plaintext must not land in a pool slot at all. ALLOCATION (honest, FR-LANG-7):
   the writer-loan struct + flatdata-view recycle through the DataWriter's freelist, but each loan-sample CONSES
   one registry cell (dw-loans) and each write-loaned conses one armed-registry cell. The RETAINED payload vector
   write-loaned allocated on EVERY write is ELIMINATED for a PIN-ELIGIBLE writer (WP-ACKED-SLOT-PINNING, ADR 0044):
   reliable + VOLATILE/finalized + a matched reliable reader PINS the committed slot until the full-ACK purge, so
   retransmit / non-ZC / extra-ZC sends read it on demand; an ineligible writer (or exhausted pin budget) still
   materialises the retained payload (the always-correct fallback). NOT cleared for ship — pending counsel (R6).
   A DISABLED DataWriter refuses with :not-enabled (outside the NOT_ENABLED-safe set, DDS 1.4 §2.2.2.1.1.7)."
  (unless (entity-enabled-p dw) (return-from loan-sample +retcode-not-enabled+))
  (let* ((ts (topic-type-support (dw-topic dw)))
         (node (dp-node (pub-participant (dw-publisher dw))))
         (lay (dds.types:type-support-flatdata-offset ts))
         (size (and (dds.types:flatdata-layout-p lay) (dds.types:flatdata-layout-size lay)))
         (ln (or (pop (dw-loan-freelist dw)) (%make-writer-loan))))
    (setf (writer-loan-done ln) nil)
    (when (and size (eq (dds.pal:pal-impl-name) :sbcl)   ; ZC foreign-SAP writes are SBCL-only (ADR 0013)
               (dds.disc:node-loan-write-eligible-p node size))
      (multiple-value-bind (sap slot base gen) (dds.disc:node-loan-write-acquire node size)
        (when sap                                        ; NIL ⇒ pool saturated ⇒ fall through to the fallback
          (let ((hdr (or (dw-loan-encap dw) (setf (dw-loan-encap dw) (%loan-encap-header ts)))))
            (dotimes (i 4) (dds.pal:store-sap-u8 sap (+ base i) (aref hdr i))))   ; the slot IS a self-describing SerializedPayload (ADR 0042 §4)
          (let ((view (or (writer-loan-view ln) (dds.types:make-flatdata-view))))
            (setf (dds.types:flatdata-view-slot-sap view) sap
                  (dds.types:flatdata-view-base-offset view) (+ base 4)   ; past the 4-octet encap header
                  (dds.types:flatdata-view-len view) (max 0 (- size 4))
                  (dds.types:flatdata-view-pool-sap view) sap
                  (dds.types:flatdata-view-slot-index view) slot
                  (dds.types:flatdata-view-generation view) gen)
            (setf (writer-loan-kind ln) :slot (writer-loan-sample ln) view (writer-loan-view ln) view
                  (writer-loan-pool-sap ln) sap (writer-loan-slot ln) slot (writer-loan-generation ln) gen
                  (writer-loan-payload-base ln) base (writer-loan-size ln) size)
            (push ln (dw-loans dw))
            (return-from loan-sample ln)))))
    (let ((ctor (dds.types:type-support-flatdata-ctor ts)))   ; graceful degradation: an owned FlatData buffer
      (setf (writer-loan-kind ln) :fallback (writer-loan-size ln) (or size 0)
            (writer-loan-sample ln) (if ctor (funcall ctor) (error "loan-sample: ~a is not a FlatData type" (dds.types:type-support-type-name ts))))
      (push ln (dw-loans dw))
      ln)))

(defun* %loan-write-payload (ln)
    (function (writer-loan) (simple-array (unsigned-byte 8) (*)))
  "WP-FLATDATA-LOAN-WRITE (R6, ADR 0042): materialise a SLOT-BACKED loan's RETAINED SerializedPayload — a
   straight slot→heap copy of ALL size octets: the slot is a SELF-DESCRIBING SerializedPayload (loan-sample
   wrote the type's 4-octet encap header + OPTIONS into it via %loan-encap-header — the same dds.cdr emitters
   %serialize-sample uses — and the app's SAP setters wrote the body), so the retained vector is byte-identical
   to what write-sample's %serialize-sample would produce for the same field values. This per-write heap vector
   is the ADR 0042 retained-payload fallback: it lives in the writer HistoryCache to serve retransmission / non-ZC
   / extra-ZC destinations. write-loaned calls this ONLY for a NON-pin-eligible writer (WP-ACKED-SLOT-PINNING, ADR
   0044); a pin-eligible writer instead PINS the committed slot and reads it on demand, eliminating this per-write
   copy (see write-loaned). NOT cleared for ship — pending counsel (R6)."
  (let* ((size (writer-loan-size ln))
         (base (writer-loan-payload-base ln))
         (sap (writer-loan-pool-sap ln))
         (vec (make-array size :element-type '(unsigned-byte 8))))
    (dotimes (i size vec) (setf (aref vec i) (dds.pal:load-sap-u8 sap (+ base i))))))

(defun* %recycle-loan (dw ln)
    (function (data-writer writer-loan) t)
  "WP-FLATDATA-LOAN-WRITE (R6, ADR 0042): drop LN from the writer's outstanding-loan registry and recycle its
   struct (and, for a fallback, free its owned FlatData buffer) to the DataWriter freelist (no GC churn). The
   embedded flatdata-view is retained on the struct for the next slot loan. NOT cleared for ship — pending
   counsel (R6)."
  (setf (dw-loans dw) (delete ln (dw-loans dw)))
  (when (and (eq (writer-loan-kind ln) :fallback) (typep (writer-loan-sample ln) 'dds.core.buffer:octet-buffer))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec (writer-loan-sample ln))))
  (setf (writer-loan-sample ln) nil (writer-loan-pool-sap ln) nil)
  (push ln (dw-loan-freelist dw))
  t)

(defun* write-loaned (dw loan)
    (function (data-writer writer-loan) (member :ok :timeout :not-enabled))
  "DataWriter::write by LOAN — WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending
   counsel). Publish the loaned sample LOAN filled by the app. SLOT-BACKED: materialise the RETAINED
   SerializedPayload from the slot (%loan-write-payload — the copy that serves retransmission, non-ZC
   destinations, and any extra ZC destination; ADR 0042 §5), COMMIT the slot (dds.disc:node-loan-write-commit —
   the release-fence + generation-store publication point, ADR 0042 §2), then publish with the change CARRYING
   the pre-committed slot: the send site (%zc-change-item) emits the slot's 20-octet ref to the FIRST
   ZC-eligible destination with NO payload->slot copy (the end-to-end 0-copy TX leg: the app's SAP-setter
   writes are the only writes the delivered bytes ever saw), or releases the slot on its fallback decision /
   the leak sweep — every non-pure case is served from the retained payload exactly as write-sample. On
   :timeout publish-sample released the slot (nothing was added). FALLBACK: exactly write-sample on the owned
   FlatData buffer. Returns +RETCODE-OK+ (:ok) or +RETCODE-TIMEOUT+ (:timeout) under the same bounded-cache
   backpressure as write-sample. IDEMPOTENT: a second write-loaned, or a write after discard-loan, is a
   validated no-op returning :ok (the loan is already terminal). Recycles the loan on success. NOT cleared for
   ship — pending counsel (R6). A DISABLED DataWriter refuses with :not-enabled (DDS 1.4 §2.2.2.1.1.7)."
  (unless (entity-enabled-p dw) (return-from write-loaned +retcode-not-enabled+))
  (when (writer-loan-done loan) (return-from write-loaned +retcode-ok+))   ; already written/discarded: no-op
  (let ((node (dp-node (pub-participant (dw-publisher dw)))))
    (if (eq (writer-loan-kind loan) :slot)
        ;; WP-ACKED-SLOT-PINNING (ADR 0044): a PIN-CAPABLE writer (reliable + volatile/finalized + >=1 matched
        ;; reliable reader) PINS the committed slot instead of eagerly copying it to the heap — pass NIL payload +
        ;; the true length so publish-sample takes the pin (or, at budget, resolves on demand). Otherwise (ADR
        ;; 0042 fallback) materialise the RETAINED payload eagerly (best-effort / no reliable reader / un-finalized
        ;; TRANSIENT_LOCAL); either is byte- and behaviour-identical downstream.
        (let* ((pin-p (dds.disc:node-loan-write-pin-capable-p node))
               (payload (if pin-p nil (%loan-write-payload loan)))
               (kh (when (%writer-keeplast-p dw)
                     (%instance-handle (topic-type-support (dw-topic dw)) (writer-loan-sample loan)))))  ; keyhash off the view
          (dds.disc:node-loan-write-commit node (writer-loan-slot loan) (writer-loan-generation loan))  ; publish the slot's generation (ADR 0042 §2)
          (setf (writer-loan-done loan) :written)
          (let ((rc (dds.disc:publish-sample node payload kh (writer-loan-slot loan) (writer-loan-generation loan)
                                             (writer-loan-size loan))))   ; ADR 0044: the true length for the pinned case
            (%recycle-loan dw loan)
            (when (eq :timeout rc) (return-from write-loaned +retcode-timeout+)))   ; slot already released inside publish-sample
          (assert-liveliness dw)
          +retcode-ok+)
        (let ((rc (write-sample dw (writer-loan-sample loan))))   ; fallback: the owned FlatData buffer
          (setf (writer-loan-done loan) :written)
          (%recycle-loan dw loan)
          rc))))

(defun* discard-loan (dw loan)
    (function (data-writer writer-loan) t)
  "DataWriter loan discard — WP-FLATDATA-LOAN-WRITE (FR-PF-4, R6, ADR 0042; NOT cleared for ship — pending
   counsel). Abandon LOAN WITHOUT publishing: SLOT-BACKED ⇒ node-loan-write-abort the slot (refcount→0, no
   generation published, invisible to every reader — ADR 0042 §2); FALLBACK ⇒ just drop the owned buffer. Then
   recycle the loan. IDEMPOTENT / double-discard-safe: a loan already :written or :discarded is a validated
   no-op. NOT cleared for ship — pending counsel (R6)."
  (unless (writer-loan-done loan)
    (when (eq (writer-loan-kind loan) :slot)
      (dds.disc:node-loan-write-abort (dp-node (pub-participant (dw-publisher dw))) (writer-loan-slot loan)))
    (setf (writer-loan-done loan) :discarded)
    (%recycle-loan dw loan))
  t)

(defun* discard-all-loans (dw)
    (function (data-writer) t)
  "WP-FLATDATA-LOAN-WRITE writer-close safety (FR-PF-4, R6, ADR 0042): discard EVERY outstanding writer-loan
   (mirrors the reader's return-all-loans) so writer-close / delete-participant leaves NO acquired-but-
   unpublished pool slot held (a leaked slot pins the pool until it gracefully falls back to non-ZC). NOT cleared
   for ship — pending counsel (R6)."
  (dolist (ln (copy-list (dw-loans dw))) (discard-loan dw ln))
  t)

(defparameter +instance-handle-nil+
  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
  "HANDLE_NIL — the instance handle for an unkeyed type (single instance).")

(defun* %instance-handle (ts sample)
    (function (t t) (simple-array (unsigned-byte 8) (16)))
  "16-octet instance handle for SAMPLE via the type-support key-hash, or HANDLE_NIL
   for an unkeyed type."
  (let ((kh (dds.types:type-support-key-hash ts)))
    (if kh (funcall kh sample) +instance-handle-nil+)))

(defun* %handle-p (x)
    (function (t) t)
  "T iff X is already a 16-octet instance handle (a (simple-array (unsigned-byte 8) (16)))."
  (typep x '(simple-array (unsigned-byte 8) (16))))

(defun* %guid-entityid (guid)
    (function ((simple-array (unsigned-byte 8) (16))) (unsigned-byte 32))
  "The EntityId (last 4 GUID octets) as an MSB-first u32 (RTPS 2.5 §9.3.1.2) — the same
   writer EntityId the data path records per sample, so an unmatched writer's GUID maps to
   the WID held in an instance's writers set."
  (logior (ash (aref guid 12) 24) (ash (aref guid 13) 16) (ash (aref guid 14) 8) (aref guid 15)))

(defun* %resolve-handle (dw sample-or-handle)
    (function (data-writer t) (simple-array (unsigned-byte 8) (16)))
  "The 16-octet instance handle for SAMPLE-OR-HANDLE on DW: SAMPLE-OR-HANDLE used directly when
   it is already a handle, else computed from a sample via the topic type-support key-hash."
  (if (%handle-p sample-or-handle)
      sample-or-handle
      (%instance-handle (topic-type-support (dw-topic dw)) sample-or-handle)))

(defun* register-instance (dw sample)
    (function (data-writer t) (or (simple-array (unsigned-byte 8) (16)) (eql :not-enabled)))
  "DataWriter::register_instance (DDS 1.4 §2.2.2.4.2.5) — register the instance of SAMPLE and
   return its 16-octet handle (the type-support key-hash). Records the handle as :alive in the
   writer's instance table; HANDLE_NIL for an unkeyed type. No wire message is emitted (registration
   is a writer-local act; the instance becomes visible to readers on the first write/dispose).
   A DISABLED DataWriter refuses with :not-enabled (outside the NOT_ENABLED-safe set, DDS 1.4
   §2.2.2.1.1.7, S2.T3)."
  (unless (entity-enabled-p dw) (return-from register-instance +retcode-not-enabled+))
  (let ((handle (%instance-handle (topic-type-support (dw-topic dw)) sample)))
    (dds.pal:with-lock ((dw-status-lock dw))
      (setf (gethash handle (dw-instances dw)) :alive))
    handle))

(defun* dispose-instance (dw sample-or-handle)
    (function (data-writer t) (or (simple-array (unsigned-byte 8) (16)) (member :timeout :not-enabled)))
  "DataWriter::dispose (DDS 1.4 §2.2.2.4.2.10) — dispose the instance named by SAMPLE-OR-HANDLE
   (a sample or a registered handle): emit a no-payload dispose DATA (StatusInfo Disposed, RTPS 2.5
   §9.6.4.9) over the reliable engine so matched readers see NOT_ALIVE_DISPOSED. Returns the handle, or
   +RETCODE-TIMEOUT+ (:timeout) if the bounded cache was full and max_blocking_time elapsed (WP-ASYNC-FLOW
   backpressure, ADR 0016 §Backpressure; on :timeout nothing was emitted and liveliness is not asserted).
   A DISABLED DataWriter refuses with :not-enabled (outside the NOT_ENABLED-safe set, DDS 1.4 §2.2.2.1.1.7)."
  (unless (entity-enabled-p dw) (return-from dispose-instance +retcode-not-enabled+))
  (let ((handle (%resolve-handle dw sample-or-handle))
        (node (dp-node (pub-participant (dw-publisher dw)))))
    (when (eq :timeout (dds.disc:dispose-instance node handle))
      (return-from dispose-instance +retcode-timeout+))
    (assert-liveliness dw)
    handle))

(defun* %writer-autodispose-p (dw)
    (function (data-writer) boolean)
  "DW's WRITER_DATA_LIFECYCLE autodispose_unregistered_instances flag (DDS 1.4 §2.2.3.21), defaulting
   to T (the policy default) when the QoS is absent or not a dds.qos:qos."
  (let ((qos (entity-qos dw)))
    (if (typep qos 'dds.qos:qos) (dds.qos:qos-autodispose-unregistered-instances qos) t)))

(defun* unregister-instance (dw sample-or-handle)
    (function (data-writer t) (or (simple-array (unsigned-byte 8) (16)) (member :timeout :not-enabled)))
  "DataWriter::unregister_instance (DDS 1.4 §2.2.2.4.2.7) — unregister the instance named by
   SAMPLE-OR-HANDLE: emit a no-payload unregister DATA over the reliable engine, relinquishing this
   writer's ownership of the instance. Per WRITER_DATA_LIFECYCLE (DDS 1.4 §2.2.3.21,
   autodispose_unregistered_instances, default TRUE) the unregister also DISPOSES the instance — the
   DATA carries StatusInfo Disposed|Unregistered (0x03) so readers report NOT_ALIVE_DISPOSED — unless
   the writer's QoS sets autodispose FALSE, in which case it carries only Unregistered (0x02, RTPS 2.5
   §9.6.4.9). Drops the handle from the writer's instance table. Returns the handle, or +RETCODE-TIMEOUT+
   (:timeout) if the bounded cache was full and max_blocking_time elapsed (WP-ASYNC-FLOW backpressure, ADR
   0016 §Backpressure; on :timeout nothing was emitted, the handle is NOT dropped, liveliness not asserted).
   A DISABLED DataWriter refuses with :not-enabled (outside the NOT_ENABLED-safe set, DDS 1.4 §2.2.2.1.1.7)."
  (unless (entity-enabled-p dw) (return-from unregister-instance +retcode-not-enabled+))
  (let ((handle (%resolve-handle dw sample-or-handle))
        (node (dp-node (pub-participant (dw-publisher dw)))))
    (when (eq :timeout (dds.disc:unregister-instance node handle (%writer-autodispose-p dw)))
      (return-from unregister-instance +retcode-timeout+))
    (dds.pal:with-lock ((dw-status-lock dw))
      (remhash handle (dw-instances dw)))
    (assert-liveliness dw)
    handle))

(defun* %resource-reject-reason (dr handle)
    (function (data-reader t) symbol)
  "A SampleRejectedStatusKind keyword if caching a sample for instance HANDLE would
   exceed the reader's RESOURCE_LIMITS (DCPS-cache-level, v1), else NIL. -1 = unlimited."
  (let ((qos (entity-qos dr)))
    (when (typep qos 'dds.qos:qos)
      (let ((max-s (dds.qos:qos-resource-max-samples qos))
            (max-i (dds.qos:qos-resource-max-instances qos))
            (max-spi (dds.qos:qos-resource-max-samples-per-instance qos))
            (cache (dr-cache dr)))
        (cond
          ((and (>= max-s 0) (>= (length cache) max-s)) :rejected-by-samples-limit)
          ((and (>= max-spi 0)
                (>= (count handle cache :test #'equalp
                                        :key (lambda (cs)
                                               (sample-info-instance-handle (cached-sample-info cs))))
                    max-spi))
           :rejected-by-samples-per-instance-limit)
          ((and (>= max-i 0)
                (not (nth-value 1 (gethash handle (dr-instances dr))))
                (>= (hash-table-count (dr-instances dr)) max-i))
           :rejected-by-instances-limit)
          (t nil))))))

(defun* %reader-sample-rejected (dr reason handle)
    (function (data-reader symbol t) t)
  "Bump DR's SAMPLE_REJECTED status (reason + instance handle) via the %notify-status
   chokepoint: set the bitmask bit, trigger the StatusCondition, and fire on_sample_rejected
   if a listener is masked for it."
  (%notify-status dr +status-sample-rejected+
   (lambda ()
     (let ((s (dr-sample-rejected dr)))
       (incf (sample-rejected-status-total-count s))
       (incf (sample-rejected-status-total-count-change s))
       (setf (sample-rejected-status-last-reason s) reason
             (sample-rejected-status-last-instance-handle s) handle)
       (values t
               (when (and (dr-listener dr) (member :sample-rejected (dr-listener-mask dr)))
                 (let ((snapshot (copy-sample-rejected-status s)))
                   (setf (sample-rejected-status-total-count-change s) 0)
                   (lambda () (on-sample-rejected (dr-listener dr) dr snapshot))))))))
  t)

(defun* %reader-instance-rec (dr handle)
    (function (data-reader (simple-array (unsigned-byte 8) (16))) instance-rec)
  "DR's instance-rec for the 16-octet HANDLE (DDS 1.4 §2.2.2.5.1.3), creating a fresh ALIVE
   record (generation counts initialized to zero per §2.2.2.5.1.5) the first time the instance
   is seen. Also seeds the view-state dr-instances entry (nil = not yet accessed) so a synthetic
   lifecycle notification surfaces with view-state NEW just like a first data sample."
  (or (gethash handle (dr-instance-recs dr))
      (progn
        (unless (nth-value 1 (gethash handle (dr-instances dr)))
          (setf (gethash handle (dr-instances dr)) nil))
        (setf (gethash handle (dr-instance-recs dr)) (make-instance-rec)))))

(defun* %enqueue-instance-notification (dr handle rec)
    (function (data-reader (simple-array (unsigned-byte 8) (16)) instance-rec) t)
  "Append a synthetic INVALID-DATA cached-sample to DR's cache for instance HANDLE carrying
   REC's current instance_state + generation counts (DDS 1.4 §2.2.2.5.1.4: a dispose/no-writers
   change yields a SampleInfo with valid_data=FALSE and no associated Data). NOT_READ so read/take
   surface it once; sequence-number 0 (no wire SN — it is an instance-state change, not a sample)."
  (setf (dr-cache dr)
        (nconc (dr-cache dr)
               (list (make-cached-sample
                      :data nil
                      :info (make-sample-info
                             :sample-state :not-read :view-state :new
                             :instance-state (instance-rec-state rec) :valid-data nil
                             :instance-handle handle
                             :disposed-generation-count (instance-rec-disposed-gen-count rec)
                             :no-writers-generation-count (instance-rec-no-writers-gen-count rec)
                             :sequence-number 0)))))
  t)

(defun* %note-not-alive-since (rec)
    (function (instance-rec) t)
  "Stamp REC's NOT-ALIVE-SINCE to now (%lease-now) — the READER_DATA_LIFECYCLE autopurge clock
   (DDS 1.4 §2.2.3.22), read by %autopurge-sweep. Single stamping point for every ALIVE->NOT_ALIVE
   transition (DRY) so the sweep's elapsed-since measurement uses the SAME clock the sweep reads."
  (setf (instance-rec-not-alive-since rec) (%lease-now))
  t)

(defun* %wake-reader-data (dr)
    (function (data-reader) t)
  "Fire DR's on_data_available (if masked) OUTSIDE the status lock, then wake its WaitSets —
   the same DATA_AVAILABLE notification path as the on-sample hook (DDS 1.4 §2.2.4.1)."
  (let ((fire nil))
    (dds.pal:with-lock ((dr-status-lock dr))
      (when (and (dr-listener dr) (member :data-available (dr-listener-mask dr)))
        (setf fire t)))
    (when fire (on-data-available (dr-listener dr) dr))
    (%notify-reader-conditions dr))
  t)

(defun* %on-disc-lifecycle (p wid sn kind key-hash status-flags)
    (function (domain-participant (unsigned-byte 32) integer (member :dispose :unregister)
              t (unsigned-byte 8)) t)
  "ON-LIFECYCLE hook (disc receiver thread): a no-payload dispose/unregister DATA arrived
   (RTPS 2.5 §9.6.4.9). WAKE ONLY — exactly like the on-sample hook (%on-participant-sample):
   the engine has already recorded (kind key-hash status-flags writer-id source-guid) by SN under the node
   lock; this hook must NOT touch the reader cache or instance-recs (those are user-thread state,
   mutated only by %drain — touching them here would race a concurrent read/take/%drain). It just
   fires DATA_AVAILABLE so a waiting reader drains the pending lifecycle change on the user thread.
   The instance-state transition itself is applied on the user thread by %drain (S2).
   WP-N-ENDPOINT-S5 (ADR 0048): the disc lifecycle callback carries only the remote writer EntityId
   (not a full GUID, so no S2 route lookup) — wake EVERY local reader; each drains only its own
   S2-source-GUID-filtered lifecycle change on the user thread, so a spurious wake of a reader with
   nothing pending is benign (level-triggered DATA_AVAILABLE, DDS 1.4 §2.2.4.1). N=1 == the sole reader."
  (declare (ignore wid sn kind key-hash status-flags))
  (dolist (dr (%participant-readers p)) (%wake-reader-data dr))
  t)

(defun* %drain-one-lifecycle (dr node key)
    (function (data-reader t cons) t)
  "Apply ONE pending dispose/unregister lifecycle change at composite KEY (a (GUID . SN) cons, keyed by
   source GUID then SN per RTPS 2.5 §8.3.5.4) on the USER thread (the
   on-sample/%drain discipline — never the receiver thread). Marks SN consumed (exactly-once via
   dr-lifecycle-drained) then applies the DDS 1.4 §2.2.2.5.1.3 reader-side transition to the instance's
   instance-rec from the StatusInfo_t FLAG bits (RTPS 2.5 §9.6.4.9), not only the derived kind: the
   Unregistered bit drops the originating writer from the instance's writers-set, and the instance
   state is the Disposed bit set -> NOT_ALIVE_DISPOSED (STICKY; disposed dominates no-writers,
   §2.2.2.5.1.3, even when Unregistered is also set — the WRITER_DATA_LIFECYCLE autodispose default,
   DDS 1.4 §2.2.3.21), else if the writers-set emptied while still :alive -> NOT_ALIVE_NO_WRITERS. So a
   Disposed|Unregistered (0x03) DROPS the writer AND ends NOT_ALIVE_DISPOSED; a pure Unregistered
   (0x02) of the last writer ends NOT_ALIVE_NO_WRITERS; a pure Dispose (0x01) ends NOT_ALIVE_DISPOSED.
   An invalid-data notification (valid_data=FALSE, §2.2.2.5.1.4) is enqueued ONLY
   when the instance_state actually transitioned (§2.2.2.5.1.4 — these no-data samples surface a CHANGE
   of state); a no-op unregister (writers remain / re-dispose of a disposed instance) produces nothing.
   Returns T if the instance transitioned."
  (push key (dr-lifecycle-drained dr))
  (let ((lc (dds.disc:node-lifecycle-change node key)) (changed nil))
    (when lc
      (destructuring-bind (kind key-hash status-flags wid source-guid) lc
        (declare (ignore kind))
        (when (%handle-p key-hash)
          (let* ((rec (%reader-instance-rec dr key-hash))
                 (old (instance-rec-state rec)))
            ;; The current owner disposing/unregistering its instance relinquishes ownership (DDS 1.4
            ;; §2.2.3.23.1) -> the next sample from the now-highest alive writer reclaims it (lazy).
            ;; Match the FULL 16-octet source GUID, not the EntityId — writers sharing 0x102 on
            ;; different participants must not cross-clear each other (DDS 1.4 §2.2.3.9.2).
            (let ((owner (instance-rec-owner-guid rec)))
              (when (and owner source-guid (equalp source-guid owner))
                (setf (instance-rec-owner-guid rec) nil (instance-rec-owner-strength rec) 0)))
            ;; Apply the instance state from the StatusInfo_t flag bits (RTPS 2.5 §9.6.4.9): Unregistered
            ;; drops the writer; Disposed dominates the resulting state (§2.2.2.5.1.3 / §2.2.3.21).
            (when (logtest status-flags dds.rtps.message:+statusinfo-unregistered+)
              (setf (instance-rec-writers rec) (remove wid (instance-rec-writers rec))))
            (cond
              ((logtest status-flags dds.rtps.message:+statusinfo-disposed+)
               (setf (instance-rec-state rec) :not-alive-disposed))
              ((and (logtest status-flags dds.rtps.message:+statusinfo-unregistered+)
                    (null (instance-rec-writers rec)) (eq old :alive))
               (setf (instance-rec-state rec) :not-alive-no-writers)))
            (unless (eq old (instance-rec-state rec))
              (%note-not-alive-since rec)   ; stamp the autopurge clock on ALIVE->NOT_ALIVE (DDS 1.4 §2.2.3.22)
              (%enqueue-instance-notification dr key-hash rec)
              (setf changed t))))))
    changed))

(defun* %on-writer-vanished (dr wid)
    (function (data-reader (unsigned-byte 32)) t)
  "A matched remote WRITER (EntityId WID) unmatched/vanished: drop it from every instance's
   writers set; any instance thereby left with no writers transitions NOT_ALIVE_NO_WRITERS
   (DDS 1.4 §2.2.2.5.1.3 — the DataReader declares an instance not-alive when it detects no
   live DataWriter writing it) and gets an invalid-data notification (§2.2.2.5.1.4). v1 has one
   user writer per remote participant, so this is the last-writer case. Wakes DATA_AVAILABLE
   once if any instance transitioned."
  (let ((changed nil))
    (maphash
     (lambda (handle rec)
       (when (member wid (instance-rec-writers rec))
         (setf (instance-rec-writers rec) (remove wid (instance-rec-writers rec)))
         (when (and (null (instance-rec-writers rec))
                    (eq (instance-rec-state rec) :alive))
           (setf (instance-rec-state rec) :not-alive-no-writers)
           (%note-not-alive-since rec)   ; stamp the autopurge clock (DDS 1.4 §2.2.3.22)
           (%enqueue-instance-notification dr handle rec)
           (setf changed t))))
     (dr-instance-recs dr))
    (when changed (%wake-reader-data dr)))
  t)

(defun* %reader-revive-instance (dr handle wid)
    (function (data-reader (simple-array (unsigned-byte 8) (16)) t) instance-rec)
  "A data sample for instance HANDLE written by WID arrived: register WID in the instance's
   writers set and revive the instance to ALIVE (DDS 1.4 §2.2.2.5.1.3). A NOT_ALIVE_DISPOSED->
   ALIVE transition bumps disposed_generation_count, a NOT_ALIVE_NO_WRITERS->ALIVE transition
   bumps no_writers_generation_count (§2.2.2.5.1.5). WID may be NIL (an offline-injected sample
   with no recorded writer); then only the state is revived. Returns the (updated) instance-rec."
  (let ((rec (%reader-instance-rec dr handle)))
    (when (and wid (not (member wid (instance-rec-writers rec))))
      (push wid (instance-rec-writers rec)))
    (ecase (instance-rec-state rec)
      (:alive)
      (:not-alive-disposed (incf (instance-rec-disposed-gen-count rec)))
      (:not-alive-no-writers (incf (instance-rec-no-writers-gen-count rec))))
    (setf (instance-rec-state rec) :alive
          (instance-rec-not-alive-since rec) nil)   ; clear the autopurge clock on revival (DDS 1.4 §2.2.3.22)
    rec))

(defun* %reader-exclusive-p (dr)
    (function (data-reader) boolean)
  "T iff the reader DR requests EXCLUSIVE ownership (DDS 1.4 §2.2.3.9.2) — the only case the data
   path arbitrates; a SHARED reader (the default) delivers every writer's samples unchanged."
  (let ((qos (entity-qos dr)))
    (and (typep qos 'dds.qos:qos) (eq :exclusive (dds.qos:qos-ownership qos)))))

(defun* %reader-keeplast-depth (dr)
    (function (data-reader) (or null (integer 1)))
  "DR's HISTORY depth iff the reader is KEEP_LAST (DDS 1.4 §2.2.3.18), else NIL — NIL = KEEP_ALL,
   no per-instance depth cap (the reader keeps every delivered sample, bounded only by RESOURCE_LIMITS)."
  (let ((qos (entity-qos dr)))
    (and (typep qos 'dds.qos:qos)
         (eq :keep-last (dds.qos:qos-history-kind qos))
         (dds.qos:qos-history-depth qos))))

(defun* %reader-instance-oldest (dr handle releasable-only)
    (function (data-reader (simple-array (unsigned-byte 8) (16)) t) (values (integer 0) t))
  "Shared KEEP_LAST scan (DRY for both the copy path %reader-keeplast-drop-oldest and the loan path
   %reader-keeplast-drop-oldest-loan): one O(N) dr-cache pass returning (values VALID-DATA-COUNT OLDEST) for
   instance HANDLE, where VALID-DATA-COUNT is ALL valid-data cached samples of the instance (the depth-cap
   decision, identical on both paths) and OLDEST is the lowest-SN cached sample to drop. When RELEASABLE-ONLY,
   OLDEST is constrained to a :NOT-READ sample (never one already handed to the app via read-loaned) — the
   loan-path UAF guard (the SHMEM slot under an app-held loan must NOT be released); else OLDEST is the lowest-SN
   valid-data sample regardless of read/sample-state (the lossy copy-path drop). Invalid-data notifications
   (sequence-number 0) are not counted. LIMITATION (v1): oldest = min SN is the true age order only for ONE writer
   per instance; with multiple writers SNs alias (RTPS 2.5 §8.3.5.4) and the reader has no merged cross-writer
   order (no source-timestamp / DESTINATION_ORDER) — lifted when DESTINATION_ORDER lands."
  (let ((count 0) (oldest nil) (oldest-sn nil))
    (dolist (cs (dr-cache dr) (values count oldest))
      (let ((info (cached-sample-info cs)))
        (when (and (sample-info-valid-data info)
                   (equalp handle (sample-info-instance-handle info)))
          (incf count)                                                  ; cap counts ALL valid-data (both paths)
          (when (or (not releasable-only) (eq :not-read (sample-info-sample-state info)))
            (let ((sn (sample-info-sequence-number info)))
              (when (or (null oldest-sn) (< sn oldest-sn))
                (setf oldest-sn sn oldest cs)))))))))

(defun* %reader-keeplast-drop-oldest (dr handle depth)
    (function (data-reader (simple-array (unsigned-byte 8) (16)) (integer 1)) t)
  "KEEP_LAST per-instance drop, COPY path (DDS 1.4 §2.2.3.18): if instance HANDLE already holds DEPTH valid-data
   samples in dr-cache, delete that instance's OLDEST (lowest sequence-number) cached sample so the imminent
   append keeps the per-instance count at DEPTH. A LOSSY drop by design — the oldest goes regardless of its
   read/sample-state (distinct from the RESOURCE_LIMITS reject, which stays); safe because a copy-path sample's
   data is a heap struct, NOT a SHMEM-slot loan (so dropping a read-but-held copy frees nothing the app aliases —
   the loan path is %reader-keeplast-drop-oldest-loan). Touches ONLY dr-cache (the instance-rec / view-state
   survive — the instance stays alive across the drop, like take removing a cache entry without forgetting the
   instance). O(N) cache scan via %reader-instance-oldest (DRY), matching the existing %resource-reject count."
  (multiple-value-bind (count oldest) (%reader-instance-oldest dr handle nil)
    (when (and (>= count depth) oldest)
      (setf (dr-cache dr) (delete oldest (dr-cache dr) :test #'eq))))
  t)

(defun* %reader-keeplast-drop-oldest-loan (dr handle depth)
    (function (data-reader (simple-array (unsigned-byte 8) (16)) (integer 1)) t)
  "KEEP_LAST per-instance drop, ZC LOAN path (DDS 1.4 §2.2.3.18; WP-KEYED-FLATDATA, ADR 0017, R6; NOT cleared for
   ship — pending counsel). The loan-aware sibling of %reader-keeplast-drop-oldest: a dropped loaned sample's data
   is a flatdata-view that (a) is registered in the loan registry dr-loans and (b) holds a ZC pool slot at
   refcount>0; a bare dr-cache delete (the copy-path mutation) would orphan the view — gone from dr-cache (so the
   app can never return-loan it) yet still in dr-loans pinning the slot → a slot LEAK until reader-close → ZC pool
   exhaustion (NFR-MEM / NFR-SEC-POSTURE). So the evicted view gets the FULL return-loan teardown: invalidate the
   dr-cache entry + %zc-release the slot + drop it from dr-loans + recycle the view (return-loan does all four
   idempotently — so we do NOT also delete). UAF GUARD: KEEP_LAST drops the instance's OLDEST, but read-loaned is
   non-destructive (it LEAVES :READ samples in dr-cache and hands their views to the app), so the oldest could be a
   view the app still holds — releasing its slot would be a use-after-free for the app's in-place read. We therefore
   constrain the candidate to a :NOT-READ view (RELEASABLE-ONLY t): never release a sample already delivered to the
   app (a take-loaned sample is gone from dr-cache entirely, so this only ever differs from the copy path for a
   read-loaned-but-not-returned view). If every over-depth sample is app-held (no :NOT-READ candidate), nothing is
   released and the new sample appends — a transient over-depth the app resolves by return-loan, the only
   memory-safe choice under the ZC loan contract (the slot is pinned until the app returns it). The depth cap counts
   ALL valid-data (matching the copy path); only the drop is guarded. O(N) scan via %reader-instance-oldest (DRY)."
  (multiple-value-bind (count oldest) (%reader-instance-oldest dr handle t)
    (when (and (>= count depth) oldest)
      (return-loan dr (list (cached-sample-data oldest)))))            ; full teardown (release slot + drop dr-loans + recycle); UAF-safe: oldest is :not-read
  t)

(defun* %reader-keeplast-drop-oldest-secured (dr handle depth)
    (function (data-reader (simple-array (unsigned-byte 8) (16)) (integer 1)) t)
  "KEEP_LAST per-instance drop, SECURED-LOAN path (DDS 1.4 §2.2.3.18; WP-DCPS-SECURED-TAKE-LOAN, ADR 0038 (i)). The
   secured sibling of %reader-keeplast-drop-oldest-loan. Unlike a FlatData view (read IN PLACE off the SHMEM slot),
   a secured sample's cached DATA is an INDEPENDENT deserialized struct — a COPY — so dropping a read-but-held
   sample is never a use-after-free (RELEASABLE-ONLY NIL, the copy-path age order); but the sample still holds a
   secured-loan-handle in dr-secured-loans pinning a decode-pool buffer, so a bare dr-cache delete would ORPHAN the
   loan (a pooled-buffer leak until reader-close -> decode-pool exhaustion, NFR-MEM). The evicted sample gets the
   full type-dispatched return-loan teardown (invalidate the cache entry + node-return-loan the buffer + drop
   dr-secured-loans) when it carries a handle; a carve-fail bare-vector fallback sample (LOAN NIL, no pooled buffer)
   is a plain lossy cache delete (mirrors %reader-keeplast-drop-oldest). O(N) scan via %reader-instance-oldest (DRY)."
  (multiple-value-bind (count oldest) (%reader-instance-oldest dr handle nil)
    (when (and (>= count depth) oldest)
      (let ((loan (cached-sample-loan oldest)))
        (if (dds.disc:secured-loan-handle-p loan)
            (return-loan dr (list loan))                              ; full teardown, type-dispatched to node-return-loan
            (setf (dr-cache dr) (delete oldest (dr-cache dr) :test #'eq))))))   ; carve-fail copy sample: lossy bare drop
  t)

(defun* %guid> (a b)
    (function ((simple-array (unsigned-byte 8) (16)) (simple-array (unsigned-byte 8) (16))) boolean)
  "Lexicographic 16-octet GUID comparison A>B. The EXCLUSIVE same-strength tie-break: DDS 1.4
   §2.2.3.9.2 leaves the choice implementation-defined but REQUIRES it be consistent across all
   readers — comparing the GUID octets is deterministic + identical on every reader."
  (dotimes (i 16 nil)
    (let ((x (aref a i)) (y (aref b i)))
      (cond ((> x y) (return t)) ((< x y) (return nil))))))

(defun* %arbitrate-owner (dr node key handle)
    (function (data-reader t cons (simple-array (unsigned-byte 8) (16)))
              (member :deliver :drop-loser :drop-unmatched))
  "EXCLUSIVE-ownership arbitration for the sample at composite KEY on instance HANDLE (DDS 1.4 §2.2.3.9.2):
   resolve the sample's FULL source GUID -> the writer's (kind strength) from the matches table, then
   return a verdict — :DELIVER, :DROP-LOSER, or :DROP-UNMATCHED. :DELIVER and (re)claim ownership when
   the instance has no current owner, the writer's strength exceeds the owner's, the source IS the
   current owner, or it ties the owner's strength with a higher GUID (the consistent tie-break).
   :DROP-LOSER for a strictly-lower-strength or losing-tie writer whose owner IS resolved — that sample
   is correctly gone, so the caller advances the drain watermark. :DROP-UNMATCHED when the source GUID
   is identified but NOT (yet) in the matches table (its SEDP has not arrived): it cannot own the
   instance YET, so the sample is dropped THIS pass, but the caller must NOT advance the watermark —
   the strength is unresolved, and once the SEDP match arrives a later drain re-evaluates it (the
   reliable engine already ACKed it, so leaving it pending is the only non-lossy choice; never let an
   as-yet-unmatched writer's sample reach the cache and claim ownership ahead of the SEDP). A sample
   with NO recorded source GUID at all (writer unidentifiable) is :DELIVERed (fail-open: never
   false-REJECT data we cannot even attribute). Owner state lives on the instance-rec (lazy recompute:
   a vanished owner is cleared elsewhere, the next sample reclaims)."
  (let ((guid (dds.disc:node-sample-writer-guid node key))
        (rec (%reader-instance-rec dr handle)))
    (if (null guid)
        :deliver                          ; unidentifiable source -> fail-open deliver
        (multiple-value-bind (kind strength) (dds.disc:matched-writer-ownership node guid)
          (declare (ignore kind))
          (if (null strength)
              :drop-unmatched             ; identified but not (yet) matched -> drop, keep pending
          (let ((owner (instance-rec-owner-guid rec)))
            (cond
              ((or (null owner) (equalp guid owner)
                   (> strength (instance-rec-owner-strength rec))
                   (and (= strength (instance-rec-owner-strength rec)) (%guid> guid owner)))
               (setf (instance-rec-owner-guid rec) (copy-seq guid)
                     (instance-rec-owner-strength rec) strength)
               :deliver)
              (t :drop-loser))))))))

(defun* %clear-owner-on-vanish (dr guid)
    (function (data-reader (simple-array (unsigned-byte 8) (16))) t)
  "A matched writer (16-octet GUID) vanished (unmatch / liveliness-lost): clear the EXCLUSIVE owner of
   every instance it owned (DDS 1.4 §2.2.3.9.2 ownership change (c)) so the next sample from the
   now-highest alive writer reclaims ownership (lazy recompute). Leaves the writers-set + instance_state
   to the S2 paths — only the ownership pointer is cleared."
  (maphash (lambda (handle rec)
             (declare (ignore handle))
             (when (and (instance-rec-owner-guid rec) (equalp guid (instance-rec-owner-guid rec)))
               (setf (instance-rec-owner-guid rec) nil (instance-rec-owner-strength rec) 0)))
           (dr-instance-recs dr))
  t)

(defun* %autopurge-instance-delay (dr rec)
    (function (data-reader instance-rec) (or null dds.qos:qos-duration))
  "The applicable READER_DATA_LIFECYCLE autopurge delay for instance REC on reader DR (DDS 1.4
   §2.2.3.22): autopurge_disposed_samples_delay for a NOT_ALIVE_DISPOSED instance,
   autopurge_nowriter_samples_delay for a NOT_ALIVE_NO_WRITERS instance; NIL for an ALIVE instance
   or when the reader's QoS is absent (never purge)."
  (let ((qos (entity-qos dr)))
    (when (typep qos 'dds.qos:qos)
      (ecase (instance-rec-state rec)
        (:alive nil)
        (:not-alive-disposed (dds.qos:qos-autopurge-disposed-samples-delay qos))
        (:not-alive-no-writers (dds.qos:qos-autopurge-nowriter-samples-delay qos))))))

(defun* %autopurge-due-p (rec delay now)
    (function (instance-rec (or null dds.qos:qos-duration) (integer 0)) boolean)
  "T iff NOT_ALIVE instance REC is due for autopurge at time NOW under DELAY (DDS 1.4 §2.2.3.22):
   DELAY is finite (not DURATION_INFINITE, the default — INFINITE never purges) and at least DELAY of
   internal-time has elapsed since the instance went not-alive. The Duration_t->internal-units
   conversion reuses %lease-internal-units (DRY), the same lease arithmetic the liveliness sweep uses."
  (and delay
       (instance-rec-not-alive-since rec)
       (< (dds.qos:qos-duration-sec delay) #x7fffffff)
       (>= (- now (instance-rec-not-alive-since rec)) (%lease-internal-units delay))))

(defun* %autopurge-purge-instance (dr handle)
    (function (data-reader (simple-array (unsigned-byte 8) (16))) t)
  "Purge ALL reader-internal state for instance HANDLE (DDS 1.4 §2.2.3.22): drop its untaken cached
   samples from dr-cache, its instance-rec (state + generation counts + writers-set + owner pointer),
   and its dr-instances view-state entry — so the instance is fully forgotten and a later sample for the
   same key starts a brand-new ALIVE instance (view-state NEW, generation counts reset). The per-writer
   dr-drained high-water is left intact (it is keyed by writer GUID, not instance — §8.3.5.4 — so a
   replayed lower SN is still suppressed while a fresh higher-SN sample still drains)."
  (setf (dr-cache dr)
        (remove handle (dr-cache dr)
                :test #'equalp
                :key (lambda (cs) (sample-info-instance-handle (cached-sample-info cs)))))
  (remhash handle (dr-instance-recs dr))
  (remhash handle (dr-instances dr))
  t)

(defun* %autopurge-sweep (dr)
    (function (data-reader) t)
  "READER_DATA_LIFECYCLE autopurge sweep on the USER/spin thread (DDS 1.4 §2.2.3.22): for each
   NOT_ALIVE instance whose applicable autopurge delay is finite AND has elapsed since the instance went
   not-alive, PURGE it (%autopurge-purge-instance). Both delays default DURATION_INFINITE, so the common
   case is a no-op — no instance is ever purged by default. Run on the DCPS announce cadence (SPIN),
   beside the writer-liveliness/lease sweeps; mutates dr-cache + instance-recs on the user/spin thread
   only (the dr-cache owner thread), never the receiver thread (S2 lock discipline). Snapshots the
   due handles before mutating so the maphash is not modified under iteration."
  (let ((now (%lease-now)) (due '()))
    (maphash
     (lambda (handle rec)
       (when (%autopurge-due-p rec (%autopurge-instance-delay dr rec) now)
         (push handle due)))
     (dr-instance-recs dr))
    (dolist (handle due) (%autopurge-purge-instance dr handle)))
  t)

(defun* %participant-readers (p)
    (function (domain-participant) list)
  "Every local DataReader contained in participant P (across all its Subscribers)."
  (let ((rs '()))
    (dolist (c (dp-children p) rs)
      (when (typep c 'subscriber) (setf rs (append (sub-readers c) rs))))))

;;; WP-N-ENDPOINT-S5 (ADR 0048): per-endpoint disc->DCPS dispatch. A status/listener/wake event
;;; resolves the LOCAL entity it is ABOUT — by the remote's TOPIC (match/unmatch/incompatible) or by
;;; the remote writer GUID's S2 delivery route (liveliness) — never a participant-wide back-ref. A
;;; different-topic participant has <=1 endpoint per topic (same-topic is fail-fast-deferred); an event
;;; with no matching local entity is DROPPED, never mis-delivered to another endpoint.

(defun* %participant-reader-for-topic (p topic-name)
    (function (domain-participant string) (or null data-reader))
  "The local DataReader in P bound to TOPIC-NAME, or NIL (WP-N-ENDPOINT-S5): the per-endpoint
   match/unmatch/incompatible dispatch key. <=1 reader per topic (same-topic deferred), so the first
   match IS the reader; NIL -> the caller drops the event (never mis-delivers to another endpoint)."
  (find topic-name (%participant-readers p)
        :key (lambda (dr) (topic-name (dr-topic dr))) :test #'string=))

(defun* %participant-writer-for-topic (p topic-name)
    (function (domain-participant string) (or null data-writer))
  "The local DataWriter in P bound to TOPIC-NAME, or NIL (WP-N-ENDPOINT-S5): writer-side mirror of
   %participant-reader-for-topic for the match/unmatch/incompatible hooks."
  (find topic-name (%participant-writers p)
        :key (lambda (dw) (topic-name (dw-topic dw))) :test #'string=))

(defun* %participant-reader-by-entity-id (p rid)
    (function (domain-participant (unsigned-byte 32)) (or null data-reader))
  "The local DataReader in P whose engine EntityId is RID, or NIL (WP-N-ENDPOINT-S5): maps an S2
   delivery route's reader-EntityId back to its DCPS DataReader (dr-entity-id)."
  (find rid (%participant-readers p) :key #'dr-entity-id :test #'=))

(defun* %participant-writer-by-entity-id (p wid)
    (function (domain-participant (unsigned-byte 32)) (or null data-writer))
  "The local DataWriter in P whose engine EntityId is WID, or NIL (WP-N-ENDPOINT-2C2, ADR 0048): writer-side
   mirror of %participant-reader-by-entity-id (keyed on dw-entity-id). Maps the matched-local EntityId threaded
   by %fire-match back to its DCPS DataWriter, so PUBLICATION_MATCHED/OFFERED_INCOMPATIBLE_QOS + the §8.5.2
   crypto-token + the durability match-side land on the RIGHT same-topic writer (not the first-by-topic)."
  (find wid (%participant-writers p) :key #'dw-entity-id :test #'=))

(defun* %participant-readers-for-writer-guid (p guid)
    (function (domain-participant (simple-array (unsigned-byte 8) (16))) list)
  "The local DataReader(s) matched to remote writer GUID (WP-N-ENDPOINT-S5): reuse the S2 delivery
   route (%reader-routes-for) -> reader-EntityId(s) -> DCPS reader by dr-entity-id. <=1 today
   (same-topic fence). NOTE: %reader-routes-for falls back to the PRIMARY reader on an empty route
   (not NIL), so at N=1 this returns the sole reader (byte-identical). This is only called for a
   MATCHED remote writer (liveliness/lifecycle fire only after %reader-route-add at the match), so at
   N>=2 the route is always non-empty and resolves the correct matched reader — the primary fallback
   is unreachable there. Correctness rests on the matched=>routed invariant, not on an empty-route drop."
  (loop for pair in (dds.disc::%reader-routes-for (dp-node p) guid)
        for dr = (%participant-reader-by-entity-id p (car pair))
        when dr collect dr))

;;;; ---- WP-FLATDATA-ZC-LOAN literal-0-copy loan API (FR-PF-3/4, R6, ADR 0017) ----
;;;; NOT cleared for ship — pending counsel (R6); see ADR 0017.

(defun* %flatdata-size (ts)
    (function (t) (or null (integer 0)))
  "WP-FLATDATA-ZC-LOAN (R6, ADR 0017): the FINAL fixed-size FlatData SerializedPayload size (+<type>-flatdata-size+,
   the loan-acquire lower bound for PAYLOAD-LEN) for type-support TS, or NIL when TS is not a :flatdata type. Reads
   the flatdata-layout size the codegen recorded; the layout IS the +size+ oracle."
  (let ((fo (dds.types:type-support-flatdata-offset ts)))
    (and (dds.types:flatdata-layout-p fo) (dds.types:flatdata-layout-size fo))))

(defun* %loan-view (dr pool-sap base-offset len slot gen)
    (function (data-reader t (integer 0) (integer 0) (integer 0) (unsigned-byte 32)) dds.types:flatdata-view)
  "WP-FLATDATA-ZC-LOAN (R6, ADR 0017): a flatdata-view over the live slot, drawn from DR's per-reader freelist
   (no per-sample GC-heap alloc; NFR-MEM) and initialised in place — SLOT-SAP=POOL-SAP, BASE-OFFSET (the XCDR2
   body start within the segment), LEN (the body length), + the loan handle (POOL-SAP/SLOT/GEN) for return-loan.
   Recycled by return-loan. NOT cleared for ship — pending counsel (R6)."
  (let ((v (or (pop (dr-view-freelist dr)) (dds.types:make-flatdata-view))))
    (setf (dds.types:flatdata-view-slot-sap v) pool-sap
          (dds.types:flatdata-view-base-offset v) base-offset
          (dds.types:flatdata-view-len v) len
          (dds.types:flatdata-view-pool-sap v) pool-sap
          (dds.types:flatdata-view-slot-index v) slot
          (dds.types:flatdata-view-generation v) gen)
    v))

(defun* %loan-instance-handle (ts view sn sguid)
    (function (t dds.types:flatdata-view integer t) (simple-array (unsigned-byte 8) (16)))
  "WP-FLATDATA-ZC-LOAN (R6, ADR 0017): a 16-octet instance handle for a loaned FlatData VIEW. WP-KEYED-FLATDATA:
   for a KEYED FlatData type (TS's key-hash non-NIL) this is the REAL per-key keyhash — key-hash-<name>-fd reads
   the @key members straight off the loaned VIEW (the -fd accessors dual-dispatch view/buffer) and serializes them
   big-endian (RTPS 2.5 §9.6.4.8), byte-identical to what a non-FlatData peer computes — so two same-key samples
   share one handle (no SN-fold aliasing), enabling correct NEW/NOT_NEW view-state + per-instance KEEP_LAST. For a
   NO_KEY type (key-hash NIL) it keeps the synthetic NON-ALIASING handle: low 8 octets = the RTPS SN; high 8 octets
   = an FNV-1a fold of the source writer's 16-octet GUID (SGUID). Folding the GUID de-aliases two co-located writers
   — each SN-stream restarts at 1, so SN alone (the earlier v1) would collide their handles and flip a NEW/NOT_NEW
   view-state (cosmetic for NO_KEY, but the handle must still be unique per source, §8.3.5.4: SN is per-writer).
   When SGUID is NIL (an un-attributed sample) the fold is the FNV-1a basis, so the handle still differs from any
   GUID-bearing writer's. Same 16-octet alloc on either branch — no 0-alloc regression (make mem measures the CDR
   path, not this DCPS loan-handle). NOT cleared for ship — pending counsel (R6)."
  (let ((kh (dds.types:type-support-key-hash ts)))
    (when kh (return-from %loan-instance-handle (funcall kh view))))   ; keyed: the real per-key keyhash off the view (RTPS 2.5 §9.6.4.8)
  (let ((h (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))
        (fold 14695981039346656037))                                   ; FNV-1a 64-bit offset basis
    (when (typep sguid '(array (unsigned-byte 8) (*)))
      (dotimes (i (length sguid))                                      ; fold the 16-octet source GUID -> 64 bits
        (setf fold (ldb (byte 64 0) (* (logxor fold (aref sguid i)) 1099511628211)))))
    (dotimes (i 8) (setf (aref h i) (ldb (byte 8 (* 8 i)) sn)))        ; low 8 = SN
    (dotimes (i 8 h) (setf (aref h (+ 8 i)) (ldb (byte 8 (* 8 i)) fold)))))  ; high 8 = GUID fold (de-alias)

(defun* %drain-one-loan (dr ts key marker sn sguid)
    (function (data-reader t cons dds.disc:zc-loan-marker integer t) t)
  "WP-FLATDATA-ZC-LOAN (R6, ADR 0017; NOT cleared for ship — pending counsel): turn an UNRESOLVED ZC-LOAN-MARKER
   (Task D, stored by the receiver thread WITHOUT copying/releasing) into a literal-0-copy delivery. Acquire the
   slot for read (%zc-acquire-for-read — generation/bounds validated, NO refcount inc: the loan is already held by
   the writer's refcount from %zc-loan through the receiver store to here); validate PAYLOAD-LEN >= the type's
   +flatdata-size+ (a short slot ⇒ a stale/forged ref ⇒ DROP, best-effort, slot left for force-reclaim); build a
   flatdata-view (base = PAYLOAD-BASE + 4, past the encap header, to the XCDR2 body; len = body length) from the
   freelist; RECORD it in the loan registry (dr-loans) so return-loan / reader-close release it; and append a
   cached-sample carrying the VIEW (read in place via <name>-<field>-fd). Registering at DRAIN time (not at
   take-loaned) means a drained-but-never-taken loan is still released at reader-close (no refcount leak). The
   per-writer watermark advances for every outcome (the reliable engine already ACKed; never retransmit). NOT
   cleared for ship — pending counsel (R6)."
  (multiple-value-bind (pool-sap slot gen payload-len payload-base)
      (dds.xport.zerocopy::%zc-acquire-for-read (dds.disc:zc-loan-marker-pool-sap marker)
                                                (dds.disc:zc-loan-marker-slot-index marker)
                                                (dds.disc:zc-loan-marker-generation marker))
    (let ((min (%flatdata-size ts)))
      (when (and pool-sap (or (null min) (>= payload-len min)))   ; stale/forged/short -> drop (best-effort)
        (let* ((view (%loan-view dr pool-sap (+ payload-base 4) (max 0 (- payload-len 4)) slot gen))
               (handle (%loan-instance-handle ts view sn sguid))       ; keyed: real per-key keyhash off the view; NO_KEY: SN+GUID fold
               (rec (%reader-revive-instance dr handle (dds.disc:node-sample-writer
                                                        (dp-node (sub-participant (dr-subscriber dr))) key))))
          (push view (dr-loans dr))                                ; register BEFORE delivery (reader-close safety)
          (let ((depth (%reader-keeplast-depth dr)))
            (when depth (%reader-keeplast-drop-oldest-loan dr handle depth)))   ; KEEP_LAST per-instance drop, LOAN-aware: releases the evicted view's loan, not a bare delete (DDS 1.4 §2.2.3.18); UAF-guarded (never an app-held :read view); for NO_KEY FlatData the per-(GUID,SN)-unique handle means the cap never fires
          (setf (dr-cache dr)
                (nconc (dr-cache dr)
                       (list (make-cached-sample
                              :data view
                              :info (make-sample-info
                                     :sample-state :not-read :view-state :new
                                     :instance-state (instance-rec-state rec) :valid-data t
                                     :instance-handle handle :sequence-number sn
                                     :disposed-generation-count (instance-rec-disposed-gen-count rec)
                                     :no-writers-generation-count (instance-rec-no-writers-gen-count rec)))))))))
    (when sguid                                                    ; advance the per-writer watermark (best-effort: ACKed, never retransmit)
      (setf (gethash sguid (dr-drained dr)) (max sn (gethash sguid (dr-drained dr) 0)))))
  t)

(defun* %drain-one-secured (dr node ts key loan sn sguid)
    (function (data-reader t t cons dds.disc:secured-loan-handle integer t) t)
  "WP-DCPS-SECURED-TAKE-LOAN (ADR 0038 residual (i)): drain ONE secured sample whose disc-node store slot is a
   dds.disc:secured-loan-handle (the decode-pool loan the receiver thread built via decode-serialized-payload-into
   — zero per-sample decrypt-output alloc). The DCPS-level win is the DECODE BUFFER: the plaintext is read IN PLACE
   from the pooled buffer (secured-loan-bytes + secured-loan-handle-len) over [0, LEN) — no allocating decrypt
   vector. The typed deserialize copy PERSISTS (Copy #2): a plain XCDR2 secured payload must still be deserialized
   into an application struct, so DATA is an INDEPENDENT struct and the honest scope is 'zero-decode-buffer-alloc
   secured read via the loan API', NOT a literal zero-copy read. Mirrors %drain-one-loan: revive the instance,
   KEEP_LAST-drop, register the LOAN handle in the SEPARATE dr-secured-loans registry BEFORE delivery (so a
   drained-but-never-taken loan is still swept at reader-close), and append a cached-sample carrying the struct as
   DATA and the handle as LOAN (for the type-dispatched return). Like %drain-one-loan the loan path does not apply
   the content-filter / RESOURCE_LIMITS / EXCLUSIVE-ownership arbitration (the disc-node decode pool is the hard
   resource bound); the per-writer watermark advances for every outcome (the reliable engine already ACKed)."
  (let* ((len (dds.disc:secured-loan-handle-len loan))
         (ob (or (dr-secured-scratch dr)
                 (setf (dr-secured-scratch dr)
                       (dds.core.buffer:octet-buffer-over (dds.disc:secured-loan-bytes loan)))))
         (data (progn                                              ; repoint the reusable wrapper at THIS pooled buffer, bound to [0,len) (zero per-sample cons; NFR-SEC-POSTURE bounds)
                 (setf (dds.core.buffer:octet-buffer-vec ob) (dds.disc:secured-loan-bytes loan)
                       (dds.core.buffer:octet-buffer-capacity ob) len)
                 (%deserialize-payload ts ob)))
         (handle (%instance-handle ts data))
         (rec (%reader-revive-instance dr handle (dds.disc:node-sample-writer node key))))
    (push loan (dr-secured-loans dr))                             ; register the LOAN handle BEFORE delivery (reader-close safety)
    (let ((depth (%reader-keeplast-depth dr)))
      (when depth (%reader-keeplast-drop-oldest-secured dr handle depth)))
    (setf (dr-cache dr)
          (nconc (dr-cache dr)
                 (list (make-cached-sample
                        :data data
                        :loan loan
                        :info (make-sample-info
                               :sample-state :not-read :view-state :new
                               :instance-state (instance-rec-state rec) :valid-data t
                               :instance-handle handle :sequence-number sn
                               :disposed-generation-count (instance-rec-disposed-gen-count rec)
                               :no-writers-generation-count (instance-rec-no-writers-gen-count rec)))))))
  (when sguid
    (setf (gethash sguid (dr-drained dr)) (max sn (gethash sguid (dr-drained dr) 0))))
  t)

(defun* take-loaned (dr)
    (function (data-reader) (values list list))
  "DataReader::take by LOAN — WP-FLATDATA-ZC-LOAN literal-0-copy RX (FR-PF-3/4, NFR-PERF-7, R6, ADR 0017; NOT
   cleared for ship — pending counsel). Drain pending changes; for each sample that is an UNRESOLVED ZC-ref on a
   loan-capable FlatData reader (Task D), the drain has already acquired the slot for read (%zc-acquire-for-read,
   no copy) and built a flatdata-view recorded in the loan registry. take-loaned REMOVES the returned samples
   from the cache (mirrors take-samples) and returns (values DATA-LIST LOANS) where DATA-LIST is the per-sample
   data (a flatdata-view for a loaned sample — read fields via <name>-<field>-fd directly off the writer's SHMEM
   slot, LITERAL 0 intra-host copies — or the deserialized struct for any copy-backed sample mixed in) and LOANS
   is the list of flatdata-views to hand back to return-loan (NIL for a copy-backed sample). SLOT LIFETIME: the
   slot is held by the writer's refcount from %zc-loan, never released by the receiver thread, until return-loan
   (or reader-close) %zc-releases it — so the app's in-place read can never race a writer force-reclaim
   (force-reclaim skips refcount>0). The app MUST return-loan the views when done (a leaked loan pins a slot ⇒
   the writer's pool eventually falls back to non-ZC — graceful, never a wedge). NOT cleared for ship — pending
   counsel (R6)."
  (%drain dr)
  (let ((data '()) (loans '()) (touched '()))
    (dolist (cs (dr-cache dr))
      (let* ((info (cached-sample-info cs)) (d (cached-sample-data cs))
             (handle (sample-info-instance-handle info)))
        (setf (sample-info-view-state info) (if (gethash handle (dr-instances dr)) :not-new :new))
        (pushnew handle touched :test #'equalp)
        (setf (sample-info-sample-state info) :read)
        (push d data)
        (cond ((dds.types:flatdata-view-p d) (push d loans))     ; FlatData: the view is both DATA and loan (ADR 0017)
              ((dds.disc:secured-loan-handle-p (cached-sample-loan cs)) (push (cached-sample-loan cs) loans)))))   ; secured: the pooled-buffer handle (ADR 0038 (i)); NIL otherwise
    (dolist (h touched) (setf (gethash h (dr-instances dr)) t))
    (setf (dr-cache dr) '())                                    ; take removes ALL drained samples
    (values (nreverse data) (nreverse loans))))

(defun* read-loaned (dr)
    (function (data-reader) (values list list))
  "DataReader::read by LOAN — WP-FLATDATA-ZC-LOAN (FR-PF-3/4, R6, ADR 0017; NOT cleared for ship — pending
   counsel). Like take-loaned but LEAVES the samples in the cache (mirrors read-samples vs take-samples): returns
   (values DATA-LIST LOANS) for the cached samples, marking each READ. The SAME loan-registry views are returned
   each call until return-loan releases them; the app still returns each view once (return-loan is idempotent, so
   a view returned after a read-then-take is a safe no-op). NOT cleared for ship — pending counsel (R6)."
  (%drain dr)
  (let ((data '()) (loans '()) (touched '()))
    (dolist (cs (dr-cache dr))
      (let* ((info (cached-sample-info cs)) (d (cached-sample-data cs))
             (handle (sample-info-instance-handle info)))
        (setf (sample-info-view-state info) (if (gethash handle (dr-instances dr)) :not-new :new))
        (pushnew handle touched :test #'equalp)
        (setf (sample-info-sample-state info) :read)
        (push d data)
        (cond ((dds.types:flatdata-view-p d) (push d loans))     ; FlatData: the view is both DATA and loan (ADR 0017)
              ((dds.disc:secured-loan-handle-p (cached-sample-loan cs)) (push (cached-sample-loan cs) loans)))))   ; secured: the pooled-buffer handle (ADR 0038 (i))
    (dolist (h touched) (setf (gethash h (dr-instances dr)) t))
    (values (nreverse data) (nreverse loans))))

(defun* return-loan (dr loans)
    (function (data-reader list) t)
  "DataReader::return_loan — WP-FLATDATA-ZC-LOAN (FR-PF-3/4, R6, ADR 0017; NOT cleared for ship — pending
   counsel). Release each loaned flatdata-view in LOANS: INVALIDATE its cache entry (drop the cached-sample(s)
   in dr-cache that still reference the view — read-loaned LEAVES them, so the entry would otherwise outlive the
   loan), %zc-release the slot (refcount→ on the 1→0 edge frees it back to the writer's pool), clear it from the
   loan registry (dr-loans), and recycle the view struct to the per-reader freelist (no GC churn). After return,
   BOTH the view AND its cache entry are invalidated: a returned loan is never re-read — once a view is recycled
   to the freelist, %loan-view may pop+re-init it for a NEW slot, so a surviving stale cache entry would alias
   the new sample's bytes (a WRONG-BYTES stale read); dropping the entry here makes reading a returned loan a
   no-op (the sample is gone from the cache), never a stale read. IDEMPOTENT / double-return-safe: a view NOT in
   the registry (already returned, or never loaned — e.g. a copy-backed sample's NIL) is skipped without a
   second %zc-release and without a second cache scan, and %zc-release itself is generation-validated (a second
   release of an already-freed/regenerated slot is a validated no-op). So return-loan(loans) twice, or returning
   a view after a read-then-take, is safe. NOT cleared for ship — pending counsel (R6).
   WP-DCPS-SECURED-TAKE-LOAN (ADR 0038 residual (i)): each loan is released via a STRICT TYPE DISPATCH — a
   flatdata-view (ADR 0017) goes to %zc-release; a dds.disc:secured-loan-handle (the zero-decode-buffer-alloc
   secured loan) goes to dds.disc:node-return-loan and is NEVER %zc-released (and a view is never node-return-loaned).
   The secured handle is SINGLE-OWNER (the disc-node registry is the authoritative owner; DCPS holds one reference
   and returns once): the dr-secured-loans membership check plus node-return-loan's own idempotence (reg-index<0 &
   buffer NIL -> no-op) make a double-return / a return-then-close a safe no-op — no double-free. The cache entry is
   invalidated (by cached-sample-loan) BEFORE the disc-node recycles the pooled buffer, so a subsequent in-place
   read can never race a pool recycle (no UAF; the deserialized struct in DATA is an independent copy, so it stays
   valid regardless)."
  (dolist (v loans)
    (cond
      ((and (dds.types:flatdata-view-p v) (member v (dr-loans dr)))       ; FlatData ZC loan (ADR 0017) -> %zc-release, exactly once
       (setf (dr-cache dr) (delete v (dr-cache dr) :key #'cached-sample-data)) ; invalidate the cache entry BEFORE recycle (no stale read)
       (dds.xport.zerocopy::%zc-release (dds.types:flatdata-view-pool-sap v)
                                        (dds.types:flatdata-view-slot-index v)
                                        (dds.types:flatdata-view-generation v))
       (setf (dr-loans dr) (delete v (dr-loans dr)))
       (push v (dr-view-freelist dr)))                                    ; recycle (NFR-MEM)
      ((and (dds.disc:secured-loan-handle-p v) (member v (dr-secured-loans dr)))   ; secured decode loan (ADR 0038 (i)) -> node-return-loan, NEVER %zc-release (strict type dispatch)
       (setf (dr-cache dr) (delete v (dr-cache dr) :key #'cached-sample-loan))     ; invalidate the cache entry BEFORE the disc-node recycles the pooled buffer (no dangling in-place read)
       (dds.disc:node-return-loan (dp-node (sub-participant (dr-subscriber dr))) v) ; the disc-node is the single owner + idempotent (reg-index<0 & buffer NIL -> no-op): frees the pooled buffer + purges the store entry
       (setf (dr-secured-loans dr) (delete v (dr-secured-loans dr))))))
  t)

(defun* return-all-loans (dr)
    (function (data-reader) t)
  "WP-FLATDATA-ZC-LOAN reader-close safety (FR-PF-3/4, R6, ADR 0017): return EVERY outstanding loan in DR's
   registries (return-loan over a snapshot of BOTH dr-loans and, per WP-DCPS-SECURED-TAKE-LOAN / ADR 0038 (i),
   dr-secured-loans) so reader-close / delete-participant leaves NO held refcount that would pin the writer's ZC
   pool AND no acquired secured decode buffer outside its pool (the secured plaintext is released — no lingering
   plaintext, no leak). Called BEFORE the engine stop-node detaches the reader-side pool mapping (the views' SAP
   must still be valid for the final %zc-release; the secured handles are released before the decode arena is torn
   down). A reader that drained secured samples but never took/returned them is swept here; stop-node's own
   dds.disc:node-return-all-loans back-stops any handle the DCPS layer never registered. NOT cleared for ship —
   pending counsel (R6)."
  (return-loan dr (append (copy-list (dr-loans dr)) (copy-list (dr-secured-loans dr))))   ; WP-DCPS-SECURED-TAKE-LOAN (ADR 0038 (i)): sweep BOTH registries, each released via its own type-dispatched path
  t)

(defun* %drain-one-sample (dr node ts key)
    (function (data-reader t t cons) t)
  "Apply ONE pending data sample at composite (GUID . SN) KEY: deserialize, drop it on a
   ContentFilteredTopic miss, reject it on RESOURCE_LIMITS (SAMPLE_REJECTED), DROP it on a lost
   EXCLUSIVE-ownership arbitration (DDS 1.4 §2.2.3.9.2 — only the highest-strength owner's samples reach
   the cache; a dropped writer is still registered in the writers-set so liveliness/no-writers tracks
   it, but its data is neither delivered nor used to revive the instance), else REVIVE its instance to
   ALIVE and register its writer (DDS 1.4 §2.2.2.5.1.3: a NOT_ALIVE_DISPOSED->ALIVE or
   NOT_ALIVE_NO_WRITERS->ALIVE transition bumps the matching generation count, §2.2.2.5.1.5) and append
   a fresh NOT_READ SampleInfo carrying the instance's current instance_state + generation counts. The
   sample is marked consumed (exactly-once via the PER-WRITER dr-drained high-water — each writer GUID
   has its own monotone SN mark, §8.3.5.4: an SN is unique only within one writer, so two writers
   sharing EntityId 0x102 must not share a high-water) for EVERY outcome EXCEPT a :DROP-UNMATCHED
   EXCLUSIVE verdict: that sample is from an identified-but-not-yet-SEDP-matched writer whose strength
   is unresolved (DDS 1.4 §2.2.3.9.2), so the watermark is LEFT PENDING — the reliable engine already
   ACKed it and will never retransmit, so advancing the watermark would lose it permanently; a later
   drain re-evaluates it once the match completes and the strength is known. A SECURED-LOAN-HANDLE store slot
   (WP-DCPS-SECURED-TAKE-LOAN, ADR 0038 (i): a secured loan-capable reader) is dispatched to %drain-one-secured —
   the plaintext is deserialized IN PLACE from the pooled decode buffer (no per-sample decrypt-output alloc) and the
   handle is registered in dr-secured-loans; a bare-vector store slot (the non-secured / carve-fail path) falls
   through to the allocating %deserialize-sample below, byte-identical."
  (let ((sguid (dds.disc:node-sample-writer-guid node key))
        (sn (dds.disc:node-sample-key-sn key))
        (advance t))                       ; advance the per-writer watermark unless arbitration keeps it pending
  (let ((bytes (dds.disc:node-sample node key)))
    (when (dds.disc:zc-loan-marker-p bytes)            ; WP-FLATDATA-ZC-LOAN (R6, ADR 0017): an UNRESOLVED ZC ref -> acquire a literal-0-copy view, never deserialize
      (%drain-one-loan dr ts key bytes sn sguid)
      (return-from %drain-one-sample t))
    (when (dds.disc:secured-loan-handle-p bytes)       ; WP-DCPS-SECURED-TAKE-LOAN (ADR 0038 (i)): a secured decode loan -> deserialize IN PLACE from the pooled buffer, register the handle, never allocate a decrypt vector
      (%drain-one-secured dr node ts key bytes sn sguid)
      (return-from %drain-one-sample t))
    (when bytes
      (let ((data (%deserialize-sample ts bytes)))
        ;; ContentFilteredTopic: drop reader-side a sample failing the filter.
        (when (or (null (dr-filter dr)) (funcall (dr-filter dr) data))
          (let* ((handle (%instance-handle ts data))
                 (reason (%resource-reject-reason dr handle))
                 (verdict (if (and (null reason) (%reader-exclusive-p dr))
                              (%arbitrate-owner dr node key handle)
                              :deliver)))
            (cond
              (reason
               ;; RESOURCE_LIMITS would be exceeded -> reject (SAMPLE_REJECTED).
               (%reader-sample-rejected dr reason handle))
              ((eq verdict :drop-unmatched)
               ;; Source writer identified but not yet SEDP-matched -> keep pending, do NOT advance.
               (setf advance nil))
              ((eq verdict :drop-loser)
               ;; Lost EXCLUSIVE arbitration (owner resolved) -> DROP the data, but still register the writer.
               (let ((wid (dds.disc:node-sample-writer node key)) (rec (%reader-instance-rec dr handle)))
                 (when (and wid (not (member wid (instance-rec-writers rec))))
                   (push wid (instance-rec-writers rec)))))
              (t
                (let ((rec (%reader-revive-instance dr handle (dds.disc:node-sample-writer node key)))
                      (depth (%reader-keeplast-depth dr)))
                  (when depth (%reader-keeplast-drop-oldest dr handle depth))   ; KEEP_LAST per-instance drop (DDS 1.4 §2.2.3.18) before append
                  (setf (dr-cache dr)
                        (nconc (dr-cache dr)
                               (list (make-cached-sample
                                      :data data
                                      :info (make-sample-info
                                             :sample-state :not-read :view-state :new
                                             :instance-state (instance-rec-state rec) :valid-data t
                                             :instance-handle handle :sequence-number sn
                                             :disposed-generation-count (instance-rec-disposed-gen-count rec)
                                             :no-writers-generation-count (instance-rec-no-writers-gen-count rec))))))))))))))
    (when (and sguid advance)
      (setf (gethash sguid (dr-drained dr)) (max sn (gethash sguid (dr-drained dr) 0)))))
  t)

(defun* %drain (dr)
    (function (data-reader) t)
  "Pull newly-received changes from the engine on the USER thread and apply them in UNIFIED
   SEQUENCE-NUMBER ORDER. Data samples and dispose/unregister lifecycle changes share ONE writer SN
   space (each lifecycle change occupies a real SN), so they form ONE ordered CacheChange stream per
   writer (DDS 1.4 §2.2.2.5 / RTPS 2.5 §8.7.4) — applying them in SN order is the conformant behaviour
   and is what makes a dispose-then-revive (revive at the higher SN wins -> ALIVE) and a
   revive-then-dispose (dispose at the higher SN wins -> NOT_ALIVE_DISPOSED) land correctly within a
   single drain pass. Pending data SNs (above the dr-drained high-water mark) and pending lifecycle SNs
   (not yet in dr-lifecycle-drained) are merged and visited in SN order; each data SN runs
   %drain-one-sample and each lifecycle SN runs %drain-one-lifecycle, each maintaining its own
   exactly-once discipline. Both streams are drained on the user thread so the reader cache +
   instance-recs are never mutated off-thread (S2)."
  (let* ((node (dp-node (sub-participant (dr-subscriber dr))))
         (ts (topic-type-support (dr-topic dr)))
         (rid (dr-entity-id dr))
         ;; WP-N-ENDPOINT-S2 (ADR 0048): the SOURCE-GUID FILTER — the data-corruption fix. When N>=2 local readers
         ;; share this node's ONE received-sample store, keep a stored key for THIS reader ONLY when the sample's
         ;; source writer GUID is matched to THIS reader (node-reader-matches-writer-p). So each reader deserializes
         ;; ONLY its own topic's bytes under ITS type-support — a reader NEVER decodes a sibling reader's sample
         ;; (silent struct garbage / OOB crash). At N<=1 the predicate is a PASS-THROUGH (byte-identical to pre-S2:
         ;; the sole reader drains every stored sample, exactly as before). A NULL source GUID (never produced for a
         ;; real stored data sample — %deliver-user-sample always records it) is NOT attributable at N>=2, so it is
         ;; filtered out (fail-closed against a cross-topic leak); at N<=1 it passes (unchanged).
         (multi (> (dds.disc:node-user-reader-count node) 1))
         (data-keys (remove-if-not
                     (lambda (key)
                       (let ((g (dds.disc:node-sample-writer-guid node key)))
                         (and (or (not multi)
                                  (and g (dds.disc:node-reader-matches-writer-p node rid g)))
                              (or (null g)
                                  ;; WP-N-ENDPOINT-2C3 (ADR 0048/0017; MEMORY-SAFETY): gate on max(per-writer
                                  ;; dr-drained, the ZC-joiner match-time high-water) so a mid-stream ZC joiner
                                  ;; NEVER drains a marker delivered before it joined (whose demux %zc-bump did not
                                  ;; count it -> its %zc-release would underflow the refcount = cross-reader UAF).
                                  ;; The watermark is 0 for the first reader / non-loan nodes -> byte-identical.
                                  (> (dds.disc:node-sample-key-sn key)
                                     (max (gethash g (dr-drained dr) 0)
                                          (dds.disc:node-reader-join-watermark node rid g)))))))
                     (dds.disc:node-sample-sns node)))
         (life-keys (remove-if-not
                     (lambda (key)
                       (or (not multi)
                           (dds.disc:node-reader-matches-writer-p node rid (car key))))
                     (set-difference (dds.disc:node-lifecycle-sns node) (dr-lifecycle-drained dr)
                                     :test #'equalp)))
         ;; Order by raw RTPS SN (extracted from each composite (GUID . SN) key) so a dispose/revive from
         ;; one writer still lands in §2.2.2.5 SN order (§8.3.5.4: SN is per-writer).
         (pending (sort (nconc (mapcar (lambda (key) (list (dds.disc:node-sample-key-sn key) :data key)) data-keys)
                               (mapcar (lambda (key) (list (dds.disc:node-sample-key-sn key) :lifecycle key)) life-keys))
                        #'< :key #'car)))
    (dolist (entry pending)
      (ecase (second entry)
        (:data (%drain-one-sample dr node ts (third entry)))
        (:lifecycle (%drain-one-lifecycle dr node (third entry)))))
    t))

(defun* %where-any (sample)
    (function (t) (eql t))
  "The default read/take WHERE predicate — selects every sample (no query filter)."
  (declare (ignore sample))
  t)

(defun* %release-secured-copy-loan (dr node cs)
    (function (data-reader t cached-sample) t)
  "WP-DCPS-SECURED-TAKE-LOAN (ADR 0038 (i)): the COPY-API loan release. If cached-sample CS carries a secured decode
   loan (cached-sample-loan is a dds.disc:secured-loan-handle), release it NOW — node-return-loan frees the pooled
   decode buffer + purges the store entry — drop it from dr-secured-loans, and clear CS's loan slot so a later
   return-loan / reader-close is a no-op on this sample. The standard read/take COPY API can release-after-snapshot
   because the returned DATA is an INDEPENDENT deserialized struct (Copy #2), read exactly once at drain: freeing the
   pooled plaintext buffer never invalidates it. This restores a secured copy-API reader to UNBOUNDED operation (the
   pooled buffer is reused per sample) — without it the unconditional secured loan opt-in would pin one decode-pool
   buffer per drained sample until reader-close (decode-pool exhaustion -> writer backpressure / SAMPLE_REJECTED).
   STRICT TYPE DISPATCH: ONLY a secured-loan-handle is released here; a flatdata-view is NEVER touched by the copy
   API (its DATA aliases the SHMEM slot, so an early release would be a use-after-free — the FlatData copy-API
   behavior is left exactly as-is, its slot pinned until the app return-loans it)."
  (let ((loan (cached-sample-loan cs)))
    (when (dds.disc:secured-loan-handle-p loan)
      (dds.disc:node-return-loan node loan)
      (setf (dr-secured-loans dr) (delete loan (dr-secured-loans dr))
            (cached-sample-loan cs) nil)))
  t)

(defun* read-samples (dr &key (states '(:read :not-read)) (where #'%where-any))
    (function (data-reader &key (:states list) (:where function)) (or list (member :not-enabled)))
  "DataReader::read — return the cached samples whose sample-state is in STATES
   (default ANY_SAMPLE_STATE, both read + not-read, per DDS 1.4) and whose data
   satisfies WHERE (a predicate over the deserialized sample; %where-any by default —
   the query-condition filter for read_w_condition) WITHOUT removing them; mark each
   READ and set its SampleInfo view-state (NEW the first time the instance is accessed,
   else NOT_NEW). Returns a list of cached-sample (data + info). WP-DCPS-SECURED-TAKE-LOAN
   (ADR 0038 (i)): a returned secured sample's decode loan is released here (release-after-snapshot,
   %release-secured-copy-loan) — the sample STAYS in the cache (its DATA struct is independent + still
   readable), so a secured copy-API reader recycles the pooled buffer per sample instead of pinning it.
   A DISABLED DataReader refuses the read with :not-enabled (outside the NOT_ENABLED-safe set,
   DDS 1.4 §2.2.2.1.1.7, S2.T3)."
  (unless (entity-enabled-p dr) (return-from read-samples +retcode-not-enabled+))
  (%drain dr)
  (let ((out '()) (touched '())
        (node (dp-node (sub-participant (dr-subscriber dr)))))
    (dolist (cs (dr-cache dr))
      (let ((info (cached-sample-info cs)))
        (when (and (member (sample-info-sample-state info) states)
                   (funcall where (cached-sample-data cs)))
          (let ((handle (sample-info-instance-handle info)))
            (setf (sample-info-view-state info)
                  (if (gethash handle (dr-instances dr)) :not-new :new))
            (pushnew handle touched :test #'equalp))
          (setf (sample-info-sample-state info) :read)
          (%release-secured-copy-loan dr node cs)   ; release the secured decode loan (data struct is independent); FlatData view untouched
          (push cs out))))
    (dolist (h touched) (setf (gethash h (dr-instances dr)) t))   ; mark accessed after snapshot
    (nreverse out)))

(defun* take-samples (dr &key (states '(:read :not-read)) (where #'%where-any))
    (function (data-reader &key (:states list) (:where function)) (or list (member :not-enabled)))
  "DataReader::take — like read-samples but REMOVE the returned samples from the
   cache (default takes both read and unread). WHERE is the same optional query
   predicate (take_w_condition filter). Returns a list of cached-sample. WP-DCPS-SECURED-TAKE-LOAN
   (ADR 0038 (i)): a TAKEN secured sample's decode loan is released here (%release-secured-copy-loan) —
   the returned DATA struct is independent, so the pooled buffer is recycled per take instead of pinned.
   A DISABLED DataReader refuses the take with :not-enabled (outside the NOT_ENABLED-safe set,
   DDS 1.4 §2.2.2.1.1.7, S2.T3)."
  (unless (entity-enabled-p dr) (return-from take-samples +retcode-not-enabled+))
  (%drain dr)
  (let ((keep '()) (out '()) (touched '())
        (node (dp-node (sub-participant (dr-subscriber dr)))))
    (dolist (cs (dr-cache dr))
      (let ((info (cached-sample-info cs)))
        (if (and (member (sample-info-sample-state info) states)
                 (funcall where (cached-sample-data cs)))
            (progn
              (let ((handle (sample-info-instance-handle info)))
                (setf (sample-info-view-state info)
                      (if (gethash handle (dr-instances dr)) :not-new :new))
                (pushnew handle touched :test #'equalp))
              (%release-secured-copy-loan dr node cs)   ; taken -> release the secured decode loan (data struct is independent); FlatData view untouched
              (push cs out))
            (push cs keep))))
    (dolist (h touched) (setf (gethash h (dr-instances dr)) t))
    (setf (dr-cache dr) (nreverse keep))
    (nreverse out)))

(defun* samples-available (dr)
    (function (data-reader) (integer 0))
  "Drain newly-received samples into the cache and return the cache size, WITHOUT
   marking anything READ — for polling before a read/take."
  (%drain dr)
  (length (dr-cache dr)))

;;; ---- Status surfacing: SEDP match / incompatible-QoS events -> entity statuses +
;;;      listeners (M3 #3, FR-DCPS-3). These fire on the disc receiver thread; status
;;;      mutation is guarded by the entity STATUS-LOCK and any listener is invoked with
;;;      a snapshot OUTSIDE the lock (a listener must never deadlock the receiver).
;;;      Reading a status (get_*_status) resets its *_change counters per DDS 1.4.

(defvar *type-compat-log* nil
  "When bound/set to a stream, %ON-DISC-MATCH writes a one-line ADVISORY type-object
   fingerprint verdict (ADR 0009) for each freshly matched remote to it; NIL (the default)
   silences it. A diagnostics opt-in only — the verdict never affects matching, and is also
   recorded on the matched entity for inspection via ENTITY-TYPE-COMPAT. NOTE: %ON-DISC-MATCH
   runs on the discovery receiver thread, so set this with a process-global SETF (not a
   thread-local LET in another thread) to observe it from a live participant.")

(defun* %entity-type-support (entity)
    (function (entity) (or null dds.types:type-support))
  "The type-support behind a matched ENTITY's Topic, for the soft type-compat check; NIL
   unless ENTITY is a DataReader/DataWriter (the only entities %ON-DISC-MATCH records against)."
  (typecase entity
    (data-reader (topic-type-support (dr-topic entity)))
    (data-writer (topic-type-support (dw-topic entity)))
    (t nil)))

(defun* %assess-and-record-type-compat (entity remote)
    (function (entity dds.rtps.discovery:endpoint-data) (or null keyword))
  "ADVISORY (ADR 0009): assess REMOTE's advertised complete TypeObject (the RTI vendor
   PID_TYPE_OBJECT_LB it carries, if any) against ENTITY's local type and record the verdict
   on ENTITY (ENTITY-TYPE-COMPAT) for inspection. NEVER affects matching — the peer already
   passed the topic+type-name gate in dds-disc. Logs one line to *TYPE-COMPAT-LOG* when set.
   Returns the verdict keyword (see DDS.TYPES:ASSESS-TYPE-OBJECT-LB), or NIL when ENTITY has
   no type-support."
  (let ((ts (%entity-type-support entity)))
    (when ts
      (multiple-value-bind (verdict missing)
          (dds.types:assess-type-object-lb
           ts (dds.rtps.discovery:endpoint-data-type-object-lb remote))
        (setf (entity-type-compat entity) verdict)
        (when *type-compat-log*
          (format *type-compat-log* "~&; type-compat[~a/~a]: ~a~@[ — missing ~{~a~^, ~}~]~%"
                  (dds.rtps.discovery:endpoint-data-topic-name remote)
                  (dds.rtps.discovery:endpoint-data-type-name remote)
                  verdict missing))
        verdict))))

(defun* %on-disc-match (p kind remote &optional local-eid)
    (function (domain-participant keyword dds.rtps.discovery:endpoint-data &optional (or null (unsigned-byte 32))) t)
  "ON-MATCH hook: a remote endpoint matched a local one. :remote-writer -> our reader
   gained a publication (SUBSCRIPTION_MATCHED); :remote-reader -> our writer gained a
   subscription (PUBLICATION_MATCHED). The 16-octet remote GUID is the matched handle.
   Also records an ADVISORY type-object fingerprint verdict on the local entity (ADR 0009).
   WP-N-ENDPOINT-2C2 (ADR 0048): the matched LOCAL endpoint is resolved by the threaded LOCAL-EID
   (%participant-reader/writer-by-entity-id) so at N>=2 SAME-topic the status/listener + the §8.5.2
   crypto-token + the durability match-side land on the RIGHT endpoint (NIL -> topic fallback, byte-identical N=1)."
  (let ((handle (copy-seq (dds.rtps.discovery:endpoint-data-guid remote)))
        (tname (dds.rtps.discovery:endpoint-data-topic-name remote)))
    (ecase kind
      (:remote-writer (let ((dr (if local-eid (%participant-reader-by-entity-id p local-eid)
                                    (%participant-reader-for-topic p tname))))
                        (when dr (%reader-matched dr handle)
                              ;; durability-aware late-joiner gate (DDS 1.4 §2.2.3.4): a TL reader matched
                              ;; a retaining writer REQUESTS its history; a VOLATILE reader matched a
                              ;; RETAINING writer SKIPS it; a VOLATILE writer retains nothing so its match
                              ;; never skips. Writer durability is its advertised QoS.
                              (dds.disc:%reader-durability-init
                               (dp-node p) handle
                               (dds.qos:qos-durability (dds.rtps.discovery:endpoint-data-qos remote)))
                              (%assess-and-record-type-compat dr remote)))
                      ;; §8.5.2.3: our user reader matched a remote writer -> (re)send our DatareaderCryptoToken
                      ;; keyed to the REAL matched-remote writer GUID (the destination_endpoint_key fix).
                      (%cm-user-token-at-match p handle nil))
      (:remote-reader (let ((dw (if local-eid (%participant-writer-by-entity-id p local-eid)
                                    (%participant-writer-for-topic p tname))))
                        (when dw (%writer-matched dw handle)
                              ;; durability-aware late-joiner proxy init (DDS 1.4 §2.2.3.4): a TL writer
                              ;; matched by a TL reader replays its retained history (firstSN + a prompt
                              ;; HEARTBEAT); else future-only. Reader durability is its advertised QoS.
                              ;; WP-N-ENDPOINT-2C2: (dw-entity-id dw) == LOCAL-EID -> THIS matched writer's own history/GUID.
                              (dds.disc:%writer-durability-init
                               (dp-node p) handle
                               (dds.qos:qos-durability (dds.rtps.discovery:endpoint-data-qos remote))
                               (dw-entity-id dw))
                              (%assess-and-record-type-compat dw remote)))
                      ;; §8.5.2.2: our user writer matched a remote reader -> (re)send our DatawriterCryptoToken
                      ;; keyed to the REAL matched-remote reader GUID (the destination_endpoint_key fix). WP-N-ENDPOINT-2C2
                      ;; (ADR 0048): thread the ACTUAL matched local writer's LOCAL-EID so each of N SAME-topic secured
                      ;; writers re-sends its OWN DW token keyed to its OWN EntityId (NIL -> node-single fallback, byte-identical N=1).
                      (%cm-user-token-at-match p handle t local-eid))))
  t)

(defun* %on-disc-unmatch (p direction remote &optional local-eid)
    (function (domain-participant keyword dds.rtps.discovery:endpoint-data &optional (or null (unsigned-byte 32))) t)
  "ON-UNMATCH hook: a previously matched remote endpoint vanished (participant-lease
   expiry, disc.lisp %lease-sweep). :remote-writer -> our reader lost a publication
   (SUBSCRIPTION_MATCHED current_count--); :remote-reader -> our writer lost a
   subscription (PUBLICATION_MATCHED current_count--). WP-N-ENDPOINT-2C2 (ADR 0048): the matched LOCAL
   endpoint is resolved by the threaded LOCAL-EID (fired once per (local,remote) pair by %lease-sweep) so at
   N>=2 SAME-topic the DECREMENT lands on the RIGHT endpoint (NIL -> topic fallback, byte-identical N=1). The
   remote's 16-octet GUID is the unmatched handle (DDS 1.4 §2.2.4.1, dds_rtf2_dcps.idl §165/§174)."
  (let ((handle (copy-seq (dds.rtps.discovery:endpoint-data-guid remote)))
        (tname (dds.rtps.discovery:endpoint-data-topic-name remote)))
    (ecase direction
      (:remote-writer (let ((dr (if local-eid (%participant-reader-by-entity-id p local-eid)
                                    (%participant-reader-for-topic p tname))))
                        (when dr (%reader-unmatched dr handle)
                              (%clear-owner-on-vanish dr handle)   ; EXCLUSIVE owner loss -> takeover (S1)
                              (%on-writer-vanished dr (%guid-entityid handle)))))
      (:remote-reader (let ((dw (if local-eid (%participant-writer-by-entity-id p local-eid)
                                    (%participant-writer-for-topic p tname))))
                        (when dw (%writer-unmatched dw handle))))))
  t)

(defun* %on-disc-liveliness-changed (p remote-writer-guid alive-p)
    (function (domain-participant (simple-array (unsigned-byte 8) (16)) t) t)
  "ON-LIVELINESS-CHANGED hook (disc announce thread, %liveliness-sweep): matched remote
   writer REMOTE-WRITER-GUID crossed alive<->not-alive (ALIVE-P is the NEW state; RTPS 2.5
   §8.4.13). Bump the local DataReader's LIVELINESS_CHANGED status (DDS 1.4 §2.2.4.1) and
   fire on_liveliness_changed. WP-N-ENDPOINT-S5 (ADR 0048): the reader(s) matched to REMOTE-WRITER-GUID
   are resolved via the S2 delivery route (%participant-readers-for-writer-guid), so at N>=2 the status
   lands on the RIGHT reader; <=1 today (same-topic fence). N=1 == the sole reader (route fallback)."
  (dolist (dr (%participant-readers-for-writer-guid p remote-writer-guid))
    (%reader-liveliness-changed dr (copy-seq remote-writer-guid) alive-p)
    ;; A not-alive writer loses ownership (DDS 1.4 §2.2.3.9.2 cause (c)) -> remaining writer takes over.
    (unless alive-p (%clear-owner-on-vanish dr remote-writer-guid)))
  t)

(defun* %on-disc-incompatible (p kind remote bad &optional local-eid)
    (function (domain-participant keyword dds.rtps.discovery:endpoint-data list &optional (or null (unsigned-byte 32))) t)
  "ON-INCOMPATIBLE-QOS hook: topic+type agreed but RxO failed. :remote-writer -> our
   reader's REQUESTED_INCOMPATIBLE_QOS; :remote-reader -> our writer's OFFERED_
   INCOMPATIBLE_QOS. BAD is the failing-policy keyword list (dds.qos:qos-rxo-compatible).
   WP-N-ENDPOINT-2C2 (ADR 0048): the incompatible LOCAL endpoint is resolved by the threaded LOCAL-EID so at
   N>=2 SAME-topic the status lands on the RIGHT endpoint (NIL -> topic fallback, byte-identical N=1)."
  (let ((tname (dds.rtps.discovery:endpoint-data-topic-name remote)))
    (ecase kind
      (:remote-writer (let ((dr (if local-eid (%participant-reader-by-entity-id p local-eid)
                                    (%participant-reader-for-topic p tname))))
                        (when dr (%reader-incompatible dr bad))))
      (:remote-reader (let ((dw (if local-eid (%participant-writer-by-entity-id p local-eid)
                                    (%participant-writer-for-topic p tname))))
                        (when dw (%writer-incompatible dw bad))))))
  t)

(defun* %on-participant-sample (p)
    (function (domain-participant) t)
  "ON-SAMPLE hook (disc receiver thread): new user data arrived for P. Fire on_data_available
   if a listener is masked for it, then wake the reader's WaitSets (DATA_AVAILABLE / ReadCondition /
   QueryCondition). Holds no node lock here (the disc layer released it before calling).
   WP-N-ENDPOINT-S5 (ADR 0048): the disc data-ready callback carries no writer identity, so wake EVERY
   local reader (DRY via %wake-reader-data); each drains only its own S2-source-GUID-filtered samples,
   so a spurious wake of a reader with nothing pending is benign (level-triggered DATA_AVAILABLE, DDS
   1.4 §2.2.4.1). N=1 == the sole reader."
  (dolist (dr (%participant-readers p)) (%wake-reader-data dr))
  t)

(defun* %reader-matched (dr handle)
    (function (data-reader t) t)
  "Bump DR's SUBSCRIPTION_MATCHED status via the %notify-status chokepoint (bitmask bit +
   StatusCondition + listener): if a listener is masked, fire on-subscription-matched with a
   snapshot (resetting the *_change counters per DDS)."
  (%notify-status dr +status-subscription-matched+
   (lambda ()
     (let ((s (dr-sub-matched dr)))
       (incf (subscription-matched-status-total-count s))
       (incf (subscription-matched-status-total-count-change s))
       (incf (subscription-matched-status-current-count s))
       (incf (subscription-matched-status-current-count-change s))
       (setf (subscription-matched-status-last-publication-handle s) handle)
       (values t
               (when (and (dr-listener dr) (member :subscription-matched (dr-listener-mask dr)))
                 (let ((snapshot (copy-subscription-matched-status s)))
                   (setf (subscription-matched-status-total-count-change s) 0
                         (subscription-matched-status-current-count-change s) 0)
                   (lambda () (on-subscription-matched (dr-listener dr) dr snapshot))))))))
  t)

(defun* %writer-matched (dw handle)
    (function (data-writer t) t)
  "Bump DW's PUBLICATION_MATCHED status via the %notify-status chokepoint (bitmask bit +
   StatusCondition + listener): if a listener is masked, fire on-publication-matched with a
   snapshot (resetting the *_change counters per DDS)."
  (%notify-status dw +status-publication-matched+
   (lambda ()
     (let ((s (dw-pub-matched dw)))
       (incf (publication-matched-status-total-count s))
       (incf (publication-matched-status-total-count-change s))
       (incf (publication-matched-status-current-count s))
       (incf (publication-matched-status-current-count-change s))
       (setf (publication-matched-status-last-subscription-handle s) handle)
       (values t
               (when (and (dw-listener dw) (member :publication-matched (dw-listener-mask dw)))
                 (let ((snapshot (copy-publication-matched-status s)))
                   (setf (publication-matched-status-total-count-change s) 0
                         (publication-matched-status-current-count-change s) 0)
                   (lambda () (on-publication-matched (dw-listener dw) dw snapshot))))))))
  t)

(defun* %reader-unmatched (dr handle)
    (function (data-reader t) t)
  "Decrement DR's SUBSCRIPTION_MATCHED on a lost match (DDS 1.4 §2.2.4.1): current_count--
   (floored at 0), current_count_change accumulates -1 (mirroring how %reader-matched
   accumulates +1), last_publication_handle := the unmatched remote's GUID, total_count
   UNCHANGED (monotonic, dds_rtf2_dcps.idl §174). Routes through the %notify-status chokepoint
   (bitmask bit + StatusCondition + listener): fires on-subscription-matched if masked (snapshot
   + reset the *_change counters per DDS), then wakes the reader's WaitSets."
  (%notify-status dr +status-subscription-matched+
   (lambda ()
     (let ((s (dr-sub-matched dr)))
       (when (plusp (subscription-matched-status-current-count s))
         (decf (subscription-matched-status-current-count s)))
       (decf (subscription-matched-status-current-count-change s))
       (setf (subscription-matched-status-last-publication-handle s) handle)
       (values t
               (when (and (dr-listener dr) (member :subscription-matched (dr-listener-mask dr)))
                 (let ((snapshot (copy-subscription-matched-status s)))
                   (setf (subscription-matched-status-total-count-change s) 0
                         (subscription-matched-status-current-count-change s) 0)
                   (lambda () (on-subscription-matched (dr-listener dr) dr snapshot))))))))
  t)

(defun* %reader-liveliness-changed (dr handle alive-p)
    (function (data-reader t t) t)
  "Apply a matched-writer liveliness transition to DR's LIVELINESS_CHANGED status
   (DDS 1.4 §2.2.4.1, dds_rtf2_dcps.idl §123-129). ALIVE-P T (not-alive -> alive):
   alive_count++, not_alive_count-- (floored at 0), alive_count_change +1,
   not_alive_count_change -1. ALIVE-P NIL (alive -> not-alive): the reverse.
   last_publication_handle := the transitioned writer's GUID (HANDLE). Routes through the
   %notify-status chokepoint (bitmask bit + StatusCondition + listener): fires
   on-liveliness-changed if masked (snapshot + reset the *_change counters per DDS), then
   wakes the reader's WaitSets."
  (%notify-status dr +status-liveliness-changed+
   (lambda ()
     (let ((s (dr-liv-changed dr)))
       (if alive-p
           (progn
             (incf (liveliness-changed-status-alive-count s))
             (when (plusp (liveliness-changed-status-not-alive-count s))
               (decf (liveliness-changed-status-not-alive-count s)))
             (incf (liveliness-changed-status-alive-count-change s))
             (decf (liveliness-changed-status-not-alive-count-change s)))
           (progn
             (when (plusp (liveliness-changed-status-alive-count s))
               (decf (liveliness-changed-status-alive-count s)))
             (incf (liveliness-changed-status-not-alive-count s))
             (decf (liveliness-changed-status-alive-count-change s))
             (incf (liveliness-changed-status-not-alive-count-change s))))
       (setf (liveliness-changed-status-last-publication-handle s) handle)
       (values t
               (when (and (dr-listener dr) (member :liveliness-changed (dr-listener-mask dr)))
                 (let ((snapshot (copy-liveliness-changed-status s)))
                   (setf (liveliness-changed-status-alive-count-change s) 0
                         (liveliness-changed-status-not-alive-count-change s) 0)
                   (lambda () (on-liveliness-changed (dr-listener dr) dr snapshot))))))))
  t)

(defun* %lease-internal-units (duration)
    (function (dds.qos:qos-duration) (integer 0))
  "A LIVELINESS lease_duration as internal-time-units (the granularity dw-last-assertion
   is stamped in), rounding the sub-second nanosec part up so a fresh assertion inside the
   lease is never prematurely judged stale (DDS 1.4 §2.2.3.11). DURATION_INFINITE
   (sec 0x7fffffff) is returned as effectively unbounded. The round-up to whole seconds is
   delegated to dds.disc::%lease-seconds (single source of that arithmetic, DRY)."
  (* (dds.disc::%lease-seconds duration) internal-time-units-per-second))

(defun* %writer-liveliness-lost-check (dw now)
    (function (data-writer (integer 0)) t)
  "Sweep one DataWriter DW for LIVELINESS_LOST at time NOW (DDS 1.4 §2.2.3.11, dds_rtf2_dcps.idl
   §118-121): if DW is still considered alive but has not asserted its own liveliness within its
   offered LIVELINESS lease_duration, fire LIVELINESS_LOST through the %notify-status chokepoint
   (total_count++ monotonic, total_count_change +1, clear the alive flag so it fires once per
   going-lost transition; bitmask bit + StatusCondition + on_liveliness_lost if masked). AUTOMATIC
   writers are kept asserted by the announce cadence (see %writer-liveliness-sweep), so they only go
   lost if the participant stops announcing. An infinite lease never goes lost. The going-lost
   decision + mutation happen atomically under DW's status lock inside %notify-status's apply-fn; a
   writer that is not lost yields (values NIL NIL), so no bit is set and no listener fires."
  (let ((qos (entity-qos dw)))
    (when (typep qos 'dds.qos:qos)
      (let* ((dur (dds.qos:qos-liveliness-lease qos))
             (lease (%lease-internal-units dur)))
        (when (and (< (dds.qos:qos-duration-sec dur) #x7fffffff)
                   (plusp lease))
          (%notify-status dw +status-liveliness-lost+
           (lambda ()
             (if (and (dw-alive-p dw) (> (- now (dw-last-assertion dw)) lease))
                 (let ((s (dw-liv-lost dw)))
                   (incf (liveliness-lost-status-total-count s))
                   (incf (liveliness-lost-status-total-count-change s))
                   (setf (dw-alive-p dw) nil)
                   (values t
                           (when (and (dw-listener dw) (member :liveliness-lost (dw-listener-mask dw)))
                             (let ((snapshot (copy-liveliness-lost-status s)))
                               (setf (liveliness-lost-status-total-count-change s) 0)
                               (lambda () (on-liveliness-lost (dw-listener dw) dw snapshot))))))
                 (values nil nil)))))))
    t))

(defun* %writer-liveliness-sweep (p)
    (function (domain-participant) (eql t))
  "Writer-side Writer Liveliness timing (DDS 1.4 §2.2.3.11 / §2.2.4.1): on the DCPS
   announce cadence (SPIN), refresh every AUTOMATIC local writer's self-assertion (the
   infrastructure asserts AUTOMATIC writers while the participant announces) and then sweep
   every local writer for LIVELINESS_LOST — a writer that has not asserted within its
   offered lease_duration fires on_liveliness_lost once per going-lost transition. MANUAL
   writers (BY_PARTICIPANT / BY_TOPIC) are NOT auto-refreshed here: the application keeps
   them alive via write / assert_liveliness. Each writer's going-lost transition is routed
   through the %notify-status chokepoint, which fires on_liveliness_lost OUTSIDE the writer's
   status lock (no lock held during the listener callback)."
  (let ((now (%lease-now)))
    (dolist (dw (%participant-writers p))
      (when (eq (%writer-liveliness-kind dw) :automatic)
        (dds.pal:with-lock ((dw-status-lock dw))
          (setf (dw-last-assertion dw) now (dw-alive-p dw) t))))
    (dolist (dw (%participant-writers p))
      (%writer-liveliness-lost-check dw now)))
  t)

(defun* %writer-unmatched (dw handle)
    (function (data-writer t) t)
  "Decrement DW's PUBLICATION_MATCHED on a lost match (DDS 1.4 §2.2.4.1): current_count--
   (floored at 0), current_count_change accumulates -1, last_subscription_handle := the
   unmatched remote's GUID, total_count UNCHANGED (monotonic, dds_rtf2_dcps.idl §165).
   Routes through the %notify-status chokepoint (bitmask bit + StatusCondition + listener):
   fires on-publication-matched if masked (snapshot + reset the *_change counters)."
  (%notify-status dw +status-publication-matched+
   (lambda ()
     (let ((s (dw-pub-matched dw)))
       (when (plusp (publication-matched-status-current-count s))
         (decf (publication-matched-status-current-count s)))
       (decf (publication-matched-status-current-count-change s))
       (setf (publication-matched-status-last-subscription-handle s) handle)
       (values t
               (when (and (dw-listener dw) (member :publication-matched (dw-listener-mask dw)))
                 (let ((snapshot (copy-publication-matched-status s)))
                   (setf (publication-matched-status-total-count-change s) 0
                         (publication-matched-status-current-count-change s) 0)
                   (lambda () (on-publication-matched (dw-listener dw) dw snapshot))))))))
  t)

(defun* %apply-requested-incompatible (s bad)
    (function (requested-incompatible-qos-status list) t)
  "Accumulate the failing policies BAD into a REQUESTED_INCOMPATIBLE_QOS status S
   (one detection event): total_count++, per-policy QosPolicyCount bumps, last_policy_id."
  (incf (requested-incompatible-qos-status-total-count s))
  (incf (requested-incompatible-qos-status-total-count-change s))
  (dolist (k bad)
    (let ((pid (rxo-policy-id k)))
      (setf (requested-incompatible-qos-status-policies s)
            (bump-policy-count (requested-incompatible-qos-status-policies s) pid))
      (setf (requested-incompatible-qos-status-last-policy-id s) pid)))
  t)

(defun* %apply-offered-incompatible (s bad)
    (function (offered-incompatible-qos-status list) t)
  "Accumulate the failing policies BAD into an OFFERED_INCOMPATIBLE_QOS status S."
  (incf (offered-incompatible-qos-status-total-count s))
  (incf (offered-incompatible-qos-status-total-count-change s))
  (dolist (k bad)
    (let ((pid (rxo-policy-id k)))
      (setf (offered-incompatible-qos-status-policies s)
            (bump-policy-count (offered-incompatible-qos-status-policies s) pid))
      (setf (offered-incompatible-qos-status-last-policy-id s) pid)))
  t)

(defun* %reader-incompatible (dr bad)
    (function (data-reader list) t)
  "Bump DR's REQUESTED_INCOMPATIBLE_QOS status via the %notify-status chokepoint (bitmask bit
   + StatusCondition + listener): fire on-requested-incompatible-qos if masked (snapshot
   deep-copying the policies)."
  (%notify-status dr +status-requested-incompatible-qos+
   (lambda ()
     (let ((s (dr-req-incompat dr)))
       (%apply-requested-incompatible s bad)
       (values t
               (when (and (dr-listener dr) (member :requested-incompatible-qos (dr-listener-mask dr)))
                 (let ((snapshot (copy-requested-incompatible-qos-status s)))
                   (setf (requested-incompatible-qos-status-policies snapshot)
                         (mapcar #'copy-qos-policy-count (requested-incompatible-qos-status-policies s)))
                   (setf (requested-incompatible-qos-status-total-count-change s) 0)
                   (lambda () (on-requested-incompatible-qos (dr-listener dr) dr snapshot))))))))
  t)

(defun* %writer-incompatible (dw bad)
    (function (data-writer list) t)
  "Bump DW's OFFERED_INCOMPATIBLE_QOS status via the %notify-status chokepoint (bitmask bit +
   StatusCondition + listener): fire on-offered-incompatible-qos if masked (snapshot
   deep-copying the policies)."
  (%notify-status dw +status-offered-incompatible-qos+
   (lambda ()
     (let ((s (dw-off-incompat dw)))
       (%apply-offered-incompatible s bad)
       (values t
               (when (and (dw-listener dw) (member :offered-incompatible-qos (dw-listener-mask dw)))
                 (let ((snapshot (copy-offered-incompatible-qos-status s)))
                   (setf (offered-incompatible-qos-status-policies snapshot)
                         (mapcar #'copy-qos-policy-count (offered-incompatible-qos-status-policies s)))
                   (setf (offered-incompatible-qos-status-total-count-change s) 0)
                   (lambda () (on-offered-incompatible-qos (dw-listener dw) dw snapshot))))))))
  t)

;;; ---- get_*_status (app thread): snapshot + reset the *_change counters (DDS 1.4) ----

(defun* get-subscription-matched-status (dr)
    (function (data-reader) subscription-matched-status)
  "DataReader::get_subscription_matched_status — a snapshot; the read-communication-status
   reset (DDS 1.4 §2.2.2.1.9) resets the *_change counters and clears the SUBSCRIPTION_MATCHED
   bit in the reader's status-changes bitmask."
  (dds.pal:with-lock ((dr-status-lock dr))
    (let ((s (dr-sub-matched dr)))
      (prog1 (copy-subscription-matched-status s)
        (setf (subscription-matched-status-total-count-change s) 0
              (subscription-matched-status-current-count-change s) 0)
        (%clear-status-changed dr +status-subscription-matched+)))))

(defun* get-publication-matched-status (dw)
    (function (data-writer) publication-matched-status)
  "DataWriter::get_publication_matched_status — snapshot; the read-communication-status reset
   (DDS 1.4 §2.2.2.1.9) resets the *_change counters and clears the PUBLICATION_MATCHED bit."
  (dds.pal:with-lock ((dw-status-lock dw))
    (let ((s (dw-pub-matched dw)))
      (prog1 (copy-publication-matched-status s)
        (setf (publication-matched-status-total-count-change s) 0
              (publication-matched-status-current-count-change s) 0)
        (%clear-status-changed dw +status-publication-matched+)))))

(defun* get-requested-incompatible-qos-status (dr)
    (function (data-reader) requested-incompatible-qos-status)
  "DataReader::get_requested_incompatible_qos_status — snapshot (policies deep-copied); the
   read-communication-status reset (DDS 1.4 §2.2.2.1.9) resets total_count_change and clears the
   REQUESTED_INCOMPATIBLE_QOS bit; the cumulative policies counts are retained per DDS."
  (dds.pal:with-lock ((dr-status-lock dr))
    (let* ((s (dr-req-incompat dr))
           (snap (copy-requested-incompatible-qos-status s)))
      (setf (requested-incompatible-qos-status-policies snap)
            (mapcar #'copy-qos-policy-count (requested-incompatible-qos-status-policies s)))
      (setf (requested-incompatible-qos-status-total-count-change s) 0)
      (%clear-status-changed dr +status-requested-incompatible-qos+)
      snap)))

(defun* get-offered-incompatible-qos-status (dw)
    (function (data-writer) offered-incompatible-qos-status)
  "DataWriter::get_offered_incompatible_qos_status — snapshot (policies deep-copied); the
   read-communication-status reset (DDS 1.4 §2.2.2.1.9) resets total_count_change and clears the
   OFFERED_INCOMPATIBLE_QOS bit; the cumulative policies counts are retained per DDS."
  (dds.pal:with-lock ((dw-status-lock dw))
    (let* ((s (dw-off-incompat dw))
           (snap (copy-offered-incompatible-qos-status s)))
      (setf (offered-incompatible-qos-status-policies snap)
            (mapcar #'copy-qos-policy-count (offered-incompatible-qos-status-policies s)))
      (setf (offered-incompatible-qos-status-total-count-change s) 0)
      (%clear-status-changed dw +status-offered-incompatible-qos+)
      snap)))

(defun* get-sample-rejected-status (dr)
    (function (data-reader) sample-rejected-status)
  "DataReader::get_sample_rejected_status — snapshot; the read-communication-status reset
   (DDS 1.4 §2.2.2.1.9) resets total_count_change and clears the SAMPLE_REJECTED bit."
  (dds.pal:with-lock ((dr-status-lock dr))
    (let ((s (dr-sample-rejected dr)))
      (prog1 (copy-sample-rejected-status s)
        (setf (sample-rejected-status-total-count-change s) 0)
        (%clear-status-changed dr +status-sample-rejected+)))))

(defun* get-liveliness-changed-status (dr)
    (function (data-reader) liveliness-changed-status)
  "DataReader::get_liveliness_changed_status — a snapshot; the read-communication-status reset
   (DDS 1.4 §2.2.4.1 / §2.2.2.1.9) resets the *_change counters and clears the LIVELINESS_CHANGED
   bit."
  (dds.pal:with-lock ((dr-status-lock dr))
    (let ((s (dr-liv-changed dr)))
      (prog1 (copy-liveliness-changed-status s)
        (setf (liveliness-changed-status-alive-count-change s) 0
              (liveliness-changed-status-not-alive-count-change s) 0)
        (%clear-status-changed dr +status-liveliness-changed+)))))

(defun* get-liveliness-lost-status (dw)
    (function (data-writer) liveliness-lost-status)
  "DataWriter::get_liveliness_lost_status — a snapshot; the read-communication-status reset
   (DDS 1.4 §2.2.4.1 / §2.2.2.1.9, dds_rtf2_dcps.idl §118-121) resets total_count_change and
   clears the LIVELINESS_LOST bit."
  (dds.pal:with-lock ((dw-status-lock dw))
    (let ((s (dw-liv-lost dw)))
      (prog1 (copy-liveliness-lost-status s)
        (setf (liveliness-lost-status-total-count-change s) 0)
        (%clear-status-changed dw +status-liveliness-lost+)))))

;;; ---- set_listener (DDS 1.4 Entity::set_listener) ----

(defun* set-reader-listener (dr listener mask)
    (function (data-reader (or null listener) list) data-reader)
  "DataReader::set_listener — install LISTENER for the statuses named in MASK (a list
   of status keywords, e.g. (:subscription-matched :requested-incompatible-qos))."
  (dds.pal:with-lock ((dr-status-lock dr))
    (setf (dr-listener dr) listener (dr-listener-mask dr) mask))
  dr)

(defun* set-writer-listener (dw listener mask)
    (function (data-writer (or null listener) list) data-writer)
  "DataWriter::set_listener — install LISTENER for the statuses named in MASK (a list
   of status keywords, e.g. (:publication-matched :offered-incompatible-qos))."
  (dds.pal:with-lock ((dw-status-lock dw))
    (setf (dw-listener dw) listener (dw-listener-mask dw) mask))
  dw)

;;; ---- INCONSISTENT_TOPIC (FR-DCPS-3): a remote topic of the same name but a
;;;      different type, detected in SEDP and surfaced on the local Topic. ----

(defun* %find-topic (p name)
    (function (domain-participant string) (or null topic))
  "The participant's local Topic registered under NAME (a plain Topic, not a CFT), or NIL."
  (find-if (lambda (c) (and (typep c 'topic) (string= (topic-name c) name))) (dp-children p)))

(defun* %on-disc-inconsistent-topic (p name)
    (function (domain-participant string) t)
  "ON-INCONSISTENT-TOPIC hook (disc receiver thread): a remote endpoint announced topic
   NAME with a different type than P's local Topic of that name. Bump the Topic's
   INCONSISTENT_TOPIC status via the %notify-status chokepoint (bitmask bit + StatusCondition
   + listener); fire on_inconsistent_topic if masked."
  (let ((tp (%find-topic p name)))
    (when tp
      (%notify-status tp +status-inconsistent-topic+
       (lambda ()
         (let ((s (topic-inconsistent-status tp)))
           (incf (inconsistent-topic-status-total-count s))
           (incf (inconsistent-topic-status-total-count-change s))
           (values t
                   (when (and (topic-listener-obj tp) (member :inconsistent-topic (topic-listener-mask tp)))
                     (let ((snapshot (copy-inconsistent-topic-status s)))
                       (setf (inconsistent-topic-status-total-count-change s) 0)
                       (lambda () (on-inconsistent-topic (topic-listener-obj tp) tp snapshot))))))))))
  t)

(defun* get-inconsistent-topic-status (tp)
    (function (topic) inconsistent-topic-status)
  "Topic::get_inconsistent_topic_status — snapshot; the read-communication-status reset (DDS
   1.4 §2.2.2.1.9) resets total_count_change and clears the INCONSISTENT_TOPIC bit."
  (dds.pal:with-lock ((topic-status-lock tp))
    (let ((s (topic-inconsistent-status tp)))
      (prog1 (copy-inconsistent-topic-status s)
        (setf (inconsistent-topic-status-total-count-change s) 0)
        (%clear-status-changed tp +status-inconsistent-topic+)))))

(defun* set-topic-listener (tp listener mask)
    (function (topic (or null listener) list) topic)
  "Topic::set_listener — install LISTENER for the statuses named in MASK (v1:
   (:inconsistent-topic))."
  (dds.pal:with-lock ((topic-status-lock tp))
    (setf (topic-listener-obj tp) listener (topic-listener-mask tp) mask))
  tp)

;;; ---- WP-DCPS-API-COMPLETION S2.T4/T5: child delete_* + delete_contained_entities (DDS 1.4 §2.2.2) ----

(defun* delete-datawriter (pub dw)
    (function (publisher data-writer) (member :ok :precondition-not-met))
  "Publisher::delete_datawriter (DDS 1.4 §2.2.2.4.1.5) — delete DW from PUB. Returns
   :precondition-not-met if DW is not contained in PUB (§2.2.2.4.1.5). Otherwise: discard any
   outstanding zero-copy write loans (no stranded pool slot), remove the writer from discovery + the
   engine registry (remove-local-writer — SEDP stops announcing it, no delivery routes to it), drop it
   from the Publisher, and mark it disabled. Node-scoped pools/threads (shared with sibling endpoints)
   are freed at delete_participant/stop-node, not here."
  (unless (member dw (pub-writers pub)) (return-from delete-datawriter +retcode-precondition-not-met+))
  (discard-all-loans dw)
  (dds.disc:remove-local-writer (dp-node (pub-participant pub)) (dw-disc-endpoint dw) (dw-entity-id dw))
  (setf (pub-writers pub) (remove dw (pub-writers pub))
        (entity-enabled-p dw) nil)
  +retcode-ok+)

(defun* delete-datareader (sub dr)
    (function (subscriber data-reader) (member :ok :precondition-not-met))
  "Subscriber::delete_datareader (DDS 1.4 §2.2.2.5.1.5) — delete DR from SUB. Returns
   :precondition-not-met if DR is not contained in SUB. Otherwise, in this ORDER: (1) remove the reader
   from discovery + the engine registry FIRST (remove-local-reader purges its delivery routes under the
   node lock, so the receiver STOPS demuxing new samples to DR — closing the window where one more sample
   would create a never-returned loan); (2) THEN return every outstanding read/secured loan (the pool is
   still mapped — freed only at stop-node — so no use-after-free, and no held refcount pins a writer pool);
   (3) drop it from the Subscriber and mark it disabled."
  (unless (member dr (sub-readers sub)) (return-from delete-datareader +retcode-precondition-not-met+))
  (dds.disc:remove-local-reader (dp-node (sub-participant sub)) (dr-disc-endpoint dr) (dr-entity-id dr))
  (return-all-loans dr)
  (setf (sub-readers sub) (remove dr (sub-readers sub))
        (entity-enabled-p dr) nil)
  +retcode-ok+)

(defun* delete-publisher (p pub)
    (function (domain-participant publisher) (member :ok :precondition-not-met))
  "DomainParticipant::delete_publisher (DDS 1.4 §2.2.2.2.1.6) — delete PUB from P. Returns
   :precondition-not-met if PUB is not contained in P, or if PUB still contains DataWriters (delete
   them first, or call delete_contained_entities on PUB). Otherwise unregister PUB from P and disable it."
  (unless (member pub (dp-children p)) (return-from delete-publisher +retcode-precondition-not-met+))
  (when (pub-writers pub) (return-from delete-publisher +retcode-precondition-not-met+))
  (setf (dp-children p) (remove pub (dp-children p))
        (entity-enabled-p pub) nil)
  +retcode-ok+)

(defun* delete-subscriber (p sub)
    (function (domain-participant subscriber) (member :ok :precondition-not-met))
  "DomainParticipant::delete_subscriber (DDS 1.4 §2.2.2.2.1.8) — delete SUB from P. Returns
   :precondition-not-met if SUB is not contained in P, or if SUB still contains DataReaders. Otherwise
   unregister SUB from P and disable it."
  (unless (member sub (dp-children p)) (return-from delete-subscriber +retcode-precondition-not-met+))
  (when (sub-readers sub) (return-from delete-subscriber +retcode-precondition-not-met+))
  (setf (dp-children p) (remove sub (dp-children p))
        (entity-enabled-p sub) nil)
  +retcode-ok+)

(defun* %topic-referenced-p (p tp)
    (function (domain-participant topic) boolean)
  "T iff any DataWriter or DataReader contained in P still uses Topic TP — the delete_topic
   precondition (DDS 1.4 §2.2.2.2.1.10): a Topic still referenced by an endpoint cannot be deleted."
  (or (and (some (lambda (w) (eq (dw-topic w) tp)) (%participant-writers p)) t)
      (and (some (lambda (r) (eq (dr-topic r) tp)) (%participant-readers p)) t)))

(defun* delete-topic (p tp)
    (function (domain-participant topic) (member :ok :precondition-not-met))
  "DomainParticipant::delete_topic (DDS 1.4 §2.2.2.2.1.10) — delete Topic TP from P. Returns
   :precondition-not-met if TP is not contained in P, or if any DataWriter/DataReader still references
   it (%topic-referenced-p). Otherwise unregister TP from P and disable it."
  (unless (member tp (dp-children p)) (return-from delete-topic +retcode-precondition-not-met+))
  (when (%topic-referenced-p p tp) (return-from delete-topic +retcode-precondition-not-met+))
  (setf (dp-children p) (remove tp (dp-children p))
        (entity-enabled-p tp) nil)
  +retcode-ok+)

(defun* delete-contained-entities (entity)
    (function (entity) (member :ok))
  "Recursively delete every entity contained in ENTITY (DDS 1.4: DomainParticipant §2.2.2.2.1.11,
   Publisher §2.2.2.4.1.13, Subscriber §2.2.2.5.1.13 delete_contained_entities). A Publisher deletes
   its DataWriters; a Subscriber deletes its DataReaders; a DomainParticipant first empties then deletes
   its Publishers and Subscribers, THEN deletes its Topics (deleted last, once no endpoint references
   them, so the delete_topic precondition holds). After this ENTITY holds no children and is itself
   deletable. Always :ok (each contained delete's precondition is satisfied by the recursion order)."
  (typecase entity
    (domain-participant
     (dolist (pub (participant-publishers entity))
       (delete-contained-entities pub)
       (delete-publisher entity pub))
     (dolist (sub (participant-subscribers entity))
       (delete-contained-entities sub)
       (delete-subscriber entity sub))
     (dolist (tp (participant-topics entity))
       (delete-topic entity tp)))
    (publisher
     (dolist (dw (publisher-datawriters entity))
       (delete-datawriter entity dw)))
    (subscriber
     (dolist (dr (subscriber-datareaders entity))
       (delete-datareader entity dr))))
  +retcode-ok+)
