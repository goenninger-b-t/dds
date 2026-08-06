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
   (access-state :initform nil :accessor dp-access-state)   ; DDS-Security 1.1 §8.4 AccessControl manager (access-control.lisp)
   (listener :initform nil :accessor dp-listener)            ; WP-DCPS-API-COMPLETION S3.T1: DomainParticipantListener (DDS 1.4 §2.2.4.1)
   (listener-mask :initform '() :accessor dp-listener-mask)
   (listener-lock :initform (dds.pal:make-lock "dp-listener") :accessor dp-listener-lock)
   (unaddressable-status :initform (make-unaddressable-peer-status) :accessor dp-unaddressable-status)  ; VENDOR EXTENSION: a matched-but-unaddressable remote (owner directive 2026-07-22)
   (status-lock :initform (dds.pal:make-lock "dp-status") :accessor dp-status-lock)  ; DDS 1.4 attaches communication statuses to Topic/Reader/Writer only; the participant gains one because UNADDRESSABLE_PEER (a vendor extension) is participant-scoped — the refusal is a property of the REMOTE PARTICIPANT, not of any one local endpoint
   (deadline-monitor :initform nil :accessor dp-deadline-monitor)  ; WP-DCPS-API-COMPLETION S4: the lazily-started per-participant deadline monitor thread (deadline.lisp), NIL until the first finite DEADLINE arms a timer
   (deadline-lock :initform (dds.pal:make-lock "dp-deadline") :accessor dp-deadline-lock)  ; WP-DCPS-API-COMPLETION S4: guards lazy deadline-monitor creation
   (autonomous-p :initform nil :accessor dp-autonomous-p)   ; WP-DCPS-API-COMPLETION S7: autonomous-discovery mode (config-gated); T -> a background announcer drives SPDP/SEDP + aging, spin is a no-op
   (announcer :initform nil :accessor dp-announcer))        ; WP-DCPS-API-COMPLETION S7: the auto-announcer thread (autodiscovery.lisp), started on enable when autonomous, stopped+JOINED on delete
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
   (default-datawriter-qos :initform nil :accessor pub-default-datawriter-qos) ; DDS 1.4 §2.2.2.4.1 get/set_default_datawriter_qos
   (listener :initform nil :accessor pub-listener)            ; WP-DCPS-API-COMPLETION S3.T1: PublisherListener (DDS 1.4 §2.2.4.1)
   (listener-mask :initform '() :accessor pub-listener-mask)
   (listener-lock :initform (dds.pal:make-lock "pub-listener") :accessor pub-listener-lock))
  (:documentation "DDS Publisher: a factory/container for DataWriters in its participant."))

(defclass subscriber (entity)
  ((participant :initarg :participant :reader sub-participant)
   (readers :initform '() :accessor sub-readers)
   (default-datareader-qos :initform nil :accessor sub-default-datareader-qos) ; DDS 1.4 §2.2.2.5.1 get/set_default_datareader_qos
   (listener :initform nil :accessor sub-listener)            ; WP-DCPS-API-COMPLETION S3.T1: SubscriberListener (DDS 1.4 §2.2.4.1)
   (listener-mask :initform '() :accessor sub-listener-mask)
   (listener-lock :initform (dds.pal:make-lock "sub-listener") :accessor sub-listener-lock))
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
   (off-deadline :initform (make-offered-deadline-missed-status) :accessor dw-off-deadline) ; WP-DCPS-API-COMPLETION S4: OFFERED_DEADLINE_MISSED (DDS 1.4 §2.2.3.7)
   (deadline-timers :initform nil :accessor dw-deadline-timers) ; WP-DCPS-API-COMPLETION S4: handle -> deadline-timer (nil until a finite offered DEADLINE arms one; NFR-MEM reuse-per-instance)
   (liv-lost :initform (make-liveliness-lost-status) :accessor dw-liv-lost)
   (last-assertion :initform (%lease-now) :accessor dw-last-assertion) ; last self-assertion stamp (DDS 1.4 §2.2.3.11)
   (alive :initform t :accessor dw-alive-p)                            ; LIVELINESS_LOST loss-transition flag
   (listener :initform nil :accessor dw-listener)
   (listener-mask :initform '() :accessor dw-listener-mask)
   (instances :initform (make-hash-table :test 'equalp) :accessor dw-instances) ; 16-octet handle -> :alive (DDS 1.4 §2.2.2.4.2)
   (loans :initform '() :accessor dw-loans)                ; WP-FLATDATA-LOAN-WRITE (R6, ADR 0042): outstanding writer-loans (writer-close safety sweep)
   (loan-freelist :initform '() :accessor dw-loan-freelist) ; WP-FLATDATA-LOAN-WRITE: recycled writer-loan structs (the struct+view recycle; the registry cell + retained payload are the documented v1 per-write cost)
   (loan-encap :initform nil :accessor dw-loan-encap)      ; WP-FLATDATA-LOAN-WRITE (ADR 0042): the type's 4-octet encap header+options, cached once from the FlatData ctor (%loan-encap-header) — written into every slot-backed loan's slot
   ;; ADR 0089 vendor-extension reliability statuses (bits 25-26). Writer-side, like the DDS statuses above.
   (rw-cache-changed :initform (make-reliable-writer-cache-changed-status) :accessor dw-rw-cache-changed)
   (rr-activity :initform (make-reliable-reader-activity-changed-status) :accessor dw-rr-activity)
   (app-ack :initform (make-application-acknowledgment-status) :accessor dw-app-ack)
   (app-ack-overdue :initform (make-application-acknowledgment-overdue-status) :accessor dw-app-ack-overdue) ; ADR 0090 A4: APPLICATION_ACKNOWLEDGMENT_OVERDUE — armed only when ACKNOWLEDGMENT_KIND is an APPLICATION kind AND the deadline is finite, so a :protocol writer never arms a timer ; ADR 0090 A3c: APPLICATION_ACKNOWLEDGMENT — fires only when a matched reader's APPLICATION acknowledges, which under :PROTOCOL never happens (nothing sends an APP_ACK), so a default writer's status stays at zero without any gate
   (rw-last-unacked :initform 0 :accessor dw-rw-last-unacked) ; ADR 0089: the last send-window level this writer reported, so the per-write notification can decide "no threshold crossed" from two integer reads and return before building anything (the ADR 0088 lesson: a closure allocates on every call, misses and hits alike)
   (rw-armed :initform nil :accessor dw-rw-armed) ; ADR 0089: T while a BACKPRESSURE EPISODE is open — set when the send window rises to the high watermark, cleared when it falls back to the low one. Without it the low and empty transitions fire on ordinary traffic (a 1-deep exchange drains to zero on every sample), which is the flood the watermarks exist to prevent
   (active-readers :initform (make-hash-table :test 'equalp) :accessor dw-active-readers) ; remote reader GUID -> T while it is acknowledging; the SET is the truth, so a repeated ACKNACK cannot inflate active-count
   (keyhash-scratch :initform nil :accessor dw-keyhash-scratch) ; TX-KEYHASH (ADR 0087): reusable :big cursor over a 256-octet buffer for the per-write instance-handle key serialization — the writer twin of dr-keyhash-scratch (ADR 0075), created once, zero per-sample make-octet-buffer/cursor/free-static (NFR-MEM)
   (keyhash-busy :initform (dds.pal:make-atomic-cell) :accessor dw-keyhash-busy) ; TX-KEYHASH (ADR 0087): CAS try-lock guarding KEYHASH-SCRATCH — a DataWriter may be written CONCURRENTLY (DDS 1.4 §2.2.2.4.2.11 places no single-thread restriction on write), and two threads serializing keys through one buffer would interleave into a WRONG instance handle; the loser allocates instead, byte-identically
   (payload-cursor :initform nil :accessor dw-payload-cursor) ; NFR-MEM: the cursor the per-write payload serializer writes through, reused instead of consed (48 B/write). Keyed by an EQ test on the pooled buffer, which is what makes it SAFE UNDER CONCURRENT WRITE without the CAS lock KEYHASH-SCRATCH needs: writer-acquire-payload-buffer pops a DISTINCT buffer per caller, so two threads can never be handed the same cursor — the second's EQ test fails and it allocates, exactly as before. The pool is a LIFO stack, so a single slot hits in steady state (acquire -> release -> acquire returns the same buffer)
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
   (app-acks :initform nil :accessor dr-app-acks) ; ADR 0090 A3b: 16-octet remote-writer GUID (equalp) -> dds.rtps.reliable:app-ack-state. LAZY — NIL until this reader's ACKNOWLEDGMENT_KIND is an APPLICATION kind, so a :PROTOCOL reader (the default, and everything gate-mem measures) never allocates the table and every APP-ACK site below is one NIL test. Per DATAREADER, deliberately NOT on the engine writer-proxy: two same-topic readers SHARE a proxy (ADR 0048) but acknowledge independently, and one speaking for the other is a FALSE ACK
   (sub-matched :initform (make-subscription-matched-status) :accessor dr-sub-matched)
   (req-incompat :initform (make-requested-incompatible-qos-status) :accessor dr-req-incompat)
   (sample-rejected :initform (make-sample-rejected-status) :accessor dr-sample-rejected)
   (req-deadline :initform (make-requested-deadline-missed-status) :accessor dr-req-deadline) ; WP-DCPS-API-COMPLETION S4: REQUESTED_DEADLINE_MISSED (DDS 1.4 §2.2.3.7)
   (sample-lost :initform (make-sample-lost-status) :accessor dr-sample-lost) ; WP-DCPS-API-COMPLETION S4: SAMPLE_LOST (DDS 1.4 §2.2.4.1)
   (deadline-timers :initform nil :accessor dr-deadline-timers) ; WP-DCPS-API-COMPLETION S4: handle -> deadline-timer (nil until a finite requested DEADLINE arms one; NFR-MEM reuse-per-instance)
   (liv-changed :initform (make-liveliness-changed-status) :accessor dr-liv-changed)
   (listener :initform nil :accessor dr-listener)
   (listener-mask :initform '() :accessor dr-listener-mask)
   ;; WP-PERF: REUSED per-reader scratch for %drain — the pending data keys, the pending lifecycle keys, and the
   ;; merged SN-ordered plan. %drain used to CONS all three afresh on EVERY take-samples, and sized them by the
   ;; number of samples STORED rather than PENDING (3716 B/sample of GC garbage — the largest remaining RX
   ;; allocation). Reused vectors + an O(pending) walk make the steady-state drain allocate ~nothing.
   (drain-data-keys :initform (make-array 8 :adjustable t :fill-pointer 0) :accessor dr-drain-data-keys)
   (drain-life-keys :initform (make-array 4 :adjustable t :fill-pointer 0) :accessor dr-drain-life-keys)
   (drain-plan :initform (make-array 8 :adjustable t :fill-pointer 0) :accessor dr-drain-plan)
   (conditions :initform '() :accessor dr-conditions)      ; read/query/status conditions bound here
   (filter :initform nil :accessor dr-filter)              ; ContentFilteredTopic predicate, or nil
   (loans :initform '() :accessor dr-loans)                ; WP-FLATDATA-ZC-LOAN (R6, ADR 0017): outstanding loaned flatdata-views (the loan registry) — return-loan / reader-close release them
   (view-freelist :initform '() :accessor dr-view-freelist) ; WP-FLATDATA-ZC-LOAN: recycled flatdata-view structs (no per-sample GC-heap alloc; NFR-MEM)
   (secured-loans :initform '() :accessor dr-secured-loans) ; WP-DCPS-SECURED-TAKE-LOAN (ADR 0038 (i)): outstanding secured decode-loan handles — SEPARATE registry from dr-loans (the type-clean two-registry discipline); return-loan / reader-close node-return-loan them
   (secured-scratch :initform nil :accessor dr-secured-scratch) ; WP-DCPS-SECURED-TAKE-LOAN: reusable octet-buffer wrapper (repointed per drain) for the in-place [0,len) secured-plaintext deserialize — created once, zero per-sample cons (NFR-MEM)
   (deser-scratch :initform nil :accessor dr-deser-scratch) ; RX-POOLING Phase A (ADR 0073): reusable octet-buffer wrapper repointed at the stored bytes per COPY-path drain, so %deserialize-sample decodes IN PLACE with no per-sample make-octet-buffer / replace / free-static (NFR-MEM)
   (wrapper-pool :initform nil :accessor dr-wrapper-pool)   ; ADR 0093 slice 1: a simple-vector STACK of recycled cached-sample wrappers, each still carrying its SampleInfo. Lazily carved on the first return, so a reader that never returns pays nothing. A VECTOR, not a list: a list freelist churns two conses per sample (32 B measured), which is most of what the pooling was meant to save
   (wrapper-pool-top :initform 0 :accessor dr-wrapper-pool-top)   ; stack pointer into WRAPPER-POOL
   (data-pool :initform nil :accessor dr-data-pool)   ; ADR 0093 slice 4: a simple-vector STACK of recycled DESERIALIZED SAMPLE structs. Per-READER, which is what makes it type-safe: one reader has exactly one type, so a parked struct is always the right type for the next sample. (The per-TYPE dds.types:sample-pool is shared across readers and its release has no bounds guard, so it is NOT used here.)
   (data-pool-top :initform 0 :accessor dr-data-pool-top)
   (keyhash-scratch :initform nil :accessor dr-keyhash-scratch) ; RX-POOLING (ADR 0075): reusable :big cursor over a 256-octet buffer for the per-sample instance-handle key serialization — created once, zero per-sample make-octet-buffer/cursor/free-static; single-threaded per reader (the drain runs on the user thread, take is single-threaded-per-reader) (NFR-MEM)
   (keyhash-out :initform nil :accessor dr-keyhash-out) ; RX-POOLING (ADR 0076): reusable 16-octet RESULT array for the drain's TRANSIENT instance-handle — the handle is used only for the instance-rec lookup, then the STABLE handle is read off the rec; created once, zero per-sample make-array on a known instance (NFR-MEM)
   (status-lock :initform (dds.pal:make-lock "dr-status") :accessor dr-status-lock)
   (cache-lock :initform (dds.pal:make-lock "dr-cache") :accessor dr-cache-lock))   ; ADR 0093 slice 3: serialises EVERY mutation of dr-cache / dr-instance-recs / the per-reader scratches. See %WITH-READER-CACHE — the "drained only on the user thread" assumption these structures were built on is FALSE, and this is what makes it true
  (:documentation "DDS DataReader: receives typed samples on a Topic into a read/take
   cache with per-instance SampleInfo, carrying its SUBSCRIPTION_MATCHED,
   REQUESTED_INCOMPATIBLE_QOS and SAMPLE_REJECTED statuses, conditions and listener."))

;; Defined in deadline.lisp (loaded after this file, WP-DCPS-API-COMPLETION S4); forward-declared
;; so write-sample / %drain-one-sample (arm/rearm) and the delete/purge paths (disarm/stop) reach
;; the deadline monitor without a compile-time undefined-function warning.
(declaim (ftype (function (t t) t) %deadline-touch %deadline-disarm-instance))
(declaim (ftype (function (data-writer t t) t) %deadline-touch-writer))
(declaim (ftype (function (t) t) %deadline-disarm-endpoint))
(declaim (ftype (function (domain-participant) t) %deadline-monitor-stop))
;; Defined in autodiscovery.lisp (loaded after this file, WP-DCPS-API-COMPLETION S7); forward-declared so
;; create-participant/enable (start) and delete-participant (stop+join) reach the announcer clean.
(declaim (ftype (function (domain-participant) t) %start-auto-announcer %stop-auto-announcer
                %apply-discovery-cadence))

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
;; conditions.lisp: forward-declared so get_datareaders (S3.T3) can drain+count a reader's
;; newly-received samples on the app thread without a compile-time undefined-function warning.
(declaim (ftype (function (data-reader list &optional list list) (integer 0)) %count-matching))

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
    ;; The participant carries exactly one status, the vendor-extension UNADDRESSABLE_PEER, because that
    ;; condition is a property of a REMOTE PARTICIPANT rather than of any single local endpoint.
    (domain-participant (dp-status-lock entity))
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

(defparameter *status-listener-invokers*
  (list (cons :inconsistent-topic (lambda (l e s) (on-inconsistent-topic l e s)))
        (cons :subscription-matched (lambda (l e s) (on-subscription-matched l e s)))
        (cons :publication-matched (lambda (l e s) (on-publication-matched l e s)))
        (cons :requested-incompatible-qos (lambda (l e s) (on-requested-incompatible-qos l e s)))
        (cons :offered-incompatible-qos (lambda (l e s) (on-offered-incompatible-qos l e s)))
        (cons :sample-rejected (lambda (l e s) (on-sample-rejected l e s)))
        (cons :sample-lost (lambda (l e s) (on-sample-lost l e s)))
        (cons :liveliness-changed (lambda (l e s) (on-liveliness-changed l e s)))
        (cons :liveliness-lost (lambda (l e s) (on-liveliness-lost l e s)))
        (cons :requested-deadline-missed (lambda (l e s) (on-requested-deadline-missed l e s)))
        (cons :offered-deadline-missed (lambda (l e s) (on-offered-deadline-missed l e s)))
        ;; VENDOR EXTENSIONS (ADR 0080, ADR 0089). A status MUST appear here or %notify-status funcalls
        ;; the NIL this assoc returns — and it does so on a RECEIVER THREAD, where the error is swallowed:
        ;; the notification silently never arrives and every other path (bitmask, snapshot) still works.
        ;; That is exactly how the first cut of ADR 0089 measured INERT on a live reliable exchange.
        (cons :unaddressable-peer (lambda (l e s) (on-unaddressable-peer l e s)))
        (cons :reliable-writer-cache-changed
              (lambda (l e s) (on-reliable-writer-cache-changed l e s)))
        (cons :reliable-reader-activity-changed
              (lambda (l e s) (on-reliable-reader-activity-changed l e s)))
        (cons :application-acknowledgment
              (lambda (l e s) (on-application-acknowledgment l e s)))
        (cons :application-acknowledgment-overdue
              (lambda (l e s) (on-application-acknowledgment-overdue l e s))))
  "Maps a communication-status keyword to the closure invoking its on_<status> listener callback
   (listener entity snapshot). The status-generic seam the %notify-status propagation walk uses to
   deliver a status to whichever listener in the containment chain handles it (DDS 1.4 §2.2.4.1).")

(declaim (inline %map-listener-ancestry))
(defun* %map-listener-ancestry (entity fn)
    (function (entity function) t)
  "Call FN on ENTITY then on each containment parent up to the DomainParticipant, MOST-SPECIFIC FIRST —
   the DDS 1.4 §2.2.4.1 listener-propagation chain — and return FN's first non-NIL result, or NIL.
   DataReader: reader -> Subscriber -> participant; DataWriter: writer -> Publisher -> participant;
   Topic: topic -> participant; Publisher/Subscriber: itself -> participant; DomainParticipant: itself.

   NFR-MEM: it WALKS the chain rather than materialising it. This used to return the chain as a fresh
   LIST, and DATA_AVAILABLE notification runs it TWICE per sample on the receiver thread (once on the
   Subscriber for DATA_ON_READERS, once on the DataReader), so five conses — 80 B — were spent per sample
   building two lists that were immediately walked and dropped. The chain is at most three entities and
   its shape is fixed per entity type, so nothing needs to be built to walk it. FN is a downward funarg:
   it is funcalled here and stored nowhere, so a caller may declare it DYNAMIC-EXTENT."
  (typecase entity
    (data-reader (let ((s (dr-subscriber entity)))
                   (or (funcall fn entity) (funcall fn s) (funcall fn (sub-participant s)))))
    (data-writer (let ((pb (dw-publisher entity)))
                   (or (funcall fn entity) (funcall fn pb) (funcall fn (pub-participant pb)))))
    (topic (or (funcall fn entity) (funcall fn (topic-participant entity))))
    (publisher (or (funcall fn entity) (funcall fn (pub-participant entity))))
    (subscriber (or (funcall fn entity) (funcall fn (sub-participant entity))))
    (t (funcall fn entity))))

(defun* %find-enabled-listener (entity status-kw)
    (function (entity keyword) t)
  "The MOST-SPECIFIC listener in ENTITY's containment chain that is installed AND enabled for
   STATUS-KW (its mask contains STATUS-KW), or NIL (DDS 1.4 §2.2.4.1). Walks %map-listener-ancestry,
   reading each entity's listener under its own listener lock; the walk STOPS at the first
   enabled listener (that listener handles the status; propagation goes no further up).
   NFR-MEM: the test is an flet declared DYNAMIC-EXTENT and the ancestry is walked, not built, so the
   whole lookup allocates nothing — it is on the per-sample DATA_AVAILABLE path."
  (flet ((%enabled-listener (e)
           (multiple-value-bind (l mask)
               (dds.pal:with-lock ((%entity-listener-lock e)) (%entity-listener e))
             (and l (member status-kw mask) l))))
    (declare (dynamic-extent #'%enabled-listener))
    (%map-listener-ancestry entity #'%enabled-listener)))

(defun* %notify-status (entity status-bit status-kw apply-fn)
    (function (entity (unsigned-byte 32) keyword function) (eql t))
  "The single communication-status notification chokepoint (DDS 1.4 §2.2.4.1). Under ENTITY's
   status lock it runs APPLY-FN — the status-specific update, which mutates the status struct and
   returns (values CHANGED-P SNAPSHOT RESET-THUNK): SNAPSHOT is a fresh copy of the status handed
   to whichever listener handles it (built whenever CHANGED, so an ancestor listener can receive
   it); RESET-THUNK zeroes the live struct's *_change counters and is run ONLY if a listener
   handles the status. When CHANGED-P, sets STATUS-BIT in the status-changes bitmask under the
   same lock. Then, OUTSIDE the lock, it walks the containment chain (%find-enabled-listener) and
   delivers SNAPSHOT to the MOST-SPECIFIC enabled listener, STOPPING there. If a listener handled
   it, %notify-status runs RESET-THUNK and CLEARS STATUS-BIT (the §2.2.4.1 reset-on-listener-
   invocation: a status a listener consumed is no longer 'changed', so its StatusCondition no
   longer triggers). If no listener is enabled anywhere up the chain, the bit stays set and no
   callback fires. Finally it triggers ENTITY's StatusCondition / reader WaitSets. Behavior-
   preserving: an entity with its own enabled listener is the most-specific link, so it still gets
   the exact prior callback. S4 (deadline / SAMPLE_LOST) reuses THIS chokepoint — no parallel path."
  (let ((changed nil) (snapshot nil) (reset-thunk nil) (lk (%entity-status-lock entity)))
    (dds.pal:with-lock (lk)
      (multiple-value-setq (changed snapshot reset-thunk) (funcall apply-fn))
      (when changed (%set-status-changed entity status-bit)))
    (when changed
      (let ((l (%find-enabled-listener entity status-kw)))
        (when l
          (funcall (cdr (assoc status-kw *status-listener-invokers*)) l entity snapshot)
          (dds.pal:with-lock (lk)
            (when reset-thunk (funcall reset-thunk))
            (%clear-status-changed entity status-bit))))
      (%trigger-status-condition entity)))
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
   valid-data + instance-handle; the generation counts and ranks default to 0/nil and are
   filled in by later increments. State kinds are kept as keywords (READ/NOT_READ,
   NEW/NOT_NEW, ALIVE/NOT_ALIVE_DISPOSED/_NO_WRITERS). sequence-number is a vendor
   extension (the RTPS writer SN).

   PUBLICATION-HANDLE is the 16-octet GUID of the remote DataWriter that wrote this sample
   (DDS 1.4 §2.2.2.5.4; this stack's InstanceHandle_t for a remote endpoint is its GUID, the
   same convention subscription-matched-status-last-publication-handle follows). Populated
   on every delivery path since ADR 0090 A3b, which needs it: acknowledge-sample identifies a
   sample by (writer, sequence number), and a sequence number is unique only within one
   writer GUID (RTPS 2.5 §8.3.5.4) — acknowledging by SN alone would acknowledge a DIFFERENT
   writer's sample of the same number, a false ack.

   ⚠️ IT IS ALIASED, NOT COPIED, AND THAT IS A LOAD-BEARING INVARIANT. The value is the exact
   object the disc node holds in disc-node-sample-writer-guids, which %source-guid freshly
   allocates per received sample and NOTHING ever mutates. Aliasing makes this field cost ZERO
   bytes per sample where a copy-seq would cost ~32 (NFR-MEM; gate-mem has under 40 B of
   headroom), and it is safe only because that object is immutable. THE CONSTRAINT THIS PLACES
   ON ADR 0088: a memoised invariant per-writer GUID (its Option B) keeps this safe; a SHARED
   MUTABLE SCRATCH (its Option A) would silently rewrite a handle the application is already
   holding. ADR 0088 recommends against Option A on other grounds; this is one more, and it is
   application-visible rather than internal."
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
  (info nil :type (or null sample-info))
  (flags 0 :type (unsigned-byte 8)))   ; the two per-wrapper booleans PACKED — see +cs-flag-*+; a 5th slot costs 16 B/sample on the copy arm

(defconstant +cs-flag-data-pinned+ 1
  "CACHED-SAMPLE-FLAGS bit: DATA was retained as an instance's get_key_value key sample (ADR 0093 slice 4),
   so it belongs to the instance-rec FOREVER and must NEVER go back to the reader's data pool.")

(defconstant +cs-flag-was-exposed+ 2
  "CACHED-SAMPLE-FLAGS bit: the application has been handed this wrapper, or its DATA struct, by one of
   the THREE list-returning access paths (ADR 0105 §4.1), so TAKE-INTO must never recycle its struct —
   the application may still be reading it.

   ⚠️ THE SET SITES ARE EXACTLY THE SET %NOTE-ACCESSED IS CALLED FROM, and that is the invariant, not a
   coincidence: %SELECT-SAMPLES-UNLOCKED (READ-SAMPLES / TAKE-SAMPLES and the six _instance/_next entries),
   TAKE-LOANED and READ-LOANED. Anything that hands a sample out marks it accessed; anything that hands a
   sample out must also latch it. READ-LOANED is the sharp one — it hands out the pooled DATA struct and
   LEAVES the wrapper in DR-CACHE, so a later TAKE-INTO re-selects it and, without the latch, parks a
   struct the application is still reading (measured: the held sample's fields changed under it).")

;;; ⚠️ THESE TWO BOOLEANS SHARE ONE SLOT, AND THAT IS A MEASURED DECISION, NOT TIDINESS. They were separate
;;; BOOLEAN slots until 2026-08-06. On SBCL/arm64 a 4-slot defstruct is 47.8 B and a 5-slot one is 64.2 B
;;; (measured), and the COPY arm allocates one wrapper PER SAMPLE because it never returns a loan and so
;;; never recycles — so the fifth slot cost a measured +17 B/sample on the very arm this ECR exists to drive
;;; to zero, while RETURN (which recycles) was unaffected. Packing restores 4 slots. A THIRD flag is free;
;;; a third SLOT would not be.

(declaim (inline cached-sample-data-pinned cached-sample-was-exposed %cs-set-flag))

(defun* cached-sample-data-pinned (cs)
    (function (cached-sample) boolean)
  "T when CS's DATA is an instance's pinned get_key_value key sample (ADR 0093 slice 4). Reads the packed
   FLAGS slot; see the note above for why it is packed."
  (logtest (cached-sample-flags cs) +cs-flag-data-pinned+))

(defun* cached-sample-was-exposed (cs)
    (function (cached-sample) boolean)
  "T once CS — or its DATA struct — has been handed to the application by any of the three list-returning
   access paths (ADR 0105 §4.1: %SELECT-SAMPLES-UNLOCKED, TAKE-LOANED, READ-LOANED). TAKE-INTO recycles
   only wrappers whose bit is CLEAR, because the application may still be holding an exposed one."
  (logtest (cached-sample-flags cs) +cs-flag-was-exposed+))

(defun* %cs-set-flag (cs bit on)
    (function (cached-sample (unsigned-byte 8) t) (unsigned-byte 8))
  "Set (ON non-NIL) or clear BIT in CS's packed FLAGS, returning the new flags. The write half of the two
   readers above — this codebase has no (setf name) function precedent, so the setter is named."
  (setf (cached-sample-flags cs)
        (if on
            (logior (cached-sample-flags cs) bit)
            (logandc2 (cached-sample-flags cs) bit))))

(defparameter *rx-wrapper-pool-enabled* t
  "ADR 0093 slice 1 — the RX copy path's WRAPPER pooling (cached-sample + sample-info), on by default.
   NIL restores the pre-slice behaviour: a fresh wrapper pair per delivered sample.

   This is the A/B lever ADR 0062 requires for sizing an allocation change against `make gate-mem`, and the
   escape hatch if a recycled wrapper is ever suspected of aliasing. ⚠️ SET IT GLOBALLY (SETF), never with
   LET: the drain runs on the receiver and user threads, so a thread-local binding is invisible there and
   the A/B reads as a no-op 'dud' — the trap that produced two false negatives in the allocation campaign.
   Delivered behaviour is IDENTICAL either way; only the allocation differs.")

(defmacro %with-reader-cache ((dr) &body body)
  "Run BODY holding DR's cache lock — the serialisation of the reader-side sample cache (ADR 0093 slice 3).

   ⚠️ THE INVARIANT THIS ENFORCES DID NOT HOLD. %DRAIN's docstring stated that both streams are drained on
   the user thread 'so the reader cache + instance-recs are never mutated off-thread (S2)', and
   dr-keyhash-scratch's says the take path is 'single-threaded-per-reader'. Neither was true. THREE
   independent contexts mutate DR-CACHE with no synchronisation whatever:

     1. the application thread — read/take/samples-available, all of which %DRAIN;
     2. whatever thread calls WAIT-SET-WAIT — its trigger predicate (%COUNT-MATCHING) %DRAINs too, and
        WS-LOCK does not exclude a taker, which never acquires it;
     3. the discovery/announcer thread — %ON-DISC-UNMATCH -> %ON-WRITER-VANISHED and %SPIN-ONCE ->
        %AUTOPURGE-SWEEP both rewrite DR-CACHE and the instance-recs.

   Concurrently SETF-ing and NCONC-ing one list from two threads loses samples outright. Today that is a
   data race on GC-managed objects; once the delivery wrappers are POOLED (ADR 0093 slice 4) the same race
   recycles a struct another thread is reading — a use-after-free no correctness test would see. That is
   why this is a PREREQUISITE of slice 4 rather than a tidy-up.

   ⚠️ LOCK ORDER: THIS LOCK IS OUTER, THE NODE LOCK IS INNER. %DRAIN takes the node lock inside this one
   (node-collect-pending-* / node-consume-sample). Nothing may take the node lock and then this: the
   discovery unmatch hook is safe precisely because %PRUNE-PARTICIPANT-LOCKED hands its removed matches out
   and fires ON-UNMATCH *outside* the node lock (dds-disc/disc.lisp).

   ⚠️ NOT RECURSIVE. An entry point that already holds it must call the -UNLOCKED variant — %DRAIN reaches
   RETURN-LOAN through the KEEP_LAST loan drop, and RETURN-LOAN recurses into itself for a wrapper that
   wraps a loan, so both go through %RETURN-LOAN-UNLOCKED."
  `(dds.pal:with-lock ((dr-cache-lock ,dr)) ,@body))

(defparameter *rx-wrapper-pool-capacity* 64
  "How many returned delivery wrappers ONE DataReader parks for reuse (ADR 0093 slice 1). Read once, when
   a reader's pool is lazily carved — on its first RETURN-LOAN, or, since ADR 0105, on its first TAKE-INTO
   that recycles (the two callers of %RECYCLE-DELIVERY).

   It is a CAP, not a budget: steady state needs ONE (take, return, reuse). The depth only matters for a
   burst — an application that takes N samples and returns them together — and beyond it a returned wrapper
   is simply dropped for the GC rather than parked. Bounded on purpose: an unbounded freelist would let an
   application that returns far more than it takes grow the pool without limit, which is a leak wearing an
   optimisation's clothes.")

(defun* %acquire-delivery (dr data instance-state instance-handle sequence-number publication-handle
                           source-timestamp disposed-gen no-writers-gen)
    (function (t t t (or null (array (unsigned-byte 8) (*))) integer
               (or null (array (unsigned-byte 8) (*))) (or null integer) integer integer)
              cached-sample)
  "Return a fully-initialised cached-sample + SampleInfo for a freshly delivered sample — popped from DR's
   wrapper pool when ADR 0093 slice-1 pooling is on and one is parked, otherwise freshly allocated (the
   pool NEVER blocks delivery: an empty pool allocates, so an application that does not RETURN-LOAN simply
   gets the pre-slice behaviour rather than a failure).

   THE PAIR IS POOLED AS ONE OBJECT. A parked wrapper keeps its SampleInfo attached, so one pop yields
   both — which is why there is one pool and not two, and why nothing is consed to link them.

   ⚠️ THERE IS EXACTLY ONE INITIALISATION PATH, AND THAT IS THE POINT. A recycled SampleInfo is reused
   UNINITIALISED and every one of its 13 slots is then assigned unconditionally — including the three ranks
   nothing else writes. Had the fresh case used MAKE-SAMPLE-INFO with keywords and the recycled case a
   separate SETF block, the two field lists would drift the first time a slot is added, and the failure
   would be a PREVIOUS sample's value surfacing in this one: silent, application-visible, and invisible to
   every allocation gate (gate-mem measures bytes, not correctness). ADDING A SLOT TO SAMPLE-INFO REQUIRES
   ADDING IT HERE. The wrapper's own LOAN slot is cleared for the same reason — a stale loan would make
   RETURN-LOAN release a loan this sample never held."
  (let* ((cs (or (and *rx-wrapper-pool-enabled* (%rx-wrapper-pop dr))
                 (make-cached-sample)))
         (si (or (cached-sample-info cs) (make-sample-info))))
    (setf (sample-info-sample-state si) :not-read
          (sample-info-view-state si) :new
          (sample-info-instance-state si) instance-state
          (sample-info-source-timestamp si) source-timestamp
          (sample-info-instance-handle si) instance-handle
          (sample-info-publication-handle si) publication-handle   ; ALIASED, never copied — see the slot docstring
          (sample-info-disposed-generation-count si) disposed-gen
          (sample-info-no-writers-generation-count si) no-writers-gen
          (sample-info-sample-rank si) 0
          (sample-info-generation-rank si) 0
          (sample-info-absolute-generation-rank si) 0
          (sample-info-valid-data si) t
          (sample-info-sequence-number si) sequence-number)
    (setf (cached-sample-data cs) data
          (cached-sample-loan cs) nil
          (cached-sample-flags cs) 0   ; ADR 0105: a RECYCLED wrapper carries stale bits; this delivery is unpinned and unexposed
          (cached-sample-info cs) si)
    cs))

(defun* %rx-wrapper-pop (dr)
    (function (t) (or null cached-sample))
  "Pop a parked delivery wrapper off DR's pool, or NIL when the pool is empty or not yet carved."
  (let ((pool (dr-wrapper-pool dr))
        (top (dr-wrapper-pool-top dr)))
    (when (and pool (plusp top))
      (let ((nt (1- top)))
        (setf (dr-wrapper-pool-top dr) nt)
        (let ((cs (svref pool nt)))
          (setf (svref pool nt) nil)   ; drop the pool's reference so a parked wrapper is never double-held
          cs)))))

(defun* %rx-data-pop (dr)
    (function (t) t)
  "Pop a recycled deserialized sample off DR's data pool, or NIL when empty / not yet carved. The caller
   decodes INTO it; a NIL simply means this delivery allocates, as it did before ADR 0093 slice 4."
  (let ((pool (dr-data-pool dr))
        (top (dr-data-pool-top dr)))
    (when (and pool (plusp top))
      (let ((nt (1- top)))
        (setf (dr-data-pool-top dr) nt)
        (let ((d (svref pool nt)))
          (setf (svref pool nt) nil)
          d)))))

(defun* %rx-data-push (dr data)
    (function (t t) t)
  "Park DATA on DR's data pool for the next delivery to decode into (ADR 0093 slice 4). Bounded by
   *RX-WRAPPER-POOL-CAPACITY*; beyond it the struct is dropped for the GC. A no-op when pooling is off or
   DATA is NIL, so the lever is a true no-op on both ends."
  (when (and *rx-wrapper-pool-enabled* data)
    (let ((pool (or (dr-data-pool dr)
                    (setf (dr-data-pool dr)
                          (make-array *rx-wrapper-pool-capacity* :initial-element nil))))   ; HOTPATH-ALLOC(COLD): once per reader
          (top (dr-data-pool-top dr)))
      (when (< top (length pool))
        (setf (svref pool top) data
              (dr-data-pool-top dr) (1+ top)))))
  t)

(defun* %recycle-delivery (dr cs)
    (function (t cached-sample) t)
  "Park CS (with its SampleInfo attached) on DR's wrapper pool for reuse (ADR 0093 slice 1).

   ⚠️ THERE ARE EXACTLY TWO CALLERS, AND EACH CARRIES ITS OWN PROOF THAT THE APPLICATION IS DONE WITH CS.
   (1) RETURN-LOAN (ADR 0093 slice 1) — the application EXPLICITLY gave the wrapper back.
   (2) TAKE-INTO, and only for a wrapper whose +CS-FLAG-WAS-EXPOSED+ is CLEAR (ADR 0105 §4.1) — the
       application was NEVER given this wrapper or its struct, because take-into copies out of it into the
       caller's own storage and hands back nothing. The latch is the proof, and it is why that call site is
       safe without an explicit return. WITHOUT the latch test it is NOT safe: an earlier READ-SAMPLES or
       READ-LOANED leaves its wrapper in DR-CACHE and a later take-into re-selects it.
   ⛔ A THIRD CALLER NEEDS A THIRD PROOF OF THE SAME STRENGTH. Do not add one on the grounds that the
   sample is leaving the cache — see the next paragraph.

   ⚠️ IT IS NEVER CALLED ON AN EVICTION THAT DOES NOT ALSO PROVE THE APPLICATION IS DONE, AND THAT IS
   DELIBERATE. A KEEP_LAST drop removes a sample from DR-CACHE, but READ is non-destructive — the
   application may still hold that very wrapper from an earlier read. Recycling it there would hand its
   struct to the next sample while the application is still reading it: a wrong-bytes aliasing bug, the
   copy-path twin of the loan use-after-free %READER-KEEPLAST-DROP-OLDEST-LOAN exists to prevent. Leaving
   the cache is NOT the proof; an explicit return, or a wrapper that provably never left, is. DATA is NOT
   recycled by caller (1)'s path beyond ADR 0093 slice 4's key-sample carve-out, honoured below.

   ⚠️ IT ALSO RESPECTS *RX-WRAPPER-POOL-ENABLED*. Parking while the acquire side is disabled would push onto
   a pool nothing ever draws from — an unbounded leak, and it measured +33.5 B/sample in the slice's own A/B
   before this guard existed. The lever must be a true no-op on BOTH ends or it is not an A/B.

   DATA and LOAN are cleared before parking, so a pooled wrapper never pins a deserialized sample."
  (when *rx-wrapper-pool-enabled*
    ;; ADR 0093 slice 4: the deserialized struct goes back to the data pool for the next decode — UNLESS it
    ;; was pinned as an instance's get_key_value key sample, in which case the instance-rec owns it forever
    ;; and recycling it would rewrite that instance's key under GET_KEY_VALUE. A pinned struct is simply
    ;; dropped from the pool's view; the next delivery allocates one. That is O(instances), not O(samples).
    (unless (cached-sample-data-pinned cs)
      (%rx-data-push dr (cached-sample-data cs)))
    (setf (cached-sample-data cs) nil
          (cached-sample-loan cs) nil)
    (%cs-set-flag cs +cs-flag-data-pinned+ nil)   ; INFO stays attached — the pair is pooled as one object
    (let ((pool (or (dr-wrapper-pool dr)
                    (setf (dr-wrapper-pool dr)
                          (make-array *rx-wrapper-pool-capacity* :initial-element nil))))   ; HOTPATH-ALLOC(COLD): once per reader, on its first return
          (top (dr-wrapper-pool-top dr)))
      (when (< top (length pool))   ; beyond the cap the wrapper is simply dropped for the GC — a cap, not a budget
        (setf (svref pool top) cs
              (dr-wrapper-pool-top dr) (1+ top)))))
  t)

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
  (not-alive-since nil :type (or null (integer 0)))
  (handle nil :type (or null (simple-array (unsigned-byte 8) (16))))   ; RX-POOLING (ADR 0076): this instance's STABLE 16-octet handle (= its dr-instance-recs hash key), copied ONCE at creation from the drain's reused key-hash scratch; SampleInfo + retention sites read it so the drain's per-sample handle need not be freshly allocated (NFR-MEM)
  (key-sample nil :type t))   ; S5.T1: a representative delivered sample carrying this instance's key fields (get_key_value); the handle is a one-way hash so the key is retained here

;;; ---- type-support serialization helpers (PLAIN_CDR(2)_LE SerializedPayload) ----

(defun* %rep->codec (rep &optional ext)
    (function (symbol &optional symbol)
              ;; The MUTABLE ids belong in this list: encapsulation-id-for maps (:xcdr2 :mutable) to
              ;; PL_CDR2_LE and (:xcdr1 :mutable) to PL_CDR_LE, so omitting them made the declared
              ;; return type a statement the function contradicts — and callers compile at (safety 0),
              ;; where the declaration is believed rather than checked.
              (values dds.cdr:cdr-mode
                      (member :plain-cdr2-le :plain-cdr-le :delimited-cdr-le :pl-cdr2-le :pl-cdr-le)))
  "Map a writer's OFFERED data-representation keyword (DDS-XTypes 1.3 §7.6.3.1.1) to the
   (values CODEC-MODE ENCAP-REP) the TX SerializedPayload uses: :xcdr2 -> (:xcdr2 :plain-cdr2-le),
   :xcdr1 -> (:xcdr1 :plain-cdr-le). CODEC-MODE drives the generated serializer's alignment cap
   (FR-CDR-2); ENCAP-REP names the +representation-ids+ encapsulation id (§7.6.3.1.2 Table 60) the
   4-octet header carries (XCDR2-LE 0x0007 / XCDR1-LE 0x0001). The XML / BE representations are out
   of scope on TX (we send LE); a NIL (absent) rep maps to the :xcdr2 default (back-compat), and any
   other unmapped rep (e.g. :xml) SIGNALS via the ecase — a FINAL PLAIN-encapsulated writer sends only
   XCDR1/XCDR2-LE.

   EXT is the TYPE'S EXTENSIBILITY, and it changes the encapsulation id — DDS-XTypes 1.3 Table 60
   keys the id on extensibility as well as encoding version: FINAL+v2+LE is CDR2_LE 0x0007 but
   APPENDABLE+v2+LE is D_CDR2_LE 0x0009. The id must agree with the framing the codec emits, because
   0x0007 tells a conformant peer there is NO DHEADER and it would read the DHEADER's four octets as
   the first member. Under XCDR1 rule (29) serializes APPENDABLE exactly as FINAL, so both map to
   PLAIN_CDR_LE and no distinction is needed there."
  (values (ecase rep ((:xcdr2 nil) :xcdr2) (:xcdr1 :xcdr1))
          (dds.cdr:encapsulation-id-for rep ext)))

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
  (multiple-value-bind (mode encap) (%rep->codec rep (dds.types:type-support-extensibility ts))
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

(defmacro %with-sample-serializer-into ((var ts sample rep dw) &body body)
  "WP-PERF (NFR-MEM / NFR-PERF-8): bind VAR to a serializer of SAMPLE — (lambda (octet-buffer) -> LENGTH),
   writing the SerializedPayload (encapsulation header + body + finalized options) DIRECTLY into a
   caller-supplied buffer — and run BODY. Framing is byte-identical to %serialize-sample (same %rep->codec,
   same header, same finalize); the ONLY difference is that the buffer is supplied, not allocated.

   That difference is the point: %serialize-sample allocated a static octet-buffer (alloc + ZERO), serialized,
   allocated a FRESH GC-HEAP vector, memcpy'd into it and freed the static buffer — two allocations, a zeroing,
   a copy and a free, on EVERY write. This serializer lets dds.disc:publish-sample-into serialize straight into
   an arena-pooled buffer the CacheChange then owns.

   ⚠️ IT IS A MACRO, AND THAT IS THE WHOLE POINT (ADR 0072). It used to be a function RETURNING the closure,
   and a closure that is RETURNED must be heap-allocated — SBCL cannot stack-allocate through the escape —
   so every write consed one (~48 B: header + code + the four captured values). As an flet declared
   DYNAMIC-EXTENT it stack-allocates instead. This is sound because publish-sample-into is a pure DOWNWARD
   FUNARG consumer: it funcalls the serializer in its pooled arm and in its `allocating` fallback (itself a
   local labels that never escapes) and stores it nowhere. Same idiom, same reasoning, as the per-ACKNACK
   %build-acknack builder.

   A FlatData type with a non-XCDR2 offered rep still needs the transcoding builder (which allocates), so that
   case is not eligible — the caller (write-sample) routes it to the allocating path."
  (let ((mode (gensym "MODE")) (encap (gensym "ENCAP")) (ser (gensym "SER")) (w (gensym "DW")))
    `(multiple-value-bind (,mode ,encap)
         (%rep->codec ,rep (dds.types:type-support-extensibility ,ts))
       (let ((,ser (dds.types:type-support-serialize ,ts))
             (,w ,dw))
         (flet ((,var (buf)
                  (let ((wc (setf (dw-payload-cursor ,w)
                                  (dds.core.buffer:cursor-reuse (dw-payload-cursor ,w) buf))))
                    (dds.cdr:make-encapsulation-header wc ,encap)
                    (funcall ,ser ,sample wc ,mode)
                    (dds.cdr:finalize-encapsulation-options wc ,encap)
                    (dds.core.buffer:cursor-position wc))))
           (declare (dynamic-extent #',var))
           ,@body)))))

(defun* %flatdata-transcoding-p (ts rep)
    (function (t symbol) t)
  "T iff serializing under REP needs the FlatData TX transcoding builder (a FlatData type whose OFFERED rep is
   not XCDR2) — the one shape that cannot serialize straight into a supplied buffer, so it stays on the
   allocating path (R6, off the measured hot path anyway)."
  (and (dds.types:type-support-flatdata-builder ts)
       (not (eq (nth-value 0 (%rep->codec rep)) :xcdr2))))

(defun* %encap->codec (encap)
    (function (symbol) (values dds.cdr:cdr-mode (member :little :big)))
  "Map a parsed SerializedPayload encapsulation id (a +representation-ids+ key, DDS-XTypes 1.3
   §7.6.3.1.2 Table 60) to the (values CODEC-MODE ENDIANNESS) the struct codec decodes the body in:
   PLAIN_CDR_LE -> (:xcdr1 :little), PLAIN_CDR_BE -> (:xcdr1 :big), PLAIN_CDR2_LE -> (:xcdr2 :little),
   PLAIN_CDR2_BE -> (:xcdr2 :big). The inverse of %rep->codec for RX: a reader accepting (:xcdr2 :xcdr1)
   reads whichever representation a peer wrote (WP-DATA-REPRESENTATION; the 8-vs-4 alignment + endianness
   come from the wire, not a hardcoded :xcdr2). DELIMITED_CDR_LE/BE (0x0009/0x0008) is an APPENDABLE
   type under encoding version 2 (Table 60) and maps to the same XCDR2 mode — its leading DHEADER is
   consumed by the generated deserializer, not here. PL_CDR2_LE/BE (0x000b/0x000a) and PL_CDR_LE/BE
   (0x0003/0x0002) are a MUTABLE type under encoding version 2 and 1 respectively and map to those
   codec modes; their per-member headers are likewise consumed by the generated deserializer. A NIL
   (absent) encap maps to the XCDR2-LE default (back-compat); a known-but-unmapped encap (XML) SIGNALS
   via the ecase — the correct conservative reject, since such a body is not decodable here
   (truly-unknown ids are already rejected upstream by parse-encapsulation-header)."
  (ecase encap
    (:plain-cdr-le   (values :xcdr1 :little))
    (:plain-cdr-be   (values :xcdr1 :big))
    ((:plain-cdr2-le nil) (values :xcdr2 :little))
    (:plain-cdr2-be  (values :xcdr2 :big))
    ;; DELIMITED_CDR = an APPENDABLE type under encoding version 2 (Table 60). Same XCDR2 codec
    ;; mode; the leading DHEADER is consumed by the generated deserializer, not here. Rejecting it
    ;; would be a false-REJECT of a conformant peer's appendable sample.
    (:delimited-cdr-le (values :xcdr2 :little))
    (:delimited-cdr-be (values :xcdr2 :big))
    ;; PL_CDR2 / PL_CDR = a MUTABLE type (Table 60), encoding version 2 and 1. While MUTABLE was
    ;; unimplemented these fell through the ecase and SIGNALLED, and this docstring called that "the
    ;; correct conservative reject" — which it was, for exactly as long as no mutable type could
    ;; exist. It is now a false-REJECT of every conformant mutable peer, and of our OWN writer's
    ;; samples: encapsulation-id-for stamps a mutable payload with precisely the id refused here.
    (:pl-cdr2-le (values :xcdr2 :little))
    (:pl-cdr2-be (values :xcdr2 :big))
    (:pl-cdr-le  (values :xcdr1 :little))
    (:pl-cdr-be  (values :xcdr1 :big))))

(defun* %deserialize-payload (ts ob &optional into)
    (function (t dds.core.buffer:octet-buffer &optional t) (values t (or null keyword)))
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
        ;; A FlatData :deserialize returns (values sample status) — a forged/short payload or a
        ;; non-transcodable representation id is now a STATUS, not a signalled reject (ADR 0064: a macro may
        ;; never emit a condition into generated code). A classic struct :deserialize returns one value, so
        ;; its status reads as NIL. Both shapes pass straight through.
        ;; ADR 0093 slice 4: with INTO (a recycled sample of this reader's type) decode IN PLACE and
        ;; allocate nothing. The generated deserialize-into resets every slot to its default BEFORE the
        ;; walk, so a member absent from THIS sample cannot keep the previous occupant's value — which is
        ;; also why a half-written struct left by a FAILED decode is harmless: the next use rewrites it
        ;; wholesale. A FlatData type has no struct-targeted into-variant, so it falls back to allocating.
        (let ((dnto (and into (dds.types:type-support-deserialize-into ts))))
          (if dnto
              (funcall dnto into rc mode)
              (funcall (dds.types:type-support-deserialize ts) rc mode)))))))

(defun* %deserialize-sample (ts bytes &optional scratch into)
    (function (t (simple-array (unsigned-byte 8) (*)) &optional (or null dds.core.buffer:octet-buffer) t)
              (values t (or null keyword)))
  "Deserialize a SerializedPayload (encap header + body) into a sample via TS. RX-POOLING Phase A (ADR 0073,
   NFR-MEM): decode DIRECTLY from the caller-owned BYTES — %deserialize-payload only READS the buffer (a cursor
   + aref, never a SAP) and returns an INDEPENDENT struct, so no copy is ever needed. When SCRATCH (a reusable
   octet-buffer wrapper) is supplied — the hot drain path passes the per-reader dr-deser-scratch — it is repointed
   at BYTES in place, so a steady-state take allocates ZERO here: no make-octet-buffer, no replace, no free-static.
   With no SCRATCH (the standalone/test path) a fresh octet-buffer-over wrapper is allocated but still shares BYTES
   — no static allocation, no copy. Byte-identical to the old copy-then-decode either way. BYTES must outlive this
   call (it does: %drain runs on the user thread, the receiver never mutates a stored sample, and
   node-consume-sample frees it only after the drain). Mirrors the secured path's dr-secured-scratch. See
   %deserialize-payload for the representation-selection contract."
  (let ((ob (cond (scratch (setf (dds.core.buffer:octet-buffer-vec scratch) bytes
                                 (dds.core.buffer:octet-buffer-capacity scratch) (length bytes))
                           scratch)
                  (t (dds.core.buffer:octet-buffer-over bytes)))))
    (%deserialize-payload ts ob into)))

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
              (values (or dds.security:access-handle null) (or null keyword)))
  "DDS-Security 1.1 §8.4: validate a participant's AccessControl configuration, returning the
   ACCESS-HANDLE to install, or NIL when AccessControl is OFF (any of IDENTITY / PERMISSIONS-CA /
   GOVERNANCE / PERMISSIONS absent — AC requires an authenticated identity plus both signed §9.4
   documents). When all are supplied: CMS-verify the signed Governance + Permissions against the
   Permissions CA and bind the LOCAL grant by the identity cert's subject name
   (validate-local-permissions), then gate check_create_participant (§8.4.2.3). Fail-closed: an
   invalid/denied config returns (values nil STATUS) — :no-subject-name / :permissions-validation-failed /
   :participant-denied — so create-participant fails closed (the participant does not join) with no signal
   (ADR 0064), freeing the handle on a check_create_participant denial. Validated up-front (before the engine
   opens) so the reject path leaks no node. The *_WITH_ORIGIN_AUTHENTICATION discovery tier (receiver-specific MACs for the builtin
   secure-SEDP endpoints, §9.5.3.3.4.3) is now WIRED (T-ORIGINAUTH), so it is accepted here — its origin-auth
   flag is carried to the disc-node by %install-access-control (no longer refused)."
  (when (and identity permissions-ca governance permissions)
    (let ((subject (dds.dare:x509-subject-name (dds.security:identity-handle-cert identity))))
      (unless subject
        (bail :no-subject-name))
      (let ((ah (dds.security:validate-local-permissions permissions-ca governance permissions subject)))
        (unless ah
          (bail :permissions-validation-failed))
        (unless (dds.security:check-create-participant ah)
          (dds.security:free-access-handle ah)
          (bail :participant-denied))
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
                                 (port 0) (autonomous nil)
                                 (identity nil) (permissions-ca nil) (governance nil) (permissions nil))
    (function (&key (:domain (integer 0)) (:qos t) (:advertise-address string) (:peers list)
                    (:port (unsigned-byte 16)) (:autonomous t)
                    (:identity t)
                    (:permissions-ca (or (simple-array (unsigned-byte 8) (*)) null))
                    (:governance (or (simple-array (unsigned-byte 8) (*)) null))
                    (:permissions (or (simple-array (unsigned-byte 8) (*)) null)))
              (values (or null domain-participant) (or null keyword)))
  "DomainParticipantFactory::create_participant — open the RTPS engine (a multicast
   disc-node) for DOMAIN, install the match/incompatible-QoS hooks that surface DDS
   statuses to the application, start the receiver, and return an enabled participant.

   Returns (values participant NIL). If the ENGINE cannot be opened — the OS refuses a socket option, the
   SPDP multicast join, or the SHMEM segment — it returns (values NIL status) rather than signalling: this
   is the TOPLEVEL DDS API boundary, where the operating contract requires a failure to surface as a
   returned value (DDS 1.4 create_participant likewise returns a NULL handle on failure, so the NIL primary
   value is the conformant shape). Callers MUST check it; a NIL participant is not usable.
   AUTONOMOUS (WP-DCPS-API-COMPLETION S7): T spawns a background announcer thread that drives the SPDP/SEDP
   announce + the lease/liveliness/autopurge sweeps on the DISCOVERY_CONFIG announce-period cadence, so the
   application never calls spin (spin becomes a no-op). NIL (default) = the deterministic app-driven spin.
   QOS carries the DISCOVERY_CONFIG vendor extension that tunes that cadence and the leaseDuration this
   participant announces to peers (dds.qos: qos-discovery-announce-period / qos-discovery-lease-duration;
   defaults 1 s / 100 s). Both are changeable via set_qos.
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
  (let ((access-handle (try (%validate-access-config identity permissions-ca governance permissions)))
        (installed nil))   ; T once the participant is fully constructed and will be returned
    (unwind-protect
        (let* ((node (try (dds.disc:make-disc-node
                           :domain domain :multicast t
                           :advertise-address advertise-address
                           :peers peers :port port
                           ;; §9.3.2.1: a security-enabled participant announces the
                           ;; authenticated GUID derived from its identity cert (so a
                           ;; conformant peer accepts our handshake); plain = demo prefix.
                           :guid-prefix (if identity
                                            (%participant-guid-prefix identity)
                                            (%make-guid-prefix))
                           :identity-token-octets
                           (when identity (dds.security:identity-token identity)))))
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
          (setf (dds.disc:disc-node-on-unaddressable node)   ; owner directive 2026-07-22: matched => addressable, else ERROR reported
                (lambda (guid kinds) (%on-disc-unaddressable p guid kinds)))
          (setf (dds.disc:disc-node-on-sample-lost node)   ; WP-DCPS-API-COMPLETION S4: reliable-GAP SAMPLE_LOST (DDS 1.4 §2.2.4.1) -> the matched DataReader
                (lambda (rid n)
                  (let ((dr (%participant-reader-by-entity-id p rid)))
                    (when dr (%fire-sample-lost dr n)))))
          (setf (dds.disc:disc-node-on-writer-cache node)   ; ADR 0089: RELIABLE_WRITER_CACHE_CHANGED
                (lambda (wid unacked replaced)
                  (let ((dw (%participant-writer-by-entity-id p wid)))
                    (when dw (%notify-writer-cache-changed dw unacked replaced)))))
          (setf (dds.disc:disc-node-on-reader-activity node)   ; ADR 0089: RELIABLE_READER_ACTIVITY_CHANGED
                (lambda (wid reader-guid activep)
                  (let ((dw (%participant-writer-by-entity-id p wid)))
                    (when dw (%notify-reader-activity dw reader-guid activep)))))
          (setf (dds.disc:disc-node-on-app-ack node)   ; ADR 0090 A3c: APPLICATION_ACKNOWLEDGMENT
                (lambda (wid reader-guid last-sn app-unacked)
                  (let ((dw (%participant-writer-by-entity-id p wid)))
                    (when dw (%notify-application-acknowledgment dw reader-guid last-sn app-unacked)))))
          (%install-type-gate p)   ; FR-TYPE-4 assignability gate (type-gate.lisp)
          (when identity           ; DDS-Security §8.7 auth manager — only for a security-enabled participant
            ;; pass the configured signed Permissions octets so the handshake emits c.perm (§9.3.2.1, T6)
            (%install-auth-manager p identity permissions))
          (when access-handle      ; DDS-Security §8.4 AccessControl manager — validated above, install the gate
            ;; A mixed-kind governance is a FAIL-CLOSED reject: create-participant returns (values NIL status)
            ;; and the unwind-protect below frees the access-handle (installed is still NIL). ADR 0064.
            (try (%install-access-control p access-handle)))
          (dds.disc:start-node node)
          (setf (dp-autonomous-p p) autonomous)   ; WP-DCPS-API-COMPLETION S7: autonomous discovery mode
          (%apply-discovery-cadence p)   ; S7: push the DISCOVERY_CONFIG announced leaseDuration onto the node BEFORE the first announce
          (setf installed t)   ; construction complete; p owns the access-handle via dp-access-state
          (%factory-register-participant (get-participant-factory) p)   ; S2.T1: the free-fn is the factory shim (DDS 1.4 §2.2.2.2.2)
          (%start-auto-announcer p)   ; S7: spawn the announcer if autonomous + enabled (idempotent; no-op otherwise)
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
  ;; ⚠️ BOTH STOPS ARE BOUNDED, AND THEIR STATUS GATES EVERYTHING BELOW (ADR 0092). The announcer SENDS
  ;; SPDP/SEDP through the node's announce buffers, and the deadline monitor can reach an application
  ;; listener that writes — so a thread that cannot be PROVEN stopped must not have the node freed under
  ;; it. Both are attempted (each is signal-then-join, so trying the second is strictly useful even when
  ;; the first timed out); if either could not be proven, the participant is left INTACT and RETRYABLE
  ;; rather than half-deleted, and the timeout is reported via dds.pal:stuck-teardown-joins.
  (multiple-value-bind (announcer-ok announcer-status) (%stop-auto-announcer p)   ; S7: stop + JOIN the autonomous announcer thread BEFORE node teardown
    (declare (ignore announcer-ok))
    (multiple-value-bind (monitor-ok monitor-status) (%deadline-monitor-stop p)   ; S4: stop + JOIN the deadline monitor thread BEFORE tearing the node down
      (declare (ignore monitor-ok))
      (when (or announcer-status monitor-status)
        (return-from delete-participant t))))
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

(defun* participant-guid-prefix (p)
    (function (domain-participant) (simple-array (unsigned-byte 8) (12)))
  "P's 12-octet RTPS GUID prefix (DDSI-RTPS 2.5 §8.2.4.2) — the network-unique participant identity
   that every endpoint GUID on P carries as its high 12 octets. Exposed as public DCPS surface for
   identity-stamping (e.g. the logging service's participant_uuid, ADR 0082 §3) so a consumer reads
   the participant's identity without reaching into the discovery node."
  (dds.disc:disc-node-guid-prefix (dp-node p)))

(defun* participant-advertise-address (p)
    (function (domain-participant) string)
  "The address P advertises its unicast locators at — its create-participant :advertise-address
   (default 127.0.0.1), IPv4 or IPv6 — i.e. where remote peers reach P on the DDS network. Exposed as
   public DCPS surface for identity-stamping (e.g. the logging service's host_ip, ADR 0082 §3)."
  (dds.disc:disc-node-advertise-address (dp-node p)))

(defun* %spin-once (p)
    (function (domain-participant) (eql t))
  "One discovery announce + sweep cycle for P (the spin body): SPDP announce (announce-participant) + SEDP
   announce + lease/liveliness aging (announce-endpoints) + writer-side LIVELINESS_LOST + reader
   READER_DATA_LIFECYCLE autopurge. Driven by spin (the deterministic manual/test path) AND by the S7
   auto-announcer thread (autonomous mode). Uses the node's announce send buffers (tx-msg/tx-payload) —
   ONE driver at a time (spin no-ops in autonomous mode)."
  (dds.disc:announce-participant (dp-node p))
  (dds.disc:announce-endpoints (dp-node p))
  (%writer-liveliness-sweep p)   ; writer-side LIVELINESS_LOST on the DCPS cadence (DDS 1.4 §2.2.3.11)
  (dolist (dr (%participant-readers p)) (%autopurge-sweep dr))   ; READER_DATA_LIFECYCLE autopurge (DDS 1.4 §2.2.3.22)
  t)

(defun* spin (p)
    (function (domain-participant) (eql t))
  "Drive one discovery announce + sweep cycle for P (SPDP + SEDP + aging) — the DETERMINISTIC manual/test
   path (%spin-once). A NO-OP when P is in AUTONOMOUS mode (WP-DCPS-API-COMPLETION S7): the background
   announcer thread owns the node's announce send buffers, so a concurrent spin would race them; an
   autonomous participant discovers/matches/ages peers with no app-driven spin."
  (unless (dp-autonomous-p p) (%spin-once p))
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
    (function (publisher topic &key (:qos t)) (values (or null data-writer) (or null keyword)))
  "Publisher::create_datawriter — register a local writer in the engine on the
   topic's name/type with the QoS reliability (v1: the single user writer); the
   endpoint kind (WITH_KEY/NO_KEY) is selected from the topic type's keyed-ness.
   When no explicit :qos is supplied, the Publisher's default DataWriter QoS applies
   (DDS 1.4 §2.2.2.4.1, set_default_datawriter_qos), falling back to the role default.
   DDS-Security §8.4.2.4: when the participant is access-controlled, check_create_datawriter must
   grant publish on the topic (local Permissions + Governance write-AC toggle) or the writer is
   refused fail-closed as (values nil :not-allowed-by-security) — no signal (ADR 0064). An exhausted
   1-octet entity-key space (255 writers/participant) yields (values nil :out-of-resources). No access-state
   (default) = unchecked, byte-identical."
  (let ((node (dp-node (pub-participant pub)))
        (ah (dp-access-state (pub-participant pub)))
        (qos (if qos-supplied-p qos
                 (%default-qos-for-create (pub-default-datawriter-qos pub) (dds.qos:make-writer-qos)))))
    (when (and ah (not (dds.security:check-create-datawriter ah (topic-name topic))))
      (bail :not-allowed-by-security))
    (let ((ep (try (dds.disc:add-local-writer node :topic (topic-name topic) :type (topic-type-name topic)
                                         :keyed (%topic-keyed-p topic)
                                         ;; ADR 0060: a created-DISABLED writer registers with the engine but is NOT
                                         ;; SEDP-announced and cannot match until enable() (DDS 1.4 §2.2.2.1.1.7).
                                         :enabled (%child-created-enabled-p pub)
                                         :qos qos :type-information (%topic-type-information topic)))))
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
    (function (subscriber t &key (:qos t)) (values (or null data-reader) (or null keyword)))
  "Subscriber::create_datareader — register a local reader in the engine on the
   topic's name/type with the QoS reliability (v1: the single user reader). TOPIC may
   be a Topic or a ContentFilteredTopic; in the latter case the reader applies the
   filter predicate reader-side (only matching samples reach read/take). The
   endpoint kind (WITH_KEY/NO_KEY) is selected from the topic type's keyed-ness.
   When no explicit :qos is supplied, the Subscriber's default DataReader QoS applies
   (DDS 1.4 §2.2.2.5.1, set_default_datareader_qos), falling back to the role default.
   DDS-Security §8.4.2.5: when the participant is access-controlled, check_create_datareader must
   grant subscribe on the topic (local Permissions + Governance read-AC toggle) or the reader is
   refused fail-closed as (values nil :not-allowed-by-security) — no signal (ADR 0064). An exhausted
   1-octet entity-key space (255 readers/participant) yields (values nil :out-of-resources). No access-state
   (default) = unchecked, byte-identical."
  (let ((node (dp-node (sub-participant sub)))
        (ah (dp-access-state (sub-participant sub)))
        (qos (if qos-supplied-p qos
                 (%default-qos-for-create (sub-default-datareader-qos sub) (dds.qos:make-reader-qos)))))
    (when (and ah (not (dds.security:check-create-datareader ah (topic-name topic))))
      (bail :not-allowed-by-security))
    (let ((ep (try (dds.disc:add-local-reader node :topic (topic-name topic) :type (topic-type-name topic)
                                         :keyed (%topic-keyed-p topic)
                                         ;; ADR 0060: a created-DISABLED reader registers with the engine but is NOT
                                         ;; SEDP-announced and cannot match until enable() (DDS 1.4 §2.2.2.1.1.7).
                                         :enabled (%child-created-enabled-p sub)
                                         :qos qos :type-information (%topic-type-information topic)))))
    (%set-user-metadata-protection node ah (topic-name topic) :reader)   ; ADR 0046 §9.4.1.2.4: the READER's own protection tiers
    (setf (dds.disc:disc-node-durability-gate-active node) t)   ; ADR 0059: DCPS owns the reader-side durability baseline from here on, so a MATCHED-but-UNARMED writer HEARTBEAT is the ADR 0043 window, not the bare-disc norm — arm the fail-safe guard
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

(defparameter +retcode-bad-parameter+ :bad-parameter
  "DDS 1.4 ReturnCode_t RETCODE_BAD_PARAMETER (§2.2.4.4): an illegal parameter value — e.g. an instance
   handle passed to read_instance/take_instance that names no known instance (§2.2.2.5.2.4). Represented
   as the keyword :bad-parameter; the operation had no effect.")

(defparameter +retcode-precondition-not-met+ :precondition-not-met
  "DDS 1.4 ReturnCode_t RETCODE_PRECONDITION_NOT_MET (§2.2.4.4): a precondition for the operation
   was not met — enable() on an entity whose factory-parent is still disabled (§2.2.2.1.1.7), or
   delete_* of a container that still holds contained entities / a Topic still referenced by an
   endpoint (§2.2.2.2.1.5). Represented as the keyword :precondition-not-met; nothing was deleted.")

(defparameter +retcode-no-data+ :no-data
  "DDS 1.4 ReturnCode_t RETCODE_NO_DATA (§2.2.4.4): the operation completed but returned no data — no
   sample satisfied the read/take selection (§2.2.2.5.3). Represented as the keyword :no-data. Returned by
   TAKE-INTO / READ-INTO (ADR 0105) alongside a count of ZERO, with the application's vectors left exactly
   as they were: an empty result is not an error, and the count is what the caller loops over.
   ⚠️ The LIST-returning READ-SAMPLES / TAKE-SAMPLES do NOT use it — an empty list already says the same
   thing, and returning a keyword there would collide with the (or list (member :not-enabled)) contract.")

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
   WP-DCPS-API-COMPLETION S2 formalizes enable().)
   On a DomainParticipant the DISCOVERY_CONFIG vendor extension (announce period + announced lease) is
   CHANGEABLE and applied LIVE (%apply-discovery-cadence): the new lease rides the next SPDP announce and a
   running autonomous announcer re-waits on the new cadence — no restart, no silent no-op."
  (multiple-value-bind (okp failing-id) (%qos-consistent-p qos)
    (declare (ignore failing-id))
    (unless okp (return-from set-qos +retcode-inconsistent-policy+)))
  (when (entity-enabled-p entity)
    (let ((old (get-qos entity)))   ; normalize an absent stored QoS to the effective default, as get_qos does
      (when (/= +qos-policy-id-invalid+ (%qos-immutable-violation old qos))
        (return-from set-qos +retcode-immutable-policy+))))
  (setf (entity-qos entity) qos)
  (when (typep entity 'domain-participant)
    (%apply-discovery-cadence entity))   ; WP-DCPS-API-COMPLETION S7: DISCOVERY_CONFIG is CHANGEABLE — re-apply the cadence + announced lease live
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
  ;; ADR 0060: a DataWriter/DataReader created DISABLED is registered with the engine but withheld from SEDP +
  ;; matching; enabling it releases it onto the wire (DDS 1.4 §2.2.2.1.1.7 — only now may it communicate).
  (typecase entity
    (data-writer (dds.disc:enable-local-endpoint (dp-node (pub-participant (dw-publisher entity)))
                                                 (dw-entity-id entity)))
    (data-reader (dds.disc:enable-local-endpoint (dp-node (sub-participant (dr-subscriber entity)))
                                                 (dr-entity-id entity)))
    (t nil))
  (when (typep entity 'domain-participant) (%start-auto-announcer entity))   ; WP-DCPS-API-COMPLETION S7: start the announcer now the participant is enabled (idempotent; no-op unless autonomous)
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
   type %instance-handle returns the SHARED +instance-handle-nil+ (eq, no allocation).

   TX-KEYHASH (ADR 0087, NFR-MEM): a KEYED writer serializes the key through DW's REUSED scratch cursor
   instead of a fresh 256-octet buffer per write — measured 112.0 -> 32.1 B/call, i.e. ~80 B/sample off
   the TX path, byte-identical handles (the RX drain has done this since ADR 0075; this is its TX twin).

   The RESULT array is still allocated fresh, deliberately: the handle is RETAINED on THREE paths —
   threaded onto the CacheChange for KEEP_LAST per-instance eviction; used as a dw-instances EQUALP hash
   key; and, when the offered DEADLINE is finite, passed on by %deadline-touch-writer as the
   dw-deadline-timers key. Recycling it would alias every change's handle and mutate live keys. The
   deadline path is the nastiest because it is CONDITIONAL — under the default DURATION_INFINITE it arms
   nothing, so a recycled array would look correct until someone configured a DEADLINE. Only the SCRATCH
   is reusable; closing the remaining 32 B needs the ADR 0076 stable-handle indirection on the writer side.

   Concurrency: guarded by a CAS try-lock, NOT a lock. A DataWriter may be written concurrently, and a
   shared serialization buffer would interleave into a WRONG instance handle — a silent mis-attribution,
   not a crash. The thread that wins KEYHASH-BUSY uses the scratch; a concurrent writer takes the
   allocating path, which is exactly today's behaviour and byte-identical. Never blocks the write path."
  (when (%writer-keeplast-p dw)
    (let ((ts (topic-type-support (dw-topic dw)))
          (busy (dw-keyhash-busy dw)))
      (if (zerop (dds.pal:cas busy 0 1))
          (unwind-protect (%instance-handle ts sample (%writer-keyhash-scratch dw))
            (dds.pal:cas busy 1 0))
          (%instance-handle ts sample)))))

(defun* write-sample (dw sample &optional source-timestamp)
    (function (data-writer t &optional (or null integer))
              (member :ok :timeout :not-enabled :bad-parameter))
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
  ;; NO CONDITION MAY ESCAPE THE PUBLIC API (owner directive, NON-NEGOTIABLE; gate-nocond rule 2).
  ;; The guard must wrap the WHOLE operation, not just the publish: the KEYHASH is computed first, and it
  ;; serializes the KEY fields — so a keyed type whose key is a string (ShapeType's key IS its colour)
  ;; signals from %write-key-hash, before the publish is even reached. DDS 1.4 §2.2.4.4: an unencodable
  ;; sample is RETCODE_BAD_PARAMETER, a STATUS, not a stack unwind. Nothing is published.
  ;; The guard covers the SERIALIZATION FAILURE CLASSES, not one condition type. It used to name
  ;; cdr-not-implemented alone, which made the promise above false in two ways: an over-long sample
  ;; signalled dds.core.buffer:buffer-overflow straight past it into the application, and once the codec
  ;; stopped refusing non-Latin-1 strings the handler caught nothing at all. A sample that cannot be
  ;; encoded — whatever the reason — is RETCODE_BAD_PARAMETER (DDS 1.4 §2.2.4.4), and nothing is published.
  (handler-case
      (%write-sample-1 dw sample source-timestamp)
    (dds.core.buffer:buffer-overflow () +retcode-bad-parameter+)
    (dds.cdr:cdr-not-implemented () +retcode-bad-parameter+)))

(defun* %write-sample-1 (dw sample source-timestamp)
    (function (data-writer t (or null integer)) (member :ok :timeout :not-enabled :bad-parameter))
  "The body of WRITE-SAMPLE. Separated so ONE handler-case at the API boundary covers the whole operation —
   keyhash + serialize + publish (see write-sample)."
  (let ((node (dp-node (pub-participant (dw-publisher dw))))
        (kh (%write-key-hash dw sample)))   ; WP-DCPS-API-COMPLETION S4: reused for both publish + offered-deadline arm (no extra keyhash cons)
    (let* ((ts (topic-type-support (dw-topic dw)))
           (rep (%writer-tx-rep dw))
           (ts-ns (or source-timestamp (dds.pal:realtime-ns)))   ; ADR 0055: a plain write stamps the CURRENT wall-clock (DDS 1.4 §2.2.2.4.2.11 write = write_w_timestamp(now))
           (rc (if (%flatdata-transcoding-p ts rep)
                   ;; FlatData under a non-XCDR2 offered rep: the transcoding builder allocates -> allocating path.
                   (dds.disc:publish-sample node (%serialize-sample ts sample rep) kh nil 0 nil
                                            (dw-entity-id dw) ts-ns)
                   ;; WP-PERF: serialize STRAIGHT INTO the writer's arena-pooled buffer — 0 bytes/sample on TX.
                   ;; Degrades to the allocating path by itself if no pool can be carved / the pool is exhausted.
                   ;; The serializer is an flet declared DYNAMIC-EXTENT (ADR 0072), so it stack-allocates:
                   ;; publish-sample-into is a pure downward-funarg consumer and stores it nowhere.
                   (%with-sample-serializer-into (%ser-into ts sample rep dw)
                     (dds.disc:publish-sample-into node #'%ser-into kh
                                                   (dw-entity-id dw)   ; WP-N-ENDPOINT-S1: THIS writer's own HistoryCache
                                                   ts-ns)))))
      (when (eq :timeout rc)
        (return-from %write-sample-1 +retcode-timeout+)))   ; full bounded cache, max_blocking_time elapsed
    (assert-liveliness dw)
    (%app-ack-deadline-arm dw)   ; ADR 0090 A4: (re)arm the acknowledgment watchdog (no-op unless APPLICATION-acked with a finite deadline)
    (%deadline-touch-writer dw kh sample)   ; WP-DCPS-API-COMPLETION S4: (re)arm this instance's offered DEADLINE (no-op + 0-alloc when DEADLINE is INFINITE; reuses the KEEP_LAST keyhash)
    (let ((h (or kh (%instance-handle (topic-type-support (dw-topic dw)) sample))))   ; S5.T1: write auto-registers the instance (DDS 1.4 §2.2.2.4.2.2)
      (unless (gethash h (dw-instances dw))                                            ; first write of this instance -> record its key holder (get_key_value); steady state is a lock-free gethash
        (dds.pal:with-lock ((dw-status-lock dw)) (setf (gethash h (dw-instances dw)) sample))))
    +retcode-ok+))

;;; ---- Timestamped writes (S5.T4, DDS 1.4 §2.2.2.4.2.11/§2.2.2.4.2.9/§2.2.2.4.2.8): supply the
;;;      source_timestamp explicitly instead of the reception time. It rides an INFO_TIMESTAMP submessage
;;;      before the DATA (RTPS 2.5 §9.4.5.9) so a matched reader's SampleInfo.source_timestamp reflects it.

(defun* %time->ns (sec nanosec)
    (function (integer (unsigned-byte 32)) integer)
  "A DDS Time_t (SEC, NANOSEC) as a single nanosecond count — the internal source_timestamp form threaded
   to the wire (INFO_TS) and surfaced in SampleInfo.source_timestamp."
  (+ (* sec 1000000000) nanosec))

(defun* write-w-timestamp (dw sample sec nanosec)
    (function (data-writer t integer (unsigned-byte 32)) (member :ok :timeout :not-enabled))
  "DataWriter::write_w_timestamp (DDS 1.4 §2.2.2.4.2.11) — write SAMPLE stamped with the given
   source_timestamp (Time_t SEC/NANOSEC) rather than the reception time; an INFO_TS carries it before the
   DATA on the wire (RTPS 2.5 §9.4.5.9). The instance is derived from SAMPLE (auto-registered), as for write."
  (write-sample dw sample (%time->ns sec nanosec)))

(defun* dispose-w-timestamp (dw sample-or-handle sec nanosec)
    (function (data-writer t integer (unsigned-byte 32))
              (or (simple-array (unsigned-byte 8) (16)) (member :timeout :not-enabled)))
  "DataWriter::dispose_w_timestamp (DDS 1.4 §2.2.2.4.2.9) — dispose the instance with the given
   source_timestamp; the lifecycle DATA is preceded by an INFO_TS."
  (dispose-instance dw sample-or-handle (%time->ns sec nanosec)))

(defun* unregister-instance-w-timestamp (dw sample-or-handle sec nanosec)
    (function (data-writer t integer (unsigned-byte 32))
              (or (simple-array (unsigned-byte 8) (16)) (member :timeout :not-enabled)))
  "DataWriter::unregister_instance_w_timestamp (DDS 1.4 §2.2.2.4.2.8) — unregister the instance with the
   given source_timestamp; the lifecycle DATA is preceded by an INFO_TS."
  (unregister-instance dw sample-or-handle (%time->ns sec nanosec)))

(defun* writedispose (dw sample &optional sec nanosec)
    (function (data-writer t &optional (or null integer) (or null (unsigned-byte 32)))
              (or (simple-array (unsigned-byte 8) (16)) (member :ok :timeout :not-enabled)))
  "DataWriter::writedispose (a Connext-compatible extension, NOT in the OMG DCPS PSM — additive interop
   behaviour on top of the standard API): write SAMPLE then dispose its instance in one call, so a reader
   sees the value AND the NOT_ALIVE_DISPOSED transition. With SEC/NANOSEC both non-NIL the write + dispose
   carry that source_timestamp (INFO_TS); otherwise the reception time is used. Returns the dispose handle,
   or the write's non-:ok return code when the write itself failed."
  (let* ((ts (and sec nanosec))
         (rc (if ts (write-w-timestamp dw sample sec nanosec) (write-sample dw sample))))
    (if (eq rc +retcode-ok+)
        (if ts (dispose-w-timestamp dw sample sec nanosec) (dispose-instance dw sample))
        rc)))

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
    ;; Gated on the CAPABILITY, not on the implementation NAME. This used to read
    ;; (eq (dds.pal:pal-impl-name) :sbcl) because the Clasp PAL stubbed store-sap-u8 out; that stub is gone
    ;; (it is cffi:mem-ref, exactly as SBCL's sap-ref-8 is), so the foreign-SAP writes work on both impls.
    ;; What zero-copy still needs is by-name SHMEM attach — and node-loan-write-eligible-p now asks for it,
    ;; so Clasp/Linux (the primary platform) takes the loan-write path exactly as SBCL does, while
    ;; Clasp/macOS-arm64 (the residual ADR 0013 defect) degrades gracefully.
    (when (and size (dds.disc:node-loan-write-eligible-p node size))
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
            (writer-loan-sample ln) (if ctor (funcall ctor) (error "loan-sample: ~a is not a FlatData type" (dds.types:type-support-type-name ts)))) ; NOCOND(GUARD): loan-sample is the FlatData-only loan-write API; a non-FlatData writer cannot reach the fallback ctor path in correct use
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

(defun* %instance-handle (ts sample &optional kh-scratch out-scratch)
    (function (t t &optional t t) (simple-array (unsigned-byte 8) (16)))
  "16-octet instance handle for SAMPLE via the type-support key-hash, or HANDLE_NIL
   for an unkeyed type. KH-SCRATCH (default NIL): a reusable :big key-serialization cursor the generated
   key-hash serializes the key in place through (zero per-sample make-octet-buffer/cursor/free-static,
   RX-POOLING ADR 0075). OUT-SCRATCH (default NIL): a reusable 16-octet RESULT array the handle is written into
   in place (no per-sample make-array, ADR 0076) — the caller MUST treat the returned handle as TRANSIENT (use
   it only for the instance-rec lookup, then read the STABLE handle off the rec). Both are sound only on a
   single-threaded-per-entity caller (the drain); NIL allocates fresh, byte-identical (every TX / register /
   unkeyed caller)."
  (let ((kh (dds.types:type-support-key-hash ts)))
    (if kh (funcall kh sample kh-scratch out-scratch) +instance-handle-nil+)))

(defun* %make-keyhash-scratch ()
    (function () t)
  "A fresh :big key-serialization cursor over a 256-octet buffer — the ONE definition of the scratch shape
   both the RX drain (dr-keyhash-scratch, ADR 0075) and the TX write (dw-keyhash-scratch, ADR 0087) reuse.
   :big because the key-hash is always serialized BIG-ENDIAN XCDR2 regardless of the payload's
   representation (RTPS 2.5 §9.6.4.8)."
  (dds.core.buffer:cursor (dds.core.buffer:make-octet-buffer 256) :endianness :big))

(defun* %reader-keyhash-scratch (dr)
    (function (data-reader) t)
  "DR's reusable :big key-serialization cursor (over a 256-octet buffer), created on first use — the drain's
   per-sample %instance-handle serializes the key in place through it, so a keyed take allocates no scratch
   (RX-POOLING, ADR 0075, NFR-MEM). Single-threaded per reader (the drain runs on the user thread; take is
   single-threaded-per-reader, the same discipline that lets the drain mutate the reader cache unlocked)."
  (or (dr-keyhash-scratch dr)
      (setf (dr-keyhash-scratch dr) (%make-keyhash-scratch))))

(defun* %writer-keyhash-scratch (dw)
    (function (data-writer) t)
  "DW's reusable :big key-serialization cursor, created on first use — the TX twin of
   %reader-keyhash-scratch (TX-KEYHASH, ADR 0087, NFR-MEM). ⚠️ ONLY safe to use while holding DW's
   KEYHASH-BUSY CAS try-lock: unlike the reader's drain, a DataWriter has NO single-thread discipline
   (DDS 1.4 §2.2.2.4.2.11 permits concurrent write on one writer), and two threads serializing keys
   through one buffer would interleave into a wrong instance handle. %write-key-hash is the only caller."
  (or (dw-keyhash-scratch dw)
      (setf (dw-keyhash-scratch dw) (%make-keyhash-scratch))))

(defun* %reader-keyhash-out (dr)
    (function (data-reader) (simple-array (unsigned-byte 8) (16)))
  "DR's reusable 16-octet key-hash RESULT array, created on first use — the drain writes the per-sample
   instance handle into it TRANSIENTLY (for the instance-rec lookup only; the STABLE handle is then read off
   the rec), so a known-instance take allocates no handle (RX-POOLING, ADR 0076, NFR-MEM). Single-threaded per
   reader, the same drain discipline as dr-keyhash-scratch."
  (or (dr-keyhash-out dr)
      (setf (dr-keyhash-out dr) (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0))))

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
      (setf (gethash handle (dw-instances dw)) sample))   ; S5.T1: the value is the key holder (get_key_value); presence = registered
    handle))

(defun* dispose-instance (dw sample-or-handle &optional source-timestamp)
    (function (data-writer t &optional (or null integer)) (or (simple-array (unsigned-byte 8) (16)) (member :timeout :not-enabled)))
  "DataWriter::dispose (DDS 1.4 §2.2.2.4.2.10) — dispose the instance named by SAMPLE-OR-HANDLE
   (a sample or a registered handle): emit a no-payload dispose DATA (StatusInfo Disposed, RTPS 2.5
   §9.6.4.9) over the reliable engine so matched readers see NOT_ALIVE_DISPOSED. Returns the handle, or
   +RETCODE-TIMEOUT+ (:timeout) if the bounded cache was full and max_blocking_time elapsed (WP-ASYNC-FLOW
   backpressure, ADR 0016 §Backpressure; on :timeout nothing was emitted and liveliness is not asserted).
   A DISABLED DataWriter refuses with :not-enabled (outside the NOT_ENABLED-safe set, DDS 1.4 §2.2.2.1.1.7)."
  (unless (entity-enabled-p dw) (return-from dispose-instance +retcode-not-enabled+))
  (let ((handle (%resolve-handle dw sample-or-handle))
        (node (dp-node (pub-participant (dw-publisher dw)))))
    (when (eq :timeout (dds.disc:dispose-instance node handle (or source-timestamp (dds.pal:realtime-ns))))   ; ADR 0055: current wall-clock on a plain dispose
      (return-from dispose-instance +retcode-timeout+))
    (assert-liveliness dw)
    handle))

(defun* %writer-autodispose-p (dw)
    (function (data-writer) boolean)
  "DW's WRITER_DATA_LIFECYCLE autodispose_unregistered_instances flag (DDS 1.4 §2.2.3.21), defaulting
   to T (the policy default) when the QoS is absent or not a dds.qos:qos."
  (let ((qos (entity-qos dw)))
    (if (typep qos 'dds.qos:qos) (dds.qos:qos-autodispose-unregistered-instances qos) t)))

(defun* unregister-instance (dw sample-or-handle &optional source-timestamp)
    (function (data-writer t &optional (or null integer)) (or (simple-array (unsigned-byte 8) (16)) (member :timeout :not-enabled)))
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
    (when (eq :timeout (dds.disc:unregister-instance node handle (%writer-autodispose-p dw)
                                                      (or source-timestamp (dds.pal:realtime-ns))))   ; ADR 0055: current wall-clock on a plain unregister
      (return-from unregister-instance +retcode-timeout+))
    (dds.pal:with-lock ((dw-status-lock dw))
      (remhash handle (dw-instances dw)))
    (assert-liveliness dw)
    handle))

(defun* %endpoint-type-support (endpoint)
    (function (t) t)
  "The topic type-support of ENDPOINT (a DataWriter or DataReader) — the keyhash/key-field machinery
   shared by lookup_instance / get_key_value across both entity kinds."
  (typecase endpoint
    (data-writer (topic-type-support (dw-topic endpoint)))
    (data-reader (topic-type-support (dr-topic endpoint)))))

(defun* lookup-instance (endpoint key-holder)
    (function (t t) (simple-array (unsigned-byte 8) (16)))
  "DataWriter/DataReader::lookup_instance (DDS 1.4 §2.2.2.4.2.13 / §2.2.2.5.2.14) — the 16-octet handle
   the middleware associates with the instance whose key matches KEY-HOLDER, or HANDLE_NIL when ENDPOINT
   knows no such instance. The handle is the type-support keyhash; 'known' means the instance has been
   registered/written (writer, dw-instances) or delivered (reader, dr-instance-recs)."
  (let ((handle (%instance-handle (%endpoint-type-support endpoint) key-holder)))
    (if (typecase endpoint
          (data-writer (nth-value 1 (gethash handle (dw-instances endpoint))))
          (data-reader (nth-value 1 (gethash handle (dr-instance-recs endpoint)))))
        handle
        +instance-handle-nil+)))

(defun* get-key-value (endpoint handle)
    (function (t (simple-array (unsigned-byte 8) (16))) t)
  "DataWriter/DataReader::get_key_value (DDS 1.4 §2.2.2.4.2.12 / §2.2.2.5.2.13) — a representative sample
   carrying the KEY FIELDS of the instance named by HANDLE, or NIL when ENDPOINT knows no such instance
   (the caller's BAD_PARAMETER). The handle is a one-way keyhash, so the key holder is the sample the
   writer registered/wrote (dw-instances value) or the reader's retained per-instance key sample."
  (typecase endpoint
    (data-writer (values (gethash handle (dw-instances endpoint))))
    (data-reader (let ((rec (gethash handle (dr-instance-recs endpoint))))
                   (and rec (instance-rec-key-sample rec))))))

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
  (%notify-status dr +status-sample-rejected+ :sample-rejected
   (lambda ()
     (let ((s (dr-sample-rejected dr)))
       (incf (sample-rejected-status-total-count s))
       (incf (sample-rejected-status-total-count-change s))
       (setf (sample-rejected-status-last-reason s) reason
             (sample-rejected-status-last-instance-handle s) handle)
       (values t (copy-sample-rejected-status s)
               (lambda () (setf (sample-rejected-status-total-count-change s) 0))))))
  t)

(defun* %reader-instance-rec (dr handle)
    (function (data-reader (simple-array (unsigned-byte 8) (16))) instance-rec)
  "DR's instance-rec for the 16-octet HANDLE (DDS 1.4 §2.2.2.5.1.3), creating a fresh ALIVE
   record (generation counts initialized to zero per §2.2.2.5.1.5) the first time the instance
   is seen. Also seeds the view-state dr-instances entry (nil = not yet accessed) so a synthetic
   lifecycle notification surfaces with view-state NEW just like a first data sample."
  (or (gethash handle (dr-instance-recs dr))
      ;; RX-POOLING (ADR 0076): first sighting of this instance -> COPY the (possibly reused-scratch) HANDLE to a
      ;; STABLE array used as BOTH hash keys AND the rec's own handle slot, so the drain can pass a reused scratch
      ;; for the lookup and read this stable handle back for SampleInfo / retention. copy-seq runs once per NEW
      ;; instance (rare); a known instance is a pure lock-free gethash (zero alloc).
      (let ((stable (copy-seq handle)))
        (unless (nth-value 1 (gethash stable (dr-instances dr)))
          (setf (gethash stable (dr-instances dr)) nil))
        (setf (gethash stable (dr-instance-recs dr)) (make-instance-rec :handle stable)))))

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

(defun* %fire-data-available (dr)
    (function (data-reader) t)
  "Fire DR's DATA_AVAILABLE on the MOST-SPECIFIC enabled listener in reader -> Subscriber ->
   DomainParticipant (DDS 1.4 §2.2.4.1 propagation), if any — OUTSIDE any status lock. A level-
   based status (unread samples), so no bitmask bit / reset is involved."
  (let ((l (%find-enabled-listener dr :data-available)))
    (when l (on-data-available l dr)))
  t)

(defun* %wake-reader-data (dr)
    (function (data-reader) t)
  "Fire DR's on_data_available (propagated up its containment chain) then wake its WaitSets —
   the DATA_AVAILABLE notification path (DDS 1.4 §2.2.4.1) when DATA_ON_READERS was not handled."
  (%fire-data-available dr)
  (%notify-reader-conditions dr)
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
  (%deliver-data-on-readers p)
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
   once if any instance transitioned.

   ⚠️ FIRED FROM THE DISCOVERY UNMATCH HOOK, i.e. NOT the application thread, so it takes the cache lock
   (ADR 0093 slice 3). Safe against the drain's lock order because dds.disc fires ON-UNMATCH *outside* the
   node lock (%prune-participant-locked hands its removed matches out first): cache lock OUTER, node lock
   INNER, never the reverse.

   ⚠️ THE NOTIFICATION IS FIRED *OUTSIDE* THE CACHE LOCK, and that is load-bearing rather than tidy.
   %WAKE-READER-DATA runs the application's ON_DATA_AVAILABLE listener, and shipped code calls take from
   inside one (src/dds-bench/xperf.lisp) — take then takes this same lock, which %WITH-READER-CACHE's own
   docstring says is NOT RECURSIVE, and SBCL answers a recursive acquisition with a SIMPLE-ERROR
   (\"Recursive lock attempt\") thrown into the discovery thread. So a matched remote writer merely
   vanishing — an ordinary shutdown — would take down the discovery thread of any application using the
   listener idiom. CHANGED is collected inside the critical section and the wake happens after it, exactly
   the discipline %PRUNE-PARTICIPANT-LOCKED already uses for the node lock (dds-disc/disc.lisp). The other
   two firing sites (%DELIVER-DATA-ON-READERS, NOTIFY-DATAREADERS) were already outside it, which is why
   only this one was reachable."
  (let ((changed nil))
    (%with-reader-cache (dr)
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
      (dr-instance-recs dr)))
    (when changed (%wake-reader-data dr)))   ; OUTSIDE the lock: the listener may call take, which retakes it
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
   ALL valid-data (matching the copy path); only the drop is guarded. O(N) scan via %reader-instance-oldest (DRY).

   MIXED-DELIVERY (github#1): an instance can hold BOTH ZC-loan samples (data = flatdata-view) AND copy-path
   samples (data = a deserialized struct) — early samples delivered before this reader's ZC-loan capability
   armed fall back to the copy path (a legitimate degrade, ADR 0017). The drop target OLDEST may therefore be a
   copy. return-loan ONLY tears down a view (or a secured handle); handed a copy struct it silently no-ops and
   the sample is NEVER evicted -> dr-cache overflows KEEP_LAST depth. So DISPATCH on the datum, mirroring
   %reader-keeplast-drop-oldest-secured: a view -> return-loan (release slot + drop dr-loans + recycle); a copy
   -> a plain dr-cache delete (a copy's data is private heap, nothing to release)."
  (multiple-value-bind (count oldest) (%reader-instance-oldest dr handle t)
    (when (and (>= count depth) oldest)
      (let ((data (cached-sample-data oldest)))
        (if (dds.types:flatdata-view-p data)
            (%return-loan-unlocked dr (list data))                      ; ZC loan: full teardown; UAF-safe (oldest is :not-read). UNLOCKED: reached from %drain, which already holds the cache lock
            (setf (dr-cache dr) (delete oldest (dr-cache dr) :test #'eq))))))   ; copy-path fallback sample: plain drop
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
            (%return-loan-unlocked dr (list loan))                    ; full teardown, type-dispatched to node-return-loan. UNLOCKED: reached from %drain
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
  (%deadline-disarm-instance dr handle)   ; WP-DCPS-API-COMPLETION S4: a purged instance no longer tracks a requested DEADLINE
  t)

(defun* %autopurge-sweep (dr)
    (function (data-reader) t)
  "READER_DATA_LIFECYCLE autopurge sweep on the USER/spin thread (DDS 1.4 §2.2.3.22): for each
   NOT_ALIVE instance whose applicable autopurge delay is finite AND has elapsed since the instance went
   not-alive, PURGE it (%autopurge-purge-instance). Both delays default DURATION_INFINITE, so the common
   case is a no-op — no instance is ever purged by default. Run on the DCPS announce cadence (SPIN),
   beside the writer-liveliness/lease sweeps. Snapshots the due handles before mutating so the maphash is
   not modified under iteration.

   ⚠️ IT DOES NOT RUN ON 'THE DR-CACHE OWNER THREAD', WHICH IS WHY IT TAKES THE CACHE LOCK (ADR 0093
   slice 3). This docstring used to claim it mutated dr-cache 'on the user/spin thread only (the dr-cache
   owner thread)'. In AUTONOMOUS mode (ADR 0056) SPIN is driven by the participant's announcer thread, so
   the sweep rewrites dr-cache and the instance-recs concurrently with an application take. There is no
   owner thread."
  (%with-reader-cache (dr)
   (let ((now (%lease-now)) (due '()))
    (maphash
     (lambda (handle rec)
       (when (%autopurge-due-p rec (%autopurge-instance-delay dr rec) now)
         (push handle due)))
     (dr-instance-recs dr))
    (dolist (handle due) (%autopurge-purge-instance dr handle))))
  t)

(defun* %participant-readers (p)
    (function (domain-participant) list)
  "Every local DataReader contained in participant P (across all its Subscribers)."
  (let ((rs '()))
    (dolist (c (dp-children p) rs)
      (when (typep c 'subscriber) (setf rs (append (sub-readers c) rs))))))

;;; WP-N-ENDPOINT-S5 (ADR 0048): per-endpoint disc->DCPS dispatch. A status/listener/wake event
;;; resolves the LOCAL entity it is ABOUT — by the remote's TOPIC (match/unmatch/incompatible) or by
;;; the remote writer GUID's S2 delivery route (liveliness) — never a participant-wide back-ref. Dispatch
;;; is primarily by local EntityId (%participant-{reader,writer}-by-entity-id); the topic-based lookups
;;; below are a NIL-eid fallback (S6: same-topic is supported, keyed per-EntityId — no fence); an event
;;; with no matching local entity is DROPPED, never mis-delivered to another endpoint.

(defun* %participant-reader-for-topic (p topic-name)
    (function (domain-participant string) (or null data-reader))
  "The FIRST local DataReader in P bound to TOPIC-NAME, or NIL (WP-N-ENDPOINT-S5): the NIL-eid FALLBACK
   for the per-endpoint match/unmatch/incompatible dispatch (the primary path keys by local EntityId via
   %participant-reader-by-entity-id; this is used only when the event carries no local-eid). With same-topic
   readers (S6) it returns the first — callers thread the EntityId to disambiguate; NIL -> the caller drops
   the event (never mis-delivers to another endpoint)."
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
   crypto-token + the durability match-side land on the RIGHT same-topic writer (not the first-by-topic).

   ADR 0089 made this ALLOCATION-FREE. It used to be (find wid (%participant-writers p) ...), and
   %participant-writers APPENDs a fresh list of every writer in the participant on every call — fine for
   the match-time callers it was written for, but this now also resolves the writer for the vendor
   reliability statuses, once per write and once per ACKNACK. Measured at 43.7 bytes/sample; walking the
   containment tree directly costs nothing and every other caller benefits too."
  (dolist (c (dp-children p) nil)
    (when (typep c 'publisher)
      (dolist (w (pub-writers c))
        (when (= wid (dw-entity-id w))
          (return-from %participant-writer-by-entity-id w))))))

(defun* %participant-readers-for-writer-guid (p guid)
    (function (domain-participant (simple-array (unsigned-byte 8) (16))) list)
  "The local DataReader(s) matched to remote writer GUID (WP-N-ENDPOINT-S5): reuse the S2 delivery
   route (%reader-routes-for) -> reader-EntityId(s) -> DCPS reader by dr-entity-id. Returns ALL matched
   same-topic readers (S6 — the route is a list of EntityIds). NOTE: %reader-routes-for falls back to the PRIMARY reader on an empty route
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

;;; ---- SAMPLE_LOST (DDS 1.4 §2.2.4.1, S4.T3) ----

(defun* %fire-sample-lost (dr n)
    (function (data-reader (integer 1)) t)
  "Raise DR's SAMPLE_LOST by N samples through the ONE %notify-status chokepoint (DDS 1.4 §2.2.4.1,
   dds_rtf2_dcps.idl §99-102): total_count += N (monotonic — samples that were never made available to
   the reader), total_count_change += N; sets the status-changed bit + triggers the StatusCondition +
   delivers on_sample_lost to the most-specific enabled listener up the hierarchy (S3). N is the batch
   count (a GAP can declare several SNs gone at once; a best-effort skip counts the whole run)."
  (%notify-status dr +status-sample-lost+ :sample-lost
   (lambda ()
     (let ((s (dr-sample-lost dr)))
       (incf (sample-lost-status-total-count s) n)
       (incf (sample-lost-status-total-count-change s) n)
       (values t (copy-sample-lost-status s)
               (lambda () (setf (sample-lost-status-total-count-change s) 0))))))
  t)

(defun* %reader-best-effort-p (dr)
    (function (data-reader) boolean)
  "T iff DR's RELIABILITY QoS is BEST_EFFORT (DDS 1.4 §2.2.3.14) — the mode with no retransmission, so a
   gap in the delivered SN stream is a permanently-lost sample. A RELIABLE reader recovers a skipped SN by
   NACK, so a drain-time skip is NOT loss there (its loss is detected only by an irrecoverable GAP)."
  (let ((qos (entity-qos dr)))
    (and (typep qos 'dds.qos:qos) (eq :best-effort (dds.qos:qos-reliability qos)))))

(defun* %reader-advance-drained (dr sguid sn)
    (function (data-reader t integer) t)
  "Advance DR's per-source-writer delivered high-water for SGUID to SN (the exactly-once drain watermark,
   §8.3.5.4), first raising SAMPLE_LOST for any best-effort SN-skip: when DR is BEST_EFFORT, a prior
   watermark exists (the baseline sample already landed — pre-baseline SNs are never 'lost'), and SN jumps
   past PRIOR+1, the (SN − PRIOR − 1) intervening SNs will never arrive (no retransmit) → fire SAMPLE_LOST
   for them (DDS 1.4 §2.2.4.1). Pure reordering (a lower SN arriving late) never jumps forward, so it is
   conservatively not counted (a false SAMPLE_LOST is the worse error). The single chokepoint every drain
   path (plain / ZC-loan / secured-loan) advances the watermark through, so the detection is DRY + uniform."
  (let ((prior (gethash sguid (dr-drained dr))))
    (when (and prior (%reader-best-effort-p dr) (> sn (1+ prior)))
      (%fire-sample-lost dr (- sn prior 1)))
    (setf (gethash sguid (dr-drained dr)) (max sn (or prior 0))))
  t)

;;; ---- APPLICATION ACKNOWLEDGMENT (VENDOR EXTENSION, ADR 0090 slice A3b) ----
;;;
;;; DDS 1.4 defines nothing here and neither does RTPS 2.5 — wait_for_acknowledgments is PROTOCOL-level,
;;; and an exhaustive search of the spec finds no application acknowledgment at all. This mirrors RTI's
;;; DataReader::acknowledge_sample / acknowledge_all, gated on the ACKNOWLEDGMENT_KIND QoS (slice A3a).
;;;
;;; ⚠️ A FALSE ACK IS WORSE THAN NO ACK — the inversion that shapes every decision below. Elsewhere in
;;; this stack a false REJECT is the worst outcome; here a writer that believes a sample acknowledged may
;;; PURGE it and report success, so an unacknowledged sample is a delay and a wrongly-acknowledged one is
;;; silent data loss. Every ambiguous case therefore resolves to "not yet acknowledged".

(defun* %reader-app-ack-explicit-p (dr)
    (function (data-reader) t)
  "T if DR's ACKNOWLEDGMENT_KIND is :APPLICATION-EXPLICIT — the only kind this slice implements.
   :APPLICATION-AUTO is accepted by the QoS and its RxO gate (A3a) but acknowledges on read/take, which is
   a later slice; until it exists, an :APPLICATION-AUTO reader acknowledges NOTHING rather than something
   approximate. Under-acknowledging stalls a writer visibly; over-acknowledging loses data silently."
  (let ((q (entity-qos dr)))
    (and q (eq (dds.qos:qos-acknowledgment-kind q) :application-explicit))))

(defun* %reader-app-ack-state (dr wguid)
    (function (data-reader t) t)
  "DR's app-ack state for remote writer WGUID, created on demand, or NIL when WGUID is not a 16-octet GUID.
   The table itself is allocated lazily, so a :PROTOCOL reader never pays for it."
  (unless (and wguid (typep wguid '(array (unsigned-byte 8) (*))) (= 16 (length wguid)))
    (return-from %reader-app-ack-state nil))
  (unless (dr-app-acks dr)
    (setf (dr-app-acks dr) (make-hash-table :test 'equalp)))
  (or (gethash wguid (dr-app-acks dr))
      (setf (gethash wguid (dr-app-acks dr))
            (dds.rtps.reliable:make-app-ack-state))))

(defun* %note-accessed (dr info)
    (function (data-reader sample-info) t)
  "Record that the application has just been handed the sample described by INFO, making it eligible for a
   later acknowledge-sample / acknowledge-all (ADR 0090 A3b). Called from EVERY path that hands a sample to
   the application and marks it READ — %select-samples, take-loaned, read-loaned — which is the whole of
   'accessed'.

   A NO-OP UNLESS THE READER IS :APPLICATION-EXPLICIT, so the default reader pays one keyword comparison
   per returned sample and allocates nothing (NFR-MEM). A sample whose publication-handle is missing is
   SKIPPED rather than recorded under a guessed writer: acknowledging the wrong writer's sequence number is
   exactly the false ack this feature must not produce."
  (when (%reader-app-ack-explicit-p dr)
    (let ((state (%reader-app-ack-state dr (sample-info-publication-handle info))))
      (when state
        (dds.rtps.reliable:app-ack-note-accessed state (sample-info-sequence-number info)))))
  t)

(defun* %reader-emit-app-ack (dr wguid state)
    (function (data-reader t t) (integer 0))
  "Emit ONE APP_ACK to writer WGUID carrying STATE's pending acknowledgments, and commit them. Returns the
   number of datagrams sent (0 if nothing was pending, or if the writer's participant is undiscovered).

   THE COMMIT HAPPENS EVEN WHEN THE SEND RESOLVES TO NO DESTINATION, and that is deliberate: the pending
   runs move to REPORTED, so the next APP_ACK still names them (with the previously-reported intervalFlags
   instead of the newly-acked one). Nothing is dropped by a lost or unsendable message — only a flag this
   stack does not interpret differs — whereas leaving them pending would re-emit them forever."
  (let ((intervals (dds.rtps.reliable:app-ack-intervals state)))
    (when (null intervals) (return-from %reader-emit-app-ack 0))
    (let ((count (dds.rtps.reliable:app-ack-commit state)))
      (dds.disc:node-send-app-ack (dp-node (sub-participant (dr-subscriber dr)))
                                  (dr-entity-id dr) wguid intervals count))))

(defun* acknowledge-sample (dr info)
    (function (data-reader sample-info) t)
  "DataReader::acknowledge_sample (VENDOR EXTENSION, ADR 0090; RTI's DDS_DataReader_acknowledge_sample) —
   tell the writer that named this sample that the APPLICATION has processed it, so it may stop retaining
   it. INFO is the SampleInfo the sample was read or taken with; the sample is identified by its
   publication-handle (the writer's GUID) and sequence-number, because a sequence number is unique only
   within one writer (RTPS 2.5 §8.3.5.4). One APP_ACK is emitted, unicast to that writer's participant.

   Returns a DDS 1.4 ReturnCode_t:
     :OK                     acknowledged (or already acknowledged — the call is idempotent).
     :NOT-ENABLED            DR is not enabled (DDS 1.4 §2.2.2.1.1.7).
     :BAD-PARAMETER          INFO carries no publication-handle, so no writer can be named.
     :PRECONDITION-NOT-MET   DR's ACKNOWLEDGMENT_KIND is not :APPLICATION-EXPLICIT, or this reader's
                             application never read or took that sample.

   ⚠️ THE :PRECONDITION-NOT-MET ARM IS THE SAFETY ARM AND IT REFUSES ON PURPOSE. A SampleInfo can only
   normally come from this reader's own read/take, but a stale one, one belonging to a different reader, or
   a fabricated one would otherwise acknowledge a sample this application never saw — after which the
   writer is entitled to purge it. Refusing costs a retained sample; accepting on faith costs the sample
   itself, so the ambiguous case resolves to 'not yet acknowledged' (ADR 0090)."
  (unless (entity-enabled-p dr) (return-from acknowledge-sample +retcode-not-enabled+))
  (unless (%reader-app-ack-explicit-p dr) (return-from acknowledge-sample +retcode-precondition-not-met+))
  (let ((state (%reader-app-ack-state dr (sample-info-publication-handle info))))
    (when (null state) (return-from acknowledge-sample +retcode-bad-parameter+))
    (let ((verdict (dds.rtps.reliable:app-ack-acknowledge state (sample-info-sequence-number info))))
      (case verdict
        (:not-accessed +retcode-precondition-not-met+)
        (:already +retcode-ok+)
        (t (%reader-emit-app-ack dr (sample-info-publication-handle info) state)
           +retcode-ok+)))))

(defun* acknowledge-all (dr)
    (function (data-reader) t)
  "DataReader::acknowledge_all (VENDOR EXTENSION, ADR 0090; RTI's DDS_DataReader_acknowledge_all) —
   acknowledge every sample this reader's application has ACCESSED and not yet acknowledged, emitting one
   APP_ACK per matched writer that has any. Returns :OK, :NOT-ENABLED, or :PRECONDITION-NOT-MET when
   ACKNOWLEDGMENT_KIND is not :APPLICATION-EXPLICIT. A reader with nothing outstanding returns :OK and
   sends nothing.

   ACCESSED, NOT RECEIVED — the distinction IS the feature. Acknowledging everything the reader HOLDS would
   acknowledge samples still sitting undelivered in its cache, i.e. precisely the samples application
   acknowledgment exists to keep a writer from purging. RTI's acknowledge_all likewise covers previously
   accessed samples."
  (unless (entity-enabled-p dr) (return-from acknowledge-all +retcode-not-enabled+))
  (unless (%reader-app-ack-explicit-p dr) (return-from acknowledge-all +retcode-precondition-not-met+))
  (when (dr-app-acks dr)
    (maphash (lambda (wguid state)
               (when (plusp (dds.rtps.reliable:app-ack-acknowledge-all state))
                 (%reader-emit-app-ack dr wguid state)))
             (dr-app-acks dr)))
  +retcode-ok+)

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
                                     :publication-handle sguid   ; DDS 1.4 §2.2.2.5.4; ALIASED, never copied — see the slot docstring
                                     :source-timestamp (dds.disc:node-sample-timestamp   ; S5.T4
                                                        (dp-node (sub-participant (dr-subscriber dr))) key)
                                     :disposed-generation-count (instance-rec-disposed-gen-count rec)
                                     :no-writers-generation-count (instance-rec-no-writers-gen-count rec)))))))))
    (when sguid                                                    ; advance the per-writer watermark (best-effort: ACKed, never retransmit)
      (%reader-advance-drained dr sguid sn)))
  t)

(defun* %drain-one-secured-deliver (dr node ts key loan sn sguid data)
    (function (data-reader t t t t integer t t) t)
  "Deliver an already-decoded secured sample DATA (the in-place decode of LOAN's pooled buffer): register
   the loan handle, revive the instance, apply the KEEP_LAST per-instance drop, append the cached sample,
   and advance the per-writer watermark. Split out of %drain-one-secured so that function's decode-reject
   path (return the loan, advance, drop) reads as a plain early exit rather than nesting the whole
   delivery inside a multiple-value-bind."
  (let* ((handle (%instance-handle ts data))
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
                               :publication-handle sguid   ; DDS 1.4 §2.2.2.5.4; ALIASED, never copied — see the slot docstring
                               :source-timestamp (dds.disc:node-sample-timestamp node key)   ; S5.T4
                               :disposed-generation-count (instance-rec-disposed-gen-count rec)
                               :no-writers-generation-count (instance-rec-no-writers-gen-count rec)))))))
  (when sguid
    (%reader-advance-drained dr sguid sn))
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
                       (dds.core.buffer:octet-buffer-over (dds.disc:secured-loan-bytes loan))))))
    ;; repoint the reusable wrapper at THIS pooled buffer, bound to [0,len) (zero per-sample cons; NFR-SEC-POSTURE bounds)
    (setf (dds.core.buffer:octet-buffer-vec ob) (dds.disc:secured-loan-bytes loan)
          (dds.core.buffer:octet-buffer-capacity ob) len)
    (multiple-value-bind (data decode-status) (%deserialize-payload ts ob)
      ;; A rejected payload is a STATUS now (ADR 0064), so DATA is NIL — never pass that to %instance-handle.
      ;; RETURN THE LOAN: this handle pins a slot in the disc-node decode pool, and it has NOT yet been
      ;; pushed onto dr-secured-loans (that happens below, on the delivery path), so nothing else would ever
      ;; free it — a forged payload would leak a pool slot per datagram until the pool starved. Advance the
      ;; watermark anyway: the reliable engine has already ACKed this SN and will not resend it.
      (when decode-status
        (dds.disc:node-return-loan node loan)
        (when sguid (%reader-advance-drained dr sguid sn))
        (return-from %drain-one-secured t))
      (%drain-one-secured-deliver dr node ts key loan sn sguid data))))

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
   the writer's pool eventually falls back to non-ZC — graceful, never a wedge).

   It latches +CS-FLAG-WAS-EXPOSED+ per wrapper (ADR 0105 §4.1) for the same reason read-loaned does, though
   only read-loaned NEEDS it: take-loaned empties DR-CACHE, so its wrappers are unreachable to a later
   selection. The latch belongs wherever a sample leaves the middleware, not only where it currently bites.
   NOT cleared for ship — pending counsel (R6)."
  ;; ADR 0093 slice 3: ONE critical section — unlike read/take-samples these mutate dr-cache inline
  ;; rather than through %select-samples, so the drain and the cache walk share the lock here.
  (%with-reader-cache (dr)
   (%drain-unlocked dr)
   (let ((data '()) (loans '()) (touched '()))
    (dolist (cs (dr-cache dr))
      (let* ((info (cached-sample-info cs)) (d (cached-sample-data cs))
             (handle (sample-info-instance-handle info)))
        (setf (sample-info-view-state info) (if (gethash handle (dr-instances dr)) :not-new :new))
        (pushnew handle touched :test #'equalp)
        (setf (sample-info-sample-state info) :read)
        (%note-accessed dr info)   ; ADR 0090 A3b: accessed is what makes a sample acknowledgeable
        (%cs-set-flag cs +cs-flag-was-exposed+ t)   ; ADR 0105 §4.1: D leaves the middleware here
        (push d data)
        (cond ((dds.types:flatdata-view-p d) (push d loans))     ; FlatData: the view is both DATA and loan (ADR 0017)
              ((dds.disc:secured-loan-handle-p (cached-sample-loan cs)) (push (cached-sample-loan cs) loans)))))   ; secured: the pooled-buffer handle (ADR 0038 (i)); NIL otherwise
    (dolist (h touched) (setf (gethash h (dr-instances dr)) t))
    (setf (dr-cache dr) '())                                    ; take removes ALL drained samples
    (values (nreverse data) (nreverse loans)))))

(defun* read-loaned (dr)
    (function (data-reader) (values list list))
  "DataReader::read by LOAN — WP-FLATDATA-ZC-LOAN (FR-PF-3/4, R6, ADR 0017; NOT cleared for ship — pending
   counsel). Like take-loaned but LEAVES the samples in the cache (mirrors read-samples vs take-samples): returns
   (values DATA-LIST LOANS) for the cached samples, marking each READ. The SAME loan-registry views are returned
   each call until return-loan releases them; the app still returns each view once (return-loan is idempotent, so
   a view returned after a read-then-take is a safe no-op).

   ⚠️ IT LATCHES +CS-FLAG-WAS-EXPOSED+ ON EVERY WRAPPER IT WALKS, and that is the sharpest instance of ADR
   0105 §4.1's hazard rather than symmetry with take-loaned. On a copy-backed sample this hands the
   application the middleware's POOLED struct and LEAVES the wrapper in DR-CACHE registered in NEITHER loan
   registry — so take-into's outstanding-loan refusal does not fire, the default (:read :not-read) mask
   re-selects the wrapper, and without the latch take-into parks a struct the application is still reading.
   Measured before the latch existed: the held sample's fields changed under it on the next delivery.
   NOT cleared for ship — pending counsel (R6)."
  ;; ADR 0093 slice 3: ONE critical section — unlike read/take-samples these mutate dr-cache inline
  ;; rather than through %select-samples, so the drain and the cache walk share the lock here.
  (%with-reader-cache (dr)
   (%drain-unlocked dr)
   (let ((data '()) (loans '()) (touched '()))
    (dolist (cs (dr-cache dr))
      (let* ((info (cached-sample-info cs)) (d (cached-sample-data cs))
             (handle (sample-info-instance-handle info)))
        (setf (sample-info-view-state info) (if (gethash handle (dr-instances dr)) :not-new :new))
        (pushnew handle touched :test #'equalp)
        (setf (sample-info-sample-state info) :read)
        (%note-accessed dr info)   ; ADR 0090 A3b: accessed is what makes a sample acknowledgeable
        (%cs-set-flag cs +cs-flag-was-exposed+ t)   ; ADR 0105 §4.1: D leaves the middleware here and the wrapper STAYS cached
        (push d data)
        (cond ((dds.types:flatdata-view-p d) (push d loans))     ; FlatData: the view is both DATA and loan (ADR 0017)
              ((dds.disc:secured-loan-handle-p (cached-sample-loan cs)) (push (cached-sample-loan cs) loans)))))   ; secured: the pooled-buffer handle (ADR 0038 (i))
    (dolist (h touched) (setf (gethash h (dr-instances dr)) t))
    (values (nreverse data) (nreverse loans)))))

(defun* %return-loan-unlocked (dr loans)
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
   valid regardless).

   ADR 0093 slice 1 — THE COPY PATH IS NOW A LOAN TOO. A third dispatch arm accepts the CACHED-SAMPLE
   wrappers that TAKE-SAMPLES returns: it releases whatever backs the wrapper (delegating to the two arms
   above, so each loan kind keeps exactly one release path), drops the cache entry, and recycles the
   wrapper + its SampleInfo to the per-reader freelists. ⚠️ RETURNING IS WHAT MAKES THE PATH ZERO-ALLOC,
   AND NOT RETURNING IS SAFE: an unreturned wrapper is simply never recycled, so the next delivery
   allocates a fresh one and the application sees exactly the pre-slice behaviour. There is no failure mode
   for a caller that ignores this — only a missed optimisation. Idempotent for the same reason as the other
   arms: a wrapper already returned is no longer in the cache and its backing release is a validated no-op.
   The DATA struct is NOT recycled here — that is ADR 0093 slice 4, which needs the get_key_value
   key-sample carve-out."
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
       (setf (dr-secured-loans dr) (delete v (dr-secured-loans dr))))
      ((cached-sample-p v)   ; ADR 0093 slice 1: the COPY-path wrapper itself, returned by take-samples
       ;; ⚠️ RELEASE WHAT BACKS IT FIRST. A cached-sample may WRAP a loan — a FlatData ZC view is its DATA,
       ;; a secured decode handle is its LOAN — and recycling the wrapper without releasing that backing
       ;; would strand the loan permanently (a pinned ZC slot / an unreturned decode buffer). Delegating to
       ;; the arms above keeps ONE release path per loan kind; both are idempotent, so a wrapper whose
       ;; backing was already released (the ordinary copy-path case, and the secured case that
       ;; %select-samples already released at selection) costs one predicate test.
       (let ((backing (or (cached-sample-loan v)
                          (let ((d (cached-sample-data v)))
                            (and (dds.types:flatdata-view-p d) d)))))
         (when backing (%return-loan-unlocked dr (list backing))))   ; HOTPATH-ALLOC(COLD): loan-backed samples only; the copy path never conses here
       (setf (dr-cache dr) (delete v (dr-cache dr)))   ; a RETURNED sample is GONE from the cache, never stale-readable (the rule the ZC arm sets)
       (%recycle-delivery dr v))))
  t)

(defun* return-loan (dr loans)
    (function (data-reader list) t)
  "DataReader::return_loan — the PUBLIC entry point: takes DR's cache lock (ADR 0093 slice 3) and releases
   each loan in LOANS. All the semantics live in %RETURN-LOAN-UNLOCKED; this exists only to serialise the
   DR-CACHE mutations that release performs against a concurrent drain on another thread.
   Callers ALREADY holding the cache lock (the KEEP_LAST loan drop inside %DRAIN, and the recursive release
   of a wrapper's backing loan) must call %RETURN-LOAN-UNLOCKED directly — the lock is not recursive."
  (%with-reader-cache (dr) (%return-loan-unlocked dr loans)))

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
  (%with-reader-cache (dr)
    (%return-loan-unlocked dr (append (copy-list (dr-loans dr)) (copy-list (dr-secured-loans dr)))))   ; WP-DCPS-SECURED-TAKE-LOAN (ADR 0038 (i)): sweep BOTH registries, each released via its own type-dispatched path
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
   through to %deserialize-sample below, which now also decodes IN PLACE through the reused per-reader
   dr-deser-scratch wrapper (RX-POOLING Phase A, ADR 0073 — zero alloc/sample), byte-identical."
  (let ((sguid (dds.disc:node-sample-writer-guid node key))
        (sn (dds.disc:node-sample-key-sn key))
        (advance t))                       ; advance the per-writer watermark unless arbitration keeps it pending
  (let ((bytes (dds.disc:node-sample-raw node key)))   ; ADR 0078: the VERBATIM entry — node-sample would copy a pooled buffer out, and this is the hot path
    (when (dds.disc:zc-loan-marker-p bytes)            ; WP-FLATDATA-ZC-LOAN (R6, ADR 0017): an UNRESOLVED ZC ref -> acquire a literal-0-copy view, never deserialize
      (%drain-one-loan dr ts key bytes sn sguid)
      (return-from %drain-one-sample t))
    (when (dds.disc:secured-loan-handle-p bytes)       ; WP-DCPS-SECURED-TAKE-LOAN (ADR 0038 (i)): a secured decode loan -> deserialize IN PLACE from the pooled buffer, register the handle, never allocate a decrypt vector
      (%drain-one-secured dr node ts key bytes sn sguid)
      (return-from %drain-one-sample t))
    (when bytes
     ;; ADR 0093 slice 4: pop a recycled struct of THIS reader's type and decode INTO it — zero allocation
     ;; for the sample itself. REUSE is NIL until the application has returned something, and then this is
     ;; byte-identical to allocating. Every non-delivery path below hands it straight back.
     (let ((reuse (and *rx-wrapper-pool-enabled* (%rx-data-pop dr)))
           (delivered nil))
      (multiple-value-bind (data decode-status)
          (if (typep bytes 'dds.core.buffer:octet-buffer)
              ;; ADR 0078: an RX-STORE-POOLED copy — the buffer IS the payload extent (its CAPACITY was set to
              ;; the exact plen at acquire), so it is decoded IN PLACE with no wrapper at all and under bounds
              ;; byte-identical to the exact-length vector it replaces (%deserialize-payload validates against
              ;; capacity). No scratch, no repointing — the reverse of the ADR 0073 wrapper, one step further.
              (%deserialize-payload ts bytes reuse)
              (%deserialize-sample ts bytes             ; RX-POOLING Phase A (ADR 0073): decode in place through the reused per-reader scratch wrapper -> zero alloc/sample
                                   (or (dr-deser-scratch dr)
                                       (setf (dr-deser-scratch dr) (dds.core.buffer:octet-buffer-over bytes)))
                                   reuse))
        ;; A REJECTED payload (FlatData: short body / non-transcodable representation id) is a STATUS now,
        ;; not a signalled condition (ADR 0064). Drop the sample: never hand a NIL DATA to the filter or to
        ;; %instance-handle. It must still fall through to the watermark advance at the tail — an early
        ;; return here would leave the sample unconsumed in the node store and re-drained on every pass,
        ;; forever. Strictly better than the old behaviour: the reject used to unwind to the receiver-thread
        ;; boundary handler, which discarded the WHOLE DATAGRAM (and every other sample batched into it);
        ;; one bad sample now costs exactly one sample.
        (when (and (null decode-status)
                   ;; ContentFilteredTopic: drop reader-side a sample failing the filter.
                   (or (null (dr-filter dr)) (funcall (dr-filter dr) data)))
          (let* ((scratch (%instance-handle ts data (%reader-keyhash-scratch dr) (%reader-keyhash-out dr)))   ; RX-POOLING (ADR 0075/0076): key serialized + result written IN PLACE through reused per-reader scratches -> zero alloc/sample. TRANSIENT: use only for the instance-rec lookup; read the STABLE handle off the rec for anything RETAINED.
                 (reason (%resource-reject-reason dr scratch))
                 (verdict (if (and (null reason) (%reader-exclusive-p dr))
                              (%arbitrate-owner dr node key scratch)
                              :deliver)))
            (cond
              (reason
               ;; RESOURCE_LIMITS would be exceeded -> reject (SAMPLE_REJECTED). The handle is RETAINED in the
               ;; SAMPLE_REJECTED status (read via get_status) -> a STABLE copy, never the reused scratch (rare path).
               (%reader-sample-rejected dr reason (copy-seq scratch)))
              ((eq verdict :drop-unmatched)
               ;; Source writer identified but not yet SEDP-matched -> keep pending, do NOT advance.
               (setf advance nil))
              ((eq verdict :drop-loser)
               ;; Lost EXCLUSIVE arbitration (owner resolved) -> DROP the data, but still register the writer.
               (let ((wid (dds.disc:node-sample-writer node key)) (rec (%reader-instance-rec dr scratch)))   ; %reader-instance-rec copies scratch->stable on a new instance
                 (when (and wid (not (member wid (instance-rec-writers rec))))
                   (push wid (instance-rec-writers rec)))))
              (t
                (let* ((rec (%reader-revive-instance dr scratch (dds.disc:node-sample-writer node key)))
                       (handle (the (simple-array (unsigned-byte 8) (16)) (instance-rec-handle rec)))   ; the STABLE handle (copied once at creation) — the ONLY handle retained past this drain
                       (depth (%reader-keeplast-depth dr))
                       (pinned nil))
                  (setf delivered t)
                  ;; S5.T1: retain the key holder for get_key_value. ⚠️ ADR 0093 slice 4 HAZARD 3: that makes
                  ;; the instance-rec the PERMANENT owner of this struct, so it must never return to the data
                  ;; pool — a later delivery decoding into it would silently rewrite the instance's key under
                  ;; GET_KEY_VALUE. PIN it; the pool loses one struct per INSTANCE, which is O(instances) and
                  ;; amortises to nothing per sample.
                  (unless (instance-rec-key-sample rec)
                    (setf (instance-rec-key-sample rec) data
                          pinned t))
                  (%deadline-touch dr handle)   ; WP-DCPS-API-COMPLETION S4: (re)arm this instance's requested DEADLINE on delivery (no-op + 0-alloc when INFINITE)
                  (when depth (%reader-keeplast-drop-oldest dr handle depth))   ; KEEP_LAST per-instance drop (DDS 1.4 §2.2.3.18) before append
                  ;; ADR 0093 slice 1: both wrappers come from DR's freelists when the application returns
                  ;; its taken samples, else are freshly allocated — delivery is identical either way.
                  (setf (dr-cache dr)
                        (nconc (dr-cache dr)
                               (list (let ((cs (%acquire-delivery
                                                dr data (instance-rec-state rec) handle sn
                                                sguid   ; DDS 1.4 §2.2.2.5.4; ALIASED, never copied — see the slot docstring
                                                (dds.disc:node-sample-timestamp node key)   ; S5.T4
                                                (instance-rec-disposed-gen-count rec)
                                                (instance-rec-no-writers-gen-count rec))))
                                       (%cs-set-flag cs +cs-flag-data-pinned+ pinned)
                                       cs)))))))))
        ;; ADR 0093 slice 4: EVERY non-delivery outcome hands the struct straight back — a decode failure, a
        ;; content-filter miss, a RESOURCE_LIMITS reject, and both EXCLUSIVE-ownership drops. Missing one
        ;; would not corrupt anything, it would just quietly drain the pool until it stopped helping.
        (unless delivered (%rx-data-push dr (or data reuse)))))))
    (when (and sguid advance)
      (%reader-advance-drained dr sguid sn)
      ;; WP-PERF: the sample has been COPIED OUT (%deserialize-sample built an independent struct), so its bytes
      ;; are dead — drop them from the shared node store. Nothing purged the plain (copy-path) store before, so
      ;; every sample a participant ever received was retained FOREVER: an unbounded leak, and — because %drain
      ;; rebuilds its pending-key list from the WHOLE store on EVERY take-samples — a QUADRATIC receive path.
      ;; ADR 0093 slice 2: UNCONDITIONAL now. The multi-reader question moved INTO node-consume-sample, which
      ;; decrements a per-(guid,SN) remaining-drainers count and purges only on the LAST reader's drain. It used
      ;; to be gated on node-sole-consumer-p, which was correct but one-sided: it refused to purge whenever two
      ;; SAME-topic readers shared the store, so those samples were retained FOREVER — the very leak (and
      ;; O(stored) drain) this call exists to fix, simply reinstated for multi-reader participants. The loan
      ;; paths return earlier and own their own store-entry lifetime (node-return-loan / %secured-loan-release).
      (dds.disc:node-consume-sample node sguid sn)))
  t)

(defun* %drain-unlocked (dr)
    (function (data-reader) t)
  "⚠️ CALLER MUST HOLD DR's CACHE LOCK — %DRAIN is the locked entry point.
   Pull newly-received changes from the engine and apply them in UNIFIED
   SEQUENCE-NUMBER ORDER. Data samples and dispose/unregister lifecycle changes share ONE writer SN
   space (each lifecycle change occupies a real SN), so they form ONE ordered CacheChange stream per
   writer (DDS 1.4 §2.2.2.5 / RTPS 2.5 §8.7.4) — applying them in SN order is the conformant behaviour
   and is what makes a dispose-then-revive (revive at the higher SN wins -> ALIVE) and a
   revive-then-dispose (dispose at the higher SN wins -> NOT_ALIVE_DISPOSED) land correctly within a
   single drain pass. Pending data SNs (above the dr-drained high-water mark) and pending lifecycle SNs
   (not yet in dr-lifecycle-drained) are merged and visited in SN order; each data SN runs
   %drain-one-sample and each lifecycle SN runs %drain-one-lifecycle, each maintaining its own
   exactly-once discipline.

   ⚠️ THE OLD CLAIM HERE — 'both streams are drained on the user thread so the reader cache +
   instance-recs are never mutated off-thread (S2)' — WAS FALSE, and is why the cache lock now exists:
   WAIT-SET-WAIT drains from whatever thread waits, and the discovery/announcer thread rewrites the same
   structures via %ON-WRITER-VANISHED and %AUTOPURGE-SWEEP. See %WITH-READER-CACHE (ADR 0093 slice 3)."
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
         (multi (> (dds.disc:node-user-reader-count node) 1)))
    ;; WP-PERF (NFR-MEM, ADR 0072): the two pending-p predicates are a NAMED flet + dynamic-extent, NOT fresh
    ;; per-call lambdas. They are DOWNWARD FUNARGS — node-collect-pending-* funcalls them per candidate UNDER the
    ;; node lock and never stores them — so SBCL stack-allocates each instead of consing a capturing closure
    ;; (over multi/node/rid/dr) every drain. %drain runs on EVERY take/read/samples-available (empty polls
    ;; included), so this is a per-CALL win, not per-delivered-sample; it also removes the dominant run-to-run
    ;; variance in the mem-per-sample poll loop (the empty-poll count varied and each drain consed these two).
    ;; NB the -UNLOCKED accessors: the predicates run INSIDE the node lock (node-collect-pending-*), and it is a
    ;; non-recursive mutex — the public lock-taking accessors would self-deadlock the drain.
    (flet ((%data-pending-p (g sn)
             (and (or (not multi) (dds.disc:node-reader-matches-writer-p-unlocked node rid g))
                  ;; WP-N-ENDPOINT-2C3 (ADR 0048/0017; MEMORY-SAFETY): gate on max(per-writer dr-drained, the
                  ;; ZC-joiner match-time high-water) so a mid-stream ZC joiner NEVER drains a marker delivered
                  ;; before it joined (its %zc-release would underflow the refcount = a cross-reader UAF).
                  (> sn (max (gethash g (dr-drained dr) 0)
                             (dds.disc:node-reader-join-watermark-unlocked node rid g)))))
           (%life-pending-p (g sn)
             (and (or (not multi) (dds.disc:node-reader-matches-writer-p-unlocked node rid g))
                  ;; comparing the (GUID, SN) pair against the drained list in place conses nothing per candidate.
                  (not (loop for k in (dr-lifecycle-drained dr)
                             thereis (and (eql (cdr k) sn) (equalp (car k) g)))))))
      (declare (dynamic-extent #'%data-pending-p #'%life-pending-p))
      ;; WP-PERF: walk the store ONCE deciding pendingness from (GUID, SN) directly — no key is consed for a
      ;; sample this reader will not take. The scratch vectors are reader-owned + reused, so the steady-state
      ;; drain conses only the keys it actually delivers.
      (let* ((data-keys (dds.disc:node-collect-pending-samples node #'%data-pending-p (dr-drain-data-keys dr)))
             (life-keys (dds.disc:node-collect-pending-lifecycle node #'%life-pending-p (dr-drain-life-keys dr)))
             ;; Order by raw RTPS SN (§8.3.5.4: SN is per-writer) so a dispose/revive from one writer still lands
             ;; in §2.2.2.5 SN order. Merged into the reader's REUSED plan vector and sorted in place.
             ;; NFR-MEM: the merged plan exists ONLY to tag each key data-vs-lifecycle, and it costs a CONS
             ;; PER KEY to do it. A pending lifecycle change is rare — a dispose or unregister, not a sample —
             ;; so the steady-state drain merges an empty list into a one-element one and pays a cons for the
             ;; privilege. With no lifecycle pending, DATA-KEYS is already the whole plan: sort it in place
             ;; (it is the reader's own reused vector) and drain it directly, consing nothing. The merged path
             ;; below is unchanged and still handles ordering across the two streams.
             (lifecycle-pending (plusp (fill-pointer life-keys)))
             (plan (when lifecycle-pending
                     (let ((v (dr-drain-plan dr)))
                       (setf (fill-pointer v) 0)
                       (loop for k across data-keys do (vector-push-extend (cons :data k) v))
                       (loop for k across life-keys do (vector-push-extend (cons :lifecycle k) v))
                       (sort v #'< :key (lambda (e) (dds.disc:node-sample-key-sn (cdr e))))))))
        (if lifecycle-pending
            (loop for entry across plan
                  do (ecase (car entry)
                       (:data (%drain-one-sample dr node ts (cdr entry)))
                       (:lifecycle (%drain-one-lifecycle dr node (cdr entry)))))
            ;; Same SN ordering (§8.3.5.4 / §2.2.2.5), same exactly-once discipline — one stream, no tagging.
            (progn
              (sort data-keys #'< :key #'dds.disc:node-sample-key-sn)
              (loop for k across data-keys do (%drain-one-sample dr node ts k))))
        t))))

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

(defun* %snapshot-view-state (dr info)
    (function (data-reader sample-info) (member :new :not-new))
  "The VIEW_STATE of INFO's instance as DR sees it right now (DDS 1.4 §2.2.2.5.1.4): NEW until the
   application has accessed that instance (via a read/take), NOT_NEW afterwards. Read from DR-INSTANCES,
   which %select-samples marks only AFTER its selection pass — so every sample of a not-yet-accessed
   instance reads NEW within one call (the DDS snapshot semantics). The single definition of the view
   state: both the view_states FILTER and the view-state STAMPED on a returned sample use it."
  (if (gethash (sample-info-instance-handle info) (dr-instances dr)) :not-new :new))

(defun* %snapshot-instance-state (dr info)
    (function (data-reader sample-info) (member :alive :not-alive-disposed :not-alive-no-writers))
  "The INSTANCE_STATE of INFO's instance as DR sees it right now (DDS 1.4 §2.2.2.5.1.3), read from the
   live per-instance record. Like the view state, this is a property of the INSTANCE and not of the
   sample: DDS 1.4 §2.2.2.5.4 computes the SampleInfo fields when the samples are RETURNED, so a sample
   that was received while its instance was ALIVE and is read AFTER the instance was disposed must report
   NOT_ALIVE_DISPOSED. (Before the three-mask work each sample kept the state frozen at delivery, so such
   a sample reported ALIVE forever.) Falls back to the delivery-time stamp when the instance has no record
   — an already-purged instance, whose samples keep the state they were delivered with. The single
   definition: both the instance_states FILTER and the state STAMPED on a returned sample use it."
  (let ((rec (gethash (sample-info-instance-handle info) (dr-instance-recs dr))))
    (if rec (instance-rec-state rec) (sample-info-instance-state info))))

(defun* %state-mask-match-p (dr info sample-states view-states instance-states)
    (function (data-reader sample-info list list list) t)
  "The DDS 1.4 THREE-MASK sample selection predicate (§2.2.2.5.3): T iff INFO's sample_state,
   view_state, and instance_state each fall in the corresponding mask. The masks are lists of keywords;
   the ANY_*_STATE defaults (+any-sample-states+ / +any-view-states+ / +any-instance-states+) admit
   everything, so a caller that passes them is byte-identical to the pre-three-mask sample-state-only
   selection. Shared by read/take (+ the _instance / _next_* variants), get_datareaders, and the
   Read/QueryCondition trigger — ONE definition of what a state mask means (ADR 0053 §2.4)."
  (and (member (sample-info-sample-state info) sample-states)
       (member (%snapshot-view-state dr info) view-states)
       (member (%snapshot-instance-state dr info) instance-states)
       t))

(defun* %copy-sample-info-into (src dst)
    (function (sample-info sample-info) sample-info)
  "Fill DST from SRC in place (ADR 0105) and return DST — the SampleInfo half of TAKE-INTO / READ-INTO,
   where the destination is an APPLICATION-OWNED struct the application allocated once and reuses.

   ⚠️ EVERY ONE OF SAMPLE-INFO'S 13 SLOTS IS ASSIGNED UNCONDITIONALLY, for exactly the reason
   %ACQUIRE-DELIVERY gives for the recycled-wrapper case: the destination is a REUSED struct still holding
   the PREVIOUS sample's fields, so a slot this function forgets hands the application a field of a sample
   it already consumed. That failure is silent, application-visible, and invisible to every allocation gate
   (they measure bytes, and the byte count is identical either way). ADDING A SLOT TO SAMPLE-INFO REQUIRES
   ADDING IT HERE — RUN-TAKE-INTO-POISON-TEST is what proves none was missed, by sentinel-filling all 13
   and observing the destination AT THE COPY rather than through a later read (ADR 0093 covered 10 of 13
   slots while appearing to cover all, because %SELECT-SAMPLES legitimately re-stamps three of them).

   ⚠️ THE TWO ARRAY SLOTS — INSTANCE-HANDLE and PUBLICATION-HANDLE — ARE ALIASED, NOT COPIED, and that is
   correct rather than lazy. Both are WRITE-ONCE immutable arrays: the instance handle is copy-seq'd once
   per INSTANCE at instance-rec creation and never mutated, and the publication handle is the per-received-
   sample GUID %SOURCE-GUID freshly allocates and nothing mutates (see the SAMPLE-INFO slot docstring,
   which makes that aliasing a load-bearing invariant of ADR 0088 Option B). Copying them would cost a
   measured ~32 B each per sample on the one arm this ADR exists to drive to zero. ⚠️ IF EITHER TARGET EVER
   BECOMES MUTABLE this must become a REPLACE into application-preallocated 16-octet arrays."
  (setf (sample-info-sample-state dst)                 (sample-info-sample-state src)
        (sample-info-view-state dst)                   (sample-info-view-state src)
        (sample-info-instance-state dst)               (sample-info-instance-state src)
        (sample-info-source-timestamp dst)             (sample-info-source-timestamp src)
        (sample-info-instance-handle dst)              (sample-info-instance-handle src)
        (sample-info-publication-handle dst)           (sample-info-publication-handle src)
        (sample-info-disposed-generation-count dst)    (sample-info-disposed-generation-count src)
        (sample-info-no-writers-generation-count dst)  (sample-info-no-writers-generation-count src)
        (sample-info-sample-rank dst)                  (sample-info-sample-rank src)
        (sample-info-generation-rank dst)              (sample-info-generation-rank src)
        (sample-info-absolute-generation-rank dst)     (sample-info-absolute-generation-rank src)
        (sample-info-valid-data dst)                   (sample-info-valid-data src)
        (sample-info-sequence-number dst)              (sample-info-sequence-number src))
  dst)

(defun* %select-samples-unlocked (dr states where handle max take-p
                         &optional (view-states +any-view-states+)
                                   (instance-states +any-instance-states+)
                                   (into-data nil) (into-infos nil))
    (function (data-reader list function (or null (simple-array (unsigned-byte 8) (16)))
              (or null (integer 0)) boolean &optional list list
              (or null simple-vector) (or null simple-vector))
              (values list (integer 0)))
  "The shared read/take core (DDS 1.4 §2.2.2.5.3). ⚠️ CALLER MUST HOLD DR's CACHE LOCK
   (%SELECT-SAMPLES is the locked entry point). Assumes DR is already drained. Selects the cached
   samples matching the THREE state masks — sample_state in STATES, view_state in VIEW-STATES,
   instance_state in INSTANCE-STATES (%state-mask-match-p; both default to ANY, so omitting them is the
   pre-three-mask behaviour) — that satisfy WHERE (the query predicate over the deserialized sample), that
   belong to HANDLE (when non-NIL — the read/take_instance filter), up to MAX (when non-NIL —
   read/take_next_sample), in cache (arrival) order. Marks each selected sample READ and stamps its two
   INSTANCE-level SampleInfo fields — view_state + instance_state — from the reader's CURRENT per-instance
   state, as DDS 1.4 §2.2.2.5.4 requires (they are computed when the samples are returned, not frozen at
   delivery); a secured decode loan is released per returned sample. TAKE-P removes the selected samples
   from the cache; otherwise they stay. Returns (values SELECTED-CACHED-SAMPLES COUNT) in order.

   ⚠️ INTO-MODE (ADR 0105). With INTO-DATA + INTO-INFOS both supplied this writes each selected sample into
   INTO-DATA[i] / INTO-INFOS[i] — application-owned storage — instead of consing a list of middleware
   wrappers, and returns (values NIL COUNT). The mode is a BRANCH INSIDE THIS FUNCTION and not a private
   loop of its own, deliberately (ADR 0105 §4.3): a separate implementation would have to replicate the
   three-mask predicate, the §2.2.2.5.4 view/instance-state snapshot stamping, %NOTE-ACCESSED for APP-ACK,
   %RELEASE-SECURED-COPY-LOAN and the two-phase touched -> DR-INSTANCES marking — and any omission is a
   silent correctness regression that no allocation gate measures.

   ⚠️ CALLER CONTRACT FOR INTO-MODE, all five checked by TAKE-INTO / READ-INTO before they get here:
   MAX is <= (length INTO-DATA) so the write index can never run off the end; the two vectors are the same
   length; the reader's type-support has a bound COPY-INTO (a FlatData type's is NIL); every destination
   element 0..MAX-1 is already a constructed sample / SampleInfo, so neither copier can fault on it
   (%INTO-DESTINATIONS-READY-P); and the reader has no outstanding loan, so no selected sample's DATA can
   be a flatdata-view.

   ⚠️ RECORDED RESIDUE — THE DESTRUCTIVE HALF IS NOT ATOMIC. The recycle for sample i runs inside the loop
   while the DR-CACHE commit runs after it, so a non-local exit part-way through leaves earlier wrappers
   BOTH parked on the pool and still listed in the cache. Every trigger the middleware controls is closed
   by the caller contract above; what remains is an application-supplied WHERE predicate that signals — out
   of contract for every access operation here, and harmless for the list-returning ones because they do
   nothing destructive before their own commit. Making it unconditionally atomic means deferring the
   recycles past the commit, which is a hot-path change and therefore needs a measurement; it is recorded
   in ADR 0105 §4.5 as slice-2 work rather than done unmeasured.

   ⚠️ THE RECYCLE IS CONDITIONAL ON *THREE* THINGS AND EACH ONE IS A REAL DEFECT WITHOUT IT.
   (a) TAKE-P — a READ leaves the wrapper IN DR-CACHE, so parking it on the wrapper pool would hand a live
       cache entry to the next delivery and the cache would then hold one wrapper describing two samples.
   (b) CACHED-SAMPLE-WAS-EXPOSED clear — a wrapper an earlier READ-SAMPLES handed out is still owned by the
       application (§4.1); recycling it rewrites data the application is reading. Such a sample is still
       TAKEN, merely not recycled, so it costs an allocation rather than correctness.
   (c) %RECYCLE-DELIVERY, never a raw %RX-DATA-PUSH (§4.5) — %DRAIN-ONE-SAMPLE pins the first struct of each
       instance as that instance's GET_KEY_VALUE key holder, and bypassing the pin rewrites the instance's
       key on the next delivery.
   Copy and recycle both run under the caller's cache lock (§4.2): %RX-DATA-POP / -PUSH are unsynchronised
   read-modify-writes, and shipped code calls take from an ON_DATA_AVAILABLE listener on the receiver
   thread, so recycling outside the lock would race two threads onto one struct (the ADR 0085 shape)."
  (let ((out '()) (keep '()) (touched '()) (n 0)
        (copy-into (and into-data
                        (dds.types:type-support-copy-into (topic-type-support (dr-topic dr)))))
        (node (dp-node (sub-participant (dr-subscriber dr)))))
    (dolist (cs (dr-cache dr))
      (let* ((info (cached-sample-info cs))
             (sel (and (%state-mask-match-p dr info states view-states instance-states)
                       (or (null max) (< n max))
                       (or (null handle) (equalp handle (sample-info-instance-handle info)))
                       (funcall where (cached-sample-data cs)))))
        (cond
          (sel
           (let ((h (sample-info-instance-handle info)))
             (setf (sample-info-view-state info) (%snapshot-view-state dr info))
             (setf (sample-info-instance-state info) (%snapshot-instance-state dr info))
             (pushnew h touched :test #'equalp))
           (setf (sample-info-sample-state info) :read)
           (%note-accessed dr info)   ; ADR 0090 A3b: accessed is what makes a sample acknowledgeable
           (%release-secured-copy-loan dr node cs)   ; release the secured decode loan (data struct is independent); FlatData view untouched
           (cond
             (into-data
              (let ((d (cached-sample-data cs)))
                (when d (funcall copy-into d (svref into-data n))))   ; valid_data NIL carries a NIL DATA: destination untouched, never a fault (ADR 0105 §3)
              (%copy-sample-info-into info (svref into-infos n))
              (when (and take-p (not (cached-sample-was-exposed cs)))
                (%recycle-delivery dr cs)))   ; the three conditions are in the docstring; each omission is a real defect
             (t
              (%cs-set-flag cs +cs-flag-was-exposed+ t)   ; ADR 0105: the app is about to hold this wrapper
              (push cs out)))
           (incf n))
          (t (when take-p (push cs keep))))))     ; take keeps only the UN-selected; read leaves the cache intact
    (dolist (h touched) (setf (gethash h (dr-instances dr)) t))   ; mark accessed after snapshot
    (when take-p (setf (dr-cache dr) (nreverse keep)))
    (values (nreverse out) n)))

(defun* %drain (dr)
    (function (data-reader) t)
  "Drain DR under its cache lock (ADR 0093 slice 3). The work is %DRAIN-UNLOCKED; this is the entry point
   every caller uses. Callers already holding the lock use the -UNLOCKED form directly — the lock is not
   recursive. Lock order: cache lock OUTER, node lock INNER (the drain takes the node lock inside)."
  (%with-reader-cache (dr) (%drain-unlocked dr)))

(defun* %select-samples (dr states where handle max take-p
                         &optional (view-states +any-view-states+)
                                   (instance-states +any-instance-states+))
    (function (data-reader list function (or null (simple-array (unsigned-byte 8) (16)))
              (or null (integer 0)) boolean &optional list list) list)
  "Select from DR's cache under its cache lock (ADR 0093 slice 3); the work is %SELECT-SAMPLES-UNLOCKED.

   Selection and the preceding drain are two SEPARATE critical sections, deliberately. Holding one lock
   across both would serialise a whole read/take against every other reader operation for no safety gain:
   the memory-safety property needed is only that no LIST MUTATION interleaves with another, and that a
   wrapper handed to the application is out of the cache before it can be recycled — both of which hold
   per-section, because selection removes the sample under the lock and RETURN-LOAN recycles under it too.
   What is NOT promised is that two threads concurrently taking from one reader each see every sample;
   DDS never promised that, and the interleaving costs a sample to one taker, never corrupts either."
  (%with-reader-cache (dr)
    ;; ONE value: the core also returns a COUNT for ADR 0105's into-mode, and letting that leak out would
    ;; silently add a second return value to read-samples/take-samples and the six _instance/_next entries.
    (values (%select-samples-unlocked dr states where handle max take-p view-states instance-states))))

(defun* read-samples (dr &key (states +any-sample-states+) (where #'%where-any)
                              (view-states +any-view-states+)
                              (instance-states +any-instance-states+))
    (function (data-reader &key (:states list) (:where function) (:view-states list)
                    (:instance-states list))
              (or list (member :not-enabled)))
  "DataReader::read (DDS 1.4 §2.2.2.5.3.1) — the cached samples matching the THREE state masks and
   satisfying WHERE (the read_w_condition query predicate; %where-any by default), WITHOUT removing them;
   each is marked READ with its view-state stamped. STATES / VIEW-STATES / INSTANCE-STATES are the DDS
   sample_states / view_states / instance_states masks, each a list of kinds and each defaulting to its
   ANY_*_STATE (so the defaults select everything). Returns a list of cached-sample. A DISABLED DataReader
   refuses with :not-enabled (DDS 1.4 §2.2.2.1.1.7, S2.T3)."
  (unless (entity-enabled-p dr) (return-from read-samples +retcode-not-enabled+))
  (%drain dr)
  (%select-samples dr states where nil nil nil view-states instance-states))

(defun* take-samples (dr &key (states +any-sample-states+) (where #'%where-any)
                              (view-states +any-view-states+)
                              (instance-states +any-instance-states+))
    (function (data-reader &key (:states list) (:where function) (:view-states list)
                    (:instance-states list))
              (or list (member :not-enabled)))
  "DataReader::take (DDS 1.4 §2.2.2.5.3.8) — like read-samples (same three state masks + WHERE) but
   REMOVES the returned samples from the cache. A DISABLED DataReader refuses with :not-enabled."
  (unless (entity-enabled-p dr) (return-from take-samples +retcode-not-enabled+))
  (%drain dr)
  (%select-samples dr states where nil nil t view-states instance-states))

;;; ---- ADR 0105: the NON-LOAN access operations. A take is not a loan. ----

(defun* %into-destinations-ready-p (sample-p data infos limit)
    (function (function simple-vector simple-vector (integer 0)) boolean)
  "T iff every destination element TAKE-INTO / READ-INTO could write — indices 0..LIMIT-1 of BOTH DATA and
   INFOS — already holds a constructed object of the right kind: a sample of the reader's own type
   (SAMPLE-P is that type's generated <name>-P predicate, carried in the type-support vtable) and a
   SAMPLE-INFO. Only 0..LIMIT-1 is examined, because that is the most the call can write; a longer vector's
   tail is the application's business.

   ⚠️ THIS IS NOT DEFENSIVE PROGRAMMING, IT IS THE NO-CONDITIONS RULE. The copiers are fully typed —
   %COPY-SAMPLE-INFO-INTO is (SAMPLE-INFO SAMPLE-INFO) and the generated COPY-INTO-<name> is (<name>
   <name>) — and entities.lisp compiles at the default safety, so a wrong-typed destination element makes
   SBCL signal a TYPE-ERROR out of the middle of the copy loop, i.e. a Lisp condition escaping src/, which
   the operating contract forbids outright. The natural mistake produces one: (MAKE-ARRAY 32) is the
   obvious reading of \"vectors the application allocates once\", and SBCL fills a simple-vector with 0, so
   the FIRST element already faults. A mere NIL test would not catch that — which is why the type-support
   carries a predicate rather than this function testing for NIL.

   ⚠️ IT IS ALSO WHAT MAKES THE DESTRUCTIVE HALF SAFE. The copy loop recycles each taken wrapper as it
   goes, while DR-CACHE is committed only after the loop; a fault part-way through therefore skipped the
   commit and left a wrapper parked on the pool AND still listed in the cache — one wrapper describing two
   samples, plus a VALID-DATA T entry whose DATA is NIL. Measured on the working tree before this guard
   existed. Validating up front removes every trigger the middleware controls; the residue is recorded in
   %SELECT-SAMPLES-UNLOCKED."
  (loop for i from 0 below limit
        always (and (funcall sample-p (svref data i))
                    (sample-info-p (svref infos i)))))

(defun* %access-into (dr data infos states where view-states instance-states max-samples take-p)
    (function (data-reader simple-vector simple-vector list function list list
               (or null (integer 0)) boolean)
              (values (integer 0) (or null keyword)))
  "The shared body of TAKE-INTO (TAKE-P T) and READ-INTO (TAKE-P NIL) — the DDS 1.4 §2.2.2.5.3.8
   max_len>0 / owns==TRUE variant, in which the middleware COPIES into the caller's collections and there
   is no loan and no return obligation (ADR 0105). Returns (values COUNT STATUS): COUNT elements of DATA
   and INFOS were filled in place, STATUS is NIL on success and a ReturnCode_t otherwise. Nothing signals.

   THE SIX REFUSALS, in the order they are cheapest to decide:
     :NOT-ENABLED               a disabled reader (DDS 1.4 §2.2.2.1.1.7)
     :PRECONDITION-NOT-MET      (/= (length DATA) (length INFOS)) — §2.2.2.5.3.8 rule 1, the collections
                                must be one-to-one, or the application cannot pair a sample with its info
     :PRECONDITION-NOT-MET      MAX-SAMPLES > (length DATA) — rule 5, third bullet: the application would
                                be asking for samples that could never be returned. NIL is LENGTH_UNLIMITED
                                and means (length DATA), which is what max_len is in this PSM
     :PRECONDITION-NOT-MET      the reader's type has NO COPY-INTO — a FlatData type, whose sample IS a
                                buffer and not a struct. Slice 1 refuses it (ADR 0105 §4.4). The same
                                clause refuses a type-support with no SAMPLE-P, because the destinations
                                could then not be validated and the next refusal would have to be skipped
     :PRECONDITION-NOT-MET      a destination element of DATA or INFOS is not already a constructed sample
                                / SAMPLE-INFO — §2.2.2.5.3.8's malformed-collection class. See
                                %INTO-DESTINATIONS-READY-P for why this is the no-conditions rule and not
                                belt-and-braces
     :PRECONDITION-NOT-MET      the reader holds an OUTSTANDING LOAN. See below
   and :NO-DATA with COUNT 0 when nothing was selected (§2.2.2.5.3) — an empty result, not an error.

   ⚠️ WHY AN OUTSTANDING LOAN IS THE LOAN-CAPABLE TEST, and why it is exact rather than a proxy. ADR 0105
   §4.4 refuses Zero-Copy / FlatData / secured readers in slice 1, because copying a flatdata-view into the
   struct pool would never %ZC-RELEASE it — recreating the ADR 0096 slot leak — and because a secured
   sample's pooled decode buffer is not ours to recycle. A ZC view is in DR-CACHE if and only if it is in
   DR-LOANS: %DRAIN-ONE-LOAN registers it before delivery and %RETURN-LOAN-UNLOCKED deletes the cache entry
   and the registry entry together, precisely so a returned loan can never be stale-read. The same holds
   for a secured handle and DR-SECURED-LOANS. So testing the two REGISTRIES under the cache lock decides
   the property for the whole cache in O(1), where a per-sample FLATDATA-VIEW-P test would cost a typecheck
   on every selected sample and decide no more. It is deliberately CONSERVATIVE: a reader that still holds
   a loan it took earlier is refused even if every cached sample is a plain struct.

   ⚠️ THE REGISTRY TEST MUST RUN UNDER THE SAME LOCK AS THE SELECTION, not before it. %DRAIN and the
   selection are two separate critical sections on purpose, so another application thread can drain
   loan-bearing samples into this reader between them; checking inside the selection's own lock makes the
   cache we test the exact cache we then read."
  (let* ((ts (topic-type-support (dr-topic dr)))
         (sample-p (dds.types:type-support-sample-p ts))
         (limit (or max-samples (length data))))
    (cond
      ((not (entity-enabled-p dr)) (values 0 +retcode-not-enabled+))
      ((/= (length data) (length infos)) (values 0 +retcode-precondition-not-met+))
      ((and max-samples (> max-samples (length data))) (values 0 +retcode-precondition-not-met+))
      ((or (null (dds.types:type-support-copy-into ts)) (null sample-p))
       (values 0 +retcode-precondition-not-met+))
      ((not (%into-destinations-ready-p sample-p data infos limit))
       (values 0 +retcode-precondition-not-met+))
      (t
       (%drain dr)
       (%with-reader-cache (dr)
         (if (or (dr-loans dr) (dr-secured-loans dr))
             (values 0 +retcode-precondition-not-met+)
             (let ((n (nth-value 1 (%select-samples-unlocked
                                    dr states where nil limit take-p
                                    view-states instance-states data infos))))
               (values n (if (zerop n) +retcode-no-data+ nil)))))))))

(defun* take-into (dr data infos &key (states +any-sample-states+) (where #'%where-any)
                                      (view-states +any-view-states+)
                                      (instance-states +any-instance-states+)
                                      (max-samples nil))
    (function (data-reader simple-vector simple-vector &key (:states list) (:where function)
                    (:view-states list) (:instance-states list) (:max-samples (or null (integer 0))))
              (values (integer 0) (or null keyword)))
  "DataReader::take into APPLICATION-OWNED storage — the DDS 1.4 §2.2.2.5.3.8 max_len>0 / owns==TRUE
   variant (ADR 0105). DATA and INFOS are vectors the application allocates ONCE and reuses forever; this
   fills elements 0..COUNT-1 IN PLACE and returns (values COUNT STATUS). There is NO loan and NO return
   obligation, which is exactly what distinguishes it from TAKE-SAMPLES: the middleware's own pooled struct
   is recycled here, inside the same critical section, instead of being handed out and waited on.

   Like TAKE-SAMPLES it REMOVES the selected samples from the reader cache, marks them READ, and applies
   the same three state masks (STATES / VIEW-STATES / INSTANCE-STATES, each defaulting to its ANY_*_STATE)
   and the same WHERE query predicate. MAX-SAMPLES defaults to NIL = LENGTH_UNLIMITED = (length DATA).

   ⚠️ DATA's and INFOS's elements must ALREADY be constructed objects — a sample of this reader's type and
   a SAMPLE-INFO — for indices 0..MAX-SAMPLES-1 (or the whole vector when MAX-SAMPLES is NIL). This fills
   them; it does not create them. (MAKE-ARRAY 32) is NOT a valid destination: it is 32 zeros.

   Refuses with PRECONDITION_NOT_MET when the two vectors differ in length, when MAX-SAMPLES exceeds
   (length DATA), when a destination element is not a constructed sample / SampleInfo, on a FlatData type,
   and — in slice 1 — on a reader holding an outstanding Zero-Copy or secured loan; with NOT_ENABLED on a
   disabled reader; and reports NO_DATA with COUNT 0 when nothing matched. See %ACCESS-INTO for why each of
   those is the rule it is.

   ⚠️ AT AN INDEX WHOSE SAMPLEINFO HAS VALID-DATA NIL, NOTHING IN THE DESTINATION SAMPLE IS MEANINGFUL —
   NOT EVEN THE KEY FIELDS. The middleware's wrapper carries a NIL sample for a dispose/unregister, so
   there is nothing to copy and the destination struct is left EXACTLY as the previous call left it: it
   holds some earlier sample's fields, and on a multi-instance reader that is a DIFFERENT INSTANCE's key.
   The instance is identified SOLELY by SAMPLE-INFO-INSTANCE-HANDLE (with GET-KEY-VALUE available to turn
   that handle into a key sample). TAKE-SAMPLES hands back a literal NIL that cannot be missed; a
   pre-allocated destination cannot, so this is part of the documented contract. ALWAYS test
   SAMPLE-INFO-VALID-DATA before reading ANY field of the destination sample."
  (%access-into dr data infos states where view-states instance-states max-samples t))

(defun* read-into (dr data infos &key (states +any-sample-states+) (where #'%where-any)
                                      (view-states +any-view-states+)
                                      (instance-states +any-instance-states+)
                                      (max-samples nil))
    (function (data-reader simple-vector simple-vector &key (:states list) (:where function)
                    (:view-states list) (:instance-states list) (:max-samples (or null (integer 0))))
              (values (integer 0) (or null keyword)))
  "DataReader::read into APPLICATION-OWNED storage — the non-destructive twin of TAKE-INTO, same lambda
   list, same refusals, same (values COUNT STATUS) contract (ADR 0105). It ships in the SAME slice and not
   later because §2.2.2.5.3.8 is the READ clause and take merely inherits it; a take-only owns==TRUE
   variant would be a conformance gap.

   The selected samples STAY in the cache marked READ, exactly as READ-SAMPLES leaves them. ⚠️ Nothing is
   recycled here, and that is not an oversight: the wrapper this copied out of is still a live cache entry,
   so parking it on the reader's pool would let the next delivery overwrite a sample the cache still lists.
   READ-INTO costs no allocation either — it simply recovers none.

   The same destination-element precondition and the same VALID-DATA caveat as TAKE-INTO apply: the
   elements must already be constructed objects, and at an invalid-data index NOTHING in the destination
   sample is meaningful — it simply keeps its previous contents, so the instance is identified only by
   SAMPLE-INFO-INSTANCE-HANDLE."
  (%access-into dr data infos states where view-states instance-states max-samples nil))

;;; ---- Instance / next sample-access (S5.T2, DDS 1.4 §2.2.2.5.3). Each carries the FULL DDS three-mask
;;;      (sample_states + view_states + instance_states) signature, as the base read/take do. ----

(defun* read-instance (dr handle &key (states +any-sample-states+) (where #'%where-any)
                            (view-states +any-view-states+)
                            (instance-states +any-instance-states+))
    (function (data-reader (simple-array (unsigned-byte 8) (16)) &key (:states list) (:where function)
                    (:view-states list) (:instance-states list))
              (or list (member :not-enabled :bad-parameter)))
  "DataReader::read_instance (DDS 1.4 §2.2.2.5.3.4) — read (without removing) only the samples of the
   instance named by HANDLE. BAD_PARAMETER when HANDLE names no known instance; :not-enabled on a disabled
   reader."
  (unless (entity-enabled-p dr) (return-from read-instance +retcode-not-enabled+))
  (%drain dr)
  (unless (nth-value 1 (gethash handle (dr-instance-recs dr)))
    (return-from read-instance +retcode-bad-parameter+))
  (%select-samples dr states where handle nil nil view-states instance-states))

(defun* take-instance (dr handle &key (states +any-sample-states+) (where #'%where-any)
                            (view-states +any-view-states+)
                            (instance-states +any-instance-states+))
    (function (data-reader (simple-array (unsigned-byte 8) (16)) &key (:states list) (:where function)
                    (:view-states list) (:instance-states list))
              (or list (member :not-enabled :bad-parameter)))
  "DataReader::take_instance (DDS 1.4 §2.2.2.5.3.5) — take (removing) only the samples of the instance
   named by HANDLE. BAD_PARAMETER when HANDLE names no known instance."
  (unless (entity-enabled-p dr) (return-from take-instance +retcode-not-enabled+))
  (%drain dr)
  (unless (nth-value 1 (gethash handle (dr-instance-recs dr)))
    (return-from take-instance +retcode-bad-parameter+))
  (%select-samples dr states where handle nil t view-states instance-states))

(defun* %handle< (a b)
    (function ((simple-array (unsigned-byte 8) (16)) (simple-array (unsigned-byte 8) (16))) boolean)
  "Strict octet-lexicographic order on two 16-octet instance handles — the reader's stable total instance
   iteration order (DDS 1.4 §2.2.2.5.8 leaves the order middleware-defined but requires it be consistent)."
  (dotimes (i 16 nil)
    (let ((x (aref a i)) (y (aref b i)))
      (cond ((< x y) (return t)) ((> x y) (return nil))))))

(defun* %next-instance-handle (dr previous-handle)
    (function (data-reader (simple-array (unsigned-byte 8) (16)))
              (or null (simple-array (unsigned-byte 8) (16))))
  "The smallest known instance handle strictly greater than PREVIOUS-HANDLE in octet order, or NIL when
   none remains — the read/take_next_instance cursor. PREVIOUS-HANDLE = HANDLE_NIL selects the FIRST
   (smallest) keyed instance (an unkeyed reader's single HANDLE_NIL instance is reached via plain read)."
  (let ((best nil))
    (maphash (lambda (h v) (declare (ignore v))
               (when (and (%handle< previous-handle h) (or (null best) (%handle< h best)))
                 (setf best h)))
             (dr-instance-recs dr))
    best))

(defun* read-next-instance (dr previous-handle &key (states +any-sample-states+) (where #'%where-any)
                                     (view-states +any-view-states+)
                                     (instance-states +any-instance-states+))
    (function (data-reader (simple-array (unsigned-byte 8) (16)) &key (:states list) (:where function)
                    (:view-states list) (:instance-states list))
              (or list (member :not-enabled)))
  "DataReader::read_next_instance (DDS 1.4 §2.2.2.5.3.6) — read the samples of the next instance after
   PREVIOUS-HANDLE in the reader's instance order (HANDLE_NIL = the first instance); an empty list when no
   next instance exists."
  (unless (entity-enabled-p dr) (return-from read-next-instance +retcode-not-enabled+))
  (%drain dr)
  (let ((h (%next-instance-handle dr previous-handle)))
    (if h (%select-samples dr states where h nil nil view-states instance-states) '())))

(defun* take-next-instance (dr previous-handle &key (states +any-sample-states+) (where #'%where-any)
                                     (view-states +any-view-states+)
                                     (instance-states +any-instance-states+))
    (function (data-reader (simple-array (unsigned-byte 8) (16)) &key (:states list) (:where function)
                    (:view-states list) (:instance-states list))
              (or list (member :not-enabled)))
  "DataReader::take_next_instance (DDS 1.4 §2.2.2.5.3.7) — take the samples of the next instance after
   PREVIOUS-HANDLE; an empty list when no next instance exists."
  (unless (entity-enabled-p dr) (return-from take-next-instance +retcode-not-enabled+))
  (%drain dr)
  (let ((h (%next-instance-handle dr previous-handle)))
    (if h (%select-samples dr states where h nil t view-states instance-states) '())))

(defun* read-next-sample (dr)
    (function (data-reader) (or null cached-sample (member :not-enabled)))
  "DataReader::read_next_sample (DDS 1.4 §2.2.2.5.3.2) — the next NOT_READ sample in order (any instance),
   read (marked READ) and returned, or NIL when none (NO_DATA)."
  (unless (entity-enabled-p dr) (return-from read-next-sample +retcode-not-enabled+))
  (%drain dr)
  (first (%select-samples dr '(:not-read) #'%where-any nil 1 nil)))

(defun* take-next-sample (dr)
    (function (data-reader) (or null cached-sample (member :not-enabled)))
  "DataReader::take_next_sample (DDS 1.4 §2.2.2.5.3.3) — the next NOT_READ sample in order, taken
   (removed) and returned, or NIL when none (NO_DATA)."
  (unless (entity-enabled-p dr) (return-from take-next-sample +retcode-not-enabled+))
  (%drain dr)
  (first (%select-samples dr '(:not-read) #'%where-any nil 1 t)))

(defun* samples-available (dr)
    (function (data-reader) (integer 0))
  "Drain newly-received samples into the cache and return the cache size, WITHOUT
   marking anything READ — for polling before a read/take."
  (%with-reader-cache (dr) (%drain-unlocked dr) (length (dr-cache dr))))

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
                              ;; A freshly matched writer is ALIVE, and the DCPS status has to be told
                              ;; so. The discovery sweep already ASSUMES it — %liveliness-sweep defaults
                              ;; a writer with no LIVELINESS-STATE entry to alive and fires only on a
                              ;; TRANSITION — so without this the count is never established: it starts
                              ;; at 0, no alive transition ever occurs to raise it, and a later
                              ;; not-alive has nothing to decrement. DDS 1.4 §2.2.4.1 defines
                              ;; alive_count as the number of currently ALIVE matched writers, so 0
                              ;; while receiving that writer's samples is simply wrong. Symmetric with
                              ;; the sweep's own "a freshly matched writer starts ALIVE" assumption, so
                              ;; the two cannot disagree, and %reader-unmatched drops it again below.
                              (%reader-liveliness-changed dr handle t)
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
                              ;; The symmetric half of the match-time ALIVE above: a writer that goes
                              ;; away stops being an ALIVE matched writer, so alive_count must drop
                              ;; with it. Without this the count only ever climbs and a participant
                              ;; that churns endpoints reports more live writers than exist.
                              ;; %reader-liveliness-changed floors at 0, so an unmatch of a writer the
                              ;; sweep had already marked not-alive cannot drive it negative.
                              (%reader-liveliness-changed dr handle nil)
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
   lands on the RIGHT reader(s), INCLUDING same-topic readers (S6 — the route is a list; the dolist below
   fires each). N=1 == the sole reader (route fallback)."
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

(defun* %deliver-data-on-readers (p)
    (function (domain-participant) t)
  "The DATA_ON_READERS / DATA_AVAILABLE delivery decision on new data for participant P (DDS 1.4
   §2.2.4.1 precedence). For each Subscriber with DataReaders: if a listener enabled for
   DATA_ON_READERS exists on the Subscriber or the DomainParticipant, invoke on_data_on_readers on
   the MOST-SPECIFIC such listener and DO NOT fire the readers' on_data_available (the precedence
   rule) — but still wake their WaitSets so a waiting reader drains; otherwise fire each reader's
   on_data_available (propagated up its own chain via %wake-reader-data). The disc callbacks are
   participant-coarse (no reader identity), so this is level-triggered — a spurious notification of a
   subscriber whose readers have nothing pending is benign (mirrors the existing DATA_AVAILABLE wake)."
  (dolist (sub (participant-subscribers p))
    (let ((readers (sub-readers sub)))
      (when readers
        (let ((l (%find-enabled-listener sub :data-on-readers)))
          (if l
              (progn
                (on-data-on-readers l sub)
                (dolist (dr readers) (%notify-reader-conditions dr)))
              (dolist (dr readers) (%wake-reader-data dr)))))))
  t)

(defun* %on-participant-sample (p)
    (function (domain-participant) t)
  "ON-SAMPLE hook (disc receiver thread): new user data arrived for P. Route through the
   DATA_ON_READERS / DATA_AVAILABLE precedence decision (%deliver-data-on-readers, DDS 1.4
   §2.2.4.1). Holds no node lock here (the disc layer released it before calling).
   WP-N-ENDPOINT-S5 (ADR 0048): the disc data-ready callback carries no writer identity, so every
   local reader is considered; each drains only its own S2-source-GUID-filtered samples, so a
   spurious wake of a reader with nothing pending is benign (level-triggered). N=1 == the sole reader."
  (%deliver-data-on-readers p)
  t)

(defun* get-datareaders (subscriber &key (sample-states '(:not-read))
                                         (view-states +any-view-states+)
                                         (instance-states +any-instance-states+))
    (function (subscriber &key (:sample-states list) (:view-states list) (:instance-states list)) list)
  "DDS Subscriber::get_datareaders (dds_rtf2_dcps.idl §993, DDS 1.4 §2.2.2.5.2.7): the list of
   SUBSCRIBER's DataReaders that hold at least one sample matching ALL THREE state masks —
   sample_state in SAMPLE-STATES (default (:not-read) — readers with NEW data), view_state in
   VIEW-STATES, and instance_state in INSTANCE-STATES (both defaulting to their ANY_*_STATE, i.e. no
   further restriction, so the default call is the pre-three-mask behaviour). Runs on the app thread and
   drains each reader's newly-received samples first (via %count-matching), so a reader that just
   received data is included."
  (remove-if-not (lambda (dr) (plusp (%count-matching dr sample-states view-states instance-states)))
                 (sub-readers subscriber)))

(defun* notify-datareaders (subscriber)
    (function (subscriber) t)
  "DDS Subscriber::notify_datareaders (dds_rtf2_dcps.idl §998, DDS 1.4 §2.2.2.5.2.8): invoke
   on_data_available on each of SUBSCRIBER's DataReaders that has new data (get_datareaders). The
   application calls this from on_data_on_readers to cascade DATA_ON_READERS down to the per-reader
   DATA_AVAILABLE callbacks (each propagated up its own reader -> Subscriber -> participant chain)."
  (dolist (dr (get-datareaders subscriber)) (%fire-data-available dr))
  t)

(defun* %reader-matched (dr handle)
    (function (data-reader t) t)
  "Bump DR's SUBSCRIPTION_MATCHED status via the %notify-status chokepoint (bitmask bit +
   StatusCondition + listener): if a listener is masked, fire on-subscription-matched with a
   snapshot (resetting the *_change counters per DDS)."
  (%notify-status dr +status-subscription-matched+ :subscription-matched
   (lambda ()
     (let ((s (dr-sub-matched dr)))
       (incf (subscription-matched-status-total-count s))
       (incf (subscription-matched-status-total-count-change s))
       (incf (subscription-matched-status-current-count s))
       (incf (subscription-matched-status-current-count-change s))
       (setf (subscription-matched-status-last-publication-handle s) handle)
       (values t (copy-subscription-matched-status s)
               (lambda () (setf (subscription-matched-status-total-count-change s) 0
                                (subscription-matched-status-current-count-change s) 0))))))
  t)

(defun* %writer-matched (dw handle)
    (function (data-writer t) t)
  "Bump DW's PUBLICATION_MATCHED status via the %notify-status chokepoint (bitmask bit +
   StatusCondition + listener): if a listener is masked, fire on-publication-matched with a
   snapshot (resetting the *_change counters per DDS)."
  (%notify-status dw +status-publication-matched+ :publication-matched
   (lambda ()
     (let ((s (dw-pub-matched dw)))
       (incf (publication-matched-status-total-count s))
       (incf (publication-matched-status-total-count-change s))
       (incf (publication-matched-status-current-count s))
       (incf (publication-matched-status-current-count-change s))
       (setf (publication-matched-status-last-subscription-handle s) handle)
       (values t (copy-publication-matched-status s)
               (lambda () (setf (publication-matched-status-total-count-change s) 0
                                (publication-matched-status-current-count-change s) 0))))))
  t)

(defun* %reader-unmatched (dr handle)
    (function (data-reader t) t)
  "Decrement DR's SUBSCRIPTION_MATCHED on a lost match (DDS 1.4 §2.2.4.1): current_count--
   (floored at 0), current_count_change accumulates -1 (mirroring how %reader-matched
   accumulates +1), last_publication_handle := the unmatched remote's GUID, total_count
   UNCHANGED (monotonic, dds_rtf2_dcps.idl §174). Routes through the %notify-status chokepoint
   (bitmask bit + StatusCondition + listener): fires on-subscription-matched if masked (snapshot
   + reset the *_change counters per DDS), then wakes the reader's WaitSets."
  (%notify-status dr +status-subscription-matched+ :subscription-matched
   (lambda ()
     (let ((s (dr-sub-matched dr)))
       (when (plusp (subscription-matched-status-current-count s))
         (decf (subscription-matched-status-current-count s)))
       (decf (subscription-matched-status-current-count-change s))
       (setf (subscription-matched-status-last-publication-handle s) handle)
       (values t (copy-subscription-matched-status s)
               (lambda () (setf (subscription-matched-status-total-count-change s) 0
                                (subscription-matched-status-current-count-change s) 0))))))
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
  (%notify-status dr +status-liveliness-changed+ :liveliness-changed
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
       (values t (copy-liveliness-changed-status s)
               (lambda () (setf (liveliness-changed-status-alive-count-change s) 0
                                (liveliness-changed-status-not-alive-count-change s) 0))))))
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
          (%notify-status dw +status-liveliness-lost+ :liveliness-lost
           (lambda ()
             (if (and (dw-alive-p dw) (> (- now (dw-last-assertion dw)) lease))
                 (let ((s (dw-liv-lost dw)))
                   (incf (liveliness-lost-status-total-count s))
                   (incf (liveliness-lost-status-total-count-change s))
                   (setf (dw-alive-p dw) nil)
                   (values t (copy-liveliness-lost-status s)
                           (lambda () (setf (liveliness-lost-status-total-count-change s) 0))))
                 (values nil nil nil)))))))
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
  (%notify-status dw +status-publication-matched+ :publication-matched
   (lambda ()
     (let ((s (dw-pub-matched dw)))
       (when (plusp (publication-matched-status-current-count s))
         (decf (publication-matched-status-current-count s)))
       (decf (publication-matched-status-current-count-change s))
       (setf (publication-matched-status-last-subscription-handle s) handle)
       (values t (copy-publication-matched-status s)
               (lambda () (setf (publication-matched-status-total-count-change s) 0
                                (publication-matched-status-current-count-change s) 0))))))
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
  (%notify-status dr +status-requested-incompatible-qos+ :requested-incompatible-qos
   (lambda ()
     (let ((s (dr-req-incompat dr)))
       (%apply-requested-incompatible s bad)
       (let ((snapshot (copy-requested-incompatible-qos-status s)))
         (setf (requested-incompatible-qos-status-policies snapshot)
               (mapcar #'copy-qos-policy-count (requested-incompatible-qos-status-policies s)))
         (values t snapshot
                 (lambda () (setf (requested-incompatible-qos-status-total-count-change s) 0)))))))
  t)

(defun* %writer-incompatible (dw bad)
    (function (data-writer list) t)
  "Bump DW's OFFERED_INCOMPATIBLE_QOS status via the %notify-status chokepoint (bitmask bit +
   StatusCondition + listener): fire on-offered-incompatible-qos if masked (snapshot
   deep-copying the policies)."
  (%notify-status dw +status-offered-incompatible-qos+ :offered-incompatible-qos
   (lambda ()
     (let ((s (dw-off-incompat dw)))
       (%apply-offered-incompatible s bad)
       (let ((snapshot (copy-offered-incompatible-qos-status s)))
         (setf (offered-incompatible-qos-status-policies snapshot)
               (mapcar #'copy-qos-policy-count (offered-incompatible-qos-status-policies s)))
         (values t snapshot
                 (lambda () (setf (offered-incompatible-qos-status-total-count-change s) 0)))))))
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

(defun* get-offered-deadline-missed-status (dw)
    (function (data-writer) offered-deadline-missed-status)
  "DataWriter::get_offered_deadline_missed_status — a snapshot; the read-communication-status reset
   (DDS 1.4 §2.2.2.1.9, dds_rtf2_dcps.idl §131-135) resets total_count_change and clears the
   OFFERED_DEADLINE_MISSED bit in the writer's status-changes bitmask."
  (dds.pal:with-lock ((dw-status-lock dw))
    (let ((s (dw-off-deadline dw)))
      (prog1 (copy-offered-deadline-missed-status s)
        (setf (offered-deadline-missed-status-total-count-change s) 0)
        (%clear-status-changed dw +status-offered-deadline-missed+)))))

(defun* get-requested-deadline-missed-status (dr)
    (function (data-reader) requested-deadline-missed-status)
  "DataReader::get_requested_deadline_missed_status — a snapshot; the read-communication-status
   reset (DDS 1.4 §2.2.2.1.9, dds_rtf2_dcps.idl §137-141) resets total_count_change and clears the
   REQUESTED_DEADLINE_MISSED bit in the reader's status-changes bitmask."
  (dds.pal:with-lock ((dr-status-lock dr))
    (let ((s (dr-req-deadline dr)))
      (prog1 (copy-requested-deadline-missed-status s)
        (setf (requested-deadline-missed-status-total-count-change s) 0)
        (%clear-status-changed dr +status-requested-deadline-missed+)))))

(defun* get-sample-lost-status (dr)
    (function (data-reader) sample-lost-status)
  "DataReader::get_sample_lost_status — a snapshot; the read-communication-status reset (DDS 1.4
   §2.2.2.1.9, dds_rtf2_dcps.idl §99-102 / §1163) resets total_count_change and clears the SAMPLE_LOST
   bit in the reader's status-changes bitmask (total_count stays monotonic)."
  (dds.pal:with-lock ((dr-status-lock dr))
    (let ((s (dr-sample-lost dr)))
      (prog1 (copy-sample-lost-status s)
        (setf (sample-lost-status-total-count-change s) 0)
        (%clear-status-changed dr +status-sample-lost+)))))

;;; ---- set_listener / get_listener on all six entity kinds (DDS 1.4 §2.2.4.1, S3.T1) ----

(defun* %entity-listener-lock (entity)
    (function (entity) t)
  "The lock guarding ENTITY's listener + listener-mask slots. DataReader/DataWriter/Topic
   reuse their status-lock (their listener slots live beside the status structs);
   Publisher/Subscriber/DomainParticipant have a dedicated listener-lock."
  (typecase entity
    (data-reader (dr-status-lock entity))
    (data-writer (dw-status-lock entity))
    (topic (topic-status-lock entity))
    (publisher (pub-listener-lock entity))
    (subscriber (sub-listener-lock entity))
    (domain-participant (dp-listener-lock entity))
    (t nil)))

(defun* %entity-listener (entity)
    (function (entity) (values t list))
  "ENTITY's installed listener + its enabled-status mask (a list of status keywords), or
   (values NIL NIL). The per-kind slot accessor behind the uniform listener-propagation walk
   (DDS 1.4 §2.2.4.1). Callers that need consistency take %entity-listener-lock first."
  (typecase entity
    (data-reader (values (dr-listener entity) (dr-listener-mask entity)))
    (data-writer (values (dw-listener entity) (dw-listener-mask entity)))
    (topic (values (topic-listener-obj entity) (topic-listener-mask entity)))
    (publisher (values (pub-listener entity) (pub-listener-mask entity)))
    (subscriber (values (sub-listener entity) (sub-listener-mask entity)))
    (domain-participant (values (dp-listener entity) (dp-listener-mask entity)))
    (t (values nil nil))))

(defun* %set-entity-listener (entity listener mask)
    (function (entity t list) t)
  "Store LISTENER + MASK into ENTITY's per-kind listener slots. CALLER HOLDS the listener lock."
  (typecase entity
    (data-reader (setf (dr-listener entity) listener (dr-listener-mask entity) mask))
    (data-writer (setf (dw-listener entity) listener (dw-listener-mask entity) mask))
    (topic (setf (topic-listener-obj entity) listener (topic-listener-mask entity) mask))
    (publisher (setf (pub-listener entity) listener (pub-listener-mask entity) mask))
    (subscriber (setf (sub-listener entity) listener (sub-listener-mask entity) mask))
    (domain-participant (setf (dp-listener entity) listener (dp-listener-mask entity) mask)))
  t)

(defun* set-listener (entity listener mask)
    (function (entity (or null listener) list) entity)
  "DDS Entity::set_listener (dds_rtf2_dcps.idl §749/§803/§888/§1006, DDS 1.4 §2.2.4.1): install
   LISTENER on ENTITY for the statuses named in MASK (a list of status keywords, e.g.
   (:publication-matched)); NIL clears it. Works uniformly on all six entity kinds
   (DomainParticipant, Publisher, Subscriber, Topic, DataWriter, DataReader). Held under
   ENTITY's listener lock."
  (dds.pal:with-lock ((%entity-listener-lock entity))
    (%set-entity-listener entity listener mask))
  entity)

(defun* get-listener (entity)
    (function (entity) t)
  "DDS Entity::get_listener (dds_rtf2_dcps.idl §751/§890/§1008, DDS 1.4 §2.2.4.1): ENTITY's
   currently installed listener object (NIL if none). Works on all six entity kinds."
  (dds.pal:with-lock ((%entity-listener-lock entity))
    (values (%entity-listener entity))))

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

(defun* %on-disc-unaddressable (p guid kinds)
    (function (domain-participant t list) t)
  "ON-UNADDRESSABLE hook (disc receiver thread), owner directive 2026-07-22: a remote endpoint matched on
   topic/type/QoS but its participant advertises NO user-data locator this implementation can send to, so
   the disc layer REFUSED the match. Report it as a real communication status on the participant through the
   %notify-status chokepoint — status bitmask bit + StatusCondition (so a WaitSet wakes) + the most-specific
   enabled listener + a get-unaddressable-peer-status snapshot.

   WHY A STATUS AND NOT A LOG. This is an ERROR an application must be able to see and act on: it means a
   peer it believes it is talking to will never receive anything. A printed line is unconsumable by an
   application, untestable by a caller, and invisible in a service. UNADDRESSABLE_PEER is a VENDOR
   EXTENSION (DDS 1.4 defines no such status) carried on a bit far outside the OMG range."
  (%notify-status p +status-unaddressable-peer+ :unaddressable-peer
   (lambda ()
     (let ((s (dp-unaddressable-status p)))
       (incf (unaddressable-peer-status-total-count s))
       (incf (unaddressable-peer-status-total-count-change s))
       (setf (unaddressable-peer-status-last-guid s) guid
             (unaddressable-peer-status-last-locator-kinds s) kinds
             ;; Name the kinds, so the status says WHAT the peer offered (e.g. shared memory (RTI Connext))
             ;; rather than a bare number an operator has to decode (ADR 0081).
             (unaddressable-peer-status-last-locator-names s)
             (mapcar #'dds.rtps.discovery:locator-kind-name kinds))
       (values t (copy-unaddressable-peer-status s)
               (lambda () (setf (unaddressable-peer-status-total-count-change s) 0))))))
  t)

(defun* get-unaddressable-peer-status (p)
    (function (domain-participant) unaddressable-peer-status)
  "DomainParticipant::get_unaddressable_peer_status (VENDOR EXTENSION) — a snapshot of the
   UNADDRESSABLE_PEER status: how many remote endpoints were refused a match because nothing could be sent
   to them, the last such GUID, and the Locator_t kinds it did offer. Mirrors the read-communication-status
   reset (DDS 1.4 §2.2.2.1.9): resets total_count_change and clears the status bit."
  (dds.pal:with-lock ((%entity-status-lock p))
    (let ((s (dp-unaddressable-status p)))
      (prog1 (copy-unaddressable-peer-status s)
        (setf (unaddressable-peer-status-total-count-change s) 0)
        (%clear-status-changed p +status-unaddressable-peer+)))))

;;;; ---- ADR 0089 vendor-extension reliability statuses. Each rides the %notify-status chokepoint, so
;;;; it gets the bitmask bit + StatusCondition + most-specific-listener walk + snapshot for free.

(defun* %writer-cache-max-samples (qos)
    (function (t) (or null (integer 1)))
  "QOS's RESOURCE_LIMITS max_samples as a finite positive bound, or NIL when it is the DDS
   LENGTH_UNLIMITED sentinel -1 (the default) or QOS is absent — an unlimited cache can never become
   FULL, so the RELIABLE_WRITER_CACHE_CHANGED full-transition simply does not arise for it (ADR 0089)."
  (and (typep qos 'dds.qos:qos)
       (let ((n (dds.qos:qos-resource-max-samples qos)))
         (and (plusp n) n))))

(defun* %writer-cache-edges (dw unacked was armed)
    (function (data-writer (integer 0) (integer 0) t) (values t t t t))
  "The four RELIABLE_WRITER_CACHE_CHANGED threshold crossings implied by DW's send window moving from WAS
   to UNACKED while a backpressure episode is or is not open (ARMED), as
   (values EMPTIED FILLED CROSSED-LOW CROSSED-HIGH) — ADR 0089.

   Every one is an EDGE: true only when the move CROSSED the threshold, never while the level merely sits
   beyond it. A writer parked above its high watermark has ONE high-watermark event, not one per write.

   THREE OF THE FOUR ARE ALSO GATED ON THE EPISODE, which is what makes the status usable. The high
   watermark OPENS an episode; the low watermark and the drain to empty CLOSE one. An exchange that never
   reaches the high watermark is not in trouble, so its perfectly ordinary drains to zero are not events —
   without this gate a reliable writer with one sample in flight reports an empty transition on EVERY
   sample, which is a per-sample application callback on the data path saying nothing. With both watermarks
   NIL (the default) no episode can ever open, so only FILLED remains: an absolute condition — the cache is
   at RESOURCE_LIMITS max_samples and the next write blocks or is refused — that needs no episode to mean
   something. Pure and allocation-free, so a caller can evaluate it before building anything.

   An ABSENT or non-dds.qos:qos QoS yields no watermarks and no bound, i.e. no events at all — the same
   defensive shape as %writer-liveliness-kind. This runs on the per-sample write path, where a condition
   is forbidden outright (the no-conditions rule), so it must not be able to signal one."
  (let* ((q (entity-qos dw))
         (qp (typep q 'dds.qos:qos))
         (low (and qp (dds.qos:qos-writer-cache-low-watermark q)))
         (high (and qp (dds.qos:qos-writer-cache-high-watermark q)))
         (maxs (%writer-cache-max-samples q)))
    (values (and armed (zerop unacked) (plusp was))                   ; episode drained to empty
            (and maxs (< was maxs) (>= unacked maxs))                 ; filled to RESOURCE_LIMITS max_samples
            (and armed low (> was low) (<= unacked low))              ; episode fell back TO the low watermark
            (and (not armed) high (< was high) (>= unacked high)))))  ; rose TO the high watermark: episode opens

;;; The four RELIABLE_WRITER_CACHE_CHANGED edges as bits of one fixnum (ADR 0089). They are a BITMASK
;;; rather than four flags for a measured reason: four separate variables that are assigned inside the
;;; status lock and then read by the notification closure are, to SBCL, four MUTABLE CLOSED-OVER
;;; variables, and it heap-allocates a value cell for each — 123.5 bytes/sample on the per-sample write
;;; path, paid whether or not any edge was actually crossed. One immutably-bound fixnum is copied into
;;; the closure and costs nothing. Same family of defect as ADR 0088's builder closure.
(defconstant +wc-edge-empty+ 1 "RELIABLE_WRITER_CACHE_CHANGED edge bit: the send window drained to empty.")
(defconstant +wc-edge-full+  2 "RELIABLE_WRITER_CACHE_CHANGED edge bit: the cache reached RESOURCE_LIMITS max_samples.")
(defconstant +wc-edge-low+   4 "RELIABLE_WRITER_CACHE_CHANGED edge bit: an open episode fell back to the low watermark.")
(defconstant +wc-edge-high+  8 "RELIABLE_WRITER_CACHE_CHANGED edge bit: the send window rose to the high watermark, opening an episode.")

(defun* %writer-cache-record-level (s unacked replaced)
    (function (reliable-writer-cache-changed-status (integer 0) (integer 0)) t)
  "Record the two RELIABLE_WRITER_CACHE_CHANGED LEVELS on S: the current send-window occupancy UNACKED
   (raising the peak if it is a new high-water mark) and the monotonic REPLACED count of KEEP_LAST
   overwrites of unacknowledged data (ADR 0089). Levels are recorded on EVERY move of the window, whether
   or not that move was an event, so a snapshot read between two events still reports the truth.
   MUST be called under the entity's status lock."
  (setf (reliable-writer-cache-changed-status-unacked-sample-count s) unacked
        (reliable-writer-cache-changed-status-replaced-unacked-sample-count s) replaced)
  (when (> unacked (reliable-writer-cache-changed-status-unacked-sample-peak s))
    (setf (reliable-writer-cache-changed-status-unacked-sample-peak s) unacked))
  t)

(defun* %writer-cache-apply (dw unacked replaced)
    (function (data-writer (integer 0) (integer 0)) (integer 0 15))
  "Under DW's STATUS LOCK: record the send-window levels and return the bitmask of thresholds this move
   crossed (0 = none). Also opens or closes the backpressure episode — the high watermark opens one, the
   low watermark or a drain to empty closes it (ADR 0089).

   THE LOCK IS NOT OPTIONAL. The two callers are different threads — the application's write thread and a
   receiver thread draining an ACKNACK — and an edge is defined by a PAIR of levels. Reading the previous
   level unlocked would let the two interleave into a crossing that never happened, or lose one that did.
   The lock is a leaf: the disc layer reads the engine state BEFORE calling, never while holding a writer
   lock, so this cannot participate in a cycle.

   Returns a fixnum, and the caller binds it once, precisely so the notification closure captures an
   immutable value rather than four mutable ones — see the +WC-EDGE-*+ constants for what that cost."
  (dds.pal:with-lock ((%entity-status-lock dw))
    (let ((s (dw-rw-cache-changed dw))
          (was (dw-rw-last-unacked dw)))
      (if (and (= was unacked)
               (= replaced (reliable-writer-cache-changed-status-replaced-unacked-sample-count s)))
          0
          (multiple-value-bind (emptied filled crossed-low crossed-high)
              (%writer-cache-edges dw unacked was (dw-rw-armed dw))
            (cond (crossed-high (setf (dw-rw-armed dw) t))
                  ((or crossed-low emptied) (setf (dw-rw-armed dw) nil)))
            (setf (dw-rw-last-unacked dw) unacked)
            (%writer-cache-record-level s unacked replaced)
            (logior (if emptied +wc-edge-empty+ 0) (if filled +wc-edge-full+ 0)
                    (if crossed-low +wc-edge-low+ 0) (if crossed-high +wc-edge-high+ 0)))))))

(defun* %notify-writer-cache-changed (dw unacked replaced)
    (function (data-writer (integer 0) (integer 0)) t)
  "RELIABLE_WRITER_CACHE_CHANGED (VENDOR EXTENSION, ADR 0089): DW's send window now holds UNACKED changes
   not yet acknowledged by every matched reliable reader, and REPLACED changes have been overwritten by
   KEEP_LAST while still unacknowledged. Called from BOTH sites where the window moves — the write path
   (it rises) and the ACKNACK purge (it falls).

   THE LEVEL IS RECORDED ON EVERY CALL; THE STATUS FIRES ONLY ON A THRESHOLD CROSSING. Those are different
   things and conflating them is what made the first cut of this status unusable: a reliable exchange moves
   the unacked count twice per sample, so notifying on every move puts an application callback on the data
   path and reports nothing an application can act on. Levels (the count, its peak, the replaced count) are
   read out of the snapshot by get-reliable-writer-cache-changed-status; only the empty / full / low / high
   crossings are events.

   The compare-and-record runs under the entity's STATUS LOCK because the two callers are different threads
   — the application's write thread and a receiver thread draining an ACKNACK — and an edge is defined by a
   pair of levels. Reading the previous level unlocked would let the two interleave into a crossing that
   never happened, or lose one that did. The lock is a leaf here: no writer/engine lock is ever held across
   it (the disc layer reads the engine state before calling, never inside), so it cannot participate in a
   cycle.

   ALLOCATION (NFR-MEM): this sits on the per-sample write path, so the guard is HERE and not inside the
   notification. An unmoved window returns after two integer compares; a move that crosses nothing costs a
   locked update of two slots. %notify-status is reached only on a real crossing — its APPLY-FN closure
   allocates on every call whether or not anything changed, which is exactly the defect that cost ADR 0088
   its entire first-cut win."
  (let ((edges (%writer-cache-apply dw unacked replaced)))
    (unless (zerop edges)
      (%notify-status dw +status-reliable-writer-cache-changed+ :reliable-writer-cache-changed
       (lambda ()
         (let ((s (dw-rw-cache-changed dw)))
           (when (logtest edges +wc-edge-empty+)
             (incf (reliable-writer-cache-changed-status-empty-count s))
             (incf (reliable-writer-cache-changed-status-empty-count-change s)))
           (when (logtest edges +wc-edge-full+)
             (incf (reliable-writer-cache-changed-status-full-count s))
             (incf (reliable-writer-cache-changed-status-full-count-change s)))
           (when (logtest edges +wc-edge-low+)
             (incf (reliable-writer-cache-changed-status-low-watermark-count s))
             (incf (reliable-writer-cache-changed-status-low-watermark-count-change s)))
           (when (logtest edges +wc-edge-high+)
             (incf (reliable-writer-cache-changed-status-high-watermark-count s))
             (incf (reliable-writer-cache-changed-status-high-watermark-count-change s)))
           (values t (copy-reliable-writer-cache-changed-status s)
                   (lambda ()
                     (setf (reliable-writer-cache-changed-status-empty-count-change s) 0
                           (reliable-writer-cache-changed-status-full-count-change s) 0
                           (reliable-writer-cache-changed-status-low-watermark-count-change s) 0
                           (reliable-writer-cache-changed-status-high-watermark-count-change s) 0)))))))
    t))

(defun* %notify-reader-activity (dw reader-guid activep)
    (function (data-writer t t) t)
  "RELIABLE_READER_ACTIVITY_CHANGED (VENDOR EXTENSION, ADR 0089): the matched remote reader named by
   READER-GUID is now acknowledging DW (ACTIVEP true) or has stopped. Membership of DW-ACTIVE-READERS is
   the truth rather than a counter, so a repeated ACKNACK from an already-active reader is NOT an event
   and cannot inflate active_count — the counter-only shape is how LIVELINESS_CHANGED.alive_count came
   to be inert (fixed 2026-07-25), and it is not repeated here.

   THE MEMBERSHIP TEST RUNS FIRST, AND THAT IS AN ALLOCATION FIX, NOT A MICRO-OPTIMISATION. This is called
   once per inbound ACKNACK — about once per sample — and %notify-status takes a CLOSURE, which is built on
   every call whether or not anything changed. Measured at 76.4 bytes/sample before this guard. In the
   steady state the answer is always 'this reader was already active', so the guard returns before anything
   is built. It is the same defect ADR 0088 found in its own first cut, inherited here unchanged.

   The guard takes the status lock because the active-reader set is a hash table mutated under that lock by
   the apply-fn below; an unlocked GETHASH racing a REMHASH can read a table mid-rehash. It is a
   double-check: apply-fn re-tests membership under the lock it holds, so a race between the two only costs
   a redundant closure, never a wrong count."
  (unless (let ((known (dds.pal:with-lock ((%entity-status-lock dw))
                         (nth-value 1 (gethash reader-guid (dw-active-readers dw))))))
            (if activep known (not known)))
    (%notify-status dw +status-reliable-reader-activity-changed+ :reliable-reader-activity-changed
     (lambda ()
       (let* ((s (dw-rr-activity dw))
              (tbl (dw-active-readers dw))
              (known (nth-value 1 (gethash reader-guid tbl)))
              (changed (if activep (not known) known)))
         (when changed
           (if activep (setf (gethash reader-guid tbl) t) (remhash reader-guid tbl))
           (let ((n (hash-table-count tbl)))
             (setf (reliable-reader-activity-changed-status-active-count s) n)
             (if activep
                 (incf (reliable-reader-activity-changed-status-active-count-change s))
                 (progn (incf (reliable-reader-activity-changed-status-inactive-count s))
                        (incf (reliable-reader-activity-changed-status-inactive-count-change s)))))
           (setf (reliable-reader-activity-changed-status-last-instance-handle s)
                 (and (typep reader-guid '(array (unsigned-byte 8) (*))) reader-guid)))
         (values changed
                 (and changed (copy-reliable-reader-activity-changed-status s))
                 (lambda ()
                   (setf (reliable-reader-activity-changed-status-active-count-change s) 0
                         (reliable-reader-activity-changed-status-inactive-count-change s) 0)))))))
  t)

(defun* get-reliable-writer-cache-changed-status (dw)
    (function (data-writer) reliable-writer-cache-changed-status)
  "DataWriter::get_reliable_writer_cache_changed_status (VENDOR EXTENSION, ADR 0089) — a snapshot of DW's
   reliable send window: the four threshold-crossing counts (empty / full / low watermark / high
   watermark), the current unacked-sample count and its high-water peak, and the count of unacknowledged
   samples KEEP_LAST has replaced. Mirrors the read-communication-status reset (DDS 1.4 §2.2.2.1.9):
   resets the four *_change deltas and clears the status bit.

   TWO FIELDS ARE DELIBERATELY NOT RESET, and both for the same reason — they are cumulative facts, not
   deltas. UNACKED-SAMPLE-PEAK is a high-water mark: resetting it on read would report the last quiet
   moment instead of the worst one, which is the only moment worth knowing. REPLACED-UNACKED-SAMPLE-COUNT
   is a running total of data already lost; a reader of this status wants 'how much have I lost', and
   losing that history to the act of looking at it would make the number unusable."
  (dds.pal:with-lock ((%entity-status-lock dw))
    (let ((s (dw-rw-cache-changed dw)))
      (prog1 (copy-reliable-writer-cache-changed-status s)
        (setf (reliable-writer-cache-changed-status-empty-count-change s) 0
              (reliable-writer-cache-changed-status-full-count-change s) 0
              (reliable-writer-cache-changed-status-low-watermark-count-change s) 0
              (reliable-writer-cache-changed-status-high-watermark-count-change s) 0)
        (%clear-status-changed dw +status-reliable-writer-cache-changed+)))))

(defun* %notify-application-acknowledgment (dw reader-guid last-sn app-unacked)
    (function (data-writer t integer (integer 0)) t)
  "APPLICATION_ACKNOWLEDGMENT (VENDOR EXTENSION, ADR 0090 A3c): the matched remote reader named by
   READER-GUID has acknowledged DW's samples up to LAST-SN on its APPLICATION's behalf, leaving APP-UNACKED
   samples in the application-level send window.

   NOT edge-triggered and NOT episode-gated, unlike ADR 0089's cache status — deliberately. That status
   reports a LEVEL that moves twice per sample in ordinary traffic, so it needed thresholds to become an
   event. This one reports an EVENT: an application acknowledgment is something the peer application did
   explicitly, it happens at most once per sample and typically far less, and suppressing any of them would
   hide the very thing the callback exists to report. The frequency is the peer's to choose.

   READER-GUID is RETAINED in the status snapshot, so it must be an object nothing mutates. The caller
   passes the writer's WRITER-LOOKUP-KEY cache entry, which is written once and never modified (ADR 0088)
   — safe by construction, the same guarantee %notify-reader-activity relies on."
  (%notify-status dw +status-application-acknowledgment+ :application-acknowledgment
   (lambda ()
     (let ((s (dw-app-ack dw)))
       (incf (application-acknowledgment-status-total-count s))
       (incf (application-acknowledgment-status-total-count-change s))
       (setf (application-acknowledgment-status-last-subscription-handle s)
             (and (typep reader-guid '(array (unsigned-byte 8) (*))) reader-guid)
             (application-acknowledgment-status-last-sequence-number s) last-sn
             (application-acknowledgment-status-app-unacked-sample-count s) app-unacked)
       (when (zerop app-unacked) (%app-ack-deadline-disarm dw))   ; nothing outstanding -> nothing can be overdue
       ;; %notify-status's apply-fn contract is (values CHANGED-P SNAPSHOT RESET-THUNK) — returning the
       ;; snapshot alone makes it the CHANGED-P value and hands the listener NIL, which is how the first
       ;; cut of this fired a callback carrying no status at all. Always CHANGED: an application
       ;; acknowledgment is an event, not a level, so there is no "nothing happened" case to suppress.
       (values t
               (copy-application-acknowledgment-status s)
               (lambda () (setf (application-acknowledgment-status-total-count-change s) 0))))))
  t)

(defun* get-application-acknowledgment-status (dw)
    (function (data-writer) application-acknowledgment-status)
  "DataWriter::get_application_acknowledgment_status (VENDOR EXTENSION, ADR 0090) — a snapshot of how many
   application acknowledgments DW has received, which reader sent the last one and up to which sequence
   number, and how many samples remain un-acknowledged BY THE APPLICATION. Mirrors the
   read-communication-status reset (DDS 1.4 §2.2.2.1.9): the *_change field is cleared on read.

   Under ACKNOWLEDGMENT_KIND :PROTOCOL this reads all zeros forever, because nothing ever sends an APP_ACK.
   That is the honest answer, not an inert status: the writer genuinely has no application-level knowledge."
  (dds.pal:with-lock ((%entity-status-lock dw))
    (let ((s (dw-app-ack dw)))
      (prog1 (copy-application-acknowledgment-status s)
        (setf (application-acknowledgment-status-total-count-change s) 0)
        (%clear-status-changed dw +status-application-acknowledgment+)))))

(defun* %app-ack-deadline-period (dw)
    (function (data-writer) (or null (integer 1)))
  "DW's ACKNOWLEDGMENT_DEADLINE in internal-time-units, or NIL when the watchdog does not apply — the
   writer is not under an APPLICATION acknowledgment kind, or the deadline is INFINITE (the explicit
   opt-out into unbounded silent retention). NIL is the whole cost for a :PROTOCOL writer: one keyword
   comparison on the write path, no timer, no monitor thread."
  (let ((q (entity-qos dw)))
    (when (and q (not (eq (dds.qos:qos-acknowledgment-kind q) :protocol))
               (not (dds.qos:duration-infinite-p (dds.qos:qos-acknowledgment-deadline q))))
      (%deadline-period-units (dds.qos:qos-acknowledgment-deadline q)))))

(defun* %app-ack-deadline-arm (dw)
    (function (data-writer) t)
  "(Re)arm DW's ACKNOWLEDGMENT_DEADLINE watchdog on write (ADR 0090 A4). A no-op — and 0-alloc, no monitor
   interaction — unless the writer is under an APPLICATION acknowledgment kind with a finite deadline, so
   the default write path is byte-identical. The timer is PER WRITER, keyed by the sentinel :app-ack."
  (let ((period (%app-ack-deadline-period dw)))
    (when period (%deadline-arm-or-rearm dw :app-ack period :app-ack)))
  t)

(defun* %app-ack-deadline-disarm (dw)
    (function (data-writer) t)
  "Disarm DW's acknowledgment watchdog — called when the application-level backlog reaches ZERO, because
   there is then nothing overdue and a still-armed timer would fire on an empty writer."
  (%deadline-disarm-instance dw :app-ack)
  t)

(defun* %fire-application-acknowledgment-overdue (dw)
    (function (data-writer) t)
  "APPLICATION_ACKNOWLEDGMENT_OVERDUE (ADR 0090 A4): DW's ACKNOWLEDGMENT_DEADLINE elapsed with samples
   still un-application-acknowledged. Fired from the deadline monitor thread.

   THE ENGINE STATE IS PULLED, not carried, and that is what makes this callback different from every
   other status in this stack: it fires because NOTHING arrived, so there is no inbound event to carry a
   count. dds.disc:node-writer-app-unacked is the one pull-shaped accessor, and it exists so dds.dcps
   never resolves an rtps-writer itself.

   A BACKLOG OF ZERO FIRES NOTHING. The timer is disarmed when the backlog drains, but a drain racing an
   expiry is ordinary, and reporting 'overdue: 0 samples' would be a false alarm on a healthy writer."
  (let ((node (dp-node (pub-participant (dw-publisher dw)))))
    (multiple-value-bind (unacked oldest laggard)
        (dds.disc:node-writer-app-unacked node (dw-entity-id dw))
      (when (plusp unacked)
        (%notify-status dw +status-application-acknowledgment-overdue+ :application-acknowledgment-overdue
         (lambda ()
           (let ((s (dw-app-ack-overdue dw)))
             (incf (application-acknowledgment-overdue-status-total-count s))
             (incf (application-acknowledgment-overdue-status-total-count-change s))
             (setf (application-acknowledgment-overdue-status-last-subscription-handle s)
                   (and (typep laggard '(array (unsigned-byte 8) (*))) laggard)
                   (application-acknowledgment-overdue-status-oldest-unacknowledged-sequence-number s) oldest
                   (application-acknowledgment-overdue-status-app-unacked-sample-count s) unacked)
             ;; (values CHANGED-P SNAPSHOT RESET-THUNK) — the contract A3c learned the hard way by
             ;; returning the snapshot alone and firing a callback that carried NIL.
             (values t
                     (copy-application-acknowledgment-overdue-status s)
                     (lambda () (setf (application-acknowledgment-overdue-status-total-count-change s) 0)))))))))
  t)

(defun* get-application-acknowledgment-overdue-status (dw)
    (function (data-writer) application-acknowledgment-overdue-status)
  "DataWriter::get_application_acknowledgment_overdue_status (VENDOR EXTENSION, ADR 0090 A4) — a snapshot of
   how many times DW's ACKNOWLEDGMENT_DEADLINE has elapsed with an un-acknowledged backlog, which reader is
   furthest behind, the oldest unconfirmed sequence number, and the backlog size. The read-reset clears the
   *_change delta (DDS 1.4 §2.2.2.1.9)."
  (dds.pal:with-lock ((%entity-status-lock dw))
    (let ((s (dw-app-ack-overdue dw)))
      (prog1 (copy-application-acknowledgment-overdue-status s)
        (setf (application-acknowledgment-overdue-status-total-count-change s) 0)
        (%clear-status-changed dw +status-application-acknowledgment-overdue+)))))

(defun* get-reliable-reader-activity-changed-status (dw)
    (function (data-writer) reliable-reader-activity-changed-status)
  "DataWriter::get_reliable_reader_activity_changed_status (VENDOR EXTENSION, ADR 0089) — a snapshot of
   how many matched remote readers are currently acknowledging DW and how many have stopped. Mirrors the
   read-communication-status reset (DDS 1.4 §2.2.2.1.9)."
  (dds.pal:with-lock ((%entity-status-lock dw))
    (let ((s (dw-rr-activity dw)))
      (prog1 (copy-reliable-reader-activity-changed-status s)
        (setf (reliable-reader-activity-changed-status-active-count-change s) 0
              (reliable-reader-activity-changed-status-inactive-count-change s) 0)
        (%clear-status-changed dw +status-reliable-reader-activity-changed+)))))

(defun* %on-disc-inconsistent-topic (p name)
    (function (domain-participant string) t)
  "ON-INCONSISTENT-TOPIC hook (disc receiver thread): a remote endpoint announced topic
   NAME with a different type than P's local Topic of that name. Bump the Topic's
   INCONSISTENT_TOPIC status via the %notify-status chokepoint (bitmask bit + StatusCondition
   + listener); fire on_inconsistent_topic if masked."
  (let ((tp (%find-topic p name)))
    (when tp
      (%notify-status tp +status-inconsistent-topic+ :inconsistent-topic
       (lambda ()
         (let ((s (topic-inconsistent-status tp)))
           (incf (inconsistent-topic-status-total-count s))
           (incf (inconsistent-topic-status-total-count-change s))
           (values t (copy-inconsistent-topic-status s)
                   (lambda () (setf (inconsistent-topic-status-total-count-change s) 0))))))))
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
  (%deadline-disarm-endpoint dw)   ; WP-DCPS-API-COMPLETION S4: drop this writer's offered-deadline timers from the monitor
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
  (%deadline-disarm-endpoint dr)   ; WP-DCPS-API-COMPLETION S4: drop this reader's requested-deadline timers from the monitor
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
