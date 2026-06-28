;;;; DDS 1.4 DCPS entity model (M3/P2, FR-DCPS-1). CLOS — this is control-plane, so
;;;; CLOS is the preferred default (FR-LANG-0); none of this is on the hot path. The
;;;; entities are a thin, typed facade over the existing RTPS engine (dds.disc): a
;;;; DomainParticipant owns a multicast disc-node; a DataWriter/DataReader binds to
;;;; the engine's single user endpoint (v1 limitation — one writer + one reader per
;;;; participant; multi-endpoint needs per-endpoint RTPS EntityIds, a later step).
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
   (type-compat :initform nil :accessor entity-type-compat))
  (:documentation "Base DDS Entity: carries the QoS and the enabled flag shared by all
   DCPS entities (DomainParticipant, Publisher/Subscriber, Topic, DataWriter/DataReader).
   TYPE-COMPAT holds the ADVISORY type-object fingerprint verdict for the most recently
   matched remote endpoint (ADR 0009; DataReader/DataWriter only, NIL on other entities and
   until a first match) — a heuristic signal, never a match gate; see ENTITY-TYPE-COMPAT."))

(defclass domain-participant (entity)
  ((domain :initarg :domain :reader dp-domain)
   (node :initarg :node :accessor dp-node)
   (children :initform '() :accessor dp-children)
   (user-reader :initform nil :accessor dp-user-reader)   ; v1: one DataReader per participant
   (user-writer :initform nil :accessor dp-user-writer)   ; v1: one DataWriter per participant
   (type-gate-state :initform nil :accessor dp-type-gate-state)   ; FR-TYPE-4 gate (type-gate.lisp)
   (auth-state :initform nil :accessor dp-auth-state)   ; DDS-Security 1.1 §8.7 auth manager (auth-manager.lisp)
   (access-state :initform nil :accessor dp-access-state))   ; DDS-Security 1.1 §8.4 AccessControl manager (access-control.lisp)
  (:documentation "DDS DomainParticipant: owns a multicast disc-node for its domain and
   its contained entities. v1 holds one DataReader + one DataWriter per participant.
   TYPE-GATE-STATE carries the FR-TYPE-4 assignability gate's TypeObject/verdict caches.
   AUTH-STATE carries the DDS-Security §8.7 authentication manager's local identity +
   per-remote handshake/key state (NIL = security OFF; see auth-manager.lisp).
   ACCESS-STATE holds the DDS-Security §8.4 AccessControl access-handle (validated Governance +
   shared Permissions) driving the permissions-gate (NIL = access-control OFF; see access-control.lisp)."))

(defclass publisher (entity)
  ((participant :initarg :participant :reader pub-participant)
   (writers :initform '() :accessor pub-writers))
  (:documentation "DDS Publisher: a factory/container for DataWriters in its participant."))

(defclass subscriber (entity)
  ((participant :initarg :participant :reader sub-participant)
   (readers :initform '() :accessor sub-readers))
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
   (pub-matched :initform (make-publication-matched-status) :accessor dw-pub-matched)
   (off-incompat :initform (make-offered-incompatible-qos-status) :accessor dw-off-incompat)
   (liv-lost :initform (make-liveliness-lost-status) :accessor dw-liv-lost)
   (last-assertion :initform (%lease-now) :accessor dw-last-assertion) ; last self-assertion stamp (DDS 1.4 §2.2.3.11)
   (alive :initform t :accessor dw-alive-p)                            ; LIVELINESS_LOST loss-transition flag
   (listener :initform nil :accessor dw-listener)
   (listener-mask :initform '() :accessor dw-listener-mask)
   (instances :initform (make-hash-table :test 'equalp) :accessor dw-instances) ; 16-octet handle -> :alive (DDS 1.4 §2.2.2.4.2)
   (status-lock :initform (dds.pal:make-lock "dw-status") :accessor dw-status-lock))
  (:documentation "DDS DataWriter: publishes typed samples on a Topic, carrying its
   PUBLICATION_MATCHED, OFFERED_INCOMPATIBLE_QOS and LIVELINESS_LOST statuses and optional
   listener. LAST-ASSERTION is the internal-real-time stamp of the most recent self-
   assertion (a write or assert_liveliness, or the announce cadence for an AUTOMATIC
   writer); ALIVE is the loss-transition flag so LIVELINESS_LOST fires once per going-lost."))

(defclass data-reader (entity)
  ((topic :initarg :topic :reader dr-topic)
   (subscriber :initarg :subscriber :reader dr-subscriber)
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
(declaim (ftype (function (domain-participant dds.security:identity-handle) domain-participant)
                %install-auth-manager))

;; Defined in access-control.lisp (loaded after this file); forward-declared so create-participant
;; can install the DDS-Security §8.4 AccessControl manager when governance + permissions are configured.
(declaim (ftype (function (domain-participant dds.security:access-handle) domain-participant)
                %install-access-control))

;; WP-FLATDATA-ZC-LOAN (R6, ADR 0017): forward-declared so create-datareader / delete-participant (defined
;; above their bodies in this file) reach the loan helpers without a compile-time undefined-function warning.
(declaim (ftype (function (t) (or null (integer 0))) %flatdata-size))
(declaim (ftype (function (domain-participant) list) %participant-readers))
(declaim (ftype (function (data-reader) t) return-all-loans))

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
  "A read/take result element: the deserialized DATA + its SAMPLE-INFO."
  (data nil :type t)
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

(defun* %deserialize-sample (ts bytes)
    (function (t (simple-array (unsigned-byte 8) (*))) t)
  "Deserialize a SerializedPayload (encap header + body) into a sample via TS, decoding the body in the
   representation the encapsulation header declares (DDS-XTypes 1.3 §7.6.3.1.2; WP-DATA-REPRESENTATION):
   the parsed encap keyword/name selects the codec mode (XCDR1/XCDR2, the 8-vs-4 alignment) AND the cursor endianness
   (LE/BE) via %encap->codec, so a reader accepting (:xcdr2 :xcdr1) reads either rep a peer sent. A FlatData
   type's :deserialize self-dispatches on the rep id and ignores the passed mode (its own RX-transcode)."
  (let* ((ob (dds.core.buffer:make-octet-buffer (length bytes)))
         (rc (dds.core.buffer:cursor ob :endianness :little)))
    (replace (dds.core.buffer:octet-buffer-vec ob) bytes)
    (let ((encap (dds.cdr:parse-encapsulation-header rc)))
      (multiple-value-bind (mode endian) (%encap->codec encap)
        (dds.core.buffer:cursor-set-endianness rc endian)
        (prog1 (funcall (dds.types:type-support-deserialize ts) rc mode)
          (dds.pal:free-static (dds.core.buffer:octet-buffer-vec ob)))))))

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
   advertises its IdentityToken + PSM bits in SPDP and the auth manager is installed, so the
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
                                              :guid-prefix (%make-guid-prefix)
                                              :identity-token-octets
                                              (when identity (dds.security:identity-token identity))))
               (p (make-instance 'domain-participant :domain domain :node node :qos qos :enabled t)))
          ;; Install hooks BEFORE the receiver thread starts so no early SEDP match is lost.
          (setf (dds.disc:disc-node-on-match node)
                (lambda (kind remote) (%on-disc-match p kind remote)))
          (setf (dds.disc:disc-node-on-unmatch node)
                (lambda (direction remote) (%on-disc-unmatch p direction remote)))
          (setf (dds.disc:disc-node-on-liveliness-changed node)
                (lambda (guid alive-p) (%on-disc-liveliness-changed p guid alive-p)))
          (setf (dds.disc:disc-node-on-lifecycle-event node)
                (lambda (wid sn kind kh sf) (%on-disc-lifecycle p wid sn kind kh sf)))
          (setf (dds.disc:disc-node-on-incompatible-qos node)
                (lambda (kind remote bad) (%on-disc-incompatible p kind remote bad)))
          (setf (dds.disc:disc-node-on-sample node)
                (lambda () (%on-participant-sample p)))
          (setf (dds.disc:disc-node-on-inconsistent-topic node)
                (lambda (topic-name) (%on-disc-inconsistent-topic p topic-name)))
          (%install-type-gate p)   ; FR-TYPE-4 assignability gate (type-gate.lisp)
          (when identity           ; DDS-Security §8.7 auth manager — only for a security-enabled participant
            (%install-auth-manager p identity))
          (when access-handle      ; DDS-Security §8.4 AccessControl manager — validated above, install the gate
            (%install-access-control p access-handle))
          (dds.disc:start-node node)
          (setf installed t)   ; construction complete; p owns the access-handle via dp-access-state
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
  (dds.disc:stop-node (dp-node p))
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

(defun* create-publisher (p)
    (function (domain-participant) publisher)
  "DomainParticipant::create_publisher — create an enabled Publisher in P."
  (let ((pub (make-instance 'publisher :participant p :enabled t)))
    (push pub (dp-children p))
    pub))

(defun* create-subscriber (p)
    (function (domain-participant) subscriber)
  "DomainParticipant::create_subscriber — create an enabled Subscriber in P."
  (let ((sub (make-instance 'subscriber :participant p :enabled t)))
    (push sub (dp-children p))
    sub))

(defun* create-topic (p name type-name type-support)
    (function (domain-participant string string t) topic)
  "DomainParticipant::create_topic. TYPE-SUPPORT is a registered dds.types
   type-support (the generated codec bundle) used by write/take."
  (let ((tp (make-instance 'topic :name name :type-name type-name
                                  :type-support type-support :participant p :enabled t)))
    (push tp (dp-children p))
    tp))

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

(defun* create-datawriter (pub topic &key (qos (dds.qos:make-writer-qos)))
    (function (publisher topic &key (:qos t)) data-writer)
  "Publisher::create_datawriter — register a local writer in the engine on the
   topic's name/type with the QoS reliability (v1: the single user writer); the
   endpoint kind (WITH_KEY/NO_KEY) is selected from the topic type's keyed-ness.
   DDS-Security §8.4.2.4: when the participant is access-controlled, check_create_datawriter must
   grant publish on the topic (local Permissions + Governance write-AC toggle) or the writer is
   refused (fail-closed SIGNAL). No access-state (default) = unchecked, byte-identical."
  (let ((node (dp-node (pub-participant pub)))
        (ah (dp-access-state (pub-participant pub))))
    (when (and ah (not (dds.security:check-create-datawriter ah (topic-name topic))))
      (error "create-datawriter: AccessControl check_create_datawriter denied publish on topic ~s"
             (topic-name topic)))
    (dds.disc:add-local-writer node :topic (topic-name topic) :type (topic-type-name topic)
                               :keyed (%topic-keyed-p topic)
                               :qos qos :type-information (%topic-type-information topic))
    (dds.disc:enable-publisher node :history-kind (dds.qos:qos-history-kind qos)
                                    :history-depth (dds.qos:qos-history-depth qos))
    (let ((dw (make-instance 'data-writer :topic topic :publisher pub :qos qos :enabled t)))
      (push dw (pub-writers pub))
      (setf (dp-user-writer (pub-participant pub)) dw)   ; v1 back-ref for status hooks
      dw)))

(defun* create-datareader (sub topic &key (qos (dds.qos:make-reader-qos)))
    (function (subscriber t &key (:qos t)) data-reader)
  "Subscriber::create_datareader — register a local reader in the engine on the
   topic's name/type with the QoS reliability (v1: the single user reader). TOPIC may
   be a Topic or a ContentFilteredTopic; in the latter case the reader applies the
   filter predicate reader-side (only matching samples reach read/take). The
   endpoint kind (WITH_KEY/NO_KEY) is selected from the topic type's keyed-ness.
   DDS-Security §8.4.2.5: when the participant is access-controlled, check_create_datareader must
   grant subscribe on the topic (local Permissions + Governance read-AC toggle) or the reader is
   refused (fail-closed SIGNAL). No access-state (default) = unchecked, byte-identical."
  (let ((node (dp-node (sub-participant sub)))
        (ah (dp-access-state (sub-participant sub))))
    (when (and ah (not (dds.security:check-create-datareader ah (topic-name topic))))
      (error "create-datareader: AccessControl check_create_datareader denied subscribe on topic ~s"
             (topic-name topic)))
    (dds.disc:add-local-reader node :topic (topic-name topic) :type (topic-type-name topic)
                               :keyed (%topic-keyed-p topic)
                               :qos qos :type-information (%topic-type-information topic))
    (dds.disc:enable-subscriber node)
    ;; WP-FLATDATA-ZC-LOAN wiring (FR-PF-3/4, R6, ADR 0017): a :flatdata-topic reader, with ZC armed, is
    ;; loan-capable — the receiver thread defers ZC resolution (holds the slot) and the loan API owns the slot
    ;; lifetime. Gated on the TYPE being FlatData AND *zerocopy-enabled*; off either way -> NIL -> byte-unchanged.
    (when (and dds.disc:*zerocopy-enabled* (%flatdata-size (topic-type-support topic)))
      (dds.disc:set-zc-loan-capable node t))
    (let ((dr (make-instance 'data-reader :topic topic :subscriber sub :qos qos :enabled t)))
      (setf (dr-filter dr) (td-filter-predicate topic))   ; nil for a plain Topic
      (push dr (sub-readers sub))
      (setf (dp-user-reader (sub-participant sub)) dr)   ; v1 back-ref for status hooks
      dr)))

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
  (dds.disc:finalize-writer-durability (dp-node (pub-participant (dw-publisher dw)))))

(defparameter +retcode-ok+ :ok
  "DDS 1.4 ReturnCode_t RETCODE_OK (§2.2.4.4): the operation succeeded. Represented as the keyword :ok.")

(defparameter +retcode-timeout+ :timeout
  "DDS 1.4 ReturnCode_t RETCODE_TIMEOUT (§2.2.4.4): the operation did not complete within the configured
   time. Returned by write/dispose/unregister when RELIABILITY.max_blocking_time elapsed on a full bounded
   (KEEP_ALL + RESOURCE_LIMITS max_samples) HistoryCache — DDS-standard block-up-to-max_blocking_time
   backpressure (WP-ASYNC-FLOW, FR-PF-2/FR-QOS, ADR 0016 §Backpressure). Represented as the keyword
   :timeout, the same sentinel the engine (dds.disc:publish-sample) surfaces.")

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
    (function (data-writer t) (member :ok :timeout))
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
   reader; the rep applies to the payload only, never to the keyhash (always XCDR2-BE, RTPS 2.5 §9.6.4.8)."
  (let ((node (dp-node (pub-participant (dw-publisher dw)))))
    (when (eq :timeout (dds.disc:publish-sample
                        node (%serialize-sample (topic-type-support (dw-topic dw)) sample
                                                (%writer-tx-rep dw))
                        (%write-key-hash dw sample)))
      (return-from write-sample +retcode-timeout+))   ; full bounded cache, max_blocking_time elapsed
    (assert-liveliness dw)
    +retcode-ok+))

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
    (function (data-writer t) (simple-array (unsigned-byte 8) (16)))
  "DataWriter::register_instance (DDS 1.4 §2.2.2.4.2.5) — register the instance of SAMPLE and
   return its 16-octet handle (the type-support key-hash). Records the handle as :alive in the
   writer's instance table; HANDLE_NIL for an unkeyed type. No wire message is emitted (registration
   is a writer-local act; the instance becomes visible to readers on the first write/dispose)."
  (let ((handle (%instance-handle (topic-type-support (dw-topic dw)) sample)))
    (dds.pal:with-lock ((dw-status-lock dw))
      (setf (gethash handle (dw-instances dw)) :alive))
    handle))

(defun* dispose-instance (dw sample-or-handle)
    (function (data-writer t) (or (simple-array (unsigned-byte 8) (16)) (eql :timeout)))
  "DataWriter::dispose (DDS 1.4 §2.2.2.4.2.10) — dispose the instance named by SAMPLE-OR-HANDLE
   (a sample or a registered handle): emit a no-payload dispose DATA (StatusInfo Disposed, RTPS 2.5
   §9.6.4.9) over the reliable engine so matched readers see NOT_ALIVE_DISPOSED. Returns the handle, or
   +RETCODE-TIMEOUT+ (:timeout) if the bounded cache was full and max_blocking_time elapsed (WP-ASYNC-FLOW
   backpressure, ADR 0016 §Backpressure; on :timeout nothing was emitted and liveliness is not asserted)."
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
    (function (data-writer t) (or (simple-array (unsigned-byte 8) (16)) (eql :timeout)))
  "DataWriter::unregister_instance (DDS 1.4 §2.2.2.4.2.7) — unregister the instance named by
   SAMPLE-OR-HANDLE: emit a no-payload unregister DATA over the reliable engine, relinquishing this
   writer's ownership of the instance. Per WRITER_DATA_LIFECYCLE (DDS 1.4 §2.2.3.21,
   autodispose_unregistered_instances, default TRUE) the unregister also DISPOSES the instance — the
   DATA carries StatusInfo Disposed|Unregistered (0x03) so readers report NOT_ALIVE_DISPOSED — unless
   the writer's QoS sets autodispose FALSE, in which case it carries only Unregistered (0x02, RTPS 2.5
   §9.6.4.9). Drops the handle from the writer's instance table. Returns the handle, or +RETCODE-TIMEOUT+
   (:timeout) if the bounded cache was full and max_blocking_time elapsed (WP-ASYNC-FLOW backpressure, ADR
   0016 §Backpressure; on :timeout nothing was emitted, the handle is NOT dropped, liveliness not asserted)."
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
  "Bump DR's SAMPLE_REJECTED status (reason + instance handle) and fire on_sample_rejected
   if a listener is masked for it."
  (let ((snapshot nil))
    (dds.pal:with-lock ((dr-status-lock dr))
      (let ((s (dr-sample-rejected dr)))
        (incf (sample-rejected-status-total-count s))
        (incf (sample-rejected-status-total-count-change s))
        (setf (sample-rejected-status-last-reason s) reason
              (sample-rejected-status-last-instance-handle s) handle)
        (when (and (dr-listener dr) (member :sample-rejected (dr-listener-mask dr)))
          (setf snapshot (copy-sample-rejected-status s))
          (setf (sample-rejected-status-total-count-change s) 0))))
    (when snapshot (on-sample-rejected (dr-listener dr) dr snapshot)))
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
   The instance-state transition itself is applied on the user thread by %drain (S2)."
  (declare (ignore wid sn kind key-hash status-flags))
  (let ((dr (dp-user-reader p)))
    (when dr (%wake-reader-data dr)))
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
        (when (dds.types:flatdata-view-p d) (push d loans))))   ; a loaned view (registry slot); NIL otherwise
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
        (when (dds.types:flatdata-view-p d) (push d loans))))
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
   a view after a read-then-take, is safe. NOT cleared for ship — pending counsel (R6)."
  (dolist (v loans)
    (when (and (dds.types:flatdata-view-p v) (member v (dr-loans dr)))   ; in the registry -> release exactly once
      (setf (dr-cache dr) (delete v (dr-cache dr) :key #'cached-sample-data)) ; invalidate the cache entry BEFORE recycle (no stale read)
      (dds.xport.zerocopy::%zc-release (dds.types:flatdata-view-pool-sap v)
                                       (dds.types:flatdata-view-slot-index v)
                                       (dds.types:flatdata-view-generation v))
      (setf (dr-loans dr) (delete v (dr-loans dr)))
      (push v (dr-view-freelist dr))))                                   ; recycle (NFR-MEM)
  t)

(defun* return-all-loans (dr)
    (function (data-reader) t)
  "WP-FLATDATA-ZC-LOAN reader-close safety (FR-PF-3/4, R6, ADR 0017): return EVERY outstanding loan in DR's
   registry (return-loan over a snapshot of dr-loans) so reader-close / delete-participant leaves NO held
   refcount that would pin the writer's pool. Called BEFORE the engine stop-node detaches the reader-side pool
   mapping (the views' SAP must still be valid for the final %zc-release). NOT cleared for ship — pending counsel
   (R6)."
  (return-loan dr (copy-list (dr-loans dr)))
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
   drain re-evaluates it once the match completes and the strength is known."
  (let ((sguid (dds.disc:node-sample-writer-guid node key))
        (sn (dds.disc:node-sample-key-sn key))
        (advance t))                       ; advance the per-writer watermark unless arbitration keeps it pending
  (let ((bytes (dds.disc:node-sample node key)))
    (when (dds.disc:zc-loan-marker-p bytes)            ; WP-FLATDATA-ZC-LOAN (R6, ADR 0017): an UNRESOLVED ZC ref -> acquire a literal-0-copy view, never deserialize
      (%drain-one-loan dr ts key bytes sn sguid)
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
         (data-keys (remove-if-not
                     (lambda (key)
                       (let ((g (dds.disc:node-sample-writer-guid node key)))
                         (or (null g)
                             (> (dds.disc:node-sample-key-sn key) (gethash g (dr-drained dr) 0)))))
                     (dds.disc:node-sample-sns node)))
         (life-keys (set-difference (dds.disc:node-lifecycle-sns node) (dr-lifecycle-drained dr)
                                    :test #'equalp))
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

(defun* read-samples (dr &key (states '(:read :not-read)) (where #'%where-any))
    (function (data-reader &key (:states list) (:where function)) list)
  "DataReader::read — return the cached samples whose sample-state is in STATES
   (default ANY_SAMPLE_STATE, both read + not-read, per DDS 1.4) and whose data
   satisfies WHERE (a predicate over the deserialized sample; %where-any by default —
   the query-condition filter for read_w_condition) WITHOUT removing them; mark each
   READ and set its SampleInfo view-state (NEW the first time the instance is accessed,
   else NOT_NEW). Returns a list of cached-sample (data + info)."
  (%drain dr)
  (let ((out '()) (touched '()))
    (dolist (cs (dr-cache dr))
      (let ((info (cached-sample-info cs)))
        (when (and (member (sample-info-sample-state info) states)
                   (funcall where (cached-sample-data cs)))
          (let ((handle (sample-info-instance-handle info)))
            (setf (sample-info-view-state info)
                  (if (gethash handle (dr-instances dr)) :not-new :new))
            (pushnew handle touched :test #'equalp))
          (setf (sample-info-sample-state info) :read)
          (push cs out))))
    (dolist (h touched) (setf (gethash h (dr-instances dr)) t))   ; mark accessed after snapshot
    (nreverse out)))

(defun* take-samples (dr &key (states '(:read :not-read)) (where #'%where-any))
    (function (data-reader &key (:states list) (:where function)) list)
  "DataReader::take — like read-samples but REMOVE the returned samples from the
   cache (default takes both read and unread). WHERE is the same optional query
   predicate (take_w_condition filter). Returns a list of cached-sample."
  (%drain dr)
  (let ((keep '()) (out '()) (touched '()))
    (dolist (cs (dr-cache dr))
      (let ((info (cached-sample-info cs)))
        (if (and (member (sample-info-sample-state info) states)
                 (funcall where (cached-sample-data cs)))
            (progn
              (let ((handle (sample-info-instance-handle info)))
                (setf (sample-info-view-state info)
                      (if (gethash handle (dr-instances dr)) :not-new :new))
                (pushnew handle touched :test #'equalp))
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

(defun* %on-disc-match (p kind remote)
    (function (domain-participant keyword dds.rtps.discovery:endpoint-data) t)
  "ON-MATCH hook: a remote endpoint matched a local one. :remote-writer -> our reader
   gained a publication (SUBSCRIPTION_MATCHED); :remote-reader -> our writer gained a
   subscription (PUBLICATION_MATCHED). The 16-octet remote GUID is the matched handle.
   Also records an ADVISORY type-object fingerprint verdict on the local entity (ADR 0009)."
  (let ((handle (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))))
    (ecase kind
      (:remote-writer (let ((dr (dp-user-reader p)))
                        (when dr (%reader-matched dr handle)
                              ;; durability-aware late-joiner gate (DDS 1.4 §2.2.3.4): a TL reader matched
                              ;; a retaining writer REQUESTS its history; a VOLATILE reader matched a
                              ;; RETAINING writer SKIPS it; a VOLATILE writer retains nothing so its match
                              ;; never skips. Writer durability is its advertised QoS.
                              (dds.disc:%reader-durability-init
                               (dp-node p) handle
                               (dds.qos:qos-durability (dds.rtps.discovery:endpoint-data-qos remote)))
                              (%assess-and-record-type-compat dr remote))))
      (:remote-reader (let ((dw (dp-user-writer p)))
                        (when dw (%writer-matched dw handle)
                              ;; durability-aware late-joiner proxy init (DDS 1.4 §2.2.3.4): a TL writer
                              ;; matched by a TL reader replays its retained history (firstSN + a prompt
                              ;; HEARTBEAT); else future-only. Reader durability is its advertised QoS.
                              (dds.disc:%writer-durability-init
                               (dp-node p) handle
                               (dds.qos:qos-durability (dds.rtps.discovery:endpoint-data-qos remote)))
                              (%assess-and-record-type-compat dw remote))))))
  t)

(defun* %on-disc-unmatch (p direction remote)
    (function (domain-participant keyword dds.rtps.discovery:endpoint-data) t)
  "ON-UNMATCH hook: a previously matched remote endpoint vanished (participant-lease
   expiry, disc.lisp %lease-sweep). :remote-writer -> our reader lost a publication
   (SUBSCRIPTION_MATCHED current_count--); :remote-reader -> our writer lost a
   subscription (PUBLICATION_MATCHED current_count--). The local entity is located the
   same way as %on-disc-match (the v1 single user reader/writer back-ref). The remote's
   16-octet GUID is the unmatched handle (DDS 1.4 §2.2.4.1, dds_rtf2_dcps.idl §165/§174)."
  (let ((handle (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))))
    (ecase direction
      (:remote-writer (let ((dr (dp-user-reader p)))
                        (when dr (%reader-unmatched dr handle)
                              (%clear-owner-on-vanish dr handle)   ; EXCLUSIVE owner loss -> takeover (S1)
                              (%on-writer-vanished dr (%guid-entityid handle)))))
      (:remote-reader (let ((dw (dp-user-writer p))) (when dw (%writer-unmatched dw handle))))))
  t)

(defun* %on-disc-liveliness-changed (p remote-writer-guid alive-p)
    (function (domain-participant (simple-array (unsigned-byte 8) (16)) t) t)
  "ON-LIVELINESS-CHANGED hook (disc announce thread, %liveliness-sweep): matched remote
   writer REMOTE-WRITER-GUID crossed alive<->not-alive (ALIVE-P is the NEW state; RTPS 2.5
   §8.4.13). Bump the local DataReader's LIVELINESS_CHANGED status (DDS 1.4 §2.2.4.1) and
   fire on_liveliness_changed. The reader is the v1 single user-reader back-ref."
  (let ((dr (dp-user-reader p)))
    (when dr
      (%reader-liveliness-changed dr (copy-seq remote-writer-guid) alive-p)
      ;; A not-alive writer loses ownership (DDS 1.4 §2.2.3.9.2 cause (c)) -> remaining writer takes over.
      (unless alive-p (%clear-owner-on-vanish dr remote-writer-guid))))
  t)

(defun* %on-disc-incompatible (p kind remote bad)
    (function (domain-participant keyword dds.rtps.discovery:endpoint-data list) t)
  "ON-INCOMPATIBLE-QOS hook: topic+type agreed but RxO failed. :remote-writer -> our
   reader's REQUESTED_INCOMPATIBLE_QOS; :remote-reader -> our writer's OFFERED_
   INCOMPATIBLE_QOS. BAD is the failing-policy keyword list (dds.qos:qos-rxo-compatible)."
  (declare (ignore remote))
  (ecase kind
    (:remote-writer (let ((dr (dp-user-reader p))) (when dr (%reader-incompatible dr bad))))
    (:remote-reader (let ((dw (dp-user-writer p))) (when dw (%writer-incompatible dw bad)))))
  t)

(defun* %on-participant-sample (p)
    (function (domain-participant) t)
  "ON-SAMPLE hook (disc receiver thread): new user data arrived for P's reader. Fire
   on_data_available if a listener is masked for it (snapshot under the status lock,
   call OUTSIDE it), then wake the reader's WaitSets (DATA_AVAILABLE / ReadCondition /
   QueryCondition). Holds no node lock here (the disc layer released it before calling)."
  (let ((dr (dp-user-reader p)))
    (when dr
      (let ((fire nil))
        (dds.pal:with-lock ((dr-status-lock dr))
          (when (and (dr-listener dr) (member :data-available (dr-listener-mask dr)))
            (setf fire t)))
        (when fire (on-data-available (dr-listener dr) dr))
        (%notify-reader-conditions dr))))
  t)

(defun* %reader-matched (dr handle)
    (function (data-reader t) t)
  "Bump DR's SUBSCRIPTION_MATCHED status; if a listener is installed for it, fire
   on-subscription-matched with a snapshot (resetting the *_change counters per DDS)."
  (let ((snapshot nil))
    (dds.pal:with-lock ((dr-status-lock dr))
      (let ((s (dr-sub-matched dr)))
        (incf (subscription-matched-status-total-count s))
        (incf (subscription-matched-status-total-count-change s))
        (incf (subscription-matched-status-current-count s))
        (incf (subscription-matched-status-current-count-change s))
        (setf (subscription-matched-status-last-publication-handle s) handle)
        (when (and (dr-listener dr) (member :subscription-matched (dr-listener-mask dr)))
          (setf snapshot (copy-subscription-matched-status s))
          (setf (subscription-matched-status-total-count-change s) 0
                (subscription-matched-status-current-count-change s) 0))))
    (when snapshot (on-subscription-matched (dr-listener dr) dr snapshot))
    (%notify-reader-conditions dr))   ; wake a StatusCondition(:subscription-matched) waiter
  t)

(defun* %writer-matched (dw handle)
    (function (data-writer t) t)
  "Bump DW's PUBLICATION_MATCHED status; if a listener is installed for it, fire
   on-publication-matched with a snapshot (resetting the *_change counters per DDS)."
  (let ((snapshot nil))
    (dds.pal:with-lock ((dw-status-lock dw))
      (let ((s (dw-pub-matched dw)))
        (incf (publication-matched-status-total-count s))
        (incf (publication-matched-status-total-count-change s))
        (incf (publication-matched-status-current-count s))
        (incf (publication-matched-status-current-count-change s))
        (setf (publication-matched-status-last-subscription-handle s) handle)
        (when (and (dw-listener dw) (member :publication-matched (dw-listener-mask dw)))
          (setf snapshot (copy-publication-matched-status s))
          (setf (publication-matched-status-total-count-change s) 0
                (publication-matched-status-current-count-change s) 0))))
    (when snapshot (on-publication-matched (dw-listener dw) dw snapshot)))
  t)

(defun* %reader-unmatched (dr handle)
    (function (data-reader t) t)
  "Decrement DR's SUBSCRIPTION_MATCHED on a lost match (DDS 1.4 §2.2.4.1): current_count--
   (floored at 0), current_count_change accumulates -1 (mirroring how %reader-matched
   accumulates +1), last_publication_handle := the unmatched remote's GUID, total_count
   UNCHANGED (monotonic, dds_rtf2_dcps.idl §174). Fires on-subscription-matched if masked
   (snapshot + reset the *_change counters per DDS), then wakes the reader's WaitSets."
  (let ((snapshot nil))
    (dds.pal:with-lock ((dr-status-lock dr))
      (let ((s (dr-sub-matched dr)))
        (when (plusp (subscription-matched-status-current-count s))
          (decf (subscription-matched-status-current-count s)))
        (decf (subscription-matched-status-current-count-change s))
        (setf (subscription-matched-status-last-publication-handle s) handle)
        (when (and (dr-listener dr) (member :subscription-matched (dr-listener-mask dr)))
          (setf snapshot (copy-subscription-matched-status s))
          (setf (subscription-matched-status-total-count-change s) 0
                (subscription-matched-status-current-count-change s) 0))))
    (when snapshot (on-subscription-matched (dr-listener dr) dr snapshot))
    (%notify-reader-conditions dr))   ; wake a StatusCondition(:subscription-matched) waiter
  t)

(defun* %reader-liveliness-changed (dr handle alive-p)
    (function (data-reader t t) t)
  "Apply a matched-writer liveliness transition to DR's LIVELINESS_CHANGED status
   (DDS 1.4 §2.2.4.1, dds_rtf2_dcps.idl §123-129). ALIVE-P T (not-alive -> alive):
   alive_count++, not_alive_count-- (floored at 0), alive_count_change +1,
   not_alive_count_change -1. ALIVE-P NIL (alive -> not-alive): the reverse.
   last_publication_handle := the transitioned writer's GUID (HANDLE). Fires
   on-liveliness-changed if masked (snapshot + reset the *_change counters per DDS),
   then wakes the reader's WaitSets."
  (let ((snapshot nil))
    (dds.pal:with-lock ((dr-status-lock dr))
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
        (when (and (dr-listener dr) (member :liveliness-changed (dr-listener-mask dr)))
          (setf snapshot (copy-liveliness-changed-status s))
          (setf (liveliness-changed-status-alive-count-change s) 0
                (liveliness-changed-status-not-alive-count-change s) 0))))
    (when snapshot (on-liveliness-changed (dr-listener dr) dr snapshot))
    (%notify-reader-conditions dr))   ; wake a StatusCondition(:liveliness-changed) waiter
  t)

(defun* %lease-internal-units (duration)
    (function (dds.qos:qos-duration) (integer 0))
  "A LIVELINESS lease_duration as internal-time-units (the granularity dw-last-assertion
   is stamped in), rounding the sub-second nanosec part up so a fresh assertion inside the
   lease is never prematurely judged stale (DDS 1.4 §2.2.3.11). DURATION_INFINITE
   (sec 0x7fffffff) is returned as effectively unbounded. The round-up to whole seconds is
   delegated to dds.disc::%lease-seconds (single source of that arithmetic, DRY)."
  (* (dds.disc::%lease-seconds duration) internal-time-units-per-second))

(defun* %writer-liveliness-lost (dw)
    (function (data-writer) t)
  "Mark DW LIVELINESS_LOST (DDS 1.4 §2.2.4.1, dds_rtf2_dcps.idl §118-121): total_count++
   (monotonic), total_count_change accumulates +1; clear the alive flag so it fires once
   per going-lost transition. Fires on_liveliness_lost if masked (snapshot + reset the
   total_count_change per DDS read-resets-change). CALLER HOLDS the status lock; the
   listener is fired OUTSIDE it via the returned snapshot."
  (let ((s (dw-liv-lost dw)) (snapshot nil))
    (incf (liveliness-lost-status-total-count s))
    (incf (liveliness-lost-status-total-count-change s))
    (setf (dw-alive-p dw) nil)
    (when (and (dw-listener dw) (member :liveliness-lost (dw-listener-mask dw)))
      (setf snapshot (copy-liveliness-lost-status s))
      (setf (liveliness-lost-status-total-count-change s) 0))
    snapshot))

(defun* %writer-liveliness-lost-check (dw now)
    (function (data-writer (integer 0)) t)
  "Sweep one DataWriter DW for LIVELINESS_LOST at time NOW (DDS 1.4 §2.2.3.11): if DW is
   still considered alive but has not asserted its own liveliness within its offered
   LIVELINESS lease_duration, fire LIVELINESS_LOST. AUTOMATIC writers are kept asserted by
   the announce cadence (see %writer-liveliness-sweep), so they only go lost if the
   participant stops announcing. An infinite lease never goes lost. Returns the snapshot to
   fire the listener with, or NIL. Snapshots under the status lock; the caller fires
   on_liveliness_lost OUTSIDE the lock."
  (let ((qos (entity-qos dw)))
    (when (typep qos 'dds.qos:qos)
      (let* ((dur (dds.qos:qos-liveliness-lease qos))
             (lease (%lease-internal-units dur)))
        (when (and (< (dds.qos:qos-duration-sec dur) #x7fffffff)
                   (plusp lease))
          (dds.pal:with-lock ((dw-status-lock dw))
            (when (and (dw-alive-p dw) (> (- now (dw-last-assertion dw)) lease))
              (%writer-liveliness-lost dw))))))))

(defun* %writer-liveliness-sweep (p)
    (function (domain-participant) (eql t))
  "Writer-side Writer Liveliness timing (DDS 1.4 §2.2.3.11 / §2.2.4.1): on the DCPS
   announce cadence (SPIN), refresh every AUTOMATIC local writer's self-assertion (the
   infrastructure asserts AUTOMATIC writers while the participant announces) and then sweep
   every local writer for LIVELINESS_LOST — a writer that has not asserted within its
   offered lease_duration fires on_liveliness_lost once per going-lost transition. MANUAL
   writers (BY_PARTICIPANT / BY_TOPIC) are NOT auto-refreshed here: the application keeps
   them alive via write / assert_liveliness. Snapshots are collected under each writer's
   status lock and the listeners fired OUTSIDE the locks."
  (let ((now (%lease-now)) (fires '()))
    (dolist (dw (%participant-writers p))
      (when (eq (%writer-liveliness-kind dw) :automatic)
        (dds.pal:with-lock ((dw-status-lock dw))
          (setf (dw-last-assertion dw) now (dw-alive-p dw) t))))
    (dolist (dw (%participant-writers p))
      (let ((snap (%writer-liveliness-lost-check dw now)))
        (when snap (push (cons dw snap) fires))))
    (dolist (f fires) (on-liveliness-lost (dw-listener (car f)) (car f) (cdr f))))
  t)

(defun* %writer-unmatched (dw handle)
    (function (data-writer t) t)
  "Decrement DW's PUBLICATION_MATCHED on a lost match (DDS 1.4 §2.2.4.1): current_count--
   (floored at 0), current_count_change accumulates -1, last_subscription_handle := the
   unmatched remote's GUID, total_count UNCHANGED (monotonic, dds_rtf2_dcps.idl §165).
   Fires on-publication-matched if masked (snapshot + reset the *_change counters)."
  (let ((snapshot nil))
    (dds.pal:with-lock ((dw-status-lock dw))
      (let ((s (dw-pub-matched dw)))
        (when (plusp (publication-matched-status-current-count s))
          (decf (publication-matched-status-current-count s)))
        (decf (publication-matched-status-current-count-change s))
        (setf (publication-matched-status-last-subscription-handle s) handle)
        (when (and (dw-listener dw) (member :publication-matched (dw-listener-mask dw)))
          (setf snapshot (copy-publication-matched-status s))
          (setf (publication-matched-status-total-count-change s) 0
                (publication-matched-status-current-count-change s) 0))))
    (when snapshot (on-publication-matched (dw-listener dw) dw snapshot)))
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
  "Bump DR's REQUESTED_INCOMPATIBLE_QOS status; fire on-requested-incompatible-qos if a
   listener is installed for it (snapshot OUTSIDE the lock, deep-copying the policies)."
  (let ((snapshot nil))
    (dds.pal:with-lock ((dr-status-lock dr))
      (let ((s (dr-req-incompat dr)))
        (%apply-requested-incompatible s bad)
        (when (and (dr-listener dr) (member :requested-incompatible-qos (dr-listener-mask dr)))
          (setf snapshot (copy-requested-incompatible-qos-status s))
          (setf (requested-incompatible-qos-status-policies snapshot)
                (mapcar #'copy-qos-policy-count (requested-incompatible-qos-status-policies s)))
          (setf (requested-incompatible-qos-status-total-count-change s) 0))))
    (when snapshot (on-requested-incompatible-qos (dr-listener dr) dr snapshot))
    (%notify-reader-conditions dr))   ; wake a StatusCondition(:requested-incompatible-qos) waiter
  t)

(defun* %writer-incompatible (dw bad)
    (function (data-writer list) t)
  "Bump DW's OFFERED_INCOMPATIBLE_QOS status; fire on-offered-incompatible-qos if a
   listener is installed for it (snapshot OUTSIDE the lock, deep-copying the policies)."
  (let ((snapshot nil))
    (dds.pal:with-lock ((dw-status-lock dw))
      (let ((s (dw-off-incompat dw)))
        (%apply-offered-incompatible s bad)
        (when (and (dw-listener dw) (member :offered-incompatible-qos (dw-listener-mask dw)))
          (setf snapshot (copy-offered-incompatible-qos-status s))
          (setf (offered-incompatible-qos-status-policies snapshot)
                (mapcar #'copy-qos-policy-count (offered-incompatible-qos-status-policies s)))
          (setf (offered-incompatible-qos-status-total-count-change s) 0))))
    (when snapshot (on-offered-incompatible-qos (dw-listener dw) dw snapshot)))
  t)

;;; ---- get_*_status (app thread): snapshot + reset the *_change counters (DDS 1.4) ----

(defun* get-subscription-matched-status (dr)
    (function (data-reader) subscription-matched-status)
  "DataReader::get_subscription_matched_status — a snapshot; resets the *_change
   counters per DDS read-resets-change semantics."
  (dds.pal:with-lock ((dr-status-lock dr))
    (let ((s (dr-sub-matched dr)))
      (prog1 (copy-subscription-matched-status s)
        (setf (subscription-matched-status-total-count-change s) 0
              (subscription-matched-status-current-count-change s) 0)))))

(defun* get-publication-matched-status (dw)
    (function (data-writer) publication-matched-status)
  "DataWriter::get_publication_matched_status — snapshot + reset the *_change counters."
  (dds.pal:with-lock ((dw-status-lock dw))
    (let ((s (dw-pub-matched dw)))
      (prog1 (copy-publication-matched-status s)
        (setf (publication-matched-status-total-count-change s) 0
              (publication-matched-status-current-count-change s) 0)))))

(defun* get-requested-incompatible-qos-status (dr)
    (function (data-reader) requested-incompatible-qos-status)
  "DataReader::get_requested_incompatible_qos_status — snapshot (policies deep-copied)
   + reset total_count_change; the cumulative policies counts are retained per DDS."
  (dds.pal:with-lock ((dr-status-lock dr))
    (let* ((s (dr-req-incompat dr))
           (snap (copy-requested-incompatible-qos-status s)))
      (setf (requested-incompatible-qos-status-policies snap)
            (mapcar #'copy-qos-policy-count (requested-incompatible-qos-status-policies s)))
      (setf (requested-incompatible-qos-status-total-count-change s) 0)
      snap)))

(defun* get-offered-incompatible-qos-status (dw)
    (function (data-writer) offered-incompatible-qos-status)
  "DataWriter::get_offered_incompatible_qos_status — snapshot (policies deep-copied)
   + reset total_count_change; the cumulative policies counts are retained per DDS."
  (dds.pal:with-lock ((dw-status-lock dw))
    (let* ((s (dw-off-incompat dw))
           (snap (copy-offered-incompatible-qos-status s)))
      (setf (offered-incompatible-qos-status-policies snap)
            (mapcar #'copy-qos-policy-count (offered-incompatible-qos-status-policies s)))
      (setf (offered-incompatible-qos-status-total-count-change s) 0)
      snap)))

(defun* get-sample-rejected-status (dr)
    (function (data-reader) sample-rejected-status)
  "DataReader::get_sample_rejected_status — snapshot + reset total_count_change."
  (dds.pal:with-lock ((dr-status-lock dr))
    (let ((s (dr-sample-rejected dr)))
      (prog1 (copy-sample-rejected-status s)
        (setf (sample-rejected-status-total-count-change s) 0)))))

(defun* get-liveliness-changed-status (dr)
    (function (data-reader) liveliness-changed-status)
  "DataReader::get_liveliness_changed_status — a snapshot; resets the *_change counters
   per DDS read-resets-change semantics (DDS 1.4 §2.2.4.1)."
  (dds.pal:with-lock ((dr-status-lock dr))
    (let ((s (dr-liv-changed dr)))
      (prog1 (copy-liveliness-changed-status s)
        (setf (liveliness-changed-status-alive-count-change s) 0
              (liveliness-changed-status-not-alive-count-change s) 0)))))

(defun* get-liveliness-lost-status (dw)
    (function (data-writer) liveliness-lost-status)
  "DataWriter::get_liveliness_lost_status — a snapshot; resets total_count_change per DDS
   read-resets-change semantics (DDS 1.4 §2.2.4.1, dds_rtf2_dcps.idl §118-121)."
  (dds.pal:with-lock ((dw-status-lock dw))
    (let ((s (dw-liv-lost dw)))
      (prog1 (copy-liveliness-lost-status s)
        (setf (liveliness-lost-status-total-count-change s) 0)))))

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
   INCONSISTENT_TOPIC status and, if a listener is masked for it, fire on_inconsistent_topic."
  (let ((tp (%find-topic p name)))
    (when tp
      (let ((snapshot nil))
        (dds.pal:with-lock ((topic-status-lock tp))
          (let ((s (topic-inconsistent-status tp)))
            (incf (inconsistent-topic-status-total-count s))
            (incf (inconsistent-topic-status-total-count-change s))
            (when (and (topic-listener-obj tp) (member :inconsistent-topic (topic-listener-mask tp)))
              (setf snapshot (copy-inconsistent-topic-status s))
              (setf (inconsistent-topic-status-total-count-change s) 0))))
        (when snapshot (on-inconsistent-topic (topic-listener-obj tp) tp snapshot)))))
  t)

(defun* get-inconsistent-topic-status (tp)
    (function (topic) inconsistent-topic-status)
  "Topic::get_inconsistent_topic_status — snapshot + reset the total_count_change."
  (dds.pal:with-lock ((topic-status-lock tp))
    (let ((s (topic-inconsistent-status tp)))
      (prog1 (copy-inconsistent-topic-status s)
        (setf (inconsistent-topic-status-total-count-change s) 0)))))

(defun* set-topic-listener (tp listener mask)
    (function (topic (or null listener) list) topic)
  "Topic::set_listener — install LISTENER for the statuses named in MASK (v1:
   (:inconsistent-topic))."
  (dds.pal:with-lock ((topic-status-lock tp))
    (setf (topic-listener-obj tp) listener (topic-listener-mask tp) mask))
  tp)
