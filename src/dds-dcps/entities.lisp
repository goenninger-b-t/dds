;;;; DDS 1.4 DCPS entity model (M3/P2, FR-DCPS-1). CLOS — this is control-plane, so
;;;; CLOS is the preferred default (FR-LANG-0); none of this is on the hot path. The
;;;; entities are a thin, typed facade over the existing RTPS engine (dds.disc): a
;;;; DomainParticipant owns a multicast disc-node; a DataWriter/DataReader binds to
;;;; the engine's single user endpoint (v1 limitation — one writer + one reader per
;;;; participant; multi-endpoint needs per-endpoint RTPS EntityIds, a later step).
;;;; write/take serialize/deserialize through the generated type-support (dds.types).

(in-package #:dds.dcps)

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
   (user-writer :initform nil :accessor dp-user-writer))  ; v1: one DataWriter per participant
  (:documentation "DDS DomainParticipant: owns a multicast disc-node for its domain and
   its contained entities. v1 holds one DataReader + one DataWriter per participant."))

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
   (listener :initform nil :accessor dw-listener)
   (listener-mask :initform '() :accessor dw-listener-mask)
   (status-lock :initform (dds.pal:make-lock "dw-status") :accessor dw-status-lock))
  (:documentation "DDS DataWriter: publishes typed samples on a Topic, carrying its
   PUBLICATION_MATCHED and OFFERED_INCOMPATIBLE_QOS statuses and optional listener."))

(defclass data-reader (entity)
  ((topic :initarg :topic :reader dr-topic)
   (subscriber :initarg :subscriber :reader dr-subscriber)
   (cache :initform '() :accessor dr-cache)                       ; list of cached-sample
   (instances :initform (make-hash-table :test 'equalp) :accessor dr-instances) ; handle -> accessed-p
   (drained :initform 0 :accessor dr-drained)                    ; highest engine SN drained
   (sub-matched :initform (make-subscription-matched-status) :accessor dr-sub-matched)
   (req-incompat :initform (make-requested-incompatible-qos-status) :accessor dr-req-incompat)
   (sample-rejected :initform (make-sample-rejected-status) :accessor dr-sample-rejected)
   (listener :initform nil :accessor dr-listener)
   (listener-mask :initform '() :accessor dr-listener-mask)
   (conditions :initform '() :accessor dr-conditions)      ; read/query/status conditions bound here
   (filter :initform nil :accessor dr-filter)              ; ContentFilteredTopic predicate, or nil
   (status-lock :initform (dds.pal:make-lock "dr-status") :accessor dr-status-lock))
  (:documentation "DDS DataReader: receives typed samples on a Topic into a read/take
   cache with per-instance SampleInfo, carrying its SUBSCRIPTION_MATCHED,
   REQUESTED_INCOMPATIBLE_QOS and SAMPLE_REJECTED statuses, conditions and listener."))

;; Defined in conditions.lisp (loaded after this file); forward-declared so the data-
;; arrival hook below can wake the reader's WaitSets without a compile-time warning.
(declaim (ftype (function (data-reader) t) %notify-reader-conditions))

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

;;; ---- type-support serialization helpers (PLAIN_CDR2_LE SerializedPayload) ----

(defun* %serialize-sample (ts sample)
    (function (t t) (simple-array (unsigned-byte 8) (*)))
  "Serialize SAMPLE via type-support TS as a PLAIN_CDR2_LE SerializedPayload."
  (let* ((buf (dds.core.buffer:make-octet-buffer 2048))
         (wc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.cdr:make-encapsulation-header wc :plain-cdr2-le)
    (funcall (dds.types:type-support-serialize ts) sample wc :xcdr2)
    (let* ((len (dds.core.buffer:cursor-position wc))
           (out (make-array len :element-type '(unsigned-byte 8))))
      (replace out (dds.core.buffer:octet-buffer-vec buf) :end1 len)
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))
      out)))

(defun* %deserialize-sample (ts bytes)
    (function (t (simple-array (unsigned-byte 8) (*))) t)
  "Deserialize a SerializedPayload (encap header + body) into a sample via TS."
  (let* ((ob (dds.core.buffer:make-octet-buffer (length bytes)))
         (rc (dds.core.buffer:cursor ob :endianness :little)))
    (replace (dds.core.buffer:octet-buffer-vec ob) bytes)
    (dds.cdr:parse-encapsulation-header rc)
    (prog1 (funcall (dds.types:type-support-deserialize ts) rc :xcdr2)
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

(defun* create-participant (&key (domain 0) (qos nil) (advertise-address "127.0.0.1"))
    (function (&key (:domain (integer 0)) (:qos t) (:advertise-address string)) domain-participant)
  "DomainParticipantFactory::create_participant — open the RTPS engine (a multicast
   disc-node) for DOMAIN, install the match/incompatible-QoS hooks that surface DDS
   statuses to the application, start the receiver, and return an enabled participant."
  (let* ((node (dds.disc:make-disc-node :domain domain :multicast t
                                        :advertise-address advertise-address
                                        :guid-prefix (%make-guid-prefix)))
         (p (make-instance 'domain-participant :domain domain :node node :qos qos :enabled t)))
    ;; Install hooks BEFORE the receiver thread starts so no early SEDP match is lost.
    (setf (dds.disc:disc-node-on-match node)
          (lambda (kind remote) (%on-disc-match p kind remote)))
    (setf (dds.disc:disc-node-on-incompatible-qos node)
          (lambda (kind remote bad) (%on-disc-incompatible p kind remote bad)))
    (setf (dds.disc:disc-node-on-sample node)
          (lambda () (%on-participant-sample p)))
    (setf (dds.disc:disc-node-on-inconsistent-topic node)
          (lambda (topic-name) (%on-disc-inconsistent-topic p topic-name)))
    (dds.disc:start-node node)
    p))

(defun* delete-participant (p)
    (function (domain-participant) (eql t))
  "Delete the participant and its contained entities; stop the engine."
  (dds.disc:stop-node (dp-node p))
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

(defun* create-datawriter (pub topic &key (qos (dds.qos:make-writer-qos)))
    (function (publisher topic &key (:qos t)) data-writer)
  "Publisher::create_datawriter — register a local writer in the engine on the
   topic's name/type with the QoS reliability (v1: the single user writer)."
  (let ((node (dp-node (pub-participant pub))))
    (dds.disc:add-local-writer node :topic (topic-name topic) :type (topic-type-name topic)
                               :qos qos :type-information (%topic-type-information topic))
    (dds.disc:enable-publisher node)
    (let ((dw (make-instance 'data-writer :topic topic :publisher pub :qos qos :enabled t)))
      (push dw (pub-writers pub))
      (setf (dp-user-writer (pub-participant pub)) dw)   ; v1 back-ref for status hooks
      dw)))

(defun* create-datareader (sub topic &key (qos (dds.qos:make-reader-qos)))
    (function (subscriber t &key (:qos t)) data-reader)
  "Subscriber::create_datareader — register a local reader in the engine on the
   topic's name/type with the QoS reliability (v1: the single user reader). TOPIC may
   be a Topic or a ContentFilteredTopic; in the latter case the reader applies the
   filter predicate reader-side (only matching samples reach read/take)."
  (let ((node (dp-node (sub-participant sub))))
    (dds.disc:add-local-reader node :topic (topic-name topic) :type (topic-type-name topic)
                               :qos qos :type-information (%topic-type-information topic))
    (dds.disc:enable-subscriber node)
    (let ((dr (make-instance 'data-reader :topic topic :subscriber sub :qos qos :enabled t)))
      (setf (dr-filter dr) (td-filter-predicate topic))   ; nil for a plain Topic
      (push dr (sub-readers sub))
      (setf (dp-user-reader (sub-participant sub)) dr)   ; v1 back-ref for status hooks
      dr)))

(defun* write-sample (dw sample)
    (function (data-writer t) (eql t))
  "DataWriter::write — serialize SAMPLE via the topic type-support and publish it
   reliably over the engine to all matched/discovered readers."
  (let ((node (dp-node (pub-participant (dw-publisher dw)))))
    (dds.disc:publish-sample node (%serialize-sample (topic-type-support (dw-topic dw)) sample))
    t))

(defparameter +instance-handle-nil+
  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
  "HANDLE_NIL — the instance handle for an unkeyed type (single instance).")

(defun* %instance-handle (ts sample)
    (function (t t) (simple-array (unsigned-byte 8) (16)))
  "16-octet instance handle for SAMPLE via the type-support key-hash, or HANDLE_NIL
   for an unkeyed type."
  (let ((kh (dds.types:type-support-key-hash ts)))
    (if kh (funcall kh sample) +instance-handle-nil+)))

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

(defun* %drain (dr)
    (function (data-reader) t)
  "Pull newly-received raw samples from the engine, deserialize, assign each to its
   instance, and append to the reader cache with fresh SampleInfo (NOT_READ, ALIVE)."
  (let* ((node (dp-node (sub-participant (dr-subscriber dr))))
         (ts (topic-type-support (dr-topic dr))))
    (dolist (sn (sort (dds.disc:node-sample-sns node) #'<))
      (when (> sn (dr-drained dr))
        (setf (dr-drained dr) sn)
        (let ((bytes (dds.disc:node-sample node sn)))
          (when bytes
            (let ((data (%deserialize-sample ts bytes)))
              ;; ContentFilteredTopic: drop reader-side a sample failing the filter.
              (when (or (null (dr-filter dr)) (funcall (dr-filter dr) data))
                (let* ((handle (%instance-handle ts data))
                       (reason (%resource-reject-reason dr handle)))
                  (if reason
                      ;; RESOURCE_LIMITS would be exceeded -> reject (SAMPLE_REJECTED).
                      (%reader-sample-rejected dr reason handle)
                      (progn
                        (unless (nth-value 1 (gethash handle (dr-instances dr)))
                          (setf (gethash handle (dr-instances dr)) nil))   ; nil = not yet accessed
                        (setf (dr-cache dr)
                              (nconc (dr-cache dr)
                                     (list (make-cached-sample
                                            :data data
                                            :info (make-sample-info
                                                   :sample-state :not-read :view-state :new
                                                   :instance-state :alive :valid-data t
                                                   :instance-handle handle :sequence-number sn))))))))))))))))

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
                              (%assess-and-record-type-compat dr remote))))
      (:remote-reader (let ((dw (dp-user-writer p)))
                        (when dw (%writer-matched dw handle)
                              (%assess-and-record-type-compat dw remote))))))
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
