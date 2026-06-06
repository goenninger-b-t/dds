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
   (enabled :initarg :enabled :initform nil :accessor entity-enabled-p)))

(defclass domain-participant (entity)
  ((domain :initarg :domain :reader dp-domain)
   (node :initarg :node :accessor dp-node)
   (children :initform '() :accessor dp-children)
   (user-reader :initform nil :accessor dp-user-reader)   ; v1: one DataReader per participant
   (user-writer :initform nil :accessor dp-user-writer))) ; v1: one DataWriter per participant

(defclass publisher (entity)
  ((participant :initarg :participant :reader pub-participant)
   (writers :initform '() :accessor pub-writers)))

(defclass subscriber (entity)
  ((participant :initarg :participant :reader sub-participant)
   (readers :initform '() :accessor sub-readers)))

(defclass topic (entity)
  ((name :initarg :name :reader topic-name)
   (type-name :initarg :type-name :reader topic-type-name)
   (type-support :initarg :type-support :reader topic-type-support)
   (participant :initarg :participant :reader topic-participant)))

(defclass data-writer (entity)
  ((topic :initarg :topic :reader dw-topic)
   (publisher :initarg :publisher :reader dw-publisher)
   (pub-matched :initform (make-publication-matched-status) :accessor dw-pub-matched)
   (off-incompat :initform (make-offered-incompatible-qos-status) :accessor dw-off-incompat)
   (listener :initform nil :accessor dw-listener)
   (listener-mask :initform '() :accessor dw-listener-mask)
   (status-lock :initform (dds.pal:make-lock "dw-status") :accessor dw-status-lock)))

(defclass data-reader (entity)
  ((topic :initarg :topic :reader dr-topic)
   (subscriber :initarg :subscriber :reader dr-subscriber)
   (cache :initform '() :accessor dr-cache)                       ; list of cached-sample
   (instances :initform (make-hash-table :test 'equalp) :accessor dr-instances) ; handle -> accessed-p
   (drained :initform 0 :accessor dr-drained)                    ; highest engine SN drained
   (sub-matched :initform (make-subscription-matched-status) :accessor dr-sub-matched)
   (req-incompat :initform (make-requested-incompatible-qos-status) :accessor dr-req-incompat)
   (listener :initform nil :accessor dr-listener)
   (listener-mask :initform '() :accessor dr-listener-mask)
   (conditions :initform '() :accessor dr-conditions)      ; read/query/status conditions bound here
   (status-lock :initform (dds.pal:make-lock "dr-status") :accessor dr-status-lock)))

;; Defined in conditions.lisp (loaded after this file); forward-declared so the data-
;; arrival hook below can wake the reader's WaitSets without a compile-time warning.
(declaim (ftype (function (data-reader) t) %notify-reader-conditions))

;;; ---- SampleInfo + cached samples (FR-DCPS-4) ----

(defstruct (sample-info (:constructor make-sample-info))
  "DDS 1.4 SampleInfo (dds_rtf2_dcps.idl §SampleInfo). v1 populates the three states +
   valid-data + instance-handle; source/publication handle, generation counts and the
   ranks default to 0/nil and are filled in by later increments. State kinds are kept
   as keywords (READ/NOT_READ, NEW/NOT_NEW, ALIVE/NOT_ALIVE_DISPOSED/_NO_WRITERS).
   sequence-number is a vendor extension (the RTPS writer SN)."
  (sample-state :not-read :type (member :read :not-read))
  (view-state :new :type (member :new :not-new))
  (instance-state :alive :type (member :alive :not-alive-disposed :not-alive-no-writers))
  (source-timestamp nil)
  (instance-handle nil)
  (publication-handle nil)
  (disposed-generation-count 0 :type integer)
  (no-writers-generation-count 0 :type integer)
  (sample-rank 0 :type integer)
  (generation-rank 0 :type integer)
  (absolute-generation-rank 0 :type integer)
  (valid-data t)
  (sequence-number 0 :type integer))

(defstruct (cached-sample (:constructor make-cached-sample))
  "A read/take result element: the deserialized DATA + its SAMPLE-INFO."
  (data nil)
  (info nil :type (or null sample-info)))

;;; ---- type-support serialization helpers (PLAIN_CDR2_LE SerializedPayload) ----

(declaim (ftype (function (t t) (simple-array (unsigned-byte 8) (*))) %serialize-sample))
(defun %serialize-sample (ts sample)
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

(declaim (ftype (function (t (simple-array (unsigned-byte 8) (*))) t) %deserialize-sample))
(defun %deserialize-sample (ts bytes)
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

(declaim (ftype (function () (simple-array (unsigned-byte 8) (12))) %make-guid-prefix))
(defun %make-guid-prefix ()
  "A unique-enough 12-octet GUID prefix per participant: vendor marker + a process
   counter + the wall clock. Without this every participant defaults to the all-zero
   prefix and the self-check makes them ignore each other's SPDP. Demo-grade."
  (let ((p (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0))
        (clk (get-universal-time))
        (n (incf *participant-counter*)))
    (setf (aref p 0) #x47 (aref p 1) #x42 (aref p 2) (logand n #xff))
    (loop for i from 3 below 12 do (setf (aref p i) (logand (ash clk (* -8 (- i 3))) #xff)))
    p))

(declaim (ftype (function (&key (:domain (integer 0)) (:qos t) (:advertise-address string)) domain-participant) create-participant))
(defun create-participant (&key (domain 0) (qos nil) (advertise-address "127.0.0.1"))
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
    (dds.disc:start-node node)
    p))

(declaim (ftype (function (domain-participant) (eql t)) delete-participant))
(defun delete-participant (p)
  "Delete the participant and its contained entities; stop the engine."
  (dds.disc:stop-node (dp-node p))
  (setf (entity-enabled-p p) nil)
  t)

(declaim (ftype (function (domain-participant) (integer 0)) discovered-count))
(defun discovered-count (p)
  "Number of remote participants P has discovered."
  (dds.disc:disc-node-discovered-count (dp-node p)))

(declaim (ftype (function (domain-participant) (integer 0)) matched-count))
(defun matched-count (p)
  "Number of remote endpoints matched against P's local endpoints."
  (dds.disc:disc-node-matched-count (dp-node p)))

(declaim (ftype (function (domain-participant) (eql t)) spin))
(defun spin (p)
  "Drive one discovery announcement cycle (SPDP + SEDP) for P. Discovery is
   caller-driven in v1 — an automatic background announcer with isolated send buffers
   is a follow-up (the engine's announce buffers are not yet thread-isolated)."
  (dds.disc:announce-participant (dp-node p))
  (dds.disc:announce-endpoints (dp-node p))
  t)

;;; ---- Publisher / Subscriber / Topic ----

(declaim (ftype (function (domain-participant) publisher) create-publisher))
(defun create-publisher (p)
  (let ((pub (make-instance 'publisher :participant p :enabled t)))
    (push pub (dp-children p))
    pub))

(declaim (ftype (function (domain-participant) subscriber) create-subscriber))
(defun create-subscriber (p)
  (let ((sub (make-instance 'subscriber :participant p :enabled t)))
    (push sub (dp-children p))
    sub))

(declaim (ftype (function (domain-participant string string t) topic) create-topic))
(defun create-topic (p name type-name type-support)
  "DomainParticipant::create_topic. TYPE-SUPPORT is a registered dds.types
   type-support (the generated codec bundle) used by write/take."
  (let ((tp (make-instance 'topic :name name :type-name type-name
                                  :type-support type-support :participant p :enabled t)))
    (push tp (dp-children p))
    tp))

;;; ---- DataWriter / DataReader ----

(declaim (ftype (function (publisher topic &key (:qos t)) data-writer) create-datawriter))
(defun create-datawriter (pub topic &key (qos (dds.qos:make-writer-qos)))
  "Publisher::create_datawriter — register a local writer in the engine on the
   topic's name/type with the QoS reliability (v1: the single user writer)."
  (let ((node (dp-node (pub-participant pub))))
    (dds.disc:add-local-writer node :topic (topic-name topic) :type (topic-type-name topic)
                               :qos qos)
    (dds.disc:enable-publisher node)
    (let ((dw (make-instance 'data-writer :topic topic :publisher pub :qos qos :enabled t)))
      (push dw (pub-writers pub))
      (setf (dp-user-writer (pub-participant pub)) dw)   ; v1 back-ref for status hooks
      dw)))

(declaim (ftype (function (subscriber topic &key (:qos t)) data-reader) create-datareader))
(defun create-datareader (sub topic &key (qos (dds.qos:make-reader-qos)))
  "Subscriber::create_datareader — register a local reader in the engine on the
   topic's name/type with the QoS reliability (v1: the single user reader)."
  (let ((node (dp-node (sub-participant sub))))
    (dds.disc:add-local-reader node :topic (topic-name topic) :type (topic-type-name topic)
                               :qos qos)
    (dds.disc:enable-subscriber node)
    (let ((dr (make-instance 'data-reader :topic topic :subscriber sub :qos qos :enabled t)))
      (push dr (sub-readers sub))
      (setf (dp-user-reader (sub-participant sub)) dr)   ; v1 back-ref for status hooks
      dr)))

(declaim (ftype (function (data-writer t) (eql t)) write-sample))
(defun write-sample (dw sample)
  "DataWriter::write — serialize SAMPLE via the topic type-support and publish it
   reliably over the engine to all matched/discovered readers."
  (let ((node (dp-node (pub-participant (dw-publisher dw)))))
    (dds.disc:publish-sample node (%serialize-sample (topic-type-support (dw-topic dw)) sample))
    t))

(defparameter +instance-handle-nil+
  (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
  "HANDLE_NIL — the instance handle for an unkeyed type (single instance).")

(declaim (ftype (function (t t) (simple-array (unsigned-byte 8) (16))) %instance-handle))
(defun %instance-handle (ts sample)
  "16-octet instance handle for SAMPLE via the type-support key-hash, or HANDLE_NIL
   for an unkeyed type."
  (let ((kh (dds.types:type-support-key-hash ts)))
    (if kh (funcall kh sample) +instance-handle-nil+)))

(declaim (ftype (function (data-reader) t) %drain))
(defun %drain (dr)
  "Pull newly-received raw samples from the engine, deserialize, assign each to its
   instance, and append to the reader cache with fresh SampleInfo (NOT_READ, ALIVE)."
  (let* ((node (dp-node (sub-participant (dr-subscriber dr))))
         (ts (topic-type-support (dr-topic dr))))
    (dolist (sn (sort (dds.disc:node-sample-sns node) #'<))
      (when (> sn (dr-drained dr))
        (setf (dr-drained dr) sn)
        (let ((bytes (dds.disc:node-sample node sn)))
          (when bytes
            (let* ((data (%deserialize-sample ts bytes))
                   (handle (%instance-handle ts data)))
              (unless (nth-value 1 (gethash handle (dr-instances dr)))
                (setf (gethash handle (dr-instances dr)) nil))   ; nil = not yet accessed
              (setf (dr-cache dr)
                    (nconc (dr-cache dr)
                           (list (make-cached-sample
                                  :data data
                                  :info (make-sample-info
                                         :sample-state :not-read :view-state :new
                                         :instance-state :alive :valid-data t
                                         :instance-handle handle :sequence-number sn))))))))))))

(declaim (ftype (function (t) (eql t)) %where-any))
(defun %where-any (sample)
  "The default read/take WHERE predicate — selects every sample (no query filter)."
  (declare (ignore sample))
  t)

(declaim (ftype (function (data-reader &key (:states list) (:where function)) list) read-samples))
(defun read-samples (dr &key (states '(:read :not-read)) (where #'%where-any))
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

(declaim (ftype (function (data-reader &key (:states list) (:where function)) list) take-samples))
(defun take-samples (dr &key (states '(:read :not-read)) (where #'%where-any))
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

(declaim (ftype (function (data-reader) (integer 0)) samples-available))
(defun samples-available (dr)
  "Drain newly-received samples into the cache and return the cache size, WITHOUT
   marking anything READ — for polling before a read/take."
  (%drain dr)
  (length (dr-cache dr)))

;;; ---- Status surfacing: SEDP match / incompatible-QoS events -> entity statuses +
;;;      listeners (M3 #3, FR-DCPS-3). These fire on the disc receiver thread; status
;;;      mutation is guarded by the entity STATUS-LOCK and any listener is invoked with
;;;      a snapshot OUTSIDE the lock (a listener must never deadlock the receiver).
;;;      Reading a status (get_*_status) resets its *_change counters per DDS 1.4.

(declaim (ftype (function (domain-participant keyword dds.rtps.discovery:endpoint-data) t) %on-disc-match))
(defun %on-disc-match (p kind remote)
  "ON-MATCH hook: a remote endpoint matched a local one. :remote-writer -> our reader
   gained a publication (SUBSCRIPTION_MATCHED); :remote-reader -> our writer gained a
   subscription (PUBLICATION_MATCHED). The 16-octet remote GUID is the matched handle."
  (let ((handle (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))))
    (ecase kind
      (:remote-writer (let ((dr (dp-user-reader p))) (when dr (%reader-matched dr handle))))
      (:remote-reader (let ((dw (dp-user-writer p))) (when dw (%writer-matched dw handle))))))
  t)

(declaim (ftype (function (domain-participant keyword dds.rtps.discovery:endpoint-data list) t) %on-disc-incompatible))
(defun %on-disc-incompatible (p kind remote bad)
  "ON-INCOMPATIBLE-QOS hook: topic+type agreed but RxO failed. :remote-writer -> our
   reader's REQUESTED_INCOMPATIBLE_QOS; :remote-reader -> our writer's OFFERED_
   INCOMPATIBLE_QOS. BAD is the failing-policy keyword list (dds.qos:qos-rxo-compatible)."
  (declare (ignore remote))
  (ecase kind
    (:remote-writer (let ((dr (dp-user-reader p))) (when dr (%reader-incompatible dr bad))))
    (:remote-reader (let ((dw (dp-user-writer p))) (when dw (%writer-incompatible dw bad)))))
  t)

(declaim (ftype (function (domain-participant) t) %on-participant-sample))
(defun %on-participant-sample (p)
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

(declaim (ftype (function (data-reader t) t) %reader-matched))
(defun %reader-matched (dr handle)
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

(declaim (ftype (function (data-writer t) t) %writer-matched))
(defun %writer-matched (dw handle)
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

(declaim (ftype (function (requested-incompatible-qos-status list) t) %apply-requested-incompatible))
(defun %apply-requested-incompatible (s bad)
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

(declaim (ftype (function (offered-incompatible-qos-status list) t) %apply-offered-incompatible))
(defun %apply-offered-incompatible (s bad)
  "Accumulate the failing policies BAD into an OFFERED_INCOMPATIBLE_QOS status S."
  (incf (offered-incompatible-qos-status-total-count s))
  (incf (offered-incompatible-qos-status-total-count-change s))
  (dolist (k bad)
    (let ((pid (rxo-policy-id k)))
      (setf (offered-incompatible-qos-status-policies s)
            (bump-policy-count (offered-incompatible-qos-status-policies s) pid))
      (setf (offered-incompatible-qos-status-last-policy-id s) pid)))
  t)

(declaim (ftype (function (data-reader list) t) %reader-incompatible))
(defun %reader-incompatible (dr bad)
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

(declaim (ftype (function (data-writer list) t) %writer-incompatible))
(defun %writer-incompatible (dw bad)
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

(declaim (ftype (function (data-reader) subscription-matched-status) get-subscription-matched-status))
(defun get-subscription-matched-status (dr)
  "DataReader::get_subscription_matched_status — a snapshot; resets the *_change
   counters per DDS read-resets-change semantics."
  (dds.pal:with-lock ((dr-status-lock dr))
    (let ((s (dr-sub-matched dr)))
      (prog1 (copy-subscription-matched-status s)
        (setf (subscription-matched-status-total-count-change s) 0
              (subscription-matched-status-current-count-change s) 0)))))

(declaim (ftype (function (data-writer) publication-matched-status) get-publication-matched-status))
(defun get-publication-matched-status (dw)
  "DataWriter::get_publication_matched_status — snapshot + reset the *_change counters."
  (dds.pal:with-lock ((dw-status-lock dw))
    (let ((s (dw-pub-matched dw)))
      (prog1 (copy-publication-matched-status s)
        (setf (publication-matched-status-total-count-change s) 0
              (publication-matched-status-current-count-change s) 0)))))

(declaim (ftype (function (data-reader) requested-incompatible-qos-status) get-requested-incompatible-qos-status))
(defun get-requested-incompatible-qos-status (dr)
  "DataReader::get_requested_incompatible_qos_status — snapshot (policies deep-copied)
   + reset total_count_change; the cumulative policies counts are retained per DDS."
  (dds.pal:with-lock ((dr-status-lock dr))
    (let* ((s (dr-req-incompat dr))
           (snap (copy-requested-incompatible-qos-status s)))
      (setf (requested-incompatible-qos-status-policies snap)
            (mapcar #'copy-qos-policy-count (requested-incompatible-qos-status-policies s)))
      (setf (requested-incompatible-qos-status-total-count-change s) 0)
      snap)))

(declaim (ftype (function (data-writer) offered-incompatible-qos-status) get-offered-incompatible-qos-status))
(defun get-offered-incompatible-qos-status (dw)
  "DataWriter::get_offered_incompatible_qos_status — snapshot (policies deep-copied)
   + reset total_count_change; the cumulative policies counts are retained per DDS."
  (dds.pal:with-lock ((dw-status-lock dw))
    (let* ((s (dw-off-incompat dw))
           (snap (copy-offered-incompatible-qos-status s)))
      (setf (offered-incompatible-qos-status-policies snap)
            (mapcar #'copy-qos-policy-count (offered-incompatible-qos-status-policies s)))
      (setf (offered-incompatible-qos-status-total-count-change s) 0)
      snap)))

;;; ---- set_listener (DDS 1.4 Entity::set_listener) ----

(declaim (ftype (function (data-reader (or null listener) list) data-reader) set-reader-listener))
(defun set-reader-listener (dr listener mask)
  "DataReader::set_listener — install LISTENER for the statuses named in MASK (a list
   of status keywords, e.g. (:subscription-matched :requested-incompatible-qos))."
  (dds.pal:with-lock ((dr-status-lock dr))
    (setf (dr-listener dr) listener (dr-listener-mask dr) mask))
  dr)

(declaim (ftype (function (data-writer (or null listener) list) data-writer) set-writer-listener))
(defun set-writer-listener (dw listener mask)
  "DataWriter::set_listener — install LISTENER for the statuses named in MASK (a list
   of status keywords, e.g. (:publication-matched :offered-incompatible-qos))."
  (dds.pal:with-lock ((dw-status-lock dw))
    (setf (dw-listener dw) listener (dw-listener-mask dw) mask))
  dw)
