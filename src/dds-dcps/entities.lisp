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
   (children :initform '() :accessor dp-children)))

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
   (publisher :initarg :publisher :reader dw-publisher)))

(defclass data-reader (entity)
  ((topic :initarg :topic :reader dr-topic)
   (subscriber :initarg :subscriber :reader dr-subscriber)
   (last-taken :initform 0 :accessor dr-last-taken)))

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

(declaim (ftype (function (t) integer) %reliability-of))
(defun %reliability-of (qos)
  "Map a QoS RELIABILITY kind to the discovery reliability constant."
  (ecase (dds.qos:qos-reliability qos)
    (:reliable    dds.rtps.discovery:+reliability-reliable+)
    (:best-effort dds.rtps.discovery:+reliability-best-effort+)))

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
   disc-node) for DOMAIN, start its receiver, and return an enabled participant."
  (let ((node (dds.disc:make-disc-node :domain domain :multicast t
                                       :advertise-address advertise-address
                                       :guid-prefix (%make-guid-prefix))))
    (dds.disc:start-node node)
    (make-instance 'domain-participant :domain domain :node node :qos qos :enabled t)))

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
                               :reliability (%reliability-of qos))
    (dds.disc:enable-publisher node)
    (let ((dw (make-instance 'data-writer :topic topic :publisher pub :qos qos :enabled t)))
      (push dw (pub-writers pub))
      dw)))

(declaim (ftype (function (subscriber topic &key (:qos t)) data-reader) create-datareader))
(defun create-datareader (sub topic &key (qos (dds.qos:make-reader-qos)))
  "Subscriber::create_datareader — register a local reader in the engine on the
   topic's name/type with the QoS reliability (v1: the single user reader)."
  (let ((node (dp-node (sub-participant sub))))
    (dds.disc:add-local-reader node :topic (topic-name topic) :type (topic-type-name topic)
                               :reliability (%reliability-of qos))
    (dds.disc:enable-subscriber node)
    (let ((dr (make-instance 'data-reader :topic topic :subscriber sub :qos qos :enabled t)))
      (push dr (sub-readers sub))
      dr)))

(declaim (ftype (function (data-writer t) (eql t)) write-sample))
(defun write-sample (dw sample)
  "DataWriter::write — serialize SAMPLE via the topic type-support and publish it
   reliably over the engine to all matched/discovered readers."
  (let ((node (dp-node (pub-participant (dw-publisher dw)))))
    (dds.disc:publish-sample node (%serialize-sample (topic-type-support (dw-topic dw)) sample))
    t))

(declaim (ftype (function (data-reader) list) take-samples))
(defun take-samples (dr)
  "DataReader::take — return the list of newly-received samples (deserialized via the
   topic type-support), in SN order; each is returned once (take semantics). v1 has
   no SampleInfo / instance-state selection yet."
  (let* ((node (dp-node (sub-participant (dr-subscriber dr))))
         (ts (topic-type-support (dr-topic dr)))
         (out '()))
    (dolist (sn (sort (dds.disc:node-sample-sns node) #'<) (nreverse out))
      (when (> sn (dr-last-taken dr))
        (setf (dr-last-taken dr) sn)
        (let ((bytes (dds.disc:node-sample node sn)))
          (when bytes (push (%deserialize-sample ts bytes) out)))))))
