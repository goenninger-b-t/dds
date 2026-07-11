;;;; DDS 1.4 builtin-topic data (M3 #5, FR-DCPS-6): DCPSParticipant / DCPSPublication /
;;;; DCPSSubscription / DCPSTopic exposed to the application. Field sets pinned from
;;;; docs/specs/xtypes-1_3-discovery-builtin-topic.idl (§164/§237/§271/§206). The data
;;;; is what discovery already collected: the disc node tracks every discovered remote
;;;; participant (SPDP) and every discovered remote endpoint (SEDP, matched or not), and
;;;; these readers surface it. Control-plane. v1 exposes the BuiltinTopicKey_t + topic/
;;;; type names + the propagated reliability/durability; the remaining QoS fields and
;;;; user/topic/group data fill in as SEDP captures more. A reader/condition-shaped
;;;; builtin Subscriber (get_builtin_subscriber / lookup_datareader) is a later wrapper.

(in-package #:dds.dcps)

(defstruct* (participant-builtin-topic-data (:constructor make-participant-builtin-topic-data))
  "DCPSParticipant builtin data (idl §164). v1: the BuiltinTopicKey_t (participant GUID
   prefix, 16 octets zero-padded); user_data not yet captured."
  (key nil :type (or null (array (unsigned-byte 8) (*)))))

(defstruct* (publication-builtin-topic-data (:constructor make-publication-builtin-topic-data))
  "DCPSPublication builtin data (idl §237). v1 subset: key / participant_key / topic_name
   / type_name + the SEDP-propagated reliability + durability."
  (key nil :type (or null (array (unsigned-byte 8) (*)))) (participant-key nil :type (or null (array (unsigned-byte 8) (*))))
  (topic-name "" :type string) (type-name "" :type string)
  (reliability :best-effort :type (member :best-effort :reliable)) (durability :volatile :type (member :volatile :transient-local :transient :persistent)))

(defstruct* (subscription-builtin-topic-data (:constructor make-subscription-builtin-topic-data))
  "DCPSSubscription builtin data (idl §271). Same v1 subset as the publication data."
  (key nil :type (or null (array (unsigned-byte 8) (*)))) (participant-key nil :type (or null (array (unsigned-byte 8) (*))))
  (topic-name "" :type string) (type-name "" :type string)
  (reliability :best-effort :type (member :best-effort :reliable)) (durability :volatile :type (member :volatile :transient-local :transient :persistent)))

(defstruct* (topic-builtin-topic-data (:constructor make-topic-builtin-topic-data))
  "DCPSTopic builtin data (idl §206). v1: distinct (name, type_name) discovered; key
   and QoS fill in later."
  (name "" :type string) (type-name "" :type string))

(defun* %prefix->key (prefix)
    (function ((simple-array (unsigned-byte 8) (12))) (simple-array (unsigned-byte 8) (16)))
  "A 16-octet BuiltinTopicKey_t from a 12-octet participant GUID prefix (zero-padded)."
  (let ((k (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace k prefix :end1 12)
    k))

(defun* %guid->participant-key (guid)
    (function ((simple-array (unsigned-byte 8) (16))) (simple-array (unsigned-byte 8) (16)))
  "The participant key (16 octets) for an endpoint GUID = its 12-octet prefix, padded."
  (let ((k (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace k guid :end2 12)
    k))

(defun* get-builtin-participant-data (p)
    (function (domain-participant) list)
  "DCPSParticipant builtin reader (FR-DCPS-6): one entry per discovered remote participant."
  (mapcar (lambda (sd)
            (make-participant-builtin-topic-data
             :key (%prefix->key (dds.rtps.discovery:spdp-data-guid-prefix sd))))
          (dds.disc:node-discovered-participants (dp-node p))))

(defun* %endpoint->publication (ep)
    (function (dds.rtps.discovery:endpoint-data) publication-builtin-topic-data)
  "Project a discovered endpoint-data EP into a DCPSPublication publication-builtin-topic-data sample."
  (let ((qos (dds.rtps.discovery:endpoint-data-qos ep))
        (guid (dds.rtps.discovery:endpoint-data-guid ep)))
    (make-publication-builtin-topic-data
     :key (copy-seq guid) :participant-key (%guid->participant-key guid)
     :topic-name (dds.rtps.discovery:endpoint-data-topic-name ep)
     :type-name (dds.rtps.discovery:endpoint-data-type-name ep)
     :reliability (dds.qos:qos-reliability qos)
     :durability (dds.qos:qos-durability qos))))

(defun* %endpoint->subscription (ep)
    (function (dds.rtps.discovery:endpoint-data) subscription-builtin-topic-data)
  "Project a discovered endpoint-data EP into a DCPSSubscription subscription-builtin-topic-data sample."
  (let ((qos (dds.rtps.discovery:endpoint-data-qos ep))
        (guid (dds.rtps.discovery:endpoint-data-guid ep)))
    (make-subscription-builtin-topic-data
     :key (copy-seq guid) :participant-key (%guid->participant-key guid)
     :topic-name (dds.rtps.discovery:endpoint-data-topic-name ep)
     :type-name (dds.rtps.discovery:endpoint-data-type-name ep)
     :reliability (dds.qos:qos-reliability qos)
     :durability (dds.qos:qos-durability qos))))

(defun* get-builtin-publication-data (p)
    (function (domain-participant) list)
  "DCPSPublication builtin reader (FR-DCPS-6): one entry per discovered remote writer."
  (mapcar #'%endpoint->publication (dds.disc:disc-node-discovered-writers-list (dp-node p))))

(defun* get-builtin-subscription-data (p)
    (function (domain-participant) list)
  "DCPSSubscription builtin reader (FR-DCPS-6): one entry per discovered remote reader."
  (mapcar #'%endpoint->subscription (dds.disc:disc-node-discovered-readers-list (dp-node p))))

;;; ---- Matched-entity introspection (S5.T3, DDS 1.4 §2.2.2.4.2.10-11 / §2.2.2.5.2.10-11): the MATCHED
;;;      subset (RxO-compatible) of the discovered endpoints, per local endpoint, via the disc match tables.

(defun* get-matched-subscriptions (dw)
    (function (data-writer) list)
  "DataWriter::get_matched_subscriptions (DDS 1.4 §2.2.2.4.2.10) — the 16-octet instance handles (remote
   GUIDs) of the DataReaders currently matched to DW (a writer matches only readers)."
  (mapcar (lambda (ep) (copy-seq (dds.rtps.discovery:endpoint-data-guid ep)))
          (dds.disc:disc-node-matched-endpoints-for
           (dp-node (pub-participant (dw-publisher dw))) (dw-entity-id dw))))

(defun* get-matched-publications (dr)
    (function (data-reader) list)
  "DataReader::get_matched_publications (DDS 1.4 §2.2.2.5.2.10) — the 16-octet instance handles (remote
   GUIDs) of the DataWriters currently matched to DR (a reader matches only writers)."
  (mapcar (lambda (ep) (copy-seq (dds.rtps.discovery:endpoint-data-guid ep)))
          (dds.disc:disc-node-matched-endpoints-for
           (dp-node (sub-participant (dr-subscriber dr))) (dr-entity-id dr))))

(defun* %matched-endpoint-for (node local-eid handle)
    (function (t (unsigned-byte 32) (simple-array (unsigned-byte 8) (16)))
              (or null dds.rtps.discovery:endpoint-data))
  "The matched remote endpoint-data of the local endpoint LOCAL-EID whose GUID equals HANDLE, or NIL when
   HANDLE names no currently-matched remote (the caller's BAD_PARAMETER)."
  (find handle (dds.disc:disc-node-matched-endpoints-for node local-eid)
        :key #'dds.rtps.discovery:endpoint-data-guid :test #'equalp))

(defun* get-matched-subscription-data (dw handle)
    (function (data-writer (simple-array (unsigned-byte 8) (16)))
              (or null subscription-builtin-topic-data))
  "DataWriter::get_matched_subscription_data (DDS 1.4 §2.2.2.4.2.11) — the SubscriptionBuiltinTopicData of
   the matched DataReader named by HANDLE, or NIL when HANDLE names no matched reader (BAD_PARAMETER)."
  (let ((ep (%matched-endpoint-for (dp-node (pub-participant (dw-publisher dw))) (dw-entity-id dw) handle)))
    (and ep (%endpoint->subscription ep))))

(defun* get-matched-publication-data (dr handle)
    (function (data-reader (simple-array (unsigned-byte 8) (16)))
              (or null publication-builtin-topic-data))
  "DataReader::get_matched_publication_data (DDS 1.4 §2.2.2.5.2.11) — the PublicationBuiltinTopicData of the
   matched DataWriter named by HANDLE, or NIL when HANDLE names no matched writer (BAD_PARAMETER)."
  (let ((ep (%matched-endpoint-for (dp-node (sub-participant (dr-subscriber dr))) (dr-entity-id dr) handle)))
    (and ep (%endpoint->publication ep))))

(defun* get-builtin-topic-data (p)
    (function (domain-participant) list)
  "DCPSTopic builtin reader (FR-DCPS-6): one entry per distinct (topic, type) discovered."
  (let ((seen (make-hash-table :test 'equal)) (out '()))
    (dolist (ep (append (dds.disc:disc-node-discovered-writers-list (dp-node p))
                        (dds.disc:disc-node-discovered-readers-list (dp-node p))))
      (let ((key (cons (dds.rtps.discovery:endpoint-data-topic-name ep)
                       (dds.rtps.discovery:endpoint-data-type-name ep))))
        (unless (gethash key seen)
          (setf (gethash key seen) t)
          (push (make-topic-builtin-topic-data :name (car key) :type-name (cdr key)) out))))
    (nreverse out)))
