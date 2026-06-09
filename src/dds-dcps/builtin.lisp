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
