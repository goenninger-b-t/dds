;;;; DDS 1.4 Listeners (M3 #3, FR-DCPS-2). CLOS objects with overridable methods —
;;;; the natural DDS idiom and off the per-sample path (status events coalesce, they
;;;; do not fire per sample). Interfaces + method names pinned from
;;;; docs/specs/dds_rtf2_dcps.idl §206-245. An application subclasses DATA-READER-
;;;; LISTENER / DATA-WRITER-LISTENER and overrides the ON-* methods it cares about;
;;;; the base methods are no-ops so partial listeners are legal. v1 fires the methods
;;;; whose status the engine already produces from the SEDP receiver thread:
;;;; ON-SUBSCRIPTION-MATCHED / ON-PUBLICATION-MATCHED and ON-(REQUESTED|OFFERED)-
;;;; INCOMPATIBLE-QOS. ON-DATA-AVAILABLE and the deadline/liveliness/sample-* methods
;;;; exist for subclassing but fire in later increments (receiver-push / those statuses).

(in-package #:dds.dcps)

(defclass listener () ()
  (:documentation "Base DDS Listener (dds_rtf2_dcps.idl interface Listener §199)."))

(defclass data-reader-listener (listener) ()
  (:documentation "DDS DataReaderListener (dds_rtf2_dcps.idl §224)."))

(defclass data-writer-listener (listener) ()
  (:documentation "DDS DataWriterListener (dds_rtf2_dcps.idl §206)."))

(defclass topic-listener (listener) ()
  (:documentation "DDS TopicListener (dds_rtf2_dcps.idl §201)."))

(defclass publisher-listener (listener) ()
  (:documentation "DDS PublisherListener (dds_rtf2_dcps.idl §221): the DataWriterListener
   callbacks, no additional callback of its own. Sits above its DataWriters in the
   listener-propagation chain (DDS 1.4 §2.2.4.1)."))

(defclass subscriber-listener (listener) ()
  (:documentation "DDS SubscriberListener (dds_rtf2_dcps.idl §247): the DataReaderListener
   callbacks plus on_data_on_readers. Sits above its DataReaders in the propagation chain
   (DDS 1.4 §2.2.4.1)."))

(defclass domain-participant-listener (listener) ()
  (:documentation "DDS DomainParticipantListener (dds_rtf2_dcps.idl §253): aggregates every
   Topic/Publisher/Subscriber/DataWriter/DataReader callback. It is the last (least specific)
   link in the listener-propagation chain (DDS 1.4 §2.2.4.1), catching a status no more
   specific enabled listener handled. All on-* generics dispatch on the base LISTENER, so a
   participant listener inherits every callback."))

(defgeneric on-inconsistent-topic (listener topic status)
  (:documentation "TopicListener::on_inconsistent_topic.")
  (:method ((listener listener) topic status) (declare (ignore topic status)) nil))

;;; ---- SubscriberListener method (§247-250); base method is a no-op ----

(defgeneric on-data-on-readers (listener subscriber)
  (:documentation "SubscriberListener::on_data_on_readers (dds_rtf2_dcps.idl §248, DDS 1.4
   §2.2.4.1): one or more of SUBSCRIBER's DataReaders have new data. When a Subscriber (or a
   DomainParticipant) listener enabled for DATA_ON_READERS handles this, it TAKES PRECEDENCE
   over the readers' on_data_available, which is then not called. Base method is a no-op.")
  (:method ((listener listener) subscriber) (declare (ignore subscriber)) nil))

;;; ---- DataReaderListener methods (§224-245); base methods are no-ops ----

(defgeneric on-data-available (listener reader)
  (:documentation "DataReaderListener::on_data_available.")
  (:method ((listener listener) reader) (declare (ignore reader)) nil))

(defgeneric on-subscription-matched (listener reader status)
  (:documentation "DataReaderListener::on_subscription_matched.")
  (:method ((listener listener) reader status) (declare (ignore reader status)) nil))

(defgeneric on-requested-incompatible-qos (listener reader status)
  (:documentation "DataReaderListener::on_requested_incompatible_qos.")
  (:method ((listener listener) reader status) (declare (ignore reader status)) nil))

(defgeneric on-requested-deadline-missed (listener reader status)
  (:documentation "DataReaderListener::on_requested_deadline_missed.")
  (:method ((listener listener) reader status) (declare (ignore reader status)) nil))

(defgeneric on-sample-rejected (listener reader status)
  (:documentation "DataReaderListener::on_sample_rejected.")
  (:method ((listener listener) reader status) (declare (ignore reader status)) nil))

(defgeneric on-sample-lost (listener reader status)
  (:documentation "DataReaderListener::on_sample_lost.")
  (:method ((listener listener) reader status) (declare (ignore reader status)) nil))

(defgeneric on-liveliness-changed (listener reader status)
  (:documentation "DataReaderListener::on_liveliness_changed.")
  (:method ((listener listener) reader status) (declare (ignore reader status)) nil))

;;; ---- DataWriterListener methods (§206-219); base methods are no-ops ----

(defgeneric on-publication-matched (listener writer status)
  (:documentation "DataWriterListener::on_publication_matched.")
  (:method ((listener listener) writer status) (declare (ignore writer status)) nil))

(defgeneric on-offered-incompatible-qos (listener writer status)
  (:documentation "DataWriterListener::on_offered_incompatible_qos.")
  (:method ((listener listener) writer status) (declare (ignore writer status)) nil))

(defgeneric on-offered-deadline-missed (listener writer status)
  (:documentation "DataWriterListener::on_offered_deadline_missed.")
  (:method ((listener listener) writer status) (declare (ignore writer status)) nil))

(defgeneric on-liveliness-lost (listener writer status)
  (:documentation "DataWriterListener::on_liveliness_lost.")
  (:method ((listener listener) writer status) (declare (ignore writer status)) nil))
