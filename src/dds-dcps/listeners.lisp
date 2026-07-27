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

;;;; ---------------------------------------------------------------------------------------------
;;;; VENDOR-EXTENSION listener operations (ADR 0089). NOT DDS 1.4 — none of these appear in
;;;; dds_rtf2_dcps.idl. They exist for parity with the RTI Connext extension listeners an application
;;;; may already be written against, so a port does not have to give up notifications it relies on.
;;;; They ride the SAME machinery as the standard callbacks: a status struct, the %notify-status
;;;; chokepoint, the containment-chain walk in %find-enabled-listener, a StatusCondition bit and a
;;;; get_*_status snapshot. Each is wired to a real event — see the constants in statuses.lisp.

(defgeneric on-unaddressable-peer (listener participant status)
  (:documentation "VENDOR EXTENSION (not DDS 1.4): a remote endpoint was compatible on topic/type/QoS but
   its participant advertises no locator this implementation can send to, so the match was REFUSED
   (ADR 0080). STATUS is an UNADDRESSABLE-PEER-STATUS snapshot naming the refused GUID and the Locator_t
   kinds it did offer.

   ADR 0089: this callback was MISSING — ADR 0080 defined the status, the bitmask bit and the snapshot
   accessor and promised a listener, but no generic function existed and no entry appeared in
   *status-listener-invokers*. Enabling :unaddressable-peer in a listener mask therefore funcalled NIL on
   the discovery thread, where the error is swallowed. The same omission made the first cut of ADR 0089's
   own statuses measure inert.")
  (:method ((listener listener) participant status) (declare (ignore participant status)) nil))

(defgeneric on-reliable-writer-cache-changed (listener writer status)
  (:documentation "VENDOR EXTENSION (not DDS 1.4): the reliable writer's send window of UNACKNOWLEDGED
   samples crossed a threshold — it emptied, it filled, or it rose to / fell to the high or low watermark
   of the WRITER-CACHE-*-WATERMARK vendor QoS. STATUS is a RELIABLE-WRITER-CACHE-CHANGED-STATUS snapshot.

   EDGE-triggered, never level-triggered. This callback runs on a RECEIVER or a WRITE thread, so firing it
   on every change of the unacked count — which a reliable exchange changes twice per sample — would put a
   per-sample application callback on the data path. Raise the high watermark to be told only about
   backpressure worth hearing about; the default {0, 1} yields two events per burst-and-drain cycle.

   The unacked count and its peak are how an application watches backpressure build BEFORE write() starts
   timing out; REPLACED-UNACKED-SAMPLE-COUNT is how it learns a KEEP_LAST writer has already lost data.")
  (:method ((listener listener) writer status) (declare (ignore writer status)) nil))

(defgeneric on-reliable-reader-activity-changed (listener writer status)
  (:documentation "VENDOR EXTENSION (not DDS 1.4): a matched remote reader of WRITER started or
   stopped acknowledging. STATUS is a RELIABLE-READER-ACTIVITY-CHANGED-STATUS snapshot. Distinct from
   on_publication_matched, which reports discovery-level matching — a reader can remain matched while
   acknowledging nothing.")
  (:method ((listener listener) writer status) (declare (ignore writer status)) nil))

(defgeneric on-application-acknowledgment (listener writer status)
  (:documentation "VENDOR EXTENSION (not DDS 1.4): a matched remote reader's APPLICATION has acknowledged
   one or more of WRITER's samples (ADR 0090; RTI's on_application_acknowledgment). STATUS is an
   APPLICATION-ACKNOWLEDGMENT-STATUS snapshot naming the acknowledging reader, the highest sequence number
   it acknowledged, and the writer's remaining application-level send window.

   THIS IS THE ONLY CALLBACK THAT REPORTS 'the application has processed it'. on_publication_matched says
   a reader exists; on_reliable_reader_activity_changed says its RTPS layer is still acknowledging; both
   can be true while the subscribing application has consumed nothing. Effective only when
   ACKNOWLEDGMENT_KIND is an APPLICATION kind — under :PROTOCOL nothing ever sends an APP_ACK, so this
   never fires, which is correct rather than inert.")
  (:method ((listener listener) writer status) (declare (ignore writer status)) nil))

;;;; NOT DEFINED HERE, deliberately (ADR 0089 §Rejected):
;;;;
;;;;   on_destination_unreachable — DOES NOT EXIST in the Connext 7.3 DataWriterListener. It was carried
;;;;     in the first cut of this slice, as an alias onto UNADDRESSABLE_PEER, on a recollection that
;;;;     turned out to be wrong; RTI's answer to an unreachable destination is the internal locator
;;;;     reachability ping, which stops using the locator instead of notifying anyone. Our
;;;;     UNADDRESSABLE_PEER (refuse the match, report the locator kinds the peer did offer) stands on its
;;;;     own merit — see ON-UNADDRESSABLE-PEER — but it is not parity and is not dressed in a Connext name.
;;;;
;;;;   on_sample_removed — a DIFFERENT EVENT under a familiar name. Connext fires it only for samples
;;;;     written with a cookie or under Zero Copy/FlatData, handing back a DDS_Cookie_t so the
;;;;     application can reclaim the buffer. Ours fired on every purge. The loss information it carried
;;;;     now lives where RTI puts it, in RELIABLE-WRITER-CACHE-CHANGED-STATUS's
;;;;     REPLACED-UNACKED-SAMPLE-COUNT. The genuine cookie callback needs a writer-loan reclaim path the
;;;;     ADR 0042 loan does not have (it retains its payload), so it is a separate slice, not this one.
