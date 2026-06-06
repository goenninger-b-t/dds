;;;; DDS 1.4 Conditions + WaitSet (M3 #3, FR-DCPS-2). CLOS control-plane. The base
;;;; DDS Condition is named WAIT-CONDITION here to avoid clashing with CL:CONDITION.
;;;; GuardCondition, ReadCondition (sample-state mask), QueryCondition (ReadCondition +
;;;; a query predicate; the DDS SQL-subset expression + parameters are deferred to #4,
;;;; shared with content-filtered topics, FR-DCPS-5), and a StatusCondition over the
;;;; communication statuses. WaitSet::wait polls (~10 ms); a condition-variable wake
;;;; driven by the receiver thread is the remaining #3 follow-up.

(in-package #:dds.dcps)

(defclass wait-condition ()
  ((trigger :initform nil :accessor %wc-trigger))
  (:documentation "Base DDS Condition (get_trigger_value)."))

(defclass guard-condition (wait-condition) ()
  (:documentation "App-controlled trigger (DDS GuardCondition)."))

(defclass read-condition (wait-condition)
  ((reader :initarg :reader :reader rc-reader)
   (states :initarg :states :initform '(:not-read) :reader rc-states))
  (:documentation "Triggers when its DataReader holds samples matching the sample-state mask."))

(defclass query-condition (read-condition)
  ((query-fn :initarg :query-fn :initform #'%where-any :reader qc-query-fn))
  (:documentation "A ReadCondition that also filters by QUERY-FN, a predicate over the
   deserialized sample. v1 takes a Lisp predicate; the DDS SQL-subset query expression
   + parameters are deferred to #4 (shared with content-filtered topics, FR-DCPS-5)."))

(defclass status-condition (wait-condition)
  ((entity :initarg :entity :reader sc-entity)
   (mask :initarg :mask :initform '(:data-available) :reader sc-mask))
  (:documentation "Triggers when an enabled status named in MASK is active on ENTITY.
   v1 supports :data-available (reader has unread samples) plus the change-driven
   statuses :subscription-matched / :requested-incompatible-qos (reader) and
   :publication-matched / :offered-incompatible-qos (writer) — each active while its
   status has an unread *_change, i.e. until the app calls the matching get_*_status."))

(defclass wait-set ()
  ((conditions :initform '() :accessor ws-conditions))
  (:documentation "DDS WaitSet — a set of conditions to wait on."))

(declaim (ftype (function () guard-condition) make-guard-condition))
(defun make-guard-condition () (make-instance 'guard-condition))

(declaim (ftype (function (guard-condition t) t) set-trigger-value))
(defun set-trigger-value (gc value)
  "DDS GuardCondition::set_trigger_value."
  (setf (%wc-trigger gc) (and value t)))

(declaim (ftype (function (data-reader &key (:states list)) read-condition) create-readcondition))
(defun create-readcondition (reader &key (states '(:not-read)))
  "DataReader::create_readcondition — triggers when samples matching STATES exist."
  (make-instance 'read-condition :reader reader :states states))

(declaim (ftype (function (data-reader &key (:states list) (:query function)) query-condition) create-querycondition))
(defun create-querycondition (reader &key (states '(:not-read)) (query #'%where-any))
  "DataReader::create_querycondition — a ReadCondition that also filters by QUERY (a
   predicate over the deserialized sample). Triggers / selects only samples whose
   sample-state is in STATES AND that satisfy QUERY. v1 takes a Lisp predicate; the
   DDS SQL-subset query expression + parameters are deferred to #4 (FR-DCPS-5)."
  (make-instance 'query-condition :reader reader :states states :query-fn query))

(declaim (ftype (function (entity &key (:mask list)) status-condition) make-status-condition))
(defun make-status-condition (entity &key (mask '(:data-available)))
  "A StatusCondition for ENTITY enabled for the statuses in MASK (v1: :data-available)."
  (make-instance 'status-condition :entity entity :mask mask))

(declaim (ftype (function (data-reader list) (integer 0)) %count-matching))
(defun %count-matching (dr states)
  "Drain newly-received samples and count those whose sample-state is in STATES."
  (%drain dr)
  (count-if (lambda (cs) (member (sample-info-sample-state (cached-sample-info cs)) states))
            (dr-cache dr)))

(declaim (ftype (function (data-reader list function) (integer 0)) %count-matching-query))
(defun %count-matching-query (dr states query-fn)
  "Drain newly-received samples and count those whose sample-state is in STATES and
   whose data satisfies QUERY-FN (the query-condition trigger predicate)."
  (%drain dr)
  (count-if (lambda (cs)
              (and (member (sample-info-sample-state (cached-sample-info cs)) states)
                   (funcall query-fn (cached-sample-data cs))))
            (dr-cache dr)))

(defgeneric condition-trigger-value (c)
  (:documentation "DDS Condition::get_trigger_value — the current trigger state."))
(defmethod condition-trigger-value ((c guard-condition)) (%wc-trigger c))
(defmethod condition-trigger-value ((c read-condition))
  (plusp (%count-matching (rc-reader c) (rc-states c))))
(defmethod condition-trigger-value ((c query-condition))
  (plusp (%count-matching-query (rc-reader c) (rc-states c) (qc-query-fn c))))
(declaim (ftype (function (entity keyword) t) %status-active-p))
(defun %status-active-p (entity kind)
  "Whether the communication status KIND is currently active on ENTITY (the trigger
   predicate for a StatusCondition). :data-available follows unread samples; the
   matched/incompatible kinds follow their *_change counter (reset by get_*_status)."
  (case kind
    (:data-available
     (and (typep entity 'data-reader) (plusp (%count-matching entity '(:not-read)))))
    (:subscription-matched
     (and (typep entity 'data-reader)
          (plusp (subscription-matched-status-total-count-change (dr-sub-matched entity)))))
    (:requested-incompatible-qos
     (and (typep entity 'data-reader)
          (plusp (requested-incompatible-qos-status-total-count-change (dr-req-incompat entity)))))
    (:publication-matched
     (and (typep entity 'data-writer)
          (plusp (publication-matched-status-total-count-change (dw-pub-matched entity)))))
    (:offered-incompatible-qos
     (and (typep entity 'data-writer)
          (plusp (offered-incompatible-qos-status-total-count-change (dw-off-incompat entity)))))
    (t nil)))

(defmethod condition-trigger-value ((c status-condition))
  (and (some (lambda (kind) (%status-active-p (sc-entity c) kind)) (sc-mask c)) t))

(declaim (ftype (function () wait-set) make-wait-set))
(defun make-wait-set () (make-instance 'wait-set))

(declaim (ftype (function (wait-set wait-condition) wait-set) attach-condition))
(defun attach-condition (ws c) (pushnew c (ws-conditions ws)) ws)

(declaim (ftype (function (wait-set wait-condition) wait-set) detach-condition))
(defun detach-condition (ws c) (setf (ws-conditions ws) (remove c (ws-conditions ws))) ws)

(declaim (ftype (function (wait-set real) list) wait-set-wait))
(defun wait-set-wait (ws timeout-seconds)
  "WaitSet::wait — block until >=1 attached condition triggers or TIMEOUT-SECONDS
   elapses; return the list of triggered conditions (empty on timeout). v1 polls
   (~10 ms); a receiver-thread-driven condvar wake is a follow-up."
  (let ((deadline (+ (get-internal-real-time)
                     (round (* timeout-seconds internal-time-units-per-second)))))
    (loop
      (let ((triggered (remove-if-not #'condition-trigger-value (ws-conditions ws))))
        (when triggered (return triggered))
        (when (>= (get-internal-real-time) deadline) (return '()))
        (sleep 0.01)))))

(declaim (ftype (function (read-condition) function) %condition-predicate))
(defun %condition-predicate (condition)
  "The sample predicate a ReadCondition imposes on read/take: a QueryCondition's
   QUERY-FN, or %where-any (select all) for a plain ReadCondition."
  (if (typep condition 'query-condition) (qc-query-fn condition) #'%where-any))

(declaim (ftype (function (data-reader read-condition) list) read-w-condition))
(defun read-w-condition (dr condition)
  "DataReader::read_w_condition — non-destructively read the cached samples selected by
   CONDITION (its sample-state mask, plus a QueryCondition's query predicate)."
  (read-samples dr :states (rc-states condition) :where (%condition-predicate condition)))

(declaim (ftype (function (data-reader read-condition) list) take-w-condition))
(defun take-w-condition (dr condition)
  "DataReader::take_w_condition — take (remove) the cached samples selected by CONDITION
   (its sample-state mask, plus a QueryCondition's query predicate)."
  (take-samples dr :states (rc-states condition) :where (%condition-predicate condition)))
