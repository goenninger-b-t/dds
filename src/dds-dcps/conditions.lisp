;;;; DDS 1.4 Conditions + WaitSet (M3 #3, FR-DCPS-2). CLOS control-plane. The base
;;;; DDS Condition is named WAIT-CONDITION here to avoid clashing with CL:CONDITION.
;;;; GuardCondition, ReadCondition (sample-state mask), QueryCondition (ReadCondition +
;;;; a query predicate; the DDS SQL-subset expression + parameters are deferred to #4,
;;;; shared with content-filtered topics, FR-DCPS-5), and a StatusCondition over the
;;;; communication statuses. WaitSet::wait is CONDVAR-DRIVEN (ADR 0007): it blocks on a
;;;; per-WaitSet condition variable that the explicit notify points signal — the disc
;;;; receiver thread on new user data (DATA_AVAILABLE), and set_trigger_value for a
;;;; GuardCondition. Each wait is capped at +waitset-wake-cap-seconds+ as a safety net
;;;; (so a missed/spurious wake bounds latency, and rare status changes still surface),
;;;; then re-checks every condition's predicate. Locking discipline (deadlock-free):
;;;; the waiter holds the WaitSet lock across the predicate check AND the atomic
;;;; condvar release (no lost wakeups), and may take the node lock inside %drain; every
;;;; signaler releases all other locks BEFORE taking the WaitSet lock to signal, so no
;;;; thread ever holds node/status-lock while acquiring a WaitSet lock. Single waiter
;;;; per WaitSet (DDS norm); condvar-signal wakes one. v1 assumes conditions are
;;;; created/attached before the wait (single-threaded setup).

(in-package #:dds.dcps)

(defparameter +waitset-wake-cap-seconds+ 0.5
  "Upper bound on a single condvar wait inside WaitSet::wait: with correct signalling
   the wait returns on the signal; the cap only bounds worst-case latency if a signal
   is missed and lets a status-change (which is not explicitly signalled) surface.")

(defclass wait-condition ()
  ((trigger :initform nil :accessor %wc-trigger)
   (wait-sets :initform '() :accessor wc-wait-sets))   ; WaitSets this condition is attached to
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
   (mask :initarg :mask :initform '(:data-available) :accessor sc-mask))
  (:documentation "Triggers when an enabled status named in MASK is active on ENTITY.
   v1 supports :data-available (reader has unread samples) plus the change-driven
   statuses :subscription-matched / :requested-incompatible-qos (reader) and
   :publication-matched / :offered-incompatible-qos (writer) — each active while its
   status has an unread *_change, i.e. until the app calls the matching get_*_status."))

(defclass wait-set ()
  ((conditions :initform '() :accessor ws-conditions)
   (lock :initform (dds.pal:make-lock "wait-set") :accessor ws-lock)
   (cv :initform (dds.pal:make-condvar) :accessor ws-cv))
  (:documentation "DDS WaitSet — a set of conditions to wait on, with a condition
   variable a signaler pulses when an attached condition may have become triggered."))

(defun* %notify-condition (c)
    (function (wait-condition) t)
  "Wake every WaitSet C is attached to: take each WaitSet's lock (holding no other
   lock — see the file header's locking discipline) and signal its condvar. Safe to
   call from the receiver thread or an app thread."
  (dolist (ws (wc-wait-sets c))
    (dds.pal:with-lock ((ws-lock ws))
      (dds.pal:condvar-signal (ws-cv ws))))
  t)

(defun* %notify-reader-conditions (dr)
    (function (data-reader) t)
  "New data arrived for DR: wake the WaitSets of every condition bound to DR (its
   read/query conditions + any reader StatusCondition). Called from the receiver
   thread via the disc ON-SAMPLE hook, holding no node lock."
  (dolist (c (dr-conditions dr)) (%notify-condition c))
  t)

(defun* make-guard-condition ()
    (function () guard-condition)
  "Create a DDS GuardCondition (an app-controlled trigger)."
  (make-instance 'guard-condition))

(defun* set-trigger-value (gc value)
    (function (guard-condition t) t)
  "DDS GuardCondition::set_trigger_value — set the trigger and wake any waiting WaitSet."
  (setf (%wc-trigger gc) (and value t))
  (%notify-condition gc))

(defun* create-readcondition (reader &key (states '(:not-read)))
    (function (data-reader &key (:states list)) read-condition)
  "DataReader::create_readcondition — triggers when samples matching STATES exist."
  (let ((c (make-instance 'read-condition :reader reader :states states)))
    (push c (dr-conditions reader))
    c))

;; Defined in filter.lisp (loaded after this file); forward-declared so the SQL form
;; of create-querycondition can compile a query_expression without a compile warning.
(declaim (ftype (function (string list function) function) compile-filter))

(defun* create-querycondition (reader &key (states '(:not-read)) (query #'%where-any)
                                          expression (parameters '()))
    (function (data-reader &key (:states list) (:query function) (:expression (or null string)) (:parameters list)) query-condition)
  "DataReader::create_querycondition — a ReadCondition that also filters by a query.
   With :EXPRESSION (a DDS Annex B query_expression) + :PARAMETERS (the DDS
   expression_parameters), the query is compiled against the reader's topic type via
   the SQL-subset grammar (FR-DCPS-5); otherwise :QUERY is a Lisp predicate over the
   deserialized sample (%where-any selects all). Triggers / selects only samples whose
   sample-state is in STATES AND that satisfy the query."
  (let* ((qfn (if expression
                  (compile-filter expression parameters
                                  (%field-resolver (topic-type-support (dr-topic reader))))
                  query))
         (c (make-instance 'query-condition :reader reader :states states :query-fn qfn)))
    (push c (dr-conditions reader))
    c))

(defun* make-status-condition (entity &key (mask '(:data-available)))
    (function (entity &key (:mask list)) status-condition)
  "A StatusCondition for ENTITY enabled for the statuses in MASK. A reader-bound status
   condition is registered for the data-arrival wake (its :data-available case)."
  (let ((c (make-instance 'status-condition :entity entity :mask mask)))
    (when (typep entity 'data-reader) (push c (dr-conditions entity)))
    c))

(defun* %default-enabled-statuses (entity)
    (function (entity) list)
  "The default enabled_statuses for ENTITY's StatusCondition — the DDS 1.4 default is the full
   set of communication statuses that apply to the entity kind (dds_rtf2_dcps.idl §684): a
   DataReader's read + reader statuses, a DataWriter's writer statuses, a Topic's
   INCONSISTENT_TOPIC. Kinds whose firing is a later slice (deadline/sample-lost, S4) are
   included so enabling them needs no API change; they simply stay inactive until they fire."
  (typecase entity
    (data-reader '(:data-available :subscription-matched :requested-incompatible-qos
                   :sample-rejected :liveliness-changed :requested-deadline-missed :sample-lost))
    (data-writer '(:publication-matched :offered-incompatible-qos :liveliness-lost
                   :offered-deadline-missed))
    (topic '(:inconsistent-topic))
    (t '())))

(defun* get-statuscondition (entity)
    (function (entity) status-condition)
  "DDS Entity::get_statuscondition (dds_rtf2_dcps.idl §682): ENTITY's own StatusCondition,
   created lazily on first call with all applicable statuses enabled (the DDS default
   enabled_statuses is the full set) and bound to ENTITY's status-changes bitmask. Idempotent —
   subsequent calls return the same object."
  (or (%entity-owned-status-condition entity)
      (setf (%entity-owned-status-condition entity)
            (make-status-condition entity :mask (%default-enabled-statuses entity)))))

(defun* set-enabled-statuses (sc mask)
    (function (status-condition list) status-condition)
  "DDS StatusCondition::set_enabled_statuses (dds_rtf2_dcps.idl §288): restrict which statuses
   (a list of DDS status keywords) make SC trigger. Its trigger becomes the entity's
   status-changes bitmask ∧ MASK (plus the level-based :data-available)."
  (setf (sc-mask sc) mask)
  sc)

(defun* get-enabled-statuses (sc)
    (function (status-condition) list)
  "DDS StatusCondition::get_enabled_statuses (dds_rtf2_dcps.idl §287): the statuses currently
   enabled on SC (a list of DDS status keywords)."
  (sc-mask sc))

(defun* %count-matching (dr states)
    (function (data-reader list) (integer 0))
  "Drain newly-received samples and count those whose sample-state is in STATES."
  (%drain dr)
  (count-if (lambda (cs) (member (sample-info-sample-state (cached-sample-info cs)) states))
            (dr-cache dr)))

(defun* %count-matching-query (dr states query-fn)
    (function (data-reader list function) (integer 0))
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
(defun* %status-active-p (entity kind)
    (function (entity keyword) t)
  "Whether the communication status KIND is currently active on ENTITY (the trigger predicate
   for a StatusCondition). :data-available is level-based on unread samples; every other kind is
   active iff its StatusChangedFlag bit is set in ENTITY's status-changes bitmask — set by the
   %notify-status chokepoint when the status fires, cleared by the matching get_*_status
   (read-communication-status reset, DDS 1.4 §2.2.4.1 / §2.2.2.1.9). This is the entity
   bitmask ∧ the StatusCondition's enabled_statuses (the caller intersects with sc-mask)."
  (if (eq kind :data-available)
      (and (typep entity 'data-reader) (plusp (%count-matching entity '(:not-read))) t)
      (let ((bit (cdr (assoc kind *status-kind->bit*))))
        (and bit (logtest bit (%entity-status-changes entity)) t))))

(defmethod condition-trigger-value ((c status-condition))
  (and (some (lambda (kind) (%status-active-p (sc-entity c) kind)) (sc-mask c)) t))

(defun* make-wait-set ()
    (function () wait-set)
  "Create a DDS WaitSet (a set of conditions to wait on)."
  (make-instance 'wait-set))

(defun* attach-condition (ws c)
    (function (wait-set wait-condition) wait-set)
  "WaitSet::attach_condition — add C to WS and back-link WS onto C (so a notify can
   wake WS). Done at setup, before the wait."
  (dds.pal:with-lock ((ws-lock ws)) (pushnew c (ws-conditions ws)))
  (pushnew ws (wc-wait-sets c))
  ws)

(defun* detach-condition (ws c)
    (function (wait-set wait-condition) wait-set)
  "WaitSet::detach_condition — remove C from WS and unlink WS from C."
  (dds.pal:with-lock ((ws-lock ws)) (setf (ws-conditions ws) (remove c (ws-conditions ws))))
  (setf (wc-wait-sets c) (remove ws (wc-wait-sets c)))
  ws)

(defun* wait-set-wait (ws timeout-seconds)
    (function (wait-set real) list)
  "WaitSet::wait — block until >=1 attached condition triggers or TIMEOUT-SECONDS
   elapses; return the list of triggered conditions (empty on timeout). Condvar-driven
   (ADR 0007): holds the WaitSet lock across each predicate check and the atomic
   condvar wait (no lost wakeup), waking on a signal or after at most
   +waitset-wake-cap-seconds+. Predicate checks may take the node lock inside %drain;
   the lock is released atomically by condvar-wait while blocked."
  (let ((deadline (+ (get-internal-real-time)
                     (round (* timeout-seconds internal-time-units-per-second)))))
    (dds.pal:with-lock ((ws-lock ws))
      (loop
        (let ((triggered (remove-if-not #'condition-trigger-value (ws-conditions ws))))
          (when triggered (return triggered))
          (let ((remaining (/ (- deadline (get-internal-real-time))
                              internal-time-units-per-second)))
            (when (<= remaining 0) (return '()))
            (dds.pal:condvar-wait (ws-cv ws) (ws-lock ws)
                                  (min remaining +waitset-wake-cap-seconds+))))))))

(defun* %condition-predicate (condition)
    (function (read-condition) function)
  "The sample predicate a ReadCondition imposes on read/take: a QueryCondition's
   QUERY-FN, or %where-any (select all) for a plain ReadCondition."
  (if (typep condition 'query-condition) (qc-query-fn condition) #'%where-any))

(defun* read-w-condition (dr condition)
    (function (data-reader read-condition) list)
  "DataReader::read_w_condition — non-destructively read the cached samples selected by
   CONDITION (its sample-state mask, plus a QueryCondition's query predicate)."
  (read-samples dr :states (rc-states condition) :where (%condition-predicate condition)))

(defun* take-w-condition (dr condition)
    (function (data-reader read-condition) list)
  "DataReader::take_w_condition — take (remove) the cached samples selected by CONDITION
   (its sample-state mask, plus a QueryCondition's query predicate)."
  (take-samples dr :states (rc-states condition) :where (%condition-predicate condition)))
