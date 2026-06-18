(in-package #:dds.durability)

;;; service-spec: the discrimination unit owned by a durability service instance.
;;; A service owns a domain + a topic-filter (explicit list or predicate function).

(defstruct* (service-spec (:constructor %make-service-spec))
  "Discrimination unit for a durability service: domain id + topic-filter + store factory + mode.
   TOPICS is either a list of (topic-string . type-string) conses, a (lambda (topic type) …) predicate, or NIL.
   When TOPICS is NIL (empty list), the service matches no topics — non-erroring no-match, distinct from a predicate."
  (domain         0   :type (integer 0))
  (topics         nil :type (or null list function))
  (store          nil :type (or null function))
  (mode           :thread :type (member :thread :process))
  (qos-overrides  nil :type list)
  (name           ""  :type string))

(defun* make-service-spec (&key (domain 0) topics
                                (store (lambda () (make-memory-store)))
                                (mode :thread)
                                (qos-overrides nil)
                                (name ""))
    (function (&key (:domain (integer 0))
                    (:topics (or null list function))
                    (:store (or null function))
                    (:mode (member :thread :process))
                    (:qos-overrides list)
                    (:name string))
              service-spec)
  "Construct a SERVICE-SPEC for DOMAIN. TOPICS is a list of (topic . type) conses or a predicate function.
   STORE is a 0-arg factory returning a DURABLE-STORE (default: in-memory). MODE is :THREAD or :PROCESS."
  (%make-service-spec :domain domain :topics topics :store store
                      :mode mode :qos-overrides qos-overrides :name name))

(defun* service-spec-matches-p (spec topic type)
    (function (service-spec string string) boolean)
  "Return T if TOPIC/TYPE is covered by SPEC's topic-filter.
   List form: exact (topic . type) cons match via string=. Function form: funcall with (topic type).
   When TOPICS is NIL or empty list, returns NIL for every (topic, type) — matches nothing, no error."
  (let ((filter (service-spec-topics spec)))
    (etypecase filter
      (list     (if (find-if (lambda (c) (and (string= (car c) topic)
                                              (string= (cdr c) type)))
                             filter)
                    t nil))
      (function (if (funcall filter topic type) t nil)))))
