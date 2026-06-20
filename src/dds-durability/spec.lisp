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
   STORE is a 0-arg factory returning a DURABLE-STORE (default: in-memory). MODE is :THREAD or :PROCESS.
   QOS-OVERRIDES is a plist of optional per-service writer/transport overrides:
     :data-representation <list>  — SEDP RxO advertisement (e.g. '(:xcdr1) for foreign interop).
     :relay-durability <keyword>  — DURABILITY for the relay writer; :TRANSIENT-LOCAL (default, byte-identical
                                    to all prior behavior) or :TRANSIENT (opt-in for cross-vendor coexistence,
                                    e.g. to receive from RTI Persistence Service which only replays to TRANSIENT
                                    readers; DURABILITY RxO: offered >= requested, TRANSIENT rank 2 > TL rank 1).
     :collect-durability <keyword> — DURABILITY for the collect reader; :TRANSIENT-LOCAL (default, byte-identical)
                                    or :TRANSIENT (opt-in for cross-vendor coexistence: a foreign persistence
                                    service stamps PID_ORIGINAL_WRITER_INFO only when replaying to a TRANSIENT
                                    reader, so a TRANSIENT collect reader records the OWI logical origin and
                                    collapses the foreign relay's copies against directly-collected samples,
                                    rather than double-recording them under the foreign relay's own wire GUID).
     :peers <list-of-(host . port)> — initial unicast SPDP peers.
     :multicast <boolean>           — when T enables multicast SPDP socket."
  (%make-service-spec :domain domain :topics topics :store store
                      :mode mode :qos-overrides qos-overrides :name name))

(defun* make-persistent-store-factory (&key dir key-dir)
    (function (&key (:dir (or pathname string)) (:key-dir (or pathname string))) function)
  "Return a 0-arg store factory that produces the PERSISTENT-tier secure file-store composition.
   The composed store is: make-encrypted-store(make-file-store(:dir DIR),
   make-file-key-provider(:dir KEY-DIR), :epoch-dir DIR).  Pass this as the :STORE argument
   to MAKE-SERVICE-SPEC to wire the PERSISTENT encrypted-on-disk tier into the service.
   KEY-DIR holds the ML-KEM-1024 keypair (perms enforced 0700 dir / 0600 key, checked at open,
   fail-closed by the key-provider); DIR holds the DARE-sealed topic logs + epochs.dat (DIR's own
   0700 enforcement is a follow-on, ADR 0026 §10). NOTE: :PROCESS service mode does NOT carry this
   factory across the subprocess boundary — use :THREAD mode for the PERSISTENT tier (ADR 0026 §10).
   The returned store requires STORE-OPEN before reads or writes, and STORE-CLOSE to flush
   and fsync the sealed log to disk; calling STORE-CLOSE is mandatory to avoid data loss."
  (let ((d (uiop:ensure-directory-pathname dir))
        (k (uiop:ensure-directory-pathname key-dir)))
    (lambda ()
      (make-encrypted-store (make-file-store :dir d)
                            (dds.dare:make-file-key-provider :dir k)
                            :epoch-dir d))))

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
