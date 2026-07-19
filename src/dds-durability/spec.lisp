(in-package #:dds.durability)

;;; service-spec: the discrimination unit owned by a durability service instance.
;;; A service owns a domain + a topic-filter (explicit list or predicate function).

(defstruct* (service-spec (:constructor %make-service-spec))
  "Discrimination unit for a durability service: domain id + topic-filter + store factory + mode.
   TOPICS is either a list of (topic-string . type-string) conses, a (lambda (topic type) …) predicate, or NIL.
   When TOPICS is NIL (empty list), the service matches no topics — non-erroring no-match, distinct from a predicate.
   HISTORY-KIND + HISTORY-DEPTH are the DURABILITY_SERVICE history QoS (DDS 1.4 §2.2.3.5): :keep-all (default,
   byte-identical — no compaction) or :keep-last with DEPTH >= 1 (compaction on file-store + eviction on in-memory).
   AUTO-DISCOVER (ADR 0026 dynamic-topic-add Phase-2b) opts the service into DISCOVERY-DRIVEN auto-serve: when
   non-NIL, service-start also spins a bare SPDP/SEDP discovery node + a poll thread that auto-adds (via the
   idempotent service-add-topic) any newly-discovered remote WRITER topic that passes AUTO-DISCOVER-FILTER, with
   NO explicit add-topic call and NO restart. NIL (default) = the fixed start-list behavior, no observable change when off.
   AUTO-DISCOVER-FILTER guards which discovered topics are served (only consulted when AUTO-DISCOVER is set):
   NIL = match-all, a function = a (lambda (topic-name) …) predicate, a string = a simple name glob (a lone
   trailing #\\* matches any suffix, otherwise an exact string= match; pass a function for richer matching)."
  (domain         0         :type (integer 0))
  (topics         nil       :type (or null list function))
  (store          nil       :type (or null function))
  (mode           :thread   :type (member :thread :process))
  (qos-overrides  nil       :type list)
  (name           ""        :type string)
  (history-kind   :keep-all :type (member :keep-all :keep-last)) ; DURABILITY_SERVICE history_kind (DDS 1.4 §2.2.3.5)
  (history-depth  1         :type (integer 1))                   ; DURABILITY_SERVICE history_depth; KEEP_LAST compaction (file-store) + eviction (in-memory)
  (auto-discover  nil       :type boolean)                       ; opt-in discovery-driven auto-serve (ADR 0026 Phase-2b); NIL (default) = fixed-set, no observable change when off
  (auto-discover-filter nil :type (or null function string)))    ; runtime topic-NAME filter under :auto-discover; NIL = match-all, function = predicate over the name, string = simple name glob (trailing #\* prefix-match, else exact)

(defun* make-service-spec (&key (domain 0) topics
                                (store (lambda () (make-memory-store)))
                                (mode :thread)
                                (qos-overrides nil)
                                (name "")
                                (history-kind  :keep-all)
                                (history-depth 1)
                                (auto-discover nil)
                                (auto-discover-filter nil))
    (function (&key (:domain (integer 0))
                    (:topics (or null list function))
                    (:store (or null function))
                    (:mode (member :thread :process))
                    (:qos-overrides list)
                    (:name string)
                    (:history-kind  (member :keep-all :keep-last))
                    (:history-depth (integer 1))
                    (:auto-discover t)
                    (:auto-discover-filter (or null function string)))
              service-spec)
  "Construct a SERVICE-SPEC for DOMAIN. TOPICS is a list of (topic . type) conses or a predicate function.
   STORE is a 0-arg factory returning a DURABLE-STORE (default: in-memory). MODE is :THREAD or :PROCESS.
   HISTORY-KIND / HISTORY-DEPTH are the DURABILITY_SERVICE history QoS (DDS 1.4 §2.2.3.5): :keep-all
   (default, byte-identical — no compaction) or :keep-last with DEPTH >= 1 (KEEP_LAST per-instance compaction).
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
     :multicast <boolean>           — when T enables multicast SPDP socket.
   AUTO-DISCOVER (default NIL, no observable change when off) opts into discovery-driven auto-serve; AUTO-DISCOVER-FILTER
   (NIL match-all / function predicate over topic-name / string name-glob) gates which discovered topics the
   service auto-adds. Under AUTO-DISCOVER an empty or predicate TOPICS start-list is permitted (the service
   starts serving nothing and auto-adds as matching writers appear); without it, TOPICS must be a non-empty
   concrete (topic . type) list (unchanged)."
  (%make-service-spec :domain domain :topics topics :store store
                      :mode mode :qos-overrides qos-overrides :name name
                      :history-kind history-kind :history-depth history-depth
                      :auto-discover (and auto-discover t)
                      :auto-discover-filter auto-discover-filter))

(defun* make-persistent-store-factory (&key dir key-dir
                                            (history-kind :keep-all) (history-depth 1))
    (function (&key (:dir (or pathname string)) (:key-dir (or pathname string))
                    (:history-kind (member :keep-all :keep-last)) (:history-depth (integer 1)))
              function)
  "Return a 0-arg store factory that produces the PERSISTENT-tier secure file-store composition.
   The composed store is: make-encrypted-store(make-file-store(:dir DIR :history-kind …),
   make-file-key-provider(:dir KEY-DIR), :epoch-dir DIR). Pass this as the :STORE argument
   to MAKE-SERVICE-SPEC to wire the PERSISTENT encrypted-on-disk tier into the service.
   HISTORY-KIND / HISTORY-DEPTH are forwarded to the file-store for compaction-on-open
   (DDS 1.4 §2.2.3.5): :keep-all (default, byte-identical) or :keep-last with DEPTH >= 1.
   KEY-DIR holds the ML-KEM-1024 keypair (perms enforced 0700 dir / 0600 key, checked at open,
   fail-closed by the key-provider); DIR holds the DARE-sealed topic logs + epochs.dat and its own 0700
   perms are ENFORCED fail-closed by the file-store (chmod 0700 on first create, assert-directory-perms-0700
   on reopen; WP-DURABILITY-HARDENING-BATCH, ADR 0026 §10.12). NOTE: :PROCESS service mode does NOT carry this
   factory across the subprocess boundary — use :THREAD mode for the PERSISTENT tier (ADR 0026 §10).
   The returned store requires STORE-OPEN before reads or writes, and STORE-CLOSE to flush
   and fsync the sealed log to disk; calling STORE-CLOSE is mandatory to avoid data loss."
  (let ((d  (uiop:ensure-directory-pathname dir))
        (k  (uiop:ensure-directory-pathname key-dir))
        (hk history-kind)
        (hd history-depth))
    (lambda ()
      (make-encrypted-store (make-file-store :dir d :history-kind hk :history-depth hd)
                            (dds.dare:make-file-key-provider :dir k)
                            :epoch-dir d))))

(defun* make-durability-store-factory (backend &key dir key-dir ms-host ms-port
                                                    (history-kind :keep-all) (history-depth 1))
    (function (string &key (:dir (or pathname string)) (:key-dir (or pathname string))
                      (:ms-host (or null string)) (:ms-port (or null (integer 0 65535)))
                      (:history-kind (member :keep-all :keep-last)) (:history-depth (integer 1)))
              (values (or null function) (or null keyword)))
  "Select+construct the 0-arg durable-store factory for a persistent-tier BACKEND — the single
   backend-dispatch seam the durability-persistent drivers (interop/durability-persistent/driver-collect
   + driver-serve) and the DPERSIST_BACKEND config-env share (DRY: one dispatch, not one per driver).
   BACKEND is case-insensitive (string-equal):
     \"sqlite\"       -> make-sqlite-store-factory (:dir DIR :key-dir KEY-DIR + HISTORY-KIND/DEPTH);
     \"microservice\" -> make-microservice-store-factory — the REMOTE client tier: MS-HOST/MS-PORT
                        address the operator-run reference server (make-microservice-server, a separate
                        process), while DIR / KEY-DIR are the CLIENT-LOCAL DARE epoch-dir / key-dir
                        (the ML-KEM anchor + epochs.dat stay local; the remote server holds only opaque
                        ciphertext). MS-PORT is REQUIRED for this backend; MS-HOST defaults to 127.0.0.1.
                        HISTORY-KIND/DEPTH are NOT construction args here — the microservice inner's
                        history policy is the SERVER's, applied at server-start (ADR 0050 §4.1, Slice 3a);
     anything else   -> make-persistent-store-factory (the file-store default, :dir DIR :key-dir KEY-DIR
                        + HISTORY-KIND/DEPTH).
   Every branch yields the same encrypted-store(inner) 0-arg closure the service-spec :STORE slot consumes;
   the microservice backend needs :THREAD service mode (a factory does not cross a :PROCESS boundary).
   Returns (VALUES FACTORY STATUS): STATUS is NIL on success, or :REQUIRES-MS-PORT when BACKEND is
   \"microservice\" and MS-PORT was omitted (ADR 0064: a config precondition returns a status, never a
   stack unwind — the CLI path validates the port earlier via %config-error, so this is reached only by a
   direct caller / test; a caller taking only the primary FACTORY reads NIL on that miss)."
  (cond
    ((string-equal backend "sqlite")
     (values (make-sqlite-store-factory :dir dir :key-dir key-dir
                                        :history-kind history-kind :history-depth history-depth)
             nil))
    ((string-equal backend "microservice")
     (unless ms-port
       (bail :requires-ms-port))
     (values (make-microservice-store-factory :host (or ms-host "127.0.0.1") :port ms-port
                                              :epoch-dir dir :key-dir key-dir)
             nil))
    (t
     (values (make-persistent-store-factory :dir dir :key-dir key-dir
                                            :history-kind history-kind :history-depth history-depth)
             nil))))

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
