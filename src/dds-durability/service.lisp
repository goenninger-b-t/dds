(in-package #:dds.durability)

;;; Task 4+5 — durability-service collect + replay path (ADR 0021 slice 2, WP-DURABILITY-SERVICE-TRANSIENT).
;;; Replay model: publish-on-collect.  Each sample the collect loop stores is IMMEDIATELY re-published
;;; through the service's own TRANSIENT_LOCAL KEEP_ALL writer.  That writer's HistoryCache mirrors the
;;; store; the existing TL retention + late-joiner replay machinery (%writer-durability-init, HEARTBEAT /
;;; ACKNACK retransmit) delivers the full pre-join history to any subsequently-discovered TL reader,
;;; even after the ORIGINAL writer is gone.  The service writer publishes under ITS OWN GUID + SNs;
;;; no new wire format is required.  The no-double-delivery case (original writer still alive) is
;;; Phase 2 (virtual-GUID / identity carrier) — do NOT implement here.
;;; MVP scope (Phase 1):
;;;   - ONE topic per service node: the spec's first explicit (topic . type) cons.
;;;     Multi-topic-per-service is a documented Phase-1 follow-up.
;;;   - DATA-kind samples only; :dispose/:unregister capture is a documented limitation
;;;     (the poll API exposes payloads, not change-kind).
;;;   - A predicate-only spec with no concrete (topic . type) signals at service-start.

;;; --- fault injection (test-only, inert by default) ---

(defparameter *durability-debug-start-fault* nil
  "Test-only fault injector. NIL (default) = inert; byte-identical behavior.
   When non-NIL, SERVICE-START raises a condition immediately after building the disc node,
   simulating a service that dies on startup (used by the crash-loop shed sub-test). Never set
   in production code.")

;;; --- error hook ---

(defun* %durability-error-count-p (n)
    (function ((integer 1)) t)
  "T iff N is a positive power of ten: rate-limits the default error hook to O(log n) lines."
  (loop for x of-type (integer 1) = n then (truncate x 10)
        when (= x 1) return t
        when (plusp (mod x 10)) return nil))

(defun* %default-durability-error-hook (condition context count)
    (function (condition t (integer 1)) t)
  "Default *DURABILITY-ERROR-HOOK*: clockless rate-limited WARN to *ERROR-OUTPUT* when COUNT is
   a power of ten (1, 10, 100, …). Mirrors the shape of dds.disc::%default-sender-emit-error-hook."
  (when (%durability-error-count-p count)
    (warn "dds.durability collect loop (~a) error #~d: ~a" context count condition))
  t)

(defparameter *durability-error-hook* #'%default-durability-error-hook
  "Funcallable (CONDITION CONTEXT COUNT) invoked when the collect loop's per-iteration
   handler-case catches an ERROR. CONTEXT tags the call site (keyword); COUNT is the
   running error tally (>= 1). Runs on the collect thread — MUST NOT block. A signalling
   hook is itself swallowed (ignore-errors). Bind to observe collect-loop errors.
   Default = %DEFAULT-DURABILITY-ERROR-HOOK.")

;;; --- durability-service struct ---

(defstruct* (durability-service (:constructor %make-durability-service))
  "Embedded TRANSIENT durability collect service (ADR 0021 slice 2, Phase 2).
   Owns K disc-nodes (one per resolved topic in SPEC); each node has a reliable
   TRANSIENT_LOCAL KEEP_ALL collecting reader + a replay writer + a dedicated collect thread.
   NODES is a list of (node . thread) pairs (K=1 is byte-identical to Phase 1).
   NODE and THREAD are kept for backward compat (process-mode proxy in runner.lisp) and
   single-arity accessor callers; they mirror the first element of NODES after service-start.
   TOPIC-NAMES is an :equal hash-table of registered topic-name strings; guards idempotency in
   service-add-topic by name (time-stable) rather than by the time-varying GUID prefix."
  (spec        nil :type (or null service-spec))
  (store       nil :type (or null durable-store))
  (node        nil :type t)
  (thread      nil :type t)
  (nodes       nil :type list)
  (topic-names (make-hash-table :test #'equal) :type hash-table)
  (lock        (dds.pal:make-lock "dds-durability-service") :type t)
  (running     nil :type t))


;;; --- construction ---

(defun* make-durability-service (spec &key store)
    (function (service-spec &key (:store (or null durable-store))) durability-service)
  "Construct a DURABILITY-SERVICE for SPEC. STORE overrides the spec's store factory
   (pass a shared store in tests); when NIL the factory (service-spec-store spec) is called.
   The service is not started until SERVICE-START is called."
  (let ((s (or store (funcall (service-spec-store spec)))))
    (%make-durability-service :spec spec :store s)))

;;; --- topic resolution ---

(defun* %service-topics (spec)
    (function (service-spec) list)
  "Return the list of (topic-name . type-name) conses to build nodes for.
   List form: returns the explicit list directly (must be non-empty).
   Predicate form: error — a predicate cannot enumerate concrete topics at start time;
   supply an explicit (topic . type) list (dynamic topic-add after start is a documented deferral per design §6).
   Empty list: error — at least one (topic . type) is required."
  (let ((f (service-spec-topics spec)))
    (etypecase f
      (list
       (unless (and (consp f) (consp (car f)))
         (error "dds.durability: service-spec has no explicit (topic . type) cons — ~
                 at least one concrete (topic . type) is required"))
       f)
      (function
       (error "dds.durability: service-spec topics is a predicate — cannot enumerate ~
               concrete topics at service-start (supply an explicit (topic . type) list; ~
               dynamic topic-add after start is a documented deferral per design §6)")))))

;;; --- GUID prefix for the collect node ---

(defun* %collect-node-prefix (spec &optional topic-name)
    (function (service-spec &optional (or null string)) (simple-array (unsigned-byte 8) (12)))
  "Build a 12-byte GUID prefix for one collect node: 'DS' + spec-name hash XOR topic hash + wall clock.
   TOPIC-NAME is mixed in so two nodes in the same multi-topic service get distinct prefixes.
   The wall-clock component makes the prefix TIME-VARYING: do NOT use for idempotency checks.
   Demo-grade (not vetted UUID)."
  (let ((p (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0))
        (clk (get-universal-time))
        (nh  (logxor (sxhash (service-spec-name spec))
                     (if topic-name (sxhash topic-name) 0))))
    (setf (aref p 0) #x44 (aref p 1) #x53)           ; 'D' 'S'
    (loop for i from 2 below 6
          do (setf (aref p i) (logand (ash nh (* -8 (- i 2))) #xff)))
    (loop for i from 6 below 12
          do (setf (aref p i) (logand (ash clk (* -8 (- i 6))) #xff)))
    p))

;;; --- per-origin collect dedup (bounded watermark, mirrors ADR 0024) ---
;;;
;;; Each seen-origins table maps GUID (equalp) -> (cons LO ABOVE-HT) where LO is the
;;; contiguous high-water SN (every SN <= LO is known-delivered) and ABOVE-HT maps
;;; integer SN -> T for out-of-order entries above LO.  Bounded: ABOVE-HT grows at most
;;; *max-gap-range* entries per GUID; pruning after watermark advance keeps memory O(live
;;; origins * *max-gap-range*), not O(total samples delivered).

(defun* %make-collect-origins ()
    (function () hash-table)
  "Return a fresh per-origin dedup table (GUID equalp -> (lo . above-ht))."
  (make-hash-table :test #'equalp))

(defun* %collect-seen-p (origins guid sn)
    (function (hash-table (simple-array (unsigned-byte 8) (*)) integer) t)
  "T iff (GUID SN) is already delivered per ORIGINS (below or equal to watermark, or in above-set)."
  (let ((entry (gethash guid origins)))
    (and entry
         (or (<= sn (car entry))
             (if (gethash sn (cdr entry)) t nil)))))

(defun* %collect-mark-seen! (origins guid sn)
    (function (hash-table (simple-array (unsigned-byte 8) (*)) integer) integer)
  "Record (GUID SN) as delivered in ORIGINS; advance watermark LO through the contiguous
   prefix; prune all ABOVE-HT entries <= new LO so the set stays bounded.
   At-cap (above-ht count > *max-gap-range*) drops the highest above-ht entry to enforce
   the bound — benign for the high out-of-order entry (if it re-arrives it is re-admitted);
   lo never advances past an un-arrived SN so silent loss cannot occur (ADR 0024 §Decision).
   Returns the updated LO for GUID after compaction."
  (let* ((entry (or (gethash guid origins)
                    (let ((e (cons 0 (make-hash-table :test #'eql))))
                      (setf (gethash guid origins) e)
                      e)))
         (lo   (car entry))
         (above (cdr entry)))
    ;; add to above-set if above watermark (never insert <= lo)
    (when (> sn lo)
      (setf (gethash sn above) t))
    ;; at-cap: shed the highest above-set entry (NFR-MEM hard bound)
    (when (> (hash-table-count above) dds.rtps.reliable:*max-gap-range*)
      (let ((hi-key (let ((m lo))
                      (maphash (lambda (k _) (declare (ignore _)) (when (> k m) (setf m k))) above)
                      m)))
        (remhash hi-key above)))
    ;; advance watermark through the contiguous run
    (loop while (gethash (1+ lo) above)
          do (incf lo)
             (remhash lo above))
    (setf (car entry) lo)
    ;; prune any residual below-lo entries from above-set
    (when (plusp lo)
      (maphash (lambda (k _)
                 (declare (ignore _))
                 (when (<= k lo)
                   (remhash k above)))
               above))
    lo))

(defun* %collect-origins-above-size (origins)
    (function (hash-table) integer)
  "Return the total number of entries in all ABOVE-HT tables across all origins in ORIGINS.
   Used by the test harness to assert boundedness (must stay <= *max-gap-range* + small constant)."
  (let ((total 0))
    (maphash (lambda (_ entry)
               (declare (ignore _))
               (incf total (hash-table-count (cdr entry))))
             origins)
    total))

;;; --- collect loop ---

(defun* %collect-loop (svc node topic-name)
    (function (durability-service t string) t)
  "Collect + replay thread body for one disc-node / topic pair.
   Polls NODE for new (GUID . SN) data + lifecycle keys, drains each into the store, and
   IMMEDIATELY re-publishes through the service writer (publish-on-collect model). Lifecycle
   changes (:dispose/:unregister) are stored with their kind and re-emitted via
   publish-relay-lifecycle with PID_ORIGINAL_WRITER_INFO. Tracks seen keys per-origin-GUID
   with a bounded watermark (ADR 0024 carry-forward, NFR-MEM).
   Sleeps ~5 ms between polls. Re-announces SPDP + SEDP every ~1.5 s (RTPS 2.5 §8.5.3.3).
   Wraps each iteration in handler-case so a transient error fires *DURABILITY-ERROR-HOOK*."
  (let ((origins-data (%make-collect-origins))
        (origins-lc   (%make-collect-origins))
        (error-count 0)
        (store (durability-service-store svc))
        (last-announce 0))
    (loop
      (unless (dds.pal:with-lock ((durability-service-lock svc))
                (durability-service-running svc))
        (return))
      (handler-case
          (let ((now (get-internal-real-time)))
            (when (> (- now last-announce)
                     (round (* 1.5 internal-time-units-per-second)))
              (dds.disc:announce-participant node)
              (dds.disc:announce-endpoints node)
              (setf last-announce now))
            ;; drain data samples
            (dolist (key (dds.disc:node-sample-sns node))
              (let ((writer-guid (dds.disc:node-sample-writer-guid node key))
                    (sn (dds.disc:node-sample-key-sn key)))
                (when (and writer-guid
                           (not (%collect-seen-p origins-data writer-guid sn)))
                  (%collect-mark-seen! origins-data writer-guid sn)
                  (let ((payload (dds.disc:node-sample node key)))
                    (when payload
                      (store-put store topic-name writer-guid sn nil :data payload)
                      (dds.disc:publish-relay-sample node payload writer-guid sn))))))
            ;; drain lifecycle changes (dispose / unregister)
            ;; key = (writer-guid . sn); dedup on (writer-guid, sn) via origins-lc watermark
            (dolist (key (dds.disc:node-lifecycle-sns node))
              (let* ((key-guid (car key))
                     (key-sn  (cdr key)))
                (when (not (%collect-seen-p origins-lc key-guid key-sn))
                  (%collect-mark-seen! origins-lc key-guid key-sn)
                  (let ((lc (dds.disc:node-lifecycle-change node key)))
                    (when lc
                      (let* ((kind         (first  lc))
                             (key-hash     (second lc))
                             (status-flags (third  lc))
                             (orig-guid    (fifth  lc))
                             (orig-sn      key-sn)
                             (kh16 (if (and key-hash
                                            (= 16 (length key-hash)))
                                       (coerce key-hash '(simple-array (unsigned-byte 8) (16)))
                                       (make-array 16 :element-type '(unsigned-byte 8)
                                                      :initial-element 0))))
                        (store-put store topic-name orig-guid orig-sn kh16 kind
                                   (make-array 0 :element-type '(unsigned-byte 8)))
                        (dds.disc:publish-relay-lifecycle
                         node kh16 status-flags orig-guid orig-sn))))))))
        (error (c)
          (let ((n (incf error-count)))
            (ignore-errors
             (funcall *durability-error-hook* c :collect-loop n)))))
      ;; group-commit: fsync all open log streams once per drain tick. A sync failure is SURFACED
      ;; via the error hook (not silently swallowed) so a failing disk is observable; the thread
      ;; survives (a transient fsync error must not kill the collect loop) — fail-closed + alive.
      (handler-case (store-sync store)
        (error (c)
          (let ((n (incf error-count)))
            (ignore-errors (funcall *durability-error-hook* c :group-commit n)))))
      (sleep 0.005)))
  t)

;;; --- pre-seed the replay writer from the store on restart ---

(defun* %seed-relay-from-store (node store topic-name)
    (function (dds.disc:disc-node durable-store string) t)
  "Pre-publish all existing records for TOPIC-NAME from STORE through NODE's replay writer.
   Called during service-start after store-open so retained history (e.g. from a prior
   run on disk) populates the TL+KEEP_ALL writer's cache before any late-joiner connects.
   No-op when the store has no records for the topic. The in-memory store is always empty
   at this point, so this is a true no-op for the TRANSIENT tier (byte-identical).
   :timeout from publish-relay-sample/publish-relay-lifecycle: structurally impossible at
   realistic seed volumes. The replay writer is TL+KEEP_ALL with no resource limit on its
   HistoryCache, and during seed-relay there is no matched reader yet so no RTPS sends
   occur — data goes directly into the local history cache without any socket interaction.
   A socket-send timeout cannot trigger without a connected reader, and cache capacity is
   unbounded (KEEP_ALL). The :timeout handler here is a backstop for unforeseen conditions;
   it has never been observed in testing and is not expected to occur. Any other ERROR is
   also routed to *durability-error-hook*."
  (let ((error-count 0))
    (dolist (r (store-get-range store topic-name))
      (let ((result
             (handler-case
                 (if (eq (durable-record-kind r) :data)
                     (dds.disc:publish-relay-sample node
                                                    (durable-record-payload r)
                                                    (durable-record-writer-guid r)
                                                    (durable-record-sn r))
                     (let* ((kh   (or (durable-record-key-hash r)
                                      (make-array 16 :element-type '(unsigned-byte 8)
                                                     :initial-element 0)))
                            (kh16 (coerce kh '(simple-array (unsigned-byte 8) (16))))
                            (sf   (ecase (durable-record-kind r)
                                    (:dispose     1)
                                    (:unregister  2))))
                       (dds.disc:publish-relay-lifecycle node kh16 sf
                                                         (durable-record-writer-guid r)
                                                         (durable-record-sn r))))
               (error (c)
                 c))))
        ;; :timeout = not cached (writer-write rejected); error = unexpected fault — both reported
        (when (or (eq result :timeout) (typep result 'error))
          (let ((n (incf error-count)))
            (ignore-errors
             (funcall *durability-error-hook*
                      (if (typep result 'error)
                          result
                          (make-condition 'simple-error
                                          :format-control "seed-relay :timeout (sn=~d topic=~a)"
                                          :format-arguments (list (durable-record-sn r) topic-name)))
                      :seed-relay n)))))))
  t)

;;; --- service-start ---

(defun* %build-disc-node (spec topic-name type-name)
    (function (service-spec string string) t)
  "Build, configure, and start one disc-node for TOPIC-NAME/TYPE-NAME within SPEC.
   Installs the on-match hook for TL late-joiner replay initialization.
   Honors :relay-durability and :collect-durability from (service-spec-qos-overrides spec): each
   :transient-local (default, byte-identical to prior behavior) or :transient (opt-in for cross-vendor
   coexistence). :collect-durability :transient makes the collect reader pull a foreign persistence
   service's OWI-stamped TRANSIENT replay so its OWI logical origin is recorded and its copies collapse
   against directly-collected samples, instead of double-recording under the foreign relay's wire GUID
   (cross-vendor coexistence, ADR 0026 §10). Returns the started node."
  (let* ((domain (service-spec-domain spec))
         (overrides (service-spec-qos-overrides spec))
         (dr-override       (getf overrides :data-representation))
         (relay-dur         (or (getf overrides :relay-durability) :transient-local))
         (collect-dur       (or (getf overrides :collect-durability) :transient-local))
         (peers-override    (getf overrides :peers))
         (mcast-override    (getf overrides :multicast))
         (node (dds.disc:make-disc-node
                :guid-prefix (%collect-node-prefix spec topic-name)
                :domain domain
                :host "127.0.0.1"
                :port 0
                :peers (or peers-override '())
                :multicast mcast-override)))
    (let ((relay-ep
           (dds.disc:add-local-writer node
                                      :topic topic-name
                                      :type type-name
                                      :qos (apply #'dds.qos:make-writer-qos
                                                  (append (when dr-override
                                                            (list :data-representation dr-override))
                                                          (list :reliability :reliable
                                                                :durability relay-dur))))))
      ;; PID_SERVICE_KIND (0x8003) = PERSISTENCE_SERVICE: gates Connext receiver-side
      ;; PID_ORIGINAL_WRITER_INFO dedup (ADR 0024 Task 8; spike 2026-06-18).
      (setf (dds.rtps.discovery:endpoint-data-service-kind relay-ep)
            dds.rtps.message:+service-kind-persistence+))
    (dds.disc:enable-publisher node :history-kind :keep-all)
    (dds.disc:add-local-reader node
                               :topic topic-name
                               :type type-name
                               :qos (dds.qos:make-reader-qos
                                     :reliability :reliable
                                     :durability collect-dur
                                     :history-kind :keep-all))
    (dds.disc:enable-subscriber node)
    (setf (dds.disc:disc-node-on-match node)
          (lambda (kind remote)
            (when (eq kind :remote-reader)
              (dds.disc:%writer-durability-init
               node
               (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
               (dds.qos:qos-durability (dds.rtps.discovery:endpoint-data-qos remote))))))
    (dds.disc:start-node node)
    node))

(defun* service-start (service)
    (function (durability-service) durability-service)
  "Resolve the spec's topics to K concrete (topic . type) pairs, then for each pair build a
   disc-node (collect reader reliable/TL/keep-all + replay writer) and spawn a collect-loop
   thread.  K=1 is byte-identical to Phase 1.  All K nodes share the same STORE.
   QoS overrides from (service-spec-qos-overrides spec):
     :data-representation <list>  — governs SEDP RxO advertisement; payload forwarded opaque.
     :relay-durability <keyword>  — DURABILITY for the relay writer; :transient-local (default,
                                    byte-identical) or :transient (opt-in for cross-vendor).
     :collect-durability <keyword> — DURABILITY for the collect reader; :transient-local (default,
                                    byte-identical) or :transient (opt-in: pull a foreign persistence
                                    service's OWI-stamped TRANSIENT replay so its origin converges).
     :peers <list-of-(host . port)> — initial unicast SPDP peers; default none.
     :multicast <boolean>         — when T enables multicast SPDP socket; default NIL.
   *DURABILITY-DEBUG-START-FAULT* when non-NIL: after building the first node, signals an
   error simulating startup failure (test-only fault injector; inert by default).
   Note: concurrent-start re-entrancy is guarded at the runner level (runner-start in runner.lisp);
   calling service-start concurrently on the same service instance is a caller error."
  (let* ((spec   (durability-service-spec service))
         (topics (%service-topics spec))
         (nodes  '()))
    ;; open the store: for file-backed tiers this replays logs + re-derives epoch DEKs
    (store-open (durability-service-store service))
    (dds.pal:with-lock ((durability-service-lock service))
      (setf (durability-service-running service) t)
      ;; register all initial topic names so service-add-topic idempotency check covers them
      (dolist (pair topics)
        (setf (gethash (car pair) (durability-service-topic-names service)) t)))
    (dolist (pair topics)
      (let* ((topic-name (car pair))
             (type-name  (cdr pair))
             (node       (%build-disc-node spec topic-name type-name)))
        ;; pre-seed the replay writer with any records already in the store
        (%seed-relay-from-store node (durability-service-store service) topic-name)
        ;; fault injector fires after the first node is built (test-only)
        (when *durability-debug-start-fault*
          (dds.pal:with-lock ((durability-service-lock service))
            (setf (durability-service-running service) nil))
          (ignore-errors (dds.disc:stop-node node))
          (error "dds.durability: *durability-debug-start-fault* is non-NIL — simulated startup failure"))
        (let ((th (dds.pal:spawn
                   (let ((n node) (tn topic-name))
                     (lambda () (%collect-loop service n tn)))
                   :name (format nil "dds-durability-collect(~a)" topic-name))))
          (push (cons node th) nodes))))
    (let ((ordered (nreverse nodes)))
      (dds.pal:with-lock ((durability-service-lock service))
        (setf (durability-service-nodes service) ordered)
        ;; mirror first pair into legacy node/thread slots for backward compat
        (setf (durability-service-node   service) (caar ordered))
        (setf (durability-service-thread service) (cdar ordered))))
    service))

;;; --- service-stop ---

(defun* service-stop (service)
    (function (durability-service) (eql t))
  "Signal all collect loops to stop; for each node: JOIN its collect thread THEN stop-node.
   The join precedes stop-node per node so each loop has fully exited before its socket is
   closed (avoids getsockname EBADF on a final in-flight poll). Idempotent.
   Also handles the process-mode proxy case (single thread in the legacy THREAD slot)."
  (let ((node-pairs nil) (legacy-th nil))
    (dds.pal:with-lock ((durability-service-lock service))
      (setf (durability-service-running service) nil)
      (setf node-pairs (durability-service-nodes service))
      (setf (durability-service-nodes service) nil)
      ;; process-mode proxy stores monitor thread in the legacy thread slot only
      (unless node-pairs
        (setf legacy-th (durability-service-thread service))
        (setf (durability-service-thread service) nil)))
    (if node-pairs
        ;; thread-mode: join+stop per node pair in order
        (dolist (pair node-pairs)
          (let ((th   (cdr pair))
                (node (car pair)))
            (when th   (ignore-errors (dds.pal:join th)))
            (when node (ignore-errors (dds.disc:stop-node node)))))
        ;; process-mode proxy: just join the monitor thread
        (when legacy-th
          (ignore-errors (dds.pal:join legacy-th))))
    (dds.pal:with-lock ((durability-service-lock service))
      (setf (durability-service-thread service) nil))
    ;; close the store: for file-backed tiers this fsyncs logs + frees epoch DEKs
    (ignore-errors (store-close (durability-service-store service))))
  t)

;;; --- service-alive-p ---

(defun* service-alive-p (service)
    (function (durability-service) boolean)
  "T iff the running flag is set and every collect-loop thread is live.
   For thread-mode multi-topic: all K threads in NODES must be non-nil.
   For the process-mode proxy: the single THREAD slot must be non-nil."
  (dds.pal:with-lock ((durability-service-lock service))
    (and (durability-service-running service)
         (let ((pairs (durability-service-nodes service)))
           (if pairs
               (every (lambda (p) (if (cdr p) t nil)) pairs)
               ;; process-mode proxy: use legacy thread slot
               (if (durability-service-thread service) t nil))))))

;;; --- service-add-topic ---

(defun* service-add-topic (service topic-name type-name)
    (function (durability-service string string) (values (eql t) (or null t)))
  "Add TOPIC-NAME/TYPE-NAME to a RUNNING SERVICE without a restart.
   Idempotent by TOPIC-NAME (string=, time-stable) — a duplicate call returns (values T NIL).
   On a fresh add: builds a new disc-node via %BUILD-DISC-NODE, pre-seeds from the store,
   spawns a collect-loop thread, and registers the (node . thread) pair under the lock.
   Returns (values T <new-node>) so callers can use the node without re-deriving the prefix.
   TOCTOU-safe: checks under the first lock, builds outside it (I/O), then re-checks under
   the final lock before push — if the topic appeared concurrently the just-built node is
   stopped and NIL is returned as the node value.
   The collect thread reads RUNNING under the lock on every iteration, so service-stop
   correctly drains and joins the new thread along with all pre-existing ones.
   Caller error: calling on a stopped service (RUNNING=NIL) is undefined — do not."
  (let* ((spec (durability-service-spec service)))
    ;; first check: fast path under lock — O(1) hash lookup
    (dds.pal:with-lock ((durability-service-lock service))
      (when (gethash topic-name (durability-service-topic-names service))
        (return-from service-add-topic (values t nil))))
    ;; build + start the new disc-node (outside the lock: I/O + socket bind)
    (let ((node (%build-disc-node spec topic-name type-name)))
      ;; pre-seed from existing store records (idempotent for empty store)
      (%seed-relay-from-store node (durability-service-store service) topic-name)
      (let ((th (dds.pal:spawn
                 (let ((n node) (tn topic-name))
                   (lambda () (%collect-loop service n tn)))
                 :name (format nil "dds-durability-collect(~a)" topic-name))))
        ;; TOCTOU re-check: register only if topic still absent (concurrent add wins)
        (dds.pal:with-lock ((durability-service-lock service))
          (when (gethash topic-name (durability-service-topic-names service))
            ;; concurrent add won; stop the just-built node and discard it
            (ignore-errors (dds.disc:stop-node node))
            (return-from service-add-topic (values t nil)))
          (setf (gethash topic-name (durability-service-topic-names service)) t)
          (push (cons node th) (durability-service-nodes service)))
        (values t node)))))
