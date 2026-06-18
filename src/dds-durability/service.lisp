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
  "Embedded TRANSIENT durability collect service (ADR 0021 slice 2, Phase 1).
   Owns a disc-node with a reliable TRANSIENT_LOCAL KEEP_ALL collecting reader that drains
   received samples (original writer GUID + SN preserved) into STORE on a dedicated thread.
   ONE topic per service node (first explicit (topic . type) in SPEC); DATA kind only."
  (spec   nil :type (or null service-spec))
  (store  nil :type (or null durable-store))
  (node   nil :type t)
  (thread nil :type t)
  (lock   (dds.pal:make-lock "dds-durability-service") :type t)
  (running nil :type t))

;;; --- construction ---

(defun* make-durability-service (spec &key store)
    (function (service-spec &key (:store (or null durable-store))) durability-service)
  "Construct a DURABILITY-SERVICE for SPEC. STORE overrides the spec's store factory
   (pass a shared store in tests); when NIL the factory (service-spec-store spec) is called.
   The service is not started until SERVICE-START is called."
  (let ((s (or store (funcall (service-spec-store spec)))))
    (%make-durability-service :spec spec :store s)))

;;; --- topic resolution ---

(defun* %service-primary-topic (spec)
    (function (service-spec) (values string string))
  "Return (values topic-name type-name) for the first concrete (topic . type) cons in SPEC.
   Signals a clear error when the spec carries only a predicate or empty topics list."
  (let ((f (service-spec-topics spec)))
    (etypecase f
      (list
       (unless (and (consp f) (consp (car f)))
         (error "dds.durability: service-spec has no explicit (topic . type) cons — ~
                 cannot determine the collection topic for this service node (multi-topic is Phase-2)"))
       (values (caar f) (cdar f)))
      (function
       (error "dds.durability: service-spec topics is a predicate — pass an explicit ~
               (topic . type) list or supply :primary-topic (multi-topic is Phase-2)")))))

;;; --- GUID prefix for the collect node ---

(defun* %collect-node-prefix (spec)
    (function (service-spec) (simple-array (unsigned-byte 8) (12)))
  "Build a 12-byte GUID prefix for the collect node: 'DS' + spec name hash + wall clock,
   so distinct service instances and runs get distinct prefixes. Demo-grade (not vetted UUID)."
  (let ((p (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0))
        (clk (get-universal-time))
        (nh (sxhash (service-spec-name spec))))
    (setf (aref p 0) #x44 (aref p 1) #x53)           ; 'D' 'S'
    (loop for i from 2 below 6
          do (setf (aref p i) (logand (ash nh (* -8 (- i 2))) #xff)))
    (loop for i from 6 below 12
          do (setf (aref p i) (logand (ash clk (* -8 (- i 6))) #xff)))
    p))

;;; --- collect loop ---

(defun* %collect-loop (svc topic-name)
    (function (durability-service string) t)
  "Collect + replay thread body: poll the disc-node for new (GUID . SN) sample keys,
   drain each into the store via store-put, and IMMEDIATELY re-publish the payload
   through the service writer (publish-on-collect model — see file header). Tracks seen
   keys locally (belt-and-suspenders on top of store-put's own idempotence). Sleeps ~5 ms
   between polls. Also re-announces SPDP + SEDP every ~1.5 s so foreign participants
   (Connext, Fast DDS) can discover the service via unicast peer or multicast (RTPS 2.5
   §8.5.3.3). Wraps each iteration in handler-case so a transient error fires
   *DURABILITY-ERROR-HOOK* and continues; a SERIOUS-CONDITION is not caught."
  (let ((seen (make-hash-table :test #'equal))
        (error-count 0)
        (node (durability-service-node svc))
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
            (dolist (key (dds.disc:node-sample-sns node))
              (unless (gethash key seen)
                (setf (gethash key seen) t)
                (let ((payload (dds.disc:node-sample node key))
                      (writer-guid (dds.disc:node-sample-writer-guid node key))
                      (sn (dds.disc:node-sample-key-sn key)))
                  (when (and payload writer-guid)
                    (store-put store topic-name writer-guid sn nil :data payload)
                    (dds.disc:publish-sample node payload))))))
        (error (c)
          (let ((n (incf error-count)))
            (ignore-errors
             (funcall *durability-error-hook* c :collect-loop n)))))
      (sleep 0.005)))
  t)

;;; --- service-start ---

(defun* service-start (service)
    (function (durability-service) durability-service)
  "Build the disc-node on the spec's domain, add (1) a reliable TRANSIENT_LOCAL KEEP_ALL
   collecting reader for the spec's first explicit topic and (2) a reliable TRANSIENT_LOCAL
   KEEP_ALL replay writer on the same topic, enable both, start the node, and spawn the
   collect-loop thread.  The writer's HistoryCache mirrors the store via publish-on-collect;
   the shipped TL late-joiner replay delivers it to any subsequently-discovered TL reader
   (DDS 1.4 §2.2.3.4).  MVP: one topic per service node.
   QoS overrides from (service-spec-qos-overrides spec):
     :data-representation <list>  — passed to make-writer-qos; governs SEDP RxO advertisement only;
                                    payload bytes forwarded opaque; default advertises (:xcdr2).
     :peers <list-of-(host . port)> — initial unicast SPDP peers for foreign-participant discovery;
                                    default none (no-op if absent).
     :multicast <boolean>         — when T enables multicast SPDP socket (join 239.255.0.1); default NIL."
  (multiple-value-bind (topic-name type-name)
      (%service-primary-topic (durability-service-spec service))
    (let* ((spec (durability-service-spec service))
           (domain (service-spec-domain spec))
           (overrides (service-spec-qos-overrides spec))
           (dr-override    (getf overrides :data-representation))
           (peers-override (getf overrides :peers))
           (mcast-override (getf overrides :multicast))
           (node (dds.disc:make-disc-node
                  :guid-prefix (%collect-node-prefix spec)
                  :domain domain
                  :host "127.0.0.1"
                  :port 0
                  :peers (or peers-override '())
                  :multicast mcast-override)))
      (dds.disc:add-local-writer node
                                 :topic topic-name
                                 :type type-name
                                 :qos (apply #'dds.qos:make-writer-qos
                                             (append (when dr-override
                                                       (list :data-representation dr-override))
                                                     (list :reliability :reliable
                                                           :durability :transient-local))))
      (dds.disc:enable-publisher node :history-kind :keep-all)
      (dds.disc:add-local-reader node
                                 :topic topic-name
                                 :type type-name
                                 :qos (dds.qos:make-reader-qos
                                       :reliability :reliable
                                       :durability :transient-local
                                       :history-kind :keep-all))
      (dds.disc:enable-subscriber node)
      ;; install the on-match hook: when a remote reader discovers our writer, initialize its
      ;; ReaderProxy durability (TL reader -> replay from firstSN; VOLATILE reader -> future-only).
      (setf (dds.disc:disc-node-on-match node)
            (lambda (kind remote)
              (when (eq kind :remote-reader)
                (dds.disc:%writer-durability-init
                 node
                 (copy-seq (dds.rtps.discovery:endpoint-data-guid remote))
                 (dds.qos:qos-durability (dds.rtps.discovery:endpoint-data-qos remote))))))
      (dds.disc:start-node node)
      (dds.pal:with-lock ((durability-service-lock service))
        (setf (durability-service-node service) node)
        (setf (durability-service-running service) t))
      (when *durability-debug-start-fault*
        (dds.pal:with-lock ((durability-service-lock service))
          (setf (durability-service-running service) nil))
        (ignore-errors (dds.disc:stop-node node))
        (error "dds.durability: *durability-debug-start-fault* is non-NIL — simulated startup failure"))
      (let ((th (dds.pal:spawn (lambda () (%collect-loop service topic-name))
                               :name "dds-durability-collect")))
        (dds.pal:with-lock ((durability-service-lock service))
          (setf (durability-service-thread service) th)))
      service)))

;;; --- service-stop ---

(defun* service-stop (service)
    (function (durability-service) (eql t))
  "Signal the collect loop to stop, JOIN the collect thread, THEN call stop-node. Idempotent.
   The join precedes stop-node so the loop has fully exited (it checks the cleared running flag
   at the top of its next iteration) before the node's socket is closed — otherwise a final
   in-flight poll would hit the just-closed socket (getsockname EBADF) and trip the error guard."
  (let ((th nil) (node nil))
    (dds.pal:with-lock ((durability-service-lock service))
      (setf (durability-service-running service) nil)
      (setf th (durability-service-thread service))
      (setf node (durability-service-node service)))
    (when th
      (ignore-errors (dds.pal:join th)))
    (when node
      (ignore-errors (dds.disc:stop-node node)))
    (dds.pal:with-lock ((durability-service-lock service))
      (setf (durability-service-thread service) nil)))
  t)

;;; --- service-alive-p ---

(defun* service-alive-p (service)
    (function (durability-service) boolean)
  "T iff the collect loop thread is running (the running flag is set and the thread handle is live)."
  (dds.pal:with-lock ((durability-service-lock service))
    (and (durability-service-running service)
         (if (durability-service-thread service) t nil))))
