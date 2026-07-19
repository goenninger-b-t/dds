(in-package #:dds.durability)

;;; Task 8 — CLI/env entrypoint + subprocess :process mode (ADR 0021 cap. 3, 5).
;;; PURE config surface: parse-durability-config is I/O-free and unit-testable.
;;; Config precedence: CLI argv > env alist/lookup > defaults.
;;; Bounds-check: all network-facing / wire-derived parse paths are explicit manual checks
;;; independent of CL safety level (NFR-SEC-POSTURE).

;;; --- status value (ADR 0064: no conditions — a malformed config is a RETURNED value, not a signal) ---

(defstruct* (durability-config-status (:constructor %make-config-status (message)))
  "A malformed / unknown / missing config argument — the STATUS VALUE threaded out of the config parsers
   (ADR 0064: no Lisp conditions in our code). Was a DURABILITY-CONFIG-ERROR condition that UNWOUND out of
   DURABILITY-SERVICE-MAIN — a toplevel entry point — on a bad CLI arg. MESSAGE is the human-readable
   diagnostic (the config is operator input, so it must name the offending flag/value); the toplevel prints
   it and exits non-zero. Always an explicit manual check, safety-level-independent (NFR-SEC-POSTURE)."
  (message "" :type string))

;; %CONFIG-ERROR is a MACRO, not a function: it expands to (BAIL <status>), a LOCAL non-local return from
;; the enclosing DEFUN* (BAIL is bound by DEFUN* in every body) — NOT a condition, no unwind past the
;; function. Every parse fn is a DEFUN* returning (VALUES result status), so a (%CONFIG-ERROR ...) inside a
;; cond/when/handler-case clause returns (VALUES NIL <status>) from that parse fn, and the caller threads it.
;; A macro emitting BAIL (a return) is fine — the forbidden pattern is a macro emitting a CONDITION.
(defmacro %config-error (fmt &rest args)
  "Return (VALUES NIL <durability-config-status>) from the enclosing DEFUN* with a formatted MESSAGE.
   Explicit, safety-level-independent. Expands to (BAIL (%make-config-status (format nil FMT ARGS...)))."
  `(bail (%make-config-status (format nil ,fmt ,@args))))

(defstruct* (cli-config (:constructor %make-cli-config))
  "The parsed durability-SERVICE CLI/env config bundle %PARSE-ARGV returns as ONE value (so the parser fits
   the (VALUES result status) convention — status threading needs a single result value, and %parse-argv
   otherwise returns eleven). Read by PARSE-DURABILITY-CONFIG. Every field mirrors a %parse-argv return
   (domain/topics/mode/max-restarts/window-seconds/name + the persistence-backend coordinates)."
  (domain 0 :type (integer 0))
  (topics '() :type list)
  (mode :thread :type (member :thread :process))
  (max-restarts 3 :type (integer 0))
  (window-seconds 5 :type (integer 1))
  (name "" :type string)
  (backend nil :type (or null string))
  (ms-host nil :type (or null string))
  (ms-port nil :type (or null (integer 0 65535)))
  (dir nil :type (or null string))
  (key-dir nil :type (or null string)))

;;; --- env lookup ---

(defun* %env-get (env name)
    (function ((or list function) string) (or null string))
  "Return the value of ENV var NAME from ENV.
   ENV may be an alist of (NAME . VALUE) strings or a 1-arg function accepting NAME."
  (etypecase env
    (list     (let ((p (assoc name env :test #'string=))) (if p (cdr p) nil)))
    (function (funcall env name))))

;;; --- topic pair parsing ---

(defun* %parse-topic-pair (token)
    (function (string) (values (or null (cons string string)) (or null durability-config-status)))
  "Parse \"NAME:TYPE\" into (values (NAME . TYPE) NIL), or (values NIL status) on a malformed token
   (no colon / empty name / empty type). Explicit bounds check; returned, never signalled (ADR 0064)."
  (let ((colon (position #\: token)))
    (unless colon
      (%config-error "malformed --topic argument ~s: expected NAME:TYPE (colon separator missing)" token))
    (when (zerop colon)
      (%config-error "malformed --topic argument ~s: topic name must not be empty" token))
    (when (= colon (1- (length token)))
      (%config-error "malformed --topic argument ~s: type name must not be empty" token))
    (values (cons (subseq token 0 colon) (subseq token (1+ colon))) nil)))

(defun* %parse-topics-env (raw)
    (function (string) (values (or null list) (or null durability-config-status)))
  "Parse a comma-separated \"NAME:TYPE,...\" env value into (values ((NAME . TYPE) ...) NIL), or
   (values NIL status) if any token is malformed. A try-loop (not mapcar) so a bad token's status
   propagates instead of being dropped by mapcar's single-value take."
  (let ((parts (loop for start = 0 then (1+ end)
                     for end = (position #\, raw :start start)
                     for tok = (string-trim '(#\Space #\Tab) (subseq raw start (or end (length raw))))
                     unless (zerop (length tok)) collect tok
                     while end)))
    (values (loop for tok in parts collect (try (%parse-topic-pair tok))) nil)))

;;; --- service persistence backend selection (semantics A; ADR 0050 §4.9) ---
;;; --backend {file|sqlite|microservice} selects the durability SERVICE's OWN client-side persistence
;;; store, wired to the shared make-durability-store-factory dispatch (spec.lisp). Distinct from the
;;; reserved --backend server MODE value (semantics B, %durability-server-mode-p) which the pre-parser
;;; intercepts BEFORE this parser — so the two roles never silently collide.

(defun* %default-persistence-dir ()
    (function () string)
  "Default CLIENT-LOCAL DARE directory for --backend microservice when --dir (env DDS_DURABILITY_DIR) is
   omitted: <temporary-directory>/dds-durability/. Only the microservice backend reaches this default — its
   durable records live on the REMOTE server, so the local dir holds only the DARE epoch-dir/key material.
   The file/sqlite backends do NOT fall back here: they REQUIRE --dir (a durable store dir must be named
   explicitly; %SERVICE-STORE-FACTORY errors otherwise — no silent temp-dir data loss)."
  (namestring (merge-pathnames "dds-durability/" (uiop:temporary-directory))))

(defun* %parse-service-backend (source val)
    (function (string (or null string)) (values (or null string) (or null durability-config-status)))
  "Parse VAL into a durability-SERVICE persistence backend: (values \"file\"/\"sqlite\"/\"microservice\" NIL)
   consumed by MAKE-DURABILITY-STORE-FACTORY, or (values NIL status) naming the valid set. SOURCE names the
   origin (a flag or env var) for the message. The reserved value \"server\" is REJECTED here with a steering
   message: it selects the microservice-SERVER MODE (semantics B, ADR 0050 §4.9), which %DURABILITY-SERVER-
   MODE-P intercepts BEFORE this service parser ever runs, so it is not a service persistence backend."
  (cond ((null val) (%config-error "~a requires an argument (one of: file, sqlite, microservice)" source))
        ((string-equal val "file") (values "file" nil))
        ((string-equal val "sqlite") (values "sqlite" nil))
        ((string-equal val "microservice") (values "microservice" nil))
        ((string-equal val "server")
         (%config-error "~a server selects the microservice SERVER mode, not a durability-service persistence backend; run the SERVER with --backend server, or pick a service backend (one of: file, sqlite, microservice)" source))
        (t (%config-error "~a ~s is not a durability-service persistence backend (expected one of: file, sqlite, microservice; 'server' selects the microservice SERVER mode)" source val))))

;;; --- argv tokenizer ---

(defun* %parse-argv (argv env)
    (function (list (or list function))
              (values (or null cli-config) (or null durability-config-status)))
  "Walk ARGV collecting --domain, --topic, --mode, --max-restarts, --window-seconds, --name and the
   persistence-backend flags --backend, --ms-host, --ms-port, --dir, --key-dir (ADR 0050 §4.9, semantics A).
   Returns (values cli-config NIL), or (values NIL status) on an unknown flag / malformed value / missing
   argument — returned, never signalled (ADR 0064). The eleven fields ride in the CLI-CONFIG bundle so this
   fits the (values result status) convention (BACKEND is NIL when neither --backend nor env
   DDS_DURABILITY_BACKEND is given — the DEFAULT-UNCHANGED in-memory path)."
  (let ((domain nil)
        (topics '())
        (mode   nil)
        (max-restarts nil)
        (window-seconds nil)
        (name nil)
        (backend nil)
        (ms-host nil)
        (ms-port nil)
        (dir nil)
        (key-dir nil)
        (rest argv))
    (loop while rest do
      (let ((flag (pop rest)))
        (cond
          ((string= flag "--domain")
           (let ((val (pop rest)))
             (unless val (%config-error "--domain requires an argument"))
             (let ((n (handler-case (parse-integer val)
                        (error () (%config-error "--domain argument ~s is not an integer" val)))))
               (when (minusp n)
                 (%config-error "--domain ~d must be >= 0" n))
               (setf domain n))))
          ((string= flag "--topic")
           (let ((val (pop rest)))
             (unless val (%config-error "--topic requires an argument"))
             (push (try (%parse-topic-pair val)) topics)))
          ((string= flag "--mode")
           (let ((val (pop rest)))
             (unless val (%config-error "--mode requires an argument"))
             (setf mode (cond ((string= val "thread")  :thread)
                              ((string= val "process") :process)
                              (t (%config-error "--mode ~s is not 'thread' or 'process'" val))))))
          ((string= flag "--max-restarts")
           (let ((val (pop rest)))
             (unless val (%config-error "--max-restarts requires an argument"))
             (let ((n (handler-case (parse-integer val)
                        (error () (%config-error "--max-restarts argument ~s is not an integer" val)))))
               (when (minusp n) (%config-error "--max-restarts ~d must be >= 0" n))
               (setf max-restarts n))))
          ((string= flag "--window-seconds")
           (let ((val (pop rest)))
             (unless val (%config-error "--window-seconds requires an argument"))
             (let ((n (handler-case (parse-integer val)
                        (error () (%config-error "--window-seconds argument ~s is not an integer" val)))))
               (when (< n 1) (%config-error "--window-seconds ~d must be >= 1" n))
               (setf window-seconds n))))
          ((string= flag "--name")
           (let ((val (pop rest)))
             (unless val (%config-error "--name requires an argument"))
             (setf name val)))
          ((string= flag "--backend")
           (setf backend (try (%parse-service-backend "--backend" (pop rest)))))
          ((string= flag "--ms-host")
           (let ((val (pop rest)))
             (unless val (%config-error "--ms-host requires an argument"))
             (setf ms-host val)))
          ((string= flag "--ms-port")
           (let ((val (pop rest)))
             (unless val (%config-error "--ms-port requires an argument"))
             (let ((n (handler-case (parse-integer val)
                        (error () (%config-error "--ms-port argument ~s is not an integer" val)))))
               (when (or (minusp n) (> n 65535))
                 (%config-error "--ms-port ~d must be in [0,65535]" n))
               (setf ms-port n))))
          ((string= flag "--dir")
           (let ((val (pop rest)))
             (unless val (%config-error "--dir requires an argument"))
             (setf dir val)))
          ((string= flag "--key-dir")
           (let ((val (pop rest)))
             (unless val (%config-error "--key-dir requires an argument"))
             (setf key-dir val)))
          (t
           (%config-error "unknown flag ~s" flag)))))
    ;; env fallbacks
    (unless domain
      (let ((v (%env-get env "DDS_DURABILITY_DOMAIN")))
        (when v
          (let ((n (handler-case (parse-integer v)
                     (error () (%config-error "env DDS_DURABILITY_DOMAIN ~s is not an integer" v)))))
            (when (minusp n) (%config-error "env DDS_DURABILITY_DOMAIN ~d must be >= 0" n))
            (setf domain n)))))
    (when (null topics)
      (let ((v (%env-get env "DDS_DURABILITY_TOPICS")))
        (when (and v (not (zerop (length v))))
          (setf topics (try (%parse-topics-env v))))))
    (unless mode
      (let ((v (%env-get env "DDS_DURABILITY_MODE")))
        (when v
          (setf mode (cond ((string= v "thread")  :thread)
                           ((string= v "process") :process)
                           (t (%config-error "env DDS_DURABILITY_MODE ~s is not 'thread' or 'process'" v)))))))
    (unless name
      (let ((v (%env-get env "DDS_DURABILITY_NAME")))
        (when (and v (plusp (length v)))
          (setf name v))))
    (unless backend
      (let ((v (%env-get env "DDS_DURABILITY_BACKEND")))
        (when (and v (plusp (length v)))
          (setf backend (try (%parse-service-backend "env DDS_DURABILITY_BACKEND" v))))))
    (unless ms-host
      (let ((v (%env-get env "DDS_DURABILITY_MS_HOST")))
        (when (and v (plusp (length v))) (setf ms-host v))))
    (unless ms-port
      (let ((v (%env-get env "DDS_DURABILITY_MS_PORT")))
        (when v
          (let ((n (handler-case (parse-integer v)
                     (error () (%config-error "env DDS_DURABILITY_MS_PORT ~s is not an integer" v)))))
            (when (or (minusp n) (> n 65535))
              (%config-error "env DDS_DURABILITY_MS_PORT ~d must be in [0,65535]" n))
            (setf ms-port n)))))
    (unless dir
      (let ((v (%env-get env "DDS_DURABILITY_DIR")))
        (when (and v (plusp (length v))) (setf dir v))))
    (unless key-dir
      (let ((v (%env-get env "DDS_DURABILITY_KEY_DIR")))
        (when (and v (plusp (length v))) (setf key-dir v))))
    (values (%make-cli-config :domain (or domain 0)
                              :topics (nreverse topics)
                              :mode (or mode :thread)
                              :max-restarts (or max-restarts 3)
                              :window-seconds (or window-seconds 5)
                              :name (or name "")
                              :backend backend :ms-host ms-host :ms-port ms-port
                              :dir dir :key-dir key-dir)
            nil)))

;;; --- service persistence store-factory (semantics A; ADR 0050 §4.9) ---

(defun* %service-store-factory (backend dir key-dir ms-host ms-port)
    (function ((or null string) (or null string) (or null string)
               (or null string) (or null (integer 0 65535)))
              (values (or null function) (or null durability-config-status)))
  "Return (values factory NIL) — the 0-arg persistence store-factory the durability SERVICE should use for
   BACKEND — or (values NIL status) on a missing REQUIRED coordinate. (values NIL NIL) when
   BACKEND is NIL (the caller then keeps MAKE-SERVICE-SPEC's in-memory default — the DEFAULT-UNCHANGED path,
   no behavior change when --backend is omitted). Reuses the shared MAKE-DURABILITY-STORE-FACTORY dispatch
   (spec.lisp) — it does NOT reimplement backend selection; it only wires the CLI-parsed values into it.
   REQUIRED-ARG discipline (a PERSISTENT backend must name its durable directory — no silent temp fallback,
   mirroring the microservice --ms-port and the SERVER mode's --inner-dir requirements):
     file / sqlite -> DIR is REQUIRED (the on-disk durable store dir); a missing DIR signals
                      DURABILITY-CONFIG-ERROR naming --dir — never a temp-dir fallback that would SILENTLY
                      lose data a reboot / tmpreaper clears;
     microservice  -> MS-PORT is REQUIRED (the remote server; MS-HOST defaults 127.0.0.1); the durable
                      records live on the REMOTE server, so DIR here is only the CLIENT-LOCAL DARE epoch-dir
                      and defaults to %DEFAULT-PERSISTENCE-DIR when omitted.
   KEY-DIR (the ML-KEM-1024 key dir) defaults to DIR/keys/. All checks are explicit + safety-level-independent."
  (if (null backend)
      (values nil nil)
      (let ((ms (string-equal backend "microservice")))
        (when (and ms (null ms-port))
          (%config-error "--backend microservice requires --ms-port (or env DDS_DURABILITY_MS_PORT): the remote microservice server to connect to"))
        (when (and (not ms) (null dir))
          (%config-error "--backend ~a requires --dir (or env DDS_DURABILITY_DIR): a PERSISTENT backend must name its durable store directory (there is no temp-dir fallback)" backend))
        (let* ((d (or dir (%default-persistence-dir)))    ; only microservice reaches the default (client-local DARE epoch-dir)
               (k (or key-dir (namestring (merge-pathnames "keys/" (uiop:ensure-directory-pathname d))))))
          ;; make-durability-store-factory (spec.lisp) returns (VALUES factory :REQUIRES-MS-PORT) on a missing
          ;; ms-port (ADR 0064 — no signal); UNREACHABLE from here (we validated ms-port above), and we take
          ;; only its PRIMARY value (the factory), so the status is a benign NIL on this path.
          (values (make-durability-store-factory backend :dir d :key-dir k :ms-host ms-host :ms-port ms-port)
                  nil)))))

;;; --- public parse entry point (PURE — no I/O) ---

(defun* parse-durability-config (&key (argv '()) (env '()))
    (function (&key (:argv list) (:env (or list function)))
              (values (or null list) (integer 0) (integer 1) (or null durability-config-status)))
  "Parse CLI ARGV + ENV into (values specs max-restarts window-seconds NIL), or (values NIL 0 1 status) on
   malformed / unknown / missing input — RETURNED, never signalled (ADR 0064; DURABILITY-SERVICE-MAIN prints
   the status message and exits non-zero rather than unwinding).
   SPECS is a list of one SERVICE-SPEC (MVP single-service).
   MAX-RESTARTS and WINDOW-SECONDS are the parsed supervisor opts (defaults 3 / 5).
   ARGV is a list of CLI token strings. ENV is an alist of (NAME . VALUE) or a 1-arg fn.
   Precedence: CLI > env > defaults.
   PERSISTENCE BACKEND (semantics A, ADR 0050 §4.9): --backend {file|sqlite|microservice} (env
   DDS_DURABILITY_BACKEND) selects the service's own store via %SERVICE-STORE-FACTORY → the shared
   MAKE-DURABILITY-STORE-FACTORY; --dir/--key-dir/--ms-host/--ms-port supply its coordinates. When --backend
   is omitted the spec keeps MAKE-SERVICE-SPEC's in-memory default (no behavior change). The reserved
   --backend server MODE value (semantics B) is intercepted upstream by %DURABILITY-SERVER-MODE-P and never
   reaches this parser."
  (multiple-value-bind (cfg status) (%parse-argv argv env)
    (when status (return-from parse-durability-config (values nil 0 1 status)))
    (multiple-value-bind (store store-status)
        (%service-store-factory (cli-config-backend cfg) (cli-config-dir cfg) (cli-config-key-dir cfg)
                                (cli-config-ms-host cfg) (cli-config-ms-port cfg))
      (when store-status (return-from parse-durability-config (values nil 0 1 store-status)))
      (values (list (apply #'make-service-spec
                           :domain (cli-config-domain cfg)
                           :topics (cli-config-topics cfg)
                           :mode   (cli-config-mode cfg)
                           :name   (cli-config-name cfg)
                           (when store (list :store store))))
              (cli-config-max-restarts cfg)
              (cli-config-window-seconds cfg)
              nil))))

;;; --- spec -> argv serializer (used by runner for subprocess launch) ---

(defun* %spec->argv (spec)
    (function (service-spec) list)
  "Serialize SPEC to a list of CLI token strings suitable for DURABILITY-SERVICE-MAIN.
   Emits --domain, --mode, --topic* and --name (when non-empty). Predicate topics cannot
   be represented on a command line; :process mode must use explicit cons-list topics."
  (let ((acc (list "--domain" (format nil "~d" (service-spec-domain spec))
                   "--mode" (if (eq (service-spec-mode spec) :process) "process" "thread"))))
    (let ((n (service-spec-name spec)))
      (when (and n (plusp (length n)))
        (setf acc (nconc acc (list "--name" n)))))
    (let ((topics (service-spec-topics spec)))
      (when (listp topics)
        (dolist (pair topics)
          (setf acc (nconc acc (list "--topic"
                                     (format nil "~a:~a" (car pair) (cdr pair))))))))
    acc))

;;; --- signal-driven graceful teardown ---

(defvar *durability-shutdown-requested* nil
  "Set by the SIGTERM/SIGINT handler installed in DURABILITY-SERVICE-MAIN; the block loop polls it.")

(defun* %graceful-shutdown (runner sup)
    (function (service-runner supervisor) t)
  "Orderly teardown: stop supervising (no restarts), then stop the runner (service-stop each service =
   join collect threads THEN close the store + free DARE/arena). Threads are joined before the FFI is
   freed, so nothing is mid-foreign-call at teardown (resolves the kill -15 SIGBUS, ADR 0026 §10)."
  (ignore-errors (supervisor-stop sup))
  (ignore-errors (runner-stop runner))
  t)

;;; --- microservice SERVER mode (ADR 0050 §4.8 follow-on; semantics B: run the KV SERVER) ---
;;; A second DURABILITY-SERVICE-MAIN mode, selected by --backend server, that runs the DARE-blind
;;; persistent microservice SERVER durability clients connect to as their microservice backend — NOT the
;;; collect/serve durability service (the default mode, unchanged). The server-run lifecycle is factored
;;; into ONE %run-microservice-server helper shared with the interop driver-ms-server(-cli) drivers (DRY).

(defstruct* (server-config (:constructor %make-server-config))
  "Parsed microservice-SERVER-mode config (DURABILITY-SERVICE-MAIN --backend server; ADR 0050 §4.8).
   HOST/PORT are the listen coordinates (PORT 0 = ephemeral); INNER-BACKEND/INNER-DIR select the DARE-blind
   persistent inner store; MAX-CONNECTIONS/RECV-TIMEOUT are the Slice-3 server knobs. Built by
   PARSE-DURABILITY-SERVER-CONFIG; consumed by DURABILITY-SERVICE-MAIN -> %RUN-MICROSERVICE-SERVER."
  (host "127.0.0.1" :type string)
  (port 0 :type (integer 0 65535))
  (inner-backend :file :type (member :file :sqlite))
  (inner-dir "" :type string)
  (max-connections +ms-default-max-connections+ :type (integer 1))
  (recv-timeout +ms-default-recv-timeout+ :type (integer 1)))

(defun* %config-parse-int (flag val min)
    (function (string (or null string) integer)
              (values (or null integer) (or null durability-config-status)))
  "Parse VAL (the argument to FLAG) as an integer >= MIN: (values int NIL), or (values NIL status). An
   explicit, safety-level-independent manual check (NFR-SEC-POSTURE) — returned, never signalled (ADR 0064).
   parse-integer's own condition on a non-integer is CONTAINED here (handler-case) and mapped to a status."
  (unless val (%config-error "~a requires an argument" flag))
  (let ((n (handler-case (parse-integer val)
             (error () (%config-error "~a argument ~s is not an integer" flag val)))))
    (when (< n min) (%config-error "~a ~d must be >= ~d" flag n min))
    (values n nil)))

(defun* %parse-inner-backend (source val)
    (function (string (or null string))
              (values (or null (member :file :sqlite)) (or null durability-config-status)))
  "Parse VAL into an inner-store backend keyword: (values (:file|:sqlite) NIL), or (values NIL status).
   SOURCE names the origin (a flag or env var) for the message. Returned, never signalled (ADR 0064)."
  (cond ((null val) (%config-error "~a requires an argument" source))
        ((string-equal val "file") (values :file nil))
        ((string-equal val "sqlite") (values :sqlite nil))
        (t (%config-error "~a ~s is not 'file' or 'sqlite'" source val))))

(defun* %parse-server-argv (argv env)
    (function (list (or list function)) (values (or null server-config) (or null durability-config-status)))
  "Walk server-mode ARGV (+ DDS_DURABILITY_* env fallbacks) into (values SERVER-CONFIG NIL), or
   (values NIL status) on an unknown flag / malformed value / missing --port|--inner-dir. Mirrors
   %parse-argv's flag-loop + env-fallback idiom; returned, never signalled (ADR 0064). Precedence: CLI > env
   > defaults. The --backend server discriminator token is consumed here (it selected this mode)."
  (let ((host nil) (port nil) (inner-backend nil) (inner-dir nil)
        (max-conn nil) (recv-to nil) (rest argv))
    (loop while rest do
      (let ((flag (pop rest)))
        (cond
          ((string= flag "--backend")
           (let ((val (pop rest)))
             (unless (and val (string-equal val "server"))
               (%config-error "--backend ~s is not 'server' (the only --backend value; server mode)" val))))
          ((string= flag "--host")
           (let ((val (pop rest)))
             (unless val (%config-error "--host requires an argument"))
             (setf host val)))
          ((string= flag "--port")
           (let ((n (try (%config-parse-int "--port" (pop rest) 0))))
             (when (> n 65535) (%config-error "--port ~d must be <= 65535" n))
             (setf port n)))
          ((string= flag "--inner-backend")
           (setf inner-backend (try (%parse-inner-backend "--inner-backend" (pop rest)))))
          ((string= flag "--inner-dir")
           (let ((val (pop rest)))
             (unless val (%config-error "--inner-dir requires an argument"))
             (setf inner-dir val)))
          ((string= flag "--max-connections")
           (setf max-conn (try (%config-parse-int "--max-connections" (pop rest) 1))))
          ((string= flag "--recv-timeout")
           (setf recv-to (try (%config-parse-int "--recv-timeout" (pop rest) 1))))
          (t (%config-error "unknown server-mode flag ~s" flag)))))
    (unless host
      (let ((v (%env-get env "DDS_DURABILITY_HOST"))) (when (and v (plusp (length v))) (setf host v))))
    (unless port
      (let ((v (%env-get env "DDS_DURABILITY_PORT")))
        (when v
          (let ((n (try (%config-parse-int "env DDS_DURABILITY_PORT" v 0))))
            (when (> n 65535) (%config-error "env DDS_DURABILITY_PORT ~d must be <= 65535" n))
            (setf port n)))))
    (unless inner-backend
      (let ((v (%env-get env "DDS_DURABILITY_INNER_BACKEND")))
        (when v (setf inner-backend (try (%parse-inner-backend "env DDS_DURABILITY_INNER_BACKEND" v))))))
    (unless inner-dir
      (let ((v (%env-get env "DDS_DURABILITY_INNER_DIR"))) (when (and v (plusp (length v))) (setf inner-dir v))))
    (unless max-conn
      (let ((v (%env-get env "DDS_DURABILITY_MAX_CONNECTIONS")))
        (when v (setf max-conn (try (%config-parse-int "env DDS_DURABILITY_MAX_CONNECTIONS" v 1))))))
    (unless recv-to
      (let ((v (%env-get env "DDS_DURABILITY_RECV_TIMEOUT")))
        (when v (setf recv-to (try (%config-parse-int "env DDS_DURABILITY_RECV_TIMEOUT" v 1))))))
    (unless port
      (%config-error "microservice server mode requires --port (or env DDS_DURABILITY_PORT)"))
    (unless (and inner-dir (plusp (length inner-dir)))
      (%config-error "microservice server mode requires --inner-dir (or env DDS_DURABILITY_INNER_DIR)"))
    (values (%make-server-config :host (or host "127.0.0.1") :port port
                                 :inner-backend (or inner-backend :file) :inner-dir inner-dir
                                 :max-connections (or max-conn +ms-default-max-connections+)
                                 :recv-timeout (or recv-to +ms-default-recv-timeout+))
            nil)))

(defun* parse-durability-server-config (&key (argv '()) (env '()))
    (function (&key (:argv list) (:env (or list function)))
              (values (or null server-config) (or null durability-config-status)))
  "Parse microservice-SERVER-mode CLI ARGV + ENV into (values SERVER-CONFIG NIL), or (values NIL status) on
   any malformed / missing argument — RETURNED, never signalled (ADR 0064; the sibling of
   PARSE-DURABILITY-CONFIG). PURE (no I/O), unit-testable. Selected when --backend server (or env
   DDS_DURABILITY_BACKEND=server) is present. Precedence CLI > env > defaults; --port and --inner-dir are
   REQUIRED (host/inner-backend/max-connections/recv-timeout default)."
  (%parse-server-argv argv env))

(defun* %durability-server-mode-p (argv env)
    (function (list (or list function)) boolean)
  "Return T iff ARGV/ENV select the microservice-SERVER mode: a --backend server token (case-insensitive)
   OR env DDS_DURABILITY_BACKEND=server. Absent -> NIL, so the durability SERVICE (the default) is
   UNCHANGED. Scanned BEFORE PARSE-DURABILITY-CONFIG so the service parser never sees the server flags."
  (if (or (loop for (a b) on argv
                thereis (and (string= a "--backend") b (string-equal b "server")))
          (let ((v (%env-get env "DDS_DURABILITY_BACKEND"))) (and v (string-equal v "server"))))
      t nil))

(defun* %durability-help-requested-p (argv)
    (function (list) boolean)
  "Return T iff ARGV requests help (-h or --help), scanned before either config parser so --help never
   trips an 'unknown flag' error."
  (if (member-if (lambda (a) (or (string= a "--help") (string= a "-h"))) argv) t nil))

(defun* durability-usage ()
    (function () string)
  "The DURABILITY-SERVICE-MAIN usage/help text covering BOTH modes: the default durability SERVICE
   (collect/serve/supervisor, ADR 0021 — including its --backend {file|sqlite|microservice} persistence
   selection, semantics A, ADR 0050 §4.9) and the microservice SERVER mode (--backend server, semantics B,
   ADR 0050 §4.8/§4.9). Documents BOTH roles of --backend: the persistence-backend VALUES and the reserved
   server MODE value. Printed on --help/-h. Kept in lockstep with the CLI flags (operating contract §5.1)."
  (format nil "Usage: durability-service-main [OPTIONS]~%~%~
     Default mode — durability SERVICE (collect + serve TRANSIENT/PERSISTENT durability, ADR 0021):~%~
     ~4t--domain N              DDS domain id (default 0; env DDS_DURABILITY_DOMAIN)~%~
     ~4t--topic NAME:TYPE       a topic to serve (repeatable; env DDS_DURABILITY_TOPICS=NAME:TYPE,...)~%~
     ~4t--mode thread|process   service execution mode (default thread; env DDS_DURABILITY_MODE)~%~
     ~4t--name NAME             service instance name (env DDS_DURABILITY_NAME)~%~
     ~4t--max-restarts N        supervisor restart budget (default 3)~%~
     ~4t--window-seconds N      supervisor restart window seconds (default 5)~%~%~
     ~2tService persistence backend (semantics A, ADR 0050 §4.9) — selects the SERVICE's OWN store; when~%~
     ~2tomitted the service keeps its in-memory default (no behavior change):~%~
     ~4t--backend BACKEND       file | sqlite | microservice (env DDS_DURABILITY_BACKEND); the reserved~%~
     ~29tvalue 'server' instead selects the SERVER mode below (semantics B)~%~
     ~4t--dir DIR               durable store dir — REQUIRED for --backend file|sqlite (no temp fallback;~%~
     ~29ta persistent backend must name its dir); for --backend microservice the~%~
     ~29tclient-local DARE epoch-dir (default <tmp>/dds-durability/); env DDS_DURABILITY_DIR~%~
     ~4t--key-dir DIR           ML-KEM-1024 key dir (default DIR/keys/; env DDS_DURABILITY_KEY_DIR)~%~
     ~4t--ms-host HOST          remote microservice server host (--backend microservice; default~%~
     ~29t127.0.0.1; env DDS_DURABILITY_MS_HOST)~%~
     ~4t--ms-port PORT          remote microservice server port (--backend microservice; REQUIRED for it;~%~
     ~29tenv DDS_DURABILITY_MS_PORT)~%~%~
     Microservice SERVER mode — run the DARE-blind persistent key-value server durability clients~%~
     connect to as their microservice backend (--backend server; env DDS_DURABILITY_BACKEND=server;~%~
     ADR 0050 §4.8). The server stores OPAQUE frames only; the connecting clients hold the DARE keys:~%~
     ~4t--backend server        select server mode (the reserved --backend MODE value; required to enter it)~%~
     ~4t--host HOST             listen host (default 127.0.0.1; env DDS_DURABILITY_HOST)~%~
     ~4t--port PORT             listen port, REQUIRED (env DDS_DURABILITY_PORT)~%~
     ~4t--inner-backend file|sqlite  persistent inner store (default file; env DDS_DURABILITY_INNER_BACKEND)~%~
     ~4t--inner-dir DIR         inner store directory, REQUIRED (env DDS_DURABILITY_INNER_DIR)~%~
     ~4t--max-connections N     concurrent-connection cap (default ~d; env DDS_DURABILITY_MAX_CONNECTIONS)~%~
     ~4t--recv-timeout SECONDS  per-connection idle/read timeout (default ~d; env DDS_DURABILITY_RECV_TIMEOUT)~%~%~
     ~4t-h, --help              print this help and exit~%"
          +ms-default-max-connections+ +ms-default-recv-timeout+))

(defun* %make-server-inner (inner-backend inner-dir)
    (function ((member :file :sqlite) (or pathname string)) durable-store)
  "Build the DARE-BLIND plain PERSISTENT inner store for microservice-SERVER mode (ADR 0050 §4.2/§4.8):
   a make-file-store (append-log-per-topic) or make-sqlite-store on INNER-DIR, opened KEEP_ALL with NO
   DARE key. The server is DARE-blind — it holds only opaque frames; the connecting clients own the DARE
   keys AND retention (the encrypted-store decorator, client-side), so the server MUST stay KEEP_ALL."
  (let ((dir (uiop:ensure-directory-pathname inner-dir)))
    (ecase inner-backend
      (:file   (make-file-store :dir dir :history-kind :keep-all))
      (:sqlite (make-sqlite-store :path (merge-pathnames "durability.sqlite3" dir) :history-kind :keep-all)))))

(defun* %run-microservice-server (&key (host "127.0.0.1") (port 0) (inner-backend :file) (inner-dir "")
                                       (max-connections +ms-default-max-connections+)
                                       (recv-timeout +ms-default-recv-timeout+)
                                       (block t) (stream *standard-output*))
    (function (&key (:host string) (:port (integer 0 65535)) (:inner-backend (member :file :sqlite))
                    (:inner-dir (or pathname string)) (:max-connections (integer 1))
                    (:recv-timeout (or null (real 0))) (:block t) (:stream stream))
              t)
  "Run the durability MICROSERVICE SERVER lifecycle — the ONE shared server-run entrypoint that
   DURABILITY-SERVICE-MAIN's --backend server mode AND the interop driver-ms-server(-cli) drivers all call
   (DRY; ADR 0050 §4.8). Builds the DARE-BLIND persistent inner (%make-server-inner: file/sqlite on
   INNER-DIR, KEEP_ALL, no key), starts make-microservice-server on HOST:PORT (PORT 0 = ephemeral) with
   MAX-CONNECTIONS / RECV-TIMEOUT, and logs a 'MS-SERVER-LISTENING port=P ...' line to STREAM (an operator
   line that is ALSO the interop-harness readiness marker).
   When BLOCK is T (operator / driver): installs a SIGTERM/SIGINT handler (dds.pal:install-signal-handler),
   BLOCKS until a signal, then microservice-server-stop (the clean §4.8 tcp-shutdown wake — no hang, no
   leak), logs 'MS-SERVER-STOPPED port=P ... stopped cleanly', and calls UIOP:QUIT 0. When NIL (in-process /
   testing): returns the running MICROSERVICE-SERVER for the caller to microservice-server-stop itself."
  (let ((srv (handler-case
                 (let ((inner (%make-server-inner inner-backend inner-dir)))
                   (make-microservice-server :host host :port port :inner inner
                                             :max-connections max-connections :recv-timeout recv-timeout))
               (error (c)
                 ;; SECURITY-FAILCLOSED boundary (ADR 0064 rule 2 / ADR 0045): a tamper/corruption refusal
                 ;; at the server's inner store-open is CONTAINED here — logged via *DURABILITY-ERROR-HOOK*,
                 ;; then fail closed (exit non-zero in operator/driver mode, NIL in-process). It never
                 ;; unwinds to the Lisp toplevel. Only STARTUP is wrapped; the serve loop is unchanged.
                 (ignore-errors (funcall *durability-error-hook* c :server-start-failed 1))
                 (if block (uiop:quit 1) (return-from %run-microservice-server nil))))))
    (let ((bound (microservice-server-port srv)))
      (format stream "~&MS-SERVER-LISTENING port=~d — durability microservice server listening (inner: ~(~a~) ~a, host ~a)~%"
              bound inner-backend (uiop:ensure-directory-pathname inner-dir) host)
      (force-output stream)
      (if block
          (let ((stop (list nil)))
            (dds.pal:install-signal-handler '(:term :int) (lambda () (setf (car stop) t)))
            (loop until (car stop) do (sleep 0.2))
            (microservice-server-stop srv)
            (format stream "~&MS-SERVER-STOPPED port=~d — durability microservice server stopped cleanly~%" bound)
            (finish-output stream)
            (uiop:quit 0))
          srv))))

;;; --- main entrypoint ---

(defun* %durability-config-fail (status block)
    (function (durability-config-status t) t)
  "Report a config STATUS at the toplevel (ADR 0064: this is where a malformed CLI/env surfaces as an exit
   code, never an unwind): print its MESSAGE + the usage to *error-output*, then UIOP:QUIT 1 when BLOCK (an
   operator run) or RETURN the STATUS when NIL (an in-process caller / test inspects it)."
  (format *error-output* "~&dds.durability: ~a~%~%~a"
          (durability-config-status-message status) (durability-usage))
  (finish-output *error-output*)
  (if block (uiop:quit 1) status))

(defun* durability-service-main (&key (argv nil) (env '()) (block t))
    (function (&key (:argv (or null list)) (:env (or list function)) (:block t)) t)
  "CLI/env entrypoint for the durability service.
   ARGV defaults to UIOP:COMMAND-LINE-ARGUMENTS when NIL. ENV is an alist or 1-arg fn.
   Parses config (including supervisor opts max-restarts/window-seconds), builds runner+supervisor.
   When BLOCK is T (subprocess body), installs a SIGTERM/SIGINT handler, polls a shutdown flag,
   then tears down in order (supervisor-stop -> runner-stop) and calls UIOP:QUIT 0.
   When NIL, returns (CONS runner sup).
   FAIL-CLOSED START (ADR 0045/0064): if a spec fails to start — a tampered/corrupt store refusing to open
   is the security case — RUNNER-START sheds that spec and returns :SERVICE-START-FAILED; the started specs
   are then torn down (zeroizing their DEKs) and the process fails closed: UIOP:QUIT 1 (BLOCK T, the exit
   code is the ReturnCode_t) or (VALUES (CONS runner sup) status) (BLOCK NIL).

   SERVICE PERSISTENCE BACKEND (semantics A, ADR 0050 §4.9): in the default SERVICE mode,
   --backend {file|sqlite|microservice} (env DDS_DURABILITY_BACKEND) selects the service's own persistence
   store via PARSE-DURABILITY-CONFIG → %SERVICE-STORE-FACTORY → the shared MAKE-DURABILITY-STORE-FACTORY
   (--dir/--key-dir for file/sqlite + the client-local DARE state; --ms-host/--ms-port for the remote
   microservice server). Omitting --backend keeps the in-memory default — no behavior change.

   MICROSERVICE SERVER MODE (semantics B, ADR 0050 §4.8): when --backend server (or env
   DDS_DURABILITY_BACKEND=server) is present, runs the DARE-blind persistent microservice SERVER
   (%RUN-MICROSERVICE-SERVER over PARSE-DURABILITY-SERVER-CONFIG) instead of the durability service — an
   operator-runnable KV server durability clients connect to as their microservice backend. The two
   --backend roles never collide: %DURABILITY-SERVER-MODE-P intercepts the reserved 'server' MODE value
   BEFORE the service parser, so a service backend value (file|sqlite|microservice) reaches semantics A and
   'server' reaches semantics B. --help/-h prints DURABILITY-USAGE. The default (no --backend server)
   durability SERVICE path is UNCHANGED; server mode with BLOCK NIL returns the running MICROSERVICE-SERVER
   (for in-process callers/tests)."
  (let ((effective-argv (or argv (uiop:command-line-arguments))))
    (cond
      ((%durability-help-requested-p effective-argv)
       (write-string (durability-usage) *standard-output*)
       (finish-output *standard-output*)
       (if block (uiop:quit 0) :help))
      ((%durability-server-mode-p effective-argv env)
       (multiple-value-bind (cfg status)
           (parse-durability-server-config :argv (or effective-argv '()) :env env)
         (if status
             (%durability-config-fail status block)   ; ADR 0064: a bad CLI/env is a RETURNED status here, not an unwind
             (%run-microservice-server :host (server-config-host cfg) :port (server-config-port cfg)
                                       :inner-backend (server-config-inner-backend cfg)
                                       :inner-dir (server-config-inner-dir cfg)
                                       :max-connections (server-config-max-connections cfg)
                                       :recv-timeout (server-config-recv-timeout cfg)
                                       :block block))))
      (t
       (multiple-value-bind (specs max-restarts window-seconds status)
           (parse-durability-config :argv (or effective-argv '()) :env env)
         (if status
             (%durability-config-fail status block)   ; ADR 0064: print the message + usage, exit non-zero — never unwind
             (let* ((runner (make-service-runner specs))
                    (sup    (make-supervisor runner
                                            :max-restarts max-restarts
                                            :window-seconds window-seconds)))
               (multiple-value-bind (r start-status) (runner-start runner)
                 (declare (ignore r))
                 (when start-status
                   ;; SECURITY-FAILCLOSED toplevel (ADR 0064/0045): a spec's store-open refused
                   ;; (tamper/corruption). Tear the started specs down (join threads, close stores,
                   ;; zeroize DEKs) and fail closed — the exit code IS the ReturnCode_t (mirrors
                   ;; %durability-config-fail); nothing unwinds to the Lisp toplevel.
                   (ignore-errors (runner-stop runner))
                   (if block
                       (uiop:quit 1)
                       (return-from durability-service-main (values (cons runner sup) start-status)))))
               (supervisor-start sup)
               (if block
                   (progn
                     (setf *durability-shutdown-requested* nil)
                     (dds.pal:install-signal-handler
                      '(:term :int)
                      (lambda () (setf *durability-shutdown-requested* t)))
                     (loop until *durability-shutdown-requested* do (sleep 0.2))
                     (%graceful-shutdown runner sup)
                     (uiop:quit 0))
                   (cons runner sup)))))))))
