(in-package #:dds.durability)

;;; Task 8 — CLI/env entrypoint + subprocess :process mode (ADR 0021 cap. 3, 5).
;;; PURE config surface: parse-durability-config is I/O-free and unit-testable.
;;; Config precedence: CLI argv > env alist/lookup > defaults.
;;; Bounds-check: all network-facing / wire-derived parse paths are explicit manual checks
;;; independent of CL safety level (NFR-SEC-POSTURE).

;;; --- condition ---

(define-condition durability-config-error (error)
  ((message :initarg :message :reader durability-config-error-message))
  (:report (lambda (c s)
             (format s "dds.durability config error: ~a"
                     (durability-config-error-message c))))
  (:documentation "Signalled by PARSE-DURABILITY-CONFIG on any malformed or unknown argument.
                   Always an explicit manual check; never a safety-0-dependent type dispatch."))

(defun* %config-error (fmt &rest args)
    (function (string &rest t) nil)
  "Signal DURABILITY-CONFIG-ERROR with a formatted message. Explicit, safety-level-independent."
  (error 'durability-config-error
         :message (apply #'format nil fmt args)))

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
    (function (string) (cons string string))
  "Parse \"NAME:TYPE\" into (NAME . TYPE). Explicit bounds check: no colon -> DURABILITY-CONFIG-ERROR."
  (let ((colon (position #\: token)))
    (unless colon
      (%config-error "malformed --topic argument ~s: expected NAME:TYPE (colon separator missing)" token))
    (when (zerop colon)
      (%config-error "malformed --topic argument ~s: topic name must not be empty" token))
    (when (= colon (1- (length token)))
      (%config-error "malformed --topic argument ~s: type name must not be empty" token))
    (cons (subseq token 0 colon) (subseq token (1+ colon)))))

(defun* %parse-topics-env (raw)
    (function (string) list)
  "Parse a comma-separated \"NAME:TYPE,...\" env value into a list of (NAME . TYPE) conses."
  (let ((parts (loop for start = 0 then (1+ end)
                     for end = (position #\, raw :start start)
                     for tok = (string-trim '(#\Space #\Tab) (subseq raw start (or end (length raw))))
                     unless (zerop (length tok)) collect tok
                     while end)))
    (mapcar #'%parse-topic-pair parts)))

;;; --- argv tokenizer ---

(defun* %parse-argv (argv env)
    (function (list (or list function))
              (values (integer 0) list (member :thread :process) (integer 0) (integer 1) string))
  "Walk ARGV collecting --domain, --topic, --mode, --max-restarts, --window-seconds, --name.
   Unknown flags → DURABILITY-CONFIG-ERROR. Returns 6 values:
   (domain topics mode max-restarts window-seconds name)."
  (let ((domain nil)
        (topics '())
        (mode   nil)
        (max-restarts nil)
        (window-seconds nil)
        (name nil)
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
             (push (%parse-topic-pair val) topics)))
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
          (setf topics (%parse-topics-env v)))))
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
    (values (or domain 0)
            (nreverse topics)
            (or mode :thread)
            (or max-restarts 3)
            (or window-seconds 5)
            (or name ""))))

;;; --- public parse entry point (PURE — no I/O) ---

(defun* parse-durability-config (&key (argv '()) (env '()))
    (function (&key (:argv list) (:env (or list function)))
              (values list (integer 0) (integer 1)))
  "Parse CLI ARGV + ENV into (values specs max-restarts window-seconds).
   SPECS is a list of one SERVICE-SPEC (MVP single-service).
   MAX-RESTARTS and WINDOW-SECONDS are the parsed supervisor opts (defaults 3 / 5).
   ARGV is a list of CLI token strings. ENV is an alist of (NAME . VALUE) or a 1-arg fn.
   Precedence: CLI > env > defaults. Signals DURABILITY-CONFIG-ERROR on malformed input."
  (multiple-value-bind (domain topics mode max-restarts window-seconds name)
      (%parse-argv argv env)
    (values (list (make-service-spec
                   :domain domain
                   :topics topics
                   :mode   mode
                   :name   name))
            max-restarts
            window-seconds)))

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
    (function (string (or null string) integer) integer)
  "Parse VAL (the argument to FLAG) as an integer >= MIN, else DURABILITY-CONFIG-ERROR. An explicit,
   safety-level-independent manual check (NFR-SEC-POSTURE) — the server-parser sibling of %parse-argv's
   inline integer guards, factored so the repeated parse+range check is written once (DRY)."
  (unless val (%config-error "~a requires an argument" flag))
  (let ((n (handler-case (parse-integer val)
             (error () (%config-error "~a argument ~s is not an integer" flag val)))))
    (when (< n min) (%config-error "~a ~d must be >= ~d" flag n min))
    n))

(defun* %parse-inner-backend (source val)
    (function (string (or null string)) (member :file :sqlite))
  "Parse VAL into an inner-store backend keyword (:file / :sqlite), else DURABILITY-CONFIG-ERROR.
   SOURCE names the origin (a flag or env var) for the message."
  (cond ((null val) (%config-error "~a requires an argument" source))
        ((string-equal val "file") :file)
        ((string-equal val "sqlite") :sqlite)
        (t (%config-error "~a ~s is not 'file' or 'sqlite'" source val))))

(defun* %parse-server-argv (argv env)
    (function (list (or list function)) server-config)
  "Walk server-mode ARGV (+ DDS_DURABILITY_* env fallbacks) into a SERVER-CONFIG. Mirrors %parse-argv's
   flag-loop + env-fallback + %config-error idiom (no divergent CLI framework). The --backend server
   discriminator token is consumed here (it selected this mode). Unknown flags, malformed values, and a
   missing --port / --inner-dir all signal DURABILITY-CONFIG-ERROR (explicit checks, safety-independent).
   Precedence: CLI > env > defaults."
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
           (let ((n (%config-parse-int "--port" (pop rest) 0)))
             (when (> n 65535) (%config-error "--port ~d must be <= 65535" n))
             (setf port n)))
          ((string= flag "--inner-backend")
           (setf inner-backend (%parse-inner-backend "--inner-backend" (pop rest))))
          ((string= flag "--inner-dir")
           (let ((val (pop rest)))
             (unless val (%config-error "--inner-dir requires an argument"))
             (setf inner-dir val)))
          ((string= flag "--max-connections")
           (setf max-conn (%config-parse-int "--max-connections" (pop rest) 1)))
          ((string= flag "--recv-timeout")
           (setf recv-to (%config-parse-int "--recv-timeout" (pop rest) 1)))
          (t (%config-error "unknown server-mode flag ~s" flag)))))
    (unless host
      (let ((v (%env-get env "DDS_DURABILITY_HOST"))) (when (and v (plusp (length v))) (setf host v))))
    (unless port
      (let ((v (%env-get env "DDS_DURABILITY_PORT")))
        (when v
          (let ((n (%config-parse-int "env DDS_DURABILITY_PORT" v 0)))
            (when (> n 65535) (%config-error "env DDS_DURABILITY_PORT ~d must be <= 65535" n))
            (setf port n)))))
    (unless inner-backend
      (let ((v (%env-get env "DDS_DURABILITY_INNER_BACKEND")))
        (when v (setf inner-backend (%parse-inner-backend "env DDS_DURABILITY_INNER_BACKEND" v)))))
    (unless inner-dir
      (let ((v (%env-get env "DDS_DURABILITY_INNER_DIR"))) (when (and v (plusp (length v))) (setf inner-dir v))))
    (unless max-conn
      (let ((v (%env-get env "DDS_DURABILITY_MAX_CONNECTIONS")))
        (when v (setf max-conn (%config-parse-int "env DDS_DURABILITY_MAX_CONNECTIONS" v 1)))))
    (unless recv-to
      (let ((v (%env-get env "DDS_DURABILITY_RECV_TIMEOUT")))
        (when v (setf recv-to (%config-parse-int "env DDS_DURABILITY_RECV_TIMEOUT" v 1)))))
    (unless port
      (%config-error "microservice server mode requires --port (or env DDS_DURABILITY_PORT)"))
    (unless (and inner-dir (plusp (length inner-dir)))
      (%config-error "microservice server mode requires --inner-dir (or env DDS_DURABILITY_INNER_DIR)"))
    (%make-server-config :host (or host "127.0.0.1") :port port
                         :inner-backend (or inner-backend :file) :inner-dir inner-dir
                         :max-connections (or max-conn +ms-default-max-connections+)
                         :recv-timeout (or recv-to +ms-default-recv-timeout+))))

(defun* parse-durability-server-config (&key (argv '()) (env '()))
    (function (&key (:argv list) (:env (or list function))) server-config)
  "Parse microservice-SERVER-mode CLI ARGV + ENV into a SERVER-CONFIG (ADR 0050 §4.8). PURE (no I/O),
   unit-testable. Selected when --backend server (or env DDS_DURABILITY_BACKEND=server) is present — see
   %DURABILITY-SERVER-MODE-P / DURABILITY-SERVICE-MAIN. Precedence CLI > env > defaults; --port and
   --inner-dir are REQUIRED (host/inner-backend/max-connections/recv-timeout default). Signals
   DURABILITY-CONFIG-ERROR on any malformed or missing argument (the sibling of PARSE-DURABILITY-CONFIG)."
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
   (collect/serve/supervisor, ADR 0021) and the microservice SERVER mode (--backend server, ADR 0050 §4.8).
   Printed on --help/-h. Kept in lockstep with the CLI flags (operating contract §5.1)."
  (format nil "Usage: durability-service-main [OPTIONS]~%~%~
     Default mode — durability SERVICE (collect + serve TRANSIENT/PERSISTENT durability, ADR 0021):~%~
     ~4t--domain N              DDS domain id (default 0; env DDS_DURABILITY_DOMAIN)~%~
     ~4t--topic NAME:TYPE       a topic to serve (repeatable; env DDS_DURABILITY_TOPICS=NAME:TYPE,...)~%~
     ~4t--mode thread|process   service execution mode (default thread; env DDS_DURABILITY_MODE)~%~
     ~4t--name NAME             service instance name (env DDS_DURABILITY_NAME)~%~
     ~4t--max-restarts N        supervisor restart budget (default 3)~%~
     ~4t--window-seconds N      supervisor restart window seconds (default 5)~%~%~
     Microservice SERVER mode — run the DARE-blind persistent key-value server durability clients~%~
     connect to as their microservice backend (--backend server; env DDS_DURABILITY_BACKEND=server;~%~
     ADR 0050 §4.8). The server stores OPAQUE frames only; the connecting clients hold the DARE keys:~%~
     ~4t--backend server        select server mode (required to enter it)~%~
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
  (let* ((inner (%make-server-inner inner-backend inner-dir))
         (srv (make-microservice-server :host host :port port :inner inner
                                        :max-connections max-connections :recv-timeout recv-timeout))
         (bound (microservice-server-port srv)))
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
        srv)))

;;; --- main entrypoint ---

(defun* durability-service-main (&key (argv nil) (env '()) (block t))
    (function (&key (:argv (or null list)) (:env (or list function)) (:block t)) t)
  "CLI/env entrypoint for the durability service.
   ARGV defaults to UIOP:COMMAND-LINE-ARGUMENTS when NIL. ENV is an alist or 1-arg fn.
   Parses config (including supervisor opts max-restarts/window-seconds), builds runner+supervisor.
   When BLOCK is T (subprocess body), installs a SIGTERM/SIGINT handler, polls a shutdown flag,
   then tears down in order (supervisor-stop -> runner-stop) and calls UIOP:QUIT 0.
   When NIL, returns (CONS runner sup).

   MICROSERVICE SERVER MODE (semantics B, ADR 0050 §4.8): when --backend server (or env
   DDS_DURABILITY_BACKEND=server) is present, runs the DARE-blind persistent microservice SERVER
   (%RUN-MICROSERVICE-SERVER over PARSE-DURABILITY-SERVER-CONFIG) instead of the durability service — an
   operator-runnable KV server durability clients connect to as their microservice backend. --help/-h
   prints DURABILITY-USAGE. The default (no --backend server) durability SERVICE path is UNCHANGED; server
   mode with BLOCK NIL returns the running MICROSERVICE-SERVER (for in-process callers/tests)."
  (let ((effective-argv (or argv (uiop:command-line-arguments))))
    (cond
      ((%durability-help-requested-p effective-argv)
       (write-string (durability-usage) *standard-output*)
       (finish-output *standard-output*)
       (if block (uiop:quit 0) :help))
      ((%durability-server-mode-p effective-argv env)
       (let ((cfg (parse-durability-server-config :argv (or effective-argv '()) :env env)))
         (%run-microservice-server :host (server-config-host cfg) :port (server-config-port cfg)
                                   :inner-backend (server-config-inner-backend cfg)
                                   :inner-dir (server-config-inner-dir cfg)
                                   :max-connections (server-config-max-connections cfg)
                                   :recv-timeout (server-config-recv-timeout cfg)
                                   :block block)))
      (t
       (multiple-value-bind (specs max-restarts window-seconds)
           (parse-durability-config :argv (or effective-argv '()) :env env)
         (let* ((runner (make-service-runner specs))
                (sup    (make-supervisor runner
                                        :max-restarts max-restarts
                                        :window-seconds window-seconds)))
           (runner-start runner)
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
               (cons runner sup))))))))
