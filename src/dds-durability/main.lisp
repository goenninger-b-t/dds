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

;;; --- main entrypoint ---

(defun* durability-service-main (&key (argv nil) (env '()) (block t))
    (function (&key (:argv (or null list)) (:env (or list function)) (:block t)) t)
  "CLI/env entrypoint for the durability service.
   ARGV defaults to UIOP:COMMAND-LINE-ARGUMENTS when NIL. ENV is an alist or 1-arg fn.
   Parses config (including supervisor opts max-restarts/window-seconds), builds runner+supervisor.
   When BLOCK is T (subprocess body), loops until killed. When NIL, returns (CONS runner sup)."
  (let ((effective-argv (or argv (uiop:command-line-arguments))))
    (multiple-value-bind (specs max-restarts window-seconds)
        (parse-durability-config :argv (or effective-argv '()) :env env)
      (let* ((runner (make-service-runner specs))
             (sup    (make-supervisor runner
                                     :max-restarts max-restarts
                                     :window-seconds window-seconds)))
        (runner-start runner)
        (supervisor-start sup)
        (if block
            (loop (sleep 1))
            (cons runner sup))))))
