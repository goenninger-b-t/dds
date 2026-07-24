;;;; The ergonomic logging API (ADR 0082 §5, FR-LOG-3/4): one macro per severity + with-trace-scope,
;;;; over categories with an independent per-category threshold. A DISABLED level costs one AREF at a
;;;; COMPILE-TIME-CONSTANT index plus a comparison and allocates nothing (FR-LOG-4): the category index
;;;; and name are resolved at macroexpansion, and the format call that builds the message sits INSIDE
;;;; the threshold gate, so it runs only when the level is enabled. The function name is captured at
;;;; compile time via dds.lang:current-function-name (the DEFUN* hook); the file best-effort via
;;;; *compile-file-truename*; the line is 0 — a documented NFR-PORT gap (FR-LOG-3), per-impl source-line
;;;; capture is a follow-on. These macros build a LogEvent and hand it to logger-emit (emit.lisp).

(in-package #:net.goenninger.dds.log)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defparameter *log-category-list*
    '(:gen :sup :mem :net :disc :sec :qos :xport :app)
    "The registered log categories, in index order (index = position). :gen (0) is the default/base
     category. A category groups related call sites under one independently-tunable threshold
     (FR-LOG-3). The list is read at MACROEXPANSION to bake a constant index into each log call
     (FR-LOG-4); a dynamic register-your-own-category API is a follow-on (ADR 0082 §9).")

  (defun* %log-category-index (keyword)
      (function (t) (or null (integer 0)))
    "The index of category KEYWORD in *log-category-list*, or NIL if it is not a registered keyword.
     Called at macroexpansion by the log macros to resolve the compile-time-constant AREF index
     (FR-LOG-4). A pure lookup — no side effects, no conditions."
    (and (keywordp keyword) (position keyword *log-category-list*)))

  (defun* %log-source-file ()
      (function () string)
    "The source file being compiled or loaded, as a string, captured at MACROEXPANSION (best-effort,
     FR-LOG-3): *compile-file-truename* under compile-file, else *load-truename* under load, else \"\"
     (e.g. the REPL). The file is the PORTABLE part of source capture; the LINE is the per-impl part and
     is currently 0 — a documented NFR-PORT gap (FR-LOG-3), never a silent zero: per-impl source-line
     capture through the PAL is a follow-on slice."
    (let ((f (or *compile-file-truename* *load-truename*)))
      (if f (namestring f) "")))

  (defun* %expand-log (severity-kw severity-const logger category control args)
      (function (keyword symbol t t t list) t)
    "Build the expansion for a per-severity log macro (FR-LOG-3/4). CATEGORY MUST be a registered
     literal keyword: its index and uppercase name are resolved HERE, at macroexpansion, so the emitted
     code is a threshold gate — (when (<= <severity-const> (aref *log-thresholds* <constant-index>))
     (logger-emit ...)) — whose disabled cost is one AREF at a literal index plus a compare, with the
     message-building FORMAT call inside the gate (no work, no allocation, when the level is off). The
     function name comes from dds.lang:current-function-name (compile-time, the enclosing DEFUN*), the
     file from %log-source-file, the line 0 (the documented NFR-PORT gap)."
    (let ((idx (%log-category-index category)))
      (unless idx
        (error "log macro: CATEGORY must be a registered literal keyword (one of ~s); got ~s."   ; NOCOND(MACRO): macroexpansion-time build rejection
               *log-category-list* category))
      `(when (<= ,severity-const (aref *log-thresholds* ,idx))
         (logger-emit ,logger :severity ,severity-kw
                      :category ,(string-upcase (symbol-name category))
                      :function (current-function-name)
                      :file ,(%log-source-file) :line 0
                      :message ,(if args `(format nil ,control ,@args) control))))))

(defparameter *log-thresholds*
  (make-array (length *log-category-list*) :element-type '(unsigned-byte 8)
              :initial-element +severity-info+)
  "Per-category threshold vector: index -> the MAX severity NUMBER enabled for that category. A log call
   in category C at level L is emitted iff (<= L (aref *log-thresholds* C-index)). Default +severity-info+
   (6): EMERG..INFO emit, DEBUG (7) and TRACE (8) are OFF by default — so a data-plane log call behind a
   default-off level costs one AREF + compare and never allocates (FR-LOG-4). Mutated by
   set-log-threshold; the AREF index in each expanded log call is a compile-time constant.")

(defun* set-log-threshold (category severity)
    (function (keyword (integer 0 8)) (integer 0 8))
  "Set CATEGORY's threshold to SEVERITY (the max severity number emitted): a log call in CATEGORY at
   level L is thereafter emitted iff (<= L SEVERITY). E.g. (set-log-threshold :net +severity-debug+)
   turns DEBUG on for :net. An unregistered CATEGORY is a no-op. Returns SEVERITY. Signals nothing."
  (let ((idx (%log-category-index category)))
    (when idx (setf (aref *log-thresholds* idx) severity))
    severity))

(defun* get-log-threshold (category)
    (function (keyword) (integer 0 8))
  "CATEGORY's current threshold (the max severity number emitted); +severity-info+ for an unregistered
   category. The runtime counterpart of the constant the log macros bake in."
  (let ((idx (%log-category-index category)))
    (if idx (aref *log-thresholds* idx) +severity-info+)))

;;; One macro per severity (FR-LOG-3). Shape: (log-<sev> logger category control &rest format-args).
;;; CONTROL is a format control string; with no ARGS it is the literal message (no format call).
;;; CATEGORY is a registered literal keyword. EMERG..INFO emit by default; DEBUG/TRACE need
;;; set-log-threshold. Each expands through %expand-log to a constant-index threshold gate.

(defmacro log-emerg (logger category control &rest args)
  "Emit an EMERG (RFC 5424 severity 0) log event in CATEGORY via LOGGER (FR-LOG-3). EMERG is never
   suppressed (0 <= every threshold). CONTROL/ARGS are a format control + args, built only if emitted."
  (%expand-log :emerg '+severity-emerg+ logger category control args))

(defmacro log-alert (logger category control &rest args)
  "Emit an ALERT (RFC 5424 severity 1) log event in CATEGORY via LOGGER (FR-LOG-3)."
  (%expand-log :alert '+severity-alert+ logger category control args))

(defmacro log-crit (logger category control &rest args)
  "Emit a CRIT (RFC 5424 severity 2) log event in CATEGORY via LOGGER (FR-LOG-3)."
  (%expand-log :crit '+severity-crit+ logger category control args))

(defmacro log-err (logger category control &rest args)
  "Emit an ERR (RFC 5424 severity 3) log event in CATEGORY via LOGGER (FR-LOG-3)."
  (%expand-log :err '+severity-err+ logger category control args))

(defmacro log-warn (logger category control &rest args)
  "Emit a WARNING (RFC 5424 severity 4, rendered WARN) log event in CATEGORY via LOGGER (FR-LOG-3)."
  (%expand-log :warn '+severity-warn+ logger category control args))

(defmacro log-notice (logger category control &rest args)
  "Emit a NOTICE (RFC 5424 severity 5) log event in CATEGORY via LOGGER (FR-LOG-3)."
  (%expand-log :notice '+severity-notice+ logger category control args))

(defmacro log-info (logger category control &rest args)
  "Emit an INFO (RFC 5424 severity 6) log event in CATEGORY via LOGGER (FR-LOG-3). On by default."
  (%expand-log :info '+severity-info+ logger category control args))

(defmacro log-debug (logger category control &rest args)
  "Emit a DEBUG (RFC 5424 severity 7) log event in CATEGORY via LOGGER (FR-LOG-3). OFF by default —
   enable per category with set-log-threshold; a disabled call costs one AREF + compare, no allocation."
  (%expand-log :debug '+severity-debug+ logger category control args))

(defmacro log-trace (logger category control &rest args)
  "Emit a TRACE (severity 8, this stack's extension below DEBUG) log event in CATEGORY via LOGGER
   (FR-LOG-3). OFF by default; a disabled call costs one AREF + compare, no allocation."
  (%expand-log :trace '+severity-trace+ logger category control args))

(defmacro with-trace-scope ((logger category &optional label) &body body)
  "Run BODY, bracketing it with TRACE entry/exit log events (event-kind :entry / :exit) in CATEGORY via
   LOGGER, the exit carrying the elapsed nanoseconds — but ONLY when TRACE is enabled for CATEGORY. When
   TRACE is OFF (the default), this expands to the threshold check plus BODY and THE CLOCK IS NOT READ
   (FR-LOG-4): no realtime-ns call, no logger-emit, no allocation. LABEL (default the enclosing
   function's name) names the scope in the messages. CATEGORY is a registered literal keyword. Exit is
   logged after BODY's normal return (multiple-value-prog1) — a non-local exit through BODY skips it."
  (let ((idx (%log-category-index category)))
    (unless idx
      (error "with-trace-scope: CATEGORY must be a registered literal keyword (one of ~s); got ~s."   ; NOCOND(MACRO): macroexpansion-time build rejection
             *log-category-list* category))
    (let ((start (gensym "START")) (lbl (gensym "LABEL"))
          (cname (string-upcase (symbol-name category))))
      `(if (<= +severity-trace+ (aref *log-thresholds* ,idx))
           (let ((,lbl ,(or label '(current-function-name)))
                 (,start (dds.pal:realtime-ns)))
             (logger-emit ,logger :severity :trace :category ,cname :event-kind :entry
                          :function (current-function-name) :message (format nil "ENTER ~a" ,lbl))
             (multiple-value-prog1 (progn ,@body)
               (logger-emit ,logger :severity :trace :category ,cname :event-kind :exit
                            :function (current-function-name)
                            :elapsed-ns (max 0 (- (dds.pal:realtime-ns) ,start))
                            :message (format nil "EXIT ~a" ,lbl))))
           (progn ,@body)))))
