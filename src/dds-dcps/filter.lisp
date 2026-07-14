;;;; DDS 1.4 content-filter / query SQL-subset grammar (M3 #4, FR-DCPS-5). Implements
;;;; Annex B of the DDS 1.4 spec (docs/specs/dds-1_4-dcps.pdf §B.2) for the
;;;; filter_expression of a ContentFilteredTopic and the query_expression of a
;;;; QueryCondition: a lexer + recursive-descent parser + compiler producing a predicate
;;;; closure (lambda (sample) -> boolean). Control-plane (CLOS-free not required); the
;;;; predicate is compiled ONCE at CFT/QueryCondition creation, off the per-sample path.
;;;;
;;;; Grammar (Annex B.2), the filter/query subset:
;;;;   Condition   ::= Predicate | Condition AND Condition | Condition OR Condition
;;;;                 | NOT Condition | '(' Condition ')'
;;;;   Predicate   ::= ComparisonPredicate | BetweenPredicate
;;;;   ComparisonPredicate ::= FIELDNAME RelOp Parameter | Parameter RelOp FIELDNAME
;;;;                         | FIELDNAME RelOp FIELDNAME
;;;;   BetweenPredicate ::= FIELDNAME 'BETWEEN' Range | FIELDNAME 'NOT BETWEEN' Range
;;;;   RelOp       ::= '=' | '>' | '>=' | '<' | '<=' | '<>' | like
;;;;   Range       ::= Parameter 'AND' Parameter
;;;;   Parameter   ::= INTEGERVALUE | CHARVALUE | FLOATVALUE | STRING | ENUMERATEDVALUE | PARAMETER
;;;; v1 scope: single-level FIELDNAMEs (dotted/nested are a later increment); CHARVALUE
;;;; and ENUMERATEDVALUE are lexed as single-quoted strings; '!=' is accepted as a
;;;; synonym for '<>'. LIKE uses SQL wildcards '%' (any sequence) and '_' (one char).
;;;; Precedence (SQL): NOT > AND > OR; parentheses override.

(in-package #:dds.dcps)

(defstruct* (filter-status (:constructor %make-filter-status (code detail)))
  "A lexical / syntactic / field-resolution failure in a filter expression — the STATUS VALUE threaded out
   of the lexer/parser/compiler (ADR 0064: no Lisp conditions in our code; this was a FILTER-ERROR
   condition, and it UNWOUND OUT OF THE DCPS API on user-supplied input — the rule-2 violation with real
   user impact). CODE is a keyword naming the failure (switchable); DETAIL is the human-readable reason
   INCLUDING the offending position/token, which is why the status is a struct and not a bare keyword: a
   filter expression is written by hand, so \"bad-parameter\" with no reason is useless to the person who
   has to fix it. The DCPS API maps CODE to the DDS ReturnCode_t :BAD-PARAMETER and hands this struct back
   alongside it."
  (code :bad-parameter :type keyword)
  (detail "" :type string))

(defun* %fs (code detail)
    (function (keyword string) filter-status)
  "Build a FILTER-STATUS with CODE and DETAIL. The single constructor used by every failure site in the
   filter lexer/parser/compiler, so the shape of a filter failure is defined in exactly one place."
  (%make-filter-status code detail))

;;; ---- Lexer: a filter string -> a list of (TYPE . VALUE) tokens ----

(defun* %whitespace-p (ch)
    (function (character) t)
  "True iff character CH is content-filter SQL lexer whitespace (space, tab, newline, return, page)."
  (member ch '(#\Space #\Tab #\Newline #\Return #\Page)))

;; The lexer helpers carry an EXTRA result — the next input index — so they return
;; (values result status next-index): the status stays in the CONVENTIONAL SECOND position (so TRY and
;; BAIL work on them unchanged) and the index rides along third. A caller that needs the index therefore
;; destructures explicitly instead of using TRY; lex-filter is the only such caller.

(defun* %lex-string (str start n)
    (function (string fixnum fixnum) (values (or null string) (or null filter-status) (or null fixnum)))
  "Lex a single-quoted STRING starting at START (just past the opening quote). Returns
   (values string NIL next-index), or (values NIL status) on an unterminated literal."
  (let ((end (position #\' str :start start :end n)))
    (unless end (bail (%fs :unterminated-string "unterminated string literal")))
    (values (subseq str start end) nil (1+ end))))

(defun* %lex-param (str start n)
    (function (string fixnum fixnum) (values (or null fixnum) (or null filter-status) (or null fixnum)))
  "Lex the digits of a %n PARAMETER starting at START (just past the '%'). Returns
   (values index NIL next-index), or (values NIL status) if no digits follow the '%'."
  (let ((i start))
    (loop while (and (< i n) (digit-char-p (char str i))) do (incf i))
    (when (= i start) (bail (%fs :expected-digits "expected digits after '%'")))
    (values (parse-integer str :start start :end i) nil i)))

(defun* %parse-float (str start end)
    (function (string fixnum fixnum) (values (or null double-float) (or null filter-status)))
  "Parse the validated numeric substring [START,END) as a double-float. Returns
   (values double NIL), or (values NIL status) if it does not read as a real."
  (let ((*read-eval* nil) (*read-default-float-format* 'double-float))
    (let ((v (read-from-string (subseq str start end))))
      (unless (realp v) (bail (%fs :malformed-float "malformed float literal")))
      (values (coerce v 'double-float) nil))))

(defun* %lex-number (str start n)
    (function (string fixnum fixnum) (values (or null cons) (or null filter-status) (or null fixnum)))
  "Lex an INTEGERVALUE (decimal or 0x-hex) or FLOATVALUE starting at START. Returns
   (values token NIL next-index), or (values NIL status)."
  (let ((i start) (sign 1) (floatp nil))
    (when (< i n)
      (case (char str i) (#\+ (incf i)) (#\- (setf sign -1) (incf i))))
    (cond
      ((and (< (1+ i) n) (char= (char str i) #\0) (char-equal (char str (1+ i)) #\x))
       (incf i 2)
       (let ((hs i))
         (loop while (and (< i n) (digit-char-p (char str i) 16)) do (incf i))
         (when (= i hs) (bail (%fs :malformed-hex "malformed hex literal")))
         (values (cons :int (* sign (parse-integer str :start hs :end i :radix 16))) nil i)))
      (t
       (let ((ds i))
         (loop while (and (< i n) (digit-char-p (char str i))) do (incf i))
         (when (and (< i n) (char= (char str i) #\.))
           (setf floatp t) (incf i)
           (loop while (and (< i n) (digit-char-p (char str i))) do (incf i)))
         (when (and (< i n) (char-equal (char str i) #\e))
           (setf floatp t) (incf i)
           (when (and (< i n) (member (char str i) '(#\+ #\-))) (incf i))
           (loop while (and (< i n) (digit-char-p (char str i))) do (incf i)))
         (when (= i ds) (bail (%fs :malformed-number "malformed number")))
         (if floatp
             (values (cons :float (* sign (try (%parse-float str ds i)))) nil i)
             (values (cons :int (* sign (parse-integer str :start ds :end i))) nil i)))))))

(defun* %lex-relop (str i n)
    (function (string fixnum fixnum) (values (or null cons) (or null filter-status) (or null fixnum)))
  "Lex a relational operator (=, >, >=, <, <=, <>, and '!=' as a synonym for <>). Returns
   (values token NIL next-index), or (values NIL status)."
  (let ((c (char str i)) (c2 (when (< (1+ i) n) (char str (1+ i)))))
    (cond
      ((and (char= c #\>) (eql c2 #\=)) (values (cons :relop :>=) nil (+ i 2)))
      ((and (char= c #\<) (eql c2 #\=)) (values (cons :relop :<=) nil (+ i 2)))
      ((and (char= c #\<) (eql c2 #\>)) (values (cons :relop :<>) nil (+ i 2)))
      ((and (char= c #\!) (eql c2 #\=)) (values (cons :relop :<>) nil (+ i 2)))
      ((char= c #\=) (values (cons :relop :=) nil (1+ i)))
      ((char= c #\>) (values (cons :relop :>) nil (1+ i)))
      ((char= c #\<) (values (cons :relop :<) nil (1+ i)))
      (t (bail (%fs :bad-operator (format nil "bad operator at ~d" i)))))))

(defun* %lex-ident (str start n)
    (function (string fixnum fixnum) (values cons null fixnum))
  "Lex an identifier (FIELDNAME, dots allowed) or a reserved keyword (AND/OR/NOT/
   BETWEEN/LIKE, case-insensitive). Cannot fail, but returns the (values token status next-index) shape
   of its sibling lexers (status always NIL) so lex-filter destructures every one of them identically."
  (let ((i start))
    (loop while (and (< i n)
                     (or (alphanumericp (char str i)) (member (char str i) '(#\_ #\.))))
          do (incf i))
    (let ((s (subseq str start i)))
      (values (cond ((string-equal s "AND") (cons :and nil))
                    ((string-equal s "OR") (cons :or nil))
                    ((string-equal s "NOT") (cons :not nil))
                    ((string-equal s "BETWEEN") (cons :between nil))
                    ((string-equal s "LIKE") (cons :like nil))
                    (t (cons :field s)))
              nil
              i))))

(defun* lex-filter (str)
    (function (string) (values (or null list) (or null filter-status)))
  "Tokenize a DDS filter/query expression STR into a list of (TYPE . VALUE) tokens. Returns
   (values tokens NIL), or (values NIL status) on any lexical failure — NEVER signals (ADR 0064)."
  (let ((toks '()) (i 0) (n (length str)))
    (declare (type fixnum i n))
    (macrolet ((lex (form key)   ; run a lexer, propagate its status, push its token, advance the index
                 `(multiple-value-bind (v st ni) ,form
                    (when st (bail st))
                    (push ,key toks)
                    (setf i ni))))
      (loop while (< i n) do
        (let ((ch (char str i)))
          (cond
            ((%whitespace-p ch) (incf i))
            ((char= ch #\() (push (cons :lparen nil) toks) (incf i))
            ((char= ch #\)) (push (cons :rparen nil) toks) (incf i))
            ((char= ch #\') (lex (%lex-string str (1+ i) n) (cons :string v)))
            ((char= ch #\%) (lex (%lex-param str (1+ i) n) (cons :param v)))
            ((or (digit-char-p ch)
                 (and (member ch '(#\+ #\-)) (< (1+ i) n) (digit-char-p (char str (1+ i)))))
             (lex (%lex-number str i n) v))
            ((member ch '(#\= #\< #\> #\!)) (lex (%lex-relop str i n) v))
            ((or (alpha-char-p ch) (char= ch #\_)) (lex (%lex-ident str i n) v))
            (t (bail (%fs :unexpected-character
                          (format nil "unexpected character ~a at ~d" ch i))))))))
    (values (nreverse toks) nil)))

(defun* %lex-single-value (str)
    (function (string) (values t (or null filter-status)))
  "Lex a DDS expression-parameter string STR as exactly one literal value (the value a
   %n placeholder denotes). Returns (values value NIL) — the integer / double-float / string — or
   (values NIL status) if STR is not exactly one literal."
  (let ((toks (try (lex-filter str))))
    (unless (and toks (null (cdr toks)) (member (car (first toks)) '(:int :float :string)))
      (bail (%fs :parameter-not-literal
                 (format nil "parameter ~s is not a single literal" str))))
    (values (cdr (first toks)) nil)))

;;; ---- Value comparison (type-aware; a cross-type comparison yields no match) ----

(defun* %like-match (s pat)
    (function (string string) t)
  "SQL LIKE: match string S against pattern PAT, '%' = any sequence (incl. empty),
   '_' = exactly one character. Iterative two-pointer match with backtracking."
  (let ((slen (length s)) (plen (length pat)) (si 0) (pp 0) (star -1) (mat 0))
    (declare (type fixnum slen plen si pp star mat))
    (loop
      (cond
        ((< si slen)
         (cond
           ((and (< pp plen) (or (char= (char pat pp) #\_) (char= (char pat pp) (char s si))))
            (incf si) (incf pp))
           ((and (< pp plen) (char= (char pat pp) #\%))
            (setf star pp mat si) (incf pp))
           ((>= star 0) (setf pp (1+ star) mat (1+ mat) si mat))
           (t (return nil))))
        (t
         (loop while (and (< pp plen) (char= (char pat pp) #\%)) do (incf pp))
         (return (= pp plen)))))))

(defun* %relop-apply (op a b)
    (function (symbol t t) t)
  "Apply RelOp OP to operand values A and B. Numbers compare numerically, strings
   lexicographically; LIKE matches a string against a pattern. A type mismatch (e.g. a
   number vs a string) is not a match (NIL) — robust for filtering."
  (if (eq op :like)
      (and (stringp a) (stringp b) (%like-match a b) t)
      (cond
        ((and (realp a) (realp b))
         (ecase op (:= (= a b)) (:<> (/= a b)) (:> (> a b)) (:>= (>= a b))
                   (:< (< a b)) (:<= (<= a b))))
        ((and (stringp a) (stringp b))
         (ecase op (:= (string= a b)) (:<> (not (string= a b)))
                   (:> (and (string> a b) t)) (:>= (and (string>= a b) t))
                   (:< (and (string< a b) t)) (:<= (and (string<= a b) t))))
        (t nil))))

;;; ---- Parser + compiler: expression -> predicate closure (lambda (sample) -> bool) ----

(defstruct* (pstate (:constructor make-pstate (rest)))
  "Mutable token-stream state for the content-filter SQL recursive-descent parser (the remaining unconsumed token list)."
  (rest nil :type list))

(defun* compile-filter (expression parameters resolver)
    (function (string list function) (values (or null function) (or null filter-status)))
  "Compile a DDS Annex B filter/query EXPRESSION into a predicate (lambda (sample) ->
   generalized boolean). PARAMETERS are the DDS expression_parameters (strings; a %n
   token denotes PARAMETERS[n], lexed as a literal). RESOLVER maps a FIELDNAME string
   to a unary accessor (sample -> value) or NIL.

   Returns (values predicate NIL), or (values NIL filter-status) on a lexical, syntactic, or
   field-resolution error. It NEVER signals (ADR 0064) — and this is the user-visible half of that rule:
   the expression is USER INPUT, and a FILTER-ERROR condition used to unwind straight out of the DCPS API
   on a typo. Every failure site below is a BAIL, which returns from THIS function; the recursive-descent
   helpers are LABELS lexically inside it, so a failure ten levels deep in the descent needs no threading
   and cannot be dropped by a caller that forgot to check. The predicate is compiled once, off hot path."
  (let ((ps (make-pstate (try (lex-filter expression)))))
    (labels ((peek () (first (pstate-rest ps)))
             (peek-type () (let ((tok (peek))) (and tok (car tok))))
             (pop-tok () (pop (pstate-rest ps)))
             (expect (type)
               (let ((tok (pop-tok)))
                 (unless (and tok (eq (car tok) type))
                   (bail (%fs :unexpected-token (format nil "expected ~a, got ~a" type tok))))
                 tok))
             (operand ()
               (let ((tok (pop-tok)))
                 (unless tok (bail (%fs :unexpected-end "unexpected end of expression")))
                 (ecase (car tok)
                   (:field (let ((acc (funcall resolver (cdr tok))))
                             (unless acc
                               (bail (%fs :unknown-field
                                          (format nil "unknown field ~s" (cdr tok)))))
                             (lambda (s) (funcall acc s))))
                   ((:int :float :string) (let ((v (cdr tok))) (lambda (s) (declare (ignore s)) v)))
                   (:param (let* ((idx (cdr tok))
                                  (pstr (nth idx parameters)))
                             (unless pstr
                               (bail (%fs :missing-parameter
                                          (format nil "no parameter %~d supplied" idx))))
                             (let ((v (try (%lex-single-value pstr))))
                               (lambda (s) (declare (ignore s)) v)))))))
             (parse-between (valfn notp)
               (let ((lo (operand)))
                 (expect :and)
                 (let ((hi (operand)))
                   (lambda (s)
                     (let* ((v (funcall valfn s))
                            (in (and (%relop-apply :>= v (funcall lo s))
                                     (%relop-apply :<= v (funcall hi s)))))
                       (if notp (not in) (and in t)))))))
             (parse-pred ()
               (let ((left (operand)))
                 (case (peek-type)
                   (:between (pop-tok) (parse-between left nil))
                   (:not (pop-tok) (expect :between) (parse-between left t))
                   ((:relop :like)
                    (let* ((optok (pop-tok))
                           (op (if (eq (car optok) :like) :like (cdr optok)))
                           (right (operand)))
                      (lambda (s) (%relop-apply op (funcall left s) (funcall right s)))))
                   (t (bail (%fs :expected-operator
                                 "expected a comparison operator, BETWEEN, or LIKE"))))))
             (parse-primary ()
               (if (eq (peek-type) :lparen)
                   (progn (pop-tok)
                          (let ((c (parse-cond))) (expect :rparen) c))
                   (parse-pred)))
             (parse-not ()
               (if (eq (peek-type) :not)
                   (progn (pop-tok) (let ((c (parse-not))) (lambda (s) (not (funcall c s)))))
                   (parse-primary)))
             (parse-and ()
               (let ((c (parse-not)))
                 (loop while (eq (peek-type) :and)
                       do (pop-tok)
                          (let ((l c) (r (parse-not)))
                            (setf c (lambda (s) (and (funcall l s) (funcall r s))))))
                 c))
             (parse-cond ()
               (let ((c (parse-and)))
                 (loop while (eq (peek-type) :or)
                       do (pop-tok)
                          (let ((l c) (r (parse-and)))
                            (setf c (lambda (s) (or (funcall l s) (funcall r s))))))
                 c)))
      (when (null (pstate-rest ps))
        (bail (%fs :empty-expression "empty filter expression")))
      (let ((pred (parse-cond)))
        (when (pstate-rest ps)
          (bail (%fs :trailing-tokens
                     (format nil "trailing tokens after expression: ~a" (pstate-rest ps)))))
        (values (lambda (sample) (and (funcall pred sample) t)) nil)))))

;;; ---- ContentFilteredTopic (FR-DCPS-5): a TopicDescription over a related Topic +
;;;      a compiled filter predicate; a DataReader created on it filters reader-side. ----

(defclass content-filtered-topic ()
  ((name :initarg :name :reader cft-name)
   (related-topic :initarg :related-topic :reader cft-related-topic)
   (expression :initarg :expression :accessor cft-expression)
   (parameters :initarg :parameters :initform '() :accessor cft-parameters)
   (predicate :initarg :predicate :accessor cft-predicate))
  (:documentation "DDS ContentFilteredTopic (dds_rtf2_dcps.idl §2.2.2.3.3): a related
   Topic + a filter_expression + expression_parameters compiled to a reader-side
   predicate (DDS 1.4 Annex B). For SEDP matching it presents the RELATED topic's
   name/type, so it matches writers on the related topic; the filter is applied in the
   reader drain. v1 filters reader-side only."))

;; A CFT presents the related Topic's name/type/type-support/participant so
;; create-datareader and the drain treat it like its related Topic.
(defmethod topic-name ((cft content-filtered-topic)) (topic-name (cft-related-topic cft)))
(defmethod topic-type-name ((cft content-filtered-topic)) (topic-type-name (cft-related-topic cft)))
(defmethod topic-type-support ((cft content-filtered-topic)) (topic-type-support (cft-related-topic cft)))
(defmethod topic-participant ((cft content-filtered-topic)) (topic-participant (cft-related-topic cft)))

;; The reader applies the CFT's CURRENT predicate, so set_expression_parameters takes
;; effect on already-created DataReaders.
(defmethod td-filter-predicate ((cft content-filtered-topic))
  (lambda (sample) (funcall (cft-predicate cft) sample)))

(defun* create-contentfilteredtopic (participant name related-topic filter-expression
                                    &optional (parameters '()))
    (function (domain-participant string topic string &optional list)
              (values (or null content-filtered-topic) (or null keyword) (or null filter-status)))
  "DomainParticipant::create_contentfilteredtopic — a ContentFilteredTopic named NAME
   over RELATED-TOPIC, filtered by FILTER-EXPRESSION (DDS Annex B) + PARAMETERS. The
   predicate is compiled now against the related topic's type (FR-DCPS-5).

   THIS IS THE TOPLEVEL DDS API BOUNDARY for a filter expression, so it is where the failure becomes a
   ReturnCode_t (ADR 0064). Returns (values cft NIL NIL) on success; on a bad expression,
   (values NIL :BAD-PARAMETER filter-status) — the DDS ReturnCode plus the filter-status whose DETAIL says
   WHICH character/token/field is wrong, because the expression came from a human. Nothing unwinds: a typo
   in a filter string used to signal FILTER-ERROR straight out of this call. The CFT is registered on the
   participant ONLY on success — a rejected expression leaves no half-built child."
  (multiple-value-bind (pred status)
      (compile-filter filter-expression parameters
                      (%field-resolver (topic-type-support related-topic)))
    (when status (return-from create-contentfilteredtopic (values nil :bad-parameter status)))
    (let ((cft (make-instance 'content-filtered-topic
                              :name name :related-topic related-topic
                              :expression filter-expression :parameters parameters
                              :predicate pred)))
      (push cft (dp-children participant))
      (values cft nil nil))))

(defun* set-cft-expression-parameters (cft parameters)
    (function (content-filtered-topic list)
              (values (or null content-filtered-topic) (or null keyword) (or null filter-status)))
  "ContentFilteredTopic::set_expression_parameters — recompile the predicate with new
   PARAMETERS; DataReaders created on CFT pick up the new predicate (they call through
   to CFT's current predicate).

   Returns (values cft NIL NIL), or (values NIL :BAD-PARAMETER filter-status) if the new PARAMETERS do not
   compile. On failure the CFT IS LEFT UNTOUCHED — its existing parameters and predicate stand, so a
   rejected set_expression_parameters cannot leave live DataReaders filtering on a half-applied change.
   (The old code assigned the parameters slot BEFORE compiling, so a throwing compile left the CFT
   describing parameters it was not actually filtering by.)"
  (multiple-value-bind (pred status)
      (compile-filter (cft-expression cft) parameters
                      (%field-resolver (topic-type-support (cft-related-topic cft))))
    (when status (return-from set-cft-expression-parameters (values nil :bad-parameter status)))
    (setf (cft-parameters cft) parameters
          (cft-predicate cft) pred)
    (values cft nil nil)))
