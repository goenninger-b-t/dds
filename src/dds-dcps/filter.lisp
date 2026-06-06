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

(define-condition filter-error (error)
  ((detail :initarg :detail :initform "" :reader filter-error-detail))
  (:report (lambda (c s) (format s "DDS filter error: ~a" (filter-error-detail c))))
  (:documentation "A lexical/syntactic/field-resolution error in a filter expression."))

;;; ---- Lexer: a filter string -> a list of (TYPE . VALUE) tokens ----

(declaim (ftype (function (character) t) %whitespace-p))
(defun %whitespace-p (ch)
  (member ch '(#\Space #\Tab #\Newline #\Return #\Page)))

(declaim (ftype (function (string fixnum fixnum) (values string fixnum)) %lex-string))
(defun %lex-string (str start n)
  "Lex a single-quoted STRING starting at START (just past the opening quote)."
  (let ((end (position #\' str :start start :end n)))
    (unless end (error 'filter-error :detail "unterminated string literal"))
    (values (subseq str start end) (1+ end))))

(declaim (ftype (function (string fixnum fixnum) (values fixnum fixnum)) %lex-param))
(defun %lex-param (str start n)
  "Lex the digits of a %n PARAMETER starting at START (just past the '%')."
  (let ((i start))
    (loop while (and (< i n) (digit-char-p (char str i))) do (incf i))
    (when (= i start) (error 'filter-error :detail "expected digits after '%'"))
    (values (parse-integer str :start start :end i) i)))

(declaim (ftype (function (string fixnum fixnum) double-float) %parse-float))
(defun %parse-float (str start end)
  "Parse the validated numeric substring [START,END) as a double-float."
  (let ((*read-eval* nil) (*read-default-float-format* 'double-float))
    (let ((v (read-from-string (subseq str start end))))
      (unless (realp v) (error 'filter-error :detail "malformed float literal"))
      (coerce v 'double-float))))

(declaim (ftype (function (string fixnum fixnum) (values cons fixnum)) %lex-number))
(defun %lex-number (str start n)
  "Lex an INTEGERVALUE (decimal or 0x-hex) or FLOATVALUE starting at START."
  (let ((i start) (sign 1) (floatp nil))
    (when (< i n)
      (case (char str i) (#\+ (incf i)) (#\- (setf sign -1) (incf i))))
    (cond
      ((and (< (1+ i) n) (char= (char str i) #\0) (char-equal (char str (1+ i)) #\x))
       (incf i 2)
       (let ((hs i))
         (loop while (and (< i n) (digit-char-p (char str i) 16)) do (incf i))
         (when (= i hs) (error 'filter-error :detail "malformed hex literal"))
         (values (cons :int (* sign (parse-integer str :start hs :end i :radix 16))) i)))
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
         (when (= i ds) (error 'filter-error :detail "malformed number"))
         (if floatp
             (values (cons :float (* sign (%parse-float str ds i))) i)
             (values (cons :int (* sign (parse-integer str :start ds :end i))) i)))))))

(declaim (ftype (function (string fixnum fixnum) (values cons fixnum)) %lex-relop))
(defun %lex-relop (str i n)
  "Lex a relational operator (=, >, >=, <, <=, <>, and '!=' as a synonym for <>)."
  (let ((c (char str i)) (c2 (when (< (1+ i) n) (char str (1+ i)))))
    (cond
      ((and (char= c #\>) (eql c2 #\=)) (values (cons :relop :>=) (+ i 2)))
      ((and (char= c #\<) (eql c2 #\=)) (values (cons :relop :<=) (+ i 2)))
      ((and (char= c #\<) (eql c2 #\>)) (values (cons :relop :<>) (+ i 2)))
      ((and (char= c #\!) (eql c2 #\=)) (values (cons :relop :<>) (+ i 2)))
      ((char= c #\=) (values (cons :relop :=) (1+ i)))
      ((char= c #\>) (values (cons :relop :>) (1+ i)))
      ((char= c #\<) (values (cons :relop :<) (1+ i)))
      (t (error 'filter-error :detail (format nil "bad operator at ~d" i))))))

(declaim (ftype (function (string fixnum fixnum) (values cons fixnum)) %lex-ident))
(defun %lex-ident (str start n)
  "Lex an identifier (FIELDNAME, dots allowed) or a reserved keyword (AND/OR/NOT/
   BETWEEN/LIKE, case-insensitive)."
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
              i))))

(declaim (ftype (function (string) list) lex-filter))
(defun lex-filter (str)
  "Tokenize a DDS filter/query expression STR into a list of (TYPE . VALUE) tokens."
  (let ((toks '()) (i 0) (n (length str)))
    (declare (type fixnum i n))
    (loop while (< i n) do
      (let ((ch (char str i)))
        (cond
          ((%whitespace-p ch) (incf i))
          ((char= ch #\() (push (cons :lparen nil) toks) (incf i))
          ((char= ch #\)) (push (cons :rparen nil) toks) (incf i))
          ((char= ch #\')
           (multiple-value-bind (v ni) (%lex-string str (1+ i) n)
             (push (cons :string v) toks) (setf i ni)))
          ((char= ch #\%)
           (multiple-value-bind (v ni) (%lex-param str (1+ i) n)
             (push (cons :param v) toks) (setf i ni)))
          ((or (digit-char-p ch)
               (and (member ch '(#\+ #\-)) (< (1+ i) n) (digit-char-p (char str (1+ i)))))
           (multiple-value-bind (tok ni) (%lex-number str i n)
             (push tok toks) (setf i ni)))
          ((member ch '(#\= #\< #\> #\!))
           (multiple-value-bind (tok ni) (%lex-relop str i n)
             (push tok toks) (setf i ni)))
          ((or (alpha-char-p ch) (char= ch #\_))
           (multiple-value-bind (tok ni) (%lex-ident str i n)
             (push tok toks) (setf i ni)))
          (t (error 'filter-error :detail (format nil "unexpected character ~a at ~d" ch i))))))
    (nreverse toks)))

(declaim (ftype (function (string) t) %lex-single-value))
(defun %lex-single-value (str)
  "Lex a DDS expression-parameter string STR as exactly one literal value (the value a
   %n placeholder denotes); returns the integer / double-float / string value."
  (let ((toks (lex-filter str)))
    (unless (and toks (null (cdr toks)) (member (car (first toks)) '(:int :float :string)))
      (error 'filter-error :detail (format nil "parameter ~s is not a single literal" str)))
    (cdr (first toks))))

;;; ---- Value comparison (type-aware; a cross-type comparison yields no match) ----

(declaim (ftype (function (string string) t) %like-match))
(defun %like-match (s pat)
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

(declaim (ftype (function (symbol t t) t) %relop-apply))
(defun %relop-apply (op a b)
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

(defstruct (pstate (:constructor make-pstate (rest)))
  (rest nil :type list))

(declaim (ftype (function (string list function) function) compile-filter))
(defun compile-filter (expression parameters resolver)
  "Compile a DDS Annex B filter/query EXPRESSION into a predicate (lambda (sample) ->
   generalized boolean). PARAMETERS are the DDS expression_parameters (strings; a %n
   token denotes PARAMETERS[n], lexed as a literal). RESOLVER maps a FIELDNAME string
   to a unary accessor (sample -> value) or NIL. Signals FILTER-ERROR on a lexical,
   syntactic, or field-resolution error. The predicate is compiled once, off hot path."
  (let ((ps (make-pstate (lex-filter expression))))
    (labels ((peek () (first (pstate-rest ps)))
             (peek-type () (let ((tok (peek))) (and tok (car tok))))
             (pop-tok () (pop (pstate-rest ps)))
             (expect (type)
               (let ((tok (pop-tok)))
                 (unless (and tok (eq (car tok) type))
                   (error 'filter-error :detail (format nil "expected ~a, got ~a" type tok)))
                 tok))
             (operand ()
               (let ((tok (pop-tok)))
                 (unless tok (error 'filter-error :detail "unexpected end of expression"))
                 (ecase (car tok)
                   (:field (let ((acc (funcall resolver (cdr tok))))
                             (unless acc
                               (error 'filter-error
                                      :detail (format nil "unknown field ~s" (cdr tok))))
                             (lambda (s) (funcall acc s))))
                   ((:int :float :string) (let ((v (cdr tok))) (lambda (s) (declare (ignore s)) v)))
                   (:param (let* ((idx (cdr tok))
                                  (pstr (nth idx parameters)))
                             (unless pstr
                               (error 'filter-error
                                      :detail (format nil "no parameter %~d supplied" idx)))
                             (let ((v (%lex-single-value pstr)))
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
                   (t (error 'filter-error
                             :detail "expected a comparison operator, BETWEEN, or LIKE")))))
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
        (error 'filter-error :detail "empty filter expression"))
      (let ((pred (parse-cond)))
        (when (pstate-rest ps)
          (error 'filter-error
                 :detail (format nil "trailing tokens after expression: ~a" (pstate-rest ps))))
        (lambda (sample) (and (funcall pred sample) t))))))
