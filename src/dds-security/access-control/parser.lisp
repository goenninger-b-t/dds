(in-package #:dds.security)

;;; DDS-Security 1.1 §9.4.1 — Governance/Permissions XML parsing primitives (xmls 3.3.0, MIT).

(defparameter +ac-whitespace+
    '(#\Space #\Tab #\Newline #\Return #\Page)
  "Characters stripped when trimming XML text content in access-control parsers.")

(defun* %ac-node-child (node name)
    (function (t string) t)
  "First child element of NODE whose tag equals NAME; NIL if absent or NODE is not a node."
  (when (typep node 'xmls:node)
    (dolist (c (xmls:node-children node))
      (when (and (typep c 'xmls:node) (string= (xmls:node-name c) name))
        (return c)))))

(defun* %ac-node-text (node)
    (function (t) (or string null))
  "Trimmed first string child of NODE; NIL if none or NODE is not a node."
  (when (typep node 'xmls:node)
    (let ((raw (find-if #'stringp (xmls:node-children node))))
      (and raw (string-trim +ac-whitespace+ raw)))))

(defun* %ac-node-children-named (node name)
    (function (t string) list)
  "All child element nodes of NODE whose tag equals NAME (in document order)."
  (if (typep node 'xmls:node)
      (remove-if-not
       (lambda (c) (and (typep c 'xmls:node) (string= (xmls:node-name c) name)))
       (xmls:node-children node))
      '()))

(defun* %ac-node-bool (parent name)
    (function (t string) boolean)
  "Boolean value of the named child element (text 'true' -> T, else NIL) — §9.4.1.2.3."
  (let ((child (%ac-node-child parent name)))
    (and child (string= "true" (or (%ac-node-text child) "")))))

(defun* %ac-node-protection-kind (parent name valid-kinds)
    (function (t string list) (or keyword null))
  "ProtectionKind from named child of PARENT (§9.4.1.2.3).
   NIL if the element is absent (required by schema), token is unknown, or keyword is not
   in VALID-KINDS — fail-closed on every non-conformant case."
  (let ((child (%ac-node-child parent name)))
    (if (null child)
        nil
        (let* ((text (or (%ac-node-text child) ""))
               (pair (rassoc text +protection-kind-xsd-strings+ :test #'string=))
               (kw   (and pair (car pair))))
          (and kw (member kw valid-kinds) kw)))))

(defun* %ac-node-text-req (parent name)
    (function (t string) (or string null))
  "Trimmed text content of named child of PARENT; NIL if absent or empty."
  (let ((child (%ac-node-child parent name)))
    (and child (%ac-node-text child))))

;;; Pure-Lisp fnmatch(3) */?/[...] for topic matching (§9.4.1.3.2.7, no FFI).

(defun* %bracket-class-match (expr start plen ch)
    (function (string fixnum fixnum character) (values symbol fixnum boolean))
  "Match CH against the POSIX fnmatch(3) bracket class in EXPR opening just after the `[` (index START).
   Returns (values STATUS END MEMBER-P): STATUS=:class + END=index past the closing `]` when the class is
   well-formed; STATUS=:unterminated + END=START + MEMBER-P=NIL when no closing `]` exists before PLEN
   (the caller then treats the `[` as a literal, per POSIX). Every EXPR index is bounds-checked against
   PLEN (no OOB even at safety-0). Negation: `!` (POSIX) or `^` (widely-supported synonym) as the first
   class char. `]` as the first class char is a literal member (not the terminator). `-` first or last in
   the class is a literal `-`; otherwise `c1-c2` is an inclusive char-code range (empty when hi<lo)."
  (let ((i start)
        (neg nil)
        (member nil)
        (first t))
    (declare (type fixnum i))
    (when (and (< i plen)
               (or (char= (char expr i) #\!) (char= (char expr i) #\^)))
      (setf neg t i (1+ i)))
    (loop
      (when (>= i plen)
        (return (values :unterminated start nil)))
      (let ((c (char expr i)))
        (cond
          ((and (char= c #\]) (not first))
           (return (values :class (1+ i) (if neg (not member) member))))
          ((and (< (+ i 2) plen)
                (char= (char expr (1+ i)) #\-)
                (not (char= (char expr (+ i 2)) #\])))
           (when (<= (char-code c) (char-code ch) (char-code (char expr (+ i 2))))
             (setf member t))
           (setf i (+ i 3) first nil))
          (t
           (when (char= c ch) (setf member t))
           (setf i (1+ i) first nil)))))))

(defun* %topic-match-p (expr topic-name)
    (function (string string) boolean)
  "Full-string POSIX fnmatch(3) matcher for topic names (§9.4.1.3.2.7, no FNM_PATHNAME): `*` matches any
   string (incl. empty), `?` any one char, `[...]` a bracket class (see %bracket-class-match — `!`/`^`
   negation, `[]...]` literal-`]`, first/last `-` literal, `c1-c2` range, unterminated `[` is a literal `[`).
   Any other char is literal. Bounds-checked throughout — a malformed class fails safe (deterministic
   no-match or literal-`[`), never a crash/OOB/unbounded loop/spurious match."
  (let ((plen (length expr))
        (slen (length topic-name)))
    (labels ((match (ei si)
               (cond ((= ei plen)               (= si slen))
                     ((char= (char expr ei) #\*)
                      (loop for k from si to slen thereis (match (1+ ei) k)))
                     ((= si slen)               nil)
                     ((char= (char expr ei) #\?)
                      (match (1+ ei) (1+ si)))
                     ((char= (char expr ei) #\[)
                      (multiple-value-bind (status end member-p)
                          (%bracket-class-match expr (1+ ei) plen (char topic-name si))
                        (if (eq status :class)
                            (and member-p (match end (1+ si)))
                            (and (char= #\[ (char topic-name si)) (match (1+ ei) (1+ si))))))
                     ((char= (char expr ei) (char topic-name si))
                      (match (1+ ei) (1+ si)))
                     (t                         nil))))
      (match 0 0))))

;;; Permissions grant rule parsing helpers (used by permissions.lisp).

(defun* %ac-parse-topics (op-node)
    (function (t) list)
  "Extract topic expression strings from a <publish> or <subscribe> element."
  (let ((topics-node (%ac-node-child op-node "topics")))
    (when topics-node
      (mapcar (lambda (t-node) (or (%ac-node-text t-node) ""))
              (%ac-node-children-named topics-node "topic")))))

(defun* %ac-parse-rule-ops (action rule-node)
    (function (symbol t) list)
  "Build (action . (operation . topics)) entries for each operation present in RULE-NODE."
  (let ((result '()))
    (dolist (op-kw '(:publish :subscribe))
      (let* ((op-str  (string-downcase (symbol-name op-kw)))
             (op-node (%ac-node-child rule-node op-str))
             (topics  (when op-node (%ac-parse-topics op-node))))
        (when topics
          (push (cons action (cons op-kw topics)) result))))
    (nreverse result)))

(defun* %ac-parse-grant-rules (grant-node)
    (function (t) list)
  "Parse ordered allow_rule/deny_rule children of GRANT-NODE into the rules list."
  (let ((result '())
        (children (if (typep grant-node 'xmls:node) (xmls:node-children grant-node) '())))
    (dolist (child children)
      (when (typep child 'xmls:node)
        (let ((name (xmls:node-name child)))
          (cond
            ((string= name "allow_rule")
             (dolist (r (%ac-parse-rule-ops :allow child)) (push r result)))
            ((string= name "deny_rule")
             (dolist (r (%ac-parse-rule-ops :deny child))  (push r result)))))))
    (nreverse result)))
