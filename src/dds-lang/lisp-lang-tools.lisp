;;;; L-1 — Language tools. Fully-contracted definition forms used throughout the stack:
;;;; DEFUN* emits the FTYPE declaim + per-required-parameter (DECLARE (TYPE ...)) and forces
;;;; a non-empty docstring (FR-LANG-8 + the operating contract §5.1); DEFSTRUCT* forces a
;;;; non-empty docstring and a :TYPE on every slot. This system is the load-order root (every
;;;; internal system depends on it transitively via dds-pal) so the forms are available
;;;; everywhere. Pure macros — no runtime cost over a hand-written defun/defstruct.

(defpackage #:net.goenninger.dds.lang
  (:nicknames #:dds.lang)
  (:use #:common-lisp)
  (:documentation
   "Language tools (L-1): DEFUN* / DEFSTRUCT* — definition forms that make the full type
    contract (FR-LANG-8) and the mandatory docstring (§5.1) structural rather than a
    convention checked after the fact. Used to define every function and struct in the stack.")
  (:export #:defun* #:defstruct* #:plusp-length #:try #:bail))

(in-package #:net.goenninger.dds.lang)

(declaim (ftype (function (t) t) plusp-length))
(defun plusp-length (x)
  "True iff X is a non-empty string (length >= 1). The predicate behind the non-empty-docstring
   CHECK-TYPE in DEFUN*/DEFSTRUCT*; combined with STRING in those callers via (AND STRING
   (SATISFIES PLUSP-LENGTH)), so it only ever sees strings — the STRINGP guard keeps it total."
  (and (stringp x) (plusp (length x))))

(defmacro defun* (name lambda-list signature docstring &body body)
  "Define a fully-contracted function: NAME with LAMBDA-LIST, declared FTYPE SIGNATURE (a
(FUNCTION (arg-types...) result) form), a mandatory non-empty DOCSTRING, and BODY.  Emits
the FTYPE declaim before the DEFUN so every caller sees the contract (M4), and forces the
docstring to exist at definition time (M5).  NAME is a symbol; LAMBDA-LIST an ordinary
lambda list; SIGNATURE a (FUNCTION ...) type specifier; DOCSTRING a non-empty string;
BODY the function body (declarations then forms).  Expands to a PROGN defining NAME.
Signals a compile-time error if DOCSTRING is not a non-empty string, SIGNATURE is not a
(FUNCTION (arg-types...) result) form, or SIGNATURE's required arg-type count does not match
LAMBDA-LIST's required parameter count (a mismatch silently mis-types parameters).  Also emits a
(DECLARE (TYPE ...)) for each required parameter from SIGNATURE so every argument is typed inside the
body, not only at the call boundary (M3/M4).  Consing: none at runtime (pure macro).

BODY is wrapped in a MACROLET binding the two STATUS-THREADING operators that implement the
no-conditions rule (operating contract: no Lisp condition is signalled anywhere in our code; a failure
is a value threaded to the caller, and the toplevel DDS API turns it into a ReturnCode_t):

  (TRY form)     evaluate FORM, which returns (VALUES result status).  If STATUS is non-NIL the
                 enclosing function IMMEDIATELY returns (VALUES NIL status) — the failure propagates
                 to ITS caller unchanged.  Otherwise TRY yields FORM's primary value.
  (BAIL status)  return (VALUES NIL STATUS) from the enclosing function.

A function that can fail therefore declares its result as (VALUES (OR NULL x) (OR NULL KEYWORD)) and
its callers wrap every call in TRY.  This exists because the failure mode of hand-written propagation
is SILENT: one unchecked call swallows the status and hands a NIL onward where a value was expected.
TRY makes the check the DEFAULT and the omission the visible thing.  Leading DECLARE forms in BODY are
hoisted OUT of the MACROLET so (DECLARE (IGNORE ...)) still refers to the lambda-list variables."
  (check-type docstring (and string (satisfies plusp-length)))
  (assert (and (consp signature) (eq (car signature) 'function) (listp (second signature))) ()
          "DEFUN* ~S: SIGNATURE must be a (FUNCTION (arg-types...) result) form, got ~S."
          name signature)
  (let ((arg-types (second signature)))
    (flet ((required (lst) (loop for x in lst until (member x lambda-list-keywords) count t)))
      (let ((ll-req (required lambda-list)) (sig-req (required arg-types)))
        (assert (= ll-req sig-req) ()
                "DEFUN* ~S: SIGNATURE declares ~D required arg type(s) but the lambda list has ~D ~
required parameter(s) — they must match (a mismatch silently mis-types parameters)."
                name sig-req ll-req)))
    (let ((decls (loop for p in lambda-list for ty in arg-types
                       until (member p lambda-list-keywords)
                       collect `(type ,ty ,p)))
          (body-decls (loop for f in body while (and (consp f) (eq (car f) 'declare)) collect f))
          (forms (loop for f on body
                       unless (and (consp (car f)) (eq (caar f) 'declare)) return f)))
      `(progn
         (declaim (ftype ,signature ,name))
         (defun ,name ,lambda-list
           ,docstring
           ,@(when decls (list (cons 'declare decls)))
           ,@body-decls
           (macrolet
               ((try (form)
                  (let ((v (gensym "VALUE")) (s (gensym "STATUS")))
                    (list 'multiple-value-bind (list v s) form
                          (list 'when s (list 'return-from ',name (list 'values nil s)))
                          v)))
                (bail (status)
                  (list 'return-from ',name (list 'values nil status))))
             ,@forms))))))

(defmacro defstruct* (name-and-options docstring &body slots)
  "Define a struct with NAME-AND-OPTIONS (as for DEFSTRUCT), a mandatory non-empty
DOCSTRING (M5), and SLOTS each of which MUST be a list slot-specifier carrying a :TYPE
(M3).  NAME-AND-OPTIONS is a symbol or (name option...) list; DOCSTRING a non-empty
string; each SLOT a DEFSTRUCT slot specifier list containing :TYPE.  Expands to a
DEFSTRUCT.  Signals a compile-time error if DOCSTRING is not a non-empty string or any
slot lacks a :TYPE.  Consing: none at runtime (pure macro)."
  (check-type docstring (and string (satisfies plusp-length)))
  (let ((struct-name (if (consp name-and-options)
                         (car name-and-options)
                         name-and-options)))
    (dolist (slot slots)
      (assert (and (consp slot) (member :type slot)) ()
              "DEFSTRUCT* ~S: slot ~S must be a list specifier carrying a :TYPE (M3)."
              struct-name slot)))
  `(defstruct ,name-and-options
     ,docstring
     ,@slots))
