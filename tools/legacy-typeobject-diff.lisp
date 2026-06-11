;;;; Differential-diff tool for RTI legacy TypeObject (PID_TYPE_OBJECT_LB) reverse engineering.
;;;; Given two raw-compressed LB payloads (or already-inflated octet vectors), inflates both
;;;; and prints a human-readable byte-level diff.  Standalone load file — not part of asdf:test-system.
;;;; Usage: scripts/with-sbcl.sh --load tools/legacy-typeobject-diff.lisp \
;;;;                              --eval '(lto-diff a b)' --eval '(uiop:quit 0)'

(require :asdf)
(push (truename ".") asdf:*central-registry*)
(if (find-package '#:quicklisp)
    (uiop:symbol-call '#:quicklisp '#:quickload :dds-types :silent t)
    (asdf:load-system :dds-types))

(in-package :cl-user)

;;; -- formatting helpers --------------------------------------------------

(declaim (ftype (function ((array (unsigned-byte 8) (*)) integer integer) string) hex-region))
(defun hex-region (vec start end)
  "Return a hex-space string for VEC[START,END)."
  (with-output-to-string (s)
    (loop for i from start below end do
      (when (> i start) (write-char #\Space s))
      (format s "~2,'0X" (aref vec i)))))

(declaim (ftype (function ((array (unsigned-byte 8) (*)) integer integer) string) ascii-region))
(defun ascii-region (vec start end)
  "Return a printable-ASCII rendering of VEC[START,END), '.' for non-printable."
  (with-output-to-string (s)
    (loop for i from start below end do
      (let ((b (aref vec i)))
        (write-char (if (<= 32 b 126) (code-char b) #\.) s)))))

;;; -- inflate-or-passthrough helper ---------------------------------------

(declaim (ftype (function ((array * (*)))
                          (or null (simple-array (unsigned-byte 8) (*))))
                inflate-or-passthrough))
(defun inflate-or-passthrough (octets)
  "Try dds.types:inflate-type-object-lb on OCTETS; if it returns NIL (not a valid compressed LB
   header, or not ZLIB), treat OCTETS as already-inflated and return them as a simple-array.
   Returns NIL only when coercion to a simple-array itself fails (should never occur)."
  (let ((typed (coerce octets '(simple-array (unsigned-byte 8) (*)))))
    (or (dds.types:inflate-type-object-lb typed) typed)))

;;; -- equal-length diff ---------------------------------------------------

(declaim (ftype (function ((simple-array (unsigned-byte 8) (*))
                           (simple-array (unsigned-byte 8) (*)))
                          list)
                diff-equal-length))
(defun diff-equal-length (a b)
  "Return a list of diff regions (start end hex-a hex-b ascii-a ascii-b) for vectors of equal
   length.  Maximal runs of differing offsets are coalesced into single regions."
  (let ((n (length a)) (regions '()) (run-start nil))
    (dotimes (i n)
      (cond
        ((= (aref a i) (aref b i))
         (when run-start
           (push (list run-start i
                       (hex-region a run-start i) (hex-region b run-start i)
                       (ascii-region a run-start i) (ascii-region b run-start i))
                 regions)
           (setf run-start nil)))
        (t
         (unless run-start (setf run-start i)))))
    (when run-start
      (push (list run-start n
                  (hex-region a run-start n) (hex-region b run-start n)
                  (ascii-region a run-start n) (ascii-region b run-start n))
            regions))
    (nreverse regions)))

;;; -- main entry point ----------------------------------------------------

(declaim (ftype (function ((array * (*))
                           (array * (*)))
                          list)
                lto-diff))
(defun lto-diff (lb-a lb-b)
  "Diff two RTI legacy TypeObject inputs LB-A and LB-B.

   Each input is first passed to dds.types:inflate-type-object-lb; if that returns NIL (i.e.
   the buffer is not a compressed LB payload, or is already inflated), the raw octets are used
   directly.  This means callers may pass either the raw compressed PID_TYPE_OBJECT_LB value or
   an already-inflated octet vector without any preprocessing.

   Equal-length case: prints every maximal run of differing offsets as
     offset-start..offset-end : A=[hex bytes] (ascii) / B=[hex bytes] (ascii)
   Returns the list of diff regions as (start end hex-a hex-b ascii-a ascii-b).

   Unequal-length case: prints the common-prefix length, common-suffix length, and the
   differing middle region of each side (hex + ASCII).  Returns NIL."
  (let* ((a (inflate-or-passthrough lb-a))
         (b (inflate-or-passthrough lb-b))
         (la (length a))
         (lb (length b)))
    (format t "A: ~d byte(s)  B: ~d byte(s)~%" la lb)
    (cond
      ((= la lb)
       (let ((regions (diff-equal-length a b)))
         (if (null regions)
             (format t "IDENTICAL — no differences~%")
             (dolist (r regions)
               (destructuring-bind (s e ha hb aa ab) r
                 (format t "~d..~d : A=[~a] (~a) / B=[~a] (~a)~%" s e ha aa hb ab))))
         regions))
      (t
       ;; find common prefix length
       (let* ((minl (min la lb))
              (prefix (loop for i below minl
                            while (= (aref a i) (aref b i))
                            finally (return i)))
              ;; find common suffix length (from end, not past the prefix boundary)
              (suffix (loop for k from 0
                            while (and (< k (- minl prefix))
                                       (= (aref a (- la 1 k)) (aref b (- lb 1 k))))
                            finally (return k)))
              (ma-start prefix) (ma-end (- la suffix))
              (mb-start prefix) (mb-end (- lb suffix)))
         (format t "Common prefix : ~d byte(s)~%" prefix)
         (format t "Common suffix : ~d byte(s)~%" suffix)
         (format t "Middle A (~d byte(s)): [~a] (~a)~%"
                 (- ma-end ma-start)
                 (hex-region a ma-start ma-end)
                 (ascii-region a ma-start ma-end))
         (format t "Middle B (~d byte(s)): [~a] (~a)~%"
                 (- mb-end mb-start)
                 (hex-region b mb-start mb-end)
                 (ascii-region b mb-start mb-end)))
       nil))))
