(in-package #:dds.cdr)

;;;; XCDR primitive + composite codec. HOT PATH: defstruct + monomorphic funs.
;;;; Implements REQUIREMENTS FR-CDR-1 (classic CDR primitives/strings/sequences)
;;;; and FR-CDR-2 (the XCDR2 4-byte alignment cap). The 16-bit encapsulation IDs,
;;;; MUTABLE EMHEADER bit layout, and byte-exactness vs. RTI are pinned by the
;;;; reference corpus (FR-CDR-3/8) — NOT encoded from memory. Modes are :xcdr1
;;;; (classic, align up to 8) and :xcdr2 (align capped at 4).

(deftype cdr-mode () '(member :xcdr1 :xcdr2))

(declaim (ftype (function (cdr-mode) (integer 4 8)) %max-align))
(declaim (ftype (function (dds.core.buffer:cursor (integer 1 8) cdr-mode) fixnum) cdr-align))
(declaim (ftype (function (dds.core.buffer:cursor (integer 0) cdr-mode) (integer 0)) cdr-put-u8))
(declaim (ftype (function (dds.core.buffer:cursor cdr-mode) (integer 0)) cdr-get-u8))
(declaim (ftype (function (dds.core.buffer:cursor (integer 0) cdr-mode) (integer 0)) cdr-put-u16))
(declaim (ftype (function (dds.core.buffer:cursor cdr-mode) (integer 0)) cdr-get-u16))
(declaim (ftype (function (dds.core.buffer:cursor (integer 0) cdr-mode) (integer 0)) cdr-put-u32))
(declaim (ftype (function (dds.core.buffer:cursor cdr-mode) (integer 0)) cdr-get-u32))
(declaim (ftype (function (dds.core.buffer:cursor (integer 0) cdr-mode) (integer 0)) cdr-put-u64))
(declaim (ftype (function (dds.core.buffer:cursor cdr-mode) (integer 0)) cdr-get-u64))
(declaim (ftype (function (integer (integer 1)) integer) %to-signed))
(declaim (ftype (function (integer (integer 1)) (integer 0)) %to-unsigned))
(declaim (ftype (function (dds.core.buffer:cursor integer cdr-mode) (integer 0)) cdr-put-i8))
(declaim (ftype (function (dds.core.buffer:cursor cdr-mode) integer) cdr-get-i8))
(declaim (ftype (function (dds.core.buffer:cursor integer cdr-mode) (integer 0)) cdr-put-i16))
(declaim (ftype (function (dds.core.buffer:cursor cdr-mode) integer) cdr-get-i16))
(declaim (ftype (function (dds.core.buffer:cursor integer cdr-mode) (integer 0)) cdr-put-i32))
(declaim (ftype (function (dds.core.buffer:cursor cdr-mode) integer) cdr-get-i32))
(declaim (ftype (function (dds.core.buffer:cursor integer cdr-mode) (integer 0)) cdr-put-i64))
(declaim (ftype (function (dds.core.buffer:cursor cdr-mode) integer) cdr-get-i64))
(declaim (ftype (function (dds.core.buffer:cursor t cdr-mode) (integer 0)) cdr-put-bool))
(declaim (ftype (function (dds.core.buffer:cursor cdr-mode) boolean) cdr-get-bool))
(declaim (ftype (function (dds.core.buffer:cursor (integer 0) cdr-mode) (integer 0)) cdr-put-enum))
(declaim (ftype (function (dds.core.buffer:cursor cdr-mode) (integer 0)) cdr-get-enum))
(declaim (ftype (function (dds.core.buffer:cursor string cdr-mode) string) cdr-put-string))
(declaim (ftype (function (dds.core.buffer:cursor cdr-mode) string) cdr-get-string))
(declaim (ftype (function (dds.core.buffer:cursor vector function cdr-mode) (integer 0)) cdr-put-sequence))
(declaim (ftype (function (dds.core.buffer:cursor function cdr-mode) simple-vector) cdr-get-sequence))
(declaim (ftype (function (dds.core.buffer:cursor (integer 0) cdr-mode) (integer 0)) cdr-put-dheader))
(declaim (ftype (function (dds.core.buffer:cursor cdr-mode) (integer 0)) cdr-get-dheader))
(declaim (ftype (function (t (integer 0 7) (integer 0)) (unsigned-byte 32)) emheader1-encode))
(declaim (ftype (function ((unsigned-byte 32)) (values t fixnum fixnum)) emheader1-decode))
(declaim (ftype (function (integer) (or null (integer 0 3))) lc-for-length))

(declaim (inline %max-align cdr-align))
(defun %max-align (mode)
  "Maximum alignment for MODE: 8 for XCDR1, 4 for XCDR2 (FR-CDR-2)."
  (ecase mode (:xcdr1 8) (:xcdr2 4)))

(defun cdr-align (cursor n mode)
  "Align CURSOR to N bytes, capped by MODE's maximum alignment."
  (dds.core.buffer:align cursor (min n (%max-align mode))))

(declaim (ftype (function ((integer 0) (integer 1 8) cdr-mode) (integer 0)) cdr-size-align))
(defun cdr-size-align (pos n mode)
  "Round POS up to the MODE-capped N-byte boundary; the size-path analogue of
   cdr-align, used by generated serialized-size functions (FR-CDR-5)."
  (let* ((m (min n (%max-align mode)))
         (rem (mod pos m)))
    (if (zerop rem) pos (+ pos (- m rem)))))

;;; unsigned integers
(defun cdr-put-u8  (c v mode) (declare (ignore mode)) (dds.core.buffer:put-u8 c v))
(defun cdr-get-u8  (c mode)   (declare (ignore mode)) (dds.core.buffer:get-u8 c))
(defun cdr-put-u16 (c v mode) (cdr-align c 2 mode) (dds.core.buffer:put-u16 c v))
(defun cdr-get-u16 (c mode)   (cdr-align c 2 mode) (dds.core.buffer:get-u16 c))
(defun cdr-put-u32 (c v mode) (cdr-align c 4 mode) (dds.core.buffer:put-u32 c v))
(defun cdr-get-u32 (c mode)   (cdr-align c 4 mode) (dds.core.buffer:get-u32 c))
(defun cdr-put-u64 (c v mode) (cdr-align c 8 mode) (dds.core.buffer:put-u64 c v))
(defun cdr-get-u64 (c mode)   (cdr-align c 8 mode) (dds.core.buffer:get-u64 c))

;;; signed integers (two's complement)
(declaim (inline %to-signed %to-unsigned))
(defun %to-signed (v bits)
  (if (>= v (ash 1 (1- bits))) (- v (ash 1 bits)) v))
(defun %to-unsigned (v bits)
  (logand v (1- (ash 1 bits))))
(defun cdr-put-i8  (c v mode) (cdr-put-u8  c (%to-unsigned v 8)  mode))
(defun cdr-get-i8  (c mode)   (%to-signed (cdr-get-u8  c mode) 8))
(defun cdr-put-i16 (c v mode) (cdr-put-u16 c (%to-unsigned v 16) mode))
(defun cdr-get-i16 (c mode)   (%to-signed (cdr-get-u16 c mode) 16))
(defun cdr-put-i32 (c v mode) (cdr-put-u32 c (%to-unsigned v 32) mode))
(defun cdr-get-i32 (c mode)   (%to-signed (cdr-get-u32 c mode) 32))
(defun cdr-put-i64 (c v mode) (cdr-put-u64 c (%to-unsigned v 64) mode))
(defun cdr-get-i64 (c mode)   (%to-signed (cdr-get-u64 c mode) 64))

;;; boolean (1 octet) and enum (32-bit; bit_bound refinement later)
(defun cdr-put-bool (c v mode) (cdr-put-u8 c (if v 1 0) mode))
(defun cdr-get-bool (c mode)   (/= 0 (cdr-get-u8 c mode)))
(defun cdr-put-enum (c v mode) (cdr-put-u32 c v mode))
(defun cdr-get-enum (c mode)   (cdr-get-u32 c mode))

;;; string: 4-byte length (INCLUDING the NUL) + octets + NUL (FR-CDR-1).
;;; Latin-1 for M1; UTF-8 byte-exactness is pinned by the corpus (FR-CDR-8).
(defun cdr-put-string (c s mode)
  (cdr-align c 4 mode)
  (let ((n (length s)))
    (dds.core.buffer:put-u32 c (1+ n))
    (dotimes (i n)
      (let ((code (char-code (char s i))))
        (when (> code 255)
          (error 'cdr-not-implemented :what "non-Latin-1 string (UTF-8 deferred)"))
        (dds.core.buffer:put-u8 c code)))
    (dds.core.buffer:put-u8 c 0)
    s))
(defun cdr-get-string (c mode)
  "Note: allocates the result string. The pooled, zero-alloc deserialize path is
   a tracked M1-perf follow-up (FR-LANG-5/NFR-DET)."
  (cdr-align c 4 mode)
  (let* ((len (dds.core.buffer:get-u32 c))
         (n (max 0 (1- len)))
         (s (make-string n)))
    (dotimes (i n) (setf (char s i) (code-char (dds.core.buffer:get-u8 c))))
    (dds.core.buffer:get-u8 c)
    s))

;;; sequence: 4-byte element count + elements (FR-CDR-1)
(defun cdr-put-sequence (c vec elem-writer mode)
  (cdr-align c 4 mode)
  (let ((n (length vec)))
    (dds.core.buffer:put-u32 c n)
    (dotimes (i n) (funcall elem-writer c (aref vec i) mode))
    n))
(defun cdr-get-sequence (c elem-reader mode)
  "Note: allocates the result vector (see cdr-get-string)."
  (cdr-align c 4 mode)
  (let* ((n (dds.core.buffer:get-u32 c))
         (vec (make-array n)))
    (dotimes (i n) (setf (aref vec i) (funcall elem-reader c mode)))
    vec))

;;;; XCDR2 framing headers. DHEADER: XTypes 1.3 §7.4.3.4.1 (UInt32 serialized
;;;; size of the following object, 4-byte aligned, stream endianness). EMHEADER1
;;;; + LC + NEXTINT: §7.4.3.4.2. Full DELIMITED/MUTABLE struct serialization is a
;;;; later increment; these are the pinned, byte-exact primitives.

(defun cdr-put-dheader (c ssize mode)
  "Write a DHEADER = UInt32 serialized size of the object that follows."
  (cdr-align c 4 mode)
  (dds.core.buffer:put-u32 c ssize))
(defun cdr-get-dheader (c mode)
  (cdr-align c 4 mode)
  (dds.core.buffer:get-u32 c))

(defconstant +lc-1-byte+  0)
(defconstant +lc-2-bytes+ 1)
(defconstant +lc-4-bytes+ 2)
(defconstant +lc-8-bytes+ 3)

(declaim (inline emheader1-encode))
(defun emheader1-encode (must-understand lc member-id)
  "EMHEADER1 = (M_FLAG<<31) + (LC<<28) + (MemberId & 0x0fffffff) (§7.4.3.4.2)."
  (logior (ash (if must-understand 1 0) 31)
          (ash (logand lc #x7) 28)
          (logand member-id #x0fffffff)))
(defun emheader1-decode (u32)
  "Inverse of emheader1-encode: (values must-understand lc member-id)."
  (values (logbitp 31 u32)
          (ldb (byte 3 28) u32)
          (logand u32 #x0fffffff)))
(defun lc-for-length (n)
  "Length code for an N-byte member when N in {1,2,4,8}; else NIL (needs NEXTINT,
   LC 4-7) (§7.4.3.4.2)."
  (case n (1 +lc-1-byte+) (2 +lc-2-bytes+) (4 +lc-4-bytes+) (8 +lc-8-bytes+) (t nil)))
