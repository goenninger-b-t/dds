(in-package #:dds.cdr)

;;;; XCDR primitive + composite codec. HOT PATH: defstruct + monomorphic funs.
;;;; Implements REQUIREMENTS FR-CDR-1 (classic CDR primitives/strings/sequences)
;;;; and FR-CDR-2 (the XCDR2 4-byte alignment cap). The 16-bit encapsulation IDs,
;;;; MUTABLE EMHEADER bit layout, and byte-exactness vs. RTI are pinned by the
;;;; reference corpus (FR-CDR-3/8) — NOT encoded from memory. Modes are :xcdr1
;;;; (classic, align up to 8) and :xcdr2 (align capped at 4).

(deftype cdr-mode () '(member :xcdr1 :xcdr2))


(declaim (inline %max-align cdr-align))
(defun* %max-align (mode)
    (function (cdr-mode) (integer 4 8))
  "Maximum alignment for MODE: 8 for XCDR1, 4 for XCDR2 (FR-CDR-2)."
  (ecase mode (:xcdr1 8) (:xcdr2 4)))

(defun* cdr-align (cursor n mode)
    (function (dds.core.buffer:cursor (integer 1 8) cdr-mode) fixnum)
  "Align CURSOR to N bytes, capped by MODE's maximum alignment."
  (dds.core.buffer:align cursor (min n (%max-align mode))))

(defun* cdr-size-align (pos n mode)
    (function ((integer 0) (integer 1 8) cdr-mode) (integer 0))
  "Round POS up to the MODE-capped N-byte boundary; the size-path analogue of
   cdr-align, used by generated serialized-size functions (FR-CDR-5)."
  (let* ((m (min n (%max-align mode)))
         (rem (mod pos m)))
    (if (zerop rem) pos (+ pos (- m rem)))))

;;; unsigned integers
(defun* cdr-put-u8  (c v mode)
    (function (dds.core.buffer:cursor (integer 0) cdr-mode) (integer 0)) "Write a u8 to cursor C (no alignment); MODE ignored." (declare (ignore mode)) (dds.core.buffer:put-u8 c v))
(defun* cdr-get-u8  (c mode)
    (function (dds.core.buffer:cursor cdr-mode) (integer 0))   "Read a u8 from cursor C; MODE ignored." (declare (ignore mode)) (dds.core.buffer:get-u8 c))
(defun* cdr-put-u16 (c v mode)
    (function (dds.core.buffer:cursor (integer 0) cdr-mode) (integer 0)) "Write a u16 to cursor C, MODE-aware 2-byte alignment (XCDR1/2)." (cdr-align c 2 mode) (dds.core.buffer:put-u16 c v))
(defun* cdr-get-u16 (c mode)
    (function (dds.core.buffer:cursor cdr-mode) (integer 0))   "Read a u16 from cursor C, MODE-aware 2-byte alignment." (cdr-align c 2 mode) (dds.core.buffer:get-u16 c))
(defun* cdr-put-u32 (c v mode)
    (function (dds.core.buffer:cursor (integer 0) cdr-mode) (integer 0)) "Write a u32 to cursor C, MODE-aware 4-byte alignment (XCDR1/2)." (cdr-align c 4 mode) (dds.core.buffer:put-u32 c v))
(defun* cdr-get-u32 (c mode)
    (function (dds.core.buffer:cursor cdr-mode) (integer 0))   "Read a u32 from cursor C, MODE-aware 4-byte alignment." (cdr-align c 4 mode) (dds.core.buffer:get-u32 c))
(defun* cdr-put-u64 (c v mode)
    (function (dds.core.buffer:cursor (integer 0) cdr-mode) (integer 0)) "Write a u64 to cursor C, MODE-capped alignment (8 for XCDR1, 4 for XCDR2)." (cdr-align c 8 mode) (dds.core.buffer:put-u64 c v))
(defun* cdr-get-u64 (c mode)
    (function (dds.core.buffer:cursor cdr-mode) (integer 0))   "Read a u64 from cursor C, MODE-capped alignment (8 for XCDR1, 4 for XCDR2)." (cdr-align c 8 mode) (dds.core.buffer:get-u64 c))

;;; signed integers (two's complement)
(declaim (inline %to-signed %to-unsigned))
(defun* %to-signed (v bits)
    (function (integer (integer 1)) integer)
  "Interpret the low BITS of unsigned integer V as a two's-complement signed value."
  (if (>= v (ash 1 (1- bits))) (- v (ash 1 bits)) v))
(defun* %to-unsigned (v bits)
    (function (integer (integer 1)) (integer 0))
  "Reduce integer V to its BITS-wide two's-complement unsigned representation (V mod 2^BITS)."
  (logand v (1- (ash 1 bits))))
(defun* cdr-put-i8  (c v mode)
    (function (dds.core.buffer:cursor integer cdr-mode) (integer 0)) "Write a two's-complement i8 to cursor C, MODE-aware alignment." (cdr-put-u8  c (%to-unsigned v 8)  mode))
(defun* cdr-get-i8  (c mode)
    (function (dds.core.buffer:cursor cdr-mode) integer)   "Read a two's-complement i8 from cursor C, MODE-aware alignment." (%to-signed (cdr-get-u8  c mode) 8))
(defun* cdr-put-i16 (c v mode)
    (function (dds.core.buffer:cursor integer cdr-mode) (integer 0)) "Write a two's-complement i16 to cursor C, MODE-aware alignment." (cdr-put-u16 c (%to-unsigned v 16) mode))
(defun* cdr-get-i16 (c mode)
    (function (dds.core.buffer:cursor cdr-mode) integer)   "Read a two's-complement i16 from cursor C, MODE-aware alignment." (%to-signed (cdr-get-u16 c mode) 16))
(defun* cdr-put-i32 (c v mode)
    (function (dds.core.buffer:cursor integer cdr-mode) (integer 0)) "Write a two's-complement i32 to cursor C, MODE-aware alignment." (cdr-put-u32 c (%to-unsigned v 32) mode))
(defun* cdr-get-i32 (c mode)
    (function (dds.core.buffer:cursor cdr-mode) integer)   "Read a two's-complement i32 from cursor C, MODE-aware alignment." (%to-signed (cdr-get-u32 c mode) 32))
(defun* cdr-put-i64 (c v mode)
    (function (dds.core.buffer:cursor integer cdr-mode) (integer 0)) "Write a two's-complement i64 to cursor C, MODE-aware alignment." (cdr-put-u64 c (%to-unsigned v 64) mode))
(defun* cdr-get-i64 (c mode)
    (function (dds.core.buffer:cursor cdr-mode) integer)   "Read a two's-complement i64 from cursor C, MODE-aware alignment." (%to-signed (cdr-get-u64 c mode) 64))

;;; boolean (1 octet) and enum (32-bit; bit_bound refinement later)
(defun* cdr-put-bool (c v mode)
    (function (dds.core.buffer:cursor t cdr-mode) (integer 0)) "Write a boolean as one octet (1/0) to cursor C." (cdr-put-u8 c (if v 1 0) mode))
(defun* cdr-get-bool (c mode)
    (function (dds.core.buffer:cursor cdr-mode) boolean)   "Read a one-octet boolean from cursor C (non-zero is true)." (/= 0 (cdr-get-u8 c mode)))
(defun* cdr-put-enum (c v mode)
    (function (dds.core.buffer:cursor (integer 0) cdr-mode) (integer 0)) "Write an enum as a 32-bit value to cursor C (bit_bound refinement later)." (cdr-put-u32 c v mode))
(defun* cdr-get-enum (c mode)
    (function (dds.core.buffer:cursor cdr-mode) (integer 0))   "Read a 32-bit enum from cursor C." (cdr-get-u32 c mode))

;;; string: 4-byte length (INCLUDING the NUL) + octets + NUL (FR-CDR-1).
;;; Latin-1 for M1; UTF-8 byte-exactness is pinned by the corpus (FR-CDR-8).
(defun* cdr-put-string (c s mode)
    (function (dds.core.buffer:cursor string cdr-mode) string)
  "Write string S to cursor C: 4-byte length (including the NUL) + octets + NUL
   (FR-CDR-1). Latin-1 for M1; signals cdr-not-implemented on non-Latin-1 input."
  (cdr-align c 4 mode)
  (let ((n (length s)))
    (dds.core.buffer:put-u32 c (1+ n))
    (dotimes (i n)
      (let ((code (char-code (char s i))))
        (when (> code 255)
          (error 'cdr-not-implemented :what "non-Latin-1 string (UTF-8 deferred)"))   ; HOTPATH-COND(GUARD): non-Latin-1 string on the SERIALIZE path (UTF-8 deferred). CAUGHT at the public API — write-sample maps it to RETCODE_BAD_PARAMETER, so it never unwinds into the application (gate-nocond rule 2). Remove when UTF-8 lands.
        (dds.core.buffer:put-u8 c code)))
    (dds.core.buffer:put-u8 c 0)
    s))
(defun* cdr-get-string (c mode)
    (function (dds.core.buffer:cursor cdr-mode) string)
  "Read a string from cursor C: 4-byte length (including the NUL) + octets + NUL
   (FR-CDR-1). The wire length is pre-validated against the remaining buffer
   extent BEFORE the result string is allocated, signalling buffer-overflow on a
   hostile length (NFR-SEC-POSTURE). Note: allocates the result string. The
   pooled, zero-alloc deserialize path is a tracked M1-perf follow-up
   (FR-LANG-5/NFR-DET)."
  (cdr-align c 4 mode)
  (let ((len (dds.core.buffer:get-u32 c)))
    ;; LEN includes the NUL: exactly LEN octets follow (NFR-SEC-POSTURE)
    (dds.core.buffer:check-room c len)
    (let* ((n (max 0 (1- len)))
           (s (make-string n)))   ; HOTPATH-ALLOC(TRACKED): decoded string, per string field. An RX DESERIALIZATION PRODUCT — pooling it collides with loan semantics (ADR 0062)
      (dotimes (i n) (setf (char s i) (code-char (dds.core.buffer:get-u8 c))))
      (dds.core.buffer:get-u8 c)
      s)))

;;; sequence: 4-byte element count + elements (FR-CDR-1)
(defun* cdr-put-sequence (c vec elem-writer mode)
    (function (dds.core.buffer:cursor vector function cdr-mode) (integer 0))
  "Write sequence VEC to cursor C: 4-byte element count + elements, each written
   via (funcall ELEM-WRITER c element mode) (FR-CDR-1)."
  (cdr-align c 4 mode)
  (let ((n (length vec)))
    (dds.core.buffer:put-u32 c n)
    (dotimes (i n) (funcall elem-writer c (aref vec i) mode))
    n))
(defun* cdr-put-octet-sequence (c vec mode)
    (function (dds.core.buffer:cursor (simple-array (unsigned-byte 8) (*)) cdr-mode) (integer 0))
  "Write an OCTET sequence (element :u8/:byte/:octet) as 4-byte element count + the octets, copied in BULK
   (FR-CDR-1). Byte-identical on the wire to the generic per-element path: an octet has alignment 1, so no
   inter-element padding exists to reproduce — only the count's 4-byte alignment, which is preserved.

   WP-PERF: the generic cdr-put-sequence calls ELEM-WRITER once PER OCTET, each call re-doing cdr-align, a
   bounds check and a cursor bump. Measured on the live receive path: ~12 ns PER OCTET, perfectly linear —
   3166 ns to serialize a 256 B payload, 204 802 ns for 16 KB. That single loop was the dominant cost in the
   entire DDS round trip and the whole of the large-payload latency. This is a memcpy (dds.core.buffer:
   put-octets -> REPLACE), which is bounds-checked exactly once."
  (cdr-align c 4 mode)
  (let ((n (length vec)))
    (dds.core.buffer:put-u32 c n)
    (dds.core.buffer:put-octets c vec 0 n)
    n))

(defun* cdr-get-octet-sequence (c mode)
    (function (dds.core.buffer:cursor cdr-mode) (simple-array (unsigned-byte 8) (*)))
  "Read an OCTET sequence (element :u8/:byte/:octet): 4-byte element count + the octets, copied in BULK into
   an exactly-sized specialized vector (FR-CDR-1). The bulk twin of cdr-put-octet-sequence; see that
   docstring for the ~12 ns/octet the per-element loop was costing (deserialize measured ~7 ns/octet:
   1983 ns for 256 B, 114 953 ns for 16 KB).

   NFR-SEC-POSTURE is unchanged and still enforced BEFORE the result vector is allocated: the wire count is
   validated against the remaining buffer extent (every octet is 1 octet on the wire), so a hostile
   0xFFFFFFFF count signals buffer-overflow rather than attempting a 4 GB allocation."
  (cdr-align c 4 mode)
  (let ((n (dds.core.buffer:get-u32 c)))
    (dds.core.buffer:check-room c n)                    ; BEFORE the allocation (hostile count)
    (let ((vec (make-array n :element-type '(unsigned-byte 8))))   ; HOTPATH-ALLOC(TRACKED): decoded octet sequence (the PAYLOAD), per sample. RX deserialization product (ADR 0062)
      (dds.core.buffer:get-octets c vec 0 n)
      vec)))

(defun* cdr-get-sequence-typed (c elem-reader mode element-type)
    (function (dds.core.buffer:cursor function cdr-mode t) vector)
  "Read a sequence from cursor C into a vector SPECIALIZED to ELEMENT-TYPE: 4-byte element count +
   elements, each read via (funcall ELEM-READER c mode) (FR-CDR-1). The wire count is pre-validated
   against the remaining buffer extent BEFORE the result vector is allocated, signalling
   buffer-overflow on a hostile count (NFR-SEC-POSTURE).

   WP-PERF (NFR-MEM): ELEMENT-TYPE is what makes this cheap. An UNTYPED make-array — no :element-type — is a
   simple-vector — ONE MACHINE WORD (8 B) PER ELEMENT whatever the element actually is — so a
   256-octet sequence<octet> cost 2 KB of heap to carry 256 B of data, 8x the payload it decodes, and
   the single largest allocation on the DCPS receive path. Specialized, the same sequence costs 256 B
   + header. The generated codec passes the element's Lisp type (it knows it at macroexpansion from
   the DSL type map), so the specialization is a compile-time constant at each call site."
  (cdr-align c 4 mode)
  (let ((n (dds.core.buffer:get-u32 c)))
    ;; every CDR element serializes to >= 1 octet (NFR-SEC-POSTURE)
    (dds.core.buffer:check-room c n)
    (let ((vec (make-array n :element-type element-type)))   ; HOTPATH-ALLOC(TRACKED): decoded typed sequence, per sample. RX deserialization product (ADR 0062)
      (dotimes (i n) (setf (aref vec i) (funcall elem-reader c mode)))
      vec)))

(defun* cdr-get-sequence (c elem-reader mode)
    (function (dds.core.buffer:cursor function cdr-mode) simple-vector)
  "Read a sequence from cursor C into an UNSPECIALIZED simple-vector (element-type T) — the generic
   entry point, kept for callers with no static element type. Prefer cdr-get-sequence-typed on any
   data path: this one costs 8 B per element regardless of element type (see that docstring)."
  (cdr-get-sequence-typed c elem-reader mode t))

;;;; XCDR2 framing headers. DHEADER: XTypes 1.3 §7.4.3.4.1 (UInt32 serialized
;;;; size of the following object, 4-byte aligned, stream endianness). EMHEADER1
;;;; + LC + NEXTINT: §7.4.3.4.2. Full DELIMITED/MUTABLE struct serialization is a
;;;; later increment; these are the pinned, byte-exact primitives.

(defun* cdr-put-dheader (c ssize mode)
    (function (dds.core.buffer:cursor (integer 0) cdr-mode) (integer 0))
  "Write a DHEADER = UInt32 serialized size of the object that follows."
  (cdr-align c 4 mode)
  (dds.core.buffer:put-u32 c ssize))
(defun* cdr-get-dheader (c mode)
    (function (dds.core.buffer:cursor cdr-mode) (integer 0))
  "Read a DHEADER = UInt32 serialized size of the object that follows."
  (cdr-align c 4 mode)
  (dds.core.buffer:get-u32 c))

(defconstant +lc-1-byte+  0)
(defconstant +lc-2-bytes+ 1)
(defconstant +lc-4-bytes+ 2)
(defconstant +lc-8-bytes+ 3)

(declaim (inline emheader1-encode))
(defun* emheader1-encode (must-understand lc member-id)
    (function (t (integer 0 7) (integer 0)) (unsigned-byte 32))
  "EMHEADER1 = (M_FLAG<<31) + (LC<<28) + (MemberId & 0x0fffffff) (§7.4.3.4.2)."
  (logior (ash (if must-understand 1 0) 31)
          (ash (logand lc #x7) 28)
          (logand member-id #x0fffffff)))
(defun* emheader1-decode (u32)
    (function ((unsigned-byte 32)) (values t fixnum fixnum))
  "Inverse of emheader1-encode: (values must-understand lc member-id)."
  (values (logbitp 31 u32)
          (ldb (byte 3 28) u32)
          (logand u32 #x0fffffff)))
(defun* lc-for-length (n)
    (function (integer) (or null (integer 0 3)))
  "Length code for an N-byte member when N in {1,2,4,8}; else NIL (needs NEXTINT,
   LC 4-7) (§7.4.3.4.2)."
  (case n (1 +lc-1-byte+) (2 +lc-2-bytes+) (4 +lc-4-bytes+) (8 +lc-8-bytes+) (t nil)))
