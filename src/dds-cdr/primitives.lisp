(in-package #:dds.cdr)

;;;; XCDR primitive + composite codec. HOT PATH: defstruct + monomorphic funs.
;;;; Implements REQUIREMENTS FR-CDR-1 (classic CDR primitives/strings/sequences)
;;;; and FR-CDR-2 (the XCDR2 4-byte alignment cap). The 16-bit encapsulation IDs,
;;;; MUTABLE EMHEADER bit layout, and byte-exactness vs. RTI are pinned by the
;;;; reference corpus (FR-CDR-3/8) — NOT encoded from memory. Modes are :xcdr1
;;;; (classic, align up to 8) and :xcdr2 (align capped at 4).



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

;;; IEEE 754 floating point (ADR 0111 slice 1; XTypes 1.3 Table 31 §7.4.1.1.1, [IEEE-754]).
;;;
;;; DELIBERATELY BUILT ON THE INTEGER WRITERS, not on a parallel float path. The bit pattern goes on the
;;; wire as a plain unsigned integer of the same width, so byte order comes from the cursor's endianness
;;; and alignment comes from CDR-ALIGN's MODE cap — both already correct and tested. A separate float
;;; writer would restate two rules that have exactly one right answer, which is how they drift apart.
;;;
;;; ⚠️ THE ALIGNMENT IS NOT THE SIZE. Float32 is size 4 / align 4, Float64 size 8 / align 8 (Table 31),
;;; and Float64 therefore inherits the XCDR1-vs-XCDR2 divergence exactly as Int64 does:
;;; MALIGN(O) = MIN(O.type.alignment, XCDR.maxalign) with MAXALIGN(VERSION1)=8, MAXALIGN(VERSION2)=4
;;; (§7.4.2) — so a Float64 aligns to 8 under XCDR1 and to 4 under XCDR2. CDR-ALIGN applies that cap.
(defun* cdr-put-f32 (c v mode)
    (function (dds.core.buffer:cursor single-float cdr-mode) (integer 0))
  "Write an IEEE 754 binary32 to cursor C, MODE-capped 4-byte alignment (XTypes Table 31: Float32)."
  (cdr-put-u32 c (dds.pal:f32-bits v) mode))
(defun* cdr-get-f32 (c mode)
    (function (dds.core.buffer:cursor cdr-mode) single-float)
  "Read an IEEE 754 binary32 from cursor C, MODE-capped 4-byte alignment (XTypes Table 31: Float32)."
  (dds.pal:f32-from-bits (cdr-get-u32 c mode)))
(defun* cdr-put-f64 (c v mode)
    (function (dds.core.buffer:cursor double-float cdr-mode) (integer 0))
  "Write an IEEE 754 binary64 to cursor C, MODE-capped alignment (8 for XCDR1, 4 for XCDR2 — Table 31
   gives Float64 alignment 8, and §7.4.2's MAXALIGN caps it at 4 under version 2)."
  (cdr-put-u64 c (dds.pal:f64-bits v) mode))
(defun* cdr-get-f64 (c mode)
    (function (dds.core.buffer:cursor cdr-mode) double-float)
  "Read an IEEE 754 binary64 from cursor C, MODE-capped alignment (8 for XCDR1, 4 for XCDR2)."
  (dds.pal:f64-from-bits (cdr-get-u64 c mode)))

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

;;; string: 4-byte length (INCLUDING the NUL) + octets + NUL (FR-CDR-1), the octets encoded as
;;; UTF-8 (RFC 3629 §3) — which is what IDL and XTypes mean by `string`. Byte-exactness is pinned
;;; by the corpus (FR-CDR-8); ASCII is a UTF-8 subset, so ASCII vectors are unaffected by encoding.
(defconstant +utf8-max-code-point+ #x10FFFF
  "The largest code point UTF-8 encodes (RFC 3629 §3). The encoding was deliberately restricted to
   the range reachable by UTF-16, so an octet sequence decoding above this is MALFORMED — not merely
   unusual — and a decoder must refuse it rather than pass on whatever it computed.")

(defun* utf8-octet-length (s)
    (function (string) (integer 0))
  "The number of octets S occupies encoded as UTF-8 (RFC 3629 §3), excluding the terminating NUL.

   An IDL `string<N>` bound counts OCTETS, so this — never CL:LENGTH — is what a bound must be
   measured against. The two coincide only for ASCII, which is exactly why using the character count
   looks correct until the first multi-byte character arrives and the buffer is too small."
  (let ((n 0))
    (declare (type (integer 0) n))
    (dotimes (i (length s) n)
      (let ((cp (char-code (char s i))))
        (incf n (cond ((< cp #x80) 1)        ; RFC 3629 §3: 0xxxxxxx
                      ((< cp #x800) 2)       ;              110xxxxx 10xxxxxx
                      ((< cp #x10000) 3)     ;              1110xxxx 10xxxxxx 10xxxxxx
                      (t 4)))))))            ;              11110xxx 10xxxxxx 10xxxxxx 10xxxxxx

(defmacro %do-utf8-octets ((byte-var cp-form) &body emit)
  "Encode code point CP-FORM to its one-to-four UTF-8 octets (RFC 3629 §3, the table quoted in
   UTF8-OCTET-LENGTH — each continuation octet carries six payload bits under the 10xxxxxx tag) and run
   EMIT once per octet with BYTE-VAR bound to it. THE SINGLE definition of the UTF-8 encode byte patterns
   (DRY): %cdr-put-utf8-char emits to a cursor, string-to-utf8-octets to a heap vector. A macro, not a
   function, so it INLINES with no per-octet funcall — the hot-path codec pays nothing for the sharing,
   and %cdr-put-utf8-char's generated code is unchanged (verified byte-exact by the corpus)."
  (let ((cp (gensym "CP")))
    (flet ((octet (bexpr) `(let ((,byte-var ,bexpr)) ,@emit)))
      `(let ((,cp ,cp-form))
         (declare (type (integer 0) ,cp))
         (cond ((< ,cp #x80) ,(octet cp))
               ((< ,cp #x800)
                ,(octet `(logior #xC0 (ash ,cp -6)))
                ,(octet `(logior #x80 (logand ,cp #x3F))))
               ((< ,cp #x10000)
                ,(octet `(logior #xE0 (ash ,cp -12)))
                ,(octet `(logior #x80 (logand (ash ,cp -6) #x3F)))
                ,(octet `(logior #x80 (logand ,cp #x3F))))
               (t
                ,(octet `(logior #xF0 (ash ,cp -18)))
                ,(octet `(logior #x80 (logand (ash ,cp -12) #x3F)))
                ,(octet `(logior #x80 (logand (ash ,cp -6) #x3F)))
                ,(octet `(logior #x80 (logand ,cp #x3F)))))))))

(defun* %cdr-put-utf8-char (c cp)
    (function (dds.core.buffer:cursor (integer 0)) t)
  "Write code point CP to cursor C as one to four UTF-8 octets (RFC 3629 §3, the table quoted in
   UTF8-OCTET-LENGTH). Each continuation octet carries six payload bits under the 10xxxxxx tag. The
   encode byte patterns are %do-utf8-octets (shared with string-to-utf8-octets), inlined here so the
   generated code is unchanged from the hand-written cond it replaced."
  (%do-utf8-octets (b cp) (dds.core.buffer:put-u8 c b)))

(defun* cdr-put-string (c s mode)
    (function (dds.core.buffer:cursor string cdr-mode) string)
  "Write string S to cursor C as UTF-8: a 4-octet length (octets INCLUDING the NUL), the encoded
   octets, then the NUL (FR-CDR-1; RFC 3629 §3 for the encoding).

   THE LENGTH PREFIX COUNTS OCTETS, NOT CHARACTERS. For a multi-byte string the two differ; the
   prefix was always defined in octets, and only a one-octet-per-character codec made them look
   interchangeable. Any caller sizing a buffer for a string member must use UTF8-OCTET-LENGTH.

   This replaces a Latin-1 codec that was wrong in both directions: it refused every character above
   U+00FF outright, and for U+0080..U+00FF it emitted a single octet that a conformant peer decodes
   as a malformed UTF-8 sequence. Topic and type names travel through here in SPDP/SEDP, so that
   defect reached discovery, not only user payloads."
  (cdr-align c 4 mode)
  (dds.core.buffer:put-u32 c (1+ (utf8-octet-length s)))
  (dotimes (i (length s))
    (%cdr-put-utf8-char c (char-code (char s i))))
  (dds.core.buffer:put-u8 c 0)
  s)

(defun* string-to-utf8-octets (s)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Encode string S to a FRESH heap octet vector of its UTF-8 bytes (RFC 3629 §3) — NO 4-octet length
   prefix and NO NUL terminator, unlike CDR-PUT-STRING which frames a CDR string. The standalone
   encoder for callers that need raw UTF-8 octets to hand to a byte sink, e.g. an RFC 5424 syslog UDP
   datagram (ADR 0082 §7, FR-LOG-8). Shares the encode byte patterns with the CDR codec via
   %do-utf8-octets (DRY). Off the measured hot path (a logging sink allocates when it emits)."
  ;; a logging-sink utility (RFC 5424 syslog datagram, FR-LOG-8), never on the RTPS per-sample path —
  ;; the codec uses %cdr-put-utf8-char into a cursor, not this.
  (let ((out (make-array (utf8-octet-length s) :element-type '(unsigned-byte 8)))   ; HOTPATH-ALLOC(COLD): logging-sink util, off the per-sample path
        (i 0))
    (declare (type (integer 0) i) (type (simple-array (unsigned-byte 8) (*)) out))
    (dotimes (k (length s))
      (%do-utf8-octets (b (char-code (char s k)))
        (setf (aref out i) b)
        (incf i)))
    out))
(defun* %utf8-lead-length (b0)
    (function ((unsigned-byte 8)) (integer 0 4))
  "Octets in the UTF-8 sequence introduced by lead octet B0, or 0 when B0 cannot lead one
   (RFC 3629 §3): 0xxxxxxx = 1, 110xxxxx = 2, 1110xxxx = 3, 11110xxx = 4. A continuation octet
   (10xxxxxx) is not a lead, and the 5- and 6-octet forms of the original UTF-8 were REMOVED by
   RFC 3629 — accepting either is how a decoder admits sequences the encoder can never produce."
  (cond ((< b0 #x80) 1)
        ((< b0 #xC0) 0)     ; 10xxxxxx — a continuation octet cannot lead a sequence
        ((< b0 #xE0) 2)
        ((< b0 #xF0) 3)
        ((< b0 #xF8) 4)
        (t 0)))             ; 11111xxx — the retired 5/6-octet leads

(defun* %utf8-decode-at (vec pos limit)
    (function ((simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) (values t (integer 0 4)))
  "Decode the UTF-8 sequence at VEC[POS], where LIMIT is the first index past the string's octets.
   Returns (values code-point octets), or (values NIL 0) when the sequence is malformed.

   REFUSES, rather than repairs, every ill-formed case (RFC 3629 §3 and the §10 security rationale):
   a bad lead octet; a sequence truncated by LIMIT; a continuation octet that is not 10xxxxxx; an
   OVER-LONG encoding (a code point written in more octets than it needs — `C0 AF` decodes to '/'
   and is the classic way past a filter that checked the one-octet form); a UTF-16 surrogate
   (U+D800..U+DFFF, which is not a character); and anything above +UTF8-MAX-CODE-POINT+.

   Substituting U+FFFD would be the other option and is wrong here: it hands the caller a string it
   cannot distinguish from one the peer actually sent."
  (let ((seq (%utf8-lead-length (aref vec pos))))
    (when (or (zerop seq) (> (+ pos seq) limit))
      (return-from %utf8-decode-at (values nil 0)))
    (let ((cp (ecase seq
                (1 (aref vec pos))
                (2 (logand (aref vec pos) #x1F))
                (3 (logand (aref vec pos) #x0F))
                (4 (logand (aref vec pos) #x07)))))
      (loop for i from 1 below seq
            do (let ((b (aref vec (+ pos i))))
                 (unless (= (logand b #xC0) #x80)          ; every continuation octet is 10xxxxxx
                   (return-from %utf8-decode-at (values nil 0)))
                 (setf cp (logior (ash cp 6) (logand b #x3F)))))
      (when (or (and (= seq 2) (< cp #x80))                ; over-long: fits in fewer octets
                (and (= seq 3) (< cp #x800))
                (and (= seq 4) (< cp #x10000))
                (<= #xD800 cp #xDFFF)                      ; surrogate half — not a character
                (> cp +utf8-max-code-point+))
        (return-from %utf8-decode-at (values nil 0)))
      (values cp seq))))

(defun* cdr-get-string (c mode)
    (function (dds.core.buffer:cursor cdr-mode) (values string (or null keyword)))
  "Read a UTF-8 string from cursor C: 4-octet length (octets INCLUDING the NUL) + the octets + NUL
   (FR-CDR-1; RFC 3629 §3 for the encoding).

   Returns (values string NIL), or (values \"\" :MALFORMED-UTF8) when the octets are not well-formed
   UTF-8. The primary value stays a STRING on the failure path deliberately: generated deserializers
   assign it into a slot declared `string`, and handing them NIL would turn a peer's malformed octets
   into a type violation at (safety 0). Callers that must not accept corrupt text — discovery's topic
   and type names, TypeLookup, TypeObject — check the status and refuse the record; a caller that
   ignores it gets an empty string, never garbage that reads as data.

   The wire length is validated against the remaining buffer extent BEFORE anything is allocated
   (NFR-SEC-POSTURE), and every octet the decoder touches is bounded by that same extent, so a
   sequence truncated at the end of a datagram is refused rather than read past. Note: allocates the
   result string; the pooled zero-alloc deserialize path is a tracked follow-up (FR-LANG-5/NFR-DET)."
  (cdr-align c 4 mode)
  (let ((len (dds.core.buffer:get-u32 c)))
    ;; LEN includes the NUL: exactly LEN octets follow (NFR-SEC-POSTURE)
    (dds.core.buffer:check-room c len)
    (let* ((n (max 0 (1- len)))
           (vec (dds.core.buffer:octet-buffer-vec (dds.core.buffer:cursor-buffer c)))
           (start (dds.core.buffer:cursor-position c))
           (limit (+ start n))
           (chars 0))
      (declare (type (integer 0) chars))
      ;; Pass 1 validates and counts characters, because the decoded length is not the octet length
      ;; and the result string is sized before it is filled. Both passes share %UTF8-DECODE-AT, so
      ;; the validation and the decode can never drift apart.
      (let ((i start))
        (loop while (< i limit)
              do (multiple-value-bind (cp seq) (%utf8-decode-at vec i limit)
                   (declare (ignore cp))
                   (when (zerop seq)
                     (dds.core.buffer:cursor-set-position c (+ start len))
                     (return-from cdr-get-string (values "" :malformed-utf8)))
                   (incf chars)
                   (incf i seq))))
      (let ((s (make-string chars))   ; HOTPATH-ALLOC(TRACKED): decoded string, per string field. An RX DESERIALIZATION PRODUCT — pooling it collides with loan semantics (ADR 0062)
            (i start) (k 0))
        (declare (type (integer 0) k))
        (loop while (< i limit)
              do (multiple-value-bind (cp seq) (%utf8-decode-at vec i limit)
                   (setf (char s k) (code-char cp))
                   (incf k)
                   (incf i seq)))
        (dds.core.buffer:cursor-set-position c (+ start len))
        (values s nil)))))

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

(defun* lc-member-extent (lc nextint)
    (function ((integer 0 7) (unsigned-byte 32)) (integer 0))
  "Octets a MUTABLE member occupies, given its length code LC and NEXTINT (§7.4.3.4.2, rule (22)).

   Measured from where the member's serialization STARTS, which differs by code and is the whole
   subtlety here:

     LC 0-3  — no NEXTINT; the member starts after the 4-octet EMHEADER1 and is 1/2/4/8 octets.
     LC 4    — the member starts after NEXTINT and is NEXTINT octets.
     LC 5-7  — rule (22) rewinds the stream 4 octets, so the member starts AT the NEXTINT word and
               that word IS the member's own leading length. The spec's phrase 'serialized member
               length is also NEXTINT' therefore counts the octets AFTER the shared word, and the
               multipliers give the game away: LC 6 = '4*NEXTINT' and LC 7 = '8*NEXTINT' only make
               sense if NEXTINT is an ELEMENT COUNT and the multiplier is the element width (1/4/8).
               So the extent from the rewind point is 4 + width*NEXTINT.

   Reading the phrase literally instead — extent = NEXTINT from the rewind point — is self-
   contradictory: for a string of L octets the member is 4+L octets long while its own leading word
   holds L, so the NEXTINT the writer wrote is overwritten by a DIFFERENT value and no reader could
   recover the length. Four octets short per member, which desynchronises every member after it."
  (ecase lc
    (0 1) (1 2) (2 4) (3 8)
    (4 nextint)
    (5 (+ 4 nextint))
    (6 (+ 4 (* 4 nextint)))
    (7 (+ 4 (* 8 nextint)))))

;;;; XCDR1 MUTABLE (PL_CDR) parameter-list framing: XTypes 1.3 §7.4.1.2.1 + Table 34, rules
;;;; (23)-(25) of §7.4.3.5. Values are read from the clause, never recalled.

(defconstant +flag-impl-extension+ #x8000
  "FLAG_IMPL_EXTENSION — the most significant bit of a 16-bit PL_CDR parameter ID, marking an
   implementation-specific interpretation (DDS-XTypes 1.3 §7.4.1.2.1). It SHALL be zero for
   user-defined data types: the clause states that implementations of user-defined types 'will never
   set the FLAG_IMPL_EXTENSION bit', which is currently used only for RTPS discovery-defined types.
   Exported so the decoder can recognise — and refuse to mistake for a member id — a PID that sets it.")

(defconstant +flag-must-understand+ #x4000
  "FLAG_MUST_UNDERSTAND — the second most significant bit of a 16-bit PL_CDR parameter ID
   (DDS-XTypes 1.3 §7.4.1.2.1). Set 'if and only if the must_understand property of the member being
   encapsulated is set to true'. When a consumer does not recognise the parameter id, this bit is what
   decides between ignoring the member and discarding the entire data sample.")

(defconstant +pid-extended+ #x3f01
  "PID_EXTENDED — the reserved parameter id introducing the LONG PL_CDR member header, used when a
   member id or length does not fit the short form (DDS-XTypes 1.3 Table 34, §7.4.1.2.1). Table 34
   marks it FLAG_MUST_UNDERSTAND=Yes, so on the wire it appears as +pid-extended-mu+ = 0x7F01.")

(defconstant +pid-extended-mu+ #x7f01
  "PID_EXTENDED with the must-understand flag set = 0x4000 + 0x3F01, stated verbatim in
   DDS-XTypes 1.3 §7.4.1.2.1. This is the 16-bit value a long-form member header carries; the member's
   OWN must-understand flag lives in the following eMemberHeader's FLAG_2, not here.")

(defconstant +pid-list-end+ #x3f02
  "PID_LIST_END = 0x3F02 — 'Indicates the end of the parameter list data structure' (DDS-XTypes 1.3
   Table 34). This is the sentinel a USER-DEFINED mutable type terminates its parameter list with.

   Parameter id 1 (+pid-sentinel-rtps+) is NOT the general terminator: Table 34 confines that to
   Simple Discovery types, which 'shall be subject to a special limitation: member ID 1 shall not be
   used and parameter ID 1 shall terminate the parameter list to provide backwards compatibility'.
   The same entry requires implementations to 'be robust to receiving parameter ID 0x3F02 to indicate
   the end of a list as well', so a decoder accepts both and an encoder of a user type writes this one.")

(defconstant +pid-list-end-mu+ #x7f02
  "PID_LIST_END with FLAG_MUST_UNDERSTAND set = 0x4000 + 0x3F02 — the value actually written to terminate
   a parameter list. DDS-XTypes 1.3 Table 34 marks PID_LIST_END 'FLAG_MUST_UNDERSTAND set? Yes', and the
   clause requires an implementation to 'set the FLAG_MUST_UNDERSTAND bit as described in Table 34'. It is
   easy to write the bare 0x3F02 instead, because rule (23) names only 'PID_SENTINEL' and the flag lives
   in a different clause; the live RTI Connext vector (corpus/xcdr2/mutabledata-connext.bin) terminates
   with 0x7F02, which is what caught it here. A decoder masks the flags off before comparing, so both
   forms are RECOGNISED — this is about what we EMIT.")

(defconstant +pid-ignore+ #x3f03
  "PID_IGNORE = 0x3F03 — 'All consumers of this Data Representation shall ignore parameters with this
   ID' (DDS-XTypes 1.3 Table 34). Distinct from an unknown id: it is skipped unconditionally, and its
   must-understand bit never causes a sample to be discarded.")

(defconstant +pid-sentinel-rtps+ #x0001
  "The RTPS parameter-list terminator, parameter id 1 (PID_SENTINEL), which DDS-XTypes 1.3 Table 34
   retains for SIMPLE DISCOVERY types ONLY. It is defined here to document why a user-defined type's
   decoder must NOT treat it as a terminator — see pl-end-of-list-p. Discovery's own ParameterList
   codec is a separate thing and keeps using it.")

(defconstant +emheader-mu-flag+ #x40000000
  "FLAG_2 of the long-form eMemberHeader = 0x40000000, which carries the MEMBER's must-understand
   flag (DDS-XTypes 1.3 §7.4.1.2.1: 'FLAG_2 encodes the must understand flag'). The remaining bits are
   FLAG_1 = 0x80000000 (implementation extension, zero for user types) and FLAG_3/FLAG_4 =
   0x20000000/0x10000000, both 'left for future extensions'; the low 28 bits are the member id.")

(declaim (inline pl-pid-encode))
(defun* pl-pid-encode (must-understand member-id)
    (function (t (integer 0)) (unsigned-byte 16))
  "The 16-bit short-form PL_CDR parameter id for MEMBER-ID (rule (24): FLAG_I + FLAG_M + M.id).
   FLAG_IMPL_EXTENSION is always zero — this emits user-defined types (§7.4.1.2.1)."
  (logior (if must-understand +flag-must-understand+ 0)
          (logand member-id #x3fff)))

(defun* pl-pid-decode (u16)
    (function ((unsigned-byte 16)) (values t fixnum t))
  "Inverse of pl-pid-encode: (values must-understand member-id impl-extension-p) for a 16-bit
   short-form PL_CDR parameter id (§7.4.1.2.1). The id is the low 14 bits; the two flag bits are
   returned separately rather than masked away, because must-understand decides whether an
   unrecognised member is skipped or discards the sample."
  (values (logtest u16 +flag-must-understand+)
          (logand u16 #x3fff)
          (logtest u16 +flag-impl-extension+)))

(declaim (inline pl-end-of-list-p))
(defun* pl-end-of-list-p (member-id)
    (function (integer) t)
  "T iff a decoded short-form PL_CDR member id terminates a USER-DEFINED type's parameter list.
   PID_LIST_END (0x3F02) and nothing else.

   It is tempting to also accept the RTPS PID_SENTINEL (parameter id 1) here, on the reasoning that a
   peer might emit it and refusing one would be a false-REJECT. THAT IS BACKWARDS, and it silently
   truncates samples. Member ids default to declaration order, so id 1 is the SECOND MEMBER of a
   typical type; treating parameter id 1 as a terminator ends the parameter list at that member and
   every later member decodes as its default — a wrong sample delivered as a good one, which is worse
   than any reject.

   DDS-XTypes 1.3 Table 34 is explicit that the id-1 terminator is not general: Simple Discovery types
   'shall be subject to a special limitation: member ID 1 shall not be used and parameter ID 1 shall
   terminate the parameter list to provide backwards compatibility.' The limitation buys back id 1 as
   a terminator precisely BY giving up id 1 as a member — and it is scoped to the built-in topic
   types, not to user-defined ones. So a user type uses PID_LIST_END and keeps member id 1."
  (= member-id +pid-list-end+))
