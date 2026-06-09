;;;; Inbound RTI PID_TYPE_OBJECT_LB: ZLIB-inflate the vendor-compressed COMPLETE TypeObject
;;;; so a peer's full type is available for match-time assignability (ADR 0009 — the
;;;; "required path" for XTypes interop, since Connext advertises types via this vendor
;;;; parameter and never the minimal-hash PID_TYPE_INFORMATION). PID_TYPE_OBJECT_LB (0x8021)
;;;; is RTI-vendor-specific, NOT an OMG-spec parameter; its wire layout is reverse-engineered
;;;; from the live Connext 7.3.1 wire (clean-room — observed bytes, no RTI source). Control
;;;; plane, off the hot path; chipz is pure-Lisp inflate (no native dependency).

(in-package #:dds.types)

(defconstant +type-object-lb-compression-zlib+ 1
  "PID_TYPE_OBJECT_LB compression_class_id for ZLIB, observed on the Connext 7.3.1 wire.
   NOT an OMG-spec constant — interop reverse-engineering (ADR 0009).")

(defparameter *max-type-object-bytes* (* 1 1024 1024)
  "Upper bound on an inbound PID_TYPE_OBJECT_LB's declared UNCOMPRESSED length; a larger
   value is rejected before inflating (resource-exhaustion guard for the discovery parser,
   NFR-SEC-POSTURE — a small compressed buffer must not be allowed to claim a huge inflate).")

(declaim (ftype (function ((array (unsigned-byte 8) (*)) &optional (integer 0) (integer 0))
                          (or null (simple-array (unsigned-byte 8) (*))))
                inflate-type-object-lb))
(defun inflate-type-object-lb (octets &optional (start 0) (end (length octets)))
  "Parse an inbound RTI PID_TYPE_OBJECT_LB parameter value OCTETS[START,END) and return the
   inflated COMPLETE TypeObject bytes (a fresh octet vector), or NIL if the buffer is short,
   the compression class is not ZLIB, a declared length is implausible, inflation fails, or
   the inflated size disagrees with the declared length.

   Vendor wire structure (little-endian, reverse-engineered from the Connext wire, clean-room):
     compression_class_id  u32   (1 = ZLIB)
     uncompressed_length   u32
     compressed_length     u32
     zlib_stream           octet[compressed_length]
   Every length is bounds-checked against the buffer FIRST, and uncompressed_length against
   *max-type-object-bytes* (NFR-SEC-POSTURE), before any allocation or inflate."
  (let ((n (- end start)))
    (when (< n 12) (return-from inflate-type-object-lb nil))
    (flet ((u32 (i) (let ((o (+ start i)))
                      (logior (aref octets o)
                              (ash (aref octets (+ o 1)) 8)
                              (ash (aref octets (+ o 2)) 16)
                              (ash (aref octets (+ o 3)) 24)))))
      (let ((class-id (u32 0)) (ulen (u32 4)) (clen (u32 8)))
        (when (or (/= class-id +type-object-lb-compression-zlib+)
                  (zerop ulen) (> ulen *max-type-object-bytes*)
                  (> (+ 12 clen) n))
          (return-from inflate-type-object-lb nil))
        (let* ((compressed (subseq octets (+ start 12) (+ start 12 clen)))
               (inflated (handler-case (chipz:decompress nil 'chipz:zlib compressed)
                           (error () nil))))
          (when (and inflated (= (length inflated) ulen))
            (coerce inflated '(simple-array (unsigned-byte 8) (*)))))))))

;;;; Type FINGERPRINT (heuristic, not a structural parse). RTI's legacy TypeObject (what
;;;; PID_TYPE_OBJECT_LB carries) is a vendor-proprietary "TypeLibrary" binary, NOT the OMG
;;;; CompleteTypeObject — a full parse is a large RTI-format reverse-engineering effort (see
;;;; ADR 0009). As a lightweight stand-in, these extract the literal strings RTI embeds (the
;;;; type name + multi-octet member names + dependent type names) for a type-aware match
;;;; heuristic and for diagnostics. Coarse on purpose: 1-octet member names and the structure
;;;; are not recovered; presence is confirmed, not order or shape.

(declaim (ftype (function ((array (unsigned-byte 8) (*)) &optional (integer 1 #.array-dimension-limit))
                          list) type-object-strings))
(defun type-object-strings (octets &optional (min-length 3))
  "The printable-ASCII runs (length >= MIN-LENGTH) in an inflated TypeObject's OCTETS, in
   order of appearance — a coarse fingerprint of the embedded names. Heuristic, not a parse."
  (let ((out '()) (start nil) (n (length octets)))
    (flet ((emit (end)
             (when (and start (>= (- end start) min-length))
               (push (map 'string #'code-char (subseq octets start end)) out))
             (setf start nil)))
      (dotimes (i n)
        (if (<= 32 (aref octets i) 126)
            (unless start (setf start i))
            (emit i)))
      (emit n))
    (nreverse out)))

(declaim (ftype (function ((array (unsigned-byte 8) (*)) list) t) type-object-mentions-all-p))
(defun type-object-mentions-all-p (octets names)
  "T iff every string in NAMES occurs as a contiguous byte substring of the inflated
   TypeObject OCTETS — a heuristic 'is this plausibly the type whose name + (multi-octet)
   member names are NAMES' check (e.g. for SEDP match-time, beyond the bare type-name).
   Coarse: it confirms presence, not structure/order, and cannot see 1-octet member names."
  (every (lambda (name)
           (search (map '(simple-array (unsigned-byte 8) (*)) #'char-code name) octets))
         names))
