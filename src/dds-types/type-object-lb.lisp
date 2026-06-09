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
