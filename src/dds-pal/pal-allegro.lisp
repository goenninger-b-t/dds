;;;; DDS.PAL — AllegroCL implementation of the L0 contract (ADR 0004 follow-through, ADR 0111 slice 1).
;;;; This file is the ONLY location permitted to carry #+allegro conditionals.
;;;;
;;;; ⛔ THIS BACKEND IS INCOMPLETE AND :DDS-PAL DOES NOT YET LOAD ON ALLEGROCL. The contract exports 118
;;;; symbols; 66 are implementation-independent (pal-contract / pal-net) and 40 are per-implementation. Only
;;;; the four IEEE 754 conversions below are implemented here. The remaining 36 — static memory
;;;; (alloc-static, free-static, static-pointer, static-length, static-sap+, static-vector-p), foreign SAP
;;;; access (load/store-sap-*, mem-ref/set-u8), atomics and fences (cas, atomic-incf, cas-sap-u32/u64,
;;;; atomic-incf-sap-u64, fence), threads and locks (make-lock, with-lock, make-condvar, condvar-wait/
;;;; signal/broadcast, join), and the platform miscellany (bytes-consed, gc-suggest, with-gc-inhibited,
;;;; pal-impl-name, fsync-stream, fsync-directory, install-signal-handler, register-image-restart-hook,
;;;; internal-bug-p) — are NOT here yet. Wiring them is its own slice; it is bounded and enumerated, not
;;;; open-ended, and AllegroCL has native answers for all of them (mp:, excl:, ff:, plus the
;;;; bordeaux-threads and CFFI backends the Clasp PAL already routes through).
;;;;
;;;; Recorded here rather than in a tracker so the gap is visible at the only place that can close it. Until
;;;; it closes, the operating contract's Definition of Done ("compiles and unit tests pass on SBCL AND
;;;; AllegroCL") is met on SBCL + Clasp only, and every "done" in this repository should be read that way.

(in-package #:dds.pal)

#-allegro
(eval-when (:compile-toplevel :load-toplevel :execute)
  ;; A diagnostic, not a condition (ADR 0064: nothing in our code signals), and not a WARN — under a
  ;; warnings-as-errors build policy that would fail a build merely for loading the wrong PAL.
  (format *error-output*
          "~&dds.pal: pal-allegro.lisp loaded on a non-Allegro build — this PAL is not the one for this image.~%"))

#+allegro
(progn

;;; IEEE 754 bit-pattern conversion (ADR 0111 §2.3; XTypes 1.3 Table 31 §7.4.1.1.1, [IEEE-754]).
;;;
;;; AllegroCL exposes the conversion as 16-bit SHORTS, most-significant first and UNSIGNED, rather than as
;;; one integer: (excl::single-float-to-shorts -1.0f0) => 49024, 0 = #xBF80 #x0000, and
;;; (excl::double-float-to-shorts -1.0d0) => 49136, 0, 0, 0 = #xBFF0 0 0 0. Probed on Allegro 11.0
;;; Enterprise (64-bit Linux x86-64 SMP), not assumed — the three backends genuinely disagree here: SBCL's
;;; single-float-bits returns a SIGNED pattern, Clasp's ext:single-float-to-bits an UNSIGNED one, and
;;; Allegro's is a multiple-value pair of unsigned shorts. Absorbing exactly this kind of divergence is what
;;; the PAL is for.
;;;
;;; ⚠️ NEGATIVE ZERO IS BIT-FAITHFUL THROUGH THESE PRIMITIVES, but NOT through Allegro's READER: the literal
;;; -0.0f0 reads as +0.0 (bits 0), and (- 0.0f0) is +0.0 too, while (* -1.0f0 0.0f0) is a true negative zero
;;; (bits #x80000000) which these functions carry intact in both directions. FLOAT-SIGN also reports 1.0 for
;;; it. A test that builds negative zero from the literal therefore silently tests +0.0 here while passing
;;; on SBCL, where the literal IS a negative zero — which is why RUN-FLOAT-PRIMITIVES-TEST constructs it by
;;; multiplication and asserts its bit pattern before using it.

(defun* f32-bits (x)
    (function (single-float) (unsigned-byte 32))
  "The IEEE 754 binary32 bit pattern of X as a 32-bit unsigned integer (XTypes 1.3 Table 31: Float32,
   encoded size 4, alignment 4). Total over denormals, the infinities, NaNs and negative zero."
  (multiple-value-bind (hi lo) (excl::single-float-to-shorts x)
    (logior (ash hi 16) lo)))

(defun* f32-from-bits (b)
    (function ((unsigned-byte 32)) single-float)
  "The single-float whose IEEE 754 binary32 bit pattern is B. Exact inverse of F32-BITS."
  (excl::shorts-to-single-float (ldb (byte 16 16) b) (ldb (byte 16 0) b)))

(defun* f64-bits (x)
    (function (double-float) (unsigned-byte 64))
  "The IEEE 754 binary64 bit pattern of X as a 64-bit unsigned integer (XTypes 1.3 Table 31: Float64,
   encoded size 8, alignment 8). Total, as F32-BITS."
  (multiple-value-bind (a b c d) (excl::double-float-to-shorts x)
    (logior (ash a 48) (ash b 32) (ash c 16) d)))

(defun* f64-from-bits (v)
    (function ((unsigned-byte 64)) double-float)
  "The double-float whose IEEE 754 binary64 bit pattern is V. Exact inverse of F64-BITS."
  (excl::shorts-to-double-float (ldb (byte 16 48) v) (ldb (byte 16 32) v)
                                (ldb (byte 16 16) v) (ldb (byte 16 0) v)))

) ; #+allegro
