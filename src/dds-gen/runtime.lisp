;;;; L3 — the RUNTIME half of the type compiler: the helpers that the code EMITTED by
;;;; define-dds-type calls on the PER-SAMPLE path. Deliberately a separate file from dsl.lisp,
;;;; which is macro-time only: its own mapcar/subseq/format nil run once at build time, so it
;;;; cannot be put under scripts/gate-hotpath.sh without blanket markers that would devalue the
;;;; marker. This file has no macro-time code at all, so it IS scanned — which is the only reason
;;;; a new per-sample allocation here can be seen (packages.lisp: "the code it EMITS is the hot path").

(in-package #:dds.gen)

(declaim (inline %copy-seq-into))
(defun* %copy-seq-into (src dst)
    (function ((or null sequence) (or null sequence)) (or null sequence))
  "Copy sequence/string SRC into DST for the generated COPY-INTO-<name> (ADR 0105), returning the
   sequence the destination slot must now hold. NIL SRC yields NIL.

   REUSE — the zero-allocation case — happens when DST is a vector of EXACTLY SRC's length and the
   SAME array element type; then DST's storage is filled by REPLACE and DST itself is returned.
   Every other shape allocates exactly one fresh sequence via COPY-SEQ.

   Reuse is deliberately NOT extended to a LONGER DST. The generated sequence/string slots are plain
   VECTOR / STRING with no fill pointer, so a longer DST could be made to read at SRC's length only by
   allocating a SUBSEQ — which allocates while claiming not to, and, because the result is stored back
   into the slot, ratchets the application's pre-sized buffer down to the shortest sample ever seen, so
   a later longer sample allocates again. One honest allocation beats two dishonest ones.

   The element-type test is a correctness guard, not an optimisation: the slot type is the
   UNSPECIALISED VECTOR (%parse-member's :ltype), so an application may legally pre-size a destination
   as, say, (unsigned-byte 8), and REPLACE into it from a (signed-byte 32) source signals a TYPE-ERROR
   after having already overwritten part of the destination. No Lisp condition may escape src/, so a
   representation mismatch falls to the allocating branch instead.

   COPY-SEQ is therefore the ONE allocation site in the whole copy path, which is exactly where
   ADR 0105 §5's slice-2 grow-in-chunks-to-a-ceiling rule has to land."
  (if (null src)
      nil
      (let ((n (length src)))
        (if (and (vectorp dst) (vectorp src)
                 (= n (length dst))
                 (equal (array-element-type dst) (array-element-type src)))
            (progn (replace dst src) dst)
            ;; HOTPATH-ALLOC(TRACKED): ADR 0105 §5 — a length or representation change reallocates until slice 2's grow-to-a-ceiling rule lands
            (copy-seq src)))))
