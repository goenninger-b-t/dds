(in-package #:dds.tests)

;;; Exercise the type compiler (FR-TOOL-1): define a type from the s-expr DSL,
;;; then round-trip it through the GENERATED codec and the registered type-support
;;; vtable. gsample's i64 follows an i32, exercising the XCDR2 alignment path.

(dds.gen:define-dds-type gsample (:extensibility :final)
  (id :i32 :key t)
  (ts :i64)
  (label :string))

(defun* run-generated-type-test ()
    (function () t)
  "Test: a define-dds-type-generated struct serializes/deserializes byte-exactly via its type-support."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 512 2))
         (s (make-gsample :id -42 :ts 9999999999 :label "gen")))
    (flet ((rt (mode)
             (let* ((b (dds.core.arena:pool-acquire pool))
                    (wc (dds.core.buffer:cursor b :endianness :little)))
               (serialize-gsample s wc mode)
               (let ((wrote (dds.core.buffer:cursor-position wc))
                     (rc (dds.core.buffer:cursor b :endianness :little)))
                 (let ((q (deserialize-gsample rc mode)))
                   (dds.core.arena:pool-release pool b)
                   (values q wrote))))))
      (multiple-value-bind (q1 len1) (rt :xcdr2)
        (%check :gen-roundtrip
                (and (= (gsample-id q1) -42)
                     (= (gsample-ts q1) 9999999999)
                     (string= (gsample-label q1) "gen"))
                "generated XCDR2 round-trip mismatch")
        (%check :gen-size
                (= len1 (serialized-size-gsample s :xcdr2))
                (format nil "serialized-size ~d != bytes written ~d"
                        (serialized-size-gsample s :xcdr2) len1)))
      ;; type-support registered and usable purely through the vtable
      (let ((ts (dds.types:find-type-support "gsample")))
        (%check :gen-registered (and ts (dds.types:type-support-p ts))
                "type-support not registered")
        (let* ((b (dds.core.arena:pool-acquire pool))
               (wc (dds.core.buffer:cursor b :endianness :little)))
          (funcall (dds.types:type-support-serialize ts) s wc :xcdr2)
          (let* ((rc (dds.core.buffer:cursor b :endianness :little))
                 (q (funcall (dds.types:type-support-deserialize ts) rc :xcdr2)))
            (%check :gen-vtable (string= "gen" (gsample-label q))
                    "type-support vtable round-trip failed"))
          (dds.core.arena:pool-release pool b)))
      (dds.core.arena:teardown-arena arena)
      t)))

(dds.gen:define-dds-type kp-keyed-t (:extensibility :final)
  (id :i32 :key t)
  (v :i32))

(dds.gen:define-dds-type kp-nokey-t (:extensibility :final)
  (a :i32)
  (b :i32))

(defun* run-keyed-p-test ()
    (function () t)
  "type-support-keyed-p is T for a type with a @key member, NIL for a keyless type."
  (let ((kts (dds.types:find-type-support "kp-keyed-t"))
        (nts (dds.types:find-type-support "kp-nokey-t")))
    (%check :keyed-p-keyed (dds.types:type-support-keyed-p kts)
            "type with @key member should have keyed-p T")
    (%check :keyed-p-nokey (not (dds.types:type-support-keyed-p nts))
            "keyless type should have keyed-p NIL"))
  t)

(dds.gen:define-dds-type gseq (:extensibility :final)
  (n :u16)
  (vals (:sequence :i32))
  (tag :string))

(defun* run-generated-sequence-test ()
    (function () t)
  "Test: a generated type with a sequence member round-trips through its XCDR codec."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 512 1))
         (s (make-gseq :n 3 :vals #(10 -20 30) :tag "seq")))
    (let* ((b (dds.core.arena:pool-acquire pool))
           (wc (dds.core.buffer:cursor b :endianness :little)))
      (serialize-gseq s wc :xcdr2)
      (let* ((wrote (dds.core.buffer:cursor-position wc))
             (rc (dds.core.buffer:cursor b :endianness :little))
             (q (deserialize-gseq rc :xcdr2)))
        (%check :gseq-roundtrip
                (and (= (gseq-n q) 3)
                     (equalp (gseq-vals q) #(10 -20 30))
                     (string= (gseq-tag q) "seq"))
                "generated sequence round-trip mismatch")
        (%check :gseq-size (= wrote (serialized-size-gseq s :xcdr2))
                (format nil "seq serialized-size ~d != bytes written ~d"
                        (serialized-size-gseq s :xcdr2) wrote))
        (dds.core.arena:pool-release pool b)))
    (dds.core.arena:teardown-arena arena)
    t))

(dds.gen:define-dds-type gpoint (:extensibility :final)
  (x :i32)
  (y :i32))

(dds.gen:define-dds-type gseg (:extensibility :final)
  (a gpoint)
  (b gpoint)
  (tag :string))

(defun* run-generated-nested-test ()
    (function () t)
  "Test: a generated type with a nested-struct member round-trips through its XCDR codec."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 512 1))
         (s (make-gseg :a (make-gpoint :x 1 :y 2)
                       :b (make-gpoint :x -3 :y 4)
                       :tag "seg")))
    (let* ((buf (dds.core.arena:pool-acquire pool))
           (wc (dds.core.buffer:cursor buf :endianness :little)))
      (serialize-gseg s wc :xcdr2)
      (let* ((wrote (dds.core.buffer:cursor-position wc))
             (rc (dds.core.buffer:cursor buf :endianness :little))
             (q (deserialize-gseg rc :xcdr2)))
        (%check :gseg-nested-roundtrip
                (and (= (gpoint-x (gseg-a q)) 1) (= (gpoint-y (gseg-a q)) 2)
                     (= (gpoint-x (gseg-b q)) -3) (= (gpoint-y (gseg-b q)) 4)
                     (string= (gseg-tag q) "seg"))
                "generated nested round-trip mismatch")
        (%check :gseg-nested-size (= wrote (serialized-size-gseg s :xcdr2))
                (format nil "nested serialized-size ~d != bytes written ~d"
                        (serialized-size-gseg s :xcdr2) wrote))
        (dds.core.arena:pool-release pool buf)))
    (dds.core.arena:teardown-arena arena)
    t))

;;; Pooled zero-alloc deserialize (NFR-PERF-8). mpoint/mline are fully fixed-size
;;; (no strings/sequences), so deserialize-into-mline fills a loaned struct in
;;; place with no per-sample allocation.

(dds.gen:define-dds-type mpoint (:extensibility :final)
  (x :i32)
  (y :i32))

(dds.gen:define-dds-type mline (:extensibility :final)
  (a mpoint)
  (b mpoint)
  (n :i32))

(defun* run-generated-into-test ()
    (function () t)
  "Test: the generated zero-alloc serialize-into path consumes no heap (NFR-MEM)."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 512 1))
         (ts (dds.types:find-type-support "mline"))
         (src (make-mline :a (make-mpoint :x 1 :y 2) :b (make-mpoint :x 3 :y 4) :n 5))
         (sample (funcall (dds.types:type-support-sample-pool-alloc ts))))
    (%check :into-loan (and sample (mline-p sample)) "sample-pool-alloc returned non-sample")
    (let* ((buf (dds.core.arena:pool-acquire pool))
           (wc (dds.core.buffer:cursor buf :endianness :little)))
      (serialize-mline src wc :xcdr2)
      (let ((rc (dds.core.buffer:cursor buf :endianness :little)))
        (deserialize-into-mline sample rc :xcdr2))
      (%check :into-roundtrip
              (and (= (mpoint-x (mline-a sample)) 1) (= (mpoint-y (mline-a sample)) 2)
                   (= (mpoint-x (mline-b sample)) 3) (= (mpoint-y (mline-b sample)) 4)
                   (= (mline-n sample) 5))
              "deserialize-into round-trip mismatch")
      (dds.core.arena:pool-release pool buf))
    (funcall (dds.types:type-support-sample-pool-free ts) sample)
    (dds.core.arena:teardown-arena arena)
    t))

;;; WP-DATA-REPRESENTATION step 2 (TX in the offered representation, DDS-XTypes 1.3 §7.6.3.1.1).
;;; txr8 has an i8 followed by an i64 so the XCDR1 8-byte alignment (i64 @ body offset 8, body 16)
;;; differs from the XCDR2 4-byte-capped alignment (i64 @ body offset 4, body 12) — the 8-vs-4 cap.
;;; txr8 is the non-FlatData (struct codec) arm; txr8fd the FlatData (TX-transcode) arm.
(dds.gen:define-dds-type txr8 (:extensibility :final)
  (a :i8 :key t)
  (b :i64))

(dds.gen:define-dds-type txr8fd (:flatdata t)
  (a :i8 :key t)
  (b :i64))

(defun* %txr8-oracle (mode va vb)
    (function (symbol integer integer) (simple-array (unsigned-byte 8) (*)))
  "Independent hand-built SerializedPayload oracle for the txr8 (i8 a, i64 b) type in MODE
   (:xcdr1 / :xcdr2): the 4-octet encap header (rep id NBO + 2-octet options whose low 2 bits =
   the body trailing pad), then the i8 at body offset 0 (two's-complement u8) + alignment pad to
   the mode-capped i64 boundary (XCDR1 -> 8, XCDR2 -> 4) + the LE i64. NO codec call — pinned to
   DDS-XTypes 1.3 §7.6.3.1.1/.2 by hand so it is a true oracle, not the code under test."
  (let* ((encap (ecase mode (:xcdr2 #x0007) (:xcdr1 #x0001)))   ; +representation-ids+ values (§7.6.3.1.2 Table 60)
         (i64-off (ecase mode (:xcdr2 4) (:xcdr1 8)))            ; i8@0, then align to min(8, mode-cap)
         (body-len (+ i64-off 8))
         (pad (mod (- 4 (mod body-len 4)) 4))                    ; trailing pad in the encap OPTIONS (§7.6.3.1.2)
         (total (+ 4 body-len))
         (out (make-array total :element-type '(unsigned-byte 8) :initial-element 0))
         (ua (logand va #xff))
         (ub (logand vb #xffffffffffffffff)))
    (setf (aref out 0) (ldb (byte 8 8) encap) (aref out 1) (ldb (byte 8 0) encap))   ; rep id, NBO
    (setf (aref out 3) (logand pad 3))                                               ; options pad bits
    (setf (aref out 4) ua)                                                           ; i8 @ body offset 0
    (dotimes (i 8) (setf (aref out (+ 4 i64-off i)) (ldb (byte 8 (* 8 i)) ub)))      ; LE i64
    out))

(defun* run-tx-representation-test ()
    (function () t)
  "WP-DATA-REPRESENTATION step 2 (DDS-XTypes 1.3 §7.6.3.1.1): a writer's OFFERED representation
   selects the TX SerializedPayload encoding. An (:xcdr1) writer emits a PLAIN_CDR_LE (0x0001)
   header + an XCDR1 (8-byte-aligned) body; the default (:xcdr2) writer emits PLAIN_CDR2_LE (0x0007)
   + an XCDR2 (4-byte-capped) body — BYTE-IDENTICAL to before. Asserted byte-exact vs %txr8-oracle
   (an independent hand-built oracle) for BOTH the non-FlatData struct codec AND the FlatData
   TX-transcode, and the XCDR1 body is 4 octets LONGER than XCDR2 (the i64's 8-vs-4 alignment)."
  (let ((ts (dds.types:find-type-support "txr8"))
        (fts (dds.types:find-type-support "txr8fd"))
        (va -2) (vb #x0102030405060708))
    (%check :txr8-ts (and ts fts) "txr8 / txr8fd type-support not registered")
    ;; non-FlatData: default XCDR2 (unchanged wire) + opt-in XCDR1, each byte-exact vs the oracle
    (let* ((s (make-txr8 :a va :b vb))
           (x2 (dds.dcps::%serialize-sample ts s :xcdr2))
           (x1 (dds.dcps::%serialize-sample ts s :xcdr1)))
      (%check :txr8-xcdr2-default-byte-exact (equalp x2 (%txr8-oracle :xcdr2 va vb))
              (format nil "non-FlatData XCDR2 default ~s != oracle ~s" x2 (%txr8-oracle :xcdr2 va vb)))
      (%check :txr8-xcdr2-encap (and (= (aref x2 0) 0) (= (aref x2 1) #x07))
              (format nil "default writer must emit PLAIN_CDR2_LE 0x0007, got ~2,'0x~2,'0x" (aref x2 0) (aref x2 1)))
      (%check :txr8-xcdr1-byte-exact (equalp x1 (%txr8-oracle :xcdr1 va vb))
              (format nil "non-FlatData XCDR1 ~s != oracle ~s" x1 (%txr8-oracle :xcdr1 va vb)))
      (%check :txr8-xcdr1-encap (and (= (aref x1 0) 0) (= (aref x1 1) #x01))
              (format nil "an (:xcdr1) writer must emit PLAIN_CDR_LE 0x0001, got ~2,'0x~2,'0x" (aref x1 0) (aref x1 1)))
      (%check :txr8-xcdr1-longer (= (length x1) (+ (length x2) 4))
              (format nil "XCDR1 payload ~d must be 4 longer than XCDR2 ~d (i64 8-vs-4 align)" (length x1) (length x2))))
    ;; FlatData (R6): identity XCDR2 unchanged + TX-transcode XCDR1, both byte-exact vs the same oracle
    (let ((fd (make-txr8fd-flatdata)))
      (setf (txr8fd-a-fd fd) va (txr8fd-b-fd fd) vb)
      (let ((fx2 (dds.dcps::%serialize-sample fts fd :xcdr2))
            (fx1 (dds.dcps::%serialize-sample fts fd :xcdr1)))
        (%check :txr8fd-xcdr2-identity-byte-exact (equalp fx2 (%txr8-oracle :xcdr2 va vb))
                (format nil "FlatData XCDR2 identity ~s != oracle ~s" fx2 (%txr8-oracle :xcdr2 va vb)))
        (%check :txr8fd-xcdr1-transcode-byte-exact (equalp fx1 (%txr8-oracle :xcdr1 va vb))
                (format nil "FlatData XCDR1 TX-transcode ~s != oracle ~s" fx1 (%txr8-oracle :xcdr1 va vb))))))
  t)

(defun* run-tx-rx-representation-roundtrip-test ()
    (function () t)
  "WP-DATA-REPRESENTATION step 2 (DDS-XTypes 1.3 §7.6.3.1.1): an (:xcdr1) writer's SerializedPayload is read
   back correctly by the reader (%serialize-sample :xcdr1 -> %deserialize-sample, which decodes in the
   encap-declared representation) — field values AND the XCDR2-BE keyhash (RTPS 2.5 §9.6.4.8, rep-independent)
   are correct, for BOTH the non-FlatData struct codec (XCDR1 8-vs-4 re-alignment) and the FlatData RX-transcode."
  (let ((ts (dds.types:find-type-support "txr8"))
        (fts (dds.types:find-type-support "txr8fd"))
        (va -2) (vb #x0102030405060708))
    ;; non-FlatData: TX XCDR1 -> RX decodes (mode/endianness from the header), values + keyhash match XCDR2
    (let* ((s (make-txr8 :a va :b vb))
           (q1 (dds.dcps::%deserialize-sample ts (dds.dcps::%serialize-sample ts s :xcdr1)))
           (q2 (dds.dcps::%deserialize-sample ts (dds.dcps::%serialize-sample ts s :xcdr2))))
      (%check :txr8-rx-xcdr1-values (and (= (txr8-a q1) va) (= (txr8-b q1) vb))
              (format nil "XCDR1 TX->RX field mismatch: a=~d b=~d" (txr8-a q1) (txr8-b q1)))
      (%check :txr8-rx-xcdr2-values (and (= (txr8-a q2) va) (= (txr8-b q2) vb))
              (format nil "XCDR2 TX->RX field mismatch: a=~d b=~d" (txr8-a q2) (txr8-b q2)))
      (%check :txr8-rx-keyhash-rep-independent
              (equalp (key-hash-txr8 s) (key-hash-txr8 q1))
              "keyhash must be identical regardless of the user-data representation (XCDR2-BE, §9.6.4.8)"))
    ;; FlatData: TX XCDR1 (transcode) -> RX (FlatData read/transcode), values via the -fd accessors + keyhash
    (let ((fd (make-txr8fd-flatdata)))
      (setf (txr8fd-a-fd fd) va (txr8fd-b-fd fd) vb)
      (let ((q1 (dds.dcps::%deserialize-sample fts (dds.dcps::%serialize-sample fts fd :xcdr1))))
        (%check :txr8fd-rx-xcdr1-values (and (= (txr8fd-a-fd q1) va) (= (txr8fd-b-fd q1) vb))
                (format nil "FlatData XCDR1 TX->RX field mismatch: a=~d b=~d" (txr8fd-a-fd q1) (txr8fd-b-fd q1)))
        (%check :txr8fd-rx-keyhash-rep-independent
                (equalp (key-hash-txr8fd-fd fd) (key-hash-txr8fd-fd q1))
                "FlatData keyhash must be identical regardless of the user-data representation (XCDR2-BE)"))))
  t)

(defun* run-mem-test ()
    (function () t)
  "Measured zero-alloc serialize + deserialize (NFR-PERF-8). Asserted on SBCL
   (exact bytes-consed); on Clasp bytes-consed is 0 (gap) so it only smokes."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 512 1))
         (ts (dds.types:find-type-support "mline"))
         (src (make-mline :a (make-mpoint :x 7 :y 8) :b (make-mpoint :x 9 :y 10) :n 11))
         (sample (funcall (dds.types:type-support-sample-pool-alloc ts)))
         (buf (dds.core.arena:pool-acquire pool))
         (wc (dds.core.buffer:cursor buf :endianness :little))
         (rc (dds.core.buffer:cursor buf :endianness :little))
         (iters 100000))
    (serialize-mline src wc :xcdr2)
    (deserialize-into-mline sample rc :xcdr2)         ; warm up both paths
    (flet ((measure (label thunk)
             (declare (type function thunk))
             (let ((before (dds.pal:bytes-consed)))
               (dotimes (i iters) (funcall thunk))
               (let* ((delta (- (dds.pal:bytes-consed) before))
                      (per (/ (float delta) iters)))
                 (format t "~&  mem[~11a]: ~9d bytes / ~d iters = ~,4f bytes/sample (~a)~%"
                         label delta iters per (dds.pal:pal-impl-name))
                 (when (eq (dds.pal:pal-impl-name) :sbcl)
                   (%check :zero-alloc (< per 1.0)
                           (format nil "~a: ~,4f bytes/sample (expected ~~0)" label per)))))))
      (measure "serialize"
               (lambda () (dds.core.buffer:cursor-reset wc) (serialize-mline src wc :xcdr2)))
      (measure "deserialize"
               (lambda () (dds.core.buffer:cursor-reset rc) (deserialize-into-mline sample rc :xcdr2)))
      (measure "round-trip"
               (lambda ()
                 (dds.core.buffer:cursor-reset wc) (serialize-mline src wc :xcdr2)
                 (dds.core.buffer:cursor-reset rc) (deserialize-into-mline sample rc :xcdr2))))
    (funcall (dds.types:type-support-sample-pool-free ts) sample)
    (dds.core.arena:pool-release pool buf)
    (dds.core.arena:teardown-arena arena)
    t))
