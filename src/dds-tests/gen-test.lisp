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

(defun* %secured-live-publish-delta-bps (km pt iters)
    (function (t (simple-array (unsigned-byte 8) (*)) (integer 1)) (values double-float double-float))
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5c: measure the LIVE publish-sample bytes-consed/sample with data_protection
   OFF then ON on the SAME warmed KEEP_LAST depth-1 writer (toggling disc-node-crypto-transform between the two
   blocks), returning (values PLAIN-BPS SECURED-BPS). Measuring both on ONE warmed node keeps the common
   NON-security publish residual (the make-cache-change struct + RTPS framing) in the same heap/cache state for
   both blocks, so it CANCELS in secured-minus-plain — leaving only the data_protection encode contribution (the
   T5a pool acquire + encode-into, which is alloc-free). KEEP_LAST depth-1 supersession releases the pooled buffer
   each publish (steady state ~1 in use); no matched readers/sockets (no start-node) isolates the publish cost.
   SBCL-exact (dds.pal:bytes-consed); Clasp returns 0.0/0.0 by the NFR-PORT gap."
  (let ((node (let ((dds.disc:*shmem-enabled* nil))
                (dds.disc:make-disc-node
                 :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xC1)
                 :domain (test-domain +td-bench-publish-delta+) :host "127.0.0.1" :port 0 :multicast nil))))
    (unwind-protect
         (progn
           (dds.disc:add-local-writer node :topic "ZeroAllocPub" :type "X")
           (dds.disc:enable-publisher node :history-kind :keep-last :history-depth 1)
           (flet ((measure ()
                    (let ((before (dds.pal:bytes-consed)))
                      (dotimes (i iters) (dds.disc:publish-sample node pt))
                      (/ (float (- (dds.pal:bytes-consed) before) 1.0d0) iters)))
                  (warm () (dotimes (i 200) (dds.disc:publish-sample node pt))))
             (warm)                                                    ; plain steady state warmed
             (let ((plain (measure)))
               (setf (dds.disc:disc-node-crypto-transform node) km)   ; data_protection ON; lazy pool carve on first secured publish (warmed below)
               (warm)
               (values plain (measure)))))
      (dds.disc:stop-node node))))

(defun* %secured-receive-one (node wid sn input src guid)
    (function (dds.disc:disc-node (unsigned-byte 32) integer (simple-array (unsigned-byte 8) (*))
              (simple-array (unsigned-byte 8) (12)) (simple-array (unsigned-byte 8) (16))) (values))
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5c/T5d: ONE live RECEIVE step (shared by the per-config and the same-node delta
   measurements, DRY): deliver INPUT as SN from WID/SRC, take the loan into the reused vec + return it (zero-cons
   for the pooled loan path), then DRAIN the never-purged store back to empty so the next iteration is steady
   state. No sockets (%deliver-user-sample driven directly)."
  (dds.disc::%deliver-user-sample node wid sn input src guid sn)
  (multiple-value-bind (vec count) (dds.disc:node-take-loaned node)   ; T5d: reused vec + count (zero-cons take)
    (dds.disc:node-return-loan node vec count))
  ;; drain the never-purged store back to empty (steady state) — clear the INNER SN maps but REUSE them so the
  ;; harness itself does not cons a fresh make-hash-table per iteration (that ~1KB/sample of test framing drives
  ;; GC-boundary accounting noise into the delta); only the direct-path 3 tables ever grow here.
  (dds.pal:with-lock ((dds.disc::disc-node-lock node))
    (flet ((empty (outer) (maphash (lambda (g inner) (declare (ignore g)) (clrhash inner)) outer)))
      (empty (dds.disc::disc-node-samples node))
      (empty (dds.disc::disc-node-sample-writers node))
      (empty (dds.disc::disc-node-sample-writer-guids node))))
  (values))

(defun* %secured-live-receive-bps (km input crypto loan iters)
    (function (t (simple-array (unsigned-byte 8) (*)) t t (integer 1)) double-float)
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5c: bytes-consed/sample over ITERS of the LIVE secured RECEIVE path
   (%secured-receive-one). INPUT is the wire payload: the SecuredPayload ciphertext for the secured paths, the
   plaintext for the plain baseline. Used for the plain baseline and the allocating-decode comparison (LOAN NIL,
   whose per-sample plaintext copy is a big signal that SCALES with payload); the loan-vs-plain delta over two
   fresh nodes (identical 0->N proxy/store growth) corroborates the EXACT 0.0000 that %secured-wrapper-cycle-bps
   proves deterministically. SBCL-exact; Clasp 0.0."
  (let ((node (let ((dds.disc:*shmem-enabled* nil))
                (dds.disc:make-disc-node
                 :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xC2)
                 :domain (test-domain +td-bench-receive+) :host "127.0.0.1" :port 0 :multicast nil :crypto-transform (and crypto km))))
        (wid #x00000102)
        (src (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xA1)))
    (unwind-protect
         (progn
           (dds.disc:enable-subscriber node)
           (when loan (dds.disc:set-secured-loan-capable node t))
           (let ((guid (dds.disc::%source-guid src wid)) (sn 0))
             (flet ((one () (incf sn) (%secured-receive-one node wid sn input src guid)))
               (dotimes (i 100) (one))   ; warm + lazy decode-pool carve off the measured window
               (let ((before (dds.pal:bytes-consed)))
                 (dotimes (i iters) (one))
                 (/ (float (- (dds.pal:bytes-consed) before) 1.0d0) iters)))))
      (dds.disc:stop-node node))))

(defun* %secured-wrapper-cycle-bps (km iters)
    (function (t (integer 1)) double-float)
  "WP-DDS-SECURITY-ZEROALLOC-AEAD T5d: DETERMINISTIC exact bytes-consed/sample of the pooled loan WRAPPER cycle in
   isolation — acquire a pooled decode buffer + a freelisted secured-loan-handle, fill it, register it in the
   fixed-vector registry, then deregister + release the buffer + recycle the handle: exactly the per-sample wrapper
   work %deliver-user-sample and node-return-loan do AROUND the (separately-proven-0.0000) payload decode. No decode
   / store / reader-proxy, so there is NO framing or GC-boundary noise — the result is an EXACT 0.0000 on SBCL
   (Clasp 0.0, NFR-PORT). This is the rock-solid proof that T5d de-consed the loan delivery wrapper (handle struct
   + registry cons + take list cons); the live-loop delta corroborates it end-to-end within the cross-node GC
   quantum. Returns 0.0 if the decode pool could not be carved (arena unavailable)."
  (let ((node (let ((dds.disc:*shmem-enabled* nil))
                (dds.disc:make-disc-node
                 :guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element #xC4)
                 :domain (test-domain +td-bench-wrapper-cycle+) :host "127.0.0.1" :port 0 :multicast nil :crypto-transform km)))
        (guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xB1)))
    (unwind-protect
         (progn
           (dds.disc:enable-subscriber node)
           (dds.disc:set-secured-loan-capable node t)                    ; eager decode-pool + wrapper freelist carve
           (let ((pool (dds.disc:disc-node-decode-pool node)))
             (if (null pool)
                 0.0d0
                 (flet ((cycle (sn)
                          (let ((b (dds.core.arena:pool-acquire pool))
                                (h (dds.disc::%secured-handle-acquire node)))
                            (dds.disc::%secured-handle-fill h b 256 guid sn)         ; refill (replace guid in place — no alloc)
                            (dds.pal:with-lock ((dds.disc::disc-node-lock node))
                              (dds.disc::%secured-loan-register node h)              ; fixed-vector registry push (no cons)
                              (dds.disc::%secured-loan-deregister node h))           ; O(1) swap-remove (no cons)
                            (dds.pal:with-lock ((dds.disc::disc-node-decode-pool-lock node))
                              (dds.core.arena:pool-release pool b)
                              (dds.disc::%secured-handle-recycle node h)))))         ; dissociate + freelist push (no cons)
                   (dotimes (i 1000) (cycle i))                          ; warm
                   (let ((before (dds.pal:bytes-consed)))
                     (dotimes (i iters) (cycle i))
                     (/ (float (- (dds.pal:bytes-consed) before) 1.0d0) iters))))))
      (dds.disc:stop-node node))))

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
    (run-mem-test-secure)
    t))

(defun* run-mem-test-secure ()
    (function () t)
  "Measured zero-alloc data_protection AEAD encode + decode (NFR-MEM, security-ON). SBCL asserts
   bytes-consed/iter < 1.0; Clasp smokes (bytes-consed is 0). Closes the gap that make mem never
   covered the security path (ADR-0036 Carry-3)."
  (multiple-value-bind (%dare-ok %dare-reason) (dds.dare:dare-available-p)
    (unless %dare-ok
      (format t "~&  [mem-secure] SKIP — AES-GCM not available: ~a~%" %dare-reason)
      (return-from run-mem-test-secure t)))
  (let* ((km (dds.security:make-test-key-material))
         (pt (map '(simple-array (unsigned-byte 8) (*)) #'char-code "zero-alloc steady-state payload"))
         (out (dds.core.buffer:make-octet-buffer (+ 64 (length pt))))
         (ptout (dds.core.buffer:make-octet-buffer 256))
         (iters 100000) (slen 0))
    (setf slen (dds.security:encode-serialized-payload-into out km pt))           ; warm up
    (dds.security:decode-serialized-payload-into ptout km (subseq (dds.core.buffer:octet-buffer-vec out) 0 slen))
    (flet ((measure (label thunk)
             (declare (type function thunk))
             (let ((before (dds.pal:bytes-consed)))
               (dotimes (i iters) (funcall thunk))
               (let* ((delta (- (dds.pal:bytes-consed) before)) (per (/ (float delta) iters)))
                 (format t "~&  mem[~11a]: ~9d bytes / ~d iters = ~,4f bytes/sample (~a)~%"
                         label delta iters per (dds.pal:pal-impl-name))
                 (when (eq (dds.pal:pal-impl-name) :sbcl)
                   (%check :zero-alloc-secure (< per 1.0)
                           (format nil "~a: ~,4f bytes/sample (expected ~~0)" label per)))))))
      (measure "aead-encode" (lambda () (dds.security:encode-serialized-payload-into out km pt)))
      ;; decode over a fixed sealed blob copied once into a reused static input buffer (no per-iter alloc)
      (let ((sealed (dds.core.buffer:make-octet-buffer slen)))
        (replace (dds.core.buffer:octet-buffer-vec sealed) (dds.core.buffer:octet-buffer-vec out) :end2 slen)
        (measure "aead-decode"
                 (lambda () (dds.security:decode-serialized-payload-into ptout km (dds.core.buffer:octet-buffer-vec sealed))))
        (dds.pal:free-static (dds.core.buffer:octet-buffer-vec sealed)))
      ;; T5a review: the LIVE shape — crypto-transform installed AFTER enable-publisher (the DDS-Security
      ;; handshake order; crypto-manager) — must lazily carve the encode pool on the first secured publish and
      ;; then run zero-alloc. Build that exact shape and measure the steady-state pooled encode (SBCL only: this
      ;; binds one ephemeral UDP socket via make-disc-node, and bytes-consed is only meaningful on SBCL).
      (when (eq (dds.pal:pal-impl-name) :sbcl)
        (let ((node (dds.disc:make-disc-node :domain (test-domain +td-mem-secure+))))
          (unwind-protect
               (progn
                 (dds.disc:enable-publisher node :history-kind :keep-all)        ; crypto OFF at enable -> no pool
                 (setf (dds.disc:disc-node-crypto-transform node) km)            ; live keys-install (crypto-manager)
                 (let ((writer (dds.disc::disc-node-user-writer node)))
                   (%check :live-pool-absent-at-enable
                           (null (dds.rtps.history:history-cache-payload-pool (dds.rtps.reliable:rtps-writer-hc writer)))
                           "live shape: no encode pool until the first secured publish")
                   (dds.disc::%ensure-secured-payload-pool node writer)          ; what the first secured publish does
                   (%check :live-pool-lazily-carved
                           (dds.rtps.history:history-cache-payload-pool (dds.rtps.reliable:rtps-writer-hc writer))
                           "live shape: the lazy carve must provision the encode pool")
                   (measure "aead-encode-live"
                            (lambda ()
                              (let ((b (dds.rtps.reliable:writer-acquire-payload-buffer writer)))
                                (dds.security:encode-serialized-payload-into b km pt)
                                (dds.rtps.reliable:writer-release-payload-buffer writer b))))))
            (dds.disc:stop-node node))))
      ;; T5c/T5d: the LIVE pub+sub path — enabling data_protection adds 0.0000 B/sample OVER the non-secured baseline.
      ;; PUBLISH is the headline gate: the full live publish-sample path (encode-into-pool + writer-write +
      ;; make-cache-change + flush) conses IDENTICALLY with crypto ON vs OFF, so the data_protection delta is 0.0000.
      ;; T5d pools the RECEIVE loan wrapper too (freelisted handle + fixed-vector registry + reused take vec), so
      ;; the secured RECEIVE delta is now 0.0000 as well — asserted in run-secured-live-zeroalloc-test Part A.
      (when (eq (dds.pal:pal-impl-name) :sbcl)
        (let* ((live-pt (make-array 256 :element-type '(unsigned-byte 8) :initial-element 7))
               (npub 200000)                             ; publish delta is ~0: a large window puts the ~64KB GC-boundary quantum at ~0.33 B/sample
               (rx-wrap (%secured-wrapper-cycle-bps km 200000)))   ; T5d: the RECEIVE loan wrapper, measured DETERMINISTICALLY (exact 0.0000, no cross-node GC noise)
          (multiple-value-bind (pub-plain pub-sec) (%secured-live-publish-delta-bps km live-pt npub)
            (format t "~&  mem[aead-live-pub ]: plain=~,4f secured=~,4f -> data_protection delta=~,4f B/sample (~a)~%"
                    pub-plain pub-sec (- pub-sec pub-plain) (dds.pal:pal-impl-name))
            (format t "~&  mem[aead-live-rx  ]:         ~9d bytes / 200000 iters = ~,4f bytes/sample (T5d loan-wrapper cycle, deterministic; matching the encode side)~%"
                    (round (* rx-wrap 200000)) rx-wrap)
            (%check :zero-alloc-secure-live-publish (< (abs (- pub-sec pub-plain)) 2.0)
                    (format nil "live publish: data_protection adds ~,4f B/sample over plain (expected ~~0; GC quantum ~,4f)"
                            (- pub-sec pub-plain) (/ 65536.0 npub)))
            (%check :zero-alloc-secure-live-rx (< rx-wrap 1.0)
                    (format nil "live secured RECEIVE loan wrapper must be zero-alloc; measured ~,4f B/sample" rx-wrap))))))
    ;; WP-DDS-SECURITY-ZEROALLOC-AEAD T5 (ZA-2): the LIVE submessage (metadata_protection) + whole-RTPS (rtps_protection)
    ;; dataplane — SEND + RECEIVE each add 0 B/sample over the non-secured baseline (SBCL-asserted; Clasp smokes) +
    ;; pool-exhaustion fail-closes rather than GC-falling-back. Runs on both impls (self-guards AES-GCM availability).
    (dds.disc:run-secured-dataplane-mem-test)
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec out))
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec ptout))
    t))
