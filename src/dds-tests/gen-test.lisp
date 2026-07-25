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

;; Deliberately NON-CONTIGUOUS and not starting the gap at 1: an enum's wire value is the DECLARED
;; constant, never the ordinal position, and only a gapped enum can tell the two apart.
(dds.gen:define-dds-enum genum-hue (:red 0) (:green 3) (:blue 7))

(dds.gen:define-dds-type genum-t (:extensibility :final)
  (id :i32 :key t)
  (hue (:enum genum-hue)))

(defun* run-gen-enum-test ()
    (function () t)
  "Test: `(:enum name)` members (XTypes 1.3 §7.3.1.2.1 — an enum's default bit bound is 32, so the
   wire representation is int32). The accessor takes and returns the KEYWORD; the codec reads and
   writes the INTEGER.

   The assertion that matters is the LAST one. A foreign publisher of a newer revision of the type
   WILL send values this build has never heard of, and the only two honest things a decoder may do
   with one are report it or drop it. Inventing a keyword — or silently substituting a neighbouring
   literal — is how a decoder lies about what was on the wire."
  ;; 1. The mapping is by DECLARED VALUE, both ways, including the gap.
  (%check :enum-to-i32 (and (eql 0 (genum-hue-to-i32 :red))
                            (eql 3 (genum-hue-to-i32 :green))
                            (eql 7 (genum-hue-to-i32 :blue)))
          "keyword -> declared i32 value")
  (%check :enum-from-i32 (and (eq :red (genum-hue-from-i32 0))
                              (eq :green (genum-hue-from-i32 3))
                              (eq :blue (genum-hue-from-i32 7)))
          "declared i32 value -> keyword")
  ;; 2. An UNKNOWN value is reported, never invented. 2 is the ordinal index of :blue and 1 is the
  ;;    ordinal index of :green — an implementation that confused position with value would return
  ;;    a plausible-looking wrong keyword for both, which is exactly the failure being excluded.
  (multiple-value-bind (kw status) (genum-hue-from-i32 42)
    (%check :enum-unknown-reported (and (null kw) (eq status :unknown-enum-value))
            (format nil "an unknown wire value must report, not invent; got ~s ~s" kw status)))
  (multiple-value-bind (kw status) (genum-hue-from-i32 2)
    (%check :enum-ordinal-is-not-value (and (null kw) (eq status :unknown-enum-value))
            (format nil "2 is :blue's ORDINAL, not a declared value — must be unknown; got ~s ~s" kw status)))
  (multiple-value-bind (v status) (genum-hue-to-i32 :chartreuse)
    (%check :enum-unknown-keyword-reported (and (null v) (eq status :unknown-enum-value))
            (format nil "an undeclared keyword must report, not encode; got ~s ~s" v status)))
  ;; 3. Round-trip through the generated codec, and the WIRE OCTETS carry the declared value.
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 512 4))   ; 3 held at once below
         (s (make-genum-t :id 1 :hue :blue))
         (b (dds.core.arena:pool-acquire pool))
         (wc (dds.core.buffer:cursor b :endianness :little)))
    (serialize-genum-t s wc :xcdr2)
    (%check :enum-size (= (dds.core.buffer:cursor-position wc) (serialized-size-genum-t s :xcdr2))
            "serialized-size must equal bytes written for an enum member")
    ;; Read the enum field's four octets RAW — buffer primitives, not the enum codec, so this is an
    ;; oracle rather than the code under test agreeing with itself. Body: i32 id @0, i32 hue @4, LE.
    (let ((rc (dds.core.buffer:cursor b :endianness :little)))
      (dotimes (i 4) (dds.core.buffer:get-u8 rc))
      (let ((o0 (dds.core.buffer:get-u8 rc)) (o1 (dds.core.buffer:get-u8 rc))
            (o2 (dds.core.buffer:get-u8 rc)) (o3 (dds.core.buffer:get-u8 rc)))
        (%check :enum-wire-is-declared-value (and (= o0 7) (= o1 0) (= o2 0) (= o3 0))
                (format nil "the wire must carry the DECLARED value 7 for :blue, not its ordinal 2; got ~2,'0x ~2,'0x ~2,'0x ~2,'0x"
                        o0 o1 o2 o3))))
    (let* ((rc (dds.core.buffer:cursor b :endianness :little))
           (q (deserialize-genum-t rc :xcdr2)))
      (%check :enum-roundtrip (and (= 1 (genum-t-id q)) (eq :blue (genum-t-hue q)))
              (format nil "enum round-trip mismatch; got id ~s hue ~s" (genum-t-id q) (genum-t-hue q))))
    ;; 4. An unknown value ARRIVING ON THE WIRE is kept VERBATIM — never a wrong keyword, and never
    ;;    flattened to a sentinel. The re-serialize is the assertion that matters: a relay must put
    ;;    back exactly what the sender sent. A NIL/sentinel slot would pass a "not a keyword" check
    ;;    and still corrupt the value on its way out, so checking the decode alone proves too little.
    (let ((wb (dds.core.arena:pool-acquire pool))
          (rb (dds.core.arena:pool-acquire pool)))
      (let ((c (dds.core.buffer:cursor wb :endianness :little)))
        (dds.cdr:cdr-put-i32 c 1 :xcdr2)
        (dds.cdr:cdr-put-i32 c 42 :xcdr2))
      (let ((q (deserialize-genum-t (dds.core.buffer:cursor wb :endianness :little) :xcdr2)))
        (%check :enum-unknown-on-wire-kept-verbatim (eql 42 (genum-t-hue q))
                (format nil "an unknown wire value must be kept as the raw int32, not a keyword; got ~s"
                        (genum-t-hue q)))
        (serialize-genum-t q (dds.core.buffer:cursor rb :endianness :little) :xcdr2)
        (let ((c (dds.core.buffer:cursor rb :endianness :little)))
          (dotimes (i 4) (dds.core.buffer:get-u8 c))
          (%check :enum-unknown-relayed-unchanged
                  (and (= 42 (dds.core.buffer:get-u8 c)) (= 0 (dds.core.buffer:get-u8 c))
                       (= 0 (dds.core.buffer:get-u8 c)) (= 0 (dds.core.buffer:get-u8 c)))
                  "re-serializing an undecodable enum value must emit it unchanged")))
      (dds.core.arena:pool-release pool rb)
      (dds.core.arena:pool-release pool wb))
    (dds.core.arena:pool-release pool b)
    (dds.core.arena:teardown-arena arena))
  ;; 5. KNOWN GAP, asserted so it cannot change silently: the member's TypeObject TypeIdentifier is
  ;;    TK_INT32, not a real XTypes enum. Our model HAS minimal-enumerated-type, but the TypeObject
  ;;    SERIALIZER cannot emit one (equivalence-hash takes a minimal-struct-type only), and those
  ;;    bytes are oracle-sensitive — the same reason sequence-member TypeIdentifiers deliberately
  ;;    error rather than guess. This is the ADR 0009 defect class and it is DEBT, not the target.
  (let* ((ts (dds.types:find-type-support "genum-t"))
         (m (second (dds.types:minimal-struct-type-members (dds.types:type-support-typeobject ts)))))
    (%check :enum-typeobject-is-int32-known-gap
            (= (dds.types:type-identifier-kind (dds.types:minimal-struct-member-type-identifier m))
               dds.types:+tk-int32+)
            "the enum member's TypeIdentifier is TK_INT32 today (documented gap)"))
  t)

;; v2 IS v1 plus a trailing member — the whole point of APPENDABLE. Both must be able to read the
;; other's samples, which is the property tested, not merely that a DHEADER appears.
(dds.gen:define-dds-type appendable-v1 (:extensibility :appendable)
  (a :i32 :key t)
  (b :i32))

(dds.gen:define-dds-type appendable-v2 (:extensibility :appendable)
  (a :i32 :key t)
  (b :i32)
  (c :i32))

(defun* run-gen-appendable-test ()
    (function () t)
  "Test: `:appendable` extensibility (DDS-XTypes 1.3 §7.4.3.5 rules 29/30, §7.4.3.4.1).

   Rule (30): XCDR[2] serializes an APPENDABLE type as DHEADER(O):UInt32 then the members as if
   FINAL. Rule (29): XCDR[1] serializes it EXACTLY as FINAL — no DHEADER. §7.4.2 says the same in
   prose. And Table 60 (§7.6.3.1.2) makes the ENCAPSULATION ID depend on extensibility, not just the
   encoding version: APPENDABLE+v2+LE is D_CDR2_LE 0x0009, not CDR2_LE 0x0007.

   The label and the framing must agree. A DHEADER under an 0x0007 label tells a conformant peer
   there is no DHEADER, so it would read the DHEADER's four octets as the first member."
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 512 4)))
    ;; 1. serialized-size must ACCOUNT for the DHEADER. %serialize-sample sizes the payload buffer
    ;;    from it, so an under-estimate here is a buffer overflow, not a cosmetic mismatch.
    (let* ((s2 (make-appendable-v2 :a 1 :b 2 :c 3))
           (b (dds.core.arena:pool-acquire pool))
           (wc (dds.core.buffer:cursor b :endianness :little)))
      (serialize-appendable-v2 s2 wc :xcdr2)
      (%check :appendable-size (= (dds.core.buffer:cursor-position wc)
                                  (serialized-size-appendable-v2 s2 :xcdr2))
              "serialized-size must include the DHEADER")
      ;; 2. THE COMPATIBILITY PROPERTY, forward: a v2 sample read by a v1 reader. The shared members
      ;;    decode, and the reader stops at the DHEADER extent instead of walking into member c.
      (let* ((rc (dds.core.buffer:cursor b :endianness :little))
             (q (deserialize-appendable-v1 rc :xcdr2)))
        (%check :appendable-v2-as-v1 (and (= 1 (appendable-v1-a q)) (= 2 (appendable-v1-b q)))
                (format nil "shared members must decode; got a=~s b=~s"
                        (appendable-v1-a q) (appendable-v1-b q)))
        (%check :appendable-v2-as-v1-consumed-extent
                (= (dds.core.buffer:cursor-position rc) (dds.core.buffer:cursor-position wc))
                (format nil "a v1 reader must skip to the DHEADER end (~d); stopped at ~d"
                        (dds.core.buffer:cursor-position wc) (dds.core.buffer:cursor-position rc))))
      (dds.core.arena:pool-release pool b))
    ;; 3. THE COMPATIBILITY PROPERTY, reverse: a v1 sample read by a v2 reader. Member c was never
    ;;    sent, so it must keep its default — and the reader must NOT read past the DHEADER extent
    ;;    to invent it.
    (let* ((s1 (make-appendable-v1 :a 7 :b 8))
           (b (dds.core.arena:pool-acquire pool))
           (wc (dds.core.buffer:cursor b :endianness :little)))
      (serialize-appendable-v1 s1 wc :xcdr2)
      (let* ((rc (dds.core.buffer:cursor b :endianness :little))
             (q (deserialize-appendable-v2 rc :xcdr2)))
        (%check :appendable-v1-as-v2 (and (= 7 (appendable-v2-a q)) (= 8 (appendable-v2-b q))
                                          (= 0 (appendable-v2-c q)))
                (format nil "an absent appended member must stay at its default; got a=~s b=~s c=~s"
                        (appendable-v2-a q) (appendable-v2-b q) (appendable-v2-c q))))
      (dds.core.arena:pool-release pool b))
    (dds.core.arena:teardown-arena arena))
  ;; 4. THE LABEL MUST MATCH THE FRAMING (Table 60). XCDR2 -> D_CDR2_LE 0x0009 with a DHEADER;
  ;;    XCDR1 -> CDR_LE 0x0001 with NO DHEADER (rule 29), so the XCDR1 payload is 4 octets shorter.
  (let* ((ts (dds.types:find-type-support "appendable-v1"))
         (s (make-appendable-v1 :a #x11111111 :b #x22222222))
         (x2 (dds.dcps::%serialize-sample ts s :xcdr2))
         (x1 (dds.dcps::%serialize-sample ts s :xcdr1)))
    (%check :appendable-encap-xcdr2 (and (= 0 (aref x2 0)) (= #x09 (aref x2 1)))
            (format nil "APPENDABLE+XCDR2 must be D_CDR2_LE 0x0009 (Table 60); got ~2,'0x~2,'0x"
                    (aref x2 0) (aref x2 1)))
    (%check :appendable-encap-xcdr1 (and (= 0 (aref x1 0)) (= #x01 (aref x1 1)))
            (format nil "APPENDABLE+XCDR1 must be CDR_LE 0x0001 (rule 29); got ~2,'0x~2,'0x"
                    (aref x1 0) (aref x1 1)))
    ;; The DHEADER is the first thing in the body and covers the two i32 members = 8 octets.
    (%check :appendable-dheader-value
            (= 8 (logior (aref x2 4) (ash (aref x2 5) 8) (ash (aref x2 6) 16) (ash (aref x2 7) 24)))
            "the DHEADER must carry the body size excluding itself (§7.4.3.4.1)")
    (%check :appendable-xcdr1-has-no-dheader (= (length x1) (- (length x2) 4))
            (format nil "XCDR1 must carry NO DHEADER (rule 29); lengths were xcdr1=~d xcdr2=~d"
                    (length x1) (length x2)))
    ;; 5. THE DHEADER IS WIRE DATA. A hostile or truncated peer can claim any extent, so a DHEADER
    ;;    larger than the buffer must be REFUSED, not followed off the end (NFR-SEC-POSTURE). The
    ;;    condition is contained here at the test boundary exactly as the receiver contains it.
    ;;    ⚠️ HONEST LIMIT: this is an ASSERTION, not a falsifiable gate. Deleting the DHEADER's
    ;;    check-room leaves it GREEN, because every member read is independently bounds-checked and
    ;;    the final skip-to-extent is itself checked — so no removal of the DHEADER check produces
    ;;    an out-of-bounds read for this to catch. The check earns its place by failing FAST, before
    ;;    any attacker-controlled member is parsed against a bogus extent, not by being observable
    ;;    here. Recorded rather than presented as proof (the alloc-static-zeroed precedent).
    (let* ((vec (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0))
           (refused nil))
      (setf (aref vec 0) #xff (aref vec 1) #xff (aref vec 2) #xff (aref vec 3) #x7f)   ; DHEADER = 2^31-1
      (handler-case
          (deserialize-appendable-v1
           (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over vec) :endianness :little)
           :xcdr2)
        (dds.core.buffer:buffer-overflow () (setf refused t)))
      (%check :appendable-dheader-bounds-checked refused
              "a DHEADER claiming more than the buffer holds must be refused, never followed"))
    ;; 5b. The Table 60 mapping itself, at its ONE definition. This assertion is why the mapping was
    ;;     hoisted: it previously existed twice (the DCPS write path and the shapes harness) with
    ;;     nothing checking either, so correcting one copy for APPENDABLE left the other silently
    ;;     emitting 0x0007 — on exactly the harness a live interop leg would have used.
    (%check :encap-id-table-60
            (and (eq :plain-cdr2-le   (dds.cdr:encapsulation-id-for :xcdr2 :final))
                 (eq :plain-cdr2-le   (dds.cdr:encapsulation-id-for :xcdr2 nil))
                 (eq :delimited-cdr-le (dds.cdr:encapsulation-id-for :xcdr2 :appendable))
                 (eq :pl-cdr2-le      (dds.cdr:encapsulation-id-for :xcdr2 :mutable))
                 ;; Rule (29): APPENDABLE is AsFinal under version 1, so both take CDR_LE.
                 (eq :plain-cdr-le    (dds.cdr:encapsulation-id-for :xcdr1 :final))
                 (eq :plain-cdr-le    (dds.cdr:encapsulation-id-for :xcdr1 :appendable))
                 (eq :pl-cdr-le       (dds.cdr:encapsulation-id-for :xcdr1 :mutable)))
            "encapsulation-id-for must implement Table 60 keyed on extensibility AND version")
    ;; 6. RX must ACCEPT its own conformant 0x0009 payload — a false-REJECT here is the worst class.
    (multiple-value-bind (q status)
        (dds.dcps::%deserialize-payload
         ts (dds.core.buffer:octet-buffer-over x2))
      (%check :appendable-rx-accepts-delimited
              (and (null status) q (= #x11111111 (appendable-v1-a q)))
              (format nil "RX must accept D_CDR2_LE 0x0009; got status ~s" status))))
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

;;;; ---- MUTABLE extensibility (ADR 0086; XTypes 1.3 §7.4.3.4.2, rules (21)-(25)) ----
;;;; mut-v1 and mut-v2 are the same type at two revisions: v2 adds a member AND reorders the
;;;; declaration, which is exactly what MUTABLE is for and what neither FINAL nor APPENDABLE
;;;; survives. The ids, not the positions, are the contract — note v2 declares them out of order on
;;;; purpose, so a positional decode cannot pass.

(dds.gen:define-dds-type mut-v1 (:extensibility :mutable)
  (a :i32 :key t)                       ; id 0
  (b :u16)                              ; id 1  <- the id that collides with the RTPS sentinel
  (label :string)                       ; id 2
  (t-ns :i64))                          ; id 3

(dds.gen:define-dds-type mut-v2 (:extensibility :mutable)
  (t-ns :i64 :id 3)
  (label :string :id 2)
  (a :i32 :id 0 :key t)
  (extra :i32 :id 7)
  (b :u16 :id 1))

;; A member a peer is not allowed to ignore (@must_understand, §7.4.1.2.1).
(dds.gen:define-dds-type mut-mu (:extensibility :mutable)
  (a :i32 :id 0)
  (critical :i32 :id 9 :must-understand t))

(defun* %mut-ser (s ser mode endianness)
    (function (t function symbol (member :little :big)) (simple-array (unsigned-byte 8) (*)))
  "Serialize S with SER into a fresh vector — a test fixture, not a data path."
  (let* ((buf (dds.core.buffer:make-octet-buffer 512))
         (wc (dds.core.buffer:cursor buf :endianness endianness)))
    (funcall ser s wc mode)
    (let* ((len (dds.core.buffer:cursor-position wc))
           (out (make-array len :element-type '(unsigned-byte 8))))
      (replace out (dds.core.buffer:octet-buffer-vec buf) :end1 len)
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))
      out)))

(defun* %mut-cursor (bytes endianness)
    (function ((simple-array (unsigned-byte 8) (*)) (member :little :big)) dds.core.buffer:cursor)
  "A read cursor over BYTES whose buffer capacity is exactly (LENGTH BYTES) — the XCDR1 parameter
   walk uses the buffer extent as its bound, so a slack capacity would weaken the test."
  (dds.core.buffer:cursor (dds.core.buffer:octet-buffer-over bytes) :endianness endianness))

(defun* run-gen-mutable-test ()
    (function () t)
  "Test: `:mutable` extensibility (ADR 0086; DDS-XTypes 1.3 §7.4.3.4.2 EMHEADER1/LC/NEXTINT,
   §7.4.1.2.1 parameter ids, §7.4.3.5 rules (21)-(25)).

   MUTABLE is the only kind whose decode is DRIVEN BY WIRE DATA — a member is located by an id and
   sized by a length the peer chose — so this covers the framing bytes, the compatibility property in
   both directions, the must-understand discard, and the hostile-length rejections."
  ;; 1. THE FRAMING BYTES, XCDR2 (rules (21)-(22)). Derived from the clause, not from our output:
  ;;    DHEADER=48 excluding itself; then per member EMHEADER1 = (M_FLAG<<31)+(LC<<28)+id, LE.
  ;;    a  : LC=2 (4 octets) id=0 -> 0x20000000 ; then the i32.
  ;;    b  : LC=1 (2 octets) id=1 -> 0x10000001 ; then the u16, then 2 pad to the next header.
  ;;    lbl: LC=4 id=2 -> 0x40000002 + NEXTINT=10 (4 length + "hello\0"); then the string.
  ;;    t  : LC=3 (8 octets) id=3 -> 0x30000003 ; then the i64 (4-aligned, XCDR2 caps at 4).
  (let* ((s (make-mut-v1 :a 1 :b 2 :label "hello" :t-ns 3))
         (x2 (%mut-ser s #'serialize-mut-v1 :xcdr2 :little)))
    (%check :mutable-xcdr2-bytes
            (equalp x2 (octets #x30 #x00 #x00 #x00
                               #x00 #x00 #x00 #x20  #x01 #x00 #x00 #x00
                               #x01 #x00 #x00 #x10  #x02 #x00  #x00 #x00
                               #x02 #x00 #x00 #x40  #x0a #x00 #x00 #x00
                               #x06 #x00 #x00 #x00  #x68 #x65 #x6c #x6c #x6f #x00  #x00 #x00
                               #x03 #x00 #x00 #x30  #x03 #x00 #x00 #x00 #x00 #x00 #x00 #x00))
            (format nil "PL_CDR2 framing must match §7.4.3.4.2; got ~{~2,'0x ~}" (coerce x2 'list)))
    ;; 2. THE FRAMING BYTES, XCDR1 (rules (23)-(25)). A parameter list: per member ALIGN(4), a 16-bit
    ;;    id, a 16-bit length, then the member with its origin reset; closed by PID_LIST_END + 0.
    ;;    Member b's id is 1 — the value the RTPS sentinel uses. It must appear as a MEMBER here.
    ;;
    ;;    THREE OF THESE FIELDS WERE WRONG UNTIL A LIVE CONNEXT VECTOR SAID SO
    ;;    (corpus/xcdr2/mutabledata-connext.bin, `make corpus`), and all three were hand-derived from the
    ;;    clause and looked right:
    ;;      - the DECLARED LENGTH is rounded up to a multiple of 4 (b, a 2-octet short, declares 4; the
    ;;        10-octet string declares 12) — a PL_CDR list is the RTPS ParameterList structure;
    ;;      - the terminator is 0x7F02, PID_LIST_END with FLAG_MUST_UNDERSTAND, which Table 34 requires
    ;;        and rule (23)'s bare "PID_SENTINEL" does not mention;
    ;;      - and Connext sends @mutable as PL_CDR (XCDR1) in the first place, which is why this leg,
    ;;        not the XCDR2 one above, is the framing that actually reaches it.
    (let ((x1 (%mut-ser s #'serialize-mut-v1 :xcdr1 :little)))
      (%check :mutable-xcdr1-bytes
              (equalp x1 (octets #x00 #x00 #x04 #x00  #x01 #x00 #x00 #x00
                                 #x01 #x00 #x04 #x00  #x02 #x00  #x00 #x00
                                 #x02 #x00 #x0c #x00  #x06 #x00 #x00 #x00
                                 #x68 #x65 #x6c #x6c #x6f #x00  #x00 #x00
                                 #x03 #x00 #x08 #x00  #x03 #x00 #x00 #x00 #x00 #x00 #x00 #x00
                                 #x02 #x7f #x00 #x00))
              (format nil "PL_CDR framing must match rules (23)-(25); got ~{~2,'0x ~}"
                      (coerce x1 'list)))
      ;; 2b. PARAMETER ID 1 IS A MEMBER, NOT A TERMINATOR. Table 34 confines the id-1 terminator to
      ;;     Simple Discovery types, which give up member id 1 to buy it. Accepting it for a user
      ;;     type ends the list at the SECOND member of a default-numbered struct and silently
      ;;     delivers defaults for everything after — a wrong sample reported as a good one.
      (multiple-value-bind (q st) (deserialize-mut-v1 (%mut-cursor x1 :little) :xcdr1)
        (%check :mutable-xcdr1-id1-is-a-member
                (and (null st) q (= 2 (mut-v1-b q)) (= 3 (mut-v1-t-ns q))
                     (string= "hello" (mut-v1-label q)))
                (format nil "member id 1 must decode as a member; status ~s sample ~s" st q))))
    ;; 3. Round-trip both encodings x both endiannesses, and serialized-size EXACT for each. The
    ;;    size sizes the payload buffer (%serialize-sample), and MUTABLE puts a header on EVERY
    ;;    member, so an omission here is a buffer overflow rather than a cosmetic mismatch.
    (dolist (mode '(:xcdr2 :xcdr1))
      (dolist (endian '(:little :big))
        (let* ((bytes (%mut-ser s #'serialize-mut-v1 mode endian))
               (ssz (serialized-size-mut-v1 s mode)))
          (%check :mutable-serialized-size-exact
                  (= ssz (length bytes))
                  (format nil "~a/~a: serialized-size ~d != bytes written ~d"
                          mode endian ssz (length bytes)))
          (multiple-value-bind (q st) (deserialize-mut-v1 (%mut-cursor bytes endian) mode)
            (%check :mutable-roundtrip
                    (and (null st) q (= 1 (mut-v1-a q)) (= 2 (mut-v1-b q))
                         (string= "hello" (mut-v1-label q)) (= 3 (mut-v1-t-ns q)))
                    (format nil "~a/~a round-trip: status ~s sample ~s" mode endian st q)))
          ;; deserialize-into fills a POOLED sample and must agree member for member.
          (let ((target (make-mut-v1 :a 99 :b 99 :label "stale" :t-ns 99)))
            (multiple-value-bind (q st) (deserialize-into-mut-v1 target (%mut-cursor bytes endian) mode)
              (%check :mutable-deserialize-into
                      (and (null st) q (= 1 (mut-v1-a q)) (= 2 (mut-v1-b q))
                           (string= "hello" (mut-v1-label q)) (= 3 (mut-v1-t-ns q)))
                      (format nil "~a/~a deserialize-into: status ~s sample ~s" mode endian st q)))))))
    ;; 4. THE COMPATIBILITY PROPERTY, forward: a v2 sample (extra member, members reordered on the
    ;;    wire) read by a v1 reader. The shared members decode BY ID and the unknown id 7 is skipped
    ;;    using the header's own length — never the member's type, which a v1 reader does not have.
    (dolist (mode '(:xcdr2 :xcdr1))
      (let* ((s2 (make-mut-v2 :a 5 :b 6 :label "wire" :t-ns 7 :extra 12345))
             (bytes (%mut-ser s2 #'serialize-mut-v2 mode :little)))
        (multiple-value-bind (q st) (deserialize-mut-v1 (%mut-cursor bytes :little) mode)
          (%check :mutable-v2-as-v1
                  (and (null st) q (= 5 (mut-v1-a q)) (= 6 (mut-v1-b q))
                       (string= "wire" (mut-v1-label q)) (= 7 (mut-v1-t-ns q)))
                  (format nil "~a: an unknown non-must-understand member must be SKIPPED; status ~s sample ~s"
                          mode st q)))
        ;; 5. And the reverse: a v1 sample read by a v2 reader. `extra` was never sent, so it must
        ;;    keep its DEFAULT — a member's absence is normal in MUTABLE, not an error.
        (let ((bytes1 (%mut-ser s #'serialize-mut-v1 mode :little)))
          (multiple-value-bind (q st) (deserialize-mut-v2 (%mut-cursor bytes1 :little) mode)
            (%check :mutable-v1-as-v2
                    (and (null st) q (= 1 (mut-v2-a q)) (= 2 (mut-v2-b q))
                         (string= "hello" (mut-v2-label q)) (= 3 (mut-v2-t-ns q))
                         (= 0 (mut-v2-extra q)))
                    (format nil "~a: an absent member must stay at its default; status ~s sample ~s"
                            mode st q))))))
    ;; 6. MUST_UNDERSTAND: the same skip becomes a DISCARD. §7.4.1.2.1 says the bit decides whether an
    ;;    unrecognised member "may be simply ignored or whether it causes the entire data sample to be
    ;;    discarded". Reported as a STATUS, never signalled (ADR 0064). mut-mu's id 9 is unknown to
    ;;    mut-v1, and the M_FLAG is what makes the difference between test 4 and this one.
    (dolist (mode '(:xcdr2 :xcdr1))
      (let* ((smu (make-mut-mu :a 1 :critical 42))
             (bytes (%mut-ser smu #'serialize-mut-mu mode :little)))
        (multiple-value-bind (q st) (deserialize-mut-v1 (%mut-cursor bytes :little) mode)
          (%check :mutable-must-understand-discards
                  (and (null q) (eq st :unknown-must-understand-member))
                  (format nil "~a: an unrecognised must-understand member must DISCARD the sample; got ~s / ~s"
                          mode q st)))))
    ;; 7. THE ENGINE PATH. Table 60 labels a MUTABLE payload PL_CDR2_LE 0x000b (v2) / PL_CDR_LE 0x0003
    ;;    (v1), and the RX side must ACCEPT it. Until MUTABLE shipped, %encap->codec had no arm for
    ;;    either id and signalled — so the stack would have refused its OWN writer's samples.
    (let* ((ts (dds.types:find-type-support "mut-v1"))
           (x2 (dds.dcps::%serialize-sample ts s :xcdr2))
           (x1 (dds.dcps::%serialize-sample ts s :xcdr1)))
      (%check :mutable-encap-xcdr2 (and (= 0 (aref x2 0)) (= #x0b (aref x2 1)))
              (format nil "MUTABLE+XCDR2 must be PL_CDR2_LE 0x000b (Table 60); got ~2,'0x~2,'0x"
                      (aref x2 0) (aref x2 1)))
      (%check :mutable-encap-xcdr1 (and (= 0 (aref x1 0)) (= #x03 (aref x1 1)))
              (format nil "MUTABLE+XCDR1 must be PL_CDR_LE 0x0003 (Table 60); got ~2,'0x~2,'0x"
                      (aref x1 0) (aref x1 1)))
      (dolist (payload (list x2 x1))
        (multiple-value-bind (q st)
            (dds.dcps::%deserialize-payload ts (dds.core.buffer:octet-buffer-over payload))
          (%check :mutable-rx-accepts-pl-cdr
                  (and (null st) q (= 1 (mut-v1-a q)) (string= "hello" (mut-v1-label q)))
                  (format nil "RX must accept its own PL_CDR(2) payload; status ~s" st)))))
    ;; 8. LC 0-7 DECODE. We emit only 0-4, so 5-7 have no encoder to check them against and are the
    ;;    codes a foreign writer is most likely to use for a length-prefixed member. Rule (22) rewinds
    ;;    4 octets for LC>=5 so NEXTINT doubles as the member's own leading length; the extent from
    ;;    that rewind point is therefore 4 + width*NEXTINT, where LC 5/6/7 give width 1/4/8. Reading
    ;;    "serialized member length is also NEXTINT" as the extent from the rewind point instead is 4
    ;;    octets short and desynchronises every following member — which is what this pins.
    (%check :mutable-lc-extent-table
            (and (= 1 (dds.cdr:lc-member-extent 0 0)) (= 2 (dds.cdr:lc-member-extent 1 0))
                 (= 4 (dds.cdr:lc-member-extent 2 0)) (= 8 (dds.cdr:lc-member-extent 3 0))
                 (= 12 (dds.cdr:lc-member-extent 4 12))
                 (= 16 (dds.cdr:lc-member-extent 5 12))       ; 4 + 1*12
                 (= 52 (dds.cdr:lc-member-extent 6 12))       ; 4 + 4*12
                 (= 100 (dds.cdr:lc-member-extent 7 12)))     ; 4 + 8*12
            "LC 4-7 extents must follow §7.4.3.4.2 with NEXTINT reused for 5-7")
    ;; A hand-built PL_CDR2 payload whose string member uses LC=5: EMHEADER1 = (5<<28)|2, then the
    ;; string's own 4-octet length IS the NEXTINT. If the decoder took the extent as NEXTINT rather
    ;; than 4+NEXTINT it would land 4 octets early and read the next EMHEADER1 out of the string.
    (let* ((lc5 (octets #x18 #x00 #x00 #x00                       ; DHEADER = 24
                        #x02 #x00 #x00 #x50                       ; EMHEADER1 LC=5 id=2
                        #x06 #x00 #x00 #x00                       ; NEXTINT = 6 = the string length
                        #x68 #x65 #x6c #x6c #x6f #x00 #x00 #x00   ; "hello\0" + 2 pad
                        #x00 #x00 #x00 #x20 #x63 #x00 #x00 #x00)) ; EMHEADER1 LC=2 id=0, i32 = 99
           (q (deserialize-mut-v1 (%mut-cursor lc5 :little) :xcdr2)))
      (%check :mutable-decodes-lc5
              (and q (string= "hello" (mut-v1-label q)) (= 99 (mut-v1-a q)))
              (format nil "a peer's LC=5 member must decode and leave the stream aligned; got ~s" q)))
    ;; 9. WIRE DATA IS HOSTILE (NFR-SEC-POSTURE). A member length that overruns the DHEADER extent is
    ;;    refused as a status; a DHEADER that overruns the buffer is refused at the boundary.
    ;; The DHEADER here is HONEST (8 octets follow it, and 8 are present) so the buffer-level check
    ;; passes and the forged NEXTINT is what must be caught — otherwise this would only re-test the
    ;; DHEADER guard below and the member-extent check would be unexercised.
    (let* ((overrun (octets #x08 #x00 #x00 #x00                    ; DHEADER = 8
                            #x02 #x00 #x00 #x40                    ; EMHEADER1 LC=4 id=2
                            #xff #xff #xff #x7f))                  ; NEXTINT = 2^31-1
           (st (nth-value 1 (deserialize-mut-v1 (%mut-cursor overrun :little) :xcdr2))))
      (%check :mutable-member-extent-checked
              (eq st :malformed-member-extent)
              (format nil "a member claiming more than the DHEADER extent must be refused; got ~s" st)))
    (let ((huge (octets #xff #xff #xff #x7f #x00 #x00 #x00 #x00))
          (refused nil))
      (handler-case (deserialize-mut-v1 (%mut-cursor huge :little) :xcdr2)
        (dds.core.buffer:buffer-overflow () (setf refused t)))
      (%check :mutable-dheader-bounds-checked refused
              "a DHEADER claiming more than the buffer holds must be refused, never followed"))
    ;; An XCDR1 parameter list that never terminates must be refused rather than treated as ending
    ;; where the payload happens to end.
    (let ((unterminated (octets #x00 #x00 #x04 #x00 #x01 #x00 #x00 #x00))
          )
      (%check :mutable-xcdr1-requires-list-end
              (eq :missing-parameter-list-end
                  (nth-value 1 (deserialize-mut-v1 (%mut-cursor unterminated :little) :xcdr1)))
              "a PL_CDR list with no PID_LIST_END must be refused"))
    ;; 10. The TypeObject must advertise the DECLARED ids, not member positions — they are what a peer
    ;;     matches on, and mut-v2 declares them out of order precisely so the two cannot coincide.
    (let* ((ts2 (dds.types:find-type-support "mut-v2"))
           (ms (dds.types:minimal-struct-type-members (dds.types:type-support-typeobject ts2))))
      (%check :mutable-typeobject-ids
              (equal '(3 2 0 7 1) (mapcar #'dds.types:minimal-struct-member-id ms))
              (format nil "the TypeObject must carry declared @ids in declaration order; got ~s"
                      (mapcar #'dds.types:minimal-struct-member-id ms)))
      (%check :mutable-typeobject-extensibility
              (eq :mutable (dds.types:minimal-struct-type-extensibility
                            (dds.types:type-support-typeobject ts2)))
              "the TypeObject must record :mutable extensibility")))
  t)
