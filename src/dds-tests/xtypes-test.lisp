;;;; TypeLookup_Request codec tests (XTypes 1.3 §7.6.3.3, FR-TYPE-3).
;;;; No Connext oracle exists for this protocol (ADR 0010): the spec text is the
;;;; oracle now; a Fast DDS peer arrives later (CONFIRM-VS-PEER markers in the codec).

(in-package #:dds.tests)

(defun* %find-le-u32 (octets value)
    (function ((simple-array (unsigned-byte 8) (*)) (unsigned-byte 32)) (or null fixnum))
  "Position of the first little-endian encoding of VALUE in OCTETS, or NIL."
  (let ((pat (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4) (setf (aref pat i) (ldb (byte 8 (* 8 i)) value)))
    (search pat octets)))

(defun* %patch-le-u32 (octets pos value)
    (function ((simple-array (unsigned-byte 8) (*)) fixnum (unsigned-byte 32))
              (simple-array (unsigned-byte 8) (*)))
  "Fresh copy of OCTETS with the 4 octets at POS replaced by VALUE little-endian."
  (let ((out (copy-seq octets)))
    (dotimes (i 4) (setf (aref out (+ pos i)) (ldb (byte 8 (* 8 i)) value)))
    out))

(defun* %hashid-of (name)
    (function (string) (unsigned-byte 28))
  "@hashid member id per XTypes 1.3 §7.3.1.2.1.1: NameHash as LE u32, AND 0x0FFFFFFF."
  (let ((h (dds.types:member-name-hash name)))
    (logand (logior (aref h 0) (ash (aref h 1) 8) (ash (aref h 2) 16) (ash (aref h 3) 24))
            #x0FFFFFFF)))

(defun* %truncation-offsets (len)
    (function (fixnum) list)
  "Sampled proper-prefix lengths for a LEN-octet buffer: the dense 0..15 onset
   (encapsulation + DHEADER + header), every 7th offset, and the last 3 offsets.
   Deterministic; keeps boundary coverage while signalling far fewer conditions."
  (loop for end from 0 below len
        when (or (< end 16) (zerop (mod end 7)) (>= end (- len 3)))
          collect end))

(defun* run-typelookup-request-test ()
    (function () t)
  "Test: TypeLookup_Request getTypes serialize/parse round-trip (XTypes 1.3 §7.6.3.3)."
  ;; the §7.3.1.2.1.1 derivation must reproduce the spec's own §7.6.3.3.3 constants
  (%check :tlreq-hashid-gettypes (= (%hashid-of "getTypes") dds.types:+tl-gettypes-hash+)
          "@hashid(getTypes) reproduces TypeLookup_getTypes_HashId 0x018252d3")
  (%check :tlreq-hashid-getdeps (= (%hashid-of "getDependencies") dds.types:+tl-getdeps-hash+)
          "@hashid(getDependencies) reproduces TypeLookup_getDependencies_HashId 0x05aafb31")
  (%check :tlreq-hashid-members
          (and (= (%hashid-of "type_ids") dds.types::+tl-member-type-ids+)
               (= (%hashid-of "continuation_point") dds.types::+tl-member-continuation-point+))
          "@hashid member ids for type_ids / continuation_point match the pinned constants")
  (let* ((guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (h1 (make-array 14 :element-type '(unsigned-byte 8) :initial-element #xAA))
         (octets (dds.types:serialize-type-lookup-request
                  :writer-guid guid :sn 5 :instance-name "dds.builtin.TOS.x"
                  :operation :get-types :type-ids (list h1))))
    (multiple-value-bind (op ids wguid sn iname)
        (dds.types:parse-type-lookup-request octets)
      (%check :tlreq-op (eq op :get-types) "operation discriminator round-trips")
      (%check :tlreq-ids (and (= 1 (length ids)) (equalp (first ids) h1)) "type_ids round-trip")
      (%check :tlreq-hdr (and (equalp wguid guid) (= sn 5) (string= iname "dds.builtin.TOS.x"))
              "RequestHeader round-trips"))
    (%check :tlreq-short (null (dds.types:parse-type-lookup-request (subseq octets 0 7)))
            "truncated request rejects (NIL)")
    (%check :tlreq-prefixes
            (loop for end in (%truncation-offsets (length octets))
                  always (null (dds.types:parse-type-lookup-request (subseq octets 0 end))))
            "every sampled proper prefix of the request rejects (NIL)")
    ;; hand-flip the union discriminator to an unknown value
    (let ((dpos (%find-le-u32 octets dds.types:+tl-gettypes-hash+)))
      (%check :tlreq-disc-found dpos "discriminator bytes located in the serialized request")
      (%check :tlreq-unknown
              (eq :unknown (dds.types:parse-type-lookup-request
                            (%patch-le-u32 octets dpos #x7FFFFFFF)))
              "unknown union discriminator yields :unknown without error"))
    ;; hand-flip the type_ids EMHEADER to an unknown member id, with and without M_FLAG
    (let* ((em (dds.cdr:emheader1-encode nil 5 dds.types::+tl-member-type-ids+))
           (epos (%find-le-u32 octets em)))
      (%check :tlreq-emheader-found epos "type_ids EMHEADER located in the serialized request")
      (multiple-value-bind (op ids)
          (dds.types:parse-type-lookup-request
           (%patch-le-u32 octets epos (dds.cdr:emheader1-encode nil 5 #x0000001)))
        (%check :tlreq-skip-unknown (and (eq op :get-types) (null ids))
                "unknown non-must-understand mutable member is skipped"))
      (%check :tlreq-mu-unknown
              (null (dds.types:parse-type-lookup-request
                     (%patch-le-u32 octets epos (dds.cdr:emheader1-encode t 5 #x0000001))))
              "unknown must-understand member rejects (NIL, §7.2.2.4.4.4.6)")))
  ;; getTypeDependencies: empty continuation omitted, parsed back as NIL
  (let* ((guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 1))
         (h1 (make-array 14 :element-type '(unsigned-byte 8) :initial-element 3))
         (octets (dds.types:serialize-type-lookup-request
                  :writer-guid guid :sn 9 :instance-name "dds.builtin.TOS.y"
                  :operation :get-deps :type-ids (list h1))))
    (multiple-value-bind (op ids wguid sn iname continuation)
        (dds.types:parse-type-lookup-request octets)
      (%check :tldeps-op (eq op :get-deps) "getTypeDependencies discriminator round-trips")
      (%check :tldeps-ids (and (= 1 (length ids)) (equalp (first ids) h1)) "type_ids round-trip")
      (%check :tldeps-hdr (and (equalp wguid guid) (= sn 9) (string= iname "dds.builtin.TOS.y"))
              "RequestHeader round-trips")
      (%check :tldeps-empty-cont (null continuation) "omitted continuation_point parses as NIL")))
  ;; getTypeDependencies with a non-empty continuation_point round-trips
  (let* ((guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 2))
         (h1 (make-array 14 :element-type '(unsigned-byte 8) :initial-element 4))
         (cont (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x5C))
         (octets (dds.types:serialize-type-lookup-request
                  :writer-guid guid :sn 11 :instance-name "i"
                  :operation :get-deps :type-ids (list h1) :continuation cont)))
    (multiple-value-bind (op ids wguid sn iname continuation)
        (dds.types:parse-type-lookup-request octets)
      (declare (ignore wguid sn iname))
      (%check :tlcont-op (eq op :get-deps) "getTypeDependencies discriminator round-trips")
      (%check :tlcont-ids (= 1 (length ids)) "type_ids round-trip alongside continuation_point")
      (%check :tlcont-cont (equalp continuation cont) "continuation_point round-trips")))
  t)

(defun* run-typelookup-reply-test ()
    (function () t)
  "Test: TypeLookup_Reply serialize/parse round-trip (XTypes 1.3 §7.6.3.3.2/.3)."
  ;; the four @hashid Out-struct member ids re-derive per §7.3.1.2.1.1
  (%check :tlrep-hashid-members
          (and (= (%hashid-of "types") dds.types::+tl-member-types+)
               (= (%hashid-of "complete_to_minimal") dds.types::+tl-member-complete-to-minimal+)
               (= (%hashid-of "dependent_typeids") dds.types::+tl-member-dependent-typeids+)
               (= (%hashid-of "continuation_point") dds.types::+tl-member-continuation-point+))
          "@hashid ids for types / complete_to_minimal / dependent_typeids / continuation_point")
  ;; getTypes reply: one TypeIdentifierTypeObjectPair round-trips byte-equal
  (let* ((m (dds.types:make-minimal-struct-type
             :name "P" :extensibility :appendable
             :members (list (dds.types:make-struct-member
                             "x" 0 (dds.types:primitive-type-identifier :i32))
                            (dds.types:make-struct-member
                             "y" 1 (dds.types:primitive-type-identifier :i32)))))
         (to (dds.types:minimal-type-object-octets m))
         (hash (dds.types:equivalence-hash m))
         (g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7))
         (rg (make-array 16 :element-type '(unsigned-byte 8) :initial-element 9))
         (octets (dds.types:serialize-type-lookup-reply
                  :writer-guid g :related-guid rg :related-sn 5
                  :operation :get-types :remote-ex :ok
                  :pairs (list (cons hash to)))))
    (multiple-value-bind (op pairs rguid rsn remote-ex)
        (dds.types:parse-type-lookup-reply octets)
      (%check :tlrep-op (eq op :get-types) "Return discriminator round-trips")
      (%check :tlrep-pair (and (= 1 (length pairs))
                               (equalp (car (first pairs)) hash)
                               (equalp (cdr (first pairs)) to))
              "TypeIdentifierTypeObjectPair round-trips byte-equal")
      (%check :tlrep-hdr (and (equalp rguid rg) (= rsn 5) (eq remote-ex :ok))
              "ReplyHeader (relatedRequestId + remoteEx) round-trips"))
    (%check :tlrep-prefixes
            (loop for end in (%truncation-offsets (length octets))
                  always (null (dds.types:parse-type-lookup-reply (subseq octets 0 end))))
            "every sampled proper prefix of the reply rejects (NIL)")
    ;; hand-flip the Return discriminator to an unknown value
    (let ((dpos (%find-le-u32 octets dds.types:+tl-gettypes-hash+)))
      (%check :tlrep-disc-found dpos "Return discriminator located in the serialized reply")
      (%check :tlrep-unknown
              (eq :unknown (dds.types:parse-type-lookup-reply
                            (%patch-le-u32 octets dpos #x7FFFFFFF)))
              "unknown TypeLookup_Return discriminator yields :unknown without error"))
    ;; hand-flip the types EMHEADER to an unknown member id with M_FLAG set
    (let* ((em (dds.cdr:emheader1-encode nil 5 dds.types::+tl-member-types+))
           (epos (%find-le-u32 octets em)))
      (%check :tlrep-emheader-found epos "types EMHEADER located in the serialized reply")
      (%check :tlrep-mu-unknown
              (null (dds.types:parse-type-lookup-reply
                     (%patch-le-u32 octets epos (dds.cdr:emheader1-encode t 5 #x0000001))))
              "unknown must-understand member rejects (NIL, §7.2.2.4.4.4.6)")))
  ;; getTypeDependencies reply: two TypeIdentfierWithSize [sic] entries round-trip
  (let* ((rg (make-array 16 :element-type '(unsigned-byte 8) :initial-element 2))
         (h1 (make-array 14 :element-type '(unsigned-byte 8) :initial-element 3))
         (h2 (make-array 14 :element-type '(unsigned-byte 8) :initial-element 4))
         (octets (dds.types:serialize-type-lookup-reply
                  :related-guid rg :related-sn 11
                  :operation :get-deps :remote-ex :ok
                  :dependencies (list (cons h1 40) (cons h2 88)))))
    (multiple-value-bind (op deps rguid rsn remote-ex)
        (dds.types:parse-type-lookup-reply octets)
      (%check :tlrepd-op (eq op :get-deps) "getTypeDependencies Return discriminator round-trips")
      (%check :tlrepd-deps (and (= 2 (length deps))
                                (equalp (car (first deps)) h1) (= (cdr (first deps)) 40)
                                (equalp (car (second deps)) h2) (= (cdr (second deps)) 88))
              "dependent_typeids (hash + typeobject_serialized_size) round-trip")
      (%check :tlrepd-hdr (and (equalp rguid rg) (= rsn 11) (eq remote-ex :ok))
              "ReplyHeader round-trips on the getTypeDependencies arm"))
    (%check :tlrepd-prefixes
            (loop for end in (%truncation-offsets (length octets))
                  always (null (dds.types:parse-type-lookup-reply (subseq octets 0 end))))
            "every sampled proper prefix of the deps reply rejects (NIL)"))
  ;; getTypeDependencies reply with a non-empty continuation_point round-trips
  (let* ((rg (make-array 16 :element-type '(unsigned-byte 8) :initial-element 6))
         (h1 (make-array 14 :element-type '(unsigned-byte 8) :initial-element 5))
         (cont (make-array 16 :element-type '(unsigned-byte 8) :initial-element #xA7))
         (octets (dds.types:serialize-type-lookup-reply
                  :related-guid rg :related-sn 13
                  :operation :get-deps :remote-ex :ok
                  :dependencies (list (cons h1 40)) :continuation cont)))
    (multiple-value-bind (op deps rguid rsn remote-ex continuation)
        (dds.types:parse-type-lookup-reply octets)
      (declare (ignore rguid rsn remote-ex))
      (%check :tlrepc-op (eq op :get-deps) "getTypeDependencies Return discriminator round-trips")
      (%check :tlrepc-deps (= 1 (length deps)) "dependent_typeids round-trip alongside continuation_point")
      (%check :tlrepc-cont (equalp continuation cont) "reply continuation_point round-trips byte-equal")))
  ;; non-OK remoteEx: header-only reply, no TypeLookup_Return arm
  (let* ((rg (make-array 16 :element-type '(unsigned-byte 8) :initial-element 1))
         (octets (dds.types:serialize-type-lookup-reply
                  :related-guid rg :related-sn 7 :remote-ex :unknown-operation)))
    (multiple-value-bind (op pairs rguid rsn remote-ex)
        (dds.types:parse-type-lookup-reply octets)
      (%check :tlrepx-op (null op) "non-OK reply carries no Return arm (op NIL)")
      (%check :tlrepx-empty (null pairs) "non-OK reply carries no result")
      (%check :tlrepx-hdr (and (equalp rguid rg) (= rsn 7) (eq remote-ex :unknown-operation))
              "REMOTE_EX_UNKNOWN_OPERATION ReplyHeader round-trips"))
    (%check :tlrepx-prefixes
            (loop for end in (%truncation-offsets (length octets))
                  always (null (dds.types:parse-type-lookup-reply (subseq octets 0 end))))
            "every sampled proper prefix of the non-OK reply rejects (NIL)"))
  t)

;;;; Self-pinned TypeLookup wire vectors (Task 5.1, FR-TYPE-3, ADR 0010): the literals
;;;; below were generated by THIS repo's serializers and frozen as regression vectors.
;;;; No live peer oracle exists (Connext does not implement the protocol, ADR 0010);
;;;; the tshark 4.6.6 RTPS dissector independently decodes both payloads field-by-field
;;;; (TL EntityIds, CDR2_LE, Request ID GUID/SN, instanceName, discriminator, type id
;;;; hashes, remote exception, TypeObject) and agrees with these bytes — see
;;;; docs/verification.csv FR-TYPE-3. CONFIRM-VS-PEER: re-pin vs a Fast DDS capture (FR-IO-2).

(defun* %tl-vector-guid ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "The fixed 16-octet requester GUID of the canonical vectors: prefix 01..0c +
   ENTITYID_TL_SVC_REQ_WRITER {{00,03,00},c3} (XTypes 1.3 Table 61)."
  (make-array 16 :element-type '(unsigned-byte 8)
                 :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 0 3 0 #xc3)))

(defun* %tl-vector-model ()
    (function () dds.types:minimal-struct-type)
  "The fixed 1-member model of the canonical reply vector: final struct tlv { long x; }."
  (dds.types:make-minimal-struct-type
   :name "tlv" :extensibility :final
   :members (list (dds.types:make-struct-member
                   "x" 0 (dds.types:primitive-type-identifier :i32)))))

(defun* run-typelookup-vector-test ()
    (function () t)
  "Test: the canonical getTypes REQUEST and REPLY serialize to the self-pinned octet
   vectors byte-exactly — freezes the emitted wire format against accidental drift."
  ;; provenance: emitted by serialize-type-lookup-request/-reply at this commit (self-pinned)
  (let* ((guid (%tl-vector-guid))
         (h (make-array 14 :element-type '(unsigned-byte 8)
                           :initial-contents (loop for i below 14 collect (+ #xA0 i))))
         (req (dds.types:serialize-type-lookup-request
               :writer-guid guid :sn 1
               :instance-name "dds.builtin.TOS.0d0e0f101112131415161718"
               :operation :get-types :type-ids (list h))))
    (%check :tlvec-request
            (equalp req (%hex-octets
                         (concatenate 'string
                          "000700000102030405060708090a0b0c000300c300000000"
                          "01000000290000006464732e6275696c74696e2e544f532e"
                          "306430653066313031313132313331343135313631373138"
                          "0000000023000000d35282011b0000006560535c13000000"
                          "01000000f1a0a1a2a3a4a5a6a7a8a9aaabacad")))
            "canonical getTypes REQUEST drifted from the pinned 115-octet vector"))
  (let* ((m (%tl-vector-model))
         (to (dds.types:minimal-type-object-octets m))
         (mhash (dds.types:equivalence-hash m)))
    (%check :tlvec-model-hash
            (equalp mhash (%hex-octets "c73b470caafdb605b296425893c0"))
            "tlv model EquivalenceHash drifted from the pinned 14 octets")
    (%check :tlvec-model-to
            (equalp to (%hex-octets
                        (concatenate 'string
                         "23000000f151010001000000000000001300000001000000"
                         "0b000000000000000100049dd4e461")))
            "tlv MinimalTypeObject drifted from the pinned 39-octet vector")
    (%check :tlvec-reply
            (equalp (dds.types:serialize-type-lookup-reply
                     :related-guid (%tl-vector-guid) :related-sn 1
                     :operation :get-types :remote-ex :ok
                     :pairs (list (cons mhash to)))
                    (%hex-octets
                     (concatenate 'string
                      "000700000102030405060708090a0b0c000300c300000000"
                      "010000000000000060000000d35282015800000000000000"
                      "50000000d14a80523b00000001000000f1c73b470caafdb6"
                      "05b296425893c00023000000f15101000100000000000000"
                      "13000000010000000b000000000000000100049dd4e46100"
                      "77658e5b0400000000000000")))
            "canonical getTypes REPLY drifted from the pinned 132-octet vector"))
  t)
