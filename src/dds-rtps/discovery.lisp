(in-package #:dds.rtps.discovery)

;;;; SPDP discovery: Locator_t codec + SPDPdiscoveredParticipantData build/parse
;;;; (RTPS 2.5 §8.5.3 / §9.6.2). Wire constants read from docs/specs/rtps-2_5.pdf
;;;; (clauses cited inline), never memorized. CLOS-free: defstruct + monomorphic
;;;; functions; every parser bounds-checks before trusting wire data.

(defconstant +locator-kind-udpv4+ 1
  "LOCATOR_KIND_UDPv4 = 1 (RTPS 2.5 §9.3.2.1 IDL / §9.3.2.4).")

;; Builtin EntityIds (RTPS 2.5 §9.3.1.3 Table 9.2): entityKey[3]+entityKind, MSB-first u32.
(defconstant +entityid-spdp-writer+     #x000100c2
  "SPDPbuiltinParticipantWriter EntityId {{00,01,00},c2} (RTPS 2.5 §9.3.1.3 Table 9.2).")
(defconstant +entityid-spdp-reader+     #x000100c7
  "SPDPbuiltinParticipantReader EntityId {{00,01,00},c7} (RTPS 2.5 §9.3.1.3 Table 9.2).")
(defconstant +entityid-sedp-pub-writer+ #x000003c2
  "SEDPbuiltinPublicationsWriter EntityId {{00,00,03},c2} (RTPS 2.5 §9.3.1.3 Table 9.2).")
(defconstant +entityid-sedp-pub-reader+ #x000003c7
  "SEDPbuiltinPublicationsReader EntityId {{00,00,03},c7} (RTPS 2.5 §9.3.1.3 Table 9.2).")
(defconstant +entityid-sedp-sub-writer+ #x000004c2
  "SEDPbuiltinSubscriptionsWriter EntityId {{00,00,04},c2} (RTPS 2.5 §9.3.1.3 Table 9.2).")
(defconstant +entityid-sedp-sub-reader+ #x000004c7
  "SEDPbuiltinSubscriptionsReader EntityId {{00,00,04},c7} (RTPS 2.5 §9.3.1.3 Table 9.2).")

;; Writer Liveliness Protocol P2P built-in endpoints (RTPS 2.5 §8.4.13.2; values §9.6.2.2).
(defconstant +entityid-p2p-participant-message-writer+ #x000200c2
  "ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER {{00,02,00},c2} (RTPS 2.5 §9.6.2.2; §8.4.13.2).")
(defconstant +entityid-p2p-participant-message-reader+ #x000200c7
  "ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER {{00,02,00},c7} (RTPS 2.5 §9.6.2.2; §8.4.13.2).")

;; ParticipantMessageData kind octet[4] (RTPS 2.5 §9.6.3.2); the integer maps to 4 big-endian octets (1 -> {0,0,0,1}).
(defconstant +pmd-kind-unknown+ 0
  "PARTICIPANT_MESSAGE_DATA_KIND_UNKNOWN {0,0,0,0} (RTPS 2.5 §9.6.3.2).")
(defconstant +pmd-kind-automatic+ 1
  "PARTICIPANT_MESSAGE_DATA_KIND_AUTOMATIC_LIVELINESS_UPDATE {0,0,0,1} (RTPS 2.5 §9.6.3.2).")
(defconstant +pmd-kind-manual-by-participant+ 2
  "PARTICIPANT_MESSAGE_DATA_KIND_MANUAL_LIVELINESS_UPDATE {0,0,0,2} (RTPS 2.5 §9.6.3.2).")

;; WLP builtin-endpoint bits (RTPS 2.5 §9.4.2.10); set in +builtin-endpoint-set-default+ (the WLP endpoints are wired).
(defconstant +be-participant-message-writer+ (ash 1 10)
  "BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_DATA_WRITER availableBuiltinEndpoints bit 10 (RTPS 2.5 §9.4.2.10).")
(defconstant +be-participant-message-reader+ (ash 1 11)
  "BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_DATA_READER availableBuiltinEndpoints bit 11 (RTPS 2.5 §9.4.2.10).")

;; TypeLookup builtin-endpoint bits (XTypes 1.3 §7.6.3.3.4 Table 62).
(defconstant +be-tl-request-writer+ (ash 1 12)
  "TypeLookupServiceRequestDataWriter availableBuiltinEndpoints bit (XTypes 1.3 Table 62).")
(defconstant +be-tl-request-reader+ (ash 1 13)
  "TypeLookupServiceRequestDataReader availableBuiltinEndpoints bit (XTypes 1.3 Table 62).")
(defconstant +be-tl-reply-writer+ (ash 1 14)
  "TypeLookupServiceReplyDataWriter availableBuiltinEndpoints bit (XTypes 1.3 Table 62).")
(defconstant +be-tl-reply-reader+ (ash 1 15)
  "TypeLookupServiceReplyDataReader availableBuiltinEndpoints bit (XTypes 1.3 Table 62).")
(defconstant +builtin-endpoint-set-default+
  (logior #x0000003F
          +be-participant-message-writer+ +be-participant-message-reader+
          +be-tl-request-writer+ +be-tl-request-reader+
          +be-tl-reply-writer+ +be-tl-reply-reader+)
  "Default availableBuiltinEndpoints mask we announce in SPDP: SPDP/SEDP announcer+
   detector bits 0-5 (BuiltinEndpointSet_t, RTPS 2.5 §9.3.2.12), the Writer Liveliness
   Protocol ParticipantMessage writer+reader bits 10-11 (RTPS 2.5 §9.4.2.10; §8.4.13),
   plus the four TypeLookup service bits 12-15 (XTypes 1.3 §7.6.3.3.4 Table 62). The
   ParticipantMessage bits are set now that the Writer Liveliness Protocol builtin
   endpoints are wired (the BuiltinParticipantMessageWriter periodically asserts this
   participant's liveliness; the reader records inbound assertions).")

(defconstant +locator-bytes+ 24
  "Locator_t size = {long kind; unsigned long port; octet address[16];} = 24 octets (RTPS 2.5 §9.3.2.1).")

(defun* write-locator (cursor kind port address)
    (function (dds.core.buffer:cursor (integer 0) (unsigned-byte 32) (simple-array (unsigned-byte 8) (16))) fixnum)
  "Write a 24-octet Locator_t: kind (i32) + port (u32) in cursor endianness, then
   16 raw address octets (RTPS 2.5 §9.3.2.1 / §9.4.2.18)."
  (dds.core.buffer:put-u32 cursor (logand kind #xFFFFFFFF))
  (dds.core.buffer:put-u32 cursor (logand port #xFFFFFFFF))
  (dds.core.buffer:put-octets cursor address 0 16)
  (dds.core.buffer:cursor-position cursor))

(defun* read-locator (cursor)
    (function (dds.core.buffer:cursor) t)
  "Read a 24-octet Locator_t. Returns (values kind port address) where KIND is the
   signed i32, or NIL if fewer than 24 octets remain. Bounds-checked; never reads
   OOB (RTPS 2.5 §9.3.2.1, NFR-SEC-POSTURE)."
  (when (< (- (dds.core.buffer:octet-buffer-capacity (dds.core.buffer:cursor-buffer cursor))
              (dds.core.buffer:cursor-position cursor))
           +locator-bytes+)
    (return-from read-locator nil))
  (let* ((ku (dds.core.buffer:get-u32 cursor))
         (kind (if (>= ku #x80000000) (- ku #x100000000) ku))
         (port (dds.core.buffer:get-u32 cursor))
         (address (make-array 16 :element-type '(unsigned-byte 8))))
    (dds.core.buffer:get-octets cursor address 0 16)
    (values kind port address)))

(defun* make-ipv4-locator (ip)
    (function ((simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (16)))
  "Build a 16-octet Locator address from a 4-octet IPv4 vector: 12 leading zeros
   then a.b.c.d at [12..15] (RTPS 2.5 §9.3.2.4)."
  (assert (= 4 (length ip)))
  (let ((address (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace address ip :start1 12 :end1 16 :start2 0 :end2 4)
    address))

;;; ---- Locator_t (RTPS 2.5 §9.3.2.4). A participant advertises a LIST of locators
;;; per traffic class (one per interface); selecting a routable one is a peer-
;;; interop necessity (foreign stacks list non-routable / 0.0.0.0 / non-UDPv4
;;; placeholders that must be skipped, not sent to). ----

(defstruct* (locator (:constructor make-locator))
  "An RTPS Locator_t: transport KIND, PORT (u32), 16-octet ADDRESS (UDPv4 in the
   low 4 octets). RTPS 2.5 §9.3.2.4."
  (kind +locator-kind-udpv4+ :type (integer 0))
  (port 0 :type (unsigned-byte 32))
  (address (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
           :type (simple-array (unsigned-byte 8) (16))))

(defun* locator-ipv4-string (loc)
    (function (locator) string)
  "Dotted-quad for a UDPv4 LOCATOR (IPv4 in address octets 12..15)."
  (let ((a (locator-address loc)))
    (format nil "~d.~d.~d.~d" (aref a 12) (aref a 13) (aref a 14) (aref a 15))))

(defun* locator-usable-udpv4-p (loc)
    (function (locator) t)
  "T iff LOC is a UDPv4 locator with a routable (non-0.0.0.0) address."
  (and (= (locator-kind loc) +locator-kind-udpv4+)
       (not (string= (locator-ipv4-string loc) "0.0.0.0"))))

(defun* usable-udpv4-locator (locators)
    (function (list) t)
  "The first routable UDPv4 LOCATOR in LOCATORS, or NIL — the locator-list selection
   that lets the data plane reach a foreign participant advertising several."
  (find-if #'locator-usable-udpv4-p locators))

;;; ---- SPDPdiscoveredParticipantData (RTPS 2.5 §8.5.3.2 / §9.6.2.2). A subset of
;;; the ParticipantBuiltinTopicData carried as a ParameterList in the SPDP DATA. ----

(defstruct* (spdp-data (:constructor make-spdp-data))
  "SPDPdiscoveredParticipantData (RTPS 2.5 §8.5.3.2 / §9.6.2.2): the subset of
   ParticipantBuiltinTopicData carried as a ParameterList in the SPDP DATA — GUID
   prefix, protocol version, vendor id, default/metatraffic unicast locator lists,
   lease duration, and the builtin-endpoint set."
  (guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)
               :type (simple-array (unsigned-byte 8) (12)))
  (version-major 2 :type (unsigned-byte 8))
  (version-minor 5 :type (unsigned-byte 8))
  (vendor-id 0 :type (unsigned-byte 16))
  (default-unicast-locators '() :type list)       ; list of LOCATOR (user traffic)
  (metatraffic-unicast-locators '() :type list)   ; list of LOCATOR (discovery)
  (lease-duration-seconds 100 :type (signed-byte 32))
  (builtin-endpoint-set 0 :type (unsigned-byte 32)))

(defun* %make-scratch (n)
    (function ((integer 0)) (values dds.core.buffer:cursor (simple-array (unsigned-byte 8) (*))))
  "A scratch octet buffer of N octets and a cursor over it (LE), for building one
   Parameter value at a time before handing it to WRITE-PARAMETER."
  (let* ((ob (dds.core.buffer:make-octet-buffer n))
         (cur (dds.core.buffer:cursor ob :endianness :little)))
    (values cur (dds.core.buffer:octet-buffer-vec ob))))

(defun* serialize-spdp-data (cursor data)
    (function (dds.core.buffer:cursor spdp-data) fixnum)
  "Serialize SPDP data as a ParameterList terminated by PID_SENTINEL (RTPS 2.5
   §8.5.3.2 / §9.4.2.11). Each Parameter value is built in a scratch buffer then
   emitted via WRITE-PARAMETER (which adds pid+length+padding)."
  ;; PID_PARTICIPANT_GUID: 12-octet prefix + 4-octet ENTITYID_PARTICIPANT (§9.3.1.2 GUID_t).
  (multiple-value-bind (c vec) (%make-scratch 16)
    (dds.core.buffer:put-octets c (spdp-data-guid-prefix data) 0 12)
    (dds.rtps.message:write-entity-id c dds.rtps.message:+entityid-participant+)
    (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-participant-guid+ vec 0 16))
  ;; PID_PROTOCOL_VERSION: ProtocolVersion_t {octet major; octet minor;} + 2 pad (§9.3.2.1).
  (multiple-value-bind (c vec) (%make-scratch 2)
    (dds.core.buffer:put-u8 c (spdp-data-version-major data))
    (dds.core.buffer:put-u8 c (spdp-data-version-minor data))
    (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-protocol-version+ vec 0 2))
  ;; PID_VENDORID: VendorId_t octet[2] + 2 pad (§9.3.2.1).
  (multiple-value-bind (c vec) (%make-scratch 2)
    (dds.core.buffer:put-u8 c (ldb (byte 8 8) (spdp-data-vendor-id data)))
    (dds.core.buffer:put-u8 c (ldb (byte 8 0) (spdp-data-vendor-id data)))
    (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-vendorid+ vec 0 2))
  ;; PID_DEFAULT_UNICAST_LOCATOR x N: one Locator_t (24 octets) per list entry
  ;; (§9.3.2.1 / §9.6.2.2). A participant may advertise several (one per interface).
  (dolist (loc (spdp-data-default-unicast-locators data))
    (multiple-value-bind (c vec) (%make-scratch +locator-bytes+)
      (write-locator c (locator-kind loc) (locator-port loc) (locator-address loc))
      (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-default-unicast-locator+
                                        vec 0 +locator-bytes+)))
  ;; PID_METATRAFFIC_UNICAST_LOCATOR x N: Locator_t (24 octets) per entry (§9.6.2.2).
  (dolist (loc (spdp-data-metatraffic-unicast-locators data))
    (multiple-value-bind (c vec) (%make-scratch +locator-bytes+)
      (write-locator c (locator-kind loc) (locator-port loc) (locator-address loc))
      (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-metatraffic-unicast-locator+
                                        vec 0 +locator-bytes+)))
  ;; PID_PARTICIPANT_LEASE_DURATION: Duration_t {long seconds; unsigned long fraction;} (§9.3.2.3).
  (multiple-value-bind (c vec) (%make-scratch 8)
    (dds.core.buffer:put-u32 c (logand (spdp-data-lease-duration-seconds data) #xFFFFFFFF))
    (dds.core.buffer:put-u32 c 0)
    (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-participant-lease-duration+ vec 0 8))
  ;; PID_BUILTIN_ENDPOINT_SET: BuiltinEndpointSet_t (u32) (§9.3.2.1 / §9.6.2.2).
  (multiple-value-bind (c vec) (%make-scratch 4)
    (dds.core.buffer:put-u32 c (spdp-data-builtin-endpoint-set data))
    (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-builtin-endpoint-set+ vec 0 4))
  (dds.rtps.message:write-parameter-sentinel cursor))

(defun* %fill-spdp-param (data pid cursor len)
    (function (spdp-data (unsigned-byte 16) dds.core.buffer:cursor (integer 0)) t)
  "ParameterList handler: fill DATA from one Parameter. Bounds is enforced by the
   caller (LEN octets are guaranteed present); inner reads re-check (§9.4.2.11)."
  (cond
    ((= pid dds.rtps.message:+pid-participant-guid+)
     (when (>= len 12)
       (dds.core.buffer:get-octets cursor (spdp-data-guid-prefix data) 0 12)))
    ((= pid dds.rtps.message:+pid-protocol-version+)
     (when (>= len 2)
       (setf (spdp-data-version-major data) (dds.core.buffer:get-u8 cursor))
       (setf (spdp-data-version-minor data) (dds.core.buffer:get-u8 cursor))))
    ((= pid dds.rtps.message:+pid-vendorid+)
     (when (>= len 2)
       (let ((hi (dds.core.buffer:get-u8 cursor)) (lo (dds.core.buffer:get-u8 cursor)))
         (setf (spdp-data-vendor-id data) (logior (ash hi 8) lo)))))
    ((= pid dds.rtps.message:+pid-default-unicast-locator+)
     (when (>= len +locator-bytes+)
       (multiple-value-bind (k p a) (read-locator cursor)
         (when k
           (push (make-locator :kind (logand k #xFFFFFFFF) :port p :address a)
                 (spdp-data-default-unicast-locators data))))))
    ((= pid dds.rtps.message:+pid-metatraffic-unicast-locator+)
     (when (>= len +locator-bytes+)
       (multiple-value-bind (k p a) (read-locator cursor)
         (when k
           (push (make-locator :kind (logand k #xFFFFFFFF) :port p :address a)
                 (spdp-data-metatraffic-unicast-locators data))))))
    ((= pid dds.rtps.message:+pid-participant-lease-duration+)
     (when (>= len 8)
       (let ((su (dds.core.buffer:get-u32 cursor)))
         (setf (spdp-data-lease-duration-seconds data)
               (if (>= su #x80000000) (- su #x100000000) su)))))
    ((= pid dds.rtps.message:+pid-builtin-endpoint-set+)
     (when (>= len 4)
       (setf (spdp-data-builtin-endpoint-set data) (dds.core.buffer:get-u32 cursor)))))
  data)

(defun* parse-spdp-data (cursor)
    (function (dds.core.buffer:cursor) t)
  "Parse an SPDP ParameterList into an SPDP-DATA struct, or NIL if the list is
   truncated (RTPS 2.5 §8.5.3.2 / §9.4.2.11). Bounds-checked via PARSE-PARAMETER-LIST."
  (let ((data (make-spdp-data)))
    (if (dds.rtps.message:parse-parameter-list
         cursor (lambda (pid c len) (%fill-spdp-param data pid c len)))
        (progn   ; locators were accumulated LIFO; restore advertised order
          (setf (spdp-data-default-unicast-locators data)
                (nreverse (spdp-data-default-unicast-locators data))
                (spdp-data-metatraffic-unicast-locators data)
                (nreverse (spdp-data-metatraffic-unicast-locators data)))
          data)
        nil)))

;;; ---- Standalone round-trip + byte-exact test (no external test framework) ----

(defun* %ip-127-0-0-1 ()
    (function () (simple-array (unsigned-byte 8) (4)))
  "The IPv4 vector 127.0.0.1."
  (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(127 0 0 1)))

(defun* %check-locator-bytes ()
    (function () t)
  "Byte-exact check: a UDPv4 locator (port 7410, 127.0.0.1) is 24 little-endian
   octets: kind LE, port LE, 12 zeros, 127 0 0 1 (RTPS 2.5 §9.3.2.1 / §9.3.2.4)."
  (let* ((ob (dds.core.buffer:make-octet-buffer 24))
         (cur (dds.core.buffer:cursor ob :endianness :little))
         (addr (make-ipv4-locator (%ip-127-0-0-1)))
         (vec (dds.core.buffer:octet-buffer-vec ob)))
    (write-locator cur +locator-kind-udpv4+ 7410 addr)
    (let ((expected (make-array 24 :element-type '(unsigned-byte 8)
                                :initial-contents '(1 0 0 0      ; kind=1 LE
                                                    #xF2 #x1C 0 0 ; port=7410 LE
                                                    0 0 0 0 0 0 0 0 0 0 0 0
                                                    127 0 0 1))))
      (dotimes (i 24)
        (assert (= (aref vec i) (aref expected i)) ()
                "Locator byte ~d: got ~d want ~d" i (aref vec i) (aref expected i))))
    t))

(defun* run-discovery-test ()
    (function () (values t t))
  "Build SPDP data, serialize, parse back, and assert every field round-trips;
   also byte-exact-check the Locator encoding. Returns T on success (ASSERT
   signals otherwise)."
  (%check-locator-bytes)
  (flet ((ip4 (a b c d) (make-ipv4-locator
                         (make-array 4 :element-type '(unsigned-byte 8)
                                     :initial-contents (list a b c d)))))
    (let* ((prefix (make-array 12 :element-type '(unsigned-byte 8)
                               :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12)))
           ;; two default-unicast locators: a 0.0.0.0 placeholder then a real one
           ;; (exactly the multi-locator shape a foreign stack advertises).
           (du0 (make-locator :kind +locator-kind-udpv4+ :port 7411 :address (ip4 0 0 0 0)))
           (du1 (make-locator :kind +locator-kind-udpv4+ :port 7411 :address (ip4 192 168 1 50)))
           (mt  (make-locator :kind +locator-kind-udpv4+ :port 7410 :address (ip4 127 0 0 1)))
           (data (make-spdp-data :guid-prefix prefix
                                 :version-major 2 :version-minor 5 :vendor-id #x010F
                                 :default-unicast-locators (list du0 du1)
                                 :metatraffic-unicast-locators (list mt)
                                 :lease-duration-seconds 30 :builtin-endpoint-set +builtin-endpoint-set-default+))
           (ob (dds.core.buffer:make-octet-buffer 512))
           (wc (dds.core.buffer:cursor ob :endianness :little)))
      (serialize-spdp-data wc data)
      (let* ((rc (dds.core.buffer:cursor ob :endianness :little))
             (back (parse-spdp-data rc)))
        (assert back () "parse-spdp-data returned NIL")
        (assert (equalp (spdp-data-guid-prefix back) prefix) () "guid-prefix mismatch")
        (assert (= (spdp-data-version-major back) 2) () "version-major mismatch")
        (assert (= (spdp-data-version-minor back) 5) () "version-minor mismatch")
        (assert (= (spdp-data-vendor-id back) #x010F) () "vendor-id mismatch")
        (let ((dlocs (spdp-data-default-unicast-locators back)))
          (assert (= 2 (length dlocs)) () "expected 2 default-unicast locators, got ~d" (length dlocs))
          (assert (= (locator-port (first dlocs)) 7411) () "default[0] port mismatch")
          (assert (string= (locator-ipv4-string (first dlocs)) "0.0.0.0") () "default[0] addr (order)")
          (assert (string= (locator-ipv4-string (second dlocs)) "192.168.1.50") () "default[1] addr (order)")
          ;; the selection skips the 0.0.0.0 placeholder and picks the routable one
          (assert (string= (locator-ipv4-string (usable-udpv4-locator dlocs)) "192.168.1.50")
                  () "usable-udpv4-locator must skip 0.0.0.0"))
        (let ((mlocs (spdp-data-metatraffic-unicast-locators back)))
          (assert (= 1 (length mlocs)) () "expected 1 metatraffic locator")
          (assert (= (locator-port (first mlocs)) 7410) () "metatraffic port mismatch")
          (assert (string= (locator-ipv4-string (first mlocs)) "127.0.0.1") () "metatraffic addr mismatch"))
        (assert (= (spdp-data-lease-duration-seconds back) 30) () "lease mismatch")
        (assert (= (spdp-data-builtin-endpoint-set back) +builtin-endpoint-set-default+) () "endpoint-set mismatch")
        (values t back)))))

;;;; ---- ParticipantMessageData: the logical content of the BuiltinParticipant-
;;;; MessageWriter/Reader used by the Writer Liveliness Protocol (RTPS 2.5 §8.4.13.4
;;;; / §9.6.3.2). A plain CDR struct (NOT a ParameterList): GuidPrefix_t prefix (12) +
;;;; octet[4] kind + sequence<octet> data. This codec produces the BARE struct bytes;
;;;; the discovery layer (Task 1.2) wraps them in the SerializedPayload encapsulation
;;;; header, exactly as the DATA submessage wraps the SPDP/SEDP ParameterList. ----

(defstruct* (participant-message (:constructor make-participant-message))
  "ParticipantMessageData (RTPS 2.5 §8.4.13.4 / §9.6.3.2). The DDS key is
   participantGuidPrefix + kind. KIND is stored as the integer the octet[4] encodes
   big-endian (value[0] is the MSB-test byte), e.g. +pmd-kind-automatic+ = 1 -> wire
   {0,0,0,1}. DATA is the variable-length sequence<octet> payload."
  (guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)
               :type (simple-array (unsigned-byte 8) (12)))
  (kind +pmd-kind-automatic+ :type (unsigned-byte 32))
  (data (make-array 0 :element-type '(unsigned-byte 8))
        :type (simple-array (unsigned-byte 8) (*))))

(defun* serialize-participant-message (pm)
    (function (participant-message) (simple-array (unsigned-byte 8) (*)))
  "Serialize a ParticipantMessageData to the bare CDR struct (no encapsulation):
   prefix(12) + kind as octet[4] big-endian + data.length (u32) + data octets (RTPS
   2.5 §9.6.3.2). DATA is the final struct member so no trailing CDR alignment pad is
   emitted (XCDR §10.2 pads only to align a following member). The sequence-length
   u32 is written little-endian to mirror the stack's default PLAIN_CDR
   encapsulation; kind is octet[4] raw so it is endianness-independent."
  (let* ((dlen (length (participant-message-data pm)))
         (total (+ 12 4 4 dlen))
         (ob (dds.core.buffer:make-octet-buffer total))
         (c (dds.core.buffer:cursor ob :endianness :little)))
    (dds.core.buffer:put-octets c (participant-message-guid-prefix pm) 0 12)
    (let ((k (participant-message-kind pm)))
      (dotimes (i 4) (dds.core.buffer:put-u8 c (ldb (byte 8 (* 8 (- 3 i))) k))))
    (dds.core.buffer:put-u32 c dlen)
    (when (plusp dlen)
      (dds.core.buffer:put-octets c (participant-message-data pm) 0 dlen))
    (dds.core.buffer:octet-buffer-vec ob)))

(defun* parse-participant-message (bytes)
    (function ((simple-array (unsigned-byte 8) (*))) t)
  "Parse the bare CDR ParticipantMessageData struct from BYTES (no encapsulation
   header). Returns a PARTICIPANT-MESSAGE, or NIL on truncation. Every field is
   bounds-checked BEFORE it is read and the wire-supplied data.length is validated
   against the remaining buffer before allocating, so a hostile length can never
   cause OOB access or exhaust the heap (NFR-SEC-POSTURE; RTPS 2.5 §9.6.3.2)."
  (let ((cap (length bytes)))
    (when (< cap 20)
      (return-from parse-participant-message nil))
    (let* ((ob (dds.core.buffer:make-octet-buffer cap))
           (c (dds.core.buffer:cursor ob :endianness :little)))
      (dds.core.buffer:put-octets c bytes 0 cap)
      (dds.core.buffer:cursor-reset c)
    (let ((prefix (make-array 12 :element-type '(unsigned-byte 8))))
      (dds.core.buffer:get-octets c prefix 0 12)
      (let ((kind 0))
        (dotimes (i 4) (setf kind (logior (ash kind 8) (dds.core.buffer:get-u8 c))))
        (let ((dlen (dds.core.buffer:get-u32 c)))
          (when (> dlen (- cap (dds.core.buffer:cursor-position c)))
            (return-from parse-participant-message nil))
          (let ((data (make-array dlen :element-type '(unsigned-byte 8))))
            (when (plusp dlen) (dds.core.buffer:get-octets c data 0 dlen))
            (make-participant-message :guid-prefix prefix :kind kind :data data))))))))

;;;; ---- SEDP: Simple Endpoint Discovery Protocol (RTPS 2.5 §8.5.4 / §9.6.2.2).
;;;; DiscoveredWriterData / DiscoveredReaderData carried as a ParameterList in the
;;;; SEDP DATA. One ENDPOINT-DATA struct serves both (shared core fields for v1).
;;;; Wire constants pinned from docs/specs/ (cited inline), never memorized. ----

;; ReliabilityQosPolicyKind: BEST_EFFORT=1, RELIABLE=2 (RELIABLE is the stronger/
;; higher value for RxO) — DDS-XTypes 1.3 §7.6.3.1.2 IDL, xtypes-1_3-discovery-builtin-topic.idl L126.
(defconstant +reliability-best-effort+ 1
  "BEST_EFFORT_RELIABILITY_QOS = 1 (DDS-XTypes 1.3 §7.6.3.1.2 IDL).")
(defconstant +reliability-reliable+ 2
  "RELIABLE_RELIABILITY_QOS = 2; the stronger/higher RxO value (DDS-XTypes 1.3 §7.6.3.1.2 IDL).")

;; QoS <-> on-the-wire kind mappings (DDS-XTypes 1.3 discovery IDL enum order, a
;; big-endian long per policy). reliability is 1/2 (not 0-based); durability is 0-3.
(defun* %reliability-wire (k)
    (function (symbol) (unsigned-byte 32))
  "Map a RELIABILITY kind keyword to its PID_RELIABILITY wire code (RTPS 2.5 §9.6.2.2)." (ecase k (:best-effort +reliability-best-effort+) (:reliable +reliability-reliable+)))
(defun* %wire-reliability (n)
    (function ((unsigned-byte 32)) symbol)
  "Map a PID_RELIABILITY wire code to a RELIABILITY kind keyword (>= the reliable code is :reliable)." (if (>= n +reliability-reliable+) :reliable :best-effort))
(defun* %durability-wire (k)
    (function (symbol) (unsigned-byte 32))
  "Map a DURABILITY kind keyword to its PID_DURABILITY wire code (0..3)." (ecase k (:volatile 0) (:transient-local 1) (:transient 2) (:persistent 3)))
(defun* %wire-durability (n)
    (function ((unsigned-byte 32)) symbol)
  "Map a PID_DURABILITY wire code (0..3) to a DURABILITY kind keyword (default :volatile)." (case n (1 :transient-local) (2 :transient) (3 :persistent) (t :volatile)))
(defun* %wire-liveliness (n)
    (function ((unsigned-byte 32)) symbol)
  "Map a PID_LIVELINESS wire kind to a LIVELINESS keyword (DDS 1.4 PSM LivelinessQosPolicyKind
   0=AUTOMATIC,1=MANUAL_BY_PARTICIPANT,2=MANUAL_BY_TOPIC); an unknown code keeps the default :automatic, never rejecting (FR-QOS-2)." (case n (1 :manual-by-participant) (2 :manual-by-topic) (t :automatic)))
(defun* %ownership-wire (k)
    (function (symbol) (unsigned-byte 32))
  "Map an OWNERSHIP kind keyword to its PID_OWNERSHIP wire code (OwnershipQosPolicyKind, dds_rtf2_dcps.idl: SHARED=0, EXCLUSIVE=1)." (ecase k (:shared 0) (:exclusive 1)))
(defun* %wire-ownership (n)
    (function ((unsigned-byte 32)) symbol)
  "Map a PID_OWNERSHIP wire code to an OWNERSHIP kind keyword (1=EXCLUSIVE, else the default :shared); an unknown code never rejects (FR-QOS-2)." (if (= n 1) :exclusive :shared))

(defstruct* (endpoint-data (:constructor make-endpoint-data))
  "DiscoveredWriterData / DiscoveredReaderData (RTPS 2.5 §8.5.4 / §9.6.2.2): a 16-octet
   GUID, topic + type names, and the QoS carried for RxO matching (FR-QOS-2)."
  (guid (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
        :type (simple-array (unsigned-byte 8) (16)))
  ;; :writer (DCPSPublication) vs :reader (DCPSSubscription) — selects the writer-only PIDs.
  ;; OwnershipStrengthQosPolicy is in DataWriterQos only, never DataReaderQos (dds_rtf2_dcps.idl).
  (role :writer :type (member :writer :reader))
  (topic-name "" :type string)
  (type-name "" :type string)
  (qos (dds.qos:make-qos) :type dds.qos:qos)
  ;; Opaque pre-serialized XTypes TypeInformation (PID_TYPE_INFORMATION, idl @id 0x0075).
  ;; dds-rtps (L4) must not depend on dds-types (L3); dds-disc/dds-dcps build + interpret it.
  (type-information nil :type (or null (simple-array (unsigned-byte 8) (*))))
  ;; Opaque inbound RTI PID_TYPE_OBJECT_LB (0x8021): the ZLIB-compressed complete TypeObject
  ;; a Connext peer advertises. Stored verbatim here (L4); dds-disc inflates + fingerprints it
  ;; (dds.types, ADR 0009). Never EMITTED — RTI-vendor + clean-room; inbound only.
  (type-object-lb nil :type (or null (simple-array (unsigned-byte 8) (*)))))

(defun* serialize-endpoint-data (cursor data)
    (function (dds.core.buffer:cursor endpoint-data) fixnum)
  "Serialize ENDPOINT-DATA as a ParameterList terminated by PID_SENTINEL (RTPS 2.5
   §8.5.4 / §9.4.2.11). Each Parameter value is built in a scratch buffer then
   emitted via WRITE-PARAMETER (which adds pid+length+padding)."
  ;; PID_ENDPOINT_GUID: GUID_t = 12-octet prefix + 4-octet entity id = 16 octets (§9.3.1.2).
  (multiple-value-bind (c vec) (%make-scratch 16)
    (dds.core.buffer:put-octets c (endpoint-data-guid data) 0 16)
    (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-endpoint-guid+ vec 0 16))
  ;; PID_TOPIC_NAME: CDR string (§9.6.2.2 / DDS-XTypes 1.3 PublicationBuiltinTopicData.topic_name).
  (let ((s (endpoint-data-topic-name data)))
    (multiple-value-bind (c vec) (%make-scratch (+ 8 (length s)))
      (dds.cdr:cdr-put-string c s :xcdr1)
      (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-topic-name+
                                        vec 0 (dds.core.buffer:cursor-position c))))
  ;; PID_TYPE_NAME: CDR string (§9.6.2.2 / DDS-XTypes 1.3 ...BuiltinTopicData.type_name).
  (let ((s (endpoint-data-type-name data)))
    (multiple-value-bind (c vec) (%make-scratch (+ 8 (length s)))
      (dds.cdr:cdr-put-string c s :xcdr1)
      (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-type-name+
                                        vec 0 (dds.core.buffer:cursor-position c))))
  ;; PID_RELIABILITY (0x001a): {long kind; Duration_t max_blocking_time;} = 12 octets.
  (multiple-value-bind (c vec) (%make-scratch 12)
    (dds.core.buffer:put-u32 c (%reliability-wire (dds.qos:qos-reliability (endpoint-data-qos data))))
    (dds.core.buffer:put-u32 c 0)
    (dds.core.buffer:put-u32 c 0)
    (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-reliability+ vec 0 12))
  ;; PID_DURABILITY (0x001d): {long kind;} = 4 octets (RTPS 2.5 §9.6.3.2).
  (multiple-value-bind (c vec) (%make-scratch 4)
    (dds.core.buffer:put-u32 c (%durability-wire (dds.qos:qos-durability (endpoint-data-qos data))))
    (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-durability+ vec 0 4))
  ;; PID_LIVELINESS (0x001b): {long kind; Duration_t lease_duration;} = 12 octets
  ;; (RTPS 2.5 Table 9.18 §9.6.2.2; DDS 1.4 PSM LivelinessQosPolicy). kind = liveliness-rank.
  ;; lease_duration is the RTPS-wire Duration_t {seconds; fraction(sec/2^32)} (§9.3.2):
  ;; the DCPS nanosec is converted to the wire fraction so an INFINITE lease emits
  ;; fraction 0xffffffff (not the DCPS nanosec sentinel), else a conformant peer reads
  ;; INFINITE as a finite ~0.5 s lease and the RxO liveliness check rejects the match.
  (let* ((q (endpoint-data-qos data)) (lease (dds.qos:qos-liveliness-lease q)))
    (multiple-value-bind (c vec) (%make-scratch 12)
      (dds.core.buffer:put-u32 c (dds.qos:liveliness-rank (dds.qos:qos-liveliness q)))
      (dds.core.buffer:put-u32 c (dds.qos:qos-duration-sec lease))
      (dds.core.buffer:put-u32 c (dds.qos:duration-nanosec->wire-fraction
                                  (dds.qos:qos-duration-nanosec lease)))
      (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-liveliness+ vec 0 12)))
  ;; PID_OWNERSHIP (0x001f): {OwnershipQosPolicyKind kind;} = 4 octets (RTPS 2.5 Table 9.18
  ;; §9.6.2.2; dds_rtf2_dcps.idl §2.2.3.9: SHARED=0, EXCLUSIVE=1). Always emitted (both roles).
  (let ((q (endpoint-data-qos data)))
    (multiple-value-bind (c vec) (%make-scratch 4)
      (dds.core.buffer:put-u32 c (%ownership-wire (dds.qos:qos-ownership q)))
      (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-ownership+ vec 0 4))
    ;; PID_OWNERSHIP_STRENGTH (0x0006): {long value;} = 4 octets (RTPS 2.5 Table 9.18 §9.6.2.2;
    ;; dds_rtf2_dcps.idl §2.2.3.10). DataWriterQos only — a :reader endpoint never emits it.
    (when (eq (endpoint-data-role data) :writer)
      (multiple-value-bind (c vec) (%make-scratch 4)
        (dds.core.buffer:put-u32 c (ldb (byte 32 0) (dds.qos:qos-ownership-strength q)))
        (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-ownership-strength+ vec 0 4))))
  ;; PID_TYPE_INFORMATION (idl @id 0x0075): opaque pre-serialized XTypes TypeInformation,
  ;; emitted only when present (peers skip unknown PIDs — backward-compatible).
  (let ((ti (endpoint-data-type-information data)))
    (when ti
      (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-type-information+
                                        ti 0 (length ti))))
  (dds.rtps.message:write-parameter-sentinel cursor))

(defun* %fill-endpoint-param (data pid cursor len)
    (function (endpoint-data (unsigned-byte 16) dds.core.buffer:cursor (integer 0)) t)
  "ParameterList handler: fill DATA from one Parameter. The caller guarantees LEN
   octets are present; inner reads gate on the minimum size (§9.4.2.11)."
  (cond
    ((= pid dds.rtps.message:+pid-endpoint-guid+)
     (when (>= len 16)
       (dds.core.buffer:get-octets cursor (endpoint-data-guid data) 0 16)))
    ((= pid dds.rtps.message:+pid-topic-name+)
     (when (>= len 4)
       (setf (endpoint-data-topic-name data) (dds.cdr:cdr-get-string cursor :xcdr1))))
    ((= pid dds.rtps.message:+pid-type-name+)
     (when (>= len 4)
       (setf (endpoint-data-type-name data) (dds.cdr:cdr-get-string cursor :xcdr1))))
    ((= pid dds.rtps.message:+pid-reliability+)
     (when (>= len 4)
       (setf (dds.qos:qos-reliability (endpoint-data-qos data))
             (%wire-reliability (dds.core.buffer:get-u32 cursor)))))
    ((= pid dds.rtps.message:+pid-durability+)
     (when (>= len 4)
       (setf (dds.qos:qos-durability (endpoint-data-qos data))
             (%wire-durability (dds.core.buffer:get-u32 cursor)))))
    ((= pid dds.rtps.message:+pid-liveliness+)
     (when (= len 12)
       (let* ((q (endpoint-data-qos data))
              (kind (%wire-liveliness (dds.core.buffer:get-u32 cursor)))
              (sec (dds.core.buffer:get-u32 cursor))
              (fraction (dds.core.buffer:get-u32 cursor)))
         (setf (dds.qos:qos-liveliness q) kind
               (dds.qos:qos-liveliness-lease q)
               (dds.qos:make-qos-duration
                sec (dds.qos:wire-fraction->duration-nanosec fraction))))))
    ((= pid dds.rtps.message:+pid-ownership+)
     (when (= len 4)
       (setf (dds.qos:qos-ownership (endpoint-data-qos data))
             (%wire-ownership (dds.core.buffer:get-u32 cursor)))))
    ((= pid dds.rtps.message:+pid-ownership-strength+)
     (when (= len 4)
       (setf (dds.qos:qos-ownership-strength (endpoint-data-qos data))
             (let ((u (dds.core.buffer:get-u32 cursor)))
               (if (>= u #x80000000) (- u #x100000000) u)))))
    ((= pid dds.rtps.message:+pid-type-information+)
     (when (> len 0)
       (let ((ti (make-array len :element-type '(unsigned-byte 8))))
         (dds.core.buffer:get-octets cursor ti 0 len)
         (setf (endpoint-data-type-information data) ti))))
    ((= pid dds.rtps.message:+pid-type-object-lb+)
     (when (> len 0)
       (let ((lb (make-array len :element-type '(unsigned-byte 8))))
         (dds.core.buffer:get-octets cursor lb 0 len)
         (setf (endpoint-data-type-object-lb data) lb)))))
  data)

(defun* parse-endpoint-data (cursor role)
    (function (dds.core.buffer:cursor (member :writer :reader)) t)
  "Parse a SEDP ParameterList into an ENDPOINT-DATA struct, or NIL if the list is
   truncated (RTPS 2.5 §8.5.4 / §9.4.2.11). Bounds-checked via PARSE-PARAMETER-LIST.
   The required ROLE seeds the QoS defaults an ABSENT parameter must assume (RTPS 2.5 §9.4.2.11.2):
   a DCPSPublication (:writer) defaults RELIABILITY to RELIABLE, a DCPSSubscription
   (:reader) to BEST_EFFORT (DDS 1.4 §2.2.3 RELIABILITY) — RTI Connext elides
   default-valued PIDs, so a reliable Connext writer carries NO PID_RELIABILITY."
  (let ((data (make-endpoint-data :role role
                                  :qos (if (eq role :writer)
                                           (dds.qos:make-writer-qos)
                                           (dds.qos:make-reader-qos)))))
    (if (dds.rtps.message:parse-parameter-list
         cursor (lambda (pid c len) (%fill-endpoint-param data pid c len)))
        data
        nil)))

(defun* endpoint-match-p (writer-data reader-data)
    (function (endpoint-data endpoint-data) (values boolean list))
  "(values MATCH-P INCOMPATIBLE): topic + type names equal AND the offered (writer)
   QoS is RxO-compatible with the requested (reader) QoS — the full DDS 1.4 §2.2.3
   table via dds.qos:qos-rxo-compatible (FR-QOS-2). INCOMPATIBLE is the failing-policy
   list (drives OFFERED/REQUESTED_INCOMPATIBLE_QOS); '(:topic-or-type) on a name
   mismatch. The boolean first value preserves the existing (when (match-p ...)) callers."
  (if (and (string= (endpoint-data-topic-name writer-data) (endpoint-data-topic-name reader-data))
           (string= (endpoint-data-type-name writer-data) (endpoint-data-type-name reader-data)))
      (dds.qos:qos-rxo-compatible (endpoint-data-qos writer-data) (endpoint-data-qos reader-data))
      (values nil '(:topic-or-type))))

(defun* %sample-guid ()
    (function () (simple-array (unsigned-byte 8) (16)))
  "A deterministic 16-octet GUID for the SEDP round-trip test."
  (make-array 16 :element-type '(unsigned-byte 8)
              :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12 0 0 1 2)))

(defun* run-sedp-test ()
    (function () t)
  "Round-trip an ENDPOINT-DATA through serialize/parse and assert the GUID, topic,
   type, and reliability kind survive; then exercise the RxO matching truth table.
   Returns T on success (ASSERT signals otherwise)."
  (let* ((guid (%sample-guid))
         (tinfo (make-array 12 :element-type '(unsigned-byte 8)
                            :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12)))
         (data (make-endpoint-data :guid guid :topic-name "Square" :type-name "ShapeType"
                                   :type-information tinfo
                                   :qos (dds.qos:make-qos :reliability :reliable
                                                          :durability :transient-local)))
         (ob (dds.core.buffer:make-octet-buffer 256))
         (wc (dds.core.buffer:cursor ob :endianness :little)))
    (serialize-endpoint-data wc data)
    (let* ((rc (dds.core.buffer:cursor ob :endianness :little))
           (back (parse-endpoint-data rc :writer)))
      (assert back () "parse-endpoint-data returned NIL")
      (assert (equalp (endpoint-data-guid back) guid) () "guid mismatch")
      (assert (string= (endpoint-data-topic-name back) "Square") () "topic-name mismatch")
      (assert (string= (endpoint-data-type-name back) "ShapeType") () "type-name mismatch")
      (assert (eq (dds.qos:qos-reliability (endpoint-data-qos back)) :reliable) () "reliability mismatch")
      (assert (eq (dds.qos:qos-durability (endpoint-data-qos back)) :transient-local) () "durability mismatch")
      (assert (equalp (endpoint-data-type-information back) tinfo) ()
              "PID_TYPE_INFORMATION opaque round-trip mismatch")))
  ;; RxO matching truth table over the wire QoS (FR-QOS-2): reliability + durability.
  (flet ((ep (topic q) (make-endpoint-data :topic-name topic :type-name "Y" :qos q)))
    (let ((w-rel (ep "T" (dds.qos:make-qos :reliability :reliable)))
          (w-be  (ep "T" (dds.qos:make-qos :reliability :best-effort)))
          (r-rel (ep "T" (dds.qos:make-qos :reliability :reliable)))
          (r-be  (ep "T" (dds.qos:make-qos :reliability :best-effort)))
          (r-topic (ep "OTHER" (dds.qos:make-qos)))
          (w-vol (ep "T" (dds.qos:make-qos :durability :volatile)))
          (r-tl  (ep "T" (dds.qos:make-qos :durability :transient-local))))
      (assert (endpoint-match-p w-rel r-be) () "(a) RELIABLE writer + BEST_EFFORT reader should match")
      (assert (endpoint-match-p w-rel r-rel) () "(b) RELIABLE writer + RELIABLE reader should match")
      (assert (not (endpoint-match-p w-be r-rel)) () "(c) BEST_EFFORT writer + RELIABLE reader must not match")
      (assert (not (endpoint-match-p w-rel r-topic)) () "(d) different topic-name must not match")
      (assert (not (endpoint-match-p w-vol r-tl)) () "(e) VOLATILE writer + TRANSIENT_LOCAL reader must not match (durability RxO)")
      (assert (endpoint-match-p r-tl w-vol) () "(f) TRANSIENT_LOCAL writer + VOLATILE reader should match")))
  t)
