(in-package #:dds.rtps.discovery)

;;;; SPDP discovery: Locator_t codec + SPDPdiscoveredParticipantData build/parse
;;;; (RTPS 2.5 §8.5.3 / §9.6.2). Wire constants read from docs/specs/rtps-2_5.pdf
;;;; (clauses cited inline), never memorized. CLOS-free: defstruct + monomorphic
;;;; functions; every parser bounds-checks before trusting wire data.

;; LOCATOR_KIND_UDPv4 = 1 (RTPS 2.5 §9.3.2.1 IDL / §9.3.2.4).
(defconstant +locator-kind-udpv4+ 1)

;; Locator_t = {long kind; unsigned long port; octet address[16];} = 24 octets (§9.3.2.1).
(defconstant +locator-bytes+ 24)

(declaim (ftype (function (dds.core.buffer:cursor (integer 0) (unsigned-byte 32) (simple-array (unsigned-byte 8) (16))) fixnum) write-locator))
(defun write-locator (cursor kind port address)
  "Write a 24-octet Locator_t: kind (i32) + port (u32) in cursor endianness, then
   16 raw address octets (RTPS 2.5 §9.3.2.1 / §9.4.2.18)."
  (dds.core.buffer:put-u32 cursor (logand kind #xFFFFFFFF))
  (dds.core.buffer:put-u32 cursor (logand port #xFFFFFFFF))
  (dds.core.buffer:put-octets cursor address 0 16)
  (dds.core.buffer:cursor-position cursor))

(declaim (ftype (function (dds.core.buffer:cursor) t) read-locator))
(defun read-locator (cursor)
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

(declaim (ftype (function ((simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (16))) make-ipv4-locator))
(defun make-ipv4-locator (ip)
  "Build a 16-octet Locator address from a 4-octet IPv4 vector: 12 leading zeros
   then a.b.c.d at [12..15] (RTPS 2.5 §9.3.2.4)."
  (assert (= 4 (length ip)))
  (let ((address (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace address ip :start1 12 :end1 16 :start2 0 :end2 4)
    address))

;;; ---- SPDPdiscoveredParticipantData (RTPS 2.5 §8.5.3.2 / §9.6.2.2). A subset of
;;; the ParticipantBuiltinTopicData carried as a ParameterList in the SPDP DATA. ----

(defstruct (spdp-data (:constructor make-spdp-data))
  (guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)
               :type (simple-array (unsigned-byte 8) (12)))
  (version-major 2 :type (unsigned-byte 8))
  (version-minor 5 :type (unsigned-byte 8))
  (vendor-id 0 :type (unsigned-byte 16))
  (default-unicast-kind +locator-kind-udpv4+ :type (integer 0))
  (default-unicast-port 0 :type (unsigned-byte 32))
  (default-unicast-address (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
                           :type (simple-array (unsigned-byte 8) (16)))
  (metatraffic-unicast-kind +locator-kind-udpv4+ :type (integer 0))
  (metatraffic-unicast-port 0 :type (unsigned-byte 32))
  (metatraffic-unicast-address (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)
                               :type (simple-array (unsigned-byte 8) (16)))
  (lease-duration-seconds 100 :type (signed-byte 32))
  (builtin-endpoint-set 0 :type (unsigned-byte 32)))

(declaim (ftype (function ((integer 0)) (values dds.core.buffer:cursor (simple-array (unsigned-byte 8) (*)))) %make-scratch))
(defun %make-scratch (n)
  "A scratch octet buffer of N octets and a cursor over it (LE), for building one
   Parameter value at a time before handing it to WRITE-PARAMETER."
  (let* ((ob (dds.core.buffer:make-octet-buffer n))
         (cur (dds.core.buffer:cursor ob :endianness :little)))
    (values cur (dds.core.buffer:octet-buffer-vec ob))))

(declaim (ftype (function (dds.core.buffer:cursor spdp-data) fixnum) serialize-spdp-data))
(defun serialize-spdp-data (cursor data)
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
  ;; PID_DEFAULT_UNICAST_LOCATOR: Locator_t (24 octets) (§9.3.2.1 / §9.6.2.2).
  (multiple-value-bind (c vec) (%make-scratch +locator-bytes+)
    (write-locator c (spdp-data-default-unicast-kind data)
                   (spdp-data-default-unicast-port data)
                   (spdp-data-default-unicast-address data))
    (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-default-unicast-locator+
                                      vec 0 +locator-bytes+))
  ;; PID_METATRAFFIC_UNICAST_LOCATOR: Locator_t (24 octets) (§9.6.2.2).
  (multiple-value-bind (c vec) (%make-scratch +locator-bytes+)
    (write-locator c (spdp-data-metatraffic-unicast-kind data)
                   (spdp-data-metatraffic-unicast-port data)
                   (spdp-data-metatraffic-unicast-address data))
    (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-metatraffic-unicast-locator+
                                      vec 0 +locator-bytes+))
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

(declaim (ftype (function (spdp-data (unsigned-byte 16) dds.core.buffer:cursor (integer 0)) t) %fill-spdp-param))
(defun %fill-spdp-param (data pid cursor len)
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
           (setf (spdp-data-default-unicast-kind data) (logand k #xFFFFFFFF))
           (setf (spdp-data-default-unicast-port data) p)
           (setf (spdp-data-default-unicast-address data) a)))))
    ((= pid dds.rtps.message:+pid-metatraffic-unicast-locator+)
     (when (>= len +locator-bytes+)
       (multiple-value-bind (k p a) (read-locator cursor)
         (when k
           (setf (spdp-data-metatraffic-unicast-kind data) (logand k #xFFFFFFFF))
           (setf (spdp-data-metatraffic-unicast-port data) p)
           (setf (spdp-data-metatraffic-unicast-address data) a)))))
    ((= pid dds.rtps.message:+pid-participant-lease-duration+)
     (when (>= len 8)
       (let ((su (dds.core.buffer:get-u32 cursor)))
         (setf (spdp-data-lease-duration-seconds data)
               (if (>= su #x80000000) (- su #x100000000) su)))))
    ((= pid dds.rtps.message:+pid-builtin-endpoint-set+)
     (when (>= len 4)
       (setf (spdp-data-builtin-endpoint-set data) (dds.core.buffer:get-u32 cursor)))))
  data)

(declaim (ftype (function (dds.core.buffer:cursor) t) parse-spdp-data))
(defun parse-spdp-data (cursor)
  "Parse an SPDP ParameterList into an SPDP-DATA struct, or NIL if the list is
   truncated (RTPS 2.5 §8.5.3.2 / §9.4.2.11). Bounds-checked via PARSE-PARAMETER-LIST."
  (let ((data (make-spdp-data)))
    (if (dds.rtps.message:parse-parameter-list
         cursor (lambda (pid c len) (%fill-spdp-param data pid c len)))
        data
        nil)))

;;; ---- Standalone round-trip + byte-exact test (no external test framework) ----

(declaim (ftype (function () (simple-array (unsigned-byte 8) (4))) %ip-127-0-0-1))
(defun %ip-127-0-0-1 ()
  "The IPv4 vector 127.0.0.1."
  (make-array 4 :element-type '(unsigned-byte 8) :initial-contents '(127 0 0 1)))

(declaim (ftype (function () t) %check-locator-bytes))
(defun %check-locator-bytes ()
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

(declaim (ftype (function () (values t t)) run-discovery-test))
(defun run-discovery-test ()
  "Build SPDP data, serialize, parse back, and assert every field round-trips;
   also byte-exact-check the Locator encoding. Returns T on success (ASSERT
   signals otherwise)."
  (%check-locator-bytes)
  (let* ((prefix (make-array 12 :element-type '(unsigned-byte 8)
                             :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12)))
         (du-addr (make-ipv4-locator (make-array 4 :element-type '(unsigned-byte 8)
                                                 :initial-contents '(192 168 1 50))))
         (mt-addr (make-ipv4-locator (%ip-127-0-0-1)))
         (data (make-spdp-data :guid-prefix prefix
                               :version-major 2 :version-minor 5
                               :vendor-id #x010F
                               :default-unicast-kind +locator-kind-udpv4+
                               :default-unicast-port 7411
                               :default-unicast-address du-addr
                               :metatraffic-unicast-kind +locator-kind-udpv4+
                               :metatraffic-unicast-port 7410
                               :metatraffic-unicast-address mt-addr
                               :lease-duration-seconds 30
                               :builtin-endpoint-set #x0000043F))
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
      (assert (= (spdp-data-default-unicast-kind back) +locator-kind-udpv4+) () "default kind mismatch")
      (assert (= (spdp-data-default-unicast-port back) 7411) () "default port mismatch")
      (assert (equalp (spdp-data-default-unicast-address back) du-addr) () "default addr mismatch")
      (assert (= (spdp-data-metatraffic-unicast-kind back) +locator-kind-udpv4+) () "meta kind mismatch")
      (assert (= (spdp-data-metatraffic-unicast-port back) 7410) () "meta port mismatch")
      (assert (equalp (spdp-data-metatraffic-unicast-address back) mt-addr) () "meta addr mismatch")
      (assert (= (spdp-data-lease-duration-seconds back) 30) () "lease mismatch")
      (assert (= (spdp-data-builtin-endpoint-set back) #x0000043F) () "endpoint-set mismatch")
      (values t back))))
