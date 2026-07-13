(in-package #:dds.rtps.discovery)

;;;; SPDP discovery: Locator_t codec + SPDPdiscoveredParticipantData build/parse
;;;; (RTPS 2.5 §8.5.3 / §9.6.2). Wire constants read from docs/specs/rtps-2_5.pdf
;;;; (clauses cited inline), never memorized. CLOS-free: defstruct + monomorphic
;;;; functions; every parser bounds-checks before trusting wire data.

(defconstant +locator-kind-udpv4+ 1
  "LOCATOR_KIND_UDPv4 = 1 (RTPS 2.5 §9.3.2.1 IDL / §9.3.2.4).")

(defconstant +locator-kind-shmem+ #x47420001
  "Vendor SHMEM Locator_t kind (GB|1); ours-to-ours intra-host only. No standard RTPS SHMEM kind exists;
   cross-vendor peers ignore an unknown kind (fail-open). Pinned in ADR 0013, not from any spec clause.")

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

;; DDS-Security 1.1 §7.4.3 secure builtin EntityIds: PSM = ParticipantStatelessMessage (auth handshake).
;; entityKind 0xC3 = WRITER_NO_KEY (best-effort); 0xC4 = READER_NO_KEY (best-effort).
;; PSM is best-effort — no HEARTBEAT/ACKNACK (DDS-Security 1.1 §7.4.3).
(defconstant +entityid-participant-stateless-writer+ #x000201c3
  "ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_WRITER {{00,02,01},c3} (DDS-Security 1.1 §7.4.3).")
(defconstant +entityid-participant-stateless-reader+ #x000201c4
  "ENTITYID_P2P_BUILTIN_PARTICIPANT_STATELESS_READER {{00,02,01},c4} (DDS-Security 1.1 §7.4.3).")

;; DDS-Security 1.1 §7.4.5 secure volatile message EntityIds (ParticipantVolatileMessageSecure).
;; 0xff entity-key prefix = vendor/security-scoped; 0xC3/C4 = best-effort NO_KEY writer/reader.
(defconstant +entityid-participant-volatile-secure-writer+ #xff0202c3
  "ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER (DDS-Security 1.1 §7.4.5).")
(defconstant +entityid-participant-volatile-secure-reader+ #xff0202c4
  "ENTITYID_P2P_BUILTIN_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER (DDS-Security 1.1 §7.4.5).")

;; DDS-Security 1.1 §7.4.5 secure builtin endpoint EntityIds (WP-DDS-SECURITY-SECURE-DISCOVERY T0).
;; 0xff entity-key prefix = security-scoped; 0xc2/c7 = reliable BUILTIN_WRITER/READER (WITH_KEY).
;; Corroboration: Fast DDS include/fastdds/rtps/common/EntityId_t.hpp lines 55-64 (#if HAVE_SECURITY);
;; Wireshark packet-rtps.c ENTITYID_*_SECURE_* (vendor-neutral, tshark 4.6.6). Spike 2026-06-27.
(defconstant +entityid-sedp-pub-secure-writer+ #xff0003c2
  "SEDPbuiltinPublicationsSecureWriter EntityId 0xff0003c2 (DDS-Security 1.1 §7.4.5; Fast DDS EntityId_t.hpp).")
(defconstant +entityid-sedp-pub-secure-reader+ #xff0003c7
  "SEDPbuiltinPublicationsSecureReader EntityId 0xff0003c7 (DDS-Security 1.1 §7.4.5; Fast DDS EntityId_t.hpp).")
(defconstant +entityid-sedp-sub-secure-writer+ #xff0004c2
  "SEDPbuiltinSubscriptionsSecureWriter EntityId 0xff0004c2 (DDS-Security 1.1 §7.4.5; Fast DDS EntityId_t.hpp).")
(defconstant +entityid-sedp-sub-secure-reader+ #xff0004c7
  "SEDPbuiltinSubscriptionsSecureReader EntityId 0xff0004c7 (DDS-Security 1.1 §7.4.5; Fast DDS EntityId_t.hpp).")
(defconstant +entityid-participant-message-secure-writer+ #xff0200c2
  "BuiltinParticipantMessageSecureWriter EntityId 0xff0200c2 (DDS-Security 1.1 §7.4.5; Fast DDS EntityId_t.hpp).")
(defconstant +entityid-participant-message-secure-reader+ #xff0200c7
  "BuiltinParticipantMessageSecureReader EntityId 0xff0200c7 (DDS-Security 1.1 §7.4.5; Fast DDS EntityId_t.hpp).")
(defconstant +entityid-spdp-secure-writer+ #xff0101c2
  "SPDPbuiltinParticipantSecureWriter EntityId 0xff0101c2 (DDS-Security 1.1 §7.4.5; Fast DDS EntityId_t.hpp).")
(defconstant +entityid-spdp-secure-reader+ #xff0101c7
  "SPDPbuiltinParticipantSecureReader EntityId 0xff0101c7 (DDS-Security 1.1 §7.4.5; Fast DDS EntityId_t.hpp).")

(defun* builtin-complementary-eid (eid)
    (function ((unsigned-byte 32)) (unsigned-byte 32))
  "The complementary builtin EntityId of EID — its matched writer<->reader pair — by flipping ONLY the low
   EntityKind octet between the with-key builtin WRITER kind 0xC2 and READER kind 0xC7 (RTPS 2.5 §9.3.1.2:
   EntityId_t's last octet is the EntityKind, and the two builtin-with-key kinds differ ONLY in it; §9.3.2 builtin
   endpoint pairing). 0xC2 -> 0xC7, any other low byte -> 0xC2; the high 3 octets (the EntityKey identifying the
   builtin tier — secure SEDP 0xff0003/0xff0004, secure SPDP 0xff0101, secure PM 0xff0200) are preserved. Pure
   arithmetic — the CALLER gates which EntityIds are valid inputs. The SINGLE shared source for the 0xC2<->0xC7
   pairing (was open-coded in dds.disc secure-sedp + dds.dcps crypto-manager thrice; ADR-0037 carry 1 DRY)."
  (logior (logand eid #xffffff00)
          (if (= (logand eid #xff) #xc2) #xc7 #xc2)))

(defun* secure-builtin-writer-eid-p (eid)
    (function ((unsigned-byte 32)) boolean)
  "T iff EID is one of the four secure-BUILTIN WRITER EntityIds (DDS-Security 1.1 §7.4.5): secure-SEDP
   publications 0xff0003c2 / subscriptions 0xff0004c2, secure participant-message 0xff0200c2, secure SPDP
   0xff0101c2. The shared gate for the origin-auth secure-builtin writer->reader pairing (with
   builtin-complementary-eid); NIL for any other EntityId (fail-closed — a HEARTBEAT/DATA for an unrecognized
   writer is dropped). The SINGLE shared source (was open-coded in dds.disc secure-sedp + dds.dcps crypto-manager)."
  (and (or (= eid +entityid-sedp-pub-secure-writer+)
           (= eid +entityid-sedp-sub-secure-writer+)
           (= eid +entityid-participant-message-secure-writer+)
           (= eid +entityid-spdp-secure-writer+))
       t))

;; DDS-Security 1.1 §7.4.6.1 BuiltinEndpointSet security bits (secure SEDP, secure PMD, PSM, PVMS).
;; Bits 16-19: secure SEDP pub/sub announcer/detector; 20-21: secure PMD writer/reader.
(defconstant +be-sedp-pub-secure-writer+ (ash 1 16)
  "DISC_BUILTIN_ENDPOINT_PUBLICATION_SECURE_ANNOUNCER bit 16 (DDS-Security 1.1 §7.4.6.1).")
(defconstant +be-sedp-pub-secure-reader+ (ash 1 17)
  "DISC_BUILTIN_ENDPOINT_PUBLICATION_SECURE_DETECTOR bit 17 (DDS-Security 1.1 §7.4.6.1).")
(defconstant +be-sedp-sub-secure-writer+ (ash 1 18)
  "DISC_BUILTIN_ENDPOINT_SUBSCRIPTION_SECURE_ANNOUNCER bit 18 (DDS-Security 1.1 §7.4.6.1).")
(defconstant +be-sedp-sub-secure-reader+ (ash 1 19)
  "DISC_BUILTIN_ENDPOINT_SUBSCRIPTION_SECURE_DETECTOR bit 19 (DDS-Security 1.1 §7.4.6.1).")
(defconstant +be-participant-message-secure-writer+ (ash 1 20)
  "BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_SECURE_DATA_WRITER bit 20 (DDS-Security 1.1 §7.4.6.1).")
(defconstant +be-participant-message-secure-reader+ (ash 1 21)
  "BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_SECURE_DATA_READER bit 21 (DDS-Security 1.1 §7.4.6.1).")
;; Bits 22-23: PSM writer/reader (authentication handshake, this slice).
(defconstant +be-participant-stateless-writer+ (ash 1 22)
  "BUILTIN_ENDPOINT_PARTICIPANT_STATELESS_MESSAGE_WRITER bit 22 (DDS-Security 1.1 §7.4.6.1).")
(defconstant +be-participant-stateless-reader+ (ash 1 23)
  "BUILTIN_ENDPOINT_PARTICIPANT_STATELESS_MESSAGE_READER bit 23 (DDS-Security 1.1 §7.4.6.1).")
;; Bits 24-25: PVMS (crypto key exchange, future slice).
(defconstant +be-participant-volatile-secure-writer+ (ash 1 24)
  "BUILTIN_ENDPOINT_PARTICIPANT_VOLATILE_MESSAGE_SECURE_WRITER bit 24 (DDS-Security 1.1 §7.4.6.1).")
(defconstant +be-participant-volatile-secure-reader+ (ash 1 25)
  "BUILTIN_ENDPOINT_PARTICIPANT_VOLATILE_MESSAGE_SECURE_READER bit 25 (DDS-Security 1.1 §7.4.6.1).")
;; Bits 26-27: secure SPDP announcer/detector (required when security is enabled).
(defconstant +be-participant-secure-announcer+ (ash 1 26)
  "DISC_BUILTIN_ENDPOINT_PARTICIPANT_SECURE_ANNOUNCER bit 26 (DDS-Security 1.1 §7.4.6.1).")
(defconstant +be-participant-secure-detector+ (ash 1 27)
  "DISC_BUILTIN_ENDPOINT_PARTICIPANT_SECURE_DETECTOR bit 27 (DDS-Security 1.1 §7.4.6.1).")

;; PID_IDENTITY_TOKEN: carries the IdentityToken DataHolder in the SPDP ParameterList.
;; Serialized as CDR-LE DataHolder: class_id + PropertySeq + BinaryPropertySeq (DDS-Security 1.1 §7.4.3.2).
(defconstant +pid-identity-token+ #x1001
  "PID_IDENTITY_TOKEN = 0x1001; SPDP ParameterList entry for IdentityToken (DDS-Security 1.1 §7.4.3.2).")
;; PID_PERMISSIONS_TOKEN: carries PermissionsToken; AccessControl / Slice-3 only.
(defconstant +pid-permissions-token+ #x1002
  "PID_PERMISSIONS_TOKEN = 0x1002; SPDP ParameterList entry for PermissionsToken (DDS-Security 1.1 §7.4.3.2).")
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

(defun* make-shmem-locator-wire (lane-count capacity)
    (function ((integer 1) (integer 8)) locator)
  "Build a SHMEM Locator_t: kind=+locator-kind-shmem+, port=CAPACITY, address[0..3]=LANE-COUNT (u32 LE)."
  (let ((a (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref a 0) (ldb (byte 8 0) lane-count) (aref a 1) (ldb (byte 8 8) lane-count)
          (aref a 2) (ldb (byte 8 16) lane-count) (aref a 3) (ldb (byte 8 24) lane-count))
    (make-locator :kind +locator-kind-shmem+ :port capacity :address a)))

(defun* shmem-locator-wire-lane-count (loc)
    (function (locator) (unsigned-byte 32))
  "Extract the lane-count from a SHMEM Locator_t's address (u32 LE in octets 0..3)."
  (let ((a (locator-address loc)))
    (logior (aref a 0) (ash (aref a 1) 8) (ash (aref a 2) 16) (ash (aref a 3) 24))))

(defun* locator-unspecified-ipv4-p (loc)
    (function (locator) t)
  "T iff LOC's IPv4 address is the unspecified address 0.0.0.0 — i.e. address octets 12..15 are all
   zero (RTPS 2.5 §9.3.2.4: Locator_t carries a 16-octet address with the IPv4 in the low 4 octets).
   Tested on the OCTETS: the dotted-quad is a rendering of this address, never its identity."
  (let ((a (locator-address loc)))
    (and (zerop (aref a 12)) (zerop (aref a 13)) (zerop (aref a 14)) (zerop (aref a 15)))))

(defun* locator-usable-udpv4-p (loc)
    (function (locator) t)
  "T iff LOC is a UDPv4 locator with a routable (non-0.0.0.0) address."
  (and (= (locator-kind loc) +locator-kind-udpv4+)
       (not (locator-unspecified-ipv4-p loc))))

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
   lease duration, and the builtin-endpoint set.

   USER-DEST is not wire data: it is an NFR-MEM memo of the user-plane (host . port) resolved from the
   locator lists above (see DDS.DISC::%USABLE-DESTINATION), cached here so the per-sample send path stops
   re-resolving it. :UNRESOLVED = not yet computed, NIL = no usable destination, a CONS = the destination.
   Because a re-announce parses a FRESH spdp-data, the memo cannot outlive the record it describes."
  (guid-prefix (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0)
               :type (simple-array (unsigned-byte 8) (12)))
  (version-major 2 :type (unsigned-byte 8))
  (version-minor 5 :type (unsigned-byte 8))
  (vendor-id 0 :type (unsigned-byte 16))
  (default-unicast-locators '() :type list)       ; list of LOCATOR (user traffic)
  (metatraffic-unicast-locators '() :type list)   ; list of LOCATOR (discovery)
  (lease-duration-seconds 100 :type (signed-byte 32))
  (lease-duration-nanosec 0 :type (integer 0))   ; the leaseDuration Duration_t FRACTION field (§9.3.2.3), carried as nanosec
  (builtin-endpoint-set 0 :type (unsigned-byte 32))
  ;; PID_SHMEM_HOST_UUID (vendor 0x8040, ADR 0013): 8-octet same-host UUID; 0 = none/absent.
  (host-uuid 0 :type (unsigned-byte 64))
  ;; PID_IDENTITY_TOKEN (0x1001, DDS-Security 1.1 §7.4.3.2): CDR-LE DataHolder octets; NIL = security OFF.
  (identity-token-octets nil :type (or null (simple-array (unsigned-byte 8) (*))))
  ;; NFR-MEM memo of the resolved user-plane (host . port) — a PURE function of the locator lists above,
  ;; so it is cached HERE rather than on the node: a re-announce parses a FRESH spdp-data, which carries a
  ;; fresh (:unresolved) memo, so the cache cannot go stale. :UNRESOLVED = not yet computed; NIL = computed,
  ;; no usable destination; a CONS = the destination. Resolved by DDS.DISC::%USABLE-DESTINATION.
  (user-dest :unresolved :type t))

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
    (dds.core.buffer:put-u32 c (dds.qos:duration-nanosec->wire-fraction   ; sub-second lease: sec/2^32 fraction, NOT a hardcoded 0
                                (spdp-data-lease-duration-nanosec data)))
    (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-participant-lease-duration+ vec 0 8))
  ;; PID_BUILTIN_ENDPOINT_SET: BuiltinEndpointSet_t (u32) (§9.3.2.1 / §9.6.2.2).
  (multiple-value-bind (c vec) (%make-scratch 4)
    (dds.core.buffer:put-u32 c (spdp-data-builtin-endpoint-set data))
    (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-builtin-endpoint-set+ vec 0 4))
  ;; PID_SHMEM_HOST_UUID (vendor 0x8040, ADR 0013): 8-octet same-host UUID (u64 LE); only when set.
  (when (plusp (spdp-data-host-uuid data))
    (multiple-value-bind (c vec) (%make-scratch 8)
      (dds.core.buffer:put-u32 c (ldb (byte 32 0) (spdp-data-host-uuid data)))
      (dds.core.buffer:put-u32 c (ldb (byte 32 32) (spdp-data-host-uuid data)))
      (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-shmem-host-uuid+ vec 0 8)))
  ;; PID_IDENTITY_TOKEN (0x1001, §7.4.3.2): CDR-LE DataHolder; omitted when NIL (security OFF).
  (let ((tok (spdp-data-identity-token-octets data)))
    (when tok
      (dds.rtps.message:write-parameter cursor +pid-identity-token+ tok 0 (length tok))))
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
       (let ((su (dds.core.buffer:get-u32 cursor))
             (fr (dds.core.buffer:get-u32 cursor)))   ; the FRACTION must be read: dropping it truncates a sub-second lease to 0 = an instant false-prune
         (setf (spdp-data-lease-duration-seconds data)
               (if (>= su #x80000000) (- su #x100000000) su))
         (setf (spdp-data-lease-duration-nanosec data)
               (dds.qos:wire-fraction->duration-nanosec fr)))))
    ((= pid dds.rtps.message:+pid-builtin-endpoint-set+)
     (when (>= len 4)
       (setf (spdp-data-builtin-endpoint-set data) (dds.core.buffer:get-u32 cursor))))
    ((= pid dds.rtps.message:+pid-shmem-host-uuid+)
     (when (>= len 8)                                ; fail-open: a short value is ignored, never an error
       (let ((lo (dds.core.buffer:get-u32 cursor)) (hi (dds.core.buffer:get-u32 cursor)))
         (setf (spdp-data-host-uuid data) (logior lo (ash hi 32))))))
    ((= pid +pid-identity-token+)
     ;; Bounds-checked before allocation: len MUST fit remaining buffer (§9.4.2.11, NFR-SEC-POSTURE).
     (let ((remaining (- (dds.core.buffer:octet-buffer-capacity (dds.core.buffer:cursor-buffer cursor))
                         (dds.core.buffer:cursor-position cursor))))
       (when (and (> len 0) (<= len remaining))
         (let ((oct (make-array len :element-type '(unsigned-byte 8))))
           (dds.core.buffer:get-octets cursor oct 0 len)
           (setf (spdp-data-identity-token-octets data) oct))))))
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
                                 :lease-duration-seconds 30 :lease-duration-nanosec 500000000
                                 :builtin-endpoint-set +builtin-endpoint-set-default+))
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
        ;; §9.3.2.3 Duration_t: the FRACTION must survive the round trip (a dropped fraction reads a
        ;; sub-second lease as 0 -> a live peer is pruned on the next sweep).
        (assert (= (spdp-data-lease-duration-nanosec back) 500000000) () "lease fraction mismatch")
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
(defun* %data-rep-wire (k)
    (function (symbol) (unsigned-byte 16))
  "Map a DATA_REPRESENTATION keyword to its DataRepresentationId_t short (DDS-XTypes 1.3 §7.6.3.1.1:
   XCDR_DATA_REPRESENTATION=0, XML_DATA_REPRESENTATION=1, XCDR2_DATA_REPRESENTATION=2). NOT the 16-bit
   RTPS encapsulation id (cdr.lisp +representation-ids+) — a distinct namespace." (ecase k (:xcdr1 0) (:xml 1) (:xcdr2 2)))
(defun* %wire-data-rep (n)
    (function ((unsigned-byte 16)) symbol)
  "Map a DataRepresentationId_t short to a DATA_REPRESENTATION keyword (DDS-XTypes 1.3 §7.6.3.1.1:
   0->:xcdr1, 1->:xml, 2->:xcdr2); an unknown id -> NIL so the SEDP parse drops it fail-open (FR-QOS-2)." (case n (0 :xcdr1) (1 :xml) (2 :xcdr2) (t nil)))

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
  (type-object-lb nil :type (or null (simple-array (unsigned-byte 8) (*))))
  ;; WP-ZEROCOPY (FR-PF-3, ADR 0014): T iff this endpoint advertised PID_ZEROCOPY_CAPABLE — it
  ;; understands a 16-byte zero-copy reference in place of the SerializedPayload. Fail-open: an
  ;; absent/garbage PID parses NIL, so a non-ZC / cross-vendor peer simply gets normal DATA. NOT
  ;; cleared for ship — pending counsel (R6).
  (zerocopy-capable nil :type boolean)
  ;; PID_ENTITY_VIRTUAL_GUID (0x8002, RTI vendor): 16-byte GUID of the original writer this relay
  ;; endpoint represents. Emitted in SEDP by a Persistence Service relay writer; triggers Connext
  ;; receiver-side PID_ORIGINAL_WRITER_INFO dedup. NIL when absent (non-relay endpoints). When set,
  ;; PID_SERVICE_KIND (0x8003) = PERSISTENCE_SERVICE is also emitted (ADR 0024 Task 8 / spike 2026-06-18).
  (entity-virtual-guid nil :type (or null (simple-array (unsigned-byte 8) (16))))
  ;; PID_SERVICE_KIND (0x8003, RTI vendor): u32 service role code; 0 = absent/not-a-service (default),
  ;; +service-kind-persistence+ (1) = Persistence Service. Emitted only when non-zero.
  (service-kind 0 :type (unsigned-byte 32)))

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
  ;; PID_DATA_REPRESENTATION (0x0073): DataRepresentationQosPolicy{sequence<short> value} = u32 count +
  ;; count*short, padded to 4 (DDS-XTypes 1.3 §7.6.3.1.1). Emitted for BOTH roles (each advertises its
  ;; own accepted/offered list); the value is 4-byte aligned so WRITE-PARAMETER adds no further padding.
  (let* ((reps (dds.qos:qos-data-representation (endpoint-data-qos data)))
         (n (length reps))
         (val-len (* 4 (ceiling (+ 4 (* 2 n)) 4))))
    (multiple-value-bind (c vec) (%make-scratch val-len)
      (dds.core.buffer:put-u32 c n)
      (dolist (r reps) (dds.core.buffer:put-u16 c (%data-rep-wire r)))
      (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-data-representation+ vec 0 val-len)))
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
  ;; PID_ZEROCOPY_CAPABLE (0x8041, vendor): a single octet 1 when this endpoint understands a
  ;; WP-ZEROCOPY reference (ADR 0014); elided otherwise (fail-open — peers skip an unknown PID).
  (when (endpoint-data-zerocopy-capable data)
    (multiple-value-bind (c vec) (%make-scratch 1)
      (dds.core.buffer:put-u8 c 1)
      (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-zerocopy-capable+ vec 0 1)))
  ;; PID_ENTITY_VIRTUAL_GUID (0x8002, RTI vendor): 16-byte GUID of original writer; triggers
  ;; Connext receiver-side PID_ORIGINAL_WRITER_INFO dedup (ADR 0024 Task 8, spike 2026-06-18).
  (let ((vg (endpoint-data-entity-virtual-guid data)))
    (when vg
      (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-entity-virtual-guid+ vg 0 16)))
  ;; PID_SERVICE_KIND (0x8003, RTI vendor): u32 LE role code; 1 = PERSISTENCE_SERVICE.
  ;; Emitted alongside PID_ENTITY_VIRTUAL_GUID; absent on non-relay endpoints (spike 2026-06-18).
  (let ((sk (endpoint-data-service-kind data)))
    (when (plusp sk)
      (multiple-value-bind (c vec) (%make-scratch 4)
        (dds.core.buffer:put-u32 c sk)
        (dds.rtps.message:write-parameter cursor dds.rtps.message:+pid-service-kind+ vec 0 4))))
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
    ((= pid dds.rtps.message:+pid-data-representation+)
     ;; DataRepresentationQosPolicy{sequence<short>} (XTypes 1.3 §7.6.3.1.1). Bounds-check the count
     ;; against LEN before any short read (NFR-SEC-POSTURE: a forged count must not over-read — skip
     ;; the PID, never error the SEDP). Unknown ids drop (fail-open). Absent PID leaves the role default.
     (when (>= len 4)
       (let ((count (dds.core.buffer:get-u32 cursor)))
         (when (<= (+ 4 (* 2 count)) len)
           (let ((reps '()))
             (dotimes (i count)
               (let ((kw (%wire-data-rep (dds.core.buffer:get-u16 cursor))))
                 (when kw (push kw reps))))
             (when reps
               (setf (dds.qos:qos-data-representation (endpoint-data-qos data)) (nreverse reps))))))))
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
         (setf (endpoint-data-type-object-lb data) lb))))
    ((= pid dds.rtps.message:+pid-zerocopy-capable+)
     (when (>= len 1)   ; fail-open: a nonzero leading octet means ZC-capable (WP-ZEROCOPY, ADR 0014)
       (setf (endpoint-data-zerocopy-capable data) (plusp (dds.core.buffer:get-u8 cursor)))))
    ((= pid dds.rtps.message:+pid-entity-virtual-guid+)
     ;; PID_ENTITY_VIRTUAL_GUID (0x8002, RTI vendor): 16-byte GUID; fail-open on wrong length.
     (when (>= len 16)
       (let ((vg (make-array 16 :element-type '(unsigned-byte 8))))
         (dds.core.buffer:get-octets cursor vg 0 16)
         (setf (endpoint-data-entity-virtual-guid data) vg))))
    ((= pid dds.rtps.message:+pid-service-kind+)
     ;; PID_SERVICE_KIND (0x8003, RTI vendor): u32 LE role code; fail-open on wrong length.
     (when (>= len 4)
       (setf (endpoint-data-service-kind data) (dds.core.buffer:get-u32 cursor)))))
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
                                                          :durability :transient-local
                                                          :data-representation '(:xcdr2 :xcdr1))))
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
      ;; PID_DATA_REPRESENTATION round-trip: the ordered sequence<short> survives (XTypes 1.3 §7.6.3.1.1).
      (assert (equal (dds.qos:qos-data-representation (endpoint-data-qos back)) '(:xcdr2 :xcdr1)) ()
              "data-representation sequence round-trip mismatch")
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

(defun* run-data-representation-wire-test ()
    (function () t)
  "Byte-exact PID_DATA_REPRESENTATION (0x0073) emission vs the pinned DDS-XTypes 1.3 §7.6.3.1.1
   layout + the live RTI Connext capture (interop/data-representation/captures/NOTES.md): for
   data-representation (:xcdr2 :xcdr1) the parameter is 73 00 (pid) 08 00 (len) 02 00 00 00 (count 2)
   02 00 (XCDR2=2) 00 00 (XCDR1=0, = XCDR_DATA_REPRESENTATION, the live-Connext-confirmed value) — the
   bare conformant sequence<short>, 4-aligned, no padding, no RTI vendor trailing mask. Returns T on
   success (ASSERT signals otherwise)."
  (let* ((data (make-endpoint-data :topic-name "Square" :type-name "ShapeType"
                                   :qos (dds.qos:make-qos :data-representation '(:xcdr2 :xcdr1))))
         (ob (dds.core.buffer:make-octet-buffer 256))
         (wc (dds.core.buffer:cursor ob :endianness :little))
         (vec (dds.core.buffer:octet-buffer-vec ob))
         (expected #(#x73 #x00 #x08 #x00 #x02 #x00 #x00 #x00 #x02 #x00 #x00 #x00))
         (n (length expected)))
    (serialize-endpoint-data wc data)
    ;; Locate the 12-octet PID_DATA_REPRESENTATION parameter in the ParameterList by its pid+len marker.
    (let ((at (loop for i from 0 to (- (dds.core.buffer:cursor-position wc) n)
                    when (and (= (aref vec i) #x73) (= (aref vec (1+ i)) #x00)
                              (= (aref vec (+ i 2)) #x08) (= (aref vec (+ i 3)) #x00))
                      return i)))
      (assert at () "PID_DATA_REPRESENTATION (73 00 08 00) not found in the emitted ParameterList")
      (dotimes (k n)
        (assert (= (aref vec (+ at k)) (aref expected k)) ()
                "PID_DATA_REPRESENTATION byte ~d: got #x~2,'0x expected #x~2,'0x"
                k (aref vec (+ at k)) (aref expected k)))))
  t)

(defun* %forge-malformed-data-rep-paramlist (count value-bytes)
    (function ((unsigned-byte 32) list) dds.core.buffer:octet-buffer)
  "Hand-build a SEDP ParameterList whose PID_DATA_REPRESENTATION (0x0073) value carries
   a FORGED u32 COUNT followed by only VALUE-BYTES octets — a malformed sequence<short>
   (the count over-states the value extent). A trailing legit PID_TOPIC_NAME 'OK' + the
   sentinel follow, to prove the parser skips the bad PID and keeps parsing (NFR-SEC-POSTURE)."
  (let* ((dst (dds.core.buffer:make-octet-buffer 256))
         (out (dds.core.buffer:cursor dst :endianness :little))
         (val (make-array (+ 4 (length value-bytes)) :element-type '(unsigned-byte 8))))
    ;; value = u32 forged-count (LE) ++ the (too-few) short octets.
    (setf (aref val 0) (ldb (byte 8 0) count) (aref val 1) (ldb (byte 8 8) count)
          (aref val 2) (ldb (byte 8 16) count) (aref val 3) (ldb (byte 8 24) count))
    (loop for b in value-bytes for i from 4 do (setf (aref val i) b))
    (dds.rtps.message:write-parameter out dds.rtps.message:+pid-data-representation+
                                      val 0 (length val))
    (multiple-value-bind (c tv) (%make-scratch 8)
      (dds.cdr:cdr-put-string c "OK" :xcdr1)
      (dds.rtps.message:write-parameter out dds.rtps.message:+pid-topic-name+
                                        tv 0 (dds.core.buffer:cursor-position c)))
    (dds.rtps.message:write-parameter-sentinel out)
    dst))

(defun* %parse-endpoint-safety0 (buf)
    (function (dds.core.buffer:octet-buffer) t)
  "Parse an endpoint ParameterList from BUF in a wrapper compiled at (SAFETY 0): a malformed
   PID_DATA_REPRESENTATION must never cause an OOB array access even with this frame's bounds-
   checks elided (NFR-SEC-POSTURE — the parser's own explicit length gates must suffice)."
  (declare (optimize (speed 3) (safety 0) (debug 0)))
  (parse-endpoint-data (dds.core.buffer:cursor buf :endianness :little) :reader))

(defun* run-data-representation-malformed-test ()
    (function () t)
  "Malformed PID_DATA_REPRESENTATION bounds/fuzz (NFR-SEC-POSTURE; XTypes 1.3 §7.6.3.1.1):
   a forged in-value COUNT larger than the value extent, and a truncated value, MUST be
   skipped cleanly — the data-representation stays at the role default and a trailing legit
   PID (topic-name 'OK') still parses — with NO OOB even at (safety 0). Both the production
   parse and the (safety 0) twin must agree (reject == reject)."
  (let ((reader-default (dds.qos:qos-data-representation (dds.qos:make-reader-qos))))
   (flet ((default-rep-p (ep)
            ;; a skipped/malformed PID must leave the seeded reader-role default untouched (not corrupt it).
            (equal (dds.qos:qos-data-representation (endpoint-data-qos ep)) reader-default))
          (parsed-ok (ep)
            (and ep (string= (endpoint-data-topic-name ep) "OK"))))
    (dolist (case (list
                   ;; (label forged-count value-bytes): count >> the value extent (first case len==4, no shorts).
                   '(:over-count-no-shorts 9 ())
                   '(:over-count-one-short 5 (#x02 #x00))            ; says 5, only 1 short present
                   '(:over-count-truncated #xffffffff (#x00 #x00 #x00)))) ; huge count, odd truncated value
      (destructuring-bind (label count value-bytes) case
        (let* ((buf (%forge-malformed-data-rep-paramlist count value-bytes))
               (prod (parse-endpoint-data (dds.core.buffer:cursor buf :endianness :little) :reader))
               (s0 (%parse-endpoint-safety0 buf)))
          (assert (parsed-ok prod) () "[~a] production parse must skip the bad PID and still read PID_TOPIC_NAME" label)
          (assert (default-rep-p prod) () "[~a] a malformed PID_DATA_REPRESENTATION must leave the role default, not corrupt it" label)
          (assert (parsed-ok s0) () "[~a] (safety 0) parse must skip the bad PID and still read PID_TOPIC_NAME (no OOB)" label)
          (assert (default-rep-p s0) () "[~a] (safety 0) parse must leave the role default" label)
          (assert (equal (parsed-ok prod) (parsed-ok s0)) () "[~a] production and (safety 0) parse must agree" label))))))
  t)
