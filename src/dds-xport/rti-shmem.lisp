;;;; RTI Connext shared-memory segment recognition (ADR 0081 slice 3).
;;;;
;;;; Answers one question: is the peer that advertised this RTI shared-memory Locator_t running on OUR
;;;; machine? RTI's own published header states the test verbatim (transport_shmem.h:89-96) — attach to the
;;;; segment and compare the UUID in its header against the one in the received locator — so there is no
;;;; locator-only way to decide it. Everything here is READ-ONLY; nothing writes to an RTI segment.

(in-package #:net.goenninger.dds.xport.rti-shmem)

;;; Addressing. From RTI's published header transport_shmem.h: the fields are declared in the order
;;; segmentKey{Offset,Factor}, semaphoreKey{Offset,Factor}, mutexKey{Offset,Factor} (:50-66) and the
;;; default property initialiser supplies 0x400000,1, 0x800000,1, 0xB00000,1 (:194-199) — a 1:1 positional
;;; match. Confirmed against live `ipcs` output and by predicting the keys for six domains before starting
;;; a peer on each. All three factors default to 1, so the mapping is a plain offset plus the RTPS port.

(defconstant +rti-shmem-segment-key-base+ #x400000
  "Offset added to the RTPS port to form the System V key of an RTI Connext shared-memory SEGMENT
   (`segmentKeyOffset`, transport_shmem.h:51/:194; factor 1). ADR 0081 §4.")

(defconstant +rti-shmem-semaphore-key-base+ #x800000
  "Offset added to the RTPS port to form the System V key of an RTI Connext shared-memory SEMAPHORE
   (`semaphoreKeyOffset`, transport_shmem.h:57/:196; factor 1). ADR 0081 §4. Not used yet — recorded so the
   three keys stay together and cannot drift apart, which is how the wrong value entered the repo once.")

(defconstant +rti-shmem-mutex-key-base+ #xB00000
  "Offset added to the RTPS port to form the System V key of an RTI Connext shared-memory MUTEX
   (`mutexKeyOffset`, transport_shmem.h:63/:198; factor 1). ADR 0081 §4. Not used yet — see above.")

;;; Segment header. Measured by controlled variation against a live Connext 7.3.1 participant: a documented
;;; property was set to a distinctive value through Connext's own QoS and the segment diffed, so each offset
;;; below is identified by a chosen value appearing where predicted, not by reading a dump and guessing.
;;; Reproduce with interop/connext/shmem-layout/. Full table and confidence per field: ADR 0081 §5.

(defconstant +rti-shmem-off-magic+ #x10
  "Byte offset of the segment-header magic word. ADR 0081 §5.")

(defconstant +rti-shmem-off-protocol-major+ #x14
  "Byte offset of the shared-memory protocol major version. RTI's header names five revisions
   (`MAJOR_BEFORE_BUG_14240_FIX` .. `MAJOR_AFTER_ROBUST_PTHREAD_MUTEX`) and specifies none of them, so this
   field is the ONLY guard against misreading a layout we have not validated. ADR 0081 §5/§7.")

(defconstant +rti-shmem-off-uuid+ #x24
  "Byte offset of the segment's `shmemUUID` — the value RTI compares against a received locator's address to
   decide co-location. Proven byte-identical to the SPDP-advertised address of the same participant.")

(defconstant +rti-shmem-uuid-bytes+ 12
  "Significant octets of an RTI shared-memory address: 96 bits, matching the published
   `NDDS_TRANSPORT_SHMEM_ADDRESS_BIT_COUNT` of -96. The Locator_t's remaining 4 octets are zero.")

(defconstant +rti-shmem-header-bytes+ #x64
  "Bytes of segment header this module requires to be present, through the end of the property block at
   0x60. Passed to the attach as its minimum extent, so the kernel refuses a shorter segment outright.")

(defconstant +rti-shmem-header-magic+ #xCE444453
  "Segment-header magic word at +RTI-SHMEM-OFF-MAGIC+, read as a native 32-bit word (octets 53 44 44 CE).
   Observed invariant across every segment and every configuration measured. ADR 0081 §5.")

(defconstant +rti-shmem-protocol-major-validated+ 2
  "The ONE shared-memory protocol major version this layout was measured against — RTI's documented
   `NDDS_TRANSPORT_SHMEM_VERSION_MAJOR_DEFAULT`, i.e. `MAJOR_AFTER_BUG_14240_FIX`. A segment declaring any
   other version is REFUSED rather than parsed: the other revisions are named but unspecified, so reading
   one with these offsets would be a guess wearing the costume of a measurement (ADR 0081 §7).")

(defun* rti-shmem-segment-key (port)
    (function ((unsigned-byte 16)) (unsigned-byte 31))
  "The System V key of the RTI Connext shared-memory segment serving RTPS PORT."
  (+ +rti-shmem-segment-key-base+ port))

(defun* %rti-shmem-header-status (sap)
    (function (t) (or null keyword))
  "NIL if the header at SAP is an RTI segment of a protocol version this layout was measured against, else
   the refusal status. The single place both the co-location test and the property reader decide whether a
   segment may be interpreted at all — they must never diverge on that."
  (cond ((/= (dds.pal:load-sap-u32 sap +rti-shmem-off-magic+) +rti-shmem-header-magic+)
         :not-an-rti-shmem-segment)
        ((/= (dds.pal:load-sap-u32 sap +rti-shmem-off-protocol-major+)
             +rti-shmem-protocol-major-validated+)
         :unvalidated-shmem-protocol-version)
        (t nil)))

(defun* %rti-shmem-header-verdict (sap host-id)
    (function (t (simple-array (unsigned-byte 8) (12))) (values t (or null keyword)))
  "Verdict for an attached RTI segment header at SAP against the 12-octet HOST-ID from a locator.
   Returns (values T NIL) when the segment is an RTI segment of a validated protocol version whose
   `shmemUUID` matches, (values NIL NIL) when it is such a segment but the UUID differs — a well-formed
   'not this host' — and (values NIL status) when the segment is not one we may interpret.

   Split out from RTI-SHMEM-SAME-HOST-P so that function can attach, take a verdict, and DETACH on a single
   path: an early exit between attach and detach would leak the attachment."
  (let ((status (%rti-shmem-header-status sap)))
    (if status
        (values nil status)
        (values (dotimes (i +rti-shmem-uuid-bytes+ t)
                  (unless (= (dds.pal:load-sap-u8 sap (+ +rti-shmem-off-uuid+ i)) (aref host-id i))
                    (return nil)))
                nil))))

(defun* rti-shmem-same-host-p (host-id port)
    (function ((simple-array (unsigned-byte 8) (12)) (unsigned-byte 16)) (values t (or null keyword)))
  "T iff the RTI Connext peer that advertised HOST-ID at RTPS PORT is on THIS machine, by RTI's own
   published test: attach to the segment keyed 0x400000+PORT and compare the `shmemUUID` in its header
   against HOST-ID (transport_shmem.h:89-96).

   Returns (values T NIL) on a match; (values NIL NIL) when the segment exists and is well-formed but names
   a different host; and (values NIL status) when no verdict could be taken, with status
   :NO-SUCH-SEGMENT (nothing is listening on that key here — the ordinary answer for a peer on another
   machine), :NOT-AN-RTI-SHMEM-SEGMENT (the key is taken by something else), :UNVALIDATED-SHMEM-PROTOCOL-VERSION
   (an RTI segment of a revision this layout was not measured against), or :SHMAT-FAILED.

   A distinct status for 'no segment' versus 'different host' matters: the first is expected and routine,
   the second means two hosts disagree about an address that is supposed to identify a machine.

   The attachment is READ-ONLY and the segment is another process's memory, so it is untrusted input: the
   minimum extent is enforced by the kernel at attach (see DDS.PAL:SYSV-SHM-ATTACH-READONLY) and every
   offset read here is a compile-time constant below that extent."
  (multiple-value-bind (segment status)
      (dds.pal:sysv-shm-attach-readonly (rti-shmem-segment-key port) +rti-shmem-header-bytes+)
    (when status (bail status))
    (multiple-value-bind (same verdict-status)
        (%rti-shmem-header-verdict (dds.pal:sysv-shm-sap segment) host-id)
      (dds.pal:sysv-shm-detach segment)
      (values same verdict-status))))

;;; The property block. RTI's shipped API documentation states that a receiver's transport properties are
;;; embedded in its segment and that a SENDER verifies the receiver's properties are compatible before
;;; using it, so reading them is a prerequisite for ever writing into one. All three offsets below were
;;; identified by setting the corresponding documented QoS property to a distinctive value and observing it
;;; appear (ADR 0081 §5) — they are measured, not published.

(defconstant +rti-shmem-off-segment-size+ #x0c
  "Byte offset of the segment's own total size in octets. Proven: it matched `ipcs` segsz exactly in both
   measured configurations. Treated as a CLAIM and verified against the kernel, never trusted — see
   RTI-SHMEM-SEGMENT-PROPERTIES.")

(defconstant +rti-shmem-off-receive-buffer-size+ #x58
  "Byte offset of `receive_buffer_size`. Proven by variation: set 777216 through
   `dds.transport.shmem.builtin.receive_buffer_size`, read 777216.")

(defconstant +rti-shmem-off-message-size-max+ #x5c
  "Byte offset of `message_size_max` — the largest single message this receiver's segment can carry, and so
   the bound on any datagram we could hand it. Proven by variation: set 20480 through
   `dds.transport.shmem.builtin.parent.message_size_max`, read 20480.")

(defconstant +rti-shmem-off-received-message-count-max+ #x60
  "Byte offset of `received_message_count_max` — how many messages the receive queue holds. Proven by
   variation: set 37 through `dds.transport.shmem.builtin.received_message_count_max`, read 37.")

(defstruct* rti-shmem-properties
  "A Connext receiver's embedded shared-memory transport properties, as read from its segment. SEGMENT-SIZE
   is kernel-verified; the other three are the documented properties of the same name."
  (segment-size 0 :type (unsigned-byte 32))
  (receive-buffer-size 0 :type (unsigned-byte 32))
  (message-size-max 0 :type (unsigned-byte 32))
  (received-message-count-max 0 :type (unsigned-byte 32)))

(defun* %rti-shmem-properties-plausible-p (props)
    (function (rti-shmem-properties) t)
  "T iff PROPS are self-consistent against the segment's own kernel-verified size.

   ⚠️ THE BOUNDS ARE PHYSICAL, NOT POLICY. Each property is checked only against what the segment can
   physically hold — a buffer cannot be larger than the segment containing it — and never against an
   invented ceiling. That is deliberate: a peer may legitimately be configured with any
   `message_size_max` its segment accommodates, and REJECTING A CONFORMANT PEER is the worst failure class
   this project recognises. A physical bound cannot false-reject a real segment; a guessed policy bound can."
  (let ((size (rti-shmem-properties-segment-size props)))
    (and (plusp (rti-shmem-properties-message-size-max props))
         (plusp (rti-shmem-properties-received-message-count-max props))
         (plusp (rti-shmem-properties-receive-buffer-size props))
         (<= (rti-shmem-properties-receive-buffer-size props) size)
         (<= (rti-shmem-properties-message-size-max props) size)
         (<= (rti-shmem-properties-received-message-count-max props) size))))

(defun* rti-shmem-segment-properties (port)
    (function ((unsigned-byte 16)) (values (or null rti-shmem-properties) (or null keyword)))
  "Read the embedded transport properties of the RTI Connext receiver serving RTPS PORT.

   Returns (values properties NIL), or (values NIL status) with status :NO-SUCH-SEGMENT,
   :NOT-AN-RTI-SHMEM-SEGMENT, :UNVALIDATED-SHMEM-PROTOCOL-VERSION, :SHMAT-FAILED, or
   :IMPLAUSIBLE-SEGMENT-PROPERTIES when the block is not self-consistent with the segment holding it.

   ⚠️ THE SEGMENT'S CLAIMED SIZE IS VERIFIED, NOT BELIEVED. The size at `+rti-shmem-off-segment-size+` is a
   number written by another process, so it is re-attached at that size and the KERNEL decides: `shmget`
   refuses a request larger than the segment, so a segment overstating its own extent fails here instead of
   becoming a bound that later sizes a buffer. Same mechanism as the header extent check, used again —
   every length taken off this segment is corroborated by something outside it before being trusted."
  (multiple-value-bind (segment status)
      (dds.pal:sysv-shm-attach-readonly (rti-shmem-segment-key port) +rti-shmem-header-bytes+)
    (when status (bail status))
    (let* ((sap (dds.pal:sysv-shm-sap segment))
           (header-status (%rti-shmem-header-status sap))
           (props (unless header-status
                    (make-rti-shmem-properties
                     :segment-size (dds.pal:load-sap-u32 sap +rti-shmem-off-segment-size+)
                     :receive-buffer-size (dds.pal:load-sap-u32 sap +rti-shmem-off-receive-buffer-size+)
                     :message-size-max (dds.pal:load-sap-u32 sap +rti-shmem-off-message-size-max+)
                     :received-message-count-max
                     (dds.pal:load-sap-u32 sap +rti-shmem-off-received-message-count-max+)))))
      (dds.pal:sysv-shm-detach segment)
      (when header-status (bail header-status))
      ;; Corroborate the claimed extent with the kernel before any of it is believed.
      (multiple-value-bind (whole vstatus)
          (dds.pal:sysv-shm-attach-readonly (rti-shmem-segment-key port)
                                            (max 1 (rti-shmem-properties-segment-size props)))
        (when vstatus (bail :implausible-segment-properties))
        (dds.pal:sysv-shm-detach whole))
      (unless (%rti-shmem-properties-plausible-p props) (bail :implausible-segment-properties))
      (values props nil))))

(defun* rti-shmem-datagram-fits-p (props bytes)
    (function (rti-shmem-properties (integer 0)) t)
  "T iff a BYTES-octet datagram is within what this receiver's segment can carry in one message.

   `message_size_max` is the documented maximum message size of RTI's shared-memory transport, so a larger
   datagram cannot be delivered through it whatever the framing turns out to be. This is the shared-memory
   analogue of the emitted-datagram-size contract ADR 0079 established for UDP: the size a peer will accept
   is a property of the peer, to be read rather than assumed."
  (<= bytes (rti-shmem-properties-message-size-max props)))

;;; Ring addressing (ADR 0081 §5.0). The cursor in a control block is a CUMULATIVE BYTE COUNT, not an
;;; offset — it exceeds the segment once enough has been written — so a record's location must be derived
;;; from it. Every constant below was measured, and each coefficient was established by varying ONE
;;; parameter alone from a common baseline rather than fitting a curve through convenient points; an
;;; earlier revision that fitted instead of varying got the modulus wrong. Reproduce with
;;; interop/connext/shmem-layout/ring-extent.sh.

(defconstant +rti-shmem-ring-start-base+ 240
  "Constant term of an RTI shared-memory ring's start offset. Measured: ring start is
   `+rti-shmem-ring-start-base+ + 8 * received_message_count_max`, which is also the value at `0x50` plus
   64. Confirmed at count 8 (304) and count 16 (368). ADR 0081 §5.0.")

(defconstant +rti-shmem-ring-entry-stride+ 8
  "Bytes of ring start, and of ring modulus, contributed per unit of `received_message_count_max`. Measured
   by varying `count` alone: 8 → 16 moved ring start by 64 and the modulus by 64. ADR 0081 §5.0.")

(defconstant +rti-shmem-ring-modulus-bias+ -64
  "Additive bias of an RTI shared-memory ring's modulus:
   `receive_buffer_size + message_size_max + 8 * count - 64`. Each coefficient was measured by varying that
   one parameter alone from a common baseline — count, then `receive_buffer_size`, then `message_size_max`.
   ADR 0081 §5.0.")

(defconstant +rti-shmem-cursor-bias+ 68
  "Subtracted from a control-block cursor before reducing it modulo the ring length. Invariant across all
   four measured configurations. ADR 0081 §5.0.")

(defun* rti-shmem-ring-start (count)
    (function ((unsigned-byte 32)) (unsigned-byte 32))
  "Byte offset at which the record ring begins, for a segment whose `received_message_count_max` is COUNT."
  (+ +rti-shmem-ring-start-base+ (* +rti-shmem-ring-entry-stride+ count)))

(defun* rti-shmem-ring-modulus (props)
    (function (rti-shmem-properties) (unsigned-byte 32))
  "Length of the record ring described by PROPS — the modulus a cumulative cursor is reduced by."
  (+ (rti-shmem-properties-receive-buffer-size props)
     (rti-shmem-properties-message-size-max props)
     (* +rti-shmem-ring-entry-stride+ (rti-shmem-properties-received-message-count-max props))
     +rti-shmem-ring-modulus-bias+))

(defun* rti-shmem-record-offset (cursor props)
    (function ((unsigned-byte 32) rti-shmem-properties) (unsigned-byte 32))
  "Byte offset within the segment of the record a control-block CURSOR refers to, for a receiver described
   by PROPS.

   CURSOR is a running total of bytes, so this is the only correct way to locate a record: `cursor - 20`
   happens to land on the `RTPS` magic, but ONLY until the ring first wraps, after which it addresses
   nothing. That coincidence was recorded as fact in an earlier revision of ADR 0081 and had to be
   retracted — hence this function rather than a subtraction at the call site."
  (+ (rti-shmem-ring-start (rti-shmem-properties-received-message-count-max props))
     (mod (- cursor +rti-shmem-cursor-bias+) (rti-shmem-ring-modulus props))))

(defconstant +rti-shmem-test-port+ 65432
  "RTPS port used by RUN-RTI-SHMEM-RECOGNITION-TEST to key its synthetic segment. Chosen so the derived
   System V key cannot collide with a live Connext participant: no domain maps to it (7400+250*d+10+2*i
   has no integral solution here), so a real RTI segment never claims it.")

(defun* %rti-shmem-put-u32-le (sap offset value)
    (function (t (integer 0) (unsigned-byte 32)) t)
  "Store VALUE at SAP+OFFSET as four little-endian octets. Test scaffolding: the PAL exports an 8-bit SAP
   store only, and writing the octets explicitly also states the byte order the reader assumes."
  (dotimes (i 4 t)
    (dds.pal:store-sap-u8 sap (+ offset i) (ldb (byte 8 (* 8 i)) value))))

(defun* run-rti-shmem-recognition-test ()
    (function () (eql t))
  "ADR 0081 slice 3: RTI-SHMEM-SAME-HOST-P must separate FOUR outcomes that a boolean would collapse.

   The measured layout is only trustworthy if the reader REFUSES what it was not measured against, so this
   drives a synthetic RTI-shaped segment through every verdict rather than only the happy path:

     1. matching `shmemUUID`                -> (T   NIL)  same host
     2. differing `shmemUUID`               -> (NIL NIL)  well-formed, ANOTHER host — not an error
     3. wrong magic                         -> (NIL :NOT-AN-RTI-SHMEM-SEGMENT)
     4. unmeasured protocol major version   -> (NIL :UNVALIDATED-SHMEM-PROTOCOL-VERSION)
     5. no segment at that key              -> (NIL :NO-SUCH-SEGMENT)
     6. a segment SHORTER than the header   -> (NIL :NO-SUCH-SEGMENT), refused at ATTACH

   Case 6 is the security property the reader rests on (NFR-SEC-POSTURE): a truncated or hostile segment
   must fail to attach rather than be read past its end, and because shmget enforces the requested extent
   the check cannot be forgotten by a caller. Verified to behave identically on macOS and Linux.

   Case 4 is the one that matters most and the reason this is not merely a happy-path test: RTI names five
   protocol revisions and specifies none, so a reader that parsed version 5 with version-2 offsets would
   report confident nonsense. Case 2 must NOT be a status — a peer on another machine is the ordinary case.

   Needs no Connext: the segment is built here, which is also what makes the failure modes reachable at all.
   FAILS rather than skips if System V shared memory is unusable — slices 3+ rest on it, so its absence is a
   result worth seeing, not something to pass over quietly."
  (let* ((port +rti-shmem-test-port+)
         (key (rti-shmem-segment-key port))
         (mine (make-array +rti-shmem-uuid-bytes+ :element-type '(unsigned-byte 8)
                                                  :initial-contents '(#x7D #xEA #x36 #x2B #x3F #xAC
                                                                      #x8E #x00 #x95 #x6A #x49 #x52)))
         (other (make-array +rti-shmem-uuid-bytes+ :element-type '(unsigned-byte 8)
                                                   :initial-element #x11)))
    ;; A leaked segment from an earlier failed run would make the exclusive create fail; reclaim it first.
    (multiple-value-bind (stale status) (dds.pal:sysv-shm-attach-readonly key +rti-shmem-header-bytes+)
      (declare (ignore status))
      (when stale (dds.pal:sysv-shm-destroy stale) (dds.pal:sysv-shm-detach stale)))
    ;; A TRUNCATED segment must fail to ATTACH, not be read past its end. This is the security property
    ;; the whole reader rests on: the extent is a precondition the kernel enforces (shmget returns EINVAL
    ;; below the requested size), so no caller can forget to check it. Verified on macOS AND Linux.
    (multiple-value-bind (short status) (dds.pal:sysv-shm-create key (1- +rti-shmem-header-bytes+))
      (when (null status)
        (multiple-value-bind (same st) (rti-shmem-same-host-p mine port)
          (dds.pal:sysv-shm-destroy short)
          (dds.pal:sysv-shm-detach short)
          (assert (and (null same) (eq st :no-such-segment)) ()   ; HOTPATH-COND(TEST): in-file self-test
                  "a segment SHORTER than the header must refuse to attach, got ~s/~s" same st))))
    (multiple-value-bind (seg status) (dds.pal:sysv-shm-create key +rti-shmem-header-bytes+)
      (assert (null status) () "System V shm unusable (~s) — ADR 0081 slice 3 rests on it" status)   ; HOTPATH-COND(TEST): in-file self-test
      (unwind-protect
           (let ((sap (dds.pal:sysv-shm-sap seg)))
             (%rti-shmem-put-u32-le sap +rti-shmem-off-magic+ +rti-shmem-header-magic+)
             (%rti-shmem-put-u32-le sap +rti-shmem-off-protocol-major+ +rti-shmem-protocol-major-validated+)
             (dotimes (i +rti-shmem-uuid-bytes+)
               (dds.pal:store-sap-u8 sap (+ +rti-shmem-off-uuid+ i) (aref mine i)))
             (multiple-value-bind (same st) (rti-shmem-same-host-p mine port)
               (assert (and same (null st)) () "matching UUID must read as same-host, got ~s/~s" same st))   ; HOTPATH-COND(TEST): in-file self-test
             (multiple-value-bind (same st) (rti-shmem-same-host-p other port)
               (assert (and (null same) (null st)) () "a different host is not an error, got ~s/~s" same st))   ; HOTPATH-COND(TEST): in-file self-test
             (%rti-shmem-put-u32-le sap +rti-shmem-off-magic+ (logxor +rti-shmem-header-magic+ 1))
             (multiple-value-bind (same st) (rti-shmem-same-host-p mine port)
               (assert (and (null same) (eq st :not-an-rti-shmem-segment)) ()   ; HOTPATH-COND(TEST): in-file self-test
                       "a foreign segment must be refused, got ~s/~s" same st))
             (%rti-shmem-put-u32-le sap +rti-shmem-off-magic+ +rti-shmem-header-magic+)
             (%rti-shmem-put-u32-le sap +rti-shmem-off-protocol-major+
                                    (+ +rti-shmem-protocol-major-validated+ 3))
             (multiple-value-bind (same st) (rti-shmem-same-host-p mine port)
               (assert (and (null same) (eq st :unvalidated-shmem-protocol-version)) ()   ; HOTPATH-COND(TEST): in-file self-test
                       "an unmeasured protocol version must be refused, not parsed, got ~s/~s" same st))
             t)
        (dds.pal:sysv-shm-destroy seg)
        (dds.pal:sysv-shm-detach seg)))
    (multiple-value-bind (same st) (rti-shmem-same-host-p mine port)
      (assert (and (null same) (eq st :no-such-segment)) ()   ; HOTPATH-COND(TEST): in-file self-test
              "an absent segment must read as :NO-SUCH-SEGMENT, got ~s/~s" same st))
    t))

(defconstant +rti-shmem-properties-test-port+ 65431
  "RTPS port for RUN-RTI-SHMEM-PROPERTIES-TEST's synthetic segment. Distinct from
   +RTI-SHMEM-TEST-PORT+ so the two self-tests cannot collide on a System V key.")

(defun* run-rti-shmem-properties-test ()
    (function () (eql t))
  "ADR 0081 slice 4: the property block must be READ exactly, and every length taken off it corroborated
   before it is believed.

   The block is written by another process, so it is untrusted input whose numbers would later size buffers
   and bound writes. This drives both halves:

     1. exact read-back of all four fields from a segment built with chosen values;
     2. RTI-SHMEM-DATAGRAM-FITS-P at the boundary — message_size_max fits, one octet more does not;
     3. a segment CLAIMING to be larger than it is        -> :IMPLAUSIBLE-SEGMENT-PROPERTIES (the kernel
        refuses the oversized re-attach, so a lie about extent cannot become a trusted bound);
     4. receive_buffer_size larger than the whole segment -> :IMPLAUSIBLE-SEGMENT-PROPERTIES;
     5. message_size_max of zero                          -> :IMPLAUSIBLE-SEGMENT-PROPERTIES.

   Case 3 is the one worth having: it is the difference between reading a length and trusting it. The
   plausibility bounds are PHYSICAL (a buffer cannot exceed the segment holding it), never an invented
   ceiling, so a peer legitimately configured with a large message_size_max is not false-rejected."
  (let* ((port +rti-shmem-properties-test-port+)
         (key (rti-shmem-segment-key port))
         (size 4096))
    (multiple-value-bind (stale status) (dds.pal:sysv-shm-attach-readonly key +rti-shmem-header-bytes+)
      (declare (ignore status))
      (when stale (dds.pal:sysv-shm-destroy stale) (dds.pal:sysv-shm-detach stale)))
    (multiple-value-bind (seg status) (dds.pal:sysv-shm-create key size)
      (assert (null status) () "System V shm unusable (~s)" status)   ; HOTPATH-COND(TEST): in-file self-test
      (unwind-protect
           (let ((sap (dds.pal:sysv-shm-sap seg)))
             (flet ((lay-out (seg-size rbs msm cnt)
                      (%rti-shmem-put-u32-le sap +rti-shmem-off-magic+ +rti-shmem-header-magic+)
                      (%rti-shmem-put-u32-le sap +rti-shmem-off-protocol-major+
                                             +rti-shmem-protocol-major-validated+)
                      (%rti-shmem-put-u32-le sap +rti-shmem-off-segment-size+ seg-size)
                      (%rti-shmem-put-u32-le sap +rti-shmem-off-receive-buffer-size+ rbs)
                      (%rti-shmem-put-u32-le sap +rti-shmem-off-message-size-max+ msm)
                      (%rti-shmem-put-u32-le sap +rti-shmem-off-received-message-count-max+ cnt)))
               (lay-out size 2048 512 8)
               (multiple-value-bind (p st) (rti-shmem-segment-properties port)
                 (assert (and p (null st)) () "a well-formed property block must read, got ~s/~s" p st)   ; HOTPATH-COND(TEST): in-file self-test
                 (assert (= (rti-shmem-properties-segment-size p) size) () "segment-size misread")   ; HOTPATH-COND(TEST): in-file self-test
                 (assert (= (rti-shmem-properties-receive-buffer-size p) 2048) () "rbs misread")   ; HOTPATH-COND(TEST): in-file self-test
                 (assert (= (rti-shmem-properties-message-size-max p) 512) () "msm misread")   ; HOTPATH-COND(TEST): in-file self-test
                 (assert (= (rti-shmem-properties-received-message-count-max p) 8) () "count misread")   ; HOTPATH-COND(TEST): in-file self-test
                 (assert (rti-shmem-datagram-fits-p p 512) () "a datagram OF message_size_max must fit")   ; HOTPATH-COND(TEST): in-file self-test
                 (assert (not (rti-shmem-datagram-fits-p p 513)) () "one octet over must NOT fit"))   ; HOTPATH-COND(TEST): in-file self-test
               ;; 3. the segment lies about its own extent — the kernel, not us, catches it.
               (lay-out (* 2 size) 2048 512 8)
               (multiple-value-bind (p st) (rti-shmem-segment-properties port)
                 (assert (and (null p) (eq st :implausible-segment-properties)) ()   ; HOTPATH-COND(TEST): in-file self-test
                         "a segment overstating its extent must be refused, got ~s/~s" p st))
               ;; 4. a buffer bigger than the segment holding it.
               (lay-out size (* 2 size) 512 8)
               (multiple-value-bind (p st) (rti-shmem-segment-properties port)
                 (assert (and (null p) (eq st :implausible-segment-properties)) ()   ; HOTPATH-COND(TEST): in-file self-test
                         "receive_buffer_size beyond the segment must be refused, got ~s/~s" p st))
               ;; 5. a receiver that can carry nothing.
               (lay-out size 2048 0 8)
               (multiple-value-bind (p st) (rti-shmem-segment-properties port)
                 (assert (and (null p) (eq st :implausible-segment-properties)) ()   ; HOTPATH-COND(TEST): in-file self-test
                         "a zero message_size_max must be refused, got ~s/~s" p st))
               t))
        (dds.pal:sysv-shm-destroy seg)
        (dds.pal:sysv-shm-detach seg)))
    t))

(defun* run-rti-shmem-ring-address-test ()
    (function () (eql t))
  "ADR 0081 §5.0: the ring address arithmetic, checked against the ACTUAL MEASUREMENTS it was derived from.

   The oracle is not a second implementation of the same formula — that would only prove the formula equals
   itself. It is the nine (cursor -> offset) pairs literally observed from live Connext 7.3.1 segments by
   interop/connext/shmem-layout/ring-extent.sh, across four configurations chosen so that each parameter
   was varied ALONE from a common baseline:

     (rbs, msm, count)   ring start   modulus   varied
     (2048, 2048,  8)        304        4096    baseline
     (2048, 2048, 16)        368        4160    count
     (4096, 2048,  8)        304        6144    receive_buffer_size
     (4096, 4096,  8)        304        8192    message_size_max

   Each configuration contributes the last pre-wrap record and the first post-wrap record, so the modulus is
   exercised at its boundary rather than only in its linear region — which is where an earlier version of
   this arithmetic was wrong and looked right.

   If someone edits a constant, this goes red against the observations rather than against an opinion."
  (let ((cases
          ;; rbs   msm   count  ring-start  modulus  ((cursor . offset) ...)
          '((2048  2048   8      304   4096  ((644 . 880) (4100 . 4336) (4164 . 304)))
            (2048  2048  16      368   4160  ((4164 . 4464) (4228 . 368)))
            (4096  2048   8      304   6144  ((6148 . 6384) (6212 . 304)))
            (4096  4096   8      304   8192  ((8196 . 8432) (8260 . 304))))))
    (dolist (c cases t)
      (destructuring-bind (rbs msm count start modulus pairs) c
        (let ((props (make-rti-shmem-properties :segment-size (+ rbs msm 4096)
                                                :receive-buffer-size rbs
                                                :message-size-max msm
                                                :received-message-count-max count)))
          (assert (= (rti-shmem-ring-start count) start) ()   ; HOTPATH-COND(TEST): in-file self-test
                  "ring start for count ~d: got ~d, measured ~d"
                  count (rti-shmem-ring-start count) start)
          (assert (= (rti-shmem-ring-modulus props) modulus) ()   ; HOTPATH-COND(TEST): in-file self-test
                  "modulus for (~d ~d ~d): got ~d, measured ~d"
                  rbs msm count (rti-shmem-ring-modulus props) modulus)
          (dolist (p pairs)
            (assert (= (rti-shmem-record-offset (car p) props) (cdr p)) ()   ; HOTPATH-COND(TEST): in-file self-test
                    "cursor ~d in (~d ~d ~d): got offset ~d, MEASURED ~d"
                    (car p) rbs msm count (rti-shmem-record-offset (car p) props) (cdr p))))))))
