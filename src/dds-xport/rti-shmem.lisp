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

(defun* %rti-shmem-header-verdict (sap host-id)
    (function (t (simple-array (unsigned-byte 8) (12))) (values t (or null keyword)))
  "Verdict for an attached RTI segment header at SAP against the 12-octet HOST-ID from a locator.
   Returns (values T NIL) when the segment is an RTI segment of a validated protocol version whose
   `shmemUUID` matches, (values NIL NIL) when it is such a segment but the UUID differs — a well-formed
   'not this host' — and (values NIL status) when the segment is not one we may interpret.

   Split out from RTI-SHMEM-SAME-HOST-P so that function can attach, take a verdict, and DETACH on a single
   path: an early exit between attach and detach would leak the attachment."
  (cond ((/= (dds.pal:load-sap-u32 sap +rti-shmem-off-magic+) +rti-shmem-header-magic+)
         (values nil :not-an-rti-shmem-segment))
        ((/= (dds.pal:load-sap-u32 sap +rti-shmem-off-protocol-major+)
             +rti-shmem-protocol-major-validated+)
         (values nil :unvalidated-shmem-protocol-version))
        (t (values (dotimes (i +rti-shmem-uuid-bytes+ t)
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
