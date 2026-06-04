(in-package #:dds.tests)

;;; M2 increment 1: RTPS Message Header + SubmessageHeader + EntityId byte-exact
;;; against RTPS 2.5 (§9.4.4 / §9.4.5.1 / §9.3.1.2). The wire-layer analogue of
;;; the byte-exact CDR corpus; values pinned from docs/specs, not memory.

(declaim (ftype (function () t) run-rtps-wire-test))
(defun run-rtps-wire-test ()
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 64 1))
         (prefix (make-array 12 :element-type '(unsigned-byte 8)
                                :initial-contents '(1 2 3 4 5 6 7 8 9 10 11 12)))
         (buf (dds.core.arena:pool-acquire pool))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    ;; RTPS Header byte-exactness (§9.4.4): 'RTPS' 2 5 vendor=0 prefix[12]
    (dds.rtps.message:write-header c prefix :vendor 0)
    (%check :rtps-header-bytes
            (equal '(#x52 #x54 #x50 #x53 2 5 0 0 1 2 3 4 5 6 7 8 9 10 11 12)
                   (%first-bytes buf 20))
            "RTPS header bytes")
    (dds.core.buffer:cursor-reset c)
    (multiple-value-bind (major minor vendor pfx) (dds.rtps.message:parse-header c)
      (%check :rtps-header-parse
              (and (= major 2) (= minor 5) (= vendor 0) (equalp pfx prefix))
              "RTPS header parse"))
    ;; SubmessageHeader (§9.4.5.1): DATA(0x15), E=little, octetsToNextHeader=16
    (dds.core.buffer:cursor-reset c)
    (dds.rtps.message:write-submessage-header
     c dds.rtps.message:+submsg-data+ dds.rtps.message:+flag-endianness+ 16)
    (%check :submsg-bytes
            (equal '(#x15 #x01 #x10 #x00) (%first-bytes buf 4))
            "submessage header bytes")
    (dds.core.buffer:cursor-reset c)
    (multiple-value-bind (id flags octets le) (dds.rtps.message:parse-submessage-header c)
      (%check :submsg-parse (and (= id #x15) (= flags #x01) (= octets 16) le)
              "submessage header parse"))
    ;; EntityId (§9.3.1.2): ENTITYID_PARTICIPANT = 0x000001c1 -> 00 00 01 c1
    (dds.core.buffer:cursor-reset c)
    (dds.rtps.message:write-entity-id c dds.rtps.message:+entityid-participant+)
    (%check :entityid-bytes
            (equal '(#x00 #x00 #x01 #xc1) (%first-bytes buf 4))
            "ENTITYID_PARTICIPANT bytes")
    (dds.core.buffer:cursor-reset c)
    (%check :entityid-parse (= #x000001c1 (dds.rtps.message:read-entity-id c))
            "EntityId parse")
    ;; bounds-check: a 3-octet buffer must not parse a submessage header (no OOB)
    (let* ((b2 (dds.core.arena:make-buffer-pool arena 3 1))
           (sb (dds.core.arena:pool-acquire b2))
           (sc (dds.core.buffer:cursor sb :endianness :little)))
      (%check :submsg-bounds (null (dds.rtps.message:parse-submessage-header sc))
              "short buffer must yield NIL, not OOB"))
    (dds.core.arena:pool-release pool buf)
    (dds.core.arena:teardown-arena arena)
    t))

;;; SequenceNumber + SequenceNumberSet byte-exact + exhaustive bitmap boundaries
;;; (RTPS 2.5 §9.3.2.10 / §9.4.2.6) — the classic off-by-one source (FR-RTPS-7, R4).

(declaim (ftype (function () t) run-rtps-seqnum-test))
(defun run-rtps-seqnum-test ()
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 64 1))
         (buf (dds.core.arena:pool-acquire pool))
         (c (dds.core.buffer:cursor buf :endianness :little)))
    ;; SequenceNumber: 1 -> high 0, low 1 (LE)
    (dds.rtps.message:write-sequence-number c 1)
    (%check :seqnum-bytes (equal '(0 0 0 0 1 0 0 0) (%first-bytes buf 8)) "seqnum=1 LE bytes")
    (dds.core.buffer:cursor-reset c)
    (%check :seqnum-rt (= 1 (dds.rtps.message:read-sequence-number c)) "seqnum=1 round-trip")
    (dds.core.buffer:cursor-reset c)
    (dds.rtps.message:write-sequence-number c #x123456789A)
    (dds.core.buffer:cursor-reset c)
    (%check :seqnum-large (= #x123456789A (dds.rtps.message:read-sequence-number c))
            "large seqnum round-trip")
    ;; SEQUENCENUMBER_UNKNOWN = {high=-1, low=0}
    (dds.core.buffer:cursor-reset c)
    (dds.rtps.message:write-sequence-number c dds.rtps.message:+sequence-number-unknown+)
    (%check :seqnum-unknown-bytes
            (equal '(#xff #xff #xff #xff 0 0 0 0) (%first-bytes buf 8)) "UNKNOWN bytes")
    (dds.core.buffer:cursor-reset c)
    (%check :seqnum-unknown-rt
            (= dds.rtps.message:+sequence-number-unknown+ (dds.rtps.message:read-sequence-number c))
            "UNKNOWN round-trip")
    ;; SequenceNumberSet spec example "1234/12:00110" (offsets 2,3 set)
    (let ((bm (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
      (dds.rtps.message:seqnum-set-bit bm 2)
      (dds.rtps.message:seqnum-set-bit bm 3)
      (%check :snset-bitmap (= #x30000000 (aref bm 0)) "1234/12 bitmap word")
      (dds.core.buffer:cursor-reset c)
      (dds.rtps.message:write-sequence-number-set c 1234 12 bm)
      (%check :snset-bytes
              (equal '(0 0 0 0 #xd2 4 0 0 #x0c 0 0 0 0 0 0 #x30) (%first-bytes buf 16))
              "1234/12 SequenceNumberSet LE bytes")
      (%check :snset-member
              (and (dds.rtps.message:seqnum-set-member-p 1234 12 bm 1236)
                   (dds.rtps.message:seqnum-set-member-p 1234 12 bm 1237)
                   (not (dds.rtps.message:seqnum-set-member-p 1234 12 bm 1234))
                   (not (dds.rtps.message:seqnum-set-member-p 1234 12 bm 1238)))
              "1234/12 membership"))
    (dds.core.buffer:cursor-reset c)
    (multiple-value-bind (base numbits bm2) (dds.rtps.message:read-sequence-number-set c)
      (%check :snset-parse (and (= base 1234) (= numbits 12) (= (aref bm2 0) #x30000000))
              "SequenceNumberSet parse"))
    ;; off-by-one boundaries: offset 0 -> bit31 word0; 31 -> bit0 word0; 32 -> bit31 word1
    (let ((bm (make-array 2 :element-type '(unsigned-byte 32) :initial-element 0)))
      (dds.rtps.message:seqnum-set-bit bm 0)
      (dds.rtps.message:seqnum-set-bit bm 31)
      (dds.rtps.message:seqnum-set-bit bm 32)
      (%check :snset-boundaries
              (and (= (aref bm 0) (logior #x80000000 1)) (= (aref bm 1) #x80000000))
              "bitmap word/bit boundaries"))
    ;; bounds: an 8-octet buffer cannot hold a SequenceNumberSet -> NIL, no OOB
    (let* ((b2 (dds.core.arena:make-buffer-pool arena 8 1))
           (sb (dds.core.arena:pool-acquire b2))
           (sc (dds.core.buffer:cursor sb :endianness :little)))
      (%check :snset-bounds (null (dds.rtps.message:read-sequence-number-set sc))
              "short buffer -> NIL"))
    (dds.core.arena:pool-release pool buf)
    (dds.core.arena:teardown-arena arena)
    t))
