;;;; MD5 (RFC 1321), vendored clean-room from the algorithm description in RFC 1321.
;;;; Used by the stack as a CONTENT / IDENTITY hash only — the XTypes EquivalenceHash
;;;; and NameHash (FR-TYPE-2) and the DDS keyhash >16-byte case (FR-TYPE-5) — NOT for
;;;; the DDS-Security profile (FR-SEC-2 mandates vetted native crypto; this is not that).
;;;; Control-plane (type registration), not a measured hot path. Provenance: docs/provenance.md.

(in-package #:dds.core.md5)

(declaim (type (simple-array (unsigned-byte 32) (64)) +k+))
(defparameter +k+
  (make-array 64 :element-type '(unsigned-byte 32)
    :initial-contents
    '(#xd76aa478 #xe8c7b756 #x242070db #xc1bdceee #xf57c0faf #x4787c62a #xa8304613 #xfd469501
      #x698098d8 #x8b44f7af #xffff5bb1 #x895cd7be #x6b901122 #xfd987193 #xa679438e #x49b40821
      #xf61e2562 #xc040b340 #x265e5a51 #xe9b6c7aa #xd62f105d #x02441453 #xd8a1e681 #xe7d3fbc8
      #x21e1cde6 #xc33707d6 #xf4d50d87 #x455a14ed #xa9e3e905 #xfcefa3f8 #x676f02d9 #x8d2a4c8a
      #xfffa3942 #x8771f681 #x6d9d6122 #xfde5380c #xa4beea44 #x4bdecfa9 #xf6bb4b60 #xbebfbc70
      #x289b7ec6 #xeaa127fa #xd4ef3085 #x04881d05 #xd9d4d039 #xe6db99e5 #x1fa27cf8 #xc4ac5665
      #xf4292244 #x432aff97 #xab9423a7 #xfc93a039 #x655b59c3 #x8f0ccc92 #xffeff47d #x85845dd1
      #x6fa87e4f #xfe2ce6e0 #xa3014314 #x4e0811a1 #xf7537e82 #xbd3af235 #x2ad7d2bb #xeb86d391))
  "MD5 per-round constants K[i] = floor(2^32 * abs(sin(i+1))) (RFC 1321).")

(declaim (type (simple-array (unsigned-byte 8) (64)) +s+))
(defparameter +s+
  (make-array 64 :element-type '(unsigned-byte 8)
    :initial-contents
    '(7 12 17 22 7 12 17 22 7 12 17 22 7 12 17 22
      5 9 14 20 5 9 14 20 5 9 14 20 5 9 14 20
      4 11 16 23 4 11 16 23 4 11 16 23 4 11 16 23
      6 10 15 21 6 10 15 21 6 10 15 21 6 10 15 21))
  "MD5 per-round left-rotate amounts s[i] (RFC 1321).")

(declaim (inline %rotl32))
(declaim (ftype (function ((unsigned-byte 32) (integer 0 31)) (unsigned-byte 32)) %rotl32))
(defun %rotl32 (x n)
  "Left-rotate the 32-bit X by N bits."
  (logand (logior (ash x n) (ash x (- n 32))) #xffffffff))

(declaim (ftype (function ((simple-array (unsigned-byte 32) (4)) (simple-array (unsigned-byte 8) (*)) fixnum) t) %md5-block))
(defun %md5-block (state bytes off)
  "Process the 64-octet block of BYTES at OFF, updating STATE (a,b,c,d) in place."
  (declare (optimize (speed 3) (safety 1)))
  (let ((m (make-array 16 :element-type '(unsigned-byte 32))))
    (declare (dynamic-extent m))
    (dotimes (i 16)
      (let ((b (+ off (* 4 i))))
        (setf (aref m i)
              (logior (aref bytes b)
                      (ash (aref bytes (+ b 1)) 8)
                      (ash (aref bytes (+ b 2)) 16)
                      (ash (aref bytes (+ b 3)) 24)))))
    (let ((a (aref state 0)) (b (aref state 1)) (c (aref state 2)) (d (aref state 3)))
      (declare (type (unsigned-byte 32) a b c d))
      (dotimes (i 64)
        (let ((f 0) (g 0))
          (declare (type (unsigned-byte 32) f) (type (mod 16) g))
          (cond
            ((< i 16) (setf f (logior (logand b c) (logand (logxor b #xffffffff) d)) g i))
            ((< i 32) (setf f (logior (logand d b) (logand (logxor d #xffffffff) c))
                            g (mod (+ (* 5 i) 1) 16)))
            ((< i 48) (setf f (logxor b c d) g (mod (+ (* 3 i) 5) 16)))
            (t (setf f (logxor c (logior b (logxor d #xffffffff))) g (mod (* 7 i) 16))))
          (setf f (logand (+ f a (aref +k+ i) (aref m g)) #xffffffff))
          (setf a d d c c b)
          (setf b (logand (+ b (%rotl32 f (aref +s+ i))) #xffffffff))))
      (setf (aref state 0) (logand (+ (aref state 0) a) #xffffffff)
            (aref state 1) (logand (+ (aref state 1) b) #xffffffff)
            (aref state 2) (logand (+ (aref state 2) c) #xffffffff)
            (aref state 3) (logand (+ (aref state 3) d) #xffffffff))))
  t)

(declaim (ftype (function ((array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (16))) md5))
(defun md5 (octets)
  "MD5 digest (RFC 1321) of OCTETS — returns a fresh 16-octet vector."
  (let* ((len (length octets))
         (bitlen (logand (* len 8) #xffffffffffffffff))
         (padlen (let ((r (mod (+ len 1) 64))) (+ len 1 (mod (- 56 r) 64) 8)))
         (msg (make-array padlen :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace msg octets)
    (setf (aref msg len) #x80)
    (dotimes (i 8)                       ; 64-bit little-endian bit length, last 8 octets
      (setf (aref msg (+ (- padlen 8) i)) (logand (ash bitlen (* -8 i)) #xff)))
    (let ((state (make-array 4 :element-type '(unsigned-byte 32)
                             :initial-contents '(#x67452301 #xefcdab89 #x98badcfe #x10325476))))
      (loop for off of-type fixnum from 0 below padlen by 64 do (%md5-block state msg off))
      (let ((out (make-array 16 :element-type '(unsigned-byte 8))))
        (dotimes (w 4)
          (let ((v (aref state w)))
            (dotimes (i 4) (setf (aref out (+ (* 4 w) i)) (logand (ash v (* -8 i)) #xff)))))
        out))))
