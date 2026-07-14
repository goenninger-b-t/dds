(in-package #:dds.core.buffer)

(define-condition buffer-overflow (error)
  ((need :initarg :need :reader buffer-overflow-need)
   (have :initarg :have :reader buffer-overflow-have))
  (:report (lambda (c s)
             (format s "buffer-overflow: need ~d octet(s), ~d remaining"
                     (buffer-overflow-need c) (buffer-overflow-have c))))
  (:documentation "Signalled when an op would read/write past the buffer extent."))

(defstruct* (octet-buffer (:constructor %make-octet-buffer))
  "Off-heap octet buffer with a stable foreign address (PAL-backed), of fixed
   CAPACITY. The unit of hot-path serialization memory (HOT PATH)."
  (vec (dds.pal:alloc-static 0) :type (simple-array (unsigned-byte 8) (*)))
  (capacity 0 :type fixnum))


(defun* make-octet-buffer (n)
    (function ((integer 0)) octet-buffer)
  "Allocate an N-octet off-heap buffer with a stable address (PAL-backed)."
  (declare (type (integer 0) n))
  (%make-octet-buffer :vec (dds.pal:alloc-static n) :capacity n))

(defun* octet-buffer-over (vec)
    (function ((simple-array (unsigned-byte 8) (*))) octet-buffer)
  "Wrap an EXISTING octet vector VEC as an octet-buffer (capacity = its length), WITHOUT a static
   allocation. For building/parsing a small message in a caller-owned (e.g. GC-heap) buffer when no
   stable foreign address is needed — NOT for a syscall/SHMEM buffer (use make-octet-buffer for those,
   whose vec has a stable PAL-backed address). Shares VEC; no copy."
  (%make-octet-buffer :vec vec :capacity (length vec)))

(defun* buffer-sap (buffer)
    (function (octet-buffer) t)
  "Raw foreign pointer to BUFFER for syscalls / SHMEM."
  (dds.pal:static-pointer (octet-buffer-vec buffer)))

(defstruct* (cursor (:constructor %make-cursor))
  "Read/write position over an octet-buffer, with the endianness and the
   alignment origin (alignment is relative to ORIGIN, default 0) (HOT PATH)."
  (buffer nil :type octet-buffer)
  (pos 0 :type fixnum)
  (origin 0 :type fixnum)
  (endianness :little :type (member :little :big)))


(defun* cursor (buffer &key (endianness :little))
    (function (octet-buffer &key (:endianness (member :little :big))) cursor)
  "Create a cursor over BUFFER at position 0, alignment origin 0."
  (%make-cursor :buffer buffer :pos 0 :origin 0 :endianness endianness))

(declaim (inline cursor-position cursor-reset cursor-set-origin cursor-set-endianness
                 cursor-set-position))
(defun* cursor-position (cursor)
    (function (cursor) fixnum) "Current byte position of CURSOR in its buffer." (cursor-pos cursor))
(defun* cursor-reset (cursor)
    (function (cursor) fixnum) "Reset CURSOR to position 0 and alignment origin 0." (setf (cursor-pos cursor) 0 (cursor-origin cursor) 0))
(defun* cursor-set-origin (cursor)
    (function (cursor) fixnum)
  "Set the alignment origin to the current position. Used after writing the
   4-byte encapsulation header so CDR alignment resets per RTPS 2.5 §10.2."
  (setf (cursor-origin cursor) (cursor-pos cursor)))
(defun* cursor-set-endianness (cursor endianness)
    (function (cursor (member :little :big)) (member :little :big))
  "Set the cursor endianness; used by the receive loop after reading a Submessage
   header's E flag (RTPS 2.5 §9.4.5.1.2)."
  (setf (cursor-endianness cursor) endianness))
(defun* cursor-set-position (cursor pos)
    (function (cursor (integer 0)) fixnum)
  "Set the cursor position (bounds-checked against the buffer capacity)."
  (let ((cap (octet-buffer-capacity (cursor-buffer cursor))))
    (when (> pos cap) (error 'buffer-overflow :need pos :have cap))   ; HOTPATH-COND(GUARD): bounds check on a wire-supplied position; cannot fire in steady state; caught at the receiver boundary (start-udp-receiver / shmem-receive-drain) so a malformed datagram never kills the thread (NFR-SEC-POSTURE)
    (setf (cursor-pos cursor) pos)))

(declaim (inline check-room))
(defun* check-room (cursor n)
    (function (cursor (integer 0)) t)
  "Signal BUFFER-OVERFLOW unless CURSOR has room for N more octets before its buffer
   capacity. Exported so parsers can pre-validate wire-supplied lengths/counts BEFORE
   allocating a result, so a hostile length can never exhaust the heap (NFR-SEC-POSTURE)."
  (let* ((buf (cursor-buffer cursor))
         (remaining (- (octet-buffer-capacity buf) (cursor-pos cursor))))
    (when (> n remaining)
      (error 'buffer-overflow :need n :have remaining))))   ; HOTPATH-COND(GUARD): the same bounds check on room-before-write; see line 71

(defun* align (cursor n)
    (function (cursor (integer 1 8)) fixnum)
  "Advance to the next N-byte boundary relative to the alignment origin (n in
   {1,2,4,8}), zero-filling padding. Origin defaults to 0; the codec sets it to
   the post-encapsulation-header position (RTPS 2.5 §10.2)."
  (declare (type (integer 1 8) n))
  (let* ((pos (cursor-pos cursor))
         (rem (mod (- pos (cursor-origin cursor)) n)))
    (unless (zerop rem)
      (let ((pad (- n rem)))
        (check-room cursor pad)
        (let ((vec (octet-buffer-vec (cursor-buffer cursor))))
          (dotimes (i pad) (setf (aref vec (+ pos i)) 0)))
        (setf (cursor-pos cursor) (+ pos pad)))))
  (cursor-pos cursor))

(defun* %put-uint (cursor value nbytes)
    (function (cursor (integer 0) (integer 1 8)) (integer 0))
  "Write VALUE as an NBYTES-wide unsigned integer at CURSOR in the cursor's endianness, advancing it; returns VALUE."
  (declare (type (integer 0) value) (type (integer 1 8) nbytes))
  (dds.pal:with-hot-optimizations
    (check-room cursor nbytes)
    (let* ((vec (octet-buffer-vec (cursor-buffer cursor)))
           (pos (cursor-pos cursor)))
      (ecase (cursor-endianness cursor)
        (:little (dotimes (i nbytes)
                   (setf (aref vec (+ pos i)) (ldb (byte 8 (* 8 i)) value))))
        (:big (dotimes (i nbytes)
                (setf (aref vec (+ pos i)) (ldb (byte 8 (* 8 (- nbytes 1 i))) value)))))
      (setf (cursor-pos cursor) (+ pos nbytes))
      value)))

(defun* %get-uint (cursor nbytes)
    (function (cursor (integer 1 8)) (integer 0))
  "Read an NBYTES-wide unsigned integer at CURSOR in the cursor's endianness, advancing it; returns the value."
  (declare (type (integer 1 8) nbytes))
  (dds.pal:with-hot-optimizations
    (check-room cursor nbytes)
    (let* ((vec (octet-buffer-vec (cursor-buffer cursor)))
           (pos (cursor-pos cursor))
           (v 0))
      (ecase (cursor-endianness cursor)
        (:little (dotimes (i nbytes)
                   (setf v (logior v (ash (aref vec (+ pos i)) (* 8 i))))))
        (:big (dotimes (i nbytes)
                (setf v (logior v (ash (aref vec (+ pos i)) (* 8 (- nbytes 1 i))))))))
      (setf (cursor-pos cursor) (+ pos nbytes))
      v)))

(defun* put-u8  (cursor v)
    (function (cursor (integer 0)) (integer 0)) "Write V as 1 octet at CURSOR (bounds-checked)." (%put-uint cursor v 1))
(defun* get-u8  (cursor)
    (function (cursor) (integer 0))   "Read 1 octet at CURSOR (bounds-checked)." (%get-uint cursor 1))
(defun* put-u16 (cursor v)
    (function (cursor (integer 0)) (integer 0)) "Write V as 2 octets at CURSOR in cursor endianness (bounds-checked)." (%put-uint cursor v 2))
(defun* get-u16 (cursor)
    (function (cursor) (integer 0))   "Read 2 octets at CURSOR in cursor endianness (bounds-checked)." (%get-uint cursor 2))
(defun* put-u32 (cursor v)
    (function (cursor (integer 0)) (integer 0)) "Write V as 4 octets at CURSOR in cursor endianness (bounds-checked)." (%put-uint cursor v 4))
(defun* get-u32 (cursor)
    (function (cursor) (integer 0))   "Read 4 octets at CURSOR in cursor endianness (bounds-checked)." (%get-uint cursor 4))
(defun* put-u64 (cursor v)
    (function (cursor (integer 0)) (integer 0)) "Write V as 8 octets at CURSOR in cursor endianness (bounds-checked)." (%put-uint cursor v 8))
(defun* get-u64 (cursor)
    (function (cursor) (integer 0))   "Read 8 octets at CURSOR in cursor endianness (bounds-checked)." (%get-uint cursor 8))

(defun* put-octets (cursor src off len)
    (function (cursor (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) (integer 0))
  "Copy LEN octets from SRC[OFF..] into the buffer at the cursor."
  (declare (type (simple-array (unsigned-byte 8) (*)) src))
  (check-room cursor len)
  (let* ((vec (octet-buffer-vec (cursor-buffer cursor)))
         (pos (cursor-pos cursor)))
    (replace vec src :start1 pos :start2 off :end2 (+ off len))
    (setf (cursor-pos cursor) (+ pos len))
    len))

(defun* get-octets (cursor dst off len)
    (function (cursor (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) (integer 0))
  "Copy LEN octets from the buffer at the cursor into DST[OFF..]."
  (declare (type (simple-array (unsigned-byte 8) (*)) dst))
  (check-room cursor len)
  (let* ((vec (octet-buffer-vec (cursor-buffer cursor)))
         (pos (cursor-pos cursor)))
    (replace dst vec :start1 off :start2 pos :end2 (+ pos len))
    (setf (cursor-pos cursor) (+ pos len))
    len))
