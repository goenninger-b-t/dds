(in-package #:dds.core.buffer)

(define-condition buffer-overflow (error)
  ((need :initarg :need :reader buffer-overflow-need)
   (have :initarg :have :reader buffer-overflow-have))
  (:report (lambda (c s)
             (format s "buffer-overflow: need ~d octet(s), ~d remaining"
                     (buffer-overflow-need c) (buffer-overflow-have c))))
  (:documentation "Signalled when an op would read/write past the buffer extent."))

(defstruct (octet-buffer (:constructor %make-octet-buffer))
  (vec (dds.pal:alloc-static 0) :type (simple-array (unsigned-byte 8) (*)))
  (capacity 0 :type fixnum))

(declaim (ftype (function ((integer 0)) octet-buffer) make-octet-buffer))
(declaim (ftype (function (octet-buffer) t) buffer-sap))

(defun make-octet-buffer (n)
  "Allocate an N-octet off-heap buffer with a stable address (PAL-backed)."
  (declare (type (integer 0) n))
  (%make-octet-buffer :vec (dds.pal:alloc-static n) :capacity n))

(defun buffer-sap (buffer)
  "Raw foreign pointer to BUFFER for syscalls / SHMEM."
  (dds.pal:static-pointer (octet-buffer-vec buffer)))

(defstruct (cursor (:constructor %make-cursor))
  (buffer nil :type octet-buffer)
  (pos 0 :type fixnum)
  (origin 0 :type fixnum)
  (endianness :little :type (member :little :big)))

(declaim (ftype (function (octet-buffer &key (:endianness (member :little :big))) cursor) cursor))
(declaim (ftype (function (cursor) fixnum) cursor-position))
(declaim (ftype (function (cursor) fixnum) cursor-reset))
(declaim (ftype (function (cursor) fixnum) cursor-set-origin))
(declaim (ftype (function (cursor (integer 0)) t) %check-room))
(declaim (ftype (function (cursor (integer 1 8)) fixnum) align))
(declaim (ftype (function (cursor (integer 0) (integer 1 8)) (integer 0)) %put-uint))
(declaim (ftype (function (cursor (integer 1 8)) (integer 0)) %get-uint))
(declaim (ftype (function (cursor (integer 0)) (integer 0)) put-u8))
(declaim (ftype (function (cursor) (integer 0)) get-u8))
(declaim (ftype (function (cursor (integer 0)) (integer 0)) put-u16))
(declaim (ftype (function (cursor) (integer 0)) get-u16))
(declaim (ftype (function (cursor (integer 0)) (integer 0)) put-u32))
(declaim (ftype (function (cursor) (integer 0)) get-u32))
(declaim (ftype (function (cursor (integer 0)) (integer 0)) put-u64))
(declaim (ftype (function (cursor) (integer 0)) get-u64))
(declaim (ftype (function (cursor (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) (integer 0)) put-octets))
(declaim (ftype (function (cursor (simple-array (unsigned-byte 8) (*)) (integer 0) (integer 0)) (integer 0)) get-octets))

(defun cursor (buffer &key (endianness :little))
  "Create a cursor over BUFFER at position 0, alignment origin 0."
  (%make-cursor :buffer buffer :pos 0 :origin 0 :endianness endianness))

(declaim (inline cursor-position cursor-reset cursor-set-origin))
(defun cursor-position (cursor) (cursor-pos cursor))
(defun cursor-reset (cursor) (setf (cursor-pos cursor) 0 (cursor-origin cursor) 0))
(defun cursor-set-origin (cursor)
  "Set the alignment origin to the current position. Used after writing the
   4-byte encapsulation header so CDR alignment resets per RTPS 2.5 §10.2."
  (setf (cursor-origin cursor) (cursor-pos cursor)))

(declaim (inline %check-room))
(defun %check-room (cursor n)
  (let* ((buf (cursor-buffer cursor))
         (remaining (- (octet-buffer-capacity buf) (cursor-pos cursor))))
    (when (> n remaining)
      (error 'buffer-overflow :need n :have remaining))))

(defun align (cursor n)
  "Advance to the next N-byte boundary relative to the alignment origin (n in
   {1,2,4,8}), zero-filling padding. Origin defaults to 0; the codec sets it to
   the post-encapsulation-header position (RTPS 2.5 §10.2)."
  (declare (type (integer 1 8) n))
  (let* ((pos (cursor-pos cursor))
         (rem (mod (- pos (cursor-origin cursor)) n)))
    (unless (zerop rem)
      (let ((pad (- n rem)))
        (%check-room cursor pad)
        (let ((vec (octet-buffer-vec (cursor-buffer cursor))))
          (dotimes (i pad) (setf (aref vec (+ pos i)) 0)))
        (setf (cursor-pos cursor) (+ pos pad)))))
  (cursor-pos cursor))

(defun %put-uint (cursor value nbytes)
  (declare (type (integer 0) value) (type (integer 1 8) nbytes))
  (dds.pal:with-hot-optimizations
    (%check-room cursor nbytes)
    (let* ((vec (octet-buffer-vec (cursor-buffer cursor)))
           (pos (cursor-pos cursor)))
      (ecase (cursor-endianness cursor)
        (:little (dotimes (i nbytes)
                   (setf (aref vec (+ pos i)) (ldb (byte 8 (* 8 i)) value))))
        (:big (dotimes (i nbytes)
                (setf (aref vec (+ pos i)) (ldb (byte 8 (* 8 (- nbytes 1 i))) value)))))
      (setf (cursor-pos cursor) (+ pos nbytes))
      value)))

(defun %get-uint (cursor nbytes)
  (declare (type (integer 1 8) nbytes))
  (dds.pal:with-hot-optimizations
    (%check-room cursor nbytes)
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

(defun put-u8  (cursor v) (%put-uint cursor v 1))
(defun get-u8  (cursor)   (%get-uint cursor 1))
(defun put-u16 (cursor v) (%put-uint cursor v 2))
(defun get-u16 (cursor)   (%get-uint cursor 2))
(defun put-u32 (cursor v) (%put-uint cursor v 4))
(defun get-u32 (cursor)   (%get-uint cursor 4))
(defun put-u64 (cursor v) (%put-uint cursor v 8))
(defun get-u64 (cursor)   (%get-uint cursor 8))

(defun put-octets (cursor src off len)
  "Copy LEN octets from SRC[OFF..] into the buffer at the cursor."
  (declare (type (simple-array (unsigned-byte 8) (*)) src))
  (%check-room cursor len)
  (let* ((vec (octet-buffer-vec (cursor-buffer cursor)))
         (pos (cursor-pos cursor)))
    (replace vec src :start1 pos :start2 off :end2 (+ off len))
    (setf (cursor-pos cursor) (+ pos len))
    len))

(defun get-octets (cursor dst off len)
  "Copy LEN octets from the buffer at the cursor into DST[OFF..]."
  (declare (type (simple-array (unsigned-byte 8) (*)) dst))
  (%check-room cursor len)
  (let* ((vec (octet-buffer-vec (cursor-buffer cursor)))
         (pos (cursor-pos cursor)))
    (replace dst vec :start1 off :start2 pos :end2 (+ pos len))
    (setf (cursor-pos cursor) (+ pos len))
    len))
