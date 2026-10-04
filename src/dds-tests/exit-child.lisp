;;;; Child-process bodies for the exit-process tests (ADR 0121). NOT a component of any ASDF system: the
;;;; parent test (exit-test.lisp) starts a fresh Lisp of its own implementation (dds.pal:lisp-eval-command),
;;;; which loads :dds-durability, LOADs this file, and calls exactly one of the functions below. Each one sets
;;;; up state that only the shutdown-hook chain can clean up, prints line markers on *STANDARD-OUTPUT* for the
;;;; parent to read, and ends the process. Nothing here is reached by the test suite's own image.

(defpackage #:net.goenninger.dds.exit-child
  (:use #:common-lisp #:net.goenninger.dds.lang)
  (:documentation "Bodies of the exit-process test's child processes (ADR 0121). Test-only."))

(in-package #:net.goenninger.dds.exit-child)

(defvar *planted-secret* nil
  "The secret buffer a child plants and never frees, so only the :DARE-SECRET-WIPE hook can wipe it.")

(defun* say (fmt &rest args)
    (function (string &rest t) (eql t))
  "Print one marker line for the parent and flush it at once (the parent polls the output file)."
  (apply #'format t (concatenate 'string "~&" fmt "~%") args)
  (finish-output)
  t)

(defun* plant (shm-name)
    (function (string) (eql t))
  "Arm the read-back seam, plant a 32-octet secret of #xA5 octets and create the shm object SHM-NAME, and
   free neither. The read-back hook reports every wipe as 'WIPE-READBACK len=N zero=T|NIL'."
  (setf dds.dare:*secret-wipe-readback-hook*
        (lambda (v) (say "WIPE-READBACK len=~d zero=~:[NIL~;T~]" (length v) (every #'zerop v))))
  (setf *planted-secret*
        (dds.dare:octets->secret (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xA5)))
  (multiple-value-bind (seg status) (dds.pal:shm-create shm-name 4096)
    (say "SHM-CREATED ok=~:[NIL~;T~] status=~a" seg status))
  t)

(defun* park-a-thread-in-read ()
    (function () t)
  "Start a thread blocked in read(2) on a pipe nobody writes: a thread parked in a foreign call, the case
   on which the old unwinding exit hung on AllegroCL (ADR 0121). Both pipe ends stay open, so the read never returns."
  (let ((fds (cffi:foreign-alloc :int :count 2)))
    (cffi:foreign-funcall "pipe" :pointer fds :int)
    (dds.pal:spawn (lambda ()
                     (cffi:with-foreign-object (b :uint8 16)
                       (cffi:foreign-funcall "read" :int (cffi:mem-aref fds :int 0)
                                                    :pointer b :unsigned-long 16 :long)))
                   :name "dds-test-parked-read")))

(defun* child-direct (shm-name)
    (function (string) nil)
  "Scenario DIRECT: plant a secret and a segment, park a thread in read(2), then (dds.pal:exit-process 3).
   The parent expects exit status 3 well inside its deadline, one all-zero read-back, and SHM-NAME gone."
  (plant shm-name)
  (park-a-thread-in-read)
  (sleep 0.5)
  (say "CHILD-EXITING")
  (dds.pal:exit-process 3))

(defun* child-wedged (shm-name)
    (function (string) nil)
  "Scenario WEDGED: register a hook that never returns, bound the chain at 2 s, then exit with 0. The newest
   hook runs first, so the wedged hook blocks the chain; the watchdog must end the process with
   +EXIT-SHUTDOWN-INCOMPLETE+ (70), not 0, and not hang."
  (plant shm-name)
  (setf dds.pal:*shutdown-hook-timeout-seconds* 2)
  (dds.pal:register-shutdown-hook :test-wedged-hook (lambda () (loop (sleep 1))))
  (say "CHILD-EXITING")
  (dds.pal:exit-process 0))

(defun* child-durability (shm-name domain)
    (function (string (integer 0 232)) nil)
  "Scenario DURABILITY: plant a secret and a segment, then run the real DURABILITY-SERVICE-MAIN (in-memory
   store, one topic) on DOMAIN in BLOCK mode. A reporter thread prints 'SHM-OWNED <names...>' once the
   service's participant has created its own SHMEM segment, so the parent knows which names must be gone
   after the SIGTERM it sends once it has read 'DURABILITY-SERVICE-READY'."
  (plant shm-name)
  (dds.pal:spawn (lambda ()
                   (loop repeat 600
                         until (>= (length (dds.pal::%owned-shm-names)) 2)
                         do (sleep 0.1))
                   (say "SHM-OWNED~{ ~a~}" (dds.pal::%owned-shm-names)))
                 :name "dds-test-shm-reporter")
  (dds.durability:durability-service-main
   :argv (list "--domain" (princ-to-string domain) "--topic" "ExitSquare:ShapeType" "--name" "exit-test")
   :env '() :block t)
  (say "UNREACHABLE: durability-service-main returned")
  (dds.pal:exit-process 99))
