;;;; DDS.PAL — process exit with a bounded shutdown-hook chain (ADR 0121).
;;;;
;;;; EXIT-PROCESS is the ONE way code in this repository ends the Lisp process. It runs the registered
;;;; shutdown hooks (newest first, each guarded, the whole chain under a watchdog deadline), flushes the
;;;; standard streams, then calls the per-implementation %HARD-EXIT, which cannot wait for another thread.
;;;; Impl-agnostic: the only implementation-specific piece is %HARD-EXIT in pal-sbcl.lisp / pal-allegro.lisp.

(in-package #:dds.pal)

(defconstant +exit-shutdown-incomplete+ 70
  "The exit status EXIT-PROCESS uses when the caller asked for 0 but the shutdown-hook chain did not finish
   cleanly (a hook signalled, or the chain overran *SHUTDOWN-HOOK-TIMEOUT-SECONDS*). 70 is EX_SOFTWARE,
   'internal software error' (/usr/include/sysexits.h:102). A caller's NON-zero code is never replaced: it
   already reports a failure, and it is the more specific one.")

(defvar *shutdown-hook-timeout-seconds* 10
  "Upper bound, in seconds, on the whole shutdown-hook chain plus the stream flush that follows it, inside
   EXIT-PROCESS (ADR 0121). A watchdog thread started by EXIT-PROCESS ends the process when it expires, so a
   hook that blocks (an fsync on a dead NFS mount, a lock held by a wedged thread) cannot keep the process
   alive. Read once per EXIT-PROCESS call. Must be a positive real. The default, 10 s, is far above the
   measured cost of the built-in hooks (sub-millisecond each with nothing to clean up) and well below the
   60 s that `timeout --kill-after=60` in the Makefile grants after its own TERM.")

(defvar *shutdown-hooks* '()
  "The registered shutdown hooks as an alist of (NAME . FUNCTION), most recently registered FIRST, which is
   the order EXIT-PROCESS runs them in (LIFO). Mutated only through REGISTER-SHUTDOWN-HOOK and
   UNREGISTER-SHUTDOWN-HOOK, under *SHUTDOWN-HOOKS-LOCK*. Not exported.")

(defvar *shutdown-hooks-lock* (make-lock "dds-shutdown-hooks")
  "Guards *SHUTDOWN-HOOKS* and *EXIT-OWNER*.")

(defvar *exit-owner* nil
  "The thread that won the right to run the exit protocol, or NIL. Set once, under *SHUTDOWN-HOOKS-LOCK*.")

(defun* register-shutdown-hook (name function)
    (function (symbol (or symbol function)) symbol)
  "Register FUNCTION (a 0-argument function, or a symbol naming one) to run when the process ends through
   EXIT-PROCESS, under the key NAME (ADR 0121). Returns NAME.

   Order: hooks run newest-registered FIRST (LIFO), like a stack of cleanups, so a subsystem loaded later
   (which may depend on an earlier one) is cleaned up before what it depends on.
   Re-registering an existing NAME replaces its function IN PLACE and keeps its position, so reloading a
   module does not duplicate or reorder its hook. A symbol is called through its current function binding at
   exit time, so redefining the function also needs no re-registration.

   Contract for a hook: it runs on the exiting thread while OTHER THREADS MAY STILL BE RUNNING. It must
   therefore never free memory or close a resource another thread might be using; it may wipe, flush, sync
   and unlink names. It should be idempotent and quick. It reports failure by returning a non-NIL SECOND
   value (a status keyword); an error it signals is also caught. Either way the failure is reported on
   *ERROR-OUTPUT*, does not stop the later hooks, and turns a requested exit status 0 into
   +EXIT-SHUTDOWN-INCOMPLETE+. A hook that blocks is cut off by the *SHUTDOWN-HOOK-TIMEOUT-SECONDS* watchdog.
   Control plane only."
  (with-lock (*shutdown-hooks-lock*)
    (let ((cell (assoc name *shutdown-hooks* :test #'eq)))
      (if cell
          (setf (cdr cell) function)
          (push (cons name function) *shutdown-hooks*))))
  name)

(defun* unregister-shutdown-hook (name)
    (function (symbol) boolean)
  "Remove the shutdown hook registered under NAME (ADR 0121). Returns T if one was removed, NIL if NAME was
   not registered."
  (with-lock (*shutdown-hooks-lock*)
    (let ((cell (assoc name *shutdown-hooks* :test #'eq)))
      (when cell
        (setf *shutdown-hooks* (remove cell *shutdown-hooks* :test #'eq))
        t))))

(defun* shutdown-hook-names ()
    (function () list)
  "The NAMEs of the registered shutdown hooks, in the order EXIT-PROCESS will run them (newest first).
   A fresh list (ADR 0121)."
  (with-lock (*shutdown-hooks-lock*)
    (mapcar #'car *shutdown-hooks*)))

(defun* %run-hook-chain (entries stream)
    (function (list t) (values list list))
  "Run each (NAME . FUNCTION) in ENTRIES in list order. A hook FAILS when it signals a SERIOUS-CONDITION or
   when it returns a non-NIL SECOND value (a status keyword, the repository's no-conditions convention,
   ADR 0064). Every call is guarded by HANDLER-CASE, so one failing hook is reported on STREAM (when STREAM
   is non-NIL) and the rest still run. Returns (VALUES RAN FAILED): the NAMEs that succeeded and the NAMEs
   that failed, each in run order. A hook that performs a non-local exit leaves this function (and its
   caller's UNWIND-PROTECT then ends the process); that truncates the chain and is the one failure a guard
   cannot absorb. Internal: EXIT-PROCESS calls it on the live registry, the test suite on synthetic entries."
  (let ((ran '()) (failed '()))
    (dolist (e entries)
      (let ((name (car e)) (fn (cdr e)))
        (handler-case
            (let ((status (nth-value 1 (funcall fn))))
              (if status
                  (progn (push name failed)
                         (when stream
                           (ignore-errors
                            (format stream "~&dds.pal:exit-process: shutdown hook ~s reported ~s~%" name status))))
                  (push name ran)))
          (serious-condition (c)
            (push name failed)
            (when stream
              (ignore-errors
               (format stream "~&dds.pal:exit-process: shutdown hook ~s failed: ~a~%" name c)))))))
    (values (nreverse ran) (nreverse failed))))

(defun* %flush-standard-streams ()
    (function () (eql t))
  "FINISH-OUTPUT every standard output stream, each guarded, so the last lines a process printed are not
   lost to the hard exit (which flushes nothing). A stream whose reader is gone (EPIPE) is skipped."
  (dolist (s (list *standard-output* *error-output* *trace-output* *debug-io* *query-io* *terminal-io*))
    (ignore-errors (finish-output s)))
  t)

(defun* %raw-stderr (text)
    (function (string) (eql t))
  "Write TEXT to file descriptor 2 with write(2), bypassing every Lisp stream and its lock. For the exit
   watchdog, which fires precisely when the exiting thread may be wedged while holding a stream. ASCII only.
   File descriptor 2 is STDERR_FILENO (/usr/include/unistd.h:212)."
  (ignore-errors
   (cffi:with-foreign-string (buf text)
     (cffi:foreign-funcall "write" :int 2 :pointer buf :unsigned-long (length text) :long)))
  t)

(defun* %start-exit-watchdog (code seconds done)
    (function ((integer 0 255) real atomic-cell) t)
  "Spawn the thread that bounds EXIT-PROCESS: once SECONDS have passed, unless DONE's value is non-zero
   (the exiting thread got as far as its own hard exit), it reports on fd 2 and hard-exits with CODE, or with
   +EXIT-SHUTDOWN-INCOMPLETE+ when CODE is 0. Polls every 0.1 s: a wait shorter than that is unreliable on
   AllegroCL (waits of 0.075 s or less return immediately, governing plan §1). Returns the thread, or NIL if
   no thread could be created (the chain is then unbounded, and that is reported on fd 2)."
  (let ((th (ignore-errors
             (spawn (lambda ()
                      (let ((deadline (+ (get-internal-real-time)
                                         (* seconds internal-time-units-per-second))))
                        (loop until (or (plusp (atomic-cell-value done))
                                        (> (get-internal-real-time) deadline))
                              do (sleep 0.1))
                        (when (zerop (atomic-cell-value done))
                          (%raw-stderr (format nil "~&dds.pal:exit-process: shutdown hooks overran ~a s; hard exit.~%"
                                               seconds))
                          (%hard-exit (if (zerop code) +exit-shutdown-incomplete+ code)))))
                    :name "dds-exit-watchdog"))))
    (unless th
      (%raw-stderr (format nil "~&dds.pal:exit-process: could not start the watchdog; hooks are unbounded.~%")))
    th))

(defun* exit-process (&optional (code 0))
    (function (&optional (integer 0 255)) nil)
  "End this process with exit status CODE, after running the shutdown-hook chain. Never returns (ADR 0121).

   The protocol, on the first thread to call it:
     1. Start a watchdog that hard-exits after *SHUTDOWN-HOOK-TIMEOUT-SECONDS*, whatever the hooks are doing.
     2. Run every hook registered with REGISTER-SHUTDOWN-HOOK, newest first, each guarded so that one
        failure does not skip the rest. The built-in hooks are, in run order for a full stack:
        :LOG-SINK-FLUSH (dds-log), :DURABILITY-STORE-SYNC (dds-durability), :DARE-SECRET-WIPE (dds-dare)
        and :PAL-SHM-UNLINK (this file); the exact order is load order, reversed.
     3. FINISH-OUTPUT the standard streams.
     4. Hard exit (%HARD-EXIT): SBCL (sb-ext:exit :code CODE :abort t), AllegroCL
        (excl:exit CODE :no-unwind t :quiet t). Neither waits for, unwinds or joins any other thread, so a
        thread parked in a foreign call cannot hang the exit, which is the defect this replaces: UIOP:QUIT on
        AllegroCL waited forever for such a thread.
   If CODE is 0 but a hook failed or the watchdog fired, the status is +EXIT-SHUTDOWN-INCOMPLETE+ (70,
   EX_SOFTWARE) instead, so an incomplete cleanup (an unwiped key, an unsynced store) cannot report success.

   A second call from ANOTHER thread while the first is running parks that thread; the first one ends the
   process. A recursive call from a hook (the SAME thread) hard-exits at once, skipping the remaining hooks,
   as SB-EXT:EXIT treats a recursive call as an abort. It keeps its own CODE, except that 0 becomes
   +EXIT-SHUTDOWN-INCOMPLETE+: the chain was truncated, so the cleanup is incomplete by construction.

   Not a hot-path function. Lisp code in src/ outside dds-pal/ must exit through this function and never
   through UIOP:QUIT or an implementation's own exit (`make gate-quit-lint`)."
  (let ((me (bordeaux-threads:current-thread)) (first nil) (owner nil))
    (with-lock (*shutdown-hooks-lock*)
      (unless *exit-owner* (setf *exit-owner* me first t))
      (setf owner *exit-owner*))
    (cond
      (first
       (let ((entries (with-lock (*shutdown-hooks-lock*) (copy-list *shutdown-hooks*)))
             (done (make-atomic-cell))
             (clean nil))
         (flet ((finish ()
                  (%flush-standard-streams)
                  (setf (atomic-cell-value done) 1)
                  (%hard-exit (if (and (zerop code) (not clean)) +exit-shutdown-incomplete+ code))))
           (%start-exit-watchdog code *shutdown-hook-timeout-seconds* done)
           ;; The protected form ends in FINISH; the cleanup runs FINISH only when a hook made a non-local
           ;; exit out of the chain (CLEAN is then still NIL, so a requested 0 becomes 70).
           (unwind-protect
                (multiple-value-bind (ran failed) (%run-hook-chain entries *error-output*)
                  (declare (ignore ran))
                  (setf clean (null failed))
                  (finish))
             (finish)))))
      ((eq owner me) (%hard-exit (if (zerop code) +exit-shutdown-incomplete+ code)))
      (t (loop (sleep 1))))))

;;; ---- the PAL's own shutdown hook ----

(defun* %unlink-owned-shm-segments ()
    (function () (integer 0))
  "Shutdown hook :PAL-SHM-UNLINK (ADR 0121): shm_unlink every POSIX shm object this process created and has
   not unlinked (%OWNED-SHM-NAMES), and forget it. Unlinks NAMES only and never unmaps, so a thread still
   using a mapping is unaffected; the kernel frees the object when the last mapping goes, which for this
   process is the exit itself. Without this, a process that exits without its orderly teardown leaves its
   segments in /dev/shm until reboot. Returns the number of names unlinked."
  (let ((n 0))
    (dolist (name (%owned-shm-names) n)
      (shm-destroy name)
      (incf n))))

(register-shutdown-hook :pal-shm-unlink '%unlink-owned-shm-segments)
