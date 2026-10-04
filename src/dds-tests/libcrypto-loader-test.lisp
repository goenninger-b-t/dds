;;;; ADR 0123 — the fail-closed libcrypto loader (WP-0.9).
;;;;
;;;;  run-libcrypto-loader-test            IN PROCESS: the /proc/self/maps counting rule on synthetic text; a
;;;;                                       pinned path that does not exist, that is not a shared object, or
;;;;                                       that is a shared object without OpenSSL_version_num is REJECTED and
;;;;                                       nothing falls back; dladdr placing the symbol in another file is
;;;;                                       rejected; and the accepted library is the one every symbol box uses.
;;;;  run-libcrypto-preload-rejection-test ONE CHILD PROCESS of this same Lisp started with LD_PRELOAD of the
;;;;                                       system libcrypto while DDS_DARE_LIBCRYPTO pins another file: the
;;;;                                       child's loader must report :MULTIPLE-LIBCRYPTO.
;;;;  run-libcrypto-rejected-refusal-test  ONE CHILD PROCESS whose DDS_DARE_LIBCRYPTO names a file that does not
;;;;                                       exist: a DARE primitive, the encrypted-store constructor and the
;;;;                                       durability service with a DARE-wrapped backend must each REFUSE
;;;;                                       cleanly; nothing may jump through a NULL function pointer.

(in-package #:dds.tests)

(defun* %libc-path ()
    (function () (or null string))
  "realpath of the object that defines realpath(3) in this process, i.e. libc: a shared object that exists on
   every supported host and certainly does not define OpenSSL_version_num."
  (let ((p (cffi:foreign-symbol-pointer "realpath")))
    (and p (let ((obj (dds.pal:dl-object-path p))) (and obj (dds.pal:real-path obj))))))

(defun* run-libcrypto-loader-test ()
    (function () (eql t))
  "ADR 0123, in process. (1) DDS.PAL:PARSE-MAPPED-OBJECT-PATHS counts distinct FILES whose basename contains
   the needle: a path repeated over several mappings counts once, a ' (deleted)' marker is dropped, a
   directory named libcrypto does not count, pseudo-paths and anonymous mappings are ignored. (2) A pinned
   DDS_DARE_LIBCRYPTO that does not exist, or names a file dlopen refuses, is :PINNED-UNLOADABLE with no
   handle; a real shared object that is not libcrypto (libc) is :SYMBOL-MISSING with no handle. (3) With a
   libcrypto loaded, %VERIFY-LIBCRYPTO against the wrong expected file is :SYMBOL-OUTSIDE. (4) When the
   loader accepted a library, OpenSSL_version_num resolved by dlsym on *LIBCRYPTO* is the pointer in its
   %OSSL-SYM box, dladdr places it in *LIBCRYPTO-PATH*, a pinned path is that very file, and exactly one
   libcrypto is mapped. None of this mutates the loader's recorded state."
  ;; (1) the counting rule
  (let* ((maps (format nil "~{~a~%~}"
                       '("7f0000000000-7f0000001000 r--p 00000000 08:01 1234 /usr/lib/x86_64-linux-gnu/libcrypto.so.3"
                         "7f0000001000-7f0000002000 r-xp 00001000 08:01 1234 /usr/lib/x86_64-linux-gnu/libcrypto.so.3"
                         "7f0000002000-7f0000003000 r--p 00000000 08:01 99 /home/u/.local/opt/openssl-3.5/lib64/libcrypto.so.3 (deleted)"
                         "7f0000003000-7f0000004000 r--p 00000000 08:01 77 /opt/libcrypto-tools/lib/libz.so.1"
                         "7f0000006000-7f0000007000 r--p 00000000 08:01 55 /usr/lib/x86_64-linux-gnu/libcrypto++.so.8"
                         "7f0000007000-7f0000008000 r--p 00000000 08:01 56 /usr/lib/x86_64-linux-gnu/libcryptopp.so.8"
                         "7f0000008000-7f0000009000 r--p 00000000 08:01 57 /opt/x/lib/libcrypto-tools.so"
                         "7f0000009000-7f000000a000 r--p 00000000 08:01 58 /opt/homebrew/lib/libcrypto.3.dylib"
                         "7f0000004000-7f0000005000 rw-p 00000000 00:00 0 [heap]"
                         "7f0000005000-7f0000006000 rw-p 00000000 00:00 0")))
         (got (dds.pal:parse-mapped-object-paths maps "libcrypto")))
    (%check :maps-count-rule
            (equal got '("/usr/lib/x86_64-linux-gnu/libcrypto.so.3"
                         "/home/u/.local/opt/openssl-3.5/lib64/libcrypto.so.3"
                         "/opt/homebrew/lib/libcrypto.3.dylib"))
            (format nil "three distinct libcrypto FILES expected, deleted marker stripped, directory names and ~
                         other libraries whose name starts with libcrypto (libcrypto++, libcryptopp, ~
                         libcrypto-tools) ignored; got ~s" got))
    (%check :maps-empty (null (dds.pal:parse-mapped-object-paths "" "libcrypto"))
            "empty maps text must yield no paths"))
  (multiple-value-bind (paths readable) (dds.pal:mapped-object-paths "libcrypto")
    (declare (ignore paths))
    (%check :maps-readable (or readable (not (member :linux *features*)))
            "/proc/self/maps must be readable on Linux"))
  ;; (2) pinned rejections, nothing falls back
  (let ((before (multiple-value-list (dds.dare:libcrypto-status))))
    (multiple-value-bind (h path status) (dds.dare::%open-libcrypto "/nonexistent/neodds/libcrypto.so.3")
      (declare (ignore path))
      (%check :pinned-missing (and (null h) (eq status :pinned-unloadable))
              (format nil "a missing pinned file must be :PINNED-UNLOADABLE with no handle; got ~s ~s" h status)))
    (let ((not-elf (namestring (asdf:system-relative-pathname :dds-tests "src/dds-tests/libcrypto-loader-test.lisp"))))
      (multiple-value-bind (h path status detail) (dds.dare::%open-libcrypto not-elf)
        (declare (ignore path))
        (%check :pinned-not-elf (and (null h) (eq status :pinned-unloadable))
                (format nil "a pinned file dlopen refuses must be :PINNED-UNLOADABLE with no handle; got ~s ~s ~a"
                        h status detail))))
    (let ((libc (%libc-path)))
      (%check :libc-found libc "dladdr must name the object that defines realpath(3)")
      (multiple-value-bind (h path status) (dds.dare::%open-libcrypto libc)
        (%check :pinned-not-libcrypto (and (null h) (eq status :symbol-missing) (equal path libc))
                (format nil "a pinned shared object without OpenSSL_version_num must be :SYMBOL-MISSING with no handle; got ~s ~s ~s"
                        h status path))))
    (%check :loader-state-untouched (equal before (multiple-value-list (dds.dare:libcrypto-status)))
            "%OPEN-LIBCRYPTO must not change the recorded loader state; only %LOAD-LIBCRYPTO does"))
  ;; (3) + (4) the accepted library
  (multiple-value-bind (status path detail pinned) (dds.dare:libcrypto-status)
    (if (not (eq status :ok))
        (note-skip "libcrypto-loader: accepted-library checks" :libcrypto
                   (format nil "no libcrypto accepted (~(~a~)~@[: ~a~])" status detail) :scope :arm)
        (let* ((sym (dds.pal:dl-sym dds.dare::*libcrypto* "OpenSSL_version_num"))
               (box (svref (dds.dare::%ossl-sym-box "OpenSSL_version_num") 0)))
          (%check :dlsym-is-box (and sym box (cffi:pointer-eq sym box))
                  (format nil "the OpenSSL_version_num box must hold dlsym on *LIBCRYPTO*; dlsym ~s box ~s" sym box))
          (%check :dladdr-inside (equal (dds.pal:real-path (dds.pal:dl-object-path sym)) path)
                  (format nil "dladdr must place OpenSSL_version_num inside ~a" path))
          (when pinned
            (%check :pinned-is-path (equal (dds.pal:real-path (uiop:getenv "DDS_DARE_LIBCRYPTO")) path)
                    (format nil "the accepted library ~a must be the pinned DDS_DARE_LIBCRYPTO file" path)))
          (%check :one-mapping (equal (dds.pal:mapped-object-paths "libcrypto") (list path))
                  (format nil "exactly one libcrypto, ~a, must be mapped; maps show ~s"
                          path (dds.pal:mapped-object-paths "libcrypto")))
          (let ((libc (%libc-path)))
            (%check :symbol-outside-rejected
                    (eq :symbol-outside (dds.dare::%verify-libcrypto dds.dare::*libcrypto* libc))
                    "verifying the accepted handle against the WRONG expected file must be :SYMBOL-OUTSIDE")))))
  t)

(defun* run-libcrypto-preload-rejection-test ()
    (function () (eql t))
  "ADR 0123 falsifier, in a child of this same Lisp (DDS.PAL:LISP-EVAL-COMMAND) started as
   `env LD_PRELOAD=libcrypto.so.3 <lisp> ...` while DDS_DARE_LIBCRYPTO (inherited) pins another file. ld.so
   resolves the bare preload name by its standard search (ld.so(8), LD_PRELOAD), i.e. to the SYSTEM
   libcrypto, before the Lisp starts; the child then loads :DDS-DARE and reports LIBCRYPTO-STATUS and the
   mapped libcrypto files. With two files mapped the status must be :MULTIPLE-LIBCRYPTO and the child exits 3.
   Not applicable, and recorded as a skip, when nothing is pinned or when the preload resolves to the pinned
   file itself (then only one file is mapped and there is nothing to reject). The child never outlives the test."
  (multiple-value-bind (status path) (dds.dare:libcrypto-status)
    (declare (ignore path))
    (unless (and (eq status :ok) (nth-value 3 (dds.dare:libcrypto-status)))
      (note-skip "libcrypto-preload-rejection" :libcrypto
                 "DDS_DARE_LIBCRYPTO does not pin an accepted libcrypto (source scripts/openssl-env.sh): nothing to defend")
      (return-from run-libcrypto-preload-rejection-test t)))
  (let* ((dir (uiop:ensure-directory-pathname
               (merge-pathnames (format nil "dds-libcrypto-test-~d/" (dds.pal:process-id))
                                (uiop:temporary-directory))))
         (out (merge-pathnames "preload.out" dir))
         (err (merge-pathnames "preload.err" dir))
         (lisp (dds.pal:lisp-eval-command
                (list "(require :asdf)"
                      "(asdf:load-system :dds-dare)"
                      "(let ((s (multiple-value-list (dds.dare:libcrypto-status)))) (format t \"~&LIBCRYPTO-STATUS ~s~%LIBCRYPTO-MAPPED ~s~%\" (first s) (dds.pal:mapped-object-paths \"libcrypto\")) (finish-output) (dds.pal:exit-process (if (eq (first s) :multiple-libcrypto) 3 4)))"))))
    (%check :preload-child-command lisp "this image must be able to launch a child of itself")
    (ensure-directories-exist dir)
    (let ((p (uiop:launch-program (append (list "env" "LD_PRELOAD=libcrypto.so.3") lisp)
                                  :output out :if-output-exists :supersede
                                  :error-output err :if-error-output-exists :supersede))
          (deadline (+ (get-internal-real-time) (* 300 internal-time-units-per-second))))
      (unwind-protect
           (progn
             (loop while (and (uiop:process-alive-p p) (< (get-internal-real-time) deadline))
                   do (sleep 0.2))
             (%check :preload-child-ended (not (uiop:process-alive-p p))
                     "the LD_PRELOAD child must finish within 300 s")
             (let* ((code (uiop:wait-process p))
                    (text (or (ignore-errors (uiop:read-file-string out)) ""))
                    (etext (or (ignore-errors (uiop:read-file-string err)) ""))
                    (sp (search "LIBCRYPTO-STATUS " text))
                    (mp (search "LIBCRYPTO-MAPPED " text))
                    (child-status (and sp (ignore-errors (let ((*package* (find-package :keyword)))
                                                           (read-from-string text t nil :start (+ sp 17))))))
                    (mapped (and mp (ignore-errors (read-from-string text t nil :start (+ mp 17))))))
               (%check :preload-child-reported (and sp mp)
                       (format nil "the child must report its loader status; exit ~s~%stdout:~%~a~%stderr:~%~a" code text etext))
               (if (< (length mapped) 2)
                   (note-skip "libcrypto-preload-rejection" :libcrypto
                              (format nil "LD_PRELOAD=libcrypto.so.3 resolved to the pinned file itself (~s): no second copy to reject" mapped))
                   (progn
                     (%check :preload-rejected (eq child-status :multiple-libcrypto)
                             (format nil "with ~d libcrypto files mapped (~s) the loader must answer :MULTIPLE-LIBCRYPTO; got ~s"
                                     (length mapped) mapped child-status))
                     (%check :preload-exit-code (eql code 3)
                             (format nil "the rejecting child must exit 3; got ~s~%stderr:~%~a" code etext))))))
        (when (uiop:process-alive-p p)
          (ignore-errors (uiop:terminate-process p :urgent t))
          (ignore-errors (uiop:wait-process p)))
        (ignore-errors (uiop:delete-directory-tree dir :validate t)))))
  t)

(defun* run-libcrypto-rejected-refusal-test ()
    (function () (eql t))
  "ADR 0123 falsifier for the REJECTED state, in a child of this same Lisp (DDS.PAL:LISP-EVAL-COMMAND) started
   as `env DDS_DARE_LIBCRYPTO=/nonexistent/... <lisp> ...`. The child loads :DDS-DURABILITY and reports
   (1) LIBCRYPTO-STATUS, which must be :PINNED-UNLOADABLE; (2) the capability DARE-AVAILABLE-P names, which
   must be :LIBCRYPTO; (3) DDS.DARE:SHA-384 on three octets, which must REFUSE with the loader's error (a
   memory fault through a NULL function pointer is what this test exists to rule out); (4) the encrypted-store
   constructor (make-encrypted-store over a memory store with a file key provider), which must refuse the same
   way; (5) DURABILITY-SERVICE-MAIN with --backend file (the DARE-wrapped PERSISTENT tier) and BLOCK NIL, whose
   start status must be :SERVICE-START-FAILED. All five as expected => exit 3. The parent also requires that
   the child's output carries no CORRUPTION WARNING and no memory-fault report. Independent of the parent's
   own pin, so it runs in pinned and unpinned runs alike. The child never outlives the test."
  (let* ((dir (uiop:ensure-directory-pathname
               (merge-pathnames (format nil "dds-libcrypto-refuse-~d/" (dds.pal:process-id))
                                (uiop:temporary-directory))))
         (out (merge-pathnames "refuse.out" dir))
         (err (merge-pathnames "refuse.err" dir))
         (root (namestring dir))
         (probe (format nil "(let* ((root ~s)
                  (refusal (lambda (thunk)
                             (handler-case (progn (funcall thunk) :returned)
                               (error (c) (let ((text (princ-to-string c)))
                                            (if (search \"is unavailable: libcrypto\" text) :refused (list :other text)))))))
                  (status (dds.dare:libcrypto-status))
                  (cap (nth-value 2 (dds.dare:dare-available-p)))
                  (sha (funcall refusal (lambda () (dds.dare:sha-384 (make-array 3 :element-type (quote (unsigned-byte 8)) :initial-element 0)))))
                  (store (funcall refusal (lambda () (dds.durability:make-encrypted-store
                                                      (dds.durability:make-memory-store)
                                                      (dds.dare:make-file-key-provider :dir (concatenate (quote string) root \"kp/\"))))))
                  (svc (nth-value 1 (dds.durability:durability-service-main
                                     :argv (list \"--backend\" \"file\" \"--dir\" (concatenate (quote string) root \"data/\")
                                                 \"--key-dir\" (concatenate (quote string) root \"keys/\")
                                                 \"--topic\" \"RefuseSquare:ShapeType\" \"--name\" \"refuse-test\")
                                     :env (quote ()) :block nil)))
                  (got (list status cap sha store svc)))
             (format t \"~~&REFUSE-RESULT ~~s~~%\" got)
             (finish-output)
             (dds.pal:exit-process (if (equal got (quote (:pinned-unloadable :libcrypto :refused :refused :service-start-failed))) 3 4)))"
                        root))
         (lisp (dds.pal:lisp-eval-command
                (list "(require :asdf)" "(asdf:load-system :dds-durability)" probe))))
    (%check :refuse-child-command lisp "this image must be able to launch a child of itself")
    (ensure-directories-exist dir)
    (let ((p (uiop:launch-program (append (list "env" "DDS_DARE_LIBCRYPTO=/nonexistent/neodds/libcrypto.so.3") lisp)
                                  :output out :if-output-exists :supersede
                                  :error-output err :if-error-output-exists :supersede))
          (deadline (+ (get-internal-real-time) (* 300 internal-time-units-per-second))))
      (unwind-protect
           (progn
             (loop while (and (uiop:process-alive-p p) (< (get-internal-real-time) deadline))
                   do (sleep 0.2))
             (%check :refuse-child-ended (not (uiop:process-alive-p p))
                     "the refusal child must finish within 300 s")
             (let* ((code (uiop:wait-process p))
                    (text (or (ignore-errors (uiop:read-file-string out)) ""))
                    (etext (or (ignore-errors (uiop:read-file-string err)) ""))
                    (rp (search "REFUSE-RESULT " text))
                    (got (and rp (ignore-errors (let ((*package* (find-package :keyword)))
                                                  (read-from-string text t nil :start (+ rp 14)))))))
               (%check :refuse-child-reported rp
                       (format nil "the child must report its results; exit ~s~%stdout:~%~a~%stderr:~%~a" code text etext))
               (%check :refuse-no-memory-fault
                       (not (or (search "CORRUPTION WARNING" text) (search "CORRUPTION WARNING" etext)
                                (search "Memory fault" text) (search "Memory fault" etext)
                                (search "memory fault" text) (search "memory fault" etext)))
                       (format nil "a rejected libcrypto must refuse, never fault through NULL~%stdout:~%~a~%stderr:~%~a"
                               text etext))
               (%check :refuse-status (eq (first got) :pinned-unloadable)
                       (format nil "a nonexistent pinned file must be :PINNED-UNLOADABLE; got ~s" got))
               (%check :refuse-capability (eq (second got) :libcrypto)
                       (format nil "DARE-AVAILABLE-P must name the :LIBCRYPTO capability; got ~s" got))
               (%check :refuse-primitive (eq (third got) :refused)
                       (format nil "SHA-384 must refuse with the loader's error; got ~s" got))
               (%check :refuse-store (eq (fourth got) :refused)
                       (format nil "the encrypted-store constructor must refuse with the loader's error; got ~s" got))
               (%check :refuse-service (eq (fifth got) :service-start-failed)
                       (format nil "the durability service with a DARE backend must fail its start; got ~s" got))
               (%check :refuse-exit-code (eql code 3)
                       (format nil "the refusing child must exit 3; got ~s~%stderr:~%~a" code etext))))
        (when (uiop:process-alive-p p)
          (ignore-errors (uiop:terminate-process p :urgent t))
          (ignore-errors (uiop:wait-process p)))
        (ignore-errors (uiop:delete-directory-tree dir :validate t)))))
  t)
