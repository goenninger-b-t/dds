;;;; DDS.PAL — dynamic loader access: open ONE shared object by path and resolve symbols IN THAT OBJECT
;;;; (ADR 0123, WP-0.9). Control plane only: these run when a library is loaded or verified, never per sample.
;;;;
;;;; WHY THE PAL NEEDS THIS. CFFI's FOREIGN-SYMBOL-POINTER takes a :LIBRARY argument and IGNORES it on both
;;;; targets: %FOREIGN-SYMBOL-POINTER declares (ignore library) and looks the name up process-wide —
;;;; SB-SYS:FIND-FOREIGN-SYMBOL-ADDRESS on SBCL (cffi-sbcl.lisp:399-403) and FF:GET-ENTRY-POINT on AllegroCL
;;;; (cffi-allegro.lisp:407-410), read in the installed cffi-20260101-git. So "the symbol from THIS library"
;;;; cannot be expressed through CFFI; with two libcrypto copies mapped, a name lookup returns whichever the
;;;; process-wide scope finds first. dlsym(3) on a dlopen(3) handle searches that object (and its own
;;;; dependencies) only.
;;;;
;;;; Everything here is CFFI + libc, identical on SBCL and AllegroCL, so the file carries no reader
;;;; conditional. Every constant and layout is read from this host's glibc 2.39 headers and confirmed by
;;;; scripts/probes/dlfcn-layout.c (output: RTLD_NOW=2 RTLD_LOCAL=0 RTLD_NOLOAD=4 sizeof_Dl_info=32
;;;; dli_fname=0 dli_fbase=8 dli_sname=16 dli_saddr=24, Linux x86_64).

(in-package #:dds.pal)

(defconstant +rtld-now+ #x00002
  "dlopen(3) mode bit RTLD_NOW: resolve every undefined symbol of the object at load time, so a broken
   library fails at DL-OPEN rather than at its first call. /usr/include/x86_64-linux-gnu/bits/dlfcn.h:25;
   probe scripts/probes/dlfcn-layout.c.")

(defconstant +rtld-local+ 0
  "dlopen(3) mode RTLD_LOCAL: the object's symbols are NOT added to the process-global lookup scope, so a
   library DL-OPEN loads cannot satisfy some other object's references by accident.
   /usr/include/x86_64-linux-gnu/bits/dlfcn.h:38; probe scripts/probes/dlfcn-layout.c.")

(defconstant +dl-info-size+ 32
  "sizeof(Dl_info), the struct dladdr(3) fills: four pointer-sized fields dli_fname, dli_fbase, dli_sname,
   dli_saddr (/usr/include/dlfcn.h:88-94). 32 on LP64 Linux; probe scripts/probes/dlfcn-layout.c.")

(defconstant +dl-info-fname-offset+ 0
  "offsetof(Dl_info, dli_fname): the path of the object containing the queried address
   (/usr/include/dlfcn.h:90). Probe scripts/probes/dlfcn-layout.c.")

(defun* %dlerror-text ()
    (function () (or null string))
  "The pending dlerror(3) message as a fresh string, or NIL when none is pending. dlerror returns a char*
   owned by libc (/usr/include/dlfcn.h:82) that must not be freed; reading it clears it."
  (let ((p (cffi:foreign-funcall "dlerror" :pointer)))
    (if (cffi:null-pointer-p p) nil (cffi:foreign-string-to-lisp p))))

(defun* dl-open (path)
    (function (string) (values t (or null string)))
  "Open the shared object at PATH with dlopen(3), mode RTLD_NOW | RTLD_LOCAL (+RTLD-NOW+, +RTLD-LOCAL+).
   Returns (VALUES HANDLE NIL) on success, HANDLE being the opaque dlopen handle as a foreign pointer, or
   (VALUES NIL REASON) with the dlerror(3) text. Never signals (ADR 0064).

   PATH should be absolute: a name without a slash is searched by the dynamic linker's rules (LD_LIBRARY_PATH,
   the cache, the default directories), which is exactly the ambiguity a caller pinning one file wants to
   avoid. Opening an object that is already loaded returns the existing handle and bumps its reference count;
   glibc identifies an already-loaded object by its name or by device+inode, so the same file opened through
   a different path is the same object, and a DIFFERENT file with the same SONAME is a second, separate copy.
   Control plane; it is not meant to be called per sample."
  (%dlerror-text)                                   ; drop any stale message so REASON is this call's
  (let ((h (cffi:foreign-funcall "dlopen" :string path :int (logior +rtld-now+ +rtld-local+) :pointer)))
    (if (cffi:null-pointer-p h)
        (values nil (or (%dlerror-text) "dlopen failed (no dlerror text)"))
        (values h nil))))

(defun* dl-sym (handle name)
    (function (t string) t)
  "The address of symbol NAME as defined in the object HANDLE (from DL-OPEN) or its own dependencies, via
   dlsym(3) (/usr/include/dlfcn.h:64), as a foreign pointer; NIL when that object does not define NAME. Unlike
   CFFI:FOREIGN-SYMBOL-POINTER, whose :LIBRARY argument both targets ignore, this never answers from another
   object that happens to define the same name. Never signals. Control plane: callers cache the result."
  (%dlerror-text)
  (let ((p (cffi:foreign-funcall "dlsym" :pointer handle :string name :pointer)))
    (if (or (cffi:null-pointer-p p) (%dlerror-text)) nil p)))

(defun* dl-close (handle)
    (function (t) boolean)
  "Release HANDLE (from DL-OPEN) with dlclose(3) (/usr/include/dlfcn.h:60): the object's reference count drops
   and, when it reaches zero, the object is unmapped. T on success, NIL when dlclose reports an error. Use it
   for a handle that was opened and then REJECTED, so a refused library does not stay mapped; never call it on
   a handle whose symbols are still cached. NIL for a NIL HANDLE. Never signals. Control plane."
  (and handle
       (zerop (%sint32 (cffi:foreign-funcall "dlclose" :pointer handle :int)))))

(defun* dl-object-path (address)
    (function (t) (or null string))
  "The file name of the loaded object that contains ADDRESS (a foreign pointer), from dladdr(3)
   (/usr/include/dlfcn.h:98) field dli_fname (+DL-INFO-FNAME-OFFSET+ within a +DL-INFO-SIZE+ Dl_info), or NIL
   when ADDRESS lies in no loaded object. The name is the one the object was loaded under, which may be a
   symlink or a relative name; pass it through REAL-PATH before comparing. Never signals."
  (cffi:with-foreign-object (info :uint8 +dl-info-size+)
    (let ((rc (%sint32 (cffi:foreign-funcall "dladdr" :pointer address :pointer info :int))))
      (if (zerop rc)
          nil
          (let ((fname (cffi:mem-ref info :pointer +dl-info-fname-offset+)))
            (if (cffi:null-pointer-p fname) nil (cffi:foreign-string-to-lisp fname)))))))

(defun* real-path (path)
    (function (string) (or null string))
  "The canonical absolute path of PATH from realpath(3) (/usr/include/stdlib.h:940): every symlink, `.` and
   `..` resolved. NIL when PATH does not exist or cannot be resolved. With a NULL second argument realpath
   mallocs the result, which this frees. The same answer on SBCL and AllegroCL, unlike TRUENAME, whose
   symlink handling is implementation-defined. Never signals."
  (let ((p (cffi:foreign-funcall "realpath" :string path :pointer (cffi:null-pointer) :pointer)))
    (if (cffi:null-pointer-p p)
        nil
        (unwind-protect (cffi:foreign-string-to-lisp p)
          (cffi:foreign-funcall "free" :pointer p :void)))))

(defun* %shared-object-basename-p (base stem)
    (function (string string) boolean)
  "T iff BASE (a file basename) is a shared-object file name of the library STEM: STEM, then a dot, then
   either `so` (Linux: libcrypto.so, libcrypto.so.3), a digit (macOS versioned: libcrypto.3.dylib) or `dylib`
   (macOS unversioned: libcrypto.dylib). A different library whose name merely starts with or contains STEM
   (libcrypto++.so.9, libcryptopp.so, libcrypto-tools.so) is NOT a match."
  (let ((n (length stem)) (m (length base)))
    (and (> m (1+ n))
         (string= stem base :end2 n)
         (char= #\. (char base n))
         (let ((rest (subseq base (1+ n))))
           (or (and (>= (length rest) 2) (string= "so" rest :end2 2))
               (digit-char-p (char rest 0))
               (and (>= (length rest) 5) (string= "dylib" rest :end2 5))))
         t)))

(defun* parse-mapped-object-paths (text stem)
    (function (string string) list)
  "The distinct file paths in TEXT, in /proc/<pid>/maps format (proc(5): address perms offset dev inode
   pathname, one mapping per line), whose BASENAME is a shared-object name of the library STEM (e.g.
   \"libcrypto\": libcrypto.so, libcrypto.so.3, libcrypto.3.dylib — see %SHARED-OBJECT-BASENAME-P; an unrelated
   libcrypto++.so or libcryptopp.so does not count), in first-seen order. A line with no pathname, or a
   pseudo-path such as [heap], is ignored; a trailing \" (deleted)\" marker is dropped so a replaced-on-disk
   library still counts once. Pure, so the counting rule is testable without a process. Every index is bounded
   by the line it reads (the input is kernel text, but a parser of external text is still bounds-checked)."
  (let ((paths '()) (start 0) (n (length text)))
    (loop while (< start n)
          do (let* ((end (or (position #\Newline text :start start) n))
                    (slash (position #\/ text :start start :end end)))
               (when slash
                 (let* ((raw (subseq text slash end))
                        (del (search " (deleted)" raw :from-end t))
                        (path (if (and del (= (+ del 10) (length raw))) (subseq raw 0 del) raw))
                        (base (subseq path (1+ (or (position #\/ path :from-end t) -1)))))
                   (when (%shared-object-basename-p base stem)
                     (pushnew path paths :test #'string=))))
               (setf start (1+ end))))
    (nreverse paths)))

(defun* mapped-object-paths (stem)
    (function (string) (values list boolean boolean))
  "(VALUES PATHS READABLE-P REQUIRED-P): the distinct files mapped into THIS process that are shared objects of
   the library STEM (e.g. \"libcrypto\"; the name rule is PARSE-MAPPED-OBJECT-PATHS'), read from /proc/self/maps
   (proc(5)). The kernel prints the path of the mapped FILE, symlinks already resolved, so two entries are two
   different files. READABLE-P is NIL (and PATHS NIL) where /proc/self/maps cannot be read. REQUIRED-P is T on
   a platform where procfs is part of the contract (Linux, proc(5)), so an unreadable maps file there is a
   fault a caller must refuse on, and NIL where the platform has no /proc/self/maps at all (macOS), so the
   caller can only record that the count was not taken. The platform decision lives here, in the PAL, so no
   caller tests *FEATURES* itself. Never signals."
  (let ((required (and (member :linux *features*) t))
        (text (ignore-errors
               (with-open-file (in "/proc/self/maps" :direction :input)
                 (with-output-to-string (out)
                   (loop for line = (read-line in nil nil) while line
                         do (write-line line out)))))))
    (if text
        (values (parse-mapped-object-paths text stem) t required)
        (values nil nil required))))
