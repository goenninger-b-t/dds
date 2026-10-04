;;;; DDS.PAL — is this kernel a real-time (PREEMPT_RT) Linux kernel? (ADR 0125, owner decision D29.)
;;;; Control plane only: read once, when the process arena is initialised, never per sample.
;;;;
;;;; WHY THE PAL. The answer is an OPERATING-SYSTEM fact, and an OS probe belongs behind the PAL so no layer
;;;; above L0 reads /sys or /proc itself (NFR-PORT). The file carries no reader conditional: both evidence
;;;; sources are plain files read with CL:OPEN, identical on SBCL and AllegroCL, and the platform test is
;;;; (member :linux *features*), as in pal-dl.lisp.
;;;;
;;;; THE TWO EVIDENCE SOURCES, read from kernel source on 2026-10-04 (operating contract §4: not from memory).
;;;;
;;;;  1. /sys/kernel/realtime. Defined in kernel/ksysfs.c of the PREEMPT_RT tree
;;;;     (git.kernel.org/pub/scm/linux/kernel/git/rt/linux-stable-rt.git, branches v6.6-rt, v6.12-rt and
;;;;     v6.19.3-rt1 all checked): `#if defined(CONFIG_PREEMPT_RT)` defines realtime_show(), which prints
;;;;     "%d\n" with the constant 1, registered as KERNEL_ATTR_RO(realtime) in kernel_attrs[] under
;;;;     `#ifdef CONFIG_PREEMPT_RT`. So the file EXISTS only on an RT-configured kernel and always reads "1".
;;;;     ⚠️ IT IS NOT IN MAINLINE. torvalds/linux master kernel/ksysfs.c (fetched the same day, VERSION 7,
;;;;     PATCHLEVEL 3, -rc5) has no realtime attribute, although CONFIG_PREEMPT_RT itself has been mainline
;;;;     since v6.12. A mainline kernel built with PREEMPT_RT therefore has NO /sys/kernel/realtime, and
;;;;     testing that file alone would call it non-real-time. Hence source 2.
;;;;
;;;;  2. The kernel's UTS version string, /proc/sys/kernel/version (proc(5): "This file contains a string
;;;;     such as: #5 Wed Feb 25 21:49:24 MET 1998" — the same string uname -v prints). mainline
;;;;     init/Makefile:28-30 sets preempt-flag-$(CONFIG_PREEMPT_RT) := PREEMPT_RT (after PREEMPT and
;;;;     PREEMPT_DYNAMIC, so on an RT kernel the RT token is the one that stands), and :36-38 builds
;;;;     UTS_VERSION as "#<build-version> <SMP> <preempt-flag> <timestamp>", cut to 64 bytes. A whole
;;;;     whitespace-delimited token PREEMPT_RT therefore marks an RT kernel. KBUILD_BUILD_VERSION replaces
;;;;     only the build-version part, not the flag. The 64-byte cut could in principle drop the flag after
;;;;     an extremely long custom build-version; source 1 covers RT-tree kernels in that case, and the
;;;;     override (*static-arena-mode* :fixed) covers everything else.
;;;;     This host (Ubuntu 24.04, 7.0.0-38-generic) reads "#38~24.04.4-Ubuntu SMP PREEMPT_DYNAMIC ..." and
;;;;     has no /sys/kernel/realtime: not real-time, by both sources.
;;;;
;;;; Both inputs are external text, so the parser is bounds-checked (operating contract §4): at most
;;;; +RT-PROBE-MAX-CHARS+ characters are read from either file, and tokenising never indexes past the string.

(in-package #:dds.pal)

(defconstant +rt-probe-max-chars+ 256
  "Upper bound on the characters READ-RT-PROBE-FILE takes from /sys/kernel/realtime or
   /proc/sys/kernel/version. The UTS version is at most 64 bytes (mainline init/Makefile:35 'Maximum length
   of UTS_VERSION is 64 chars') and the sysfs file is \"1\\n\"; the bound only keeps an unexpected file from
   being read without limit.")

(defparameter *rt-sysfs-path* "/sys/kernel/realtime"
  "Path of the PREEMPT_RT tree's realtime attribute (kernel/ksysfs.c, linux-stable-rt v6.6-rt / v6.12-rt /
   v6.19.3-rt1: exists only under CONFIG_PREEMPT_RT, reads \"1\"). A special so a test can point it at a
   fixture; production never rebinds it.")

(defparameter *rt-uts-version-path* "/proc/sys/kernel/version"
  "Path of the kernel's UTS version string (proc(5)); on a PREEMPT_RT kernel it carries the token
   PREEMPT_RT (mainline init/Makefile:30, :37). A special so a test can point it at a fixture.")

(defun* read-rt-probe-file (path)
    (function (string) (or null string))
  "The first at most +RT-PROBE-MAX-CHARS+ characters of the file at PATH, or NIL when it does not exist or
   cannot be read. Never signals. Control plane."
  (ignore-errors
   (with-open-file (in path :direction :input :if-does-not-exist nil)
     (when in
       (let* ((buf (make-string +rt-probe-max-chars+))
              (n (read-sequence buf in)))
         (subseq buf 0 (min n +rt-probe-max-chars+)))))))

(defun* %rt-token-present-p (text token first-only)
    (function (string string t) boolean)
  "True iff TOKEN occurs in TEXT as a whole whitespace-delimited token (so PREEMPT_RTX or XPREEMPT_RT do not
   count). With FIRST-ONLY true, only the first token of TEXT is compared. Bounds-checked: every index stays
   within TEXT."
  (let ((n (length text)) (k (length token)) (start 0))
    (flet ((ws-p (c) (member c '(#\Space #\Tab #\Newline #\Return))))
      (loop
        (loop while (and (< start n) (ws-p (char text start))) do (incf start))
        (when (>= start n) (return nil))
        (let ((end start))
          (loop while (and (< end n) (not (ws-p (char text end)))) do (incf end))
          (when (and (= (- end start) k) (string= text token :start1 start :end1 end))
            (return t))
          (when first-only (return nil))
          (setf start end))))))

(defun* classify-real-time-kernel (linux-p sysfs-text uts-version)
    (function (t (or null string) (or null string)) (values boolean keyword))
  "Pure decision behind REAL-TIME-KERNEL-P, separated so a test can drive every branch with fixture text.
   LINUX-P: whether the platform is Linux. SYSFS-TEXT: the content of /sys/kernel/realtime or NIL if absent.
   UTS-VERSION: the content of /proc/sys/kernel/version or NIL. Returns (VALUES REAL-TIME-P SOURCE):
     T   :SYSFS-REALTIME — the first token of SYSFS-TEXT is \"1\" (PREEMPT_RT tree, kernel/ksysfs.c);
     T   :UTS-VERSION    — UTS-VERSION carries the whole token PREEMPT_RT (mainline init/Makefile:30, :37);
     NIL :NOT-REAL-TIME  — Linux, and neither source says real-time;
     NIL :NOT-LINUX      — not Linux; PREEMPT_RT is a Linux configuration, so the question does not arise.
   A sysfs file that exists but does not read \"1\" is not evidence either way, so the UTS check still runs."
  (cond ((not linux-p) (values nil :not-linux))
        ((and sysfs-text (%rt-token-present-p sysfs-text "1" t))
         (values t :sysfs-realtime))
        ((and uts-version (%rt-token-present-p uts-version "PREEMPT_RT" nil))
         (values t :uts-version))
        (t (values nil :not-real-time))))

(defun* real-time-kernel-p ()
    (function () (values boolean keyword))
  "(VALUES REAL-TIME-P SOURCE): is the running kernel a real-time Linux (PREEMPT_RT) kernel? SOURCE names
   the evidence — :SYSFS-REALTIME (/sys/kernel/realtime reads 1; PREEMPT_RT tree only), :UTS-VERSION (the
   kernel version string carries PREEMPT_RT; mainline and RT tree), :NOT-REAL-TIME or :NOT-LINUX. The
   sources and their kernel-source citations are in this file's header (ADR 0125). Reads two small files;
   never signals; control plane only — dds.core.arena calls it once, when *STATIC-ARENA-MODE* is :AUTO."
  (let ((linux (and (member :linux *features*) t)))
    (if linux
        (classify-real-time-kernel t (read-rt-probe-file *rt-sysfs-path*)
                                   (read-rt-probe-file *rt-uts-version-path*))
        (classify-real-time-kernel nil nil nil))))
