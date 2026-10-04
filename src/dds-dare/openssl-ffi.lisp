(in-package #:dds.dare)

;;; OpenSSL libcrypto CFFI bindings for DDS.DARE (Task 1: SHA-384, HKDF-SHA384).
;;;
;;; Host: OpenSSL 3.6.2 7 Apr 2026, dylib = /opt/homebrew/opt/openssl@3/lib/libcrypto.dylib
;;; OPENSSLDIR: /opt/homebrew/etc/openssl@3
;;;
;;; Pinned signatures (verified against installed headers, /opt/homebrew/opt/openssl@3/include/openssl/):
;;;
;;;   EVP_Q_digest(OSSL_LIB_CTX *libctx, const char *name, const char *propq,
;;;                const void *data, size_t datalen,
;;;                unsigned char *md, size_t *mdlen)  -> int (1=ok, <=0 error)
;;;     Source: evp.h line 744 (OpenSSL 3.6.2)
;;;
;;;   EVP_Q_mac(OSSL_LIB_CTX *libctx, const char *name, const char *propq,
;;;             const char *subalg, const OSSL_PARAM *params,
;;;             const void *key, size_t keylen,
;;;             const unsigned char *data, size_t datalen,
;;;             unsigned char *out, size_t outsize, size_t *outlen) -> uchar* (NULL=error)
;;;     One-shot MAC (analogue of EVP_Q_digest); HMAC-SHA256 = name "HMAC", subalg "SHA256".
;;;     Source: evp.h line 1271 (OpenSSL 3.6.2)
;;;
;;;   EVP_KDF_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
;;;                 const char *properties) -> EVP_KDF* (NULL on error)
;;;   EVP_KDF_free(EVP_KDF *kdf)  -> void
;;;   EVP_KDF_CTX_new(EVP_KDF *kdf) -> EVP_KDF_CTX* (NULL on error)
;;;   EVP_KDF_CTX_free(EVP_KDF_CTX *ctx) -> void
;;;   EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen,
;;;                  const OSSL_PARAM params[]) -> int (1=ok, <=0 error)
;;;     Source: kdf.h lines 29-45 (OpenSSL 3.6.2)
;;;
;;;   OpenSSL_version_num(void) -> unsigned long
;;;     Encoding: (major<<28)|(minor<<20)|(patch<<4)|status; release=0xf.
;;;     3.6.2 release -> 0x3060002f (confirmed via `python3 -c "print(hex((3<<28)|(6<<20)|(2<<4)|0xf))"`)
;;;     Source: crypto.h line 181 (OpenSSL 3.6.2)
;;;
;;;   EVP_KEM_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
;;;                 const char *properties) -> EVP_KEM* (NULL on error)
;;;   EVP_KEM_free(EVP_KEM *wrap) -> void
;;;     Source: evp.h lines 1994-1997 (OpenSSL 3.6.2)
;;;
;;; OSSL_PARAM struct layout (verified via C offsetof on arm64-macOS, sizeof=40; re-verified on Linux x86_64
;;; against the OpenSSL 3.5.9 <openssl/core.h> struct ossl_param_st, lines 85-91, by scripts/probes/
;;; ossl-param-layout.c, which scripts/build-openssl.sh runs on every install: "sizeof=40 key=0 data_type=8
;;; data=16 data_size=24 return_size=32 INTEGER=1 UNSIGNED_INTEGER=2 UTF8_STRING=4 OCTET_STRING=5"):
;;;   +0  key          : const char*  (8 bytes)
;;;   +8  data_type    : unsigned int (4 bytes) + 4 bytes padding
;;;   +16 data         : void*        (8 bytes)
;;;   +24 data_size    : size_t       (8 bytes)
;;;   +32 return_size  : size_t       (8 bytes)
;;; OSSL_PARAM data type constants (core.h §95–160):
;;;   OSSL_PARAM_UTF8_STRING = 4, OSSL_PARAM_OCTET_STRING = 5
;;; OSSL_PARAM_END sentinel: key=NULL, all zeros.

;;; --- libcrypto loading: fail-closed when pinned (ADR 0123, WP-0.9) ---
;;;
;;; WHICH libcrypto, and proof that it is the one in use. Three facts shape this:
;;;  1. CFFI cannot pin a library: FOREIGN-SYMBOL-POINTER's :LIBRARY is ignored on both targets
;;;     (cffi-sbcl.lisp:399-403, cffi-allegro.lisp:407-410), so a by-name lookup answers from the process-wide
;;;     scope — whichever libcrypto the loader met first. Symbols are therefore resolved with DDS.PAL:DL-SYM on
;;;     the handle DDS.PAL:DL-OPEN returned for the chosen file.
;;;  2. Two libcrypto copies in one process are not safe even with the right handle: a dlopen()ed object's
;;;     own PLT references are bound through the global scope first, so the pinned copy's internal calls can
;;;     land in a system copy that LD_PRELOAD or an earlier load put there. So a load is accepted only when
;;;     /proc/self/maps shows exactly ONE libcrypto file (DDS.PAL:MAPPED-OBJECT-PATHS).
;;;  3. A pinned path that fails must never degrade to "whatever libcrypto.so.3 resolves to": that is how a
;;;     run on the system 3.0 library looked like a run on 3.5. With DDS_DARE_LIBCRYPTO set, the ONLY
;;;     candidate is that file.
;;; A rejection is a STATUS (ADR 0064 forbids a signal here), held in *LIBCRYPTO-STATUS*: *LIBCRYPTO* stays
;;; NIL, every OpenSSL symbol box stays NIL, DARE-AVAILABLE-P answers NIL with the reason, and the test
;;; harness fails the run before its first test (dds.tests::%libcrypto-preflight-failure).
;;;
;;; Candidates when DDS_DARE_LIBCRYPTO is unset or empty, in order: the Homebrew realpaths
;;; /opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib, /usr/local/opt/openssl@3/lib/libcrypto.3.dylib,
;;; /opt/homebrew/lib/libcrypto.3.dylib (macOS), then the loader names libcrypto.so.3 and libcrypto.so (Linux).
;;; Whatever is found is verified the same way (symbol inside the opened file, one libcrypto mapped).

(defvar *libcrypto* nil
  "The dlopen(3) handle (a foreign pointer, from DDS.PAL:DL-OPEN) of the ONE libcrypto that DARE and
   DDS-Security call, or NIL when none was accepted. Every OpenSSL symbol is resolved IN THIS OBJECT with
   DDS.PAL:DL-SYM (%OSSL-SYM-BOX), never by a process-wide name lookup. Set at load and again by the image-restart
   hook %DARE-RERESOLVE-FOREIGN-POINTERS; NIL whenever *LIBCRYPTO-STATUS* is not :OK (ADR 0123).")

(defvar *libcrypto-path* nil
  "realpath(3) of the libcrypto file *LIBCRYPTO* refers to, or of the pinned file that was rejected; NIL when
   no candidate was found. Diagnostic; read through LIBCRYPTO-STATUS.")

(defvar *libcrypto-status* :absent
  "Outcome of the last libcrypto load (ADR 0123), one of:
     :OK                  a libcrypto was opened and verified; *LIBCRYPTO* is its handle.
     :ABSENT              DDS_DARE_LIBCRYPTO is unset and no candidate could be opened (not a rejection:
                          nothing was configured and nothing is there).
     :PINNED-UNLOADABLE   DDS_DARE_LIBCRYPTO names a file that does not exist or that dlopen(3) refuses.
     :SYMBOL-MISSING      the opened file does not define OpenSSL_version_num, so it is not libcrypto.
     :SYMBOL-OUTSIDE      dladdr(3) places OpenSSL_version_num in a different file than the one opened.
     :MULTIPLE-LIBCRYPTO  /proc/self/maps shows more than one libcrypto file mapped into the process.
     :MAPS-UNREADABLE     /proc/self/maps cannot be read on Linux, so the single-copy rule cannot be checked.
   Every value except :OK and :ABSENT is a REJECTION: the library is not used and nothing falls back.")

(defvar *libcrypto-detail* nil
  "Human-readable detail for *LIBCRYPTO-STATUS* (the dlerror text, the offending paths, ...), or NIL.")

(defvar *libcrypto-pinned-p* nil
  "T iff the last load was pinned by a non-empty DDS_DARE_LIBCRYPTO, i.e. the only candidate was that file.")

(defun* libcrypto-status ()
    (function () (values keyword (or null string) (or null string) boolean))
  "(VALUES STATUS PATH DETAIL PINNED-P) of the libcrypto DARE loaded (ADR 0123). STATUS is *LIBCRYPTO-STATUS*:
   :OK, :ABSENT, or a rejection (:PINNED-UNLOADABLE :SYMBOL-MISSING :SYMBOL-OUTSIDE :MULTIPLE-LIBCRYPTO
   :MAPS-UNREADABLE). PATH is the realpath of the accepted or rejected file, DETAIL the reason text, PINNED-P
   T iff the environment variable DDS_DARE_LIBCRYPTO pinned the file. A caller that must not run on the wrong
   library tests STATUS for :OK; a rejection never falls back to another copy, so :OK means the pinned file
   (when PINNED-P) or the first verified candidate (when not)."
  (values *libcrypto-status* *libcrypto-path* *libcrypto-detail* *libcrypto-pinned-p*))

(defun* %libcrypto-candidates ()
    (function () list)
  "The unpinned search list (used only when DDS_DARE_LIBCRYPTO is unset or empty): the Homebrew absolute
   paths that exist, then the loader names libcrypto.so.3 and libcrypto.so."
  (append (remove-if-not #'probe-file '("/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib"
                                         "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib"
                                         "/opt/homebrew/lib/libcrypto.3.dylib"))
          (list "libcrypto.so.3" "libcrypto.so")))

(defun* %verify-libcrypto (handle expected)
    (function (t (or null string)) (values keyword (or null string) (or null string)))
  "Check that HANDLE is the one libcrypto in this process (ADR 0123). Returns (VALUES STATUS PATH DETAIL):
   STATUS :OK or a rejection keyword (see *LIBCRYPTO-STATUS*); PATH the realpath of the file that defines
   OpenSSL_version_num. Checks, in order: (1) DDS.PAL:DL-SYM finds OpenSSL_version_num in HANDLE;
   (2) dladdr(3) puts that address inside EXPECTED (a realpath) when EXPECTED is given; (3) /proc/self/maps
   lists exactly one libcrypto file, and it is PATH. Whether procfs is part of the platform contract is the
   PAL's answer (DDS.PAL:MAPPED-OBJECT-PATHS, third value): where it is not (macOS) check (3) is skipped and
   DETAIL says so; where it is (Linux) an unreadable maps file is itself a rejection. The caller (%OPEN-LIBCRYPTO)
   releases HANDLE with DDS.PAL:DL-CLOSE on any rejection."
  (let* ((sym (dds.pal:dl-sym handle "OpenSSL_version_num"))
         (obj (and sym (dds.pal:dl-object-path sym)))
         (path (and obj (dds.pal:real-path obj))))
    (cond ((null sym)
           (values :symbol-missing expected "the opened object does not define OpenSSL_version_num"))
          ((null path)
           (values :symbol-outside expected "dladdr could not name the object containing OpenSSL_version_num"))
          ((and expected (string/= path expected))
           (values :symbol-outside path
                   (format nil "OpenSSL_version_num resolves in ~a, not in the opened ~a" path expected)))
          (t
           (multiple-value-bind (mapped readable required) (dds.pal:mapped-object-paths "libcrypto")
             (cond ((and (not readable) required)
                    (values :maps-unreadable path "cannot read /proc/self/maps to count libcrypto copies"))
                   ((not readable)
                    (values :ok path "single-copy check skipped: no /proc/self/maps on this platform"))
                   ((/= 1 (length mapped))
                    (values :multiple-libcrypto path
                            (format nil "~d libcrypto mappings: ~{~a~^, ~}" (length mapped) mapped)))
                   ((string/= (first mapped) path)
                    (values :symbol-outside path
                            (format nil "the one mapped libcrypto is ~a, not ~a" (first mapped) path)))
                   (t (values :ok path nil))))))))

(defun* %open-libcrypto (&optional (pinned (uiop:getenv "DDS_DARE_LIBCRYPTO")))
    (function (&optional (or null string)) (values t (or null string) keyword (or null string) boolean))
  "Open and verify the libcrypto DARE will use (ADR 0123). Returns (VALUES HANDLE PATH STATUS DETAIL PINNED-P);
   HANDLE is NIL unless STATUS is :OK. Never signals (ADR 0064).
   PINNED (default: the DDS_DARE_LIBCRYPTO environment variable) non-empty: that file is the ONLY candidate.
   A missing or unopenable file is :PINNED-UNLOADABLE, a failed check is its rejection keyword, and nothing
   else is tried. Empty or unset: the %LIBCRYPTO-CANDIDATES are tried in order; the first one that opens is
   verified and accepted or rejected, and the search does not continue past a rejection either. A handle that
   was opened and then rejected is released with DDS.PAL:DL-CLOSE, so the refused file does not stay mapped
   (when another reference holds it, dlclose only drops this one)."
  (if (and pinned (plusp (length pinned)))
      (let ((real (dds.pal:real-path pinned)))
        (if (null real)
            (values nil nil :pinned-unloadable (format nil "DDS_DARE_LIBCRYPTO=~a does not exist" pinned) t)
            (multiple-value-bind (h err) (dds.pal:dl-open real)
              (if (null h)
                  (values nil real :pinned-unloadable (format nil "dlopen ~a: ~a" real err) t)
                  (multiple-value-bind (status path detail) (%verify-libcrypto h real)
                    (unless (eq status :ok) (dds.pal:dl-close h))   ; a refused library does not stay mapped
                    (values (and (eq status :ok) h) (or path real) status detail t))))))
      (dolist (candidate (%libcrypto-candidates)
                         (values nil nil :absent "no libcrypto candidate could be opened" nil))
        (let ((h (dds.pal:dl-open candidate)))
          (when h
            (multiple-value-bind (status path detail) (%verify-libcrypto h nil)
              (unless (eq status :ok) (dds.pal:dl-close h))
              (return (values (and (eq status :ok) h) path status detail nil))))))))

(defun* %load-libcrypto ()
    (function () t)
  "Run %OPEN-LIBCRYPTO and record its outcome in *LIBCRYPTO*, *LIBCRYPTO-PATH*, *LIBCRYPTO-STATUS*,
   *LIBCRYPTO-DETAIL* and *LIBCRYPTO-PINNED-P*. Returns the handle or NIL. Called at load and by the
   image-restart hook."
  (multiple-value-bind (h path status detail pinned) (%open-libcrypto)
    (setf *libcrypto* h
          *libcrypto-path* path
          *libcrypto-status* status
          *libcrypto-detail* detail
          *libcrypto-pinned-p* pinned)
    h))

(eval-when (:load-toplevel :execute)
  (%load-libcrypto))

;;; %ossl-sym resolves an OpenSSL symbol to a cached foreign function pointer. To survive a DUMPED IMAGE
;;; (save-lisp-and-die), the pointer is NOT stored directly in a per-call-site (load-time-value … t): that value is
;;; frozen into the image and CANNOT be re-resolved after libcrypto is re-mapped at a new address on image restart,
;;; so the first AEAD/X.509 call after restart would dereference a dangling pointer. Instead each NAME resolves to a
;;; shared MUTABLE 1-slot box, interned once in *OSSL-SYM-BOXES*; every call site caches the BOX (stable identity) in
;;; a load-time-value and reads slot 0 per call. The image-restart hook %DARE-RERESOLVE-FOREIGN-POINTERS re-resolves
;;; every box IN PLACE, so all call sites see live pointers after restart. Per-call cost is one SVREF — no measurable
;;; change vs the prior direct load-time-value, and still zero cons. (ADR 0038/0039 saved-image residual.)
(defvar *ossl-sym-boxes* (make-hash-table :test 'equal)
  "NAME (string) -> a mutable 1-slot (simple-vector 1) box holding NAME's address in *LIBCRYPTO* (%LIBCRYPTO-SYM) for
   NAME (NIL when unresolved). All %ossl-sym call sites for a NAME share ONE box; the boxes are interned at load
   (each call site's load-time-value evaluates %OSSL-SYM-BOX) and re-resolved IN PLACE by %DARE-RERESOLVE-FOREIGN-
   POINTERS at image restart, so a dumped image (save-lisp-and-die) re-populates every cached EVP/X.509 pointer
   rather than dereferencing a dangling one. See %OSSL-SYM for the save-lisp-and-die contract.")

(defun* %libcrypto-sym (name)
    (function (string) t)
  "NAME resolved IN *LIBCRYPTO* (DDS.PAL:DL-SYM on its handle, ADR 0123), or NIL when no libcrypto was
   accepted or it does not define NAME. Never a process-wide lookup, so a second libcrypto copy cannot answer."
  (and *libcrypto* (dds.pal:dl-sym *libcrypto* name)))

(defun* %ossl-sym-box (name)
    (function (string) simple-vector)
  "Return the shared mutable 1-slot box for the libcrypto symbol NAME, interning + resolving it once in
   *OSSL-SYM-BOXES*. Slot 0 holds (%LIBCRYPTO-SYM NAME) — dlsym on the *LIBCRYPTO* handle — or NIL when no
   libcrypto was accepted; it is re-resolved in place by the image-restart hook. Called at LOAD time from each
   %ossl-sym call site's load-time-value (so the box exists before any AEAD/X.509 call), never on the per-call path."
  (or (gethash name *ossl-sym-boxes*)
      (setf (gethash name *ossl-sym-boxes*)
            (vector (%libcrypto-sym name)))))

(defun* %libcrypto-unavailable (name)
    (function (string) nil)
  "Refuse a call to OpenSSL function NAME because its %OSSL-SYM box is empty: no libcrypto was accepted (the
   loader rejected a pinned or found library, ADR 0123, or none exists) or the accepted one lacks NAME. Signals
   an ERROR naming NAME and LIBCRYPTO-STATUS instead of letting the call site jump through a NULL function
   pointer (a memory fault that leaves the image's integrity in doubt). Reached only through %OSSL-SYM, never
   when the library was accepted and defines NAME, so it costs nothing on a working system."
  ;; NOCOND(CRYPTO-FFI): libcrypto unusable (loader rejected it or symbol absent, ADR 0123); cannot fire with an accepted libcrypto; contained in dds-dare like every other CRYPTO-FFI fault
  (error "libcrypto function ~a is unavailable: libcrypto ~(~a~)~@[ (~a)~]~@[: ~a~]; DARE refuses (ADR 0123)"
         name *libcrypto-status* *libcrypto-path* *libcrypto-detail*))

(defmacro %ossl-sym (name)
  "Cached function pointer for OpenSSL symbol NAME, resolved through a re-resolvable box (%OSSL-SYM-BOX) so the cache
   survives a DUMPED IMAGE (save-lisp-and-die): the per-call-site load-time-value caches the shared BOX (stable
   identity) and slot 0 — re-resolved at image restart by %DARE-RERESOLVE-FOREIGN-POINTERS — carries the live pointer.
   An EMPTY box (no libcrypto accepted, ADR 0123) never reaches the call: %LIBCRYPTO-UNAVAILABLE refuses with an
   error instead of a jump through NULL. One SVREF and one NIL test per call (zero cons)."
  `(or (svref (load-time-value (%ossl-sym-box ,name) nil) 0)
       (%libcrypto-unavailable ,name)))

(defmacro %ossl-sym-or-nil (name)
  "Like %OSSL-SYM but answers NIL for an empty box instead of refusing: for the capability PROBES
   (DARE-AVAILABLE-P, the test preflight) whose job is to report a missing symbol as a status, never to call it.
   Every other call site uses %OSSL-SYM. Same shared box, same zero-cons read."
  `(svref (load-time-value (%ossl-sym-box ,name) nil) 0))

;;; --- version gate ---

;; ADR 0064: the DARE-UNAVAILABLE condition is GONE — dare-available-p returns (VALUES AVAILABLE REASON)
;; instead of signalling; the crypto capability probe fails CLOSED by returning NIL, never a plaintext fallback.

(defun* dare-available-p ()
    (function () (values boolean (or null string) (or null (member :libcrypto :openssl-pqc))))
  "Return (VALUES AVAILABLE REASON CAPABILITY): AVAILABLE is T iff libcrypto is loaded, OpenSSL_version_num
   >= 3.5.0, and ML-KEM-1024 is fetchable from the default provider (FIPS 203, CNSA 2.0 requirement); REASON
   is NIL then, or a human-readable string naming why DARE is unavailable; CAPABILITY is NIL then, or the
   missing capability in the ADR 0122 skip vocabulary: :LIBCRYPTO when no libcrypto was accepted (none
   found, or the loader REJECTED one — a pinned DDS_DARE_LIBCRYPTO that cannot be opened, a symbol outside
   the opened file, more than one libcrypto mapped; REASON then carries LIBCRYPTO-STATUS, ADR 0123), :OPENSSL-PQC when a libcrypto is loaded but is older than 3.5.0 or cannot
   fetch ML-KEM-1024 (or lacks EVP_KEM_fetch). A two-value caller is unaffected by the third value.
   ADR 0064: the crypto capability probe fails CLOSED by RETURNING NIL (never a DARE-UNAVAILABLE signal,
   never a plaintext fallback) — a caller checks AVAILABLE and, on NIL, skips/refuses with REASON. The one
   boundary handler-case catches CFFI's own load-foreign-library-error (an external library condition) and
   folds it to the REASON string; since ADR 0123 the loader opens libcrypto with DDS.PAL:DL-OPEN, which
   returns a status, so that clause is a defensive remainder."
  (handler-case
      (progn
        (unless *libcrypto*
          (return-from dare-available-p
            (values nil (format nil "libcrypto not loaded: ~(~a~)~@[ (~a)~]~@[: ~a~]"
                                *libcrypto-status* *libcrypto-path* *libcrypto-detail*)
                    :libcrypto)))
        (let* ((ver-ptr (%ossl-sym-or-nil "OpenSSL_version_num"))
               (ver (if ver-ptr
                        (cffi:foreign-funcall-pointer ver-ptr nil :unsigned-long)
                        (return-from dare-available-p
                          (values nil "OpenSSL_version_num symbol not found" :libcrypto)))))
          ;; 3.5.0 dev threshold = 0x30500000; any release of 3.5+ is >= 0x3050000f
          (unless (>= ver #x30500000)
            (return-from dare-available-p
              (values nil (format nil "OpenSSL version 0x~8,'0x < 3.5.0 (0x30500000)" ver) :openssl-pqc)))
          (let* ((kem-fetch-ptr (%ossl-sym-or-nil "EVP_KEM_fetch"))
                 (kem (if kem-fetch-ptr
                          (cffi:foreign-funcall-pointer kem-fetch-ptr nil
                                                        :pointer (cffi:null-pointer)
                                                        :string "ML-KEM-1024"
                                                        :pointer (cffi:null-pointer)
                                                        :pointer)
                          (return-from dare-available-p
                            (values nil "EVP_KEM_fetch symbol not found" :openssl-pqc)))))
            (if (cffi:null-pointer-p kem)
                (return-from dare-available-p
                  (values nil "ML-KEM-1024 not fetchable from default provider" :openssl-pqc))
                (progn
                  (cffi:foreign-funcall-pointer (%ossl-sym "EVP_KEM_free") nil
                                                :pointer kem :void)
                  (values t nil nil))))))
    (cffi:load-foreign-library-error (e)
      (values nil (format nil "libcrypto load failed: ~a" e) :libcrypto))))

;;; --- internal helpers ---

(defun* %ascii (s)
    (function (string) (simple-array (unsigned-byte 8) (*)))
  "Convert ASCII string S to an octet vector (test helper; no Unicode support needed)."
  (let* ((n (length s))
         (v (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n v)
      (setf (aref v i) (char-code (char s i))))))

;;; OSSL_PARAM builder — constructs a flat foreign array of OSSL_PARAM structs.
;;; Each slot is 40 bytes (C offsetof on arm64-macOS, and on Linux x86_64 against OpenSSL 3.5.9 core.h).
;;; Layout per slot: key(8) data_type(4) pad(4) data(8) data_size(8) return_size(8).

(defconstant +ossl-param-size+ 40)
(defconstant +ossl-param-data-type-integer+ 1)           ; OSSL_PARAM_INTEGER (core.h line 103) — signed int BN
(defconstant +ossl-param-data-type-unsigned-integer+ 2)  ; OSSL_PARAM_UNSIGNED_INTEGER (core.h line 107) — BN "priv"
(defconstant +ossl-param-data-type-utf8-string+ 4)       ; OSSL_PARAM_UTF8_STRING (core.h line 117)
(defconstant +ossl-param-data-type-octet-string+ 5)      ; OSSL_PARAM_OCTET_STRING (core.h line 123)

(defun* %set-ossl-param-slot (base idx key-ptr data-type data-ptr data-size)
    (function (cffi:foreign-pointer fixnum cffi:foreign-pointer fixnum cffi:foreign-pointer fixnum) t)
  "Write one OSSL_PARAM slot at BASE + IDX*40 bytes. Offsets key 0, data_type 8, data 16, data_size 24,
   return_size 32: verified by offsetof on arm64-macOS and on Linux x86_64 against OpenSSL 3.5.9 core.h
   (scripts/probes/ossl-param-layout.c, run by scripts/build-openssl.sh)."
  (let ((p (cffi:inc-pointer base (* idx +ossl-param-size+))))
    (setf (cffi:mem-ref p :pointer 0)  key-ptr)
    (setf (cffi:mem-ref p :uint32 8)   data-type)
    (setf (cffi:mem-ref p :pointer 16) data-ptr)
    (setf (cffi:mem-ref p :size 24)    data-size)
    (setf (cffi:mem-ref p :size 32)    0))
  t)

(defun* %set-ossl-param-end (base idx)
    (function (cffi:foreign-pointer fixnum) t)
  "Write the OSSL_PARAM_END sentinel (all-zero 40-byte slot) at BASE + IDX*40."
  (let ((p (cffi:inc-pointer base (* idx +ossl-param-size+))))
    (dotimes (i +ossl-param-size+)
      (setf (cffi:mem-ref p :uint8 i) 0)))
  t)

;;; EVP_CIPHER bindings for AES-256-GCM (Task 2).
;;;
;;; Pinned signatures (verified against /opt/homebrew/opt/openssl@3/include/openssl/evp.h):
;;;
;;;   EVP_CIPHER_CTX_new(void) -> EVP_CIPHER_CTX*        (evp.h line 921)
;;;   EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c) -> void     (evp.h line 923)
;;;   EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type,
;;;                        int arg, void *ptr) -> int     (evp.h line 926)
;;;   EVP_aes_256_gcm(void) -> const EVP_CIPHER*         (evp.h line 1104)
;;;   EVP_EncryptInit_ex(EVP_CIPHER_CTX*, const EVP_CIPHER*,
;;;                       ENGINE*, const uchar* key,
;;;                       const uchar* iv) -> int (1=ok) (evp.h line 780)
;;;   EVP_EncryptUpdate(EVP_CIPHER_CTX*, uchar* out, int* outl,
;;;                      const uchar* in, int inl) -> int (evp.h line 788)
;;;   EVP_EncryptFinal_ex(EVP_CIPHER_CTX*, uchar* out,
;;;                        int* outl) -> int              (evp.h line 790)
;;;   EVP_DecryptInit_ex(EVP_CIPHER_CTX*, const EVP_CIPHER*,
;;;                       ENGINE*, const uchar* key,
;;;                       const uchar* iv) -> int (1=ok) (evp.h line 797)
;;;   EVP_DecryptUpdate(EVP_CIPHER_CTX*, uchar* out, int* outl,
;;;                      const uchar* in, int inl) -> int (evp.h line 805)
;;;   EVP_DecryptFinal_ex(EVP_CIPHER_CTX*, uchar* out,
;;;                        int* outl) -> int (<=0=auth fail) (evp.h line 809)
;;;
;;; GCM ctrl constants (evp.h lines 388–394, via AEAD aliases):
;;;   EVP_CTRL_GCM_SET_IVLEN = EVP_CTRL_AEAD_SET_IVLEN = 0x9
;;;   EVP_CTRL_GCM_GET_TAG   = EVP_CTRL_AEAD_GET_TAG   = 0x10
;;;   EVP_CTRL_GCM_SET_TAG   = EVP_CTRL_AEAD_SET_TAG   = 0x11

(defconstant +gcm-ctrl-set-ivlen+ #x09  "EVP_CTRL_GCM_SET_IVLEN (evp.h, via AEAD_SET_IVLEN=0x9).")
(defconstant +gcm-ctrl-get-tag+   #x10  "EVP_CTRL_GCM_GET_TAG (evp.h, via AEAD_GET_TAG=0x10).")
(defconstant +gcm-ctrl-set-tag+   #x11  "EVP_CTRL_GCM_SET_TAG (evp.h, via AEAD_SET_TAG=0x11).")
(defconstant +aes-256-gcm-key-len+  32  "AES-256 key length in octets (FIPS 197 §5).")
(defconstant +aes-gcm-nonce-len+    12  "GCM standard 96-bit (12-byte) nonce (SP 800-38D §5.2.1.1).")
(defconstant +aes-gcm-tag-len+      16  "GCM authentication tag length in octets (128-bit, SP 800-38D §5.2.1.2).")

;;; Cached null pointer — (cffi:null-pointer) conses ~16 B per call; this load-time singleton is 0-cons
;;; at every :pointer-NULL argument site on the AEAD hot path (null is address 0, so it is reload-stable).
(defvar *%null-ptr* (cffi:null-pointer)
  "Cached CFFI null pointer for OpenSSL :pointer NULL arguments on the zero-alloc AEAD hot path.
   Read once into a boxed singleton so passing NULL to FOREIGN-FUNCALL-POINTER conses 0 B/call
   (vs ~16 B for a fresh (cffi:null-pointer)). Null is address 0, so the cached value is image-reload-safe.")

;;; EVP_aes_256_gcm() returns a const static EVP_CIPHER* — cache the handle once at load time.
(defvar *%aes-256-gcm-cipher* nil
  "Cached EVP_aes_256_gcm() cipher singleton (const static EVP_CIPHER*, evp.h line 1104, OpenSSL 3.6.2).
   Resolved once at load time after *LIBCRYPTO* is set. Valid for the lifetime of *LIBCRYPTO*.")

(eval-when (:load-toplevel :execute)
  (when *libcrypto*
    (setf *%aes-256-gcm-cipher*
          (cffi:foreign-funcall-pointer
           (%libcrypto-sym "EVP_aes_256_gcm")
           nil :pointer))))

;;; --- saved-image (save-lisp-and-die) foreign-pointer re-resolution (ADR 0038/0039 residual, resolved) ---
;;; All libcrypto pointers DARE caches — the %ossl-sym boxes (every EVP/X.509 function pointer) and the
;;; EVP_aes_256_gcm() cipher singleton — are resolved ONCE at load and frozen into a dumped image; *%null-ptr*
;;; is address 0 (reload-stable) so it needs no re-resolution. On image restart libcrypto is re-mapped at a new
;;; address, so the frozen pointers dangle. This hook (registered via the portable dds.pal seam) re-opens
;;; *libcrypto* and re-resolves every box + the cipher IN PLACE at startup, before any AEAD/X.509 call.

(defun* %dare-reresolve-foreign-pointers ()
    (function () (eql t))
  "Re-resolve every cached libcrypto foreign pointer after an image restart (save-lisp-and-die). Re-opens
   *LIBCRYPTO* through %LOAD-LIBCRYPTO — the same fail-closed, verified load as at load time (ADR 0123), so a
   restarted image whose pinned library has gone missing ends up with *LIBCRYPTO* NIL and a rejection status,
   never with a fallback copy — then re-resolves every %OSSL-SYM box in *OSSL-SYM-BOXES* IN PLACE (so all EVP/X.509 call sites see
   the live pointer) and *%AES-256-GCM-CIPHER*; *%NULL-PTR* is address 0 (reload-stable) and is intentionally left
   as-is. Registered as an image-restart hook (dds.pal:register-image-restart-hook) at DARE load, so the FIRST
   AEAD/X.509 call after a dumped core restarts uses live pointers, not dangling ones. Idempotent; when no
   libcrypto is accepted every box and the cipher become NIL. §5.1 save-lisp-and-die contract: any build that dumps a core carrying
   dds.dare (e.g. a delivered durability-service executable, operating contract §1) has this hook, so it re-resolves crypto
   on startup instead of the latent dangling-pointer AEAD call this residual described."
  (%load-libcrypto)
  ;; Every box is rewritten, also when the reload was rejected: %LIBCRYPTO-SYM answers NIL without a handle,
  ;; so a rejected restart CLEARS the pointers the dumped image carried instead of leaving them dangling.
  (maphash (lambda (name box)
             (setf (svref box 0) (%libcrypto-sym name)))
           *ossl-sym-boxes*)
  (setf *%aes-256-gcm-cipher*
        (let ((fp (%libcrypto-sym "EVP_aes_256_gcm")))
          (and fp (cffi:foreign-funcall-pointer fp nil :pointer))))
  t)

(eval-when (:load-toplevel :execute)
  (dds.pal:register-image-restart-hook '%dare-reresolve-foreign-pointers))

;;; EVP_PKEY KEM bindings for ML-KEM-1024 (Task 3).
;;;
;;; Pinned signatures (verified against /opt/homebrew/opt/openssl@3/include/openssl/evp.h,
;;; OpenSSL 3.6.2 7 Apr 2026; man pages EVP_PKEY_encapsulate(3), EVP_PKEY_decapsulate(3),
;;; EVP_PKEY-ML-KEM(7), EVP_KEM-ML-KEM-1024(7)):
;;;
;;;   EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx, const char *name,
;;;                               const char *propquery) -> EVP_PKEY_CTX*  (evp.h line 1887)
;;;   EVP_PKEY_CTX_new_from_pkey(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
;;;                               const char *propquery) -> EVP_PKEY_CTX*  (evp.h line 1890)
;;;   EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx) -> void                         (evp.h line 1893)
;;;   EVP_PKEY_free(EVP_PKEY *pkey) -> void                                 (evp.h line 1440)
;;;   EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx) -> int (1=ok)                (evp.h line 2119)
;;;   EVP_PKEY_generate(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey) -> int (1=ok) (evp.h line 2121)
;;;   EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey,
;;;                                unsigned char *pub, size_t *len) -> int  (evp.h line 1937)
;;;     For ML-KEM-1024: len = 1568 (ek, FIPS-203 Table 2, confirmed via C oracle)
;;;   EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey,
;;;                                 unsigned char *priv, size_t *len) -> int (evp.h line 1935)
;;;     For ML-KEM-1024: len = 3168 (dk, FIPS-203 Table 2, confirmed via C oracle)
;;;   EVP_PKEY_new_raw_public_key_ex(OSSL_LIB_CTX *libctx, const char *keytype,
;;;                                   const char *propq,
;;;                                   const unsigned char *key, size_t keylen)
;;;                                   -> EVP_PKEY*                         (evp.h line 1929)
;;;   EVP_PKEY_new_raw_private_key_ex(OSSL_LIB_CTX *libctx, const char *keytype,
;;;                                    const char *propq,
;;;                                    const unsigned char *key, size_t keylen)
;;;                                    -> EVP_PKEY*                        (evp.h line 1922)
;;;   EVP_PKEY_encapsulate_init(EVP_PKEY_CTX *ctx,
;;;                              const OSSL_PARAM params[]) -> int (1=ok)  (evp.h line 2064)
;;;   EVP_PKEY_encapsulate(EVP_PKEY_CTX *ctx,
;;;                         unsigned char *wrappedkey, size_t *wrappedkeylen,
;;;                         unsigned char *genkey, size_t *genkeylen) -> int (evp.h line 2067)
;;;     wrappedkey = ML-KEM ciphertext c (1568 bytes); genkey = shared secret K (32 bytes).
;;;     NULL/NULL first call queries sizes; non-NULL second call fills buffers.
;;;   EVP_PKEY_decapsulate_init(EVP_PKEY_CTX *ctx,
;;;                              const OSSL_PARAM params[]) -> int (1=ok)  (evp.h line 2070)
;;;   EVP_PKEY_decapsulate(EVP_PKEY_CTX *ctx,
;;;                         unsigned char *unwrapped, size_t *unwrappedlen,
;;;                         const unsigned char *wrapped, size_t wrappedlen) -> int (evp.h line 2073)
;;;     unwrapped = shared secret K; wrapped = ML-KEM ciphertext c.
;;;
;;; ML-KEM-1024 sizes (FIPS-203 Aug 2024, Table 2; confirmed via C oracle on OpenSSL 3.6.2):
;;;   Public key ek: 1568 bytes   Private key dk: 3168 bytes
;;;   Ciphertext c:  1568 bytes   Shared secret K: 32 bytes

(defconstant +ml-kem-1024-pub-len+   1568 "ML-KEM-1024 public key (ek) size in octets (FIPS-203 Table 2).")
(defconstant +ml-kem-1024-priv-len+  3168 "ML-KEM-1024 private key (dk) size in octets (FIPS-203 Table 2).")
(defconstant +ml-kem-1024-ct-len+    1568 "ML-KEM-1024 ciphertext (c) size in octets (FIPS-203 Table 2).")
(defconstant +ml-kem-1024-ss-len+      32 "ML-KEM-1024 shared secret (K) size in octets (FIPS-203 Table 2).")

;;; X.509 / EVP_PKEY primitives for DDS-Security 1.1 §8.7 Authentication plugin (Auth T1).
;;;
;;; All function pointers resolved via (%ossl-sym ...) on *LIBCRYPTO* — the same handle-based
;;; pattern as Task 1-3 (collision-safe against a different resident libcrypto).
;;;
;;; Signatures verified against installed OpenSSL 3.6.2 headers:
;;;   /opt/homebrew/opt/openssl@3/include/openssl/{pem.h,x509.h,x509_vfy.h,evp.h}
;;;   C compilation of verification oracle confirmed no warnings (arm64-macOS 2026-06-23).
;;;
;;;   BIO_new_mem_buf(const void *buf, int len) -> BIO*   (bio.h line 783)
;;;   BIO_free(BIO *a) -> int                             (bio.h line 733)
;;;
;;;   PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u) -> X509*
;;;     (pem.h DECLARE_PEM_rw(X509, X509) -> PEM_read_cb_fnsig -> pem.h lines 75-77)
;;;   X509_free(X509 *a) -> void                          (x509.h — OPENSSL_sk_free family)
;;;
;;;   X509_STORE_new(void) -> X509_STORE*                 (x509_vfy.h line 516)
;;;   X509_STORE_free(X509_STORE *xs) -> void             (x509_vfy.h line 517)
;;;   X509_STORE_add_cert(X509_STORE *xs, X509 *x) -> int (x509_vfy.h line 712)
;;;
;;;   X509_STORE_CTX_new(void) -> X509_STORE_CTX*         (x509_vfy.h line 585)
;;;   X509_STORE_CTX_free(X509_STORE_CTX *ctx) -> void    (x509_vfy.h line 589)
;;;   X509_STORE_CTX_init(X509_STORE_CTX*, X509_STORE*, X509*, NULL) -> int (x509_vfy.h line 590)
;;;   X509_verify_cert(X509_STORE_CTX *ctx) -> int (>0=ok) (x509_vfy.h line 246)
;;;
;;;   X509_get_subject_name(const X509 *a) -> X509_NAME*  (x509.h line 857)
;;;   X509_NAME_oneline(const X509_NAME*, char *buf, int size) -> char* (x509.h line 816)
;;;     When buf=NULL + size=0, OpenSSL allocates the string; caller must OPENSSL_free it.
;;;   CRYPTO_free(void *ptr, const char *file, int line) -> void
;;;     OPENSSL_free(ptr) expands to CRYPTO_free(ptr,__FILE__,__LINE__); call directly with
;;;     NULL file / 0 line to avoid needing compile-time macros.
;;;
;;;   X509_get_pubkey(X509 *x) -> EVP_PKEY*               (x509.h line 886)
;;;   EVP_PKEY_free(EVP_PKEY *pkey) -> void               (evp.h line 1440)
;;;   EVP_PKEY_get_id(const EVP_PKEY *pkey) -> int        (evp.h line 1364)
;;;     EVP_PKEY_RSA = NID_rsaEncryption = 6  (obj_mac.h line 543)
;;;     EVP_PKEY_EC  = NID_X9_62_id_ecPublicKey = 408 (obj_mac.h line 178)
;;;
;;;   PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u) -> EVP_PKEY*
;;;     (pem.h DECLARE_PEM_rw_cb macro, same cb pattern)

(defconstant +evp-pkey-nid-rsa+  6
  "NID_rsaEncryption = EVP_PKEY_RSA (obj_mac.h line 543 / evp.h line 63, OpenSSL 3.6.2).")
(defconstant +evp-pkey-nid-ec+   408
  "NID_X9_62_id_ecPublicKey = EVP_PKEY_EC (obj_mac.h line 178 / evp.h line 73, OpenSSL 3.6.2).")

;;; --- X.509 / PEM load primitives ---

;;; d2i_X509(X509 **a, const unsigned char **pp, long length) -> X509* (x509.h, OpenSSL 3.6.2).
;;; DER-decode an X509 certificate from a raw DER buffer (as produced by i2d_X509 / x509-to-der).

(defun* x509-load-cert-der (der-octets)
    (function ((simple-array (unsigned-byte 8) (*))) (or cffi:foreign-pointer null))
  "Load an X.509 certificate from DER-OCTETS via d2i_X509 (x509.h, OpenSSL 3.6.2).
   Returns a foreign X509* pointer (caller MUST release via X509-FREE) or NIL on failure.
   Use this instead of X509-LOAD-CERT when the cert bytes are DER (from X509-TO-DER)."
  (let* ((n (length der-octets)))
    (cffi:with-foreign-pointer (buf n)
      (dotimes (i n)
        (setf (cffi:mem-aref buf :uint8 i) (aref der-octets i)))
      (cffi:with-foreign-pointer (pp (cffi:foreign-type-size :pointer))
        (setf (cffi:mem-ref pp :pointer) buf)
        (let ((cert (cffi:foreign-funcall-pointer (%ossl-sym "d2i_X509") nil
                                                   :pointer (cffi:null-pointer)
                                                   :pointer pp
                                                   :long n
                                                   :pointer)))
          (if (cffi:null-pointer-p cert) nil cert))))))

(defun* x509-load-cert (pem-octets)
    (function ((simple-array (unsigned-byte 8) (*))) (or cffi:foreign-pointer null))
  "Load an X.509 certificate from PEM-OCTETS via PEM_read_bio_X509 over a mem BIO.
   Returns a foreign X509* pointer (caller MUST release via X509-FREE) or NIL on failure.
   No GC heap allocation; the BIO and cert are OpenSSL-internal foreign objects."
  (let* ((n (length pem-octets)))
    (cffi:with-foreign-pointer (buf n)
      (dotimes (i n)
        (setf (cffi:mem-aref buf :uint8 i) (aref pem-octets i)))
      (let ((bio (cffi:foreign-funcall-pointer (%ossl-sym "BIO_new_mem_buf") nil
                                               :pointer buf :int n :pointer)))
        (when (cffi:null-pointer-p bio)
          (return-from x509-load-cert nil))
        (unwind-protect
             (let ((cert (cffi:foreign-funcall-pointer (%ossl-sym "PEM_read_bio_X509") nil
                                                       :pointer bio
                                                       :pointer (cffi:null-pointer)
                                                       :pointer (cffi:null-pointer)
                                                       :pointer (cffi:null-pointer)
                                                       :pointer)))
               (if (cffi:null-pointer-p cert) nil cert))
          (cffi:foreign-funcall-pointer (%ossl-sym "BIO_free") nil :pointer bio :int))))))

(defun* x509-to-pem (cert)
    (function (cffi:foreign-pointer) (or (simple-array (unsigned-byte 8) (*)) null))
  "PEM-encode X509* CERT via PEM_write_bio_X509 over a mem BIO (pem.h, OpenSSL 3.6.2).
   Returns the '-----BEGIN CERTIFICATE-----' PEM octets (fresh heap vector) or NIL on failure.
   This is the DDS-Security 1.1 §9.3.2.1 c.id credential form a conformant peer expects:
   corroborated against Fast DDS store_certificate_in_buffer (PEM_write_bio_X509) which fills
   the c.id binary-property + load_certificate (PEM_read_bio_X509_AUX) which reads it. Reads the
   BIO back via BIO_ctrl/BIO_CTRL_INFO=3 (bio.h:92 / BIO_get_mem_data macro bio.h:615)."
  (let ((bio (cffi:foreign-funcall-pointer
               (%ossl-sym "BIO_new") nil
               :pointer (cffi:foreign-funcall-pointer (%ossl-sym "BIO_s_mem") nil :pointer)
               :pointer)))
    (when (cffi:null-pointer-p bio) (return-from x509-to-pem nil))
    (unwind-protect
         (let ((wc (cffi:foreign-funcall-pointer (%ossl-sym "PEM_write_bio_X509") nil
                                                  :pointer bio :pointer cert :int)))
           (unless (= wc 1) (return-from x509-to-pem nil))
           (cffi:with-foreign-pointer (dptr (cffi:foreign-type-size :pointer))
             (let ((len (cffi:foreign-funcall-pointer (%ossl-sym "BIO_ctrl") nil
                                                       :pointer bio
                                                       :int 3        ; BIO_CTRL_INFO (bio.h:92)
                                                       :long 0
                                                       :pointer dptr
                                                       :long)))
               (when (<= len 0) (return-from x509-to-pem nil))
               (let* ((ptr (cffi:mem-ref dptr :pointer))
                      (out (make-array len :element-type '(unsigned-byte 8))))
                 (dotimes (j len out)
                   (setf (aref out j) (cffi:mem-aref ptr :uint8 j)))))))
      (cffi:foreign-funcall-pointer (%ossl-sym "BIO_free") nil :pointer bio :int))))

(defun* x509-load-cert-auto (octets)
    (function ((simple-array (unsigned-byte 8) (*))) (or cffi:foreign-pointer null))
  "Load an X.509 certificate from OCTETS in EITHER PEM or DER form (decode-tolerant).
   Tries PEM first (X509-LOAD-CERT / PEM_read_bio_X509 — the DDS-Security §9.3.2.1 c.id wire
   form emitted by Fast DDS and by our own X509-TO-PEM), then falls back to DER (X509-LOAD-CERT-DER
   / d2i_X509) so a legacy DER-bearing peer is not falsely rejected. Returns a foreign X509*
   (caller MUST X509-FREE) or NIL if neither parses. Fail-closed: NIL on any malformed input."
  (or (x509-load-cert octets)
      (x509-load-cert-der octets)))

(defun* x509-free (cert)
    (function ((or cffi:foreign-pointer null)) t)
  "Release an X509* handle returned by X509-LOAD-CERT (X509_free, x509.h)."
  (when (and cert (not (cffi:null-pointer-p cert)))
    (cffi:foreign-funcall-pointer (%ossl-sym "X509_free") nil :pointer cert :void))
  t)

(defun* x509-load-ca (ca-pem-octets)
    (function ((simple-array (unsigned-byte 8) (*))) (or cffi:foreign-pointer null))
  "Load a CA certificate into an X509_STORE trust store from CA-PEM-OCTETS.
   Returns a foreign X509_STORE* pointer (caller MUST release via X509-CA-FREE) or NIL.
   Uses X509_STORE_new + X509_STORE_add_cert (x509_vfy.h); stores keep the cert ref."
  (let ((ca-cert (x509-load-cert ca-pem-octets)))
    (unless ca-cert (return-from x509-load-ca nil))
    (unwind-protect
         (let ((store (cffi:foreign-funcall-pointer (%ossl-sym "X509_STORE_new") nil :pointer)))
           (when (cffi:null-pointer-p store)
             (return-from x509-load-ca nil))
           (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "X509_STORE_add_cert") nil
                                                   :pointer store :pointer ca-cert :int)))
             (if (= rc 1)
                 store
                 (progn (cffi:foreign-funcall-pointer (%ossl-sym "X509_STORE_free") nil
                                                      :pointer store :void)
                        nil))))
      (x509-free ca-cert))))

(defun* x509-ca-free (store)
    (function ((or cffi:foreign-pointer null)) t)
  "Release an X509_STORE* returned by X509-LOAD-CA (X509_STORE_free, x509_vfy.h line 517)."
  (when (and store (not (cffi:null-pointer-p store)))
    (cffi:foreign-funcall-pointer (%ossl-sym "X509_STORE_free") nil :pointer store :void))
  t)

(defun* x509-verify-chain (ca-store cert)
    (function (cffi:foreign-pointer cffi:foreign-pointer) boolean)
  "Verify CERT (X509*) against CA-STORE (X509_STORE*) via X509_STORE_CTX.
   Returns T if chain verifies; NIL on any error or verification failure (fail-closed).
   Uses X509_STORE_CTX_new/init/X509_verify_cert/free (x509_vfy.h lines 585/590/246/589)."
  (let ((ctx (cffi:foreign-funcall-pointer (%ossl-sym "X509_STORE_CTX_new") nil :pointer)))
    (when (cffi:null-pointer-p ctx)
      (return-from x509-verify-chain nil))
    (unwind-protect
         (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "X509_STORE_CTX_init") nil
                                                 :pointer ctx
                                                 :pointer ca-store
                                                 :pointer cert
                                                 :pointer (cffi:null-pointer)
                                                 :int)))
           (if (= rc 1)
               (= 1 (cffi:foreign-funcall-pointer (%ossl-sym "X509_verify_cert") nil
                                                   :pointer ctx :int))
               nil))
      (cffi:foreign-funcall-pointer (%ossl-sym "X509_STORE_CTX_free") nil :pointer ctx :void))))

(defun* x509-subject-name (cert)
    (function (cffi:foreign-pointer) (or string null))
  "Extract the subject-name string from CERT (X509*) via X509_get_subject_name + X509_NAME_oneline.
   Returns the /CN=.../O=... string (OpenSSL one-line format) or NIL on error.
   The OpenSSL-allocated C string is copied into a Lisp string then freed via CRYPTO_free."
  (let ((name (cffi:foreign-funcall-pointer (%ossl-sym "X509_get_subject_name") nil
                                             :pointer cert :pointer)))
    (when (cffi:null-pointer-p name) (return-from x509-subject-name nil))
    (let ((str-ptr (cffi:foreign-funcall-pointer (%ossl-sym "X509_NAME_oneline") nil
                                                 :pointer name
                                                 :pointer (cffi:null-pointer)
                                                 :int 0
                                                 :pointer)))
      (when (cffi:null-pointer-p str-ptr) (return-from x509-subject-name nil))
      (unwind-protect
           (cffi:foreign-string-to-lisp str-ptr)
        (cffi:foreign-funcall-pointer (%ossl-sym "CRYPTO_free") nil
                                      :pointer str-ptr
                                      :pointer (cffi:null-pointer)
                                      :int 0
                                      :void)))))

(defun* x509-subject-name-sha256 (cert)
    (function (cffi:foreign-pointer) (or (simple-array (unsigned-byte 8) (32)) null))
  "SHA-256 of CERT's DER-encoded subject name via X509_NAME_digest(X509_get_subject_name(cert),
   EVP_sha256()) (OpenSSL 3.6.2). Returns a fresh 32-octet vector or NIL on error. This is the digest
   the DDS-Security 1.1 §9.3.2.1 authenticated-participant GUID prefix is derived from (the identical
   digest a conformant replier recomputes when it checks the c.pdata participant_key's 47 bits)."
  (let ((name (cffi:foreign-funcall-pointer (%ossl-sym "X509_get_subject_name") nil
                                             :pointer cert :pointer)))
    (when (cffi:null-pointer-p name) (return-from x509-subject-name-sha256 nil))
    (let ((md (cffi:foreign-funcall-pointer (%ossl-sym "EVP_sha256") nil :pointer)))
      (when (cffi:null-pointer-p md) (return-from x509-subject-name-sha256 nil))
      (cffi:with-foreign-pointer (out 32)
        (cffi:with-foreign-pointer (len-ptr (cffi:foreign-type-size :unsigned-int))
          (setf (cffi:mem-ref len-ptr :unsigned-int) 0)
          (let ((rc (cffi:foreign-funcall-pointer (%ossl-sym "X509_NAME_digest") nil
                                                   :pointer name :pointer md
                                                   :pointer out :pointer len-ptr :int)))
            (when (or (/= rc 1) (/= (cffi:mem-ref len-ptr :unsigned-int) 32))
              (return-from x509-subject-name-sha256 nil))
            (let ((v (make-array 32 :element-type '(unsigned-byte 8))))
              (dotimes (i 32 v) (setf (aref v i) (cffi:mem-aref out :uint8 i))))))))))

(defun* x509-public-key (cert)
    (function (cffi:foreign-pointer) (or cffi:foreign-pointer null))
  "Extract the public key EVP_PKEY* from CERT (X509*) via X509_get_pubkey (x509.h line 886).
   Returns a foreign EVP_PKEY* (caller MUST release via PKEY-FREE) or NIL on error."
  (let ((pk (cffi:foreign-funcall-pointer (%ossl-sym "X509_get_pubkey") nil
                                           :pointer cert :pointer)))
    (if (cffi:null-pointer-p pk) nil pk)))

(defun* pkey-free (pkey)
    (function ((or cffi:foreign-pointer null)) t)
  "Release an EVP_PKEY* returned by X509-PUBLIC-KEY or PKEY-LOAD-PRIVATE (evp.h line 1440)."
  (when (and pkey (not (cffi:null-pointer-p pkey)))
    (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_free") nil :pointer pkey :void))
  t)

(defun* pkey-load-private (pem-octets)
    (function ((simple-array (unsigned-byte 8) (*))) (or cffi:foreign-pointer null))
  "Load an EVP_PKEY* private key from PEM-OCTETS via PEM_read_bio_PrivateKey over a mem BIO.
   Returns a foreign EVP_PKEY* (caller MUST release via PKEY-FREE) or NIL on failure.
   The raw PEM bytes are in a foreign with-foreign-pointer buffer (never on GC heap as a secret)."
  (let* ((n (length pem-octets)))
    (cffi:with-foreign-pointer (buf n)
      (dotimes (i n)
        (setf (cffi:mem-aref buf :uint8 i) (aref pem-octets i)))
      (let ((bio (cffi:foreign-funcall-pointer (%ossl-sym "BIO_new_mem_buf") nil
                                               :pointer buf :int n :pointer)))
        (when (cffi:null-pointer-p bio)
          (return-from pkey-load-private nil))
        (unwind-protect
             (let ((pk (cffi:foreign-funcall-pointer (%ossl-sym "PEM_read_bio_PrivateKey") nil
                                                     :pointer bio
                                                     :pointer (cffi:null-pointer)
                                                     :pointer (cffi:null-pointer)
                                                     :pointer (cffi:null-pointer)
                                                     :pointer)))
               (if (cffi:null-pointer-p pk) nil pk))
          (progn
            (dotimes (i n) (setf (cffi:mem-aref buf :uint8 i) 0))
            (cffi:foreign-funcall-pointer (%ossl-sym "BIO_free") nil :pointer bio :int)))))))

(defun* pkey-kind (pkey)
    (function (cffi:foreign-pointer) (member :ec :rsa nil))
  "Return :EC or :RSA for the EVP_PKEY* handle via EVP_PKEY_get_id (evp.h line 1364), or NIL for an
   unrecognized key type. NID_rsaEncryption=6, NID_X9_62_id_ecPublicKey=408 (obj_mac.h; OpenSSL 3.6.2).
   ADR 0064: an unrecognized key type is a status VALUE (NIL), not a signal — the sole caller
   (%cert-algo-string) already maps a non-:ec/:rsa result to its documented fail-closed NIL (§8.7.2.2), so
   returning NIL here is exactly what a peer cert with an unsupported key type must yield."
  (let ((id (cffi:foreign-funcall-pointer (%ossl-sym "EVP_PKEY_get_id") nil
                                           :pointer pkey :int)))
    (cond ((= id +evp-pkey-nid-rsa+) :rsa)
          ((= id +evp-pkey-nid-ec+)  :ec)
          (t nil))))

(defconstant +cms-text+ #x1
  "OpenSSL CMS_TEXT flag (cms.h:179): require + strip the S/MIME text/plain MIME wrapper from the
   verified content. Used for the MIME multipart/signed container form (the S/MIME text wrapper).")

(defun* cms-verify (smime-octets ca-store)
    (function ((simple-array (unsigned-byte 8) (*)) cffi:foreign-pointer)
              (or (simple-array (unsigned-byte 8) (*)) null))
  "Verify a Permissions-CA-signed governance/permissions document in SMIME-OCTETS against CA-STORE
   (X509_STORE*), returning the verified inner-content bytes; NIL on any failure (fail-closed).
   Decode-tolerant of BOTH §9.4.1.1 container forms (DDS-Security 1.1 §9.4.1.1; RFC 5652 + RFC 5751):
     (1) bare-PEM CMS SignedData (-----BEGIN PKCS7-----, embedded content) via PEM_read_bio_CMS (flags=0);
     (2) MIME multipart/signed S/MIME (detached content + Content-Type: text/plain wrapper) via
         SMIME_read_CMS + CMS_TEXT — the form Fast DDS validate_remote_permissions emits/reads
         (SMIME_read_PKCS7 + PKCS7_verify(PKCS7_TEXT|...), Permissions.cpp:354/406; clean-room, Apache-2.0).
   Form (1) is tried first (byte-identical to the prior PEM-only path); form (2) is the fallback so a
   cross-vendor c.perm and any S/MIME-signed document validate (WP-DDS-SECURITY-FASTDDS-INTEROP T6).
   Both verify the full chain against CA-STORE (CMS_verify, cms.h:276-277) then recover the plaintext
   via BIO_ctrl/BIO_CTRL_INFO=3 (OpenSSL 3.6.2); fail-closed matches §8.4 AccessControl policy."
  (let ((n (length smime-octets)))
    (cffi:with-foreign-pointer (buf (max 1 n))
      (dotimes (i n)
        (setf (cffi:mem-aref buf :uint8 i) (aref smime-octets i)))
      (let ((cms       (cffi:null-pointer))
            (bcont     (cffi:null-pointer))   ; SMIME detached-content BIO (form 2 only)
            (smime-bio (cffi:null-pointer))   ; kept alive across CMS_verify (form 2 references it)
            (flags     0))
        (unwind-protect
             (handler-case
                 (progn
                   ;; form (1): bare-PEM CMS (-----BEGIN PKCS7-----); embedded content, flags=0.
                   (let ((bio1 (cffi:foreign-funcall-pointer (%ossl-sym "BIO_new_mem_buf") nil
                                                             :pointer buf :int n :pointer)))
                     (unless (cffi:null-pointer-p bio1)
                       (unwind-protect
                            (setf cms (cffi:foreign-funcall-pointer (%ossl-sym "PEM_read_bio_CMS") nil
                                                                    :pointer bio1
                                                                    :pointer (cffi:null-pointer)
                                                                    :pointer (cffi:null-pointer)
                                                                    :pointer (cffi:null-pointer)
                                                                    :pointer))
                         (cffi:foreign-funcall-pointer (%ossl-sym "BIO_free") nil :pointer bio1 :int))))
                   ;; form (2): MIME multipart/signed S/MIME — only if the PEM parse did not yield a CMS.
                   (when (cffi:null-pointer-p cms)
                     (setf smime-bio (cffi:foreign-funcall-pointer (%ossl-sym "BIO_new_mem_buf") nil
                                                                   :pointer buf :int n :pointer))
                     (unless (cffi:null-pointer-p smime-bio)
                       (cffi:with-foreign-object (bcont-ptr :pointer)
                         (setf (cffi:mem-ref bcont-ptr :pointer) (cffi:null-pointer))
                         (setf cms (cffi:foreign-funcall-pointer (%ossl-sym "SMIME_read_CMS") nil
                                                                 :pointer smime-bio
                                                                 :pointer bcont-ptr
                                                                 :pointer))
                         (setf bcont (cffi:mem-ref bcont-ptr :pointer)
                               flags +cms-text+))))
                   (when (cffi:null-pointer-p cms)
                     (return-from cms-verify nil))
                   ;; shared tail: chain-verify against CA-STORE, recover the inner content bytes.
                   (let ((bio-out (cffi:foreign-funcall-pointer
                                    (%ossl-sym "BIO_new") nil
                                    :pointer (cffi:foreign-funcall-pointer
                                               (%ossl-sym "BIO_s_mem") nil :pointer)
                                    :pointer)))
                     (when (cffi:null-pointer-p bio-out)
                       (return-from cms-verify nil))
                     (unwind-protect
                          (let ((rc (cffi:foreign-funcall-pointer
                                      (%ossl-sym "CMS_verify") nil
                                      :pointer cms
                                      :pointer (cffi:null-pointer)  ; certs: use embedded / store
                                      :pointer ca-store
                                      :pointer bcont                ; detached content (form 2) or NULL (form 1)
                                      :pointer bio-out
                                      :unsigned-int flags           ; 0 (form 1) | CMS_TEXT (form 2)
                                      :int)))
                            (unless (= rc 1) (return-from cms-verify nil))
                            (cffi:with-foreign-pointer
                                (dptr (cffi:foreign-type-size :pointer))
                              (let ((len (cffi:foreign-funcall-pointer
                                           (%ossl-sym "BIO_ctrl") nil
                                           :pointer bio-out
                                           :int 3     ; BIO_CTRL_INFO (bio.h)
                                           :long 0
                                           :pointer dptr
                                           :long)))
                                (when (<= len 0)
                                  (return-from cms-verify nil))
                                (let* ((ptr (cffi:mem-ref dptr :pointer))
                                       (result (make-array len
                                                 :element-type '(unsigned-byte 8))))
                                  (dotimes (j len result)
                                    (setf (aref result j)
                                          (cffi:mem-aref ptr :uint8 j)))))))
                       (cffi:foreign-funcall-pointer (%ossl-sym "BIO_free") nil
                                                      :pointer bio-out :int))))
               (error () nil))
          ;; outermost cleanup (every exit path): cms handle, SMIME detached content, SMIME source BIO.
          (unless (cffi:null-pointer-p cms)
            (cffi:foreign-funcall-pointer (%ossl-sym "CMS_ContentInfo_free") nil :pointer cms :void))
          (unless (cffi:null-pointer-p bcont)
            (cffi:foreign-funcall-pointer (%ossl-sym "BIO_free") nil :pointer bcont :int))
          (unless (cffi:null-pointer-p smime-bio)
            (cffi:foreign-funcall-pointer (%ossl-sym "BIO_free") nil :pointer smime-bio :int)))))))
