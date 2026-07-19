(in-package #:dds.dare)

;;; Task 5: Pluggable key-provider vtable + default file-based ML-KEM-1024 provider.
;;; Mirrors the durable-store vtable pattern (ADR 0021, cap.7).
;;; Private key never leaves the provider — decapsulate is performed internally so an
;;; HSM/KMS backend can keep the key off-process.

;;; Perms mechanism: set with `chmod 600 <key>` / `chmod 700 <dir>` via uiop:run-program
;;; (impl-agnostic, no #+sbcl/#+clasp).  Check via `LC_ALL=C ls -la <key>` — parse the
;;; 10-char POSIX mode string; positions 4,5 (group r/w) and 7,8 (other r/w) must be '-'.
;;; LC_ALL=C pins the mode-string format regardless of host locale.  Fail-CLOSED: if the
;;; mode string cannot be obtained/parsed, refuse to load (signal), never open.

;;; Slot naming: internal vtable slots use the `fn-` prefix (fn-recipient-public-key etc.)
;;; to avoid collision with the public dispatch defun*s that carry the clean exported names.

(defstruct* (key-provider (:constructor %make-key-provider))
  "Pluggable KEM key provider vtable (ADR 0021 cap.7): all operations are function slots
   so the caller is decoupled from the backing implementation (file, HSM, KMS, etc.).
   NAME is a keyword identifying the provider kind."
  (name                  :unknown :type keyword)
  (fn-recipient-pub-key  nil      :type (or null function))
  (fn-decapsulate        nil      :type (or null function))
  (fn-open               nil      :type (or null function))
  (fn-close              nil      :type (or null function)))

;;; Public dispatch defun*s — one slot read + funcall; no CLOS dispatch.

(defun* key-provider-recipient-public-key (kp)
    (function (key-provider) (simple-array (unsigned-byte 8) (*)))
  "Return the ML-KEM-1024 public key (ek, 1568 bytes, FIPS-203 Table 2) held by KP.
   The public key is safe to distribute — only the private key is kept inside the provider."
  (funcall (key-provider-fn-recipient-pub-key kp)))

(defun* key-provider-decapsulate (kp kem-ciphertext)
    (function (key-provider (simple-array (unsigned-byte 8) (*)))
              (simple-array (unsigned-byte 8) (*)))
  "Perform ML-KEM-1024 decapsulation of KEM-CIPHERTEXT (1568 bytes, FIPS-203 Table 2)
   using the private key held internally by KP.  Returns the 32-byte shared secret as a
   foreign-backed secret buffer (static-vector, §6) the CALLER owns and MUST free with
   FREE-SECRET-OCTETS.  The raw private key is never exposed to the caller — KMS hook point."
  (funcall (key-provider-fn-decapsulate kp) kem-ciphertext))

(defun* key-provider-open (kp)
    (function (key-provider) (eql t))
  "Open (initialise) the key provider: load or generate the ML-KEM-1024 keypair.
   Returns T.  Signals a descriptive error if the private key file has unsafe permissions."
  (funcall (key-provider-fn-open kp)))

(defun* key-provider-close (kp)
    (function (key-provider) (eql t))
  "Close the key provider, zeroizing + freeing the foreign secret private-key buffer (§6).
   Idempotent — a second close is safe (free-secret-octets is a no-op on NIL).  Returns T."
  (funcall (key-provider-fn-close kp)))

;;; File-based provider internals.

(defun* %kp-file-pub (dir)
    (function (pathname) pathname)
  "Canonical public-key file pathname within DIR."
  (uiop:merge-pathnames* "ml-kem-1024.pub" dir))

(defun* %kp-file-priv (dir)
    (function (pathname) pathname)
  "Canonical private-key file pathname within DIR."
  (uiop:merge-pathnames* "ml-kem-1024.key" dir))

(defun* %read-octet-file (path)
    (function (pathname) (simple-array (unsigned-byte 8) (*)))
  "Read the entire file at PATH into a fresh heap octet vector (for the non-secret public key)."
  (with-open-file (s path :element-type '(unsigned-byte 8))
    (let* ((n (file-length s))
           (v (make-array n :element-type '(unsigned-byte 8))))
      (read-sequence v s)
      v)))

(defun* %read-octet-file-secret (path)
    (function (pathname) (simple-array (unsigned-byte 8) (*)))
  "Read the entire file at PATH into a fresh foreign-backed secret buffer (static-vector).
   Used for the ML-KEM private key so it lives in non-moving memory and can be reliably wiped
   (design spec §6). Caller MUST release the result with FREE-SECRET-OCTETS."
  (with-open-file (s path :element-type '(unsigned-byte 8))
    (let* ((n (file-length s))
           (v (%make-secret-octets n)))
      (read-sequence v s)
      v)))

(defun* %write-octet-file (path octets)
    (function (pathname (simple-array (unsigned-byte 8) (*))) t)
  "Write OCTETS to file at PATH as raw binary; overwrites if existing."
  (with-open-file (s path :direction :output :element-type '(unsigned-byte 8)
                          :if-exists :supersede :if-does-not-exist :create)
    (write-sequence octets s))
  t)

;;; Testability seam: rebind to (constantly nil) in tests to simulate ls unavailable.
(defvar *perms-mode-reader* nil
  "When non-NIL, a function (pathname) => (or null string) used by %assert-key-perms
   instead of the default %ls-mode-string.  Intended for tests only — do not rebind in
   production code.  NIL means use the real %ls-mode-string.")

(defun* %ls-mode-string (path)
    (function (pathname) (or null string))
  "Return the 10-char POSIX mode string for PATH via `LC_ALL=C ls -la`, or NIL on failure.
   LC_ALL=C pins the POSIX mode-string format regardless of host locale.
   Mechanism: uiop:run-program (impl-agnostic; no #+sbcl/#+clasp).
   `ls -la` output line format: `<mode> <nlinks> <user> <group> <size> <date> <name>`."
  (handler-case
      (let* ((native (uiop:native-namestring path))
             (out  (uiop:run-program (list "env" "LC_ALL=C" "ls" "-la" native)
                                     :output :string :error-output nil))
             (line (find-if (lambda (l) (> (length l) 10))
                            (uiop:split-string out :separator '(#\Newline)))))
        (when (and line (>= (length line) 10))
          (subseq line 0 10)))
    (error () nil)))

(defun* %perms-too-loose-p (mode-string)
    (function ((or null string)) boolean)
  "Return T if MODE-STRING shows group or other read/write bits set.
   Checks POSIX mode string positions 4,5 (group r/w) and 7,8 (other r/w).
   A NIL or too-short mode-string MUST be handled by the caller as an unverifiable
   state — %assert-key-perms signals on NIL; it never silently allows load."
  (unless (and mode-string (>= (length mode-string) 9))
    (return-from %perms-too-loose-p nil))
  (or (char/= (char mode-string 4) #\-)    ; group-read
      (char/= (char mode-string 5) #\-)    ; group-write
      (char/= (char mode-string 7) #\-)    ; other-read
      (char/= (char mode-string 8) #\-)))  ; other-write

(defun* enforce-directory-perms-0700 (dir-path)
    (function (pathname) t)
  "Set directory DIR-PATH to 0700 (owner-only) via chmod. uiop:run-program is impl-agnostic
   (no #+sbcl/#+clasp; the operating contract §4). Public seam so any directory holding sensitive
   cleartext (the durability store dir D — cleartext frame metadata) gets the SAME 0700 enforcement
   as the key dir K, reusing one mechanism (DRY; ADR 0026 §10.12)."
  (uiop:run-program (list "chmod" "700" (uiop:native-namestring dir-path)))
  t)

(defun* assert-directory-perms-0700 (dir-path)
    (function (pathname) t)
  "Signal a clear error if DIR-PATH has any group/other read/write bit set, or if permissions
   CANNOT BE VERIFIED (ls unavailable/unparseable). Fail-CLOSED: never proceed unless perms are
   positively verified as tight (0700). Reuses %ls-mode-string / %perms-too-loose-p /
   *perms-mode-reader* — the exact mechanism that guards the key dir K (DRY; ADR 0026 §10.12)."
  (let* ((reader (or *perms-mode-reader* #'%ls-mode-string))
         (mode   (funcall reader dir-path)))
    (unless (and mode (>= (length mode) 9))   ; NOCOND(SECURITY-FAILCLOSED): fail-closed perm refusal at the durability store-open/key-provider-open boundary; caught at runner-start; a store we create has enforced-tight perms so loose perms is externally-introduced
      (error "durability store dir ~a: cannot verify permissions ~
              (ls unavailable or output unparseable); refusing to open (fail-closed)"
             dir-path))
    (when (%perms-too-loose-p mode)   ; NOCOND(SECURITY-FAILCLOSED): fail-closed perm refusal at the durability store-open/key-provider-open boundary; caught at runner-start; a store we create has enforced-tight perms so loose perms is externally-introduced
      (error "durability store dir ~a has unsafe permissions (~a); refusing to open — ~
              must be 0700 (no group or other read/write access)"
             dir-path mode)))
  t)

(defun* %enforce-key-perms (priv-path dir-path)
    (function (pathname pathname) t)
  "Set private-key file to 0600 and key directory to 0700 via chmod.
   uiop:run-program is impl-agnostic (no #+sbcl/#+clasp; the operating contract §4).
   The 0700 directory step reuses ENFORCE-DIRECTORY-PERMS-0700 (DRY, shared with the store dir D)."
  (uiop:run-program (list "chmod" "600" (uiop:native-namestring priv-path)))
  (enforce-directory-perms-0700 dir-path)
  t)

(defun* %assert-key-perms (priv-path)
    (function (pathname) t)
  "Signal a clear error if the private-key file at PRIV-PATH has permissions looser than
   0600, or if permissions CANNOT BE VERIFIED (ls unavailable/unparseable).  Fail-CLOSED:
   the key is never loaded unless perms are positively verified as tight.  Never logs key bytes."
  (let* ((reader (or *perms-mode-reader* #'%ls-mode-string))
         (mode   (funcall reader priv-path)))
    (unless (and mode (>= (length mode) 9))   ; NOCOND(SECURITY-FAILCLOSED): fail-closed perm refusal at the durability store-open/key-provider-open boundary; caught at runner-start; a store we create has enforced-tight perms so loose perms is externally-introduced
      (error "DARE key-provider: cannot verify permissions on ~a ~
              (ls unavailable or output unparseable); refusing to load private key"
             priv-path))
    (when (%perms-too-loose-p mode)   ; NOCOND(SECURITY-FAILCLOSED): fail-closed perm refusal at the durability store-open/key-provider-open boundary; caught at runner-start; a store we create has enforced-tight perms so loose perms is externally-introduced
      (error "DARE key-provider: private key ~a has unsafe permissions (~a); ~
              refusing to load — must be 0600 (no group or other read/write)"
             priv-path mode)))
  t)

;;; File-based key-provider constructor.

(defun* make-file-key-provider (&key dir)
    (function (&key (:dir t)) (values (or null key-provider) (or null keyword)))
  "Construct a file-based ML-KEM-1024 key provider backed by files in DIR. Returns (VALUES PROVIDER STATUS):
   STATUS is :REQUIRES-DIR when :DIR was omitted (ADR 0064: a construction precondition returns a status, not
   a signal); every in-tree caller passes :dir and takes the primary PROVIDER, so STATUS is a benign NIL there.
   Files: `<dir>/ml-kem-1024.pub` (public key, 1568 B) + `<dir>/ml-kem-1024.key` (private key, 3168 B).
   On KEY-PROVIDER-OPEN:
     - Both files exist: check private-key perms (refuse if looser than 0600), then load.
     - Files absent: ml-kem-1024-keygen, write both files, enforce 0600/0700 perms.
   KEY-PROVIDER-DECAPSULATE performs ml-kem-1024-decapsulate internally; the raw private key
   is never returned to the caller (KMS hook point, ADR 0021 cap.7).  The in-memory private key
   is held in a foreign-backed secret buffer (static-vector, design spec §6).
   KEY-PROVIDER-CLOSE zeroizes + frees it (idempotent — a second close is safe).
   KEY-PROVIDER-DECAPSULATE returns a foreign secret shared-secret the CALLER owns + must free."
  (let* ((dir-path  (uiop:ensure-directory-pathname
                     (cond ((null dir)
                            (bail :requires-dir))
                           ((stringp dir) (pathname dir))
                           (t dir))))
         (pub-key   nil)
         (priv-key  nil))
    (%make-key-provider
     :name :file
     :fn-open
     (lambda ()
       ;; defensive: a re-open must not leak a prior foreign secret priv-key (idempotent on NIL); §6
       (setf priv-key (free-secret-octets priv-key))
       (let* ((pub-path  (%kp-file-pub  dir-path))
              (priv-path (%kp-file-priv dir-path)))
         (cond
           ((and (uiop:file-exists-p pub-path) (uiop:file-exists-p priv-path))
            ;; existing keypair: perms-check then load (priv into a foreign secret buffer, §6)
            (%assert-key-perms priv-path)
            (setf pub-key  (%read-octet-file pub-path))
            (setf priv-key (%read-octet-file-secret priv-path)))
           (t
            ;; generate + persist: create priv EMPTY + chmod BEFORE writing key bytes
            ;; (mitigates TOCTOU: key content never exists at umask default perms)
            (ensure-directories-exist dir-path)
            (with-open-file (s priv-path :direction :output :element-type '(unsigned-byte 8)
                                         :if-exists :supersede :if-does-not-exist :create))
            (%enforce-key-perms priv-path dir-path)
            (multiple-value-bind (pub priv)
                (ml-kem-1024-keygen)
              (setf pub-key pub priv-key priv))
            (%write-octet-file pub-path  pub-key)
            (%write-octet-file priv-path priv-key))))
       t)
     :fn-recipient-pub-key
     (lambda ()
       (unless pub-key   ; NOCOND(GUARD): "call key-provider-open first" invariant; the decorator always opens before use; cannot fire in correct use
         (error "DARE key-provider: not open — call key-provider-open first"))
       pub-key)
     :fn-decapsulate
     (lambda (kem-ciphertext)
       (unless priv-key   ; NOCOND(GUARD): "call key-provider-open first" invariant; the decorator always opens before use; cannot fire in correct use
         (error "DARE key-provider: not open — call key-provider-open first"))
       (ml-kem-1024-decapsulate priv-key kem-ciphertext))
     :fn-close
     (lambda ()
       ;; zeroize + free the foreign secret priv-key buffer (idempotent on NIL); §6
       (setf priv-key (free-secret-octets priv-key))
       (setf pub-key nil)
       t))))
