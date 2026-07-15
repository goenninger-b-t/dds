(in-package #:dds.security)

;;; DDS-Security 1.1 §9.5.2 CryptoTransformKeyMaterial_DH — the pre-shared key bundle that
;;; parameterizes encode/decode-serialized-payload. Every field name and width is pinned from
;;; §9.5.2 Table 65; none from memory.

;;; MVP SCAFFOLD: make-test-key-material returns a FIXED pre-shared KeyMaterial for offline
;;; testing. The Slice-2 Auth handshake (DDS-Security §8.7 authentication plugin) replaces
;;; this with keys derived from the DH exchange. Do not ship this test key in production.

(defconstant +km-master-salt-len+ 32
  "CryptoTransformKeyMaterial.master_salt width: 32 octets (DDS-Security 1.1 §9.5.2 Table 65).")
(defconstant +km-sender-key-id-len+ 4
  "CryptoTransformKeyMaterial.sender_key_id width: octet[4] (§9.5.2 Table 65).")
(defconstant +km-master-sender-key-len+ 32
  "CryptoTransformKeyMaterial.master_sender_key width: 32 octets for AES-256 (§9.5.2 Table 65).")
(defconstant +km-receiver-specific-key-id-len+ 4
  "CryptoTransformKeyMaterial.receiver_specific_key_id width: octet[4] (§9.5.2 Table 65).")
(defconstant +km-master-receiver-specific-key-len+ 32
  "CryptoTransformKeyMaterial.master_receiver_specific_key width: 32 octets (§9.5.2 Table 65).
   All-zeros when receiver_specific_key_id is zero (participant-level protection, no per-receiver key).")

(defstruct* (session-cache (:constructor %make-session-cache (id key &optional recv-key-id recv-master-key)))
  "One derived session key TOGETHER WITH the full discriminant it was derived for — published as a SINGLE
   IMMUTABLE object (ADR 0059).

   WHY ONE OBJECT. These caches are read lock-free on the hot AEAD path and re-derived on a miss. Publishing the
   discriminant and the key in SEPARATE slots is not tear-safe: two threads missing concurrently with DIFFERENT
   session_ids can interleave their stores so the KM ends up advertising id S1 alongside key(S2) — a subsequent
   hit on S1 then returns the WRONG key. Fail-closed (a wrong key cannot forge a GCM tag; the datagram is
   dropped), but a silent drop nonetheless, and it is REACHABLE: start-node runs up to THREE receiver threads
   (unicast UDP + multicast UDP + SHMEM) that all feed %handle-datagram and can decode datagrams from the SAME
   peer under the SAME participant KM, while session_id comes off the WIRE (a peer — or an attacker — may vary it
   per datagram). The prior design was safe only by the accident that conformant peers use a fixed session_id.
   With one object the reader sees either the old pair or the new pair, never a mix, so the tear is IMPOSSIBLE by
   construction — which also discharges the ADR 0038(a)/0039(d) forward requirement that a future rtps_protection
   REKEYING (session_id rotation) would otherwise have had to harden.

   ID is the 4-octet session_id. KEY is the derived 32-octet session key. RECV-KEY-ID / RECV-MASTER-KEY are the
   two extra discriminant fields of the receiver-specific (origin-auth) cache and are NIL on the send-side cache
   — the master key is part of the discriminant because the SAME key_id may be presented with DIFFERENT master
   keys (a wrong-key origin-auth probe), and the derived key depends on it. Never mutated after construction."
  (id nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (key nil :type (or null (simple-array (unsigned-byte 8) (32))))
  (recv-key-id nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (recv-master-key nil :type (or null (simple-array (unsigned-byte 8) (*)))))

(defstruct* (key-material (:constructor %make-key-material))
  "DDS-Security 1.1 §9.5.2 CryptoTransformKeyMaterial_DH — the key bundle used by
   encode-serialized-payload / decode-serialized-payload. The three MASTER secret slots (master_salt,
   master_sender_key, master_receiver_specific_key) are held in FOREIGN/STATIC (off-GC-heap, non-moved,
   SAP-addressable) memory and WIPED-then-freed on teardown via ZEROIZE-KEY-MATERIAL — a moving GC cannot
   copy them, freed heap cannot linger with key bytes, and they can be reliably wiped (operating contract
   NFR-MEM / CNSA-2.0 data-at-rest; ADR-0034 master-slot hardening). The derived session-key caches
   (the session-cache objects' KEY + discriminant copies) are EPHEMERAL plain GC-HEAP vectors —
   re-derivable per session from the master secrets, short-lived, GC-reclaimed (NOT long-lived
   secrets-at-rest): a fresh foreign-static copy per session_id would UNBOUNDEDLY leak un-wiped key bytes on
   session_id rotation (reachable pre-auth, before the GCM auth check), and free-on-replace would be a
   use-after-free of the lock-free-shared slot pointer — so they stay heap. Build instances with the
   MAKE-KEY-MATERIAL wrapper (it hardens the master slots); %MAKE-KEY-MATERIAL is the raw constructor. Fields:
     transformation-kind : octet[4] — the CryptoTransformKind selecting the AEAD algorithm (public, on wire).
     master-salt         : octet[32] — SECRET; foreign-static; entropy mixed into the session-key KDF (§9.5.3.3.4.2).
     sender-key-id       : octet[4]  — the CryptoTransformKeyId placed in SecureDataHeader (public, on wire).
     master-sender-key   : octet[32] — SECRET; foreign-static; the HMAC-SHA256 key in the session-key KDF (§9.5.3.3.4.2).
     iv-counter          : (unsigned-byte 64) — MONOTONIC counter incremented on every encode call;
                           combined with session-id forms the 12-byte AES-GCM nonce. Held under
                           iv-counter-lock to make nonce uniqueness STRUCTURAL — two concurrent
                           encodes of the same km never race to the same counter value.
     iv-counter-lock     : opaque lock — guards iv-counter.
     cached-session-*    : the §9.5.3.3.4.2 common session-key cache (%km-session-key-at).
     cached-recv-*       : the §9.5.3.3.4.3 receiver-specific session-key cache for origin authentication
                           (%km-receiver-session-key-at) — derived once per (receiver_specific_key_id, session_id).
     cached-receiver-descriptor-list : the §9.5.3.3.4.3 memoized origin-auth receiver-descriptor list
                           (km-receiver-descriptor{-list}) — built once from the immutable receiver fields, reused
                           per datagram so the live origin-auth send/receive resolvers cons nothing.
   MVP SCAFFOLD — the Slice-2 Auth handshake replaces make-test-key-material."
  (transformation-kind +transformation-kind-aes256-gcm+
   :type (simple-array (unsigned-byte 8) (*)))
  (master-salt (make-array +km-master-salt-len+ :element-type '(unsigned-byte 8) :initial-element 0)
   :type (simple-array (unsigned-byte 8) (*)))
  (sender-key-id (make-array +km-sender-key-id-len+ :element-type '(unsigned-byte 8) :initial-element 0)
   :type (simple-array (unsigned-byte 8) (*)))
  (master-sender-key (make-array +km-master-sender-key-len+ :element-type '(unsigned-byte 8) :initial-element 0)
   :type (simple-array (unsigned-byte 8) (*)))
  ;; §9.5.2 Table 65: receiver-specific key fields. All-zeros = no per-receiver key (participant-level).
  (receiver-specific-key-id
   (make-array +km-receiver-specific-key-id-len+ :element-type '(unsigned-byte 8) :initial-element 0)
   :type (simple-array (unsigned-byte 8) (*)))
  (master-receiver-specific-key
   (make-array +km-master-receiver-specific-key-len+ :element-type '(unsigned-byte 8) :initial-element 0)
   :type (simple-array (unsigned-byte 8) (*)))
  ;; Nonce-uniqueness state: iv-counter is the only mutable field; must be incremented atomically.
  (iv-counter 0 :type (unsigned-byte 64))
  (iv-counter-lock (dds.pal:make-lock "km-iv") :type t)
  ;; §9.5.3.3.4.2 / §9.5.3.3.4.3 session-key caches — ONE session-cache object each (see the session-cache
  ;; docstring: discriminant + key are published together, so a concurrent re-derive can never be observed TORN).
  ;; The cached key is an ephemeral plain GC-heap vector (re-derivable, GC-reclaimed, not a secret-at-rest).
  (cached-send-session nil :type (or null session-cache))
  (cached-recv-session nil :type (or null session-cache))
  ;; §9.5.3.3.4.3 origin-auth receiver-descriptor cache: the (list (cons receiver_specific_key_id .
  ;; master_receiver_specific_key)) the live per-datagram origin-auth resolvers return — built once from the
  ;; IMMUTABLE receiver fields and reused, so the resolver conses nothing per datagram (km-receiver-descriptor{-list}).
  ;; NIL = not-yet-built (an origin-auth KM's list is always non-NIL once built; a non-origin-auth KM never reaches
  ;; the slot — %km-origin-auth-p gates first). Re-keying mints a NEW KM (fresh slot); fence-published like the caches above.
  (cached-receiver-descriptor-list nil :type (or null cons))
  ;; ADR-0034 secret hygiene: set T by ZEROIZE-KEY-MATERIAL after the secret slots are wiped + freed. Makes the
  ;; choke idempotent (a second call / dedup re-walk is a no-op) and marks a torn-down KM structurally UNUSABLE
  ;; (fail-closed — its foreign secret buffers are freed; NEVER derive/seal/open on a zeroized KM).
  (zeroized nil :type boolean))

(defun* make-key-material (&key
                           (transformation-kind +transformation-kind-aes256-gcm+)
                           (master-salt (make-array +km-master-salt-len+ :element-type '(unsigned-byte 8) :initial-element 0))
                           (sender-key-id (make-array +km-sender-key-id-len+ :element-type '(unsigned-byte 8) :initial-element 0))
                           (master-sender-key (make-array +km-master-sender-key-len+ :element-type '(unsigned-byte 8) :initial-element 0))
                           (receiver-specific-key-id (make-array +km-receiver-specific-key-id-len+ :element-type '(unsigned-byte 8) :initial-element 0))
                           (master-receiver-specific-key (make-array +km-master-receiver-specific-key-len+ :element-type '(unsigned-byte 8) :initial-element 0))
                           (iv-counter 0)
                           (iv-counter-lock (dds.pal:make-lock "km-iv")))
    (function (&key (:transformation-kind (simple-array (unsigned-byte 8) (*)))
                    (:master-salt (simple-array (unsigned-byte 8) (*)))
                    (:sender-key-id (simple-array (unsigned-byte 8) (*)))
                    (:master-sender-key (simple-array (unsigned-byte 8) (*)))
                    (:receiver-specific-key-id (simple-array (unsigned-byte 8) (*)))
                    (:master-receiver-specific-key (simple-array (unsigned-byte 8) (*)))
                    (:iv-counter (unsigned-byte 64))
                    (:iv-counter-lock t))
              key-material)
  "Construct a §9.5.2 KeyMaterial, hardening the three SECRET master slots (master_salt,
   master_sender_key, master_receiver_specific_key) into FOREIGN/STATIC (off-GC-heap) buffers via
   dds.dare:octets->secret — a moving GC cannot copy them and ZEROIZE-KEY-MATERIAL can reliably wipe
   them on teardown (ADR-0034; operating contract NFR-MEM / CNSA-2.0 data-at-rest). The passed secret
   vectors are COPIED (caller keeps ownership of its heap copies; a real-secret producer should wipe its
   own transient); the public fields (transformation_kind, the two key_ids) are stored as passed. Wraps
   the raw %MAKE-KEY-MATERIAL. Control-plane (keying), never the hot path."
  (%make-key-material
   :transformation-kind transformation-kind
   :master-salt (dds.dare:octets->secret master-salt)
   :sender-key-id sender-key-id
   :master-sender-key (dds.dare:octets->secret master-sender-key)
   :receiver-specific-key-id receiver-specific-key-id
   :master-receiver-specific-key (dds.dare:octets->secret master-receiver-specific-key)
   :iv-counter iv-counter
   :iv-counter-lock iv-counter-lock))

(define-condition key-material-zeroized-error (error)
  ()
  (:report (lambda (c s) (declare (ignore c))
             (format s "operation on a zeroized KeyMaterial (master secret buffers freed; fail-closed, ADR-0034)")))
  (:documentation
   "Signaled by the KeyMaterial crypto entry points that read the MASTER secrets (%km-session-key-at,
    %km-receiver-session-key-at, km-receiver-descriptor-list) when the KM has been zeroized by
    ZEROIZE-KEY-MATERIAL — its foreign-static master buffers are freed, so any derive/seal/open must
    FAIL-CLOSED rather than dereference freed memory (a use-after-free). Defense-in-depth beyond the
    quiescent-teardown contract (ADR-0034). Subclass of ERROR so the decode fail-closed handlers resolve
    it to NIL, while an encode surfaces it loudly (never a silent wrong result)."))

(defun* zeroize-key-material (km)
    (function ((or null key-material)) null)
  "Wipe-then-free the three MASTER secret slots of KM — the single teardown choke for §9.5.2 KeyMaterial secret
   hygiene (ADR-0034; operating contract NFR-MEM / CNSA-2.0 data-at-rest). Wipes then releases the foreign-static
   master_salt, master_sender_key, master_receiver_specific_key via dds.dare:free-secret-octets (fill-0 then
   free-static; SBCL frees, Clasp recycles zeroed), then DROPS the derived §9.5.3.3.4.2/.4.3 session-key caches
   (the two session-cache objects) and the memoized origin-auth
   receiver-descriptor cons. The derived caches are EPHEMERAL plain GC-HEAP vectors (re-derivable, not
   secrets-at-rest), so dropping the references suffices — GC reclaims them; NO wipe/free is done or needed
   (free-secret-octets on a heap vector would be wrong, and free-on-replace would UAF the lock-free hit path).
   IDEMPOTENT + fail-closed: the KEY-MATERIAL-ZEROIZED flag is set FIRST so a second call — or a dedup re-walk —
   is a no-op, and a zeroized KM reads as structurally unusable (the crypto entry points then signal
   KEY-MATERIAL-ZEROIZED-ERROR). MUST run only when the data path is QUIESCED (participant teardown, after the
   receiver thread is joined): the master buffers are freed here, so a concurrent reader would use-after-free.
   NIL is a no-op. Returns NIL."
  (when (and km (not (key-material-zeroized km)))
    (setf (key-material-zeroized km) t)
    (dds.dare:free-secret-octets (key-material-master-salt km))
    (dds.dare:free-secret-octets (key-material-master-sender-key km))
    (dds.dare:free-secret-octets (key-material-master-receiver-specific-key km))
    ;; derived caches are plain GC-heap (ephemeral, re-derivable) — drop the references; no wipe/free (GC reclaims)
    (setf (key-material-cached-send-session km) nil
          (key-material-cached-recv-session km) nil
          (key-material-cached-receiver-descriptor-list km) nil))
  nil)

(defun* wipe-key-material-secrets (km)
    (function ((or null key-material)) null)
  "Zero the three MASTER secret slots of KM IN PLACE (fill-0, WITHOUT freeing the foreign-static buffers) and drop
   the derived §9.5.3.3.4.2/.4.3 session-key caches — the ADR-0034 MINOR-4 prompt secret-hygiene wipe when a REMOTE
   participant is LOST/unmatched (cm-forget-remote-participant), so its §9.5.2 key material does not linger in memory
   until the participant teardown. UNLIKE zeroize-key-material this does NOT free (free-static) the master buffers and
   does NOT set the terminal KEY-MATERIAL-ZEROIZED flag: the foreign buffers stay ALLOCATED, so a concurrent in-flight
   decode on the receiver thread (a lease-expired peer's delayed/replayed datagram, resolved before the drop) reads
   ZEROS -> a wrong session key -> a fail-closed GCM drop, NEVER a use-after-free — the SOLE free stays at the QUIESCED
   participant teardown (cm-teardown walks all-kms + free-secret-octets each AFTER the receiver thread is joined; the
   flag is left clear so that free still runs). The derived caches are EPHEMERAL plain GC-heap vectors (re-derivable,
   GC-reclaimed), so dropping the references suffices — a stale reader keeps its OWN vector alive (no UAF). Skips a
   KM already zeroized (its buffers are freed — a fill would UAF). Idempotent; NIL is a no-op. Returns NIL."
  (when (and km (not (key-material-zeroized km)))
    (let ((s (key-material-master-salt km))
          (k (key-material-master-sender-key km))
          (r (key-material-master-receiver-specific-key km)))
      (when s (fill s 0))
      (when k (fill k 0))
      (when r (fill r 0)))
    (setf (key-material-cached-send-session km) nil
          (key-material-cached-recv-session km) nil
          (key-material-cached-receiver-descriptor-list km) nil))
  nil)

(defun* %session-id-eq-at (cached-id vec off)
    (function ((or null (simple-array (unsigned-byte 8) (*))) (simple-array (unsigned-byte 8) (*)) fixnum) t)
  "T iff CACHED-ID is the 4-octet session_id sitting at VEC[OFF..OFF+4) — the session-cache hit test, in one
   place for both the send-side and the receiver-specific cache (DRY). Zero-alloc: four AREF compares, no
   subseq. A NIL CACHED-ID (an empty cache) never matches."
  (and cached-id (= (length cached-id) 4)
       (= (aref cached-id 0) (aref vec off))
       (= (aref cached-id 1) (aref vec (+ off 1)))
       (= (aref cached-id 2) (aref vec (+ off 2)))
       (= (aref cached-id 3) (aref vec (+ off 3)))
       t))

(defun* %km-session-key-at (km session-id-vec session-id-off)
    (function (key-material (simple-array (unsigned-byte 8) (*)) fixnum) (simple-array (unsigned-byte 8) (32)))
  "Cached §9.5.3.3.4.2 session key for KM at the 4-octet session_id in SESSION-ID-VEC[OFF..OFF+4]. The key is
   constant for a fixed master key + salt + session_id, so it is derived once and reused (the per-sample KDF is
   removed). The derived key is an EPHEMERAL plain GC-HEAP vector — re-derivable, GC-reclaimed, NOT a
   secret-at-rest: a fresh foreign-static copy per session_id would UNBOUNDEDLY leak un-wiped keys on session_id
   rotation (reachable pre-auth: this runs before the GCM auth check, and a hostile peer sets arbitrary session_id
   per datagram), and free-on-replace would UAF the lock-free-shared slot pointer — so it stays heap (ADR-0034).
   FAIL-CLOSED: if KM is zeroized (its master buffers are freed) this signals KEY-MATERIAL-ZEROIZED-ERROR BEFORE
   dereferencing them, so a torn-down KM is structurally unusable — a single flag check off the zero-alloc hit path.
   Hit path is lock-free + zero-alloc; miss path uses a release fence (key store → fence → id store) and hit path
   uses an acquire fence (id match → fence → key load) to guarantee barrier-safe cache publication on weak-memory
   platforms (arm64/Apple Silicon; operating contract §4). A benign concurrent same-value miss race is still
   harmless — both missers derive the identical deterministic key."
  (when (key-material-zeroized km) (error 'key-material-zeroized-error))
  (assert (<= (+ session-id-off 4) (length session-id-vec)))
  (let ((sc (key-material-cached-send-session km)))   ; ONE load of the published pair (ADR 0059) — id + key cannot disagree
    (if (and sc (%session-id-eq-at (session-cache-id sc) session-id-vec session-id-off))
        (progn
          ;; Acquire fence: the object's fields must be seen as the release-publishing thread wrote them.
          (dds.pal:fence :acquire)
          (session-cache-key sc))
        (let* ((sid (subseq session-id-vec session-id-off (+ session-id-off 4)))
               (k   (derive-session-key (key-material-master-sender-key km)
                                        (key-material-master-salt km) sid))   ; ephemeral GC-heap key, GC-reclaimed
               (new (%make-session-cache sid k)))                             ; fully built BEFORE publication
          ;; Release fence: the object's fields are visible before the pointer that publishes them.
          (dds.pal:fence :release)
          (setf (key-material-cached-send-session km) new)   ; ONE store: a concurrent reader sees the OLD or the NEW pair, never a mix
          k))))

(defun* %km-origin-auth-p (km)
    (function (key-material) boolean)
  "T iff KM carries origin-auth receiver-specific key material — a NON-ZERO receiver_specific_key_id (the
   §9.5.3.3.4.3 origin-auth-enabled marker; an all-zero id is the disabled sentinel). The receiver fields are
   immutable after mint, so this is a stable per-KM predicate."
  (notevery #'zerop (key-material-receiver-specific-key-id km)))

(defun* km-receiver-descriptor-list (km)
    (function (key-material) list)
  "The MEMOIZED §9.5.3.3.4.3 origin-auth receiver-descriptor list of KM: (list (cons receiver_specific_key_id .
   master_receiver_specific_key)) when KM carries a receiver-specific key, else NIL. This is exactly what the live
   per-datagram origin-auth ENCODE resolvers return for :receivers (rtps_protection cm-rtps-encode-receivers +
   secure-SEDP cm-secure-sedp-encode-receivers) and, via KM-RECEIVER-DESCRIPTOR, what the DECODE resolvers return
   for my-receiver-key — so caching the one list/cons on the KM makes those resolvers cons ZERO GC-heap bytes per
   datagram (closing the resolver-list residual under ADR-0039's zero-alloc origin-auth claim). The list is built
   once from KM's IMMUTABLE receiver fields (a benign concurrent double-build derives the identical content);
   re-keying mints a NEW KeyMaterial (fresh cache) and participant loss drops the KM (and its cache), so a stale
   descriptor is impossible — the %km-session-key-at invalidation model. Hit path is lock-free + zero-alloc under an
   ACQUIRE fence; the one-time cold build publishes the list under a RELEASE fence (contents visible before the slot
   store) — the first fill amortizes, steady state is 0 B (the %km-session-key-at convention). The returned list is
   READ-ONLY for the transform (%put-receiver-macs-into / %verify-receiver-mac-into read (car r)/(cdr r) only), so
   sharing the cached instance across datagrams is safe. Cache is probed FIRST so the hit path is a pure slot load +
   ACQUIRE fence — no %km-origin-auth-p scan — hence guaranteed zero-alloc. FAIL-CLOSED: a zeroized KM signals
   KEY-MATERIAL-ZEROIZED-ERROR (its master_receiver_specific_key is freed) rather than returning NIL — a NIL
   descriptor reads as origin-auth-disabled, so returning it for a zeroized origin-auth KM would be a fail-OPEN
   gate bypass (ADR-0034); the flag check is off the zero-alloc hit path."
  (when (key-material-zeroized km) (error 'key-material-zeroized-error))
  (let ((cached (key-material-cached-receiver-descriptor-list km)))
    (if cached
        (progn (dds.pal:fence :acquire) cached)
        (when (%km-origin-auth-p km)
          (let ((built (list (cons (key-material-receiver-specific-key-id km)
                                   (key-material-master-receiver-specific-key km)))))
            (dds.pal:fence :release)
            (setf (key-material-cached-receiver-descriptor-list km) built)
            built)))))

(defun* km-receiver-descriptor (km)
    (function (key-material) (or null cons))
  "The §9.5.3.3.4.3 origin-auth receiver descriptor (receiver_specific_key_id . master_receiver_specific_key) of
   KM, or NIL when KM carries no receiver-specific key. The CAR of the MEMOIZED KM-RECEIVER-DESCRIPTOR-LIST — the
   same single cached cons the ENCODE :receivers list holds — so the DECODE my-receiver-key resolvers
   (cm-rtps-decode-receiver / cm-secure-sedp-decode-receiver) are zero-alloc per datagram too."
  (car (km-receiver-descriptor-list km)))

;;; Fixed test key material — a known, PUBLISHED, non-secret value for offline round-trip tests.
;;; The 32-byte master_sender_key and master_salt are the two consecutive NIST SP 800-56C rev2
;;; §4.2 example KDK values (each the ASCII encoding of a 32-character string of successive hex
;;; digits), providing a recognisable independent reference. The sender_key_id is 0xDEADBEEF.
;;; MUST NOT be used outside test harnesses — no session derives security from this key.

(defconstant +test-master-sender-key+
    (if (boundp '+test-master-sender-key+)
        (symbol-value '+test-master-sender-key+)
        (make-array 32 :element-type '(unsigned-byte 8)
                       :initial-contents
                       '(#x00 #x01 #x02 #x03 #x04 #x05 #x06 #x07
                         #x08 #x09 #x0a #x0b #x0c #x0d #x0e #x0f
                         #x10 #x11 #x12 #x13 #x14 #x15 #x16 #x17
                         #x18 #x19 #x1a #x1b #x1c #x1d #x1e #x1f)))
  "Fixed AES-256 master_sender_key for make-test-key-material (test scaffold only; §9.5.2 Table 65).
   Value: consecutive bytes 0x00..0x1F (32 octets). Not secret; for offline tests only.")

(defconstant +test-master-salt+
    (if (boundp '+test-master-salt+)
        (symbol-value '+test-master-salt+)
        (make-array 32 :element-type '(unsigned-byte 8)
                       :initial-contents
                       '(#x40 #x41 #x42 #x43 #x44 #x45 #x46 #x47
                         #x48 #x49 #x4a #x4b #x4c #x4d #x4e #x4f
                         #x50 #x51 #x52 #x53 #x54 #x55 #x56 #x57
                         #x58 #x59 #x5a #x5b #x5c #x5d #x5e #x5f)))
  "Fixed master_salt for make-test-key-material (test scaffold only; §9.5.2 Table 65).
   Value: consecutive bytes 0x40..0x5F (32 octets). Not secret; for offline tests only.")

(defconstant +test-sender-key-id+
    (if (boundp '+test-sender-key-id+)
        (symbol-value '+test-sender-key-id+)
        (make-array 4 :element-type '(unsigned-byte 8)
                      :initial-contents '(#xde #xad #xbe #xef)))
  "Fixed sender_key_id for make-test-key-material (test scaffold only). Value: 0xDEADBEEF.")

(defstruct* (crypto-keys (:constructor make-crypto-keys))
  "Per-writer key resolver for the DDS-Security §9.5.3.3 secured data path (T6).
   ENCODE-KEY-FN resolves the local writer's KeyMaterial by its 16-octet GUID for outgoing samples
   (§9.5.3.3.4.4). DECODE-KEY-FN resolves the remote writer's KeyMaterial by its 16-octet wire GUID
   for incoming samples (§9.5.3.3.4.5). Both return NIL when no key exists — caller MUST fail-closed."
  (encode-key-fn (error 'contract-violation :detail "crypto-keys: :encode-key-fn required") :type function)   ; NOCOND(CONTRACT): required-initarg poison default
  (decode-key-fn (error 'contract-violation :detail "crypto-keys: :decode-key-fn required") :type function))   ; NOCOND(CONTRACT): required-initarg poison default

(defun* make-test-key-material (&key (kind :encrypt))
    (function (&key (:kind (member :sign :encrypt))) key-material)
  "Return a fresh key-material with FIXED pre-shared test values (§9.5.2; Table 65 field names).
   Intended for offline unit / round-trip tests only. The Slice-2 Auth handshake replaces this
   with per-session KEM-derived keys. Every field is a COPY so callers cannot alias the constants.
   KIND (:encrypt default -> AES256-GCM {0,0,0,4}; :sign -> AES256-GMAC {0,0,0,3}) sets the advertised
   transformation_kind, selecting the ENCRYPT vs the GMAC/SIGN payload sub-tier in encode/decode-serialized-
   payload; the fixed master key/salt/id are IDENTICAL for both (only the advertised kind + the seal-vs-GMAC
   framing differ), so a :sign km yields a DETERMINISTIC GMAC SecuredPayload (the byte-exact golden's oracle).
   NONCE-REUSE WARNING: because this returns a fresh instance with iv-counter=0 over a FIXED
   master key, at most ONE instance may be used to ENCODE at a time — two encoders over this
   fixed key start at the same counter and produce colliding nonces (catastrophic for AES-GCM);
   it is an offline test/round-trip scaffold replaced by the Slice-2 per-writer derived key."
  (make-key-material
   :transformation-kind (copy-seq (ecase kind
                                    (:encrypt +transformation-kind-aes256-gcm+)
                                    (:sign    +transformation-kind-aes256-gmac+)))
   :master-salt         (copy-seq +test-master-salt+)
   :sender-key-id       (copy-seq +test-sender-key-id+)
   :master-sender-key   (copy-seq +test-master-sender-key+)
   :iv-counter          0
   :iv-counter-lock     (dds.pal:make-lock "km-iv")))

;;; --- generic §8.5 CryptoKeyFactory KeyMaterial generator (T6) ---
;;; The single random-fill primitive behind both the participant/entity KeyMaterial the
;;; crypto-manager mints and the per-writer KeyMaterial (generate-writer-key-material delegates here).

(defparameter *sender-key-id-counter* 0
  "Monotonic source for the allocated 4-octet CryptoTransformKeyId (sender_key_id, §9.5.2 Table 65)
   handed out by GENERATE-KEY-MATERIAL. Guarded by *SENDER-KEY-ID-LOCK*; the first allocation is 1
   (never zero on the wire). Process-global so every KeyMaterial a participant mints carries a
   distinct transformation_key_id, keeping a receiver's O(1) transformation_key_id -> KeyMaterial
   decode index unambiguous. NOT a wire constant — an allocation counter (§9.5.2 leaves
   CryptoTransformKeyId assignment to the implementation).")

(defparameter *sender-key-id-lock* (dds.pal:make-lock "sender-key-id")
  "Guards *SENDER-KEY-ID-COUNTER* across concurrent GENERATE-KEY-MATERIAL calls (control-plane).")

(defun* %alloc-sender-key-id ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "Allocate the next process-unique, NON-ZERO 4-octet sender_key_id (big-endian; §9.5.2 Table 65),
   wrapping modulo 2^32 and skipping zero. Control-plane (keying), never the hot path."
  (let ((n (dds.pal:with-lock (*sender-key-id-lock*)
             (let ((c (logand (1+ *sender-key-id-counter*) #xffffffff)))
               (when (zerop c) (setf c 1))
               (setf *sender-key-id-counter* c)))))
    (let ((kid (make-array 4 :element-type '(unsigned-byte 8))))
      (setf (aref kid 0) (ldb (byte 8 24) n)
            (aref kid 1) (ldb (byte 8 16) n)
            (aref kid 2) (ldb (byte 8 8) n)
            (aref kid 3) (ldb (byte 8 0) n))
      kid)))

(defun* %nonzero-random-key-id ()
    (function () (simple-array (unsigned-byte 8) (*)))
  "A cryptographically random NON-ZERO 4-octet receiver_specific_key_id (§9.5.2 Table 65), resampled
   until non-zero: zero is the §9.5.3.3.4.3 'origin authentication disabled' sentinel, so a random
   draw must never collide with it (the T6 fix for the T3 carry). Control-plane."
  (loop for kid = (dds.dare:random-bytes 4)
        when (notevery #'zerop kid) return kid))

(defun* generate-key-material (&key (origin-auth nil) (kind :encrypt))
    (function (&key (:origin-auth t) (:kind (member :sign :encrypt))) key-material)
  "Generate a fresh §9.5.2 KeyMaterial_AES_GCM_GMAC — the generic §8.5 CryptoKeyFactory primitive
   reused for participant- and entity-level keys (and, via GENERATE-WRITER-KEY-MATERIAL, per-writer
   keys). master_salt (32B) + master_sender_key (32B) are cryptographically random
   (dds.dare:random-bytes); sender_key_id is a process-unique NON-ZERO 4-octet allocation
   (%ALLOC-SENDER-KEY-ID) so a receiver's O(1) transformation_key_id -> KeyMaterial decode index
   stays unambiguous. KIND selects the §9.5.2 Table 65 transformation_kind the KeyMaterial ADVERTISES:
   :encrypt (default) -> AES256-GCM {0,0,0,4}; :sign -> AES256-GMAC {0,0,0,3}. This MUST equal the wire
   CryptoHeader transformation_kind a peer sees for this endpoint's submessages, because a conformant
   receiver (Fast DDS AESGCMGMAC_Transform::find_key) matches a stored KeyMaterial to an inbound submessage
   on BOTH transformation_kind AND sender_key_id — a SIGN endpoint advertising a GCM KeyMaterial is rejected
   'Key material not found' (the AES-256 master key is identical for GCM and GMAC; only the advertised kind +
   the SEC_BODY-vs-verbatim framing differ). With ORIGIN-AUTH NIL (default) the receiver-specific fields stay
   all-zero (no per-receiver origin authentication, §9.5.2). With ORIGIN-AUTH true both are populated: a
   NON-ZERO random receiver_specific_key_id (zero is the §9.5.3.3.4.3 origin-auth-disabled sentinel — never
   emitted) + a random 32B master_receiver_specific_key, for the *_WITH_ORIGIN_AUTHENTICATION protection kinds
   (§9.5.3.3.4.3; consumed by derive-receiver-specific-session-key / compute-receiver-specific-mac). The
   KeyMaterial's SECRET master slots are held in FOREIGN/STATIC memory (make-key-material hardens them) and
   wiped on teardown by ZEROIZE-KEY-MATERIAL (ADR-0034 resolved; operating contract NFR-MEM / CNSA-2.0
   data-at-rest); the transient heap randoms are wiped here after the copy. The caller owns the key-material
   lifecycle. Control-plane, not the hot path."
  (let* ((tk   (ecase kind
                 (:encrypt +transformation-kind-aes256-gcm+)
                 (:sign    +transformation-kind-aes256-gmac+)))
         (salt (dds.dare:random-bytes 32))
         (mkey (dds.dare:random-bytes 32)))
    (if origin-auth
        (let ((rsk (dds.dare:random-bytes 32)))
          (prog1 (make-key-material :transformation-kind          (copy-seq tk)
                                    :master-salt                  salt
                                    :sender-key-id                (%alloc-sender-key-id)
                                    :master-sender-key            mkey
                                    :receiver-specific-key-id     (%nonzero-random-key-id)
                                    :master-receiver-specific-key rsk)
            (fill salt 0) (fill mkey 0) (fill rsk 0)))   ; wipe transient heap randoms (KM holds static copies)
        (prog1 (make-key-material :transformation-kind (copy-seq tk)
                                  :master-salt         salt
                                  :sender-key-id       (%alloc-sender-key-id)
                                  :master-sender-key   mkey)
          (fill salt 0) (fill mkey 0)))))
