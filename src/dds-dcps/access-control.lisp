;;;; DDS-Security 1.1 §8.4 AccessControl MANAGER (M7/P6 Slice 3). The DCPS-layer manager that
;;;; ties the §8.4 AccessControl plugin (dds-security/access-control, T3) to the discovery
;;;; PERMISSIONS-GATE hook (dds-disc, T4) and the Slice-2 authentication manager (auth-manager.lisp).
;;;; It mirrors auth-manager.lisp / type-gate.lisp: per-participant state hangs off the
;;;; domain-participant (DP-ACCESS-STATE = the validated access-handle, analogous to DP-AUTH-STATE);
;;;; one hook is installed on the disc-node — the PERMISSIONS-GATE — composed as the THIRD sequential
;;;; gate after the auth-gate at %match-remote-endpoint. dds-disc stays crypto/policy-free (it just
;;;; calls the gate). The gate body runs OUTSIDE the node lock on the receiver thread and is fail-closed.
;;;;
;;;; SHARED-DOCUMENT model (our-to-our this slice): every participant is configured with the SAME
;;;; signed multi-grant Permissions document; the access-handle retains the FULL grant-list. For a
;;;; REMOTE participant the gate selects the remote's grant from that list by the remote's VALIDATED
;;;; handshake-certificate subject name (AUTH-REMOTE-VALIDATED-SUBJECT — the x509-subject-name of the
;;;; §8.7 chain-verified peer cert, NOT the self-asserted SPDP IdentityToken cert-sn). The remote
;;;; proved possession of the private key for THAT cert and the subject is read from the validated
;;;; cert, so it cannot be forged (authorizing on the self-asserted token would let any CA-issued peer
;;;; escalate by advertising a privileged cert-sn). The conformant per-participant c.perm-in-handshake
;;;; exchange (each peer sends its OWN signed permissions) is a documented Slice-5 cross-vendor carry (ADR 0035).
;;;;
;;;; Spec: OMG DDS-Security 1.1 §8.4 (AccessControl operations), §9.4 (Governance/Permissions builtin
;;;; plugin + S/MIME signing), §7.3 (endpoint-match gating). Design:
;;;; docs/superpowers/specs/2026-06-26-dds-security-access-control-design.md.

(in-package #:dds.dcps)

;;; --- the permissions-gate (§8.4 / §7.3, consulted at endpoint match, OUTSIDE the node lock) ---

(defun* %participant-permissions-gate (p node remote local)
    (function (domain-participant dds.disc:disc-node
               dds.rtps.discovery:endpoint-data dds.rtps.discovery:endpoint-data)
              (member :compatible :incompatible :pending))
  "The DDS-Security §8.4 AccessControl gate installed on P's disc-node PERMISSIONS-GATE hook
   (consulted as the THIRD sequential gate after the auth-gate returns :compatible, in
   %MATCH-REMOTE-ENDPOINT; both directions, receiver thread, OUTSIDE the node lock). Verdict ladder:
     local NOT access-controlled (no DP-ACCESS-STATE)        -> :compatible (AC OFF, byte-identical);
     no auth manager (DP-AUTH-STATE NIL — misconfig: AC needs auth) -> :pending (fail-closed, never matches);
     remote AUTH-REMOTE absent / auth in flight (< :authenticated) -> :pending (parked; resumed when auth
                                                                reaches :keyed — or :authenticated when the
                                                                governance mandates no protection, §8.5 keying
                                                                then not a match precondition — both of which call
                                                                DDS.DISC:RESUME-PARKED-MATCHES);
     remote VALIDATED subject absent (no handshake-cert subject) -> :incompatible (cannot authorize -> deny);
     remote subject has NO grant in the shared Permissions   -> :incompatible (no permissions -> deny);
     remote grant denies the topic (direction-aware)         -> :incompatible (access denied);
     remote grant allows the topic                           -> :compatible.
   The remote's grant is selected from the access-handle's FULL grant-list by the remote's VALIDATED
   handshake-certificate subject name (AUTH-REMOTE-VALIDATED-SUBJECT, surfaced from the §8.7 handshake
   at :authenticated; §8.7.2.5 — the unforgeable authorization identity, never the self-asserted token).
   Direction: %REMOTE-WRITER-P decides which §8.4 remote check applies — a remote writer is vetted with
   CHECK-REMOTE-DATAWRITER (the local read path), a remote reader with CHECK-REMOTE-DATAREADER (the local
   write path) — over the endpoint's topic name. The auth-remote table is read under the auth manager's
   lock (the same lock %PARTICIPANT-AUTH-GATE uses). LOCAL is unused (the verdict is per remote subject)."
  (declare (ignore local))
  (let ((ah (dp-access-state p))
        (ms (dp-auth-state p)))
    (block gate
      (when (null ah) (return-from gate :compatible))   ; AC OFF: unchanged plain path
      (when (null ms) (return-from gate :pending))       ; AC requires auth; no auth manager -> fail-closed park
      (let* ((prefix (%remote-endpoint-prefix remote))
             ;; snapshot (state . validated-subject) under the lock; the VALIDATED §8.7.2.5 handshake-cert subject, NOT the self-asserted token
             (snap (dds.pal:with-lock ((auth-manager-state-lock ms))
                     (let ((ar (gethash prefix (dds.disc:disc-node-auth-state node))))
                       (when ar (cons (auth-remote-state ar) (auth-remote-validated-subject ar)))))))
        (when (null snap) (return-from gate :pending))            ; auth-remote not yet recorded
        ;; §8.4.2.9: authorize once the §8.7.2.5 validated subject is bound — at :keyed, OR at :authenticated when
        ;; the governance mandates NO protection (keying is not a match precondition then, disc-node-crypto-keying-
        ;; required-p NIL; the auth-gate ran first and already enforced the keying policy). :handshaking/:none ->
        ;; park (resumed at :authenticated when keying is not required, else at :keyed). NEVER weakens: the subject
        ;; is the §8.7 chain-verified cert's, and the grant check below still gates authorization.
        (unless (or (eq (car snap) :keyed)
                    (and (eq (car snap) :authenticated)
                         (not (dds.disc:disc-node-crypto-keying-required-p node))))
          (return-from gate :pending))
        (let ((remote-subject (cdr snap)))                          ; the VALIDATED handshake-cert subject (unforgeable)
          (when (null remote-subject) (return-from gate :incompatible))   ; no validated subject -> cannot authorize -> deny
          (let ((grant (dds.security:permissions-grant-for
                        remote-subject (dds.security:access-handle-grants ah))))
            (when (null grant) (return-from gate :incompatible))   ; remote subject has no permissions grant -> deny
            (let* ((topic   (dds.rtps.discovery:endpoint-data-topic-name remote))
                   (allowed (if (%remote-writer-p remote)
                                (dds.security:check-remote-datawriter ah grant topic)
                                (dds.security:check-remote-datareader ah grant topic))))
              (if allowed :compatible :incompatible))))))))

;;; --- installer (mirror %INSTALL-AUTH-MANAGER) ---

(defun* %install-access-control (p access-handle)
    (function (domain-participant dds.security:access-handle)
              (values (or null domain-participant) (or null keyword)))
  "Store ACCESS-HANDLE (the participant's validated §8.4 Governance + shared Permissions, owning the
   Permissions-CA X509_STORE*) in P's DP-ACCESS-STATE and install %PARTICIPANT-PERMISSIONS-GATE on P's
   disc-node PERMISSIONS-GATE hook (composed after the Slice-2 auth-gate). Installed ONLY for an
   access-controlled participant (governance + permissions configured AND an identity); a participant
   with no permissions keeps DP-ACCESS-STATE NIL and the gate stays :compatible (byte-identical plain
   path). When governance protects discovery, also install the secure-SEDP routing predicate + the
   EFFECTIVE base protection kind (SECURE-SEDP-PROTECTION-KIND) so the announce HONORS the
   discovery_protection_kind directive (SIGN vs ENCRYPT). DELETE-PARTICIPANT frees the held access-handle.
   FAIL-CLOSED REJECTS (BEFORE any state is installed) a governance whose topic_rule sets data_protection
   AND metadata_protection to DIFFERENT non-NONE kinds on the same user endpoint — the single-km downgrade
   combo (§9.5.2, ADR-0040); same-kind and any-NONE combos are accepted unchanged.

   Returns (values P NIL) on success, or (values NIL :MIXED-KIND-GOVERNANCE) on the fail-closed reject —
   RETURNED, never signalled (ADR 0064). No state is installed before the check, so a rejected governance
   leaves P untouched; create-participant maps the status to a ReturnCode and (via its unwind-protect) frees
   the access-handle, exactly as it did when this signalled."
  ;; §9.5.2 single-km fail-closed (ADR-0040): a topic_rule with data AND metadata protection at DIFFERENT non-NONE kinds is unrepresentable by one EntityCrypto key (the payload kind wins -> the metadata tier is DOWNGRADED); reject at install, never silently collapse to one km
  (let* ((gov (dds.security:access-handle-governance access-handle))
         (bad (and gov (dds.security:governance-mixed-nonnone-kind-conflict gov))))
    (when bad
      (bail :mixed-kind-governance)))
  (setf (dp-access-state p) access-handle)
  (setf (dds.disc:disc-node-permissions-gate (dp-node p))
        (lambda (node remote local) (%participant-permissions-gate p node remote local)))
  ;; T9 (DDS-Security 1.1 §9.4.1.2.3): when governance protects discovery (discovery_protection_kind != NONE)
  ;; install the per-topic predicate that routes a protected topic's DiscoveredWriter/ReaderData ONLY over the
  ;; secure SEDP endpoints (off plain SEDP) and, being non-NIL, marks secure discovery active (so the disc-node
  ;; advertises SPDP BuiltinEndpointSet bits 16-19). The announce HONORS the directive's base kind via
  ;; SECURE-SEDP-PROTECTION-KIND (:sign authenticated-but-visible | :encrypt confidential — NOT a hardcoded
  ;; ENCRYPT; T9-review conformance fix). T-ORIGINAUTH: protection-kind-base ALSO yields whether the
  ;; *_WITH_ORIGIN_AUTHENTICATION tier applies — set SECURE-SEDP-ORIGIN-AUTH so the crypto-manager mints
  ;; receiver-specific keys for the secure-SEDP readers and the announce/decode emit/verify per-receiver MACs
  ;; (§9.5.3.3.4.3). discovery_protection_kind = NONE leaves all slots default -> the plain SEDP path is
  ;; byte-identical (the secure-SEDP resolvers installed by %install-crypto-manager never engage —
  ;; %announce-secure-endpoints is a no-op without a protected-topic predicate; origin-auth stays NIL).
  (let* ((gov (dds.security:access-handle-governance access-handle))
         (disc-kind (and gov (dds.security:governance-discovery-protection gov))))
    (when (and disc-kind (not (eq disc-kind :none)))
      (multiple-value-bind (base origin-auth) (dds.security:protection-kind-base disc-kind)
        (setf (dds.disc:disc-node-secure-sedp-protection-kind (dp-node p)) base)
        (setf (dds.disc:disc-node-secure-sedp-origin-auth (dp-node p)) origin-auth))
      (setf (dds.disc:disc-node-discovery-protected-topic-p (dp-node p))
            (lambda (topic) (dds.security:topic-discovery-protected-p gov topic)))))
  ;; T11 (DDS-Security 1.1 §8.4.1.6 / §9.4.1.2.3): when governance protects liveliness
  ;; (liveliness_protection_kind != NONE) install the EFFECTIVE base kind (SECURE-PM-PROTECTION-KIND :sign|:encrypt
  ;; — so the secure WLP HONORS the directive, never a hardcoded ENCRYPT) + the origin-auth flag
  ;; (SECURE-PM-ORIGIN-AUTH, §9.5.3.3.4.3). When != :none, assert-participant-liveliness routes every WLP assertion
  ;; over the secure BuiltinParticipantMessageSecureWriter (off plain) and SPDP advertises bits 20/21. The secure
  ;; SPDP re-announce needs NO install here — it rides the discovery tier above (bits 26/27, gated on
  ;; discovery-protected-topic-p, protected per SECURE-SEDP-PROTECTION-KIND). NONE leaves the slot :none ->
  ;; plain WLP, BYTE-IDENTICAL (the secure WLP announce is a no-op without a non-NONE kind).
  (let* ((gov (dds.security:access-handle-governance access-handle))
         (live-kind (and gov (dds.security:governance-liveliness-protection gov))))
    (when (and live-kind (not (eq live-kind :none)))
      (multiple-value-bind (base origin-auth) (dds.security:protection-kind-base live-kind)
        (setf (dds.disc:disc-node-secure-pm-protection-kind (dp-node p)) base)
        (setf (dds.disc:disc-node-secure-pm-origin-auth (dp-node p)) origin-auth))))
  ;; T10 (DDS-Security 1.1 §9.4.1.2.3 / §8.5.1.10-.12): when governance protects whole-RTPS messages
  ;; (rtps_protection_kind != NONE) install the EFFECTIVE base kind (RTPS-PROTECTION-KIND :sign|:encrypt — so the
  ;; engagement HONORS the directive, never a hardcoded ENCRYPT) and the origin-auth flag (protection-kind-base's
  ;; second value -> RTPS-PROTECTION-ORIGIN-AUTH, driving the crypto-manager to mint the local ParticipantCrypto's
  ;; receiver-specific key, §9.5.3.3.4.3). rtps_protection_kind = NONE leaves both default -> the data path is plain,
  ;; BYTE-IDENTICAL (the crypto-manager's rtps-protection-encode resolver never wraps under :none).
  (let* ((gov (dds.security:access-handle-governance access-handle))
         (rtps-kind (and gov (dds.security:governance-rtps-protection gov))))
    (when (and rtps-kind (not (eq rtps-kind :none)))
      (multiple-value-bind (base origin-auth) (dds.security:protection-kind-base rtps-kind)
        (setf (dds.disc:disc-node-rtps-protection-kind (dp-node p)) base)
        (setf (dds.disc:disc-node-rtps-protection-origin-auth (dp-node p)) origin-auth))))
  ;; §9.4.1.2.4 data_protection_kind PARTICIPANT-level default: stamp the MOST-PROTECTIVE serialized-payload tier
  ;; over all topic rules (governance-effective-data-protection) as a FAIL-CLOSED fallback so an endpoint added via
  ;; add-local-{writer,reader} (bypassing create-datawriter/reader, which calls %set-user-metadata-protection
  ;; per-topic) never DOWNGRADES below a later data=ENCRYPT rule when the FIRST rule is data=NONE (false-ACCEPT).
  ;; ALSO install the per-topic resolver (topic -> data_protection_kind); add-local-{writer,reader}
  ;; (%refine-user-data-protection) REFINE the slot to the endpoint's ACTUAL rule, so a genuine data=NONE topic is
  ;; NOT forced to protection (no false-REJECT) — the most-protective default governs only until a per-topic path
  ;; runs. :none (governance-sign — the visible SIGN payload) makes %deliver-user-sample / publish-sample SKIP the
  ;; SecuredPayload transform (plain); data=ENCRYPT keeps it. No governance leaves the slot :unset + resolver NIL ->
  ;; the transform, when installed, is applied as before (backward-identical — Slice-1 direct-KM + keyed pubsub).
  (let ((gov (dds.security:access-handle-governance access-handle)))
    (when gov
      (setf (dds.disc:disc-node-user-data-protection-kind (dp-node p))
            (dds.security:governance-effective-data-protection gov))
      (setf (dds.disc:disc-node-topic-data-protection-resolver (dp-node p))
            (lambda (topic) (dds.security:topic-data-protection gov topic)))))
  ;; §9.4.1.2.4 metadata_protection_kind PARTICIPANT-level default (SYMMETRIC to data_protection above): stamp the
  ;; MOST-PROTECTIVE user-DATA-submessage tier over all topic rules (governance-effective-metadata-protection) as a
  ;; FAIL-CLOSED fallback so an endpoint added via add-local-{writer,reader} never DOWNGRADES below a later
  ;; metadata=SIGN/ENCRYPT rule when the FIRST rule is metadata=NONE (an unprotected user submessage on a protected
  ;; topic = false-ACCEPT). ALSO install the per-topic resolver (topic -> metadata_protection_kind);
  ;; add-local-{writer,reader} (%refine-user-protection) REFINE the slot to the endpoint's ACTUAL rule, so a genuine
  ;; metadata=NONE topic stays :none (no false-REJECT). No governance leaves the slot :none + resolver NIL ->
  ;; byte-identical (the user submessage path stays plain).
  (let ((gov (dds.security:access-handle-governance access-handle)))
    (when gov
      (setf (dds.disc:disc-node-user-submessage-protection-kind (dp-node p))
            (dds.security:governance-effective-metadata-protection gov))
      (setf (dds.disc:disc-node-topic-metadata-protection-resolver (dp-node p))
            (lambda (topic) (dds.security:topic-metadata-protection gov topic)))))
  ;; DDS-Security 1.1 §7.3/§8.5: §8.5 crypto-token keying is a §7.3 endpoint-match precondition ONLY when the
  ;; governance mandates protection (governance-any-protection-p); an all-NONE governance (authentication +
  ;; access-control only) matches at :authenticated on §8.7 auth + §8.4 permissions alone (§8.4.2.9 — matching is
  ;; an access-control decision; a conformant peer such as RTI Connext exchanges no crypto token at GOV=none). A
  ;; NIL/absent governance leaves the slot default T -> the strict :keyed gate stays (fail-closed).
  (let ((gov (dds.security:access-handle-governance access-handle)))
    (when gov
      (setf (dds.disc:disc-node-crypto-keying-required-p (dp-node p))
            (dds.security:governance-any-protection-p gov))))
  (values p nil))
