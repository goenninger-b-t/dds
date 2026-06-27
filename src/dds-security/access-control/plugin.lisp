(in-package #:dds.security)

;;; DDS-Security 1.1 §8.4 AccessControl plugin: validate + check predicates.

(defstruct* (access-handle (:constructor make-access-handle))
  "DDS-Security 1.1 §8.4 AccessControl plugin handle: owns the Permissions CA X509_STORE* + parsed docs.
   PERMISSIONS is the LOCAL subject's selected grant; GRANTS retains the FULL parsed grant-list
   (§9.4.1.3.2 grant+, every subject) so the dds-dcps permissions-gate can select a REMOTE peer's
   grant by its validated-handshake-cert subject (the shared-Permissions-document model)."
  (governance  nil                 :type (or governance null))
  (permissions nil                 :type (or permissions null))
  (grants      '()                 :type list)
  (ca-store    (cffi:null-pointer) :type cffi:foreign-pointer)
  (subject     ""                  :type string))

(defun* validate-local-permissions (perm-ca-pem-octets governance-smime-octets
                                    permissions-smime-octets local-subject)
    (function ((simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               (simple-array (unsigned-byte 8) (*))
               string)
              (or access-handle null))
  "DDS-Security 1.1 §8.4.2.1 validate_local_permissions: load Permissions CA; CMS-verify both
   signed documents; parse; bind subject (fail-closed). Returns ACCESS-HANDLE (owns ca-store) or NIL."
  (block validate
    (let ((ca-store (dds.dare:x509-load-ca perm-ca-pem-octets)))
      (unless ca-store (return-from validate nil))
      (let ((gov-content (dds.dare:cms-verify governance-smime-octets ca-store)))
        (unless gov-content
          (dds.dare:x509-ca-free ca-store)
          (return-from validate nil))
        (let ((perm-content (dds.dare:cms-verify permissions-smime-octets ca-store)))
          (unless perm-content
            (dds.dare:x509-ca-free ca-store)
            (return-from validate nil))
          (let ((gov (parse-governance gov-content)))
            (unless gov
              (dds.dare:x509-ca-free ca-store)
              (return-from validate nil))
            (let ((perms-list (parse-permissions perm-content)))
              (unless perms-list
                (dds.dare:x509-ca-free ca-store)
                (return-from validate nil))
              (let ((perms (find local-subject perms-list
                                 :key #'permissions-subject-name :test #'string=)))
                (unless perms
                  (dds.dare:x509-ca-free ca-store)
                  (return-from validate nil))
                (make-access-handle :governance gov
                                    :permissions perms
                                    :grants perms-list
                                    :ca-store ca-store
                                    :subject local-subject)))))))))

(defun* free-access-handle (ah)
    (function (access-handle) null)
  "Release the Permissions CA X509_STORE* owned by AH (X509_STORE_free, DDS-Security 1.1 §8.4)."
  (dds.dare:x509-ca-free (access-handle-ca-store ah))
  nil)

(defun* validate-remote-permissions (ah remote-permissions-smime-octets remote-subject)
    (function (access-handle (simple-array (unsigned-byte 8) (*)) string)
              (or permissions null))
  "DDS-Security 1.1 §8.4.2.2 validate_remote_permissions: CMS-verify against the SAME Permissions CA
   in AH; parse; bind remote-subject (fail-closed). Returns a PERMISSIONS struct or NIL."
  (block validate-remote
    (let ((content (dds.dare:cms-verify remote-permissions-smime-octets
                                        (access-handle-ca-store ah))))
      (unless content (return-from validate-remote nil))
      (let ((perms-list (parse-permissions content)))
        (unless perms-list (return-from validate-remote nil))
        (let ((perms (find remote-subject perms-list
                           :key #'permissions-subject-name :test #'string=)))
          (unless perms (return-from validate-remote nil))
          perms)))))

;;; Check predicates §8.4.2.3–8.4.2.8: Governance AC toggle gates — when AC is OFF, access is unrestricted.

(defun* check-create-participant (ah)
    (function (access-handle) boolean)
  "DDS-Security 1.1 §8.4.2.3 check_create_participant: Governance enable_join_access_control gate
   (§9.4.1.2.3 Table 30). T when join-AC is off or local permissions are bound.
   NOTE: allow_unauthenticated_participants is not separately enforced here; the Slice-2 auth-gate
   strictly refuses unauthenticated participants upstream (allow_unauthenticated=false enforced
   there); enforcement of this governance toggle at the access-control layer is a Slice-5 item."
  (if (governance-enable-join-ac (access-handle-governance ah))
      (not (null (access-handle-permissions ah)))
      t))

(defun* check-create-datawriter (ah topic)
    (function (access-handle string) boolean)
  "DDS-Security 1.1 §8.4.2.4 check_create_datawriter: Governance write-AC toggle (§9.4.1.2.3 Table 32) + local Permissions publish check."
  (multiple-value-bind (read-ac write-ac)
      (governance-topic-rule (access-handle-governance ah) topic)
    (declare (ignore read-ac))
    (if write-ac
        (permissions-allow-publish-p (access-handle-permissions ah) topic)
        t)))

(defun* check-create-datareader (ah topic)
    (function (access-handle string) boolean)
  "DDS-Security 1.1 §8.4.2.5 check_create_datareader: Governance read-AC toggle (§9.4.1.2.3 Table 32) + local Permissions subscribe check."
  (multiple-value-bind (read-ac write-ac)
      (governance-topic-rule (access-handle-governance ah) topic)
    (declare (ignore write-ac))
    (if read-ac
        (permissions-allow-subscribe-p (access-handle-permissions ah) topic)
        t)))

(defun* check-remote-datawriter (ah remote-perms topic)
    (function (access-handle permissions string) boolean)
  "DDS-Security 1.1 §8.4.2.7 check_remote_datawriter: local Governance READ-AC toggle gates the
   remote publisher (§9.4.1.2.3 Table 32: enable_read_access_control gates the local read path,
   which includes vetting incoming remote datawriters). When read-AC is off, unrestricted; when on,
   the remote participant's PUBLISH permission must be granted."
  (multiple-value-bind (read-ac write-ac)
      (governance-topic-rule (access-handle-governance ah) topic)
    (declare (ignore write-ac))
    (if read-ac
        (permissions-allow-publish-p remote-perms topic)
        t)))

(defun* check-remote-datareader (ah remote-perms topic)
    (function (access-handle permissions string) boolean)
  "DDS-Security 1.1 §8.4.2.8 check_remote_datareader: local Governance WRITE-AC toggle gates the
   remote subscriber (§9.4.1.2.3 Table 32: enable_write_access_control gates the local write path,
   which includes vetting incoming remote datareaders). When write-AC is off, unrestricted; when on,
   the remote participant's SUBSCRIBE permission must be granted."
  (multiple-value-bind (read-ac write-ac)
      (governance-topic-rule (access-handle-governance ah) topic)
    (declare (ignore read-ac))
    (if write-ac
        (permissions-allow-subscribe-p remote-perms topic)
        t)))
