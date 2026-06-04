(in-package #:dds.tests)

;;; Exercise the type compiler (FR-TOOL-1): define a type from the s-expr DSL,
;;; then round-trip it through the GENERATED codec and the registered type-support
;;; vtable. gsample's i64 follows an i32, exercising the XCDR2 alignment path.

(dds.gen:define-dds-type gsample (:extensibility :final)
  (id :i32 :key t)
  (ts :i64)
  (label :string))

(declaim (ftype (function () t) run-generated-type-test))
(defun run-generated-type-test ()
  (let* ((arena (dds.core.arena:init-arena :bytes (* 64 1024)))
         (pool (dds.core.arena:make-buffer-pool arena 512 2))
         (s (make-gsample :id -42 :ts 9999999999 :label "gen")))
    (flet ((rt (mode)
             (let* ((b (dds.core.arena:pool-acquire pool))
                    (wc (dds.core.buffer:cursor b :endianness :little)))
               (serialize-gsample s wc mode)
               (let ((wrote (dds.core.buffer:cursor-position wc))
                     (rc (dds.core.buffer:cursor b :endianness :little)))
                 (let ((q (deserialize-gsample rc mode)))
                   (dds.core.arena:pool-release pool b)
                   (values q wrote))))))
      (multiple-value-bind (q1 len1) (rt :xcdr2)
        (%check :gen-roundtrip
                (and (= (gsample-id q1) -42)
                     (= (gsample-ts q1) 9999999999)
                     (string= (gsample-label q1) "gen"))
                "generated XCDR2 round-trip mismatch")
        (%check :gen-size
                (= len1 (serialized-size-gsample s :xcdr2))
                (format nil "serialized-size ~d != bytes written ~d"
                        (serialized-size-gsample s :xcdr2) len1)))
      ;; type-support registered and usable purely through the vtable
      (let ((ts (dds.types:find-type-support "gsample")))
        (%check :gen-registered (and ts (dds.types:type-support-p ts))
                "type-support not registered")
        (let* ((b (dds.core.arena:pool-acquire pool))
               (wc (dds.core.buffer:cursor b :endianness :little)))
          (funcall (dds.types:type-support-serialize ts) s wc :xcdr2)
          (let* ((rc (dds.core.buffer:cursor b :endianness :little))
                 (q (funcall (dds.types:type-support-deserialize ts) rc :xcdr2)))
            (%check :gen-vtable (string= "gen" (gsample-label q))
                    "type-support vtable round-trip failed"))
          (dds.core.arena:pool-release pool b)))
      (dds.core.arena:teardown-arena arena)
      t)))
