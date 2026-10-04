;; The ADR 0119 / WP-0.7 ring-primitive A/B (bench/report/2026-10-03-shmem-lane-poison.md).
;;
;; One lane of a 65 536-octet ring in a static (alloc-static, non-GC) region, a 64-octet static payload.
;; Each pass enqueues BATCH records, then makes one drain call. 2 000 warm-up passes, then the timed loop:
;; 1 000 000 passes at batch 1, 20 000 passes at batch 64. The BEFORE arm (OLD-LANE-ENQUEUE / OLD-LANE-DRAIN,
;; old-ring.lisp) and the AFTER arm (the current %LANE-ENQUEUE / %LANE-DRAIN) alternate five times.
;; ns/record = monotonic-ns over the loop / records delivered, and INCLUDES the enqueue. B/record is the
;; dds.pal:bytes-consed delta (exact on SBCL; it does not move for this workload on AllegroCL).
;;
;; Run: bench/shmem-lane-ab/run.sh ./scripts/with-sbcl.sh   (or ./scripts/with-allegro.sh)
(in-package :cl-user)

(defun shmem-lane-ab-run-one (arm batch batches)
  (let* ((cap 65536)
         (m (dds.pal:alloc-static (dds.xport.shmem::%segment-bytes 1 cap)))
         (sap (dds.pal:static-pointer m))
         (sink (dds.core.buffer:make-octet-buffer cap))
         (pbuf (dds.core.buffer:make-octet-buffer 64))
         (payload (dds.core.buffer:octet-buffer-vec pbuf))
         (n 0)
         (fn (lambda (b s) (declare (ignore b s)) (incf n))))
    (dds.xport.shmem::%ring-init sap 1 cap)
    (flet ((pass (count)
             (if (eq arm :before)
                 (dotimes (i count)
                   (dotimes (j batch) (dds.xport.shmem::old-lane-enqueue sap 0 cap payload 0 64))
                   (dds.xport.shmem::old-lane-drain sap 0 cap sink fn))
                 (dotimes (i count)
                   (dotimes (j batch) (dds.xport.shmem::%lane-enqueue sap 1 0 cap payload 0 64))
                   (dds.xport.shmem::%lane-drain sap 1 0 cap sink fn)))))
      (pass 2000)
      (setf n 0)
      (let* ((b0 (dds.pal:bytes-consed)) (t0 (dds.pal:monotonic-ns)))
        (pass batches)
        (let ((dt (- (dds.pal:monotonic-ns) t0)) (db (- (dds.pal:bytes-consed) b0)))
          (assert (= n (* batch batches)))
          (format t "~&arm=~6a batch=~3d records=~8d  ns/record=~7,2f  ns/drain-call=~9,2f  B/record=~,4f~%"
                  arm batch n (/ dt n 1.0) (/ dt batches 1.0) (/ db n 1.0))
          (finish-output))))
    (dds.pal:pshared-destroy sap dds.xport.shmem::+mutex-off+ dds.xport.shmem::+cond-off+)
    (dds.pal:free-static (dds.core.buffer:octet-buffer-vec sink))
    (dds.pal:free-static payload)
    (dds.pal:free-static m)))

(dotimes (rep 5)
  (dolist (arm '(:before :after))
    (shmem-lane-ab-run-one arm 1 1000000)
    (shmem-lane-ab-run-one arm 64 20000)))
