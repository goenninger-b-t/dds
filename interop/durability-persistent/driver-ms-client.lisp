;;;; MICROSERVICE durability backend — a CLIENT PROCESS (ADR 0050 §4.8, the live 2-process capstone).
;;;;
;;;; A small put / get-range / reconnect client for the live 2-process microservice proof. Runs as its OWN
;;;; OS process and talks to driver-ms-server.lisp (a separate process) over TCP, so the microservice wire
;;;; protocol + the server's PERSISTENT file inner + the always-on DARE composition are exercised
;;;; process-to-process (not in one Lisp image). The store is built via make-durability-store-factory —
;;;; the SAME backend-dispatch seam driver-collect.lisp / driver-serve.lisp use (DRY): DPERSIST_BACKEND=
;;;; microservice → make-encrypted-store(make-microservice-store(ms-host:ms-port)) with the DARE epoch-dir/
;;;; key-dir kept CLIENT-LOCAL (DPERSIST_DIR / DPERSIST_KEYDIR). The server sees only opaque sealed frames.
;;;;
;;;; Modes (DPERSIST_MS_OP): put | get | reconnect.
;;;;   put       — open, PUT N deterministic records to TOPIC across the process boundary, close. "MS-PUT-DONE".
;;;;   get       — open, GET-RANGE(TOPIC), assert N records recovered BYTE-EXACT across processes, close.
;;;;               "MS-GET-OK" / "MS-GET-FAIL".
;;;;   reconnect — open (connect server v1) + confirm it sees the N records ("MS-RC-OPENED"), then WAIT for
;;;;               the harness restart-signal file (DPERSIST_MS_SIGNAL); once it appears, GET-RANGE again —
;;;;               which triggers the Slice-1 bounded reconnect to the RESTARTED server (v2, same port) —
;;;;               and assert the persistent inner + DARE chain recovered BYTE-EXACT ("MS-RC-RECOVERED" /
;;;;               "MS-RC-FAIL"). This proves the mid-session client reconnect across a real server restart.
;;;;
;;;; Config (env vars): DPERSIST_MS_OP, DPERSIST_MS_HOST (127.0.0.1), DPERSIST_MS_PORT (required),
;;;; DPERSIST_DIR (client-local epoch-dir), DPERSIST_KEYDIR (client-local key-dir), DPERSIST_BACKEND
;;;; (microservice), DPERSIST_N (record count, default 5), DPERSIST_TOPIC (default "Square"),
;;;; DPERSIST_MS_SIGNAL (reconnect-mode restart sentinel file).

(asdf:load-system :dds-durability)

(let* ((op       (or (uiop:getenv "DPERSIST_MS_OP")
                     (error "driver-ms-client: DPERSIST_MS_OP (put|get|reconnect) is required")))
       (host     (or (uiop:getenv "DPERSIST_MS_HOST") "127.0.0.1"))
       (port     (parse-integer (or (uiop:getenv "DPERSIST_MS_PORT")
                                    (error "driver-ms-client: DPERSIST_MS_PORT is required"))))
       (dir      (or (uiop:getenv "DPERSIST_DIR") "/tmp/dms-client-D"))
       (key-dir  (or (uiop:getenv "DPERSIST_KEYDIR") "/tmp/dms-client-K"))
       (backend  (or (uiop:getenv "DPERSIST_BACKEND") "microservice"))
       (n        (parse-integer (or (uiop:getenv "DPERSIST_N") "5")))
       (topic    (or (uiop:getenv "DPERSIST_TOPIC") "Square"))
       (signal   (uiop:getenv "DPERSIST_MS_SIGNAL"))
       (store    (funcall (dds.durability:make-durability-store-factory
                           backend :dir dir :key-dir key-dir :ms-host host :ms-port port))))
  (labels ((guid (i)                                    ; 16-byte writer-GUID surrogate; byte0=i keeps (guid,sn) sort = i order
             (let ((g (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref g 0) (logand i 255)) g))
           (payload (i)                                 ; 32 deterministic bytes both put + get recompute (byte-exact oracle)
             (let ((p (make-array 32 :element-type '(unsigned-byte 8))))
               (dotimes (j 32 p) (setf (aref p j) (logand (+ (* i 7) j 3) 255)))))
           (rec= (rec i)                                ; a recovered record matches the deterministic expected(i)?
             (and (string= (dds.durability:durable-record-topic rec) topic)
                  (equalp (dds.durability:durable-record-writer-guid rec) (guid i))
                  (= (dds.durability:durable-record-sn rec) (+ i 1))
                  (eq (dds.durability:durable-record-kind rec) :data)
                  (null (dds.durability:durable-record-key-hash rec))
                  (equalp (dds.durability:durable-record-payload rec) (payload i))))
           (recovered-p (recs)                          ; get-range gives exactly N records, each byte-exact + in order
             (and (= (length recs) n)
                  (loop for r in recs for i from 0 always (rec= r i))))
           (wait-file (path secs)                       ; bounded poll for the harness restart sentinel (never a hang)
             (let ((deadline (+ (get-internal-real-time)
                                (round (* secs internal-time-units-per-second)))))
               (loop (when (uiop:file-exists-p path) (return t))
                     (when (> (get-internal-real-time) deadline) (return nil))
                     (sleep 0.1))))
           (retry-get (secs)                            ; get-range with a bounded retry to span the restart instant
             (let ((deadline (+ (get-internal-real-time)
                                (round (* secs internal-time-units-per-second)))))
               (loop (let ((recs (handler-case (dds.durability:store-get-range store topic)
                                   (error () nil))))
                       (when (recovered-p recs) (return recs)))
                     (when (> (get-internal-real-time) deadline) (return nil))
                     (sleep 0.5)))))
    (dds.durability:store-open store)
    (cond
      ((string-equal op "put")
       (dotimes (i n)
         (dds.durability:store-put store topic (guid i) (+ i 1) nil :data (payload i)))
       (dds.durability:store-close store)
       (format t "~%MS-PUT-DONE topic=~a n=~d host=~a port=~d~%" topic n host port) (force-output)
       (finish-output) (uiop:quit 0))
      ((string-equal op "get")
       (let ((recs (dds.durability:store-get-range store topic)))
         (dds.durability:store-close store)
         (if (recovered-p recs)
             (progn (format t "~%MS-GET-OK topic=~a n=~d (byte-exact across processes)~%" topic n)
                    (force-output) (finish-output) (uiop:quit 0))
             (progn (format t "~%MS-GET-FAIL topic=~a got=~d want=~d~%" topic (length recs) n)
                    (force-output) (finish-output) (uiop:quit 1)))))
      ((string-equal op "reconnect")
       (let ((recs0 (dds.durability:store-get-range store topic)))
         (format t "~%MS-RC-OPENED topic=~a n=~d seen=~d~%" topic n (length recs0)) (force-output))
       (when signal (wait-file signal 30))              ; wait for the harness to restart the server (bounded)
       (let ((recs (retry-get 30)))                     ; this get-range re-dials to the restarted server (Slice 1)
         (dds.durability:store-close store)
         (if (and recs (recovered-p recs))
             (progn (format t "~%MS-RC-RECOVERED topic=~a n=~d (reconnect + persistent recovery byte-exact)~%" topic n)
                    (force-output) (finish-output) (uiop:quit 0))
             (progn (format t "~%MS-RC-FAIL topic=~a got=~d want=~d~%" topic (if recs (length recs) -1) n)
                    (force-output) (finish-output) (uiop:quit 1)))))
      (t (error "driver-ms-client: unknown DPERSIST_MS_OP ~a (want put|get|reconnect)" op)))))
