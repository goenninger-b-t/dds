;;;; Standalone Square/ShapeType publisher + subscriber over multicast discovery.
;;;; Built entirely on the participant data plane (dds.disc) + the generated codec
;;;; (dds.gen). Two processes discover each other via SPDP multicast on the domain's
;;;; well-known group, match the "Square" topic via SEDP, and exchange ShapeType
;;;; samples reliably. The same participant is intended to interop with RTI
;;;; rtishapesdemo / Fast DDS / Cyclone Shapes (see docs/interop-shapes.md).

(in-package #:dds.shapes)

;; Two selectable Square payload types (:type :canonical | :tagged at runtime):
;;  - shape-type   : the EXACT RTI canonical ShapeType (color @key; x; y; shapesize).
;;                   Use for interop with rtishapesdemo / DDSSpy.
;;  - tagged-shape : the same + a per-publisher uuid + per-sample seq (stream id +
;;                   ordering/loss). DIVERGES from canonical => harness<->harness only.
;; Both :final with only 32-bit/string members => XCDR1 and XCDR2 bytes coincide.
(dds.gen:define-dds-type shape-type (:extensibility :final)
  (color :string :key t)
  (x :i32)
  (y :i32)
  (shapesize :i32))

(dds.gen:define-dds-type tagged-shape (:extensibility :final)
  (color :string :key t)
  (x :i32)
  (y :i32)
  (shapesize :i32)
  (uuid :string)
  (seq :u32))

(declaim (ftype (function () string) %make-uuid))
(defun %make-uuid ()
  "A random RFC-4122 v4 UUID string identifying one publisher stream. Demo-grade
   (seeds from make-random-state t; production wants a vetted UUID source)."
  (let ((rs (make-random-state t))
        (b (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16) (setf (aref b i) (random 256 rs)))
    (setf (aref b 6) (logior #x40 (logand (aref b 6) #x0f)))   ; version 4
    (setf (aref b 8) (logior #x80 (logand (aref b 8) #x3f)))   ; variant 10x
    (format nil "~(~2,'0x~2,'0x~2,'0x~2,'0x-~2,'0x~2,'0x-~2,'0x~2,'0x-~2,'0x~2,'0x-~2,'0x~2,'0x~2,'0x~2,'0x~2,'0x~2,'0x~)"
            (aref b 0) (aref b 1) (aref b 2) (aref b 3) (aref b 4) (aref b 5)
            (aref b 6) (aref b 7) (aref b 8) (aref b 9) (aref b 10) (aref b 11)
            (aref b 12) (aref b 13) (aref b 14) (aref b 15))))

(declaim (ftype (function ((unsigned-byte 8)) (simple-array (unsigned-byte 8) (12))) %make-prefix))
(defun %make-prefix (role)
  "A 12-octet GUID prefix: marker 'G' 'B' + ROLE byte + wall-clock-derived tail, so
   a publisher (role #x50) and subscriber (role #x53), and successive runs, get
   distinct prefixes. Demo-grade, not a real GUID allocator."
  (let ((p (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0))
        (clk (get-universal-time)))
    (setf (aref p 0) #x47 (aref p 1) #x42 (aref p 2) role)
    (loop for i from 3 below 12
          do (setf (aref p i) (logand (ash clk (* -8 (- i 3))) #xff)))
    p))

(declaim (ftype (function (function) (simple-array (unsigned-byte 8) (*))) %serialize-payload))
(defun %serialize-payload (serialize-fn)
  "Build a PLAIN_CDR2_LE SerializedPayload: an encapsulation header + whatever
   SERIALIZE-FN writes (called with the XCDR2 cursor). Returns a fresh octet vector
   — the data-plane publish payload. Works for either shape type."
  (let* ((buf (dds.core.buffer:make-octet-buffer 256))
         (wc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.cdr:make-encapsulation-header wc :plain-cdr2-le)
    (funcall serialize-fn wc)
    (let* ((len (dds.core.buffer:cursor-position wc))
           (out (make-array len :element-type '(unsigned-byte 8))))
      (replace out (dds.core.buffer:octet-buffer-vec buf) :end1 len)
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))
      out)))

(declaim (ftype (function ((simple-array (unsigned-byte 8) (*)) function) t) %deserialize-with))
(defun %deserialize-with (bytes deserialize-fn)
  "Parse a SerializedPayload's encapsulation header (honoring representation +
   endianness, so a foreign CDR_LE/BE or CDR2_LE/BE sender is handled), then call
   DESERIALIZE-FN with (cursor mode). Both shape types are :final (no DHEADER)."
  (let* ((ob (dds.core.buffer:make-octet-buffer (length bytes)))
         (rc (dds.core.buffer:cursor ob :endianness :little)))
    (replace (dds.core.buffer:octet-buffer-vec ob) bytes)
    (let ((rep (dds.cdr:parse-encapsulation-header rc)))
      (dds.core.buffer:cursor-set-endianness
       rc (if (member rep '(:plain-cdr-be :plain-cdr2-be :pl-cdr-be :pl-cdr2-be :delimited-cdr-be))
              :big :little))
      (let ((mode (if (member rep '(:plain-cdr-le :plain-cdr-be)) :xcdr1 :xcdr2)))
        (prog1 (funcall deserialize-fn rc mode)
          (dds.pal:free-static (dds.core.buffer:octet-buffer-vec ob)))))))

(declaim (ftype (function (dds.disc:disc-node (integer 0)) t) %reannounce))
(defun %reannounce (node last)
  "Re-announce SPDP + SEDP if more than ~1.5 s have passed since LAST (an internal
   real-time stamp). Returns the new stamp (LAST if no announce). Keeps a late-
   joining peer (or Connext) discovering + matching this participant."
  (let ((now (get-internal-real-time)))
    (if (> (- now last) (round (* 1.5 internal-time-units-per-second)))
        (progn (dds.disc:announce-participant node)
               (dds.disc:announce-endpoints node)
               now)
        last)))

(declaim (ftype (function (&key (:domain (integer 0)) (:color string) (:shapesize (integer 0)) (:rate (integer 1)) (:count (integer 0)) (:advertise-address string) (:type symbol)) t) run-publisher))
(defun run-publisher (&key (domain 0) (color "BLUE") (shapesize 30) (rate 30) (count 0)
                           (advertise-address "127.0.0.1") (type :tagged))
  "Publish an animated Square on DOMAIN via multicast discovery. TYPE selects the
   payload: :canonical = the exact RTI ShapeType (color/x/y/shapesize — for interop
   with rtishapesdemo / DDSSpy); :tagged = + per-publisher uuid + per-sample seq
   (harness<->harness). RATE updates/sec; COUNT 0 = forever (Ctrl-C)."
  (check-type type (member :canonical :tagged))
  (let ((node (dds.disc:make-disc-node :guid-prefix (%make-prefix #x50) :domain domain
                                       :multicast t :advertise-address advertise-address)))
    (dds.disc:add-local-writer node :topic "Square" :type "ShapeType"
                               :reliability dds.rtps.discovery:+reliability-reliable+)
    (dds.disc:enable-publisher node)
    (dds.disc:start-node node)
    (let ((uuid (%make-uuid)))
      (format t "~&[pub] Square/ShapeType[~(~a~)] color=~a domain=~d uuid=~a (multicast 239.255.0.1). Ctrl-C to stop.~%"
              type color domain uuid)
      (let ((x 50) (y 50) (dx 3) (dy 2) (period (/ 1.0 rate)) (n 0) (last 0) (seq 0)
            (dests (make-hash-table :test 'equalp)))
        (unwind-protect
             (loop
               (setf last (%reannounce node last))
               ;; report the data destination we resolve for each discovered peer
               (dolist (p (dds.disc:node-discovered-participants node))
                 (let ((prefix (dds.rtps.discovery:spdp-data-guid-prefix p)))
                   (unless (gethash prefix dests)
                     (setf (gethash prefix dests) t)
                     (let ((d (dds.disc:resolved-destination p)))
                       (format t "~&[pub] peer discovered -> DATA destination ~a~%"
                               (if d (format nil "~a:~d" (car d) (cdr d))
                                   "NONE (no routable UDPv4 locator)"))))))
               (setf x (+ x dx) y (+ y dy))
               (when (or (<= x 0) (>= x 240)) (setf dx (- dx) x (min 240 (max 0 x))))
               (when (or (<= y 0) (>= y 240)) (setf dy (- dy) y (min 240 (max 0 y))))
               (incf seq)
               (dds.disc:publish-sample
                node (ecase type
                       (:canonical
                        (%serialize-payload
                         (lambda (wc) (serialize-shape-type
                                       (make-shape-type :color color :x x :y y :shapesize shapesize)
                                       wc :xcdr2))))
                       (:tagged
                        (%serialize-payload
                         (lambda (wc) (serialize-tagged-shape
                                       (make-tagged-shape :color color :x x :y y :shapesize shapesize
                                                          :uuid uuid :seq seq)
                                       wc :xcdr2))))))
               (incf n)
               (when (zerop (mod n 30))
                 (format t "~&[pub] sent ~d samples; peers=~d; ACKNACKs received=~d~%"
                         n (hash-table-count dests) (dds.disc:node-acks-in node)))
               (when (and (plusp count) (>= n count)) (return))
               (sleep period))
          (dds.disc:stop-node node)
          (format t "~&[pub] stopped after ~d samples; ACKNACKs received=~d (uuid=~a).~%"
                  n (dds.disc:node-acks-in node) uuid))))
    t))

(declaim (ftype (function ((simple-array (unsigned-byte 8) (12))) string) %hex-prefix))
(defun %hex-prefix (prefix)
  "Lowercase hex of a 12-octet GUID prefix."
  (format nil "~(~{~2,'0x~}~)" (coerce prefix 'list)))

(declaim (ftype (function (dds.rtps.discovery:locator) string) %fmt-locator))
(defun %fmt-locator (loc)
  "Human-readable locator: 'UDPv4 a.b.c.d:port', or 'kind=#xK port=P' for non-UDPv4
   (e.g. SHMEM / UDPv6 — exactly the entries a foreign stack may also advertise)."
  (let ((kind (dds.rtps.discovery:locator-kind loc))
        (port (dds.rtps.discovery:locator-port loc)))
    (if (= kind dds.rtps.discovery:+locator-kind-udpv4+)
        (format nil "UDPv4 ~a:~d" (dds.rtps.discovery:locator-ipv4-string loc) port)
        (format nil "kind=#x~x port=~d" kind port))))

(declaim (ftype (function (list) string) %fmt-locators))
(defun %fmt-locators (locs)
  "Comma-separated locator list, or '(none)'."
  (if (null locs) "(none)" (format nil "~{~a~^, ~}" (mapcar #'%fmt-locator locs))))

(declaim (ftype (function (dds.rtps.discovery:spdp-data) t) %print-participant))
(defun %print-participant (p)
  "Print a discovered participant's advertised locators + the data destination this
   stack resolves for it."
  (format t "~&[spy] participant ~a~%" (%hex-prefix (dds.rtps.discovery:spdp-data-guid-prefix p)))
  (format t "        vendor=~2,'0x.~2,'0x version=~d.~d lease=~ds endpoints=#x~8,'0x~%"
          (ldb (byte 8 8) (dds.rtps.discovery:spdp-data-vendor-id p))
          (ldb (byte 8 0) (dds.rtps.discovery:spdp-data-vendor-id p))
          (dds.rtps.discovery:spdp-data-version-major p)
          (dds.rtps.discovery:spdp-data-version-minor p)
          (dds.rtps.discovery:spdp-data-lease-duration-seconds p)
          (dds.rtps.discovery:spdp-data-builtin-endpoint-set p))
  (format t "        default-unicast:     ~a~%"
          (%fmt-locators (dds.rtps.discovery:spdp-data-default-unicast-locators p)))
  (format t "        metatraffic-unicast: ~a~%"
          (%fmt-locators (dds.rtps.discovery:spdp-data-metatraffic-unicast-locators p)))
  (let ((dest (dds.disc:resolved-destination p)))
    (format t "        -> resolved data destination: ~a~%"
            (if dest (format nil "~a:~d" (car dest) (cdr dest))
                "NONE (no routable UDPv4 locator advertised)"))))

(declaim (ftype (function (&key (:domain (integer 0)) (:seconds (integer 0)) (:advertise-address string)) t) run-spy))
(defun run-spy (&key (domain 0) (seconds 0) (advertise-address "127.0.0.1"))
  "Discovery diagnostic: join multicast SPDP on DOMAIN and print every discovered
   participant's advertised locators + the destination this stack resolves for it
   (no reader/writer). Use it to see exactly what we extract from a foreign SPDP
   announcement, e.g. RTI DDSSpy. SECONDS 0 = forever (Ctrl-C to stop)."
  (let ((node (dds.disc:make-disc-node :guid-prefix (%make-prefix #x59) :domain domain
                                       :multicast t :advertise-address advertise-address)))
    (dds.disc:start-node node)
    (format t "~&[spy] watching domain ~d (multicast 239.255.0.1). Ctrl-C to stop.~%" domain)
    (let ((seen (make-hash-table :test 'equalp)) (last 0) (start (get-internal-real-time)))
      (unwind-protect
           (loop
             (let ((now (get-internal-real-time)))
               (when (> (- now last) (round (* 1.5 internal-time-units-per-second)))
                 (dds.disc:announce-participant node)
                 (setf last now)))
             (dolist (p (dds.disc:node-discovered-participants node))
               (let ((prefix (dds.rtps.discovery:spdp-data-guid-prefix p)))
                 (unless (gethash prefix seen)
                   (setf (gethash prefix seen) t)
                   (%print-participant p))))
             (when (and (plusp seconds)
                        (> (/ (- (get-internal-real-time) start) internal-time-units-per-second)
                           seconds))
               (return))
             (sleep 0.1))
        (dds.disc:stop-node node)
        (format t "~&[spy] stopped; ~d participant(s) discovered.~%" (hash-table-count seen)))
      t)))

(declaim (ftype (function (&key (:domain (integer 0)) (:seconds (integer 0)) (:advertise-address string) (:type symbol)) t) run-subscriber))
(defun run-subscriber (&key (domain 0) (seconds 0) (advertise-address "127.0.0.1") (type :tagged))
  "Subscribe to Square on DOMAIN via multicast discovery and print every shape.
   TYPE selects the payload codec (:canonical | :tagged) and must match the
   publisher. SECONDS 0 = forever (Ctrl-C). Receives from rtishapesdemo / DDSSpy
   (use :canonical) or this harness's publisher."
  (check-type type (member :canonical :tagged))
  (let ((node (dds.disc:make-disc-node :guid-prefix (%make-prefix #x53) :domain domain
                                       :multicast t :advertise-address advertise-address)))
    (dds.disc:add-local-reader node :topic "Square" :type "ShapeType"
                               :reliability dds.rtps.discovery:+reliability-reliable+)
    (dds.disc:enable-subscriber node)
    (dds.disc:start-node node)
    (format t "~&[sub] Square/ShapeType[~(~a~)] domain=~d (multicast 239.255.0.1). Ctrl-C to stop.~%" type domain)
    (let ((printed (make-hash-table :test 'eql))
          (expected (make-hash-table :test 'equal))   ; uuid -> next expected app seq
          (last 0) (seen 0) (start (get-internal-real-time)))
      (unwind-protect
           (loop
             (setf last (%reannounce node last))
             (dolist (sn (sort (dds.disc:node-sample-sns node) #'<))
               (unless (gethash sn printed)
                 (setf (gethash sn printed) t)
                 ;; a sample we cannot parse (wrong TYPE, foreign encoding, malformed)
                 ;; must never crash the subscriber — skip it with a hint.
                 (handler-case
                     (ecase type
                       (:canonical
                        (let ((s (%deserialize-with (dds.disc:node-sample node sn) #'deserialize-shape-type)))
                          (declare (type shape-type s))
                          (format t "~&[sub] Square ~a x=~d y=~d size=~d~%"
                                  (shape-type-color s) (shape-type-x s)
                                  (shape-type-y s) (shape-type-shapesize s))
                          (incf seen)))
                       (:tagged
                        (let ((s (%deserialize-with (dds.disc:node-sample node sn) #'deserialize-tagged-shape)))
                          (declare (type tagged-shape s))
                          (let* ((u (tagged-shape-uuid s)) (q (tagged-shape-seq s)) (exp (gethash u expected)))
                            (when (and exp (/= q exp))
                              (format t "~&[sub] GAP from ~a: expected seq ~d, got ~d~%" u exp q))
                            (setf (gethash u expected) (1+ q))
                            (format t "~&[sub] Square ~a x=~d y=~d size=~d uuid=~a seq=~d~%"
                                    (tagged-shape-color s) (tagged-shape-x s) (tagged-shape-y s)
                                    (tagged-shape-shapesize s) u q)
                            (incf seen)))))
                   (error (e)
                     (format t "~&[sub] sn=~d: cannot parse as ~(~a~) (~a) — TYPE mismatch? RTI Squares are canonical: run TYPE=canonical~%"
                             sn type (type-of e))))))
             (when (and (plusp seconds)
                        (> (/ (- (get-internal-real-time) start) internal-time-units-per-second)
                           seconds))
               (return))
             (sleep 0.05))
        (dds.disc:stop-node node)
        (format t "~&[sub] stopped; received ~d shapes.~%" seen))
      t)))
