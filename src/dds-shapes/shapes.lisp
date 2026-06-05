;;;; Standalone Square/ShapeType publisher + subscriber over multicast discovery.
;;;; Built entirely on the participant data plane (dds.disc) + the generated codec
;;;; (dds.gen). Two processes discover each other via SPDP multicast on the domain's
;;;; well-known group, match the "Square" topic via SEDP, and exchange ShapeType
;;;; samples reliably. The same participant is intended to interop with RTI
;;;; rtishapesdemo / Fast DDS / Cyclone Shapes (see docs/interop-shapes.md).

(in-package #:dds.shapes)

;; The Shapes type, EXTENDED with a per-publisher UUID + a per-sample sequence
;; number (uuid identifies the source stream; seq orders it / exposes loss). NOTE:
;; the two trailing fields make this DIVERGE from RTI's canonical ShapeType — it
;; interops harness<->harness, but a stock rtishapesdemo Square reader would reject
;; the type (extra members) unless RTI registers a matching IDL. color is the @key.
;; :final + only 32-bit/string members => XCDR1 and XCDR2 bytes coincide (no DHEADER).
(dds.gen:define-dds-type shape-type (:extensibility :final)
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

(declaim (ftype (function (shape-type) (simple-array (unsigned-byte 8) (*))) %serialize-shape))
(defun %serialize-shape (shape)
  "Serialize SHAPE as a PLAIN_CDR2_LE SerializedPayload (encapsulation header +
   XCDR2 body) into a fresh octet vector — the data-plane publish payload."
  (let* ((buf (dds.core.buffer:make-octet-buffer 256))
         (wc (dds.core.buffer:cursor buf :endianness :little)))
    (dds.cdr:make-encapsulation-header wc :plain-cdr2-le)
    (serialize-shape-type shape wc :xcdr2)
    (let* ((len (dds.core.buffer:cursor-position wc))
           (out (make-array len :element-type '(unsigned-byte 8))))
      (replace out (dds.core.buffer:octet-buffer-vec buf) :end1 len)
      (dds.pal:free-static (dds.core.buffer:octet-buffer-vec buf))
      out)))

(declaim (ftype (function ((simple-array (unsigned-byte 8) (*))) shape-type) %deserialize-shape))
(defun %deserialize-shape (bytes)
  "Parse a SerializedPayload into a shape-type, honoring the encapsulation header's
   representation + endianness so a foreign sender (CDR_LE/BE or CDR2_LE/BE) is
   handled. ShapeType is :final so there is no DHEADER in any of these encodings."
  (let* ((ob (dds.core.buffer:make-octet-buffer (length bytes)))
         (rc (dds.core.buffer:cursor ob :endianness :little)))
    (replace (dds.core.buffer:octet-buffer-vec ob) bytes)
    (let ((rep (dds.cdr:parse-encapsulation-header rc)))
      (dds.core.buffer:cursor-set-endianness
       rc (if (member rep '(:plain-cdr-be :plain-cdr2-be :pl-cdr-be :pl-cdr2-be :delimited-cdr-be))
              :big :little))
      (let ((mode (if (member rep '(:plain-cdr-le :plain-cdr-be)) :xcdr1 :xcdr2)))
        (prog1 (deserialize-shape-type rc mode)
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

(declaim (ftype (function (&key (:domain (integer 0)) (:color string) (:shapesize (integer 0)) (:rate (integer 1)) (:count (integer 0)) (:advertise-address string)) t) run-publisher))
(defun run-publisher (&key (domain 0) (color "BLUE") (shapesize 30) (rate 30) (count 0)
                           (advertise-address "127.0.0.1"))
  "Publish an animated Square ShapeType on DOMAIN via multicast discovery. RATE is
   updates/sec; COUNT 0 means run forever (Ctrl-C to stop). Watchable in RTI
   rtishapesdemo (subscribe to Square on the same domain)."
  (let ((node (dds.disc:make-disc-node :guid-prefix (%make-prefix #x50) :domain domain
                                       :multicast t :advertise-address advertise-address)))
    (dds.disc:add-local-writer node :topic "Square" :type "ShapeType"
                               :reliability dds.rtps.discovery:+reliability-reliable+)
    (dds.disc:enable-publisher node)
    (dds.disc:start-node node)
    (let ((uuid (%make-uuid)))
      (format t "~&[pub] Square/ShapeType color=~a domain=~d uuid=~a (multicast 239.255.0.1). Ctrl-C to stop.~%"
              color domain uuid)
      (let ((x 50) (y 50) (dx 3) (dy 2) (period (/ 1.0 rate)) (n 0) (last 0) (seq 0))
        (unwind-protect
             (loop
               (setf last (%reannounce node last))
               (setf x (+ x dx) y (+ y dy))
               (when (or (<= x 0) (>= x 240)) (setf dx (- dx) x (min 240 (max 0 x))))
               (when (or (<= y 0) (>= y 240)) (setf dy (- dy) y (min 240 (max 0 y))))
               (incf seq)
               (dds.disc:publish-sample
                node (%serialize-shape (make-shape-type :color color :x x :y y
                                                        :shapesize shapesize :uuid uuid :seq seq)))
               (incf n)
               (when (zerop (mod n 30))
                 (format t "~&[pub] seq=~d sent (~d total); Square ~a (~d,~d)~%" seq n color x y))
               (when (and (plusp count) (>= n count)) (return))
               (sleep period))
          (dds.disc:stop-node node)
          (format t "~&[pub] stopped after ~d samples (uuid=~a).~%" n uuid))))
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

(declaim (ftype (function (&key (:domain (integer 0)) (:seconds (integer 0)) (:advertise-address string)) t) run-subscriber))
(defun run-subscriber (&key (domain 0) (seconds 0) (advertise-address "127.0.0.1"))
  "Subscribe to Square ShapeType on DOMAIN via multicast discovery and print every
   shape received. SECONDS 0 means run forever (Ctrl-C to stop). Receives from RTI
   rtishapesdemo (publish Square on the same domain) or this harness's publisher."
  (let ((node (dds.disc:make-disc-node :guid-prefix (%make-prefix #x53) :domain domain
                                       :multicast t :advertise-address advertise-address)))
    (dds.disc:add-local-reader node :topic "Square" :type "ShapeType"
                               :reliability dds.rtps.discovery:+reliability-reliable+)
    (dds.disc:enable-subscriber node)
    (dds.disc:start-node node)
    (format t "~&[sub] Square/ShapeType domain=~d (multicast 239.255.0.1). Ctrl-C to stop.~%" domain)
    (let ((printed (make-hash-table :test 'eql))
          (expected (make-hash-table :test 'equal))   ; uuid -> next expected app seq
          (last 0) (seen 0) (start (get-internal-real-time)))
      (unwind-protect
           (loop
             (setf last (%reannounce node last))
             (dolist (sn (sort (dds.disc:node-sample-sns node) #'<))
               (unless (gethash sn printed)
                 (setf (gethash sn printed) t)
                 (let* ((s (%deserialize-shape (dds.disc:node-sample node sn)))
                        (u (shape-type-uuid s)) (q (shape-type-seq s))
                        (exp (gethash u expected)))
                   (when (and exp (/= q exp))
                     (format t "~&[sub] GAP from ~a: expected seq ~d, got ~d~%" u exp q))
                   (setf (gethash u expected) (1+ q))
                   (format t "~&[sub] Square ~a x=~d y=~d size=~d uuid=~a seq=~d~%"
                           (shape-type-color s) (shape-type-x s) (shape-type-y s)
                           (shape-type-shapesize s) u q))
                 (incf seen)))
             (when (and (plusp seconds)
                        (> (/ (- (get-internal-real-time) start) internal-time-units-per-second)
                           seconds))
               (return))
             (sleep 0.05))
        (dds.disc:stop-node node)
        (format t "~&[sub] stopped; received ~d shapes.~%" seen))
      t)))
