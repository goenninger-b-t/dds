(in-package #:dds.core.arena)

(defparameter *static-arena-bytes* (* 64 1024 1024)
  "Master off-heap byte budget for all hot-path memory (REQUIREMENTS NFR-MEM).
   Read ONCE at init-arena; rebinding afterwards has no effect until teardown.")

(define-condition arena-exhausted (error)
  ((requested :initarg :requested :reader arena-exhausted-requested)
   (remaining :initarg :remaining :reader arena-exhausted-remaining))
  (:report (lambda (c s)
             (format s "static arena exhausted: requested ~d, ~d budget remaining"
                     (arena-exhausted-requested c) (arena-exhausted-remaining c))))
  (:documentation "Raised at provisioning time when a pool exceeds the budget."))

(defstruct (arena (:constructor %make-arena))
  "Static, startup-allocated off-heap memory region with a fixed byte budget;
   pools are carved from it via make-buffer-pool (NFR-MEM)."
  (byte-budget 0 :type fixnum)
  (bytes-used 0 :type fixnum)
  (pools '() :type list)
  (initialized nil :type boolean))

(defstruct (buffer-pool (:constructor %make-buffer-pool))
  (element-bytes 0 :type fixnum)
  (capacity 0 :type fixnum)
  (slots #() :type simple-vector)
  (top 0 :type fixnum)
  (in-use 0 :type fixnum)
  (high-water 0 :type fixnum))

(declaim (ftype (function (arena) boolean) arena-initialized-p))
(declaim (ftype (function (buffer-pool) fixnum) pool-capacity))
(declaim (ftype (function (buffer-pool) fixnum) pool-in-use))
(declaim (ftype (function (buffer-pool) fixnum) pool-high-water))
(declaim (ftype (function (&key (:bytes (integer 0))) arena) init-arena))
(declaim (ftype (function (arena) arena) teardown-arena))
(declaim (ftype (function (arena (integer 1) (integer 1)) buffer-pool) make-buffer-pool))
(declaim (ftype (function (buffer-pool) t) pool-acquire))
(declaim (ftype (function (buffer-pool t) (values)) pool-release))
(declaim (ftype (function (arena) list) arena-report))

(defun arena-initialized-p (arena) "True while ARENA is live (between init-arena and teardown-arena)." (arena-initialized arena))
(defun pool-capacity (pool) "Fixed number of buffers POOL was provisioned with." (buffer-pool-capacity pool))
(defun pool-in-use (pool) "Number of buffers currently checked out of POOL." (buffer-pool-in-use pool))
(defun pool-high-water (pool) "Peak in-use count seen for POOL (NFR-OBS / budget tracking)." (buffer-pool-high-water pool))

(defun init-arena (&key (bytes *static-arena-bytes*))
  "Create the arena with a fixed BYTE budget (defaults from *static-arena-bytes*,
   read once here). One-shot; pools are carved from it via make-buffer-pool."
  (declare (type (integer 0) bytes))
  (%make-arena :byte-budget bytes :bytes-used 0 :pools '() :initialized t))

(defun teardown-arena (arena)
  "Free every pool's static buffers and mark the arena uninitialized."
  (dolist (pool (arena-pools arena))
    (loop for b across (buffer-pool-slots pool)
          when b do (dds.pal:free-static (dds.core.buffer:octet-buffer-vec b))))
  (setf (arena-pools arena) '()
        (arena-bytes-used arena) 0
        (arena-initialized arena) nil)
  arena)

(defun make-buffer-pool (arena element-bytes capacity)
  "Carve a fixed-capacity pool of CAPACITY octet-buffers of ELEMENT-BYTES each,
   pre-allocated once from off-heap static memory. Steady-state acquire/release
   is index manipulation with zero allocation."
  (declare (type (integer 1) element-bytes capacity))
  (let* ((want (* element-bytes capacity))
         (remaining (- (arena-byte-budget arena) (arena-bytes-used arena))))
    (when (> want remaining)
      (error 'arena-exhausted :requested want :remaining remaining))
    (let ((slots (make-array capacity)))
      (dotimes (i capacity)
        (setf (svref slots i) (dds.core.buffer:make-octet-buffer element-bytes)))
      (let ((pool (%make-buffer-pool :element-bytes element-bytes
                                     :capacity capacity
                                     :slots slots
                                     :top capacity)))
        (incf (arena-bytes-used arena) want)
        (push pool (arena-pools arena))
        pool))))

(defun pool-acquire (pool)
  "Pop a buffer from POOL. Return NIL on exhaustion — the caller applies
   RESOURCE_LIMITS, never a GC-heap fallback (NFR-MEM)."
  (let ((top (buffer-pool-top pool)))
    (when (zerop top)
      (return-from pool-acquire nil))
    (let ((new-top (1- top)))
      (setf (buffer-pool-top pool) new-top)
      (let ((obj (svref (buffer-pool-slots pool) new-top)))
        (setf (svref (buffer-pool-slots pool) new-top) nil)
        (incf (buffer-pool-in-use pool))
        (when (> (buffer-pool-in-use pool) (buffer-pool-high-water pool))
          (setf (buffer-pool-high-water pool) (buffer-pool-in-use pool)))
        obj))))

(defun pool-release (pool obj)
  "Return OBJ to POOL."
  (let ((top (buffer-pool-top pool)))
    (setf (svref (buffer-pool-slots pool) top) obj
          (buffer-pool-top pool) (1+ top))
    (decf (buffer-pool-in-use pool))
    (values)))

(defun arena-report (arena)
  "Plist of reserved sizes per pool for startup logging (NFR-OBS)."
  (list :byte-budget (arena-byte-budget arena)
        :bytes-used (arena-bytes-used arena)
        :pools (mapcar (lambda (p)
                         (list :element-bytes (buffer-pool-element-bytes p)
                               :capacity (buffer-pool-capacity p)
                               :high-water (buffer-pool-high-water p)))
                       (arena-pools arena))))
