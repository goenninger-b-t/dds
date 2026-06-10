# RTPS engine

The RTPS engine (**L4**, system `dds-rtps`) is the wire-protocol heart of the stack: it
implements the OMG DDSI-RTPS 2.5 message framing, the submessage codec, the `HistoryCache`,
and the stateful reliable writer/reader state machines. It sits above the [CDR codec, buffers
& the arena](cdr-and-memory.md) (which give it the `octet-buffer`/`cursor` it reads and writes
through) and below [Discovery](discovery.md) and [DCPS](dcps.md), which drive it. Two of its
packages — `dds.rtps.message` (the network attack surface) and `dds.rtps.history` (the
per-sample `CacheChange` store) — are CLOS-free hot-path packages: `defstruct` + monomorphic
functions, with every wire constant pinned from the in-repo spec (`docs/specs/rtps-2_5.pdf`)
and every parser bounds-checked before it trusts wire data.

The engine is split across four packages:

| Package | Nickname | Responsibility |
|---|---|---|
| `net.goenninger.dds.rtps.message` | `dds.rtps.message` | Header + submessage framing, EntityId/SequenceNumber(Set), ParameterList (PID) codec, port mapping, the dispatch loop |
| `net.goenninger.dds.rtps.history` | `dds.rtps.history` | `CacheChange`, the `HistoryCache` (HISTORY + RESOURCE_LIMITS) |
| `net.goenninger.dds.rtps.reliable` | `dds.rtps.reliable` | the stateful reliable writer/reader (ReaderProxy/WriterProxy, HEARTBEAT/ACKNACK/GAP, reorder/dedup) |
| `net.goenninger.dds.rtps.discovery` | `dds.rtps.discovery` | SPDP/SEDP `Locator_t` + ParameterList codecs — covered on the [Discovery](discovery.md) page |

This page covers the first three. The discovery codecs (`dds.rtps.discovery`) are documented
under [Discovery](discovery.md) because that is where they are consumed.

---

## API reference

### Message header & framing (`dds.rtps.message`)

The 20-octet RTPS Header and the 4-octet SubmessageHeader (RTPS 2.5 §9.4.4 / §9.4.5.1).

- `dds.rtps.message:+protocol-id+` — the 4-octet RTPS message magic `'R','T','P','S'` (§9.4.4).
- `dds.rtps.message:+protocol-version-major+` / `+protocol-version-minor+` — ProtocolVersion 2.5 (§9.4.4).
- `dds.rtps.message:+vendor-id-unknown+` — `VENDORID_UNKNOWN = {0,0}` (§8.3.5.2). A conformant peer (e.g. RTI Connext) ignores a participant that advertises this; a non-zero id is required.
- `dds.rtps.message:+vendor-id-dev-provisional+` — `0x01FF`, this stack's provisional development VendorId (FR-RTPS-2), non-conflicting with the OMG DDS-RTPS registry (sequential assignments reach `0x0119` as of 2026-06-09). Replaced by an OMG-assigned id once obtained.
- `dds.rtps.message:*vendor-id*` — the 16-bit VendorId written into the RTPS header and the SPDP `PID_VENDORID`; defaults to `+vendor-id-dev-provisional+` (`0x01FF`).
- `dds.rtps.message:write-header` *(cursor guid-prefix &key vendor)* — write the 20-octet RTPS Header (12-octet GUID prefix; header fields are octet arrays, so no endianness).
- `dds.rtps.message:parse-header` *(cursor)* — parse a 20-octet Header; returns `(values major minor vendor guid-prefix)`, or `NIL` on a short buffer / wrong magic. Bounds-checked.
- `dds.rtps.message:write-submessage-header` *(cursor submessage-id flags octets-to-next)* — write a 4-octet SubmessageHeader; `octetsToNextHeader` is a u16 in the cursor's endianness, which the caller keeps consistent with the E flag.
- `dds.rtps.message:parse-submessage-header` *(cursor)* — parse a 4-octet SubmessageHeader; returns `(values submessage-id flags octets-to-next little-endian-p)`, or `NIL` on a short buffer. `octetsToNextHeader` is read with the endianness from the E flag, independent of the cursor.
- `dds.rtps.message:+flag-endianness+` — the submessage E (EndiannessFlag), bit 0; 1 = little-endian (§9.4.5.1.2).

**SubmessageKind ids** (§9.4.5.1.1): `+submsg-pad+`, `+submsg-acknack+`, `+submsg-heartbeat+`,
`+submsg-gap+`, `+submsg-info-ts+`, `+submsg-info-src+`, `+submsg-info-reply-ip4+`,
`+submsg-info-dst+`, `+submsg-info-reply+`, `+submsg-nack-frag+`, `+submsg-heartbeat-frag+`,
`+submsg-data+`, `+submsg-data-frag+`.

### EntityId & SequenceNumber (`dds.rtps.message`)

EntityId is 4 octets `entityKey[3]+entityKind`, MSB-first (§9.3.1.2); SequenceNumber is
`high (i32) + low (u32)` (§9.3.2.10).

- `dds.rtps.message:+entityid-unknown+` — `ENTITYID_UNKNOWN` as an MSB-first u32 (§9.3.1.2).
- `dds.rtps.message:+entityid-participant+` — `ENTITYID_PARTICIPANT = #x000001c1` (§9.3.1.2).
- `dds.rtps.message:write-entity-id` *(cursor entity-id)* — write a 4-octet EntityId MSB-first.
- `dds.rtps.message:read-entity-id` *(cursor)* — read a 4-octet EntityId as a u32 (MSB-first).
- `dds.rtps.message:+sequence-number-unknown+` — `SEQUENCENUMBER_UNKNOWN = {high=-1, low=0}` (§8.3.5.4).
- `dds.rtps.message:write-sequence-number` *(cursor seqnum)* — write an 8-octet SequenceNumber (high i32 then low u32, cursor endianness).
- `dds.rtps.message:read-sequence-number` *(cursor)* — read an 8-octet SequenceNumber as a signed 64-bit value.

### SequenceNumberSet (`dds.rtps.message`)

`bitmapBase + numBits + M=(numBits+31)/32` longs; offset `deltaN` maps to
`bitmap[deltaN/32]`, bit `(31 - deltaN%32)` — MSB-first (§9.4.2.6). The classic off-by-one
source.

- `dds.rtps.message:+seqnum-set-max-bits+` — maximum `numBits` in a SequenceNumberSet (256) (§9.4.2.6).
- `dds.rtps.message:write-sequence-number-set` *(cursor base numbits bitmap)* — write a SequenceNumberSet (`bitmapBase + numBits + M` longs).
- `dds.rtps.message:read-sequence-number-set` *(cursor)* — parse a SequenceNumberSet; returns `(values base numBits bitmap-words)`, or `NIL` on a short buffer / `numBits>256`. Bounds-checked.
- `dds.rtps.message:seqnum-set-bit` *(bitmap delta)* — set the bit for offset `DELTA` (word `DELTA/32`, bit `31 - DELTA%32`).
- `dds.rtps.message:seqnum-set-bit-p` *(bitmap delta)* — T iff the bit for offset `DELTA` is set.
- `dds.rtps.message:seqnum-set-member-p` *(base numbits bitmap seqnum)* — T iff `SEQNUM` is in the set, per the §9.4.2.6 membership rule.

### Reliability submessages: HEARTBEAT / ACKNACK / GAP (`dds.rtps.message`)

Base forms of the three reliability submessages (§9.4.5.7 / §9.4.5.3 / §9.4.5.6). The E flag
derives from the cursor's endianness so the two stay consistent. The GroupInfo (G) and
Filtered (F) extensions are not emitted or parsed in v1.

- `dds.rtps.message:write-heartbeat` *(cursor reader-id writer-id first-sn last-sn count &key final liveliness)* — write a complete HEARTBEAT submessage (base form; body = 28).
- `dds.rtps.message:parse-heartbeat-body` *(cursor flags)* — parse a HEARTBEAT body after its header; returns `(values reader-id writer-id first-sn last-sn count final-p liveliness-p)` or `NIL`.
- `dds.rtps.message:write-acknack` *(cursor reader-id writer-id base numbits bitmap count &key final)* — write a complete ACKNACK submessage (body = 24+4*M).
- `dds.rtps.message:parse-acknack-body` *(cursor flags)* — parse an ACKNACK body; returns `(values reader-id writer-id base numbits bitmap count final-p)` or `NIL`.
- `dds.rtps.message:write-gap` *(cursor reader-id writer-id gap-start base numbits bitmap)* — write a complete GAP submessage (base form; body = 28+4*M).
- `dds.rtps.message:parse-gap-body` *(cursor flags)* — parse a GAP body (base form); returns `(values reader-id writer-id gap-start base numbits bitmap)` or `NIL`.
- HEARTBEAT flags: `+heartbeat-flag-final+` (F), `+heartbeat-flag-liveliness+` (L), `+heartbeat-flag-group-info+` (G; not v1).
- ACKNACK flag: `+acknack-flag-final+` (F).
- GAP flags: `+gap-flag-group-info+` (G), `+gap-flag-filtered+` (F; not parsed in v1).

### DATA submessage (`dds.rtps.message`)

`extraFlags + octetsToInlineQos + readerId + writerId + writerSN + [inlineQos if Q] +
serializedPayload [if D||K]` (§9.4.5.4). v1 emits and parses the **base form (Q=0)**;
`serializedPayload` is passed/returned as a byte region, left in place for the caller.

- `dds.rtps.message:write-data` *(cursor reader-id writer-id writer-sn payload payload-off payload-len &key key)* — write a complete DATA submessage with a `serializedPayload`, no inlineQos. `KEY t` emits a key payload (K=1,D=0); else data (D=1,K=0).
- `dds.rtps.message:parse-data-body` *(cursor flags octets-to-next)* — parse a DATA body (base form, Q=0); returns `(values reader-id writer-id writer-sn has-payload payload-offset payload-len key-p)`, or `NIL` if Q is set (inlineQos deferred) or the buffer is short.
- DATA flags: `+data-flag-inline-qos+` (Q), `+data-flag-data+` (D), `+data-flag-key+` (K), `+data-flag-non-standard+` (N).

### ParameterList / PID codec (`dds.rtps.message`)

A list of `(parameterId, length, value)` Parameters, each 4-byte aligned, terminated by
`PID_SENTINEL` (§9.4.2.11; FR-RTPS-9). The PID constants come from the §9.6.2.2 table. This
codec is the substrate the [Discovery](discovery.md) SPDP/SEDP `ParameterList`s are built on.

- `dds.rtps.message:write-parameter` *(cursor pid value off len)* — write one Parameter: pid + length (padded to a multiple of 4) + value + padding.
- `dds.rtps.message:write-parameter-sentinel` *(cursor)* — write `PID_SENTINEL`, terminating a ParameterList.
- `dds.rtps.message:parse-parameter-list` *(cursor handler)* — iterate Parameters until `PID_SENTINEL`, calling `(handler pid cursor len)` with the cursor at the value; returns `T` on clean termination, `NIL` on a truncated list. Bounds-checked.
- PID constants: `+pid-pad+`, `+pid-sentinel+`, `+pid-participant-lease-duration+`, `+pid-topic-name+`, `+pid-type-name+`, `+pid-protocol-version+`, `+pid-vendorid+`, `+pid-reliability+`, `+pid-durability+`, `+pid-default-unicast-locator+`, `+pid-metatraffic-unicast-locator+`, `+pid-participant-guid+`, `+pid-builtin-endpoint-set+`, `+pid-endpoint-guid+`, `+pid-key-hash+`, `+pid-type-information+`.

### Port mapping (`dds.rtps.message`)

The RTPS well-known port formula (§9.6.1.1): `PB=7400 DG=250 PG=2 d0=0 d1=10 d2=1 d3=11`.

- `dds.rtps.message:spdp-multicast-port` *(domain)* — discovery (SPDP) multicast port: `PB + DG*domain + d0`.
- `dds.rtps.message:spdp-unicast-port` *(domain participant-id)* — discovery (SPDP) unicast port: `PB + DG*domain + d1 + PG*participantId`.
- `dds.rtps.message:user-multicast-port` *(domain)* — user-traffic multicast port: `PB + DG*domain + d2`.
- `dds.rtps.message:user-unicast-port` *(domain participant-id)* — user-traffic unicast port: `PB + DG*domain + d3 + PG*participantId`.

### Message dispatch (`dds.rtps.message`)

- `dds.rtps.message:dispatch-message` *(cursor handler &optional msg-end)* — parse an RTPS message: parse the Header, then for each submessage call `(handler id flags cursor body-len)` with the cursor at the body and its endianness set per the E flag. `MSG-END` bounds the message (e.g. a UDP datagram size); defaults to the buffer capacity. Returns `T` on a well-formed message, `NIL` on bad magic / truncation. Bounds-checked throughout.

### HistoryCache (`dds.rtps.history`)

The change store honouring HISTORY (KEEP_LAST depth / KEEP_ALL) and RESOURCE_LIMITS
(max_samples) (FR-RTPS-5). A hot-path package: the `cache-change` struct and the cache
ops are `defstruct` + monomorphic functions, no CLOS.

- `dds.rtps.history:make-cache-change` *(&key kind writer-guid sn instance-key-hash serialized-payload source-timestamp inline-qos)* — construct a `CacheChange`: the pooled per-sample record (change `KIND` `:data`/`:dispose`/`:unregister`, writer GUID, sequence number, instance key hash, serialized payload, source timestamp, inline QoS).
- `dds.rtps.history:cache-change` / `cache-change-p` — the struct type and its predicate.
- Accessors: `cache-change-kind`, `cache-change-writer-guid`, `cache-change-sn`, `cache-change-instance-key-hash`, `cache-change-serialized-payload`, `cache-change-source-timestamp`, `cache-change-inline-qos`.
- `dds.rtps.history:make-history-cache` *(kind depth resource-limits type-support)* — create a `HistoryCache` with HISTORY (`KIND` `:keep-last`/`:keep-all`, `DEPTH`) and RESOURCE_LIMITS (an integer, a plist with `:max-samples`, or `NIL` = unlimited).
- `dds.rtps.history:history-cache` — the struct type.
- `dds.rtps.history:hc-add-change` *(hc change)* — add a change, enforcing HISTORY + RESOURCE_LIMITS; returns `:OK`, `:DUPLICATE` (SN already present), or `:REJECTED-RESOURCE-LIMITS` (KEEP_ALL at max_samples). KEEP_LAST evicts the lowest SN when at depth.
- `dds.rtps.history:hc-get-change` *(hc seqnum)* — the `CacheChange` with `SEQNUM`, or `NIL`.
- `dds.rtps.history:hc-remove-change` *(hc seqnum)* — remove the change with `SEQNUM`; returns `T` if one was present (and decrements the count).
- `dds.rtps.history:hc-change-count` *(hc)* — the number of changes currently stored.
- `dds.rtps.history:hc-min-seq` *(hc)* / `hc-max-seq` *(hc)* — lowest / highest sequence number present, or `NIL` if empty.
- `dds.rtps.history:hc-changes-for-reader` *(hc reader-proxy)* — the cache changes in ascending SN order (v1 ignores `READER-PROXY`; per-reader filtering lives in the reliable writer).
- `dds.rtps.history:history-not-implemented` — the condition signalled for not-yet-implemented HistoryCache behaviour.

### Reliable writer (`dds.rtps.reliable`)

The stateful reliable writer (§8.4.2): a `HistoryCache`, the last SN written, the HEARTBEAT
count, and a reader-id → `ReaderProxy` table. Operates on submessage field **values** (not
bytes) so the state machine is directly testable; the byte/transport wiring lives a layer up
in [Discovery](discovery.md)'s data plane.

- `dds.rtps.reliable:make-rtps-writer` *(&key hc last-sn hb-count proxies)* — construct a reliable writer (pass `:hc` a `HistoryCache`).
- `dds.rtps.reliable:rtps-writer` — the struct type.
- `dds.rtps.reliable:writer-write` *(writer payload)* — add a new change to the writer's HistoryCache; returns its sequence number.
- `dds.rtps.reliable:writer-heartbeat` *(writer)* — return `(values firstSN lastSN count)` for a HEARTBEAT (§8.3.7.5).
- `dds.rtps.reliable:writer-data-list` *(writer reader-id)* — changes not yet acked by `READER-ID`, as a list of `(sn . payload)` in SN order.
- `dds.rtps.reliable:writer-on-acknack` *(writer reader-id base numbits bitmap)* — process an ACKNACK (§8.3.7.1): confirm SN < `BASE`, then for each NACKed SN return a resend if present, else a GAP. Returns `(values data-resends gap-sns)`, `data-resends` a list of `(sn . payload)`.
- `dds.rtps.reliable:get-reader-proxy` *(writer reader-id)* — the `ReaderProxy` for `READER-ID`, created on first use.
- `dds.rtps.reliable:reader-proxy` — the struct type (the writer-side proxy for one matched reader).
- `dds.rtps.reliable:reader-proxy-acked-base` — the reader's acknowledged watermark (it has acknowledged all SN < acked-base).

### Reliable reader (`dds.rtps.reliable`)

The stateful reliable reader (§8.4.10): a writer-id → `WriterProxy` table. Handles dedup
(duplicate SN overwrites), reorder (stored by SN), and GAP.

- `dds.rtps.reliable:make-rtps-reader` *(&key proxies)* — construct a reliable reader.
- `dds.rtps.reliable:rtps-reader` — the struct type.
- `dds.rtps.reliable:reader-on-data` *(reader writer-id sn payload)* — accept a DATA; idempotent (duplicate SN overwrites — dedup); tracks the highest SN seen so reordered delivery is harmless.
- `dds.rtps.reliable:reader-on-heartbeat` *(reader writer-id first-sn last-sn)* — update the available range `[firstSN, lastSN]` (§8.3.7.5).
- `dds.rtps.reliable:reader-acknack` *(reader writer-id)* — compute an ACKNACK (§8.3.7.1): `(values base numBits bitmap)`. `BASE` is the lowest unreceived SN in `[first, last]` (or `last+1` if none); the bitmap NACKs the unreceived SNs in `[base, last]` (capped at 256).
- `dds.rtps.reliable:reader-on-gap` *(reader writer-id gap-start base numbits bitmap)* — mark GAPped SNs as irrelevant so they do not block the ack (§8.3.7.4): the range `[gapStart, base-1]` plus the SNs listed in the bitmap.
- `dds.rtps.reliable:reader-complete-p` *(reader writer-id)* — T iff every SN in the available range `[first, last]` has been received or GAPped.
- `dds.rtps.reliable:get-writer-proxy` *(reader writer-id)* — the `WriterProxy` for `WRITER-ID`, created on first use.
- `dds.rtps.reliable:writer-proxy` — the struct type (the reader-side proxy for one matched writer).
- `dds.rtps.reliable:writer-proxy-received` — the SN → `payload | :gap` table of what the reader has seen.

---

## Examples

All examples below are adapted from the verified test suite in `src/dds-tests/rtps-test.lisp`
and `src/dds-tests/integration-test.lisp`. Buffers come from the [arena](cdr-and-memory.md);
the `cursor` carries the endianness.

### 1. Frame and dispatch a message (DATA + HEARTBEAT)

Build a Header, a DATA submessage, and a HEARTBEAT into one buffer, then walk them back out
with `dispatch-message`. Adapted from `run-rtps-dispatch-test`.

```lisp
(let* ((buf     (dds.core.buffer:make-octet-buffer 256))
       (c       (dds.core.buffer:cursor buf :endianness :little))
       (prefix  (make-array 12 :element-type '(unsigned-byte 8) :initial-element 0))
       (rid     dds.rtps.message:+entityid-participant+)
       (wid     dds.rtps.message:+entityid-unknown+)
       (payload (make-array 8 :element-type '(unsigned-byte 8)
                              :initial-contents '(0 #x11 0 0 #x2a 0 0 0))))
  ;; write: Header, then DATA (writerSN 7), then HEARTBEAT [1,7] count 1, FinalFlag set
  (dds.rtps.message:write-header c prefix :vendor 0)
  (dds.rtps.message:write-data c rid wid 7 payload 0 8)
  (dds.rtps.message:write-heartbeat c rid wid 1 7 1 :final t)
  ;; rewind and dispatch: the handler sees DATA then HEARTBEAT in order
  (dds.core.buffer:cursor-reset c)
  (let ((seen '()))
    (dds.rtps.message:dispatch-message
     c (lambda (id flags cur body-len)
         (cond
           ((= id dds.rtps.message:+submsg-data+)
            (multiple-value-bind (r w sn) (dds.rtps.message:parse-data-body cur flags body-len)
              (declare (ignore r w))
              (push (list :data sn) seen)))
           ((= id dds.rtps.message:+submsg-heartbeat+)
            (multiple-value-bind (r w first) (dds.rtps.message:parse-heartbeat-body cur flags)
              (declare (ignore r w))
              (push (list :heartbeat first) seen))))))
    (nreverse seen)))                 ; => ((:DATA 7) (:HEARTBEAT 1))
```

### 2. SequenceNumberSet round-trip + membership

The §9.4.2.6 spec example `1234/12:00110` (offsets 2 and 3 set). Adapted from
`run-rtps-seqnum-test`.

```lisp
(let* ((buf (dds.core.buffer:make-octet-buffer 64))
       (c   (dds.core.buffer:cursor buf :endianness :little))
       (bm  (make-array 1 :element-type '(unsigned-byte 32) :initial-element 0)))
  (dds.rtps.message:seqnum-set-bit bm 2)
  (dds.rtps.message:seqnum-set-bit bm 3)
  ;; bitmap word is MSB-first: offsets 2,3 -> #x30000000
  (dds.rtps.message:write-sequence-number-set c 1234 12 bm)
  ;; membership: base+2 and base+3 are in the set; base itself and base+4 are not
  (list (dds.rtps.message:seqnum-set-member-p 1234 12 bm 1236)    ; => T
        (dds.rtps.message:seqnum-set-member-p 1234 12 bm 1234)    ; => NIL
        ;; parse it back
        (multiple-value-list
         (progn (dds.core.buffer:cursor-reset c)
                (dds.rtps.message:read-sequence-number-set c)))))  ; => (1234 12 #(#x30000000))
```

### 3. HistoryCache: KEEP_LAST eviction and KEEP_ALL RESOURCE_LIMITS

Adapted from `run-history-test`. KEEP_LAST evicts the lowest SN at depth; KEEP_ALL rejects
beyond `max_samples` and detects duplicates.

```lisp
;; KEEP_LAST depth 3: adding SN 1..4 evicts SN 1
(let ((hc (dds.rtps.history:make-history-cache :keep-last 3 nil nil)))
  (dolist (sn '(1 2 3 4))
    (dds.rtps.history:hc-add-change hc (dds.rtps.history:make-cache-change :sn sn)))
  (list (dds.rtps.history:hc-change-count hc)            ; => 3
        (dds.rtps.history:hc-get-change hc 1)            ; => NIL (evicted)
        (dds.rtps.history:hc-min-seq hc)                 ; => 2
        (mapcar #'dds.rtps.history:cache-change-sn
                (dds.rtps.history:hc-changes-for-reader hc nil)))) ; => (2 3 4)

;; KEEP_ALL with max_samples = 2: the 3rd add is rejected, a duplicate is detected
(let ((hc (dds.rtps.history:make-history-cache :keep-all 1 2 nil)))
  (list (dds.rtps.history:hc-add-change hc (dds.rtps.history:make-cache-change :sn 1)) ; :OK
        (dds.rtps.history:hc-add-change hc (dds.rtps.history:make-cache-change :sn 2)) ; :OK
        (dds.rtps.history:hc-add-change hc (dds.rtps.history:make-cache-change :sn 3)) ; :REJECTED-RESOURCE-LIMITS
        (dds.rtps.history:hc-add-change hc (dds.rtps.history:make-cache-change :sn 1)))) ; :DUPLICATE
```

### 4. Reliable delivery through a lossy/reorder/duplicate channel

The value-level writer/reader state machines driven by HEARTBEAT → ACKNACK → resend until
the reader is complete. Adapted from `run-reliability-test` (here without the loss injection,
to show the clean handshake).

```lisp
(let* ((writer (dds.rtps.reliable:make-rtps-writer
                :hc (dds.rtps.history:make-history-cache :keep-all 1 nil nil)))
       (reader (dds.rtps.reliable:make-rtps-reader))
       (wid 1) (rid 2) (n 10))
  ;; writer queues 10 samples
  (dotimes (i n) (dds.rtps.reliable:writer-write writer (format nil "m~d" (1+ i))))
  ;; one HEARTBEAT/ACKNACK/resend round, repeated until complete
  (dotimes (round 8)
    (multiple-value-bind (first last count) (dds.rtps.reliable:writer-heartbeat writer)
      (declare (ignore count))
      (dds.rtps.reliable:reader-on-heartbeat reader wid first last))
    (when (dds.rtps.reliable:reader-complete-p reader wid) (return))
    (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wid)
      (multiple-value-bind (resends gaps)
          (dds.rtps.reliable:writer-on-acknack writer rid base numbits bitmap)
        (declare (ignore gaps))
        ;; "deliver" each NACKed change to the reader
        (dolist (cell resends)
          (dds.rtps.reliable:reader-on-data reader wid (car cell) (cdr cell))))))
  (dds.rtps.reliable:reader-complete-p reader wid))      ; => T
```

### 5. GAP: NACKing evicted samples

When a KEEP_LAST writer has already evicted low SNs, an ACKNACK for them yields a GAP (not a
resend) for the evicted range and a resend for what is still cached. Adapted from
`run-gap-handling-test`.

```lisp
(let* ((writer (dds.rtps.reliable:make-rtps-writer
                :hc (dds.rtps.history:make-history-cache :keep-last 2 nil nil)))
       (reader (dds.rtps.reliable:make-rtps-reader))
       (wid 1) (rid 2))
  (dotimes (i 5) (dds.rtps.reliable:writer-write writer (format nil "m~d" (1+ i)))) ; hc holds SN 4,5
  (dds.rtps.reliable:reader-on-heartbeat reader wid 1 5)        ; reader thinks [1,5] available
  (multiple-value-bind (base numbits bitmap) (dds.rtps.reliable:reader-acknack reader wid)
    (multiple-value-bind (resends gaps)
        (dds.rtps.reliable:writer-on-acknack writer rid base numbits bitmap)
      (list (mapcar #'car resends)    ; => (4 5)   present SNs resent
            gaps))))                  ; => (1 2 3)  evicted SNs gapped
```

---

## Notes / status

- **Connext interop is pending a Connext install.** Correctness here is established by
  byte-exact tests against the RTPS 2.5 spec clauses (e.g. the §9.4.5.4 DATA byte image and
  the §9.4.2.6 SequenceNumberSet bytes in `rtps-test.lisp`) and by an offline UDP-loopback
  end-to-end path (`run-end-to-end-test`), not yet by a live RTI Connext capture. The wire
  oracle (tshark RTPS dissector + Connext) is wired separately — see [Interop](interop.md).
- **VendorId is a provisional development value.** `dds.rtps.message:*vendor-id*` defaults to
  `+vendor-id-dev-provisional+` = `0x01FF` (FR-RTPS-2), pending an OMG-assigned id. This was changed
  from `VENDORID_UNKNOWN` (`0x0000`) after a live Connext 7.3.1 capture (2026-06-09) showed Connext
  ignores a participant advertising the zero/unknown VendorId — establishing no unicast discovery
  channel at all; with `0x01FF` Connext accepts the participant and runs the reliable channel. Some
  unit tests still write `:vendor 0` to the header codec directly (codec round-trip, not discovery).
- **DATA handles InlineQos (Q).** When the Q flag is set, `parse-data-body` SKIPS the inlineQos
  ParameterList (every read bounds-checked against the submessage extent first) and reports the
  `serializedPayload` that follows it. Required for keyed types: RTI Connext sends keyed user
  DATA with inlineQos carrying `PID_KEY_HASH`. The payload is handed back as a `[offset, len)`
  region in the receive buffer, left in place for the caller to deserialize. (Emitting inlineQos
  is still a v1 gap.)
- **DATA_FRAG codec (RTPS 2.5 §9.4.5.5).** `write-data-frag` / `parse-data-frag-body` implement the
  fragmented-DATA submessage (flags E=0x01/Q=0x02/K=0x04 pinned from §9.4.5.5; wire order
  `fragmentStartingNum/fragmentsInSubmessage/fragmentSize/sampleSize`); the parser is
  bounds-checked, fuzzed, and rejects the spec-invalid cases (fragmentStartingNum 0, frags 0,
  fragmentSize > sampleSize). The reliable engine carries the rest: `reader-on-data-frag`
  reassembly (guarded by `*max-reassembly-bytes*` / `*max-reassembly-fragments*`),
  `reader-frag-acknack` (NACK_FRAG generation), `writer-frag-plan` / `writer-frag-plan-for`
  (fragment packing + NACK_FRAG-named resends), `writer-frag-heartbeat`, `writer-on-nack-frag`;
  the UDP data plane wires them up (see [Discovery](discovery.md), including the debug-only
  `dds.disc:*debug-drop-fragment-numbers*` fragment-loss injection used for the live NACK_FRAG
  proof). Validated bidirectionally against live RTI Connext 7.3.1 (2026-06-10), including
  forced-fragment-loss recovery driven by Connext's NACK_FRAG. Real Connext-emitted DATA_FRAG
  and NACK_FRAG submessages are locked as byte-exact regression vectors (decode + re-encode);
  the NACK_FRAG capture exposed and fixed a wrong `write-nack-frag` octetsToNextHeader
  (24+4\*M → the spec-correct 28+4\*M, §9.4.5.14 + §9.4.2.8). HEARTBEAT_FRAG has no Connext
  vector: Connext 7.3.1 heartbeats fragmented samples with plain HEARTBEAT (our stack emits
  HEARTBEAT_FRAG and Connext accepts it).
- **HEARTBEAT/ACKNACK/GAP are base forms.** The GroupInfo (G) and Filtered/FilteredCount (F)
  extensions are neither emitted nor parsed in v1.
- **The reliable state machines are value-level, not byte-level.** `dds.rtps.reliable`
  operates on submessage field values so the logic is directly testable; the
  byte/transport/thread wiring lives in the [Discovery](discovery.md) data plane
  (`dataplane.lisp`). The docstrings note the per-reader-proxy / resend-list consing there as
  a documented v1 concern; it is not on a measured hot path.
- **HistoryCache v1 keys changes by SN in a hash-table.** A pooled, zero-alloc store +
  non-consing iteration, per-instance KEEP_LAST, and LIFESPAN expiry are tracked follow-ups
  (see the docstring in `history.lisp`). `hc-changes-for-reader` ignores its `reader-proxy`
  argument for now.

## See also

- [Discovery](discovery.md) — SPDP/SEDP and the reliable UDP data plane that drive this engine.
- [CDR codec, buffers & the arena](cdr-and-memory.md) — the `octet-buffer`/`cursor` and the static arena.
- [DCPS — the DDS entity API](dcps.md) — the DDS-level API layered over the engine.
- [Transports](transports.md) — the UDPv4 transport the data plane sends through.
- [Interop with RTI Connext](interop.md) — the wire oracle and Shapes interop harness.
