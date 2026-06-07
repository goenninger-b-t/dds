# QoS & Requested/Offered (RxO) matching

The `dds-qos` system (layer L3) is the control plane's value model: the DDS 1.4 QoS
policy set as a copy-by-value `defstruct`, plus the single Requested/Offered (RxO)
compatibility implementation that decides whether a writer and a reader may match. It is
deliberately foundational — it depends only on `dds-core`, so **both** the discovery
matcher ([Discovery](discovery.md)) and the DCPS entity layer ([DCPS](dcps.md)) share one
`qos-rxo-compatible` rather than re-deriving the §2.2.3 truth table twice. It also carries
the XTypes `TYPE_CONSISTENCY_ENFORCEMENT` policy used by the [type system](type-system.md),
which is reader-only and intentionally *not* part of RxO.

All symbols below are exported from the `net.goenninger.dds.qos` package (nickname
`dds.qos`). The docstrings in `src/dds-qos/qos.lisp` are the contract; this page condenses
them.

## API reference

### Duration_t and its total order

| Symbol | Description |
|---|---|
| `dds.qos:qos-duration` | DDS `Duration_t` struct: a `sec` + `nanosec` pair, both non-negative integers. |
| `dds.qos:make-qos-duration` | Constructor: `(make-qos-duration &optional (sec 0) (nanosec 0))`. |
| `dds.qos:qos-duration-sec` | Accessor for the seconds field. |
| `dds.qos:qos-duration-nanosec` | Accessor for the nanoseconds field. |
| `dds.qos:+duration-zero+` | The zero duration `{0, 0}`; the minimum of the total order. |
| `dds.qos:+duration-infinite+` | `DURATION_INFINITE` = `{0x7fffffff, 0x7fffffff}`; the maximum of the total order. |
| `dds.qos:duration<=` | Total order on `Duration_t`: `(duration<= a b)` is true when `a <= b`, with `DURATION_INFINITE` comparing as the maximum. Drives the duration-policy RxO checks. |

### The `qos` value struct

`dds.qos:qos` (constructor `dds.qos:make-qos`, copier `dds.qos:copy-qos`) holds the
RxO-relevant and commonly-held policies; defaults follow DDS 1.4 §2.2.3. Each slot below has
a package-qualified accessor.

| Accessor | Policy / slot | Default |
|---|---|---|
| `dds.qos:qos-reliability` | RELIABILITY kind — `:best-effort` or `:reliable` | `:best-effort` |
| `dds.qos:qos-durability` | DURABILITY kind — `:volatile`, `:transient-local`, `:transient`, `:persistent` | `:volatile` |
| `dds.qos:qos-deadline` | DEADLINE period (`qos-duration`) | `+duration-infinite+` |
| `dds.qos:qos-latency-budget` | LATENCY_BUDGET duration (`qos-duration`) | `+duration-zero+` |
| `dds.qos:qos-ownership` | OWNERSHIP kind — `:shared` or `:exclusive` | `:shared` |
| `dds.qos:qos-ownership-strength` | OWNERSHIP_STRENGTH (integer) | `0` |
| `dds.qos:qos-liveliness` | LIVELINESS kind — `:automatic`, `:manual-by-participant`, `:manual-by-topic` | `:automatic` |
| `dds.qos:qos-liveliness-lease` | LIVELINESS lease duration (`qos-duration`) | `+duration-infinite+` |
| `dds.qos:qos-destination-order` | DESTINATION_ORDER kind — `:by-reception-timestamp` or `:by-source-timestamp` | `:by-reception-timestamp` |
| `dds.qos:qos-presentation-scope` | PRESENTATION access scope — `:instance`, `:topic`, `:group` | `:instance` |
| `dds.qos:qos-presentation-coherent` | PRESENTATION `coherent_access` flag | `nil` |
| `dds.qos:qos-presentation-ordered` | PRESENTATION `ordered_access` flag | `nil` |
| `dds.qos:qos-data-representation` | DATA_REPRESENTATION list. Writer: the *offered* representation is `(first …)`. Reader: the *set* of accepted representations. | `(:xcdr1)` |
| `dds.qos:qos-partition` | PARTITION — a list of partition-name strings | `()` |
| `dds.qos:qos-history-kind` | HISTORY kind (held, non-RxO) — `:keep-last` or `:keep-all` | `:keep-last` |
| `dds.qos:qos-history-depth` | HISTORY depth (held, non-RxO) | `1` |
| `dds.qos:qos-lifespan` | LIFESPAN duration (held, non-RxO) | `+duration-infinite+` |
| `dds.qos:qos-resource-max-samples` | RESOURCE_LIMITS `max_samples` (`-1` = `LENGTH_UNLIMITED`) | `-1` |
| `dds.qos:qos-resource-max-instances` | RESOURCE_LIMITS `max_instances` (`-1` = `LENGTH_UNLIMITED`) | `-1` |
| `dds.qos:qos-resource-max-samples-per-instance` | RESOURCE_LIMITS `max_samples_per_instance` (`-1` = `LENGTH_UNLIMITED`) | `-1` |
| `dds.qos:qos-type-consistency` | TYPE_CONSISTENCY_ENFORCEMENT policy (a `type-consistency-enforcement`, reader-only, not RxO) | `(make-type-consistency-enforcement)` |

### Endpoint-flavoured constructors

| Symbol | Description |
|---|---|
| `dds.qos:make-writer-qos` | `(make-writer-qos &rest args)` — a `qos` with DataWriter defaults (RELIABILITY defaults to `:reliable`); `args` override slots. |
| `dds.qos:make-reader-qos` | `(make-reader-qos &rest args)` — a `qos` with DataReader defaults (RELIABILITY defaults to `:best-effort`); `args` override slots. |

### RxO compatibility

`dds.qos:qos-rxo-compatible` — `(qos-rxo-compatible offered requested)` decides RxO
compatibility of an OFFERED (writer) QoS against a REQUESTED (reader) QoS per DDS 1.4
§2.2.3. It returns **two values**: `(values compatible-p incompatible)`, where
`compatible-p` is a boolean and `incompatible` is the ordered list of policy keywords that
failed. A non-empty list is exactly the set of policies that would raise
OFFERED/REQUESTED_INCOMPATIBLE_QOS and block the endpoint match. The rule per policy class:

- **Kind-ordered** (`:reliability`, `:durability`, `:liveliness`, `:destination-order`,
  `:presentation`): the offered ordinal rank must be `>=` the requested rank.
- **Duration** (`:deadline`, `:latency-budget`, and the liveliness lease): offered
  duration must be `<=` requested.
- **`:ownership`**: the kinds must be *equal*.
- **`:data-representation`**: the writer's offered representation `(first offered)` must be a
  member of the reader's accepted-representation set.

(PARTITION is **not** checked here — see `partition-match-p` below.)

### Partition matching

`dds.qos:partition-match-p` — `(partition-match-p a b)` is true when the two partition lists
overlap (DDS 1.4 §2.2.3 PARTITION). An empty partition list denotes the default partition,
which matches another empty list. A partition mismatch silently prevents matching and is
**not** an RxO incompatibility (no status is raised). v1 does exact name matching;
wildcard/`fnmatch` names are a later increment (see [Notes / status](#notes--status)).

### `TYPE_CONSISTENCY_ENFORCEMENT` policy

`dds.qos:type-consistency-enforcement` (constructor `dds.qos:make-type-consistency-enforcement`,
copier `dds.qos:copy-type-consistency-enforcement`) is the XTypes 1.3 §7.6.3.4 policy
(policy id 24). It applies to **DataReaders only**, has **no** request/offered semantics, and
is therefore deliberately absent from `qos-rxo-compatible`. Its `kind` selects coercion vs
equivalence; the four boolean flags modulate `ALLOW_TYPE_COERCION` assignability. Fields and
their defaults per §7.6.3.4.1:

| Accessor | Meaning | Default |
|---|---|---|
| `dds.qos:type-consistency-enforcement-kind` | `:allow-type-coercion` or `:disallow-type-coercion` | `:allow-type-coercion` |
| `dds.qos:type-consistency-enforcement-ignore-sequence-bounds` | ignore sequence bounds during assignability | `t` |
| `dds.qos:type-consistency-enforcement-ignore-string-bounds` | ignore string bounds during assignability | `t` |
| `dds.qos:type-consistency-enforcement-ignore-member-names` | match members by ID only, not name | `nil` |
| `dds.qos:type-consistency-enforcement-prevent-type-widening` | forbid a wider writer type building a narrower reader type | `nil` |
| `dds.qos:type-consistency-enforcement-force-type-validation` | require type info to be present in order to match | `nil` |

The enforcement *decision* (assignability vs structural equivalence) lives in the type system —
see `enforce-type-consistency` on the [Type system](type-system.md) page; this policy is just
the value carrier the reader holds.

## Examples

All examples are adapted from passing tests: `run-qos-rxo-test` (in `src/dds-qos/qos.lisp`)
and `run-dcps-incompatible-qos-test` / `run-assignability-test` (in
`src/dds-tests/integration-test.lisp`).

### Build a writer and a reader QoS

```lisp
(ql:quickload :dds-qos)

;; make-writer-qos defaults RELIABILITY to :reliable; make-reader-qos to :best-effort.
;; Extra keyword args override individual slots.
(let ((w (dds.qos:make-writer-qos))
      (r (dds.qos:make-reader-qos :durability :transient-local)))
  (values (dds.qos:qos-reliability w)            ; => :reliable
          (dds.qos:qos-reliability r)            ; => :best-effort
          (dds.qos:qos-durability  r)))          ; => :transient-local
```

### Check RxO — a compatible and an incompatible pair

```lisp
;; Compatible: a RELIABLE writer satisfies a BEST_EFFORT reader (offered rank >= requested).
;; qos-rxo-compatible returns (values compatible-p incompatible-policy-list).
(dds.qos:qos-rxo-compatible (dds.qos:make-writer-qos)
                            (dds.qos:make-reader-qos))
;; => T, NIL          ; compatible, no incompatible policies

;; Incompatible: a VOLATILE writer cannot satisfy a reader requesting TRANSIENT_LOCAL
;; (offered durability rank < requested). This is the case run-dcps-incompatible-qos-test
;; drives end-to-end into REQUESTED/OFFERED_INCOMPATIBLE_QOS.
(dds.qos:qos-rxo-compatible (dds.qos:make-qos :durability :volatile)
                            (dds.qos:make-qos :durability :transient-local))
;; => NIL, (:DURABILITY)

;; Multiple simultaneous failures are all reported (order-independent set):
(nth-value 1
  (dds.qos:qos-rxo-compatible
    (dds.qos:make-qos :reliability :best-effort :ownership :shared)
    (dds.qos:make-qos :reliability :reliable    :ownership :exclusive)))
;; => (:RELIABILITY :OWNERSHIP)
```

### Partition matching (gates the match, no status)

```lisp
;; Empty (default) partitions match each other.
(dds.qos:partition-match-p (dds.qos:make-qos) (dds.qos:make-qos))           ; => T

;; Overlapping name lists match; disjoint ones do not.
(dds.qos:partition-match-p (dds.qos:make-qos :partition '("A" "B"))
                           (dds.qos:make-qos :partition '("B")))            ; => T
(dds.qos:partition-match-p (dds.qos:make-qos :partition '("A"))
                           (dds.qos:make-qos :partition '("B")))            ; => NIL
```

### TYPE_CONSISTENCY_ENFORCEMENT defaults

```lisp
;; The policy's spec defaults (XTypes 1.3 §7.6.3.4.1), as checked by run-assignability-test.
(let ((tce (dds.qos:make-type-consistency-enforcement)))
  (list (dds.qos:type-consistency-enforcement-kind tce)                     ; :ALLOW-TYPE-COERCION
        (dds.qos:type-consistency-enforcement-ignore-sequence-bounds tce)   ; T
        (dds.qos:type-consistency-enforcement-ignore-string-bounds tce)     ; T
        (dds.qos:type-consistency-enforcement-ignore-member-names tce)      ; NIL
        (dds.qos:type-consistency-enforcement-prevent-type-widening tce)    ; NIL
        (dds.qos:type-consistency-enforcement-force-type-validation tce)))  ; NIL

;; A reader QoS carries it by default:
(dds.qos:type-consistency-enforcement-kind
 (dds.qos:qos-type-consistency (dds.qos:make-reader-qos)))                  ; => :ALLOW-TYPE-COERCION
```

## Notes / status

- **RxO-relevant policies** (checked by `qos-rxo-compatible`): RELIABILITY, DURABILITY,
  DEADLINE, LATENCY_BUDGET, OWNERSHIP, LIVELINESS (kind + lease), DESTINATION_ORDER,
  PRESENTATION (scope + the coherent/ordered flags), and DATA_REPRESENTATION.
- **Held (non-RxO) policies** carried for completeness but not part of compatibility:
  HISTORY (kind + depth), LIFESPAN, RESOURCE_LIMITS (`max_samples` /
  `max_instances` / `max_samples_per_instance`), OWNERSHIP_STRENGTH, and
  TYPE_CONSISTENCY_ENFORCEMENT.
- **PARTITION gates matching but raises no status.** It is excluded from
  `qos-rxo-compatible` and handled by `partition-match-p`; a mismatch silently prevents the
  match. Per the source docstring, **wildcard / `fnmatch` partition names are a later
  increment — v1 matches names exactly.**
- **TYPE_CONSISTENCY_ENFORCEMENT is reader-only and deliberately excluded from RxO.** It has
  no request/offered semantics and is immutable after enable; the actual enforcement
  decision (assignability under `:allow-type-coercion` vs structural equivalence under
  `:disallow-type-coercion`) is made by the [type system](type-system.md), not here.
- **The QoS set is the RxO-relevant + commonly-held subset, not yet the full 22+2 policies.**
  The source notes the remaining policies are filled in as the entity model lands.
- The `reliability-max-blocking` slot exists on the `qos` struct (default `100 ms`, used for
  RELIABILITY `max_blocking_time`) but its accessor is **not currently exported**, so it is
  omitted from the API reference above.

## See also

- [DCPS — the DDS entity API](dcps.md) — where RxO failures surface as
  REQUESTED/OFFERED_INCOMPATIBLE_QOS statuses + listeners.
- [Type system & code generation](type-system.md) — assignability and `enforce-type-consistency`.
- [Discovery](discovery.md) — SEDP endpoint matching driven by `qos-rxo-compatible` +
  `partition-match-p`.
