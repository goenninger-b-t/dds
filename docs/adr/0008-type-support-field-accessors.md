# ADR 0008 — type-support gains field-accessors (DDS.TYPES)

- **Status:** Accepted (2026-06-06)
- **Deciders:** A0 (integrator)
- **Amends:** ADR 0002 (the frozen L3 `type-support` record, §7.3)

## Context

Content-filtered topics and query conditions (FR-DCPS-5, M3 #4) evaluate a DDS
SQL-subset filter expression (Annex B of the DDS 1.4 spec) against each sample. The
expression references fields by their **IDL member name** (e.g. `id`, `color`). The
generated codec exposes only positional serialize/deserialize and per-type accessors
(`<type>-<slot>`); there is no name→value reflection, which the filter evaluator needs
to resolve a FIELDNAME to a sample value. This is off the hot path (control plane).

## Decision

Add one slot to the frozen `type-support` record:

```
field-accessors  ; alist (FIELD-NAME-STRING . unary-accessor-fn), nil unless generated
```

- Key: the IDL member name, downcased (matched case-insensitively against a FIELDNAME).
- Value: a unary function `sample -> value` (the generated `<type>-<slot>` accessor).
- `define-dds-type` emits an entry for every **scalar / string** member (the filterable
  members). Sequence and nested-struct members are omitted in v1 (not filterable yet;
  dotted/nested FIELDNAMEs are a later increment).
- Exposed via the reader `type-support-field-accessors`.

The slot defaults to `nil`, so the hot path never reads it and types that predate this
slot are unaffected.

## Compatibility

**Backward-compatible.** `make-type-support` is keyword-constructed; the new slot
defaults to `nil`, so every existing call site is unchanged. The hot-path engine funcalls
serialize/deserialize/key-hash only and never touches `field-accessors`; the
`hotpath-purity-gate` file set does not include `type-support.lisp`. Additive extension
of the §7.3 contract, not a breaking change.

## Consumers

- `dds.types` (type-support.lisp slot + export).
- `dds.gen` (dsl.lisp — `define-dds-type` emits the alist).
- `dds.dcps` (the filter evaluator resolves a FIELDNAME via this alist — commit 2 of #4).

## Verification

The filter-grammar unit tests compile + evaluate expressions against generated types
(`dcps-msg`, `shape-type`) by resolving FIELDNAMEs through `field-accessors`. Green on
Clasp + SBCL.
