# ADR 0006 — Package naming convention

- **Status:** Accepted (2026-06-04)
- **Decision authority:** DG1SBG (owner), by explicit command
- **Relates to:** FR-LANG-6 (stable package/naming contract)

## Decision

Every Lisp package in the stack uses a reverse-DNS canonical name under the
owner's domain, with the short dotted form as a **nickname**:

```
canonical:  net.goenninger.dds.<layer>[.<sub>]
nickname:   dds.<layer>[.<sub>]
```

Current packages:

| Canonical | Nickname |
|---|---|
| `net.goenninger.dds.pal` | `dds.pal` |
| `net.goenninger.dds.core.buffer` | `dds.core.buffer` |
| `net.goenninger.dds.core.arena` | `dds.core.arena` |
| `net.goenninger.dds.cdr` | `dds.cdr` |
| `net.goenninger.dds.types` | `dds.types` |
| `net.goenninger.dds.rtps.history` | `dds.rtps.history` |
| `net.goenninger.dds.xport` | `dds.xport` |
| `net.goenninger.dds.tests` | `dds.tests` |

## Rationale & consequences

- Reverse-DNS canonical names avoid collisions with other libraries in a shared
  image (the owner runs AllegroCL in production alongside other systems).
- The `dds.*` nickname keeps all `in-package`/qualified references terse and
  unchanged; the rename touched only the 8 `defpackage` forms.
- **New packages MUST follow this scheme** — declare the `net.goenninger.dds.*`
  canonical name and the `dds.*` nickname. The hot-path-purity gate and spec
  references continue to name packages by their `dds.*` nickname.
- ASDF **system** names are unchanged (`dds-pal`, `dds-core`, …); this ADR governs
  Lisp packages only.
