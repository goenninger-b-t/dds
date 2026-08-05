# ADR 0104 — A libc symbol POINTER must not depend on which CFFI happens to be loaded

- **Status:** **Accepted** — root-caused, fixed, falsified, suite green on the affected image.
- **Date:** 2026-08-05
- **Requirements at stake:** **NFR-PORT** (three implementations, documented gaps only), **NFR-MEM** (the
  cached pointers exist *because* the zero-allocation datagram path may not resolve a symbol per call).
- **Relates to:** **ADR 0013** (the PAL contract these pointers live under), **ADR 0066** (the raw
  `recvfrom(2)` path that dies first when the pointer is NIL), **ADR 0103** (blocked by this — the Clasp
  image that carries the ADR 0103 fix is exactly the image that exhibits this).

---

## 1. The symptom

The whole suite died on Clasp, inside the UDP receiver thread:

```
#'ensure-core-pointer *** Illegal argument value: PTR may not be NIL - fn = %foreign-funcall-pointer
   |---> src/dds-pal/pal-net.lisp:650          ; the raw recvfrom(2) fast path
```

`dds.pal::*recvfrom-fp*` was `NIL`. It is a `defparameter` initialised **once at load** from
`cffi:foreign-symbol-pointer`, so a NIL there is not a transient failure — every datagram receive on that
image is a hard error, and `run-all-tests` aborts.

## 2. What it is NOT — and this correction matters

The first framing was *"the installed Clasp is broken for `foreign-symbol-pointer`"*, which reads as
*"FFI is broken there"*. **That is false, and another project on this host using CFFI heavily on the same
binary disproves it.** Measured on the affected image:

| probe | result |
|---|---|
| by-name `cffi:foreign-funcall "getpid"` | **works** |
| by-name `shm_open` / `fstat` / `close` / `shm_unlink` / `__error` | **all work** |
| `cffi:foreign-symbol-pointer "getpid"` | **NIL** |
| … with `:library :default` | NIL |
| … after explicitly `load-foreign-library`ing libSystem | **still NIL** |

Only the **dlsym-handle** API is affected. Code that calls foreign functions **by name** — the ordinary
`defcfun` / `foreign-funcall` style — is entirely unaffected. This stack is unusual in caching *pointers*,
and it does so deliberately: a by-name foreign call re-resolves through dlsym on **every** call on Clasp
(~3.8 µs measured, `*clock-gettime-fp*`'s docstring), which is intolerable on a per-datagram path.

**So the blast radius is precisely "the projects that cache foreign symbol pointers", which is this one.**

## 3. The root cause — two different CFFI distributions answer the same call

`SYS:` resolves differently depending on whether Clasp runs from its **source tree** or from an
**installed prefix**, and ASDF's source registry follows it:

| image | `SYS:` | `asdf:load-system :cffi` loads |
|---|---|---|
| Clasp run from its build tree | the clasp source tree | Clasp's **bundled contrib CFFI** |
| Clasp installed under a prefix | `<prefix>/share/clasp/` | **Quicklisp's** `cffi-…-git` |

The two backends differ by one line in `cffi-clasp.lisp`:

```lisp
;; Clasp's BUNDLED contrib CFFI — correct:
(defun %foreign-symbol-pointer (name library)
  ;; CFFI's :default library marker means the global namespace (RTLD_DEFAULT).
  (clasp-ffi:%foreign-symbol-pointer name (if (eq library :default) :rtld-default library)))

;; Quicklisp's upstream CFFI — returns NIL:
(defun %foreign-symbol-pointer (name library)
  (clasp-ffi:%foreign-symbol-pointer name library))
```

CFFI's own `foreign-symbol-pointer` defaults `:library` to the marker `:default` and passes it straight
down. Clasp's primitive does **not** know that keyword — it wants `:rtld-default` — so upstream CFFI hands
it a handle it cannot interpret and gets `NIL`. The bundled contrib carries the translation; upstream does
not. An installed Clasp ships **no contrib lisp tree**, so it always falls through to Quicklisp's CFFI and
**every** default-library lookup silently yields NIL.

**The judgement worth keeping: the same source, the same Clasp version, and the same host produced opposite
behaviour, because the dependency resolved to a different copy.** Neither binary is broken.

## 4. The evidence

Two builds of the **same** Clasp version (`3.0.1-112-gc7faba5ec`, macOS arm64), each with its **own clean
fasl cache** — the caches matter, because both report the same version string and therefore share an ASDF
output-translation directory by default:

| symbol | installed prefix | source tree |
|---|---|---|
| `recvfrom` | **NIL** | resolved |
| `sendto` | **NIL** | resolved |
| `clock_gettime` | **NIL** | resolved |
| `memcpy` | **NIL** | resolved |
| `__atomic_compare_exchange_8` | **NIL** | resolved |
| `__atomic_fetch_add_8` | **NIL** | resolved |

Calling the Clasp primitive **directly with `:rtld-default`** resolves all six on **both** images, which is
what makes the fix a removal of a dependency rather than a workaround for one build.

⚠️ **The atomics line is the one to notice.** `*cas-u64-fp*` / `*cas-u32-fp*` / `*fetch-add-u64-fp*`
(`pal-clasp.lisp`) resolve through the same call, so the foreign-SAP CAS behind the SHMEM lane claim and the
Zero-Copy refcount would have been NIL too. The suite died in the receiver thread first and never reached
them; a reader who fixed only `recvfrom` would have shipped the next failure.

## 5. The fix

One resolver in `pal-contract.lisp` (which loads before both `pal-clasp.lisp` and `pal-net.lisp`), used by
all ten sites:

```lisp
(defun* %global-symbol-pointer (name)
    (function (string) t)
  #+clasp (clasp-ffi:%foreign-symbol-pointer name :rtld-default)
  #-clasp (cffi:foreign-symbol-pointer name))
```

On Clasp this asks for the global namespace **explicitly**, so the answer no longer depends on which CFFI
was loaded. SBCL is unchanged. Reader conditionals are permitted inside `dds-pal/` and nowhere else, which
is exactly where this belongs. The ten sites — `clock_gettime`, `memcpy`, `sendto`, `recvfrom`, the
image-restart re-resolve hook, and the three Clasp atomics — now share one definition rather than repeating
the call, so a future site cannot reintroduce the bare form by copy-paste.

`dds-dare`'s OpenSSL bindings are **not** affected and were deliberately left alone: they resolve against an
explicit `:library *libcrypto*` handle (ADR-era clean-room decision, handle-based dispatch), which never goes
near the `:default` marker.

## 6. Falsification

Not argued — observed. With the bare form, on the installed image: `*recvfrom-fp*` NIL and the suite aborts
in the UDP receiver thread. With the resolver: **629 passed, 0 FAILED, `skipped: 0 — every test ran`.**
The failing and passing runs differ only in this change.

## 7. What this does NOT close

- **It is not fixed upstream.** Quicklisp's CFFI still lacks the `:default` → `:rtld-default` translation on
  the Clasp backend. Any *other* Common Lisp project that caches foreign symbol pointers will hit this on an
  installed Clasp. Worth reporting upstream; not done here.
- **`SYS:`-dependent dependency resolution remains.** An installed Clasp silently picks a different CFFI than
  a source-tree Clasp. This ADR removes our *dependence* on that difference; it does not remove the
  difference, and other Quicklisp-provided contribs may diverge the same way.
- ⚠️ **Two builds of one Clasp version share an ASDF fasl-cache directory**, because the cache is keyed on
  the version string and both report the same one. Any A/B across two such builds must give each its own
  `XDG_CACHE_HOME`, or it measures whichever build compiled first. This bit the first comparison in this
  investigation and produced one round of wrong conclusions before the caches were separated.
