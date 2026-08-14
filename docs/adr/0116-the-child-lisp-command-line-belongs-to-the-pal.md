# ADR 0116 — The child-Lisp command line belongs to the PAL

- **Status:** Accepted — **the flags only**; the child's ASDF/Quicklisp bootstrap is explicitly a separate
  slice (§5)
- **Date:** 2026-08-07
- **Requirement:** NFR-PORT, NFR-BUILD; ADR 0021 capability 3 (thread-or-process execution per service)
- **Related:** ADR 0113/0114 (the AllegroCL port that surfaced it)

---

## 1. The defect

`dds-durability/runner.lisp` `:process` mode launches a child Lisp running `durability-service-main`. It
built the command line inline:

```lisp
(list* lisp-bin "--dynamic-space-size" "512"
                "--eval" "(require :asdf)"
                "--eval" "(asdf:load-system :dds-durability)"
                "--eval" (format nil "(dds.durability:durability-service-main :argv ~s)" argv))
```

Those are **SBCL's** flags. Clasp happens to accept `--eval`; **AllegroCL evaluates with `-e` and has no
`--dynamic-space-size` at all**.

⛔ **A child handed another implementation's flags does not report an error.** It never starts, and the
parent waits for a service that will never come up — so this **stalled the entire test suite** on
AllegroCL at `durability-microservice-fuzz`, after 529 of 645 tests had run, and accounted for four of the
twenty failures around it. The failure mode is a hang, not a diagnostic, which is why it cost a bisect to
locate.

## 2. The decision

`dds.pal:lisp-eval-command` — the PAL owns the child command line, exactly as it owns every other
per-implementation spelling:

| implementation | command |
|---|---|
| SBCL | `argv0 --dynamic-space-size 512 --eval F₁ --eval F₂ …` |
| Clasp | `argv0 --non-interactive --eval F₁ --eval F₂ …` |
| AllegroCL | `argv0 -batch -e F₁ -e F₂ …` |

The binary is always this image's own `UIOP:ARGV0`, so a child is the same implementation as its parent —
which is what makes a single per-implementation mapping sufficient.

- SBCL's 512 MB cap is the **pre-existing value**, preserved so the refactor changes no behaviour on the
  implementation that already worked.
- Clasp gains `--non-interactive` so a failing child cannot park in a REPL that never exits.
- ⚠️ AllegroCL is **deliberately not given `-q`**: `-q` suppresses the init file, which is precisely where
  a site puts its ASDF/Quicklisp bootstrap — and a child that cannot find ASDF is the very failure this
  function exists to prevent.

  > ⛔ **CORRECTED 2026-08-14 (ADR 0117 review). The rationale above is FALSE and was never measured.**
  > On the CI host, `(find-package :ql)` and `(find-package :asdf)` are **both NIL after startup with AND
  > without `-q`** — the init file's bootstrap does not survive `-batch`, so omitting `-q` buys the child
  > nothing. What running the init file *does* do is start a swank listener on a fixed port 4008, so a
  > second concurrent run aborts with `"Local socket address already in use (errno 98)"`. `scripts/with-allegro.sh`
  > now passes `-q`. The child bootstraps Quicklisp explicitly instead (§5).

### Returning NIL rather than a broken command

`LISP-EVAL-COMMAND` answers **NIL** when `ARGV0` is unusable, and the runner bails `:no-argv0` on that.

This replaced a real defect introduced while writing this ADR: the runner had its own `ARGV0` guard, and
moving command construction into the PAL left that guard **validating a different call than the one that
built the command**. One check, on the value actually used, is the only arrangement that cannot drift.

## 3. Why this belongs in the PAL and not in the durability runner

The runner is not the only plausible launcher — anything that spawns a peer, a probe, or a service has the
same problem — and the knowledge involved ("how does *this* Lisp evaluate a form from the command line") is
exactly the class the PAL exists to hold. Leaving it inline would guarantee the next launcher re-derives it,
and re-derives it wrong on the implementation nobody tested.

## 4. Verification

- The composed command is correct on all three: SBCL `--dynamic-space-size 512 --eval`, Clasp
  `--non-interactive --eval`, AllegroCL `-batch -e`, each checked on the real implementation.
- All three compile and answer NIL when `ARGV0` is unavailable (as under `--load`), so the runner sheds the
  spec instead of launching a malformed command.
- The full SBCL suite, to prove the refactor did not regress the implementation whose flags these were.

⚠️ Two defects were made and caught while writing this: the guard/use mismatch above, and a dropped closing
paren in **all three** PAL files — found by `READ error during COMPILE-FILE`, not by inspection.

## 5. ⛔ What this does NOT fix — the child bootstrap, a separate slice

Probed on the CI host: an AllegroCL child has **neither ASDF nor Quicklisp**. There is no Allegro init file
there, where SBCL's child inherits both from `~/.sbclrc`. So after this ADR an Allegro child starts with
*correct* flags and then fails at `(asdf:load-system :dds-durability)`.

> ⛔ **CORRECTED 2026-08-14 (ADR 0117 review).** The **conclusion** holds — the child does have neither —
> but the premise is wrong: `/home/frgo/.clinit.cl` **does** exist on the CI host and **is** loaded
> (`alisp` reports `during loading init file`), and it even bootstraps Quicklisp from
> `/opt/common-lisp/quicklisp/setup.lisp`. The reason the child has nothing is that the init file's
> bootstrap does not survive `-batch` (measured, see the §2 correction), not that no init file exists.
>
> ⛔ **The stall attributed to this path never ran through it.** `src/dds-durability/runner.lisp:52` gates
> `:process` mode on `(eq (dds.pal:pal-impl-name) :sbcl)`, and both the `LISP-EVAL-COMMAND` call (`:66`)
> and the `:no-argv0` bail (`:70`) sit **inside** that branch — that gate has been present since the file
> was created (`c212408`), so an AllegroCL child was never handed SBCL's flags and the `:no-argv0` guard
> cannot fire there. On AllegroCL control reaches `:97`, which prints *":process mode not available on
> ALLEGRO — starting in-thread"*. The AllegroCL suite stall at `durability-microservice-fuzz` had a
> different, already-located cause with no subprocess in it: `CODE-CHAR` → NIL in the microservice's UTF-8
> decoder, fixed by `%MS-CHAR` in **ADR 0117**. `LISP-EVAL-COMMAND`'s AllegroCL arm is preventive
> PAL-contract completion, **not** the fix for any observed stall.
>
> The bootstrap gap itself is now closed: the PAL and the launcher both `PROBE-FILE` `~/quicklisp/setup.lisp`
> and then `/opt/common-lisp/quicklisp/setup.lisp`, loading whichever exists (192.168.2.113 has only the
> site path, and a bare `LOAD` would signal `FILE-ERROR` out of a PAL contract function).

That is a **deployment** question, not a flags question — most likely passing `CL_SOURCE_REGISTRY` and a
Quicklisp setup path through `UIOP:LAUNCH-PROGRAM`'s `:environment`, which is a decision about how a child
finds its world rather than about how it is invoked. Bundling it here would conflate two unrelated things
and make neither reviewable.

**So `:process`-mode durability remains non-functional on AllegroCL**, and the four durability arms that
depend on it are expected to keep failing there. What changes is that they now fail *reporting* rather than
*hanging*, which is the difference between a diagnosable problem and a stalled suite.
