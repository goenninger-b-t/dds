# The `into` arm is 224 B/sample, not zero — and 239 of the 463 it replaced were the access path

**NFR-MEM / ADR 0105 slice 1, Task 8 · macOS/arm64, SBCL · `mem-per-sample`, 60 000 samples, three runs per
arm, quiet machine**

## The headline, stated the way the plan requires

Slice 1's owner-stated exit criterion is **a genuinely 0 B/sample `into` arm**. It is **not met**. The arm
measures **223.9 / 225.0 / 223.9 B/sample**. That is the finding; it is not rounded, not described as
"essentially zero", and not phrased around.

## The three arms

| arm | type | access path | B/sample |
|---|---|---|---|
| COPY | `perf-data` | `take-samples`, samples dropped | 463.0 / 464.1 / 463.0 |
| RETURN | `perf-data` | `take-samples` + `return-loan` | 254.5 / 255.5 / 255.5 |
| **`:fixed-copy`** | `perf-fixed` | `take-samples`, samples dropped | **462.1 / 464.2 / 463.1** |
| **`:into`** | `perf-fixed` | `take-into` (owns==TRUE) | **223.9 / 225.0 / 223.9** |

## What the number decomposes into

`:fixed-copy` and `:into` measure the **same type** through **different access paths**, which is the only
comparison here that means anything — and it is why `:fixed-copy` exists at all. Without it the into figure
is a bare number nobody can attribute.

- **~239 B/sample is the access path.** 463 → 224 on an identical type. That is what ADR 0105 bought: no
  loan handed out, so the wrapper and its decoded struct are recycled inside the call rather than waiting
  on an application that never returns them.
- **~224 B/sample is NOT the access path, and is unattributed.** It survives an access operation that
  allocates nothing of its own, so it lives in the write path, the engine, or a receive-path site none of
  Tasks 5–7 touched. Attributing it is the next hunt and it is slice-2 work, not a rounding error.

## ⚠️ A premise of ADR 0105 §7.1 did not reproduce

§7.1 justifies introducing a fixed-size bench type by asserting that `perf-data`'s `(:sequence :octet)`
member costs **"a measured 15.73 B/sample"** even at zero length, and that the into-arm measured on
`perf-data` would therefore report a floor belonging to the type.

Measured today, on the COPY arm, the two types are **indistinguishable**: `perf-data` 463.0 and
`perf-fixed` 463.1 — a 0.1 B difference against a ~1 B run-to-run spread. **The 15.7 B floor is not there.**
Most likely it was removed by a later change (ADR 0093 slice 4 decodes into a recycled struct and resets
slots in place) and §7.1's figure went stale, but this measurement does not establish the cause and I am not
claiming one.

`perf-fixed` still earns its place, on the two grounds the test now pins rather than on the stale one:

- its key is **4 octets**, so the keyhash takes the direct branch. A key over 16 octets — or any string key,
  whose maximum size is not an integer — takes the MD5 branch, measured at 255.6 B/call on `shape-type`.
  Neither `dsl.lisp` nor `md5.lisp` is in `gate-hotpath`'s `HOTPATH_FILES`, so that allocation would appear
  in **no** tracked inventory: the arm would simply never reach zero and nothing would say why;
- it has no size-dependent member, so the arm cannot acquire a type-dependent floor later.

## The test, and the check that needed a control

`run-perf-fixed-shape-test` asserts both properties from the **outside**, on observable behaviour, because
both are silent when they break:

- the **direct key branch**, from the shape of the handle — the four big-endian key octets followed by
  twelve zeros, which an MD5 digest essentially cannot be. Falsified by giving `perf-fixed` a string key:
  RED at `:pfs-key-direct`, first octet 17 instead of 1.
- **fixed size**, by requiring two samples with different field values to serialize to equal lengths.

⚠️ That second check carries a **positive control**, and it needs one. Sabotaging `perf-fixed` with a
sequence member does **not** falsify it — the build fails earlier, in the constructor, so the assertion is
never reached and "it went red" would prove nothing about the assertion. The control is `perf-data`, which
genuinely has a sequence: two of *its* samples at 4 and 32 octets must serialize to **different** lengths
through the very same measurement. Without it, an equal-length comparison that could never distinguish
anything would sit there reading green forever.
