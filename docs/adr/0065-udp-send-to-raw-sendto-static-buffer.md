# ADR 0065 — `udp-send-to` sends via raw `sendto(2)` and requires a PAL-static buffer

- **Status:** Accepted
- **Date:** 2026-07-20
- **Requirements:** NFR-MEM (0 bytes/sample steady state), NFR-PERF-8, NFR-PERF-3, FR-XPORT-1, NFR-SEC-POSTURE
- **Relates to:** ADR 0062 (the per-sample allocation budget — this is the first RECEIVER-THREAD slice)
- **Contract touched:** `DDS.PAL` — `udp-send-to` (precondition tightened), `*udp-raw-sendto*` (added)

## Context

ADR 0062 split the per-sample allocation budget by phase and directed the work TX-first. That work
landed five slices (3560 → 2883 B/sample). Re-measuring the remaining budget with a probe around each
phase of the `mem-per-sample` cycle — `write-sample`, the empty `take-samples`, the sleep window, the
successful `take-samples` — attributes it as:

| phase | B/sample | share |
|---|---|---|
| WRITE (TX, user thread) | 873 | 30 % |
| MISS (an empty `take-samples`) | 153 | 5 % |
| **the sleep window = RECEIVER THREADS** | **1267** | **44 %** |
| HIT (the take that returns the sample) | 590 | 20 % |

The sleep window is a clean receiver-thread probe because `(sleep 0.0002)` allocates **0 B** on the
calling thread (measured): every byte accrued across it came from another thread. A control arm —
the same cycle tempo with the writer idle — costs 197 B, which is exactly the two empty takes, so
**93 % of the measured number is genuinely marginal per-sample cost**, not amortized background chatter.

Two corrections to the record follow from this:

1. **The receiver thread, not the take path, is the largest remaining phase.** The scoping note that
   preceded this work attributed ~1883 B (65 %) to the user drain/take path and named it the target.
   It counted the whole poll region as user-thread work. The take path is **590 B**; the receiver
   thread is **1267 B**. That matters because it changes *which* problem is next: loan-safe RX pooling
   carries five hazards (read/take aliasing, the WaitSet cross-thread drain, `instance-rec-key-sample`
   retaining sample #1 forever, the N≥2-reader shared-store leak, the KEEP_LAST loan UAF guard), and
   the receiver thread carries **none** of them.
2. **Message counts are exactly 1 DATA + 1 ACKNACK per sample** (counter deltas, not inference). So
   every per-datagram cost on the ACKNACK path is paid once per sample, undivided.

Isolating the primitives on that path (a tight loop of N identical calls, one `bytes-consed` delta
around the loop — the shape that reproduced the empty-take figure exactly) found the cost concentrated
in one place:

| variant | B/call |
|---|---|
| `udp-send-to` as shipped | 360 |
| `sb-bsd-sockets:socket-send` with the address list hoisted | 98 |
| raw `sendto(2)` with a pre-built sockaddr | **0** |

`udp-send-to` was `(socket-send socket buffer length :address (list (%parse-ipv4 host) port))`. About
262 B of the 360 is `%parse-ipv4` **re-parsing the dotted-quad destination STRING on every datagram** —
four `parse-integer` calls, each of which conses. The rest is `socket-send`'s own keyword parsing,
generic-function dispatch, and per-call alien sockaddr.

This is the same defect class as `89bf344`, which removed a `format nil` that rendered an IP string per
locator per send. That fixed the octets→string direction; **the string→octets direction was still there,
on every datagram we send.**

## Decision

1. **`udp-send-to` builds its destination in a pre-allocated foreign `struct sockaddr_in` and calls
   `sendto(2)` directly.** The datagram bytes on the wire are unchanged; only the syscall wrapper differs.

2. **The destination scratch is PER-THREAD**, carved from the same per-thread foreign allocation that
   already backs `*thread-timespec*` and `*thread-atomic-cell*` (24 → 40 octets, one `foreign-alloc` per
   thread, bound by `spawn`). Not global: several threads send on one socket concurrently — each receiver
   thread answers HEARTBEATs while the user thread announces — and a torn destination address is **silent
   mis-delivery**, a datagram to the wrong peer, not a crash. A thread the PAL did not create falls back
   to `with-foreign-object`, which is stack-allocated on SBCL and a real malloc on Clasp.

3. **`sendto` is called through a pre-resolved function pointer** (`*sendto-fp*`), never by name. A
   by-name foreign call re-resolves through `dlsym` on **every** call on Clasp (~3.8 µs measured, the
   defect `*clock-gettime-fp*` documents), and this sits on the ACKNACK path.

4. **`udp-send-to`'s BUFFER precondition is tightened: it MUST be PAL-static (`alloc-static`).** The
   buffer is handed to the kernel by raw pointer, and NFR-MEM is explicit that anything addressed by a
   pointer/SAP is foreign/static and never a plain heap array, because SBCL's and AllegroCL's GCs *move*
   objects — a heap vector's address can be invalidated underneath a blocking syscall. This aligns the
   PAL signature with the memory model the rest of the stack already obeys.

5. **The dotted-quad parse is total and bounded** (NFR-SEC-POSTURE). `HOST` derives from a peer's
   advertised locator, i.e. from wire data. `%fill-sockaddr-in` accumulates digits in a fixnum, caps the
   octet index at 4 and masks each value to 8 bits, so it can never write outside `sin_addr`'s four
   octets. A malformed host yields a well-formed address whose datagram goes nowhere — UDP is
   best-effort and the reliable layer recovers — and can never corrupt the block or the memory after it.

6. **`*udp-raw-sendto*` (default T) keeps the `socket-send` path** as the A/B lever ADR 0062 requires for
   sizing an allocation change, and as an escape hatch if a platform's `sockaddr_in` layout differs from
   the two documented below.

### The ABI constants, and how they are falsified

`sizeof(struct sockaddr_in)` is 16 on both targets, and the layouts differ **only in the first two
octets**, read from the platform headers and never reconstructed from memory:

```
Darwin (MacOSX.sdk/usr/include/netinet/in.h; AF_INET = 2 from sys/socket.h)
  sin_len(u8)@0 = 16   sin_family(u8)@1 = AF_INET   sin_port(u16 net)@2   sin_addr(u32 net)@4   sin_zero[8]@8
Linux/glibc (POSIX 1003.1 <netinet/in.h>) — no sin_len; sin_family is a 2-octet host-order field
  sin_family(u16 host)@0 = AF_INET                  sin_port(u16 net)@2   sin_addr(u32 net)@4   sin_zero[8]@8
```

The prefix is computed from `*features*` rather than a reader conditional, so the shared PAL file stays
conditional-free (the `*clock-monotonic-id*` pattern). 64-bit little-endian only (REQUIREMENTS §8).

**A wrong prefix cannot fail silently, and the gate that proves it already existed.** The kernel rejects
an unknown address family, `sendto(2)` returns −1, and the datagram is dropped. `run-udp-loopback-test`
now runs **both** arms of `*udp-raw-sendto*` and asserts byte-exact delivery in each, so a wrong layout
fails loudly and platform-specifically. **CI/Linux is the oracle for the non-Darwin branch — macOS
cannot see it** (the standing lesson from the uninitialized-memory-on-the-wire and
cannot-shut-down-on-Linux defects, both of which only CI could see).

## Consequences

- **`gate-mem` 2883.0 → 2730.2 B/sample**, A/B'd with the flag set globally (a `let` binding would never
  reach the receiver threads — the trap that misled slices 1 and 3). arm64 ceiling 2950 → 2800.
- The isolated per-call figure (360 B) over-predicted the end-to-end delta (~153–175 B) by roughly 2×.
  **This is the third time a per-site number has over-reported and the ADR 0062 rule holds: per-site
  numbers RANK candidates, `gate-mem` SIZES them.**
- Every UDP datagram the stack sends benefits — discovery announces, HEARTBEATs, ACKNACKs,
  retransmits — not only the measured path.
- **Migration.** Two consumers. `DDS.XPORT.UDP:MAKE-UDP-TRANSPORT` already passed an octet-buffer vec
  (PAL-backed by construction) and needed no buffer change; its send lambda now maps a negative
  `sendto` return to 0 octets sent, because the raw path reports a refused destination by RETURNING
  negative where `socket-send` reported it by SIGNALLING — both arms present one behaviour to the
  caller. `run-udp-loopback-test` moved from a heap array to `alloc-static`.
- **A pre-existing latent defect is closed in passing.** `*clock-gettime-fp*` cached a foreign-symbol
  pointer at load time with **no image-restart hook**, so a dumped core (a delivered
  durability-service executable, per ADR 0038/0039 §5.1) would restart with a dangling pointer and call
  through it. `*sendto-fp*` would have added a second. Both are now re-resolved by one
  `%pal-reresolve-foreign-pointers` hook, mirroring `dds.dare`'s.

## What this ADR does NOT do

- It does not touch the SHMEM path (user DATA rides SHMEM intra-host; only the ACKNACK return path is UDP).
- It does not batch syscalls. `sendmmsg`/`recvmmsg` and `sendmsg`-iovec (IMPLEMENTATION-PLAN §6.1,
  FR-XPORT-6) remain a later step; this ADR only removes the allocation from the existing one-datagram call.
- It does not address the remaining ~900 B of receiver-thread allocation, nor the 590 B take path.
  Those are separately sized and remain open under ADR 0062.
