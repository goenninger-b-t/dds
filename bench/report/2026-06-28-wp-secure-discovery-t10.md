# WP-DDS-SECURITY-SECURE-DISCOVERY T10 — rtps_protection integrated send/receive bench

Integrated whole-RTPS-message protection of a representative 256-octet post-header submessage stream, 100000 iterations each, ENCRYPT tier (§8.5.1.10-.12). The send wrap (%maybe-wrap-srtps) and receive unwrap (%handle-datagram) overwrite the REUSED node buffer in place — no fresh per-datagram message-sized array; the residual GC is the codec's →octets return + AEAD intermediates (the inherited T4 carry) + one plain-region subseq per datagram. ns/op = dds.pal:monotonic-ns delta / iters; GC bytes/op = dds.pal:bytes-consed delta / iters (SBCL exact; Clasp 0, NFR-PORT). 'plain' is the unwrapped send (dest not :keyed / rtps NONE) — byte-identical, 0 added.

| path | ns/op | GC bytes/op |
|------|-------|-------------|
| plain (no wrap) | 0.0 | 0 |
| T4-encode (codec) | 5276.5 | 1949 |
| T10-send (integrated) | 5245.0 | 2222 |
| T4-decode (codec) | 5214.9 | 1949 |
| T10-recv (integrated) | 5272.6 | 2287 |

