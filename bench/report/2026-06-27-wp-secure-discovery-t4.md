# WP-DDS-SECURITY-SECURE-DISCOVERY T4 — whole-RTPS-message protection micro-bench

Encode + decode of a representative 256-octet datagram submessage stream, 100000 iterations each (§8.5.1.10-.12). Encode scratch is static-arena-backed (dds.pal:alloc-static); the GMAC/GCM core is the shared %seal/%open-with-km over DDS.DARE/OpenSSL. ns/op = dds.pal:monotonic-ns delta / iters; GC bytes/op = dds.pal:bytes-consed delta / iters (SBCL exact; Clasp reports 0, NFR-PORT). T4 BASELINE; T10 re-measures the integrated path.

| op | ns/op | GC bytes/op |
|----|-------|-------------|
| encode sign | 5204.9 | 1726 |
| decode sign | 5039.2 | 1743 |
| encode encrypt | 5083.1 | 2000 |
| decode encrypt | 5148.2 | 1998 |

