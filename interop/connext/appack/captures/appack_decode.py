#!/usr/bin/env python3
"""Decode the captured APP_ACK / APP_ACK_CONF bodies (ADR 0090).

The layout below is a HYPOTHESIS, assembled from Wireshark's dissector FIELD NAMES plus the ordinary
RTPS submessage prologue. It is believed only if it consumes every body EXACTLY -- no leftover octets,
no overrun -- across every capture. A layout that merely "looks plausible" on one sample is how wire
bugs get shipped, so the self-check is the point of this script.

    APP_ACK body:
      readerId                   4
      writerId                   4
      virtualWriterCount   i32   4
      per virtual writer:
        virtualWriterGuid       16   (guidPrefix 12 + entityId 4)
        intervalCount        i16  2
        octetsToNextVirtualWriter i16 2
        per interval:
          firstSN             SN  8   (i32 high, u32 low)
          lastSN              SN  8
          intervalFlags      i16  2
          intervalPayloadLength i16 2
          payload                 n
      count                i32   4
"""
import struct, sys

def sn(b, o):
    hi, lo = struct.unpack_from('<iI', b, o)
    return (hi << 32) | lo

def decode_app_ack(b):
    out, o = [], 0
    rid, wid = b[0:4], b[4:8]                  # EntityId_t is an OCTET ARRAY, not an int: no endianness
    vwc, = struct.unpack_from('<i', b, 8); o += 12
    out.append("readerId=%s writerId=%s virtualWriterCount=%d" % (rid.hex(), wid.hex(), vwc))
    for v in range(vwc):
        guid = b[o:o+16]; o += 16
        icount, onext = struct.unpack_from('<hh', b, o); o += 4
        out.append("  VW[%d] guid=%s intervalCount=%d octetsToNextVirtualWriter=%d"
                   % (v, guid.hex(), icount, onext))
        for i in range(icount):
            first = sn(b, o); o += 8
            last  = sn(b, o); o += 8
            flags, plen = struct.unpack_from('<hh', b, o); o += 4
            payload = b[o:o+plen]; o += plen
            out.append("    interval[%d] SN %d..%d flags=0x%04x payloadLen=%d payload=%s"
                       % (i, first, last, flags, plen, payload.hex() or "-"))
    count, = struct.unpack_from('<i', b, o); o += 4
    out.append("  count=%d" % count)
    return out, o

def decode_app_ack_conf(b):
    o = 0
    rid, wid = b[0:4], b[4:8]                  # EntityId_t is an OCTET ARRAY, not an int
    vwc, = struct.unpack_from('<i', b, 8); o += 12
    out = ["readerId=%s writerId=%s virtualWriterCount=%d" % (rid.hex(), wid.hex(), vwc)]
    for v in range(vwc):
        guid = b[o:o+16]; o += 16
        out.append("  VW[%d] guid=%s" % (v, guid.hex()))
    count, = struct.unpack_from('<i', b, o); o += 4
    out.append("  count=%d" % count)
    return out, o

sys.path.insert(0, '.')
import rtpsscan

ok = bad = 0
for lt, f in rtpsscan.frames(sys.argv[1]):
    p = rtpsscan.udp_payload(lt, f)
    if not p: continue
    for vendor, sid, flags, body in rtpsscan.submessages(p):
        if sid not in (0x1c, 0x1d): continue
        name = "APP_ACK" if sid == 0x1c else "APP_ACK_CONF"
        try:
            lines, used = (decode_app_ack if sid == 0x1c else decode_app_ack_conf)(body)
        except Exception as e:
            print("%s len=%d  DECODE ERROR: %s" % (name, len(body), e)); bad += 1; continue
        status = "EXACT" if used == len(body) else "MISMATCH consumed=%d of %d" % (used, len(body))
        if used == len(body): ok += 1
        else: bad += 1
        print("\n%s len=%d  [%s]" % (name, len(body), status))
        for l in lines: print("   ", l)

print("\n==== LAYOUT SELF-CHECK: %d exact, %d mismatched ====" % (ok, bad))
print("VERDICT:", "layout CONFIRMED on every body" if bad == 0 else "layout IS WRONG -- do not build on it")
