#!/usr/bin/env python3
"""Enumerate RTPS submessages in a pcap, independently of any dissector (ADR 0090).

Application acknowledgment has no OMG clause, so the wire IS the specification. This parses the
RTPS framing we already implement -- magic/version/vendor/guidPrefix, then a chain of
{submessageId, flags, octetsToNextHeader} -- and reports what actually appeared, so the claim
about APP_ACK rests on observed bytes rather than on a dissector's say-so.
"""
import struct, sys, collections

# RTPS 2.5 SubmessageKind (docs/specs/rtps-2_5.pdf 9.4.5.1.1) + the RTI extensions named by
# Wireshark's dissector metadata (tshark -G values). Anything else prints as raw hex.
KIND = {0x00:"HEADER_EXTENSION",0x01:"PAD",0x06:"ACKNACK",0x07:"HEARTBEAT",0x08:"GAP",
        0x09:"INFO_TS",0x0c:"INFO_SRC",0x0d:"INFO_REPLY_IP4",0x0e:"INFO_DST",0x0f:"INFO_REPLY",
        0x12:"NACK_FRAG",0x13:"HEARTBEAT_FRAG",0x15:"DATA",0x16:"DATA_FRAG",
        0x14:"DATA_SESSION*",0x17:"ACKNACK_BATCH*",0x18:"DATA_BATCH*",0x19:"HEARTBEAT_BATCH*",
        0x1a:"ACKNACK_SESSION*",0x1b:"HEARTBEAT_SESSION*",0x1c:"APP_ACK*",0x1d:"APP_ACK_CONF*",
        0x1e:"HEARTBEAT_VIRTUAL*",0x81:"DATA_FRAG_SESSION*",
        0x30:"SEC_BODY",0x31:"SEC_PREFIX",0x32:"SEC_POSTFIX",0x33:"SRTPS_PREFIX",0x34:"SRTPS_POSTFIX"}

def frames(path):
    d = open(path,'rb').read()
    magic, = struct.unpack_from('<I', d, 0)
    if magic == 0xa1b2c3d4: endian, nano = '<', False
    elif magic == 0xd4c3b2a1: endian, nano = '>', False
    else: sys.exit("not a classic pcap (magic %08x)" % magic)
    linktype, = struct.unpack_from(endian+'I', d, 20)
    off = 24
    while off + 16 <= len(d):
        ts, tus, incl, orig = struct.unpack_from(endian+'IIII', d, off)
        off += 16
        yield linktype, d[off:off+incl]
        off += incl

def udp_payload(linktype, f):
    if linktype == 0:                      # DLT_NULL: 4-byte address family
        if len(f) < 4: return None
        f = f[4:]
    elif linktype == 1:                    # Ethernet
        if len(f) < 14: return None
        f = f[14:]
    if len(f) < 20 or (f[0] >> 4) != 4: return None
    ihl = (f[0] & 0x0f) * 4
    if f[9] != 17: return None             # not UDP
    u = f[ihl:]
    if len(u) < 8: return None
    return u[8:]

def submessages(p):
    """Yield (id, flags, body) for one RTPS message, or None if it is not RTPS."""
    if len(p) < 20 or p[:4] != b'RTPS': return
    vendor = p[6:8]
    off = 20
    while off + 4 <= len(p):
        sid, flags = p[off], p[off+1]
        le = flags & 0x01
        octets, = struct.unpack_from('<H' if le else '>H', p, off+2)
        body_start = off + 4
        body_len = octets if octets else (len(p) - body_start)
        if body_start + body_len > len(p): body_len = len(p) - body_start
        yield vendor, sid, flags, p[body_start:body_start+body_len]
        off = body_start + body_len

def main(path):
    counts, vendors, appacks = collections.Counter(), collections.Counter(), []
    nrtps = 0
    for lt, f in frames(path):
        p = udp_payload(lt, f)
        if not p: continue
        if len(p) >= 4 and p[:4] == b'RTPS': nrtps += 1
        for vendor, sid, flags, body in submessages(p):
            vendors[vendor.hex()] += 1
            counts[sid] += 1
            if sid in (0x1c, 0x1d):
                appacks.append((sid, flags, body))
    print("RTPS messages: %d" % nrtps)
    print("vendorIds seen: %s" % dict(vendors))
    print("\nsubmessages observed:")
    for sid, n in sorted(counts.items()):
        print("  0x%02x  %-20s %d" % (sid, KIND.get(sid, "UNKNOWN"), n))
    print("\n(* = not in RTPS 2.5; named from Wireshark dissector metadata)")
    if appacks:
        print("\n=== APP_ACK / APP_ACK_CONF bodies ===")
        for sid, flags, body in appacks[:6]:
            print("  0x%02x flags=0x%02x len=%d\n    %s" % (sid, flags, len(body), body.hex()))
    else:
        print("\n!! NO APP_ACK (0x1c) OR APP_ACK_CONF (0x1d) IN THIS CAPTURE")

main(sys.argv[1])
