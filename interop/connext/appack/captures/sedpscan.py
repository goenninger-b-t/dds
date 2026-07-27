import struct, collections, sys
sys.path.insert(0,'.')
from rtpsscan import frames, udp_payload, submessages
def params(payload):
    if len(payload) < 4: return
    e = '<' if (payload[1] & 0x01) else '>'
    off = 4
    while off + 4 <= len(payload):
        pid, plen = struct.unpack_from(e+'HH', payload, off); off += 4
        if pid == 0x0001: return
        if off + plen > len(payload): return
        yield pid, payload[off:off+plen]; off += plen
seen = collections.defaultdict(dict)
for lt, f in frames(sys.argv[1]):
    p = udp_payload(lt, f)
    if not p: continue
    for vendor, sid, flags, body in submessages(p):
        if sid != 0x15 or len(body) < 20: continue
        e = '<' if (flags & 0x01) else '>'
        _, o2iq = struct.unpack_from(e+'HH', body, 0)
        wid = struct.unpack_from('>I', body, 8)[0]
        if wid not in (0x000003c2, 0x000004c2): continue
        off = 4 + o2iq
        if flags & 0x02:
            o = off
            while o + 4 <= len(body):
                pid, plen = struct.unpack_from(e+'HH', body, o); o += 4 + plen
                if pid == 0x0001: break
            off = o
        kind = "PUB" if wid == 0x000003c2 else "SUB"
        for pid, val in params(body[off:]):
            if pid >= 0x8000 or pid in (0x001a,):
                seen[kind][pid] = val.hex() if len(val) <= 12 else "len%d" % len(val)
for kind in ("PUB","SUB"):
    print("%s: %s" % (kind, {("0x%04x"%k):v for k,v in sorted(seen[kind].items())}))
