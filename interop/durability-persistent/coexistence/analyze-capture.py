#!/usr/bin/env python3
# Raw RTPS byte-walk over a macOS lo0 (DLT_NULL) pcapng capture — no tshark dissector required
# (tshark 4.6.x on this host does not dissect DLT_NULL; see the README "tshark / macOS lo0" note).
# Reports, per relay-writer EntityId: DATA count, distinct own-SN, and the inline-QoS PIDs carried.
# The load-bearing question for the WP-DURABILITY-PERSISTENT coexistence leg (ADR 0024):
#   does RTI Persistence Service stamp PID_ORIGINAL_WRITER_INFO (0x0061) on its relayed samples?
# (Our relay does, on every sample; that is the receiver-side dedup key.)
import struct, collections, sys

def frames(path):
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] == b'\x0a\x0d\x0d\x0a':           # pcapng
        off = 0
        while off + 12 <= len(data):
            btype, blen = struct.unpack_from('<II', data, off)
            if blen < 12 or off + blen > len(data):
                break
            if btype == 6:                          # Enhanced Packet Block
                caplen = struct.unpack_from('<I', data, off + 20)[0]
                yield data[off + 28:off + 28 + caplen]
            off += blen
    else:                                           # classic pcap (little-endian)
        off = 24
        while off + 16 <= len(data):
            caplen = struct.unpack_from('<I', data, off + 8)[0]
            yield data[off + 16:off + 16 + caplen]
            off += 16 + caplen

def rtps_payload(pkt):
    if len(pkt) < 4:
        return None
    ip = pkt[4:]                                    # strip 4-byte DLT_NULL address family
    if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 17:
        return None
    udp = ip[(ip[0] & 0xf) * 4:]
    if len(udp) < 8:
        return None
    ulen = struct.unpack_from('>H', udp, 4)[0]
    payload = udp[8:ulen] if ulen >= 8 else udp[8:]
    return payload if payload[:4] == b'RTPS' else None

DATA, DATA_FRAG = 0x15, 0x16
PID_NAME = {0x0061: 'PID_ORIGINAL_WRITER_INFO', 0x0070: 'PID_KEY_HASH'}

def main(path):
    own_sn = collections.defaultdict(set)
    data_by_writer = collections.Counter()
    pids_by_writer = collections.defaultdict(collections.Counter)
    owi_origin = collections.defaultdict(set)
    for pkt in frames(path):
        p = rtps_payload(pkt)
        if not p:
            continue
        off = 20
        while off + 4 <= len(p):
            sid, flags = p[off], p[off + 1]
            le = (flags & 1) == 1
            E = '<' if le else '>'
            elen = struct.unpack_from(E + 'H', p, off + 2)[0]
            sub = p[off + 4:off + 4 + elen] if elen else p[off + 4:]
            if sid in (DATA, DATA_FRAG) and len(sub) >= 24:
                qflag = (flags >> 1) & 1
                otiq = struct.unpack_from(E + 'H', sub, 2)[0]
                wId = sub[8:12].hex()
                shi, slo = struct.unpack_from(E + 'iI', sub, 16)
                own_sn[wId].add((shi << 32) | slo)
                data_by_writer[wId] += 1
                iq = 4 + otiq
                if qflag and iq < len(sub):
                    q = iq
                    while q + 4 <= len(sub):
                        pid = struct.unpack_from(E + 'H', sub, q)[0]
                        plen = struct.unpack_from(E + 'H', sub, q + 2)[0]
                        val = sub[q + 4:q + 4 + plen]
                        if pid == 0x0001:
                            break
                        pids_by_writer[wId][pid] += 1
                        if pid == 0x0061 and len(val) >= 24:
                            oshi, oslo = struct.unpack_from(E + 'iI', val, 16)
                            owi_origin[wId].add(val[0:16].hex() + f":{(oshi << 32) | oslo}")
                        q += 4 + plen
            if elen == 0:
                break
            off += 4 + elen
    print("relay-writer EntityId | DATA | distinct own-SN | distinct OWI-origin | inline-QoS PIDs")
    for w in sorted(data_by_writer, key=lambda k: -data_by_writer[k]):
        pids = ', '.join(f"0x{p:04x}({PID_NAME.get(p, '?')}):{c}"
                         for p, c in pids_by_writer[w].most_common())
        print(f"  {w} | {data_by_writer[w]} | {len(own_sn[w])} | "
              f"{len(owi_origin[w])} | {pids or '(none)'}")

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'captures/coexistence-transient.pcap')
