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
PID_NAME = {0x0061: 'PID_ORIGINAL_WRITER_INFO', 0x0070: 'PID_KEY_HASH',
            0x0071: 'PID_STATUS_INFO', 0x0001: 'PID_SENTINEL'}

def data_submessages(path):
    "Yield (E, srcGuidPrefix, writerEntityIdHex, ownSN, qflag, iqOffset, sub) for every DATA/DATA_FRAG."
    for pkt in frames(path):
        p = rtps_payload(pkt)
        if not p:
            continue
        src_prefix = p[8:20]                          # RTPS hdr: 'RTPS'(4) ver(2) vendor(2) guidPrefix(12)
        off = 20
        while off + 4 <= len(p):
            sid, flags = p[off], p[off + 1]
            E = '<' if (flags & 1) else '>'
            elen = struct.unpack_from(E + 'H', p, off + 2)[0]
            sub = p[off + 4:off + 4 + elen] if elen else p[off + 4:]
            if sid in (DATA, DATA_FRAG) and len(sub) >= 24:
                qflag = (flags >> 1) & 1
                otiq = struct.unpack_from(E + 'H', sub, 2)[0]
                shi, slo = struct.unpack_from(E + 'iI', sub, 16)
                yield (E, src_prefix, sub[8:12].hex(), (shi << 32) | slo, qflag, 4 + otiq, sub)
            if elen == 0:
                break
            off += 4 + elen

def dedup_union(path):
    "Cross-relay exactly-once arithmetic: collect the per-relay-writer set of OWI origin (GUID,SN)"
    " tuples, then report the UNION (= the count a receiver deduplicating on (origGUID,origSN) must"
    " deliver) versus the SUM (= the naive 2N a non-deduplicating receiver would deliver). The"
    " gap UNION < SUM is the wire proof that exactly-once required collapsing two relay streams."
    per_writer = collections.defaultdict(set)              # writerEID -> {(origGUIDhex, origSN)}
    for E, src_prefix, wId, own_sn, qflag, iq, sub in data_submessages(path):
        if not (qflag and iq < len(sub)):
            continue
        q = iq
        while q + 4 <= len(sub):
            pid = struct.unpack_from(E + 'H', sub, q)[0]
            plen = struct.unpack_from(E + 'H', sub, q + 2)[0]
            val = sub[q + 4:q + 4 + plen]
            if pid == 0x0001:
                break
            if pid == 0x0061 and len(val) >= 24:
                oshi, oslo = struct.unpack_from(E + 'iI', val, 16)
                per_writer[wId].add((val[0:16].hex(), (oshi << 32) | oslo))
            q += 4 + plen
    if not per_writer:
        print("No OWI-stamping writer in this capture (no replay-with-OWI episode captured).")
        return
    union = set()
    total = 0
    relays = sorted(per_writer)
    for wId in relays:
        s = per_writer[wId]
        sns = sorted({sn for _, sn in s})
        contiguous = bool(sns) and sns == list(range(sns[0], sns[-1] + 1))
        print(f"  relay 0x{wId}: OWI origin tuples={len(s)} "
              f"origSN[min={sns[0]} max={sns[-1]} contiguous={contiguous}]")
        union |= s
        total += len(s)
    print(f"  --> relays-that-stamped-OWI = {len(relays)} ({', '.join('0x'+w for w in relays)})")
    print(f"  --> SUM over relays (naive, no dedup) = {total}")
    print(f"  --> UNION (distinct origin (GUID,SN))  = {len(union)}   <= exactly-once N a dedup receiver delivers")
    if len(relays) >= 2 and len(union) < total:
        print(f"  => DUAL-RELAY OVERLAP PRESENT: SUM {total} > UNION {len(union)} "
              f"(dedup must collapse {total - len(union)} duplicate copies)")
    elif len(relays) < 2:
        print("  => only ONE relay stamped OWI on this capture's replay window "
              "(cross-relay overlap not captured here; see the receiver delivery count + README)")


def owi_dump(path):
    "Decode each DATA's PID_ORIGINAL_WRITER_INFO (0x0061) origin (GUID,SN) and decide Branch A vs B."
    owi_samples = collections.defaultdict(list)        # writerEID -> [(ownSN, origGUIDhex, origSN, valhex)]
    owi_origins = collections.defaultdict(set)         # writerEID -> {(origGUIDhex, origSN)}
    direct_guids = set()                               # full GUIDs of writers that send DATA without OWI
    for E, src_prefix, wId, own_sn, qflag, iq, sub in data_submessages(path):
        has_owi = False
        if qflag and iq < len(sub):
            q = iq
            while q + 4 <= len(sub):
                pid = struct.unpack_from(E + 'H', sub, q)[0]
                plen = struct.unpack_from(E + 'H', sub, q + 2)[0]
                val = sub[q + 4:q + 4 + plen]
                if pid == 0x0001:
                    break
                if pid == 0x0061 and len(val) >= 24:    # GUID(16) | SN.high(i32 LE) | SN.low(u32 LE)
                    has_owi = True
                    oshi, oslo = struct.unpack_from(E + 'iI', val, 16)
                    osn = (oshi << 32) | oslo
                    oguid = val[0:16].hex()
                    owi_origins[wId].add((oguid, osn))
                    if len(owi_samples[wId]) < 5:
                        owi_samples[wId].append((own_sn, oguid, osn, val[:24].hex()))
                q += 4 + plen
        if not has_owi:
            direct_guids.add((src_prefix + bytes.fromhex(wId)).hex())
    if not owi_origins:
        print("No PID_ORIGINAL_WRITER_INFO (0x0061) on any DATA in this capture.")
        print("=> No per-sample OWI present in THIS capture (does not by itself prove absence; the"
              " emitter may only stamp OWI when replaying retained history to a late joiner).")
        return
    for wId in sorted(owi_origins):
        oguids = {g for g, _ in owi_origins[wId]}
        osns = sorted({s for _, s in owi_origins[wId]})
        contiguous = osns == list(range(osns[0], osns[-1] + 1))
        print(f"=== writer EntityId 0x{wId} — {len(owi_origins[wId])} distinct OWI origin(s) ===")
        print("  ownSN | origGUID(hex) | origSN | 0x0061 body (24B hex)")
        for s in owi_samples[wId]:
            print(f"    {s[0]} | {s[1]} | {s[2]} | {s[3]}")
        print(f"  origin GUID set: {sorted(oguids)}")
        print(f"  origin SN: min={osns[0]} max={osns[-1]} count={len(osns)} contiguous={contiguous}")
        for og in sorted(oguids):
            is_direct = og in direct_guids
            verdict = ('Branch A (origin == an original writer real GUID/SN seen in-capture)'
                       if is_direct else
                       'INCONCLUSIVE here (origin GUID not seen as a direct writer in THIS capture — '
                       'either Branch B synthetic, OR Branch A but the original writer is not in-window)')
            print(f"  origin {og}: also-a-direct-writer-GUID={is_direct} => {verdict}")

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
    args = sys.argv[1:]
    if args and args[0] == '--owi-dump':
        owi_dump(args[1] if len(args) > 1 else 'captures/coexistence-transient.pcap')
    elif args and args[0] == '--dedup-union':
        dedup_union(args[1] if len(args) > 1 else 'captures/coexistence-transient.pcap')
    else:
        main(args[0] if args else 'captures/coexistence-transient.pcap')
