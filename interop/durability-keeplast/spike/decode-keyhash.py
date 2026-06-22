#!/usr/bin/env python3
# Spike decoder: walk inline-QoS of every DATA-with-payload submessage in a pcap/pcapng,
# looking for PID_KEY_HASH (0x0070, 16-octet body, RTPS 2.5 §9.6.4.8).
# Supports DLT_NULL (loopback, lo0, 4-byte AF header) and DLT_EN10MB (Ethernet, en0, 14-byte header).
# Reports: per-writer-EntityId count of DATA samples with PID_KEY_HASH present,
# the unique 16-octet values seen, and their hex representations.
# Build-clean spike — no src/ changes, no library imports beyond stdlib.
import struct, collections, sys

PID_KEY_HASH  = 0x0070    # RTPS 2.5 §9.6.3.7, §9.6.4.8
PID_STATUS_INFO = 0x0071
PID_OWI       = 0x0061
PID_SENTINEL  = 0x0001

DATA, DATA_FRAG = 0x15, 0x16

def link_type_from_pcapng(data):
    off = 0
    while off + 12 <= len(data):
        btype, blen = struct.unpack_from('<II', data, off)
        if btype == 1 and blen >= 12:
            return struct.unpack_from('<H', data, off + 8)[0]
        if blen == 0: break
        off += blen
    return 1

def frames(path):
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] == b'\x0a\x0d\x0d\x0a':           # pcapng
        dlt = link_type_from_pcapng(data)
        off = 0
        while off + 12 <= len(data):
            btype, blen = struct.unpack_from('<II', data, off)
            if blen < 12 or off + blen > len(data):
                break
            if btype == 6:                          # Enhanced Packet Block
                caplen = struct.unpack_from('<I', data, off + 20)[0]
                yield (dlt, data[off + 28:off + 28 + caplen])
            off += blen
    else:                                           # classic pcap
        dlt = struct.unpack_from('<I', data, 20)[0]
        off = 24
        while off + 16 <= len(data):
            caplen = struct.unpack_from('<I', data, off + 8)[0]
            yield (dlt, data[off + 16:off + 16 + caplen])
            off += 16 + caplen

def rtps_payload(dlt, pkt):
    # Strip link-layer header to get to IP
    if dlt == 0 or dlt == 228:                     # DLT_NULL (lo0, 4-byte AF)
        if len(pkt) < 4: return None
        ip = pkt[4:]
    elif dlt == 1:                                  # DLT_EN10MB (Ethernet, 14-byte header)
        if len(pkt) < 14: return None
        ethertype = struct.unpack_from('>H', pkt, 12)[0]
        if ethertype == 0x8100:                     # 802.1Q VLAN tag
            ip = pkt[18:]
        else:
            ip = pkt[14:]
    else:
        return None
    if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 17:
        return None
    ihl = (ip[0] & 0xf) * 4
    udp = ip[ihl:]
    if len(udp) < 8: return None
    ulen = struct.unpack_from('>H', udp, 4)[0]
    payload = udp[8:max(8, ulen)]
    return payload if len(payload) >= 4 and payload[:4] == b'RTPS' else None

def decode_all(path):
    total           = collections.Counter()
    with_payload    = collections.Counter()
    with_keyhash    = collections.Counter()
    keyhash_vals    = collections.defaultdict(set)
    status_infos    = collections.defaultdict(set)
    samples         = collections.defaultdict(list)   # writerEId -> [(sn, keyhash_hex, si)]
    key_on_data     = collections.defaultdict(int)    # keyhash present + D-flag (regular write)
    key_on_keyonly  = collections.defaultdict(int)    # keyhash present + K-flag only (dispose)

    for dlt, pkt in frames(path):
        p = rtps_payload(dlt, pkt)
        if not p:
            continue
        off = 20
        while off + 4 <= len(p):
            sid, flags = p[off], p[off + 1]
            E = '<' if (flags & 1) else '>'
            elen = struct.unpack_from(E + 'H', p, off + 2)[0]
            sub = p[off + 4:off + 4 + elen] if elen else p[off + 4:]
            if sid == DATA and len(sub) >= 24:
                q_flag = (flags >> 1) & 1
                d_flag = (flags >> 2) & 1
                k_flag = (flags >> 3) & 1
                wId    = sub[8:12].hex()
                shi    = struct.unpack_from(E + 'i', sub, 12)[0]
                slo    = struct.unpack_from(E + 'I', sub, 16)[0]
                sn     = (shi << 32) | slo

                total[wId] += 1
                has_payload = bool(d_flag or k_flag)
                if has_payload:
                    with_payload[wId] += 1

                keyhash = None
                si_val  = None
                if q_flag:
                    otiq = struct.unpack_from(E + 'H', sub, 2)[0]
                    q    = 4 + otiq
                    while q + 4 <= len(sub):
                        pid  = struct.unpack_from(E + 'H', sub, q)[0]
                        plen = struct.unpack_from(E + 'H', sub, q + 2)[0]
                        val  = sub[q + 4:q + 4 + plen]
                        if pid == PID_SENTINEL:
                            break
                        if pid == PID_KEY_HASH and len(val) >= 16:
                            keyhash = val[:16]
                        if pid == PID_STATUS_INFO and len(val) >= 4:
                            si_val = val[:4].hex()
                        q += 4 + plen

                if keyhash is not None:
                    with_keyhash[wId] += 1
                    keyhash_vals[wId].add(bytes(keyhash))
                    if si_val:
                        status_infos[wId].add(si_val)
                    if d_flag:
                        key_on_data[wId] += 1
                    if k_flag and not d_flag:
                        key_on_keyonly[wId] += 1
                    if has_payload and len(samples[wId]) < 5:
                        samples[wId].append((sn, keyhash.hex(), si_val))
            if elen == 0:
                break
            off += 4 + elen

    return total, with_payload, with_keyhash, keyhash_vals, status_infos, samples, key_on_data, key_on_keyonly

# RTPS 2.5 §8.2.4 entity kind (low byte of EntityId)
ENTITY_KIND = {0xc1:'builtin-pmd', 0xc2:'builtin-w-key', 0xc3:'builtin-w-nokey',
               0xc4:'builtin-r-nokey', 0xc7:'builtin-r-key',
               0x01:'user-participant', 0x02:'user-w-key', 0x03:'user-w-nokey',
               0x04:'user-r-nokey', 0x07:'user-r-key', 0x82:'user-w-key-GROUP'}

def report(path):
    total, with_payload, with_keyhash, keyhash_vals, status_infos, samples, key_on_data, key_on_keyonly = decode_all(path)
    if not total:
        print(f"No RTPS DATA submessages found in {path}")
        return
    print(f"\n=== PID_KEY_HASH (0x0070) analysis: {path} ===\n")
    print(f"{'writer-EntityId':<20} {'kind':<22} {'total-DATA':>10} {'w/payload':>10} {'w/keyhash':>10} {'keyhash?':>10}")
    print("-" * 88)
    for wId in sorted(total):
        tp   = total[wId]
        wp   = with_payload[wId]
        wk   = with_keyhash[wId]
        yn   = "YES" if wk else "no"
        kind = ENTITY_KIND.get(int(wId[6:8], 16), f"?0x{wId[6:8]}")
        print(f"  0x{wId:<18} {kind:<22} {tp:>10} {wp:>10} {wk:>10}   {yn}")
    any_keyhash = sum(with_keyhash.values())
    print(f"\nTotal DATA: {sum(total.values())}  w/payload: {sum(with_payload.values())}  w/PID_KEY_HASH: {any_keyhash}")

    if any_keyhash:
        print(f"\n--- PID_KEY_HASH (0x0070) values per writer ---")
        for wId in sorted(keyhash_vals):
            vals = keyhash_vals[wId]
            kd   = key_on_data.get(wId, 0)
            kk   = key_on_keyonly.get(wId, 0)
            kind = ENTITY_KIND.get(int(wId[6:8], 16), '?')
            print(f"\n  writer 0x{wId} ({kind}):  keyhash-on-DATA(D=1)={kd}  keyhash-on-KEY-only(K=1,D=0)={kk}")
            for v in sorted(vals):
                print(f"    value (hex): {v.hex()}")
                if v[4:] == bytes(12):
                    print(f"    => padded short key (form 2, RTPS 2.5 §9.6.4.8): key bytes[0:4]={v[:4].hex()}")
                else:
                    print(f"    => MD5 hash (form 1, RTPS 2.5 §9.6.4.8)")
            if wId in status_infos:
                print(f"    status_info when keyhash present: {sorted(status_infos[wId])}")
            if wId in samples:
                print(f"    first <=5 keyhash-bearing DATA (sn, keyhash, status_info):")
                for s in samples[wId]:
                    si = s[2] if s[2] else "(none)"
                    print(f"      sn={s[0]:5d}  keyhash={s[1]}  si={si}")
        print()
        # Separate builtin vs user
        user_with_kh = {w for w in keyhash_vals if ENTITY_KIND.get(int(w[6:8],16),'?').startswith('user')}
        builtin_with_kh = {w for w in keyhash_vals} - user_with_kh
        if user_with_kh:
            print(f"USER-DATA writers with PID_KEY_HASH: {sorted(user_with_kh)}")
            user_data_kh = sum(key_on_data.get(w,0) for w in user_with_kh)
            print(f"  => keyhash-on-DATA(D=1) samples from user writers: {user_data_kh}")
            if user_data_kh > 0:
                print("FINDING (user data): PID_KEY_HASH IS PRESENT on user-topic keyed DATA-with-payload.")
                print("=> T1 gated key-capture is feasible from the wire (per-instance compaction viable).")
            else:
                print("FINDING (user data): PID_KEY_HASH appears on KEY-ONLY (dispose/unregister) but NOT on regular DATA.")
                print("=> User-data regular writes do NOT carry PID_KEY_HASH in inline-QoS.")
                print("=> T5 live per-instance DoD falls back to keep-all-safe for regular writes.")
        else:
            print("No user-topic writers carried PID_KEY_HASH. Only builtin writers did.")
            if builtin_with_kh:
                print(f"  (builtin writers with keyhash: {sorted(builtin_with_kh)} — expected, builtin protocol)")
    else:
        print("\nFINDING: PID_KEY_HASH is ABSENT from all DATA submessages.")
        print("=> Connext does NOT include PID_KEY_HASH on keyed data-with-payload samples.")
        print("=> T5 live per-instance DoD falls back to keep-all-safe; in-process tests are authoritative.")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("usage: decode-keyhash.py <pcap-or-pcapng-file>")
        sys.exit(1)
    report(sys.argv[1])
