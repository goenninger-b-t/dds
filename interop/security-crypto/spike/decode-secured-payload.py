#!/usr/bin/env python3
"""
Decode a tshark/pcap capture of a Connext-Security DATA submessage carrying a
SecuredPayload (DDS-Security 1.1 §9.5.3.3, serialized-payload protection).

Usage:
  python3 decode-secured-payload.py [capture.pcap]

The script walks every RTPS DATA submessage, identifies the serialized-payload
region (the bytes after the inline-QoS block), and parses the SecuredPayload
structure:

  SecureDataHeader   (20 bytes)
    transformation_kind   [0:4]   = CryptoTransformKind (octet[4])
    transformation_key_id [4:8]   = CryptoTransformKeyId (octet[4])
    session_id            [8:12]  = (octet[4])   LE uint32 within RTPS LE-E flag
    init_vector_suffix    [12:20] = (octet[8])   random, per-session

  crypto_content         (4 + ciphertext_len bytes)
    length prefix         [0:4]  = uint32 LE/BE per RTPS endianness flag
    ciphertext            [4:4+N]

  SecureDataTag          (4 + 16 bytes, receiver_specific_macs=0)
    common_mac            [0:16] = AES-GCM authentication tag
    receiver_specific_macs_count [16:20] = 0 (no per-reader MACs for payload protection)

References:
  DDS-Security 1.1 §9.5.3.3.1 (SecureDataHeader)
  DDS-Security 1.1 §9.5.3.3.3 (SecureDataTag)
  DDS-Security 1.1 §9.5.3.3.4.4 (encode_serialized_data)
  OMG RTPS 2.5 §8.3.7.2 (DATA submessage wire layout)

Hex-dump produced with field annotations for the spike report.
"""
import struct
import sys
import textwrap

# CryptoTransformKind constants (DDS-Security 1.1 §9.5.3.3.1 Table 69)
TRANSFORM_KIND = {
    bytes([0, 0, 0, 0]): "CRYPTO_TRANSFORMATION_KIND_NONE",
    bytes([0, 0, 0, 1]): "CRYPTO_TRANSFORMATION_KIND_AES128_GMAC",
    bytes([0, 0, 0, 2]): "CRYPTO_TRANSFORMATION_KIND_AES128_GCM",
    bytes([0, 0, 0, 3]): "CRYPTO_TRANSFORMATION_KIND_AES256_GMAC",
    bytes([0, 0, 0, 4]): "CRYPTO_TRANSFORMATION_KIND_AES256_GCM",
}


def hexdump(data, indent=4, prefix=""):
    """Format bytes as annotated hex dump."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{' ' * indent}{prefix}{i:04x}  {hex_part:<47}  {asc_part}")
    return "\n".join(lines)


def frames(path):
    """Yield raw frame bytes from a pcap or pcapng file."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] == b"\x0a\x0d\x0d\x0a":           # pcapng
        off = 0
        while off + 12 <= len(data):
            btype, blen = struct.unpack_from("<II", data, off)
            if blen < 12 or off + blen > len(data):
                break
            if btype == 6:                          # Enhanced Packet Block
                caplen = struct.unpack_from("<I", data, off + 20)[0]
                yield data[off + 28:off + 28 + caplen]
            off += blen
    else:                                           # classic pcap (little-endian hdr)
        off = 24
        while off + 16 <= len(data):
            caplen = struct.unpack_from("<I", data, off + 8)[0]
            yield data[off + 16:off + 16 + caplen]
            off += 16 + caplen


def rtps_payload(pkt):
    """Strip link/IP/UDP headers and return the RTPS PDU bytes, or None."""
    if len(pkt) < 4:
        return None
    # macOS loopback DLT_NULL: 4-byte AF prefix then IPv4
    ip = pkt[4:]
    if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 17:   # not IPv4/UDP
        return None
    udp = ip[(ip[0] & 0xF) * 4:]
    if len(udp) < 8:
        return None
    ulen = struct.unpack_from(">H", udp, 4)[0]
    payload = udp[8:ulen] if ulen >= 8 else udp[8:]
    return payload if payload[:4] == b"RTPS" else None


def data_submessages(rtps_pdu):
    """Yield (flags, endian, submsg_bytes) for every DATA (0x15) submessage."""
    off = 20                                        # skip RTPS header (20 bytes)
    while off + 4 <= len(rtps_pdu):
        sid = rtps_pdu[off]
        flags = rtps_pdu[off + 1]
        le = bool(flags & 0x01)
        E = "<" if le else ">"
        elen = struct.unpack_from(E + "H", rtps_pdu, off + 2)[0]
        if elen == 0:
            break
        sub = rtps_pdu[off + 4:off + 4 + elen]
        if sid == 0x15 and len(sub) >= 24:          # DATA submessage
            yield flags, le, sub
        off += 4 + elen


def parse_secured_payload(payload_bytes, le):
    """
    Parse SecuredPayload from the DATA serialized-payload region.
    Returns a dict with all fields and offsets, or raises ValueError.

    Wire layout (DDS-Security 1.1 §9.5.3.3):
      SecureDataHeader  (20 bytes)
        [0:4]   transformation_kind   (CryptoTransformKind = octet[4])
        [4:8]   transformation_key_id (CryptoTransformKeyId = octet[4])
        [8:12]  session_id            (octet[4])
        [12:20] init_vector_suffix    (octet[8])
      crypto_content
        [20:24] length (uint32, endian per RTPS E flag)
        [24:24+N] ciphertext
      SecureDataTag  (at offset 24+N)
        [0:16]  common_mac            (AES-GCM tag, 16 bytes)
        [16:20] receiver_specific_macs_count (uint32, = 0 for payload protection)
    """
    E = "<" if le else ">"
    if len(payload_bytes) < 4:
        raise ValueError(f"payload too short for CDR header: {len(payload_bytes)} bytes")

    # The serialized-payload starts with a 4-byte CDR/RTPS encapsulation header.
    # For a SecuredPayload this header is the first 4 bytes of SecureDataHeader:
    # the transformation_kind bytes [0..3].
    #
    # However, Connext may write a standard CDR encapsulation header here FIRST
    # (0x00 0x03 0x00 0x00 for XCDR2-LE or 0x00 0x01 0x00 0x00 for CDR-LE)
    # before the SecuredPayload. Detect the actual start.
    off = 0
    # Peek at the first 4 bytes — if they look like a known CDR header, skip them.
    cdr_reprs = {
        bytes([0x00, 0x00, 0x00, 0x00]),  # CDR_BE
        bytes([0x00, 0x01, 0x00, 0x00]),  # CDR_LE
        bytes([0x00, 0x02, 0x00, 0x00]),  # PL_CDR_BE
        bytes([0x00, 0x03, 0x00, 0x00]),  # PL_CDR_LE
        bytes([0x00, 0x04, 0x00, 0x00]),  # PL_CDR2_BE
        bytes([0x00, 0x05, 0x00, 0x00]),  # PL_CDR2_LE
        bytes([0x00, 0x06, 0x00, 0x00]),  # CDR2_BE
        bytes([0x00, 0x07, 0x00, 0x00]),  # CDR2_LE
    }
    if payload_bytes[0:4] in cdr_reprs:
        off = 4                             # standard representation header; skip

    if len(payload_bytes) - off < 24:
        raise ValueError(f"payload too short for SecureDataHeader: {len(payload_bytes)} bytes (off={off})")

    result = {"cdr_header_bytes": payload_bytes[0:off] if off else None, "base_off": off}

    # SecureDataHeader (20 bytes)
    hdr_off = off
    tk = payload_bytes[off:off + 4]
    result["transformation_kind_bytes"] = tk
    result["transformation_kind_name"] = TRANSFORM_KIND.get(bytes(tk), f"UNKNOWN({tk.hex()})")
    result["transformation_kind_offset"] = off

    key_id = payload_bytes[off + 4:off + 8]
    result["transformation_key_id"] = key_id
    result["transformation_key_id_offset"] = off + 4

    sess_id = payload_bytes[off + 8:off + 12]
    result["session_id"] = sess_id
    result["session_id_u32_le"] = struct.unpack_from("<I", sess_id, 0)[0]
    result["session_id_offset"] = off + 8

    iv_suffix = payload_bytes[off + 12:off + 20]
    result["init_vector_suffix"] = iv_suffix
    result["init_vector_suffix_offset"] = off + 12

    off += 20   # end of SecureDataHeader

    # crypto_content: 4-byte length prefix + ciphertext
    if len(payload_bytes) - off < 4:
        raise ValueError("truncated at crypto_content length prefix")
    ct_len = struct.unpack_from(E + "I", payload_bytes, off)[0]
    result["crypto_content_length_offset"] = off
    result["crypto_content_length"] = ct_len
    off += 4
    if len(payload_bytes) - off < ct_len:
        raise ValueError(f"ciphertext truncated: need {ct_len}, have {len(payload_bytes) - off}")
    result["ciphertext_offset"] = off
    result["ciphertext"] = payload_bytes[off:off + ct_len]
    off += ct_len

    # SecureDataTag: common_mac (16) + receiver_specific_macs_count (4)
    if len(payload_bytes) - off < 20:
        raise ValueError(f"truncated at SecureDataTag: have {len(payload_bytes) - off} bytes, need 20")
    mac = payload_bytes[off:off + 16]
    result["common_mac"] = mac
    result["common_mac_offset"] = off
    rsm_count = struct.unpack_from(E + "I", payload_bytes, off + 16)[0]
    result["receiver_specific_macs_count"] = rsm_count
    result["receiver_specific_macs_count_offset"] = off + 16

    return result


def decode_data_payload(sub, flags, le):
    """Extract the serialized-payload region from a DATA submessage body."""
    E = "<" if le else ">"
    # DATA body: extraFlags(2) + octetsToInlineQos(2) + readerEntityId(4) +
    #            writerEntityId(4) + writerSeqNum(8) = 20 bytes before inline-QoS
    if len(sub) < 20:
        return None, None, None, None
    q_flag = bool((flags >> 1) & 1)             # Q flag: inline-QoS present
    d_flag = bool((flags >> 2) & 1)             # D flag: serialized payload present
    if not d_flag:
        return None, None, None, None
    otiq = struct.unpack_from(E + "H", sub, 2)[0]
    writer_eid = sub[8:12]
    seq_hi, seq_lo = struct.unpack_from(E + "iI", sub, 16)
    sn = (seq_hi << 32) | seq_lo
    payload_off = 4 + otiq                       # payload starts after inline-QoS
    if q_flag:
        # skip inline-QoS PIDs
        q = payload_off
        while q + 4 <= len(sub):
            pid = struct.unpack_from(E + "H", sub, q)[0]
            plen = struct.unpack_from(E + "H", sub, q + 2)[0]
            if pid == 0x0001:                   # PID_SENTINEL
                q += 4
                break
            q += 4 + plen
        payload_off = q
    payload = sub[payload_off:]
    return writer_eid.hex(), sn, payload, payload_off


def main(path):
    print(f"=== DDS-Security 1.1 §9.5.3.3 SecuredPayload decoder ===")
    print(f"    Capture: {path}\n")
    found = 0
    for pkt in frames(path):
        rtps = rtps_payload(pkt)
        if not rtps:
            continue
        src_prefix = rtps[8:20].hex()
        for flags, le, sub in data_submessages(rtps):
            w_eid, sn, payload, payload_off = decode_data_payload(sub, flags, le)
            if payload is None or len(payload) == 0:
                continue
            try:
                r = parse_secured_payload(payload, le)
            except ValueError as exc:
                continue                         # not a SecuredPayload; skip silently
            # Sanity check: AES128/256 GCM or GMAC kind?
            if r["transformation_kind_bytes"] not in [bytes([0,0,0,2]), bytes([0,0,0,3]),
                                                       bytes([0,0,0,4])]:
                continue
            found += 1
            E = "<" if le else ">"
            print(f"--- Sample #{found} ---")
            print(f"  RTPS src guidPrefix : {src_prefix}")
            print(f"  writerEntityId      : 0x{w_eid}")
            print(f"  writerSeqNumber     : {sn}")
            print(f"  RTPS endianness     : {'LE' if le else 'BE'} (E-flag={'1' if le else '0'})")
            print()
            print(f"  SecureDataHeader (offsets relative to serialized-payload start):")
            off = r["base_off"]
            if r["cdr_header_bytes"] is not None:
                print(f"    CDR header          @ [{r['base_off']-4}:{r['base_off']}] = {r['cdr_header_bytes'].hex()} (skipped)")
            tk = r["transformation_kind_bytes"]
            print(f"    transformation_kind @ [{r['transformation_kind_offset']}:{r['transformation_kind_offset']+4}] = {tk.hex()} => {r['transformation_kind_name']}")
            ki = r["transformation_key_id"]
            print(f"    transformation_key_id @ [{r['transformation_key_id_offset']}:{r['transformation_key_id_offset']+4}] = {ki.hex()}")
            si = r["session_id"]
            print(f"    session_id          @ [{r['session_id_offset']}:{r['session_id_offset']+4}] = {si.hex()} (LE u32 = {r['session_id_u32_le']})")
            iv = r["init_vector_suffix"]
            print(f"    init_vector_suffix  @ [{r['init_vector_suffix_offset']}:{r['init_vector_suffix_offset']+8}] = {iv.hex()}")
            print()
            ct = r["ciphertext"]
            print(f"  crypto_content:")
            print(f"    length              @ [{r['crypto_content_length_offset']}:{r['crypto_content_length_offset']+4}] = {r['crypto_content_length']} bytes ({E}uint32)")
            print(f"    ciphertext          @ [{r['ciphertext_offset']}:{r['ciphertext_offset']+len(ct)}] ({len(ct)} bytes)")
            if len(ct) <= 64:
                print(f"      hex: {ct.hex()}")
            else:
                print(f"      first 32B: {ct[:32].hex()} ...")
                print(f"      last  16B: ...{ct[-16:].hex()}")
            print()
            mac = r["common_mac"]
            print(f"  SecureDataTag:")
            print(f"    common_mac          @ [{r['common_mac_offset']}:{r['common_mac_offset']+16}] = {mac.hex()}")
            print(f"    receiver_specific_macs_count @ [{r['receiver_specific_macs_count_offset']}:{r['receiver_specific_macs_count_offset']+4}] = {r['receiver_specific_macs_count']}")
            print()
            nonce = si + iv
            print(f"  Nonce (session_id ∥ init_vector_suffix, 12 bytes) = {nonce.hex()}")
            aad_start = r["base_off"]
            aad_end = r["base_off"] + 20
            aad = payload[aad_start:aad_end]
            print(f"  AAD = SecureDataHeader [{aad_start}:{aad_end}] = {aad.hex()}")
            print()
            print("  Full serialized-payload hex dump:")
            print(hexdump(payload, indent=4))
            print()
    if found == 0:
        print("No SecuredPayload (AES-GCM/GMAC transformation_kind) found in capture.")
        print("Either the capture has no security-protected DATA, or metadata_protection")
        print("is also ENCRYPT (requiring SEC_PREFIX parsing first).")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "captures/security-payload.pcap"
    main(path)
