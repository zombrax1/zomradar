import argparse
import re
import struct


def pcap_ip_offset(data):
    if data[:4] != b"\xd4\xc3\xb2\xa1":
        raise ValueError("unsupported packet capture format")
    try:
        return {0: 4, 1: 14, 113: 16}[struct.unpack_from("<I", data, 20)[0]]
    except (KeyError, struct.error) as error:
        raise ValueError("unsupported packet capture link type") from error


def packets(path):
    data = open(path, "rb").read()
    ip_offset = pcap_ip_offset(data)
    ether_type_offset = ip_offset - 2
    offset = 24
    number = 0
    while offset + 16 <= len(data):
        number += 1
        sec, usec, captured, _ = struct.unpack_from("<IIII", data, offset)
        raw = data[offset + 16 : offset + 16 + captured]
        offset += 16 + captured
        ipv4 = raw[:4] in (b"\x02\x00\x00\x00", b"\x00\x00\x00\x02") if ip_offset == 4 else raw[ether_type_offset:ip_offset] == b"\x08\x00"
        if len(raw) < ip_offset + 40 or not ipv4:
            continue
        ip = raw[ip_offset:]
        ip_header = (ip[0] & 15) * 4
        if ip[9] != 6 or len(ip) < ip_header + 20:
            continue
        total = struct.unpack_from("!H", ip, 2)[0]
        source_port, dest_port = struct.unpack_from("!HH", ip, ip_header)
        if 30101 not in (source_port, dest_port):
            continue
        tcp_header = (ip[ip_header + 12] >> 4) * 4
        payload = ip[ip_header + tcp_header : total]
        if payload:
            yield {
                "number": number,
                "time": sec + usec / 1_000_000,
                "direction": "C" if dest_port == 30101 else "S",
                "sequence": struct.unpack_from("!I", ip, ip_header + 4)[0],
                "payload": payload,
            }


def stream(segments, direction):
    selected = sorted((p for p in segments if p["direction"] == direction), key=lambda p: p["sequence"])
    if not selected:
        return b"", [], []
    base = selected[0]["sequence"]
    output = bytearray()
    origins = []
    gaps = []
    for part in selected:
        start = part["sequence"] - base
        if start > len(output):
            gaps.append((len(output), start))
            output.extend(b"\x00" * (start - len(output)))
            origins.extend([None] * (start - len(origins)))
        overlap = max(0, len(output) - start)
        new = part["payload"][overlap:]
        output.extend(new)
        origins.extend([part] * len(new))
    return bytes(output), origins, gaps


def frames(data, origins):
    offset = 0
    while offset + 2 <= len(data):
        size = int.from_bytes(data[offset : offset + 2], "big")
        end = offset + 2 + size
        if size == 0 or end > len(data):
            break
        origin = origins[offset] if offset < len(origins) else None
        yield offset, data[offset + 2 : end], origin
        offset = end


def strings(data):
    return [m.group().decode("ascii") for m in re.finditer(rb"[ -~]{4,}", data)]


def unpack_sproto(data):
    output = bytearray()
    offset = 0
    while offset < len(data):
        header = data[offset]
        offset += 1
        if header == 0xFF:
            if offset >= len(data):
                raise ValueError("missing raw-block count")
            size = (data[offset] + 1) * 8
            offset += 1
            if offset + size > len(data):
                raise ValueError("short raw block")
            output.extend(data[offset : offset + size])
            offset += size
            continue
        for bit in range(8):
            if header & (1 << bit):
                if offset >= len(data):
                    raise ValueError("short packed block")
                output.append(data[offset])
                offset += 1
            else:
                output.append(0)
    return bytes(output)


def main():
    assert pcap_ip_offset(b"\xd4\xc3\xb2\xa1" + bytes(16) + struct.pack("<I", 1)) == 14
    assert pcap_ip_offset(b"\xd4\xc3\xb2\xa1" + bytes(16) + struct.pack("<I", 0)) == 4
    assert pcap_ip_offset(b"\xd4\xc3\xb2\xa1" + bytes(16) + struct.pack("<I", 113)) == 16
    assert unpack_sproto(bytes.fromhex("7d020c08b20f021404051f04a131ad03")) == bytes.fromhex(
        "02000c08b20f0200000004000500000004a131ad03000000"
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    parser.add_argument("--direction", choices=("C", "S"))
    parser.add_argument("--grep")
    parser.add_argument("--hex", action="store_true")
    parser.add_argument("--unpack", action="store_true")
    args = parser.parse_args()

    captured = list(packets(args.pcap))
    for direction in ([args.direction] if args.direction else ["C", "S"]):
        data, origins, gaps = stream(captured, direction)
        parsed = list(frames(data, origins))
        print(f"{direction}: {len(data)} bytes, {len(parsed)} frames, gaps={gaps}")
        for index, (offset, frame, origin) in enumerate(parsed, 1):
            shown = unpack_sproto(frame) if args.unpack else frame
            found = strings(shown)
            if args.grep and args.grep.lower().encode() not in shown.lower():
                continue
            packet = origin["number"] if origin else "?"
            timestamp = origin["time"] if origin else 0
            print(
                f"{direction}{index:03} packet={packet} time={timestamp:.6f} "
                f"offset={offset} len={len(frame)} head={shown[:16].hex()} strings={found}"
            )
            if args.hex:
                print(shown.hex(" "))


if __name__ == "__main__":
    main()
