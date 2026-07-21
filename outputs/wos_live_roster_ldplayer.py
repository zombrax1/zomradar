import argparse
import socket
import struct
from pathlib import Path

import wos_live_roster as base


def ethernet_tcp_segments(path, port, client=True):
    raw = path.read_bytes()
    if len(raw) < 24 or struct.unpack_from("<I", raw, 20)[0] != 1:
        raise ValueError("LDPlayer capture must be standard Ethernet PCAP")
    offset = 24
    while offset + 16 <= len(raw):
        _, _, captured, _ = struct.unpack_from("<IIII", raw, offset)
        packet = raw[offset + 16 : offset + 16 + captured]
        offset += 16 + captured
        if len(packet) < 54 or packet[12:14] != b"\x08\x00":
            continue
        ip = packet[14:]
        header = (ip[0] & 15) * 4
        if ip[9] != 6:
            continue
        source, destination = struct.unpack_from("!HH", ip, header)
        tcp_header = (ip[header + 12] >> 4) * 4
        payload = ip[header + tcp_header : struct.unpack_from("!H", ip, 2)[0]]
        if payload and ((client and destination == port) or (not client and source == port)):
            remote_ip = socket.inet_ntoa(ip[16:20] if client else ip[12:16])
            yield struct.unpack_from("!I", ip, header + 4)[0], payload, remote_ip, source if client else destination


base.tcp_segments = ethernet_tcp_segments


def chat_token(path):
    frame = base.fpnn_auth_frame(Path(path))
    token = base.msgpack_value(frame[16 + frame[7] :])["token"]
    if not token:
        raise ValueError("empty chat token")
    return token


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract your LDPlayer WOS chat token from an Ethernet PCAP")
    parser.add_argument("capture", nargs="?", default="capture.pcap")
    args = parser.parse_args()
    print(chat_token(args.capture))
