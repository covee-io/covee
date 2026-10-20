"""Authoritative UDP DNS responder for the isolated DNS acceptance.

It answers A queries at or under one zone with a fixed address, answers other
types under the zone with NOERROR and no data, and answers everything else
NXDOMAIN. Every query it receives is logged as one JSON line, so the
acceptance can prove which names a client did, and did not, send to it.
"""
import json
import socket
import struct
import sys

TYPE_A, CLASS_IN = 1, 1
NXDOMAIN = 3


def parse_question(packet):
    """Return (id, flags, name, type, class, question bytes) for one plain query, otherwise None."""
    if len(packet) < 17:
        return None
    ident, flags, count = struct.unpack("!HHH", packet[:6])
    # Responses and non-QUERY opcodes are not ours to answer.
    if flags & 0x8000 or (flags >> 11) & 0xF or count != 1:
        return None
    labels, offset = [], 12
    while True:
        if offset >= len(packet):
            return None
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        # A compression pointer cannot appear in a question, and labels may not run past the packet.
        if length & 0xC0 or offset + 1 + length > len(packet):
            return None
        labels.append(packet[offset + 1:offset + 1 + length].decode("latin-1").lower())
        offset += 1 + length
    if offset + 4 > len(packet) or len(".".join(labels)) > 253:
        return None
    qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
    return ident, flags, ".".join(labels), qtype, qclass, packet[12:offset + 4]


def build_response(packet, zone, address):
    """Return (response bytes, log record), or (None, None) for anything that is not a plain query."""
    question = parse_question(packet)
    if question is None:
        return None, None
    ident, flags, name, qtype, qclass, raw = question
    inside = name == zone or name.endswith("." + zone)
    rcode = 0 if inside else NXDOMAIN
    answer = b""
    if inside and qtype == TYPE_A and qclass == CLASS_IN:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", TYPE_A, CLASS_IN, 5, 4) + socket.inet_aton(address)
    # QR, AA and RA, with the client's RD copied back.
    header = struct.pack("!HHHHHH", ident, 0x8000 | 0x0400 | 0x0080 | (flags & 0x0100) | rcode, 1, 1 if answer else 0, 0, 0)
    return header + raw + answer, {"event": "query", "qname": name, "qtype": qtype, "rcode": rcode, "answered": bool(answer)}


def serve(zone, address, port=53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(json.dumps({"event": "listening", "zone": zone, "port": port}), flush=True)
    while True:
        packet, peer = sock.recvfrom(4096)
        response, record = build_response(packet, zone, address)
        if response is None:
            continue
        sock.sendto(response, peer)
        print(json.dumps(record), flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] != "serve":
        sys.exit("usage: dns_stub.py serve ZONE IPV4")
    socket.inet_aton(sys.argv[3])
    serve(sys.argv[2].lower(), sys.argv[3])
