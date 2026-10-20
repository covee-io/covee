from pathlib import Path
import socket
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab"))
import dns_stub


def query(name, qtype=1, *, ident=0x1234, flags=0x0100, qclass=1):
    labels = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", ident, flags, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, qclass)


def header(response):
    return struct.unpack("!HHHHHH", response[:12])


class StubResolverTests(unittest.TestCase):
    def respond(self, packet):
        return dns_stub.build_response(packet, "corp.lab.invalid", "192.0.2.53")

    def test_a_query_inside_the_zone_gets_the_fixed_address(self):
        response, record = self.respond(query("Svc.Corp.Lab.Invalid"))
        ident, flags, questions, answers, authority, additional = header(response)
        self.assertEqual((ident, questions, answers, authority, additional), (0x1234, 1, 1, 0, 0))
        self.assertEqual(flags & 0x000F, 0)
        self.assertTrue(flags & 0x8000 and flags & 0x0400 and flags & 0x0100)
        self.assertEqual(response[-4:], socket.inet_aton("192.0.2.53"))
        self.assertEqual(record, {"event": "query", "qname": "svc.corp.lab.invalid", "qtype": 1, "rcode": 0, "answered": True})

    def test_zone_apex_is_inside_the_zone(self):
        self.assertTrue(self.respond(query("corp.lab.invalid"))[1]["answered"])

    def test_other_types_inside_the_zone_have_no_data(self):
        response, record = self.respond(query("svc.corp.lab.invalid", qtype=28))
        self.assertEqual(header(response)[1] & 0x000F, 0)
        self.assertEqual(header(response)[3], 0)
        self.assertFalse(record["answered"])

    def test_names_outside_the_zone_are_nxdomain(self):
        for name in ("other.lab.invalid", "corp.lab.invalid.example", "notcorp.lab.invalid", "lab.invalid"):
            with self.subTest(name=name):
                response, record = self.respond(query(name))
                self.assertEqual(header(response)[1] & 0x000F, dns_stub.NXDOMAIN)
                self.assertEqual(header(response)[3], 0)
                self.assertEqual(record["rcode"], dns_stub.NXDOMAIN)

    def test_recursion_desired_is_echoed_not_invented(self):
        self.assertFalse(header(self.respond(query("svc.corp.lab.invalid", flags=0))[0])[1] & 0x0100)

    def test_non_queries_and_malformed_packets_are_ignored(self):
        good = query("svc.corp.lab.invalid")
        bad = [b"", good[:16], good[:-3], query("svc.corp.lab.invalid", flags=0x8100), query("svc.corp.lab.invalid", flags=0x1100),
               good[:4] + struct.pack("!H", 2) + good[6:],                       # two questions
               good[:12] + b"\xc0\x0c" + good[14:],                              # compression pointer in the question
               good[:12] + b"\x3f" + b"a" * 5,                                   # label runs past the packet
               good[:12] + (b"\x3f" + b"a" * 63) * 5 + b"\x00\x00\x01\x00\x01"]  # name beyond 253 bytes
        for packet in bad:
            with self.subTest(packet=packet[:20]):
                self.assertEqual(self.respond(packet), (None, None))

    def test_question_is_echoed_unchanged(self):
        packet = query("svc.corp.lab.invalid")
        self.assertEqual(self.respond(packet)[0][12:12 + len(packet) - 12], packet[12:])


if __name__ == "__main__":
    unittest.main()
