"""HTTP payload test over a client's SOCKS5 -> userspace WireGuard path."""

import http.server
import ipaddress
import json
import re
import socket
import struct
import sys

PAYLOAD = b"covee-overlay-proof-v1\n"


def read_exact(connection, length):
    result = b""
    while len(result) < length:
        part = connection.recv(length - len(result))
        if not part:
            raise ConnectionError("unexpected EOF")
        result += part
    return result


def fetch(proxy, destination, port, hostname):
    phase = "proxy-connect"
    try:
        if not re.fullmatch(r"[A-Za-z0-9.-]+", hostname):
            raise ValueError("invalid HTTP hostname")
        with socket.create_connection((proxy, 1055), timeout=6) as connection:
            connection.sendall(b"\x05\x01\x00")
            if read_exact(connection, 2) != b"\x05\x00":
                raise ValueError("SOCKS5 authentication negotiation failed")
            address = ipaddress.ip_address(destination)
            if address.version != 4:
                raise ValueError("probe requires an IPv4 overlay address")
            phase = "overlay-connect"
            connection.sendall(b"\x05\x01\x00\x01" + address.packed + struct.pack("!H", port))
            header = read_exact(connection, 4)
            if header[0] != 5 or header[2] != 0 or header[1] > 8:
                raise ValueError("invalid SOCKS5 response")
            if header[3] == 1:
                read_exact(connection, 6)
            elif header[3] == 4:
                read_exact(connection, 18)
            elif header[3] == 3:
                read_exact(connection, read_exact(connection, 1)[0] + 2)
            else:
                raise ValueError("invalid SOCKS5 address type")
            if header[1]:
                if header[1] in (7, 8):
                    raise ValueError(f"SOCKS5 rejected probe command or address type: {header[1]}")
                # These replies prove only a failed dial. Callers establish the
                # cause with positive controls and independent client/map state.
                print(json.dumps({"status": "blocked", "phase": phase, "failure_kind": "socks-connect-rejected",
                                  "socks_reply": header[1], "proxy": proxy, "destination": destination, "port": port}))
                return 2
            phase = "http-payload"
            connection.sendall((f"GET /proof HTTP/1.0\r\nHost: {hostname}:{port}\r\n"
                                "Connection: close\r\n\r\n").encode("ascii"))
            response = b""
            while True:
                part = connection.recv(4096)
                if not part:
                    break
                response += part
                if len(response) > 65536:
                    raise ValueError("unexpectedly large HTTP response")
            headers, _, body = response.partition(b"\r\n\r\n")
            if not headers.startswith(b"HTTP/1.0 200") and not headers.startswith(b"HTTP/1.1 200"):
                status_line = headers.partition(b"\r\n")[0].decode("ascii", errors="replace")[:120]
                raise ValueError(f"expected HTTP 200; received {status_line!r}")
            if body != PAYLOAD:
                raise ValueError("overlay payload mismatch")
            print(json.dumps({"status": "ok", "proxy": proxy, "destination": destination, "hostname": hostname, "port": port,
                              "payload": PAYLOAD.decode().strip()}))
            return 0
    except TimeoutError:
        print(json.dumps({"status": "error", "phase": phase, "failure_kind": "probe-timeout",
                          "proxy": proxy, "destination": destination, "port": port, "error": "timeout"}))
        return 1
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "error", "phase": phase, "error": str(error)}))
        return 1


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/proof":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "serve":
        http.server.ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
    elif len(sys.argv) == 6 and sys.argv[1] == "fetch":
        sys.exit(fetch(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]))
    else:
        sys.exit("usage: probe.py serve | fetch PROXY OVERLAY_IPV4 PORT HTTP_HOSTNAME")
