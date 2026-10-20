#!/usr/bin/env python3
"""Keep a Covee network's public hostname pointing at its current public address.

`covee dns auto` installs this on the network server for networks on a home or
office connection whose public address can change; covee-dns.timer runs it
every five minutes. It asks checkip.amazonaws.com which address the server's
internet traffic comes from and reads the hostname's A record in Route 53. When
they differ it changes the record, after checking that the new address already
answers as this network (when the router lets the server reach itself).

Its AWS key may only read the zone's records and UPSERT this one A record. It
uses only the Python standard library, and prints nothing when nothing changed.

  dns_updater.py --config /srv/covee/dns-updater.json [--check] [--json]

  --check   report the public address, the record and whether the address
            answers as this network; change nothing
  --json    print the result as JSON
"""
import argparse
import datetime
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import sys
import urllib.parse
from xml.sax.saxutils import escape
import xml.etree.ElementTree as ET

ROUTE53_HOST = "route53.amazonaws.com"
ROUTE53_NS = "{https://route53.amazonaws.com/doc/2013-04-01/}"
CHECKIP_HOST = "checkip.amazonaws.com"
HOSTNAME = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
ZONE_ID = re.compile(r"^Z[A-Z0-9]{1,32}$")
ACCESS_KEY_ID = re.compile(r"^AKIA[A-Z0-9]{16}$")


class UpdaterError(RuntimeError):
    pass


def https(host, method, path, headers=None, body=b"", address=None, timeout=15):
    """One HTTPS request to host over IPv4, optionally to a chosen address.

    The certificate is checked against host either way. Returns (status, body).
    """
    if address is None:
        address = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    headers = dict(headers or {})
    if not any(k.lower() == "host" for k in headers):
        headers["Host"] = host
    context = ssl.create_default_context()
    with socket.create_connection((address, 443), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as sock:
            conn = http.client.HTTPConnection(host, 443, timeout=timeout)
            conn.sock = sock
            conn.request(method, path, body=body or None, headers=headers)
            response = conn.getresponse()
            return response.status, response.read(1 << 20)


def _quote(value):
    return urllib.parse.quote(str(value), safe="-_.~")


def sign(method, path, query, headers, body, access_key_id, secret_access_key, now, region="us-east-1", service="route53"):
    """Return headers with an AWS Signature Version 4 Authorization added."""
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    day = amz_date[:8]
    signed_headers = {k.lower(): " ".join(str(v).split()) for k, v in headers.items()}
    signed_headers["x-amz-date"] = amz_date
    names = sorted(signed_headers)
    canonical = "\n".join([
        method,
        path,
        "&".join(f"{_quote(k)}={_quote(v)}" for k, v in sorted((str(k), str(v)) for k, v in query)),
        "".join(f"{name}:{signed_headers[name]}\n" for name in names),
        ";".join(names),
        hashlib.sha256(body).hexdigest(),
    ])
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ("AWS4" + secret_access_key).encode()
    for part in (day, region, service, "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    out = dict(headers)
    out["x-amz-date"] = amz_date
    out["Authorization"] = f"AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, SignedHeaders={';'.join(names)}, Signature={signature}"
    return out


def _error_text(data):
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return data[:200].decode("utf-8", "replace").strip()
    code = root.findtext(f".//{ROUTE53_NS}Code") or root.findtext(".//Code") or ""
    message = root.findtext(f".//{ROUTE53_NS}Message") or root.findtext(".//Message") or ""
    return f"{code}: {message}".strip(": ")


class Route53:
    """The two Route 53 calls the updater needs, signed with its own key."""

    def __init__(self, zone_id, access_key_id, secret_access_key, transport=https, clock=None):
        self.zone_id = zone_id
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.transport = transport
        self.clock = clock or (lambda: datetime.datetime.now(datetime.timezone.utc))

    def _call(self, method, path, query=(), body=b""):
        headers = {"host": ROUTE53_HOST}
        if body:
            headers["content-type"] = "application/xml"
        headers = sign(method, path, query, headers, body, self.access_key_id, self.secret_access_key, self.clock())
        target = path + ("?" + "&".join(f"{_quote(k)}={_quote(v)}" for k, v in query) if query else "")
        status, data = self.transport(ROUTE53_HOST, method, target, headers, body)
        if status >= 300:
            raise UpdaterError(f"Route 53 refused the request ({status} {_error_text(data)})")
        try:
            return ET.fromstring(data)
        except ET.ParseError as exc:
            raise UpdaterError(f"Route 53 sent an unreadable answer: {exc}") from exc

    def current_a(self, name):
        """The A record's addresses, or [] when the name has none."""
        fqdn = name.rstrip(".") + "."
        root = self._call("GET", f"/2013-04-01/hostedzone/{self.zone_id}/rrset", [("name", fqdn), ("type", "A"), ("maxitems", "1")])
        for rrset in root.iter(f"{ROUTE53_NS}ResourceRecordSet"):
            if (rrset.findtext(f"{ROUTE53_NS}Name") or "").lower() != fqdn.lower() or rrset.findtext(f"{ROUTE53_NS}Type") != "A":
                continue
            if rrset.find(f"{ROUTE53_NS}AliasTarget") is not None:
                raise UpdaterError(f"{name} is a Route 53 alias record; the updater only changes plain A records")
            if rrset.find(f"{ROUTE53_NS}SetIdentifier") is not None:
                raise UpdaterError(f"{name} uses a Route 53 routing policy; the updater only changes plain A records")
            return [v.text.strip() for v in rrset.iter(f"{ROUTE53_NS}Value") if v.text]
        return []

    def upsert_a(self, name, address, ttl):
        """Point name at address; returns Route 53's change ID."""
        fqdn = escape(name.rstrip(".") + ".")
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">'
            "<ChangeBatch><Comment>covee address updater</Comment><Changes><Change><Action>UPSERT</Action>"
            f"<ResourceRecordSet><Name>{fqdn}</Name><Type>A</Type><TTL>{int(ttl)}</TTL>"
            f"<ResourceRecords><ResourceRecord><Value>{escape(address)}</Value></ResourceRecord></ResourceRecords>"
            "</ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"
        ).encode()
        root = self._call("POST", f"/2013-04-01/hostedzone/{self.zone_id}/rrset/", body=body)
        return (root.findtext(f".//{ROUTE53_NS}Id") or "").rsplit("/", 1)[-1]


def public_ipv4(transport=https):
    """The public IPv4 address this server's internet traffic comes from."""
    try:
        status, body = transport(CHECKIP_HOST, "GET", "/", {}, b"")
    except (OSError, http.client.HTTPException) as exc:
        raise UpdaterError(f"could not ask {CHECKIP_HOST} for the public address: {exc}") from exc
    text = body.decode("ascii", "replace").strip()
    try:
        address = ipaddress.IPv4Address(text)
    except ValueError:
        raise UpdaterError(f"{CHECKIP_HOST} answered {status} with something that is not an IPv4 address") from None
    if status != 200 or not address.is_global:
        raise UpdaterError(f"{CHECKIP_HOST} reported {address}, which is not a public address")
    return str(address)


def serves(address, hostname, transport=https):
    """Whether address answers HTTPS as hostname with this network's sign-in issuer."""
    try:
        status, body = transport(hostname, "GET", "/identity/.well-known/openid-configuration", {}, b"", address=address, timeout=10)
        return status == 200 and json.loads(body).get("issuer") == f"https://{hostname}/identity"
    except (OSError, ValueError, AttributeError, http.client.HTTPException):
        return False


def load_config(path):
    with open(path, encoding="utf-8") as handle:
        config = json.load(handle)
    hostname = str(config.get("hostname", "")).lower().rstrip(".")
    if not HOSTNAME.match(hostname):
        raise UpdaterError("the configuration's hostname is not a valid DNS name")
    if not ZONE_ID.match(str(config.get("zone_id", ""))):
        raise UpdaterError("the configuration's zone_id is not a Route 53 hosted zone ID")
    ttl = config.get("ttl", 300)
    if not isinstance(ttl, int) or not 60 <= ttl <= 86400:
        raise UpdaterError("the configuration's ttl must be 60-86400 seconds")
    credentials = str(config.get("credentials", ""))
    if not os.path.isabs(credentials):
        raise UpdaterError("the configuration's credentials must be an absolute path")
    return {"hostname": hostname, "zone_id": config["zone_id"], "ttl": ttl, "verify": config.get("verify", True) is not False, "credentials": credentials}


def load_credentials(path):
    info = os.stat(path)
    if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise UpdaterError(f"{path} must be readable only by its owner")
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    key_id, secret = data.get("access_key_id", ""), data.get("secret_access_key", "")
    if not ACCESS_KEY_ID.match(key_id) or len(secret) < 20:
        raise UpdaterError(f"{path} does not hold an AWS access key")
    return key_id, secret


def run(config, transport=None, clock=None, check=False):
    transport = transport or https
    key_id, secret = load_credentials(config["credentials"])
    route53 = Route53(config["zone_id"], key_id, secret, transport, clock)
    hostname = config["hostname"]
    public = public_ipv4(transport)
    current = route53.current_a(hostname)
    result = {"hostname": hostname, "public": public, "record": current}
    if check:
        result["serves"] = serves(public, hostname, transport)
        result["action"] = "checked"
        return result
    if current == [public]:
        result["action"] = "unchanged"
        return result
    if config["verify"] and not serves(public, hostname, transport):
        result["action"] = "refused"
        result["reason"] = f"{public} does not answer as {hostname} yet (check the router's port forwards)"
        return result
    result["change"] = route53.upsert_a(hostname, public, config["ttl"])
    result["action"] = "changed"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Keep a Covee network's hostname pointing at its public address.")
    parser.add_argument("--config", required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = run(load_config(args.config), check=args.check)
    except (UpdaterError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    elif result["action"] == "changed":
        print(f"{result['hostname']}: {', '.join(result['record']) or 'no record'} -> {result['public']} (change {result['change']})")
    elif result["action"] == "refused":
        print(f"{result['hostname']}: not changed from {', '.join(result['record']) or 'no record'}: {result['reason']}", file=sys.stderr)
    elif result["action"] == "checked":
        print(f"{result['hostname']}: public address {result['public']}, record {', '.join(result['record']) or 'none'}, answers: {result['serves']}")
    return 1 if result["action"] == "refused" else 0


if __name__ == "__main__":
    sys.exit(main())
