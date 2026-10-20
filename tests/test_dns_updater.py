import datetime
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import dns_updater

NS = "https://route53.amazonaws.com/doc/2013-04-01/"
AT = datetime.datetime(2026, 10, 12, 23, 59, 0, tzinfo=datetime.timezone.utc)
KEY_ID, SECRET = "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"


def rrset(name="control.covee.io.", kind="A", values=("1.2.3.4",), extra=""):
    records = "".join(f"<ResourceRecord><Value>{v}</Value></ResourceRecord>" for v in values)
    return (f'<ListResourceRecordSetsResponse xmlns="{NS}"><ResourceRecordSets><ResourceRecordSet>'
            f"<Name>{name}</Name><Type>{kind}</Type>{extra}<TTL>300</TTL><ResourceRecords>{records}</ResourceRecords>"
            "</ResourceRecordSet></ResourceRecordSets><IsTruncated>false</IsTruncated></ListResourceRecordSetsResponse>").encode()


class FakeInternet:
    """Answers the updater's requests and remembers them."""

    def __init__(self, public="1.2.3.4", record=None, serves=True, route53_status=200):
        self.public = public
        self.record = rrset() if record is None else record
        self.serves_issuer = serves
        self.route53_status = route53_status
        self.calls = []

    def __call__(self, host, method, path, headers=None, body=b"", address=None, timeout=15):
        self.calls.append({"host": host, "method": method, "path": path, "headers": dict(headers or {}), "body": body, "address": address})
        if host == dns_updater.CHECKIP_HOST:
            return 200, (self.public + "\n").encode()
        if host == dns_updater.ROUTE53_HOST:
            if self.route53_status != 200:
                return self.route53_status, f'<ErrorResponse xmlns="{NS}"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>not allowed</Message></Error></ErrorResponse>'.encode()
            if method == "GET":
                return 200, self.record
            return 200, f'<ChangeResourceRecordSetsResponse xmlns="{NS}"><ChangeInfo><Id>/change/C123</Id><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>'.encode()
        if path == "/identity/.well-known/openid-configuration":
            if self.serves_issuer is None:
                raise ConnectionRefusedError("refused")
            issuer = f"https://{host}/identity" if self.serves_issuer else "https://other.example/identity"
            return 200, json.dumps({"issuer": issuer}).encode()
        raise AssertionError(f"unexpected request {method} {host}{path}")

    def posts(self):
        return [c for c in self.calls if c["method"] == "POST"]


class SigningTests(unittest.TestCase):
    # Expected values come from aws-sdk-go-v2's v4 signer for the same requests.
    def test_get_matches_the_aws_sdk(self):
        headers = dns_updater.sign("GET", "/2013-04-01/hostedzone/Z0EXAMPLE12345678/rrset",
                                   [("name", "control.covee.io."), ("type", "A"), ("maxitems", "1")],
                                   {"host": dns_updater.ROUTE53_HOST}, b"", KEY_ID, SECRET, AT)
        self.assertEqual(headers["Authorization"],
                         "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261012/us-east-1/route53/aws4_request, "
                         "SignedHeaders=host;x-amz-date, Signature=868910c271f22ad7ee853c8e51f6a9c19f02553d01f5b19803aed93be0610e9d")
        self.assertEqual(headers["x-amz-date"], "20261012T235900Z")

    def test_post_with_a_body_matches_the_aws_sdk(self):
        headers = dns_updater.sign("POST", "/2013-04-01/hostedzone/Z0EXAMPLE12345678/rrset/", [],
                                   {"host": dns_updater.ROUTE53_HOST, "content-type": "application/xml"},
                                   b"<x>body</x>", KEY_ID, SECRET, AT)
        self.assertTrue(headers["Authorization"].endswith(
            "SignedHeaders=content-type;host;x-amz-date, Signature=1c81835503eafe5f3ff05ab6a06cbd25af91e61356032692d1f9facc83114150"))


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.credentials = os.path.join(self.dir.name, "key.json")
        with open(self.credentials, "w") as handle:
            json.dump({"access_key_id": KEY_ID, "secret_access_key": SECRET}, handle)
        os.chmod(self.credentials, 0o400)
        self.config_path = os.path.join(self.dir.name, "dns-updater.json")
        self.write_config()

    def write_config(self, **changes):
        config = {"hostname": "control.covee.io", "zone_id": "Z0EXAMPLE12345678", "ttl": 300, "verify": True, "credentials": self.credentials}
        config.update(changes)
        with open(self.config_path, "w") as handle:
            json.dump(config, handle)

    def run_updater(self, internet, check=False):
        return dns_updater.run(dns_updater.load_config(self.config_path), transport=internet, clock=lambda: AT, check=check)

    def test_nothing_changes_when_the_record_is_current(self):
        internet = FakeInternet()
        result = self.run_updater(internet)
        self.assertEqual(result["action"], "unchanged")
        self.assertEqual(internet.posts(), [])
        read = [c for c in internet.calls if c["host"] == dns_updater.ROUTE53_HOST][0]
        self.assertEqual(read["path"], "/2013-04-01/hostedzone/Z0EXAMPLE12345678/rrset?name=control.covee.io.&type=A&maxitems=1")
        self.assertIn("Credential=AKIAIOSFODNN7EXAMPLE/20261012/us-east-1/route53/aws4_request", read["headers"]["Authorization"])
        self.assertNotIn(SECRET, json.dumps(internet.calls, default=str))

    def test_a_new_address_is_checked_then_written(self):
        internet = FakeInternet(public="5.6.7.8")
        result = self.run_updater(internet)
        self.assertEqual((result["action"], result["change"], result["record"]), ("changed", "C123", ["1.2.3.4"]))
        probe = [c for c in internet.calls if c["host"] == "control.covee.io"][0]
        self.assertEqual(probe["address"], "5.6.7.8")
        (post,) = internet.posts()
        self.assertEqual(post["path"], "/2013-04-01/hostedzone/Z0EXAMPLE12345678/rrset/")
        body = post["body"].decode()
        for part in ("<Action>UPSERT</Action>", "<Name>control.covee.io.</Name>", "<Type>A</Type>", "<TTL>300</TTL>", "<Value>5.6.7.8</Value>"):
            self.assertIn(part, body)
        self.assertIn("SignedHeaders=content-type;host;x-amz-date", post["headers"]["Authorization"])

    def test_an_address_that_does_not_answer_as_the_network_is_not_written(self):
        for answer in (False, None):
            internet = FakeInternet(public="5.6.7.8", serves=answer)
            result = self.run_updater(internet)
            self.assertEqual(result["action"], "refused")
            self.assertIn("port forwards", result["reason"])
            self.assertEqual(internet.posts(), [])

    def test_without_verification_a_new_address_is_written_directly(self):
        self.write_config(verify=False)
        internet = FakeInternet(public="5.6.7.8", serves=None)
        self.assertEqual(self.run_updater(internet)["action"], "changed")
        self.assertFalse(any(c["host"] == "control.covee.io" for c in internet.calls))

    def test_a_missing_record_is_created(self):
        internet = FakeInternet(record=rrset(name="www.covee.io."))
        result = self.run_updater(internet)
        self.assertEqual((result["action"], result["record"]), ("changed", []))

    def test_check_reports_without_changing(self):
        internet = FakeInternet(public="5.6.7.8", serves=False)
        result = self.run_updater(internet, check=True)
        self.assertEqual((result["action"], result["serves"], result["public"]), ("checked", False, "5.6.7.8"))
        self.assertEqual(internet.posts(), [])

    def test_alias_and_routing_policy_records_are_left_alone(self):
        for extra in ("<AliasTarget><HostedZoneId>Z1</HostedZoneId><DNSName>x.</DNSName></AliasTarget>", "<SetIdentifier>a</SetIdentifier>"):
            internet = FakeInternet(public="5.6.7.8", record=rrset(extra=extra))
            with self.assertRaises(dns_updater.UpdaterError):
                self.run_updater(internet)
            self.assertEqual(internet.posts(), [])

    def test_private_or_garbled_public_addresses_are_refused(self):
        for answer in ("192.168.1.44", "100.64.0.1", "<html>", "2001:db8::1"):
            with self.assertRaises(dns_updater.UpdaterError):
                self.run_updater(FakeInternet(public=answer))

    def test_route53_errors_are_reported_with_their_code(self):
        with self.assertRaisesRegex(dns_updater.UpdaterError, "403 AccessDenied: not allowed"):
            self.run_updater(FakeInternet(route53_status=403))

    def test_credentials_readable_by_others_are_refused(self):
        os.chmod(self.credentials, 0o440)
        with self.assertRaisesRegex(dns_updater.UpdaterError, "readable only by its owner"):
            self.run_updater(FakeInternet())

    def test_bad_configuration_is_refused(self):
        for change in ({"hostname": "not a name"}, {"zone_id": "../x"}, {"ttl": 5}, {"credentials": "key.json"}):
            self.write_config(**change)
            with self.assertRaises(dns_updater.UpdaterError):
                dns_updater.load_config(self.config_path)

    def test_main_is_quiet_when_unchanged_and_fails_when_refused(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(dns_updater, "https", FakeInternet()), redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(dns_updater.main(["--config", self.config_path]), 0)
        self.assertEqual((out.getvalue(), err.getvalue()), ("", ""))
        with patch.object(dns_updater, "https", FakeInternet(public="5.6.7.8", serves=False)), redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(dns_updater.main(["--config", self.config_path]), 1)
        self.assertIn("not changed from 1.2.3.4", err.getvalue())
        out = io.StringIO()
        with patch.object(dns_updater, "https", FakeInternet(public="5.6.7.8")), redirect_stdout(out):
            self.assertEqual(dns_updater.main(["--config", self.config_path, "--json"]), 0)
        self.assertEqual(json.loads(out.getvalue())["action"], "changed")


if __name__ == "__main__":
    unittest.main()
