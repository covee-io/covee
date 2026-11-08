import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import deploy
import deploy_backup


def result(stdout=b""):
    return type("Result", (), {"stdout": stdout, "returncode": 0})()


def certificate(directory, name, *hosts):
    cert, key = directory / f"{name}.crt", directory / f"{name}.key"
    deploy.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "30",
                "-subj", f"/CN={hosts[0]}", "-addext", "subjectAltName=" + ",".join("DNS:" + h for h in hosts),
                "-keyout", key, "-out", cert])
    key.chmod(0o400)
    cert.chmod(0o400)
    return cert, key


def running(runtime, *args, **kwargs):
    """Runtime.compose on a network whose coordinator is up."""
    return result(b"abc123\n" if args[:2] == ("ps", "--quiet") else b"")


CUSTOM = {"extra_records": [{"name": "nas.mesh.covee.io", "type": "A", "value": "192.168.1.20"}]}
NODES = [{"id": "1", "given_name": "mac-mini", "ip_addresses": ["fd7a:115c:a1e0::7", "100.64.0.7"], "tags": []},
         {"id": "2", "given_name": "pi", "ip_addresses": ["fd7a:115c:a1e0::8"]},
         {"id": "3", "given_name": "hosts", "ip_addresses": ["100.64.0.3", "fd7a:115c:a1e0::3"], "tags": ["tag:covee-hosts"]}]


# Paths the hosts device must accept or refuse, checked against both deploy.py and
# its own checkPath: one it would refuse leaves it serving its previous hosts.
HOST_PATHS = [
    ("", True), ("/", True), ("/a/b", True), ("/some/sub/service", True), ("/a%20b", True), ("/a%2Fb", True), ("/a%3Fb", True), ("/caf\u00e9", True),
    ("/a.b", True), ("/a./b", True), ("/%ff", True), ("/%25", True), ("/%252e%252e", True), ("/a+b", True), ("/a;b=c", True), ("/~user", True),
    ("/" + "a" * 1023, True),
    ("a", False), ("a/b", False), ("/foo%", False), ("/foo%2", False), ("/foo%zz", False), ("/foo%2g", False),
    ("/a%2e%2e/b", False), ("/a%2E%2E/b", False), ("/a%2e./b", False), ("/a.%2e/b", False), ("/../x", False), ("/a..b", False),
    ("/a%5Cb", False), ("/a%5cb", False), ("/a%00", False), ("/a%0a", False), ("/a%1f", False), ("/a%7f", False),
    ("/a b", False), ("/a\tb", False), ("/a\\b", False), ("/a?b", False), ("/a#b", False), ("/a\x7fb", False),
    ("/" + "a" * 1024, False), ("/" + "\u00e9" * 512, False),
]
GO_CHECK = """package main

import (
\t"encoding/json"
\t"os"
)

func main() {
\tvar paths []string
\tif err := json.NewDecoder(os.Stdin).Decode(&paths); err != nil {
\t\tpanic(err)
\t}
\taccepted := make([]bool, len(paths))
\tfor i, path := range paths {
\t\taccepted[i] = checkPath(path) == nil
\t}
\tjson.NewEncoder(os.Stdout).Encode(accepted)
}
"""


class FakeCoordinator:
    """Answers the coordinator commands deploy.py runs, and keeps the policy it is given."""

    def __init__(self, nodes=NODES, policy='{"grants": [], "ssh": []}'):
        self.nodes, self.policy, self.calls = nodes, policy, []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs.get("data")))
        if args[:2] == ("nodes", "list"):
            return result(json.dumps(self.nodes).encode())
        if args[:2] == ("policy", "get"):
            return result(self.policy.encode())
        if args[:2] == ("policy", "set"):
            self.policy = kwargs["data"].decode()
        return result()

    def writes(self):
        return [c for c in self.calls if c[0][:2] == ("policy", "set")]


class HostsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        certs = cls.base / "certs"
        certs.mkdir(mode=0o700)
        cls.wildcard = certificate(certs, "wildcard", "control.covee.io", "*.mesh.covee.io")
        cls.control_only = certificate(certs, "control", "control.covee.io", "console.mesh.covee.io")
        deploy.write_private(cls.base / "google-secret", "private-google-secret")
        cls.raw = {"control_host": "control.covee.io", "admin_host": "localhost", "dns_base_domain": "mesh.covee.io",
                   "tls": {"control_cert_file": str(cls.control_only[0]), "control_key_file": str(cls.control_only[1])},
                   "dns": CUSTOM,
                   "identity": {"providers": [{"id": "google", "kind": "google", "client_id": "google-id.apps.googleusercontent.com",
                                               "client_secret_file": str(cls.base / "google-secret")}],
                                "grants": [{"provider": "google", "subject": "1234567890", "role": "Covee.Admin", "enroll": True}]}}
        cls.template = cls.base / "template"
        deploy.prepare(cls.template, cls.raw)
        cls.hosts_template = cls.base / "hosts-template"
        deploy.prepare(cls.hosts_template, cls.raw_with_hosts())

    @classmethod
    def raw_with_hosts(cls):
        raw = json.loads(json.dumps(cls.raw))
        raw["hosts"] = True
        raw["tls"] = {"control_cert_file": str(cls.wildcard[0]), "control_key_file": str(cls.wildcard[1])}
        return raw

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def copy(self, template=None, suffix=""):
        directory = self.base / (self.id().rsplit(".", 1)[-1] + suffix)
        shutil.copytree(template or self.template, directory)
        metadata = deploy.load_json(directory / "deployment.json")
        deploy.replace_private(directory / "runtime.env", deploy.runtime_env(directory, metadata))
        return directory

    def spec(self, directory):
        return deploy.load_json(directory / "deployment.json")["spec"]

    def files(self, directory):
        return {str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*")
                if p.is_file() and not p.name.startswith(".") and "state/headscale" not in str(p)}

    def records(self, directory):
        return json.loads((directory / deploy.HOSTS_CONFIG / deploy.HOSTS_RECORDS_FILE).read_text())

    def hosts_file(self, directory):
        return json.loads((directory / deploy.HOSTS_CONFIG / deploy.HOSTS_FILE).read_text())

    def assert_hosts(self, directory, on):
        metadata = deploy.validate(directory, production=True)
        self.assertEqual(bool(metadata["spec"].get("hosts")), on)
        self.assertEqual("hosts_node" in deploy.runtime_images(metadata), on)
        self.assertEqual("COVEE_HOSTS_NODE_IMAGE='covee-hosts-node:portable-local'" in (directory / "runtime.env").read_text(), on)
        self.assertEqual(str(deploy.HOSTS_COMPOSE) in [str(p) for p in deploy.Runtime(directory).base], on)
        dns = deploy.load_json(directory / "headscale.yaml")["dns"]
        self.assertEqual("extra_records_path" in dns, on)
        self.assertEqual("extra_records" in dns, not on)
        if on:
            self.assertEqual(dns["extra_records_path"], "/etc/covee-hosts/extra-records.json")
            for name in (deploy.HOSTS_NODE_STATE, deploy.HOSTS_CONFIG, deploy.HOSTS_TLS):
                self.assertEqual((directory / name).stat().st_mode & 0o777, 0o700)
            tls = directory / deploy.HOSTS_TLS
            self.assertEqual((tls / "fullchain.pem").read_bytes(), (directory / "ingress-control.crt").read_bytes())
            self.assertEqual((tls / "privkey.pem").read_bytes(), (directory / "ingress-control.key").read_bytes())
        else:
            self.assertEqual(dns["extra_records"], CUSTOM["extra_records"])

    # The setting

    def test_the_setting_is_a_boolean_for_production_networks_with_the_broker(self):
        self.assertNotIn("hosts", deploy.validate_spec(self.raw))
        for value in ("yes", 1, None):
            with self.subTest(value=value), self.assertRaisesRegex(deploy.DeploymentError, "true or false"):
                deploy.validate_spec({**self.raw, "hosts": value})
        direct = {key: value for key, value in self.raw.items() if key != "identity"}
        with self.assertRaisesRegex(deploy.DeploymentError, "identity broker"):
            deploy.validate_spec({**direct, "hosts": True})
        lab = {"control_host": "ingress", "admin_host": "admin", "dns_base_domain": "mesh.lab.invalid", "public_port": 8443, "hosts": True}
        with self.assertRaisesRegex(deploy.DeploymentError, "production"):
            deploy.validate_spec(lab, lab=True)
        self.assertIs(deploy.validate_spec({**self.raw, "hosts": False})["hosts"], False)

    def test_without_hosts_the_coordinator_settings_are_unchanged(self):
        directory = self.copy()
        self.assert_hosts(directory, False)
        spec = self.spec(directory)
        # Exactly the block (and key order) runtimes had before hosts existed.
        self.assertEqual(json.dumps(deploy.dns_config(spec)), json.dumps(
            {"magic_dns": True, "base_domain": "mesh.covee.io", "override_local_dns": False,
             "nameservers": {"global": [], "split": {}}, "search_domains": [], "extra_records": CUSTOM["extra_records"]}))
        self.assertFalse((directory / deploy.HOSTS_CONFIG).exists())
        self.assertEqual(deploy.dns_config({**spec, "hosts": False}), deploy.dns_config(spec))

    def test_with_hosts_the_records_come_from_the_file(self):
        spec = {**self.spec(self.template), "hosts": True}
        config = deploy.dns_config(spec)
        self.assertNotIn("extra_records", config, "headscale refuses extra_records with extra_records_path")
        self.assertEqual(config["extra_records_path"], "/etc/covee-hosts/extra-records.json")

    def test_prepare_with_hosts(self):
        directory = self.copy(self.hosts_template)
        self.assert_hosts(directory, True)
        self.assertEqual(self.hosts_file(directory), {"hosts": []})
        self.assertEqual(self.records(directory), CUSTOM["extra_records"], "custom records are carried into the file")
        for name in (deploy.HOSTS_FILE, deploy.HOSTS_RECORDS_FILE):
            self.assertFalse((directory / deploy.HOSTS_CONFIG / name).stat().st_mode & 0o077)

    def test_prepare_refuses_a_certificate_without_the_wildcard(self):
        raw = self.raw_with_hosts()
        raw["tls"] = self.raw["tls"]
        with self.assertRaisesRegex(deploy.DeploymentError, r"cover every name under mesh.covee.io \(\*.mesh.covee.io\)"):
            deploy.prepare(self.base / "no-wildcard", raw)

    def test_the_coordinator_dns_settings_cannot_drift(self):
        directory = self.copy(self.hosts_template)
        path = directory / deploy.HOSTS_CONFIG / deploy.HOSTS_RECORDS_FILE
        deploy.replace_private(path, "not json", mode=0o600)
        with self.assertRaises(deploy.DeploymentError):
            deploy.validate(directory, production=True)
        deploy.replace_private(path, json.dumps(CUSTOM["extra_records"]), mode=0o600)
        deploy.validate(directory, production=True)
        config = deploy.load_json(directory / "headscale.yaml")
        config["dns"]["extra_records"] = []
        deploy.replace_private(directory / "headscale.yaml", json.dumps(config))
        with self.assertRaisesRegex(deploy.DeploymentError, "DNS differs"):
            deploy.validate(directory, production=True)

    # The requested hosts

    def test_valid_hosts_get_defaults(self):
        spec = self.spec(self.template)
        hosts = deploy.validate_hosts({"hosts": [{"name": "grafana", "device": "mac-mini", "port": 8080},
                                                 {"name": "a1-b", "device": "pi", "port": 443, "path": "/some/sub/service", "scheme": "https", "verify": False}]}, spec)
        self.assertEqual(hosts, [{"name": "grafana", "device": "mac-mini", "port": 8080, "path": "", "scheme": "http", "verify": True},
                                 {"name": "a1-b", "device": "pi", "port": 443, "path": "/some/sub/service", "scheme": "https", "verify": False}])
        self.assertEqual(deploy.validate_hosts({"hosts": []}, spec), [])

    def test_bad_hosts_are_refused_in_plain_language(self):
        spec = self.spec(self.template)
        good = {"name": "grafana", "device": "mac-mini", "port": 8080}
        cases = [
            ([], "given as"), ({"hosts": {}}, "given as"), ({"hosts": [], "extra": 1}, "given as"),
            ({"hosts": [good] * 257}, "at most 256"),
            ({"hosts": ["grafana"]}, "needs a name"), ({"hosts": [{"name": "grafana", "port": 80}]}, "needs a name"),
            ({"hosts": [{**good, "colour": "red"}]}, "needs a name"),
            ({"hosts": [{**good, "name": "Grafana"}]}, "one word"), ({"hosts": [{**good, "name": "graf.ana"}]}, "one word"),
            ({"hosts": [{**good, "name": "-grafana"}]}, "one word"), ({"hosts": [{**good, "name": "grafana-"}]}, "one word"),
            ({"hosts": [{**good, "name": ""}]}, "one word"), ({"hosts": [{**good, "name": "a" * 64}]}, "one word"),
            ({"hosts": [{**good, "name": 5}]}, "one word"),
            ({"hosts": [{**good, "name": "hosts"}]}, "Covee uses itself"), ({"hosts": [{**good, "name": "console"}]}, "Covee uses itself"),
            ({"hosts": [{**good, "name": "gateway"}]}, "Covee uses itself"), ({"hosts": [{**good, "name": "admin"}]}, "Covee uses itself"),
            ({"hosts": [{**good, "name": "nas"}]}, "already used in this network's DNS settings"),
            ({"hosts": [good, {**good, "port": 9090}]}, "two hosts named grafana"),
            ({"hosts": [{**good, "device": "Mac Mini"}]}, "device name"), ({"hosts": [{**good, "device": ""}]}, "device name"),
            ({"hosts": [{**good, "port": 0}]}, "1 to 65535"), ({"hosts": [{**good, "port": 65536}]}, "1 to 65535"),
            ({"hosts": [{**good, "port": "8080"}]}, "1 to 65535"), ({"hosts": [{**good, "port": True}]}, "1 to 65535"),
            ({"hosts": [{**good, "path": "some"}]}, "must start with one /"), ({"hosts": [{**good, "path": "/a/../b"}]}, "'..'"),
            ({"hosts": [{**good, "path": "/a?b=1"}]}, "'?'"), ({"hosts": [{**good, "path": "/a#b"}]}, "'#'"),
            ({"hosts": [{**good, "path": "/a b"}]}, "spaces"), ({"hosts": [{**good, "path": None}]}, "must start with one /"),
            ({"hosts": [{**good, "scheme": "ftp"}]}, "http or https"), ({"hosts": [{**good, "verify": "no"}]}, "true or false"),
        ]
        for raw, message in cases:
            with self.subTest(raw=str(raw)[:80]), self.assertRaisesRegex(deploy.DeploymentError, message):
                deploy.validate_hosts(raw, spec)

    def test_hosts_resolve_to_devices_in_the_network(self):
        spec = self.spec(self.template)
        hosts = deploy.validate_hosts({"hosts": [{"name": "grafana", "device": "mac-mini", "port": 8080, "path": "/some/sub/service"},
                                                 {"name": "pihole", "device": "pi", "port": 80}]}, spec)
        entries, warnings = deploy.resolve_hosts(hosts, NODES, spec)
        self.assertEqual(warnings, [])
        self.assertEqual(entries, [
            {"name": "grafana.mesh.covee.io", "address": "100.64.0.7", "port": 8080, "path": "/some/sub/service",
             "scheme": "http", "verify": True, "device": "mac-mini", "node_id": "1"},
            {"name": "pihole.mesh.covee.io", "address": "fd7a:115c:a1e0::8", "port": 80, "path": "",
             "scheme": "http", "verify": True, "device": "pi", "node_id": "2"}])
        self.assertEqual(deploy.host_target(entries[0]), "http://mac-mini:8080/some/sub/service")
        refusals = [
            ({"name": "grafana", "device": "mac-studio", "port": 80}, NODES, "^No device named mac-studio in this network$"),
            ({"name": "mac-mini", "device": "pi", "port": 80}, NODES, "already the name of a device"),
            ({"name": "grafana", "device": "hosts", "port": 80}, NODES, "hosts device itself"),
            ({"name": "grafana", "device": "new", "port": 80}, [{"given_name": "new", "ip_addresses": []}], "no address"),
            # The hosts device refuses a target outside the network's ranges.
            ({"name": "grafana", "device": "new", "port": 80}, [{"given_name": "new", "ip_addresses": ["203.0.113.7"]}], "no address"),
        ]
        for host, nodes, message in refusals:
            with self.subTest(host=host), self.assertRaisesRegex(deploy.DeploymentError, message):
                deploy.resolve_hosts(deploy.validate_hosts({"hosts": [host]}, spec), nodes, spec)
        # Camel-case output of other coordinator versions works too.
        camel = [{"givenName": "mac-mini", "ipAddresses": ["100.64.0.7"]}]
        self.assertEqual(deploy.resolve_hosts(hosts[:1], camel, spec)[0][0]["address"], "100.64.0.7")

    # The access policy

    def test_policy_gets_the_hosts_grants_once_and_replaces_stale_ones(self):
        entries = [{"address": "100.64.0.7", "port": 8080}, {"address": "100.64.0.7", "port": 8080}, {"address": "fd7a:115c:a1e0::8", "port": 80}]
        text = '''{
  // The printer.
  "tagOwners": {"tag:printer": []},
  "grants": [
    {"src": ["autogroup:member"], "dst": ["tag:printer"], "ip": ["tcp:631"]},
    {"src": ["tag:covee-hosts"], "dst": ["100.64.0.99/32"], "ip": ["tcp:3000"]},
    {"src": ["tag:covee-hosts", "tag:printer"], "dst": ["100.64.0.1/32"], "ip": ["tcp:22"]},
  ],
}'''
        merged = deploy.with_hosts_access(text, entries)
        policy = json.loads(merged)
        self.assertEqual(policy["tagOwners"], {"tag:printer": [], "tag:covee-hosts": []})
        self.assertEqual(policy["grants"], [
            {"src": ["autogroup:member"], "dst": ["tag:printer"], "ip": ["tcp:631"]},
            {"src": ["tag:covee-hosts", "tag:printer"], "dst": ["100.64.0.1/32"], "ip": ["tcp:22"]},
            {"src": ["autogroup:member"], "dst": ["tag:covee-hosts"], "ip": ["tcp:443", "tcp:80"]},
            {"src": ["tag:covee-hosts"], "dst": ["100.64.0.7/32"], "ip": ["tcp:8080"]},
            {"src": ["tag:covee-hosts"], "dst": ["fd7a:115c:a1e0::8/128"], "ip": ["tcp:80"]}])
        self.assertIsNone(deploy.with_hosts_access(merged, entries), "already there: no write")
        fewer = json.loads(deploy.with_hosts_access(merged, entries[:1]))
        self.assertNotIn({"src": ["tag:covee-hosts"], "dst": ["fd7a:115c:a1e0::8/128"], "ip": ["tcp:80"]}, fewer["grants"])
        none = json.loads(deploy.with_hosts_access(merged, []))
        self.assertEqual([g for g in none["grants"] if g["src"] == ["tag:covee-hosts"]], [])
        self.assertIn(deploy.hosts_member_grant(), none["grants"])

        removed = json.loads(deploy.without_hosts_access(merged))
        self.assertEqual(removed["grants"], policy["grants"][:2])
        self.assertIsNone(deploy.without_hosts_access(json.dumps(removed)))
        for bad in ("not json", "[]", '{"grants": {}}', '{"tagOwners": []}'):
            with self.subTest(bad=bad), self.assertRaises(deploy.DeploymentError):
                deploy.with_hosts_access(bad, [])

    # set-hosts

    def test_set_hosts_writes_the_hosts_records_and_grants(self):
        directory = self.copy(self.hosts_template)
        runtime = deploy.Runtime(directory)
        coordinator = FakeCoordinator()
        wanted = {"hosts": [{"name": "grafana", "device": "mac-mini", "port": 8080, "path": "/some/sub/service", "scheme": "http", "verify": True}]}
        with patch.object(deploy.Runtime, "compose", running), patch.object(runtime, "control", coordinator):
            reply = runtime.set_hosts(wanted)
        self.assertEqual(reply, {"hosts": [{"name": "grafana.mesh.covee.io", "target": "http://mac-mini:8080/some/sub/service"}], "changed": True})
        self.assertEqual(self.hosts_file(directory), {"hosts": [
            {"name": "grafana.mesh.covee.io", "address": "100.64.0.7", "port": 8080, "path": "/some/sub/service",
             "scheme": "http", "verify": True, "device": "mac-mini", "node_id": "1"}]})
        self.assertEqual(self.records(directory), [
            {"name": "nas.mesh.covee.io", "type": "A", "value": "192.168.1.20"},
            {"name": "grafana.mesh.covee.io", "type": "A", "value": "100.64.0.3"},
            {"name": "grafana.mesh.covee.io", "type": "AAAA", "value": "fd7a:115c:a1e0::3"}])
        checked = [c[0][:2] for c in coordinator.calls if c[0][0] == "policy"]
        self.assertEqual(checked, [("policy", "get"), ("policy", "check"), ("policy", "set")], "checked before it is set")
        self.assertIn({"src": ["tag:covee-hosts"], "dst": ["100.64.0.7/32"], "ip": ["tcp:8080"]}, json.loads(coordinator.policy)["grants"])
        deploy.validate(directory, production=True)

        # The same list again changes nothing; restarts never happen.
        calls = []
        with patch.object(deploy.Runtime, "compose", lambda r, *a, **k: calls.append(a) or running(r, *a)), patch.object(runtime, "control", coordinator):
            self.assertEqual(runtime.set_hosts(wanted)["changed"], False)
        self.assertEqual(calls, [("ps", "--quiet", "headscale")])
        self.assertEqual(len(coordinator.writes()), 1)

        # Another list replaces it completely.
        with patch.object(deploy.Runtime, "compose", running), patch.object(runtime, "control", coordinator):
            reply = runtime.set_hosts({"hosts": [{"name": "pihole", "device": "pi", "port": 80, "scheme": "https", "verify": False}]})
        self.assertEqual(reply["hosts"], [{"name": "pihole.mesh.covee.io", "target": "https://pi:80"}])
        self.assertEqual([r["name"] for r in self.records(directory)], ["nas.mesh.covee.io", "pihole.mesh.covee.io", "pihole.mesh.covee.io"])
        grants = json.loads(coordinator.policy)["grants"]
        self.assertEqual([g for g in grants if g["src"] == ["tag:covee-hosts"]], [{"src": ["tag:covee-hosts"], "dst": ["fd7a:115c:a1e0::8/128"], "ip": ["tcp:80"]}])

        with patch.object(deploy.Runtime, "compose", running), patch.object(runtime, "control", coordinator):
            self.assertEqual(runtime.set_hosts({"hosts": []}), {"hosts": [], "changed": True})
        self.assertEqual(self.records(directory), CUSTOM["extra_records"])
        self.assertEqual(self.hosts_file(directory), {"hosts": []})

    def test_set_hosts_refusals_change_nothing(self):
        directory = self.copy(self.hosts_template)
        runtime = deploy.Runtime(directory)
        before = self.files(directory)
        coordinator = FakeCoordinator()
        with patch.object(deploy.Runtime, "compose", running), patch.object(runtime, "control", coordinator):
            with self.assertRaisesRegex(deploy.DeploymentError, "^No device named mac-studio in this network$"):
                runtime.set_hosts({"hosts": [{"name": "grafana", "device": "mac-studio", "port": 80}]})
            with self.assertRaisesRegex(deploy.DeploymentError, "not joined"):
                with patch.object(coordinator, "nodes", NODES[:2]):
                    runtime.set_hosts({"hosts": []})
            coordinator_refusal = FakeCoordinator()
            with patch.object(runtime, "control", coordinator_refusal), \
                    patch.object(deploy.Runtime, "set_policy", side_effect=deploy.DeploymentError("headscale failed (exit 1)")):
                with self.assertRaisesRegex(deploy.DeploymentError, "access policy would not take these hosts; nothing was changed"):
                    runtime.set_hosts({"hosts": [{"name": "grafana", "device": "mac-mini", "port": 8080}]})
        with patch.object(deploy.Runtime, "compose", return_value=result()):
            with self.assertRaisesRegex(deploy.DeploymentError, "not running"):
                runtime.set_hosts({"hosts": []})
        self.assertEqual(coordinator.writes(), [])
        self.assertEqual(self.files(directory), before)
        with self.assertRaisesRegex(deploy.DeploymentError, "not turned on"):
            deploy.Runtime(self.copy(suffix="-off")).set_hosts({"hosts": []})

    def test_a_failed_set_hosts_restores_the_files_and_the_policy(self):
        directory = self.copy(self.hosts_template)
        runtime = deploy.Runtime(directory)
        before = self.files(directory)
        coordinator = FakeCoordinator()
        original = coordinator.policy
        with patch.object(deploy.Runtime, "compose", running), patch.object(runtime, "control", coordinator), \
                patch.object(deploy, "write_hosts_records", side_effect=deploy.DeploymentError("disk full")):
            with self.assertRaisesRegex(deploy.DeploymentError, "previous hosts were restored"):
                runtime.set_hosts({"hosts": [{"name": "grafana", "device": "mac-mini", "port": 8080}]})
        self.assertEqual(self.files(directory), before)
        self.assertEqual(coordinator.policy, original)

    # Custom DNS settings

    def test_update_dns_keeps_the_records_file_in_sync(self):
        directory = self.copy(self.hosts_template)
        runtime = deploy.Runtime(directory)
        with patch.object(deploy.Runtime, "compose", running), patch.object(runtime, "control", FakeCoordinator()):
            runtime.set_hosts({"hosts": [{"name": "grafana", "device": "mac-mini", "port": 8080}]})
        added = {"extra_records": [{"name": "printer.mesh.covee.io", "type": "A", "value": "192.168.1.30"}]}
        with patch.object(deploy.Runtime, "compose", return_value=result()):
            self.assertFalse(runtime.update_dns(added))
        self.assertEqual(self.records(directory), [
            {"name": "printer.mesh.covee.io", "type": "A", "value": "192.168.1.30"},
            {"name": "grafana.mesh.covee.io", "type": "A", "value": "100.64.0.3"},
            {"name": "grafana.mesh.covee.io", "type": "AAAA", "value": "fd7a:115c:a1e0::3"}])
        self.assertNotIn("extra_records", deploy.load_json(directory / "headscale.yaml")["dns"])
        deploy.validate(directory, production=True)

        before = self.files(directory)
        clash = {"extra_records": [{"name": "grafana.mesh.covee.io", "type": "A", "value": "192.168.1.31"}]}
        with patch.object(deploy.Runtime, "compose", return_value=result()):
            with self.assertRaisesRegex(deploy.DeploymentError, "name of a host"):
                runtime.update_dns(clash)
            # A failed restart puts the records file back as well.
            with patch.object(deploy, "validate", side_effect=[deploy.validate(directory, production=True), deploy.DeploymentError("bad")]):
                with self.assertRaisesRegex(deploy.DeploymentError, "previous DNS settings were restored"):
                    runtime.update_dns({})
        self.assertEqual(self.files(directory), before)

    # enable-hosts and disable-hosts

    def test_enable_on_a_running_network(self):
        directory = self.copy()
        with patch.object(deploy.Runtime, "compose", return_value=result()), patch.object(deploy.Runtime, "start") as start:
            reply = deploy.Runtime(directory).enable_hosts(str(self.wildcard[0]), str(self.wildcard[1]))
            start.assert_called_once_with()
        self.assertEqual(reply, {"hosts": True, "changed": True})
        self.assertEqual((directory / "ingress-control.crt").read_bytes(), self.wildcard[0].read_bytes())
        self.assertEqual((directory / "identity-trust.pem").read_bytes(), (directory / "internal-ca.crt").read_bytes() + self.wildcard[0].read_bytes())
        self.assert_hosts(directory, True)
        self.assertEqual(self.hosts_file(directory), {"hosts": []})
        self.assertEqual(self.records(directory), CUSTOM["extra_records"])
        with patch.object(deploy.Runtime, "compose", return_value=result()) as compose:
            self.assertEqual(deploy.Runtime(directory).enable_hosts(str(self.wildcard[0]), str(self.wildcard[1])), {"hosts": True, "changed": False})
            compose.assert_not_called()

    def test_enable_refuses_a_certificate_without_the_wildcard_and_changes_nothing(self):
        directory = self.copy()
        before = self.files(directory)
        with patch.object(deploy.Runtime, "compose", return_value=result()) as compose:
            with self.assertRaisesRegex(deploy.DeploymentError, r"cover every name under mesh.covee.io"):
                deploy.Runtime(directory).enable_hosts(str(self.control_only[0]), str(self.control_only[1]))
            compose.assert_not_called()
        self.assertEqual(self.files(directory), before)
        self.assertFalse((directory / deploy.HOSTS_CONFIG).exists())

    def test_a_failed_enable_restores_every_file(self):
        directory = self.copy()
        before = self.files(directory)
        starts = []

        def start(runtime):
            starts.append(runtime.hosts)
            if runtime.hosts:
                raise deploy.DeploymentError("the hosts device failed")

        with patch.object(deploy.Runtime, "compose", return_value=result()), patch.object(deploy.Runtime, "start", start):
            with self.assertRaisesRegex(deploy.DeploymentError, "previous settings were restored"):
                deploy.Runtime(directory).enable_hosts(str(self.wildcard[0]), str(self.wildcard[1]))
        self.assertEqual(starts, [True, False])
        self.assertEqual(self.files(directory), before)
        for name in (deploy.HOSTS_NODE_STATE, deploy.HOSTS_CONFIG, deploy.HOSTS_TLS):
            self.assertFalse((directory / name).exists())
        self.assert_hosts(directory, False)

    def test_a_failed_enable_after_an_earlier_time_with_hosts_leaves_no_private_key(self):
        directory = self.copy()
        deploy.create_hosts_dirs(directory)
        (directory / deploy.HOSTS_NODE_STATE / "kept").write_text("the device's old identity")

        def start(runtime):
            if runtime.hosts:
                raise deploy.DeploymentError("the hosts device failed")

        with patch.object(deploy.Runtime, "compose", return_value=result()), patch.object(deploy.Runtime, "start", start):
            with self.assertRaisesRegex(deploy.DeploymentError, "previous settings were restored"):
                deploy.Runtime(directory).enable_hosts(str(self.wildcard[0]), str(self.wildcard[1]))
        self.assertEqual(list((directory / deploy.HOSTS_TLS).iterdir()), [])
        self.assertTrue((directory / deploy.HOSTS_NODE_STATE / "kept").exists())
        self.assert_hosts(directory, False)

    def test_disable_on_a_running_network(self):
        directory = self.copy(self.hosts_template)
        runtime = deploy.Runtime(directory)
        coordinator = FakeCoordinator()
        with patch.object(deploy.Runtime, "compose", running), patch.object(runtime, "control", coordinator):
            runtime.set_hosts({"hosts": [{"name": "grafana", "device": "mac-mini", "port": 8080}]})
        deploy.write_private(directory / deploy.HOSTS_NODE_STATE / deploy.CONSOLE_NODE_IDENTITY, "{}")
        calls = []

        def compose(runtime_, *args, **kwargs):
            calls.append((runtime_.hosts, args))
            return running(runtime_, *args)

        with patch.object(deploy.Runtime, "compose", compose), patch.object(deploy.Runtime, "control", coordinator), \
                patch.object(deploy.Runtime, "pin_images"), patch.object(deploy.Runtime, "wait"), \
                patch.object(deploy.Runtime, "delete_tagged_nodes") as delete, patch.object(deploy.Runtime, "start") as start:
            self.assertEqual(runtime.disable_hosts(), {"hosts": False, "changed": True})
            delete.assert_called_once_with("tag:covee-hosts", "hosts")
            start.assert_not_called()
        self.assertIn((True, ("rm", "--stop", "--force", "hosts-node")), calls)
        # The coordinator restarts once, without the hosts overlay; nothing else restarts.
        self.assertIn((False, ("up", "--detach", "--no-deps", "--force-recreate", "--remove-orphans", "headscale")), calls)
        self.assertFalse(any(args[:1] == ("stop",) for _, args in calls))
        grants = json.loads(coordinator.policy)["grants"]
        self.assertEqual([g for g in grants if "tag:covee-hosts" in g["src"] + g["dst"]], [])
        self.assert_hosts(directory, False)
        self.assertEqual(self.hosts_file(directory), {"hosts": []})
        self.assertFalse((directory / deploy.HOSTS_NODE_STATE / deploy.CONSOLE_NODE_IDENTITY).exists())
        self.assertEqual(list((directory / deploy.HOSTS_TLS).iterdir()), [], "no copy of the private key stays behind")
        self.assertEqual(deploy.Runtime(directory).disable_hosts(), {"hosts": False, "changed": False})

    def test_a_failed_disable_restores_every_file_and_the_policy(self):
        directory = self.copy(self.hosts_template)
        runtime = deploy.Runtime(directory)
        coordinator = FakeCoordinator()
        with patch.object(deploy.Runtime, "compose", running), patch.object(runtime, "control", coordinator):
            runtime.set_hosts({"hosts": [{"name": "grafana", "device": "mac-mini", "port": 8080}]})
        before, policy = self.files(directory), coordinator.policy
        with patch.object(deploy.Runtime, "compose", running), patch.object(deploy.Runtime, "control", coordinator), \
                patch.object(deploy.Runtime, "pin_images"), patch.object(deploy.Runtime, "delete_tagged_nodes"), \
                patch.object(deploy.Runtime, "wait", side_effect=deploy.DeploymentError("unhealthy")), \
                patch.object(deploy.Runtime, "start") as start:
            with self.assertRaisesRegex(deploy.DeploymentError, "previous settings were restored"):
                runtime.disable_hosts()
            start.assert_called_once_with()
        self.assertEqual(self.files(directory), before)
        self.assertEqual(coordinator.policy, policy)
        self.assert_hosts(directory, True)

    # The hosts device

    def test_a_new_hosts_device_gets_a_one_time_key_and_its_address_once_joined(self):
        directory = self.copy(self.hosts_template)
        runtime = deploy.Runtime(directory)
        nodes = [*NODES, {"id": "9", "given_name": "hosts-1", "tags": ["tag:covee-hosts"]}, {"id": "10", "given_name": "hosts-laptop", "tags": []}]
        coordinator = FakeCoordinator(nodes=nodes)
        with patch.object(runtime, "control", coordinator), patch.object(runtime, "create_device_key", return_value={"key": "hskey-auth-" + "c" * 40}) as key:
            runtime.prepare_hosts_node()
            key.assert_called_once_with(["tag:covee-hosts"], expiration="1h")
        policy = json.loads(coordinator.policy)
        self.assertEqual(policy["tagOwners"], {"tag:covee-hosts": []})
        self.assertEqual(policy["grants"], [deploy.hosts_member_grant()])
        deleted = [c[0] for c in coordinator.calls if c[0][:2] == ("nodes", "delete")]
        self.assertEqual(deleted, [("nodes", "delete", "--identifier", "3", "--force"), ("nodes", "delete", "--identifier", "9", "--force")])
        join = directory / deploy.HOSTS_NODE_STATE / deploy.CONSOLE_JOIN_KEY
        self.assertEqual(join.stat().st_mode & 0o777, 0o600)

        # Joined: no new key, and its address goes into the records of the hosts already set.
        deploy.write_hosts(directory, [{"name": "grafana.mesh.covee.io", "address": "100.64.0.70", "port": 8080, "path": "",
                                        "scheme": "http", "verify": True, "device": "mac-mini"}])
        deploy.write_private(directory / deploy.HOSTS_NODE_STATE / deploy.CONSOLE_NODE_IDENTITY, "{}")
        coordinator.nodes = NODES
        with patch.object(runtime, "control", coordinator), patch.object(runtime, "create_device_key") as key:
            runtime.prepare_hosts_node()
            key.assert_not_called()
            with patch.object(runtime, "wait"):
                runtime.finish_hosts_node()
        self.assertFalse(join.exists())
        self.assertEqual(self.hosts_file(directory)["hosts"][0]["address"], "100.64.0.7", "the device's current address")
        self.assertEqual(self.records(directory)[1:], [{"name": "grafana.mesh.covee.io", "type": "A", "value": "100.64.0.3"},
                                                       {"name": "grafana.mesh.covee.io", "type": "AAAA", "value": "fd7a:115c:a1e0::3"}])
        self.assertIn({"src": ["tag:covee-hosts"], "dst": ["100.64.0.7/32"], "ip": ["tcp:8080"]}, json.loads(coordinator.policy)["grants"])
        self.assertNotIn({"src": ["tag:covee-hosts"], "dst": ["100.64.0.70/32"], "ip": ["tcp:8080"]}, json.loads(coordinator.policy)["grants"])
        deploy.validate(directory, production=True)

    def test_start_writes_the_files_the_coordinator_and_hosts_device_need(self):
        directory = self.copy(self.hosts_template)
        for name in (deploy.HOSTS_FILE, deploy.HOSTS_RECORDS_FILE):
            (directory / deploy.HOSTS_CONFIG / name).unlink()
        shutil.rmtree(directory / deploy.HOSTS_TLS)
        (directory / deploy.HOSTS_TLS).mkdir(mode=0o700)
        order = []
        runtime = deploy.Runtime(directory)
        with patch.object(runtime, "pin_images"), patch.object(runtime, "bootstrap", lambda: order.append(self.records(directory))), \
                patch.object(runtime, "compose", return_value=result()), \
                patch.object(runtime, "prepare_hosts_node", lambda: order.append("prepare")), \
                patch.object(runtime, "finish_hosts_node", lambda: order.append("finish")):
            runtime.start()
        self.assertEqual(order, [CUSTOM["extra_records"], "prepare", "finish"])
        self.assert_hosts(directory, True)

    # Paths

    def test_paths_follow_the_hosts_devices_rules(self):
        for path, accepted in HOST_PATHS:
            with self.subTest(path=path[:40]):
                self.assertEqual(deploy.valid_host_path(path), accepted)
        # Beyond the device's rules: a leading // would read as a host, and broken text cannot be sent.
        for path in ("//", "//a/b", "/\ud800"):
            with self.subTest(path=path):
                self.assertFalse(deploy.valid_host_path(path))

    @unittest.skipUnless(shutil.which("go") and (deploy.ROOT / "deploy/hosts-node/hosts.go").is_file(), "requires Go and the hosts device's source")
    def test_the_hosts_device_agrees_about_paths(self):
        build = self.base / "go-check"
        build.mkdir()
        shutil.copy(deploy.ROOT / "deploy/hosts-node/hosts.go", build / "hosts.go")
        (build / "go.mod").write_text("module covee.io/hosts-path-check\n\ngo 1.22\n")
        (build / "check.go").write_text(GO_CHECK)
        paths = [path for path, _ in HOST_PATHS]
        answer = subprocess.run(["go", "run", "."], cwd=build, input=json.dumps(paths).encode(), capture_output=True, timeout=300,
                                env={**os.environ, "GOFLAGS": "", "GOWORK": "off", "GOTOOLCHAIN": "local"})
        self.assertEqual(answer.returncode, 0, answer.stderr.decode())
        for (path, accepted), device in zip(HOST_PATHS, json.loads(answer.stdout)):
            with self.subTest(path=path[:40]):
                self.assertEqual(device, accepted, "the hosts device's answer")

    # Hosts stay with their device

    def set_hosts(self, runtime, coordinator, *hosts):
        with patch.object(deploy.Runtime, "compose", running), patch.object(runtime, "control", coordinator):
            return runtime.set_hosts({"hosts": list(hosts)})

    def test_a_new_device_with_the_same_name_does_not_inherit_a_host(self):
        directory = self.copy(self.hosts_template)
        runtime = deploy.Runtime(directory)
        grafana = {"name": "grafana", "device": "mac-mini", "port": 8080}
        coordinator = FakeCoordinator()
        self.set_hosts(runtime, coordinator, grafana)
        before = self.files(directory)
        coordinator.nodes = [{**NODES[0], "id": "44", "ip_addresses": ["100.64.0.44"]}, *NODES[1:]]
        message = "^The device mac-mini is not the same device as when host grafana was added. Remove the host and add it again if this is the right device.$"
        with self.assertRaisesRegex(deploy.DeploymentError, message):
            self.set_hosts(runtime, coordinator, grafana)
        with self.assertRaisesRegex(deploy.DeploymentError, message):
            self.set_hosts(runtime, coordinator, {**grafana, "port": 9090})
        self.assertEqual(self.files(directory), before)

        # Removing it works, and then the new device can have it.
        self.assertEqual(self.set_hosts(runtime, coordinator), {"hosts": [], "changed": True})
        self.set_hosts(runtime, coordinator, grafana)
        self.assertEqual(self.hosts_file(directory)["hosts"][0]["node_id"], "44")
        self.assertEqual(self.hosts_file(directory)["hosts"][0]["address"], "100.64.0.44")
        # Pointing a host at another device on purpose is a plain change.
        self.set_hosts(runtime, coordinator, {**grafana, "device": "pi"})
        self.assertEqual(self.hosts_file(directory)["hosts"][0]["node_id"], "2")

    def test_the_same_device_keeps_its_hosts_when_its_address_changes(self):
        directory = self.copy(self.hosts_template)
        runtime = deploy.Runtime(directory)
        grafana = {"name": "grafana", "device": "mac-mini", "port": 8080}
        coordinator = FakeCoordinator()
        self.set_hosts(runtime, coordinator, grafana)
        coordinator.nodes = [{**NODES[0], "ip_addresses": ["100.64.0.77"]}, *NODES[1:]]
        self.set_hosts(runtime, coordinator, grafana)
        self.assertEqual(self.hosts_file(directory)["hosts"][0]["address"], "100.64.0.77")

    def test_hosts_whose_devices_were_replaced_can_all_be_removed(self):
        directory = self.copy(self.hosts_template)
        runtime = deploy.Runtime(directory)
        first, second = {"name": "grafana", "device": "mac-mini", "port": 8080}, {"name": "pihole", "device": "pi", "port": 80}
        third = {"name": "wiki", "device": "mac-mini", "port": 3000}
        coordinator = FakeCoordinator()
        self.set_hosts(runtime, coordinator, first, second, third)
        kept = self.hosts_file(directory)["hosts"]
        coordinator.nodes = [{**NODES[0], "id": "44", "ip_addresses": ["100.64.0.44"]}, NODES[2]]
        # Each list still names a host with a replaced or missing device, and neither blocks the other's removal.
        reply = self.set_hosts(runtime, coordinator, second, third)
        self.assertEqual(reply["warnings"], ["No device named pi in this network", deploy.replaced_device_message("mac-mini", "wiki")])
        self.assertEqual(self.hosts_file(directory)["hosts"], kept[1:], "kept as they were, not moved")
        self.assertEqual(self.set_hosts(runtime, coordinator, third)["warnings"], [deploy.replaced_device_message("mac-mini", "wiki")])
        self.assertEqual(self.set_hosts(runtime, coordinator), {"hosts": [], "changed": True})
        # Anything but a removal is still refused.
        self.set_hosts(runtime, coordinator, {**first, "device": "mac-mini"})
        coordinator.nodes = [NODES[2]]
        with self.assertRaisesRegex(deploy.DeploymentError, "^No device named mac-mini in this network$"):
            self.set_hosts(runtime, coordinator, first)

    def test_a_start_never_moves_a_host_to_another_device(self):
        directory = self.copy(self.hosts_template)
        runtime = deploy.Runtime(directory)
        coordinator = FakeCoordinator()
        self.set_hosts(runtime, coordinator, {"name": "grafana", "device": "mac-mini", "port": 8080}, {"name": "pihole", "device": "pi", "port": 80})
        coordinator.nodes = [{**NODES[0], "id": "44", "ip_addresses": ["100.64.0.44"]}, {**NODES[1], "ip_addresses": ["100.64.0.88"]}, NODES[2]]
        problems = io.StringIO()
        with patch.object(runtime, "control", coordinator), contextlib.redirect_stderr(problems):
            runtime.refresh_hosts()
        grafana, pihole = self.hosts_file(directory)["hosts"]
        self.assertEqual((grafana["address"], grafana["node_id"]), ("100.64.0.7", "1"), "the old address stays")
        self.assertIn(deploy.replaced_device_message("mac-mini", "grafana"), problems.getvalue())
        self.assertEqual((pihole["address"], pihole["node_id"]), ("100.64.0.88", "2"), "the same device's new address is followed")
        destinations = [g["dst"] for g in json.loads(coordinator.policy)["grants"] if g["src"] == ["tag:covee-hosts"]]
        self.assertEqual(destinations, [["100.64.0.7/32"], ["100.64.0.88/32"]], "no grant reaches the new mac-mini")

        coordinator.nodes = [NODES[2]]
        problems = io.StringIO()
        with patch.object(runtime, "control", coordinator), contextlib.redirect_stderr(problems):
            runtime.refresh_hosts()
        self.assertEqual(self.hosts_file(directory)["hosts"][0]["address"], "100.64.0.7")
        self.assertIn("No device named pi", problems.getvalue())

    def test_a_device_that_takes_a_hosts_name_gets_a_warning_not_a_refusal(self):
        directory = self.copy(self.hosts_template)
        runtime = deploy.Runtime(directory)
        grafana = {"name": "grafana", "device": "mac-mini", "port": 8080}
        coordinator = FakeCoordinator()
        self.assertNotIn("warnings", self.set_hosts(runtime, coordinator, grafana), "omitted when there are none")
        coordinator.nodes = [*NODES, {"id": "5", "given_name": "grafana", "ip_addresses": ["100.64.0.5"]}]
        reply = self.set_hosts(runtime, coordinator, grafana, {"name": "pihole", "device": "pi", "port": 80})
        self.assertEqual(len(reply["warnings"]), 1)
        self.assertIn("The device grafana and the host grafana.mesh.covee.io have the same name", reply["warnings"][0])
        self.assertIn("Rename the host", reply["warnings"][0])
        self.assertEqual([h["name"] for h in reply["hosts"]], ["grafana.mesh.covee.io", "pihole.mesh.covee.io"])
        # A new host cannot take a device's name.
        coordinator.nodes = [*coordinator.nodes, {"id": "6", "given_name": "wiki", "ip_addresses": ["100.64.0.6"]}]
        with self.assertRaisesRegex(deploy.DeploymentError, "wiki is already the name of a device"):
            self.set_hosts(runtime, coordinator, grafana, {"name": "wiki", "device": "pi", "port": 80})

    # check-hosts

    def test_check_hosts_changes_nothing_and_works_with_hosts_off(self):
        for template, suffix in ((self.template, "-off"), (self.hosts_template, "-on")):
            directory = self.copy(template, suffix)
            runtime = deploy.Runtime(directory)
            before = self.files(directory)
            coordinator = FakeCoordinator(nodes=NODES[:2])
            with patch.object(deploy.Runtime, "compose", running), patch.object(runtime, "control", coordinator):
                self.assertEqual(runtime.check_hosts({"hosts": [{"name": "grafana", "device": "mac-mini", "port": 8080}]}), {"ok": True})
                with self.assertRaisesRegex(deploy.DeploymentError, "^No device named mac-studio in this network$"):
                    runtime.check_hosts({"hosts": [{"name": "grafana", "device": "mac-studio", "port": 8080}]})
                with self.assertRaisesRegex(deploy.DeploymentError, "already the name of a device"):
                    runtime.check_hosts({"hosts": [{"name": "pi", "device": "mac-mini", "port": 8080}]})
                with self.assertRaisesRegex(deploy.DeploymentError, "must start with one /"):
                    runtime.check_hosts({"hosts": [{"name": "grafana", "device": "mac-mini", "port": 8080, "path": "/foo%"}]})
            self.assertEqual([c[0][:2] for c in coordinator.calls], [("nodes", "list")] * 3, "only reads the devices")
            self.assertEqual(self.files(directory), before)
            with patch.object(deploy.Runtime, "compose", return_value=result()):
                with self.assertRaisesRegex(deploy.DeploymentError, "not running"):
                    runtime.check_hosts({"hosts": []})

    def test_check_hosts_from_the_command_line(self):
        directory = self.copy()
        config = self.base / "check-hosts.json"
        config.write_text(json.dumps({"hosts": [{"name": "grafana", "device": "mac-mini", "port": 8080}]}))
        argv = ["deploy.py", "check-hosts", "--config", str(config), "--directory", str(directory)]
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", argv), patch.object(deploy.Runtime, "compose", running), patch.object(deploy.Runtime, "control", FakeCoordinator()), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(deploy.main(), 0)
        self.assertEqual(json.loads(out.getvalue()), {"ok": True})
        config.write_text(json.dumps({"hosts": [{"name": "grafana", "device": "mac-studio", "port": 8080}]}))
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", argv), patch.object(deploy.Runtime, "compose", running), patch.object(deploy.Runtime, "control", FakeCoordinator()), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(deploy.main(), 1)
        self.assertEqual(err.getvalue(), "ERROR: No device named mac-studio in this network\n")
        self.assertEqual(out.getvalue(), "")

    # Interrupted changes

    def test_an_interrupted_change_of_hosts_is_put_right(self):
        directory = self.copy(self.hosts_template)
        runtime = deploy.Runtime(directory)
        coordinator = FakeCoordinator()
        grafana, pihole = {"name": "grafana", "device": "mac-mini", "port": 8080}, {"name": "pihole", "device": "pi", "port": 80}
        self.set_hosts(runtime, coordinator, grafana, pihole)
        whole = self.records(directory)
        kept = self.hosts_file(directory)["hosts"]

        # Stopped between the two files: hosts.json no longer has pihole, the records still do.
        deploy.write_hosts(directory, kept[:1])
        deploy.validate(directory, production=True)
        self.assertEqual(self.set_hosts(runtime, coordinator, grafana)["changed"], True)
        self.assertEqual([r["name"] for r in self.records(directory)], ["nas.mesh.covee.io", "grafana.mesh.covee.io", "grafana.mesh.covee.io"])

        # The same, repaired by a start, which keeps the hosts device's address.
        self.set_hosts(runtime, coordinator, grafana, pihole)
        self.assertEqual(self.records(directory), whole)
        deploy.write_hosts(directory, kept[:1])
        with patch.object(runtime, "pin_images"), patch.object(runtime, "bootstrap"), patch.object(runtime, "compose", return_value=result()), \
                patch.object(runtime, "prepare_hosts_node"), patch.object(runtime, "finish_hosts_node"):
            runtime.start()
        self.assertEqual([r["name"] for r in self.records(directory)], ["nas.mesh.covee.io", "grafana.mesh.covee.io", "grafana.mesh.covee.io"])
        self.assertEqual({r["value"] for r in self.records(directory)[1:]}, {"100.64.0.3", "fd7a:115c:a1e0::3"})

    # Other commands

    def test_rename_is_refused_while_hosts_are_on(self):
        directory = self.copy(self.hosts_template)
        before = self.files(directory)
        with patch.object(deploy.Runtime, "compose", return_value=result()) as compose:
            with self.assertRaisesRegex(deploy.DeploymentError, r"This network has hosts.*turn them off first \(`covee host off <network>`\), then rename"):
                deploy.Runtime(directory).rename("new.covee.io", "mesh.new.covee.io", str(self.wildcard[0]), str(self.wildcard[1]))
            compose.assert_not_called()
        self.assertEqual(self.files(directory), before)

    def test_renewal_needs_the_wildcard_and_refreshes_the_hosts_copy(self):
        directory = self.copy(self.hosts_template)
        runtime = deploy.Runtime(directory)
        renewed = certificate(self.base / "certs", "renewed", "control.covee.io", "*.mesh.covee.io")
        with patch.object(runtime, "compose", return_value=result()), patch.object(runtime, "start") as start:
            with self.assertRaisesRegex(deploy.DeploymentError, "cover every name under mesh.covee.io"):
                runtime.renew_certificates(str(self.control_only[0]), str(self.control_only[1]))
            runtime.renew_certificates(str(renewed[0]), str(renewed[1]))
            start.assert_not_called()
        self.assertEqual((directory / deploy.HOSTS_TLS / "fullchain.pem").read_bytes(), renewed[0].read_bytes())
        self.assertEqual((directory / deploy.HOSTS_TLS / "privkey.pem").read_bytes(), renewed[1].read_bytes())
        before = self.files(directory)
        with patch.object(runtime, "compose", return_value=result()), patch.object(deploy, "validate", side_effect=deploy.DeploymentError("invalid")):
            with self.assertRaisesRegex(deploy.DeploymentError, "previous certificates were restored"):
                runtime.renew_certificates(str(self.wildcard[0]), str(self.wildcard[1]))
        self.assertEqual({k: v for k, v in self.files(directory).items() if not k.endswith((".crt", ".key")) or k.startswith("ingress-control")},
                         {k: v for k, v in before.items() if not k.endswith((".crt", ".key")) or k.startswith("ingress-control")})

    def test_build_includes_the_hosts_device_image(self):
        with patch.object(deploy, "run") as run:
            deploy.build(include_identity=True)
        tags = [call.args[0][call.args[0].index("--tag") + 1] for call in run.call_args_list if "--tag" in call.args[0]]
        self.assertIn("covee-hosts-node:portable-local", tags)
        self.assertIn(str(deploy.ROOT / "deploy/Dockerfile.hosts-node"), [str(a) for call in run.call_args_list for a in call.args[0]])

    def test_backup_covers_the_hosts_and_restore_keeps_the_hosts_image(self):
        directory = self.copy(self.hosts_template)
        deploy.write_private(directory / deploy.HOSTS_NODE_STATE / deploy.CONSOLE_NODE_IDENTITY, "{}")
        deploy.write_private(directory / deploy.HOSTS_NODE_STATE / deploy.CONSOLE_JOIN_KEY, "hskey-auth-secret", mode=0o600)
        names = [name for name, _, _ in deploy_backup._snapshot_paths(directory)]
        for name in ("state/hosts/hosts.json", "state/hosts/extra-records.json", "state/hosts-node/covee-joined",
                     "state/hosts-tls/fullchain.pem", "state/hosts-tls/privkey.pem"):
            self.assertIn(name, names)
        self.assertNotIn("state/hosts-node/join-key", names, "a one-time join key is never backed up")
        for name in ("state/hosts", "state/hosts/hosts.json", "state/hosts-node/x", "state/hosts-tls/privkey.pem"):
            deploy_backup._safe_name(name)
        with self.assertRaises(deploy_backup.BackupError):
            deploy_backup._safe_name("state/hostsx/file")
        # Restore rebases the runtime's image references, the optional devices' included.
        deploy_backup._rebase(directory)
        self.assertIn("COVEE_HOSTS_NODE_IMAGE='covee-hosts-node:portable-local'", (directory / "runtime.env").read_text())


if __name__ == "__main__":
    unittest.main()
