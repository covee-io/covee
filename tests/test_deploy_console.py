import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import deploy


def result(stdout=b""):
    return type("Result", (), {"stdout": stdout, "returncode": 0})()


def two_name_certificate(directory, name, *hosts):
    cert, key = directory / f"{name}.crt", directory / f"{name}.key"
    deploy.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "30",
                "-subj", f"/CN={hosts[0]}", "-addext", "subjectAltName=" + ",".join("DNS:" + h for h in hosts),
                "-keyout", key, "-out", cert])
    key.chmod(0o400)
    cert.chmod(0o400)
    return cert, key


class PolicyTests(unittest.TestCase):
    def test_the_console_grant_is_added_once(self):
        merged = deploy.with_console_access('{"grants": [], "ssh": []}')
        policy = json.loads(merged)
        self.assertEqual(policy["tagOwners"], {"tag:covee-console": []})
        self.assertEqual(policy["grants"], [{"src": ["autogroup:member"], "dst": ["tag:covee-console"], "ip": ["tcp:443"]}])
        self.assertEqual(policy["ssh"], [])
        self.assertIsNone(deploy.with_console_access(merged))

    def test_existing_rules_comments_and_trailing_commas_are_kept_or_tolerated(self):
        text = '''{
  // Members may use the printer.
  "tagOwners": {"tag:printer": ["autogroup:admin"],},
  "grants": [
    {"src": ["autogroup:member"], "dst": ["tag:printer"], "ip": ["tcp:631"]}, /* the office printer */
  ],
  "hosts": {"note": "a // in a string stays"},
}'''
        policy = json.loads(deploy.with_console_access(text))
        self.assertEqual(policy["tagOwners"], {"tag:printer": ["autogroup:admin"], "tag:covee-console": []})
        self.assertEqual(len(policy["grants"]), 2)
        self.assertEqual(policy["hosts"]["note"], "a // in a string stays")

    def test_unreadable_policies_are_refused(self):
        for text in ("not json", "[]", '{"grants": {}}', '{"tagOwners": []}', '{"a": 1 /* open'):
            with self.subTest(text=text), self.assertRaises(deploy.DeploymentError):
                deploy.with_console_access(text)


class ConsoleNetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        cls.certs = cls.base / "certs"
        cls.certs.mkdir(mode=0o700)
        cls.both = two_name_certificate(cls.certs, "both", "control.covee.io", "console.mesh.covee.io")
        cls.control_only = two_name_certificate(cls.certs, "control", "control.covee.io")
        deploy.write_private(cls.base / "google-secret", "private-google-secret")
        cls.raw = {"control_host": "control.covee.io", "admin_host": "localhost", "dns_base_domain": "mesh.covee.io",
                   "tls": {"control_cert_file": str(cls.control_only[0]), "control_key_file": str(cls.control_only[1])},
                   "identity": {"providers": [{"id": "google", "kind": "google", "client_id": "google-id.apps.googleusercontent.com",
                                               "client_secret_file": str(cls.base / "google-secret")}],
                                "grants": [{"provider": "google", "subject": "1234567890", "role": "Covee.Admin", "enroll": True}]}}
        cls.template = cls.base / "template"
        deploy.prepare(cls.template, cls.raw)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def copy(self):
        directory = self.base / self.id().rsplit(".", 1)[-1]
        shutil.copytree(self.template, directory)
        metadata = deploy.load_json(directory / "deployment.json")
        deploy.replace_private(directory / "runtime.env", deploy.runtime_env(directory, metadata))
        return directory

    def raw_with_console(self, cert):
        raw = json.loads(json.dumps(self.raw))
        raw["console_in_network"] = True
        raw["tls"] = {"control_cert_file": str(cert[0]), "control_key_file": str(cert[1])}
        return raw

    def assert_console_contract(self, directory):
        metadata = deploy.validate(directory, production=True)
        self.assertEqual(deploy.console_host(metadata["spec"]), "console.mesh.covee.io")
        console = [c for c in deploy.load_json(directory / "identity.json")["clients"] if c["kind"] == "console"][0]
        self.assertEqual(console["redirect_uri"], "https://localhost:8444/auth/oidc/callback")
        self.assertEqual(console["extra_redirect_uris"], ["https://console.mesh.covee.io/auth/oidc/callback"])
        self.assertIn("COVEE_ADDITIONAL_ORIGINS=https://console.mesh.covee.io\n", (directory / "management.env").read_text())
        env = (directory / "runtime.env").read_text()
        self.assertIn("COVEE_MESH_CONSOLE_HOST='console.mesh.covee.io'\n", env)
        self.assertIn("COVEE_CONSOLE_NODE_IMAGE=", env)
        state = directory / deploy.CONSOLE_NODE_STATE
        self.assertTrue(state.is_dir())
        self.assertEqual(state.stat().st_mode & 0o777, 0o700)
        self.assertIn(str(deploy.CONSOLE_COMPOSE), [str(part) for part in deploy.Runtime(directory).base])

    def test_the_setting_needs_the_identity_broker_and_a_boolean(self):
        raw = {"control_host": "control.covee.io", "admin_host": "localhost", "dns_base_domain": "mesh.covee.io", "console_in_network": True,
               "oidc": {}, "tls": {}}
        with self.assertRaisesRegex(deploy.DeploymentError, "identity broker"):
            deploy.validate_spec(raw)
        for value in ("yes", 1, None):
            with self.subTest(value=value), self.assertRaisesRegex(deploy.DeploymentError, "true or false"):
                deploy.validate_spec({**self.raw, "console_in_network": value})
        self.assertIsNone(deploy.console_host(deploy.validate_spec(self.raw)))

    def test_prepare_serves_the_console_inside_the_network(self):
        directory = self.base / "prepared-with-console"
        deploy.prepare(directory, self.raw_with_console(self.both))
        self.assert_console_contract(directory)

    def test_prepare_refuses_a_certificate_without_the_console_name(self):
        with self.assertRaisesRegex(deploy.DeploymentError, "also name the in-network console host"):
            deploy.prepare(self.base / "prepared-without-name", self.raw_with_console(self.control_only))

    def test_without_the_setting_nothing_changes(self):
        directory = self.copy()
        metadata = deploy.validate(directory, production=True)
        self.assertNotIn("console_node", deploy.runtime_images(metadata))
        self.assertNotIn("COVEE_MESH_CONSOLE_HOST", (directory / "runtime.env").read_text())
        self.assertNotIn("extra_redirect_uris", (directory / "identity.json").read_text())
        self.assertNotIn(str(deploy.CONSOLE_COMPOSE), [str(part) for part in deploy.Runtime(directory).base])

    def test_enable_on_a_running_network(self):
        directory = self.copy()
        runtime = deploy.Runtime(directory)
        with patch.object(deploy.Runtime, "compose", return_value=result()), patch.object(deploy.Runtime, "start") as start:
            reply = runtime.enable_console_network(str(self.both[0]), str(self.both[1]))
            start.assert_called_once_with()
        self.assertEqual(reply, {"console": "https://console.mesh.covee.io"})
        self.assert_console_contract(directory)
        self.assertEqual((directory / "ingress-control.crt").read_bytes(), self.both[0].read_bytes())
        with self.assertRaisesRegex(deploy.DeploymentError, "already"):
            deploy.Runtime(directory).enable_console_network(str(self.both[0]), str(self.both[1]))

    def test_enable_refuses_a_certificate_without_the_console_name_and_changes_nothing(self):
        directory = self.copy()
        before = {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file()}
        with patch.object(deploy.Runtime, "compose", return_value=result()) as compose:
            with self.assertRaisesRegex(deploy.DeploymentError, "must also name console.mesh.covee.io"):
                deploy.Runtime(directory).enable_console_network(str(self.control_only[0]), str(self.control_only[1]))
            compose.assert_not_called()
        self.assertEqual({p.name: p.read_bytes() for p in directory.iterdir() if p.is_file()}, before)
        self.assertFalse((directory / deploy.CONSOLE_NODE_STATE).exists())

    def test_a_failed_start_restores_every_file(self):
        directory = self.copy()
        before = {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file()}
        starts = []

        def start(runtime):
            starts.append(bool(runtime.console))
            if runtime.console:
                raise deploy.DeploymentError("the console node failed")

        with patch.object(deploy.Runtime, "compose", return_value=result()), patch.object(deploy.Runtime, "start", start):
            with self.assertRaisesRegex(deploy.DeploymentError, "previous settings were restored"):
                deploy.Runtime(directory).enable_console_network(str(self.both[0]), str(self.both[1]))
        self.assertEqual(starts, [True, False])
        after = {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file() and not p.name.startswith(".")}
        self.assertEqual(after, {k: v for k, v in before.items() if not k.startswith(".")})
        self.assertFalse((directory / deploy.CONSOLE_NODE_STATE).exists())
        deploy.validate(directory, production=True)

    def test_a_new_console_device_gets_a_one_time_key_and_stale_entries_are_removed(self):
        directory = self.base / "join-key"
        deploy.prepare(directory, self.raw_with_console(self.both))
        runtime = deploy.Runtime(directory)
        nodes = [{"id": 7, "given_name": "console", "tags": ["tag:covee-console"]},
                 {"id": 8, "given_name": "macbook-pro", "tags": []},
                 {"id": 9, "given_name": "console-1", "forced_tags": ["tag:covee-console"]}]
        replies = {"policy get": result(b'{"grants": [], "ssh": []}'), "nodes list": result(json.dumps(nodes).encode())}
        calls = []

        def control(*args, **kwargs):
            calls.append((args, kwargs.get("data")))
            return replies.get(" ".join(args[:2]), result())

        with patch.object(runtime, "control", control), patch.object(runtime, "create_device_key", return_value={"key": "hskey-auth-" + "a" * 40}) as key:
            runtime.prepare_console_node()
            key.assert_called_once_with(["tag:covee-console"], expiration="1h")
        policy_writes = [c for c in calls if c[0][:2] in (("policy", "check"), ("policy", "set"))]
        self.assertEqual([c[0][:2] for c in policy_writes], [("policy", "check"), ("policy", "set")])
        self.assertIn(b"tag:covee-console", policy_writes[1][1])
        deleted = [c[0] for c in calls if c[0][:2] == ("nodes", "delete")]
        self.assertEqual(deleted, [("nodes", "delete", "--identifier", "7", "--force"), ("nodes", "delete", "--identifier", "9", "--force")])
        join = directory / deploy.CONSOLE_NODE_STATE / deploy.CONSOLE_JOIN_KEY
        self.assertEqual(join.read_text(), "hskey-auth-" + "a" * 40 + "\n")
        self.assertEqual(join.stat().st_mode & 0o777, 0o600)

        # Once joined: no new key, nothing deleted, and the key file goes away.
        deploy.write_private(directory / deploy.CONSOLE_NODE_STATE / deploy.CONSOLE_NODE_IDENTITY, "{}")
        calls.clear()
        replies["policy get"] = result(deploy.with_console_access('{"grants": [], "ssh": []}').encode())
        with patch.object(runtime, "control", control), patch.object(runtime, "create_device_key") as key:
            runtime.prepare_console_node()
            key.assert_not_called()
        self.assertEqual([c[0][:2] for c in calls], [("policy", "get")])
        with patch.object(runtime, "wait"):
            runtime.finish_console_node()
        self.assertFalse(join.exists())

    def test_the_overlay_never_publishes_the_console_listener(self):
        overlay = deploy.CONSOLE_COMPOSE.read_text()
        self.assertNotIn("ports:", overlay)
        self.assertIn("networks: [backend]", overlay)
        self.assertIn("COVEE_CONSOLE_TARGET: ingress:8447", overlay)
        self.assertIn('TS_NO_LOGS_NO_SUPPORT: "true"', overlay)


if __name__ == "__main__":
    unittest.main()
