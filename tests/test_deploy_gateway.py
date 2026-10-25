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


def certificate(directory, host):
    cert, key = directory / "control.crt", directory / "control.key"
    deploy.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "30",
                "-subj", f"/CN={host}", "-addext", f"subjectAltName=DNS:{host}", "-keyout", key, "-out", cert])
    key.chmod(0o400)
    cert.chmod(0o400)
    return cert, key


class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        certs = cls.base / "certs"
        certs.mkdir(mode=0o700)
        cert, key = certificate(certs, "covee.example.com")
        deploy.write_private(cls.base / "google-secret", "private-google-secret")
        cls.raw = {"control_host": "covee.example.com", "admin_host": "localhost", "dns_base_domain": "mesh.example.com",
                   "tls": {"control_cert_file": str(cert), "control_key_file": str(key)},
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

    def assert_gateway(self, directory, on):
        metadata = deploy.validate(directory, production=True)
        self.assertEqual(bool(metadata["spec"].get("gateway")), on)
        self.assertEqual("gateway" in deploy.runtime_images(metadata), on)
        self.assertEqual("COVEE_GATEWAY_IMAGE=" in (directory / "runtime.env").read_text(), on)
        self.assertEqual(str(deploy.GATEWAY_COMPOSE) in [str(p) for p in deploy.Runtime(directory).base], on)
        if on:
            for name in (deploy.GATEWAY_STATE, deploy.GATEWAY_CONFIG):
                self.assertEqual((directory / name).stat().st_mode & 0o777, 0o700)

    def test_the_setting_is_a_boolean_and_off_by_default(self):
        self.assertNotIn("gateway", deploy.validate_spec(self.raw))
        for value in ("yes", 1, None):
            with self.subTest(value=value), self.assertRaisesRegex(deploy.DeploymentError, "true or false"):
                deploy.validate_spec({**self.raw, "gateway": value})
        self.assert_gateway(self.copy(), False)

    def test_prepare_with_a_gateway(self):
        directory = self.base / "prepared"
        deploy.prepare(directory, {**self.raw, "gateway": True})
        self.assert_gateway(directory, True)

    def test_turning_it_on_and_off_on_a_running_network(self):
        directory = self.copy()
        calls = []

        def compose(runtime, *args, **kwargs):
            calls.append(args)
            return result()

        with patch.object(deploy.Runtime, "compose", compose), patch.object(deploy.Runtime, "pin_images"), \
                patch.object(deploy.Runtime, "prepare_gateway") as prepare, patch.object(deploy.Runtime, "finish_gateway") as finish:
            self.assertEqual(deploy.Runtime(directory).set_gateway(True), {"gateway": True, "changed": True})
            prepare.assert_called_once_with()
            finish.assert_called_once_with()
        self.assert_gateway(directory, True)
        self.assertIn(("up", "--detach"), calls)
        self.assertEqual(deploy.Runtime(directory).set_gateway(True), {"gateway": True, "changed": False})

        calls.clear()
        with patch.object(deploy.Runtime, "compose", compose), patch.object(deploy.Runtime, "pin_images"), \
                patch.object(deploy.Runtime, "delete_tagged_nodes") as delete:
            self.assertEqual(deploy.Runtime(directory).set_gateway(False), {"gateway": False, "changed": True})
            delete.assert_called_once_with("tag:covee-gateway", "gateway")
        self.assertIn(("rm", "--stop", "--force", "gateway"), calls)
        self.assertIn(("up", "--detach", "--remove-orphans"), calls)
        self.assert_gateway(directory, False)
        # The console's settings stay for the next time it is turned on.
        self.assertTrue((directory / deploy.GATEWAY_CONFIG).is_dir())

    def test_a_failed_start_restores_the_settings(self):
        directory = self.copy()
        before = {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file() and not p.name.startswith(".")}
        with patch.object(deploy.Runtime, "compose", return_value=result()), patch.object(deploy.Runtime, "pin_images"), \
                patch.object(deploy.Runtime, "prepare_gateway", side_effect=deploy.DeploymentError("no key")):
            with self.assertRaisesRegex(deploy.DeploymentError, "previous settings were restored"):
                deploy.Runtime(directory).set_gateway(True)
        after = {p.name: p.read_bytes() for p in directory.iterdir() if p.is_file() and not p.name.startswith(".")}
        self.assertEqual(after, before)
        self.assert_gateway(directory, False)

    def test_a_new_gateway_gets_a_tag_owner_and_a_one_time_key(self):
        directory = self.base / "join"
        deploy.prepare(directory, {**self.raw, "gateway": True})
        runtime = deploy.Runtime(directory)
        nodes = [{"id": 3, "given_name": "gateway", "tags": ["tag:covee-gateway"]}, {"id": 4, "given_name": "gateway-laptop", "tags": []}]
        replies = {"policy get": result(b'{"grants": [], "ssh": []}'), "nodes list": result(json.dumps(nodes).encode())}
        calls = []

        def control(*args, **kwargs):
            calls.append((args, kwargs.get("data")))
            return replies.get(" ".join(args[:2]), result())

        with patch.object(runtime, "control", control), patch.object(runtime, "create_device_key", return_value={"key": "hskey-auth-" + "b" * 40}) as key:
            runtime.prepare_gateway()
            key.assert_called_once_with(["tag:covee-gateway"], expiration="1h")
        written = [c[1] for c in calls if c[0][:2] == ("policy", "set")]
        self.assertEqual(json.loads(written[0])["tagOwners"], {"tag:covee-gateway": []})
        # iPhone and Android clients send the gateway's private DNS through the network.
        self.assertEqual(json.loads(written[0])["nodeAttrs"], [{"target": ["*"], "attr": ["user-dial-routes"]}])
        self.assertEqual([c[0] for c in calls if c[0][:2] == ("nodes", "delete")], [("nodes", "delete", "--identifier", "3", "--force")])
        join = directory / deploy.GATEWAY_STATE / deploy.CONSOLE_JOIN_KEY
        self.assertEqual(join.stat().st_mode & 0o777, 0o600)

        # Joined: no key, no policy write when the owner is there, and the key file goes away.
        deploy.write_private(directory / deploy.GATEWAY_STATE / deploy.CONSOLE_NODE_IDENTITY, "{}")
        calls.clear()
        replies["policy get"] = result(written[0])
        with patch.object(runtime, "control", control), patch.object(runtime, "create_device_key") as key:
            runtime.prepare_gateway()
            key.assert_not_called()
        self.assertEqual([c[0][:2] for c in calls], [("policy", "get")])
        with patch.object(runtime, "wait"):
            runtime.finish_gateway()
        self.assertFalse(join.exists())

    def test_every_device_dials_routes_for_dns_once(self):
        text = '{"grants": [], "nodeAttrs": [{"target": ["tag:x"], "attr": ["funnel"]}]}'
        merged = json.loads(deploy.with_node_attribute(text, deploy.DIAL_ROUTES))
        self.assertEqual(merged["nodeAttrs"], [{"target": ["tag:x"], "attr": ["funnel"]},
                                               {"target": ["*"], "attr": ["user-dial-routes"]}])
        self.assertIsNone(deploy.with_node_attribute(json.dumps(merged), deploy.DIAL_ROUTES), "already given: no write")
        self.assertIn("user-dial-routes", deploy.with_node_attribute("{}", deploy.DIAL_ROUTES))
        with self.assertRaises(deploy.DeploymentError):
            deploy.with_node_attribute('{"nodeAttrs": {}}', deploy.DIAL_ROUTES)

    def test_dns_from_the_console_replaces_only_the_split_part(self):
        directory = self.base / "dns"
        deploy.prepare(directory, {**self.raw, "gateway": True, "dns": {"nameservers": ["1.1.1.1"], "split": {"old.example": ["10.0.0.2"]}}})
        runtime = deploy.Runtime(directory)
        dns_file = directory / deploy.GATEWAY_CONFIG / "dns.json"
        deploy.write_private(dns_file, json.dumps({"split": {"vault.azure.net": ["168.63.129.16"]}}), mode=0o600)
        with patch.object(deploy.Runtime, "update_dns", return_value=True) as update:
            self.assertEqual(runtime.apply_gateway_dns(), {"changed": True, "restarted": True})
            wanted = update.call_args.args[0]
            self.assertEqual(update.call_args.kwargs, {"coordinator_only": True}, "console sessions survive a DNS change")
        self.assertEqual(wanted["split"], {"vault.azure.net": ["168.63.129.16"]})
        self.assertEqual(wanted["nameservers"], ["1.1.1.1"])
        status = json.loads((directory / deploy.GATEWAY_CONFIG / "dns-status.json").read_text())
        self.assertEqual(status["split"], {"vault.azure.net": ["168.63.129.16"]})
        self.assertNotIn("error", status)

        # A rejected setting is reported for the console, and nothing restarts.
        with patch.object(deploy.Runtime, "update_dns", side_effect=deploy.DeploymentError("DNS update failed")):
            with self.assertRaises(deploy.DeploymentError):
                runtime.apply_gateway_dns()
        self.assertIn("DNS update failed", json.loads((directory / deploy.GATEWAY_CONFIG / "dns-status.json").read_text())["error"])

        # Unchanged settings restart nothing.
        deploy.replace_private(dns_file, json.dumps({"split": {"old.example": ["10.0.0.2"]}}), mode=0o600)
        with patch.object(deploy.Runtime, "update_dns") as update:
            self.assertEqual(runtime.apply_gateway_dns(), {"changed": False, "restarted": False})
            update.assert_not_called()

        for bad in ('{"split": []}', '{"split": {}, "global": ["8.8.8.8"]}', '[]'):
            deploy.replace_private(dns_file, bad, mode=0o600)
            with self.subTest(bad=bad), self.assertRaises(deploy.DeploymentError):
                runtime.apply_gateway_dns()

    def test_a_coordinator_only_dns_change_restarts_just_the_coordinator(self):
        directory = self.copy()
        calls = []

        def compose(runtime, *args, **kwargs):
            calls.append(args)
            return result(b"abc123\n" if args[:2] == ("ps", "--quiet") else b"")

        with patch.object(deploy.Runtime, "compose", compose), patch.object(deploy.Runtime, "wait"), \
                patch.object(deploy.Runtime, "start") as start:
            self.assertTrue(deploy.Runtime(directory).update_dns({"split": {"vault.azure.net": ["168.63.129.16"]}}, coordinator_only=True))
            start.assert_not_called()
        self.assertIn(("up", "--detach", "--no-deps", "--force-recreate", "headscale"), calls)
        self.assertFalse(any(c[:1] == ("stop",) for c in calls), "the console and sign-in service keep running")
        self.assertIn("vault.azure.net", (directory / "headscale.yaml").read_text())

    def test_the_overlay_keeps_the_gateway_unprivileged_and_unpublished(self):
        overlay = deploy.GATEWAY_COMPOSE.read_text()
        self.assertNotIn("ports:", overlay)
        self.assertIn("cap_drop: [ALL]", overlay)
        self.assertIn("read_only: true", overlay)
        self.assertNotIn("privileged", overlay)
        self.assertNotIn("NET_ADMIN", overlay)
        self.assertIn("networks: [backend, gateway-egress]", overlay)
        self.assertIn('TS_NO_LOGS_NO_SUPPORT: "true"', overlay)
        self.assertIn("COVEE_GATEWAY_TAG: tag:covee-gateway", overlay)
        self.assertIn("com.docker.network.bridge.name: covee-gw0", overlay)


if __name__ == "__main__":
    unittest.main()
