import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import deploy

OLD_ISSUER = "https://control.covee.io/identity"
NEW_ISSUER = "https://covee.example.org/identity"
ACCOUNTS = [(1, "alice", None),
            (2, "u923c", OLD_ISSUER + "/923c74307a1f"),
            (3, "elsewhere", "https://accounts.example.org/42"),
            (4, "lookalike", OLD_ISSUER + "2/77")]


def two_name_certificate(directory, name, *hosts):
    cert, key = directory / f"{name}.crt", directory / f"{name}.key"
    deploy.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "30",
                "-subj", f"/CN={hosts[0]}", "-addext", "subjectAltName=" + ",".join("DNS:" + h for h in hosts),
                "-keyout", key, "-out", cert])
    key.chmod(0o400)
    cert.chmod(0o400)
    return cert, key


def running_compose(calls):
    def compose(runtime, *args, **kwargs):
        calls.append(args)
        return type("Result", (), {"stdout": b"abc123\n" if args[:1] == ("ps",) else b"", "returncode": 0})()
    return compose


class RenameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        certs = cls.base / "certs"
        certs.mkdir(mode=0o700)
        cls.old = two_name_certificate(certs, "old", "control.covee.io", "console.mesh.covee.io")
        cls.new = two_name_certificate(certs, "new", "covee.example.org", "console.home.example.org")
        cls.new_control_only = two_name_certificate(certs, "new-control", "covee.example.org")
        deploy.write_private(cls.base / "google-secret", "private-google-secret")
        cls.raw = {"control_host": "control.covee.io", "admin_host": "localhost", "dns_base_domain": "mesh.covee.io",
                   "console_in_network": True,
                   "tls": {"control_cert_file": str(cls.old[0]), "control_key_file": str(cls.old[1])},
                   "dns": {"extra_records": [{"name": "nas.mesh.covee.io", "type": "A", "value": "100.64.0.9"}]},
                   "identity": {"providers": [{"id": "google", "kind": "google", "client_id": "google-id.apps.googleusercontent.com",
                                               "client_secret_file": str(cls.base / "google-secret")}],
                                "grants": [{"provider": "google", "subject": "1234567890", "role": "Covee.Admin", "enroll": True}]}}
        cls.template = cls.base / "template"
        deploy.prepare(cls.template, cls.raw)
        connection = sqlite3.connect(cls.template / "state/headscale/db.sqlite")
        with connection:
            connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, provider_identifier TEXT UNIQUE)")
            connection.executemany("INSERT INTO users VALUES (?, ?, ?)", ACCOUNTS)
        connection.close()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def copy(self):
        directory = self.base / self.id().rsplit(".", 1)[-1]
        shutil.copytree(self.template, directory)
        metadata = deploy.load_json(directory / "deployment.json")
        deploy.replace_private(directory / "runtime.env", deploy.runtime_env(directory, metadata))
        return directory

    def accounts(self, directory):
        connection = sqlite3.connect(directory / "state/headscale/db.sqlite")
        try:
            return connection.execute("SELECT id, name, provider_identifier FROM users ORDER BY id").fetchall()
        finally:
            connection.close()

    def snapshot(self, directory):
        files = {p.relative_to(directory): p.read_bytes() for p in directory.rglob("*") if p.is_file() and not p.name.startswith(".")}
        return files

    def test_a_running_network_moves_to_its_new_names_and_keeps_its_accounts(self):
        directory = self.copy()
        calls = []
        with patch.object(deploy.Runtime, "compose", running_compose(calls)), patch.object(deploy.Runtime, "start") as start:
            reply = deploy.Runtime(directory).rename("covee.example.org", "home.example.org", str(self.new[0]), str(self.new[1]))
            start.assert_called_once_with()
        self.assertEqual(reply, {"control": "https://covee.example.org", "issuer": NEW_ISSUER, "devices": "home.example.org",
                                 "console": "https://console.home.example.org", "accounts_moved": 1, "restarted": True})
        self.assertIn(("stop",), calls, "every service stops while the accounts move")
        metadata = deploy.validate(directory, production=True)
        spec = metadata["spec"]
        self.assertEqual((spec["control_host"], spec["dns_base_domain"]), ("covee.example.org", "home.example.org"))
        self.assertEqual(spec["dns"]["extra_records"], [{"name": "nas.home.example.org", "type": "A", "value": "100.64.0.9"}])
        headscale = deploy.load_json(directory / "headscale.yaml")
        self.assertEqual(headscale["server_url"], "https://covee.example.org")
        self.assertEqual(headscale["dns"]["base_domain"], "home.example.org")
        self.assertEqual(headscale["oidc"]["issuer"], NEW_ISSUER)
        identity = deploy.load_json(directory / "identity.json")
        self.assertEqual(identity["issuer"], NEW_ISSUER)
        clients = {c["kind"]: c for c in identity["clients"]}
        self.assertEqual(clients["enrollment"]["redirect_uri"], "https://covee.example.org/oidc/callback")
        self.assertEqual(clients["console"]["extra_redirect_uris"], ["https://console.home.example.org/auth/oidc/callback"])
        env = (directory / "management.env").read_text()
        self.assertIn(f"COVEE_OIDC_ISSUER={NEW_ISSUER}\n", env)
        self.assertIn("COVEE_ADDITIONAL_ORIGINS=https://console.home.example.org\n", env)
        self.assertNotIn("covee.io", env)
        runtime = (directory / "runtime.env").read_text()
        self.assertIn("COVEE_CONTROL_HOST='covee.example.org'\n", runtime)
        self.assertIn("COVEE_MESH_CONSOLE_HOST='console.home.example.org'\n", runtime)
        self.assertEqual((directory / "ingress-control.crt").read_bytes(), self.new[0].read_bytes())
        self.assertEqual(self.accounts(directory), [(1, "alice", None), (2, "u923c", NEW_ISSUER + "/923c74307a1f"),
                                                    (3, "elsewhere", "https://accounts.example.org/42"), (4, "lookalike", OLD_ISSUER + "2/77")])
        with patch.object(deploy.Runtime, "compose", running_compose([])), self.assertRaisesRegex(deploy.DeploymentError, "already uses these names"):
            deploy.Runtime(directory).rename("covee.example.org", "home.example.org", str(self.new[0]), str(self.new[1]))

    def test_a_stopped_network_is_renamed_without_starting_it(self):
        directory = self.copy()

        def stopped(runtime, *args, **kwargs):
            return type("Result", (), {"stdout": b"", "returncode": 0})()

        with patch.object(deploy.Runtime, "compose", stopped), patch.object(deploy.Runtime, "start") as start:
            reply = deploy.Runtime(directory).rename("covee.example.org", "home.example.org", str(self.new[0]), str(self.new[1]))
            start.assert_not_called()
        self.assertFalse(reply["restarted"])
        deploy.validate(directory, production=True)

    def test_refusals_change_nothing(self):
        directory = self.copy()
        before = self.snapshot(directory)
        cases = [(("covee.example.org", "home.example.org", self.new_control_only), "must also name console.home.example.org"),
                 (("covee.home.example.org", "home.example.org", self.new), "inside the mesh DNS domain"),
                 (("covee.example.org", "covee.example.org", self.new), "separate names"),
                 (("covee.example.org", "home.example.org", self.old), "does not match the configured hostname"),  # cert_pair: not for the new host
                 (("Covee.example.org", "home.example.org", self.new), "lowercase")]
        for (host, domain, cert), message in cases:
            with self.subTest(host=host, domain=domain), patch.object(deploy.Runtime, "compose") as compose:
                with self.assertRaisesRegex(deploy.DeploymentError, message):
                    deploy.Runtime(directory).rename(host, domain, str(cert[0]), str(cert[1]))
                compose.assert_not_called()
        self.assertEqual(self.snapshot(directory), before)

    def test_networks_with_covee_accounts_are_refused(self):
        directory = self.copy()
        metadata = deploy.load_json(directory / "deployment.json")
        metadata["spec"]["identity"]["providers"].append({"id": "local", "kind": "local"})
        with patch.object(deploy, "validate", return_value=metadata), patch.object(deploy.Runtime, "compose") as compose:
            with self.assertRaisesRegex(deploy.DeploymentError, "passkeys"):
                deploy.Runtime(directory).rename("covee.example.org", "home.example.org", str(self.new[0]), str(self.new[1]))
            compose.assert_not_called()

    def test_a_failed_start_restores_every_file_and_the_accounts(self):
        directory = self.copy()
        before = self.snapshot(directory)
        starts = []

        def start(runtime):
            host = deploy.load_json(runtime.directory / "deployment.json")["spec"]["control_host"]
            starts.append(host)
            # The coordinator wrote to its database before failing.
            (runtime.directory / "state/headscale/db.sqlite-wal").write_bytes(b"partial")
            if host == "covee.example.org":
                raise deploy.DeploymentError("the coordinator did not become healthy")

        calls = []
        with patch.object(deploy.Runtime, "compose", running_compose(calls)), patch.object(deploy.Runtime, "start", start):
            with self.assertRaisesRegex(deploy.DeploymentError, "previous names, certificate and accounts were restored"):
                deploy.Runtime(directory).rename("covee.example.org", "home.example.org", str(self.new[0]), str(self.new[1]))
        self.assertEqual(starts, ["covee.example.org", "control.covee.io"])
        self.assertEqual([c for c in calls if c[:1] == ("stop",)], [("stop",), ("stop",)], "stopped again before the database is put back")
        after = self.snapshot(directory)
        after.pop(Path("state/headscale/db.sqlite-wal"))  # written by the second, restored start
        self.assertEqual(after, before)
        self.assertEqual(self.accounts(directory), ACCOUNTS)
        deploy.validate(directory, production=True)

    def test_move_accounts_matches_the_whole_issuer_prefix(self):
        directory = self.copy()
        database = directory / "state/headscale/db.sqlite"
        self.assertEqual(deploy.move_accounts(database, OLD_ISSUER, NEW_ISSUER), 1)
        self.assertEqual(deploy.move_accounts(database, OLD_ISSUER, NEW_ISSUER), 0, "nothing left to move")
        with self.assertRaisesRegex(deploy.DeploymentError, "could not be moved"):
            deploy.move_accounts(directory / "deployment.json", OLD_ISSUER, NEW_ISSUER)


if __name__ == "__main__":
    unittest.main()
