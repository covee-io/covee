import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import deploy


@unittest.skipIf(os.getuid() == 0 or shutil.which("openssl") is None, "requires non-root account and OpenSSL")
class DeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        cls.template = cls.base / "template"
        cls.lab = {"control_host": "ingress", "admin_host": "admin", "dns_base_domain": "mesh.lab.invalid",
                   "public_bind": "127.0.0.1", "public_port": 8443}
        deploy.prepare(cls.template, cls.lab, lab=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.directory = self.base / self.id().rsplit(".", 1)[-1]
        shutil.copytree(self.template, self.directory)
        metadata = deploy.load_json(self.directory / "deployment.json")
        deploy.replace_private(self.directory / "runtime.env", deploy.runtime_env(self.directory, metadata))

    def test_preparation_private_and_not_production(self):
        deploy.validate(self.directory)
        with self.assertRaisesRegex(deploy.DeploymentError, "lab"):
            deploy.validate(self.directory, production=True)
        for path in self.directory.rglob("*"):
            self.assertFalse(path.stat().st_mode & 0o077, path.name)
        config = deploy.load_json(self.directory / "headscale.yaml")
        self.assertTrue(config["derp"]["server"]["verify_clients"])
        self.assertFalse(config["logtail"]["enabled"])
        self.assertEqual(json.loads((self.directory / "initial-policy.hujson").read_text()), {"grants": [], "ssh": []})

    def test_existing_state_and_root_refused(self):
        with self.assertRaisesRegex(deploy.DeploymentError, "existing state"):
            deploy.prepare(self.directory, self.lab, lab=True)
        with patch.object(deploy.os, "getuid", return_value=0):
            with self.assertRaisesRegex(deploy.DeploymentError, "UID 0"):
                deploy.prepare(self.base / "root-forbidden", self.lab, lab=True)
        self.assertFalse((self.base / "root-forbidden").exists())

    def test_world_readable_secret_and_symlink_rejected(self):
        secret = self.directory / "secrets/admin-token"
        secret.chmod(0o444)
        with self.assertRaisesRegex(deploy.DeploymentError, "private regular"):
            deploy.validate(self.directory)
        secret.unlink()
        secret.symlink_to(self.template / "secrets/admin-token")
        with self.assertRaisesRegex(deploy.DeploymentError, "private regular"):
            deploy.validate(self.directory)

    def test_diagnostic_exposure_and_unverified_relay_rejected(self):
        path = self.directory / "headscale.yaml"
        original = deploy.load_json(path)
        for mutation in (lambda c: c.update(metrics_listen_addr="0.0.0.0:9090"),
                         lambda c: c.update(grpc_allow_insecure=True),
                         lambda c: c["derp"]["server"].update(verify_clients=False),
                         lambda c: c["logtail"].update(enabled=True),
                         lambda c: c["node"].update(expiry="999999999999999999d")):
            config = copy.deepcopy(original)
            mutation(config)
            deploy.replace_private(path, json.dumps(config))
            with self.assertRaises(deploy.DeploymentError):
                deploy.validate(self.directory)

    def test_certificate_host_and_key_binding(self):
        deploy.cert_pair(self.directory / "ingress-control.crt", self.directory / "ingress-control.key", "ingress")
        with self.assertRaises(deploy.DeploymentError):
            deploy.cert_pair(self.directory / "ingress-control.crt", self.directory / "ingress-control.key", "wrong.invalid")
        with self.assertRaisesRegex(deploy.DeploymentError, "does not match"):
            deploy.cert_pair(self.directory / "ingress-control.crt", self.directory / "ingress-admin.key", "ingress")

    def test_hostname_mismatch_rejected_when_openssl_exits_zero(self):
        native_run = deploy.run

        def openssl_30_status(args, **kwargs):
            if "-checkhost" in args:
                result = native_run(args, **{**kwargs, "check": False})
                self.assertIn(b"does NOT match certificate", result.stdout)
                return subprocess.CompletedProcess(result.args, 0, result.stdout, result.stderr)
            return native_run(args, **kwargs)

        with patch.object(deploy, "run", side_effect=openssl_30_status):
            with self.assertRaisesRegex(deploy.DeploymentError, "configured hostname"):
                deploy.cert_pair(self.directory / "ingress-control.crt", self.directory / "ingress-control.key", "wrong.invalid")

    def test_hostname_check_fails_closed_on_missing_or_ambiguous_output(self):
        native_run = deploy.run
        for output in (b"", b"Hostname other.invalid does match certificate\n",
                       b"Hostname ingress does NOT match certificate\n",
                       b"Hostname ingress does match certificate\nHostname ingress does NOT match certificate\n"):
            def unexpected_hostname_output(args, **kwargs):
                if "-checkhost" in args:
                    return subprocess.CompletedProcess(args, 0, output, b"")
                return native_run(args, **kwargs)

            with self.subTest(output=output), patch.object(deploy, "run", side_effect=unexpected_hostname_output):
                with self.assertRaisesRegex(deploy.DeploymentError, "configured hostname"):
                    deploy.cert_pair(self.directory / "ingress-control.crt", self.directory / "ingress-control.key", "ingress")

    def test_hostname_san_precedence_and_wildcards_remain_enforced(self):
        cert, key = self.directory / "san.crt", self.directory / "ingress-control.key"
        deploy.run(["openssl", "req", "-new", "-x509", "-key", key, "-days", "2",
                    "-subj", "/CN=cn-only.covee.io", "-addext",
                    "subjectAltName=DNS:*.mesh.covee.io,DNS:control.covee.io", "-out", cert])
        cert.chmod(0o400)
        for host in ("peer.mesh.covee.io", "control.covee.io"):
            with self.subTest(host=host):
                deploy.cert_pair(cert, key, host)
        for host in ("cn-only.covee.io", "deep.peer.mesh.covee.io", "mesh.covee.io"):
            with self.subTest(host=host), self.assertRaises(deploy.DeploymentError):
                deploy.cert_pair(cert, key, host)

    def test_source_credentials_never_echoed(self):
        path = self.directory / "credential-source"
        secret = "private-value-must-never-appear"
        deploy.write_private(path, secret + "\n")
        self.assertEqual(deploy.read_source(str(path), secret=True), (secret + "\n").encode())
        for value in (secret + "\n\n", " " + secret, secret + "\r", "", secret + "\nsecond"):
            deploy.replace_private(path, value)
            with self.assertRaises(deploy.DeploymentError) as caught:
                deploy.read_source(str(path), secret=True)
            self.assertNotIn(secret, str(caught.exception))
        path.chmod(0o644)
        with self.assertRaisesRegex(deploy.DeploymentError, "permissions"):
            deploy.read_source(str(path), private=True)

    def test_spec_rejects_ambiguous_hosts_ports_and_paths(self):
        for changed in ({"control_host": "Ingress"}, {"control_host": "a..invalid"}, {"admin_host": "ingress"},
                        {"public_bind": "any"}, {"public_port": True}, {"stun_port": 65536}, {"node_expiry": "0d"},
                        {"unrecognized": "value"}, {"node_expiry": "999999999999999999d"}, {"node_expiry": "366d"}):
            with self.subTest(changed=changed), self.assertRaises(deploy.DeploymentError):
                deploy.validate_spec({**self.lab, **changed}, lab=True)
        metadata = deploy.load_json(self.directory / "deployment.json")
        for path in ("/tmp/$(bad)", "/tmp/unsafe'path", "/tmp/unsafe\npath"):
            with self.assertRaises(deploy.DeploymentError):
                deploy.runtime_env(Path(path), metadata)

    def test_production_requires_restricted_separate_identity(self):
        raw = {**self.lab, "control_host": "control.covee.io", "public_port": 443,
               "oidc": {"issuer": "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
                        "coordinator_client_id": "coordinator", "console_client_id": "console",
                        "coordinator_client_secret_file": "/private/one", "console_client_secret_file": "/private/two"},
               "tls": {"control_cert_file": "/private/cert", "control_key_file": "/private/key"},
               "allowed_group_ids": ["22222222-2222-2222-2222-222222222222"]}
        raw["admin_host"] = "localhost"
        deploy.validate_spec(raw)
        for mutate in (lambda s: s.update(allowed_group_ids=[]),
                       lambda s: s["oidc"].update(issuer="https://login.microsoftonline.com/common/v2.0"),
                       lambda s: s["oidc"].update(issuer="http://issuer.example.com"),
                       lambda s: s["oidc"].update(issuer="https://issuer.example/path\nCOVEE_HEADSCALE_URL=https://other.example"),
                       lambda s: s.update(stun_port=12345),
                       lambda s: s["oidc"].update(console_client_id="coordinator")):
            invalid = copy.deepcopy(raw)
            mutate(invalid)
            with self.assertRaises(deploy.DeploymentError):
                deploy.validate_spec(invalid)

    def test_mutated_storage_and_duplicate_environment_rejected(self):
        path = self.directory / "headscale.yaml"
        original = deploy.load_json(path)
        for mutation in (lambda c: c["database"]["sqlite"].update(write_ahead_log=False),
                         lambda c: c["policy"].update(mode="file"),
                         lambda c: c.update(tls_cert_path=""),
                         lambda c: c.update(server_url="https://unintended.example")):
            modified = copy.deepcopy(original)
            mutation(modified)
            deploy.replace_private(path, json.dumps(modified))
            with self.assertRaises(deploy.DeploymentError):
                deploy.validate(self.directory)
        deploy.replace_private(path, json.dumps(original))
        env_path = self.directory / "management.env"
        deploy.replace_private(env_path, env_path.read_text() + "COVEE_HEADSCALE_URL=https://unintended.example\n")
        with self.assertRaisesRegex(deploy.DeploymentError, "duplicate"):
            deploy.validate(self.directory)

    def test_ambient_deployment_environment_does_not_override_selected_runtime(self):
        with patch.dict(os.environ, {"COVEE_DEPLOY_DIR": "/different/private/state", "COVEE_PUBLIC_BIND": "0.0.0.0"}):
            with patch.object(deploy, "run") as run:
                deploy.Runtime(self.directory).compose("config", "--quiet")
                self.assertNotIn("COVEE_DEPLOY_DIR", run.call_args.kwargs["env"])
                self.assertNotIn("COVEE_PUBLIC_BIND", run.call_args.kwargs["env"])
                self.assertIn("PATH", run.call_args.kwargs["env"])

    def test_missing_initialized_database_stops_ingress_and_cannot_start(self):
        deploy.write_private(self.directory / "state/headscale/.policy-initialized", "initialized")
        runtime = deploy.Runtime(self.directory)
        with patch.object(runtime, "compose") as compose:
            with self.assertRaisesRegex(deploy.DeploymentError, "database is missing"):
                runtime.bootstrap()
            compose.assert_called_once_with("stop", "ingress", "management", timeout=60)

    def test_policy_failure_cannot_finish_bootstrap(self):
        runtime = deploy.Runtime(self.directory)
        for initialized in (False, True):
            if initialized:
                deploy.write_private(self.directory / "state/headscale/.policy-initialized", "initialized")
                deploy.write_private(self.directory / "state/headscale/db.sqlite", "database-placeholder")
            with patch.object(runtime, "compose") as compose, patch.object(runtime, "wait"), patch.object(runtime, "rotate_api_key") as rotate:
                with patch.object(runtime, "control", side_effect=deploy.DeploymentError("policy unavailable")):
                    with self.assertRaisesRegex(deploy.DeploymentError, "policy unavailable"):
                        runtime.bootstrap()
                self.assertEqual(compose.call_args_list[-1].args, ("up", "--detach", "headscale"))
                rotate.assert_not_called()

    def test_concurrent_operations_cannot_overlap_snapshot_and_rotation(self):
        runtime = deploy.Runtime(self.directory)
        with runtime.acquire_lock():
            with self.assertRaisesRegex(deploy.DeploymentError, "Another operation"):
                runtime.acquire_lock()
        with runtime.acquire_lock():
            pass

    @unittest.skipUnless(shutil.which("docker"), "Compose CLI is optional for unit tests")
    def test_ipv6_public_binding_renders_unambiguously(self):
        metadata = deploy.load_json(self.directory / "deployment.json")
        metadata["spec"]["public_bind"] = "::"
        deploy.replace_private(self.directory / "deployment.json", json.dumps(metadata))
        deploy.replace_private(self.directory / "runtime.env", deploy.runtime_env(self.directory, metadata))
        deploy.validate(self.directory)
        config = json.loads(deploy.Runtime(self.directory).compose("config", "--format", "json").stdout)
        control_ports = config["services"]["ingress"]["ports"]
        self.assertEqual(control_ports[0]["host_ip"], "::")
        self.assertEqual(control_ports[1]["host_ip"], "127.0.0.1")
        self.assertNotIn("ports", config["services"]["management"])


@unittest.skipIf(os.getuid() == 0 or shutil.which("openssl") is None, "requires non-root account and OpenSSL")
class SocialDeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        cls.cert_source = cls.base / "cert-source"
        deploy.prepare(cls.cert_source, {"control_host": "ingress", "admin_host": "admin", "dns_base_domain": "mesh.lab.invalid", "public_port": 8443}, lab=True)
        deploy.issue_certificate(cls.cert_source, "social-control", "control.covee.io")
        deploy.write_private(cls.base / "google-secret", "private-google-secret")
        deploy.write_private(cls.base / "entra-secret", "private-entra-secret")
        deploy.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", cls.base / "apple-key"])
        (cls.base / "apple-key").chmod(0o400)
        cls.raw = {"control_host": "control.covee.io", "admin_host": "localhost", "dns_base_domain": "mesh.covee.io",
                   "tls": {"control_cert_file": str(cls.cert_source / "social-control.crt"), "control_key_file": str(cls.cert_source / "social-control.key")},
                   "identity": {"providers": [
                       {"id": "google", "kind": "google", "client_id": "google-id.apps.googleusercontent.com", "client_secret_file": str(cls.base / "google-secret")},
                       {"id": "apple", "kind": "apple", "client_id": "io.covee.signin", "team_id": "ABCDEFGHIJ", "key_id": "KLMNOPQRST", "private_key_file": str(cls.base / "apple-key")},
                       {"id": "entra", "kind": "entra", "client_id": "entra-id", "client_secret_file": str(cls.base / "entra-secret"),
                        "issuer": "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0", "allowed_group_ids": ["22222222-2222-2222-2222-222222222222"]}],
                       "grants": [{"provider": "google", "subject": "1234567890", "role": "Covee.Admin", "enroll": True},
                                  {"provider": "apple", "subject": "00123.abcdef.1234", "role": "Covee.Reader", "enroll": False}]}}
        cls.template = cls.base / "template"
        deploy.prepare(cls.template, cls.raw)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.directory = self.base / self.id().rsplit(".", 1)[-1]
        shutil.copytree(self.template, self.directory)
        metadata = deploy.load_json(self.directory / "deployment.json")
        deploy.replace_private(self.directory / "runtime.env", deploy.runtime_env(self.directory, metadata))

    def test_private_broker_contract_and_separate_downstream_credentials(self):
        metadata = deploy.validate(self.directory, production=True)
        config = deploy.load_json(self.directory / "identity.json")
        self.assertEqual(config["issuer"], "https://control.covee.io/identity")
        self.assertEqual(config["providers"][0]["client_secret_file"], "/run/identity-secrets/google-client-secret")
        self.assertNotIn(str(self.base), (self.directory / "deployment.json").read_text())
        self.assertEqual(deploy.load_json(self.directory / "headscale.yaml")["oidc"]["allowed_groups"], ["covee.enroll"])
        self.assertEqual(deploy.load_json(self.directory / "headscale.yaml")["oidc"]["scope"], ["openid", "profile"])
        first = (self.directory / "secrets/oidc-client-secret").read_text()
        second = (self.directory / "secrets/entra-client-secret").read_text()
        self.assertGreaterEqual(len(first), 32)
        self.assertNotEqual(first, second)
        self.assertEqual(set(deploy.runtime_images(metadata)), {"headscale", "management", "ingress", "identity"})
        for path in self.directory.rglob("*"):
            self.assertFalse(path.stat().st_mode & 0o077, path.name)

    def test_ambiguous_provider_or_authorization_configuration_rejected(self):
        mutations = [lambda s: s.update(oidc={}), lambda s: s.update(allowed_group_ids=[]),
                     lambda s: s["identity"].update(providers=[]),
                     lambda s: s["identity"]["providers"].append(s["identity"]["providers"][0]),
                     lambda s: s["identity"]["providers"][0].update(issuer="https://untrusted.example"),
                     lambda s: s["identity"]["providers"][1].update(team_id="incorrect"),
                     lambda s: s["identity"]["providers"][2].update(issuer="https://login.microsoftonline.com/common/v2.0"),
                     lambda s: s["identity"]["grants"][0].update(subject="email@example.com"),
                     lambda s: s["identity"]["grants"][0].update(role="Owner"),
                     lambda s: s["identity"]["grants"][0].update(enroll="true"),
                     lambda s: s["identity"]["grants"].append(s["identity"]["grants"][0])]
        for mutate in mutations:
            raw = copy.deepcopy(self.raw)
            mutate(raw)
            with self.subTest(raw=raw), self.assertRaises(deploy.DeploymentError):
                deploy.validate_spec(raw)
        with self.assertRaisesRegex(deploy.DeploymentError, "token lab"):
            deploy.validate_spec(self.raw, lab=True)

    def test_prepared_provider_grants_trust_and_secrets_cannot_drift(self):
        path = self.directory / "identity.json"
        original = path.read_bytes()
        config = json.loads(original)
        config["grants"][0]["role"] = "Covee.Reader"
        deploy.replace_private(path, json.dumps(config))
        with self.assertRaisesRegex(deploy.DeploymentError, "provider/client/grant"):
            deploy.validate(self.directory)
        deploy.replace_private(path, original)
        trust = self.directory / "identity-trust.pem"
        deploy.replace_private(trust, (self.directory / "internal-ca.crt").read_bytes())
        with self.assertRaisesRegex(deploy.DeploymentError, "identity trust"):
            deploy.validate(self.directory)
        deploy.replace_private(trust, (self.template / "identity-trust.pem").read_bytes())
        deploy.write_private(self.directory / "identity-secrets/unexpected-secret", "unexpected")
        with self.assertRaisesRegex(deploy.DeploymentError, "configured providers"):
            deploy.validate(self.directory)

    def test_bootstrap_discovers_identity_before_headscale_and_keeps_policy_gate(self):
        runtime = deploy.Runtime(self.directory)
        self.assertIn(deploy.IDENTITY_COMPOSE, runtime.base)
        with patch.object(runtime, "compose") as compose, patch.object(runtime, "wait"), patch.object(runtime, "rotate_api_key") as rotate:
            with patch.object(runtime, "control", side_effect=deploy.DeploymentError("policy unavailable")):
                with self.assertRaisesRegex(deploy.DeploymentError, "policy unavailable"):
                    runtime.bootstrap()
            calls = [call.args for call in compose.call_args_list]
            self.assertEqual(calls[0], ("stop", "ingress", "management", "headscale"))
            self.assertEqual(calls[1], ("--file", deploy.IDENTITY_BOOTSTRAP_COMPOSE, "up", "--detach", "--no-deps", "--force-recreate", "identity", "ingress"))
            self.assertEqual(calls[-1], ("up", "--detach", "headscale"))
            rotate.assert_not_called()

    def test_grant_update_validates_subjects_and_restarts_only_broker(self):
        runtime = deploy.Runtime(self.directory)
        invalid = [{"provider": "google", "subject": "123", "role": "Owner", "enroll": True}]
        old = (self.directory / "identity.json").read_bytes()
        with patch.object(runtime, "compose") as compose, patch.object(runtime, "wait") as wait:
            with self.assertRaises(deploy.DeploymentError):
                runtime.update_identity_grants(invalid)
            self.assertEqual((self.directory / "identity.json").read_bytes(), old)
            compose.assert_not_called()
            grants = [{"provider": "apple", "subject": "new.verified.subject", "role": "Covee.Reader", "enroll": True}]
            runtime.update_identity_grants(grants)
            compose.assert_called_once_with("up", "--detach", "--no-deps", "--force-recreate", "identity", timeout=120)
            wait.assert_called_once_with("identity")
        self.assertEqual(deploy.validate(self.directory, production=True)["spec"]["identity"]["grants"], grants)
        self.assertEqual(deploy.load_json(self.directory / "identity.json")["grants"], grants)

    def test_provider_update_changes_providers_in_place_and_restarts_only_broker(self):
        runtime = deploy.Runtime(self.directory)
        google, apple, entra = copy.deepcopy(self.raw["identity"]["providers"])
        secrets_dir = self.directory / "identity-secrets"
        before = {path.name: path.read_bytes() for path in secrets_dir.iterdir()}
        old_identity = (self.directory / "identity.json").read_bytes()
        with patch.object(runtime, "compose") as compose, patch.object(runtime, "wait") as wait:
            # Apple still has a grant: disabling it must be refused without changes.
            with self.assertRaisesRegex(deploy.DeploymentError, "grants"):
                runtime.update_identity_providers([google, entra])
            compose.assert_not_called()
            self.assertEqual((self.directory / "identity.json").read_bytes(), old_identity)
            runtime.update_identity_grants([{"provider": "google", "subject": "1234567890", "role": "Covee.Admin", "enroll": True}])
            compose.reset_mock()
            wait.reset_mock()
            # Remove Apple and rotate the Entra secret in one replacement.
            rotated = self.base / (self.id().rsplit(".", 1)[-1] + "-entra")
            deploy.write_private(rotated, "rotated-entra-secret\n", mode=0o600)
            entra["client_secret_file"] = str(rotated)
            runtime.update_identity_providers([entra, google])
            compose.assert_called_once_with("up", "--detach", "--no-deps", "--force-recreate", "identity", timeout=120)
            wait.assert_called_once_with("identity")
        metadata = deploy.validate(self.directory, production=True)
        self.assertEqual([p["id"] for p in metadata["spec"]["identity"]["providers"]], ["entra", "google"])
        self.assertNotIn(str(self.base), (self.directory / "deployment.json").read_text())
        self.assertEqual({p.name for p in secrets_dir.iterdir()}, {"entra-client-secret", "google-client-secret"})
        self.assertEqual((secrets_dir / "entra-client-secret").read_bytes(), b"rotated-entra-secret\n")
        self.assertEqual((secrets_dir / "google-client-secret").read_bytes(), before["google-client-secret"])
        config = deploy.load_json(self.directory / "identity.json")
        self.assertEqual([p["id"] for p in config["providers"]], ["entra", "google"])
        self.assertEqual(config["providers"][0]["client_secret_file"], "/run/identity-secrets/entra-client-secret")

    def test_certificate_renewal_reissues_internal_certificates_and_installs_a_new_public_one(self):
        runtime = deploy.Runtime(self.directory)
        internal = ["headscale-internal", "management-internal", "identity-internal", "ingress-admin"]
        before = {name: (self.directory / f"{name}.crt").read_bytes() for name in internal}
        name = "renewed-" + self.id().rsplit(".", 1)[-1][-12:]
        deploy.issue_certificate(self.cert_source, name, "control.covee.io")
        cert, key = self.cert_source / f"{name}.crt", self.cert_source / f"{name}.key"
        idle, busy = type("R", (), {"stdout": b""})(), type("R", (), {"stdout": b"container"})()
        with patch.object(runtime, "compose", return_value=idle), patch.object(runtime, "start") as start:
            result = runtime.renew_certificates(str(cert), str(key))
            start.assert_not_called()
        for name_ in internal:
            self.assertNotEqual((self.directory / f"{name_}.crt").read_bytes(), before[name_], name_)
        self.assertEqual((self.directory / "ingress-control.crt").read_bytes(), cert.read_bytes())
        self.assertEqual((self.directory / "identity-trust.pem").read_bytes(), (self.directory / "internal-ca.crt").read_bytes() + cert.read_bytes())
        self.assertEqual(list(self.directory.glob("*.renew.*")), [])
        self.assertGreaterEqual(result["internal_days_left"], 88)
        self.assertEqual(result["admin_certificate"], "renewed")
        deploy.validate(self.directory, production=True)
        # A running network restarts behind the persisted-policy gate.
        with patch.object(runtime, "compose", return_value=busy) as compose, patch.object(runtime, "start") as start:
            runtime.renew_certificates()
            compose.assert_any_call("stop", "ingress", "management", "headscale", timeout=60)
            start.assert_called_once_with()

    def test_failed_or_mismatched_certificate_renewal_changes_nothing(self):
        runtime = deploy.Runtime(self.directory)
        files = {path: path.read_bytes() for path in self.directory.iterdir() if path.suffix in (".crt", ".key", ".pem")}
        idle = type("R", (), {"stdout": b""})()
        other = "other-" + self.id().rsplit(".", 1)[-1][-12:]
        deploy.issue_certificate(self.cert_source, other, "other.covee.io")
        with patch.object(runtime, "compose", return_value=idle):
            # Refused either way: OpenSSL versions differ in how they report the mismatch.
            with self.assertRaises(deploy.DeploymentError):
                runtime.renew_certificates(str(self.cert_source / f"{other}.crt"), str(self.cert_source / f"{other}.key"))
            with self.assertRaisesRegex(deploy.DeploymentError, "both"):
                runtime.renew_certificates(str(self.cert_source / f"{other}.crt"), None)
            with patch.object(deploy, "validate", side_effect=deploy.DeploymentError("invalid")):
                with self.assertRaisesRegex(deploy.DeploymentError, "previous certificates were restored"):
                    runtime.renew_certificates()
        self.assertEqual({path: path.read_bytes() for path in files}, files)
        self.assertEqual(list(self.directory.glob("*.renew.*")), [])
        deploy.validate(self.directory, production=True)

    def test_local_accounts_provider_needs_no_settings_and_gets_a_private_state_folder(self):
        raw = copy.deepcopy(self.raw)
        raw["identity"]["providers"].append({"id": "local", "kind": "local"})
        deploy.validate_spec(raw)
        for bad in ({"id": "local", "kind": "local", "client_id": "x"}, {"id": "local", "kind": "local", "accounts_file": "/tmp/elsewhere.json"},
                    {"id": "local", "kind": "google"}):
            broken = copy.deepcopy(self.raw)
            broken["identity"]["providers"].append(bad)
            with self.subTest(bad=bad), self.assertRaises(deploy.DeploymentError):
                deploy.validate_spec(broken)
        five = copy.deepcopy(raw)
        five["identity"]["providers"].append({"id": "local", "kind": "local"})
        with self.assertRaises(deploy.DeploymentError):
            deploy.validate_spec(five)
        directory = self.base / ("local-" + self.id().rsplit(".", 1)[-1][-10:])
        deploy.prepare(directory, raw)
        config = deploy.load_json(directory / "identity.json")
        local = [p for p in config["providers"] if p["id"] == "local"]
        self.assertEqual(local, [{"id": "local", "kind": "local", "accounts_file": deploy.LOCAL_ACCOUNTS_FILE}])
        self.assertFalse((directory / "identity-secrets/local-client-secret").exists())
        state = directory / "state/identity"
        self.assertTrue(state.is_dir())
        self.assertEqual(state.stat().st_mode & 0o777, 0o700)
        deploy.validate(directory, production=True)

    def test_older_runtimes_get_the_broker_state_folder_when_started(self):
        runtime = deploy.Runtime(self.directory)
        state = self.directory / "state/identity"
        if state.exists():
            state.rmdir()
        with patch.object(runtime, "pin_images"), patch.object(runtime, "bootstrap"), patch.object(runtime, "compose"):
            runtime.start()
        self.assertTrue(state.is_dir())
        self.assertEqual(state.stat().st_mode & 0o777, 0o700)

    def test_local_account_commands_are_validated_and_run_in_the_broker(self):
        runtime = deploy.Runtime(self.directory)
        with self.assertRaisesRegex(deploy.DeploymentError, "not enabled"):
            runtime.local_accounts("list")
        google, apple, entra = copy.deepcopy(self.raw["identity"]["providers"])
        with patch.object(runtime, "compose"), patch.object(runtime, "wait"):
            runtime.update_identity_providers([google, apple, entra, {"id": "local", "kind": "local"}])
        answer = type("R", (), {"stdout": json.dumps({"email": "alice@example.org", "invite_token": "t" * 43, "expires": "2026-10-15T20:00:00Z"}).encode(), "returncode": 0})()
        with patch.object(runtime, "compose", return_value=answer) as compose:
            created = runtime.local_accounts("invite", email="Alice@Example.org", name="Alice", role="admin", enroll=True, expires="72h")
            compose.assert_called_once_with("exec", "-T", "identity", "/covee-identity", "accounts", "invite", "--email", "alice@example.org",
                                            "--name", "Alice", "--role", "admin", "--enroll", "true", "--expires", "72h", check=False)
            self.assertEqual(created["invite_token"], "t" * 43)
            compose.reset_mock()
            for action, kwargs in (("invite", {"email": "not-an-email", "name": "A", "expires": "72h"}), ("invite", {"email": "a@b.co", "name": "", "expires": "72h"}),
                                   ("invite", {"email": "a@b.co", "name": "A\nB", "expires": "72h"}), ("invite", {"email": "a@b.co", "name": "A", "expires": "999h"}),
                                   ("update", {"email": "a@b.co", "role": "owner"}), ("delete-all", {})):
                with self.subTest(action=action, kwargs=kwargs), self.assertRaises(deploy.DeploymentError):
                    runtime.local_accounts(action, **kwargs)
            compose.assert_not_called()
        refused = type("R", (), {"stdout": json.dumps({"error": "an account with this email exists"}).encode(), "returncode": 1})()
        with patch.object(runtime, "compose", return_value=refused):
            with self.assertRaisesRegex(deploy.DeploymentError, "exists"):
                runtime.local_accounts("invite", email="a@b.co", name="A", role="none", enroll=True, expires="72h")

    def test_device_keys_are_tag_owned_bounded_and_validated(self):
        runtime = deploy.Runtime(self.directory)
        # The shape Headscale 0.29 prints, with protobuf timestamps.
        reply = type("Result", (), {"stdout": json.dumps({"id": 2, "key": "hskey-auth-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4",
                                                          "expiration": {"seconds": 1791835261, "nanos": 489491608}, "acl_tags": ["tag:server"]}).encode()})()
        with patch.object(runtime, "control", return_value=reply) as control:
            created = runtime.create_device_key(["tag:server"], expiration="24h", reusable=True)
            control.assert_called_once_with("preauthkeys", "create", "--tags", "tag:server", "--expiration", "24h", "--output", "json", "--reusable")
            self.assertEqual(created["key"], "hskey-auth-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4")
            self.assertEqual(created["expiration"], "2026-10-12T20:01:01Z")
            control.reset_mock()
            for tags, expiration in ((["server"], "24h"), ([], "24h"), (["tag:Server"], "24h"), (["tag:a", "tag:a"], "24h"),
                                     (["tag:server; rm -rf /"], "24h"), (["tag:server"], "1m"), (["tag:server"], "91d"), (["tag:server"], "forever")):
                with self.subTest(tags=tags, expiration=expiration), self.assertRaises(deploy.DeploymentError):
                    runtime.create_device_key(tags, expiration=expiration)
            control.assert_not_called()
        with patch.object(runtime, "control", return_value=type("Result", (), {"stdout": b"not json"})()):
            with self.assertRaisesRegex(deploy.DeploymentError, "invalid device key"):
                runtime.create_device_key(["tag:server"])

    def test_failed_provider_update_restores_the_previous_providers(self):
        runtime = deploy.Runtime(self.directory)
        google, apple, entra = copy.deepcopy(self.raw["identity"]["providers"])
        files = {p: p.read_bytes() for p in [self.directory / "identity.json", self.directory / "deployment.json", *(self.directory / "identity-secrets").iterdir()]}
        with patch.object(runtime, "compose") as compose, patch.object(runtime, "wait", side_effect=[deploy.DeploymentError("unhealthy"), None]):
            with self.assertRaisesRegex(deploy.DeploymentError, "previous providers were restored"):
                runtime.update_identity_providers([google, apple, entra, ][:2] + [dict(entra, client_id="other-entra-id")])
            self.assertEqual(compose.call_count, 2, "the broker restarts again with the restored settings")
        self.assertEqual({p: p.read_bytes() for p in files}, files)
        self.assertEqual({p.name for p in (self.directory / "identity-secrets").iterdir()}, {p.name for p in files if p.parent.name == "identity-secrets"})
        deploy.validate(self.directory, production=True)

    @unittest.skipUnless(shutil.which("docker"), "Compose CLI is optional for unit tests")
    def test_optional_compose_has_private_identity_and_exact_public_origin_routing(self):
        runtime = deploy.Runtime(self.directory)
        config = json.loads(runtime.compose("config", "--format", "json").stdout)
        identity = config["services"]["identity"]
        self.assertNotIn("ports", identity)
        self.assertTrue(identity["read_only"])
        self.assertEqual(identity["cap_drop"], ["ALL"])
        self.assertNotIn("internal-ca.key", str(identity["volumes"]))
        ingress = config["services"]["ingress"]
        self.assertEqual(ingress["ports"][0]["target"], 443)
        self.assertEqual(ingress["ports"][1]["host_ip"], "127.0.0.1")
        self.assertEqual(ingress["environment"]["COVEE_INGRESS_CONTROL_LISTEN"], ":443")
        self.assertIn("control.covee.io", ingress["networks"]["backend"]["aliases"])
        bootstrap = json.loads(runtime.compose("--file", deploy.IDENTITY_BOOTSTRAP_COMPOSE, "config", "--format", "json").stdout)
        self.assertEqual(bootstrap["services"]["ingress"]["environment"]["COVEE_IDENTITY_ONLY"], "true")


LAB = {"control_host": "ingress", "admin_host": "admin", "dns_base_domain": "mesh.lab.invalid",
       "public_bind": "127.0.0.1", "public_port": 8443}
CUSTOM_DNS = {"override_local_dns": True,
              "nameservers": ["9.9.9.9", "2620:fe::fe", "https://dns.quad9.net/dns-query"],
              "split": {"corp.example.com": ["10.20.0.53", "10.20.1.53"], "10.in-addr.arpa": ["10.20.0.53"]},
              "search_domains": ["corp.example.com", "svc.example.com"],
              "extra_records": [{"name": "grafana.mesh.lab.invalid", "type": "A", "value": "100.64.0.3"},
                                {"name": "grafana.mesh.lab.invalid", "type": "AAAA", "value": "fd7a:115c:a1e0::3"}]}
DEFAULT_DNS_BLOCK = {"magic_dns": True, "base_domain": "mesh.lab.invalid", "override_local_dns": False,
                     "nameservers": {"global": [], "split": {}}, "search_domains": [], "extra_records": []}


@unittest.skipIf(os.getuid() == 0 or shutil.which("openssl") is None, "requires non-root account and OpenSSL")
class CustomDNSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name)
        cls.plain = cls.base / "plain"
        cls.custom = cls.base / "custom"
        deploy.prepare(cls.plain, LAB, lab=True)
        deploy.prepare(cls.custom, {**LAB, "dns": copy.deepcopy(CUSTOM_DNS)}, lab=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.directory = self.base / self.id().rsplit(".", 1)[-1]
        shutil.copytree(self.custom, self.directory)
        metadata = deploy.load_json(self.directory / "deployment.json")
        deploy.replace_private(self.directory / "runtime.env", deploy.runtime_env(self.directory, metadata))

    def dns(self, **changes):
        return {**copy.deepcopy(CUSTOM_DNS), **changes}

    def test_default_coordinator_dns_is_unchanged_without_custom_settings(self):
        deploy.validate(self.plain)
        self.assertEqual(deploy.load_json(self.plain / "headscale.yaml")["dns"], DEFAULT_DNS_BLOCK)
        self.assertNotIn("dns", deploy.load_json(self.plain / "deployment.json")["spec"])
        self.assertEqual(deploy.validate_spec({**LAB, "dns": {}}, lab=True).get("dns"), None)

    def test_custom_settings_render_exactly_and_validate(self):
        deploy.validate(self.directory)
        self.assertEqual(deploy.load_json(self.directory / "headscale.yaml")["dns"], {
            "magic_dns": True, "base_domain": "mesh.lab.invalid", "override_local_dns": True,
            "nameservers": {"global": CUSTOM_DNS["nameservers"],
                            "split": {"10.in-addr.arpa": ["10.20.0.53"], "corp.example.com": ["10.20.0.53", "10.20.1.53"]}},
            "search_domains": ["corp.example.com", "svc.example.com"],
            "extra_records": CUSTOM_DNS["extra_records"]})
        self.assertEqual(deploy.load_json(self.directory / "deployment.json")["spec"]["dns"]["nameservers"], CUSTOM_DNS["nameservers"])

    def test_documented_forms_are_accepted(self):
        for dns in ({"nameservers": ["10.0.0.53"]}, {"nameservers": ["100.64.0.9"]}, {"nameservers": ["2001:4860:4860::8888"]},
                    {"nameservers": ["https://9.9.9.9/dns-query"]}, {"nameservers": ["https://[2620:fe::fe]/dns-query"]},
                    {"nameservers": ["https://dns.example.com:8443/dns-query/profile-1"]},
                    {"split": {"corp": ["10.0.0.53"]}}, {"split": {"168.192.in-addr.arpa": ["192.168.0.1"]}},
                    {"search_domains": ["corp"]}, {"override_local_dns": False}):
            with self.subTest(dns=dns):
                deploy.validate_spec({**LAB, "dns": dns}, lab=True)

    def test_shipped_example_stays_valid_for_the_documented_hosts(self):
        example = deploy.load_json(Path(deploy.ROOT) / "deploy/dns.example.json")
        raw = {**LAB, "control_host": "covee.example.com", "admin_host": "localhost", "dns_base_domain": "mesh.example.com",
               "public_port": 443, "dns": example}
        # The default-valued override flag is dropped from the canonical form; everything else must survive unchanged.
        canonical = deploy.validate_spec(raw, lab=True)["dns"]
        self.assertEqual(canonical, {key: value for key, value in example.items() if key != "override_local_dns"})
        shipped = deploy.load_json(Path(deploy.ROOT) / "deploy/deployment.example.json")
        self.assertEqual((shipped["control_host"], shipped["dns_base_domain"]), ("covee.example.com", "mesh.example.com"))

    def test_unusable_or_dangerous_values_are_rejected(self):
        many = [f"10.0.0.{i}" for i in range(1, 10)]
        invalid = [
            {"nameservers": ["dns.example.com"]},          # Headscale would forward this unusable bare name
            {"nameservers": ["127.0.0.1"]}, {"nameservers": ["0.0.0.0"]}, {"nameservers": ["0.1.2.3"]},
            {"nameservers": ["224.0.0.1"]}, {"nameservers": ["fe80::1"]}, {"nameservers": ["169.254.1.1"]},
            {"nameservers": ["255.255.255.255"]}, {"nameservers": ["::ffff:1.2.3.4"]}, {"nameservers": ["::1"]},
            {"nameservers": ["100.100.100.100"]},        # the client's own forwarder would loop
            {"nameservers": ["10.0.0.1:53"]}, {"nameservers": ["1.1.1.1%eth0"]}, {"nameservers": ["1.1.1.1\n"]},
            {"nameservers": ["http://dns.example.com/dns-query"]},
            {"nameservers": ["https://user:pass@dns.example.com/dns-query"]},
            {"nameservers": ["https://dns.example.com/dns-query?token=secret"]},
            {"nameservers": ["https://dns.example.com/dns-query#x"]},
            {"nameservers": ["https://dns.example.com/../x"]}, {"nameservers": ["https://dns.example.com//x"]},
            {"nameservers": ["https://localhost/dns-query"]}, {"nameservers": ["https://dns.example.com:0/dns-query"]},
            {"nameservers": ["https://127.0.0.1/dns-query"]},
            {"nameservers": ["1.1.1.1", "1.1.1.1"]}, {"nameservers": many}, {"nameservers": "1.1.1.1"}, {"nameservers": [1]},
            {"override_local_dns": True}, {"override_local_dns": "yes"}, {"override_local_dns": 1},
            {"unexpected": 1}, {"nameservers": ["1.1.1.1"], "dnssec": True},
            {"split": {"Corp.Example.com": ["10.0.0.53"]}}, {"split": {"corp.example.com.": ["10.0.0.53"]}},
            {"split": {"corp..example.com": ["10.0.0.53"]}}, {"split": {"": ["10.0.0.53"]}}, {"split": {".": ["10.0.0.53"]}},
            {"split": {"corp.example.com": []}}, {"split": {"corp.example.com": "10.0.0.53"}}, {"split": []},
            {"split": {f"d{i}.example.com": ["10.0.0.53"] for i in range(33)}},
            {"split": {"mesh.lab.invalid": ["10.0.0.53"]}},      # would override MagicDNS
            {"split": {"peer.mesh.lab.invalid": ["10.0.0.53"]}},
            {"split": {"ingress": ["10.0.0.53"]}},               # would capture the coordinator name
            {"split": {"admin": ["10.0.0.53"]}},
            {"search_domains": ["corp.example.com", "corp.example.com"]}, {"search_domains": ["mesh.lab.invalid"]},
            {"search_domains": [f"d{i}.example.com" for i in range(7)]}, {"search_domains": ["Corp.Example.com"]},
            {"search_domains": "corp.example.com"},
            {"extra_records": [{"name": "x.mesh.lab.invalid", "type": "CNAME", "value": "y.mesh.lab.invalid"}]},
            {"extra_records": [{"name": "x.mesh.lab.invalid", "type": "A", "value": "fd7a::3"}]},
            {"extra_records": [{"name": "x.mesh.lab.invalid", "type": "AAAA", "value": "100.64.0.3"}]},
            {"extra_records": [{"name": "x.other.invalid", "type": "A", "value": "100.64.0.3"}]},   # clients never ask the resolver
            {"extra_records": [{"name": "mesh.lab.invalid", "type": "A", "value": "100.64.0.3"}]},
            {"extra_records": [{"name": "X.mesh.lab.invalid", "type": "A", "value": "100.64.0.3"}]},
            {"extra_records": [{"name": "x.mesh.lab.invalid", "type": "A", "value": "127.0.0.1"}]},
            {"extra_records": [{"name": "x.mesh.lab.invalid", "type": "A", "value": "0.0.0.0"}]},
            {"extra_records": [{"name": "x.mesh.lab.invalid", "type": "A", "value": "100.64.0.3", "ttl": 5}]},
            {"extra_records": [{"name": "x.mesh.lab.invalid", "type": "A"}]},
            {"extra_records": [{"name": "x.mesh.lab.invalid", "type": "A", "value": "100.64.0.3"}] * 2},
            {"extra_records": [{"name": f"h{i}.mesh.lab.invalid", "type": "A", "value": "100.64.0.3"} for i in range(129)]},
            {"extra_records": {"name": "x.mesh.lab.invalid"}}, "1.1.1.1", ["1.1.1.1"],
        ]
        for dns in invalid:
            with self.subTest(dns=dns), self.assertRaises(deploy.DeploymentError):
                deploy.validate_spec({**LAB, "dns": dns}, lab=True)

    def test_split_route_cannot_capture_a_production_coordinator_name(self):
        raw = {**LAB, "control_host": "control.covee.io", "admin_host": "localhost", "dns_base_domain": "mesh.covee.io", "public_port": 443,
               "oidc": {"issuer": "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
                        "coordinator_client_id": "coordinator", "console_client_id": "console",
                        "coordinator_client_secret_file": "/private/one", "console_client_secret_file": "/private/two"},
               "tls": {"control_cert_file": "/private/cert", "control_key_file": "/private/key"},
               "allowed_group_ids": ["22222222-2222-2222-2222-222222222222"]}
        deploy.validate_spec({**raw, "dns": {"split": {"corp.example.com": ["10.0.0.53"]}}})
        for domain in ("control.covee.io", "covee.io", "io"):
            with self.subTest(domain=domain), self.assertRaisesRegex(deploy.DeploymentError, "capture"):
                deploy.validate_spec({**raw, "dns": {"split": {domain: ["10.0.0.53"]}}})
        with self.assertRaisesRegex(deploy.DeploymentError, "redefine"):
            deploy.validate_spec({**raw, "admin_host": "admin.mesh.covee.io",
                                  "dns": {"extra_records": [{"name": "admin.mesh.covee.io", "type": "A", "value": "100.64.0.3"}]}})
        # Devices would answer the coordinator's name themselves; Headscale refuses this too.
        with self.assertRaisesRegex(deploy.DeploymentError, "inside the mesh DNS domain"):
            deploy.validate_spec({**raw, "control_host": "control.mesh.covee.io"})

    def test_prepared_dns_cannot_drift_from_recorded_settings(self):
        config_path, metadata_path = self.directory / "headscale.yaml", self.directory / "deployment.json"
        config, metadata = deploy.load_json(config_path), deploy.load_json(metadata_path)
        mutated = copy.deepcopy(config)
        mutated["dns"]["nameservers"]["global"].append("8.8.8.8")
        deploy.replace_private(config_path, json.dumps(mutated))
        with self.assertRaisesRegex(deploy.DeploymentError, "DNS differs"):
            deploy.validate(self.directory)
        deploy.replace_private(config_path, json.dumps(config))
        deploy.validate(self.directory)
        for edit in (lambda spec: spec["dns"].update(search_domains=[]), lambda spec: spec.pop("dns"),
                     lambda spec: spec["dns"].update(nameservers=["127.0.0.1"])):
            changed = copy.deepcopy(metadata)
            edit(changed["spec"])
            deploy.replace_private(metadata_path, json.dumps(changed))
            with self.assertRaises(deploy.DeploymentError):
                deploy.validate(self.directory)

    def runtime(self, running):
        runtime = deploy.Runtime(self.directory)
        patches = (patch.object(runtime, "compose"), patch.object(runtime, "start"))
        compose, start = (p.start() for p in patches)
        for p in patches:
            self.addCleanup(p.stop)
        compose.return_value.stdout = b"container-id\n" if running else b""
        return runtime, compose, start

    def test_update_rewrites_both_files_and_restarts_through_the_start_gate(self):
        runtime, compose, start = self.runtime(running=True)
        update = self.dns(nameservers=["1.1.1.1"], override_local_dns=True)
        self.assertTrue(runtime.update_dns(update))
        self.assertEqual([call.args for call in compose.call_args_list],
                         [("ps", "--quiet", "headscale"), ("stop", "ingress", "management", "headscale")])
        start.assert_called_once_with()
        self.assertEqual(deploy.load_json(self.directory / "headscale.yaml")["dns"]["nameservers"]["global"], ["1.1.1.1"])
        self.assertEqual(deploy.validate(self.directory)["spec"]["dns"]["nameservers"], ["1.1.1.1"])

    def test_update_of_a_stopped_runtime_starts_nothing(self):
        runtime, compose, start = self.runtime(running=False)
        self.assertFalse(runtime.update_dns(self.dns(search_domains=[])))
        self.assertEqual([call.args for call in compose.call_args_list], [("ps", "--quiet", "headscale")])
        start.assert_not_called()
        self.assertEqual(deploy.load_json(self.directory / "headscale.yaml")["dns"]["search_domains"], [])

    def test_empty_update_clears_custom_dns(self):
        runtime, _, _ = self.runtime(running=False)
        runtime.update_dns({})
        self.assertEqual(deploy.load_json(self.directory / "headscale.yaml")["dns"], DEFAULT_DNS_BLOCK)
        self.assertNotIn("dns", deploy.validate(self.directory)["spec"])

    def test_invalid_update_leaves_files_and_services_untouched(self):
        runtime, compose, start = self.runtime(running=True)
        before = [(self.directory / name).read_bytes() for name in ("headscale.yaml", "deployment.json")]
        for dns in ({"nameservers": ["127.0.0.1"]}, {"split": {"ingress": ["10.0.0.53"]}}, {"bogus": True}):
            with self.subTest(dns=dns), self.assertRaises(deploy.DeploymentError):
                runtime.update_dns(dns)
        self.assertEqual([(self.directory / name).read_bytes() for name in ("headscale.yaml", "deployment.json")], before)
        compose.assert_not_called()
        start.assert_not_called()

    def test_failed_restart_restores_the_previous_settings_and_tries_again(self):
        runtime, compose, start = self.runtime(running=True)
        before = [(self.directory / name).read_bytes() for name in ("headscale.yaml", "deployment.json")]
        start.side_effect = [deploy.DeploymentError("coordinator did not become healthy"), None]
        with self.assertRaisesRegex(deploy.DeploymentError, "previous DNS settings were restored"):
            runtime.update_dns(self.dns(nameservers=["1.1.1.1"]))
        self.assertEqual([(self.directory / name).read_bytes() for name in ("headscale.yaml", "deployment.json")], before)
        self.assertEqual(start.call_count, 2)
        deploy.validate(self.directory)

if __name__ == "__main__":
    unittest.main()
