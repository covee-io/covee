"""Keep disposable root clients' CA access separate from private runtime files."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import deploy_check


class AcceptanceCAFixtureTests(unittest.TestCase):
    def fixture(self, base):
        runtime = base / "runtime"
        runtime.mkdir(mode=0o700)
        for name, content in (("internal-ca.crt", b"public-certificate\n"), ("internal-ca.key", b"private-key-sentinel\n")):
            path = runtime / name
            path.write_bytes(content)
            path.chmod(0o400)
        with patch.object(deploy_check, "image_id", return_value="sha256:" + "0" * 64):
            overlay, _ = deploy_check.override(runtime)
        return runtime, runtime.with_name(runtime.name + ".client-ca.crt"), overlay

    def test_only_public_certificate_is_copied_without_relaxing_private_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime, public_ca, overlay = self.fixture(Path(temporary))
            self.assertEqual(public_ca.read_bytes(), b"public-certificate\n")
            self.assertEqual(public_ca.stat().st_mode & 0o777, 0o444)
            self.assertEqual(public_ca.parent, runtime.parent)
            self.assertNotIn(b"private-key-sentinel", public_ca.read_bytes())
            for name in ("internal-ca.crt", "internal-ca.key"):
                self.assertEqual((runtime / name).stat().st_mode & 0o777, 0o400)
            text = overlay.read_text()
            self.assertEqual(text.count(str(public_ca) + ":/lab-ca.crt:ro"), 3)
            # Three clients, the probe and the DNS resolver all drop every capability.
            self.assertEqual(text.count("cap_drop: [ALL]"), 5)
            self.assertEqual(text.count("user: '0:0'"), 3)
            self.assertIn("ports: !reset []", text)

    def test_dns_resolver_is_unprivileged_isolated_and_sees_only_its_script(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime, public_ca, overlay = self.fixture(Path(temporary))
            text = overlay.read_text()
            start = text.index("  resolver:\n")
            block = text[start:text.index("\nnetworks:\n", start)]
            self.assertIn("read_only: true", block)
            self.assertIn("cap_drop: [ALL]", block)
            self.assertIn("security_opt: [no-new-privileges:true]", block)
            self.assertIn(f"user: '{os.getuid()}:{os.getgid()}'", block)
            self.assertNotIn("user: '0:0'", block)
            self.assertNotIn("cap_add", block)
            self.assertNotIn("ports", block)
            self.assertNotIn("privileged: true", block)
            self.assertIn("networks: [backend]", block)
            # Port 53 is reachable through a namespaced sysctl, not a capability or root.
            self.assertIn("sysctls: [net.ipv4.ip_unprivileged_port_start=0]", block)
            mounts = [line.strip() for line in block.splitlines() if line.strip().startswith("- ")]
            self.assertEqual(len(mounts), 1)
            self.assertTrue(mounts[0].endswith('lab/dns_stub.py:/lab/dns_stub.py:ro"'))
            for secret in ("internal-ca", "secrets", str(public_ca), str(runtime)):
                self.assertNotIn(secret, block)

    def test_existing_public_fixture_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime, public_ca, _ = self.fixture(Path(temporary))
            before = public_ca.read_bytes()
            with patch.object(deploy_check, "image_id", return_value="unused"):
                with self.assertRaises(FileExistsError):
                    deploy_check.override(runtime)
            self.assertEqual(public_ca.read_bytes(), before)

    @unittest.skipUnless(os.environ.get("COVEE_TEST_CLIENT_CA") == "1", "explicit Docker client-CA qualification only")
    def test_capability_restricted_root_can_read_only_the_public_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime, public_ca, _ = self.fixture(Path(temporary))
            command = ["docker", "run", "--rm", "--network=none", "--user", "0:0", "--read-only",
                       "--cap-drop=ALL", "--security-opt=no-new-privileges",
                       "--mount", f"type=bind,src={public_ca},dst=/lab-ca.crt,readonly",
                       "--entrypoint", "/bin/sh", "tailscale/tailscale:v1.102.3", "-c", "cat /lab-ca.crt"]
            result = subprocess.run(command, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertEqual(result.stdout, b"public-certificate\n")
            for name in ("internal-ca.crt", "internal-ca.key"):
                self.assertEqual((runtime / name).stat().st_mode & 0o777, 0o400)


if __name__ == "__main__":
    unittest.main()
