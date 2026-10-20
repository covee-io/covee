import base64
import io
import json
import struct
import sys
import tarfile
import gzip
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_cli
import host_prepare
import proxmox


def ed25519_line():
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(range(32))
    return "ssh-ed25519 " + base64.b64encode(blob).decode() + " covee@home"


def addresses(interface="eth0", cidr="192.0.2.30/24"):
    ip, prefix = cidr.split("/")
    return [{"ifname": interface, "addr_info": [{"family": "inet", "local": ip, "prefixlen": int(prefix), "dynamic": True}]}]


class PayloadTests(unittest.TestCase):
    def test_payload_is_reproducible_and_limited_to_server_sources(self):
        first, manifest = build_cli.build_payload()
        second, _ = build_cli.build_payload()
        self.assertEqual(first, second, "two builds of the same tree must be byte-identical")
        names = set(manifest)
        self.assertIn("scripts/deploy.py", names)
        self.assertIn("scripts/host_prepare.py", names)
        self.assertIn("deploy/proxmox/bootstrap-guest.sh", names)
        self.assertIn("cmd/covee-console/main.go", names)
        self.assertFalse(any(name.startswith(("cli/", "docs/", "evidence/", "native/", ".cache/")) for name in names))
        self.assertFalse(any("__pycache__" in name or name.endswith(".pyc") for name in names))
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(first))) as archive:
            members = archive.getmembers()
        self.assertEqual(members[0].name, "PAYLOAD-MANIFEST.json")
        self.assertTrue(all(m.uid == 0 and m.gid == 0 and m.mtime == 0 and m.mode == 0o644 and m.isfile() for m in members))

    def test_verify_payload_detects_changes(self):
        data, _ = build_cli.build_payload()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                archive.extractall(root, filter="data")
            (root / ".cache/covee").mkdir(parents=True)
            (root / ".cache/covee/build.log").write_text("build cache is ignored")
            self.assertGreater(host_prepare.verify_payload(root), 50)
            (root / "scripts/extra.py").write_text("print('x')")
            with self.assertRaisesRegex(host_prepare.HostError, "differ"):
                host_prepare.verify_payload(root)
            (root / "scripts/extra.py").unlink()
            with (root / "scripts/deploy.py").open("a") as handle:
                handle.write("# changed\n")
            with self.assertRaisesRegex(host_prepare.HostError, "changed"):
                host_prepare.verify_payload(root)


class GuestConfigTests(unittest.TestCase):
    def raw(self, **change):
        raw = {"network_interface": "eth0", "ipv4_cidr": "192.0.2.30/24", "ssh_source_cidrs": ["192.0.2.0/24"],
               "ssh_public_key": ed25519_line(), "control_host": "control.covee.io"}
        raw.update(change)
        return raw

    def test_config_matches_the_proxmox_guest_settings(self):
        with patch.object(host_prepare, "ip_json", return_value=addresses()):
            config = host_prepare.guest_config(self.raw())
        self.assertEqual(config["ipv4"], "192.0.2.30")
        self.assertEqual(config["ssh_public_key"].split()[0], "ssh-ed25519")
        files = proxmox.guest_files(config)
        self.assertIn("AllowUsers covee", files["/etc/ssh/sshd_config.d/00-covee.conf"][1])
        firewall = files["/usr/local/sbin/covee-guest-firewall"][1]
        self.assertIn("-s 192.0.2.0/24 -p tcp --dport 22", firewall)
        self.assertIn("--ctorigdst 192.0.2.30 --ctorigdstport 443", firewall)

    def test_rejects_lockouts_and_wrong_addresses(self):
        bad = [{"network_interface": "lo"}, {"network_interface": "eth0; reboot"}, {"ssh_source_cidrs": ["0.0.0.0/0"]},
               {"ssh_source_cidrs": ["10.0.0.0/8"]}, {"ssh_source_cidrs": []}, {"ssh_source_cidrs": ["192.0.2.5/24"]},
               {"ipv4_cidr": "198.51.100.7/24"}, {"ssh_public_key": "ssh-rsa AAAA"}]
        for change in bad:
            with self.subTest(change=change), patch.object(host_prepare, "ip_json", return_value=addresses()):
                with self.assertRaises((host_prepare.HostError, proxmox.PlanError)):
                    host_prepare.guest_config(self.raw(**change))


class SystemStepTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.commands, self.written = [], {}
        patches = [
            patch.object(host_prepare, "MARKER", self.base / "complete"),
            patch.object(host_prepare, "APPLIED", self.base / "applied"),
            patch.object(host_prepare.os, "geteuid", return_value=0),
            patch.object(host_prepare, "require_supported"),
            patch.object(host_prepare, "ip_json", return_value=addresses()),
            patch.object(host_prepare, "run", side_effect=self.record_run),
            patch.object(host_prepare, "write", side_effect=self.record_write),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def record_run(self, argv, **kwargs):
        self.commands.append(list(argv))
        if argv[:1] == ["touch"]:
            Path(host_prepare.MARKER).touch()

    def record_write(self, path, content, mode, owner=(0, 0)):
        self.written[str(path)] = (content, mode)
        if Path(path) == host_prepare.APPLIED:
            Path(path).write_text(content)

    def raw(self):
        return {"network_interface": "eth0", "ipv4_cidr": "192.0.2.30/24", "ssh_source_cidrs": ["192.0.2.0/24"],
                "ssh_public_key": ed25519_line(), "control_host": "control.covee.io"}

    def run_system(self, virt):
        with patch.object(host_prepare.subprocess, "run", return_value=type("R", (), {"stdout": virt + "\n"})()):
            return host_prepare.system(self.raw())

    def test_applies_the_pilot_files_and_steps_once(self):
        result = self.run_system("none")
        self.assertTrue(result["changed"])
        install = next(c for c in self.commands if c[:3] == ["apt-get", "-y", "install"])
        self.assertNotIn("qemu-guest-agent", install, "the guest agent is only installed on KVM")
        self.assertIn(["/usr/local/sbin/covee-bootstrap"], self.commands)
        self.assertNotIn(["systemctl", "enable", "--now", "qemu-guest-agent"], self.commands)
        self.assertEqual(self.commands[-1], ["touch", "/var/lib/covee-bootstrap-complete"])
        expected = set(proxmox.guest_files(host_prepare.guest_config(self.raw())))
        self.assertTrue(expected <= set(self.written))
        mode = self.written["/usr/local/sbin/covee-guest-firewall"][1]
        self.assertEqual(mode, 0o700)
        # Same settings again: nothing is reapplied.
        self.commands.clear()
        self.assertFalse(self.run_system("none")["changed"])
        self.assertEqual(self.commands, [])

    def test_the_firewall_alone_is_rewritten_and_applied_when_it_changed(self):
        firewall = self.base / "covee-guest-firewall"
        with patch.object(host_prepare, "FIREWALL", str(firewall)):
            result = host_prepare.firewall(self.raw())
            self.assertEqual(result, {"firewall": "applied", "changed": True})
            content, mode = self.written[str(firewall)]
            self.assertIn("-i covee-gw0 -p tcp --dport 22", content)
            self.assertEqual(mode, 0o700)
            self.assertEqual(self.commands, [[str(firewall)], [str(firewall), "verify"]])
            # Current rules: nothing is rewritten or run.
            firewall.write_text(content)
            self.commands.clear()
            self.written.clear()
            self.assertEqual(host_prepare.firewall(self.raw()), {"firewall": "current", "changed": False})
            self.assertEqual((self.commands, self.written), ([], {}))

    def test_kvm_servers_also_get_the_guest_agent(self):
        self.run_system("kvm")
        install = next(c for c in self.commands if c[:3] == ["apt-get", "-y", "install"])
        self.assertIn("qemu-guest-agent", install)
        self.assertIn(["systemctl", "enable", "--now", "qemu-guest-agent"], self.commands)


class RootOnlyTests(unittest.TestCase):
    def test_changing_steps_require_root(self):
        with patch.object(host_prepare.os, "geteuid", return_value=1000):
            for step in (host_prepare.account, host_prepare.system, host_prepare.firewall):
                with self.assertRaisesRegex(host_prepare.HostError, "root"):
                    step({})


if __name__ == "__main__":
    unittest.main()
