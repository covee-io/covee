import base64
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import proxmox
import proxmox_host


def ed25519_line():
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(range(32))
    return "ssh-ed25519 " + base64.b64encode(blob).decode() + " covee@home"


class FakeHost:
    """Records Proxmox commands and answers them like a small single-node host."""

    def __init__(self, base, *, used=(100, 101, 102), answers_ping=False, interface="eth0"):
        self.base, self.used, self.answers_ping, self.interface = base, set(used), answers_ping, interface
        self.commands = []

    def sh(self, *argv, check=True):
        argv = [str(a) for a in argv]
        self.commands.append(argv)
        out, code = "", 0
        if argv[:2] == ["ping", "-c"]:
            code = 0 if self.answers_ping else 1
        elif argv[:2] == ["curl", "--fail"]:
            Path(argv[argv.index("--output") + 1]).write_bytes(b"ubuntu image")
        elif argv[:3] == ["qm", "cloudinit", "dump"]:
            out = f"version: 1\nconfig:\n    - type: physical\n      name: {self.interface}\n"
        if check and code:
            raise subprocess.CalledProcessError(code, argv, "", "failed")
        return subprocess.CompletedProcess(argv, code, out, "")

    def pvesh(self, path, *extra):
        if path == "/cluster/resources":
            return [{"vmid": v} for v in self.used]
        raise AssertionError(path)


class ProxmoxHostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.snippets = self.base / "storage" / "snippets"
        self.request = {"node": "pve", "vmid": 103, "name": "covee-office", "disk_storage": "nvme", "snippet_storage": "snippets",
                        "snippet_directory": str(self.snippets), "bridge": "vmbr0", "network_interface": "eth0", "vlan_tag": None,
                        "ipv4_cidr": "192.168.50.21/24", "gateway_ipv4": "192.168.50.1", "dns_servers": ["192.168.50.1"],
                        "ssh_source_cidrs": ["192.168.50.0/24"], "ssh_public_key": ed25519_line(), "control_host": "control.covee.io",
                        "cores": 4, "memory_mib": 8192, "disk_gib": 64}
        self.lock = {"url": "https://cloud-images.ubuntu.com/x.img", "sha256": proxmox_host.hashlib.sha256(b"ubuntu image").hexdigest()}
        for p in (patch.object(proxmox_host, "STAGING", self.base / "staging"), patch.object(proxmox_host, "lock", return_value=self.lock),
                  patch.object(proxmox_host.os, "geteuid", return_value=0)):
            p.start()
            self.addCleanup(p.stop)

    def host(self, **kwargs):
        fake = FakeHost(self.base, **kwargs)
        for p in (patch.object(proxmox_host, "sh", side_effect=fake.sh), patch.object(proxmox_host, "pvesh", side_effect=fake.pvesh)):
            p.start()
            self.addCleanup(p.stop)
        return fake

    def test_creates_the_reviewed_pilot_vm_and_starts_it(self):
        fake = self.host()
        result = proxmox_host.create(dict(self.request))
        self.assertEqual(result["vmid"], 103)
        self.assertFalse(result["image_reused"])
        snippet = self.snippets / "covee-103.cloud-config.yaml"
        config = json.loads(snippet.read_text().removeprefix("#cloud-config\n"))
        self.assertEqual(config["users"][0]["name"], "covee")
        self.assertEqual(config["users"][0]["ssh_authorized_keys"][0], ed25519_line().rsplit(" ", 1)[0])
        self.assertEqual(snippet.stat().st_mode & 0o777, 0o600)
        names = [" ".join(c[:2]) for c in fake.commands]
        self.assertIn("qm create", names)
        self.assertEqual(fake.commands[-1], ["qm", "start", "103"])
        create = next(c for c in fake.commands if c[:2] == ["qm", "create"])
        self.assertIn("vmbr0", " ".join(create))
        self.assertTrue(any("--cicustom" in c and "user=snippets:snippets/covee-103.cloud-config.yaml" in c for c in fake.commands))

    def test_reuses_a_verified_cached_image_instead_of_downloading(self):
        cached = self.base / "staging" / "101" / proxmox_host.IMAGE_NAME
        cached.parent.mkdir(parents=True)
        cached.write_bytes(b"ubuntu image")
        fake = self.host()
        self.assertTrue(proxmox_host.create(dict(self.request))["image_reused"])
        self.assertFalse(any(c[:2] == ["curl", "--fail"] for c in fake.commands))

    def test_refuses_used_ids_answering_addresses_and_leftover_files(self):
        self.host(used=(100, 101, 103))
        with self.assertRaisesRegex(proxmox_host.HostError, "in use"):
            proxmox_host.create(dict(self.request))
        patch.stopall()
        self.setUp_patches_again()
        self.host(answers_ping=True)
        with self.assertRaisesRegex(proxmox_host.HostError, "answers"):
            proxmox_host.create(dict(self.request))
        (self.base / "staging" / "103").mkdir(parents=True)
        self.host()
        with self.assertRaisesRegex(proxmox_host.HostError, "already exist"):
            proxmox_host.create(dict(self.request))

    def setUp_patches_again(self):
        for p in (patch.object(proxmox_host, "STAGING", self.base / "staging"), patch.object(proxmox_host, "lock", return_value=self.lock),
                  patch.object(proxmox_host.os, "geteuid", return_value=0)):
            p.start()
            self.addCleanup(p.stop)

    def test_wrong_interface_name_leaves_the_vm_stopped(self):
        fake = self.host(interface="ens18")
        with self.assertRaisesRegex(proxmox_host.HostError, "not started"):
            proxmox_host.create(dict(self.request))
        self.assertNotIn(["qm", "start", "103"], fake.commands)

    def test_rejects_bad_requests_before_touching_the_host(self):
        fake = self.host()
        for change in ({"ssh_public_key": "ssh-rsa AAAA"}, {"ipv4_cidr": "192.168.50.0/24"}, {"node": "pve; reboot"}, {"ssh_source_cidrs": ["0.0.0.0/0"]}):
            with self.subTest(change=change), self.assertRaises((proxmox_host.HostError, proxmox.PlanError)):
                proxmox_host.create({**self.request, **change})
        self.assertEqual(fake.commands, [])


if __name__ == "__main__":
    unittest.main()
