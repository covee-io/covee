import base64
import copy
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import proxmox


class ProxmoxPlanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.key = self.base / "operator.pub"
        blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(range(32))
        self.key.write_text("ssh-ed25519 " + base64.b64encode(blob).decode() + " test-only\n")
        self.config = {"node": "pve-test", "vmid": 789, "name": "covee-pilot", "disk_storage": "local-lvm", "snippet_storage": "local", "snippet_directory": "/var/lib/vz/snippets", "bridge": "vmbr0", "network_interface": "ens18", "vlan_tag": None, "ipv4_cidr": "192.0.2.30/24", "gateway_ipv4": "192.0.2.1", "dns_servers": ["192.0.2.1"], "ssh_source_cidrs": ["192.0.2.40/32"], "ssh_public_key_file": str(self.key), "control_host": "control.test-owned.net", "cores": 4, "memory_mib": 8192, "disk_gib": 64}

    def test_template_cannot_produce_runnable_plan_without_inputs(self):
        raw = json.loads((proxmox.ASSETS / "pilot.example.json").read_text())
        with self.assertRaises(proxmox.PlanError):
            proxmox.render(raw, self.base / "absent")
        self.assertFalse((self.base / "absent").exists())

    def test_untrusted_inputs_cannot_inject_commands_or_expand_exposure(self):
        changes = [{"vmid": True}, {"node": "pve; touch /tmp/injected"}, {"disk_storage": "local,import-from=/etc/shadow"}, {"bridge": "vmbr0\nBAD"}, {"vlan_tag": 4095}, {"snippet_directory": "/var/lib/vz/../snippets"}, {"ipv4_cidr": "192.0.2.0/24"}, {"ipv4_cidr": "192.0.2.255/24"}, {"gateway_ipv4": "198.51.100.1"}, {"gateway_ipv4": "192.0.2.30"}, {"ssh_source_cidrs": ["0.0.0.0/0"]}, {"ssh_source_cidrs": ["10.0.0.0/8"]}, {"ssh_source_cidrs": ["192.0.2.30/24"]}, {"ssh_source_cidrs": ["::/0"]}, {"dns_servers": ["1.1.1.1; false"]}, {"control_host": "control.example.com"}, {"control_host": "Control.host.net"}, {"memory_mib": 1024}]
        for change in changes:
            with self.subTest(change=change):
                raw = copy.deepcopy(self.config)
                raw.update(change)
                with self.assertRaises(proxmox.PlanError):
                    proxmox.validate(raw)
        for change in ({"control_host": "example.com"}, {"control_host": "192.0.2.30"}, {"ssh_source_cidrs": [123]}, {"dns_servers": [123]}):
            raw = {**self.config, **change}
            with self.subTest(change=change), self.assertRaises(proxmox.PlanError):
                proxmox.validate(raw)

    def test_ssh_private_key_options_and_malformed_key_refused(self):
        for content in ("-----BEGIN OPENSSH PRIVATE KEY-----\nsecret", "ssh-ed25519 AAAA", "command=evil " + self.key.read_text(), self.key.read_text() + self.key.read_text()):
            self.key.write_text(content)
            with self.assertRaises(proxmox.PlanError):
                proxmox.validate(self.config)

    def test_private_no_apply_bundle_and_no_overwrite(self):
        directory = self.base / "bundle"
        with patch.object(subprocess, "run", side_effect=AssertionError("renderer must not execute commands")):
            plan = proxmox.render(self.config, directory)
        self.assertEqual(plan["status"], "prepared-not-applied")
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        for path in directory.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        original = (directory / "cloud-config.yaml").read_bytes()
        with self.assertRaises(FileExistsError):
            proxmox.render(self.config, directory)
        self.assertEqual((directory / "cloud-config.yaml").read_bytes(), original)
        cloud = json.loads(original.decode().split("\n", 1)[1])
        self.assertFalse(cloud["ssh_pwauth"])
        self.assertTrue(cloud["disable_root"])
        self.assertEqual(cloud["users"][0]["uid"], 10001)
        self.assertIn(cloud["users"][0]["primary_group"], cloud["groups"])
        self.assertNotIn("passwd", cloud["users"][0])
        phases = plan["commands"]
        self.assertEqual(phases["download_into_new_staging_directory"][-1][0:3], ["sha256sum", "--check", "--strict"])
        self.assertTrue(all(argv[0] != "qm" for argv in phases["read_only_preflight"]))
        rendered_commands = json.dumps(phases)
        for destructive in ("destroy", "pve-firewall", "cipassword", "qm reset"):
            self.assertNotIn(destructive, rendered_commands)

    def test_rendered_guest_scripts_parse_and_forbidden_admin_port_stays_unpublished(self):
        config = proxmox.validate(self.config)
        for content in (proxmox.firewall(config), (proxmox.ASSETS / "bootstrap-guest.sh").read_text()):
            result = subprocess.run(["/bin/sh", "-n"], input=content, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        firewall = proxmox.firewall(config)
        self.assertIn("--ctorigdst 192.0.2.30 --ctorigdstport 443", firewall)
        self.assertIn("--ctorigdst 192.0.2.30 --ctorigdstport 3478", firewall)
        self.assertNotIn("8444", firewall)
        self.assertIn("-s 192.0.2.40/32 -p tcp --dport 22", firewall)
        self.assertIn("-i covee-gw0 -p tcp --dport 22", firewall, "admins reach SSH through the gateway")
        self.assertNotIn("-F DOCKER", firewall)

    def firewall_model(self, fail="", verify=False, docker=False, reported_interface=None, reported_address=None):
        """Execute the actual shell with isolated state, never real host iptables."""
        executable = self.base / "iptables-model"
        executable.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
p = Path(os.environ["MODEL_STATE"])
s = json.loads(p.read_text()) if p.exists() else {"v4": {}, "v6": {}}
family = "v6" if sys.argv[1] == "v6" else "v4"
state = s[family]
chains = state.setdefault("chains", {"INPUT": [], "FORWARD": []})
policies = state.setdefault("policies", {})
args = sys.argv[2:]
if args[0] == "-w": args = args[1:]
if os.environ.get("FAIL_RULE") and os.environ["FAIL_RULE"] in " ".join(args):
    sys.exit(23)
action, chain = args[:2]
rule = args[2:]
ok = True
if action == "-P": policies[chain] = rule[0]
elif action == "-N":
    ok = chain not in chains
    if ok: chains[chain] = []
elif chain not in chains: ok = False
elif action == "-F": chains[chain] = []
elif action == "-A": chains[chain].append(rule)
elif action == "-I": chains[chain].insert(int(rule[0])-1, rule[1:])
elif action == "-C": ok = rule in chains[chain]
elif action == "-D":
    ok = rule in chains[chain]
    if ok: chains[chain].remove(rule)
elif action == "-S":
    if chain in policies: print("-P", chain, policies[chain])
    for r in chains[chain]: print("-A", chain, *r)
else: raise AssertionError(args)
p.write_text(json.dumps(s))
sys.exit(0 if ok else 1)
''')
        executable.chmod(0o700)
        script = proxmox.firewall(proxmox.validate(self.config))
        script = script.replace("IPT=/usr/sbin/iptables", f"IPT='{executable} v4'")
        script = script.replace("IP6T=/usr/sbin/ip6tables", f"IP6T='{executable} v6'")
        ip = self.base / "ip-model"
        ip.write_text('''#!/usr/bin/env python3
import os, sys
interface = os.environ["MODEL_INTERFACE"]
if interface != sys.argv[-1]: sys.exit(1)
print("2:", interface, "inet", os.environ["MODEL_ADDRESS"], "scope global", interface)
''')
        ip.chmod(0o700)
        script = script.replace("/usr/sbin/ip -4", f"{ip} -4")
        environment = {**os.environ, "MODEL_STATE": str(self.base / "firewall-state.json"), "FAIL_RULE": fail,
                       "MODEL_INTERFACE": self.config["network_interface"] if reported_interface is None else reported_interface,
                       "MODEL_ADDRESS": self.config["ipv4_cidr"] if reported_address is None else reported_address}
        mode = ["verify"] if verify else (["docker"] if docker else [])
        result = subprocess.run(["/bin/sh", "-s", "--", *mode],
                                input=script, text=True, capture_output=True, env=environment)
        state_path = self.base / "firewall-state.json"
        return result, json.loads(state_path.read_text()) if state_path.exists() else {}

    def test_discovered_guest_interface_is_explicit_safe_and_not_loopback(self):
        for value in (None, "", "lo", "eth0+", "eth0/foo", "eth0 xyz", "eth0;true", "eth0\ntrue", "a" * 16):
            with self.subTest(value=value), self.assertRaises(proxmox.PlanError):
                proxmox.validate({**self.config, "network_interface": value})
        for value in ("ens18", "eth0", "a" * 15):
            self.assertEqual(proxmox.validate({**self.config, "network_interface": value})["network_interface"], value)
        self.config["network_interface"] = "eth0"
        plan = proxmox.render(self.config, self.base / "eth0-plan")
        self.assertEqual(plan["guest_interface"], "eth0")
        self.assertIn("physical interface name to equal **eth0**", (self.base / "eth0-plan/plan.md").read_text())

    def test_docker_start_requires_exact_discovered_interface_and_ipv4(self):
        for interface in ("eth0", "ens18"):
            self.config["network_interface"] = interface
            for change in ({"reported_interface": "missing0"}, {"reported_address": "192.0.2.31/24"}):
                with self.subTest(interface=interface, change=change):
                    result, state = self.firewall_model(docker=True, **change)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(state, {})  # The daemon prerequisite fails before any firewall mutation.
            result, state = self.firewall_model(docker=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(["-i", interface, "-j", "DROP"], state["v4"]["chains"]["COVEE-DOCKER"])
            (self.base / "firewall-state.json").unlink()

    def test_user_policy_is_seeded_without_docker_and_replay_preserves_other_rules(self):
        result, state = self.firewall_model()
        self.assertEqual(result.returncode, 0, result.stderr)
        chains = state["v4"]["chains"]
        self.assertEqual(chains["FORWARD"][0], ["-j", "DOCKER-USER"])
        self.assertEqual(chains["DOCKER-USER"][0], ["-j", "COVEE-DOCKER"])
        self.assertIn(["-i", "ens18", "-j", "DROP"], chains["COVEE-DOCKER"])
        unrelated = ["-s", "203.0.113.9", "-j", "RETURN"]
        chains["DOCKER-USER"].append(unrelated)
        (self.base / "firewall-state.json").write_text(json.dumps(state))
        result, state = self.firewall_model()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(unrelated, state["v4"]["chains"]["DOCKER-USER"])
        self.assertEqual(state["v4"]["chains"]["DOCKER-USER"].count(["-j", "COVEE-DOCKER"]), 1)
        self.assertEqual(self.firewall_model(verify=True)[0].returncode, 0)

    def test_failed_policy_rebuild_retains_external_drop_and_can_recover(self):
        result, state = self.firewall_model(fail="-A COVEE-DOCKER -i ens18 -p tcp")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state["v4"]["policies"]["INPUT"], "DROP")
        self.assertEqual(state["v4"]["chains"]["DOCKER-USER"][0], ["-i", "ens18", "-j", "DROP"])
        self.assertEqual(state["v4"]["chains"]["FORWARD"][0], ["-j", "DOCKER-USER"])
        result, state = self.firewall_model()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(["-i", "ens18", "-j", "DROP"], state["v4"]["chains"]["DOCKER-USER"])

    def test_boot_services_require_firewall_and_docker_seeds_before_start(self):
        cloud = proxmox.cloud_config(proxmox.validate(self.config))
        files = {entry["path"]: entry["content"] for entry in cloud["write_files"]}
        unit = files["/etc/systemd/system/covee-guest-firewall.service"]
        self.assertIn("DefaultDependencies=no", unit)
        self.assertIn("Before=network-pre.target ssh.service ssh.socket docker.service docker.socket", unit)
        for service in ("systemd-networkd.service", "ssh.service", "ssh.socket"):
            dropin = files[f"/etc/systemd/system/{service}.d/covee-firewall.conf"]
            self.assertIn("Requires=covee-guest-firewall.service", dropin)
            self.assertIn("After=covee-guest-firewall.service", dropin)
        bootstrap = (proxmox.ASSETS / "bootstrap-guest.sh").read_text()
        self.assertIn("ExecStartPre=/usr/local/sbin/covee-guest-firewall docker\n", bootstrap)
        self.assertIn("ExecStartPost=/usr/local/sbin/covee-guest-firewall verify", bootstrap)
        self.assertNotIn("touch /var/lib/covee-bootstrap-complete", bootstrap)

    def test_any_initialization_failure_prevents_completion_marker(self):
        cloud = proxmox.cloud_config(proxmox.validate(self.config))
        marker = self.base / "complete"
        log = self.base / "commands.log"
        stub = '''#!/usr/bin/env python3
import os, sys
from pathlib import Path
command = " ".join([Path(sys.argv[0]).name, *sys.argv[1:]])
with open(os.environ["COMMAND_LOG"], "a") as stream: stream.write(command + "\\n")
sys.exit(17 if command == os.environ.get("FAIL_COMMAND") else 0)
'''
        for name in ("sysctl", "systemctl", "install", "sshd", "bootstrap"):
            executable = self.base / name
            executable.write_text(stub)
            executable.chmod(0o700)
        command = cloud["runcmd"][0]
        script = command[-1].replace("/var/lib/covee-bootstrap-complete", str(marker))
        script = script.replace("/usr/local/sbin/covee-bootstrap", str(self.base / "bootstrap"))
        for failure in ("sysctl --system", "install -d -m 0755 /run/sshd", "sshd -t", "systemctl restart ssh", "bootstrap", "systemctl enable --now qemu-guest-agent", ""):
            with self.subTest(failure=failure):
                marker.touch()  # A retry must remove any previous success marker.
                environment = {**os.environ, "PATH": str(self.base) + os.pathsep + os.environ["PATH"],
                               "COMMAND_LOG": str(log), "FAIL_COMMAND": failure}
                result = subprocess.run([*command[:-1], script], capture_output=True, text=True, env=environment)
                self.assertEqual(result.returncode == 0, not bool(failure), result.stderr)
                self.assertEqual(marker.exists(), not bool(failure))


if __name__ == "__main__":
    unittest.main()
