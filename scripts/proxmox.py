#!/usr/bin/env python3
"""Render a private Proxmox pilot bundle; never contact or mutate a hypervisor."""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import struct

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "deploy/proxmox"


class PlanError(ValueError):
    pass


def identifier(value, field, pattern=r"[a-zA-Z][a-zA-Z0-9_.-]{0,62}"):
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise PlanError(f"{field} must be an explicit valid identifier")
    return value


def number(value, field, low, high):
    if type(value) is not int or not low <= value <= high:
        raise PlanError(f"{field} must be an integer in {low}..{high}")
    return value


def public_key(path):
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise PlanError("ssh_public_key_file must be an absolute path to a public key")
    return parse_public_key(Path(path).read_text())


def parse_public_key(text):
    key = text.strip()
    parts = key.split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519" or "\n" in key:
        raise PlanError("Provide exactly one OpenSSH Ed25519 public key, without options")
    try:
        blob = base64.b64decode(parts[1], validate=True)
        size = struct.unpack(">I", blob[:4])[0]
        algorithm = blob[4:4 + size]
        tail = blob[4 + size:]
        valid = algorithm == b"ssh-ed25519" and len(tail) == 36 and tail[:4] == b"\0\0\0 "
    except (ValueError, struct.error):
        valid = False
    if not valid:
        raise PlanError("Invalid Ed25519 public-key encoding")
    return " ".join(parts[:2])


def validate(raw):
    required = set(json.loads((ASSETS / "pilot.example.json").read_text()))
    if not isinstance(raw, dict) or set(raw) != required:
        raise PlanError(f"Configuration keys must be exactly: {', '.join(sorted(required))}")
    result = dict(raw)
    for field in ("node", "name", "disk_storage", "snippet_storage", "bridge"):
        result[field] = identifier(raw[field], field)
    result["network_interface"] = identifier(raw["network_interface"], "network_interface", r"[a-zA-Z][a-zA-Z0-9_.-]{0,14}")
    if result["network_interface"] == "lo":
        raise PlanError("network_interface must be the discovered guest ingress interface, not loopback")
    number(raw["vmid"], "vmid", 100, 999999999)
    number(raw["cores"], "cores", 2, 16)
    number(raw["memory_mib"], "memory_mib", 4096, 65536)
    number(raw["disk_gib"], "disk_gib", 32, 1024)
    if raw["vlan_tag"] is not None:
        number(raw["vlan_tag"], "vlan_tag", 1, 4094)
    snippet = raw["snippet_directory"]
    if (not isinstance(snippet, str) or not snippet.startswith("/") or
            str(PurePosixPath(snippet)) != snippet or ".." in PurePosixPath(snippet).parts or
            not re.fullmatch(r"/[a-zA-Z0-9_./-]+/snippets", snippet)):
        raise PlanError("snippet_directory must be an explicit normalized absolute snippets directory")
    try:
        interface = ipaddress.IPv4Interface(raw["ipv4_cidr"])
        gateway = ipaddress.IPv4Address(raw["gateway_ipv4"])
    except (ValueError, TypeError) as exc:
        raise PlanError("An explicit static IPv4 CIDR and IPv4 gateway are required") from exc
    if interface.network.prefixlen > 30 or interface.ip in (interface.network.network_address, interface.network.broadcast_address):
        raise PlanError("VM address must be a usable host address with a prefix of /30 or wider")
    if gateway not in interface.network or gateway in (interface.ip, interface.network.network_address, interface.network.broadcast_address):
        raise PlanError("Gateway must be a different usable address in the VM subnet")
    result["ipv4_cidr"], result["gateway_ipv4"] = str(interface), str(gateway)
    result["ipv4"] = str(interface.ip)
    for field in ("dns_servers", "ssh_source_cidrs"):
        if not isinstance(raw[field], list) or not 1 <= len(raw[field]) <= 8:
            raise PlanError(f"{field} must contain 1..8 explicit IPv4 entries")
        if any(not isinstance(item, str) for item in raw[field]):
            raise PlanError(f"{field} entries must be strings")
    try:
        result["dns_servers"] = [str(ipaddress.IPv4Address(item)) for item in raw["dns_servers"]]
        cidrs = [ipaddress.IPv4Network(item, strict=True) for item in raw["ssh_source_cidrs"]]
    except (ValueError, TypeError) as exc:
        raise PlanError("Invalid DNS address or non-canonical SSH source CIDR") from exc
    if any(item.prefixlen < 24 or item.network_address.is_multicast or item.network_address.is_unspecified or item.is_loopback for item in cidrs):
        raise PlanError("SSH must be restricted to specific management source networks, /24 or narrower; prefer /32")
    result["ssh_source_cidrs"] = [str(item) for item in cidrs]
    host = raw["control_host"]
    if not isinstance(host, str) or len(host) > 253 or "." not in host or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
        raise PlanError("control_host must be an owned lowercase DNS hostname")
    reserved = ("example.com", "example.net", "example.org", "invalid", "test", "localhost", "local")
    if any(host == suffix or host.endswith("." + suffix) for suffix in reserved):
        raise PlanError("Replace the example control hostname with the actual owned hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise PlanError("control_host must be a DNS hostname, not an IP address")
    result["ssh_public_key"] = public_key(raw["ssh_public_key_file"])
    return result


# The gateway device's own network (deploy/compose.gateway.yaml names its
# bridge). SSH from it lets an admin manage this server through the network
# itself; only the gateway container is on it.
GATEWAY_BRIDGE = "covee-gw0"


def firewall(config):
    # This chain belongs to the new guest only. Never flush Docker-owned chains.
    interface = config["network_interface"]
    lines = ["#!/bin/sh", "set -eu", "IPT=/usr/sbin/iptables", "IP6T=/usr/sbin/ip6tables",
             'case "${1:-}" in docker|verify)',
             f"  /usr/sbin/ip -4 -o address show dev {interface} | grep -F ' inet {config['ipv4_cidr']} ' >/dev/null",
             ";; esac",
             'if [ "${1:-}" = verify ]; then',
             '  test "$($IPT -w -S FORWARD | sed -n \'/^-A /{p;q;}\')" = "-A FORWARD -j DOCKER-USER"',
             "$IPT -w -C DOCKER-USER -j COVEE-DOCKER", "  exit 0", "fi",
             "$IPT -w -P INPUT DROP",
             "$IPT -w -N COVEE-INPUT 2>/dev/null || $IPT -w -S COVEE-INPUT >/dev/null",
             "$IPT -w -F COVEE-INPUT", "$IPT -w -A COVEE-INPUT -i lo -j ACCEPT",
             "$IPT -w -A COVEE-INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
             "$IPT -w -A COVEE-INPUT -p icmp -j ACCEPT"]
    for cidr in config["ssh_source_cidrs"]:
        lines.append(f"$IPT -w -A COVEE-INPUT -i {interface} -s {cidr} -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT")
    lines.append(f"$IPT -w -A COVEE-INPUT -i {GATEWAY_BRIDGE} -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT")
    lines += [f"$IPT -w -A COVEE-INPUT -i {interface} -p tcp --dport 443 -j ACCEPT",
              f"$IPT -w -A COVEE-INPUT -i {interface} -p udp --dport 3478 -j ACCEPT",
              "$IPT -w -A COVEE-INPUT -j DROP",
              "$IPT -w -C INPUT -j COVEE-INPUT 2>/dev/null || $IPT -w -I INPUT 1 -j COVEE-INPUT",
              "$IP6T -w -P INPUT DROP", "$IP6T -w -P FORWARD DROP",
              # Seed the user chain before Docker can restore published ports.
              # Moby preserves pre-existing DOCKER-USER rules across restarts.
              "$IPT -w -N DOCKER-USER 2>/dev/null || $IPT -w -S DOCKER-USER >/dev/null",
              f"$IPT -w -C DOCKER-USER -i {interface} -j DROP 2>/dev/null || $IPT -w -I DOCKER-USER 1 -i {interface} -j DROP",
              "$IPT -w -C FORWARD -j DOCKER-USER 2>/dev/null || $IPT -w -I FORWARD 1 -j DOCKER-USER",
              "$IPT -w -N COVEE-DOCKER 2>/dev/null || $IPT -w -S COVEE-DOCKER >/dev/null",
              "$IPT -w -F COVEE-DOCKER",
              "$IPT -w -A COVEE-DOCKER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"]
    for protocol, port in (("tcp", 443), ("udp", 3478)):
        lines.append(f"$IPT -w -A COVEE-DOCKER -i {interface} -p {protocol} -m conntrack --ctdir ORIGINAL --ctorigdst {config['ipv4']} --ctorigdstport {port} -j RETURN")
    lines += [f"$IPT -w -A COVEE-DOCKER -i {interface} -j DROP",
              "$IPT -w -A COVEE-DOCKER -j RETURN",
              "$IPT -w -C DOCKER-USER -j COVEE-DOCKER 2>/dev/null || $IPT -w -I DOCKER-USER 1 -j COVEE-DOCKER",
              f"$IPT -w -D DOCKER-USER -i {interface} -j DROP"]
    return "\n".join(lines) + "\n"


GUEST_PACKAGES = ["ca-certificates", "curl", "gnupg", "iptables", "iproute2", "openssl", "python3", "qemu-guest-agent", "unattended-upgrades", "age"]


def guest_files(config):
    files = {
        "/etc/ssh/sshd_config.d/00-covee.conf": ("0600", "PermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthenticationMethods publickey\nAllowUsers covee\nX11Forwarding no\nAllowAgentForwarding no\nAllowTcpForwarding local\nGatewayPorts no\n"),
        "/etc/sysctl.d/60-covee.conf": ("0644", "net.ipv6.conf.all.disable_ipv6=1\nnet.ipv6.conf.default.disable_ipv6=1\nnet.ipv4.conf.all.accept_redirects=0\nnet.ipv4.conf.default.accept_redirects=0\nnet.ipv4.conf.all.send_redirects=0\nnet.ipv4.conf.default.send_redirects=0\nnet.ipv4.conf.all.accept_source_route=0\nnet.ipv4.conf.default.accept_source_route=0\n"),
        "/usr/local/sbin/covee-guest-firewall": ("0700", firewall(config)),
        "/usr/local/sbin/covee-bootstrap": ("0700", (ASSETS / "bootstrap-guest.sh").read_text()),
        "/etc/systemd/system/covee-guest-firewall.service": ("0644", "[Unit]\nDescription=Restricted Covee guest ingress\nDefaultDependencies=no\nAfter=local-fs.target systemd-modules-load.service\nBefore=network-pre.target ssh.service ssh.socket docker.service docker.socket shutdown.target\nWants=network-pre.target\nConflicts=shutdown.target\n\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/covee-guest-firewall\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n"),
        "/etc/apt/apt.conf.d/52covee-unattended": ("0644", 'Unattended-Upgrade::Automatic-Reboot "false";\nAPT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'),
    }
    for unit in ("systemd-networkd.service", "ssh.service", "ssh.socket"):
        files[f"/etc/systemd/system/{unit}.d/covee-firewall.conf"] = (
            "0644", "[Unit]\nRequires=covee-guest-firewall.service\nAfter=covee-guest-firewall.service\n")
    return files


def guest_initialize(*, guest_agent=True):
    """Ordered root commands that apply guest_files; the marker is written last."""
    initialize = [
        ["rm", "-f", "/var/lib/covee-bootstrap-complete"],
        ["sysctl", "--system"], ["systemctl", "daemon-reload"],
        ["systemctl", "enable", "--now", "covee-guest-firewall.service"],
        ["install", "-d", "-m", "0755", "/run/sshd"],
        ["sshd", "-t"], ["systemctl", "restart", "ssh"],
        ["/usr/local/sbin/covee-bootstrap"],
    ]
    if guest_agent:
        initialize.append(["systemctl", "enable", "--now", "qemu-guest-agent"])
    return initialize + [["touch", "/var/lib/covee-bootstrap-complete"]]


def cloud_config(config):
    files = guest_files(config)
    initialize = guest_initialize()
    return {
        "hostname": config["name"], "manage_etc_hosts": True, "disable_root": True,
        "ssh_pwauth": False, "ssh_deletekeys": True, "groups": ["docker", "covee"],
        "users": [{"name": "covee", "uid": 10001, "primary_group": "covee", "groups": ["sudo", "docker"], "shell": "/bin/bash", "lock_passwd": True,
                   "sudo": ["ALL=(ALL) NOPASSWD:ALL"], "ssh_authorized_keys": [config["ssh_public_key"]]}],
        "package_update": True, "package_upgrade": True,
        "packages": GUEST_PACKAGES,
        "write_files": [{"path": path, "owner": "root:root", "permissions": mode, "content": content} for path, (mode, content) in files.items()],
        # Cloud-init's generated runcmd script does not itself use `set -e`.
        # One fail-fast child owns the completion marker for all initialization.
        "runcmd": [["/bin/sh", "-eu", "-c", "\n".join(shlex.join(argv) for argv in initialize)]],
    }


def commands(config, lock):
    vmid = str(config["vmid"])
    stage = f"/var/lib/vz/covee-bootstrap/{vmid}"
    image = f"{stage}/ubuntu-24.04-server-cloudimg-amd64.img"
    snippet = f"{config['snippet_directory']}/covee-{vmid}.cloud-config.yaml"
    network = f"virtio,bridge={config['bridge']}"
    if config["vlan_tag"] is not None:
        network += f",tag={config['vlan_tag']}"
    return {
        "read_only_preflight": [["hostname", "--short"], ["pveversion", "--verbose"], ["pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json"], ["pvesh", "get", f"/storage/{config['disk_storage']}", "--output-format", "json"], ["pvesh", "get", f"/storage/{config['snippet_storage']}", "--output-format", "json"], ["pvesm", "status"], ["ip", "-json", "link", "show", config["bridge"]]],
        "download_into_new_staging_directory": [["mkdir", "-m", "0700", stage], ["curl", "--fail", "--location", "--proto", "=https", "--tlsv1.2", "--output", image, lock["url"]], ["sha256sum", "--check", "--strict", f"{stage}/cloud-image.sha256"]],
        "create_new_vm_after_checks": [["qm", "create", vmid, "--name", config["name"], "--ostype", "l26", "--cores", str(config["cores"]), "--memory", str(config["memory_mib"]), "--balloon", "0", "--cpu", "host", "--net0", network, "--scsihw", "virtio-scsi-pci", "--agent", "enabled=1", "--onboot", "0"], ["qm", "set", vmid, "--scsi0", f"{config['disk_storage']}:0,import-from={image},discard=on,ssd=1"], ["qm", "resize", vmid, "scsi0", f"{config['disk_gib']}G"], ["qm", "set", vmid, "--ide2", f"{config['disk_storage']}:cloudinit", "--boot", "order=scsi0", "--serial0", "socket", "--vga", "serial0", "--ipconfig0", f"ip={config['ipv4_cidr']},gw={config['gateway_ipv4']}", "--nameserver", " ".join(config["dns_servers"]), "--cicustom", f"user={config['snippet_storage']}:snippets/covee-{vmid}.cloud-config.yaml"], ["qm", "cloudinit", "dump", vmid, "network"], ["qm", "config", vmid]],
        "first_boot_after_review": [["qm", "start", vmid], ["qm", "terminal", vmid]],
        "required_new_snippet_file": snippet,
        "required_image_sha256": lock["sha256"],
    }


def render(raw, directory):
    config = validate(raw)
    lock = json.loads((ASSETS / "image-lock.json").read_text())
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    plan = {"status": "prepared-not-applied", "hypervisor_node": config["node"], "vmid": config["vmid"], "control_host": config["control_host"], "guest_ipv4": config["ipv4"], "guest_interface": config["network_interface"], "image": lock, "commands": commands(config, lock)}
    try:
        image_path = f"/var/lib/vz/covee-bootstrap/{config['vmid']}/ubuntu-24.04-server-cloudimg-amd64.img"
        outputs = {"cloud-config.yaml": "#cloud-config\n" + json.dumps(cloud_config(config), indent=2) + "\n", "plan.json": json.dumps(plan, indent=2) + "\n", "cloud-image.sha256": f"{lock['sha256']}  {image_path}\n"}
        text = ["# Proxmox pilot plan — prepared, not applied", "", f"Run the reviewed commands on node **{config['node']}** only. New VM ID: **{config['vmid']}**. No existing VM may use this ID anywhere in the cluster.", "", "Before mutations: verify node, unused cluster-wide VM ID, writable local/block disk storage, snippet-capable storage with the exact configured directory, bridge/VLAN, free disk/RAM, unused IPv4 and recovery console. Stop if any preflight command fails. Do not add or enable Proxmox host firewall rules.", "", "Copy the cloud config into the required NEW snippet path with a no-overwrite operation; verify `pvesm path STORAGE:snippets/FILE` resolves to that path. Create the staging parent separately if needed. Never overwrite a snippet or reuse a failed partial VM without investigating it.", "", "After creating the new staging directory and before its checksum command, copy `cloud-image.sha256` into that directory. Require checksum success before any `qm create` or disk import.", "", f"Before first boot, require the generated `qm cloudinit dump {config['vmid']} network` physical interface name to equal **{config['network_interface']}**. Stop and correct the prepared input/snippet if it differs. The firewall uses this explicit name; it does not infer it from the host bridge or a default route.", ""]
        for phase, values in plan["commands"].items():
            if not isinstance(values, list):
                continue
            text += [f"## {phase.replace('_', ' ')}", "", "```sh"]
            text.extend(shlex.join(argv) for argv in values)
            text += ["```", ""]
        text += [f"New snippet path: `{plan['commands']['required_new_snippet_file']}`", "", "Guest cloud-init installs current signed packages and security updates. Verify its completion marker and package receipt; review and reboot the guest for kernel updates before exposing it. IPv6 is intentionally disabled inside this single-interface pilot. Public DNS must have no AAAA record pointing here. Do not expose the guest until these controls and live port tests pass.", ""]
        outputs["plan.md"] = "\n".join(text)
        for name, content in outputs.items():
            fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(content)
    except Exception:
        # No remote side effects; leave partial private output for inspection.
        raise
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["plan"])
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    try:
        render(json.loads(args.config.read_text()), args.directory)
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Proxmox plan failed: {exc}\n")
    print(f"Prepared local plan in {args.directory}; no remote actions performed.")


if __name__ == "__main__":
    main()
