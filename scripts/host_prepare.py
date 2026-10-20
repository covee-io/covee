#!/usr/bin/env python3
"""Prepare a fresh, dedicated Ubuntu 24.04 server for Covee over SSH.

`covee setup` runs this on the server. It applies the same hardened files and
steps that cloud-init applies to a new Proxmox pilot VM (scripts/proxmox.py):
a `covee` service account, a restrictive firewall, SSH limited to that
account, Docker, and the /srv/covee and /opt/covee directories.

  facts                 read-only JSON about the server, any user
  verify-payload DIR    check an unpacked payload against its manifest
  account               root: create the covee account; JSON on stdin
  system                root: harden and install; JSON on stdin
  firewall              root: rewrite and apply only the firewall; JSON on stdin
"""
import hashlib
import ipaddress
import json
import os
import platform
import pwd
import grp
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))
import proxmox  # noqa: E402

SERVICE_USER, SERVICE_ID = "covee", 10001
MARKER = Path("/var/lib/covee-bootstrap-complete")
APPLIED = Path("/var/lib/covee-host-config.sha256")


class HostError(RuntimeError):
    pass


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


def os_release():
    values = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        key, _, value = line.partition("=")
        values[key] = value.strip().strip('"')
    return values


def architecture():
    try:
        return subprocess.run(["dpkg", "--print-architecture"], check=True, capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return platform.machine()


def ip_json(*args):
    return json.loads(subprocess.run(["ip", "-j", *args], check=True, capture_output=True, text=True).stdout)


def public_ipv4():
    try:
        with urlopen("https://checkip.amazonaws.com", timeout=10) as response:
            value = response.read(64).decode().strip()
        address = ipaddress.IPv4Address(value)
        return str(address) if address.is_global else None
    except (OSError, ValueError):
        return None


def facts():
    release = os_release()
    route = ip_json("route", "get", "1.1.1.1")[0]
    interface = route["dev"]
    cidr, dynamic = None, None
    for link in ip_json("-4", "address", "show", "dev", interface):
        for info in link.get("addr_info", []):
            if info.get("family") == "inet" and info.get("local") == route.get("prefsrc"):
                cidr = f"{info['local']}/{info['prefixlen']}"
                dynamic = bool(info.get("dynamic"))
    client = os.environ.get("SSH_CONNECTION", "").split()
    try:
        virt = subprocess.run(["systemd-detect-virt"], capture_output=True, text=True).stdout.strip() or "none"
    except OSError:
        virt = "unknown"
    try:
        pwd.getpwnam(SERVICE_USER)
        service_user = True
    except KeyError:
        service_user = False
    sudo = os.geteuid() == 0 or subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0
    return {
        "os": release.get("ID"), "codename": release.get("VERSION_CODENAME"), "pretty": release.get("PRETTY_NAME"),
        "architecture": architecture(), "hostname": platform.node(),
        "interface": interface, "ipv4_cidr": cidr, "dhcp": dynamic, "gateway": route.get("gateway"),
        "ssh_client": client[0] if client else None, "virtualization": virt,
        "public_ipv4": public_ipv4(), "service_user": service_user,
        "prepared": MARKER.exists(), "docker": shutil.which("docker") is not None, "passwordless_sudo": sudo,
    }


def verify_payload(directory):
    directory = Path(directory)
    manifest = json.loads((directory / "PAYLOAD-MANIFEST.json").read_text())
    found = set()
    for path in directory.rglob("*"):
        relative = path.relative_to(directory).as_posix()
        if relative == "PAYLOAD-MANIFEST.json" or relative.startswith(".cache/") or relative == ".cache" or "__pycache__" in path.parts:
            continue
        if path.is_symlink():
            raise HostError(f"unexpected symlink in payload: {relative}")
        if path.is_file():
            found.add(relative)
    if found != set(manifest):
        raise HostError("payload files differ from its manifest")
    for relative, digest in manifest.items():
        if hashlib.sha256((directory / relative).read_bytes()).hexdigest() != digest:
            raise HostError(f"payload file changed: {relative}")
    return len(manifest)


def require_root():
    if os.geteuid() != 0:
        raise HostError("run this step as root")


def require_supported():
    release = os_release()
    if release.get("ID") != "ubuntu" or release.get("VERSION_CODENAME") != "noble" or architecture() != "amd64":
        raise HostError("Covee setup currently supports Ubuntu 24.04 (noble) on amd64 servers")


def account(config):
    require_root()
    require_supported()
    key = proxmox.parse_public_key(config["ssh_public_key"])
    try:
        group = grp.getgrnam(SERVICE_USER)
        if group.gr_gid != SERVICE_ID:
            raise HostError(f"group {SERVICE_USER} exists with GID {group.gr_gid}, not {SERVICE_ID}")
    except KeyError:
        run(["groupadd", "--gid", str(SERVICE_ID), SERVICE_USER])
    run(["groupadd", "--force", "--system", "docker"])
    try:
        user = pwd.getpwnam(SERVICE_USER)
        if user.pw_uid != SERVICE_ID:
            raise HostError(f"user {SERVICE_USER} exists with UID {user.pw_uid}, not {SERVICE_ID}")
        run(["usermod", "--append", "--groups", "sudo,docker", SERVICE_USER])
    except KeyError:
        run(["useradd", "--uid", str(SERVICE_ID), "--gid", SERVICE_USER, "--groups", "sudo,docker",
             "--create-home", "--shell", "/bin/bash", SERVICE_USER])
    run(["passwd", "--lock", SERVICE_USER], stdout=subprocess.DEVNULL)
    home = Path(pwd.getpwnam(SERVICE_USER).pw_dir)
    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(mode=0o700, exist_ok=True)
    os.chown(ssh_dir, SERVICE_ID, SERVICE_ID)
    ssh_dir.chmod(0o700)
    write(ssh_dir / "authorized_keys", key + "\n", 0o600, owner=(SERVICE_ID, SERVICE_ID))
    # The same passwordless sudo the Proxmox pilot's cloud-init grants.
    sudoers = "covee ALL=(ALL) NOPASSWD:ALL\n"
    with tempfile.NamedTemporaryFile("w", dir="/etc/sudoers.d", delete=False) as handle:
        handle.write(sudoers)
    os.chmod(handle.name, 0o440)
    try:
        run(["visudo", "-cf", handle.name], stdout=subprocess.DEVNULL)
        os.replace(handle.name, "/etc/sudoers.d/90-covee")
    finally:
        if os.path.exists(handle.name):
            os.unlink(handle.name)
    return {"service_user": SERVICE_USER, "uid": SERVICE_ID}


def write(path, content, mode, owner=(0, 0)):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".covee-")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
        os.chown(temporary, *owner)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def guest_config(raw):
    interface = raw.get("network_interface")
    if not isinstance(interface, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,14}", interface) or interface == "lo":
        raise HostError("network_interface must be the server's ingress interface")
    try:
        address = ipaddress.IPv4Interface(raw["ipv4_cidr"])
        sources = [ipaddress.IPv4Network(item, strict=True) for item in raw["ssh_source_cidrs"]]
    except (KeyError, TypeError, ValueError) as error:
        raise HostError("explicit IPv4 address and SSH source networks are required") from error
    if not 1 <= len(sources) <= 8 or any(item.prefixlen < 24 for item in sources):
        raise HostError("SSH must be limited to 1..8 specific networks, /24 or narrower")
    present = any(info.get("local") == str(address.ip) and info.get("prefixlen") == address.network.prefixlen
                  for link in ip_json("-4", "address", "show", "dev", interface) for info in link.get("addr_info", []))
    if not present:
        raise HostError(f"{interface} does not have the address {address}")
    return {"name": platform.node(), "network_interface": interface, "ipv4_cidr": str(address), "ipv4": str(address.ip),
            "ssh_source_cidrs": [str(item) for item in sources], "ssh_public_key": proxmox.parse_public_key(raw["ssh_public_key"]),
            "control_host": raw["control_host"]}


FIREWALL_FILE = "/usr/local/sbin/covee-guest-firewall"
FIREWALL = FIREWALL_FILE  # where it is written; tests point it elsewhere


def firewall(raw):
    """Rewrite and apply only the firewall, so a prepared server gets the
    rules of newer Covee files without being prepared again."""
    require_root()
    config = guest_config(raw)
    mode, content = proxmox.guest_files(config)[FIREWALL_FILE]
    path = Path(FIREWALL)
    if path.is_file() and path.read_text() == content:
        return {"firewall": "current", "changed": False}
    write(path, content, int(mode, 8))
    run([FIREWALL])
    run([FIREWALL, "verify"])
    return {"firewall": "applied", "changed": True}


def system(raw):
    require_root()
    require_supported()
    config = guest_config(raw)
    # The firewall's rules are part of what is applied, so newer rules count as a change.
    digest = hashlib.sha256((json.dumps(config, sort_keys=True) + proxmox.firewall(config)).encode()).hexdigest()
    if MARKER.exists() and APPLIED.exists() and APPLIED.read_text().strip() == digest:
        print("This server is already prepared with these settings.", flush=True)
        return {"prepared": True, "changed": False}
    virt = subprocess.run(["systemd-detect-virt"], capture_output=True, text=True).stdout.strip()
    guest_agent = virt in ("kvm", "qemu")
    packages = [p for p in proxmox.GUEST_PACKAGES if guest_agent or p != "qemu-guest-agent"]
    # needrestart must only list services, never prompt or restart them mid-setup.
    environment = {**os.environ, "DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "l"}
    print("Installing security updates and required packages...", flush=True)
    run(["apt-get", "update"], env=environment)
    run(["apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "upgrade"], env=environment)
    run(["apt-get", "-y", "install", *packages], env=environment)
    print("Writing the firewall, SSH and Docker settings...", flush=True)
    for path, (mode, content) in proxmox.guest_files(config).items():
        write(path, content, int(mode, 8))
    print("Applying them and installing Docker...", flush=True)
    for argv in proxmox.guest_initialize(guest_agent=guest_agent):
        run(argv, env=environment)
    write(APPLIED, digest + "\n", 0o600)
    return {"prepared": True, "changed": True}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("facts", "verify-payload", "account", "system", "firewall"):
        print(__doc__, file=sys.stderr)
        return 2
    command = sys.argv[1]
    try:
        if command == "facts":
            result = facts()
        elif command == "verify-payload":
            if len(sys.argv) != 3:
                raise HostError("verify-payload needs the payload directory")
            result = {"files": verify_payload(sys.argv[2])}
        else:
            raw = json.loads(sys.stdin.read())
            result = {"account": account, "system": system, "firewall": firewall}[command](raw)
    except (HostError, proxmox.PlanError) as error:
        print(json.dumps({"error": str(error)}))
        return 1
    except subprocess.CalledProcessError as error:
        print(json.dumps({"error": f"command failed with status {error.returncode}: {' '.join(map(str, error.cmd))}"}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
