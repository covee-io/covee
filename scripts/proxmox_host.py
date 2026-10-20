#!/usr/bin/env python3
"""Create a Covee network VM on a Proxmox VE host, for `covee setup`.

Runs on the Proxmox host as root, from the payload `covee setup` copies there.
It applies the same reviewed plan as scripts/proxmox.py: the pinned Ubuntu
image, the hardened cloud-init (covee account, firewall, Docker) and the qm
commands. It never reuses a VM ID or an address that answers, and never
overwrites a cloud-init snippet.

  facts      read-only JSON: node, next free VM ID, storages, bridges, gateway
  create     JSON on stdin; creates and starts one VM; prints JSON
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import proxmox  # noqa: E402

STAGING = Path("/var/lib/vz/covee-bootstrap")
IMAGE_NAME = "ubuntu-24.04-server-cloudimg-amd64.img"


class HostError(RuntimeError):
    pass


def sh(*argv, check=True):
    return subprocess.run([str(a) for a in argv], check=check, capture_output=True, text=True)


def pvesh(path, *extra):
    return json.loads(sh("pvesh", "get", path, "--output-format", "json", *extra).stdout)


def lock():
    return json.loads((proxmox.ASSETS / "image-lock.json").read_text())


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cached_image():
    """An already verified copy of the pinned image from an earlier VM, if any."""
    want = lock()["sha256"]
    for candidate in sorted(STAGING.glob(f"*/{IMAGE_NAME}")):
        if candidate.is_file() and not candidate.is_symlink() and sha256(candidate) == want:
            return candidate
    return None


def used_vmids():
    return {int(item["vmid"]) for item in pvesh("/cluster/resources", "--type", "vm") if "vmid" in item}


def facts():
    node = sh("hostname", "--short").stdout.strip()
    storages = pvesh(f"/nodes/{node}/storage")
    disks = [{"id": s["storage"], "free_gib": int(s.get("avail", 0)) >> 30} for s in storages
             if s.get("active") and "images" in s.get("content", "").split(",")]
    snippets = []
    for s in storages:
        if s.get("active") and "snippets" in s.get("content", "").split(","):
            path = pvesh(f"/storage/{s['storage']}").get("path")
            if path:
                snippets.append({"id": s["storage"], "directory": str(Path(path) / "snippets")})
    bridges = [link["ifname"] for link in json.loads(sh("ip", "-j", "link", "show", "type", "bridge").stdout)]
    route = json.loads(sh("ip", "-j", "route", "show", "default").stdout)
    gateway = route[0].get("gateway") if route else None
    host_cidr = None
    if route:
        for link in json.loads(sh("ip", "-j", "-4", "address", "show", "dev", route[0]["dev"]).stdout):
            for info in link.get("addr_info", []):
                if info.get("family") == "inet":
                    host_cidr = f"{info['local']}/{info['prefixlen']}"
    client = os.environ.get("SSH_CONNECTION", "").split()
    return {"node": node, "next_vmid": int(pvesh("/cluster/nextid")), "used_vmids": sorted(used_vmids()),
            "disk_storages": sorted(disks, key=lambda d: -d["free_gib"]), "snippet_storages": snippets,
            "bridges": bridges, "gateway": gateway, "host_cidr": host_cidr,
            "ssh_client": client[0] if client else None, "cached_image": bool(cached_image()),
            "version": sh("pveversion").stdout.strip()}


def create(request):
    if os.geteuid() != 0:
        raise HostError("run this step as root on the Proxmox host")
    key_text = request.pop("ssh_public_key")
    with tempfile.TemporaryDirectory() as temporary:
        key_file = Path(temporary) / "covee.pub"
        key_file.write_text(proxmox.parse_public_key(key_text) + "\n")
        config = proxmox.validate({**request, "ssh_public_key_file": str(key_file)})
    vmid, address = config["vmid"], config["ipv4"]
    if vmid in used_vmids():
        raise HostError(f"VM ID {vmid} is already in use")
    if sh("ping", "-c", "2", "-W", "1", address, check=False).returncode == 0:
        raise HostError(f"{address} already answers on the network; choose a free address")
    snippet = Path(config["snippet_directory"]) / f"covee-{vmid}.cloud-config.yaml"
    stage = STAGING / str(vmid)
    if snippet.exists() or stage.exists():
        raise HostError(f"files for VM {vmid} already exist ({snippet} or {stage}); investigate before reusing the ID")
    pinned = lock()
    STAGING.mkdir(mode=0o700, parents=True, exist_ok=True)
    stage.mkdir(mode=0o700)
    image = stage / IMAGE_NAME
    source = cached_image()
    if source:
        shutil.copyfile(source, image)
    else:
        sh("curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--tlsv1.2", "--output", image, pinned["url"])
    if sha256(image) != pinned["sha256"]:
        image.unlink()
        raise HostError("the downloaded Ubuntu image does not match its pinned checksum")
    snippet.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(snippet, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write("#cloud-config\n" + json.dumps(proxmox.cloud_config(config), indent=2) + "\n")
    commands = proxmox.commands(config, pinned)
    created = False
    try:
        for argv in commands["create_new_vm_after_checks"]:
            sh(*argv)
            created = True
        dump = sh("qm", "cloudinit", "dump", str(vmid), "network").stdout
        if f"name: {config['network_interface']}" not in dump:
            raise HostError(f"the VM's network interface is not named {config['network_interface']}; it was created but not started")
        sh("qm", "start", str(vmid))
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip().splitlines()[-1:] or [""]
        state = f"VM {vmid} was created but not started; inspect or remove it" if created else "nothing was created"
        raise HostError(f"{' '.join(map(str, error.cmd[:3]))} failed: {detail[0]} ({state})") from error
    return {"vmid": vmid, "name": config["name"], "ipv4": address, "node": config["node"], "image_reused": bool(source)}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("facts", "create"):
        print(__doc__, file=sys.stderr)
        return 2
    try:
        result = facts() if sys.argv[1] == "facts" else create(json.loads(sys.stdin.read()))
    except (HostError, proxmox.PlanError, ValueError) as error:
        print(json.dumps({"error": str(error)}))
        return 1
    except subprocess.CalledProcessError as error:
        print(json.dumps({"error": f"command failed: {' '.join(map(str, error.cmd[:3]))}"}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
