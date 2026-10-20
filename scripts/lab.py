#!/usr/bin/env python3
"""Manage only the isolated covee-lab Compose project (Python 3.10+)."""

import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "--project-name", "covee-lab", "--file", str(ROOT / "lab/compose.yaml")]
SECRETS = set()
HEADSCALE_BINARY = None
RESULT = ROOT / ".cache/covee/lab/results.json"
TLS_DIR = ROOT / ".cache/covee/lab-tls"


class LabError(RuntimeError):
    pass


def redact(value):
    value = str(value)
    for secret in SECRETS:
        value = value.replace(secret, "[REDACTED]")
    return re.sub(r"(?:hskey|tskey)-[A-Za-z0-9_-]+", "[REDACTED]", value)


def log(message):
    print(redact(message), flush=True)


def run(arguments, *, stdin=None, timeout=40, check=True):
    try:
        result = subprocess.run(arguments, input=stdin, text=True, capture_output=True, timeout=timeout)
    except FileNotFoundError as error:
        raise LabError(f"Required executable is missing: {arguments[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise LabError(f"Command timed out after {timeout}s: {redact(' '.join(arguments))}") from error
    if check and result.returncode:
        detail = redact((result.stderr + "\n" + result.stdout).strip())[-4000:]
        raise LabError(f"Command failed ({result.returncode}): {redact(' '.join(arguments))}\n{detail}")
    return result


def compose(*arguments, **kwargs):
    return run(COMPOSE + list(arguments), **kwargs)


def execute(service, *arguments, **kwargs):
    return compose("exec", "-T", service, *arguments, **kwargs)


def parse_json(value, context):
    try:
        return json.loads(value)
    except json.JSONDecodeError as error:
        # Never echo malformed CLI output: it can contain generated credentials.
        raise LabError(f"Invalid JSON from {context}") from error


def headscale(*arguments):
    result = control(*arguments, "--output", "json")
    return parse_json(result.stdout, "Headscale " + arguments[0])


def control(*arguments, **kwargs):
    global HEADSCALE_BINARY
    if HEADSCALE_BINARY is None:
        container = compose("ps", "--quiet", "headscale").stdout.strip()
        if not container:
            raise LabError("Headscale container is not running")
        # ko-built images use a hashed /ko-app executable path. Avoid assuming
        # a shell or a headscale executable on PATH in the distroless image.
        HEADSCALE_BINARY = run(["docker", "inspect", "--format", "{{.Path}}", container]).stdout.strip()
        if not HEADSCALE_BINARY.startswith("/") or "headscale" not in Path(HEADSCALE_BINARY).name:
            raise LabError("Unexpected Headscale container entrypoint")
    return execute("headscale", HEADSCALE_BINARY, *arguments, **kwargs)


def wait_for(description, operation, *, timeout=45):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            result = operation()
            if result:
                return result
        except LabError as error:
            last_error = error
        time.sleep(1)
    detail = f": {last_error}" if last_error else ""
    raise LabError(f"Timed out waiting for {description}{detail}")


def prerequisite():
    run(["docker", "compose", "version"], timeout=15)
    run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=15)
    compose("config", "--quiet", timeout=15)


def ensure_tls():
    """Create disposable lab trust without changing host trust or disabling TLS."""
    run(["openssl", "version"], timeout=10)
    TLS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    TLS_DIR.chmod(0o700)
    required = [TLS_DIR / name for name in ("ca.crt", "ca.key", "server.crt", "server.key")]
    if any(path.exists() for path in required):
        if not all(path.is_file() for path in required):
            raise LabError("Incomplete .cache/covee/lab-tls; run down --purge to reset this disposable lab")
        for name in ("ca.crt", "server.crt"):
            valid = run(["openssl", "x509", "-checkend", "3600", "-noout", "-in", str(TLS_DIR / name)], check=False)
            if valid.returncode:
                raise LabError("Lab TLS certificate expires within one hour; run down --purge, then check")
        return
    log("Creating a seven-day lab CA and headscale TLS certificate in .cache/covee/lab-tls.")
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "7",
         "-subj", "/CN=Covee Lab CA", "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(TLS_DIR / "ca.key"),
         "-out", str(TLS_DIR / "ca.crt")])
    for name in ("ca.key",):
        (TLS_DIR / name).chmod(0o600)
    run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=headscale",
         "-keyout", str(TLS_DIR / "server.key"), "-out", str(TLS_DIR / "server.csr")])
    (TLS_DIR / "server.key").chmod(0o600)
    extensions = TLS_DIR / "server-extensions.cnf"
    extensions.write_text("subjectAltName=DNS:headscale\nbasicConstraints=critical,CA:FALSE\n"
                          "keyUsage=critical,digitalSignature,keyEncipherment\n"
                          "extendedKeyUsage=serverAuth\n", encoding="utf-8")
    run(["openssl", "x509", "-req", "-in", str(TLS_DIR / "server.csr"), "-CA", str(TLS_DIR / "ca.crt"),
         "-CAkey", str(TLS_DIR / "ca.key"), "-CAcreateserial", "-days", "7", "-sha256", "-extfile", str(extensions),
         "-out", str(TLS_DIR / "server.crt")])
    run(["openssl", "verify", "-CAfile", str(TLS_DIR / "ca.crt"), "-verify_hostname", "headscale", str(TLS_DIR / "server.crt")])


def remove_lab_tls():
    # Delete known artifacts only, never recursively traverse an arbitrary path.
    for name in ("ca.crt", "ca.key", "ca.srl", "server.crt", "server.key", "server.csr", "server-extensions.cnf"):
        (TLS_DIR / name).unlink(missing_ok=True)
    if TLS_DIR.exists():
        TLS_DIR.rmdir()


def node_name(index):
    return f"lab-node{index}"


def user_name(index):
    return f"lab-user{index}"


def node_by_name(nodes, name):
    return next((node for node in nodes if node.get("given_name") == name or node.get("name") == name), None)


def ipv4(node):
    for address in node.get("ip_addresses", []):
        if ipaddress.ip_address(address).version == 4:
            return address
    raise LabError("Registered node has no IPv4 overlay address")


def has_direct_pong(output):
    for line in output.splitlines():
        match = re.match(r"^pong from .+ via (\S+) in \S+$", line)
        if not match:
            continue
        host, separator, port = match.group(1).rpartition(":")
        try:
            ipaddress.ip_address(host.strip("[]"))
            if separator and 0 < int(port) <= 65535:
                return True
        except ValueError:
            continue
    return False


def bootstrap():
    # Go's JSON encoder may emit null for a nil empty list; that is ready too.
    wait_for("Headscale admin socket", lambda: headscale("users", "list") or True)
    users = {user["name"]: user for user in (headscale("users", "list") or [])}
    nodes = headscale("nodes", "list") or []
    for index in range(1, 9):
        name = user_name(index)
        if name not in users:
            users[name] = headscale("users", "create", name)
        wait_for(f"node{index} daemon", lambda: execute(f"node{index}", "tailscale", "status", "--json").returncode == 0)
        arguments = ["up", "--login-server=https://headscale:8080", "--accept-dns=false", "--accept-routes=false",
                     f"--hostname={node_name(index)}", "--timeout=30s"]
        if node_by_name(nodes, node_name(index)) is None:
            key = headscale("preauthkeys", "create", "--user", str(users[name]["id"]), "--expiration", "10m")
            secret = key.get("key")
            if not isinstance(secret, str) or not secret:
                raise LabError("Headscale returned no pre-auth key")
            SECRETS.add(secret)
            arguments += ["--force-reauth", "--auth-key=" + secret]
        execute(f"node{index}", "tailscale", *arguments, timeout=40)
        log(f"Registered {node_name(index)} as {name}")

    def all_registered():
        current = headscale("nodes", "list")
        for index in range(1, 9):
            node = node_by_name(current, node_name(index))
            if node is None or str(node.get("user", {}).get("id")) != str(users[user_name(index)]["id"]):
                return False
        return current

    return wait_for("eight nodes under eight distinct user identities", all_registered)


def up():
    prerequisite()
    ensure_tls()
    log("Starting isolated covee-lab containers; first run may download pinned images.")
    compose("up", "--detach", timeout=600)
    return bootstrap()


def set_policy(ports):
    policy = {"acls": [{"action": "accept", "src": ["*"], "dst": [f"*:{port}" for port in ports]}]}
    control("policy", "set", "--file", "/dev/stdin", stdin=json.dumps(policy))


def parse_probe(result):
    value = parse_json(result.stdout, "overlay HTTP probe")
    if not isinstance(value, dict):
        raise LabError("Overlay probe returned a non-object")
    if result.returncode == 0 and value.get("status") == "ok":
        return value
    connection_denied = (value.get("failure_kind") == "socks-connect-rejected"
                         and type(value.get("socks_reply")) is int and 1 <= value["socks_reply"] <= 6)
    if result.returncode == 2 and value.get("status") == "blocked" and value.get("phase") == "overlay-connect" and connection_denied:
        return value
    raise LabError(f"Overlay probe failed: {redact(json.dumps(value))}; {redact(result.stderr)}")


def fetch(address, port, hostname, *, proxy="node1"):
    result = execute("probe", "python3", "/lab/probe.py", "fetch", proxy, address, str(port), hostname, check=False, timeout=15)
    return parse_probe(result)


def expect_payload(address, port, hostname, *, proxy="node1"):
    value = fetch(address, port, hostname, proxy=proxy)
    return value if value["status"] == "ok" else False


def write_result(value):
    RESULT.parent.mkdir(parents=True, exist_ok=True)
    RESULT.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def daemon_status(service):
    status = parse_json(execute(service, "tailscale", "status", "--json").stdout, f"{service} status")
    if not isinstance(status, dict) or not isinstance(status.get("BackendState"), str):
        raise LabError(f"{service} returned no backend state")
    return status


def needs_login(service):
    status = daemon_status(service)
    if status["BackendState"] != "NeedsLogin":
        return False
    # A deleted node can receive a minimal expired self node with no stable ID.
    # Save only these observations, never the whole status or key material.
    own_node = status.get("Self")
    return {"backend_state": status["BackendState"],
            "self_id_present": bool(isinstance(own_node, dict) and own_node.get("ID"))}


def check_revocation(nodes, destination, hostname, report):
    log("Verifying a fresh node8 HTTP connection before deleting its identity.")
    revoked = node_by_name(nodes, node_name(8))
    if revoked is None:
        raise LabError("Node8 is missing before the revocation check")
    revoked_ip = ipv4(revoked)
    evidence = {"status": "running", "node": node_name(8), "source_overlay_ip": revoked_ip,
                "destination": destination, "port": 8080, "established_session_behavior": "not_tested"}
    report["checks"]["revocation"] = evidence
    write_result(report)
    evidence["before_delete_payload"] = wait_for("node8 HTTP payload before deletion", lambda: expect_payload(
        destination, 8080, hostname, proxy="node8"))
    write_result(report)
    for service in ("node1", "node2"):
        wait_for(f"node8 initially visible to {service}", lambda service=service: peer_present(revoked_ip, service=service))

    headscale("nodes", "delete", "--identifier", str(revoked["id"]), "--force")
    evidence["delete_requested_at"] = datetime.now(timezone.utc).isoformat()
    write_result(report)
    wait_for("node8 removed from control inventory", lambda: node_by_name(headscale("nodes", "list") or [], node_name(8)) is None)
    evidence["control_inventory_removed"] = True
    write_result(report)
    for service in ("node1", "node2"):
        wait_for(f"node8 withdrawn from {service} peer map", lambda service=service: not peer_present(revoked_ip, service=service))
        evidence.setdefault("peer_maps_removed", []).append(service)
        write_result(report)
    evidence["revoked_client_state"] = wait_for("deleted node8 to enter NeedsLogin", lambda: needs_login("node8"))
    write_result(report)

    def denied():
        value = fetch(destination, 8080, hostname, proxy="node8")
        return value if value["status"] == "blocked" else False

    evidence["fresh_connection_denial"] = wait_for("fresh node8 TCP dial to fail after deletion", denied)
    write_result(report)
    # SOCKS reply 1 describes any failed dial, not its authorization reason.
    # Require the destination to remain healthy through another registered peer.
    evidence["surviving_peer_payload"] = wait_for("node1 HTTP payload after node8 deletion", lambda: expect_payload(
        destination, 8080, hostname))
    evidence["fresh_connection_denied"] = True
    evidence["status"] = "passed"
    write_result(report)


def check():
    report = {"status": "running", "started_at": datetime.now(timezone.utc).isoformat(), "checks": {},
              "scope": "Headscale compatibility lab using upstream Tailscale Linux userspace clients"}
    write_result(report)
    policy_changed = False
    try:
        nodes = up()
        report["checks"]["registration"] = {"users": 8, "nodes": 8, "distinct_user_ownership": True}
        write_result(report)
        report["versions"] = {
            "headscale": control("version").stdout.strip(),
            "tailscale": execute("node1", "tailscale", "version").stdout.strip(),
        }
        report["images"] = parse_json(compose("images", "--format", "json").stdout, "Compose images")
        report["tls"] = {"control": "https://headscale:8080", "trust": "generated seven-day lab CA via SSL_CERT_FILE",
                         "certificate_verification": True, "embedded_derp_stun": True}
        write_result(report)
        destination = ipv4(node_by_name(nodes, node_name(2)))
        log("Verifying a direct peer path and TSMP through WireGuard.")
        direct = execute("node1", "tailscale", "ping", "--until-direct=true", "--c=5", "--timeout=3s", destination)
        if not has_direct_pong(direct.stdout):
            raise LabError("Discovery ping CLI returned no pong via a direct UDP endpoint")
        report["checks"]["direct"] = direct.stdout.strip()
        write_result(report)
        tsmp = execute("node1", "tailscale", "ping", "--tsmp", "--c=3", "--timeout=3s", destination)
        if "pong from" not in tsmp.stdout:
            raise LabError("TSMP ping CLI returned no peer pong")
        report["checks"]["tsmp"] = tsmp.stdout.strip()
        write_result(report)

        log("Verifying overlay HTTP payload on two allowed ports.")
        destination_status = parse_json(execute("node2", "tailscale", "status", "--json").stdout, "node2 status")
        destination_hostname = destination_status.get("Self", {}).get("DNSName", "").rstrip(".")
        if not destination_hostname:
            raise LabError("Node2 status has no DNSName for the Serve HTTP Host header")
        set_policy([8080, 8081])
        policy_changed = True
        for port in (8080, 8081):
            execute("node2", "tailscale", "serve", "--bg", "--yes", f"--http={port}", "http://127.0.0.1:8000")
            wait_for(f"HTTP payload on overlay port {port}", lambda port=port: expect_payload(destination, port, destination_hostname))
            report["checks"][f"http_{port}"] = {"status": "passed", "destination": destination, "port": port,
                                               "payload": "covee-overlay-proof-v1"}
            write_result(report)
        report["checks"]["http"] = {"source": "node1 SOCKS5 userspace overlay", "destination": destination,
                                   "http_hostname": destination_hostname,
                                   "ports": [8080, 8081], "payload": "covee-overlay-proof-v1"}

        log("Verifying forced DERP relay with node3's UDP sockets disabled.")
        relay = execute("node3", "tailscale", "ping", "--until-direct=false", "--c=1", "--timeout=5s", destination)
        if "pong from" not in relay.stdout or "via DERP(lab)" not in relay.stdout:
            raise LabError("Node3 did not report the expected DERP(lab) relay path")
        report["checks"]["relay_discovery"] = relay.stdout.strip()
        write_result(report)
        relay_tsmp = execute("node3", "tailscale", "ping", "--tsmp", "--c=3", "--timeout=3s", destination)
        if "pong from" not in relay_tsmp.stdout:
            raise LabError("Node3 relay TSMP returned no pong")
        report["checks"]["relay_tsmp"] = relay_tsmp.stdout.strip()
        write_result(report)
        relay_payload = wait_for("HTTP payload over forced DERP", lambda: expect_payload(destination, 8080, destination_hostname, proxy="node3"))
        report["checks"]["relay_http"] = {"source": "node3", "udp_disabled": True, "relay": "DERP(lab)",
                                         "payload_evidence": relay_payload}
        write_result(report)

        log("Denying overlay port 8081 while keeping 8080 reachable.")
        set_policy([8080])
        blocked = wait_for("policy to deny port 8081", lambda: (value if (value := fetch(destination, 8081, destination_hostname))["status"] == "blocked" else False))
        wait_for("allowed port 8080 after policy change", lambda: expect_payload(destination, 8080, destination_hostname))
        set_policy([8080, 8081])
        wait_for("port 8081 after restoring policy", lambda: expect_payload(destination, 8081, destination_hostname))
        report["checks"]["policy_deny_restore"] = {"denied_port": 8081, "allowed_port": 8080,
                                                  "denial": blocked, "restored_payload": True}
        write_result(report)

        check_revocation(nodes, destination, destination_hostname, report)
        report["status"] = "passed"
        log("Lab checks passed: eight users/nodes, direct and relayed TSMP/HTTP, policy deny/restore, fresh-dial revocation.")
    except (LabError, OSError, ValueError, KeyError) as error:
        report["status"] = "failed"
        report["error"] = redact(error)
        raise
    finally:
        if policy_changed:
            try:
                set_policy([8080, 8081])
            except LabError as error:
                report["policy_restore_error"] = redact(error)
                report["status"] = "failed"
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        write_result(report)
    if report["status"] != "passed":
        raise LabError(f"Failed to restore lab policy; see {RESULT.relative_to(ROOT)}")
    log(f"Evidence written to {RESULT}")


def peer_present(address, *, service="node1"):
    status = daemon_status(service)
    own_node = status.get("Self")
    if status["BackendState"] != "Running" or not isinstance(own_node, dict) or not own_node.get("TailscaleIPs"):
        raise LabError(f"Cannot verify peer withdrawal: {service} has no running overlay identity")
    return any(address in peer.get("TailscaleIPs", []) for peer in (status.get("Peer") or {}).values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["up", "check", "status", "down"])
    parser.add_argument("--purge", action="store_true", help="With down only: delete this project's lab state volumes")
    args = parser.parse_args()
    if args.purge and args.command != "down":
        parser.error("--purge is only valid with down")
    try:
        if args.command == "up":
            up()
        elif args.command == "check":
            check()
        elif args.command == "status":
            log(compose("ps").stdout.rstrip())
        elif args.command == "down":
            compose("down", *(["--volumes"] if args.purge else []), timeout=120)
            if args.purge:
                remove_lab_tls()
            log("Stopped covee-lab" + (" and deleted its state volumes." if args.purge else "; lab state volumes preserved."))
    except (LabError, OSError, ValueError, KeyError) as error:
        log(f"ERROR: {redact(error)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
