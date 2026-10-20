"""Real client acceptance of a disposable, unpublished portable runtime."""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import time

import deploy


RESOLVER_ZONE, RESOLVER_ANSWER = "corp.lab.invalid", "192.0.2.53"
EXTRA_RECORD = {"name": "svc.mesh.lab.invalid", "type": "A", "value": "100.64.0.77"}


def input_hashes():
    paths = [deploy.ROOT / "Dockerfile", deploy.ROOT / "go.mod", deploy.ROOT / "go.sum",
             deploy.ROOT / "deploy/compose.yaml", deploy.ROOT / "deploy/Dockerfile.ingress",
             deploy.ROOT / "deploy/headscale/source-lock.json"]
    for directory in ("cmd", "internal"):
        paths.extend(path for path in (deploy.ROOT / directory).rglob("*") if path.is_file())
    paths.extend((deploy.ROOT / "scripts").glob("deploy*.py"))
    paths.append(deploy.ROOT / "lab/dns_stub.py")
    return {str(path.relative_to(deploy.ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(paths)}


def wait(description, operation, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = operation()
            if value:
                return value
        except (deploy.DeploymentError, ValueError, KeyError):
            pass
        time.sleep(1)
    raise deploy.DeploymentError("Acceptance timed out: " + description)


def image_id(tag):
    return deploy.run(["docker", "image", "inspect", "--format", "{{.Id}}", tag]).stdout.decode().strip()


def override(directory, *, external_client_project=None):
    client_image = image_id("tailscale/tailscale:v1.102.3")
    probe_image = image_id("python:3.14.0-alpine3.22")
    # The disposable clients run as root with DAC override removed. On Linux,
    # they cannot read the operator's mode-0400 runtime CA. Share only a separate
    # public certificate copy; keep the runtime, CA key and secrets private.
    client_ca = directory.with_name(directory.name + ".client-ca.crt")
    deploy.write_private(client_ca, (directory / "internal-ca.crt").read_bytes(), mode=0o444)
    # Paths are JSON quoted, a valid YAML scalar, and never shell evaluated.
    ca = json.dumps(str(client_ca) + ":/lab-ca.crt:ro")
    lines = ["services:", "  headscale:", "    ports: !reset []", "  ingress:", "    ports: !reset []",
             "    networks:", "      backend:", "        aliases: [admin]", "      edge: {}"]
    for index in range(1, 4):
        lines += [f"  node{index}:", f"    image: {client_image}", "    entrypoint: [/usr/local/bin/tailscaled]",
                  "    command: [--tun=userspace-networking, --state=/var/lib/tailscale/tailscaled.state, --socket=/var/run/tailscale/tailscaled.sock, --socks5-server=0.0.0.0:1055]",
                  "    user: '0:0'", "    read_only: true", "    cap_drop: [ALL]", "    security_opt: [no-new-privileges:true]",
                  "    tmpfs: [/tmp, /var/run/tailscale]", "    networks: [backend]", "    environment:",
                  "      TS_NO_LOGS_NO_SUPPORT: 'true'", "      SSL_CERT_FILE: /lab-ca.crt"]
        if index == 3:
            lines += ["      TS_DEBUG_ALWAYS_USE_DERP: 'true'"]
        lines += [f"    volumes: [node{index}-state:/var/lib/tailscale, {ca}]"]
    lines += ["  probe:", f"    image: {probe_image}", "    command: [python3, /lab/probe.py, serve]",
              "    network_mode: service:node2", "    depends_on: [node2]", f"    user: '{__import__('os').getuid()}:{__import__('os').getgid()}'",
              "    read_only: true", "    cap_drop: [ALL]", "    security_opt: [no-new-privileges:true]", "    volumes:"]
    for source, target in ((deploy.ROOT / "lab/probe.py", "/lab/probe.py"),
                           (deploy.ROOT / "scripts/deploy_probe.py", "/lab/deploy_probe.py"),
                           (directory / "internal-ca.crt", "/run/covee/internal-ca.crt"),
                           (directory / "secrets/admin-token", "/run/secrets/admin-token"),
                           (directory / "secrets/headscale-api-key", "/run/secrets/headscale-api-key")):
        lines += ["      - " + json.dumps(str(source) + ":" + target + ":ro")]
    # A throwaway resolver on the internal network. Port 53 needs no capability once the namespaced sysctl allows it.
    lines += ["  resolver:", f"    image: {probe_image}",
              f"    command: [python3, /lab/dns_stub.py, serve, {RESOLVER_ZONE}, {RESOLVER_ANSWER}]",
              f"    user: '{__import__('os').getuid()}:{__import__('os').getgid()}'", "    read_only: true", "    cap_drop: [ALL]",
              "    security_opt: [no-new-privileges:true]", "    sysctls: [net.ipv4.ip_unprivileged_port_start=0]",
              "    networks: [backend]", "    volumes:", "      - " + json.dumps(str(deploy.ROOT / "lab/dns_stub.py") + ":/lab/dns_stub.py:ro")]
    lines += ["networks:", "  backend: {internal: true}", "  edge: {internal: true}",
              "  coordinator-egress: {internal: true}", "  management-egress: {internal: true}", "volumes:"]
    for index in range(1, 4):
        if external_client_project:
            lines += [f"  node{index}-state:", "    external: true", f"    name: {external_client_project}_node{index}-state"]
        else:
            lines += [f"  node{index}-state: {{}}"]
    path = directory / "acceptance.compose.yaml"
    deploy.write_private(path, "\n".join(lines) + "\n")
    return path, {"client": client_image, "probe": probe_image}


def execute(runtime, service, *args, **kwargs):
    return runtime.compose("exec", "-T", service, *args, **kwargs)


def control_json(runtime, *args):
    return json.loads(runtime.control(*args, "--output", "json").stdout)


def client_status(runtime, index):
    result = execute(runtime, f"node{index}", "tailscale", "status", "--json", check=False)
    return json.loads(result.stdout) if result.stdout else {}


def set_policy(runtime, ports):
    policy = {"acls": [{"action": "accept", "src": ["*"], "dst": [f"*:{port}" for port in ports]}]} if ports else {"grants": [], "ssh": []}
    runtime.control("policy", "set", "--file", "/dev/stdin", data=json.dumps(policy).encode())


def fetch(runtime, address, port=8080, proxy="node1"):
    result = execute(runtime, "probe", "python3", "/lab/probe.py", "fetch", proxy, address, str(port), "portable-node2.mesh.lab.invalid",
                     timeout=12, check=False)
    value = json.loads(result.stdout)
    if result.returncode == 0 and value.get("status") == "ok":
        return "ok"
    if result.returncode == 2 and value.get("status") == "blocked" and value.get("failure_kind") == "socks-connect-rejected":
        return "blocked"
    raise deploy.DeploymentError("Overlay payload probe could not establish success or policy rejection")


def enroll(runtime):
    for index in range(1, 4):
        user = control_json(runtime, "users", "create", f"acceptance-user{index}")
        key = control_json(runtime, "preauthkeys", "create", "--user", str(user["id"]), "--expiration", "10m")["key"]
        wait("client daemon", lambda: client_status(runtime, index) or False)
        execute(runtime, f"node{index}", "sh", "-c", "umask 077; cat > /tmp/enrollment-key", data=key.encode())
        try:
            execute(runtime, f"node{index}", "tailscale", "up", "--login-server=https://ingress:8443", "--auth-key=file:/tmp/enrollment-key",
                    "--accept-dns=false", "--accept-routes=false", f"--hostname=portable-node{index}", "--timeout=40s", timeout=50)
        finally:
            execute(runtime, f"node{index}", "rm", "-f", "/tmp/enrollment-key")


def dns_status(runtime, index):
    result = execute(runtime, f"node{index}", "tailscale", "dns", "status", "--json", check=False)
    return json.loads(result.stdout) if result.stdout else {}


def dns_query(runtime, index, name, qtype="A"):
    """The client's own forwarder answer: (response code, A/AAAA answer bodies), or ("error", []) when it cannot answer."""
    result = execute(runtime, f"node{index}", "tailscale", "dns", "query", "--json", name, qtype, timeout=40, check=False)
    try:
        value = json.loads(result.stdout)
    except ValueError:
        return "error", []
    return value.get("ResponseCode", "error"), [answer["Body"] for answer in value.get("Answers") or []]


def resolver_address(runtime):
    container = runtime.compose("ps", "--quiet", "resolver").stdout.decode().strip()
    networks = json.loads(deploy.run(["docker", "inspect", container]).stdout)[0]["NetworkSettings"]["Networks"]
    addresses = [network["IPAddress"] for name, network in networks.items() if name.endswith("_backend") and network["IPAddress"]]
    if len(addresses) != 1:
        raise deploy.DeploymentError("Could not determine the isolated resolver address")
    return addresses[0]


def resolver_queries(runtime):
    logs = runtime.compose("logs", "--no-color", "--no-log-prefix", "resolver", check=False).stdout.decode()
    return [record["qname"] for record in map(json.loads, (line for line in logs.splitlines() if line.startswith("{")))
            if record.get("event") == "query"]


def resolver_info(address):
    return {"Addr": address}


def dns_converged(runtime, expect):
    """Every client has received the settings. expect maps dns-status fields to a value (None means absent or empty) or a predicate."""
    for index in range(1, 4):
        status = dns_status(runtime, index)
        for field, wanted in expect.items():
            value = status.get(field) or None
            matches = wanted(value) if callable(wanted) else value == wanted
            if not matches:
                return False
    return True


def dns_retained(runtime, resolver):
    status = dns_status(runtime, 1)
    records = [(r["Name"], r.get("Type"), r["Value"]) for r in status.get("ExtraRecords") or []]
    return (status.get("SplitDNSRoutes") == {RESOLVER_ZONE: [resolver_info(resolver)]}
            and records == [(EXTRA_RECORD["name"], "A", EXTRA_RECORD["value"])])


def dns_acceptance(runtime, node2_address):
    """Custom DNS on three real clients: delivery, scoping, removal and upstream outage, with a throwaway resolver."""
    for index in range(1, 4):
        execute(runtime, f"node{index}", "tailscale", "set", "--accept-dns=true")
    base = "mesh.lab.invalid"
    peer = f"portable-node2.{base}"
    extra_name, extra_value = EXTRA_RECORD["name"], EXTRA_RECORD["value"]
    zone_name, outside = f"svc.{RESOLVER_ZONE}", "public.other.lab.invalid"
    ok = "RCodeSuccess"
    wait("baseline MagicDNS configuration", lambda: dns_converged(runtime, {"TailscaleDNS": True, "SplitDNSRoutes": None, "Resolvers": None}))
    wait("baseline MagicDNS answer", lambda: dns_query(runtime, 1, peer) == (ok, [node2_address]))
    baseline = dns_status(runtime, 1)
    if baseline["CurrentTailnet"]["MagicDNSSuffix"] != base or baseline.get("ExtraRecords"):
        raise deploy.DeploymentError("Baseline clients unexpectedly carry custom DNS")
    resolver = resolver_address(runtime)
    route = {RESOLVER_ZONE: [resolver_info(resolver)]}
    split = {"split": {RESOLVER_ZONE: [resolver]}, "search_domains": [RESOLVER_ZONE], "extra_records": [EXTRA_RECORD]}
    # Only queries made during this phase count, so the proof does not depend on the resolver's earlier history.
    first = len(resolver_queries(runtime))
    seen = lambda: resolver_queries(runtime)[first:]
    result = {"resolver": "isolated throwaway UDP resolver", "zone": RESOLVER_ZONE}

    # Success: split route, search domain and extra record reach every client, and only the zone is sent upstream.
    if not runtime.update_dns(split):
        raise deploy.DeploymentError("Expected the running coordinator to restart for the DNS update")
    wait("split DNS delivered to every client", lambda: dns_converged(runtime, {
        "SplitDNSRoutes": route, "Resolvers": None,
        "SearchDomains": lambda value: value == sorted([base, RESOLVER_ZONE]),
        "ExtraRecords": lambda value: value and [(r["Name"], r.get("Type"), r["Value"]) for r in value] == [(extra_name, "A", extra_value)]}), timeout=120)
    wait("zone answered by the designated resolver", lambda: dns_query(runtime, 1, zone_name) == (ok, [RESOLVER_ANSWER]))
    for index in (2, 3):
        if dns_query(runtime, index, zone_name) != (ok, [RESOLVER_ANSWER]):
            raise deploy.DeploymentError("A client did not use the split DNS resolver")
    if dns_query(runtime, 1, extra_name) != (ok, [extra_value]) or dns_query(runtime, 1, peer) != (ok, [node2_address]):
        raise deploy.DeploymentError("Extra record or MagicDNS peer name did not resolve locally")
    code, answers = dns_query(runtime, 1, outside)
    if answers:
        raise deploy.DeploymentError("A name outside every route was answered")
    queried = seen()
    if zone_name not in queried or any(name in queried for name in (extra_name, peer, outside)):
        raise deploy.DeploymentError("Resolver queries did not match the configured scope")
    result["success"] = {"split_route_search_domain_and_extra_record_on_all_clients": True, "zone_answered_by_resolver": True,
                         "extra_record_and_magicdns_peer_answered_locally": True}
    result["denial"] = {"names_outside_routes_not_sent_to_split_resolver": True, "extra_record_not_leaked": True, "magicdns_peer_not_leaked": True}

    # Without override a global resolver is only a fallback, which clients apply as their default resolver solely
    # behind an exit node, so it is delivered but must not capture ordinary names.
    runtime.update_dns({**split, "nameservers": [resolver]})
    wait("fallback resolver delivered", lambda: dns_converged(runtime, {"FallbackResolvers": [resolver_info(resolver)], "Resolvers": None}), timeout=120)
    if dns_query(runtime, 1, outside)[1] or outside in seen():
        raise deploy.DeploymentError("A fallback-only resolver captured a name outside every route")
    runtime.update_dns({**split, "nameservers": [resolver], "override_local_dns": True})
    wait("override resolver delivered", lambda: dns_converged(runtime, {"Resolvers": [resolver_info(resolver)], "FallbackResolvers": None}), timeout=120)
    wait("override resolver used for a non-local name", lambda: dns_query(runtime, 1, outside)[0] == "RCodeNameError" and outside in seen())
    if dns_query(runtime, 1, extra_name) != (ok, [extra_value]) or dns_query(runtime, 1, peer) != (ok, [node2_address]) or {extra_name, peer} & set(seen()):
        raise deploy.DeploymentError("Override resolver captured names the client answers locally")
    result["global_resolver"] = {"fallback_without_override_delivered_but_not_used_without_exit_node": True, "override_delivered_and_used": True,
                                 "local_names_still_answered_locally": True}

    # Revocation: removing the route stops the clients using the resolver.
    runtime.update_dns({"extra_records": [EXTRA_RECORD]})
    wait("route and resolvers withdrawn", lambda: dns_converged(runtime, {
        "SplitDNSRoutes": None, "Resolvers": None, "FallbackResolvers": None,
        "SearchDomains": [base]}), timeout=120)
    before = len(seen())
    code, answers = dns_query(runtime, 1, zone_name)
    if RESOLVER_ANSWER in answers or len(seen()) != before:
        raise deploy.DeploymentError("A client kept using a withdrawn resolver")
    if dns_query(runtime, 1, extra_name) != (ok, [extra_value]):
        raise deploy.DeploymentError("The retained extra record stopped resolving")
    result["revocation"] = {"withdrawn_route_not_used": True, "no_further_queries_to_resolver": True, "retained_extra_record_still_resolves": True}

    # Outage: an unreachable upstream fails only its own names.
    runtime.update_dns(split)
    wait("split DNS restored", lambda: dns_converged(runtime, {"SplitDNSRoutes": route}), timeout=120)
    wait("zone answered after restoration", lambda: dns_query(runtime, 1, zone_name) == (ok, [RESOLVER_ANSWER]))
    runtime.compose("stop", "resolver", timeout=60)
    try:
        if RESOLVER_ANSWER in dns_query(runtime, 1, zone_name)[1]:
            raise deploy.DeploymentError("Zone answered while its resolver was stopped")
        if dns_query(runtime, 1, extra_name) != (ok, [extra_value]) or dns_query(runtime, 1, peer) != (ok, [node2_address]):
            raise deploy.DeploymentError("Local names failed during an upstream resolver outage")
    finally:
        runtime.compose("start", "resolver", timeout=60)
    wait("zone answered after the resolver returned", lambda: dns_query(runtime, 1, zone_name) == (ok, [RESOLVER_ANSWER]))
    result["outage"] = {"zone_fails_without_resolver": True, "local_names_unaffected": True, "recovers_when_resolver_returns": True}
    result["final_resolver"] = resolver
    return result


def inspect_runtime(runtime):
    ids = runtime.compose("ps", "--quiet", "headscale", "management", "ingress").stdout.decode().split()
    if len(ids) != 3:
        raise deploy.DeploymentError("Expected exactly three runtime containers")
    containers = json.loads(deploy.run(["docker", "inspect", *ids]).stdout)
    networks = set()
    for container in containers:
        config, host = container["Config"], container["HostConfig"]
        if config["User"].split(":")[0] in ("", "0", "root") or not host["ReadonlyRootfs"] or host["Privileged"]:
            raise deploy.DeploymentError("Runtime violated unprivileged/read-only contract")
        if "ALL" not in host["CapDrop"] or "no-new-privileges:true" not in host["SecurityOpt"] or host.get("PortBindings"):
            raise deploy.DeploymentError("Runtime capability or unpublished-port contract failed")
        if host["PidsLimit"] <= 0 or host["Memory"] <= 0 or host["NanoCpus"] <= 0:
            raise deploy.DeploymentError("Runtime resource limits missing")
        for mount in container["Mounts"]:
            if "docker.sock" in mount["Source"] or mount["Destination"].startswith("/dev/") or mount["Destination"].endswith("internal-ca.key"):
                raise deploy.DeploymentError("Forbidden privileged or CA private-key mount")
        networks.update(container["NetworkSettings"]["Networks"])
    for network in networks:
        if not json.loads(deploy.run(["docker", "network", "inspect", network]).stdout)[0]["Internal"]:
            raise deploy.DeploymentError("Acceptance runtime escaped internal-only networks")
    return {"non_root": True, "read_only": True, "dropped_capabilities": True, "resource_limits": True,
            "host_ports": [], "internal_only_networks": len(networks), "private_ca_key_unmounted": True}


def check():
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    directory = deploy.ROOT / ".cache/covee/deploy" / ("check-" + stamp)
    report = {"format": 1, "started_at": stamp, "status": "running", "checks": {}, "inputs_sha256": input_hashes(),
              "scope": "isolated Docker; no published ports, host trust/DNS/firewall/VPN changes or live Entra"}
    spec = {"control_host": "ingress", "admin_host": "admin", "dns_base_domain": "mesh.lab.invalid",
            "public_bind": "127.0.0.1", "public_port": 8443}
    deploy.prepare(directory, spec, lab=True)
    override_path, helper_images = override(directory)
    runtime = deploy.Runtime(directory, override=override_path)
    report["project"] = runtime.project
    report["images"] = {**runtime.pin_images(), **helper_images}
    success = False
    cleanup_runtimes = [runtime]
    try:
        print("Starting an unpublished, internal-only portable acceptance project.", flush=True)
        runtime.compose("config", "--quiet")
        runtime.bootstrap()
        runtime.compose("up", "--detach", timeout=120)
        report["checks"]["container_isolation"] = inspect_runtime(runtime)
        wait("gateway TLS", lambda: execute(runtime, "probe", "python3", "/lab/deploy_probe.py", "public", check=False).returncode == 0)
        report["checks"]["public_boundary"] = json.loads(execute(runtime, "probe", "python3", "/lab/deploy_probe.py", "public").stdout)
        wait("private management readiness", lambda: execute(runtime, "probe", "python3", "/lab/deploy_probe.py", "ready", check=False).returncode == 0)
        report["checks"]["private_management"] = json.loads(execute(runtime, "probe", "python3", "/lab/deploy_probe.py", "management").stdout)
        print("TLS boundaries passed. Enrolling three real Tailscale clients.", flush=True)
        enroll(runtime)
        nodes = control_json(runtime, "nodes", "list")
        if len(nodes) != 3 or any(client_status(runtime, i).get("BackendState") != "Running" for i in range(1, 4)):
            raise deploy.DeploymentError("Real clients failed to enroll through gateway")
        target = next(node for node in nodes if node.get("given_name") == "portable-node2")
        address = next(ip for ip in target["ip_addresses"] if ipaddress.ip_address(ip).version == 4)
        for port in (8080, 8081):
            execute(runtime, "node2", "tailscale", "serve", "--bg", "--yes", f"--http={port}", "http://127.0.0.1:8000")
        wait("default deny", lambda: fetch(runtime, address) == "blocked")
        report["checks"]["default_deny"] = True
        set_policy(runtime, [8080, 8081])
        wait("direct overlay payload", lambda: fetch(runtime, address) == "ok")
        direct = execute(runtime, "node1", "tailscale", "ping", "--until-direct=true", "--c=5", "--timeout=3s", address).stdout.decode()
        import lab
        if not lab.has_direct_pong(direct):
            raise deploy.DeploymentError("No direct UDP endpoint confirmed")
        wait("payload after direct UDP discovery", lambda: fetch(runtime, address) == "ok")
        peer = next(p for p in client_status(runtime, 1)["Peer"].values() if address in p.get("TailscaleIPs", []))
        if not peer.get("CurAddr"):
            raise deploy.DeploymentError("Direct endpoint was not retained for payload verification")
        report["checks"]["direct_payload"] = True
        relay = execute(runtime, "node3", "tailscale", "ping", "--until-direct=false", "--c=1", "--timeout=5s", address).stdout.decode()
        if "via DERP(owned)" not in relay:
            raise deploy.DeploymentError("Owned relay not confirmed")
        wait("owned DERP payload", lambda: fetch(runtime, address, proxy="node3") == "ok")
        report["checks"]["owned_derp_payload"] = True
        set_policy(runtime, [8080])
        wait("withdrawn port denied", lambda: fetch(runtime, address, port=8081) == "blocked")
        wait("retained port allowed", lambda: fetch(runtime, address) == "ok")
        set_policy(runtime, [8080, 8081])
        wait("restored port", lambda: fetch(runtime, address, port=8081) == "ok")
        report["checks"]["policy_withdrawal_and_restore"] = True
        print("Direct, owned relay and policy checks passed. Checking custom DNS on the real clients.", flush=True)
        report["checks"]["custom_dns"] = dns_acceptance(runtime, address)
        dns_resolver_address = report["checks"]["custom_dns"]["final_resolver"]
        print("Custom DNS passed. Checking restart persistence.", flush=True)
        key_hashes = {name: hashlib.sha256((directory / "state/headscale" / name).read_bytes()).hexdigest()
                      for name in ("noise_private.key", "derp_private.key")}
        runtime.compose("restart", "headscale", "management", "ingress", timeout=120)
        runtime.wait("headscale")
        wait("reconnection after restart", lambda: fetch(runtime, address) == "ok")
        wait("custom DNS retained after restart", lambda: dns_retained(runtime, dns_resolver_address))
        if control_json(runtime, "nodes", "list") != nodes:
            # last_seen/online fields can legitimately change; compare stable identity only.
            after = control_json(runtime, "nodes", "list")
            stable = lambda items: sorted((n["id"], n["node_key"], tuple(n["ip_addresses"])) for n in items)
            if stable(after) != stable(nodes):
                raise deploy.DeploymentError("Node identity changed on restart")
        if any(hashlib.sha256((directory / "state/headscale" / name).read_bytes()).hexdigest() != digest for name, digest in key_hashes.items()):
            raise deploy.DeploymentError("Coordinator keys changed on restart")
        # Cached WireGuard peers can work while control is broken. New policy
        # propagation proves clients have reconnected to the restarted server.
        set_policy(runtime, [8080])
        wait("post-restart policy withdrawal", lambda: fetch(runtime, address, port=8081) == "blocked")
        wait("post-restart retained port", lambda: fetch(runtime, address) == "ok")
        set_policy(runtime, [8080, 8081])
        wait("post-restart policy restoration", lambda: fetch(runtime, address, port=8081) == "ok")
        report["checks"]["restart_identity_and_connectivity"] = True
        print("Restart passed. Testing encrypted backup and a separate restored runtime.", flush=True)
        import deploy_backup
        identity = directory.with_name(directory.name + ".age-identity")
        archive = directory.with_name(directory.name + ".tar.age")
        keygen = deploy.ROOT / ".cache/covee/deploy/tools/age-keygen"
        if not keygen.is_file():
            import shutil
            keygen = shutil.which("age-keygen")
            if not keygen:
                raise deploy.DeploymentError("age-keygen is required for real recovery acceptance")
        deploy.run([keygen, "--output", identity])
        identity.chmod(0o600)
        recipient = deploy.run([keygen, "-y", identity]).stdout.decode().strip()
        deploy_backup.backup(runtime, archive, recipient)
        runtime.wait("headscale")
        wait("connectivity after consistent snapshot", lambda: fetch(runtime, address) == "ok")
        runtime.compose("down", timeout=120)
        restored_dir = directory.with_name(directory.name + "-restored")
        deploy_backup.restore(archive, restored_dir, identity)
        deploy.validate(restored_dir)
        restored_override, _ = override(restored_dir, external_client_project=runtime.project)
        restored = deploy.Runtime(restored_dir, override=restored_override)
        cleanup_runtimes.append(restored)
        restored.bootstrap()
        restored.compose("up", "--detach", timeout=120)
        inspect_runtime(restored)
        wait("restored original client identity and data path", lambda: fetch(restored, address) == "ok")
        wait("custom DNS retained after encrypted restore", lambda: dns_retained(restored, dns_resolver_address))
        wait("restored owned relay", lambda: fetch(restored, address, proxy="node3") == "ok")
        set_policy(restored, [8080])
        wait("restored policy withdrawal", lambda: fetch(restored, address, port=8081) == "blocked")
        set_policy(restored, [8080, 8081])
        wait("restored policy propagation", lambda: fetch(restored, address, port=8081) == "ok")
        wait("restored management readiness", lambda: execute(restored, "probe", "python3", "/lab/deploy_probe.py", "ready", check=False).returncode == 0)
        execute(restored, "probe", "python3", "/lab/deploy_probe.py", "recovered")
        stable = lambda items: sorted((n["id"], n["node_key"], tuple(n["ip_addresses"])) for n in items)
        if stable(control_json(restored, "nodes", "list")) != stable(nodes):
            raise deploy.DeploymentError("Restored node identities or addresses differ")
        for name, digest in key_hashes.items():
            if hashlib.sha256((restored_dir / "state/headscale" / name).read_bytes()).hexdigest() != digest:
                raise deploy.DeploymentError("Restored coordinator key differs")
        report["checks"]["encrypted_restore"] = {"new_runtime_project": restored.project, "original_clients_reconnect_without_enrollment": True,
                                                  "direct_and_owned_derp_payloads": True, "keys_users_policy_audit_retained": True, "custom_dns_retained": True,
                                                  "ciphertext_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
        report["status"] = "passed"
        success = True
    except Exception as error:
        report["status"] = "failed"
        report["failure"] = str(error) if isinstance(error, deploy.DeploymentError) else type(error).__name__
        logs = runtime.compose("logs", "--no-color", "--tail", "150", check=False)
        deploy.write_private(directory / "failure-private.log", logs.stdout + logs.stderr)
        raise
    finally:
        try:
            for selected in reversed(cleanup_runtimes):
                selected.compose("down", "--volumes", timeout=120)
            report["cleanup"] = "isolated project stopped; disposable client volumes removed; private diagnostic state retained"
        except deploy.DeploymentError:
            report["cleanup"] = "failed; inspect only the named project"
            report["status"] = "failed"
            report["cleanup_failure"] = True
            success = False
        if input_hashes() != report["inputs_sha256"]:
            report["status"] = "failed"
            report["inputs_changed_during_run"] = True
            success = False
        evidence = deploy.ROOT / "evidence/deployment"
        evidence.mkdir(parents=True, exist_ok=True)
        target = evidence / ("acceptance-" + stamp + ".json")
        target.write_text(json.dumps(report, indent=2) + "\n")
        print("Acceptance evidence: " + str(target.relative_to(deploy.ROOT)), flush=True)
    if not success:
        if report.get("inputs_changed_during_run"):
            raise deploy.DeploymentError("Acceptance inputs changed during verification; rerun with frozen sources")
        raise deploy.DeploymentError("Acceptance cleanup failed")
    print("Portable deployment acceptance passed; live Entra and public-host acceptance remain separate.")
