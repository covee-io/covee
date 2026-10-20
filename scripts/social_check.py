#!/usr/bin/env python3
"""Qualify optional broker container wiring without host ports or account login.

Only public Google OIDC discovery metadata is fetched. Provider tokens and
account credentials are neither supplied nor requested by this smoke test.
"""
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import sys
import time
from urllib.parse import urlsplit


def probe(phase):
    context = ssl.create_default_context(cafile="/run/covee/identity-trust.pem")
    control, admin = "control.social.invalid", "admin.social.invalid"
    def request(host, port, method, path, body=None, headers=None):
        connection = http.client.HTTPSConnection(host, port, context=context, timeout=15)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            data = response.read(1 << 20)
            return response.status, data
        finally:
            connection.close()
    status, data = request(control, 443, "GET", "/identity/.well-known/openid-configuration")
    discovery = json.loads(data)
    assert status == 200 and discovery["issuer"] == "https://" + control + "/identity"
    assert discovery["code_challenge_methods_supported"] == ["S256"]
    for path in ("/api/v1/users", "/api/login", "/identity/healthz", "/identity/api/users", "/identity/callback/unknown", "/metrics"):
        assert request(control, 443, "GET", path)[0] == 404
    if phase == "bootstrap":
        assert request(control, 443, "GET", "/key?v=131")[0] == 404
        assert request(admin, 8444, "GET", "/api/session")[0] == 404
    else:
        assert request(control, 443, "GET", "/key?v=131")[0] == 200
        assert request(admin, 8444, "GET", "/api/session")[0] == 401
        status, data = request(admin, 8444, "GET", "/auth/config")
        assert status == 200 and json.loads(data) == {"mode": "oidc", "signinLabel": "Continue to sign in"}
        status, data = request(admin, 8444, "POST", "/auth/oidc/login", "{}", {"Origin": "https://" + admin + ":8444", "Content-Type": "application/json"})
        assert status == 200
        target = urlsplit(json.loads(data)["authorizationUrl"])
        assert target.netloc == control and target.path == "/identity/authorize"
        assert request(control, 443, "GET", target.path + "?" + target.query)[0] == 200
        assert request(admin, 8444, "POST", "/api/login", "{}", {"Origin": "https://" + admin + ":8444", "Content-Type": "application/json"})[0] == 404
    print(json.dumps({"status": "passed", "phase": phase}))


def check():
    import deploy
    from deploy_check import image_id, input_hashes
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    base = deploy.ROOT / ".cache/covee/deploy/social-checks" / stamp
    base.mkdir(parents=True, mode=0o700)
    source = base / "source"
    source.mkdir(mode=0o700)
    cert, key = source / "control.crt", source / "control.key"
    deploy.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "3", "-sha256",
                "-subj", "/CN=control.social.invalid", "-addext", "subjectAltName=DNS:control.social.invalid", "-keyout", key, "-out", cert])
    cert.chmod(0o400)
    key.chmod(0o400)
    deploy.write_private(source / "google-secret", "disposable-placeholder-not-a-provider-credential")
    spec = {"control_host": "control.social.invalid", "admin_host": "admin.social.invalid", "dns_base_domain": "mesh.social.invalid", "public_bind": "127.0.0.1",
            "tls": {"control_cert_file": str(cert), "control_key_file": str(key)},
            "identity": {"providers": [{"id": "google", "kind": "google", "client_id": "disposable-test.apps.googleusercontent.com", "client_secret_file": str(source / "google-secret")}], "grants": []}}
    directory = deploy.prepare(base / "runtime", spec)
    probe_image = image_id("python:3.14.0-alpine3.22")
    overlay = "\n".join([
        "services:", "  headscale:", "    ports: !reset []", "  ingress:", "    ports: !reset []",
        "    networks:", "      backend:", "        aliases: [control.social.invalid, admin.social.invalid]", "      edge: {}",
        "  probe:", f"    image: {probe_image}", "    entrypoint: [python3, /lab/social_check.py]", "    command: [--probe, active]",
        f"    user: '{os.getuid()}:{os.getgid()}'", "    read_only: true", "    cap_drop: [ALL]", "    security_opt: [no-new-privileges:true]", "    networks: [backend]",
        "    volumes:", "      - " + json.dumps(str(Path(__file__).resolve()) + ":/lab/social_check.py:ro"),
        "      - " + json.dumps(str(directory / "identity-trust.pem") + ":/run/covee/identity-trust.pem:ro"),
        "networks:", "  backend: {internal: true}", "  edge: {internal: true}", "  coordinator-egress: {internal: true}", "  management-egress: {internal: true}",
        # The identity service alone needs external provider discovery. No host
        # ports are published; provider client credentials are dummy values.
        "  identity-egress: {}", ""
    ])
    path = base / "smoke.compose.yaml"
    deploy.write_private(path, overlay)
    runtime = deploy.Runtime(directory, override=path)
    report = {"format": 1, "started_at": stamp, "status": "running", "checks": {}, "inputs_sha256": input_hashes(),
              "limits": {"live_provider_account_login": False, "signed_native_vpn": False, "public_exposure": False, "identity_provider_metadata": "real Google HTTPS discovery only"}}
    for filename in ("deploy/compose.identity.yaml", "deploy/compose.identity-bootstrap.yaml", "deploy/Dockerfile.identity", "scripts/social_check.py"):
        report["inputs_sha256"][filename] = hashlib.sha256((deploy.ROOT / filename).read_bytes()).hexdigest()
    failure = None
    try:
        runtime.pin_images()
        report["images"] = {name: image_id(ref) for name, ref in deploy.runtime_images(deploy.load_json(directory / "deployment.json")).items()}
        runtime.compose("config", "--quiet")
        runtime.compose("--file", deploy.IDENTITY_BOOTSTRAP_COMPOSE, "up", "--detach", "--no-deps", "identity", "ingress", timeout=120)
        def run_probe(phase):
            return runtime.compose("run", "--rm", "--no-deps", "probe", "--probe", phase, check=False, timeout=30)
        deadline = time.monotonic() + 90
        while True:
            result = run_probe("bootstrap")
            if result.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise deploy.DeploymentError("Broker discovery or identity-only bootstrap did not become ready")
            time.sleep(1)
        report["checks"]["identity_only_bootstrap_denies_control_and_administration"] = "passed"
        runtime.bootstrap()
        report["checks"]["headscale_discovers_exact_broker_issuer_and_initializes_deny_policy"] = "passed"
        runtime.compose("up", "--detach", "--force-recreate", "management", timeout=120)
        runtime.compose("up", "--detach", "--force-recreate", "ingress", timeout=120)
        deadline = time.monotonic() + 60
        while True:
            result = run_probe("active")
            if result.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise deploy.DeploymentError("Private console broker discovery and public route checks failed")
            time.sleep(1)
        report["checks"]["console_discovers_broker_and_navigates_to_provider_chooser"] = "passed"
        report["checks"]["public_backend_segregation_and_token_bypass_denial"] = "passed"
        ids = runtime.compose("ps", "--quiet", "headscale", "management", "ingress", "identity").stdout.decode().split()
        containers = json.loads(deploy.run(["docker", "inspect", *ids]).stdout)
        assert len(containers) == 4
        metadata = deploy.load_json(directory / "deployment.json")
        for container in containers:
            assert container["Config"]["User"] == f"{metadata['uid']}:{metadata['gid']}"
            host = container["HostConfig"]
            assert host["ReadonlyRootfs"] and host["CapDrop"] == ["ALL"]
            assert not host.get("PortBindings")
        report["checks"]["four_nonroot_readonly_capdrop_services_with_zero_host_ports"] = "passed"
        policy = runtime.control("policy", "get").stdout.decode()
        assert json.loads(policy) == {"grants": [], "ssh": []}
        report["checks"]["persisted_explicit_default_deny"] = "passed"
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["failure_type"] = type(error).__name__
        failure = error
        logs = runtime.compose("logs", "--no-color", "--tail", "100", check=False)
        deploy.write_private(base / "private-diagnostics.log", logs.stdout + logs.stderr, mode=0o600)
    finally:
        try:
            runtime.compose("down", timeout=120)
            report["cleanup"] = "selected-project-stopped"
        except deploy.DeploymentError as error:
            report["cleanup"] = "failed"
            report["status"] = "failed"
            failure = failure or error
        current = input_hashes()
        for filename in ("deploy/compose.identity.yaml", "deploy/compose.identity-bootstrap.yaml", "deploy/Dockerfile.identity", "scripts/social_check.py"):
            current[filename] = hashlib.sha256((deploy.ROOT / filename).read_bytes()).hexdigest()
        if current != report["inputs_sha256"]:
            report["inputs_changed_during_run"] = True
            report["status"] = "failed"
            failure = failure or deploy.DeploymentError("Social smoke source inputs changed during verification")
        evidence = deploy.ROOT / "evidence/deployment" / ("social-runtime-" + stamp + ".json")
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_text(json.dumps(report, indent=2) + "\n")
    if failure:
        raise deploy.DeploymentError("Social runtime smoke failed; private diagnostics retained") from failure
    print("Optional social runtime smoke passed; no host ports or provider account login. Evidence: " + str(evidence.relative_to(deploy.ROOT)))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--probe":
        probe(sys.argv[2])
    elif len(sys.argv) == 1:
        check()
    else:
        raise SystemExit("usage: social_check.py")
