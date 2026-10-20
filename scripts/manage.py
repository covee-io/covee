#!/usr/bin/env python3
"""Build and verify the management service against the isolated Headscale lab."""

import argparse
from datetime import datetime, timedelta, timezone
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
import urllib.error
import urllib.request

import lab

ROOT = lab.ROOT
STATE = ROOT / ".cache/covee/management"
ORIGIN = "http://127.0.0.1:8089"
COMPOSE = lab.COMPOSE + ["--file", str(ROOT / "lab/management.yaml")]
RESULT = ROOT / ".cache/covee/lab/management-results.json"
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def compose(*arguments, **kwargs):
    return lab.run(COMPOSE + list(arguments), **kwargs)


def private_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def credentials():
    path = STATE / "credentials.json"
    if not path.exists():
        raise lab.LabError("Run manage.py up first")
    value = json.loads(path.read_text(encoding="utf-8"))
    for name in ("adminToken", "headscaleAPIKey"):
        secret = value.get(name)
        if not isinstance(secret, str) or not re.fullmatch(r"[A-Za-z0-9._-]{32,}", secret):
            raise lab.LabError("Invalid private management credentials file")
        lab.SECRETS.add(secret)
    return value


def api_key_prefix(value):
    match = re.match(r"^hskey-api-([A-Za-z0-9_-]{12})-", value)
    return match.group(1) if match else value.split(".", 1)[0].rstrip("*")


def timestamp(value):
    # The CLI's encoding/json emits protobuf seconds/nanos objects; REST uses
    # RFC3339 strings. Both are produced by the pinned Headscale release.
    if isinstance(value, dict):
        return datetime.fromtimestamp(int(value["seconds"]) + int(value.get("nanos", 0)) / 1_000_000_000, timezone.utc)
    if isinstance(value, str):
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is not None:
            return result
    raise lab.LabError("Unexpected Headscale expiration timestamp format")


def up():
    lab.up()
    current = credentials() if (STATE / "credentials.json").exists() else {}
    current_keys = lab.headscale("apikeys", "list") or []
    known = next((key for key in current_keys if current and api_key_prefix(key.get("prefix", "")) == api_key_prefix(current["headscaleAPIKey"])), None)
    expiry = timestamp(known["expiration"]) if known and known.get("expiration") else datetime.min.replace(tzinfo=timezone.utc)
    if expiry < datetime.now(timezone.utc) + timedelta(hours=1):
        previous = current.get("headscaleAPIKey")
        key = lab.headscale("apikeys", "create", "--expiration", "24h")
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9._-]{32,}", key):
            raise lab.LabError("Headscale returned an unexpected API key format")
        lab.SECRETS.add(key)
        current = {"adminToken": current.get("adminToken") or secrets.token_urlsafe(32),
                   "headscaleAPIKey": key,
                   "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()}
        private_write(STATE / "credentials.json", json.dumps(current) + "\n")
        # Only revoke the prior key stored by this runner, never unrelated keys.
        if previous and known:
            lab.control("apikeys", "expire", "--prefix", api_key_prefix(previous))
    private_write(STATE / "admin-token", current["adminToken"] + "\n")
    private_write(STATE / "service.env", "COVEE_ADMIN_TOKEN=" + current["adminToken"] + "\n"
                  + "COVEE_HEADSCALE_API_KEY=" + current["headscaleAPIKey"] + "\n")
    compose("config", "--quiet")
    compose("up", "--detach", "--build", "management", timeout=600)
    if compose("port", "management", "8089").stdout.strip() != "127.0.0.1:8089":
        raise lab.LabError("Management console was not published on the expected loopback port")
    lab.wait_for("management service", lambda: ready(), timeout=45)
    expect(request("GET", "/api/readyz", token=current["adminToken"]), 200, "Headscale API readiness")
    lab.log(f"Console ready at {ORIGIN}. Admin token: {STATE / 'admin-token'} (private file).")


def request(method, path, body=None, *, opener=None, token=None, csrf=None, origin=None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if csrf:
        headers["X-CSRF-Token"] = csrf
    if origin:
        headers["Origin"] = origin
    data = None if body is None else json.dumps(body).encode()
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(ORIGIN + path, data=data, headers=headers, method=method)
    try:
        response = (opener or HTTP).open(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    except (urllib.error.URLError, TimeoutError) as error:
        raise lab.LabError("Management service is unreachable") from error
    with response:
        status = response.status
        payload = response.read(2_097_153)
        if len(payload) > 2_097_152:
            raise lab.LabError("Management response exceeded test limit")
        try:
            value = json.loads(payload) if payload else {}
        except json.JSONDecodeError as error:
            raise lab.LabError("Management service returned invalid JSON") from error
        return status, value, response.headers


def ready():
    try:
        return request("GET", "/healthz")[0] == 200
    except lab.LabError:
        return False


def expect(result, status, context):
    if result[0] != status:
        # Bodies can contain one-time credentials. Report only bounded codes.
        code = result[1].get("code", "unknown") if isinstance(result[1], dict) else "unknown"
        raise lab.LabError(f"{context}: expected HTTP {status}, got {result[0]} ({code})")
    return result[1]


def console_check():
    paths = {"/": "text/html", "/devices": "text/html", "/app.js": "javascript", "/app.css": "text/css"}
    for path, media in paths.items():
        with HTTP.open(ORIGIN + path, timeout=10) as response:
            body = response.read(1_048_577)
            if response.status != 200 or response.url != ORIGIN + path or media not in response.headers.get("Content-Type", ""):
                raise lab.LabError("Console route or static asset did not serve correctly: " + path)
            if not body or len(body) > 1_048_576:
                raise lab.LabError("Console route or static asset has invalid size")
            if response.headers.get("Cache-Control") != "no-store" or response.headers.get("X-Content-Type-Options") != "nosniff" or "script-src 'self'" not in response.headers.get("Content-Security-Policy", ""):
                raise lab.LabError("Console response lacks required security headers")
    return {"routes": list(paths), "status": 200, "redirects": False, "securityHeaders": True, "realBrowserVisualCheck": "not_tested"}


def check():
    report = {"status": "running", "startedAt": datetime.now(timezone.utc).isoformat(),
              "scope": "Covee management API against real pinned Headscale lab", "checks": {}}
    token = None
    created_user = None
    created_device = None
    client_started = False
    original = None
    policy_changed = False
    try:
        up()
        token = credentials()["adminToken"]
        report["checks"]["consoleServing"] = console_check()
        report["images"] = lab.parse_json(compose("images", "--format", "json").stdout, "management lab images")
        expect(request("GET", "/api/users"), 401, "anonymous users")
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))
        session = expect(request("POST", "/api/login", {"token": token}, opener=opener, origin=ORIGIN), 200, "login")
        csrf = session["csrfToken"]
        expect(request("GET", "/api/session", opener=opener), 200, "authenticated session")
        expect(request("POST", "/api/users", {"name": "should-not-exist"}, opener=opener, origin=ORIGIN), 403, "missing CSRF")
        expect(request("POST", "/api/users", {"name": "should-not-exist"}, opener=opener, csrf=csrf, origin="https://example.invalid"), 403, "foreign origin")
        users = expect(request("GET", "/api/users", token=token), 200, "user list")["users"]
        devices = expect(request("GET", "/api/devices", token=token), 200, "device list")["devices"]
        if len(users) < 8 or len(devices) < 8:
            raise lab.LabError("Expected the real eight-user/eight-device baseline")
        report["checks"]["authentication"] = {"anonymousDenied": True, "cookieSession": True, "missingCSRFDenied": True, "foreignOriginDenied": True}
        report["checks"]["inventory"] = {"users": len(users), "devices": len(devices)}
        name = "mgmt-check-" + secrets.token_hex(4)
        created_user = expect(request("POST", "/api/users", {"name": name}, token=token), 201, "create user")["user"]
        identifier = str(created_user["id"])
        key = expect(request("POST", "/api/keys", {"userId": identifier, "expiryHours": 1}, token=token), 201, "create enrollment key")
        secret = key["secret"]
        if not isinstance(secret, str) or len(secret) < 16:
            raise lab.LabError("No one-time enrollment secret returned")
        lab.SECRETS.add(secret)
        key_id = str(key["key"]["id"])
        compose("up", "--detach", "check-client", timeout=120)
        client_started = True
        lab.wait_for("disposable verification client", lambda: compose("exec", "-T", "check-client", "tailscale", "status", "--json").returncode == 0)
        compose("exec", "-T", "check-client", "tailscale", "up", "--login-server=https://headscale:8080", "--accept-dns=false", "--accept-routes=false", "--hostname=" + name, "--auth-key=" + secret, "--timeout=30s", timeout=40)

        def find_device(device_name):
            current = expect(request("GET", "/api/devices", token=token), 200, "verification device inventory")["devices"]
            return next((device for device in current if device["name"] == device_name and str(device["userId"]) == identifier), None)

        created_device = lab.wait_for("real client enrolled with management key", lambda: find_device(name))
        device_id = str(created_device["id"])
        renamed = name + "-renamed"
        expect(request("PATCH", "/api/devices/" + device_id, {"name": renamed}, token=token), 200, "rename device")
        lab.wait_for("persisted device rename", lambda: find_device(renamed))
        expect(request("POST", "/api/devices/" + device_id + "/expire", {}, token=token), 200, "expire device")
        lab.wait_for("device expiration", lambda: (find_device(renamed) or {}).get("expired"))
        lab.wait_for("expired client NeedsLogin", lambda: lab.parse_json(compose("exec", "-T", "check-client", "tailscale", "status", "--json").stdout, "verification client status").get("BackendState") == "NeedsLogin")
        expect(request("DELETE", "/api/devices/" + device_id, token=token), 200, "delete device")
        lab.wait_for("device removed from coordinator", lambda: find_device(renamed) is None)
        created_device = None
        report["checks"]["devices"] = {"managementKeyEnrollment": True, "ownership": True, "renamePersisted": True, "expirationPersisted": True, "clientNeedsLogin": True, "deletionPersisted": True}
        keys = expect(request("GET", "/api/keys?userId=" + identifier, token=token), 200, "list keys")
        serialized = json.dumps(keys)
        if secret in serialized or "hskey-" in serialized or any("secret" in item or "key" in item for item in keys["keys"]):
            raise lab.LabError("Enrollment secret leaked from key list")
        expect(request("POST", f"/api/keys/{key_id}/expire", {"userId": str(users[0]["id"])}, token=token), 404, "cross-user key expiration")
        expect(request("POST", f"/api/keys/{key_id}/expire", {"userId": identifier}, token=token), 200, "expire enrollment key")
        refreshed = expect(request("GET", "/api/keys?userId=" + identifier, token=token), 200, "expired key list")
        expired = next(item for item in refreshed["keys"] if str(item["id"]) == key_id)
        if datetime.fromisoformat(expired["expiresAt"].replace("Z", "+00:00")) > datetime.now(timezone.utc):
            raise lab.LabError("Enrollment key was not expired upstream")
        report["checks"]["usersAndKeys"] = {"created": True, "secretOnlyOnCreation": True, "ownershipEnforced": True, "expirationPersisted": True}
        original = expect(request("GET", "/api/policy", token=token), 200, "read policy")
        changed = expect(request("PUT", "/api/policy", {"policy": original["policy"] + "\n", "revision": original["revision"]}, token=token), 200, "write policy")
        policy_changed = True
        expect(request("PUT", "/api/policy", {"policy": original["policy"], "revision": original["revision"]}, token=token), 409, "stale policy revision")
        invalid = request("PUT", "/api/policy", {"policy": "{ definitely invalid", "revision": changed["revision"]}, token=token)
        if invalid[0] not in (400, 422):
            raise lab.LabError("Invalid policy was not rejected")
        still = expect(request("GET", "/api/policy", token=token), 200, "policy after invalid update")
        if still["revision"] != changed["revision"]:
            raise lab.LabError("Rejected policy altered upstream state")
        expect(request("PUT", "/api/policy", {"policy": original["policy"], "revision": still["revision"]}, token=token), 200, "restore policy")
        policy_changed = False
        report["checks"]["policy"] = {"roundTrip": True, "staleRevisionDenied": True, "invalidPolicyDenied": True, "originalRestored": True}
        expect(request("DELETE", "/api/users/" + identifier, token=token), 200, "delete empty user")
        created_user = None
        audit = expect(request("GET", "/api/audit", token=token), 200, "read audit")
        if len(audit["events"]) < 8:
            raise lab.LabError("Expected durable administrative audit records")
        serialized = json.dumps(audit)
        if any(value in serialized for value in lab.SECRETS) or "definitely invalid" in serialized:
            raise lab.LabError("Secret or raw policy leaked to audit")
        expect(request("POST", "/api/logout", {}, opener=opener, csrf=csrf, origin=ORIGIN), 200, "logout")
        expect(request("GET", "/api/session", opener=opener), 401, "revoked session")
        report["checks"]["auditAndLogout"] = {"records": len(audit["events"]), "secretsAbsent": True, "sessionRevoked": True}
        # Verify the records survive a real service restart.
        compose("restart", "management", timeout=60)
        lab.wait_for("management service after restart", ready)
        after = expect(request("GET", "/api/audit", token=token), 200, "audit after restart")
        prior_ids = {event["id"] for event in audit["events"]}
        if not prior_ids.issubset({event["id"] for event in after["events"]}):
            raise lab.LabError("Audit records did not survive process restart")
        report["checks"]["auditAndLogout"]["restartPersistence"] = True
        report["status"] = "passed"
    except (lab.LabError, OSError, ValueError, KeyError, StopIteration) as error:
        report["status"] = "failed"
        report["error"] = lab.redact(error)
        raise
    finally:
        if policy_changed and original:
            try:
                current = expect(request("GET", "/api/policy", token=token), 200, "cleanup policy read")
                expect(request("PUT", "/api/policy", {"policy": original["policy"], "revision": current["revision"]}, token=token), 200, "cleanup policy")
            except lab.LabError as error:
                report["policyRestoreError"] = lab.redact(error)
        if created_user:
            try:
                if created_device:
                    expect(request("DELETE", "/api/devices/" + str(created_device["id"]), token=token), 200, "cleanup device")
                expect(request("DELETE", "/api/users/" + str(created_user["id"]), token=token), 200, "cleanup user")
            except lab.LabError as error:
                report["userCleanupError"] = lab.redact(error)
        if client_started:
            try:
                compose("stop", "check-client", timeout=45)
                compose("rm", "--force", "check-client", timeout=45)
            except lab.LabError as error:
                report["clientCleanupError"] = lab.redact(error)
        if any(name in report for name in ("policyRestoreError", "userCleanupError", "clientCleanupError")):
            report["status"] = "failed"
        report["finishedAt"] = datetime.now(timezone.utc).isoformat()
        RESULT.parent.mkdir(parents=True, exist_ok=True)
        RESULT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if report["status"] != "passed":
        raise lab.LabError(f"Management cleanup failed; see {RESULT.relative_to(ROOT)}")
    lab.log(f"Management integration passed; evidence: {RESULT.relative_to(ROOT)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["up", "check", "status", "down"])
    args = parser.parse_args()
    try:
        if args.command == "up":
            up()
        elif args.command == "check":
            check()
        elif args.command == "status":
            lab.log(compose("ps").stdout.rstrip())
        elif args.command == "down":
            compose("down", timeout=120)
            lab.log("Stopped covee-lab including management; state volumes preserved.")
    except (lab.LabError, OSError, ValueError, KeyError, StopIteration) as error:
        lab.log("ERROR: " + lab.redact(error))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
