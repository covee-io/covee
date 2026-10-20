"""Container-only acceptance probes. Credentials never leave this process."""
import http.client
import json
from pathlib import Path
import ssl
import sys

CA = "/run/covee/internal-ca.crt"


def request(host, port, method, path, body=None, headers=None):
    connection = http.client.HTTPSConnection(host, port, timeout=10, context=ssl.create_default_context(cafile=CA))
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read(1 << 20)
        return response.status, dict(response.getheaders()), data
    finally:
        connection.close()


def assert_status(result, expected):
    if result[0] != expected:
        raise RuntimeError(f"Unexpected HTTP status {result[0]}, expected {expected}")


def public():
    credential = Path("/run/secrets/headscale-api-key").read_text().strip()
    denied = ["/api/v1/user", "/api/v1/users", "/metrics", "/swagger", "/swagger/index.html",
              "/debug/pprof/", "/health", "/healthz", "/version", "/api/session", "/auth/config",
              "/verify", "/api%2fv1/user", "//api/v1/user", "/key/../api/v1/user"]
    for path in denied:
        for headers in ({}, {"Authorization": "Bearer " + credential}):
            assert_status(request("ingress", 8443, "GET", path, headers=headers), 404)
    assert_status(request("ingress", 8443, "GET", "/key?v=133"), 200)
    assert_status(request("ingress", 8443, "GET", "/key?v=133", headers={"Host": "admin:8444"}), 421)
    assert_status(request("ingress", 8443, "GET", "/api/v1/user", headers={"X-Original-URL": "/key", "X-Rewrite-URL": "/key"}), 404)
    return {"denied_paths": len(denied), "valid_backend_credential_cannot_bypass": True, "host_confusion_denied": True}


def management():
    assert_status(request("admin", 8444, "GET", "/healthz"), 200)
    assert_status(request("admin", 8444, "GET", "/api/users"), 401)
    assert_status(request("admin", 8444, "GET", "/key?v=133"), 404)
    token = Path("/run/secrets/admin-token").read_text().strip()
    status, headers, body = request("admin", 8444, "POST", "/api/login", json.dumps({"token": token}),
                                    {"Origin": "https://admin:8444", "Content-Type": "application/json"})
    assert_status((status, headers, body), 200)
    cookie = headers.get("Set-Cookie", "").partition(";")[0]
    if not cookie or "Secure" not in headers.get("Set-Cookie", "") or "HttpOnly" not in headers.get("Set-Cookie", ""):
        raise RuntimeError("Session cookie lacks security attributes")
    csrf = json.loads(body)["csrfToken"]
    assert_status(request("admin", 8444, "GET", "/api/users", headers={"Cookie": cookie}), 200)
    assert_status(request("admin", 8444, "POST", "/api/users", '{"name":"csrf-must-fail"}', {"Cookie": cookie, "Origin": "https://admin:8444"}), 403)
    assert_status(request("admin", 8444, "POST", "/api/users", '{"name":"acceptance-console"}',
                          {"Cookie": cookie, "Origin": "https://admin:8444", "X-CSRF-Token": csrf, "Content-Type": "application/json"}), 201)
    assert_status(request("admin", 8444, "POST", "/api/logout", "{}",
                          {"Cookie": cookie, "Origin": "https://admin:8444", "X-CSRF-Token": csrf}), 200)
    assert_status(request("admin", 8444, "GET", "/api/session", headers={"Cookie": cookie}), 401)
    return {"tls_session_csrf_upstream_write_and_logout": True, "auth_mode": "disposable-token-lab"}


def ready():
    assert_status(request("admin", 8444, "GET", "/healthz"), 200)
    return {"ready": True}


def recovered():
    token = Path("/run/secrets/admin-token").read_text().strip()
    headers = {"Authorization": "Bearer " + token}
    users = request("admin", 8444, "GET", "/api/users", headers=headers)
    audit = request("admin", 8444, "GET", "/api/audit", headers=headers)
    assert_status(users, 200)
    assert_status(audit, 200)
    if b"acceptance-console" not in users[2] or b"user.create" not in audit[2]:
        raise RuntimeError("Restored user or audit not present")
    return {"management_user_and_audit_retained": True}


if __name__ == "__main__":
    try:
        operation = {"public": public, "management": management, "ready": ready, "recovered": recovered}[sys.argv[1]]
        print(json.dumps(operation()))
    except Exception as error:
        # Never include HTTP bodies/headers, cookie values or secret file data.
        print(json.dumps({"error": str(error) if isinstance(error, RuntimeError) else type(error).__name__}))
        sys.exit(1)
