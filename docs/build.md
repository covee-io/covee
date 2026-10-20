# Management console build

Covee has its own Go management service and browser console. Headscale 0.29.4 is the coordinator. In the lab, upstream Tailscale 1.102.3 clients provide the network engine. The console covers administration; it does not by itself close the gaps in the [feature parity inventory](feature-parity.md).

## Run locally

Install Docker Engine/Desktop with Compose v2 and Python 3.10+. From the repository:

```sh
python3 scripts/manage.py up
```

Open <http://127.0.0.1:8089>. The runner creates a random admin token in `.cache/covee/management/admin-token`, a private file readable by its owner. Use that token to sign in. Upstream credentials stay in the service. Enrollment secrets appear once when a new key is created. The lab uses port 8089, so it does not collide with a standalone service on its default 8088.

The runner starts the existing eight-user networking lab and builds the management container. It publishes only the console on the host loopback interface. The management service joins a separate bridge for that port publication; Headscale and its clients stay on the internal Docker network, with separate disposable state and no host VPN, DNS, TUN or trust-store changes. The management process runs as UID 10001 with dropped capabilities and a read-only root filesystem. Audit records persist in a dedicated project volume.

```sh
python3 scripts/manage.py check
python3 scripts/manage.py status
python3 scripts/manage.py down
```

`check` creates a test user and enrollment key, enrolls a disposable ninth client, verifies device rename/expiration/deletion, tests authenticated API access, CSRF, key ownership, secret omission, key expiration, policy validation and stale revisions, removes the test user/client, and checks audit persistence across a real process restart. It restores the original policy even if a subsequent assertion fails. Sanitized results go to `.cache/covee/lab/management-results.json`. `down` stops only this Docker project and preserves its volumes.

The networking acceptance suite is separate:

```sh
python3 scripts/lab.py check
```

It proves direct and forced-relay encrypted traffic, policy denial/restoration, and fresh-connection denial after node deletion. Established-session revocation and broader platform parity remain separate obligations. The lab re-enrolls node8 on its next startup after a deletion check.

The lab CA expires after seven days. `python3 scripts/lab.py down --purge` deletes the lab's networking state and CA; use this only when intentionally resetting the disposable lab. The management runner detects a missing or expired API key on its next startup and creates a replacement. Management audit state is separate and is not removed by that networking reset.

## Service configuration

The binary embeds its console and uses the pinned Go OIDC/OAuth dependencies in `go.mod`. Build with Go 1.26.1 or the Dockerfile:

```sh
mkdir -p .cache/covee/bin
go build -o .cache/covee/bin/covee-console ./cmd/covee-console
go test -race ./...
python3 -m unittest discover -s tests -v
```

| Environment variable | Behavior |
| --- | --- |
| `COVEE_LISTEN` | Listener address; default `127.0.0.1:8088` |
| `COVEE_PUBLIC_URL` | Exact browser origin, no trailing slash; default `http://127.0.0.1:8088` |
| `COVEE_AUTH_MODE` | `token` (default lab mode) or `oidc` |
| `COVEE_ADMIN_TOKEN` | Required in token mode: random token, at least 32 characters; forbidden in OIDC mode |
| `COVEE_ADMIN_TOKEN_FILE` | Alternative: absolute path to a mounted administrator-token file |
| `COVEE_HEADSCALE_URL` | Required coordinator HTTPS origin |
| `COVEE_HEADSCALE_API_KEY` | Required coordinator API credential |
| `COVEE_HEADSCALE_API_KEY_FILE` | Alternative: absolute path to a mounted coordinator-credential file |
| `COVEE_HEADSCALE_CA_FILE` | Optional PEM CA bundle, added to system roots |
| `COVEE_DATA_DIR` | Audit directory; default `./data` |
| `COVEE_ALLOW_HTTP` | `true` permits non-loopback HTTP for isolated tests; default false |
| `COVEE_OIDC_ISSUER` | Exact HTTPS issuer; tenant-specific v2.0 issuer for Entra |
| `COVEE_OIDC_CLIENT_ID` | Confidential console application ID, separate from coordinator enrollment |
| `COVEE_OIDC_CLIENT_SECRET` / `_FILE` | OIDC credential; the same single-source rules apply |
| `COVEE_OIDC_LABEL` | Optional sign-in button text, at most 100 characters; display only, requires OIDC mode |
| `COVEE_TLS_CERT_FILE` / `COVEE_TLS_KEY_FILE` | Optional paired absolute paths enabling HTTPS with TLS 1.2 minimum |

For each credential, set exactly one of the value variable or its `_FILE` alternative. Presence counts even when a variable is empty; unset the unused variable rather than leaving it empty. Files must resolve to readable regular files at absolute paths; projected-secret symlinks are supported. The file limit is 8192 bytes including an optional single trailing LF or CRLF, which is removed. Other surrounding whitespace, embedded line breaks, empty values and ambiguous sources fail startup without printing secret contents or source paths. File contents are read at startup; rotating a file requires a service restart. Prepare actual file permissions for the service's numeric UID, and mount the files read-only.

For deployment beyond loopback, use a TLS reverse proxy, set the exact external HTTPS public origin, and keep the Go listener and Headscale API private. TLS verification remains enabled between management and Headscale. The checked-in Compose overlay is a local lab configuration, not a production deployment.

The [portable production deployment contract](production-deployment.md) records provider requirements, public-route isolation, host/container hardening and security findings that must be resolved before public production.

## Administration and evidence boundaries

The console supports users, device inventory and rename/expire/delete, enrollment-key creation and expiration, approval of the exit nodes and local networks devices offer, the gateway's destinations and private DNS, a HuJSON policy editor with optimistic revision checks, and an audit viewer. It supports either a shared local token for isolated labs or OIDC with individual actors and server-enforced roles. Custom DNS settings are applied with `deploy.py update-dns`, and certificates are renewed with `covee cert renew` or `deploy.py renew-certificates`, not in the console. Device approval, Services, Funnel, Tailnet Lock, measured capacity and coordinator high availability remain unimplemented.

Browser login exchanges the admin token for an eight-hour HttpOnly SameSite Strict cookie. Browser mutations require an exact Origin and a session CSRF token. Tokens are held in memory and cookies rather than browser storage. The API also accepts the administrator bearer token for scripts. Changing the administrator token requires a service restart, which invalidates all in-memory sessions.

OIDC mode disables token login and bearer authentication entirely, including when a bearer token accompanies a valid cookie. Login uses signed ID tokens, exact issuer/audience validation, nonce, single-use browser-bound state and PKCE S256. The callback is `<COVEE_PUBLIC_URL>/auth/oidc/callback`. Entra app roles must have the exact values `Covee.Admin` or `Covee.Reader`; groups do not substitute for app roles. Administrators can mutate; readers can inspect users, devices, policies and audit without receiving enrollment secrets. Every API mutation enforces its role server-side. Sessions expire at the earlier of one hour or ID-token expiry. Discovery fails startup after ten seconds if unavailable. No refresh-token, Graph/SCIM, continuous-access or back-channel logout integration is implemented; disabling an identity does not invalidate an already established session immediately.

The optional [identity broker](social-login.md) adds Google and Apple alongside Entra for console login and coordinator enrollment. It gives the console its own confidential client and preserves this same cookie, CSRF and role enforcement. Google/Apple roles come from explicit provider-and-subject grants, never email or upstream role claims. Broker ID tokens last five minutes, so console sessions are bounded by that expiry. The native apps use the same coordinator browser flow, with no provider secrets embedded in the applications. Apple uses its documented server-side code exchange with ES256 client authentication; its upstream leg does not advertise PKCE, while both downstream clients and the Google/Entra legs require S256. Live provider registrations and real-account acceptance remain operator steps.

Administrative writes first append and sync an audit intent; inability to record that intent prevents the upstream mutation. A result record follows the upstream attempt. If the mutation succeeds but recording the result fails, the service reports that the outcome is uncertain rather than claiming failure or retrying the mutation. The audit stores action, target, outcome, time, request identity and the authenticated actor (issuer, subject and role in OIDC mode), without raw policy, enrollment secrets or API credentials. It is a local append-only application log, not tamper-proof storage against a host or Docker administrator.

Policy revisions protect changes made through this service. Headscale's own API has no compare-and-swap operation; concurrent direct CLI/API writers can still race. Production operation should restrict policy writes to one management instance until a stronger coordinator transaction contract is added. Sessions and the policy-write mutex are process-local, so this release is a single-instance service.

The 24-hour Headscale management key created by the runner is renewed by the next `up` or `check` when less than one hour remains. It is not a long-running credential rotation service. Docker operators can inspect container environment credentials and state. Protect the host, private cache directory and persistent volumes accordingly.
