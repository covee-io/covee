# Operating the portable coordinator

This package runs patched Headscale, the management console and a TLS gateway on one Linux host. An optional fourth identity-broker container adds Google and Apple sign-in alongside Entra. It does not provision a cloud account, change the host firewall or install a system service. Complete the [production deployment gates](../docs/production-deployment.md#gates-before-public-production) before accepting a public installation.

`covee setup` drives these same commands over SSH on a server it prepares, and adds what this package leaves out, such as the firewall and the timers ([CLI](../docs/cli.md)). This page is for running the package by hand.

## Prepare the host and identity

Use a dedicated non-root service account, preferably UID/GID 10001. Preparation records the current account's numeric UID/GID and uses it for every selected container and its private files. UID 0 is forbidden; do not run these commands with `sudo`. The account must own the runtime directory and be able to read its source secrets and certificates. Docker daemon access is a privileged host responsibility, including for a non-root account; review who can use it.

Install Python 3, OpenSSL, Docker Engine and Docker Compose v2. Build on the destination architecture, Linux amd64 or arm64. `scripts/build_headscale.py build --platform linux/amd64` supports a specific Headscale target, but the management and gateway builds in `deploy.py build` use Docker's native platform by default. Cross-building Headscale alone does not produce a complete amd64 deployment.

Provide a stable owned hostname, its public TLS certificate/full chain and private key, persistent local or attached block storage, and direct TCP 443 plus UDP 3478 ingress. Do not put SQLite WAL on NFS/SMB. Restrict operator SSH and retain independent provider-console or other recovery access. Apply and verify provider and Docker-aware host controls for IPv4 and IPv6; these scripts do not do that work. The combined profile is unsupported on Runpod without separate relay/STUN and stable, qualified ingress; see [provider compatibility](../docs/production-deployment.md#provider-compatibility).

For Google/Apple sign-in, or a shared Entra/Google/Apple chooser, follow [social login setup](../docs/social-login.md) and use [deployment.social.example.json](deployment.social.example.json). That optional profile uses one upstream registration per enabled provider and explicit subject grants for Google/Apple; do not combine it with the direct-Entra settings below. Build it with `python3 scripts/deploy.py build --with-identity`. Existing direct-Entra installations need an explicit identity migration before changing profiles.

For the existing direct-Entra profile, create two separate confidential Entra app registrations using a tenant-specific v2 issuer:

| Registration | Exact redirect URI, for the hostname `covee.example.com` | Authorization |
| --- | --- | --- |
| Coordinator enrollment | `https://covee.example.com/oidc/callback` | Require user assignment. Set explicit allowed group object UUIDs in `allowed_group_ids` and configure group claims for those groups. Enrollment uses PKCE S256. |
| Management console | `https://localhost:8444/auth/oidc/callback` | Require user assignment. Define user app roles with exact values `Covee.Admin` and `Covee.Reader`, then assign the appropriate role. Readers cannot mutate configuration. |

Register the actual origins exactly if you change hostnames or ports. Keep client secrets on the server; Apple apps do not receive them. Enrollment groups and console roles are independent. Group admission does not synchronize network policy. There is no Graph/SCIM reconciliation or continuous revocation: removing an Entra assignment does not immediately revoke a console session or enrolled device. Console sessions last at most one hour and are also bounded by ID-token expiry; restarting management ends them.

Copy and edit [deployment.example.json](deployment.example.json) outside the runtime directory. Replace every example tenant/client/group UUID, hostname and absolute source-file path. Source private keys and client secrets must be private, account-owned regular files. The optional `tls.admin_cert_file` and `tls.admin_key_file` fields accept a matching certificate/key for the configured admin hostname. Otherwise preparation issues an admin certificate from the private runtime CA.

## Prepare, validate and start

The paths below assume a checkout at `/opt/covee`, an operator-owned `/srv/covee`, and configuration at `/srv/covee/deployment.json`. Adapt these paths before use. The build account needs write access to the checkout's local `.cache` directory. The prepared runtime directory must not already exist.

```sh
cd /opt/covee
python3 scripts/deploy.py prepare --config /srv/covee/deployment.json --directory /srv/covee/runtime
python3 scripts/deploy.py validate --directory /srv/covee/runtime
python3 scripts/deploy.py build
python3 scripts/deploy.py up --directory /srv/covee/runtime
python3 scripts/deploy.py status --directory /srv/covee/runtime
```

`prepare` creates private configuration, certificates, secrets and state directories without starting services. `validate` checks configuration, ownership, file modes, TLS and the rendered Compose configuration; it does not prove live provider login or public exposure behavior. `build` builds the three base images, including the [pinned downstream Headscale patchset](headscale/README.md); add `--with-identity` for the optional fourth image. `up` pins locally built image IDs, verifies persisted policy before opening coordinator routes at the gateway, and issues a fresh 24-hour coordinator API credential. A new installation starts with an explicit deny-all network/SSH policy. Grant intended access deliberately through the private console.

All runtime operations use the selected directory's Compose project and configuration. Mutable CLI operations use a private `fcntl` lock; an overlapping operation fails instead of running concurrently. Direct Docker/Compose actions bypass this lock and require operator coordination, especially during backups and credential rotation.

To stop the selected runtime while retaining its state:

```sh
python3 scripts/deploy.py down --directory /srv/covee/runtime
```

## Custom DNS

By default clients receive MagicDNS for `dns_base_domain` and nothing else: no global nameservers, split routes, search domains or extra records. Add an optional `dns` object to the deployment JSON, shaped like [dns.example.json](dns.example.json), to push more to every enrolled device.

| Field | Meaning |
| --- | --- |
| `nameservers` | Global resolvers, at most 8: bare IPv4/IPv6 addresses or `https://` DNS-over-HTTPS URLs. |
| `override_local_dns` | `false` (default): the nameservers are sent as fallback resolvers. A client makes them its default resolvers only while it routes through an exit node, and otherwise keeps its local DNS for every name outside the split routes. `true`: clients use the nameservers instead of their local DNS for every name they do not answer themselves. Requires `nameservers`. |
| `split` | Up to 32 domain suffixes, each sent only to its own resolvers (at most 8). Lowercase, no trailing dot. Reverse zones such as `10.in-addr.arpa` work. |
| `search_domains` | At most 6. The MagicDNS domain is always a search domain and must not be repeated. |
| `extra_records` | Up to 128 `{"name", "type", "value"}` records, `A` or `AAAA` only because clients ignore other types. Names must be inside the MagicDNS domain. |

Validation is deliberately stricter than Headscale's. Headscale logs and drops some bad entries and forwards others that no client can use, such as a bare hostname, so a typo would otherwise reach every device. Preparation and `validate` reject:

- resolvers that are loopback, wildcard, multicast, link-local, reserved, IPv4-mapped, scoped or `100.100.100.100` (the client's own forwarder), `host:port` forms, plain `http://` and any URL with credentials, a query, a fragment or a non-normalized path. The configuration goes to every device, so it must hold no secrets;
- a split route for the MagicDNS domain or anything under it, or for any suffix of `control_host` or `admin_host`. A route that captures the coordinator's own name can lock clients out once their cached address expires;
- extra records outside the MagicDNS domain (clients would never ask their resolver) or naming `control_host`/`admin_host`, and A/AAAA values that do not match their type or are loopback, wildcard, multicast, link-local or reserved;
- duplicates, uppercase names, trailing dots, unknown fields and anything over the limits above.

Resolvers must be reachable from the device wherever it is. A resolver on your office LAN works for a laptop in the office and not from a phone on cellular unless the address is reachable through the mesh, for example through a subnet route. With `override_local_dns: true` every name goes to your resolvers, including `control_host`, so they must resolve it. DNS-over-HTTPS URLs pass validation, but the isolated acceptance has no internet access and does not exercise them. Avoid extra-record names that match a node's MagicDNS name; that combination is not qualified.

Apply a change to a prepared runtime with the complete intended object (`{}` clears all custom DNS):

```sh
python3 scripts/deploy.py update-dns --directory /srv/covee/runtime --config /srv/covee/dns.json
```

The command re-validates, rewrites `headscale.yaml` and `deployment.json` together, and, if the coordinator is running, stops the gateway, console and coordinator and starts them through the same persisted-policy gate as `up`. Public routes stay closed until that check passes. Clients reconnect and receive the new configuration. Plan for a short interruption of enrollment, policy changes and relays. If the restart fails, the previous files are restored and a restart is attempted again. A stopped runtime is only updated and picks the change up at the next `up`. Backups already include both files.

## Reach the private console

The admin listener is published only on host `127.0.0.1:8444`; the public control hostname does not expose the console or coordinator API. Forward it over an independently configured, restricted SSH recovery connection:

```sh
ssh -N -L 8444:127.0.0.1:8444 operator@host.example.com
```

Open `https://localhost:8444` on the operator machine. If using the generated admin certificate, transfer only `internal-ca.crt` through a trusted channel and configure trust manually on that machine. Keep `internal-ca.key` private on the server. Alternatively provide your own admin certificate/key with a matching hostname. Do not disable certificate verification. A different admin hostname needs a matching certificate, exact Entra callback and an operator-managed local resolution/forwarding arrangement.

## Rotate and monitor credentials

The console's coordinator API key expires after 24 hours. Every `up` creates a fresh key; regular rotation must run while the installation stays up:

```sh
python3 scripts/deploy.py rotate-api-key --directory /srv/covee/runtime
```

Rotation atomically replaces the mounted key file and recreates management so its startup-only secret reader loads the new credential. Existing console sessions end. Previously issued keys expire at their original deadline. The example [service](systemd/covee-api-key.service) and [timer](systemd/covee-api-key.timer) schedule rotation every 12 hours after a boot-time run. Edit their user, group, checkout, Python, runtime and Docker access settings for the host; review and install them through your host-management process. Nothing here installs or starts these units; `covee setup` installs equivalent ones on the servers it builds. Monitor rotation failures and credential expiry.

Preparation generates an internal CA valid for 365 days and private leaf certificates valid for 90 days. `renew-certificates` reissues the leaf certificates and, given `--cert` and `--key`, installs a new public certificate for the control host:

```sh
python3 scripts/deploy.py renew-certificates --directory /srv/covee/runtime --cert /srv/covee/tls/fullchain.pem --key /srv/covee/tls/privkey.pem
```

It validates the result, restarts a running runtime once, and restores every previous file if anything fails. It cannot renew the internal CA, and refuses once the CA has fewer than 30 days left. There is no ACME integration here: public certificates are supplied from outside, and `covee cert renew` gets them from Let's Encrypt on the networks the CLI manages. Monitor all certificate and Entra client-secret deadlines, arrange renewal before expiry, and verify the replacement/restart procedure. Also monitor disk/resource limits, failed enrollment, policy/device changes, backups and unexpected public exposure. Container log limits do not replace independently retained security records.

## Encrypt backups and restore into a new directory

Use `age` and `age-keygen` v1.3.2 from `PATH`, or the local tool cache at `.cache/covee/deploy/tools/`. The backup/restore CLI resolves `age` from `PATH` first and then that cache. Create and retain a recovery identity outside the runtime, preferably off-host; use its public `age1…` recipient for backup. The identity must never be included in the runtime or its archive.

The output parent directory must already exist and be private to the operator. The archive filename must be new:

```sh
python3 scripts/deploy.py backup --directory /srv/covee/runtime --output /srv/covee/backups/coordinator.age --recipient age1REPLACE_WITH_PUBLIC_RECIPIENT
```

Backup pauses only services currently running in this runtime's Compose project, streams the complete configuration, secrets, internal CA and persistent state directly into age encryption, and then restarts that original service subset, including on failure. Plan for this service interruption. It creates no plaintext tar archive. Keep encrypted copies and recovery credentials independently of the host/provider and test recovery periodically.

Restore only backups from your trusted store and verify their recorded hashes through an independent trusted channel. Age protects ciphertext confidentiality and integrity; it does not establish the sender's identity. Encryption and decryption have a five-minute streaming deadline, including child processes.

Restore requires a private, operator-owned age identity and a new destination directory. It rejects unsafe archive members and cleans up an unsuccessful new restore. It rebases runtime paths and numeric UID/GID to the restoring non-root operator; it does not start services or provision a replacement host.

```sh
python3 scripts/deploy.py restore --archive /srv/covee/backups/coordinator.age --identity /secure/recovery/covee.agekey --directory /srv/covee/restored-runtime
python3 scripts/deploy.py validate --directory /srv/covee/restored-runtime
```

Before running `up` against restored state, make the recorded image IDs available or rebuild reviewed images, recheck certificates and Entra inputs, and qualify the replacement host's storage, ingress and recovery controls. Verify keys, users, nodes, policy and client behavior before considering recovery complete. A single coordinator with backups is not active-active high availability.

## Local qualification

```sh
python3 scripts/deploy.py check
```

Before the first run on a machine, pull the two pinned helper images it expects to find locally: `docker pull tailscale/tailscale:v1.102.3` and `docker pull python:3.14.0-alpine3.22`. Without them the command stops at its first Docker call with only "docker failed" (its output is suppressed to protect credentials). This command uses a separate disposable Docker project without host-published ports or a host VPN/TUN. It exercises three isolated userspace clients, gateway isolation and new-directory encrypted restoration. Treat its result as local qualification evidence. Live Entra, signed Mac/iPhone acceptance, the chosen provider's public transport/firewall and off-host recovery still require their own evidence in the [production gates](../docs/production-deployment.md#gates-before-public-production).

The acceptance run covers direct and owned-relay traffic, policy changes, [custom DNS](#custom-dns) on the real clients, restart and encrypted restoration into a separate project using the original client identities. Its DNS phase applies each change with `update-dns` against the running stack and uses a throwaway resolver, so it covers delivery, scoping, withdrawal and an upstream outage on Linux userspace clients. It does not cover macOS or iOS resolver integration or DNS-over-HTTPS. Its report records immutable image IDs and checks that the input hashes did not change during the run. Its scope is isolated Docker with disposable token authentication, not live Entra or public hosting. Separately, the identity broker's tests and `python3 scripts/social_check.py` cover signed local provider flows, the actual console's broker role handling, social encrypted backup/restore and four-container bootstrap/discovery.
