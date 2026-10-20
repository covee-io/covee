# Portable production deployment

This is the contract the Covee server runtime is built to: what it needs from a host, what it exposes, and how it is hardened. `covee setup` applies it on a server it prepares ([CLI](cli.md)); [operations and commands](../deploy/README.md) cover preparation, validation, startup, bounded credential rotation and encrypted backup/restore by hand. Local qualification is separate from production certification. The isolated `lab/` configuration must not be reused as a public deployment.

The runtime must be independent of Azure, DigitalOcean or another provider. Provider-specific provisioning supplies compute, addressing, firewall rules, storage and recovery access. The coordinator, management service, policy and OIDC configuration must remain portable between those providers. Entra ID does not require Azure hosting.

The local deployment acceptance (`python3 scripts/deploy.py check`) runs the runtime in an isolated Docker project with three real clients enrolled through the TLS ingress. It checks public API/diagnostic denial, private administration and CSRF, default deny, direct and owned-relay payloads, policy withdrawal and restoration, control reconnection after a restart, and encrypted restoration: the original clients reconnect to the restored instance without enrolling again. Its report records image IDs and input hashes and verifies cleanup. The [coordinator build](../deploy/headscale/README.md) records pinned source, patches, toolchain, binary and selected security regressions in its manifest. These are isolated local checks; they use neither live Entra nor a public host.

An optional fourth container provides [Entra/Google/Apple federation](social-login.md). Its local tests and runtime smoke cover signed provider fixtures, console authorization, private credential backup/restore and actual Headscale/console discovery through identity-only startup. They do not cover real provider accounts, Apple's browser Origin/SameSite behavior, provider-driven revocation/deletion or signed native VPN flows. Two further optional containers join the network as tagged devices, each unprivileged in user space: the in-network console device and the gateway device ([CLI](cli.md)).

## Runtime and provider boundary

The package builds three OCI images: patched Headscale, the Go management console, and a Go TLS gateway. Compose runs one instance of each on a supported Linux host. The public gateway serves only client protocols; its separate administration listener is published on host loopback. Internal connections use verified TLS. Kubernetes or managed-container adapters must preserve the same contract. Containers alone do not establish host or application security.

| Requirement | Deployment contract |
| --- | --- |
| Public origin | A stable owned HTTPS hostname on TCP 443, including after host restart or replacement. |
| Client transport | Direct TLS or a verified proxy preserving long-lived client connections and the custom `POST /ts2021` upgrade. GET upgrades must also work for browser/WASM compatibility. Ordinary WebSocket support is insufficient evidence. |
| Database storage | Persistent local filesystem or attached block disk with correct SQLite locking, shared-memory and durable-write semantics. The current WAL database must not use an NFS/SMB share. |
| Relay networking | Public TCP 443 and UDP 3478 for the embedded DERP/STUN profile. A coordinator-only profile may use separately hosted compatible relays. |
| Administration | A private authenticated management path and an independent recovery path. Public client connectivity must not imply public admin connectivity. |
| Runtime isolation | Non-root processes, restricted writes, no privileged containers, host network, Docker socket or TUN access for these server components. |
| Continuity | State survives process/container replacement; encrypted off-host backups and tested restoration are mandatory. |
| Configuration | Public origin, OIDC issuer/client ID, secret file locations, persistent storage, relay map, policy and limits are explicit inputs. No provider credentials are application dependencies. |

The [Headscale requirements](https://headscale.net/stable/setup/requirements/) describe the public ports and durable state. [SQLite WAL documentation](https://sqlite.org/wal.html) excludes network filesystems; a network-attached **block disk** formatted locally is different from a network **file share**. Its suitability still needs an actual recovery test.

The [Headscale proxy documentation](https://headscale.net/stable/ref/integration/reverse-proxy/) describes the custom upgrade, but labels itself community-maintained and unverified. Qualify the selected proxy with the real pinned clients; do not infer compatibility from its feature list.

## Public exposure

Publish only the TLS ingress and the optional embedded STUN UDP socket. Keep the raw coordinator listener, management listener, gRPC, metrics, debug interfaces, database and container runtime unpublished. Port 80 is optional only for a deliberately selected certificate challenge; DNS-01 or TLS-ALPN-01 can avoid that requirement where supported.

Enforce this at both provider and host/container-network boundaries, covering IPv4 and IPv6. Docker-published traffic can bypass ordinary UFW filtering, so UFW alone is not proof of isolation. Use minimal port publication and tested Docker-aware forwarding controls. Do not disable Docker's firewall management as a shortcut. [Docker firewall behavior](https://docs.docker.com/engine/network/packet-filtering-firewalls/)

Headscale mounts its authenticated administrative API on the same HTTP listener as its client endpoints. TLS passthrough alone therefore does not isolate that API. The public ingress needs a default-deny method/path allowlist, or a reviewed upstream change that separates those listeners. The unfiltered backend must remain private in either design.

The initial public allowlist is derived from pinned `hscontrol/app.go`, not from a blanket reverse proxy of `/`:

| Methods | Paths | Purpose |
| --- | --- | --- |
| GET, POST | `/ts2021` | Client control upgrade |
| GET | `/key` | Coordinator public key |
| GET | `/register/{auth_id}`, `/auth/{auth_id}` | Enrollment and reauthentication |
| GET | `/oidc/callback` | Identity-provider callback |
| GET, POST | `/register/confirm/{auth_id}` | Enrollment confirmation |
| HEAD | `/machine/ping-response` | Client connectivity response |
| GET | `/derp` | Embedded relay upgrade, when enabled |
| GET, HEAD | `/derp/probe`, `/derp/latency-check` | Relay probes, when enabled |
| GET | `/bootstrap-dns` | Relay DNS bootstrap, when enabled |

Match only expected path segments and methods. Verify proxy/backend agreement on encoded paths, double slashes and normalization. Preserve necessary query parameters and upgrades without permitting arbitrary backend paths. Keep `/api`, `/swagger`, `/version`, `/health`, `/metrics`, debug paths and the management console private. For the embedded relay, `/verify` is handled in process and does not need public exposure; an external relay needs a separately reviewed authenticated verification design.

Do not place browser SSO preauthentication in front of the client control protocol. Entra authentication belongs in the coordinator's OIDC enrollment flow. Trust forwarded client headers only from explicitly configured proxy addresses, replacing client-supplied forwarding headers at ingress.

### Exposure inside the control channel

The pinned Headscale source accepts an unregistered machine key at the Noise handshake and mounts `/metrics` inside that encrypted connection (`hscontrol/noise.go`, the router inside `NoiseUpgradeHandler`). An outer HTTP path filter cannot inspect this route after `/ts2021` is upgraded. Keeping TCP 9090 private does not resolve this finding.

The [maintained downstream patchset](../deploy/headscale/README.md) removes this route. Its race-tested regression completes an actual Noise handshake with a never-enrolled machine key and requires inner `/metrics` and `/metrics/` requests to return 404. The patch is applied to a disposable copy of the locked upstream source. The outer gateway also rejects public administrative/diagnostic paths, including requests carrying a valid backend credential.

## Host and container controls

- Use a supported minimal Linux image and a dedicated service account. Disable password/root SSH login. Administrative SSH must use a private route or a narrow operator allowlist; no unrestricted public TCP 22.
- Retain provider-console or other independent recovery access. Recovery must not depend solely on the network this coordinator controls.
- Pin runtime artifacts by immutable digest and record source/build provenance. Scan dependencies and images, review advisories, and qualify upgrades before rollout. Schedule OS security patching and reboots with recovery and client-reconnect tests.
- Run coordinator, ingress and management as non-root with read-only root filesystems, all unnecessary capabilities dropped, `no-new-privileges`, default seccomp or a tested stricter profile, bounded CPU/memory/PIDs/file descriptors, and bounded writable tmpfs.
- Grant write access only to the component's own state. Pre-create numeric-UID-owned state directories with restrictive permissions. Successful execution of a non-root `version` command does not prove full startup or persistence permissions.
- Mount secrets read-only instead of putting values in Compose, source control, image layers, command arguments or generated reports. The management service accepts `COVEE_ADMIN_TOKEN_FILE` and `COVEE_HEADSCALE_API_KEY_FILE`; exactly one source is permitted for each secret.
- Prepare actual source-file ownership and access. Compose file-backed secrets do not enforce requested `uid`, `gid` and `mode` settings. [Compose secret behavior](https://docs.docker.com/reference/compose-file/services/#secrets)
- Verify TLS on both public ingress and management-to-coordinator connections. If ingress terminates public TLS, use verified internal TLS for upstream connections. Do not use `COVEE_ALLOW_HTTP=true` or disable certificate verification in production.
- Keep provider credentials outside the runtime. Where an adapter needs provider APIs, use narrowly scoped identities and separate provisioning/recovery permissions from application operation.

Runtime images default to UID/GID 10001. Preparation uses the dedicated non-root operator's actual numeric UID/GID for all three containers and private bind-mounted files, avoiding a privileged initialization container. UID 0 is rejected. On Linux, create a dedicated service account, preferably UID 10001. Local Mac Docker qualification uses the local operator's numeric identity; this does not qualify a chosen Linux host's ownership, storage or firewall. The `lab/` Headscale, the upstream image run as root, is a separate disposable configuration.

## Identity, policy and administration

Use a tenant-specific Entra issuer, PKCE S256 and explicit enrollment restrictions. Require OIDC availability at coordinator startup rather than falling back to a different enrollment method. Define node expiration deliberately; the current lab's default is no expiration. Keep the confidential application's secret on the server, never in Apple apps.

OIDC identifies users; network authorization remains an explicit policy decision. Install and test a policy that denies access unless intentionally granted before opening enrollment. Group admission is not network-policy group synchronization, and removing or disabling an Entra identity does not currently revoke its enrolled devices automatically. Build and test suspension/revocation reconciliation, including behavior during control-plane outages. Handle group-token overage deliberately. [Headscale OIDC behavior and limitations](https://headscale.net/stable/ref/oidc/)

The management console supports OIDC with exact `Covee.Admin` and `Covee.Reader` app roles, individual sessions and authenticated issuer/subject/role in durable audit intent/result records. OIDC mode rejects shared tokens and bearer authentication. Signed local provider tests cover issuer/audience/signature, nonce, PKCE, browser-bound single-use state, expiry, reader mutation denial and CSRF. This is not live Entra evidence. Administration remains private regardless of its authentication mode.

Use separate confidential Entra applications for coordinator enrollment and the console. Register their exact callback URLs and require user assignment. Coordinator group admission and console app roles are independent. Sessions last at most one hour and no longer than the ID token; restarting management signs everyone out. There is no Graph/SCIM reconciliation, refresh-token session extension, continuous-access evaluation or back-channel logout. Removing an Entra assignment does not immediately revoke an existing console session or an enrolled node.

The console login limiter uses the socket peer address, so users share the gateway's rate bucket. Do not interpret it as a per-user or per-public-IP limiter. The gateway separately bounds administration and public sockets/streams, TLS/header time, body size and upstream connections without a response write timeout that would end long-lived control streams. Internet bandwidth/DDoS protection remains a provider responsibility.

MFA and Conditional Access can govern enrollment, but do not establish continuous device-posture enforcement. The Apple provider abandons a start after 90 seconds, or after 10 minutes once the coordinator has asked the person to sign in in the browser; MFA and enrollment on signed devices must fit within that window.

## DNS

The coordinator always serves MagicDNS for `dns_base_domain`. Global, split and search-domain resolvers and extra records are an optional, validated `dns` deployment setting, applied with `update-dns`; see [Custom DNS in the operations guide](../deploy/README.md#custom-dns). The setting is sent to every enrolled device, so it carries no credentials, and validation rejects values Headscale would only log or forward unusably. Resolver choice is an availability and privacy decision: with `override_local_dns` enabled, every name a device does not answer locally, including the coordinator's, depends on the resolvers you list. DNS-over-HTTPS is accepted but not covered by the isolated acceptance, and OS resolver integration on macOS and iOS is a separate native result.

## Storage, logging and recovery

Persist the database, Noise/DERP private keys, configuration/policy references and management audit. Do not replace server keys silently during container recreation. Treat state and backups as sensitive control-plane material. Use encrypted storage and encrypted backups with recovery credentials available independently of the failed host/provider.

Initially use a documented stopped-service backup, or a correctly implemented SQLite online-backup procedure. Copying a live `db.sqlite` alone is not a consistent WAL backup. Restore into a clean isolated instance and verify the intended keys, identities, addresses, policy and client behavior before accepting the recovery procedure. A single instance with restore capability is not active-active high availability.

Do not log authorization headers, cookies, enrollment secrets, OIDC codes/state, or raw callback query strings. Enrollment IDs in paths also require redaction. Bound logs and audit storage, forward security-relevant events to independently controlled storage, and define retention. The current local audit is not tamper-proof against a compromised host administrator.

Monitor certificate/secret expiry, enrollment failures, resource/disk exhaustion, repeated connection failures, backup failures, unexpected public exposure and policy/device changes. Review internet-volume limits and provider DDoS protection for both TCP and UDP; application limits do not prevent every upstream bandwidth attack.

## Provider compatibility

| Provider/profile | Assessment |
| --- | --- |
| Azure VM, DigitalOcean Droplet, ordinary Linux VPS, a VM at home | Appropriate when they satisfy the same ingress, storage, isolation and recovery contract. `covee setup` accepts any such server running Ubuntu 24.04 on amd64. |
| Existing Kubernetes cluster | Candidate with one coordinator replica, suitable block storage and verified client/relay ingress. Rescheduling alone does not establish coordinator HA. |
| Runpod Pods | The combined profile cannot run unchanged: documented lack of UDP, changing public TCP mappings after resets, and an HTTP proxy whose custom-upgrade compatibility is unproven. A provider adapter would need stable ingress, separate relay/STUN and qualified durable storage. |
| Managed serverless containers | Conditional: validate transport, persistence, replacement lifecycle and secret/key durability. Keep connection-serving capacity available. |
| Invocation functions | Useful for future directory/background jobs; not a drop-in runtime for the current Headscale process. |

DigitalOcean documents [TCP/UDP firewall rules](https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/) and [attached block volumes](https://docs.digitalocean.com/products/volumes/how-to/create/). Runpod documents [no Pod UDP and changing TCP mappings](https://docs.runpod.io/pods/configuration/expose-ports), plus [storage lifecycles](https://docs.runpod.io/pods/storage/types/). Its local volume survives stop/restart but not Pod termination; network-volume database semantics have not been qualified. Do not substitute an unverified network volume for the current SQLite storage.

## Gates before public production

1. Continue dependency/advisory review of coordinator, engine, toolchain and image roots. The downstream coordinator applies the three [source-confirmed fixes](control-plane.md#production-security-follow-up), with pinned provenance, a selected race-test suite and mandatory regression checks. This is not an exhaustive security audit or Tailscale SSH product acceptance.
2. Preserve the tested inner Noise diagnostic removal and public gateway allowlist through upgrades. Real POST/GET custom upgrades and pipelined protocol bytes have regression coverage; qualify actual external client paths on the selected host.
3. Verify the chosen host's UID ownership, persistent block storage, bounded resources, image provenance and private mounts. Check IPv4 and IPv6 exposure from outside the deployment, including Docker-published ports and operator access.
4. Configure and verify live Entra enrollment and console app roles, rejected identities, group overage, MFA, reauthentication and device suspension/revocation. Local signed-provider tests do not prove the tenant's policies or Apple browser lifecycle.
5. Verify certificate renewal, secret rotation, upgrades and independent off-host recovery. The backup tool pauses only the selected runtime, encrypts directly with age, and restores into a new directory. Arrange monitoring and the supplied 12-hour API-key rotation timer; leaf certificates expire after 90 days and internal CA after 365 days. Certificate renewal is not automated in this build.
6. Complete signed Mac/iPhone acceptance, real-world NAT traversal, capacity and operational observability. Check that MFA and enrollment fit within the native provider's sign-in window (10 minutes once browser sign-in starts).
7. Qualify the chosen resolvers on the real devices: split-domain answers, no leakage of other names, behavior with each resolver stopped, and the coordinator's own name under `override_local_dns`. The isolated acceptance proves delivery and client behavior on Linux userspace clients with a throwaway resolver, not macOS or iOS resolver integration.
8. Record provider-specific addressing, storage, firewall and independent recovery evidence. Perform only scoped authorized exposure checks against the deployed target.

Missing tenant/domain/provider inputs do not justify permissive defaults. The package is a tested foundation for a compatible host; it must not be described as a qualified public production deployment until the external gates have evidence.
