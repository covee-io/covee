# Covee feature parity inventory

This is an initial inventory of **44 feature families** of Tailscale's product, each with a stable ID, plane, scope and primary official source, measured against the pinned versions below. A documentation citation, an imported open-source component or a passing basic mesh test does not establish product parity. **No row is verified yet**; two DNS rows are partial ([what is verified](#what-is-verified)).

## Evidence and version boundary

| Item | Pinned or observed version | Meaning |
| --- | --- | --- |
| Reference client | Tailscale **1.102.3** | The initial compatibility baseline. |
| Open client protocol | [v1.102.3 tailcfg](https://github.com/tailscale/tailscale/blob/v1.102.3/tailcfg/tailcfg.go), capability version **142** | Wire-format and feature negotiation must be checked against this source. |
| Newer upstream release | **1.104.1**, October 7, 2026 | Separate candidate for later compatibility work, not an automatic baseline upgrade. |
| Self-hosted control-plane baseline | [Headscale v0.29.4](https://github.com/juanfont/headscale/releases/tag/v0.29.4), September 23, 2026; commit `8106636c7f8d0cf8c9d4fb0beae94415069b768b` | A component to evaluate in the lab. Its supported feature list is not Covee test evidence. |

Current documentation is broader than any one release. For example, the [v1.104.1 changelog](https://tailscale.com/changelog) lists client-side netmap caching for Linux and Windows. Do not infer equivalent restart behavior for v1.102.3. Documentation also describes [MagicRoute beta](https://tailscale.com/docs/features/magicroute), [declarative node sharing alpha](https://tailscale.com/docs/features/declarative-node-sharing) and adjacent products that require their own version, platform and service eligibility checks.

The two scopes follow two documentation tracks:

- **core, a baseline candidate:** a target capability to qualify against client 1.102.3, its platform and the chosen server. The label does not assert that every current documented mode existed in that release.
- **extension, from current documentation:** an evolving capability or adjacent product kept separate from the 1.102.3 baseline. Inclusion does not establish a minimum supported client version or remove it from the requested parity scope.

Tailscale publishes its core daemon, CLI, client-side control protocol and DERP implementation; its hosted coordination server is not open source. This makes source-based protocol work possible, and Tailscale's public documentation describes platform behavior. [Open source at Tailscale](https://tailscale.com/opensource).

## Requirements and acceptance

`core` and `extension` are planning categories, not claims of implementation. An extension still needs qualification before any claim of parity with the corresponding Tailscale product. Several rows intentionally cover related modes; split them into narrower stable IDs when test fixtures expose different eligibility or behavior.

| Stable ID | Feature and primary official source | Plane | Scope | Covee status |
| --- | --- | --- | --- | --- |
| `identity.enrollment` | [SSO and custom OIDC enrollment with user and device approval](https://tailscale.com/docs/integrations/identity) | control | core | unverified |
| `identity.lifecycle` | [Auth keys, node-key expiry, tagged and ephemeral device lifecycle](https://tailscale.com/docs/features/access-control/auth-keys) | control | core | unverified |
| `identity.provisioning` | [SCIM user and group provisioning](https://tailscale.com/docs/features/user-group-provisioning) | control | core | unverified |
| `identity.workload_federation` | [Workload identity federation for enrollment and API access](https://tailscale.com/docs/features/workload-identity-federation) | control | core | unverified |
| `network.wireguard_addresses` | [End-to-end encrypted dual-stack mesh and stable node addresses](https://tailscale.com/docs/concepts/tailscale-osi) | data | core | unverified |
| `network.nat_direct` | [Direct peer discovery and NAT traversal](https://tailscale.com/docs/reference/device-connectivity) | data | core | unverified |
| `network.derp` | [Self-hosted DERP discovery and encrypted relay fallback](https://tailscale.com/docs/reference/derp-servers) | data | core | unverified |
| `network.peer_relay` | [Policy-controlled peer relays](https://tailscale.com/docs/features/peer-relay) | data | core | unverified |
| `network.mobility_offline` | [Network movement, sleep recovery and control-plane outage behavior](https://tailscale.com/docs/reference/coordination-server-down) | client | core | unverified |
| `routing.subnet` | [Subnet routing, site-to-site networking and overlapping networks](https://tailscale.com/docs/features/subnet-routers) | data | core | unverified |
| `routing.exit` | [Exit nodes, client selection and LAN access controls](https://tailscale.com/docs/features/exit-nodes) | data | core | unverified |
| `routing.ha` | [Subnet and connector failover with route selection](https://tailscale.com/kb/1115/subnet-failover/) | control | core | unverified |
| `routing.app_connectors` | [Domain-based app connectors and route discovery](https://tailscale.com/docs/features/app-connectors) | control | core | unverified |
| `routing.magicroute` | [MagicRoute scoring and regional route selection](https://tailscale.com/docs/features/magicroute) | control | extension | unverified |
| `dns.magicdns` | [Automatic node naming and MagicDNS resolution](https://tailscale.com/docs/features/magicdns) | control | core | partial |
| `dns.resolvers` | [Global, split and search-domain DNS with resolver behavior](https://tailscale.com/docs/reference/dns-in-tailscale) | client | core | partial |
| `dns.https_certificates` | [Owned-domain TLS certificate issuance and renewal](https://tailscale.com/docs/how-to/set-up-https-certificates) | control | core | unverified |
| `policy.acl_grants` | [ACLs and grants with network, application and via permissions](https://tailscale.com/docs/features/access-control/acls) | control | core | unverified |
| `policy.selectors_tags` | [Groups, tags, autogroups, IP sets and automatic approvers](https://tailscale.com/docs/reference/syntax/policy-file) | control | core | unverified |
| `policy.posture` | [Built-in, custom and integrated device posture](https://tailscale.com/docs/features/device-posture) | control | core | unverified |
| `policy.validation` | [Policy tests, SSH tests, preview and atomic policy updates](https://tailscale.com/docs/features/tailnet-policy-file/manage-tailnet-policies) | control | core | unverified |
| `ssh.access` | [Tailscale SSH identity and local-account authorization](https://tailscale.com/docs/features/tailscale-ssh) | application | core | unverified |
| `ssh.check` | [SSH check mode and browser reauthentication](https://tailscale.com/docs/features/tailscale-ssh) | control | core | unverified |
| `ssh.recording` | [SSH session recording with enforced-recorder policy](https://tailscale.com/kb/1246/tailscale-ssh-session-recording/) | application | core | unverified |
| `files.taildrop` | [Taildrop file transfer between eligible personal devices](https://tailscale.com/docs/features/taildrop) | application | core | unverified |
| `files.taildrive` | [Taildrive directory sharing with read and write capabilities](https://tailscale.com/docs/features/taildrive) | application | core | unverified |
| `services.serve` | [Private Serve HTTP, HTTPS and TCP forwarding](https://tailscale.com/docs/features/tailscale-serve) | application | core | unverified |
| `services.funnel` | [Public Funnel ingress and controlled exposure](https://tailscale.com/docs/features/tailscale-funnel) | application | core | unverified |
| `trust.tailnet_lock` | [Tailnet Lock signatures, trusted signers and recovery](https://tailscale.com/docs/features/tailnet-lock) | control | core | unverified |
| `services.vip` | [Named Tailscale Services with stable addresses and multiple hosts](https://tailscale.com/docs/features/tailscale-services) | control | core | unverified |
| `sharing.link` | [Link-based cross-tailnet node sharing](https://tailscale.com/kb/1084/sharing/) | control | core | unverified |
| `sharing.declarative` | [Declarative cross-tailnet sharing with mutual policy opt-in](https://tailscale.com/docs/features/declarative-node-sharing) | control | extension | unverified |
| `kubernetes.operator` | [Kubernetes ingress, egress and highly available proxy integration](https://tailscale.com/docs/kubernetes-operator) | application | core | unverified |
| `kubernetes.access_recording` | [Kubernetes API identity, RBAC and session/request recording](https://tailscale.com/docs/kubernetes-operator/api-server-access) | application | core | unverified |
| `automation.api_webhooks` | [Scoped APIs, OAuth clients/apps, GitOps and signed webhooks](https://tailscale.com/docs/reference/tailscale-api) | control | core | unverified |
| `operations.logs` | [Configuration audit, network flow and log streaming](https://tailscale.com/docs/features/logging) | operations | core | unverified |
| `operations.coordinator_ha` | [Coordinator durability, recovery and outage-compatible clients](https://tailscale.com/docs/reference/coordination-server-down) | operations | core | unverified |
| `platform.clients_packaging` | [Platform clients, installers, updates and managed settings](https://tailscale.com/docs/install) | client | core | unverified |
| `embedding.tsnet_userspace` | [tsnet embedding and userspace SOCKS5/HTTP networking](https://tailscale.com/docs/features/tsnet) | client | core | unverified |
| `operations.client_diagnostics` | [CLI, local web UI, netcheck, status and client metrics](https://tailscale.com/kb/1080/cli) | client | core | unverified |
| `identity.tsidp` | [Tailnet-derived OIDC identity provider for applications](https://tailscale.com/docs/features/tsidp) | application | extension | unverified |
| `extension.pam` | [Privileged access management for protocol-aware resources](https://tailscale.com/docs/privileged-access-management) | application | extension | unverified |
| `extension.aperture` | [Aperture AI gateway, governance and agent identity](https://tailscale.com/docs/aperture/what-is-aperture) | application | extension | unverified |
| `extension.mullvad` | [Third-party privacy exit-node integration](https://tailscale.com/docs/features/exit-nodes/mullvad-exit-nodes) | application | extension | unverified |

## What is verified

Two rows are **partial**. Both come from Covee's isolated deployment acceptance (`python3 scripts/deploy.py check`), which runs three real Tailscale 1.102.3 Linux userspace clients against the Covee coordinator, with a throwaway resolver, in a Docker project without internet access.

- `dns.magicdns`: a peer's fully qualified MagicDNS name resolves to its address, is still answered locally when custom resolvers are set, and keeps resolving while an upstream resolver is down. Not yet verified: short names and search-domain expansion by an OS resolver; name collisions, renaming or removing a node, and cache expiry; IPv6 answers; behavior during coordinator loss, restarts and reconnection; macOS and iOS.
- `dns.resolvers`: global, fallback, split and search-domain settings and extra records reach every client and behave as configured. Split-domain queries go only to their resolver and other names do not leak to it; a withdrawn route stops being used; resolution recovers after an upstream outage; the settings survive a coordinator restart and an encrypted restore. Not yet verified: macOS and iOS resolver integration; DNS-over-HTTPS; fallback resolvers behind an exit node; `--accept-dns=false` and conflicting or overlapping suffixes; resolver reachability from real networks such as cellular, TCP fallback for large answers and IPv6 resolvers; behavior during coordinator loss.

Every other row is unverified.

## Acceptance obligations

Each row needs four kinds of check before it can be called verified: success, denial, revocation and outage. Each check describes a test obligation, not a completed test. A meaningful result must include client and server versions and hashes, the network topology, the policy revision, actions, expected and observed outcomes, supporting logs or captures and cleanup.

Success alone is insufficient. The same fixture must exercise an unauthorized identity or operation, withdrawal of an existing permission and a dependency failure where relevant. Revocation timing must distinguish clients that received an update from disconnected clients that still hold old state.

Some superficially similar actions have different documented effects:

- Revoking an [auth key](https://tailscale.com/docs/features/access-control/auth-keys) prevents further use of that enrollment credential; it does not deauthorize already enrolled nodes. Node removal, key expiry and policy withdrawal need separate checks.
- Disabling [HTTPS issuance](https://tailscale.com/docs/how-to/set-up-https-certificates) does not revoke existing certificates. Network permission is a separate control.
- [SCIM suspension and deletion](https://tailscale.com/docs/features/user-group-provisioning) map differently across providers. Test the selected provider and separately measure retained device-key access.
- [DERP](https://tailscale.com/docs/reference/derp-servers) relays encrypted packets. Relay reachability must not bypass endpoint access policy or reveal application plaintext.

Equivalent DNS, certificates, relays and public ingress must use infrastructure and domains we control. This inventory does not assume access to Tailscale-owned `ts.net` names, its hosted control plane or its public ingress infrastructure.

## Headscale baseline and unresolved gaps

Headscale describes itself as a self-hosted coordination alternative for projects and labs. The following is an assessment of upstream documentation and source, **not evidence that Covee implements the feature**. The pinned [feature list](https://github.com/juanfont/headscale/blob/v0.29.4/docs/about/features.md), [policy reference](https://github.com/juanfont/headscale/blob/v0.29.4/docs/ref/policy.md) and [changelog](https://github.com/juanfont/headscale/blob/v0.29.4/CHANGELOG.md) define the baseline.

| Area | Source-confirmed upstream position | Covee obligation |
| --- | --- | --- |
| Enrollment, OIDC, DNS, tags, IPv4/IPv6 and ephemeral nodes | Listed as supported. OIDC groups cannot be used directly in ACLs. | Verify identity mapping, lifecycle and the selected group-provisioning design. |
| Subnet/exit routing, route filtering, DERP and peer relays | Listed as supported; [route docs](https://github.com/juanfont/headscale/blob/v0.29.4/docs/ref/routes.md) describe HA routing. | Test failover and route withdrawal; subnet-router HA does not prove coordinator HA. |
| ACLs and grants | Supported, including app capabilities and via routing; autogroup coverage is partial. | Differential tests for selectors, capabilities, visibility and packet-filter behavior. |
| Taildrop and Taildrive | Listed as supported. | Verify client eligibility, permissions, transfers and interruption behavior. |
| SSH and check mode | Supported; check-mode identity constraints are documented. Policy tests and SSH tests are beta. | Test rejection, reauthentication, policy withdrawal and recorder integration independently. |
| Device posture and IP sets | Explicitly unsupported by the pinned policy reference. | Separate implementation and tests are required for parity. |
| Serve | Pinned feature list marks a gap; [issue 1921](https://github.com/juanfont/headscale/issues/1921) concerns HTTPS support and reports HTTP behavior. | Do not collapse partial HTTP operation into full Serve and certificate parity. |
| Funnel | Pinned feature list marks unsupported; [issue 1040](https://github.com/juanfont/headscale/issues/1040) is closed as not planned. | Design and validate owned public ingress separately. |
| Network flow logs | Pinned feature list marks unsupported; [issue 1687](https://github.com/juanfont/headscale/issues/1687) tracks the request. | Implement flow collection, access control, storage and export obligations separately. |
| Tailnet Lock | [Issue 1307](https://github.com/juanfont/headscale/issues/1307) remains an open feature-gap request. | Treat trust signatures, signer changes and recovery as unverified work. |
| Other control endpoints | Pinned [noise.go](https://github.com/juanfont/headscale/blob/v0.29.4/hscontrol/noise.go) routes `/machine/whoami`, `/machine/set-dns`, `/machine/set-device-attr`, `/machine/audit-log`, `/machine/id-token`, `/machine/feature/query`, `/machine/update-health` and `/machine/c2n` to HTTP 501. | Trace each endpoint to its client consumer before determining feature impact; the names alone do not establish the complete missing behavior. |
| Coordinator HA, cross-tailnet sharing, Services/VIPs, SCIM and workload federation | Complete parity was not established by the inspected baseline sources. This is not a claim that no related implementation exists. | Inspect relevant code and build isolated fixtures before selecting an implementation strategy. |

Track later upstream fixes separately from this release. In particular, reported follow-up work on [SSH policy withdrawal](https://github.com/juanfont/headscale/pull/3517), [repeated rejected checks](https://github.com/juanfont/headscale/pull/3526) and [disabled logtail](https://github.com/juanfont/headscale/pull/3522) warrants focused regression fixtures. A later fix is not present merely because the repository's default branch contains it, and its practical effect on our pinned topology remains unverified.

## Verification sequence

1. Establish a reproducible isolated lab with pinned binaries, owned control and relay endpoints, two users and at least two clients. Record the versions actually running.
2. Verify enrollment, encrypted mesh, explicit deny policy, node removal, direct/DERP/peer-relay paths and restart behavior. Test real application traffic; discovery pings alone do not prove application authorization.
3. Add subnet and exit routing, DNS, tag ownership, grants and SSH. Measure permission withdrawal and fail-close behavior under dependency failure.
4. Add certificate issuance, files, Serve, public ingress, identity integrations, Services, sharing and Kubernetes as separate fixtures.
5. Run capacity and recovery tests independently of functional parity, then qualify additional client versions and platforms.
6. Expand adjacent products and preview modes using explicit version-qualified fixtures; preserve separate results for modes unavailable on the baseline.

A row can become **verified** only when its selected modes pass all applicable checks and the evidence identifies the tested boundary. **Partial** means only some modes or platforms passed. **Blocked** records a concrete missing dependency or upstream incompatibility. No row is verified yet; the two partial rows are described [above](#what-is-verified).

## Open scope

This is not a complete enumeration of every setting, API endpoint, managed-device control, platform UI, integration, preview, limit or support workflow. Areas that need further decomposition include 4via6 overlap routing, IP pools, local account mapping, posture-provider freshness, OAuth app consent, API compatibility, admin roles and interface workflows, network lockdown, platform-specific MDM policies, client update channels, container/NAS packaging and mobile background behavior.

Covee sets no limit on the number of users or devices: it owns its identity and authorization rules. That still leaves finite resources: identity count, node count, policy size, map-update fan-out, concurrent sessions, relay bandwidth, log retention and recovery time must have measured operating envelopes.

Absolute feature parity remains an objective requiring a versioned scope and evidence. This inventory makes gaps reviewable; it does not claim that the objective has been achieved.
