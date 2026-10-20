# Isolated compatibility lab

This lab runs Headscale **0.29.4**, eight upstream Tailscale **1.102.3** Linux
userspace clients, and a Python HTTP/SOCKS5 test helper. It establishes a small,
repeatable compatibility baseline. It is not a homegrown replacement or a claim
of full feature parity.

Prerequisites: Docker Engine/Desktop with Linux containers and Docker Compose v2,
Python 3.10+, OpenSSL with `req -addext` support, and enough capacity for ten small containers. The first start pulls
three public container images. All runtime communication stays on an internal
Docker bridge. No public DNS, hosted DERP server, or Tailscale account is used.

From the repository root:

```sh
python3 scripts/lab.py up
python3 scripts/lab.py check
python3 scripts/lab.py status
python3 scripts/lab.py down
```

`check` also starts and bootstraps the lab if necessary. `up` reuses its state and
repairs the deliberately deleted eighth node on the next run. `down` preserves
state. To delete **only this Compose project's state volumes and generated lab certificates**:

```sh
python3 scripts/lab.py down --purge
```

The fixed project name is `covee-lab`; do not use that name for unrelated
Compose stacks. There are no host port bindings, host network access, privileged
containers, TUN devices, or host VPN changes. Containers drop all capabilities.
The probe sidecar shares node2's lab network namespace and provides the HTTP
backend on its loopback interface, so Serve does not require routing privileges.
The SOCKS5 listener is unauthenticated and reachable only inside the lab bridge.
Control and the real embedded DERP server use HTTPS on that bridge. The
orchestrator generates a seven-day lab CA and a server certificate with the
`headscale` DNS SAN under `.cache/covee/lab-tls`. Only the server key reaches Headscale;
clients mount only the CA certificate through `SSL_CERT_FILE`. Certificate
verification stays enabled and host trust is unchanged. Certificates are reused
until near expiry; `down --purge` resets the disposable lab and its certificates.
Headscale also serves local STUN on UDP 3478. No ports are published to the host.
Client logging is disabled with `TS_NO_LOGS_NO_SUPPORT=true`, Headscale logtail and
update checks are off, and public DERP maps are absent. Clients decline DNS
integration. The current checks require a direct path, but the local relay is
also tested separately: node3 uses the upstream test knob
`TS_DEBUG_ALWAYS_USE_DERP=true`, which disables its UDP sockets, while the other
seven clients use normal path selection.

Tailscale Serve routes HTTP by the peer hostname, so the probe sends the
destination's `Self.DNSName` as the HTTP Host header while dialing the overlay
IP. Non-200 responses fail, and only the HTTP status line is included in the
diagnostic.

Version overrides are explicit environment variables:

```sh
HEADSCALE_VERSION=0.29.4 TAILSCALE_VERSION=v1.102.3 python3 scripts/lab.py check
```

`PYTHON_IMAGE_VERSION` defaults to `3.14.0-alpine3.22`. Tags pin versions, not image
digests. The report records actual container image IDs and client/server versions.
If moving to a different version, reset the disposable lab state to avoid treating
a database migration as a compatibility check.

The check writes `.cache/covee/lab/results.json` after each completed check and on failure,
preserving partial successes. It:

1. Creates eight distinct users and verifies one registered client belongs to
   each identity. This is not a load test or a proof of unlimited scale.
2. Requires a direct discovery ping and a TSMP pong through WireGuard.
3. Dials node2's **overlay IP** through node1's userspace SOCKS5 proxy, checks HTTP
   200 and an exact payload on two ports. Repeats discovery, TSMP and HTTP from
   node3 with UDP disabled, requiring the discovery result to identify `DERP(lab)`.
   It then denies one port through policy.
   The other port must still work, and restoring policy must restore the payload.
4. Proves an exact HTTP payload over a fresh TCP connection from node8, then
   deletes node8. Requires inventory removal, withdrawal from node1 and the
   destination node2's peer maps, and node8 entering `NeedsLogin`. A new node8
   SOCKS5 TCP dial must then fail while a new node1 connection still returns the
   exact payload. Node8 remains deleted until the next `up` or `check`, which
   enrolls it again. Already-established session behavior remains **untested**.

Every payload probe opens and closes a new SOCKS5/TCP connection. A SOCKS error
alone does not identify an authorization decision: this Tailscale version returns
the same generic reply for any TCP dial error. The revocation result therefore
combines the failed new dial with successful probes and independent control and
client-state observations. Proxy connection failures, malformed SOCKS replies,
HTTP errors and payload mismatches cannot count as denied connections. A deleted
client's expired self map can omit its stable ID; the check accepts that only
after observing the explicit `NeedsLogin` backend state. Evidence is saved after
each revocation phase, including the successful probe before deletion.

Generated pre-auth keys are single-use, expire after ten minutes, stay in memory
in the orchestrator, and are redacted from its errors. They are briefly passed as
arguments to `tailscale up` inside the lab container. Docker access is an admin
boundary; this is not a secrets-isolation harness.

Not covered: real NAT traversal, subnet routing, exit nodes,
system DNS integration, SSH, file transfer, other operating systems, SSO/SCIM,
device posture, administration UI, high availability, throughput, or full SaaS
feature parity. Nothing here changes a production tailnet.

Implementation references:

- [Headscale 0.29.4 example configuration](https://github.com/juanfont/headscale/blob/v0.29.4/config-example.yaml)
- [Tailscale 1.102.3 ping implementation](https://github.com/tailscale/tailscale/blob/v1.102.3/cmd/tailscale/cli/ping.go)
- [Tailscale 1.102.3 Serve implementation](https://github.com/tailscale/tailscale/blob/v1.102.3/cmd/tailscale/cli/serve_v2.go)
- [Tailscale 1.102.3 TLS verification](https://github.com/tailscale/tailscale/blob/v1.102.3/net/tlsdial/tlsdial.go)
- [Tailscale 1.102.3 TSMP handling before packet ACLs](https://github.com/tailscale/tailscale/blob/v1.102.3/net/tstun/wrap.go#L1027)
- [Tailscale 1.102.3 Serve HTTP Host routing](https://github.com/tailscale/tailscale/blob/v1.102.3/ipn/ipnlocal/serve.go#L750)
- [Tailscale 1.102.3 forced DERP test knob](https://github.com/tailscale/tailscale/blob/v1.102.3/wgengine/magicsock/debugknobs.go#L34)
- [Headscale deleted-node expired-self response](https://github.com/juanfont/headscale/blob/8106636c7f8d0cf8c9d4fb0beae94415069b768b/hscontrol/noise.go#L722-L753)
- [Tailscale 1.102.3 NeedsLogin engine deconfiguration](https://github.com/tailscale/tailscale/blob/53a0d659afa51835dd7a9283873cca44261454f8/ipn/ipnlocal/local.go#L6320-L6332)
- [Tailscale 1.102.3 generic SOCKS TCP dial failure](https://github.com/tailscale/tailscale/blob/v1.102.3/net/socks5/socks5.go#L194-L207)
