# Native Apple engine investigation and implementation

Covee has a real embedded packet engine in `native/engine`, pinned to `tailscale.com v1.102.3`, commit `53a0d659afa51835dd7a9283873cca44261454f8`. The Go module checksum is `h1:M1czCAtMuIcg+2Z+FBPbJyAk3ZEQGEFKnvHthtE1c6M=`. This module requires Go 1.26.6 and is separate from the management service module.

The native engine is a foundation for our Mac and iPhone clients. Compilation and local packet tests do not establish signed Network Extension execution, Apple device acceptance, or full client parity.

## Reusable engine boundary

Tailscale's common daemon, coordination and WireGuard code is open source; the Apple GUI wrappers are not included in that repository. Our Swift clients therefore provide their own application, VPN lifecycle and platform integration. [Upstream repository](https://github.com/tailscale/tailscale/tree/v1.102.3)

The implementation uses `wgengine.NewUserspaceEngine` with a custom `tun.Device`, `router.CallbackRouter` and `ipnlocal.NewLocalBackend`. `CallbackRouter` implements the router and DNS configuration interfaces and gives the adapter the engine's calculated local addresses, included routes, excluded routes, DNS servers, matching/search domains and MTU. This preserves the engine's routing and DNS decisions. [Engine configuration](https://github.com/tailscale/tailscale/blob/v1.102.3/wgengine/userspace.go#L169), [callback router](https://github.com/tailscale/tailscale/blob/v1.102.3/wgengine/router/callback.go), [backend initialization](https://github.com/tailscale/tailscale/blob/v1.102.3/ipn/ipnlocal/local.go#L541)

`tsnet.Server.Tun` is another public packet boundary at this pin: providing a real TUN changes its handling so unclaimed packets can reach that device. Its default mode is userspace application networking. Our implementation uses the lower-level engine because `tsnet.Server` does not expose the engine's OS router/DNS callbacks. The separate `libtailscale` C library wraps userspace application networking and does not supply this Apple system VPN bridge. [Pinned tsnet implementation](https://github.com/tailscale/tailscale/blob/v1.102.3/tsnet/tsnet.go#L306), [libtailscale](https://github.com/tailscale/libtailscale)

## Apple integration

Apple's `NEPacketTunnelProvider.packetFlow` supplies raw IP packets selected by the tunnel's configured routes, and injects decrypted packets back into the OS. Swift passes those packets to our C ABI without a utun address-family header. The provider must apply `NEPacketTunnelNetworkSettings` and await its completion before reporting success. The Network Extension entitlement is required. [Packet tunnel provider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider), [packet flow](https://developer.apple.com/documentation/networkextension/nepackettunnelflow)

For a directly distributed Mac client, the packet tunnel is packaged as a system extension. The iOS client uses an app extension. The Mac system extension uses `packet-tunnel-provider-systemextension`; iOS uses `packet-tunnel-provider`. [Apple deployment requirements](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment), [Network Extension entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)

The first implementation uses the public `virtualInterface.name` property, available on macOS 15 and iOS 18. The installed Xcode SDK's `NEPacketTunnelProvider.h` explicitly states that the interface is available when a packet provider's `startTunnel` is called. Swift supplies its name as `tunnelInterfaceName`. This matters: upstream's `ts_macext` DNS resolver binds forwarded tailnet DNS sockets to the actual tunnel interface. A synthetic TUN name would break that lookup. Supporting older OS releases needs a separately implemented and tested fallback. [Apple virtual interface API](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/virtualinterface-7l3ol), [upstream resolver binding](https://github.com/tailscale/tailscale/blob/v1.102.3/net/dns/resolver/macios_ext.go)

## Implemented ABI and behavior

The public interface is `native/engine/include/CoveeEngine.h`:

- `create` validates controller/configuration and decodes existing state. HTTPS is required except for a loopback test controller; optional CA PEM augments the system roots.
- `start` creates the real Tailscale engine/backend and begins coordination with the selected controller.
- `write_packet` copies packets from Apple into the engine; `read_packet` blocks until a decrypted packet is ready for Apple.
- `next_event` delivers bounded, typed network/status/error JSON. Status contains stable peer IDs, names, IPs and online state, with no private keys or enrollment secrets.
- `ack_network` acknowledges a network-settings generation only after the OS completion. The engine propagates failure and waits at most 15 seconds. Stop releases pending waits.
- `set_exit_node` chooses an approved exit node, or none, and whether the local network stays reachable. `set_offer_exit_node` offers the device as an exit node, which is refused on iPhone and while the device itself uses one. `set_accept_routes` turns the use of other devices' routes, such as the network gateway's, on or off. A refusal returns a reason and never stops the engine.
- `stop` cancels work and unblocks packet reads; `destroy` removes the handle. A stopped engine cannot restart. `last_error` returns the last error message.

State is a JSON map of names to base64 bytes. The Swift persistence callback must durably save the entire map, for example in the provider's Keychain access group, before returning success. Failed persistence leaves the store's previous in-memory state intact and returns failure through `ipn.StateStore.WriteState`. Because upstream can log profile-save failures and continue using its in-memory identity, our adapter also installs a sticky fatal latch: it synchronously closes both packet directions, rejects subsequent state writes, suppresses queued or concurrent Running/status delivery, and schedules backend shutdown outside the store/backend locks. It delivers one safe `{"type":"error","code":"persistence","error":"Durable client identity could not be saved; tunnel stopped."}` event even after shutdown. That event supersedes held/queued events and survives short-buffer retries. The engine does not create a plaintext state file or a diagnostic log uploader. [Upstream control-state persistence handling](https://github.com/tailscale/tailscale/blob/v1.102.3/ipn/ipnlocal/local.go#L1967), [upstream preference persistence handling](https://github.com/tailscale/tailscale/blob/v1.102.3/ipn/ipnlocal/local.go#L3132)

Both packet directions have bounded queues. Oversized native read buffers are checked; insufficient packet/event buffers preserve the pending item for retry. Packet input validates IPv4/IPv6 length framing. Error messages redact the configured enrollment secret and common upstream key prefixes. The engine itself does not open an OS TUN, alter host routes/DNS, install a VPN profile, or activate an extension; those actions belong to the signed Swift provider.

## Tests

`go test -race -tags ts_macext -timeout 90s -count=1 -json ./...` runs the engine's tests on macOS arm64. They cover persistence rollback/reload, fatal identity-save failures during real enrollment, copying and buffer retry, malformed packets and congestion, stop unblocking, native network-settings acknowledgement/failure, secret redaction/configuration validation, and actual backend startup. The fatal-path tests cover held native packets, held WireGuard input, held Running events, queued network settings, error priority after shutdown and prevention of state-store recovery within the same handle.

The integration test starts two of our engines and local upstream test-control/DERP/STUN servers. It proves exact bidirectional IPv4 UDP payload delivery through WireGuard using our custom packet device, and confirms that addressed network/DNS configurations pass through the native acknowledgement boundary. The test relay uses upstream's test-only TLS configuration; this test does not establish production certificate deployment. No host VPN was installed or activated.

A second integration test allows the initial machine key to persist, then rejects the actual enrolled profile save containing a nonzero private node key and assigned node ID. It verifies the explicit persistence error, absence of connected/Running status, rejected packet input/output and completed backend shutdown. Event consumption runs concurrently with `start`, as the Apple provider must acknowledge configurations that can be emitted during startup.

A Mac arm64 C archive compiled and linked with a native C smoke program. That program confirms real backend startup, state callback invocation and restore, event short-buffer retry/NUL termination, malformed-packet rejection, stop unblocking a native packet reader, and stale-handle rejection. The smoke also checks that persistence failure fails startup, preserves the typed error after stop, and rejects packet input/output. Mac linking needs Security, CoreFoundation, SystemConfiguration, IOKit and libresolv. IOKit is Mac-only. See `native/engine/tests/cabi_smoke.c`.

## Remaining evidence and build work

Signed Mac/iPhone execution is still required to prove packetFlow operation, real utun DNS binding, OS route/DNS application and cleanup, and interaction with other VPN configurations. Device tests must also cover enrollment/restart, background memory, network changes, sleep/wake, IPv6, forced DERP, revocation and controller outage.

Exit-node selection and offering has native API and UI but still needs acceptance tests. VPN on demand, multi-account/tailnet switching, Taildrop/share extensions, platform policies/MDM, and app-specific conveniences need native API/UI work and acceptance tests before they can be called parity. The engine API exposes the controller, hostname, enrollment, route acceptance and exit nodes; it does not expose every LocalBackend preference or local API feature.

The upstream protocol and public Go API are version-pinned implementation dependencies. Future upgrades must rerun the engine/Apple compatibility tests. The adapter sets no limit on users or devices; memory, event size and controller capacity are the practical limits, and they are to be measured.
