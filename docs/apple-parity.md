# Native macOS and iPhone parity

Native clients are required deliverables. A browser console, an embedded `tsnet` client usable only by its own process, and an unsigned app that builds do not establish system-wide VPN parity.

The reference for this project is Tailscale **1.102.3**, capability version **142**, with Headscale **0.29.4** as the tested coordination foundation. Tailscale's public documentation, cited below, describes candidate behavior; qualify it against each reference build before making a parity claim.

## Delivery architecture

Build a shared Swift model and engine boundary with native SwiftUI clients, with separate host-app and packet-tunnel targets. The packet tunnel owns the mesh engine; the app owns onboarding, status, settings and user interaction. Keep long-lived node identity in Keychain, not in provider configuration, UserDefaults, logs or the administration API. The app communicates with its own extension through typed provider messages. Browser administration credentials are not device-enrollment credentials.

The open Tailscale repository supplies reusable daemon and protocol code; Tailscale's own Apple apps are not part of it. Covee therefore provides its own Apple apps and engine integration around that open-source code. [Tailscale open-source boundaries](https://tailscale.com/opensource), [upstream repository](https://github.com/tailscale/tailscale/tree/v1.102.3).

| Deliverable | Apple-supported packaging | Signing and deployment obligation | Covee today |
| --- | --- | --- | --- |
| iPhone/iPad client | App plus `NEPacketTunnelProvider` app extension | Matching app/extension identities and Network Extension provisioning; signed device installation | Built; distributed through TestFlight |
| Mac App Store client | App plus packet-tunnel app extension | Store signing/provisioning; this provider form is App Store only on macOS | Not built; Covee ships the standalone Mac client |
| Standalone Mac client | App plus packet-tunnel **system extension** | Developer ID provisioning for `packet-tunnel-provider-systemextension`; host system-extension installation capability; signed and notarized distribution | Built; signed with Developer ID, notarized and released as `Covee.dmg` |

Apple distinguishes macOS app extensions, which follow the logged-in user, from system extensions, which run independently of that user. The project should retain separate Mac Store and standalone targets/configurations rather than change entitlements on one ambiguous artifact. iOS per-app packet-tunnel mode requires a managed device; ordinary destination-based mesh routing does not require that mode. [Apple TN3134: provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment).

For direct Mac distribution, enable Network Extension capability on the Developer ID identity and obtain a matching profile. The containing app needs `com.apple.developer.system-extension.install` to activate its system extension. Distribution also requires the normal Developer ID notarization workflow. These are release dependencies, not reasons to delay unsigned compilation and engine-boundary tests. [Network Extensions entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension), [System Extension entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.system-extension.install), [notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).

## Toolchain

The native builds are checked with this toolchain:

| Item | Version |
| --- | --- |
| Xcode | 27.0, build `27A266a` |
| Swift | Apple Swift 6.4, `swiftlang-6.4.0.34.1` |
| Native SDKs | macOS 27.0 and iOS 27.0 |
| iOS Simulator SDK | 27.0 |
| Project generation | XcodeGen |

The NetworkExtension details below were read from the headers of the iOS Simulator 27.0 SDK. Building the native source changes no certificates, provisioning profiles, Keychain entries, VPN settings, trust store or host DNS and routes.

Simulator compilation establishes SDK/API compatibility and can exercise UI/model logic. Real-device and signed Mac tests remain necessary for tunnel activation, consent, entitlement enforcement, Keychain sharing, background lifecycle and networking. For example, Apple's local-network privacy behavior is not implemented by the simulator; extension and containing-app permission behavior also differs. [Apple TN3179](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy).

## Acceptance matrix

Each row is a native runtime acceptance check; no row has a recorded acceptance result yet. “Candidate” identifies a platform mode to test, not an implementation claim. Record reference app/build and OS, Covee revision, engine revision, coordinator version, policy hash, topology, actions, expected/actual behavior, timing and cleanup. Run tunnel tests on devices and networks set aside for them, so that no other VPN or network setting is disturbed.

| ID | Requirement and platform scope | Finite success check | Denial, lifecycle and failure check |
| --- | --- | --- | --- |
| APP-01 | Own native clients: Mac and iPhone | Install own bundle; complete custom-coordinator onboarding; show actual extension/engine state, device identity and addresses | Invalid HTTPS URL, certificate failure, wrong/expired enrollment token and denied VPN consent show actionable failure; no false Connected state |
| APP-02 | Packet path: both | From an unrelated system app, reach controlled TCP/UDP services over overlay IPv4 and IPv6; prove direct UDP and forced DERP transport | Deny a service in policy and test fresh connections; remove node and measure propagation; record established-flow behavior separately |
| APP-03 | Identity and reauthentication: both | Restart app/extension without changing node identity; display login-required/expiry states; switch test accounts without mixing identities | Reboot while locked, first unlock, logout, deletion and restore are separate cases; no token/key in preferences, logs or diagnostic export |
| APP-04 | Split DNS/MagicDNS: both | Resolve peer FQDNs and short names; send a private suffix only to its configured resolver; public queries follow selected DNS mode | Test NXDOMAIN, timeout, conflicting suffixes and coordinator DNS updates; capture where queries go; turning VPN off restores OS behavior |
| APP-05 | Routes/subnet **consumer**: both | Reach approved IPv4/IPv6 private prefixes from Wi-Fi and cellular; exercise overlap/more-specific routes with controlled destinations | Reject unapproved routes; test LAN overlap and route withdrawal without leaking traffic onto the LAN; public internet remains usable in mesh-only mode |
| APP-06 | Exit-node **consumer**: both | Select/clear a permitted exit node; validate controlled public IPv4/IPv6 egress and DNS; exercise LAN-access preference | Offline, expired and withdrawn exit nodes follow the recorded reference fail-closed behavior; classify OS-exempt traffic explicitly. Configure global `dns.nameservers` before enabling exit nodes: clients apply the fallback resolvers as their default only while an exit node is selected (pinned `ipn/ipnlocal/node_backend.go`), and on Apple a primary tunnel without VPN-sourced DNS breaks name resolution |
| APP-07 | Subnet/exit-node **host**: Mac candidate | Advertise, approve and exercise forwarding from another node; measure userspace throughput and CPU | Unapproved/expired advertisement denies forwarding; sleep and logout behavior match chosen Mac packaging; do not imply an always-available sleeping laptop |
| APP-08 | iPhone route/exit **hosting**: eligibility pending | Establish whether pinned iOS reference exposes/implements the mode before defining parity checks | Current exit-node documentation mentions iOS hosting but is not proof for 1.102.3; keep this separate from verified exit-node consumption |
| APP-09 | On Demand: both | Exercise configured Wi-Fi, cellular and Ethernet rules where available; retry after app termination and extension restart | Explicit Disconnect removes automatic reconnection unless managed policy says otherwise; test conflicting VPN/On Demand ownership and captive-portal recovery |
| APP-10 | Mobility and resource lifecycle: both | Transfer payload while Wi-Fi changes to cellular and back; sleep/wake Mac; lock/background iPhone; recover extension crash | Report interruption and reconnection latency; test coordinator/DERP loss, low-memory termination, low-power mode, MTU pressure and persistent TCP separately |
| APP-11 | Taildrop: both | Send and receive controlled small/large files, verify SHA-256, destination and user ownership; integrate native sharing/export | Reject unauthorized sender/path traversal/name collisions; test cancellation, storage exhaustion and interrupted receiving; do not promise unsupported reference resume behavior |
| APP-12 | Taildrive: Mac server/client, iPhone consumer candidate | Access permitted WebDAV share; Mac selects a share directory; iPhone opens the share through its native Files workflow | Prove read-only/read-write policy, revoked access, unavailable share and sandbox scope; iPhone sharing is outside the documented platform mode |
| APP-13 | Native controls and accessibility: both | Status, peers, copied addresses, coordinator selection, DNS/routes/exit preferences and diagnostics reflect real engine data; VoiceOver/Dynamic Type/keyboard navigation usable | Pending/connecting/reconnecting/failed states remain distinct; prevent stale state and double mutation; confirmation for removing identity |
| APP-14 | Automation: Mac and iPhone candidate | App Intents/Shortcuts connect, disconnect, inspect state and select a permitted exit node | Disabled/managed actions return explicit failure; no admin/enrollment secret enters shortcut output; actions wait for actual state transition |
| APP-15 | Management and updates: both | Apply documented managed settings, update over a prior signed build without losing identity or private-state protections | Managed restrictions visibly explain disabled choices; bad update does not silently reset trust or keys; diagnose app/extension version mismatch |
| APP-16 | Installation and release: each package separately | Verify nested signatures/profiles/entitlements, host activation/consent, clean install, upgrade, uninstall and release provenance | Test denied activation, revocation, duplicate installs and extension replacement; Store and standalone routes each need evidence |

The packet-tunnel adapter must connect `NEPacketTunnelFlow` packets to the mesh engine and derive addresses, included/excluded routes, DNS settings and MTU from validated engine state. It must await successful `setTunnelNetworkSettings` before completing `startTunnel` successfully. Placeholder adapters should return an explicit unavailable error, never claim a tunnel is connected. [NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider), [startTunnel lifecycle](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/starttunnel(options:completionhandler:)).

Route acceptance must distinguish default routes from `includeAllNetworks` and `enforceRoutes`. Apple's routing rules allow certain system traffic exceptions and route precedence; “every packet uses the exit node” would be an inaccurate acceptance claim. Destination-based mesh routes and split DNS are the starting mode; arbitrary per-app bypass is a different deployment capability. [Apple VPN routing](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic), [Apple TN3120: supported packet-tunnel use cases](https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers).

Shared Keychain access requires matching access-group entitlements across the host and extension. On macOS, use the data-protection Keychain when relying on these access-group semantics. `AfterFirstUnlockThisDeviceOnly` is a candidate for unattended background node identity: it permits access after the first unlock and does not migrate to another device, so reboot-before-unlock and restore require deliberate behavior. This is a proposed storage policy, not an observed Tailscale implementation. [Apple access-group sharing](https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps), [accessibility class](https://developer.apple.com/documentation/security/ksecattraccessibleafterfirstunlockthisdeviceonly).

## Platform-specific qualification

- Tailscale documents Mac subnet/exit hosting, including userspace forwarding and sleep limitations; route consumption is a separate capability. [Subnet routers](https://tailscale.com/docs/features/subnet-routers?tab=macos), [exit nodes](https://tailscale.com/docs/features/exit-nodes?tab=macos).
- Current exit-node documentation includes an iOS hosting workflow, whereas the current managed `AdvertiseExitNode` platform list omits iOS. Establish exact app/build eligibility before including iPhone hosting in the pinned baseline; do not resolve that uncertainty by assuming either support or impossibility. [iOS exit-node workflow](https://tailscale.com/docs/features/exit-nodes?tab=ios), [system-policy platform lists](https://tailscale.com/docs/features/tailscale-system-policies).
- Taildrive's documented server platforms are Linux, macOS and Windows; iOS consumes shares. Taildrop receiving on Mac/iOS has a documented resume limitation. [Taildrive](https://tailscale.com/docs/features/taildrive), [Taildrop](https://tailscale.com/docs/features/taildrop).
- On Demand and native Shortcuts are Apple client requirements rather than coordinator features. Test user configuration and managed settings separately. [On Demand](https://tailscale.com/docs/features/client/ios-vpn-on-demand), [Shortcuts](https://tailscale.com/docs/features/mac-ios-shortcuts), [iOS MDM deployment](https://tailscale.com/docs/integrations/mdm/ios).
- The documented Tailscale SSH **server** on macOS uses the open-source CLI daemon variant. Do not score the standalone GUI or iPhone app against a Linux/CLI-only server mode. Ordinary SSH connectivity from an SSH app over the mesh remains an Apple packet-path check. [Tailscale SSH platform scope](https://tailscale.com/docs/features/tailscale-ssh).

## What each milestone needs

| Milestone | Dependencies |
| --- | --- |
| Native source, shared state model, onboarding UI, testable engine protocol | Toolchain and API shape |
| Unsigned Mac/iPhone build and simulator UI/model tests | Correct target packaging and SDK availability; results name the scheme, destination and disabled signing |
| Encrypted mesh engine in the provider | Go/Swift ABI, packet flow, route/DNS adapter, persistent state, notifications and lifecycle integration; covered by the Go encrypted-packet and C ABI tests |
| Signed Mac activation and signed iPhone tunnel tests | A Team ID, matching identifiers, capabilities and profiles, and test devices; `scripts/apple_release.py` signs with Xcode-managed signing |
| Device access to a coordinator | An HTTPS endpoint reachable from the device, with a trusted certificate and owned DNS and relay addresses, such as a network from `covee setup`; the Docker lab's hostname and CA are not reachable from a device |
| Native runtime parity | A working signed tunnel plus the reference app on controlled Mac/iPhone devices, and the matrix above |
| Public Apple release | Developer ID signing and notarization for the Mac ([Releasing Covee](release.md)); App Store review for the iPhone, after TestFlight; actual device acceptance |

The [native implementation](apple-build.md) includes both SwiftUI clients, the shared real engine, provider-owned Keychain persistence, packet-flow bridging and acknowledged OS settings. It builds for macOS 15/iOS 18 and arm64; older OS support and Intel Mac remain open. Source/build/unit results do not close any native runtime row above.
