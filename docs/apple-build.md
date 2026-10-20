# Build the Mac and iPhone clients

Covee has native SwiftUI clients for the Mac and the iPhone/iPad, built around an embedded mesh engine. The Mac app contains a packet-tunnel **system extension**; the iPhone/iPad app contains a packet-tunnel **app extension**. Both are Covee's own Apple apps, around the open-source Tailscale engine at a pinned version ([engine details](apple-engine-research.md)).

This page covers building and testing the apps locally, unsigned. Signed builds come from `scripts/apple_release.py` ([below](#signed-builds)), and the Mac app is released as `Covee.dmg` ([Releasing Covee](release.md)). Compilation, unit tests and the local encrypted-packet test do not by themselves establish Apple VPN operation or full feature parity; the [native acceptance matrix](apple-parity.md) lists what device testing must cover.

## Build locally

Requirements: an Apple Silicon Mac, Xcode and its command-line tools, XcodeGen, Python 3.10+, Go, and network access to download the pinned Go modules/toolchain. The builds are checked with Xcode 27.0 (`27A266a`) and Swift 6.4. The separate engine module requests Go 1.26.6; the script permits automatic toolchain download. The management service has its own Go module and toolchain requirement.

```sh
python3 scripts/apple.py build
python3 scripts/apple.py test
```

The build creates three real Go C archives, generates the Xcode project and compiles all three app/extension pairs with signing disabled. The test command runs unhosted macOS model and network-settings tests; it does not save a VPN profile or start a tunnel. Logs and command reports are under `.cache/covee/apple/`.

For a single platform, use `--platform macos`, `--platform ios` or `--platform ios-simulator`. After an engine build, `--skip-engine` reuses the existing archives. Regenerate the project with `python3 scripts/apple.py generate`, then open `native/apple/Covee.xcodeproj` to inspect the source in Xcode. `native/apple/project.yml` is the project source of truth.

To produce optimized Release bundles and verified ZIP packages:

```sh
python3 scripts/apple.py build --configuration Release
python3 scripts/apple.py test --configuration Release
python3 scripts/package_apple.py
```

Release app bundles are under the corresponding `Release`, `Release-iphoneos` and `Release-iphonesimulator` product folders. Packaging creates a new timestamped directory under `dist/covee/apple/` with all three ZIPs, a manifest of source/product hashes and copied build logs. ZIP CRCs, arm64 executables, embedded providers and identifiers are checked. Builds recreate their own app bundle, so a stale embedded extension from an earlier build cannot survive. The Mac system-extension filename matches its bundle identifier as [Apple requires](https://developer.apple.com/documentation/systemextensions). These are unsigned build packages; signing and provisioning are still required for device VPN use.

| Build | Scheme | Unsigned output |
| --- | --- | --- |
| Mac | `Covee-macOS` | `.cache/covee/apple/derived/macos/Build/Products/Debug/Covee.app` |
| iPhone/iPad | `Covee-iOS` | `.cache/covee/apple/derived/ios/Build/Products/Debug-iphoneos/Covee.app` |
| iOS Simulator | `Covee-iOS` | `.cache/covee/apple/derived/ios-simulator/Build/Products/Debug-iphonesimulator/Covee.app` |

These build products are not signed installable releases. With `CODE_SIGNING_ALLOWED=NO`, the Mac and simulator linker still emits ad-hoc Mach-O signatures without a Team ID or sealed bundle; there is no developer/distribution signature or provisioned VPN identity. Generated projects, archives and derived products are ignored by Git; the packaging manifest records source and product hashes.

## Implemented behavior

- Native Mac window/menu-bar app and native iPhone tabs for connection, devices and settings.
- Custom HTTPS coordinator, validated device name, transient enrollment key and coordinator-origin sign-in link.
- Explicit Connect/Disconnect actions. The Mac app requests its own system-extension activation when Connect is pressed. There is no automatic connection on launch.
- Exit-node selection, with an option to keep the local network reachable; a Mac can offer itself as an exit node; a switch turns the network gateway's routes on or off.
- A real `wgengine`/`LocalBackend` engine, raw IPv4/IPv6 packet bridge, OS route/DNS/MTU conversion and acknowledgement after Apple completes the network-settings request.
- Serialized network-settings updates and final withdrawal during stop; bounded startup, status requests and engine queues; stale replies cannot populate a newer app connection.
- Device identity in the provider's data-protection Keychain, accessible after first unlock on that device. Saved app configuration contains only coordinator and hostname. Enrollment keys are start options, not saved configuration.
- A failed identity save latches a fatal error, immediately blocks packet forwarding and stops the backend; queued Running/network snapshots cannot hide the storage failure.
- Actual engine status, overlay addresses and visible peers. Connected requires both the OS tunnel and a running engine.

The initial minimum versions are **macOS 15 and iOS 18**, with arm64 builds. Apple exposes the actual virtual tunnel interface through a public API on these versions. The engine uses that interface name to bind forwarded tailnet DNS correctly. Older Apple OS versions and Intel Mac builds remain qualification work. [Engine integration details](apple-engine-research.md).

## What the checks establish

The Swift tests exercise coordinator/hostname validation, enrollment-key bounds, trusted sign-in links, secret-free configuration, Connected semantics, IPv4/IPv6 route and DNS conversion, malformed input, and settings-update/stop ordering. They use injected apply callbacks, not a live VPN.

The production-tag Go race tests exercise state rollback/reload, buffer bounds/retry, cancellation, settings acknowledgements, validation and redaction. A local integration test starts two real engines plus test coordination/relay services and exchanges exact encrypted IPv4 UDP payloads in both directions. Another lets machine-key storage succeed and rejects the later enrolled-profile save, then checks an explicit fatal error, blocked forwarding and completed shutdown. These tests do not use Apple's packet flow or modify host routing. The C program links the actual Mac archive and checks startup, persistence callbacks/restore, event retry and stop/destroy behavior. [Engine research and source pin](apple-engine-research.md).

## Signed builds

`scripts/apple_release.py` signs the apps through the Apple account signed in to Xcode, with Xcode-managed signing; it needs no local Developer ID private key or notary profile. For the Mac, it archives with development signing and the `-development` entitlements, because development profiles do not offer the system-extension Network Extension value. It then exports for Developer ID with destination "upload": Xcode re-signs the app and its provider with the final `packet-tunnel-provider-systemextension` entitlement and submits them to Apple's notary service. The script exports the notarized, stapled app and verifies its signature, Gatekeeper's assessment, the staple, the entitlements and the Info.plist values the system extension depends on. For the iPhone, it builds a development-signed app for a registered device, or a TestFlight build ([Releasing Covee](release.md)). See Apple's [export guidance](https://developer.apple.com/forums/thread/737894) and [deployment requirements](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment).

## Device testing

Devices need a reachable HTTPS coordinator with a trusted certificate and owned relay endpoints, such as a network set up by `covee setup` ([Set up your network](guide/server.md)). The Docker lab's `https://headscale:8080` hostname and private CA are not reachable from a device.

Device acceptance must prove enrollment, actual system-app traffic, split DNS, subnet access, identity across restart, disconnect cleanup and policy/revocation on both platforms. Follow with IPv6, forced relay, Wi-Fi/cellular transitions, sleep/wake and background recovery.

On Demand, account switching, Taildrop, Taildrive, Shortcuts/App Intents, managed policies, diagnostics, the App Store release, in-app updates and the remaining [parity matrix](apple-parity.md) are still open. Existing engine capabilities do not make those native user flows implemented or verified. Upstream sources remain pinned in `native/engine/go.mod`/`go.sum`, and each release carries the license of every Go module compiled into the app (`THIRD_PARTY_LICENSES.txt`).
