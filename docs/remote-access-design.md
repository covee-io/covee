# Screen sharing and SSH from the Covee apps

Status: built on 2026-10-25, all three phases.
- **SSH terminal:** in the Mac and iPhone apps, on swift-nio-ssh rather than Citadel. Citadel's latest release swaps Apple's NIOSSH for a personal fork created in April 2026, which Covee does not take for SSH.
- **Screen sharing:** on iPhone and iPad, with a copy of RoyalVNCKit in `native/apple/Vendor/RoyalVNC`. The Mac opens macOS Screen Sharing.
- **Keyless SSH:** the console's Access policy page offers the rule.

What follows is the proposal as written.

## Goal

From Covee on a Mac or an iPhone, open another device's screen (VNC) or a terminal on it (SSH) with one tap in the device list. No addresses, ports or keys to type.

## What the network already gives

- Every device has a stable name under the network's suffix, such as `laptop.mesh.example.com`, and a fixed 100.x address. The apps already list devices with their names, addresses and whether they are online. The engine's peer status also says each device's operating system and, for servers running Tailscale SSH, their SSH host keys (`ipnstate.PeerStatus.OS`, `SSH_HostKeys`).
- Traffic between devices is encrypted end to end by WireGuard. VNC, which is not encrypted by itself, is therefore safe inside the network.
- The access policy decides who may reach which port. With the rule in [Let devices reach each other](guide/devices.md#let-devices-reach-each-other), people's devices reach each other on every port, so VNC and SSH between them need nothing more. A tagged server needs its own rule.
- The viewer and the terminal run in the app, not in the network extension, so they do not count against the extension's memory limit on iPhone (about 50 MB).

## What the other device needs

| Device | Screen sharing | SSH |
|---|---|---|
| Mac | Screen Sharing on (System Settings → General → Sharing); sign in with a macOS account | Remote Login on; password or key |
| Linux server | A VNC server, rarely installed | OpenSSH, or keyless Tailscale SSH (Phase 2) |
| Windows | Uses RDP, not VNC; out of scope | OpenSSH Server, if installed |
| iPhone, iPad | Cannot be reached this way: iOS has no screen sharing or SSH server | |

## Phase 1: open the right app

A device's detail view (tap it under Devices; on a Mac, also the menu bar's Devices menu) gets **Share screen** and **Open SSH**. Each button appears only when the device answers on that port. The check is a short TCP connect to port 5900 or 22, made only when the detail opens.

- **Mac:** Share screen opens `vnc://<device>` in macOS Screen Sharing. It is built in, the best viewer for Macs, and handles the macOS sign-in. Open SSH opens `ssh://<user>@<device>` in Terminal, with this Mac's user name as the default.
- **iPhone:** opens `vnc://` or `ssh://` in an installed app that handles them. [Screens](https://help.edovia.com/screens-5/features/url-schemes) handles `vnc://`. Termius is reported to handle `ssh://`, and iOS picks the app installed or updated most recently. With no such app, Covee names one to install.

Effort: 2 to 3 days for both apps with tests. No new libraries and no App Review risk.

## Phase 2: a built-in SSH terminal, both apps

- **Libraries.** All suit an Apache-2.0 app in the App Store.
  - [SwiftTerm](https://github.com/migueldeicaza/SwiftTerm) (MIT): an xterm terminal with UIKit and AppKit views, used by several shipping SSH apps.
  - [Citadel](https://github.com/orlandos-nl/Citadel) (MIT): an SSH client on Apple's [swift-nio-ssh](https://github.com/apple/swift-nio-ssh) (Apache-2.0).
- **Keys.** The app makes one SSH key per device, a P-256 key held in the Secure Enclave, so it never leaves the device. **Copy public key** handles manual setup. **Install my key** signs in once with a password and appends the key to `~/.ssh/authorized_keys`.
- **Host keys.** A server running Tailscale SSH is checked against the host keys the coordinator publishes for it, so there is no "trust this server?" prompt. For other servers, the app trusts the key on first use, keeps it per device, and stops with a clear warning if it changes.
- **Keyless SSH to servers (Tailscale SSH).** A Linux server running the standard Tailscale client with `tailscale set --ssh` lets network members in by identity, with no keys and no passwords. Headscale 0.29.4, the version Covee runs, supports the policy's `ssh` section with the `accept` and `check` actions. Covee would add three things:
  - an SSH rule template on the console's Access policy page, for example `{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server"], "users": ["autogroup:nonroot"]}`;
  - the server step in the guide;
  - a policy check in tests.

  Two limits: a tagged device cannot SSH into a person's device (Headscale's rule), and a Mac cannot serve Tailscale SSH under Covee, so it uses Remote Login.
- **iPhone extras:**
  - a key row (Esc, Ctrl, Tab, arrows), font size and landscape;
  - sessions end when iOS suspends the app, which is an iOS limit. Mosh would survive it; it stays out of scope.

Effort: 2 to 3 weeks for a solid first version in both apps, plus 2 to 3 days for keyless SSH.

## Phase 3: built-in screen sharing on iPhone and iPad

- **Library.** [RoyalVNC](https://github.com/royalapplications/royalvnc) (RoyalVNCKit, MIT, Swift).
  - Supports VNC password and Apple Remote Desktop sign-in.
  - Supports the Tight, ZRLE and Zlib encodings.
  - Its repository was archived in September 2026, so Covee would pin a copy, vendor it and maintain it.
  - Early check: that its Apple Remote Desktop sign-in works against current macOS Screen Sharing.
- **Interface:** a full-screen view, pinch to zoom, a trackpad-style pointer, a keyboard with modifier keys, and later the clipboard.
- **The Mac keeps using macOS Screen Sharing.** It is better than anything Covee would build.

Effort: 3 to 4 weeks for a good first version on iPhone and iPad.

## Recommendation

1. **Phase 1 now.** It takes days and works with what is already installed.
2. **Phase 2 next.** One-tap, keyless SSH from the phone into the network's servers is the standout feature.
3. **Phase 3 only if** screen sharing from the iPhone without a third-party app matters enough for the month it costs.

## Safety

- Ports are checked only when a device's detail opens: two ports with a short timeout, never a scan.
- No password is stored unless the person asks; it would go in the Keychain. SSH keys stay in the Secure Enclave. Screen sharing runs only inside the network.
- Nothing here changes the network extension or the coordinator, except the policy template in Phase 2.
