# Changelog

## Unreleased

- People appear by email and name. Sign-ins pass the person's email address and name from Microsoft, Google, Apple or a Covee account to the server, so the admin console and device lists show them instead of an account ID. Access still depends only on the account, never on the address. People who signed in before see the change after their next sign-in.
- Updates and other server changes finish even when the connection to the server drops, as it does when you reach the server through the network's own gateway and the change restarts it. The command keeps running on the server, and the CLI connects again and carries on from where it left off.
- The guide tells Windows users to turn on Tailscale's **Run unattended**, since Tailscale on Windows otherwise disconnects when you exit it from the taskbar.
- Covee for Mac and iPhone stay connected. If the connection stops for any reason other than **Disconnect**, such as the system ending Covee's network extension or a network change, the system starts it again by itself. A passing problem, such as the coordinator out of reach for a moment or network settings applied late, no longer ends a working connection. On iPhone, the engine keeps its memory well below the limit the system sets for VPN apps.
- Settings shows the recent connection history: when each connection started, and why it ended.
- On iPhone, Covee no longer runs out of memory when a gateway's private DNS can't be answered. The system ends a VPN app's network extension at 50 MB, and each lookup waiting on an unreachable DNS server held memory, so a phone's apps could push it over within seconds. Lookups waiting at once are now capped, and a network with a gateway tells iPhone and Android devices to send that DNS through the network, as Macs already do (Tailscale's `user-dial-routes`), so it is answered. The connection history notes memory use over 40 MB.
- Terminal and screen sharing in Covee for Mac and iPhone. Choose a device under **Devices** to open a terminal on it or share its screen.
  - The terminal signs in over SSH: with your network identity on servers running Tailscale SSH, otherwise with a key Covee makes and keeps in the Secure Enclave, or once with a password, after which Covee offers to install its key.
  - Covee confirms each device's SSH identity the first time and refuses to connect if it changes.
  - On a Mac, Share screen opens macOS Screen Sharing; on iPhone and iPad the screen opens in Covee, with touch, zoom, scrolling and a keyboard with modifier keys.
  - The console's Access policy page has the rule for signing in to servers without keys.
  - Settings lists the open-source software Covee includes, with its licenses.
- Covee for Mac and iPhone remember your networks. The Network page lists each network the device has connected to or has a saved sign-in for, so moving between them takes one tap instead of typing an address; **Switch network**, also in the Mac's menu bar, moves to another while connected.
- The warning that the network status is unavailable no longer appears after one slow answer, and it goes away once the answers are back.
- Signing in to the admin console works in Safari, including on iPhone and iPad, where it showed "Request origin is not allowed".

## 0.1.0 (2026-10-20)

The first public release.

- `covee setup` builds a complete network on an Ubuntu 24.04 server: an existing one over SSH, or a new VM on a Proxmox host. DNS in Route 53 or Cloudflare is managed automatically; other DNS hosts are guided. Sign-in with Microsoft Entra ID, Google, Apple or Covee accounts (passkey, or password with an authenticator app). A Let's Encrypt certificate. Keys and secrets in AWS Parameter Store or only on your computer.
- Running networks: `status`, `console` (admin console through an SSH tunnel, or inside the network), `update`, `backup` and restore, `cert renew`, `rename`, `dns auto` for changing home addresses, people and sign-in methods, device keys.
- The gateway: `covee gateway` and the admin console's Gateway page carry chosen traffic (address ranges or host names, for everyone or chosen people) to private networks the server reaches, with private DNS.
- Covee for Mac (Apple silicon, macOS 15): connect, sign in, exit nodes, and the gateway switch, from the window or the menu bar. Distributed as a signed, notarized disk image.
- Covee for iPhone in TestFlight.
