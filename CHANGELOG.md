# Changelog

## 0.1.0 (unreleased)

The first public release.

- `covee setup` builds a complete network on an Ubuntu 24.04 server: an existing one over SSH, or a new VM on a Proxmox host. DNS in Route 53 or Cloudflare is managed automatically; other DNS hosts are guided. Sign-in with Microsoft Entra ID, Google, Apple or Covee accounts (passkey, or password with an authenticator app). A Let's Encrypt certificate. Keys and secrets in AWS Parameter Store or only on your computer.
- Running networks: `status`, `console` (admin console through an SSH tunnel, or inside the network), `update`, `backup` and restore, `cert renew`, `rename`, `dns auto` for changing home addresses, people and sign-in methods, device keys.
- The gateway: `covee gateway` and the admin console's Gateway page carry chosen traffic (address ranges or host names, for everyone or chosen people) to private networks the server reaches, with private DNS.
- Covee for Mac (Apple silicon, macOS 15): connect, sign in, exit nodes, and the gateway switch, from the window or the menu bar. Distributed as a signed, notarized disk image.
- Covee for iPhone in TestFlight.
