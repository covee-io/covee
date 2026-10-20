# Distributed design: the Covee CLI

Covee is distributed as a command-line tool. An admin runs `covee setup` on their own computer, and the CLI builds a complete, self-contained network on infrastructure the admin chooses, guiding them through every step, sign-in included. No central Covee service exists: nothing the network depends on runs on Covee's servers, and the CLI never phones home. Each organization runs its own networks.

This document explains why Covee is built this way and how the parts fit. The [CLI reference](cli.md) lists every command, and the [guide](guide/README.md) walks through setting up and running a network.

The design rests on these decisions:

- **Distributed.** Each organization runs its own networks, and there is no central control plane.
- **Domains.** Each organization uses its own domain.
- **Sign-in apps.** Each organization registers its own Google, Apple and Microsoft sign-in apps; the CLI automates or guides each one.
- **Covee accounts.** People without one of those accounts sign in with a passkey, or with a password plus an authenticator code.
- **The CLI is the product.** Setup and day-to-day changes go through a guided CLI, not hand-edited files.

## Why a CLI

A self-hosted coordinator is usually installed once per network and configured by files on its server. Being portable between hosting providers ([production contract](production-deployment.md)) does not make it repeatable without expert help. Standing up a network by hand takes all of this:

- a server, a DNS record and a Let's Encrypt certificate;
- for a server at home, router port forwards for TCP 443 and UDP 3478, and often a local DNS override;
- Google, Apple and Microsoft app registrations, each pointing at that server's callback URL;
- copying each secret to a safe store off the server;
- SSH and `deploy.py` for every change;
- an SSH tunnel to reach the admin console;
- for a home connection, a public address that changes while nothing keeps its DNS record current.

Every one of those steps can be done from one computer, with the admin's own AWS, Azure, Google and Apple logins. The CLI turns that sequence into a repeatable, guided product.

## Shape

```text
Admin's computer                                   Infrastructure the admin chooses
covee CLI ───── uses the admin's own logins ─────► domain host:   Route 53, Cloudflare, or by hand
  │                                                secrets store: Parameter Store, or local files
  │                                                sign-in apps:  Microsoft automatic; Google, Apple guided
  │
  ├── creates or prepares ───────────────────────► network server: a new Proxmox VM, or an existing
  │   then manages over SSH                        Ubuntu server (a cloud VM, a machine at home)
  │                                                Headscale + SQLite, TLS gateway, owned relay,
  │                                                sign-in broker, admin console; optional console
  │                                                and gateway devices
  │                                                          ▲
  │                                                          │ HTTPS 443, UDP 3478
  │                                                devices: Covee Mac and iPhone apps,
  │                                                stock Tailscale clients on Linux and others
  │
  └── network record (no secret values) in ~/.config/covee on the admin's computer
```

One network is one server plus its DNS name and sign-in setup. An organization can have several networks, for example one in a cloud and one at home, and the CLI manages them all.

## The setup choices

`covee setup` asks its questions in order. Each answer is checked before moving on. Setup then shows a summary, including what costs money, and changes nothing until it is confirmed.

| Choice | Options | Planned |
| --- | --- | --- |
| Domain host | Route 53 or Cloudflare, which the CLI changes itself; any other host, where the CLI shows the record to add and waits until it resolves | Azure DNS |
| Network server | A new VM on a Proxmox host, or an existing Ubuntu 24.04 server reached over SSH, such as a cloud VM or a machine at home | Azure VM, then AWS EC2, DigitalOcean, Hetzner |
| Sign-in methods | Microsoft, Google, Apple, Covee accounts (any combination) | |
| Secrets store | AWS Parameter Store, or only private files (mode 400) on the admin's computer | Azure Key Vault |
| Backups | Downloaded to the admin's computer and checked there; the newest three also stay on the server | S3, Azure Blob, an attached disk; scheduled backups |
| Where the CLI keeps its network record | A local file | S3 with a DynamoDB lock, for several admins |

The network server must be always on and reachable on TCP 443 and UDP 3478. The coordinator holds a long-lived connection to every device and keeps the network map in memory, so it cannot run on Lambda or similar request-based services.

### Why "backend DB" is two different things

- **The network's own database.** This is always **SQLite** on the server's disk, protected by encrypted backups. Headscale's own configuration calls PostgreSQL "highly discouraged as it is only supported for legacy reasons", and DynamoDB would mean rewriting Headscale's storage layer.
- **The CLI's network record.** This is where the CLI stores what it built: the server, the DNS record, the sign-in app IDs, where each secret lives and the finished setup steps. It never holds secret values. A local file is enough for one admin. For several admins or machines, the planned shared record lives in S3, with a DynamoDB lock so two people can't change the same network at once, the same way Terraform shares its state.

## A setup run

Setup asks every question first: the organization and network name, the hostname and device name suffix, where the DNS is, the server, the networks allowed to reach SSH, the public address, the sign-in methods and where to keep secrets. It ends with a summary and waits for a confirmation, then runs each step, saving progress after each one:

```text
Summary for network office (Example Co):
  • covee.example.com will point to 203.0.113.10, using Route 53 zone example.com (Z…)
  • Devices inside the network get names ending in .mesh.example.com
  • Server ubuntu@203.0.113.10 will be dedicated to Covee (SSH from 198.51.100.0/24 only)
  • Sign-in: Microsoft (Entra ID / Office 365), Google
  • Keys and secrets: AWS Parameter Store us-east-1 /covee/office/* (SecureString), plus a private copy on this computer
  • A free Let's Encrypt certificate for covee.example.com
  Nothing here costs money except the server you provide and AWS's usual fees for DNS.
? Set up now (Y/n): y
[1/13] Create the server login key
[2/13] Set up Microsoft sign-in
[3/13] Set up Google sign-in
…
[13/13] Check the network

Network office is running at https://covee.example.com.
```

### What the CLI automates and what it guides

| Step | How | Notes |
| --- | --- | --- |
| DNS record | Automatic through Route 53's or Cloudflare's API; by hand elsewhere | An optional updater on the server keeps a Route 53 record on a home connection's changing address, with an AWS key limited to that one record |
| Certificate | Automatic | Issued by the CLI through a DNS check, so no port needs to be open yet, and renewed with `covee cert renew`. Renewal by the server itself is planned |
| Server | Automatic: a new Proxmox VM, or SSH to an existing Ubuntu server | Both use the hardened cloud-init steps and firewall rules from `scripts/proxmox.py` |
| Server firewall | Automatic | Admits SSH only from the networks the admin allows, plus TCP 443, UDP 3478 and ping. A cloud provider's own firewall stays the admin's to set |
| Home router port forward | Shown, not checked | Routers have no common API. A check from outside the network is planned |
| Microsoft sign-in | Automatic through Microsoft Graph with the admin's sign-in | Each network gets its own app "Covee <network>", the Covee.Admin, Covee.Reader and Covee.User roles, a "Covee <network> users" group and a client secret |
| Google sign-in | Guided | Google offers no API for creating sign-in clients. The CLI opens the console page, shows exactly what to enter, and checks the values |
| Apple sign-in | Guided | No API for Services IDs or Sign in with Apple keys. Same guided pattern; the CLI checks that the key is a P-256 `.p8` file |
| Covee accounts | Automatic | Built into the sign-in broker |
| Secrets | Automatic | Copied to the chosen store and to the server, then verified by reading back without displaying them |
| First admin | Automatic | With Microsoft, the person running setup has the Covee Admin role; with Covee accounts, setup ends by inviting them as an admin |

The CLI asks before replacing a DNS record, before changes in a Microsoft tenant, before accepting a provider's terms such as Let's Encrypt's Subscriber Agreement, and before deleting anything.

A second network in the same organization reuses that organization's Google sign-in client: the CLI shows the new callback URL to add to it. Microsoft sign-in gets a new app and group for each network, so letting someone into one network never lets them into another.

## Day to day

The same CLI manages running networks. It reaches the server over SSH with a dedicated key kept in the secrets store. With the [gateway](guide/gateway.md) on and an entry that covers the server's address, that SSH connection can travel over the Covee network itself.

```text
covee list | status | console               the networks, their health and expiry dates, the private console
covee auth add|remove <provider>            change sign-in methods on the running network
covee grant · covee users …                 approve Google and Apple accounts; manage Covee accounts
covee device token                          a key for a Linux server or other machine without a person
covee gateway                               let devices reach places only the server can
covee cert renew · backup · update          certificates, encrypted backups, newer Covee files
covee dns auto · rename                     a changing home address; a new hostname
```

Changes take effect on the running network without rebuilding it. Grants, sign-in methods and custom DNS are changed in place (`deploy.py update-identity-grants`, `update-identity-providers`, `update-dns`), restarting only the services that must restart. A restore onto a new server goes through `covee setup`, choosing a backup instead of an empty network.

## Devices

- **Mac or iPhone:** open the Covee app, enter the network's address and sign in in the browser. Invite links and QR codes that fill in the address are planned; later, typing an email address could find the network through the organization's domain.
- **Linux:** run `covee device token`, then the stock client: `tailscale up --login-server=https://covee.example.com --auth-key=<token>`. A person can also sign in instead, without a token.

## Trust

- There is no Covee-run service. The CLI uses the admin's own cloud and provider logins, and nothing reports back to Covee.
- The network record never contains secret values. Secrets live only in the chosen store, in private files on the admin's computer and on the server.
- Each organization owns and can revoke its own sign-in apps.
- The admin console stays private: reached through `covee console` or from devices in the network, never exposed on the public hostname.
- Device keys and the coordinator database leave the server only inside the organization's encrypted backup, whose key is kept only on the admin's computer and in the secrets store.
- The CLI installs only the server files it carries, which the server checks against their SHA-256 hashes before using them; Headscale is built from a pinned, hash-checked source archive.

## How the parts fit

| Part | Role |
| --- | --- |
| Headscale 0.29.4, patched and pinned, with SQLite | The coordinator ([downstream build](../deploy/headscale/README.md)) |
| TLS gateway (`cmd/covee-ingress`) | The public listener on TCP 443; it passes only the client, relay and sign-in routes |
| Sign-in broker (`cmd/covee-identity`, `internal/identity`) | Microsoft, Google, Apple and Covee accounts, with sign-in methods that change on the running network |
| Management console (`cmd/covee-console`, `internal/management`, `internal/console`) | The private admin console, opened through `covee console` or inside the network |
| Console and gateway devices (`deploy/console-node`, `deploy/gateway`) | Optional tagged devices on the server, unprivileged in user space: the console inside the network, and the gateway to private networks |
| `scripts/deploy.py` | The server-side engine the CLI drives over SSH: prepare, validate, start, backup, restore, DNS, grants, sign-in methods and rename |
| `scripts/host_prepare.py`, `scripts/proxmox.py`, `scripts/proxmox_host.py` | Prepare an existing server, or create a new Proxmox VM, with the same hardened steps |
| The `covee` CLI (`cli/`) | Asks, checks and drives everything above. A single Go binary for macOS and Linux, distributed through GitHub releases and Homebrew, so admins need nothing else installed |
| Mac and iPhone apps (`native/`) | Covee's own clients; other devices use the stock Tailscale client |

## Built and planned

Built:

- `covee setup` on a new Proxmox VM or an existing Ubuntu 24.04 server, with Route 53, Cloudflare or manual DNS, all four sign-in methods, Parameter Store or local secrets, and a local network record; or from a backup, to move or rebuild a network.
- Day to day without rebuilds: sign-in methods, approvals, Covee accounts, device tokens, the console inside the network, certificates, backups, updates, the home address updater, renaming and the gateway.

Planned:

- Azure: an Azure VM, Azure DNS and Key Vault.
- The shared network record (S3 with a DynamoDB lock), for several admins.
- Invite links and QR codes in the Mac and iPhone apps.
- The port-forward guide, with a reachability check from outside the network.
- Automatic certificate renewal on the server, and scheduled backups.
- AWS EC2, DigitalOcean and Hetzner servers; servers other than Ubuntu 24.04 on amd64; a Windows CLI; `covee destroy`, which lists everything it will remove and asks for the network name to confirm.

## Still open

1. **The outside reachability check.** With no Covee service to probe from, the check could run from a short-lived function in the admin's own cloud account or from a public port-check service.
2. **UDP 3478.** Whether a network may start with TCP 443 only. That avoids the second port forward, at the cost of more relayed traffic and fewer direct connections.
3. **The server-side engine.** Keep `deploy.py` (Python on the server) or port it into the Go binary, which would let the CLI copy itself to the server.
