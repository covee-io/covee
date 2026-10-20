# What Covee is

Covee gives a person or an organization its own private network. Devices in the network have private addresses and names (`laptop.mesh.example.com`) and reach each other over encrypted [WireGuard](https://www.wireguard.com/) connections, directly when they can and through a relay when they cannot, whether they are at home, in an office, on a phone network or in a cloud.

## How it works

```
 your computer                     your server (Ubuntu 24.04)
 ┌──────────────┐  covee setup    ┌───────────────────────────────────────┐
 │ covee (CLI)  │ ──── SSH ─────▶ │ coordinator · relay · sign-in · console │
 └──────────────┘                 │ (optional) gateway to private networks │
                                  └──────────────────┬────────────────────┘
                                     HTTPS 443, UDP 3478│
            ┌──────────────┬──────────────┬────────────┴──┐
         Mac app       iPhone        Linux server     other devices
            └──────── direct, encrypted WireGuard connections ───────┘
```

- **The `covee` command** runs on your computer. It sets up the server over SSH, registers the sign-in apps, gets the certificate, and later updates, backs up and renames the network. It uses your own accounts (SSH, AWS, Azure) and never talks to a Covee service: there isn't one.
- **The server** runs the coordinator ([Headscale](https://github.com/juanfont/headscale), an open-source implementation of the Tailscale control server), a relay and a STUN server for devices that cannot connect directly, a sign-in service, and an admin console. Everything runs in hardened containers. From the internet, the server accepts only HTTPS on TCP 443 and STUN on UDP 3478, and SSH only from the networks you allow.
- **Devices** run the Covee app (on the Mac; the iPhone app is in testing) or the standard [Tailscale](https://tailscale.com/) client (iPhone, Linux and the other platforms Tailscale supports), pointed at your server. Traffic between devices is end-to-end encrypted: the server relays it when needed but cannot read it.
- **The gateway** (optional) lets devices reach places only the server can, such as a cloud's private networks, through the server.

## What you need

- **A computer** with macOS or Linux to run `covee`.
- **A server** for the network: a fresh Ubuntu 24.04 (amd64) machine that stays on, with at least 2 CPUs, 4 GB of memory and a 32 GB disk (4 CPUs and 8 GB are better). A cloud VM works, and so does a VM on a Proxmox host at home, which `covee` can create for you. It must be reachable from the internet on TCP 443 and UDP 3478: a cloud VM with a public address, or a home server with those two ports forwarded on your router.
- **A domain name** you own, for the network's address, such as `covee.example.com`. Covee manages the DNS records itself in Amazon Route 53 or Cloudflare; with any other DNS host it tells you which records to add.
- **A way for people to sign in**: a Microsoft 365 / Entra ID tenant you administer, a Google Cloud or Apple Developer account, or Covee's own accounts (a passkey, or a password with an authenticator app). You can use several at once.
- **Optionally, an AWS account**, to keep the network's keys and secrets in AWS Systems Manager Parameter Store as well as on your computer.

## What it costs

Covee is free and open source ([Apache 2.0](../../LICENSE)). You pay only for the server and the domain: a small cloud VM costs a few dollars to a few tens of dollars a month, and a server at home costs nothing extra.

## What is not there yet

- Servers other than Ubuntu 24.04 on amd64.
- Automatic certificate renewal and scheduled backups: both are one command for now ([Run your network](operations.md)).
- Renewing the network's internal certificate authority, which lasts a year from setup. `covee status` warns 60 days before it expires.
- A Windows app, and the iPhone app in the App Store. Meanwhile, Windows and iPhone can use Tailscale's own apps ([Connect your devices](devices.md)).

Next: [install the covee command](install.md).
