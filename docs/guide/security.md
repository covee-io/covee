# Security

## What protects your network

- **End-to-end encryption.** Devices talk over WireGuard, with keys that never leave them. The server coordinates and relays, but cannot read the traffic between devices. Traffic to the server's own devices, the gateway and the in-network console, ends on the server.
- **A hardened server.** From the internet, the server accepts only TCP 443 (the coordinator, sign-in and relay), UDP 3478 (STUN) and ping. It accepts SSH only from the networks you allow, and from the gateway when it is on, with key-based login for a single `covee` account. The services run in containers as an unprivileged user, with read-only file systems and no added capabilities.
- **A private admin console.** The console is never published on the internet: it opens through an SSH tunnel from an administrator's computer, or inside the network for its devices. It requires a sign-in by an administrator, or by a reader who can look but not change anything, and it records every change.
- **Access you decide.** A new network allows no traffic between devices until its access policy says so. Each network keeps its own list of who may sign in; with Microsoft, each network also has its own app and group.
- **Secrets kept apart.** Keys and secrets stay on the server, on your computer and, if you choose, in AWS Parameter Store as encrypted parameters. Backups are encrypted to a key that is kept only on your computer and in Parameter Store; a restore copies it to the new server for the restore and deletes it right after.
- **No Covee service, no telemetry.** `covee` and the apps talk only to your own server and the providers you choose: your DNS host, Let's Encrypt, your sign-in provider and, to learn the network's public address, checkip.amazonaws.com. To set itself up and update, the server downloads Ubuntu's and Docker's packages, container base images and the source code Covee builds, such as Headscale's from GitHub. Nothing is reported anywhere.

## What you are responsible for

- Keeping the server up to date: security updates install automatically, but restart it now and then so kernel updates take effect, and run `covee update` when a new Covee version is out.
- Renewing the certificate (`covee cert renew`) and taking backups (`covee backup`), until both are automatic.
- Who is in your sign-in groups, and what the access policy allows.
- Protecting the computer and accounts that manage the network: they hold its keys.

## Reporting a vulnerability

Please report security problems privately through [GitHub's private vulnerability reporting](https://github.com/covee-io/covee/security/advisories/new) for the repository, not in public issues. See [SECURITY.md](../../SECURITY.md).
