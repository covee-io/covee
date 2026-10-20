# The covee CLI

`covee` runs on the admin's computer and builds a complete, self-contained network on a server they choose, sign-in included. It uses the admin's own AWS, Azure and SSH logins and never contacts a Covee service. This page is the reference for every command; the [guide](guide/README.md) walks through setting up and running a network, and the [distributed design](distributed-design.md) explains how the parts fit.

## Build

```sh
python3 scripts/build_cli.py                                   # for this computer
python3 scripts/build_cli.py --target darwin/arm64 --target linux/amd64
```

The binary lands in `dist/cli/<os>-<arch>/covee`. It embeds the server source that setup installs (the Dockerfile, the Go modules, `cmd`, `internal`, `deploy`, `scripts` and `lab`), with a `PAYLOAD-MANIFEST.json` of SHA-256 hashes that the server checks before using them. Two builds of the same tree produce byte-identical payloads. The CLI's Go code is its own module in `cli/`, so the server images keep their existing dependencies.

## What setup needs

- **A server**, one of two kinds.
  - **A new VM on Proxmox.** Setup creates it through `ssh root@<proxmox host>`. That host needs a storage with the "Snippets" content type enabled for cloud-init files. Setup runs `scripts/proxmox_host.py` there, which applies the reviewed plan of `scripts/proxmox.py`: the pinned Ubuntu 24.04 cloud image, checked against its SHA-256, and a hardened cloud-init. Setup asks for the VM ID, disk storage, snippet storage, bridge, a free fixed address, gateway, DNS server and the size.
  - **An existing server:** a fresh Ubuntu 24.04 amd64 server, reachable with `ssh user@address` without a password prompt, whose account can use `sudo` without a password. It can be a cloud VM, a Proxmox VM or a machine at home. Setup dedicates it to Covee: afterwards SSH accepts only a new `covee` account with a key setup creates, from the networks you allow, and the firewall admits only TCP 443 and UDP 3478 besides that.
- **A hostname** on a domain you own. Setup can manage the DNS records in Route 53 or Cloudflare; for any other DNS host, it shows the records to add and waits until they resolve.
- **Cloudflare** (when chosen): an API token made from Cloudflare's "Edit zone DNS" template, for the zone that holds the hostname. Give a file or Parameter Store name holding it, or paste it unseen. It is kept as the secret `cloudflare-dns-token`. A record that already points at the server, such as one kept by OpenTofu, is left as it is; otherwise the record is set to DNS only, because Cloudflare's proxy cannot carry Covee.
- **Microsoft sign-in:** the Azure CLI, signed in as a tenant administrator (`az login --allow-no-subscriptions`). Setup creates the network's own app "Covee <network>", its roles, the "Covee <network> users" group and a client secret. Each network has its own app and group, so letting someone into one network never lets them into another in the same tenant.
- **Google or Apple sign-in:** access to the Google Cloud console or the Apple Developer account. Neither offers a way to create sign-in apps automatically, so setup shows exactly what to enter, then checks the values. It checks that the Apple key is a P-256 `.p8` file.
- **AWS credentials** (the default AWS CLI profile, or `AWS_PROFILE`) when Route 53 or Parameter Store is chosen. Setup shows which AWS identity it is using.

## `covee setup`

Setup asks every question first and changes nothing until you confirm a summary:

- organization and network name;
- whether to start from an empty network or from a backup (see below);
- public hostname, and the name suffix devices get inside the network;
- DNS host, and whether the admin console should also open inside the network (default yes);
- where the network runs: an existing server (address and admin account) or a new Proxmox VM;
- networks allowed to reach SSH;
- public IPv4 address, and, for a server behind a router with Route 53 DNS, whether that address can change;
- sign-in methods;
- where the copy of record of secrets lives.

It refuses settings that would lock you out, such as SSH sources that exclude the address you are connecting from, and servers it cannot prepare. It asks before replacing an existing DNS record, before any changes in your Microsoft tenant, and before accepting Let's Encrypt's Subscriber Agreement.

It then runs these steps, saving progress after each one:

1. Create the `covee` account's SSH key.
2. Set up each chosen sign-in method.
3. Point the hostname at the public address.
4. Get the certificate through a DNS check, so no port needs to be open yet.
5. Create the `covee` account (`scripts/host_prepare.py account`).
6. Harden the server and install Docker. This applies the same files and steps as the cloud-init of a new Proxmox VM (`scripts/host_prepare.py system`, which reuses `scripts/proxmox.py`).
7. Install the Covee files in `/opt/covee/src`.
8. Copy keys and secrets to `/srv/covee/secrets`.
9. Build the services.
10. Prepare a new `/srv/covee/runtime-N` and start it.
11. Schedule the console's key renewal, and, if the public address can change, install the address updater (see below).
12. Check the network.

If a step fails, fix the cause and run `covee setup <network>` again: finished steps are skipped. A runtime directory is never overwritten. If the build fails, setup shows the end of the newest build log.

On a new Proxmox VM, cloud-init prepares the VM instead of steps 5 and 6, and setup waits for it to finish.

### Moving or rebuilding a network from a backup

Choose "A backup of a network" and give the `.tar.age` file and its key. The key can be a file containing the `AGE-SECRET-KEY` line, or its Parameter Store name. For backups made by `covee backup`, setup finds the key itself.

Setup decrypts the backup on this computer. From it, setup takes:
- the hostname and mesh domain;
- the sign-in methods, with their app IDs and secrets;
- the approved accounts and the device list.

So nothing needs registering again. On the server, the backup is restored into a new runtime, and its key is deleted from the server right after. Setup then installs a new certificate.

The DNS record moves to the new server only at the very end, once it runs. Then stop the old server so devices cannot reconnect to the outdated copy. Devices keep their identity, addresses and sign-in, and follow on their own.

A network at home, behind a router, keeps the same public address, so its DNS record does not change. Instead, change the router by hand before stopping the old server:
- point the TCP 443 and UDP 3478 port forwards at the new server's local address;
- point any local DNS override for the hostname there too.

A backup does not record when the Microsoft client secret expires, so `covee status` shows it as unknown on a restored network.

## Where things are kept

On this computer, in `~/.config/covee` (or `$COVEE_HOME`), private to your account:

| Path | Contents |
| --- | --- |
| `networks/<name>.json` | The network record: hostname, server, DNS zone, sign-in app IDs, where each secret lives, certificate expiry, finished steps. It never contains secret values |
| `secrets/<name>/` | Private copies (mode 400): `ssh-private-key`, `tls-private-key`, `acme-account-key`, and whichever of `entra-client-secret`, `google-client-secret`, `apple-private-key`, `backup-age-identity`, `dns-updater-key` and `cloudflare-dns-token` apply |
| `certificates/<name>/fullchain.pem` | The public certificate chain |
| `known_hosts` | Each server's SSH key, recorded on first contact and required afterwards |

With Parameter Store chosen, each secret is also stored as `/covee/<network>/<name>` (SecureString, AWS-managed key, Standard tier) and verified by reading it back. If the local copy is missing, for example on another computer, it is restored from there. The public certificate chain is not stored there.

## After setup

```sh
covee list                     # networks this computer manages
covee status <network>         # services, and days left on every certificate and secret
covee console <network>        # private admin console through an SSH tunnel; needs local port 8444 free
covee console <network> --in-network  # also serve the console to devices in the network
covee grant <network> --provider google|apple --subject ID [--role admin|reader|none] [--no-devices]
covee auth add <network> microsoft|google|apple|accounts     # turn on a sign-in method
covee auth remove <network> microsoft|google|apple|accounts  # turn one off
covee users list|invite|update|reset|remove <network> ...  # Covee accounts
covee device token <network> [--tag server] [--expires 24h] [--reusable] [--ephemeral]
covee gateway <network> [--off]  # a gateway device on the server, to reach private networks
covee cert renew <network>     # new public certificate plus the 90-day internal ones
covee backup <network>         # encrypted backup, downloaded and verified
covee update <network>         # install this CLI's Covee files and restart
covee dns auto <network> [--off]  # keep the hostname on a home connection's changing address
covee rename <network> --hostname H [--mesh-domain D]  # move to a new hostname, such as one on your own domain
```

The console tunnel works only at `https://localhost:8444`, the address registered for its sign-in, so close any other console tunnel first.

**The console inside the network.** With it on, devices connected to the network open the console at `https://console.<mesh domain>`, for example `https://console.mesh.example.com`, or with **Manage network** in the Mac and iPhone apps.
- **The console device.** A small service on the server joins the network as the tagged device `console` (`tag:covee-console`), using Tailscale's tsnet library in user space. It passes connections on its port 443 to a console listener of the TLS gateway that is never published, so nothing new is reachable from the internet.
- **Access.** The network policy gets one grant: members may reach TCP 443 of `tag:covee-console`. The console still requires an administrator's sign-in.
- **Certificate.** The public certificate also names the console host, so browsers trust it. `covee cert renew` keeps both names.
- **How it starts.** The server gives the console device a one-hour, one-time key the first time it joins, and deletes the key afterwards. The device's identity is part of backups.
- **Turning it on.** Setup offers it; for an existing network, run `covee update <network>` first, then `covee console <network> --in-network`.

Microsoft access comes from your tenant: the admin who ran setup is already a Covee Admin, and members of the network's "Covee <network> users" group can add devices.

Google and Apple accounts need one approval:
1. Sign in through `covee console`.
2. Copy the ID shown on the "not approved" page.
3. Run `covee grant`, which merges the approval into the network's access list and restarts only the sign-in service.

### What each command restarts

| Command | Restarts | Devices |
| --- | --- | --- |
| `grant`, `auth add`, `auth remove` | only the sign-in service (`deploy.py update-identity-grants` / `update-identity-providers`) | stay connected |
| `device token`, `dns auto`, the console's **Add a device** and route approvals | nothing (a Headscale pre-auth key, a policy edit or a route approval; a separate timer) | stay connected |
| `cert renew`, `backup`, `update` | every service once, in the identity-aware order | reconnect on their own within a minute |
| `rename` | every service once | need the new address once (see below) |

**Sign-in methods.** `auth add` runs the same Microsoft, Google or Apple step as setup. It copies the secret to the server and replaces the provider list in place. If the sign-in service does not come back healthy, the server restores the previous list and the record is left unchanged. `auth remove` refuses to remove the last method. Accounts approved through the removed method lose access only after you confirm.

**Covee accounts** sign in without Google, Apple or Microsoft. The network's own sign-in service keeps them in `state/identity/accounts.json`, which is included in backups and restores.
- **Invites only.** An admin runs `covee users invite <network> --email E --name N [--role admin|reader|none] [--no-devices]` and sends the one-time link privately. It is valid 72 hours by default; set `--expires` from 1h to 336h.
- **Two ways to sign in.** The link sets up either a passkey (Face ID, Touch ID, Windows Hello or a security key) or a password plus a 6-digit authenticator-app code. A password alone is never enough.
- **How secrets are kept.** Passwords are stored with Argon2id (19 MiB, 2 passes), and at most two hashes run at once in the 256 MB container. Authenticator codes follow RFC 6238, and a used code cannot be reused.
- **Lockout.** Five wrong attempts lock the account for 15 minutes.
- **Changes.** `covee users update` changes the role or device access. `covee users reset` removes every passkey and the password and sends a new invite. `covee users remove` deletes the account.
- **Your own account.** When setup turns accounts on, it ends by inviting you as an admin.

**Device tokens** are for machines that cannot sign in, such as Linux servers. The key is owned by its tags (for example `tag:server`), works for joining for at most 90 days, and is shown once. The network denies all traffic by default, so allow the tag in the console's access rules.

**Adding a Linux server, an exit node or a local network from the console.** Under **Devices → Add a device**, choose *A server or other machine*:
- **The key.** It belongs to its tag (`tag:server` by default), not a person. Its lifetime, from 1 hour to 90 days, is only the window for joining; a tagged machine never has to sign in again and stays until you remove it. Personal computers sign in again when the network's device access period ends (30 days).
- **Access.** *Let everyone's devices reach it* adds `{src: [autogroup:member], dst: [<tag>], ip: ["*"]}` to the policy. The tag always gets an owner entry, because a machine cannot join with an unknown tag. Policy edits are checked by Headscale first and keep the policy's comments.
- **The commands.** The console shows the key and the commands to run, both shown once: install the standard Tailscale client from `tailscale.com/install.sh`, then `tailscale up --login-server=https://<coordinator> --auth-key=…`, with `--hostname`, `--advertise-exit-node` and `--advertise-routes=192.168.50.0/24` as chosen. Exit nodes and local networks also get the IP-forwarding settings.
- **Approving.** A machine that offers an exit node or local networks shows *Exit node: approve* or *Local networks: approve* in the device list. Under **Manage**, tick what it may serve and save. *Let everyone's devices use what is approved* adds a grant to `autogroup:internet` for an exit node, and one to each approved network.
- **Using an exit node.** In the Mac app's **Exit node** section or the menu bar's **Exit node** menu, and in the iPhone app, pick the machine. *Allow local network access* keeps printers and other local devices reachable while traffic goes through it.
- **A Mac as an exit node.** Turn on *Offer this Mac as an exit node* in the Mac app's **Exit node** section or the menu bar's **Exit node** menu, then approve it in the console like any other machine. The app relays the traffic itself, as Tailscale's macOS client does, so it is somewhat slower than Linux. While approved, the Mac stays awake as long as the Covee app is open (the display can still sleep; closing a laptop's lid still sleeps it). Like Tailscale, it shares the internet but not the Mac's own local network. A device cannot offer an exit node and use one at the same time. An iPhone cannot be an exit node.
- **After a Mac app update,** disconnect and connect once in Covee so macOS switches to the new network extension.

**A gateway to private networks.** `covee gateway <network>` adds a gateway device on the server, so devices in the network can reach places only the server can: a cloud's private networks (for example Azure's Key Vault and AKS behind private endpoints), or the internet with the server's own address, for services that allow only that address. `covee gateway <network> --off` removes the device and keeps its settings for next time. Run `covee update` first.
- **Choosing what goes through it.** On the console's **Gateway** page, add entries: a name, one or more destinations (address ranges such as `10.20.0.0/16`, addresses, or host names such as `cluster0-shard-00-00.abc.mongodb.net`), and who may use them (everyone in the network, or chosen people). Everything else goes from each device directly. Host names are looked up from the server every 5 minutes, so private names get their private addresses; a name that fails to resolve keeps its previous addresses.
- **Private DNS.** Also on the Gateway page, list domains (such as `blob.core.windows.net`) whose names a private resolver answers (Azure's is `168.63.129.16`). Devices ask it through the gateway. List a service's private zone too when it lies outside the public domain: Key Vault needs `vault.azure.net` and `privatelink.vaultcore.azure.net`, since Macs and iPhones look up the private name separately. The server applies a change within a minute; the coordinator restarts for a few seconds, and devices stay connected.
- **What the console keeps in step.** The device offers exactly the listed routes, they are approved, and each entry has its own access rule (plus one for the private resolvers). The console removes only rules it added itself; the rest of the policy and its comments stay.
- **On devices.** The Mac and iPhone apps use the gateway's routes while **Use the network's gateway** is on (Settings, or the menu bar on a Mac). Linux machines need `tailscale up --accept-routes`.
- **How it runs.** The device runs unprivileged in user space, like the in-network console, and forwards by connecting from the server, so traffic leaves with the server's address. Nothing about the server's firewall changes; what the server itself may reach is up to its own network (for a cloud server, its security group).

**Certificates.** `cert renew` gets a new Let's Encrypt certificate and installs it. It also reissues the runtime's internal certificates, which last only 90 days. It works even when certificates are about to expire or already have, which the deployment tool's normal validation would otherwise refuse. The internal CA lasts a year and is not renewed; `status` warns 60 days ahead.

**Backups.**
1. `backup` creates an age key for the network on first use. The private half goes only to your secrets store, as `backup-age-identity`, never to the server.
2. It takes a stopped-service snapshot on the server and downloads it to `~/.config/covee/backups/<network>/`.
3. It checks the download against the server's SHA-256.
4. It decrypts the archive on this computer to prove it holds this network's deployment description and coordinator database.
5. The newest three backups also stay on the server.

**Updates.** `update` installs the CLI's embedded files, rebuilds the images and restarts the runtime. If the build fails, the network keeps running the previous images.

**A changing home address.** Home connections, and some office ones, get a new public address from time to time; the hostname then points at the old one and the network is unreachable. `covee dns auto <network>` (or the setup question) fixes that:
- **Route 53 only.** The updater is for hostnames in Route 53.
- **What runs.** A timer on the server, `covee-dns.timer`, runs `/opt/covee/dns-updater/dns_updater.py` every 5 minutes. It asks `checkip.amazonaws.com` which address the server's traffic comes from and compares it with the Route 53 record. When they differ, it changes the record (TTL 300 seconds). It prints nothing while nothing changes.
- **Its own narrow AWS key.** Covee creates IAM user `covee-<network>-dns`. Its only permissions are reading the zone and UPSERTing the hostname's A record. The key is kept as `dns-updater-key` in the secrets store and in `/srv/covee/secrets` on the server.
- **A test before each change.** When the router lets the server reach itself through the public address, the updater first checks that the new address answers as this network, so a VPN's address is never published. Setup also asks before taking over a record that points somewhere other than the server's own public address.
- **Checking it.** `covee status` shows the updater's last run. `covee update` refreshes its script. `covee dns auto <network> --off` removes it from the server and deletes the IAM user.

**Moving a network to another name.** `covee rename <network> --hostname control.example.org --mesh-domain home.example.org` moves a running network to a new public hostname and a new name suffix for its devices, for example from a name on someone else's domain to one on your own. Run `covee update` first. The suffix defaults to `mesh.<your domain>`, and the hostname must stay outside it, because devices answer names under the suffix themselves.
- **Prepared first, while the network runs.** The new hostname gets an A record at the connection's current address. Microsoft's Covee app gets the new return address through Microsoft Graph. For Google and Apple, which have no API for this, covee shows what to add and then waits until Google's or Apple's own sign-in page accepts the new address. Then a Let's Encrypt certificate names the new hosts. Nothing on the server changes until all of this has worked, so a run that stops here can simply be repeated.
- **One switch on the server.** `deploy.py rename` stops every service, rewrites the coordinator, sign-in, console and gateway settings for the new names, installs the certificate and starts again. The sign-in service's address changes with the hostname, so the coordinator's accounts are moved to it as well: people keep their accounts. If anything fails, every file and the coordinator database are put back and the network keeps its old names.
- **Afterwards.** The address updater may change only the new record. covee offers to delete the old record, which nothing keeps current any more. The providers keep accepting the old address until you remove it there.
- **Devices keep their sign-in** but need the new address once. In the Covee app, disconnect, change the coordinator address, and connect. On a Linux machine with the Tailscale client, run `sudo tailscale down && sudo tailscale up --login-server=https://<new hostname>`; if it lists settings the machine already has, run the complete command it shows. A device that has not been given the new address cannot reach the network.
- **Not with Covee accounts.** Their passkeys belong to the old name, so `rename` refuses while Covee accounts are on.

For scripted runs, `COVEE_ANSWERS=answers.json` supplies answers by question ID to any command, and no browser pages open.

## Not yet available

- **Automatic renewal and scheduled backups.** Both are run by hand for now.
- **A reachability check from outside your own network.**
- **Servers other than Ubuntu 24.04 on amd64.**
