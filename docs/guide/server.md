# Set up your network

`covee setup` builds a complete network on a server you choose, sign-in included. It asks its questions first, shows a summary, and changes nothing until you confirm it; a few confirmations come later, during the run, such as accepting Let's Encrypt's agreement. It takes about fifteen minutes, most of it building the services on the server.

## 1. Prepare a server

Choose one:

- **A cloud VM** with a public IPv4 address, running Ubuntu 24.04 LTS (amd64), with at least 2 CPUs, 4 GB of memory and a 32 GB disk (4 CPUs and 8 GB are better). You must be able to run `ssh <user>@<address>` without a password prompt, as a user other than `root` who can `sudo` without a password (the default on most cloud images). In the provider's firewall (security group, network security group), allow:
  - TCP 443 and UDP 3478 from anywhere;
  - SSH (TCP 22) only from your own address or a management network.
- **A server at home or in an office**, physical or virtual, with Ubuntu 24.04 (amd64), the same size and the same kind of SSH access. On your router, forward TCP 443 and UDP 3478 to it. If your internet address changes from time to time and your domain is in Route 53, Covee keeps the record up to date.
- **A new VM on a Proxmox host**: `covee` creates it for you over `ssh root@<proxmox host>`, with 4 CPUs, 8 GB of memory and a 64 GB disk, or 2 CPUs, 4 GB and 32 GB. The host needs a storage with the "Snippets" content type for cloud-init files, and a free fixed address on your network.

The server is dedicated to Covee: setup replaces its SSH access with a `covee` account and a key it creates, and installs a firewall that admits only SSH from the networks you allow, plus TCP 443, UDP 3478 and ping.

## 2. Choose a name

Pick a hostname on a domain you own, such as `covee.example.com`. Devices get names under a suffix that defaults to `mesh.example.com`. If your DNS is in **Route 53** or **Cloudflare**, `covee` creates and updates the records itself:

- Route 53: it uses your AWS CLI credentials.
- Cloudflare: create an API token from Cloudflare's "Edit zone DNS" template, limited to your zone. Give `covee` a file or Parameter Store name holding it, or paste it when asked; it is never shown. The record must stay "DNS only": Cloudflare's proxy cannot carry the network's connections.

With any other DNS host, `covee` shows the records to add and waits until they resolve.

## 3. Choose how people sign in

- **Microsoft (Entra ID / Microsoft 365)**: sign in to the Azure CLI as a tenant administrator first. `covee` registers the network's own app and a group `Covee <network> users`; people in that group can add devices.
- **Google** or **Apple**: during the run, `covee` guides you through creating the sign-in app in their consoles, and checks what you enter.
- **Covee accounts**: people sign in with a passkey, or a password plus an authenticator app. You invite each person with a one-time link.

## 4. Run setup

```sh
covee setup
```

You will be asked for:

- the organization and network name;
- the hostname and device name suffix, and where the DNS is;
- the server: an existing one (its address and admin user) or a new Proxmox VM;
- the networks allowed to reach SSH: one to eight IPv4 ranges, each a /24 or narrower, including the address you connect from (setup refuses settings that would lock you out);
- the public address the hostname should point to;
- the sign-in methods;
- where to keep the network's keys and secrets: AWS Parameter Store, or only on this computer.

After your confirmation, setup creates the server's login key, registers sign-in, sets the DNS record, gets a free [Let's Encrypt](https://letsencrypt.org/) certificate (it asks before accepting their Subscriber Agreement), hardens the server, installs Docker, builds and starts the services, and checks that the network answers. If anything fails, fix the cause and run `covee setup <network>` again: it continues where it stopped.

When it finishes:

```
Network home is running at https://covee.example.com.
```

## 5. Check it

```sh
covee status <network>     # services, certificates and secrets, with days left
covee console <network>    # the admin console, through an SSH tunnel
```

The admin console opens at `https://localhost:8444`; your browser warns about its private certificate the first time, which is expected. Sign in with an administrator account. Devices in the network can also open it at `https://console.<suffix>`, with a normal certificate.

A new network allows no traffic between devices until you add a rule for it in the console. [Connect your devices](devices.md) shows how.

## Moving to another server

`covee backup <network>` saves an encrypted backup. `covee setup`, choosing "A backup of a network", rebuilds the network on a new server from it, with every device, account and setting; devices follow on their own once the DNS record moves.

Next: [connect your devices](devices.md).
