# Run your network

Everything here runs from the computer that set the network up, or any computer with its record and keys (see [Install](install.md#where-covee-keeps-things)).

## At a glance

```sh
covee list                 # the networks this computer manages
covee status <network>     # services, and days left on every certificate and secret
covee console <network>    # the admin console, through an SSH tunnel
```

## People

- **Microsoft**: add people to the group `Covee <network> users` in Entra ID; they can then add devices. Administrators have the Covee Admin role on the network's app.
- **Google and Apple**: approve each account with `covee grant <network> --provider google --subject <id> [--role admin|reader|none]`. The role is the person's access to the admin console and defaults to `admin`; use `none` for someone who only adds devices. The ID appears on the page shown to someone who signs in before being approved.
- **Covee accounts**: `covee users invite <network> --email E --name N` makes a one-time invite link (valid 72 hours) to send privately. `covee users list | update | reset | remove` manage them.
- Sign-in methods can be added or removed later: `covee auth add <network> microsoft|google|apple|accounts`, `covee auth remove …`. Devices stay connected.

## Devices and access

The admin console's **Devices** page lists every device, lets you rename, expire or remove one, and approve the exit nodes and local networks devices offer. **Access policy** holds the network's rules (who may reach what; see [Let devices reach each other](devices.md#let-devices-reach-each-other)); **Gateway** what goes through the gateway; **Activity** every change made in the console.

## Updates

When a new Covee version is out, update the command (`brew upgrade covee`), then each network:

```sh
covee update <network>
```

It installs the new files, rebuilds the services (several minutes) and restarts them; devices reconnect on their own within a minute.

The server installs security updates by itself but never restarts on its own. Restart it now and then, for example once a month, from your cloud provider's console or Proxmox, so kernel updates take effect. The services start again by themselves.

## Certificates

The public certificate comes from Let's Encrypt and lasts about three months. `covee status` shows the days left on it and on the network's internal certificates. Renew them when it shows 30 days or fewer:

```sh
covee cert renew <network>
```

The network's internal certificate authority lasts a year from setup and is not renewed by this command; `covee status` warns 60 days before it expires. Renewing the certificates automatically on the server is planned.

## Backups

```sh
covee backup <network>
```

The services pause for a few seconds while an encrypted snapshot is taken on the server; `covee` downloads it to `~/.config/covee/backups`, decrypts it there to check it can be restored, and keeps the newest three on the server too. The key that decrypts backups is kept only on your computer and in Parameter Store; a restore copies it to the new server for the restore and deletes it right after. To restore or move a network, run `covee setup` and choose "A backup of a network". Scheduled backups are planned.

## A changing home internet address

For a network at home whose domain is in Route 53, `covee dns auto <network>` makes the server check its public address every five minutes and update the record. It uses an AWS key that may change only that one record. `--off` removes it.

## A new name

`covee rename <network> --hostname covee.example.org` moves a running network to a new address and device name suffix. It needs current Covee files on the server (run `covee update` first), and is not available while Covee accounts are turned on. Devices keep their sign-in; each needs the new address once.

## Where things are kept

On your computer, `~/.config/covee`: the network records (never secret values), private copies of keys and secrets, certificates and backups. With Parameter Store, every secret is also in AWS as `/covee/<network>/<name>`. On the server, `/srv/covee` holds the network and `/opt/covee` Covee's files.

See the [CLI reference](../cli.md) for every option.
