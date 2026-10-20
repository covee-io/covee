# Reach private networks through the gateway

The gateway is a device on the network's server that carries devices' traffic to places only the server can reach:

- **A cloud's private networks**: for example databases, Kubernetes APIs and private endpoints (Azure Key Vault, storage) in the virtual network the server is in, or in networks peered with it.
- **Services that allow only one address**: traffic to them leaves through the server, so the service sees the server's address (or its cloud NAT gateway's), which it already allows.

You choose exactly what goes through it. Everything else goes from each device directly.

## Turn it on

```sh
covee update <network>     # the gateway needs current Covee files
covee gateway <network>
```

A gateway device joins the network. Nothing goes through it yet.

## Choose what goes through it

Open the admin console (`covee console <network>`) and go to **Gateway**.

- **Add destination**: give it a name, list the destinations, and choose who may use them.
  - Destinations can be address ranges (`10.40.0.0/16`), single addresses (`203.0.113.7`) or host names (`db.example.com`). The server looks host names up every five minutes, so a private name gets its private address, and a service whose addresses change keeps working.
  - **Who**: everyone in the network, or only the people you choose.
- **Private DNS**: list domains, such as `blob.core.windows.net`, whose names a private resolver answers, such as Azure's `168.63.129.16`. Devices then get the private address of a private endpoint by its usual name. When a service's private zone is not inside its public domain, list both: Azure Key Vault needs `vault.azure.net` and `privatelink.vaultcore.azure.net`, because Macs and iPhones look up the private name separately. The server applies a change within a minute; the coordinator restarts for a few seconds and devices stay connected.

The page shows whether each entry is active, and the addresses it found for each host name. The console keeps the network's access rules for the gateway in step by itself, and never changes rules it did not add.

## On devices

- **Mac and iPhone (Covee app)**: on by default. Turn **Use the network's gateway** off in Settings or the menu bar to stop using it.
- **Linux**: `sudo tailscale set --accept-routes`.

## What the server must be able to reach

The gateway can only reach what the server can. In a cloud, allow the server's outbound traffic to the private networks you list, in its security group or network security group. For services that check the address, use the address the server's traffic leaves with: its public address, or its NAT gateway's.

Traffic through the gateway is encrypted from the device to the server. From there it continues to its destination as if the server had sent it.

## Managing the server through the gateway

The server also accepts SSH from the gateway. If a gateway entry covers the server address `covee` connects to (the address you gave setup), administrators whose devices may use that entry can run `covee` commands through the network itself, without a separate VPN or tunnel to the server.

## Turn it off

```sh
covee gateway <network> --off
```

The device is removed; the Gateway page keeps its settings for the next time.

Next: [run your network](operations.md).
