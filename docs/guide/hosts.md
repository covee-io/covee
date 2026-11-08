# Give your services their own addresses

A host is an address of your choosing for a service on one of your devices. For example, `https://grafana.mesh.example.com` can open port 8080 of the device `mac-mini`, at the path `/some/sub/service`. Browsers show a valid certificate, and you don't need to remember a device, a port or a path.

Only devices in your network can open a host. From anywhere else the name doesn't exist, and nothing new is reachable from the internet.

## Add a host

```sh
covee update <network>     # hosts need current Covee files
covee host add <network> grafana --to mac-mini:8080/some/sub/service
```

The address is the name you chose followed by the name ending of your network's devices. The command prints the full address.

The first host on a network asks you to confirm three changes:

- A device called `hosts` joins the network, on the server. It receives the requests and passes them to your services.
- The network's certificate is renewed to cover every name under that ending.
- The coordinator restarts once, and devices reconnect within a minute.

After that, adding or removing a host takes a few seconds and doesn't disconnect anyone.

## What the service needs

- **The device must be connected to the network**, and its name must be the one shown under **Devices** or in `covee status`.
- **The service must accept connections from the network.** A service that listens only on `localhost` can't be reached this way. Set it to listen on all addresses (`0.0.0.0`), or on the device's network address.
- **Apps that build their own links** may need to be told their new address, or their path. This is usually a setting such as "public URL" or "base path".

If the service itself uses HTTPS, add `--https`. If its certificate is self-signed, also add `--no-verify`, which skips checking that certificate.

## Change and remove hosts

```sh
covee host list <network>            # every host and where it goes
covee host add <network> grafana --to mac-mini:3000   # the same name again changes where it goes
covee host remove <network> grafana
covee host off <network>             # remove every host and the hosts device
```

## Who can open a host

Everyone with a signed-in device in the network, on any device that's connected. Tagged devices, such as servers joined with a device key, can't. The service's own sign-in, if it has one, still applies.

Covee adds the access rules for this by itself: people's devices may reach the hosts device, and the hosts device may reach only the device and port of each host. It removes the rule for a target once no host uses it.

## Good to know

- A host's name can't be the same as a device's name, because both end in the same way. The names `hosts`, `console`, `gateway` and `admin` are reserved.
- To rename a network that has hosts, run `covee host off <network>` first, then rename it and add the hosts again.
