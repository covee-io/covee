# Covee

**Your own private network.** Covee connects your devices, wherever they are, over direct, encrypted [WireGuard](https://www.wireguard.com/) connections, coordinated by a server you own. People sign in with Microsoft, Google, Apple or a Covee account. No per-user or per-device limits, and no Covee service in the middle.

- **One command sets it up.** `covee setup` turns a fresh Ubuntu server, in a cloud or at home, into a complete network: coordinator, relay, sign-in, certificate and admin console.
- **Works with the clients you know.** The Covee apps for Mac and iPhone, and Tailscale's clients on Linux and other platforms, connect to your server.
- **Reach what only the server can.** The optional gateway carries chosen traffic to a cloud's private networks, or out through the server's address for allowlisted services, configured in the admin console.
- **Yours to run.** Everything lives on your server and your computer: no telemetry, no account with us.

Covee builds on [Headscale](https://github.com/juanfont/headscale), an open-source implementation of the Tailscale control server, and on the open-source [Tailscale](https://github.com/tailscale/tailscale) client engine. It is an independent project, not affiliated with Tailscale Inc.

## Get started

```sh
brew install covee-io/tap/covee      # or download from the releases page
covee setup                           # build your network
```

Then connect your devices: download **Covee for Mac** from the [releases page](https://github.com/covee-io/covee/releases/latest), or use Tailscale's client on other platforms. The [guide](docs/guide/README.md) walks through every step:

1. [What Covee is](docs/guide/introduction.md), and what you need
2. [Install the covee command](docs/guide/install.md)
3. [Set up your network](docs/guide/server.md)
4. [Connect your devices](docs/guide/devices.md)
5. [Reach private networks through the gateway](docs/guide/gateway.md)
6. [Run your network](docs/guide/operations.md)
7. [Security](docs/guide/security.md)

## Status

Covee is young. It runs real networks, but expect rough edges, and read [what is not there yet](docs/guide/introduction.md#what-is-not-there-yet). Servers must run Ubuntu 24.04 on amd64; the Mac app needs macOS 15 on Apple silicon; the iPhone app is in TestFlight.

## In this repository

| Path | What |
| --- | --- |
| `cli/` | the `covee` command (Go) |
| `cmd/`, `internal/` | the server's services: management API and admin console, sign-in broker, TLS gateway (Go) |
| `deploy/` | container images and compose files for the server, including the gateway device |
| `native/` | the Mac and iPhone apps (SwiftUI) and their packet engine (Go, built on Tailscale's) |
| `scripts/` | the deployment tool the server runs (`deploy.py`), server preparation, build and release tools |
| `tests/` | tests for the Python tools; Go and Swift tests sit beside their code |
| `docs/` | the [guide](docs/guide/README.md), the [CLI reference](docs/cli.md) and design notes |

## Building from source

```sh
python3 scripts/build_cli.py              # the covee command, in dist/cli/
python3 scripts/apple.py build            # the Mac and iPhone apps, unsigned
python3 -m unittest discover -s tests     # Python tests
(cd cli && go test ./...) && go test ./... # Go tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for more.

## License

Covee is licensed under the [Apache License 2.0](LICENSE). It includes and builds on open-source software under their own licenses; release archives list them in `THIRD_PARTY_LICENSES.txt`. "Tailscale" is a trademark of Tailscale Inc. and "WireGuard" a registered trademark of Jason A. Donenfeld; Covee is not affiliated with either.
