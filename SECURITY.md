# Security policy

## Reporting a vulnerability

Please report security problems **privately**, through [GitHub's private vulnerability reporting](https://github.com/covee-io/covee/security/advisories/new) for this repository. Do not open a public issue for a vulnerability.

Include what you found, how to reproduce it, and what it lets an attacker do. You will get an answer as soon as possible. Covee is maintained by one person, so allow a few days. Once a fix is released, the advisory is published with credit to you, unless you prefer otherwise.

## Supported versions

Security fixes go into the latest release. Update the `covee` command and run `covee update <network>` to get them on a network.

## Scope

In scope: the `covee` command, the server services and deployment tooling in this repository, the gateway device, and the Mac and iPhone apps.

Problems in Headscale, Tailscale or WireGuard themselves belong with those projects; if you are unsure, report here and it will be passed on.

## How Covee is protected

See [docs/guide/security.md](docs/guide/security.md).
