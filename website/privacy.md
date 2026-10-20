# Privacy

Covee is free, open-source software that you run yourself, made by Helder Feixas. This page covers this website, the Covee apps for Mac and iPhone, and the `covee` command.

## In short

Covee collects nothing. The apps and the `covee` command send no analytics, crash reports or other data to the Covee project or to anyone else. There is no Covee account and no Covee service.

## The apps and the covee command

- They connect only to the network server that you or your organization run, and to the services that network uses: your sign-in provider (Microsoft, Google or Apple) when you sign in, and, for the `covee` command, the DNS host, Let's Encrypt, the cloud accounts chosen during setup and checkip.amazonaws.com, to learn a network's public address.
- Your network's server keeps what a network needs about you: your name and email address from your sign-in provider, your devices' names and addresses, and when they were last online. It stays on that server, under the control of whoever runs it; the Covee project never receives it. Ask your network's administrator what they keep and for how long.
- On your device, the app keeps your network's address, its settings and the keys that identify the device, in the device's own storage and Keychain.
- Traffic between devices is end-to-end encrypted with WireGuard. The network's server relays it when two devices cannot connect directly, but cannot read it.
- Your network's server tells Tailscale's apps, which can also join a Covee network, not to send their diagnostic logs to Tailscale. Tailscale's apps are covered by [Tailscale's privacy policy](https://tailscale.com/privacy-policy).

## Testing through TestFlight

If you test a Covee app through Apple's TestFlight, Apple shares with the developer what TestFlight collects: your name and email address if you were invited by email, the app's crash reports, and any feedback you choose to send. They are used only to fix problems in Covee. See [Apple's TestFlight terms](https://www.apple.com/legal/internet-services/itunes/testflight/sren/terms.html).

## This website

- covee.io is a static website hosted by GitHub Pages. It sets no cookies, has no analytics or tracking, and loads nothing from other sites.
- Like any web host, GitHub receives your IP address and browser details when you visit, and when you download Covee from its release pages. See [GitHub's privacy statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement).

## Questions

Open an issue on [GitHub](https://github.com/covee-io/covee/issues). For a security problem, report it privately as described in the [security policy](https://github.com/covee-io/covee/security/policy).

## Changes

If this policy changes, the new version is published here with its date. Last updated 19 October 2026.
