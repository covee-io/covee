# Connect your devices

Every device needs the network's address, such as `https://covee.example.com`, and someone allowed to sign in: a person in the Microsoft group, an approved Google or Apple account, or an invited Covee account. Servers and other machines without a person can join with a device key instead.

## Mac

1. Download [Covee.dmg](https://github.com/covee-io/covee/releases/latest/download/Covee.dmg) from the latest release, open it and drag Covee to Applications. Or: `brew install --cask covee-io/tap/covee`.
2. Open Covee. On the **Network** page, enter the network's address under **Coordinator** and click **Connect**.
3. The first time, macOS asks you to allow Covee's network extension, in System Settings → General → Login Items & Extensions → Network Extensions, and to add a VPN configuration. Allow both.
4. Covee shows **Complete sign in**. Click **Open coordinator sign in**, sign in on the network's page in your browser, and return to Covee: the Mac is connected.

Covee also lives in the menu bar. From there you can disconnect, see the other devices and copy their addresses, choose an exit node, and turn the network gateway's routes on or off (**Use the network's gateway**). Requires macOS 15 or later on Apple silicon.

## iPhone

The Covee iPhone app is in testing (TestFlight) and not yet in the App Store. Meanwhile, use Tailscale's iPhone app, which works with your own server:

1. Install [Tailscale](https://apps.apple.com/app/tailscale/id1470499037) from the App Store, and don't sign in yet.
2. In the iPhone's **Settings** app, scroll to the apps, open **Tailscale**, and enter your network's address under **Alternate Coordination Server URL**. If the phone was signed in to Tailscale before, also turn on **Reset Keychain**.
3. Close Tailscale from the app switcher, open it again and choose the regular sign-in (not single sign-on). Your network's sign-in page opens.

## Linux

Install the standard [Tailscale client](https://tailscale.com/download/linux), then:

```sh
sudo tailscale up --login-server=https://covee.example.com
```

It prints a link; open it on any device and sign in. To use what the network's gateway offers, add `--accept-routes`.

## Windows, Android and others

Tailscale's own apps also work with your own server. On Windows, install Tailscale and run `tailscale login --login-server=https://covee.example.com` in a terminal. On Android, open the app's account menu before signing in, choose **Use an alternate server** and enter your network's address. These platforms have not been tested with Covee yet.

## Servers and machines without a person

In the admin console, open **Devices → Add a device** and choose **A server or other machine**. The console makes a one-time key owned by a tag (such as `tag:server`) and shows the commands to run on the machine; it can also let everyone in the network reach the new machine. From your computer, `covee device token <network> --tag server` makes the same kind of key and prints the command to run; then allow the tag on the console's **Access policy** page.

A tagged machine stays connected until you remove it. Devices of people sign in again when the network's device period ends (30 days).

## Let devices reach each other

A new network allows no traffic between devices: each device reaches the network's own services, such as the console, but no other device, until an administrator allows it on the console's **Access policy** page. For example, this rule lets every person's devices reach each other on every port:

```json
{"src": ["autogroup:member"], "dst": ["autogroup:member"], "ip": ["*"]}
```

Add it to the `grants` list in the policy, next to the rules Covee keeps there for the console, servers, shared networks and the gateway. Rules use [Tailscale's policy syntax](https://tailscale.com/kb/1324/grants), as Headscale implements it, and the console checks a policy before saving it.

## Exit nodes and shared local networks

A device can offer itself as an **exit node**, so others send their internet traffic through it, or share a **local network** behind it (such as a home or office network). An administrator approves this in the console (**Manage** on the device), and can let everyone use it.

Next: [reach private networks through the gateway](gateway.md).
