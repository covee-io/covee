# Connect your devices

Every device needs the network's address, such as `https://covee.example.com`, and someone allowed to sign in: a person in the Microsoft group, an approved Google or Apple account, or an invited Covee account. Servers and other machines without a person can join with a device key instead.

## Mac

1. Download [Covee.dmg](https://github.com/covee-io/covee/releases/latest/download/Covee.dmg) from the latest release, open it and drag Covee to Applications. Or: `brew install --cask covee-io/tap/covee`.
2. Open Covee. On the **Network** page, enter the network's address under **Coordinator** and click **Connect**.
3. The first time, macOS asks you to allow Covee's network extension, in System Settings → General → Login Items & Extensions → Network Extensions, and to add a VPN configuration. Allow both.
4. Covee shows **Complete sign in**. Click **Open coordinator sign in**, sign in on the network's page in your browser, and return to Covee: the Mac is connected.

Covee remembers each network it connects to. To move to another, choose **Switch network** on the Network page or in the menu bar; while disconnected, pick one under **Your networks**. A network you have used before needs no new sign-in.

Covee also lives in the menu bar. From there you can disconnect, see the other devices and copy their addresses, choose an exit node, and turn the network gateway's routes on or off (**Use the network's gateway**). Closing or quitting Covee leaves the Mac connected, and if the connection stops for any other reason, it starts again by itself; choose **Disconnect** to leave the network. Requires macOS 15 or later on Apple silicon.

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

Tailscale's own apps also work with your own server. On Windows, install Tailscale and run `tailscale login --login-server=https://covee.example.com` in a terminal. Tailscale on Windows disconnects when you exit it from the taskbar or sign out of Windows; to stay connected, right-click its icon in the taskbar and turn on **Preferences → Run unattended** (or run `tailscale set --unattended=true`). On Android, open the app's account menu before signing in, choose **Use an alternate server** and enter your network's address. These platforms have not been tested with Covee yet.

## Terminal and screen sharing

Covee for Mac and iPhone can open a terminal on another device in the network, or show its screen. Choose a device under **Devices**; on a Mac, the menu bar's **Devices** menu offers the same.

- **Open terminal** signs in over SSH. A server that runs Tailscale with SSH turned on lets you in with your network identity, with no key or password (see below). Otherwise Covee signs in with its own SSH key, which it makes on your device and keeps in the Secure Enclave where there is one. The first time, a device may not know that key yet: sign in with the password once, and Covee offers to install its key. **Settings → Copy Covee's SSH key** gives the key, to add to `~/.ssh/authorized_keys` yourself.
- The first connection to a device shows its SSH identity to confirm. Covee remembers it and refuses to connect if it ever changes, in case another computer is posing as the device. A device that was reinstalled has a new identity; choose **Forget the old identity** to accept it.
- **Share screen** opens macOS Screen Sharing on a Mac. On iPhone and iPad the screen opens in Covee:
  - tap to click, tap with two fingers for a right click;
  - touch and hold, then move, to drag;
  - pinch to zoom; two fingers move around a zoomed screen, or scroll it when it isn't zoomed;
  - the keyboard button types, with Esc, Tab, arrows and modifier keys above the keyboard.
- The other device must allow it. On a Mac, turn on **Remote Login** for the terminal and **Screen Sharing** for its screen, in System Settings → General → Sharing. On Linux, an SSH server, or Tailscale SSH.
- An iPhone or iPad can't be reached this way, since iOS has no SSH or screen sharing server.

**Signing in to servers without keys.** On a Linux server that runs Tailscale, turn on Tailscale SSH:

```sh
sudo tailscale set --ssh
```

Then allow it in the policy's `ssh` list. The console's **Access policy** page has this rule ready to copy; it lets everyone sign in as any user but root to servers tagged `tag:server`:

```json
{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server"], "users": ["autogroup:nonroot"]}
```

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
