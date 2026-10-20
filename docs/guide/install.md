# Install the covee command

`covee` is a single program for macOS (Apple silicon and Intel) and Linux (amd64 and arm64). It carries the Covee files it installs on your server, so there is nothing else to install on your computer.

## With Homebrew (Mac or Linux)

```sh
brew install covee-io/tap/covee
```

## From the release page

Download the archive for your computer from the [latest release](https://github.com/covee-io/covee/releases/latest):

| Computer | Archive |
| --- | --- |
| Mac with Apple silicon | `covee_<version>_darwin_arm64.tar.gz` |
| Intel Mac | `covee_<version>_darwin_amd64.tar.gz` |
| Linux, amd64 | `covee_<version>_linux_amd64.tar.gz` |
| Linux, arm64 | `covee_<version>_linux_arm64.tar.gz` |

Check it against `SHA256SUMS` from the same release, then unpack it and put `covee` on your path:

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing
tar -xzf covee_<version>_darwin_arm64.tar.gz
sudo install covee_<version>_darwin_arm64/covee /usr/local/bin/covee
covee version
```

The Mac builds are signed with a Developer ID and notarized by Apple, so macOS opens them without a warning.

## Tools covee uses when you need them

- `ssh`, to reach your server (already on macOS and Linux).
- The [AWS CLI](https://aws.amazon.com/cli/), signed in, if you use Route 53 or Parameter Store.
- The [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli), signed in as a tenant administrator (`az login --allow-no-subscriptions`), if people sign in with Microsoft.

## Where covee keeps things

`covee` keeps each network's record, its keys and secrets, and its certificates in `~/.config/covee`, readable only by you. Keep that folder safe. If you choose Parameter Store during setup, the keys and secrets are kept there too, and another computer can manage the network once you copy the network's record (`~/.config/covee/networks/<network>.json`) to it.

Next: [set up your network](server.md).
