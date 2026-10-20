# Releasing Covee

Covee is released as open source under the [Apache 2.0 license](../LICENSE). A release is built by `scripts/release.py` on a Mac, from a committed version of the code, and published as a GitHub release.

## What a release contains

| File | For |
| --- | --- |
| `covee_<version>_darwin_arm64.tar.gz`, `…_darwin_amd64.tar.gz` | the `covee` command on Macs with Apple silicon or Intel |
| `covee_<version>_linux_amd64.tar.gz`, `…_linux_arm64.tar.gz` | the `covee` command on Linux |
| `Covee.dmg` | the Mac app (Apple silicon, macOS 15 or later), on a disk image signed with the Developer ID, notarized by Apple and stapled, so it opens without a warning even offline. The name is the same in every release, so `releases/latest/download/Covee.dmg` always downloads the newest; the volume and the app carry the version |
| `SHA256SUMS` | checking the downloads |

Each archive carries `LICENSE`, `NOTICE` and `THIRD_PARTY_LICENSES.txt`, the license of every Go module compiled into it, as the Tailscale, Headscale and other licenses require. The `covee` command embeds the server it installs, so one download is all a network administrator needs. Linux devices join with the standard Tailscale client. The iPhone app goes through TestFlight, separately.

## Making a release

```sh
python3 scripts/release.py build --version 0.1.0
python3 scripts/release.py publish --version 0.1.0
# after publishing the draft on GitHub:
python3 scripts/release.py tap --version 0.1.0
```

`build` refuses uncommitted changes and exports the commit, so only committed files are released. It runs every test, builds the four `covee` archives with the server payload embedded, signs and notarizes the Mac builds, builds and notarizes the Mac app with `apple_release.py`, puts it on a disk image that it signs, notarizes, staples and checks with Gatekeeper, and writes everything into `dist/release/<version>/` with `manifest.json`, `notes.md`, the Homebrew formula `covee.rb` (the CLI) and cask `covee-cask.rb` (the Mac app). It takes about as long as the Mac app's notarization plus the tests.

`publish` tags the built commit `v<version>`, pushes the tag and creates a **draft** GitHub release on `covee-io/covee` with the files and notes. Nothing is public until the draft is published on GitHub. It refuses a build that skipped tests or the Mac app, or whose files changed afterwards.

`tap`, once the release is published, commits the formula and the cask to `covee-io/homebrew-tap`, so that `brew install covee-io/tap/covee` installs the CLI and `brew install --cask covee-io/tap/covee` the Mac app. It refuses a release that is still a draft, whose downloads would not work yet.

The Mac app's version comes from `MARKETING_VERSION` in `native/apple/project.yml`; `build` stops if it does not match `--version`.

## The iPhone app in TestFlight

```sh
python3 scripts/apple_release.py testflight --upload
```

builds the iPhone app for the App Store, checks the Apple Distribution signature, the TestFlight entitlements and the privacy manifests (`App/PrivacyInfo.xcprivacy`, `PacketTunnel/PrivacyInfo.xcprivacy`), and uploads it through the Apple account signed in to Xcode. Without `--upload` it stops after the checks. The app is **Covee Network** in App Store Connect (the name "Covee" was taken; the phone still shows Covee), bundle ID `io.covee.ios`. The internal group **Covee testers** receives every new build automatically; App Store Connect users on the team can be added to it, up to 100. The export-compliance answer (standard encryption only, no documents needed) is recorded as `ITSAppUsesNonExemptEncryption` in the app's Info.plist. The App Store itself accepts VPN apps only from organization developer accounts.

## What a signed release needs

- **A Mac with Xcode**, Go, Python 3 and the AWS CLI. `publish` and `tap` also need the GitHub CLI (`gh`), signed in with push access to `covee-io/covee` and `covee-io/homebrew-tap`; `--repo` and `--tap` name other repositories.
- **The team's Apple account, signed in to Xcode.** `apple_release.py` signs the Mac app with Xcode-managed signing and sends it to Apple's notary service through that account. The app itself needs no local certificate.
- **A Developer ID Application certificate, with its private key, in the login keychain**, for the team `87LFD98HJU`: `TEAM` in `scripts/release.py` and the default `--team` of `scripts/apple_release.py`. `build` finds it with `security find-identity -v -p codesigning` and signs the Mac `covee` builds and the disk image with it. Create one in Xcode (Settings → Accounts → Manage Certificates → + → Developer ID Application) or at developer.apple.com (Certificates → + → Developer ID Application). Without it, `build` stops. `--unsigned` lets the Mac `covee` builds go unsigned, and the release notes then say so, but the disk image is always signed: a build without the certificate also needs `--skip-app`, which `publish` refuses.
- **An App Store Connect API key for notarization**, in AWS Systems Manager Parameter Store in `us-east-1`: the `.p8` file's text as the SecureString `/covee/release/notary-key`, its key ID as `/covee/release/notary-key-id` and the issuer ID as `/covee/release/notary-issuer`. A team key with the Developer role is enough. The AWS CLI must be signed in with permission to read and decrypt them. `build` writes the key to a private temporary file for each upload and never prints it. The names and the region are constants at the top of `scripts/release.py` (`NOTARY_KEY`, `NOTARY_KEY_ID`, `NOTARY_ISSUER`, `REGION`), and `python3 scripts/release.py --help` lists them; no option changes them.
- **The Homebrew tap**: the public repository `covee-io/homebrew-tap` holds `Formula/covee.rb` and `Casks/covee.rb`, which `release.py tap` updates after each published release.

Certificates expire. Note the Developer ID certificate's expiry date, shown in Keychain Access and under Certificates on developer.apple.com, and make a new one before it passes: `build` uses only a valid certificate, so it stops at signing once the old one has expired.
