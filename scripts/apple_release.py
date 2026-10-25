#!/usr/bin/env python3
"""Sign and install the Covee apps through the Apple account signed in to Xcode.

Mac (`macos`): sign, notarize and optionally install. iPhone (`ios`): sign for
development and install on a connected iPhone (see the end of this text).

It needs no local Developer ID certificate or notary keychain profile, only
the Apple account signed in to Xcode:

1. Archive with Xcode-managed development signing. The -development
   entitlements stand in because development profiles do not offer the
   system-extension Network Extension values.
2. Export for Developer ID with destination "upload". Xcode re-signs with the
   final entitlements and submits the app to Apple's notary service.
3. Export the notarized, stapled app once Apple has accepted it.
4. Verify the signature, Gatekeeper, the staple, the entitlements and the
   Info.plist values the system extension depends on.
5. With --install, place it at /Applications/Covee.app. A previous copy is moved
   into the release folder, not deleted.

  python3 scripts/apple_release.py macos [--team 87LFD98HJU] [--install] [--skip-engine]
  python3 scripts/apple_release.py ios --device UDID [--install] [--remove-bundle BUNDLE_ID] [--skip-engine]
  python3 scripts/apple_release.py testflight [--upload] [--skip-engine]

TestFlight (`testflight`): archive the iPhone app, export it for App Store
Connect with Xcode-managed distribution signing, check the signature,
entitlements and privacy manifests, and with --upload send it to App Store
Connect through the same Xcode account. The app must already exist in App
Store Connect with bundle ID io.covee.ios.

For the iPhone, the app is built with Xcode-managed development signing for the
named device (the phone must be registered to the team and in Developer Mode),
verified, and installed with devicectl. --remove-bundle uninstalls an older app,
such as a test build with another bundle identifier, after the new one is installed.

Automatic signing may register the io.covee.* App IDs and their capabilities
in the team's developer account. The script never enters or stores
credentials, and never starts the VPN.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
APPLE = ROOT / "native/apple"
OUT = ROOT / ".cache/covee/apple-release"
APP_NAME = "Covee.app"
EXTENSION = "Contents/Library/SystemExtensions/io.covee.macos.tunnel.systemextension"
NETWORK = "com.apple.developer.networking.networkextension"
SYSTEM_INSTALL = "com.apple.developer.system-extension.install"
APP_GROUPS = "com.apple.security.application-groups"
FINAL_NETWORK = ["packet-tunnel-provider-systemextension"]
NOTARY_WAIT_SECONDS = 45 * 60


# SwiftTerm makes its version string with a package build plugin; without these
# flags xcodebuild stops and waits for the plugin to be trusted in Xcode.
PACKAGE_FLAGS = ["-skipPackagePluginValidation", "-skipMacroValidation"]


class ReleaseError(RuntimeError):
    pass


def archive_command(project, archive, derived, team, build):
    return ["xcodebuild", "archive", "-project", str(project), "-scheme", "Covee-macOS", "-configuration", "Release",
            "-destination", "generic/platform=macOS", "-archivePath", str(archive), "-derivedDataPath", str(derived),
            "-allowProvisioningUpdates", "ARCHS=arm64", "ONLY_ACTIVE_ARCH=NO",
            "CODE_SIGN_STYLE=Automatic", f"DEVELOPMENT_TEAM={team}", "CODE_SIGN_IDENTITY=Apple Development",
            "COVEE_ENTITLEMENTS_VARIANT=-development", f"CURRENT_PROJECT_VERSION={build}"] + PACKAGE_FLAGS


def ios_build_command(project, derived, team, build, device):
    # The destination picks the SDK; -sdk would also build package build tools for the phone.
    return ["xcodebuild", "build", "-project", str(project), "-scheme", "Covee-iOS", "-configuration", "Release",
            "-destination", f"id={device}", "-derivedDataPath", str(derived),
            "-allowProvisioningUpdates", "ARCHS=arm64", "ONLY_ACTIVE_ARCH=NO",
            "CODE_SIGN_STYLE=Automatic", f"DEVELOPMENT_TEAM={team}", "CODE_SIGN_IDENTITY=Apple Development",
            f"CURRENT_PROJECT_VERSION={build}"] + PACKAGE_FLAGS


def ios_archive_command(project, archive, derived, team, build):
    return ["xcodebuild", "archive", "-project", str(project), "-scheme", "Covee-iOS", "-configuration", "Release",
            "-destination", "generic/platform=iOS", "-archivePath", str(archive), "-derivedDataPath", str(derived),
            "-allowProvisioningUpdates", "ARCHS=arm64", "ONLY_ACTIVE_ARCH=NO",
            "CODE_SIGN_STYLE=Automatic", f"DEVELOPMENT_TEAM={team}", "CODE_SIGN_IDENTITY=Apple Development",
            f"CURRENT_PROJECT_VERSION={build}"] + PACKAGE_FLAGS


def app_store_options(team, destination):
    """Export for App Store Connect: 'export' writes the .ipa here, 'upload' sends it to TestFlight."""
    return {"method": "app-store-connect", "destination": destination, "signingStyle": "automatic", "teamID": team,
            "uploadSymbols": True, "manageAppVersionAndBuildNumber": False}


def check_app_store_entitlements(app, extension, team):
    """App Store signed iPhone app and provider: packet tunnel, TestFlight allowed, no debugging."""
    problems = []
    for name, ents, bundle in (("app", app, "io.covee.ios"), ("extension", extension, "io.covee.ios.tunnel")):
        if ents.get(NETWORK) != ["packet-tunnel-provider"]:
            problems.append(f"{name}: Network Extension entitlement is {ents.get(NETWORK)}")
        if ents.get("application-identifier") != f"{team}.{bundle}":
            problems.append(f"{name}: application identifier is {ents.get('application-identifier')}")
        if ents.get("com.apple.developer.team-identifier") != team:
            problems.append(f"{name}: team entitlement is {ents.get('com.apple.developer.team-identifier')}")
        if ents.get("beta-reports-active") is not True:
            problems.append(f"{name}: not signed for TestFlight (beta-reports-active is {ents.get('beta-reports-active')})")
        if ents.get("get-task-allow"):
            problems.append(f"{name}: debugging entitlement get-task-allow must not be present")
    if problems:
        raise ReleaseError("unexpected App Store entitlements:\n  " + "\n  ".join(problems))


def check_ios_entitlements(app, extension, team):
    """Development-signed iPhone app and provider: packet tunnel only, no app groups or shared keychain."""
    problems = []
    for name, ents, bundle in (("app", app, "io.covee.ios"), ("extension", extension, "io.covee.ios.tunnel")):
        if ents.get(NETWORK) != ["packet-tunnel-provider"]:
            problems.append(f"{name}: Network Extension entitlement is {ents.get(NETWORK)}")
        if ents.get("application-identifier") != f"{team}.{bundle}":
            problems.append(f"{name}: application identifier is {ents.get('application-identifier')}")
        if ents.get("com.apple.developer.team-identifier") != team:
            problems.append(f"{name}: team entitlement is {ents.get('com.apple.developer.team-identifier')}")
        unexpected = set(ents) - {NETWORK, "application-identifier", "com.apple.developer.team-identifier", "get-task-allow", "keychain-access-groups"}
        if unexpected:
            problems.append(f"{name}: unexpected entitlements {sorted(unexpected)}")
        groups = ents.get("keychain-access-groups")
        if groups not in (None, [f"{team}.{bundle}"], [f"{team}.*"]):
            problems.append(f"{name}: keychain access groups are {groups}")
    if problems:
        raise ReleaseError("unexpected signed entitlements:\n  " + "\n  ".join(problems))


def export_options(team):
    return {"method": "developer-id", "destination": "upload", "signingStyle": "automatic", "teamID": team}


def build_number(now):
    # Each release needs a higher CFBundleVersion, or macOS keeps the installed extension.
    return now.strftime("%Y%m%d%H%M")


def check_entitlements(app, extension, team):
    """Raise unless both bundles carry exactly the entitlements the system extension needs."""
    group = [team + ".io.covee"]
    problems = []
    for name, ents, install in (("app", app, True), ("extension", extension, False)):
        if ents.get(NETWORK) != FINAL_NETWORK:
            problems.append(f"{name}: Network Extension entitlement is {ents.get(NETWORK)}, expected {FINAL_NETWORK}")
        if ents.get(APP_GROUPS) != group:
            problems.append(f"{name}: app groups are {ents.get(APP_GROUPS)}, expected {group}")
        if ents.get(SYSTEM_INSTALL, False) is not install:
            problems.append(f"{name}: system-extension install entitlement is {ents.get(SYSTEM_INSTALL)}")
        if ents.get("com.apple.developer.team-identifier") != team:
            problems.append(f"{name}: team entitlement is {ents.get('com.apple.developer.team-identifier')}")
        for debug in ("get-task-allow", "com.apple.security.get-task-allow"):
            if ents.get(debug):
                problems.append(f"{name}: debugging entitlement {debug} must not be present")
    if problems:
        raise ReleaseError("unexpected signed entitlements:\n  " + "\n  ".join(problems))


def check_info(app, extension, team, build):
    problems = []
    for name, info in (("app", app), ("extension", extension)):
        if info.get("CFBundleVersion") != build:
            problems.append(f"{name}: CFBundleVersion is {info.get('CFBundleVersion')!r}, expected {build!r}")
    if app.get("CFBundleIdentifier") != "io.covee.macos" or extension.get("CFBundleIdentifier") != "io.covee.macos.tunnel":
        problems.append("unexpected bundle identifiers")
    service = extension.get("NetworkExtension", {}).get("NEMachServiceName", "")
    if not service.startswith(team + ".io.covee."):
        problems.append(f"extension: NEMachServiceName {service!r} does not start with the app group {team}.io.covee")
    if problems:
        raise ReleaseError("unexpected Info.plist values:\n  " + "\n  ".join(problems))


class Release:
    def __init__(self, team, out):
        self.team = team
        self.out = out
        self.receipt = {"schemaVersion": 1, "status": "running", "team": team, "startedAt": now_iso(), "steps": [],
                        "credentialsEntered": False, "vpnStarted": False, "installed": False}

    def save(self):
        (self.out / "receipt.json").write_text(json.dumps(self.receipt, indent=2) + "\n", encoding="utf-8")

    def run(self, label, command, *, cwd=ROOT, check=True):
        log = self.out / f"{label}.log"
        print(f"{label}…", flush=True)
        with log.open("w", encoding="utf-8") as handle:
            result = subprocess.run(command, cwd=cwd, stdout=handle, stderr=subprocess.STDOUT, text=True)
        self.receipt["steps"].append({"step": label, "exitCode": result.returncode, "log": str(log.relative_to(ROOT))})
        self.save()
        text = log.read_text(encoding="utf-8", errors="replace")
        if check and result.returncode:
            raise ReleaseError(f"{label} failed (log: {log}):\n{text[-4000:]}")
        return result.returncode, text


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def entitlements(rel, path, label):
    _, text = rel.run(label, ["codesign", "-d", "--entitlements", "-", "--xml", str(path)])
    # codesign's other output shares the log; keep only the property list.
    start, end = text.find("<?xml"), text.find("</plist>")
    if start < 0 or end < start:
        raise ReleaseError(f"no entitlements found for {path}")
    return plistlib.loads(text[start:end + len("</plist>")].encode())


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def release_ios(args):
    if not args.device:
        raise SystemExit("ios needs --device UDID (see `xcrun devicectl list devices`)")
    stamp = datetime.now(timezone.utc)
    out = OUT / ("ios-" + stamp.strftime("%Y%m%dT%H%M%SZ"))
    out.mkdir(parents=True)
    rel = Release(args.team, out)
    build = build_number(stamp)
    rel.receipt.update({"platform": "ios", "build": build, "device": args.device})
    try:
        if not args.skip_engine:
            rel.run("engine", [sys.executable, "scripts/apple.py", "engine", "--platform", "ios"])
        rel.run("generate", ["xcodegen", "generate", "--spec", str(APPLE / "project.yml"), "--project", str(APPLE)])
        rel.run("build", ios_build_command(APPLE / "Covee.xcodeproj", out / "derived", args.team, build, args.device))
        app = out / "derived/Build/Products/Release-iphoneos" / APP_NAME
        extension = app / "PlugIns/Covee-iOS-Tunnel.appex"
        rel.run("verify-signature", ["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)])
        _, details = rel.run("signing-details", ["codesign", "-dvv", str(app)])
        if f"TeamIdentifier={args.team}" not in details or "Authority=Apple Development" not in details:
            raise ReleaseError("the app is not development-signed by the team:\n" + details)
        check_ios_entitlements(entitlements(rel, app, "entitlements-app"), entitlements(rel, extension, "entitlements-extension"), args.team)
        info = plistlib.loads((app / "Info.plist").read_bytes())
        if info.get("CFBundleIdentifier") != "io.covee.ios" or info.get("CFBundleVersion") != build:
            raise ReleaseError(f"unexpected app Info.plist: {info.get('CFBundleIdentifier')} {info.get('CFBundleVersion')}")
        rel.receipt["appExecutableSHA256"] = sha256(app / "Covee")
        if args.install:
            rel.run("install", ["xcrun", "devicectl", "device", "install", "app", "--device", args.device, str(app), "--timeout", "120"])
            listing = out / "installed-apps.json"
            rel.run("confirm-installed", ["xcrun", "devicectl", "device", "info", "apps", "--device", args.device,
                                          "--bundle-id", "io.covee.ios", "--json-output", str(listing)])
            apps = json.loads(listing.read_text()).get("result", {}).get("apps", [])
            if not any(a.get("bundleIdentifier") == "io.covee.ios" for a in apps):
                raise ReleaseError("devicectl does not list io.covee.ios on the phone after installing")
            rel.receipt["installed"] = f"io.covee.ios on {args.device}"
            for bundle in args.remove_bundle:
                rel.run("remove-" + bundle, ["xcrun", "devicectl", "device", "uninstall", "app", "--device", args.device, bundle])
                rel.receipt.setdefault("removedBundles", []).append(bundle)
        rel.receipt["status"] = "passed"
        print(f"Covee {build} for iPhone is signed" + (" and installed on the phone" if args.install else f": {app}"), flush=True)
    except (ReleaseError, OSError, subprocess.SubprocessError, plistlib.InvalidFileException, ValueError) as error:
        rel.receipt["status"] = "failed"
        rel.receipt["error"] = str(error)[:4000]
        print(f"ERROR: {error}", file=sys.stderr)
    finally:
        rel.receipt["finishedAt"] = now_iso()
        rel.save()
        print(f"Receipt: {out / 'receipt.json'}", flush=True)
    return 0 if rel.receipt["status"] == "passed" else 1


def release_testflight(args):
    stamp = datetime.now(timezone.utc)
    out = OUT / ("testflight-" + stamp.strftime("%Y%m%dT%H%M%SZ"))
    out.mkdir(parents=True)
    rel = Release(args.team, out)
    build = build_number(stamp)
    rel.receipt.update({"platform": "ios-app-store", "build": build, "uploaded": False})
    archive = out / "Covee-iOS.xcarchive"
    try:
        if not args.skip_engine:
            rel.run("engine", [sys.executable, "scripts/apple.py", "engine", "--platform", "ios"])
        rel.run("generate", ["xcodegen", "generate", "--spec", str(APPLE / "project.yml"), "--project", str(APPLE)])
        rel.run("archive", ios_archive_command(APPLE / "Covee.xcodeproj", archive, out / "derived", args.team, build))
        # The apps show these licenses; a release must carry the current list.
        rel.run("acknowledgements", [sys.executable, "scripts/apple_acknowledgements.py", "--check",
                                     "--checkouts", str(out / "derived/SourcePackages/checkouts")])
        options = out / "options-export.plist"
        options.write_bytes(plistlib.dumps(app_store_options(args.team, "export")))
        rel.run("export", ["xcodebuild", "-exportArchive", "-archivePath", str(archive), "-exportOptionsPlist", str(options),
                           "-exportPath", str(out / "export"), "-allowProvisioningUpdates"])
        ipa = out / "export/Covee.ipa"
        rel.run("unpack", ["ditto", "-x", "-k", str(ipa), str(out / "ipa")])
        app = out / "ipa/Payload" / APP_NAME
        extension = app / "PlugIns/Covee-iOS-Tunnel.appex"
        rel.run("verify-signature", ["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)])
        _, details = rel.run("signing-details", ["codesign", "-dvv", str(app)])
        if f"TeamIdentifier={args.team}" not in details or "Authority=Apple Distribution" not in details:
            raise ReleaseError("the app is not signed for App Store distribution by the team:\n" + details)
        check_app_store_entitlements(entitlements(rel, app, "entitlements-app"),
                                     entitlements(rel, extension, "entitlements-extension"), args.team)
        info = plistlib.loads((app / "Info.plist").read_bytes())
        if info.get("CFBundleIdentifier") != "io.covee.ios" or info.get("CFBundleVersion") != build:
            raise ReleaseError(f"unexpected app Info.plist: {info.get('CFBundleIdentifier')} {info.get('CFBundleVersion')}")
        missing = [str(b.relative_to(out)) for b in (app, extension) if not (b / "PrivacyInfo.xcprivacy").is_file()]
        if missing:
            raise ReleaseError("the App Store requires a privacy manifest in: " + ", ".join(missing))
        rel.receipt.update({"version": info.get("CFBundleShortVersionString"), "ipaSHA256": sha256(ipa),
                            "appExecutableSHA256": sha256(app / "Covee")})
        if args.upload:
            options = out / "options-upload.plist"
            options.write_bytes(plistlib.dumps(app_store_options(args.team, "upload")))
            rel.run("upload", ["xcodebuild", "-exportArchive", "-archivePath", str(archive), "-exportOptionsPlist", str(options),
                               "-exportPath", str(out / "upload"), "-allowProvisioningUpdates"])
            rel.receipt["uploaded"] = True
        rel.receipt["status"] = "passed"
        print(f"Covee {info.get('CFBundleShortVersionString')} ({build}) for the App Store is signed"
              + (" and uploaded to App Store Connect; TestFlight shows it once Apple has processed it" if args.upload else f": {ipa}"), flush=True)
    except (ReleaseError, OSError, subprocess.SubprocessError, plistlib.InvalidFileException) as error:
        rel.receipt["status"] = "failed"
        rel.receipt["error"] = str(error)[:4000]
        print(f"ERROR: {error}", file=sys.stderr)
    finally:
        rel.receipt["finishedAt"] = now_iso()
        rel.save()
        print(f"Receipt: {out / 'receipt.json'}", flush=True)
    return 0 if rel.receipt["status"] == "passed" else 1


def release(args):
    if args.platform == "ios":
        return release_ios(args)
    if args.platform == "testflight":
        return release_testflight(args)
    stamp = datetime.now(timezone.utc)
    out = OUT / stamp.strftime("%Y%m%dT%H%M%SZ")
    out.mkdir(parents=True)
    rel = Release(args.team, out)
    build = build_number(stamp)
    rel.receipt["build"] = build
    archive = out / "Covee.xcarchive"
    try:
        if not args.skip_engine:
            rel.run("engine", [sys.executable, "scripts/apple.py", "engine", "--platform", "macos"])
        rel.run("generate", ["xcodegen", "generate", "--spec", str(APPLE / "project.yml"), "--project", str(APPLE)])
        rel.run("archive", archive_command(APPLE / "Covee.xcodeproj", archive, out / "derived", args.team, build))
        # The apps show these licenses; a release must carry the current list.
        rel.run("acknowledgements", [sys.executable, "scripts/apple_acknowledgements.py", "--check",
                                     "--checkouts", str(out / "derived/SourcePackages/checkouts")])
        options = out / "options-upload.plist"
        options.write_bytes(plistlib.dumps(export_options(args.team)))
        rel.run("upload-for-notarization", ["xcodebuild", "-exportArchive", "-archivePath", str(archive),
                                            "-exportOptionsPlist", str(options), "-exportPath", str(out / "upload"),
                                            "-allowProvisioningUpdates"])
        deadline = time.monotonic() + NOTARY_WAIT_SECONDS
        attempt = 0
        while True:
            attempt += 1
            code, text = rel.run(f"export-notarized-{attempt}", ["xcodebuild", "-exportNotarizedApp", "-archivePath", str(archive),
                                                                 "-exportPath", str(out / "notarized")], check=False)
            if code == 0:
                break
            if "processing" not in text and "not ready" not in text:
                raise ReleaseError(f"Apple did not accept the app (log: {out}/export-notarized-{attempt}.log):\n{text[-3000:]}")
            if time.monotonic() > deadline:
                raise ReleaseError("Apple's notary service did not finish within 45 minutes; run the export again later")
            time.sleep(30)
        app = out / "notarized" / APP_NAME
        extension = app / EXTENSION
        rel.run("verify-signature", ["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)])
        _, gatekeeper = rel.run("verify-gatekeeper", ["spctl", "--assess", "--type", "execute", "-vv", str(app)])
        if "Notarized Developer ID" not in gatekeeper:
            raise ReleaseError("Gatekeeper does not report a notarized Developer ID app:\n" + gatekeeper)
        rel.run("verify-staple", ["xcrun", "stapler", "validate", str(app)])
        _, details = rel.run("signing-details", ["codesign", "-dvv", str(app)])
        if f"TeamIdentifier={args.team}" not in details or "Authority=Developer ID Application" not in details:
            raise ReleaseError("the app is not signed with the team's Developer ID certificate:\n" + details)
        check_entitlements(entitlements(rel, app, "entitlements-app"), entitlements(rel, extension, "entitlements-extension"), args.team)
        check_info(plistlib.loads((app / "Contents/Info.plist").read_bytes()),
                   plistlib.loads((extension / "Contents/Info.plist").read_bytes()), args.team, build)
        executable = app / "Contents/MacOS/Covee"
        rel.receipt["appExecutableSHA256"] = sha256(executable)
        rel.receipt["extensionExecutableSHA256"] = sha256(extension / "Contents/MacOS/io.covee.macos.tunnel")
        rel.receipt["notarizedApp"] = str(app.relative_to(ROOT))
        if args.install:
            target = Path("/Applications") / APP_NAME
            if target.exists():
                previous = out / "previous" / APP_NAME
                previous.parent.mkdir()
                shutil.move(str(target), str(previous))
                rel.receipt["previousInstallMovedTo"] = str(previous.relative_to(ROOT))
            rel.run("install", ["ditto", str(app), str(target)])
            if sha256(target / "Contents/MacOS/Covee") != rel.receipt["appExecutableSHA256"]:
                raise ReleaseError("the installed app does not match the notarized one")
            rel.run("verify-installed-gatekeeper", ["spctl", "--assess", "--type", "execute", "-vv", str(target)])
            rel.receipt["installed"] = str(target)
        rel.receipt["status"] = "passed"
        print(f"Covee {build} is notarized" + (" and installed in /Applications" if args.install else f": {app}"), flush=True)
    except (ReleaseError, OSError, subprocess.SubprocessError, plistlib.InvalidFileException) as error:
        rel.receipt["status"] = "failed"
        rel.receipt["error"] = str(error)[:4000]
        print(f"ERROR: {error}", file=sys.stderr)
    finally:
        rel.receipt["finishedAt"] = now_iso()
        rel.save()
        print(f"Receipt: {out / 'receipt.json'}", flush=True)
    return 0 if rel.receipt["status"] == "passed" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("platform", choices=["macos", "ios", "testflight"])
    parser.add_argument("--upload", action="store_true", help="testflight: upload the checked build to App Store Connect")
    parser.add_argument("--device", help="iPhone UDID for ios")
    parser.add_argument("--remove-bundle", action="append", default=[], help="ios: uninstall this older app after installing")
    parser.add_argument("--team", default="87LFD98HJU", help="Apple Developer team ID")
    parser.add_argument("--install", action="store_true", help="install the app (Mac: /Applications; iPhone: the --device)")
    parser.add_argument("--skip-engine", action="store_true", help="reuse the engine archive already built")
    return release(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
