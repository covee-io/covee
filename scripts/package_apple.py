#!/usr/bin/env python3
"""Package the last successful unsigned Apple build without installing a VPN."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache/covee/apple"


def digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            checksum.update(block)
    return {"path": str(path.relative_to(ROOT)), "bytes": path.stat().st_size,
            "sha256": checksum.hexdigest()}


def main():
    report = json.loads((CACHE / "build-results.json").read_text())
    if report["status"] != "passed" or report.get("signed") is not False:
        raise RuntimeError("A successful unsigned build is required before packaging.")
    configuration = report["configuration"]
    if configuration not in {"Debug", "Release"}:
        raise RuntimeError("Unknown build configuration.")
    passed = {step["step"] for step in report["steps"] if step["exitCode"] == 0}
    platforms = {"macos": configuration, "ios": configuration + "-iphoneos",
                 "ios-simulator": configuration + "-iphonesimulator"}
    if not all("app-" + platform in passed for platform in platforms):
        raise RuntimeError("Build all three app targets before packaging.")
    timestamp = datetime.now(timezone.utc)
    destination = ROOT / "dist/covee/apple" / timestamp.strftime("%Y%m%dT%H%M%S%fZ")
    destination.mkdir(parents=True)
    packages = []
    for platform, products in platforms.items():
        app = CACHE / "derived" / platform / "Build/Products" / products / "Covee.app"
        mac = platform == "macos"
        plist = app / ("Contents/Info.plist" if mac else "Info.plist")
        info = plistlib.loads(plist.read_bytes())
        expected_id = "io.covee.macos" if mac else "io.covee.ios"
        if info["CFBundleIdentifier"] != expected_id:
            raise RuntimeError("Unexpected application identity: " + str(app))
        providers = list(app.glob("Contents/Library/SystemExtensions/*.systemextension" if mac else "PlugIns/*.appex"))
        if len(providers) != 1:
            raise RuntimeError("Exactly one embedded packet provider is required: " + str(app))
        provider = providers[0]
        provider_info = plistlib.loads((provider / ("Contents/Info.plist" if mac else "Info.plist")).read_bytes())
        if provider_info["CFBundleIdentifier"] != expected_id + ".tunnel":
            raise RuntimeError("Unexpected packet provider identity.")
        if mac and provider.name != provider_info["CFBundleIdentifier"] + ".systemextension":
            raise RuntimeError("Mac system extension filename must match its bundle identifier.")
        for bundle, metadata in [(app, info), (provider, provider_info)]:
            binary = bundle / ("Contents/MacOS" if mac else "") / metadata["CFBundleExecutable"]
            architectures = subprocess.check_output(["xcrun", "lipo", "-archs", str(binary)], text=True).strip()
            if architectures != "arm64":
                raise RuntimeError("Expected arm64 executable: " + str(binary))
        archive = destination / ("Covee-" + platform + "-arm64-unsigned.zip")
        subprocess.run(["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(app), str(archive)], check=True)
        with zipfile.ZipFile(archive) as contents:
            if contents.testzip() is not None:
                raise RuntimeError("Archive CRC validation failed: " + str(archive))
            if not any(name.endswith(provider.name + "/" + ("Contents/Info.plist" if mac else "Info.plist")) for name in contents.namelist()):
                raise RuntimeError("Embedded provider missing from packaged archive.")
        packages.append({"platform": platform, "configuration": configuration,
                         "app": str(app.relative_to(ROOT)), "bundleIdentifier": expected_id,
                         "minimumOS": info.get("LSMinimumSystemVersion", info.get("MinimumOSVersion")),
                         "provider": str(provider.relative_to(app)), "archive": digest(archive),
                         "bundleFiles": [digest(p) for p in sorted(app.rglob("*")) if p.is_file()]})
    copied_report = destination / "build-results.json"
    for step in report["steps"]:
        source_log = ROOT / step["log"]
        packaged_log = destination / source_log.name
        shutil.copyfile(source_log, packaged_log)
        step["originalLog"] = step["log"]
        step["log"] = str(packaged_log.relative_to(ROOT))
    copied_report.write_text(json.dumps(report, indent=2) + "\n")
    test_evidence = None
    cached_tests = CACHE / "test-results.json"
    if cached_tests.exists():
        tests = json.loads(cached_tests.read_text())
        if tests["status"] == "passed" and tests.get("configuration") == configuration:
            for step in tests["steps"]:
                source_log = ROOT / step["log"]
                packaged_log = destination / ("tests-" + source_log.name)
                shutil.copyfile(source_log, packaged_log)
                step["originalLog"] = step["log"]
                step["log"] = str(packaged_log.relative_to(ROOT))
            saved_tests = destination / "test-results.json"
            saved_tests.write_text(json.dumps(tests, indent=2) + "\n")
            test_evidence = digest(saved_tests)
    manifest = {"schemaVersion": 1, "recordedAt": timestamp.isoformat(), "result": "passed",
                "scope": "Unsigned arm64 app bundles; archive contents and embedded providers verified",
                "configuration": configuration, "developerSigned": False,
                "installableVPNRelease": False, "installed": False, "vpnActivated": False,
                "packages": packages, "buildReport": digest(copied_report),
                "testReport": test_evidence,
                "engineArchives": [digest(CACHE / "engine" / ("libcovee-" + platform + ".a")) for platform in platforms],
                "sources": [digest(p) for directory in [ROOT / "native/apple", ROOT / "native/engine"]
                            for p in sorted(directory.rglob("*")) if p.is_file()
                            and "build" not in p.relative_to(directory).parts
                            and not any(part.endswith(".xcodeproj") for part in p.relative_to(directory).parts)]
                           + [digest(ROOT / "scripts/apple.py"), digest(Path(__file__).resolve())]}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (destination / "README.txt").write_text(
        "Covee " + configuration + " build artifacts\n\n"
        "All three app bundles contain their real packet-tunnel providers.\n"
        "The Mac build requires Apple Silicon and macOS 15+. iPhone requires iOS 18+.\n"
        "These are unsigned build artifacts, not installable signed VPN releases.\n"
        "Mac/simulator binaries may have linker ad-hoc signatures without a Team ID.\n"
        "Device VPN use requires an owned signing team, matching Network Extension\n"
        "provisioning, and a reachable trusted HTTPS coordinator.\n")
    print(str(destination))
    for package in packages:
        print(package["archive"]["path"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
