#!/usr/bin/env python3
"""Build unsigned Apple clients and their real packet engine; never install a VPN."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "native/engine"
APPLE = ROOT / "native/apple"
CACHE = ROOT / ".cache/covee/apple"
REPORT = CACHE / "build-results.json"
PLATFORMS = {
    "macos": ("macosx", "darwin", "arm64-apple-macos15.0", "Covee-macOS", "platform=macOS,arch=arm64"),
    "ios": ("iphoneos", "ios", "arm64-apple-ios18.0", "Covee-iOS", "generic/platform=iOS"),
    "ios-simulator": ("iphonesimulator", "ios", "arm64-apple-ios18.0-simulator", "Covee-iOS", "generic/platform=iOS Simulator"),
}


class BuildError(RuntimeError):
    pass


def output(arguments):
    return subprocess.check_output(arguments, text=True).strip()


def run(arguments, label, report, *, cwd=ROOT, env=None):
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / (label + ".log")
    print(label + "…", flush=True)
    with path.open("w", encoding="utf-8") as log:
        result = subprocess.run(arguments, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT)
    record = {"step": label, "command": arguments, "exitCode": result.returncode,
              "log": str(path.relative_to(ROOT))}
    report["steps"].append(record)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if result.returncode:
        tail = path.read_text(encoding="utf-8", errors="replace")[-8000:]
        raise BuildError(label + " failed; log: " + str(path) + "\n" + tail)


def environment(platform):
    sdk, goos, target, _, _ = PLATFORMS[platform]
    sdk_path = output(["xcrun", "--sdk", sdk, "--show-sdk-path"])
    compiler = output(["xcrun", "--sdk", sdk, "--find", "clang"])
    result = os.environ.copy()
    result.update({"GOOS": goos, "GOARCH": "arm64", "CGO_ENABLED": "1", "CC": compiler,
                   "GOCACHE": str(ROOT / ".cache/covee/apple-go-build"),
                   "GOMODCACHE": str(ROOT / ".cache/covee/apple-go-mod"),
                   "GOPATH": str(ROOT / ".cache/covee/apple-go"), "GOTOOLCHAIN": "auto",
                   "CGO_CFLAGS": f"-target {target} -isysroot {sdk_path}",
                   "CGO_LDFLAGS": f"-target {target} -isysroot {sdk_path}"})
    return result


def engine(platform, report):
    (CACHE / "engine").mkdir(exist_ok=True)
    run(["go", "build", "-tags=ts_macext", "-trimpath", "-ldflags=-s -w", "-buildmode=c-archive",
         "-o", str(CACHE / f"engine/libcovee-{platform}.a"), "."],
        "engine-" + platform, report, cwd=ENGINE, env=environment(platform))


def generate(report):
    run(["xcodegen", "generate", "--spec", str(APPLE / "project.yml"), "--project", str(APPLE)], "generate-project", report)


def build(platform, report, configuration):
    sdk, _, _, scheme, destination = PLATFORMS[platform]
    # A renamed embedded extension must not survive in an older app bundle.
    product_folder = configuration if platform == "macos" else configuration + ("-iphoneos" if platform == "ios" else "-iphonesimulator")
    previous_bundle = CACHE / "derived" / platform / "Build/Products" / product_folder / "Covee.app"
    if previous_bundle.exists():
        shutil.rmtree(previous_bundle)
    run(["xcodebuild", "-project", str(APPLE / "Covee.xcodeproj"), "-scheme", scheme,
         "-configuration", configuration, "-sdk", sdk, "-destination", destination,
         "-derivedDataPath", str(CACHE / "derived" / platform), "ARCHS=arm64", "ONLY_ACTIVE_ARCH=YES",
         "CODE_SIGNING_ALLOWED=NO", "build"], "app-" + platform, report)


def test(report, configuration):
    # Both are unhosted unit bundles; these tests never save or start a VPN.
    for scheme in ("CoveeCoreTests", "CoveePacketTunnelTests"):
        run(["xcodebuild", "-project", str(APPLE / "Covee.xcodeproj"), "-scheme", scheme,
             "-configuration", configuration,
             "-destination", "platform=macOS,arch=arm64", "-derivedDataPath", str(CACHE / "tests"),
             "CODE_SIGNING_ALLOWED=NO", "test"], "test-" + scheme, report)


def main():
    global REPORT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["engine", "generate", "build", "test"])
    parser.add_argument("--platform", choices=["all", *PLATFORMS], default="all")
    parser.add_argument("--configuration", choices=["Debug", "Release"], default="Debug")
    parser.add_argument("--skip-engine", action="store_true", help="Reuse already built archives")
    args = parser.parse_args()
    REPORT = CACHE / (args.command + "-results.json")
    report = {"schemaVersion": 1, "status": "running", "startedAt": datetime.now(timezone.utc).isoformat(),
              "scope": "Unsigned arm64 Apple app/extension compile and unhosted unit tests; no live VPN proof",
              "command": args.command, "platform": args.platform, "configuration": args.configuration, "steps": [],
              "signed": False, "installed": False, "vpnActivated": False,
              "signingPolicy": "CODE_SIGNING_ALLOWED=NO; no developer/distribution signing; linker ad-hoc Mach-O signatures may be present"}
    CACHE.mkdir(parents=True, exist_ok=True)
    try:
        report["xcode"] = output(["xcodebuild", "-version"])
        report["swift"] = output(["swift", "--version"])
        selected = list(PLATFORMS) if args.platform == "all" else [args.platform]
        if args.command in ("engine", "build") and not args.skip_engine:
            for platform in selected:
                engine(platform, report)
        if args.command in ("generate", "build", "test"):
            generate(report)
        if args.command == "build":
            for platform in selected:
                build(platform, report, args.configuration)
        if args.command == "test":
            test(report, args.configuration)
        report["status"] = "passed"
        print("Apple " + args.command + " passed. Report: " + str(REPORT), flush=True)
    except (BuildError, OSError, subprocess.SubprocessError) as error:
        report["status"] = "failed"
        report["error"] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        report["finishedAt"] = datetime.now(timezone.utc).isoformat()
        REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
