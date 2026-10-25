#!/usr/bin/env python3
"""Write the open-source license list the Mac and iPhone apps show in Settings.

It collects the license (and NOTICE) files of every Go module the iPhone
engine is built from, and of the Swift packages the apps link, including the
copy of RoyalVNC in native/apple/Vendor, into native/apple/App/Acknowledgements.txt.

  python3 scripts/apple_acknowledgements.py [--checkouts DIR] [--check]

DIR is an Xcode SourcePackages/checkouts folder; by default the one from
`scripts/apple.py build`. --check fails when the file is out of date instead
of writing it.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "native/engine"
OUTPUT = ROOT / "native/apple/App/Acknowledgements.txt"
DEFAULT_CHECKOUTS = ROOT / ".cache/covee/apple/derived/ios/SourcePackages/checkouts"
VENDOR = ROOT / "native/apple/Vendor"
# Swift packages used only to build, never linked into the apps.
BUILD_ONLY = {"swift-argument-parser", "swift-docc-plugin", "swift-docc-symbolkit", "package-benchmark", "swift-png", "swift-jpeg", "h"}
LICENSE_NAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE", "NOTICE.txt", "NOTICE.md")


def license_files(directory):
    return [directory / name for name in LICENSE_NAMES if (directory / name).is_file()]


def go_modules():
    env = {**os.environ, "GOOS": "ios", "GOARCH": "arm64", "CGO_ENABLED": "1"}
    listed = subprocess.run(["go", "list", "-deps", "-tags", "ts_macext", "-json", "."], cwd=ENGINE, env=env,
                            check=True, capture_output=True, text=True).stdout
    modules = {}
    decoder = json.JSONDecoder()
    index = 0
    while index < len(listed):
        while index < len(listed) and listed[index].isspace():
            index += 1
        if index >= len(listed):
            break
        package, index = decoder.raw_decode(listed, index)
        module = package.get("Module")
        if module and not module.get("Main") and module.get("Dir"):
            modules[module["Path"]] = (module.get("Version", ""), Path(module["Dir"]))
    return sorted(modules.items())


def swift_packages(checkouts):
    if not checkouts.is_dir():
        raise SystemExit(f"No Swift package checkouts at {checkouts}; run `python3 scripts/apple.py build` first.")
    packages = [(path.name, "", path) for path in sorted(checkouts.iterdir()) if path.is_dir() and path.name not in BUILD_ONLY]
    packages += [(path.name, "copy in Covee", path) for path in sorted(VENDOR.iterdir()) if path.is_dir()]
    return packages


def render(checkouts):
    parts = ["Open-source software in Covee", "",
             "Covee is open source under the Apache License 2.0: https://github.com/covee-io/covee",
             "It includes the following software, each under its own license, reproduced below.", ""]
    missing = []
    goroot = Path(subprocess.run(["go", "env", "GOROOT"], check=True, capture_output=True, text=True).stdout.strip())
    goversion = subprocess.run(["go", "env", "GOVERSION"], check=True, capture_output=True, text=True).stdout.strip()
    # The Go standard library is compiled into the engine too.
    # Homebrew keeps Go's LICENSE one folder above GOROOT.
    entries = [(f"Go standard library ({goversion})", next((d for d in (goroot, goroot.parent) if license_files(d)), goroot))]
    entries += [(f"{path} {version}".strip(), directory) for path, (version, directory) in go_modules()]
    entries += [(f"{name} ({note})" if note else name, directory) for name, note, directory in swift_packages(checkouts)]
    for title, directory in entries:
        files = license_files(directory)
        if not files:
            missing.append(title)
            continue
        parts += ["=" * 72, title, "=" * 72]
        for path in files:
            parts += [path.read_text(encoding="utf-8", errors="replace").strip(), ""]
    if missing:
        raise SystemExit("No license file found for: " + ", ".join(missing))
    # CryptoSwift's license asks for this acknowledgment in the product's documentation.
    parts += ["=" * 72, 'This product includes software developed by the "Marcin Krzyzanowski" (http://krzyzanowskim.com/).', ""]
    return "\n".join(parts)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--checkouts", type=Path, default=DEFAULT_CHECKOUTS)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    text = render(args.checkouts)
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != text:
            print(f"{OUTPUT.relative_to(ROOT)} is out of date; run scripts/apple_acknowledgements.py", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(text, encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(ROOT)} ({len(text) // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
