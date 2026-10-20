#!/usr/bin/env python3
"""Build the `covee` CLI with the server payload embedded.

The payload is the reviewed server source that `covee setup` installs on each
network server: a reproducible gzipped tar with a PAYLOAD-MANIFEST.json of
per-file SHA-256 hashes, the same manifest format the pilot VMs received.

  python3 scripts/build_cli.py                    build for this computer
  python3 scripts/build_cli.py --target linux/amd64 --target darwin/arm64
  python3 scripts/build_cli.py --payload-only     only write the payload
"""
import argparse
import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "cli"
ASSET = CLI / "internal/payload/assets/payload.tar.gz"
INCLUDE = (".dockerignore", "Dockerfile", "go.mod", "go.sum", "cmd", "internal", "deploy", "scripts", "lab")
SKIP_PARTS = {"__pycache__", ".DS_Store"}
SKIP_SUFFIXES = (".pyc",)


def payload_files(root=ROOT):
    files = []
    for entry in INCLUDE:
        path = root / entry
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(p for p in path.rglob("*") if p.is_file())
        else:
            raise SystemExit(f"payload entry missing: {entry}")
    result = []
    for path in files:
        relative = path.relative_to(root)
        if any(part in SKIP_PARTS for part in relative.parts) or path.name.endswith(SKIP_SUFFIXES):
            continue
        if path.is_symlink():
            raise SystemExit(f"payload must not contain symlinks: {relative}")
        result.append(relative.as_posix())
    return sorted(result)


def build_payload(root=ROOT):
    """Return the payload archive bytes and its manifest."""
    names = payload_files(root)
    manifest = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names}
    entries = [("PAYLOAD-MANIFEST.json", (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode())]
    entries += [(name, (root / name).read_bytes()) for name in names]
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0, compresslevel=9) as stream:
        stream.write(raw.getvalue())
    return compressed.getvalue(), manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", action="append", help="GOOS/GOARCH, repeatable; default this computer")
    parser.add_argument("--payload-only", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/cli")
    parser.add_argument("--version", help="release version such as 0.1.0 (scripts/release.py); default 0.1.0-dev+<payload hash>")
    args = parser.parse_args()
    data, manifest = build_payload()
    ASSET.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    print(f"Payload: {len(manifest)} files, {len(data)} bytes, sha256 {digest}")
    if args.payload_only:
        return 0
    version = args.version or f"0.1.0-dev+{digest[:12]}"
    targets = args.target or [f"{os.uname().sysname.lower()}/{ {'x86_64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64'}[os.uname().machine] }"]
    for target in targets:
        goos, goarch = target.split("/")
        out = args.output / f"{goos}-{goarch}" / "covee"
        out.parent.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0"}
        subprocess.run(["go", "build", "-trimpath", "-ldflags", f"-s -w -X main.version={version}", "-o", str(out), "./cmd/covee"],
                       cwd=CLI, env=env, check=True)
        print(f"Built {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out} ({version})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
