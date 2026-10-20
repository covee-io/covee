#!/usr/bin/env python3
"""Build and publish a Covee release from a committed version of the code.

  python3 scripts/release.py build --version 0.1.0 [--unsigned] [--skip-tests] [--skip-app]
  python3 scripts/release.py publish --version 0.1.0 [--repo covee-io/covee]
  python3 scripts/release.py tap --version 0.1.0 [--tap covee-io/homebrew-tap]

build exports the current commit, never uncommitted files, into
.cache/covee/release/<version>/source and from that copy:

1. runs the Python, Go, CLI, engine and console tests;
2. builds the covee CLI for Macs (Apple Silicon and Intel) and Linux (amd64 and
   arm64) with the server payload embedded;
3. signs the Mac CLI builds with the team's Developer ID Application
   certificate and has Apple notarize them. --unsigned skips this while there
   is no such certificate: Homebrew and curl installs work without it, a
   browser download is blocked by macOS;
4. builds, notarizes and checks the Mac app with apple_release.py, and puts it
   in a disk image (Covee.dmg, the same name in every release so a
   download link can always point to the latest) that is signed with the Developer ID,
   notarized and stapled, so it opens without a warning even offline;
5. writes the archives, each with LICENSE, NOTICE and THIRD_PARTY_LICENSES.txt
   (the license of every Go module compiled in), SHA256SUMS, release notes,
   Homebrew's formula (the CLI) and cask (the Mac app) and manifest.json into
   dist/release/<version>.

--skip-tests and --skip-app are for trying the build; publish refuses their
result.

Notarizing the CLI uses an App Store Connect API key kept in Parameter Store
(us-east-1): /covee/release/notary-key (SecureString, the .p8 text), with
/covee/release/notary-key-id and /covee/release/notary-issuer beside it. The
key is written to a private temporary file for the upload only and never
printed.

publish tags the built commit v<version>, pushes the tag and creates a draft
GitHub release with the files. Nobody sees it until it is published on GitHub.

tap, once the release is published, commits the formula and cask to the
Homebrew tap, so `brew install covee-io/tap/covee` and
`brew install --cask covee-io/tap/covee` install it.
"""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / ".cache/covee/release"
DIST = ROOT / "dist/release"
TARGETS = ("darwin/arm64", "darwin/amd64", "linux/amd64", "linux/arm64")
TEAM = "87LFD98HJU"
REPO = "covee-io/covee"
TAP = "covee-io/homebrew-tap"
HOMEPAGE = "https://covee.io"
REGION = "us-east-1"
NOTARY_KEY, NOTARY_KEY_ID, NOTARY_ISSUER = "/covee/release/notary-key", "/covee/release/notary-key-id", "/covee/release/notary-issuer"
VERSION = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.]+)?$")
LICENSE_FILE = re.compile(r"^(LICEN[CS]E|COPYING|NOTICE|PATENTS)(-[A-Za-z0-9.-]+|\.(txt|md|rst))?$", re.IGNORECASE)
MODULE_LIST = "{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{if .Replace}}{{.Replace.Dir}}{{else}}{{.Dir}}{{end}}{{end}}{{end}}"


class ReleaseError(RuntimeError):
    pass


def check_version(version):
    if not VERSION.match(version or ""):
        raise ReleaseError(f"{version!r} is not a version such as 0.1.0 or 0.2.0-beta.1")
    return version


def git(*args, cwd=ROOT):
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if result.returncode:
        raise ReleaseError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def committed(version, cwd=ROOT):
    """Return the commit to release; refuse uncommitted changes or a tag naming another commit."""
    changes = git("status", "--porcelain", cwd=cwd)
    if changes.strip():
        raise ReleaseError("a release is built only from committed code; commit or remove these changes first:\n" + changes)
    commit = git("rev-parse", "HEAD", cwd=cwd).strip()
    tagged = subprocess.run(["git", "rev-parse", "-q", "--verify", f"refs/tags/v{version}^{{commit}}"],
                            cwd=cwd, capture_output=True, text=True).stdout.strip()
    if tagged and tagged != commit:
        raise ReleaseError(f"v{version} is already the tag of commit {tagged[:12]}; choose a new version")
    return commit


def remove_tree(path):
    """Remove a folder, including Go's module cache, whose folders are read-only."""
    def writable(func, target, error):
        if not isinstance(error, PermissionError):
            raise error
        os.chmod(os.path.dirname(target), 0o755)
        if os.path.isdir(target) and not os.path.islink(target):
            os.chmod(target, 0o755)
        func(target)
    shutil.rmtree(path, onexc=writable)


def export(commit, dest, cwd=ROOT):
    if dest.exists():
        remove_tree(dest)
    dest.mkdir(parents=True)
    archive = subprocess.run(["git", "archive", "--format=tar", commit], cwd=cwd, capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        source.extractall(dest, filter="data")


class Build:
    def __init__(self, version, work):
        self.work = work
        self.logs = work / "logs"
        self.logs.mkdir(parents=True, exist_ok=True)
        self.manifest = {"schemaVersion": 1, "version": version, "startedAt": now_iso(), "steps": [], "skipped": []}

    def run(self, label, command, *, cwd, env=None, check=True):
        log = self.logs / f"{label}.log"
        print(f"{label}…", flush=True)
        with log.open("w", encoding="utf-8") as handle:
            result = subprocess.run(command, cwd=cwd, env=env, stdout=handle, stderr=subprocess.STDOUT, text=True)
        self.manifest["steps"].append({"step": label, "exitCode": result.returncode})
        text = log.read_text(encoding="utf-8", errors="replace")
        if check and result.returncode:
            raise ReleaseError(f"{label} failed (log: {log}):\n{text[-4000:]}")
        return text


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def test_steps(source):
    steps = [("tests-python", [sys.executable, "-m", "unittest", "discover", "-s", "tests"], source),
             ("tests-go", ["go", "test", "-race", "./..."], source),
             ("tests-cli", ["go", "test", "./..."], source / "cli"),
             ("tests-engine", ["go", "test", "./..."], source / "native/engine")]
    if shutil.which("node"):
        steps.append(("tests-console", ["node", "--test", "internal/console/frontend.test.cjs"], source))
    return steps


def go_modules(module_dir, package, targets, cgo="0"):
    """Every module compiled into package for the targets: {(path, version): directory}."""
    found = {}
    for target in targets:
        goos, goarch = target.split("/")
        env = {**os.environ, "GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": cgo, "GOFLAGS": "-mod=readonly"}
        result = subprocess.run(["go", "list", "-deps", "-f", MODULE_LIST, package], cwd=module_dir, env=env,
                                capture_output=True, text=True)
        if result.returncode:
            raise ReleaseError(f"go list for {target} failed:\n{result.stderr[-2000:]}")
        for line in result.stdout.splitlines():
            if line.strip():
                path, version, directory = line.split("\t")
                found[(path, version)] = directory
    return found


def third_party_licenses(modules, go_root, go_version):
    """The license texts of the Go toolchain and every module; refuse a module with none."""
    # Homebrew's Go keeps LICENSE beside GOROOT rather than in it.
    go_license = next((p for p in (Path(go_root) / "LICENSE", Path(go_root).parent / "LICENSE") if p.is_file()), None)
    if go_license is None:
        raise ReleaseError(f"no LICENSE found for the Go toolchain at {go_root}")
    go_files = [go_license] + [p for p in (Path(go_root) / "PATENTS",) if p.is_file()]
    sections = [("Go " + go_version + " (standard library and runtime)", go_files)]
    missing = []
    for (path, version), directory in sorted(modules.items()):
        files = sorted(p for p in Path(directory or "/nonexistent").glob("*") if p.is_file() and LICENSE_FILE.match(p.name))
        if files:
            sections.append((f"{path} {version}".strip(), files))
        else:
            missing.append(f"{path} {version}".strip())
    if missing:
        raise ReleaseError("no license file found for: " + ", ".join(missing) + "; check their licenses before releasing")
    parts = ["Covee includes the following third-party software, each under its own license.\n"]
    for title, files in sections:
        parts.append("=" * 78 + "\n" + title + "\n" + "=" * 78 + "\n")
        for file in files:
            if len(files) > 1:
                parts.append(f"--- {file.name}\n")
            parts.append(file.read_text(encoding="utf-8", errors="replace").rstrip() + "\n\n")
    return "".join(parts)


def tar_gz(folder, files):
    """A reproducible .tar.gz of files [(name, bytes, mode)] inside one folder."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, data, mode in files:
            info = tarfile.TarInfo(f"{folder}/{name}")
            info.size, info.mode, info.mtime = len(data), mode, 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0, compresslevel=9) as stream:
        stream.write(raw.getvalue())
    return compressed.getvalue()


def dmg_name(version):
    """The same in every release, so releases/latest/download/Covee.dmg always
    downloads the newest Mac app; the volume and the app carry the version."""
    return "Covee.dmg"


def cli_archive_name(version, target):
    goos, goarch = target.split("/")
    return f"covee_{version}_{goos}_{goarch}.tar.gz"


def developer_id(identities, team=TEAM):
    """The SHA-1 and name of the team's Developer ID Application identity in `security find-identity` output."""
    match = re.search(r"\b([0-9A-F]{40})\s+\"(Developer ID Application: [^\"]+ \(" + re.escape(team) + r"\))\"", identities)
    return (match.group(1), match.group(2)) if match else None


def ssm_value(name, decrypt):
    command = ["aws", "ssm", "get-parameter", "--region", REGION, "--name", name, "--query", "Parameter.Value", "--output", "text"]
    result = subprocess.run(command + (["--with-decryption"] if decrypt else []), capture_output=True, text=True)
    if result.returncode:
        raise ReleaseError(f"could not read {name} from Parameter Store: {result.stderr.strip()[-300:]}")
    return result.stdout.strip()


def sign_and_notarize(build, binaries, identity):
    """Sign the Mac CLI builds with Developer ID and wait for Apple to accept them."""
    for binary in binaries:
        build.run(f"sign-{binary.parent.name}", ["codesign", "--force", "--options", "runtime", "--timestamp",
                                                 "--identifier", "io.covee.cli", "--sign", identity[0], str(binary)], cwd=ROOT)
        details = build.run(f"signed-{binary.parent.name}", ["codesign", "-dvv", str(binary)], cwd=ROOT)
        if f"Authority={identity[1]}" not in details or f"TeamIdentifier={TEAM}" not in details:
            raise ReleaseError(f"{binary} is not signed with {identity[1]}:\n{details}")
    with tempfile.TemporaryDirectory(prefix="covee-notary-") as private:
        bundle = Path(private) / "covee"
        bundle.mkdir()
        for binary in binaries:
            shutil.copy2(binary, bundle / f"covee-{binary.parent.name}")
        upload = Path(private) / "covee-cli.zip"
        build.run("zip-for-notarization", ["ditto", "-c", "-k", "--keepParent", str(bundle), str(upload)], cwd=ROOT)
        notarize(build, upload, "cli", "the CLI builds")


def notarize(build, upload, label, what):
    """Have Apple notarize a zip or disk image, with the notary key from
    Parameter Store in a private temporary file, and wait for the answer."""
    with tempfile.TemporaryDirectory(prefix="covee-notary-key-") as private:
        key = Path(private) / "notary.p8"
        descriptor = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(ssm_value(NOTARY_KEY, True) + "\n")
        text = build.run(f"notarize-{label}", ["xcrun", "notarytool", "submit", str(upload), "--key", str(key),
                                               "--key-id", ssm_value(NOTARY_KEY_ID, False), "--issuer", ssm_value(NOTARY_ISSUER, False),
                                               "--wait", "--timeout", "45m", "--output-format", "json"], cwd=ROOT, check=False)
    status = notary_status(text)
    if status != "Accepted":
        raise ReleaseError(f"Apple did not accept {what} (status {status!r}); see {build.logs / f'notarize-{label}.log'}")


def disk_image(build, folder, version, identity, dmg):
    """The Mac app's disk image: the app, an Applications shortcut to drag it
    to, and its license files; signed with the Developer ID, notarized and
    stapled, and checked as Gatekeeper will check it."""
    stage = folder.parent / "dmg"
    if stage.exists():
        remove_tree(stage)
    build.run("dmg-stage", ["ditto", str(folder), str(stage)], cwd=ROOT)
    os.symlink("/Applications", stage / "Applications")
    if dmg.exists():
        dmg.unlink()
    build.run("dmg-create", ["hdiutil", "create", "-volname", f"Covee {version}", "-srcfolder", str(stage), "-fs", "HFS+",
                             "-format", "UDZO", "-imagekey", "zlib-level=9", "-ov", str(dmg)], cwd=ROOT)
    build.run("dmg-sign", ["codesign", "--force", "--timestamp", "--sign", identity[0], str(dmg)], cwd=ROOT)
    details = build.run("dmg-signed", ["codesign", "-dvv", str(dmg)], cwd=ROOT)
    if f"Authority={identity[1]}" not in details or f"TeamIdentifier={TEAM}" not in details:
        raise ReleaseError(f"{dmg.name} is not signed with {identity[1]}:\n{details}")
    notarize(build, dmg, "dmg", "the disk image")
    build.run("dmg-staple", ["xcrun", "stapler", "staple", str(dmg)], cwd=ROOT)
    build.run("dmg-staple-check", ["xcrun", "stapler", "validate", str(dmg)], cwd=ROOT)
    verdict = build.run("dmg-gatekeeper", ["spctl", "--assess", "--type", "open", "--context", "context:primary-signature",
                                           "--verbose=2", str(dmg)], cwd=ROOT, check=False)
    if "accepted" not in verdict or "Notarized Developer ID" not in verdict:
        raise ReleaseError(f"Gatekeeper does not accept {dmg.name} as a notarized Developer ID disk image:\n{verdict}")


def notary_status(output):
    """The status in notarytool's JSON reply, which may follow other output."""
    start = output.find("{")
    try:
        return json.JSONDecoder().raw_decode(output[start:])[0].get("status") if start >= 0 else None
    except ValueError:
        return None


def mac_app(build, source, version):
    """Build and notarize the Mac app with apple_release.py; return the app and its receipt."""
    build.run("mac-app", [sys.executable, "scripts/apple_release.py", "macos"], cwd=source)
    receipts = sorted((source / ".cache/covee/apple-release").glob("2*/receipt.json"))
    receipt = json.loads(receipts[-1].read_text()) if receipts else {}
    if receipt.get("status") != "passed":
        raise ReleaseError("the Mac app build did not pass; see " + str(build.logs / "mac-app.log"))
    app = source / receipt["notarizedApp"]
    shown = plistlib.loads((app / "Contents/Info.plist").read_bytes()).get("CFBundleShortVersionString")
    if shown != version:
        raise ReleaseError(f"the Mac app calls itself {shown!r}; set MARKETING_VERSION to {version!r} in native/apple/project.yml and commit")
    return app, receipt


def release_notes(version, commit, payload, signed, cli_targets):
    systems = {"darwin/arm64": "Mac with Apple silicon", "darwin/amd64": "Intel Mac",
               "linux/amd64": "Linux on amd64", "linux/arm64": "Linux on arm64"}
    lines = [f"Covee {version}", "",
             "**covee**, the command that builds and runs your own network:"]
    lines += [f"- {systems[t]}: `{cli_archive_name(version, t)}`" for t in cli_targets]
    lines += ["", f"**Covee for Mac**: `{dmg_name(version)}` (Apple silicon, macOS 15 or later). Open it and drag Covee to Applications, or `brew install --cask covee-io/tap/covee`.", "",
              "Known limits:",
              "- Network servers must run Ubuntu 24.04 on amd64.",
              "- The iPhone app is in TestFlight, not yet in the App Store; Tailscale's iPhone app can join a Covee network meanwhile.",
              "- No Windows version yet."]
    if not signed:
        lines.append("- The Mac builds of `covee` are not signed yet: install them with Homebrew or `curl`. macOS blocks the file when it is downloaded in a browser.")
    lines += ["", "Check downloads against `SHA256SUMS`.", "",
              f"Built from commit `{commit}`; server payload sha256 `{payload}`."]
    return "\n".join(lines) + "\n"


def homebrew_formula(version, repo, sums):
    """A Homebrew formula installing the CLI from the release's archives."""
    base = f"https://github.com/{repo}/releases/download/v{version}/"

    def block(target, indent):
        name = cli_archive_name(version, target)
        return f'{indent}url "{base}{name}"\n{indent}sha256 "{sums[name]}"\n'

    return (
        "class Covee < Formula\n"
        '  desc "Build and run your own private network"\n'
        f'  homepage "{HOMEPAGE}"\n'
        f'  version "{version}"\n'
        '  license "Apache-2.0"\n\n'
        "  on_macos do\n"
        "    on_arm do\n" + block("darwin/arm64", "      ") + "    end\n"
        "    on_intel do\n" + block("darwin/amd64", "      ") + "    end\n"
        "  end\n\n"
        "  on_linux do\n"
        "    on_arm do\n" + block("linux/arm64", "      ") + "    end\n"
        "    on_intel do\n" + block("linux/amd64", "      ") + "    end\n"
        "  end\n\n"
        "  def install\n"
        '    bin.install "covee"\n'
        "  end\n\n"
        "  test do\n"
        '    assert_match version.to_s, shell_output("#{bin}/covee version")\n'
        "  end\n"
        "end\n"
    )


def homebrew_cask(version, repo, sums):
    """A Homebrew cask installing the Mac app from the release's disk image."""
    name = dmg_name(version)
    return (
        'cask "covee" do\n'
        f'  version "{version}"\n'
        f'  sha256 "{sums[name]}"\n\n'
        f'  url "https://github.com/{repo}/releases/download/v#{{version}}/Covee.dmg"\n'
        '  name "Covee"\n'
        '  desc "Connect to your own private network"\n'
        f'  homepage "{HOMEPAGE}"\n\n'
        '  depends_on macos: ">= :sequoia"\n'
        '  depends_on arch: :arm64\n\n'
        '  app "Covee.app"\n\n'
        '  uninstall quit: "io.covee.macos"\n\n'
        '  zap trash: [\n'
        '    "~/Library/Containers/io.covee.macos",\n'
        '    "~/Library/Preferences/io.covee.macos.plist",\n'
        '  ]\n'
        "end\n"
    )


def build(args):
    version = check_version(args.version)
    commit = committed(version)
    work, out = WORK / version, DIST / version
    for folder in (out, work):
        if folder.exists():
            remove_tree(folder)
    out.mkdir(parents=True)
    source = work / "source"
    rel = Build(version, work)
    rel.manifest.update({"commit": commit, "cliTargets": list(TARGETS)})
    print(f"Covee {version} from commit {commit[:12]}", flush=True)
    try:
        export(commit, source)
        rel.run("payload", [sys.executable, "scripts/build_cli.py", "--payload-only"], cwd=source)
        payload = sha256((source / "cli/internal/payload/assets/payload.tar.gz").read_bytes())
        rel.manifest["payloadSHA256"] = payload
        if args.skip_tests:
            rel.manifest["skipped"].append("tests")
        else:
            for label, command, cwd in test_steps(source):
                rel.run(label, command, cwd=cwd)
            if not shutil.which("node"):
                rel.manifest["skipped"].append("console tests (node is not installed)")
        binaries = work / "cli"
        if binaries.exists():
            remove_tree(binaries)
        targets = [part for target in TARGETS for part in ("--target", target)]
        rel.run("cli", [sys.executable, "scripts/build_cli.py", "--version", version, "--output", str(binaries), *targets], cwd=source)
        host = host_target()
        if host in TARGETS:
            reported = subprocess.run([str(binaries / host.replace("/", "-") / "covee"), "version"],
                                      capture_output=True, text=True).stdout.strip()
            if reported != f"covee {version}":
                raise ReleaseError(f"the built CLI reports {reported!r}, not covee {version}")
        macs = [binaries / t.replace("/", "-") / "covee" for t in TARGETS if t.startswith("darwin/")]
        identity = developer_id(subprocess.run(["security", "find-identity", "-v", "-p", "codesigning"],
                                               capture_output=True, text=True).stdout)
        if identity:
            sign_and_notarize(rel, macs, identity)
            rel.manifest["cliSigned"] = identity[1]
        elif args.unsigned:
            rel.manifest["cliSigned"] = None
        else:
            raise ReleaseError("there is no Developer ID Application certificate for team " + TEAM + " on this Mac; "
                               "create one in Xcode (Settings, Accounts, Manage Certificates) or build with --unsigned")
        go_root = subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True, check=True).stdout.strip()
        go_version = subprocess.run(["go", "env", "GOVERSION"], capture_output=True, text=True, check=True).stdout.strip()
        texts = [(name, (source / name).read_bytes(), 0o644) for name in ("LICENSE", "NOTICE")]
        cli_notices = third_party_licenses(go_modules(source / "cli", "./cmd/covee", TARGETS), go_root, go_version).encode()
        files = {}
        for target in TARGETS:
            name = cli_archive_name(version, target)
            binary = (binaries / target.replace("/", "-") / "covee").read_bytes()
            files[name] = tar_gz(name[: -len(".tar.gz")], [("covee", binary, 0o755), *texts, ("THIRD_PARTY_LICENSES.txt", cli_notices, 0o644)])
        if args.skip_app:
            rel.manifest["skipped"].append("Mac app")
        else:
            app, receipt = mac_app(rel, source, version)
            app_notices = third_party_licenses(go_modules(source / "native/engine", ".", ["darwin/arm64"], cgo="1"), go_root, go_version)
            folder = work / "mac" / f"Covee-{version}"
            if folder.parent.exists():
                remove_tree(folder.parent)
            folder.mkdir(parents=True)
            rel.run("copy-app", ["ditto", str(app), str(folder / "Covee.app")], cwd=ROOT)
            for name, data, _ in texts:
                (folder / name).write_bytes(data)
            (folder / "THIRD_PARTY_LICENSES.txt").write_text(app_notices, encoding="utf-8")
            if not identity:
                raise ReleaseError("the Mac app's disk image must be signed; it needs the Developer ID Application certificate")
            image = folder.parent / dmg_name(version)
            disk_image(rel, folder, version, identity, image)
            files[image.name] = image.read_bytes()
            rel.manifest["macApp"] = {"build": receipt["build"], "appExecutableSHA256": receipt["appExecutableSHA256"],
                                      "extensionExecutableSHA256": receipt["extensionExecutableSHA256"]}
        sums = {name: sha256(data) for name, data in files.items()}
        for name, data in files.items():
            (out / name).write_bytes(data)
        (out / "SHA256SUMS").write_text("".join(f"{sums[n]}  {n}\n" for n in sorted(sums)), encoding="utf-8")
        (out / "notes.md").write_text(release_notes(version, commit, payload, bool(rel.manifest["cliSigned"]), TARGETS), encoding="utf-8")
        (out / "covee.rb").write_text(homebrew_formula(version, args.repo, sums), encoding="utf-8")
        if dmg_name(version) in sums:
            (out / "covee-cask.rb").write_text(homebrew_cask(version, args.repo, sums), encoding="utf-8")
        rel.manifest["files"] = {name: {"sha256": sums[name], "bytes": len(data)} for name, data in sorted(files.items())}
        rel.manifest["status"] = "built"
        print(f"Built Covee {version} in {out.relative_to(ROOT)}", flush=True)
    except (ReleaseError, OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        rel.manifest["status"] = "failed"
        rel.manifest["error"] = str(error)[:4000]
        print(f"ERROR: {error}", file=sys.stderr)
    finally:
        rel.manifest["finishedAt"] = now_iso()
        (out / "manifest.json").write_text(json.dumps(rel.manifest, indent=2) + "\n", encoding="utf-8")
    return 0 if rel.manifest["status"] == "built" else 1


def host_target():
    machine = {"x86_64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(os.uname().machine, os.uname().machine)
    return f"{os.uname().sysname.lower()}/{machine}"


def ready_to_publish(out):
    """The manifest of a complete, unchanged build, or an error saying what is wrong."""
    manifest = json.loads((out / "manifest.json").read_text())
    if manifest.get("status") != "built":
        raise ReleaseError(f"the build in {out} did not finish; run build again")
    if manifest.get("skipped"):
        raise ReleaseError("this build skipped " + ", ".join(manifest["skipped"]) + "; a release needs a full build")
    for name, recorded in manifest["files"].items():
        if sha256((out / name).read_bytes()) != recorded["sha256"]:
            raise ReleaseError(f"{name} changed after the build; run build again")
    return manifest


def publish(args):
    version = check_version(args.version)
    out = DIST / version
    try:
        manifest = ready_to_publish(out)
        tag, commit = f"v{version}", manifest["commit"]
        existing = subprocess.run(["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}"],
                                  cwd=ROOT, capture_output=True, text=True).stdout.strip()
        if existing and existing != commit:
            raise ReleaseError(f"{tag} already names commit {existing[:12]}")
        if not existing:
            git("tag", "-a", tag, commit, "-m", f"Covee {version}")
        git("push", "origin", f"refs/tags/{tag}")
        files = [str(out / name) for name in manifest["files"]] + [str(out / "SHA256SUMS")]
        subprocess.run(["gh", "release", "create", tag, "--repo", args.repo, "--draft", "--verify-tag",
                        "--title", f"Covee {version}", "--notes-file", str(out / "notes.md"), *files], check=True)
    except (ReleaseError, OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Draft release {tag} created on {args.repo}; publish it on GitHub when ready. "
          f"The Homebrew formula is {out / 'covee.rb'}.", flush=True)
    return 0


def tap(args):
    """Commit the published release's formula and cask to the Homebrew tap."""
    version = check_version(args.version)
    out = DIST / version
    try:
        manifest = ready_to_publish(out)
        state = subprocess.run(["gh", "release", "view", f"v{version}", "--repo", args.repo, "--json", "isDraft"],
                               capture_output=True, text=True)
        if state.returncode or json.loads(state.stdout or "{}").get("isDraft", True):
            raise ReleaseError(f"v{version} is not published on {args.repo} yet; its downloads would not work")
        with tempfile.TemporaryDirectory(prefix="covee-tap-") as folder:
            clone = Path(folder) / "tap"
            subprocess.run(["gh", "repo", "clone", args.tap, str(clone), "--", "--depth", "1"], check=True, capture_output=True)
            (clone / "Formula").mkdir(exist_ok=True)
            shutil.copy2(out / "covee.rb", clone / "Formula/covee.rb")
            if dmg_name(version) in manifest["files"]:
                (clone / "Casks").mkdir(exist_ok=True)
                shutil.copy2(out / "covee-cask.rb", clone / "Casks/covee.rb")
            git("add", "-A", cwd=clone)
            if not git("status", "--porcelain", cwd=clone).strip():
                print(f"The tap already has Covee {version}.", flush=True)
                return 0
            git("commit", "-m", f"Covee {version}", cwd=clone)
            git("push", "origin", "HEAD", cwd=clone)
    except (ReleaseError, OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"{args.tap} now installs Covee {version}.", flush=True)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("build", help="build and check every release file")
    make.add_argument("--version", required=True)
    make.add_argument("--repo", default=REPO, help="GitHub repository the Homebrew formula downloads from")
    make.add_argument("--unsigned", action="store_true", help="allow Mac CLI builds without a Developer ID signature")
    make.add_argument("--skip-tests", action="store_true", help="for trying the build only")
    make.add_argument("--skip-app", action="store_true", help="for trying the build only")
    push = commands.add_parser("publish", help="tag the built commit and create a draft GitHub release")
    push.add_argument("--version", required=True)
    push.add_argument("--repo", default=REPO)
    brew = commands.add_parser("tap", help="put a published release in the Homebrew tap")
    brew.add_argument("--version", required=True)
    brew.add_argument("--repo", default=REPO)
    brew.add_argument("--tap", default=TAP)
    args = parser.parse_args(argv)
    try:
        return {"build": build, "publish": publish, "tap": tap}[args.command](args)
    except ReleaseError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
