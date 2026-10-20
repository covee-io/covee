#!/usr/bin/env python3
"""Build a hash-locked downstream Headscale without changing the research checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import fcntl
from datetime import datetime, timezone
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ROOT / "deploy/headscale"
LOCK = INPUTS / "source-lock.json"
SOURCE = ROOT / ".cache/covee/deploy/headscale-src"
BUILD = ROOT / ".cache/covee/deploy/headscale-build"
# Which locked patched tree the prepared source cache was made for. Kept
# outside the source so it is not part of the tree digest.
PREPARED_FOR = BUILD / "prepared-tree.sha256"
IMAGE = "covee-headscale:hardened-local"
SOURCE_COMMIT = "8106636c7f8d0cf8c9d4fb0beae94415069b768b"
TEST_PACKAGES = ["./hscontrol", "./hscontrol/mapper", "./hscontrol/policy/...", "./hscontrol/servertest"]
TEST_PATTERN = (
    "^(TestCoveeUnregisteredNoiseCannotReadMetrics|TestSSHAction.*|TestSSHPolicy.*|"
    "TestSSHCheck.*|TestCompileSSHPolicy.*|TestInitialMapCarriesDebugConfigOnEveryStream|"
    "TestMapResponseBuilder_WithDebugConfig|TestGenerateMapResponseDebugOnlyOnFullMaps|"
    "TestLogTailDisabledOnEveryStream|TestPolicyChanges|"
    "TestPollNetMapHandler_DeletedNodeGetsExpiredSelf)$"
)
REQUIRED_TESTS = {
    "TestCoveeUnregisteredNoiseCannotReadMetrics",
    "TestSSHActionHandler_RejectsWithoutCheck",
    "TestSSHActionFollowUp_RejectsVerdictAfterCheckRemoved",
    "TestSSHActionFollowUp_ConsumedVerdictNotReplayed",
    "TestSSHActionFollowUp_ConcurrentWaiters",
    "TestSSHPolicyEmptyOnWire",
    "TestSSHCheckParams",
    "TestInitialMapCarriesDebugConfigOnEveryStream",
    "TestLogTailDisabledOnEveryStream",
    "TestGenerateMapResponseDebugOnlyOnFullMaps",
    "TestPollNetMapHandler_DeletedNodeGetsExpiredSelf",
}


class BuildError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_digest(directory: Path) -> str:
    """Hash names, executable bits and bytes, including unexpected files."""
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise BuildError(f"unexpected source symlink: {path.relative_to(directory)}")
        if path.is_file():
            name = path.relative_to(directory).as_posix()
            executable = bool(path.stat().st_mode & 0o111)
            digest.update(f"{name}\0{int(executable)}\0{sha256(path)}\n".encode())
    return digest.hexdigest()


def checked_relative(base: Path, name: str) -> Path:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise BuildError(f"unsafe input path: {name}")
    candidate = base / name
    if candidate.is_symlink() or not candidate.resolve().is_relative_to(base.resolve()):
        raise BuildError(f"input escapes its directory: {name}")
    return candidate


def read_lock() -> dict:
    lock = json.loads(LOCK.read_text())
    if lock.get("schema_version") != 1 or lock["source"]["commit"] != SOURCE_COMMIT:
        raise BuildError("unsupported or unexpected Headscale source lock")
    if lock["source"]["url"] != f"https://codeload.github.com/juanfont/headscale/tar.gz/{SOURCE_COMMIT}":
        raise BuildError("unexpected upstream source location")
    if not lock["toolchain"]["image"].startswith("golang:1.26.9-bookworm@sha256:"):
        raise BuildError("unrecognized toolchain pin")
    for entry in [*lock["patches"], *lock["upstream_provenance"]]:
        path = checked_relative(INPUTS, entry["path"])
        if not path.is_file() or sha256(path) != entry["sha256"]:
            raise BuildError(f"input hash mismatch: {entry['path']}")
    return lock


def verify_source(lock: dict) -> str:
    if not SOURCE.is_dir() or SOURCE.is_symlink():
        raise BuildError("prepared source missing; run prepare")
    actual = tree_digest(SOURCE)
    if actual != lock["patched_tree_sha256"]:
        raise BuildError("prepared source differs from the locked patchset; use prepare --reset-source only for this disposable cache")
    return actual


def extract_source(archive: Path, destination: Path, commit: str) -> None:
    prefix = f"headscale-{commit}"
    with tarfile.open(archive, "r:gz") as source:
        for member in source:
            name = PurePosixPath(member.name)
            if not name.parts or name.parts[0] != prefix:
                raise BuildError("unexpected archive prefix")
            if len(name.parts) == 1:
                continue
            relative = PurePosixPath(*name.parts[1:]).as_posix()
            target = checked_relative(destination, relative)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = source.extractfile(member)
                if stream is None:
                    raise BuildError("unreadable archive member")
                with stream, target.open("wb") as output:
                    shutil.copyfileobj(stream, output)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
            else:
                raise BuildError(f"unsupported archive member: {member.name}")


def capture(command: list[str], *, cwd: Path = ROOT) -> str:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if result.returncode:
        raise BuildError(f"command failed: {' '.join(command[:4])}\n{result.stderr[-4000:]}")
    return result.stdout.strip()


def made_for_lock(lock: dict) -> bool:
    """Whether the existing source cache was prepared for this lock's patchset.

    A cache made for this lock must verify exactly. One made for another
    patchset (or, without a record, whose tree is not this lock's) is stale.
    """
    made_for = PREPARED_FOR.read_text().strip() if PREPARED_FOR.is_file() else None
    if made_for is not None:
        return made_for == lock["patched_tree_sha256"]
    return tree_digest(SOURCE) == lock["patched_tree_sha256"]


def prepare(lock: dict, reset_source: bool = False) -> None:
    BUILD.mkdir(parents=True, exist_ok=True)
    if SOURCE.exists() and not reset_source:
        if made_for_lock(lock):
            # Made for this lock: any difference now is drift or tampering, which stops the build.
            verify_source(lock)
            PREPARED_FOR.write_text(lock["patched_tree_sha256"] + "\n")
            print("Prepared source verified; research checkout unchanged.", flush=True)
            return
        # The locked patchset changed since this cache was made (for example by
        # `covee update`); regenerate it from the verified archive and patches.
        print("The locked patchset changed; regenerating the prepared source.", flush=True)
    archive = BUILD / "source.tar.gz"
    if not archive.is_file() or sha256(archive) != lock["source"]["archive_sha256"]:
        archive.unlink(missing_ok=True)
        print("Downloading the exact locked upstream source archive...", flush=True)
        with urlopen(lock["source"]["url"], timeout=120) as response, archive.open("wb") as output:
            shutil.copyfileobj(response, output)
    if sha256(archive) != lock["source"]["archive_sha256"]:
        raise BuildError("upstream source archive hash mismatch")
    with tempfile.TemporaryDirectory(prefix="headscale-prepare-", dir=BUILD) as temporary:
        staged = Path(temporary)
        extract_source(archive, staged, SOURCE_COMMIT)
        for patch in lock["patches"]:
            patch_path = checked_relative(INPUTS, patch["path"])
            capture(["git", "apply", "--check", str(patch_path)], cwd=staged)
            capture(["git", "apply", str(patch_path)], cwd=staged)
        if tree_digest(staged) != lock["patched_tree_sha256"]:
            raise BuildError("deterministically patched tree does not match lock")
        if SOURCE.exists():
            if SOURCE.is_symlink():
                raise BuildError("refusing to replace a source-cache symlink")
            shutil.rmtree(SOURCE)
        shutil.copytree(staged, SOURCE)
    verify_source(lock)
    PREPARED_FOR.write_text(lock["patched_tree_sha256"] + "\n")
    print("Prepared exact upstream source plus locked downstream patches.", flush=True)


def native_platform() -> str:
    os_name, arch = capture(["docker", "info", "--format", "{{.OSType}} {{.Architecture}}"]).split()
    arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(arch, arch)
    platform = f"{os_name}/{arch}"
    if platform not in ("linux/amd64", "linux/arm64"):
        raise BuildError(f"unsupported Docker platform: {platform}")
    return platform


def builder_command(lock: dict, platform: str, *, cgo: bool) -> list[str]:
    uid, gid = os.getuid(), os.getgid()
    if uid == 0:
        raise BuildError("Run the builder as a non-root account that owns its source and cache")
    return [
        "docker", "run", "--rm", "--init", "--platform", platform,
        # Dropping every capability also removes root's DAC override on Linux.
        # Preserve the private bind mounts by using their invoking owner.
        "--user", f"{uid}:{gid}",
        # At most four CPUs, but never more than the host has: Docker rejects that.
        f"--cpus={max(1, min(4, os.cpu_count() or 1))}", "--memory=8g", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--read-only", "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=4g,mode=1777",
        "--mount", f"type=bind,src={SOURCE},dst=/src,readonly",
        "--mount", f"type=bind,src={BUILD},dst=/cache",
        "--workdir", "/src", "--env", "HOME=/tmp", "--env", "GOTOOLCHAIN=local",
        "--env", "GOFLAGS=-mod=readonly", "--env", "GOMODCACHE=/cache/go-mod",
        "--env", "GOCACHE=/cache/go-build", "--env", f"CGO_ENABLED={int(cgo)}",
        lock["toolchain"]["image"],
    ]


def run_logged(command: list[str], path: Path) -> dict:
    started = datetime.now(timezone.utc).isoformat()
    print(f"Running {path.name}; full output: {path.relative_to(ROOT)}", flush=True)
    with path.open("w") as output:
        result = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
    receipt = {
        "command": command, "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "exit_code": result.returncode, "log": str(path.relative_to(ROOT)), "log_sha256": sha256(path),
    }
    if result.returncode:
        print(path.read_text(errors="replace")[-8000:], file=sys.stderr)
        raise BuildError(f"{path.name} failed with exit code {result.returncode}")
    print(f"Passed: {path.name}", flush=True)
    return receipt


def test(lock: dict, platform: str) -> dict:
    prepare(lock)
    (BUILD / "test-results.json").unlink(missing_ok=True)
    command = builder_command(lock, platform, cgo=True) + [
        "go", "test", "-json", "-race", "-p", "2", "-count=1", "-timeout=15m",
        "-run", TEST_PATTERN, *TEST_PACKAGES,
    ]
    result = run_logged(command, BUILD / "security-tests.log")
    verify_source(lock)
    events = []
    for line in (BUILD / "security-tests.log").read_text().splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    passed_tests = {event["Test"] for event in events if event.get("Action") == "pass" and "Test" in event}
    if missing := REQUIRED_TESTS - passed_tests:
        raise BuildError("required security regressions did not execute: " + ", ".join(sorted(missing)))
    result.update({"status": "passed", "platform": platform, "source_tree_sha256": lock["patched_tree_sha256"]})
    result["passed_test_count"] = len(passed_tests)
    result["required_tests"] = sorted(REQUIRED_TESTS)
    (BUILD / "test-results.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def build(lock: dict, platform: str, image: str) -> dict:
    BUILD.mkdir(parents=True, exist_ok=True)
    (BUILD / "manifest.json").unlink(missing_ok=True)
    tests = test(lock, platform)
    (BUILD / "bin").mkdir(exist_ok=True)
    binary = BUILD / "bin/headscale"
    binary.unlink(missing_ok=True)
    command = builder_command(lock, platform, cgo=False) + [
        "go", "build", "-p", "2", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=",
        "-o", "/cache/bin/headscale", "./cmd/headscale",
    ]
    compilation = run_logged(command, BUILD / "compile.log")
    verify_source(lock)
    image_context = BUILD / "image"
    if image_context.exists():
        shutil.rmtree(image_context)
    image_context.mkdir()
    shutil.copyfile(binary, image_context / "headscale")
    (image_context / "headscale").chmod(0o755)
    shutil.copyfile(SOURCE / "LICENSE", image_context / "LICENSE")
    (image_context / "state").mkdir()
    (image_context / "state/.keep").touch()
    image_build = run_logged([
        "docker", "build", "--platform", platform, "--tag", image,
        "--build-arg", "RUNTIME_IMAGE=" + lock["runtime"]["image"],
        "--build-arg", "SOURCE_COMMIT=" + SOURCE_COMMIT,
        "--build-arg", "PATCHSET_SHA256=" + lock["patched_tree_sha256"],
        "--file", str(INPUTS / "Dockerfile"), str(image_context),
    ], BUILD / "image-build.log")
    inspection = json.loads(capture(["docker", "image", "inspect", image]))[0]
    if inspection["Config"]["User"] != "10001:10001":
        raise BuildError("runtime image does not declare required non-root UID/GID")
    smoke = run_logged([
        "docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", image, "version",
    ], BUILD / "runtime-smoke.log")
    manifest = {
        "schema_version": 1, "status": "built-and-regression-tested",
        "built_at": datetime.now(timezone.utc).isoformat(),
        "source": lock["source"], "patched_tree_sha256": lock["patched_tree_sha256"],
        "patches": lock["patches"], "upstream_provenance": lock["upstream_provenance"],
        "source_lock_sha256": sha256(LOCK), "builder_script_sha256": sha256(Path(__file__)),
        "runtime_dockerfile_sha256": sha256(INPUTS / "Dockerfile"),
        "toolchain": lock["toolchain"], "runtime": lock["runtime"],
        "platform": platform, "image": image, "image_id": inspection["Id"],
        "runtime_user": inspection["Config"]["User"], "binary_sha256": sha256(binary),
        "tests": tests, "compilation": compilation, "image_build": image_build, "runtime_smoke": smoke,
        "qualification": "Local source regressions and image smoke only; no public deployment, Entra acceptance or production certification.",
    }
    (BUILD / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"image": image, "image_id": inspection["Id"], "manifest": str((BUILD / "manifest.json").relative_to(ROOT))}, indent=2), flush=True)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify", "test", "build"))
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"))
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--reset-source", action="store_true", help="replace only the disposable prepared source cache")
    args = parser.parse_args(argv)
    if args.reset_source and args.command != "prepare":
        parser.error("--reset-source is only valid for prepare")
    try:
        BUILD.mkdir(parents=True, exist_ok=True)
        with (BUILD / ".build.lock").open("a") as build_lock:
            fcntl.flock(build_lock, fcntl.LOCK_EX)
            lock = read_lock()
            if args.command == "prepare":
                prepare(lock, args.reset_source)
            elif args.command == "verify":
                print(json.dumps({"status": "verified", "source_tree_sha256": verify_source(lock)}, indent=2))
            else:
                platform = args.platform or native_platform()
                if args.command == "test":
                    test(lock, platform)
                else:
                    build(lock, platform, args.image)
    except (BuildError, OSError, ValueError, KeyError) as error:
        print(f"Headscale build stopped: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
