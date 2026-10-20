"""Fail-closed source integrity and archive handling for the downstream build."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("headscale_builder", ROOT / "scripts/build_headscale.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class HeadscaleIntegrityTests(unittest.TestCase):
    def test_builder_refuses_root_and_preserves_operator_identity(self):
        lock = builder.read_lock()
        with patch.object(builder.os, "getuid", return_value=0):
            with self.assertRaisesRegex(builder.BuildError, "non-root"):
                builder.builder_command(lock, "linux/amd64", cgo=False)
        with patch.object(builder.os, "getuid", return_value=10001), patch.object(builder.os, "getgid", return_value=1001):
            command = builder.builder_command(lock, "linux/amd64", cgo=True)
        self.assertEqual(command[command.index("--user") + 1], "10001:1001")
        self.assertIn("--cap-drop=ALL", command)
        self.assertIn("--security-opt=no-new-privileges", command)
        self.assertIn("--read-only", command)

    def test_builder_never_asks_for_more_cpus_than_the_host_has(self):
        lock = builder.read_lock()
        for available, expected in ((2, "--cpus=2"), (16, "--cpus=4"), (None, "--cpus=1")):
            with self.subTest(available=available), patch.object(builder.os, "cpu_count", return_value=available), \
                    patch.object(builder.os, "getuid", return_value=10001):
                self.assertIn(expected, builder.builder_command(lock, "linux/amd64", cgo=False))

    @unittest.skipUnless(os.environ.get("COVEE_TEST_PRIVATE_BUILDER") == "1", "explicit Docker private-mount qualification only")
    def test_private_mounts_are_readable_and_outputs_keep_operator_ownership(self):
        lock = builder.read_lock()
        with tempfile.TemporaryDirectory(prefix="covee-private-builder-") as temporary:
            root = Path(temporary)
            source, cache = root / "source", root / "cache"
            source.mkdir(mode=0o700)
            cache.mkdir(mode=0o700)
            (source / "go.mod").write_text("module private.example\n")
            (source / "go.mod").chmod(0o600)
            with patch.object(builder, "SOURCE", source), patch.object(builder, "BUILD", cache):
                command = builder.builder_command(lock, builder.native_platform(), cgo=False)
            command.insert(command.index(lock["toolchain"]["image"]), "--network=none")
            command += ["/bin/sh", "-eu", "-c", 'umask 077; test "$(id -u)" = "$1"; test "$(id -g)" = "$2"; cat /src/go.mod >/dev/null; printf private > /cache/output', "private-builder", str(os.getuid()), str(os.getgid())]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((cache / "output").read_text(), "private")
            self.assertEqual((cache / "output").stat().st_uid, os.getuid())
            self.assertEqual((cache / "output").stat().st_gid, os.getgid())
            for directory in (root, source, cache):
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_a_cache_made_for_an_older_patchset_is_stale_but_drift_still_stops(self):
        lock = {"patched_tree_sha256": "a" * 64}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, cache = root / "source", root / "cache"
            source.mkdir()
            cache.mkdir()
            (source / "file.go").write_text("package x\n")
            with patch.object(builder, "SOURCE", source), patch.object(builder, "BUILD", cache), \
                    patch.object(builder, "PREPARED_FOR", cache / "prepared-tree.sha256"):
                # No record and a different tree: an older cache, regenerate.
                self.assertFalse(builder.made_for_lock(lock))
                # No record but the right tree: current.
                self.assertTrue(builder.made_for_lock({"patched_tree_sha256": builder.tree_digest(source)}))
                # Recorded for an older patchset: regenerate.
                (cache / "prepared-tree.sha256").write_text("b" * 64 + "\n")
                self.assertFalse(builder.made_for_lock(lock))
                # Recorded for this patchset: it must verify, so an edited tree stops the build.
                (cache / "prepared-tree.sha256").write_text("a" * 64 + "\n")
                self.assertTrue(builder.made_for_lock(lock))
                with self.assertRaisesRegex(builder.BuildError, "differs from the locked patchset"):
                    builder.prepare(lock)

    def test_locked_inputs_detect_patch_and_provenance_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs = Path(temporary)
            lock = json.loads(builder.LOCK.read_text())
            for entry in [*lock["patches"], *lock["upstream_provenance"]]:
                target = inputs / entry["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((builder.INPUTS / entry["path"]).read_bytes())
            lock_path = inputs / "source-lock.json"
            lock_path.write_text(json.dumps(lock))
            with patch.object(builder, "INPUTS", inputs), patch.object(builder, "LOCK", lock_path):
                builder.read_lock()
                for entry in [lock["patches"][0], lock["upstream_provenance"][0]]:
                    target = inputs / entry["path"]
                    original = target.read_bytes()
                    target.write_bytes(original + b"\nmodified\n")
                    with self.assertRaisesRegex(builder.BuildError, "input hash mismatch"):
                        builder.read_lock()
                    target.write_bytes(original)

    def test_different_source_commit_or_location_is_rejected(self):
        lock = json.loads(builder.LOCK.read_text())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "source-lock.json"
            with patch.object(builder, "LOCK", path):
                lock["source"]["commit"] = "0" * 40
                path.write_text(json.dumps(lock))
                with self.assertRaisesRegex(builder.BuildError, "source lock"):
                    builder.read_lock()
                lock["source"]["commit"] = builder.SOURCE_COMMIT
                lock["source"]["url"] = "https://example.invalid/source.tar.gz"
                path.write_text(json.dumps(lock))
                with self.assertRaisesRegex(builder.BuildError, "source location"):
                    builder.read_lock()

    def test_tree_hash_detects_changed_added_and_executable_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            file = source / "main.go"
            file.write_text("package main\n")
            file.chmod(0o644)
            original = builder.tree_digest(source)
            lock = {"patched_tree_sha256": original}
            with patch.object(builder, "SOURCE", source):
                builder.verify_source(lock)
                file.write_text("package altered\n")
                with self.assertRaisesRegex(builder.BuildError, "differs"):
                    builder.verify_source(lock)
                file.write_text("package main\n")
                file.chmod(0o755)
                self.assertNotEqual(original, builder.tree_digest(source))
                file.chmod(0o644)
                (source / "unexpected.go").write_text("package main\n")
                with self.assertRaisesRegex(builder.BuildError, "differs"):
                    builder.verify_source(lock)

    def test_source_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / "actual").write_text("source")
            (source / "alias").symlink_to("actual")
            with self.assertRaisesRegex(builder.BuildError, "source symlink"):
                builder.tree_digest(source)

    def test_archive_rejects_parent_traversal_and_symlinks(self):
        for kind in ("traversal", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "source.tar.gz"
                destination = root / "source"
                destination.mkdir()
                name = f"headscale-{builder.SOURCE_COMMIT}/" + ("../escaped" if kind == "traversal" else "link")
                member = tarfile.TarInfo(name)
                if kind == "symlink":
                    member.type = tarfile.SYMTYPE
                    member.linkname = "../../escaped"
                else:
                    member.size = 4
                with tarfile.open(archive, "w:gz") as stream:
                    stream.addfile(member, io.BytesIO(b"data") if member.isfile() else None)
                with self.assertRaises(builder.BuildError):
                    builder.extract_source(archive, destination, builder.SOURCE_COMMIT)
                self.assertFalse((root / "escaped").exists())

    def test_archive_preserves_bytes_and_executable_bit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "source.tar.gz"
            destination = root / "source"
            destination.mkdir()
            member = tarfile.TarInfo(f"headscale-{builder.SOURCE_COMMIT}/tools/check")
            member.mode = 0o755
            member.size = 4
            with tarfile.open(archive, "w:gz") as stream:
                stream.addfile(member, io.BytesIO(b"data"))
            builder.extract_source(archive, destination, builder.SOURCE_COMMIT)
            target = destination / "tools/check"
            self.assertEqual(b"data", target.read_bytes())
            self.assertTrue(target.stat().st_mode & 0o111)


if __name__ == "__main__":
    unittest.main()
