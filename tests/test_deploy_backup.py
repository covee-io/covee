"""Real age round trips and adversarial archive/operation boundary checks."""

import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import deploy_backup as snapshots
from deploy import CONFIG_FILES, SECRET_FILES, IMAGES, IDENTITY_IMAGE, identity_files, replace_private, runtime_env


class FakeRuntime:
    def __init__(self, directory, services=("headscale", "management")):
        self.directory, self.services, self.calls, self.times = directory, services, [], []

    def compose(self, *args, **kwargs):
        self.calls.append(args)
        self.times.append(time.monotonic())
        output = "\n".join(self.services).encode() if args[0] == "ps" else b""
        return subprocess.CompletedProcess([], 0, stdout=output, stderr=b"")

    def start(self):
        # Stands in for deploy.Runtime.start(), the ordered identity-aware start.
        self.calls.append(("ordered-start",))
        self.times.append(time.monotonic())


def private_file(path, data):
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    path.chmod(0o400)


def prepared_fixture(directory):
    directory.mkdir(mode=0o700)
    for name in snapshots.REQUIRED_DIRS:
        (directory / name).mkdir(mode=0o700)
    for name in CONFIG_FILES:
        private_file(directory / name, "fixture configuration " + name)
    for name in SECRET_FILES:
        private_file(directory / "secrets" / name, "sensitive-fixture-secret-" + name)
    metadata = {"format": 1, "lab": True, "uid": os.getuid(), "gid": os.getgid(), "spec": {
        "control_host": "ingress", "admin_host": "admin", "public_bind": "127.0.0.1",
        "public_port": 8443, "admin_port": 8444, "stun_port": 3478}}
    private_file(directory / "deployment.json", json.dumps(metadata))
    private_file(directory / "runtime.env", runtime_env(directory, metadata))
    private_file(directory / "state/headscale/db.sqlite", b"sensitive-fixture-database-bytes\0\1\2")
    private_file(directory / "state/headscale/noise_private.key", "sensitive-fixture-noise-key")
    private_file(directory / "state/management/audit.jsonl", '{"action":"fixture"}\n')


def member_archive(name, *, kind=tarfile.REGTYPE, size=None, data=b"fixture", linkname=""):
    member = tarfile.TarInfo(name)
    member.type, member.linkname = kind, linkname
    member.size = (len(data) if kind in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0) if size is None else size
    header = member.tobuf(format=tarfile.USTAR_FORMAT)
    payload = data if kind in (tarfile.REGTYPE, tarfile.AREGTYPE) and member.size == len(data) else b""
    return header + payload + b"\0" * ((-len(payload)) % 512) + b"\0" * 1024


class ArchiveBoundaryTests(unittest.TestCase):
    def test_traversal_and_noncanonical_names_are_rejected_before_writes(self):
        names = ["/state/headscale/escape", "../escape", "state/headscale/../../escape", "state/headscale//escape",
                 "state/headscale/./escape", "state/headscale\\escape", "other/escape", "state/headscale/space name"]
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                target = Path(temp) / "new"
                target.mkdir(mode=0o700)
                with self.assertRaises(snapshots.BackupError):
                    snapshots._extract(io.BytesIO(member_archive(name)), target)
                self.assertEqual(list(target.iterdir()), [])

    def test_links_special_files_and_extension_records_are_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE,
                     tarfile.BLKTYPE, tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_SPARSE):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                target = Path(temp) / "new"
                target.mkdir(mode=0o700)
                with self.assertRaises(snapshots.BackupError):
                    snapshots._extract(io.BytesIO(member_archive("state/headscale/unsafe", kind=kind, linkname="../../outside")), target)
                self.assertEqual(list(target.iterdir()), [])

    def test_declared_oversize_and_bad_checksums_are_rejected(self):
        oversized = member_archive("state/headscale/db.sqlite", size=snapshots.MAX_MEMBER_BYTES + 1)
        corrupted = bytearray(member_archive("state/headscale/db.sqlite"))
        corrupted[0] ^= 1
        for payload in (oversized, bytes(corrupted)):
            with self.subTest(kind=len(payload)), tempfile.TemporaryDirectory() as temp:
                target = Path(temp) / "new"
                target.mkdir(mode=0o700)
                with self.assertRaises(snapshots.BackupError):
                    snapshots._extract(io.BytesIO(payload), target)
                self.assertEqual(list(target.iterdir()), [])

    def test_duplicate_members_cannot_replace_restored_files(self):
        first = member_archive("state/headscale/db.sqlite", data=b"first")[:-1024]
        second = member_archive("state/headscale/db.sqlite", data=b"second")
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            with self.assertRaises(snapshots.BackupError):
                snapshots._extract(io.BytesIO(first + second), target)
            self.assertEqual((target / "state/headscale/db.sqlite").read_bytes(), b"first")


class EncryptedSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.getuid() == 0:
            raise unittest.SkipTest("runtime operations deliberately require a non-root service account")
        try:
            cls.age = snapshots._age("age")
        except snapshots.BackupError as error:
            raise unittest.SkipTest(str(error))
        cls.keygen = shutil.which("age-keygen") or str(ROOT / ".cache/covee/deploy/tools/age-keygen")
        if not Path(cls.keygen).is_file():
            raise unittest.SkipTest("age-keygen is required for real encryption tests")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / "runtime"
        prepared_fixture(self.source)
        self.runtime = FakeRuntime(self.source)
        self.identity = self.base / "identity"
        subprocess.run([self.keygen, "--output", str(self.identity)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.identity.chmod(0o600)
        self.recipient = subprocess.run([self.keygen, "-y", str(self.identity)], check=True,
                                        capture_output=True).stdout.decode().strip()

    def encrypt(self, payload, name="malicious.age"):
        archive = self.base / name
        with archive.open("wb") as output:
            subprocess.run([self.age, "--encrypt", "--recipient", self.recipient], input=payload, stdout=output,
                           stderr=subprocess.DEVNULL, check=True)
        return archive

    def stalled_age(self):
        executable = self.base / "stalled-age"
        started, survived = self.base / "plugin-started", self.base / "plugin-survived"
        armed = self.base / "plugin-armed"
        # Encryption preflight succeeds, but a real payload is never consumed.
        # On decryption the leader exits while its child retains the pipe.
        # The delayed marker proves that killing only the leader is insufficient.
        child = ("import os, time\nfrom pathlib import Path\nPath(" + repr(str(started)) + ").write_text(str(os.getpid()))\n"
                 "while not Path(" + repr(str(armed)) + ").is_file(): time.sleep(0.005)\n"
                 "time.sleep(2)\nPath(" + repr(str(survived)) + ").write_text('survived')\n")
        executable.write_text("#!" + sys.executable + "\n"
                              "import os, stat, subprocess, sys, time\n"
                              "if '--encrypt' in sys.argv and not stat.S_ISFIFO(os.fstat(0).st_mode): sys.exit(0)\n"
                              "child = subprocess.Popen([sys.executable, '-c', " + repr(child) + "])\n"
                              "if '--decrypt' in sys.argv: sys.exit(0)\n"
                              "time.sleep(60)\n")
        executable.chmod(0o700)
        return executable, started, survived

    def deadline_after_child_start(self, started, *, leader_exits=False):
        original = snapshots._AgeDeadline
        operation_seconds = snapshots.AGE_TIMEOUT_SECONDS
        ready = {}

        class ReadyDeadline(original):
            def __init__(self, seconds):
                self.fixture_operation = seconds == operation_seconds
                super().__init__(seconds)

            def attach(self, process):
                super().attach(process)
                if not self.fixture_operation:
                    return  # The encryption recipient preflight stays unchanged.
                until = time.monotonic() + 10
                while not started.is_file():
                    if time.monotonic() >= until:
                        raise AssertionError("Stalled child fixture did not become ready")
                    time.sleep(0.005)
                if leader_exits:
                    process.wait(timeout=10)
                    ready["leader_exited"] = True
                # Exercise the real deadline and process-group cleanup only
                # after the child is running. Interpreter startup under load
                # must not consume the fixture's short streaming deadline.
                self.timer.cancel()
                self.timer.join(timeout=6)
                ready["deadline_started"] = time.monotonic()
                self.timer = snapshots.threading.Timer(0.5, self._expire)
                self.timer.daemon = True
                self.timer.start()
                started.with_name("plugin-armed").touch(mode=0o600)

        return patch.object(snapshots, "_AgeDeadline", ReadyDeadline), ready

    def test_real_age_roundtrip_preserves_state_secrets_and_internal_ca(self):
        archive = snapshots.backup(self.runtime, self.base / "backup.age", self.recipient, self.age)
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b"sensitive-fixture", archive.read_bytes())
        self.assertEqual(self.runtime.calls[1:], [("stop", "--timeout", "20", "headscale", "management"),
                                                 ("start", "headscale", "management")])
        target = snapshots.restore(archive, self.base / "restored", self.identity, self.age)
        for name in ("secrets/admin-token", "secrets/headscale-api-key", "internal-ca.key",
                     "state/headscale/noise_private.key", "state/headscale/db.sqlite", "state/management/audit.jsonl"):
            self.assertEqual((target / name).read_bytes(), (self.source / name).read_bytes())
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        self.assertEqual((target / "internal-ca.key").stat().st_mode & 0o777, 0o400)
        self.assertEqual((target / "state/headscale/db.sqlite").stat().st_mode & 0o777, 0o600)
        metadata = json.loads((target / "deployment.json").read_bytes())
        self.assertEqual((metadata["uid"], metadata["gid"]), (os.getuid(), os.getgid()))
        env = (target / "runtime.env").read_text()
        self.assertIn(f"COVEE_DEPLOY_DIR='{target}'", env)
        self.assertNotIn(str(self.source), env)
        for service, image in IMAGES.items():
            self.assertIn(f"COVEE_{service.upper()}_IMAGE='{image}'", env)

    def test_failed_snapshot_restarts_exact_original_subset_and_removes_output(self):
        self.runtime.services = ("headscale",)
        paths = snapshots._snapshot_paths(self.source)
        archive = self.base / "failed.age"
        with patch.object(snapshots, "_snapshot_paths", side_effect=[paths, snapshots.BackupError("fixture failure")]):
            with self.assertRaises(snapshots.BackupError):
                snapshots.backup(self.runtime, archive, self.recipient, self.age)
        self.assertFalse(archive.exists())
        self.assertEqual(self.runtime.calls[1:], [("stop", "--timeout", "20", "headscale"), ("start", "headscale")])

    def test_social_identity_backup_restores_signing_key_provider_secrets_and_image(self):
        metadata = json.loads((self.source / "deployment.json").read_bytes())
        metadata["lab"] = False
        metadata["spec"]["identity"] = {"providers": [{"id": "google", "kind": "google"}, {"id": "apple", "kind": "apple"}], "grants": []}
        replace_private(self.source / "deployment.json", json.dumps(metadata))
        replace_private(self.source / "runtime.env", runtime_env(self.source, metadata))
        files, dirs = identity_files(metadata)
        for name in dirs:
            (self.source / name).mkdir(mode=0o700)
        for name in files:
            private_file(self.source / name, "sensitive-social-fixture-" + name)
        self.runtime.services = ("headscale", "management", "ingress", "identity")
        archive = snapshots.backup(self.runtime, self.base / "social.age", self.recipient, self.age)
        self.assertNotIn(b"sensitive-social-fixture", archive.read_bytes())
        target = snapshots.restore(archive, self.base / "restored-social", self.identity, self.age)
        for name in files:
            self.assertEqual((target / name).read_bytes(), (self.source / name).read_bytes())
            self.assertFalse((target / name).stat().st_mode & 0o077)
        self.assertIn("COVEE_IDENTITY_IMAGE='" + IDENTITY_IMAGE + "'", (target / "runtime.env").read_text())
        # Found live on 2026-10-12: a plain `compose start` left Headscale unable to reach
        # its issuer through the stopped gateway. The broker profile must use the ordered start.
        self.assertEqual(self.runtime.calls[-1], ("ordered-start",))

    def test_local_accounts_are_backed_up_and_restored(self):
        metadata = json.loads((self.source / "deployment.json").read_bytes())
        metadata["lab"] = False
        metadata["spec"]["identity"] = {"providers": [{"id": "local", "kind": "local", "accounts_file": "/var/lib/covee-identity/accounts.json"}], "grants": []}
        replace_private(self.source / "deployment.json", json.dumps(metadata))
        replace_private(self.source / "runtime.env", runtime_env(self.source, metadata))
        files, dirs = identity_files(metadata)
        for name in dirs:
            (self.source / name).mkdir(mode=0o700, exist_ok=True)
        for name in files:
            private_file(self.source / name, "sensitive-social-fixture-" + name)
        (self.source / "state/identity").mkdir(mode=0o700)
        private_file(self.source / "state/identity/accounts.json", '{"accounts": "sensitive-local-accounts"}')
        archive = snapshots.backup(self.runtime, self.base / "local.age", self.recipient, self.age)
        self.assertNotIn(b"sensitive-local-accounts", archive.read_bytes())
        target = snapshots.restore(archive, self.base / "restored-local", self.identity, self.age)
        restored = target / "state/identity/accounts.json"
        self.assertEqual(restored.read_bytes(), (self.source / "state/identity/accounts.json").read_bytes())
        self.assertEqual(restored.stat().st_mode & 0o777, 0o600)
        self.assertEqual((target / "state/identity").stat().st_mode & 0o777, 0o700)
        self.assertNotIn(("start", "headscale", "identity", "ingress", "management"), self.runtime.calls)

    def test_stalled_encrypt_stream_kills_plugin_and_restarts_services(self):
        executable, started, survived = self.stalled_age()
        private_file(self.source / "state/headscale/large.sqlite", b"x" * (256 << 10))
        archive = self.base / "stalled.age"
        deadline, ready = self.deadline_after_child_start(started)
        with deadline, self.assertRaises(snapshots.BackupError):
            snapshots.backup(self.runtime, archive, self.recipient, executable)
        self.assertLess(self.runtime.times[-1] - ready["deadline_started"], 3)
        self.assertTrue(started.is_file())
        self.assertFalse(archive.exists())
        self.assertEqual(self.runtime.calls[1:], [("stop", "--timeout", "20", "headscale", "management"),
                                                 ("start", "headscale", "management")])
        time.sleep(2.1)
        self.assertFalse(survived.exists())

    def test_stalled_decrypt_pipe_is_bounded_after_leader_exit(self):
        executable, started, survived = self.stalled_age()
        archive = self.base / "stalled.age"
        archive.write_bytes(b"fixture encrypted archive")
        target = self.base / "not-restored"
        deadline, ready = self.deadline_after_child_start(started, leader_exits=True)
        with deadline, self.assertRaises(snapshots.BackupError):
            snapshots.restore(archive, target, self.identity, executable)
        self.assertTrue(ready["leader_exited"])
        self.assertLess(time.monotonic() - ready["deadline_started"], 3)
        self.assertTrue(started.is_file())
        self.assertFalse(target.exists())
        time.sleep(2.1)
        self.assertFalse(survived.exists())

    def test_already_stopped_runtime_remains_stopped(self):
        self.runtime.services = ()
        snapshots.backup(self.runtime, self.base / "stopped.age", self.recipient, self.age)
        self.assertEqual(len(self.runtime.calls), 1)

    def test_existing_outputs_and_restore_directories_are_never_overwritten(self):
        archive = self.base / "existing.age"
        archive.write_bytes(b"existing backup")
        with self.assertRaises(snapshots.BackupError):
            snapshots.backup(self.runtime, archive, self.recipient, self.age)
        self.assertEqual(archive.read_bytes(), b"existing backup")
        self.assertEqual(self.runtime.calls, [])
        target = self.base / "existing-runtime"
        target.mkdir()
        sentinel = target / "sentinel"
        sentinel.write_bytes(b"existing state")
        with self.assertRaises(snapshots.BackupError):
            snapshots.restore(archive, target, self.identity, self.age)
        self.assertEqual(sentinel.read_bytes(), b"existing state")

    def test_invalid_recipient_and_symlinked_state_fail_before_stopping_services(self):
        with self.assertRaises(snapshots.BackupError):
            snapshots.backup(self.runtime, self.base / "invalid.age", "not-a-recipient", self.age)
        self.assertEqual(self.runtime.calls, [])
        (self.source / "state/headscale/external").symlink_to(self.identity)
        with self.assertRaises(snapshots.BackupError):
            snapshots.backup(self.runtime, self.base / "symlink.age", self.recipient, self.age)
        self.assertEqual(self.runtime.calls, [])

    def test_aliased_output_inside_runtime_is_rejected_before_stopping_services(self):
        alias = self.base / "state-alias"
        alias.symlink_to(self.source / "state/headscale", target_is_directory=True)
        (self.base / "other").mkdir()
        outputs = (alias / "snapshot.age",
                   self.base / "other/../runtime/state/headscale/snapshot.age")
        for output in outputs:
            with self.subTest(output=str(output)), self.assertRaises(snapshots.BackupError):
                snapshots.backup(self.runtime, output, self.recipient, self.age)
            self.assertFalse(output.exists())
            self.assertEqual(self.runtime.calls, [])

    def test_malicious_encrypted_archive_is_removed_without_writing_outside_target(self):
        for index, payload in enumerate((member_archive("../escaped"),
                                         member_archive("state/headscale/link", kind=tarfile.SYMTYPE, linkname="../../../escaped"),
                                         member_archive("state/headscale/large", size=snapshots.MAX_MEMBER_BYTES + 1))):
            with self.subTest(index=index):
                archive = self.encrypt(payload, f"malicious-{index}.age")
                target = self.base / f"rejected-{index}"
                with self.assertRaises(snapshots.BackupError):
                    snapshots.restore(archive, target, self.identity, self.age)
                self.assertFalse(target.exists())
                self.assertFalse((self.base / "escaped").exists())

    def test_encryption_authentication_failure_cleans_partial_restoration(self):
        archive = snapshots.backup(self.runtime, self.base / "corrupted.age", self.recipient, self.age)
        data = bytearray(archive.read_bytes())
        data[-1] ^= 1
        archive.write_bytes(data)
        target = self.base / "not-restored"
        with self.assertRaises(snapshots.BackupError):
            snapshots.restore(archive, target, self.identity, self.age)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
