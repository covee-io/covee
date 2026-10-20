"""Encrypted, stopped-service snapshots for one explicitly selected runtime."""

import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import threading

from deploy import CONFIG_FILES, SECRET_FILES, ROOT, DeploymentError, identity_files, load_json, runtime_env, runtime_images

MAX_MEMBER_BYTES = 1 << 30
MAX_TOTAL_BYTES = 4 << 30
MAX_MEMBERS = 100_000
MAX_PATH_BYTES = 255
BLOCK_BYTES = 512
CHUNK_BYTES = 64 << 10
AGE_TIMEOUT_SECONDS = 300
_TERMINATE_LOCK = threading.Lock()
REQUIRED_FILES = (*CONFIG_FILES, "deployment.json", "runtime.env", *("secrets/" + name for name in SECRET_FILES))
REQUIRED_DIRS = ("secrets", "state", "state/headscale", "state/management")
OPTIONAL_IDENTITY_FILES = {"identity.json", "identity-internal.crt", "identity-internal.key", "identity-trust.pem", "secrets/identity-signing-key",
                           "identity-secrets/entra-client-secret", "identity-secrets/google-client-secret", "identity-secrets/apple-private-key"}


def _contract(directory):
    metadata = load_json(directory / "deployment.json")
    files, dirs = identity_files(metadata)
    return (*REQUIRED_FILES, *files), (*REQUIRED_DIRS, *dirs)


class BackupError(DeploymentError):
    """An operational error whose message contains no credential material."""


def _age(binary):
    executable = shutil.which(str(binary))
    if not executable and str(binary) == "age":
        fallback = ROOT / ".cache/covee/deploy/tools/age"
        if fallback.is_file() and os.access(fallback, os.X_OK):
            executable = str(fallback)
    if not executable:
        raise BackupError("age is required; install it or supply a local age_binary")
    return executable


def _terminate(process):
    if process is not None:
        # age plugins can retain inherited pipe descriptors after age exits.
        # Each invocation owns its process group, so terminate that whole
        # group even when the leader has already returned.
        with _TERMINATE_LOCK:
            # Darwin can report EPERM when a group consists only of its
            # unreaped zombie leader. Reap before signalling, and retry that
            # exact exit race without suppressing a live permission failure.
            process.poll()
            if not getattr(process, "_covee_group_terminated", False):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError as error:
                    # A process in Darwin's exit transition can briefly be
                    # unsignalable before poll() can reap it. Only accept
                    # that explanation after a bounded successful reap.
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        raise error
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process._covee_group_terminated = True
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass


class _AgeDeadline:
    """Bound pipe streaming as well as waiting for the age process."""

    def __init__(self, seconds):
        self.process = None
        self.expired = threading.Event()
        self.lock = threading.Lock()
        self.timer = threading.Timer(seconds, self._expire)
        self.timer.daemon = True
        self.timer.start()

    def attach(self, process):
        with self.lock:
            self.process = process
            expired = self.expired.is_set()
        if expired:
            _terminate(process)

    def _expire(self):
        with self.lock:
            self.expired.set()
            process = self.process
        _terminate(process)

    def cancel(self):
        self.timer.cancel()
        self.timer.join(timeout=6)


def _preflight_recipient(binary, recipient):
    process = None
    deadline = _AgeDeadline(10)
    try:
        process = subprocess.Popen([binary, "--encrypt", "--recipient", recipient], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        deadline.attach(process)
        if process.wait(timeout=15) or deadline.expired.is_set():
            raise BackupError("age rejected the encryption recipient or exceeded its deadline")
    finally:
        deadline.cancel()
        _terminate(process)


def _close_pipes(process):
    if process is not None:
        for pipe in (process.stdin, process.stdout, process.stderr):
            if pipe is not None:
                try:
                    pipe.close()
                except OSError:
                    pass


def _safe_name(name):
    if not isinstance(name, str) or not name or len(name.encode("utf-8")) > MAX_PATH_BYTES:
        raise BackupError("Archive member has an invalid name")
    if not name.isascii() or any(ord(ch) <= 0x20 or ord(ch) >= 0x7f for ch in name) or "\\" in name:
        raise BackupError("Archive member has an ambiguous name")
    p = PurePosixPath(name)
    if p.is_absolute() or str(p) != name or any(part in (".", "..") for part in p.parts):
        raise BackupError("Archive member escapes the new runtime directory")
    allowed = name in REQUIRED_FILES or name in REQUIRED_DIRS or name in OPTIONAL_IDENTITY_FILES or name == "identity-secrets"
    allowed = allowed or name.startswith("state/headscale/") or name.startswith("state/management/")
    # Local Covee accounts; absent from runtimes prepared before they existed.
    allowed = allowed or name == "state/identity" or name.startswith("state/identity/")
    # The in-network console device's identity, so a restored network keeps its console device.
    allowed = allowed or name == "state/console-node" or name.startswith("state/console-node/")
    # The gateway device's identity (its settings are in state/management).
    allowed = allowed or name == "state/gateway" or name.startswith("state/gateway/")
    if not allowed:
        raise BackupError("Archive member is outside the runtime file contract")
    return p


def _snapshot_paths(directory):
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or os.getuid() == 0:
        raise BackupError("Backup requires a private runtime owned by its non-root operator")
    required_files, required_dirs = _contract(directory)
    names = list(required_files) + list(required_dirs)
    for optional in ("state/identity", "state/console-node", "state/gateway"):
        if (directory / optional).is_dir():
            names.append(optional)
    for root in (directory / "state/headscale", directory / "state/management", directory / "state/identity", directory / "state/console-node",
                 directory / "state/gateway"):
        for current, dirs, files in os.walk(root, followlinks=False):
            # A leftover one-time join key is never backed up.
            names.extend(str((Path(current) / name).relative_to(directory)) for name in dirs + files if name != "join-key")
    total = 0
    paths = []
    for name in sorted(set(names)):
        _safe_name(name)
        source = directory / name
        entry = source.lstat()
        if entry.st_uid != os.getuid() or not (stat.S_ISREG(entry.st_mode) or stat.S_ISDIR(entry.st_mode)):
            raise BackupError("Runtime snapshot permits only operator-owned regular files and directories")
        if stat.S_ISDIR(entry.st_mode) and entry.st_mode & 0o077:
            raise BackupError("Runtime snapshot directories must exclude group and other users")
        if name in required_files and (not stat.S_ISREG(entry.st_mode) or entry.st_mode & 0o077):
            raise BackupError("Runtime configuration and secrets must be private regular files")
        if stat.S_ISREG(entry.st_mode):
            if entry.st_nlink != 1 or entry.st_size > MAX_MEMBER_BYTES:
                raise BackupError("Runtime contains a hard-linked or oversized file")
            total += entry.st_size
        if total > MAX_TOTAL_BYTES or len(paths) >= MAX_MEMBERS:
            raise BackupError("Runtime exceeds snapshot size or member limits")
        paths.append((name, source, entry))
    return paths


def backup(runtime, output, recipient, age_binary="age"):
    """Stop only this runtime's running services and stream an encrypted tar.

    The original running subset is restarted even when snapshotting fails.
    No plaintext tar is written, and existing outputs are never overwritten.
    """
    directory, output = Path(runtime.directory).absolute(), Path(output).absolute()
    binary = _age(age_binary)
    if not isinstance(recipient, str) or not recipient or len(recipient) > 8192 or any(ch in recipient for ch in "\r\n\0"):
        raise BackupError("A valid age recipient is required")
    try:
        canonical_directory = directory.resolve(strict=True)
        # The new leaf must remain absent, but its existing parent must be
        # canonical before comparing it with the selected runtime. Lexical
        # comparisons miss both parent symlinks and paths containing '..'.
        output = output.parent.resolve(strict=True) / output.name
    except (OSError, RuntimeError) as error:
        raise BackupError("Backup requires existing runtime and output parent directories") from error
    try:
        output.relative_to(canonical_directory)
    except ValueError:
        pass
    else:
        raise BackupError("Backup output must be outside the selected runtime")
    if not output.parent.is_dir() or output.exists() or output.is_symlink():
        raise BackupError("Backup requires a new output file in an existing directory")
    try:
        _preflight_recipient(binary, recipient)
        _snapshot_paths(directory)
        result = runtime.compose("ps", "--status", "running", "--services")
        running = sorted(set(result.stdout.decode("ascii").splitlines()))
        if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", service) for service in running):
            raise BackupError("Could not establish the selected runtime's running services")
    except BackupError:
        raise
    except Exception as error:
        raise BackupError("Backup preflight failed; no services were stopped") from error

    process = None
    deadline = None
    stopped = False
    created = False
    try:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
        with os.fdopen(fd, "wb") as encrypted:
            if running:
                stopped = True
                runtime.compose("stop", "--timeout", "20", *running, timeout=120)
            deadline = _AgeDeadline(AGE_TIMEOUT_SECONDS)
            process = subprocess.Popen([binary, "--encrypt", "--recipient", recipient], stdin=subprocess.PIPE,
                                       stdout=encrypted, stderr=subprocess.DEVNULL, start_new_session=True)
            deadline.attach(process)
            with tarfile.open(fileobj=process.stdin, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                for name, source, entry in _snapshot_paths(directory):
                    member = tarfile.TarInfo(name)
                    member.mtime = int(entry.st_mtime)
                    member.uid = member.gid = 0
                    member.uname = member.gname = ""
                    if stat.S_ISDIR(entry.st_mode):
                        member.type = tarfile.DIRTYPE
                        member.mode = 0o700
                        archive.addfile(member)
                    else:
                        member.size = entry.st_size
                        member.mode = 0o600 if name.startswith("state/") else 0o400
                        source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                        with os.fdopen(source_fd, "rb") as content:
                            opened = os.fstat(content.fileno())
                            if not stat.S_ISREG(opened.st_mode) or opened.st_ino != entry.st_ino or opened.st_size != entry.st_size:
                                raise BackupError("Runtime file changed while snapshotting")
                            archive.addfile(member, content)
            process.stdin.close()
            if process.wait(timeout=AGE_TIMEOUT_SECONDS) or deadline.expired.is_set():
                raise BackupError("age could not finish encrypting the snapshot")
            encrypted.flush()
            os.fsync(encrypted.fileno())
        output.chmod(0o600)
        return output
    except BaseException as error:
        _terminate(process)
        if created:
            output.unlink(missing_ok=True)
        if isinstance(error, (BackupError, KeyboardInterrupt, SystemExit)):
            raise
        raise BackupError("Encrypted snapshot failed; partial output was removed") from error
    finally:
        if deadline is not None:
            deadline.cancel()
        _terminate(process)
        _close_pipes(process)
        if stopped:
            try:
                if "headscale" in running and load_json(directory / "deployment.json")["spec"].get("identity"):
                    # With the identity broker, Headscale discovers its issuer through the
                    # gateway when it starts. A plain `compose start` races that and leaves
                    # Headscale failing, so use the ordered start: broker and gateway first,
                    # then the coordinator behind its persisted-policy gate.
                    runtime.start()
                else:
                    runtime.compose("start", *running, timeout=120)
            except Exception as error:
                raise BackupError("Snapshot operation ended but the original services could not be restarted; inspect the selected runtime") from error


def _read_exact(stream, size):
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, CHUNK_BYTES))
        if not chunk:
            raise BackupError("Encrypted archive is truncated or could not be decrypted")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _extract(stream, destination):
    """Parse fixed-size USTAR headers without processing extension records."""
    seen, total = set(), 0
    while True:
        block = _read_exact(stream, BLOCK_BYTES)
        if block == b"\0" * BLOCK_BYTES:
            if _read_exact(stream, BLOCK_BYTES) != b"\0" * BLOCK_BYTES:
                raise BackupError("Archive end marker is invalid")
            tail = stream.read(tarfile.RECORDSIZE + 1)
            if len(tail) > tarfile.RECORDSIZE or any(tail):
                raise BackupError("Archive has unexpected trailing content")
            break
        if block[257:263] != tarfile.POSIX_MAGIC[:6] or block[263:265] != b"00":
            raise BackupError("Only plain USTAR archives are accepted")
        try:
            member = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
        except (tarfile.TarError, UnicodeError, ValueError) as error:
            raise BackupError("Archive header is invalid") from error
        if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
            raise BackupError("Archive links, special files and extension records are forbidden")
        name = member.name.removesuffix("/") if member.isdir() else member.name
        _safe_name(name)
        if name in seen or len(seen) >= MAX_MEMBERS:
            raise BackupError("Archive repeats a member or exceeds its member limit")
        seen.add(name)
        if member.size < 0 or member.size > MAX_MEMBER_BYTES or member.isdir() and member.size:
            raise BackupError("Archive member exceeds its size limit")
        total += member.size
        if total > MAX_TOTAL_BYTES:
            raise BackupError("Archive exceeds its total size limit")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if member.isdir():
            target.mkdir(exist_ok=True, mode=0o700)
            target.chmod(0o700)
            continue
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as output:
            remaining = member.size
            while remaining:
                chunk = _read_exact(stream, min(remaining, CHUNK_BYTES))
                output.write(chunk)
                remaining -= len(chunk)
            output.flush()
            os.fsync(output.fileno())
        padding = (-member.size) % BLOCK_BYTES
        if padding and any(_read_exact(stream, padding)):
            raise BackupError("Archive member padding is invalid")
        target.chmod(0o600 if name.startswith("state/") else 0o400)
    if "deployment.json" not in seen:
        raise BackupError("Archive is missing required runtime metadata")
    required_files, required_dirs = _contract(destination)
    if not set(required_files).issubset(seen):
        raise BackupError("Archive is missing required runtime configuration or secrets")
    if any(not (destination / name).is_dir() for name in required_dirs):
        raise BackupError("Archive is missing required runtime state directories")
    if (seen & OPTIONAL_IDENTITY_FILES) != (set(required_files) & OPTIONAL_IDENTITY_FILES) or ("identity-secrets" in seen) != ("identity-secrets" in required_dirs):
        raise BackupError("Archive identity files differ from its selected profile")


def _replace_private(path, content):
    temporary = path.with_name(path.name + ".restore-temporary")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(content.encode())
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _rebase(destination):
    metadata_file = destination / "deployment.json"
    if metadata_file.stat().st_size > 1 << 20 or (destination / "runtime.env").stat().st_size > 1 << 20:
        raise BackupError("Archive runtime metadata is oversized")
    metadata = json.loads(metadata_file.read_bytes())
    if metadata.get("format") != 1 or type(metadata.get("lab")) is not bool or not isinstance(metadata.get("spec"), dict):
        raise BackupError("Archive runtime metadata is invalid")
    images = {}
    expected_images = runtime_images(metadata)
    for line in (destination / "runtime.env").read_text().splitlines():
        match = re.fullmatch(r"COVEE_(HEADSCALE|MANAGEMENT|INGRESS|IDENTITY)_IMAGE='([^']+)'", line)
        if match:
            service, image = match.group(1).lower(), match.group(2)
            if service not in expected_images or service in images or image != expected_images[service] and not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
                raise BackupError("Archive image reference is not an approved local image or immutable image ID")
            images[service] = image
    if set(images) != set(expected_images):
        raise BackupError("Archive is missing runtime image references")
    metadata["uid"], metadata["gid"] = os.getuid(), os.getgid()
    rebased = runtime_env(destination, metadata, images)
    _replace_private(metadata_file, json.dumps(metadata, indent=2) + "\n")
    _replace_private(destination / "runtime.env", rebased)


def restore(archive, destination, identity, age_binary="age"):
    """Decrypt into a new private directory; never overwrite existing state."""
    archive, destination, identity = Path(archive).absolute(), Path(destination).absolute(), Path(identity).absolute()
    binary = _age(age_binary)
    if os.getuid() == 0 or destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise BackupError("Restore requires a new directory operated by a non-root account")
    if archive.is_symlink() or not archive.is_file() or identity.is_symlink() or not identity.is_file():
        raise BackupError("Restore requires regular archive and identity files")
    if identity.stat().st_mode & 0o077 or identity.stat().st_uid != os.getuid():
        raise BackupError("The age identity must be private and owned by the restoring operator")
    process = None
    deadline = None
    created = False
    try:
        destination.mkdir(mode=0o700)
        created = True
        deadline = _AgeDeadline(AGE_TIMEOUT_SECONDS)
        process = subprocess.Popen([binary, "--decrypt", "--identity", str(identity), str(archive)],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
        deadline.attach(process)
        _extract(process.stdout, destination)
        process.stdout.close()
        if process.wait(timeout=AGE_TIMEOUT_SECONDS) or deadline.expired.is_set():
            raise BackupError("age could not authenticate the complete encrypted archive")
        _rebase(destination)
        return destination
    except BaseException as error:
        _terminate(process)
        if created:
            shutil.rmtree(destination)
        if isinstance(error, (BackupError, KeyboardInterrupt, SystemExit)):
            raise
        raise BackupError("Restore failed; the new directory was removed") from error
    finally:
        if deadline is not None:
            deadline.cancel()
        _terminate(process)
        _close_pipes(process)
