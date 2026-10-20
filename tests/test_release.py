import io
import json
import subprocess
import sys
import tarfile
import gzip
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import release

SUMS = {release.cli_archive_name("0.1.0", t): f"{i:064x}" for i, t in enumerate(release.TARGETS)}


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


class VersionTests(unittest.TestCase):
    def test_release_versions(self):
        for good in ("0.1.0", "1.12.3", "0.2.0-beta.1"):
            self.assertEqual(release.check_version(good), good)
        for bad in ("v0.1.0", "01.0.0", "0.1", "0.1.0+build", "", None):
            with self.assertRaises(release.ReleaseError):
                release.check_version(bad)


class CommittedTests(unittest.TestCase):
    def setUp(self):
        self.repo = Path(tempfile.mkdtemp())
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "--allow-empty", "-m", "one")

    def test_clean_tree_gives_the_commit(self):
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.repo, capture_output=True, text=True).stdout.strip()
        self.assertEqual(release.committed("0.1.0", cwd=self.repo), head)

    def test_uncommitted_files_are_refused(self):
        (self.repo / "stray.txt").write_text("x")
        with self.assertRaisesRegex(release.ReleaseError, "stray.txt"):
            release.committed("0.1.0", cwd=self.repo)

    def test_a_version_tagged_on_another_commit_is_refused(self):
        git(self.repo, "tag", "v0.1.0")
        git(self.repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "--allow-empty", "-m", "two")
        with self.assertRaisesRegex(release.ReleaseError, "already the tag"):
            release.committed("0.1.0", cwd=self.repo)
        release.committed("0.1.1", cwd=self.repo)


class LicenseTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        # Homebrew's layout: GOROOT is libexec, LICENSE sits beside it.
        self.goroot = self.dir / "go/libexec"
        self.goroot.mkdir(parents=True)
        (self.dir / "go/LICENSE").write_text("Go license text")
        (self.goroot / "PATENTS").write_text("Go patents text")

    def module(self, name, files):
        path = self.dir / name
        path.mkdir()
        for file, text in files.items():
            (path / file).write_text(text)
        return str(path)

    def test_every_module_license_is_included(self):
        modules = {("example.com/a", "v1.0.0"): self.module("a", {"LICENSE": "A license", "license.go": "package a"}),
                   ("example.com/b", "v2.1.0"): self.module("b", {"LICENSE.txt": "B license", "NOTICE.txt": "B notice"})}
        text = release.third_party_licenses(modules, str(self.goroot), "go1.26.1")
        for part in ("Go go1.26.1", "Go license text", "Go patents text", "example.com/a v1.0.0", "A license",
                     "example.com/b v2.1.0", "B license", "B notice"):
            self.assertIn(part, text)
        self.assertNotIn("package a", text)

    def test_a_module_without_a_license_stops_the_release(self):
        modules = {("example.com/a", "v1.0.0"): self.module("a", {"LICENSE": "A"}),
                   ("example.com/none", "v0.1.0"): self.module("none", {"README.md": "hi"})}
        with self.assertRaisesRegex(release.ReleaseError, "example.com/none v0.1.0"):
            release.third_party_licenses(modules, str(self.goroot), "go1.26.1")


class RemoveTreeTests(unittest.TestCase):
    def test_read_only_go_module_folders_are_removed(self):
        work = Path(tempfile.mkdtemp())
        module = work / "source/.cache/mod/example.com/m@v1.0.0"
        (module / "sub").mkdir(parents=True)
        (module / "sub/file.go").write_text("package m")
        for folder in (module / "sub", module):
            folder.chmod(0o555)
        release.remove_tree(work / "source")
        self.assertFalse((work / "source").exists())


class ArchiveTests(unittest.TestCase):
    def test_archives_are_reproducible_and_keep_the_program_executable(self):
        files = [("covee", b"\x7fELF", 0o755), ("LICENSE", b"Apache", 0o644)]
        first = release.tar_gz("covee_0.1.0_linux_amd64", files)
        self.assertEqual(first, release.tar_gz("covee_0.1.0_linux_amd64", files))
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(first))) as archive:
            members = {m.name: m for m in archive.getmembers()}
        self.assertEqual(sorted(members), ["covee_0.1.0_linux_amd64/LICENSE", "covee_0.1.0_linux_amd64/covee"])
        self.assertEqual(members["covee_0.1.0_linux_amd64/covee"].mode, 0o755)
        self.assertEqual(members["covee_0.1.0_linux_amd64/covee"].mtime, 0)


class SigningTests(unittest.TestCase):
    def test_only_the_teams_developer_id_is_used(self):
        listing = ('  1) ' + "A" * 40 + ' "Apple Development: Example Developer (AAAAAAAAAA)"\n'
                   '  2) ' + "B" * 40 + ' "Developer ID Application: Someone Else (ZZZZZZZZZZ)"\n')
        self.assertIsNone(release.developer_id(listing))
        listing += '  3) ' + "C" * 40 + f' "Developer ID Application: Example Developer ({release.TEAM})"\n'
        self.assertEqual(release.developer_id(listing), ("C" * 40, f"Developer ID Application: Example Developer ({release.TEAM})"))

    def test_notary_status_is_read_from_its_json(self):
        self.assertEqual(release.notary_status('Conducting pre-submission checks\n{"id": "x", "status": "Accepted"}\n'), "Accepted")
        self.assertEqual(release.notary_status('{"status": "Invalid"}'), "Invalid")
        self.assertIsNone(release.notary_status("Error: no network"))
        self.assertIsNone(release.notary_status("{not json"))


class PublishedTextTests(unittest.TestCase):
    def test_homebrew_formula_downloads_each_platforms_archive(self):
        formula = release.homebrew_formula("0.1.0", "covee-io/covee", SUMS)
        for name, digest in SUMS.items():
            self.assertIn(f'url "https://github.com/covee-io/covee/releases/download/v0.1.0/{name}"\n      sha256 "{digest}"', formula)
        self.assertIn('license "Apache-2.0"', formula)
        self.assertIn('homepage "https://covee.io"', formula)
        self.assertIn('bin.install "covee"', formula)

    def test_homebrew_cask_installs_the_disk_image(self):
        cask = release.homebrew_cask("0.1.0", "covee-io/covee", {"Covee.dmg": "d" * 64})
        self.assertIn('version "0.1.0"', cask)
        self.assertIn('sha256 "' + "d" * 64 + '"', cask)
        self.assertIn('url "https://github.com/covee-io/covee/releases/download/v#{version}/Covee.dmg"', cask)
        self.assertIn('app "Covee.app"', cask)
        self.assertIn('depends_on macos: ">= :sequoia"', cask)

    def test_notes_warn_about_unsigned_mac_builds_only_when_unsigned(self):
        unsigned = release.release_notes("0.1.0", "c" * 40, "p" * 64, False, release.TARGETS)
        signed = release.release_notes("0.1.0", "c" * 40, "p" * 64, True, release.TARGETS)
        self.assertIn("not signed yet", unsigned)
        self.assertNotIn("not signed yet", signed)
        for name in SUMS:
            self.assertIn(name, signed)
        self.assertIn("Covee.dmg", signed)


class ReadyToPublishTests(unittest.TestCase):
    def setUp(self):
        self.out = Path(tempfile.mkdtemp())
        (self.out / "covee.tar.gz").write_bytes(b"archive")
        self.manifest = {"status": "built", "skipped": [], "commit": "c" * 40,
                         "files": {"covee.tar.gz": {"sha256": release.sha256(b"archive"), "bytes": 7}}}

    def save(self):
        (self.out / "manifest.json").write_text(json.dumps(self.manifest))

    def test_a_complete_unchanged_build_is_ready(self):
        self.save()
        self.assertEqual(release.ready_to_publish(self.out)["commit"], "c" * 40)

    def test_incomplete_failed_or_changed_builds_are_refused(self):
        cases = [({"skipped": ["tests"]}, None, "skipped tests"),
                 ({"status": "failed"}, None, "did not finish"),
                 ({}, b"tampered", "changed after the build")]
        for change, content, message in cases:
            with self.subTest(message):
                self.setUp()
                self.manifest.update(change)
                self.save()
                if content:
                    (self.out / "covee.tar.gz").write_bytes(content)
                with self.assertRaisesRegex(release.ReleaseError, message):
                    release.ready_to_publish(self.out)


if __name__ == "__main__":
    unittest.main()
