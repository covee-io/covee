import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import apple_release as release

TEAM = "87LFD98HJU"


def good_entitlements(install):
    ents = {release.NETWORK: ["packet-tunnel-provider-systemextension"], release.APP_GROUPS: [TEAM + ".io.covee"],
            "com.apple.developer.team-identifier": TEAM, "com.apple.application-identifier": TEAM + ".io.covee.macos"}
    if install:
        ents[release.SYSTEM_INSTALL] = True
    return ents


def good_info(build="202610130200"):
    app = {"CFBundleIdentifier": "io.covee.macos", "CFBundleVersion": build}
    extension = {"CFBundleIdentifier": "io.covee.macos.tunnel", "CFBundleVersion": build,
                 "NetworkExtension": {"NEMachServiceName": TEAM + ".io.covee.macos.tunnel"}}
    return app, extension


class ReleaseTests(unittest.TestCase):
    def test_archive_signs_for_development_with_the_development_entitlements(self):
        command = release.archive_command(Path("/p/Covee.xcodeproj"), Path("/o/Covee.xcarchive"), Path("/o/derived"), TEAM, "202610130200")
        for part in ("archive", "-allowProvisioningUpdates", "CODE_SIGN_STYLE=Automatic", f"DEVELOPMENT_TEAM={TEAM}",
                     "COVEE_ENTITLEMENTS_VARIANT=-development", "CURRENT_PROJECT_VERSION=202610130200", "Covee-macOS"):
            self.assertIn(part, command)

    def test_export_uploads_for_developer_id_notarization(self):
        self.assertEqual(release.export_options(TEAM), {"method": "developer-id", "destination": "upload", "signingStyle": "automatic", "teamID": TEAM})

    def test_build_numbers_increase_with_time(self):
        early = release.build_number(datetime(2026, 10, 13, 2, 0, tzinfo=timezone.utc))
        late = release.build_number(datetime(2026, 10, 13, 2, 1, tzinfo=timezone.utc))
        self.assertTrue(early.isdigit() and int(late) > int(early))

    def test_the_final_entitlements_are_accepted(self):
        release.check_entitlements(good_entitlements(True), good_entitlements(False), TEAM)

    def test_wrong_entitlements_are_refused(self):
        changes = [
            ("app", {release.NETWORK: ["packet-tunnel-provider"]}),  # still the development value
            ("extension", {release.APP_GROUPS: None}),  # a missing app group breaks the tunnel
            ("extension", {release.APP_GROUPS: [TEAM + ".io.other"]}),
            ("app", {release.SYSTEM_INSTALL: False}),
            ("extension", {release.SYSTEM_INSTALL: True}),
            ("app", {"get-task-allow": True}),
            ("extension", {"com.apple.developer.team-identifier": "OTHERTEAM1"}),
        ]
        for which, change in changes:
            app, extension = good_entitlements(True), good_entitlements(False)
            target = app if which == "app" else extension
            for key, value in change.items():
                if value is None:
                    target.pop(key)
                else:
                    target[key] = value
            with self.subTest(which=which, change=change), self.assertRaises(release.ReleaseError):
                release.check_entitlements(app, extension, TEAM)

    def test_info_plists_must_match_the_build_and_the_app_group(self):
        release.check_info(*good_info(), TEAM, "202610130200")
        app, extension = good_info()
        with self.assertRaisesRegex(release.ReleaseError, "CFBundleVersion"):
            release.check_info({**app, "CFBundleVersion": "YES"}, extension, TEAM, "202610130200")
        bad = {**extension, "NetworkExtension": {"NEMachServiceName": "io.covee.macos.tunnel"}}
        with self.assertRaisesRegex(release.ReleaseError, "NEMachServiceName"):
            release.check_info(app, bad, TEAM, "202610130200")


class IOSReleaseTests(unittest.TestCase):
    def good(self, bundle):
        return {release.NETWORK: ["packet-tunnel-provider"], "application-identifier": f"{TEAM}.{bundle}",
                "com.apple.developer.team-identifier": TEAM, "get-task-allow": True, "keychain-access-groups": [f"{TEAM}.*"]}

    def test_build_targets_the_named_phone_with_development_signing(self):
        command = release.ios_build_command(Path("/p/Covee.xcodeproj"), Path("/o/derived"), TEAM, "202610130300", "00008000-0000000000000001")
        for part in ("build", "Covee-iOS", "id=00008000-0000000000000001", "-allowProvisioningUpdates",
                     "CODE_SIGN_STYLE=Automatic", "CURRENT_PROJECT_VERSION=202610130300", "-skipPackagePluginValidation"):
            self.assertIn(part, command)
        self.assertNotIn("COVEE_ENTITLEMENTS_VARIANT=-development", command)
        # A forced SDK would also build SwiftTerm's build tool for the phone instead of this Mac.
        self.assertNotIn("-sdk", command)

    def test_development_entitlements_are_accepted_and_extras_refused(self):
        release.check_ios_entitlements(self.good("io.covee.ios"), self.good("io.covee.ios.tunnel"), TEAM)
        for change in ({release.NETWORK: ["packet-tunnel-provider-systemextension"]}, {release.APP_GROUPS: [TEAM + ".io.covee"]},
                       {"application-identifier": TEAM + ".io.example.ios"}, {"keychain-access-groups": ["OTHER.*"]}):
            with self.subTest(change=change), self.assertRaises(release.ReleaseError):
                release.check_ios_entitlements({**self.good("io.covee.ios"), **change}, self.good("io.covee.ios.tunnel"), TEAM)


class TestFlightTests(unittest.TestCase):
    def good(self, bundle):
        return {release.NETWORK: ["packet-tunnel-provider"], "application-identifier": f"{TEAM}.{bundle}",
                "com.apple.developer.team-identifier": TEAM, "beta-reports-active": True, "get-task-allow": False}

    def test_archive_is_generic_ios_with_the_timestamp_build(self):
        command = release.ios_archive_command(Path("/p/Covee.xcodeproj"), Path("/o/a.xcarchive"), Path("/o/d"), TEAM, "202610171500")
        for part in ("archive", "Covee-iOS", "generic/platform=iOS", "-allowProvisioningUpdates", f"DEVELOPMENT_TEAM={TEAM}",
                     "CURRENT_PROJECT_VERSION=202610171500"):
            self.assertIn(part, command)
        self.assertFalse(any(p.startswith("id=") for p in command))

    def test_export_options_target_app_store_connect(self):
        for destination in ("export", "upload"):
            options = release.app_store_options(TEAM, destination)
            self.assertEqual((options["method"], options["destination"], options["teamID"]), ("app-store-connect", destination, TEAM))
            self.assertFalse(options["manageAppVersionAndBuildNumber"])

    def test_app_store_entitlements_are_accepted_and_debug_or_missing_testflight_refused(self):
        release.check_app_store_entitlements(self.good("io.covee.ios"), self.good("io.covee.ios.tunnel"), TEAM)
        for change in ({"get-task-allow": True}, {"beta-reports-active": None}, {release.NETWORK: ["packet-tunnel-provider-systemextension"]},
                       {"application-identifier": f"{TEAM}.io.covee.macos"}):
            with self.subTest(change), self.assertRaises(release.ReleaseError):
                release.check_app_store_entitlements(self.good("io.covee.ios"), {**self.good("io.covee.ios.tunnel"), **change}, TEAM)


if __name__ == "__main__":
    unittest.main()
