"""Regression cases for the two Headscale serialization boundaries in the runner."""

from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import manage


class ManagementRunnerTests(unittest.TestCase):
    def test_cli_and_rest_expiration_formats_agree(self):
        expected = datetime(2026, 10, 10, 0, 0, 0, 500000, tzinfo=timezone.utc)
        self.assertEqual(manage.timestamp({"seconds": "1791590400", "nanos": 500000000}), expected)
        self.assertEqual(manage.timestamp("2026-10-10T00:00:00.5Z"), expected)

    def test_unzoned_expiration_cannot_be_treated_as_valid(self):
        with self.assertRaises(manage.lab.LabError):
            manage.timestamp("2026-10-10T00:00:00")

    def test_raw_and_display_key_prefixes_match_for_scoped_rotation(self):
        prefix = "Ab_-01234567"
        self.assertEqual(manage.api_key_prefix("hskey-api-" + prefix + "-secret"), prefix)
        self.assertEqual(manage.api_key_prefix("hskey-api-" + prefix + "-***"), prefix)
        self.assertEqual(manage.api_key_prefix("legacy1.secret"), "legacy1")
        self.assertEqual(manage.api_key_prefix("legacy1***"), "legacy1")


if __name__ == "__main__":
    unittest.main()
