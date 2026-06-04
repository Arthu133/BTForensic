import tempfile
import unittest
from pathlib import Path

from btforensic.defender_hunting import build_defender_kql, load_defender_input, sanitize_mde_record
from btforensic.domain_utils import normalize_target


class DefenderHuntingTest(unittest.TestCase):
    def test_kql_pack_contains_mde_tables_and_target(self):
        target = normalize_target("https://linkedin.com/login")
        kql = build_defender_kql(
            target=target,
            history_summaries=[{"first_seen_utc": "2024-01-01T10:00:00Z", "last_seen_utc": "2024-01-01T11:00:00Z"}],
            window_minutes=30,
            device_name="HOST01",
            account_name="user@example.com",
        )

        self.assertIn('let TargetDomain = "linkedin.com";', kql)
        self.assertIn("DeviceNetworkEvents", kql)
        self.assertIn("DeviceProcessEvents", kql)
        self.assertIn("DeviceFileEvents", kql)
        self.assertIn("AlertEvidence", kql)
        self.assertIn('let DeviceFilter = "HOST01";', kql)

    def test_csv_input_is_summarized_and_safely_masked(self):
        target = normalize_target("linkedin.com")
        csv_text = (
            "Timestamp,DeviceName,InitiatingProcessAccountName,InitiatingProcessFileName,"
            "InitiatingProcessCommandLine,RemoteUrl,RemoteIP,ActionType\n"
            "2024-01-01T10:00:00Z,HOST01,alice,msedge.exe,"
            "\"msedge.exe https://linkedin.com/login?token=abc\","
            "https://linkedin.com/login?token=abc,10.0.0.8,ConnectionSuccess\n"
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mde.csv"
            path.write_text(csv_text, encoding="utf-8")
            summary = load_defender_input(path, target)

        self.assertEqual(summary["total_rows"], 1)
        self.assertEqual(summary["target_matching_rows"], 1)
        self.assertTrue(summary["top_devices"][0]["value"].startswith("[DEVICE_REDACTED:"))
        self.assertNotIn("HOST01", str(summary))
        self.assertIn("token=%5BREDACTED%5D", summary["top_remote_urls"][0]["value"])
        self.assertIn("token=%5BREDACTED%5D", summary["sample_matching_records"][0]["InitiatingProcessCommandLine"])

    def test_sensitive_fields_are_redacted(self):
        sanitized = sanitize_mde_record(
            {
                "Authorization": "Bearer secret",
                "RemoteUrl": "https://example.com/a?code=123",
                "InitiatingProcessCommandLine": "browser.exe --session abc https://example.com/?password=x",
            }
        )

        self.assertEqual(sanitized["Authorization"], "[REDACTED]")
        self.assertIn("code=%5BREDACTED%5D", sanitized["RemoteUrl"])
        self.assertIn("--session [REDACTED]", sanitized["InitiatingProcessCommandLine"])
        self.assertIn("password=%5BREDACTED%5D", sanitized["InitiatingProcessCommandLine"])


if __name__ == "__main__":
    unittest.main()
