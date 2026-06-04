import unittest

from btforensic.summary_builder import build_case_summary, probable_callers


class SummaryBuilderTest(unittest.TestCase):
    def test_probable_callers_prioritize_anonymization_origin(self):
        context = {
            "network_log_matches": [
                {
                    "file": "Default/Network/a.tmp",
                    "line": None,
                    "source": "net.http_server_properties.servers",
                    "matched_server": "https://linkedin.com",
                    "inferred_origins_from_anonymization": ["https://origin.example"],
                }
            ]
        }
        callers = probable_callers(context)
        self.assertEqual(callers[0]["caller"], "https://origin.example")
        self.assertEqual(callers[0]["confidence"], "high")
        self.assertEqual(callers[0]["method"], "decoded anonymization payload")

    def test_case_summary_counts_evidence(self):
        context = {
            "target_raw": "linkedin.com",
            "target_domain": "linkedin.com",
            "profiles": ["Default"],
            "visits_matches": [{}],
            "cookies_matches": [{}, {}],
            "bookmarks_matches": [],
            "downloads_matches": [],
            "network_log_matches": [{}],
            "network_scan_summaries": [
                {
                    "primary_tmp_files_scanned": 5,
                    "primary_tmp_files_with_target": 1,
                    "files_with_target": ["Default/Network/a.tmp"],
                }
            ],
            "history_summaries": [{"first_seen_utc": "2024-01-01T00:00:00Z", "last_seen_utc": "2024-01-02T00:00:00Z", "access_count": 1}],
            "errors": [],
        }
        summary = build_case_summary(context)
        self.assertEqual(summary["history_match_count"], 1)
        self.assertEqual(summary["cookie_match_count"], 2)
        self.assertEqual(summary["network_match_count"], 1)
        self.assertEqual(summary["network_scan"]["primary_tmp_files_scanned"], 5)
        self.assertEqual(summary["network_scan"]["primary_tmp_files_with_target"], 1)


if __name__ == "__main__":
    unittest.main()
