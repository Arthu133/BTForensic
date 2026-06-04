import base64
import json
import logging
import tempfile
import unittest
from pathlib import Path

from btforensic.domain_utils import normalize_target
from btforensic.network_log_analyzer import analyze_network_logs


class NetworkLogAnalyzerTest(unittest.TestCase):
    def test_tmp_match_decodes_anonymization_origin(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "Default"
            network = profile / "Network"
            network.mkdir(parents=True)
            payload = base64.urlsafe_b64encode(
                b"top_frame_site=https%3A%2F%2Forigin.example request=https%3A%2F%2Flinkedin.com"
            ).decode("ascii")
            (network / "request.tmp").write_text(
                f'GET https://linkedin.com/feed anonymization_key="{payload}"',
                encoding="utf-8",
            )

            result = analyze_network_logs(
                "Default",
                profile,
                normalize_target("linkedin.com"),
                logging.getLogger("test"),
            )

            self.assertEqual(len(result["network_log_matches"]), 1)
            match = result["network_log_matches"][0]
            self.assertEqual(match["discovery_method"], "primary_network_tmp_select_string")
            self.assertIn("Select-String", match["select_string_equivalent"])
            self.assertIn("https://origin.example", match["inferred_origins_from_anonymization"])
            self.assertIn("https://linkedin.com", match["anonymization_urls"])

    def test_http_server_properties_tmp_matches_jq_style_server_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "Default"
            network = profile / "Network"
            network.mkdir(parents=True)
            payload = base64.b64encode(
                b"\x00\x00https://origin.example\x00"
            ).decode("ascii")
            data = {
                "net": {
                    "http_server_properties": {
                        "servers": [
                            {"server": "https://unrelated.example", "anonymization": payload},
                            {"server": "https://linkedin.com", "anonymization": payload},
                        ]
                    }
                }
            }
            (network / "Network Persistent State.tmp").write_text(json.dumps(data), encoding="utf-8")

            result = analyze_network_logs(
                "Default",
                profile,
                normalize_target("linkedin.com"),
                logging.getLogger("test"),
            )

            structured = [
                item for item in result["network_log_matches"]
                if item.get("source") == "net.http_server_properties.servers"
            ]
            self.assertEqual(len(structured), 1)
            self.assertEqual(structured[0]["discovery_method"], "primary_network_tmp_select_string")
            self.assertEqual(structured[0]["matched_server"], "https://linkedin.com")
            self.assertIn("https://origin.example", structured[0]["inferred_origins_from_anonymization"])


if __name__ == "__main__":
    unittest.main()
