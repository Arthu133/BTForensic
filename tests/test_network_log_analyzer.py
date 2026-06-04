import base64
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
            self.assertIn("https://origin.example", match["inferred_origins_from_anonymization"])
            self.assertIn("https://linkedin.com", match["anonymization_urls"])


if __name__ == "__main__":
    unittest.main()
