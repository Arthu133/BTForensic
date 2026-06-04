import json
import logging
import tempfile
import unittest
from pathlib import Path

from btforensic.bookmark_analyzer import analyze_bookmarks
from btforensic.domain_utils import normalize_target


class BookmarkAnalyzerTest(unittest.TestCase):
    def test_strict_privacy_does_not_export_full_raw_bookmarks(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "Default"
            profile.mkdir()
            raw_output = Path(tmp) / "raw"
            bookmarks = {
                "roots": {
                    "bookmark_bar": {
                        "type": "folder",
                        "name": "Bookmarks Bar",
                        "children": [
                            {
                                "type": "url",
                                "name": "Target",
                                "url": "https://linkedin.com/login?token=abc",
                                "date_added": "0",
                            },
                            {
                                "type": "url",
                                "name": "Private unrelated",
                                "url": "https://private.example/?session=secret",
                                "date_added": "0",
                            },
                        ],
                    }
                }
            }
            (profile / "Bookmarks").write_text(json.dumps(bookmarks), encoding="utf-8")

            result = analyze_bookmarks(
                "Default",
                profile,
                normalize_target("linkedin.com"),
                raw_output,
                logging.getLogger("test"),
            )

            raw_file = raw_output / "Default_bookmarks.json"
            raw_text = raw_file.read_text(encoding="utf-8")
            self.assertTrue(result["raw_bookmarks"]["redacted"])
            self.assertIn("Full raw bookmarks are not exported", raw_text)
            self.assertIn("linkedin.com", raw_text)
            self.assertIn("token=%5BREDACTED%5D", raw_text)
            self.assertNotIn("private.example", raw_text)
            self.assertNotIn("secret", raw_text)


if __name__ == "__main__":
    unittest.main()
