import unittest

from btforensic.timeline_builder import build_timeline


class TimelineBuilderTest(unittest.TestCase):
    def test_timeline_is_chronological(self):
        timeline = build_timeline(
            visits=[
                {"visit_time_utc": "2024-01-02T00:00:00Z", "profile": "Default", "url": "https://example.com/2"},
                {"visit_time_utc": "2024-01-01T00:00:00Z", "profile": "Default", "url": "https://example.com/1"},
            ],
            cookies=[],
            bookmarks=[],
            downloads=[],
            network_matches=[],
            origins={},
        )
        self.assertEqual(timeline[0]["timestamp_utc"], "2024-01-01T00:00:00Z")
        self.assertEqual(timeline[1]["timestamp_utc"], "2024-01-02T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
