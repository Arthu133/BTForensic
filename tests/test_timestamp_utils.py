from datetime import datetime, timezone
import unittest

from btforensic.timestamp_utils import chrome_time_to_datetime, chrome_time_to_iso_utc


class TimestampUtilsTest(unittest.TestCase):
    def test_chrome_epoch_conversion(self):
        value = 11644473600000000
        self.assertEqual(chrome_time_to_datetime(value), datetime(1970, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(chrome_time_to_iso_utc(value), "1970-01-01T00:00:00Z")

    def test_invalid_values_return_none(self):
        self.assertIsNone(chrome_time_to_datetime(None))
        self.assertIsNone(chrome_time_to_datetime("not-a-number"))


if __name__ == "__main__":
    unittest.main()
