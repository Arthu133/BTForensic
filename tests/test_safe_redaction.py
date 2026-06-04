import unittest

from btforensic.safe_redaction import mask_url_query, redact_headers, safe_cookie_record, sha256_value


class SafeRedactionTest(unittest.TestCase):
    def test_cookie_value_is_hashed_not_returned(self):
        row = {"host_key": ".example.com", "name": "sid", "path": "/", "value": "secret-cookie"}
        record = safe_cookie_record(row)
        self.assertNotIn("value", record)
        self.assertEqual(record["value_sha256"], sha256_value("secret-cookie"))

    def test_sensitive_headers_are_redacted(self):
        headers = redact_headers({"Authorization": "Bearer abc", "User-Agent": "test"})
        self.assertEqual(headers["Authorization"], "[REDACTED]")
        self.assertEqual(headers["User-Agent"], "test")

    def test_sensitive_query_params_are_masked(self):
        url = mask_url_query("https://example.com/callback?code=abc&ok=1")
        self.assertIn("code=%5BREDACTED%5D", url)
        self.assertIn("ok=1", url)
        self.assertNotIn("abc", url)


if __name__ == "__main__":
    unittest.main()
