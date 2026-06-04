import unittest

from btforensic.safe_redaction import (
    REDACTED_STRICT,
    mask_url_query,
    redact_headers,
    redact_local_path,
    redact_sensitive_text,
    safe_cookie_record,
    sanitize_for_privacy,
    sha256_value,
)


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

    def test_strict_text_redacts_paths_and_secret_patterns(self):
        text = redact_sensitive_text(
            r'C:\Users\alice\Downloads\file.exe Authorization: Bearer abc.def.ghi https://example.com/?token=123',
            redact_paths=True,
        )
        self.assertIn("[LOCAL_PATH_REDACTED:", text)
        self.assertNotIn("alice", text)
        self.assertNotIn("abc.def.ghi", text)
        self.assertNotIn("secret", text.lower())
        self.assertNotIn("token=123", text)

    def test_strict_sanitizer_redacts_snippet_identity_and_local_path(self):
        record = sanitize_for_privacy(
            {
                "DeviceName": "HOST01",
                "AccountUpn": "alice@example.com",
                "file": r"C:\Users\alice\AppData\Local\Chrome\User Data\Default\Network\a.tmp",
                "snippet": "GET https://example.com/?session=abc",
                "path": "/",
            }
        )
        self.assertTrue(record["DeviceName"].startswith("[DEVICE_REDACTED:"))
        self.assertTrue(record["AccountUpn"].startswith("[ACCOUNT_REDACTED:"))
        self.assertIn("[LOCAL_PATH_REDACTED:", record["file"])
        self.assertEqual(record["snippet"], REDACTED_STRICT)
        self.assertEqual(record["path"], "/")

    def test_redact_local_path_is_idempotent(self):
        redacted = redact_local_path(r"C:\Users\alice\Downloads\a.exe")
        self.assertEqual(redact_local_path(redacted), redacted)

    def test_summary_counter_values_are_preserved_after_redaction(self):
        record = sanitize_for_privacy({"top_devices": [{"value": "[DEVICE_REDACTED:abc123]", "count": 2}]})
        self.assertEqual(record["top_devices"][0]["value"], "[DEVICE_REDACTED:abc123]")

    def test_underscore_identity_keys_are_redacted(self):
        record = sanitize_for_privacy({"device_name": "HOST01", "account_name": "alice"})
        self.assertTrue(record["device_name"].startswith("[DEVICE_REDACTED:"))
        self.assertTrue(record["account_name"].startswith("[ACCOUNT_REDACTED:"))


if __name__ == "__main__":
    unittest.main()
