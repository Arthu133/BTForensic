import base64
import unittest

from btforensic.anonymization_decoder import decode_anonymization_payload


class AnonymizationDecoderTest(unittest.TestCase):
    def test_url_encoded_payload(self):
        result = decode_anonymization_payload("https%3A%2F%2Fexample.com")
        self.assertIn("url_encoding", result["detected"])
        self.assertIn("https://example.com", result["decoded"])

    def test_base64_payload(self):
        encoded = base64.urlsafe_b64encode(b"https://example.com").decode("ascii")
        result = decode_anonymization_payload(encoded)
        self.assertIn("base64", result["detected"])
        self.assertIn("https://example.com", result["decoded"])
        self.assertIn("https://example.com", result["extracted_urls"])
        self.assertIn("example.com", result["extracted_domains"])

    def test_nested_encoded_payload_extracts_origin_url(self):
        encoded = base64.urlsafe_b64encode(
            b'top_frame_site=https%3A%2F%2Forigin.example frame_site=https%3A%2F%2Ftarget.example'
        ).decode("ascii")
        result = decode_anonymization_payload(encoded)
        self.assertIn("base64", result["detected"])
        self.assertIn("url_encoding", result["detected"])
        self.assertIn("https://origin.example", result["extracted_urls"])
        self.assertIn("https://target.example", result["extracted_urls"])


if __name__ == "__main__":
    unittest.main()
