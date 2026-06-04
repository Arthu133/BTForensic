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


if __name__ == "__main__":
    unittest.main()
