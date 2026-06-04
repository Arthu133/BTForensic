import unittest

from btforensic.domain_utils import extract_host, host_matches_domain, normalize_target, url_matches_target


class DomainUtilsTest(unittest.TestCase):
    def test_normalize_domain_target(self):
        target = normalize_target("example.com")
        self.assertEqual(target.domain, "example.com")
        self.assertFalse(target.is_url)

    def test_subdomain_matches(self):
        self.assertTrue(host_matches_domain("sub.example.com", "example.com"))
        self.assertTrue(host_matches_domain("www.example.com", "example.com"))
        self.assertFalse(host_matches_domain("badexample.com", "example.com"))

    def test_url_target_path_priority(self):
        target = normalize_target("https://example.com/login")
        self.assertTrue(url_matches_target("https://example.com/login?code=abc", target))
        self.assertTrue(url_matches_target("https://sub.example.com/login/step", target))
        self.assertFalse(url_matches_target("https://example.com/admin", target))

    def test_extract_host_without_scheme(self):
        self.assertEqual(extract_host("sub.example.com/path"), "sub.example.com")


if __name__ == "__main__":
    unittest.main()
