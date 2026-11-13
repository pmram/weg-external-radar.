import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from scan import assess, excluded, hostname, seed_candidates
from check_sites import public_addresses
from unittest.mock import patch

def sample(url, title="WEG Official Portal"):
    return {"url": url, "title": title, "description": "Login customer portal"}

class ScannerTests(unittest.TestCase):
    def test_genuine_domain_excluded(self):
        self.assertTrue(excluded("weg.net"))
        self.assertTrue(excluded("portal.weg.net"))
    def test_sibling_spoof_is_not_allowlisted(self):
        self.assertFalse(excluded("weg.net.evil.example"))
    def test_news_and_social_excluded(self):
        self.assertTrue(excluded("news.example.com"))
        self.assertTrue(excluded("linkedin.com"))
    def test_brand_mention_not_enough(self):
        self.assertIsNone(assess(sample("https://industrial-supplier.example/products/weg")))
    def test_lookalike_candidate(self):
        item = assess(sample("https://weg-support.example/login"))
        self.assertIsNotNone(item)
        self.assertGreaterEqual(item["score"], 75)
    def test_unrelated_brand_word_not_enough(self):
        self.assertIsNone(assess(sample("https://newgeneration.example")))
    def test_german_word_weg_is_not_brand(self):
        self.assertIsNone(assess(sample('https://auf-dem-weg-zur-arbeit.example')))
        self.assertIsNone(assess(sample('https://fett-weg-spritze.example')))
    def test_weg_motors_candidate(self):
        self.assertIsNotNone(assess(sample('https://wegmotors.example')))
    def test_weg_connect_is_detected(self):
        item = assess(sample("https://weg-connect.kz/", "weg-connect.kz"))
        self.assertIsNotNone(item)
        self.assertEqual(item["domain"], "weg-connect.kz")
    def test_known_domain_is_seeded(self):
        self.assertIn("weg-connect.kz", [x["url"].split("/")[2] for x in seed_candidates()])
    def test_reject_private_ip_dns(self):
        fake = [(2, 1, 6, "", ("127.0.0.1", 0)), (2, 1, 6, "", ("10.0.0.1", 0))]
        with patch("socket.getaddrinfo", return_value=fake):
            self.assertEqual(public_addresses("test.example"), [])
    def test_invalid_scheme(self):
        self.assertEqual(hostname("javascript:alert(1)"), "")
    def test_auth_in_url_only_ignored(self):
        self.assertIsNone(assess(sample("https://company.example/weg-login")))
if __name__ == "__main__":
    unittest.main()
