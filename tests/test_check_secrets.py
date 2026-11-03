"""Tests du contrôle de sécurité du dépôt (scripts/check_secrets.py)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from check_secrets import scan_line  # noqa: E402

# Les valeurs « interdites » sont assemblées à l'exécution, pour que ce fichier
# lui-même passe le contrôle.
J = "".join


def kinds(line):
    return {k for k, _ in scan_line(line)}


class Detects(unittest.TestCase):
    def test_ip_addresses(self):
        self.assertIn("adresse IP", kinds("host = " + J(["192", ".168", ".1", ".10"])))
        self.assertIn("adresse IP", kinds("wan " + J(["81", ".82", ".83", ".84"])))
        self.assertIn("adresse IPv6", kinds("ip " + J(["fe8", "0:", ":1ff:fe23", ":4567:890a"])))

    def test_mac_addresses(self):
        self.assertIn("adresse MAC", kinds("mac " + J(["3c", ":22:fb", ":12:34:56"])))
        self.assertIn("adresse MAC", kinds("mac " + J(["3C", "-22-FB", "-12-34-56"])))

    def test_keys_and_tokens(self):
        self.assertIn("clé Anthropic", kinds(J(["sk", "-ant-", "api03-", "A" * 30])))
        self.assertIn("jeton GitHub", kinds(J(["gh", "p_", "a" * 36])))
        self.assertIn("jeton GitHub", kinds(J(["github", "_pat_", "a" * 50])))
        self.assertIn("jeton JWT", kinds(J(["ey", "JhbGciOiJIUzI1NiJ9", ".eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".abcdefghij"])))
        self.assertIn("clé privée", kinds(J(["-----BEGIN ", "RSA PRIVATE KEY-----"])))
        self.assertIn("clé Supabase", kinds(J(["sb", "_secret_", "x" * 20])))
        self.assertIn("URL de projet Supabase", kinds(J(["https://", "abcdefghijklmnopqrst", ".supabase.co"])))

    def test_passwords(self):
        self.assertIn("mot de passe / secret en clair", kinds('password = "' + "Sup3rS3cret!" + '"'))
        self.assertIn("mot de passe / secret en clair", kinds('"shared_secret": "' + "k" * 40 + '"'))
        self.assertIn("identifiants dans une URL", kinds("https://admin:" + "hunter22" + "@gw.local/"))


class Allows(unittest.TestCase):
    def test_harmless(self):
        for line in [
            'version: "1.0.0"',
            "firmware 6.6.77.15516 et 4.1.13",
            "doc 192.0.2.1, 198.51.100.12, 203.0.113.9, 2001:db8::1",
            "fausses MAC aa:00:00:00:00:03 et aa:bb:cc:dd:ee:ff",
            "heure 12:30:00",
            "unifi_password: password",
            'opts["shared_secret"]',
            "SECRET = \"s\" * 40",
        ]:
            self.assertEqual(scan_line(line), [], line)


if __name__ == "__main__":
    unittest.main()
