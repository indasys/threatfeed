import unittest
from validate import gha_escape, run

def errs(rep):
    return " | ".join(m for _, m in rep.errors)

class Checks(unittest.TestCase):
    def test_gueltig(self):
        self.assertTrue(run("1.2.3.4/32\n8.8.4.0/24\n2a00:1450::/48\n").ok)

    def test_format(self):
        for bad in ("1.2.3.4\n", "1.2.3.4/32", "1.2.3.4/32 \n", "# x\n", "\n", "1.2.3.4/32\r\n"):
            self.assertFalse(run(bad).ok, bad)

    def test_hostbits_und_nullen(self):
        self.assertIn("host bits", errs(run("1.2.3.4/24\n")))
        self.assertFalse(run("01.2.3.4/32\n").ok)
        self.assertIn("kanonisch", errs(run("2A00:1450::/48\n")))

    def test_reserviert(self):
        for bad in ("10.1.2.3/32\n", "100.64.0.1/32\n", "255.255.255.255/32\n", "fe80::1/128\n", "2001:db8::/48\n"):
            self.assertIn("reserviert", errs(run(bad)), bad)

    def test_praefix(self):
        self.assertIn("zu groß", errs(run("8.0.0.0/15\n")))
        self.assertIn("Label large-net", errs(run("8.8.0.0/16\n")))
        self.assertTrue(run("8.8.0.0/16\n", labels=["large-net"]).ok)

    def test_duplikat_ueberlappung_sortierung(self):
        self.assertIn("Duplikat", errs(run("1.2.3.4/32\n1.2.3.4/32\n")))
        self.assertIn("abgedeckt", errs(run("1.2.3.0/24\n1.2.3.4/32\n")))
        self.assertIn("sortiert", errs(run("9.9.9.9/32\n1.1.1.1/32\n")))

    def test_leer_und_schrumpfen(self):
        base = "".join(f"1.1.1.{i}/32\n" for i in range(10))
        self.assertIn("leer", errs(run("", base)))
        self.assertIn("schrumpft", errs(run("1.1.1.0/32\n", base)))

    def test_bulk(self):
        head = "".join(f"1.1.{i // 256}.{i % 256}/32\n" for i in range(300))
        self.assertIn("Label bulk", errs(run(head)))
        self.assertTrue(run(head, labels=["bulk"]).ok)

    def test_pfade(self):
        self.assertFalse(run("1.2.3.4/32\n", changed=["README.md"]).ok)
        self.assertTrue(run("1.2.3.4/32\n", changed=["threatfeed.txt", "tools/validate.py", ".gitattributes"]).ok)

    def test_annotation_escape(self):
        self.assertEqual(gha_escape("a%0A::x\r\n"), "a%250A::x%0D%0A")

if __name__ == "__main__":
    unittest.main()
