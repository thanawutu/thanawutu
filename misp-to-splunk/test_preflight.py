"""ทดสอบการขยาย macro ของแอปจากไฟล์จริง:  python3 -m unittest -v test_preflight"""
import os
import unittest

import preflight as p

MACROS = os.path.join(p.APP_DIR, "default", "macros.conf")


class MacroTest(unittest.TestCase):
    def setUp(self):
        self.m = p.load_macros(MACROS)

    def test_all_app_macros_expand(self):
        for name in ("tbcert_misp_src", "tbcert_misp_events_normalize", "tbcert_misp_normalize"):
            out = p.expand(f"`{name}`", self.m)
            self.assertNotIn("`", out, name)

    def test_continuations_joined(self):
        out = p.expand("`tbcert_misp_normalize`", self.m)
        self.assertNotIn("\\\n", out)
        self.assertIn("| table _key indicator", out)
        self.assertIn("(?i)^(tlp:red", out)          # macro ซ้อนถูกแทนค่า

    def test_strip_lookups(self):
        out = p.strip_app_lookups(p.expand("`tbcert_misp_normalize`", self.m))
        self.assertNotIn("lookup tbcert_", out)
        self.assertIn("| eval trust=", out)

    def test_unknown_macro(self):
        with self.assertRaises(KeyError):
            p.expand("`nope`", self.m)


if __name__ == "__main__":
    unittest.main()
