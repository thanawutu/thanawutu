"""V2: browsers cache appserver/static by app.conf [install] build - it must change with the card script."""
import hashlib
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(HERE, "..", "TA-imperva-ioc-block-v2")

# sha256 of appserver/static/imperva_form.js for each build number; when the script changes, raise
# [install] build in default/app.conf and add the new pair here (otherwise browsers keep the old card)
KNOWN = {
    4: "7c7ab5999896d1f7ca13bba9410c2d1ff02181c7f7c2c85c186d1a1ffe1d41ae",
    3: "7fe1f40dad3cdb84884da9450da3273a37ae12f5e7182a2978f410f8bb213519",
    2: "e9a5aaf1aea0ddc1bf92c5d28d90407fb318d59e61aaa12c987b8f51b2b2b1fe",
}


class TestBuild(unittest.TestCase):
    def test_build_matches_the_card_script(self):
        conf = open(os.path.join(APP, "default", "app.conf"), encoding="utf-8").read()
        build = int(re.search(r"^build = (\d+)$", conf, re.M).group(1))
        js = hashlib.sha256(open(os.path.join(APP, "appserver", "static", "imperva_form.js"), "rb").read()).hexdigest()
        self.assertEqual(KNOWN.get(build), js, "imperva_form.js changed: raise [install] build in app.conf "
                                               "and record the new sha256 in tests_v2/test_static_build.py")


if __name__ == "__main__":
    unittest.main()
