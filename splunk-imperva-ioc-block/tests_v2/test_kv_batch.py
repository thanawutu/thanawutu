"""V2: KV store writes are split - one batch_save of more than 1000 documents fails on Splunk
("Request exceeds API limits ... max_documents_per_batch_save=1000"), e.g. the first_listed state of
1,483 IP rules of 9 policies."""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "stubs"))
sys.path.insert(0, os.path.join(HERE, "..", "TA-imperva-ioc-block-v2", "bin"))

import splunk_helpers as sh  # noqa: E402


class TestKvBatch(unittest.TestCase):
    def test_batches_of_500_never_over_1000(self):
        calls = []

        def fake(path, sessionKey=None, getargs=None, postargs=None, method="GET", raiseAllErrors=False,
                 proxyMode=False, rawResult=False, timeout=None, jsonargs=None, token=False):
            docs = json.loads(jsonargs)
            if len(docs) > 1000:
                raise Exception("[HTTP 400] Request exceeds API limits")
            calls.append((path, len(docs)))
            return None, "[]"
        saved = getattr(sh.rest, "simpleRequest", None)
        sh.rest.simpleRequest = fake
        try:
            sh.kv_upsert("k", [{"_key": "e_%d" % i} for i in range(1483)], "imperva_auto_unblock")
            sh.kv_upsert("k", [], "imperva_auto_unblock")
            sh.kv_upsert("k", None)
        finally:
            sh.rest.simpleRequest = saved
        self.assertEqual([n for _p, n in calls], [500, 500, 483])
        self.assertTrue(all(p.endswith("/storage/collections/data/imperva_auto_unblock/batch_save") for p, _n in calls))


if __name__ == "__main__":
    unittest.main()
