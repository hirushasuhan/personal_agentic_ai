import json
import os
import unittest

import _bootstrap  # noqa: F401
import conformance
from hardware_telemetry import HardwareTelemetry
from net_guard import validate_url, UrlRejected

DIR = conformance.OUT_DIR


def load(name):
    with open(os.path.join(DIR, name), encoding="utf-8") as f:
        return json.load(f)


class Vectors(unittest.TestCase):
    def test_tier_vectors_match_the_code(self):
        t = HardwareTelemetry(cpu_sample_ms=0)
        vectors = load("tier_policy_vectors.json")
        self.assertGreaterEqual(len(vectors), 200)
        for v in vectors:
            i, e = v["input"], v["expected"]
            t.cpu_count = i["cpu_cores"]
            b = t._calculate_budget(i["avail_ram_mb"], i["memory_load_pct"], i["cpu_load_pct"], i["battery"])
            got = {"compute_tier": b.compute_tier, "max_context_bytes": b.max_context_bytes,
                   "allow_speculation": b.allow_speculation, "thread_pool_limit": b.thread_pool_limit, "reasons": b.reasons}
            self.assertEqual(got, e, i)

    def test_url_vectors_match_the_code(self):
        for v in load("url_policy_vectors.json"):
            self.assertEqual(conformance.evaluate_url(v["url"]), v["expected"], v["url"])

    def test_checked_in_files_are_in_sync_with_generators(self):
        """If this fails the policy changed: run `python conformance.py` AND review the vector diff."""
        self.assertEqual(load("tier_policy_vectors.json"), json.loads(json.dumps(conformance.tier_policy_vectors())))
        self.assertEqual(load("url_policy_vectors.json"), conformance.url_policy_vectors())

    def test_multicast_and_unspecified_addresses_are_rejected(self):
        for url in ("http://224.0.0.1/", "http://239.255.255.250/", "http://[ff02::1]/", "http://0.0.0.0/", "http://240.0.0.1/"):
            with self.assertRaises(UrlRejected, msg=url):
                validate_url(url)


if __name__ == "__main__":
    unittest.main()
