"""Claims lint (review risk R3): unfalsifiable security claims must not creep back into code or docs.

Every security statement has to be backed by a named test or a named residual risk
(docs/THREAT_MODEL.md). A line that merely QUOTES a banned phrase (e.g. the policy itself) opts out
with the marker `claims-lint: quote`.
"""
import os
import re
import unittest

import _bootstrap  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BANNED = re.compile(
    r"100\s?%\s*(secure|safe|private|clean|protected|secured)|zero\s+(memory\s+)?leak|unhackable|unbreakable|"
    r"completely\s+(safe|secure)|fully\s+(secure|safe)|absolutely\s+(safe|secure)|guaranteed\s+(safe|secure)|"
    r"impossible to (hack|bypass|break)|cannot be (hacked|bypassed)",
    re.IGNORECASE,
)
SKIP_DIRS = {".git", "__pycache__", "target", "build", "bin", "node_modules"}


class ClaimsLint(unittest.TestCase):
    def test_no_unfalsifiable_security_claims(self):
        offenders = []
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if not fn.endswith((".md", ".py", ".rs", ".cpp", ".h", ".toml", ".txt")) or fn == "test_claims.py":
                    continue
                path = os.path.join(dirpath, fn)
                with open(path, encoding="utf-8", errors="replace") as f:
                    for n, line in enumerate(f, 1):
                        if BANNED.search(line) and "claims-lint: quote" not in line:
                            offenders.append(f"{os.path.relpath(path, ROOT)}:{n}: {line.strip()[:110]}")
        self.assertEqual(offenders, [], "unfalsifiable claims found:\n" + "\n".join(offenders))

    def test_lint_actually_detects_claims(self):
        for bad in ("This engine is 100% secure", "ensures zero memory leakage", "fully secure design", "100 % private"):
            self.assertTrue(BANNED.search(bad), bad)
        self.assertFalse(BANNED.search("defense in depth with named residual risks"))


if __name__ == "__main__":
    unittest.main()
