import unittest

import _bootstrap  # noqa: F401
from ast_guard import check_source


class AstGuard(unittest.TestCase):
    def rules(self, src):
        return {v.rule for v in check_source(src).violations}

    def test_safe_code_passes(self):
        src = "import math\nfrom dataclasses import dataclass\n\n@dataclass\nclass P:\n    x: float\n\ndef f(p):\n    return math.sqrt(p.x)\n"
        self.assertTrue(check_source(src).ok)

    def test_blocked_imports(self):
        for src in ("import os", "import subprocess", "from socket import socket", "import ctypes", "from . import x", "import os.path"):
            self.assertIn("import", self.rules(src), src)

    def test_blocked_calls(self):
        for src in ("eval('1')", "exec('x=1')", "open('/etc/passwd')", "__import__('os')", "getattr(a, 'b')"):
            self.assertTrue(self.rules(src), src)

    def test_dunder_escape_blocked(self):
        self.assertIn("dunder", self.rules("x = ().__class__.__bases__[0].__subclasses__()"))
        self.assertIn("dunder", self.rules("__builtins__"))

    def test_init_and_name_allowed(self):
        self.assertTrue(check_source("class A:\n    def __init__(self):\n        super().__init__()\nprint(__name__)\n").ok)
        self.assertNotIn("dunder", self.rules("class A:\n    def __init__(self):\n        super().__init__()\n"))

    def test_syntax_error_rejected(self):
        self.assertEqual(self.rules("def (:"), {"syntax"})

    def test_unbounded_loop_is_a_warning_not_a_violation(self):
        rep = check_source("while True:\n    pass\n")
        self.assertTrue(rep.ok)
        self.assertEqual([w.rule for w in rep.warnings], ["unbounded-loop"])
        self.assertEqual(check_source("while True:\n    break\n").warnings, [])

    def test_oversize_source_rejected(self):
        self.assertEqual(self.rules("x = 1\n" * 100_000), {"size"})


if __name__ == "__main__":
    unittest.main()
