"""
Tier-1 prototype of the RSI Safety Spec: static AST allow-list for AI-generated Python.

This is a LINT-LEVEL gate - it rejects obviously dangerous patches cheaply and early.
It is NOT a sandbox: a determined adversary can bypass any static Python filter.
The real containment boundary is Tier 2 (MicroVM, no network). Never rely on this alone.

Rules: import allow-list, forbidden builtins, no dunder access, size/complexity caps,
warning on `while True` without a `break`.
"""

from __future__ import annotations

import ast
import sys
from dataclasses import dataclass, field
from typing import List

ALLOWED_IMPORTS = {"math", "re", "json", "dataclasses", "typing", "collections", "itertools", "functools",
                   "heapq", "bisect", "string", "textwrap", "statistics", "enum", "fractions", "decimal", "__future__"}
FORBIDDEN_CALLS = {"eval", "exec", "compile", "open", "__import__", "input", "breakpoint", "globals", "locals",
                   "vars", "getattr", "setattr", "delattr", "memoryview", "exit", "quit"}
ALLOWED_DUNDERS = {"__init__", "__name__", "__future__"}
MAX_SOURCE_BYTES = 200_000
MAX_NODES = 20_000


@dataclass
class Violation:
    rule: str
    line: int
    detail: str

    def __str__(self) -> str:
        return f"line {self.line}: [{self.rule}] {self.detail}"


@dataclass
class GuardReport:
    ok: bool
    violations: List[Violation] = field(default_factory=list)
    warnings: List[Violation] = field(default_factory=list)


def check_source(source: str) -> GuardReport:
    v: List[Violation] = []
    w: List[Violation] = []
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        return GuardReport(False, [Violation("size", 0, f"source exceeds {MAX_SOURCE_BYTES} bytes")])
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return GuardReport(False, [Violation("syntax", e.lineno or 0, e.msg)])

    nodes = list(ast.walk(tree))
    if len(nodes) > MAX_NODES:
        return GuardReport(False, [Violation("complexity", 0, f"more than {MAX_NODES} AST nodes")])

    for n in nodes:
        line = getattr(n, "lineno", 0)
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in ALLOWED_IMPORTS:
                    v.append(Violation("import", line, f"module '{a.name}' not in allow-list"))
        elif isinstance(n, ast.ImportFrom):
            if n.level or (n.module or "").split(".")[0] not in ALLOWED_IMPORTS:
                v.append(Violation("import", line, f"module '{'.' * n.level}{n.module or ''}' not in allow-list"))
        elif isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in FORBIDDEN_CALLS:
            v.append(Violation("call", line, f"call to forbidden builtin '{n.func.id}'"))
        elif isinstance(n, ast.Attribute) and n.attr.startswith("__") and n.attr.endswith("__") and n.attr not in ALLOWED_DUNDERS:
            v.append(Violation("dunder", line, f"access to '{n.attr}'"))
        elif isinstance(n, ast.Name) and n.id.startswith("__") and n.id.endswith("__") and n.id not in ALLOWED_DUNDERS:
            v.append(Violation("dunder", line, f"reference to '{n.id}'"))
        elif isinstance(n, ast.While) and isinstance(n.test, ast.Constant) and n.test.value is True:
            if not any(isinstance(c, ast.Break) for c in ast.walk(n)):
                w.append(Violation("unbounded-loop", line, "`while True` without a break"))
    return GuardReport(ok=not v, violations=v, warnings=w)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python ast_guard.py <file.py>")
        sys.exit(2)
    with open(sys.argv[1], encoding="utf-8") as f:
        rep = check_source(f.read())
    print("PASS" if rep.ok else "REJECT")
    for x in rep.violations:
        print("  violation:", x)
    for x in rep.warnings:
        print("  warning  :", x)
    sys.exit(0 if rep.ok else 1)
