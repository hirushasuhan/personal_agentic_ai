"""
Capability broker with taint tracking (review risk R7, ADR-006).

Prompt injection cannot be filtered out reliably, so the design assumes it WILL sometimes succeed and
limits what a hijacked reasoner can do:

  1. Deny by default: a tool runs only if the USER granted it (grants are fixed at construction; no tool
     or model output can add one - the Constitution forbids self-granted authority).
  2. Scoped: path arguments must resolve (symlinks included) inside the granted roots; grants can expire
     and carry a call budget.
  3. Taint: when a task's context contained untrusted data (`tainted=True`), ANY non-read tool needs
     explicit human confirmation. No confirmation channel => denied (fail closed).
  4. Always-confirm: destructive and outbound-network tools need a human even when untrusted data was
     not involved.
  5. Every decision - allowed or denied - goes into a hash-chained audit log (tamper-evident).

The Phase 1 reasoner has no tool access; this broker is the contract Phase 3/5 must route all side
effects through.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


class Risk(IntEnum):
    READ = 0
    WRITE = 1
    DESTRUCTIVE = 2
    NETWORK_OUT = 3


class PermissionDenied(Exception):
    pass


@dataclass(frozen=True)
class Tool:
    name: str
    risk: Risk
    func: Callable[..., Any]
    path_args: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Grant:
    tool: str
    roots: Tuple[str, ...] = ()          # allowed directory roots for the tool's path arguments
    expires: Optional[float] = None      # epoch seconds
    max_calls: Optional[int] = None


@dataclass
class ToolRequest:
    tool: str
    risk: Risk
    args_summary: str
    tainted: bool
    reason_for_confirmation: str


@dataclass
class AuditEntry:
    seq: int
    timestamp: float
    tool: str
    args_summary: str
    allowed: bool
    reason: str
    tainted: bool
    confirmed: Optional[bool]
    prev_hash: str
    hash: str = ""


def _summ(args: Dict[str, Any]) -> str:
    return json.dumps(args, default=str, ensure_ascii=False)[:200]


class ToolBroker:
    def __init__(self, tools: Sequence[Tool], grants: Sequence[Grant],
                 confirm: Optional[Callable[[ToolRequest], bool]] = None, clock: Callable[[], float] = time.time):
        self._tools = {t.name: t for t in tools}
        self._grants = {g.tool: g for g in grants}     # no API to add grants later
        self._calls: Dict[str, int] = {}
        self._confirm = confirm
        self._clock = clock
        self.audit: List[AuditEntry] = []

    # ------------------------------------------------------------------ audit
    def _record(self, tool, args, allowed, reason, tainted, confirmed=None) -> None:
        prev = self.audit[-1].hash if self.audit else "0" * 64
        e = AuditEntry(len(self.audit), self._clock(), tool, _summ(args), allowed, reason, tainted, confirmed, prev)
        e.hash = self._digest(e)
        self.audit.append(e)

    @staticmethod
    def _digest(e: AuditEntry) -> str:
        body = json.dumps([e.seq, e.timestamp, e.tool, e.args_summary, e.allowed, e.reason, e.tainted, e.confirmed, e.prev_hash])
        return hashlib.sha256(body.encode("utf-8")).hexdigest()

    def verify_audit_chain(self) -> bool:
        prev = "0" * 64
        for i, e in enumerate(self.audit):
            if e.seq != i or e.prev_hash != prev or e.hash != self._digest(e):
                return False
            prev = e.hash
        return True

    # ----------------------------------------------------------------- policy
    def _deny(self, name, args, reason, tainted, confirmed=None):
        self._record(name, args, False, reason, tainted, confirmed)
        raise PermissionDenied(reason)

    @staticmethod
    def _inside(path: str, roots: Sequence[str]) -> bool:
        real = os.path.realpath(path)
        for r in roots:
            rr = os.path.realpath(r)
            try:
                if os.path.commonpath([real, rr]) == rr:
                    return True
            except ValueError:   # different drives on Windows
                continue
        return False

    def invoke(self, name: str, args: Dict[str, Any], tainted: bool) -> Any:
        """`tainted` must be True whenever untrusted data (web, files, other programs) was in the task's context."""
        args = copy.deepcopy(args)  # what is confirmed is exactly what runs
        tool, grant = self._tools.get(name), self._grants.get(name)
        if tool is None:
            self._deny(name, args, "unknown tool", tainted)
        if grant is None:
            self._deny(name, args, "tool not granted by the user", tainted)
        if grant.expires is not None and self._clock() >= grant.expires:
            self._deny(name, args, "grant expired", tainted)
        if grant.max_calls is not None and self._calls.get(name, 0) >= grant.max_calls:
            self._deny(name, args, "call budget exhausted", tainted)
        for pa in tool.path_args:
            val = args.get(pa)
            if not isinstance(val, str) or not grant.roots or not self._inside(val, grant.roots):
                self._deny(name, args, f"path argument '{pa}' is outside the granted roots", tainted)

        needs, why = False, ""
        if tool.risk >= Risk.DESTRUCTIVE:
            needs, why = True, "destructive or outbound actions always need a human"
        elif tainted and tool.risk >= Risk.WRITE:
            needs, why = True, "untrusted data was in context; side effects need a human"
        confirmed = None
        if needs:
            if self._confirm is None:
                self._deny(name, args, f"confirmation required ({why}) but no confirmation channel", tainted)
            try:
                confirmed = bool(self._confirm(ToolRequest(name, tool.risk, _summ(args), tainted, why)))
            except Exception:
                confirmed = False
            if not confirmed:
                self._deny(name, args, "human declined (or confirmation failed)", tainted, confirmed=False)

        self._calls[name] = self._calls.get(name, 0) + 1
        self._record(name, args, True, "allowed" + (" after human confirmation" if confirmed else ""), tainted, confirmed)
        return tool.func(**args)
