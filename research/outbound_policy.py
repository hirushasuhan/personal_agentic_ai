"""
Outbound privacy controls (ADR-002): domain allow-list, offline mode, visible request log.

Everything the engine sends to the internet - including the topic text inside the URL - is
recorded here so the USER can see exactly what left the machine. The log is an in-memory
ring buffer: it is never written to disk (stateless principle) and can be cleared at any time.
"""

from __future__ import annotations

import time
import urllib.parse
from collections import deque
from dataclasses import dataclass
from typing import Deque, Iterable, List, Optional

from net_guard import UrlRejected

DEFAULT_ALLOWED_DOMAINS = ("wikipedia.org", "duckduckgo.com")


@dataclass
class OutboundEvent:
    timestamp: float
    host: str
    url: str
    purpose: str
    allowed: bool
    reason: str = ""


class OutboundPolicy:
    def __init__(self, allowed_domains: Optional[Iterable[str]] = DEFAULT_ALLOWED_DOMAINS,
                 offline: bool = False, max_log: int = 200):
        """allowed_domains=None disables the allow-list (net_guard's SSRF rules still apply)."""
        self.allowed_domains = None if allowed_domains is None else tuple(d.lower().lstrip(".") for d in allowed_domains)
        self.offline = offline
        self.log: Deque[OutboundEvent] = deque(maxlen=max_log)

    def check(self, url: str, purpose: str = "") -> None:
        """Records the attempt and raises UrlRejected if policy forbids it."""
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        reason = ""
        if self.offline:
            reason = "offline mode: all network access is disabled"
        elif self.allowed_domains is not None and not any(host == d or host.endswith("." + d) for d in self.allowed_domains):
            reason = f"domain '{host}' is not in the allow-list"
        self.log.append(OutboundEvent(time.time(), host, url, purpose, not reason, reason))
        if reason:
            raise UrlRejected(reason)

    def clear(self) -> None:
        self.log.clear()

    def format_log(self) -> str:
        if not self.log:
            return "Outbound requests: none (nothing left this machine)."
        lines = ["Outbound requests this session (exactly what was sent):"]
        for e in self.log:
            t = time.strftime("%H:%M:%S", time.localtime(e.timestamp))
            lines.append(f"  {t} {'ALLOW' if e.allowed else 'BLOCK'} {e.url}" + (f"  [{e.reason}]" if e.reason else "")
                         + (f"  ({e.purpose})" if e.purpose else ""))
        return "\n".join(lines)
