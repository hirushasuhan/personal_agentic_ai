"""
Local knowledge sources (ADR-002): answer from files on this machine - no network at all.

LocalKnowledge     : keyword search over a directory of .txt/.md files (your notes, offline docs)
CompositeKnowledge : try sources in order (e.g. local first, then network) and return the first valid payload

Both expose the same `query_live_knowledge(topic, max_bytes, lang)` as NetworkPipeline, so they plug
into StatelessAgentCore unchanged. Content still goes through DataVerifier (it is untrusted too: a
downloaded file can contain injected instructions).
"""

from __future__ import annotations

import os
import re
from typing import List, Optional, Sequence, Tuple

from data_verifier import DataVerifier, VerifiedPayload


class LocalKnowledge:
    def __init__(self, root: str, verifier: Optional[DataVerifier] = None, extensions: Tuple[str, ...] = (".txt", ".md"),
                 max_file_bytes: int = 2 * 1024 * 1024, max_files: int = 2000):
        self.root = os.path.realpath(root)
        if not os.path.isdir(self.root):
            raise ValueError(f"knowledge directory not found: {root}")
        self.verifier = verifier or DataVerifier()
        self.extensions = tuple(e.lower() for e in extensions)
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files

    def _candidates(self):
        count = 0
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                if not fn.lower().endswith(self.extensions) or os.path.islink(full):
                    continue
                real = os.path.realpath(full)
                if os.path.commonpath([real, self.root]) != self.root:  # never leave the root
                    continue
                count += 1
                if count > self.max_files:
                    return
                yield real

    def query_live_knowledge(self, topic: str, max_bytes: int = 1 << 20, lang: str = "en") -> VerifiedPayload:
        tokens = [t for t in re.findall(r"\w+", (topic or "").lower()) if len(t) >= 2]
        if not tokens:
            return VerifiedPayload(False, 0.0, "", 0, 0, "Empty topic.", source="local")
        best: Optional[Tuple[int, str]] = None
        for path in self._candidates():
            try:
                with open(path, "rb") as f:
                    text = f.read(self.max_file_bytes).decode("utf-8", errors="replace").lower()
            except OSError:
                continue
            name = os.path.basename(path).lower()
            score = sum(5 for t in tokens if t in name) + sum(min(text.count(t), 20) for t in tokens)
            if score > 0 and (best is None or score > best[0]):
                best = (score, path)
        if best is None:
            return VerifiedPayload(False, 0.0, "", 0, 0, "No local document matches this topic.", source="local")
        with open(best[1], "rb") as f:
            raw = f.read(min(self.max_file_bytes, max_bytes)).decode("utf-8", errors="replace")
        rel = os.path.relpath(best[1], self.root)
        return self.verifier.sanitize_and_verify(raw, max_bytes_allowed=max_bytes, source=f"local:{rel}")


class CompositeKnowledge:
    def __init__(self, sources: Sequence[object]):
        self.sources = list(sources)

    def query_live_knowledge(self, topic: str, max_bytes: int = 1 << 20, lang: str = "en") -> VerifiedPayload:
        reasons: List[str] = []
        for src in self.sources:
            p = src.query_live_knowledge(topic, max_bytes=max_bytes, lang=lang)
            if p.is_valid:
                return p
            reasons.append(f"{p.source or type(src).__name__}: {p.rejection_reason}")
        return VerifiedPayload(False, 0.0, "", 0, 0, " | ".join(reasons) or "No knowledge sources configured.")
