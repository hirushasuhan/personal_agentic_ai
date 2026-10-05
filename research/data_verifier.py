"""
Data Verifier & Sanitization Module (Python Research Prototype)
Part of Personal Agentic AI (PAI) - The Direct Ingestion Pillar.

Everything arriving from the network is UNTRUSTED. This module:
  1. extracts visible text with a real HTML parser (not regexes),
  2. truncates by BYTES (never splits a UTF-8 character),
  3. scores quality in a Unicode-aware way (Sinhala/Tamil/CJK are first-class),
  4. scans for prompt-injection phrases aimed at the reasoning engine.
"""

from __future__ import annotations

import html
import re
import unicodedata
import zlib
import math
from collections import Counter
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import List, Tuple

# Tags whose content is never visible prose.
_SKIP_TAGS = {"script", "style", "svg", "noscript", "template", "iframe", "nav", "footer", "aside", "canvas", "object", "embed"}
_BLOCK_TAGS = {"p", "div", "br", "li", "ul", "ol", "tr", "table", "section", "article", "main", "header",
               "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "hr", "dd", "dt", "dl"}

# (flag name, pattern) - heuristics, not a guarantee. See docs/THREAT_MODEL.md (T3).
INJECTION_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("ignore-previous-instructions", re.compile(r"\b(ignore|disregard|forget)\b[^.\n]{0,30}\b(previous|prior|above|earlier|all)\b[^.\n]{0,30}\b(instructions?|prompts?|rules|guidelines)\b", re.I)),
    ("role-reassignment", re.compile(r"\byou are (now|no longer)\b|\bfrom now on,? you\b|\bnew instructions?\s*:", re.I)),
    ("prompt-exfiltration", re.compile(r"\b(reveal|print|show|repeat|output)\b[^.\n]{0,20}\b(your|the)\b[^.\n]{0,15}\b(system|hidden|initial|secret) (prompt|instructions?)\b", re.I)),
    ("chat-template-tokens", re.compile(r"</?(system|assistant|user)>|<\|(im_start|im_end|system|endoftext)\|>|\[/?INST\]", re.I)),
    ("secret-exfiltration", re.compile(r"\b(send|post|upload|email|exfiltrate)\b[^.\n]{0,50}\b(api[_ -]?keys?|passwords?|secrets?|tokens?|credentials?)\b", re.I)),
    ("conceal-from-user", re.compile(r"\b(do not|don't|never) (tell|inform|show|mention)[^.\n]{0,20}\bthe user\b", re.I)),
]


@dataclass
class VerifiedPayload:
    is_valid: bool
    quality_score: float  # 0.0 to 1.0
    sanitized_text: str
    original_size_bytes: int
    cleaned_size_bytes: int
    rejection_reason: str = ""
    injection_flags: Tuple[str, ...] = ()
    truncated: bool = False
    source: str = ""


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_startendtag(self, tag, attrs):
        if tag.lower() in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in _SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        if self._skip_depth == 0:
            self.parts.append(data)


_WS = re.compile(r"[ \t\r\f\v ]+")
_NL = re.compile(r"\n\s*\n+")


class DataVerifier:
    def __init__(self, min_quality_threshold: float = 0.35, min_chars: int = 40,
                 injection_policy: str = "reject"):
        """injection_policy: 'reject' (default, security-first) or 'flag' (keep text, report flags)."""
        if injection_policy not in ("reject", "flag"):
            raise ValueError("injection_policy must be 'reject' or 'flag'")
        self.min_quality_threshold = min_quality_threshold
        self.min_chars = min_chars
        self.injection_policy = injection_policy

    # ------------------------------------------------------------------ public
    def sanitize_and_verify(self, raw_content: str, max_bytes_allowed: int = 16 * 1024 * 1024,
                            source: str = "") -> VerifiedPayload:
        """Sanitizes raw HTML or text payloads and evaluates quality."""
        if not raw_content or not raw_content.strip():
            return VerifiedPayload(False, 0.0, "", 0, 0, "Empty or null content payload.", source=source)

        raw_bytes = raw_content.encode("utf-8", errors="replace")
        orig_bytes = len(raw_bytes)
        truncated = orig_bytes > max_bytes_allowed
        if truncated:  # byte-accurate cut that never splits a multi-byte character
            raw_content = raw_bytes[:max_bytes_allowed].decode("utf-8", errors="ignore")
        del raw_bytes

        clean_text = self._extract_text(raw_content)
        cleaned_bytes = len(clean_text.encode("utf-8"))

        score, reason = self._compute_quality_score(clean_text)
        flags = tuple(self._scan_injection(clean_text))
        if flags:
            score = max(0.0, score - 0.3)
            if self.injection_policy == "reject":
                reason = reason or f"Possible prompt-injection content: {', '.join(flags)}"
                score = min(score, 0.1)

        is_valid = score >= self.min_quality_threshold and not reason
        return VerifiedPayload(
            is_valid=is_valid,
            quality_score=round(score, 2),
            sanitized_text=clean_text if is_valid else "",
            original_size_bytes=orig_bytes,
            cleaned_size_bytes=cleaned_bytes,
            rejection_reason="" if is_valid else (reason or f"Quality score {score:.2f} below threshold {self.min_quality_threshold}."),
            injection_flags=flags,
            truncated=truncated,
            source=source,
        )

    # --------------------------------------------------------------- internals
    @staticmethod
    def _extract_text(raw: str) -> str:
        parser = _TextExtractor()
        try:
            parser.feed(raw)
            parser.close()
        except Exception:
            # Malformed markup must never crash ingestion: fall back to a crude strip.
            return _NL.sub("\n\n", _WS.sub(" ", re.sub(r"<[^>]*>", " ", html.unescape(raw)))).strip()
        text = "".join(parser.parts)
        text = "\n".join(_WS.sub(" ", ln).strip() for ln in text.split("\n"))
        return _NL.sub("\n\n", text).strip()

    @staticmethod
    def _scan_injection(text: str) -> List[str]:
        return [name for name, pat in INJECTION_PATTERNS if pat.search(text)]

    def _compute_quality_score(self, text: str) -> Tuple[float, str]:
        """Heuristic quality score from letter density, entropy, compressibility and length."""
        if len(text) < self.min_chars:
            return 0.1, "Payload too brief to extract meaningful factual reasoning."

        # Letters AND combining marks (category L*/M*) so Sinhala/Tamil/Hindi vowel signs count.
        non_space = [c for c in text if not c.isspace()]
        if not non_space:
            return 0.0, "Payload contains only whitespace."
        letters = sum(1 for c in non_space if unicodedata.category(c)[0] in ("L", "M"))
        letter_ratio = letters / len(non_space)
        if letter_ratio < 0.4:
            return 0.2, "Excessive non-textual symbols or binary garbage detected."

        n = len(text)
        entropy = -sum((c / n) * math.log2(c / n) for c in Counter(text).values())
        if entropy < 2.5:
            return 0.25, "Low entropy (repetitive patterns or spam detected)."

        raw = text.encode("utf-8")
        if len(raw) >= 200 and len(zlib.compress(raw, 6)) / len(raw) < 0.12:
            return 0.25, "Highly repetitive content (compression ratio) - likely spam."

        if len(text.split()) < 10 and n < 200:
            return 0.3, "Insufficient word count for cognitive deduction."

        score = min(1.0, 0.4 + (letter_ratio * 0.4) + (min(entropy, 4.5) / 4.5 * 0.2))
        return score, ""


if __name__ == "__main__":
    verifier = DataVerifier()
    sample_html = """
    <html>
        <head><title>Test Page</title><script>alert('malicious')</script></head>
        <body>
            <nav><a href="#">Home</a><a href="#">About</a></nav>
            <h1>Understanding Pure Reasoning AI Engines</h1>
            <p>A pure reasoning engine is a stateless cognitive architecture that avoids storing gigabytes of factual weights.</p>
            <p>Instead, it relies on real-time sensory ingestion and immediate memory deallocation to maintain peak efficiency.</p>
        </body>
    </html>
    """
    result = verifier.sanitize_and_verify(sample_html)
    print("--- Data Verifier Test ---")
    print(f"Is Valid: {result.is_valid} | Score: {result.quality_score} | Flags: {result.injection_flags}")
    print(f"Original Size: {result.original_size_bytes}B -> Cleaned: {result.cleaned_size_bytes}B")
    print(f"Sanitized Text Preview:\n{result.sanitized_text}")
