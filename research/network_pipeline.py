"""
Direct Network Ingestion Pipeline (Python Research Prototype)
Part of Personal Agentic AI (PAI) - The Direct Ingestion Pillar.

Streams live internet data directly into memory over plain HTTP(S) - no headless browser.

Security properties (see docs/THREAT_MODEL.md):
  * every URL (and every redirect hop) passes net_guard.validate_url -> no file://, no SSRF
  * hard byte caps on every read
  * transport errors are reported as errors; they are NEVER fed to the verifier as "knowledge"
  * `lang` is whitelisted before being placed in a hostname

Transports: "urllib" (default, battle-tested) | "raw" (socket+ssl, experimental, see raw_http.py)
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional, Tuple

from data_verifier import DataVerifier, VerifiedPayload
from net_guard import UrlRejected, validate_url
from outbound_policy import OutboundPolicy
from raw_http import RawHttpClient, RawHttpError

USER_AGENT = "PersonalAgenticAI/1.1 (Direct Socket Ingestion; Stateless Core)"
_LANG_RE = re.compile(r"^[a-z]{2,3}(-[a-z]{2,8})?$")
_TEXT_TYPES = ("text/", "application/json", "application/xml", "application/xhtml+xml")


class NetworkError(Exception):
    pass


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3

    def __init__(self, allow_private: bool, policy: Optional[OutboundPolicy] = None):
        self.allow_private = allow_private
        self.policy = policy

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl, self.allow_private)  # raises UrlRejected -> caught in _http_get
        if self.policy:
            self.policy.check(newurl, "redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class NetworkPipeline:
    def __init__(self, timeout_sec: float = 6.0, transport: str = "urllib", allow_private: bool = False,
                 verifier: Optional[DataVerifier] = None, policy: Optional[OutboundPolicy] = None):
        if transport not in ("urllib", "raw"):
            raise ValueError("transport must be 'urllib' or 'raw'")
        self.timeout_sec = timeout_sec
        self.transport = transport
        self.allow_private = allow_private
        self.verifier = verifier or DataVerifier()
        self.policy = policy or OutboundPolicy()  # default: Wikipedia + DuckDuckGo only, logged
        self.default_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/json,text/plain;q=0.9,*/*;q=0.8",
        }
        self._raw = RawHttpClient(timeout=timeout_sec, allow_private=allow_private, user_agent=USER_AGENT)

    # ------------------------------------------------------------------ public
    def fetch_url(self, url: str, max_bytes: int = 4 * 1024 * 1024) -> VerifiedPayload:
        """Fetches a URL directly and passes it through the verifier."""
        try:
            content_type, body, truncated = self._http_get(url, max_bytes, purpose="fetch_url")
        except NetworkError as e:
            return self._failed(f"Network error: {e}", url)
        if not content_type.lower().startswith(_TEXT_TYPES):
            return self._failed(f"Unsupported content type '{content_type or 'unknown'}' (text/JSON/XML only).", url)
        text = self._decode(body, content_type)
        payload = self.verifier.sanitize_and_verify(text, max_bytes_allowed=max_bytes, source=url)
        payload.truncated = payload.truncated or truncated
        return payload

    def query_live_knowledge(self, topic: str, max_bytes: int = 1024 * 1024, lang: str = "en") -> VerifiedPayload:
        """
        Resolves a topic to a Wikipedia page (search -> summary) and falls back to DuckDuckGo's
        Instant Answer API. `lang` selects the Wikipedia edition ("si" = Sinhala).
        """
        topic = (topic or "").strip()
        if not topic:
            return self._failed("Empty topic.", "")
        if not _LANG_RE.match(lang or ""):
            return self._failed(f"Invalid language code '{lang}'.", "")

        wiki_error = ""
        try:
            title = self._wikipedia_resolve_title(topic, lang)
            if title:
                summary_url = f"https://{lang}.wikipedia.org/api/rest_v1/page/summary/{urllib.parse.quote(title.replace(' ', '_'), safe='')}"
                _, body, _ = self._http_get(summary_url, max_bytes, accept="application/json", purpose="wikipedia summary")
                data = json.loads(body.decode("utf-8", errors="replace"))
                text = f"TOPIC: {data.get('title', '')}\nDESCRIPTION: {data.get('description', '')}\n\nSUMMARY:\n{data.get('extract', '')}"
                return self.verifier.sanitize_and_verify(text, max_bytes_allowed=max_bytes, source=summary_url)
        except (NetworkError, ValueError) as e:  # ValueError covers JSON errors
            wiki_error = str(e)

        fallback = self._duckduckgo(topic, max_bytes)
        if not fallback.is_valid and wiki_error:
            fallback.rejection_reason = f"Wikipedia: {wiki_error} | DuckDuckGo: {fallback.rejection_reason}"
        return fallback

    # --------------------------------------------------------------- internals
    def _wikipedia_resolve_title(self, topic: str, lang: str) -> Optional[str]:
        url = f"https://{lang}.wikipedia.org/w/rest.php/v1/search/title?q={urllib.parse.quote(topic)}&limit=1"
        _, body, _ = self._http_get(url, 256 * 1024, accept="application/json", purpose="wikipedia title search")
        pages = json.loads(body.decode("utf-8", errors="replace")).get("pages", [])
        if pages:
            return pages[0].get("title")
        # Fallback to full-text search/page for compound queries (e.g. 'Rust ownership' -> 'Rust (programming language)')
        page_url = f"https://{lang}.wikipedia.org/w/rest.php/v1/search/page?q={urllib.parse.quote(topic)}&limit=1"
        _, pbody, _ = self._http_get(page_url, 256 * 1024, accept="application/json", purpose="wikipedia page search")
        ppages = json.loads(pbody.decode("utf-8", errors="replace")).get("pages", [])
        return ppages[0].get("title") if ppages else None

    def _duckduckgo(self, query: str, max_bytes: int) -> VerifiedPayload:
        url = f"https://api.duckduckgo.com/?q={urllib.parse.quote_plus(query)}&format=json&no_html=1&skip_disambig=1"
        try:
            _, body, _ = self._http_get(url, 256 * 1024, accept="application/json", purpose="duckduckgo fallback")
            data = json.loads(body.decode("utf-8", errors="replace"))
        except (NetworkError, ValueError) as e:
            return self._failed(f"Search fallback failed: {e}", url)
        abstract = (data.get("AbstractText") or "").strip()
        if not abstract:
            return self._failed("Search fallback returned no abstract for this query.", url)
        raw = f"HEADING: {data.get('Heading') or query}\nDETAILS: {abstract}"
        return self.verifier.sanitize_and_verify(raw, max_bytes_allowed=max_bytes, source=url)

    def _http_get(self, url: str, max_bytes: int, accept: Optional[str] = None, purpose: str = "") -> Tuple[str, bytes, bool]:
        """Returns (content_type, body_bytes, truncated). Raises NetworkError on any failure."""
        try:
            self.policy.check(url, purpose)  # allow-list / offline mode / visible log (ADR-002)
            if self.transport == "raw":
                return self._raw_get(url, max_bytes, accept)
            validate_url(url, self.allow_private)
            headers = dict(self.default_headers)
            if accept:
                headers["Accept"] = accept
            opener = urllib.request.build_opener(_GuardedRedirect(self.allow_private, self.policy))
            with opener.open(urllib.request.Request(url, headers=headers), timeout=self.timeout_sec) as resp:
                body = resp.read(max_bytes + 1)  # +1 detects truncation
                return resp.headers.get("Content-Type", ""), body[:max_bytes], len(body) > max_bytes
        except UrlRejected as e:
            raise NetworkError(f"URL rejected by outbound policy: {e}")
        except urllib.error.HTTPError as e:
            raise NetworkError(f"HTTP {e.code} {e.reason}")
        except urllib.error.URLError as e:
            raise NetworkError(f"connection failed: {e.reason}")
        except (TimeoutError, OSError) as e:
            raise NetworkError(f"{type(e).__name__}: {e}")

    def _raw_get(self, url: str, max_bytes: int, accept: Optional[str]) -> Tuple[str, bytes, bool]:
        for _ in range(4):  # initial request + up to 3 redirects, each re-validated
            try:
                r = self._raw.get(url, accept=accept or self.default_headers["Accept"], max_bytes=max_bytes)
            except RawHttpError as e:
                raise NetworkError(str(e))
            if r.status in (301, 302, 303, 307, 308) and "location" in r.headers:
                url = urllib.parse.urljoin(url, r.headers["location"])
                self.policy.check(url, "redirect")
                continue
            if r.status >= 400:
                raise NetworkError(f"HTTP {r.status} {r.reason}")
            return r.headers.get("content-type", ""), r.body, r.truncated
        raise NetworkError("too many redirects")

    @staticmethod
    def _decode(body: bytes, content_type: str) -> str:
        m = re.search(r"charset=([\w.\-]+)", content_type, re.I)
        try:
            return body.decode(m.group(1) if m else "utf-8", errors="replace")
        except LookupError:
            return body.decode("utf-8", errors="replace")

    @staticmethod
    def _failed(reason: str, source: str) -> VerifiedPayload:
        return VerifiedPayload(False, 0.0, "", 0, 0, reason, source=source)


if __name__ == "__main__":
    net = NetworkPipeline()
    print("Testing direct knowledge ingestion for topic: 'Rust (programming language)'...")
    res = net.query_live_knowledge("Rust (programming language)")
    print(f"Is Valid: {res.is_valid} | Score: {res.quality_score}")
    print(f"Reason: {res.rejection_reason}" if not res.is_valid else f"Ingested text snippet:\n{res.sanitized_text[:200]}...")
