"""
Minimal raw-socket HTTP/1.1 client (socket + ssl, no urllib/http.client).

Purpose: validate the Phase 2 design (C++ Winsock/IOCP pipeline) in Python first:
  * connects to the IP already validated by net_guard (DNS-rebinding safe), TLS SNI = real host
  * hard caps: header size, body size, total wall-clock deadline (slow-loris protection)
  * understands Content-Length, chunked, and read-until-close; requests Accept-Encoding: identity
  * does NOT follow redirects (caller decides, re-validating each hop)

EXPERIMENTAL: verified against a local test server only; keep NetworkPipeline's default
transport ("urllib") for real use until it has been exercised against live HTTPS endpoints.
"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass
from typing import Dict, Optional

from net_guard import validate_url

MAX_HEADER_BYTES = 64 * 1024


class RawHttpError(Exception):
    pass


@dataclass
class RawResponse:
    status: int
    reason: str
    headers: Dict[str, str]  # lower-cased names
    body: bytes
    truncated: bool
    remote_ip: str


class _Reader:
    def __init__(self, sock: socket.socket, deadline: float):
        self.sock, self.deadline, self.buf = sock, deadline, b""

    def _fill(self) -> bool:
        if time.monotonic() > self.deadline:
            raise RawHttpError("total deadline exceeded")
        chunk = self.sock.recv(65536)
        if not chunk:
            return False
        self.buf += chunk
        return True

    def read_until(self, delim: bytes, limit: int) -> bytes:
        while delim not in self.buf:
            if len(self.buf) > limit:
                raise RawHttpError("header section too large")
            if not self._fill():
                raise RawHttpError("connection closed before delimiter")
        head, _, self.buf = self.buf.partition(delim)
        return head

    def read(self, n: int) -> bytes:
        while len(self.buf) < n:
            if not self._fill():
                break
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def read_to_close(self, limit: int) -> bytes:
        while len(self.buf) <= limit and self._fill():
            pass
        out, self.buf = self.buf[: limit + 1], b""
        return out


class RawHttpClient:
    def __init__(self, timeout: float = 6.0, total_timeout: float = 15.0, max_bytes: int = 4 * 1024 * 1024,
                 allow_private: bool = False, user_agent: str = "PersonalAgenticAI/1.1 (raw-socket)"):
        self.timeout, self.total_timeout = timeout, total_timeout
        self.max_bytes, self.allow_private, self.user_agent = max_bytes, allow_private, user_agent

    def get(self, url: str, accept: str = "*/*", max_bytes: Optional[int] = None) -> RawResponse:
        limit = max_bytes if max_bytes is not None else self.max_bytes
        parts, ips = validate_url(url, self.allow_private)
        https = parts.scheme.lower() == "https"
        port = parts.port or (443 if https else 80)
        host = parts.hostname or ""
        path = urllib.parse.quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
        if parts.query:
            path += "?" + parts.query
        host_header = host if parts.port in (None, 80, 443) else f"{host}:{port}"
        deadline = time.monotonic() + self.total_timeout

        sock = socket.create_connection((ips[0], port), timeout=self.timeout)
        try:
            if https:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            req = (f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {self.user_agent}\r\n"
                   f"Accept: {accept}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
            sock.sendall(req.encode("ascii"))
            rd = _Reader(sock, deadline)

            head = rd.read_until(b"\r\n\r\n", MAX_HEADER_BYTES).decode("iso-8859-1")
            lines = head.split("\r\n")
            try:
                _, status_s, *reason = lines[0].split(" ", 2)
                status = int(status_s)
            except ValueError:
                raise RawHttpError(f"bad status line: {lines[0][:80]!r}")
            headers: Dict[str, str] = {}
            for ln in lines[1:]:
                k, sep, v = ln.partition(":")
                if sep:
                    headers[k.strip().lower()] = v.strip()

            truncated = False
            if "chunked" in headers.get("transfer-encoding", "").lower():
                body = bytearray()
                while True:
                    size_line = rd.read_until(b"\r\n", 1024).split(b";")[0].strip()
                    try:
                        size = int(size_line, 16)
                    except ValueError:
                        raise RawHttpError("bad chunk size")
                    if size == 0:
                        break
                    want = min(size, limit + 1 - len(body))  # never buffer more than the cap
                    chunk = rd.read(want)
                    if len(chunk) < want:
                        raise RawHttpError("connection closed mid-chunk")
                    body += chunk
                    if size > want or len(body) > limit:
                        truncated = True
                        break
                    rd.read(2)  # CRLF terminating the chunk
                data = bytes(body[:limit])
            elif "content-length" in headers:
                try:
                    clen = int(headers["content-length"])
                except ValueError:
                    raise RawHttpError("bad Content-Length")
                data = rd.read(min(clen, limit + 1))
                truncated = clen > limit or len(data) > limit
                data = data[:limit]
            else:
                data = rd.read_to_close(limit)
                truncated = len(data) > limit
                data = data[:limit]
            return RawResponse(status, " ".join(reason), headers, data, truncated, ips[0])
        except (socket.timeout, TimeoutError):
            raise RawHttpError("socket timeout")
        finally:
            try:
                sock.close()
            except Exception:
                pass
