import http.server
import socketserver
import threading
import unittest
import json

import _bootstrap  # noqa: F401
from net_guard import UrlRejected, validate_url
from network_pipeline import NetworkPipeline, _GuardedRedirect
from outbound_policy import OutboundPolicy
from raw_http import RawHttpClient

PROSE = ("A pure reasoning engine is a stateless cognitive architecture that avoids storing gigabytes of "
         "factual weights and instead relies on real-time ingestion of verified information. " * 2)


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/html":
            body = f"<html><body><p>{PROSE}</p><script>evil()</script></body></html>".encode()
            self._send(200, "text/html; charset=utf-8", body)
        elif self.path == "/json":
            self._send(200, "application/json", json.dumps({"a": 1}).encode())
        elif self.path == "/binary":
            self._send(200, "application/octet-stream", b"\x00\x01" * 100)
        elif self.path == "/big":
            self._send(200, "text/plain", (PROSE.encode()) * 200)
        elif self.path == "/chunked":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            data = PROSE.encode()
            for i in range(0, len(data), 50):
                part = data[i:i + 50]
                self.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/html")
            self.end_headers()
        elif self.path == "/404":
            self._send(404, "text/plain", b"nope")
        else:
            self._send(404, "text/plain", b"nope")

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Server:
    def __enter__(self):
        class Quiet(socketserver.ThreadingTCPServer):
            def handle_error(self, request, client_address):  # clients that hit the byte cap hang up early
                pass

        self.srv = Quiet(("127.0.0.1", 0), _Handler)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"
        return self

    def __exit__(self, *a):
        self.srv.shutdown()
        self.srv.server_close()


class UrlPolicy(unittest.TestCase):
    def test_rejected_urls(self):
        for url in ("file:///etc/passwd", "ftp://example.com/x", "gopher://x/", "http://127.0.0.1/",
                    "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://10.0.0.5/",
                    "https://user:pw@example.com/", "http://127.0.0.1:8080/", "", "javascript:alert(1)"):
            with self.assertRaises(UrlRejected, msg=url):
                validate_url(url)

    def test_private_allowed_only_when_explicit(self):
        validate_url("http://127.0.0.1:8080/", allow_private=True)

    def test_redirect_into_private_space_is_blocked(self):
        h = _GuardedRedirect(allow_private=False)
        with self.assertRaises(UrlRejected):
            h.redirect_request(None, None, 302, "Found", {}, "http://169.254.169.254/")

    def test_pipeline_surfaces_policy_error_instead_of_fake_content(self):
        r = NetworkPipeline().fetch_url("file:///etc/hostname")
        self.assertFalse(r.is_valid)
        self.assertIn("outbound policy", r.rejection_reason)

    def test_bad_language_code_rejected(self):
        r = NetworkPipeline().query_live_knowledge("rust", lang="evil.com/x")
        self.assertFalse(r.is_valid)
        self.assertIn("Invalid language", r.rejection_reason)


class Transports(unittest.TestCase):
    def check_transport(self, transport):
        with Server() as s:
            net = NetworkPipeline(transport=transport, allow_private=True, timeout_sec=3, policy=OutboundPolicy(allowed_domains=None))
            ok = net.fetch_url(s.base + "/html")
            self.assertTrue(ok.is_valid, ok.rejection_reason)
            self.assertIn("stateless cognitive architecture", ok.sanitized_text)
            self.assertNotIn("evil()", ok.sanitized_text)
            self.assertTrue(net.fetch_url(s.base + "/redirect").is_valid)  # redirect followed
            self.assertIn("content type", net.fetch_url(s.base + "/binary").rejection_reason)
            self.assertIn("404", net.fetch_url(s.base + "/404").rejection_reason)
            big = net.fetch_url(s.base + "/big", max_bytes=2000)
            self.assertTrue(big.truncated)
            self.assertLessEqual(big.cleaned_size_bytes, 2000)

    def test_urllib_transport(self):
        self.check_transport("urllib")

    def test_raw_socket_transport(self):
        self.check_transport("raw")

    def test_raw_chunked_decoding(self):
        with Server() as s:
            r = RawHttpClient(allow_private=True, timeout=3).get(s.base + "/chunked")
            self.assertEqual(r.status, 200)
            self.assertEqual(r.body, PROSE.encode())

    def test_raw_cap_is_enforced_on_chunked_and_length(self):
        with Server() as s:
            c = RawHttpClient(allow_private=True, timeout=3)
            for path in ("/chunked", "/big"):
                r = c.get(s.base + path, max_bytes=100)
                self.assertTrue(r.truncated, path)
                self.assertLessEqual(len(r.body), 100, path)

    def test_connection_refused_is_a_clean_error(self):
        r = NetworkPipeline(allow_private=True, timeout_sec=1, policy=OutboundPolicy(allowed_domains=None)).fetch_url("http://127.0.0.1:9/")
        self.assertFalse(r.is_valid)
        self.assertIn("Network error", r.rejection_reason)


if __name__ == "__main__":
    unittest.main()
