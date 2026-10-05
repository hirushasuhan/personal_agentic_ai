"""
Outbound URL guard (SSRF / local-file-read protection) for the Direct Ingestion pillar.

Rules enforced before ANY connection:
  * scheme must be http or https (blocks file://, ftp://, gopher:// ...)
  * no embedded credentials (user:pass@host) - classic URL-confusion trick
  * port must be 80 or 443 (unless allow_private=True, used by tests)
  * every resolved IP must be globally routable - blocks loopback, RFC1918,
    link-local (169.254.169.254 cloud metadata), multicast, reserved

Known gap (documented): a plain urllib request re-resolves DNS, so a DNS-rebinding
attacker could win a race. RawHttpClient avoids this by connecting to the IP validated here.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from typing import List, Tuple

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}


class UrlRejected(ValueError):
    """Raised when a URL violates the outbound policy."""


def validate_url(url: str, allow_private: bool = False) -> Tuple[urllib.parse.SplitResult, List[str]]:
    """Returns (parsed_url, validated_ips) or raises UrlRejected."""
    if not isinstance(url, str) or not url.strip():
        raise UrlRejected("empty URL")
    parts = urllib.parse.urlsplit(url.strip())
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise UrlRejected(f"scheme '{parts.scheme or '(none)'}' not allowed (http/https only)")
    host = parts.hostname
    if not host:
        raise UrlRejected("URL has no host")
    if parts.username is not None or parts.password is not None:
        raise UrlRejected("credentials in URL are not allowed")
    try:
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except ValueError:
        raise UrlRejected("invalid port")
    if not allow_private and port not in ALLOWED_PORTS:
        raise UrlRejected(f"port {port} not allowed")

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise UrlRejected(f"DNS resolution failed: {e}")

    ips: List[str] = []
    for info in infos:
        raw_ip = info[4][0].split("%")[0]
        ip = ipaddress.ip_address(raw_ip)
        if ip.version == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if not allow_private and (not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified
                                  or ip.is_loopback or ip.is_link_local or ip.is_private):
            raise UrlRejected(f"{host} resolves to non-public address {ip}")
        if str(ip) not in ips:
            ips.append(str(ip))
    if not ips:
        raise UrlRejected("no addresses resolved")
    return parts, ips
