"""
Outbound URL guard (SSRF / local-file-read protection) for the Direct Ingestion pillar.
Matches docs/NET_POLICY.md and core/src/url_policy.rs.

Rules enforced before ANY connection:
  * ASCII only, no whitespace, control characters, or backslashes
  * scheme must be http or https (case-insensitive)
  * no credentials or '@' in authority
  * port must be 80 or 443 (unless allow_private=True, used by tests)
  * IP literal must be canonical (no octal, hex, dword, or partial dotted IPv4)
  * every IP must not match the Canonical Blocked CIDR table (RFC 1918, RFC 3927,
    loopback, multicast, carrier-grade NAT, reserved, broadcast, ULA, link-local)
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from typing import List, Tuple, Union

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}

# Canonical Blocked CIDR Table (docs/NET_POLICY.md)
BLOCKED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # RFC 1122 This host
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # RFC 6598 Carrier-Grade NAT
    ipaddress.ip_network("127.0.0.0/8"),        # RFC 1122 Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # RFC 3927 Link-Local / Metadata
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # RFC 6890 IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # RFC 5737 TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # RFC 2544 Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # RFC 5737 TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # RFC 5737 TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # RFC 5771 Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # RFC 1112 Reserved / Class E
    ipaddress.ip_network("255.255.255.255/32"), # RFC 919 Broadcast
]

BLOCKED_IPV6_NETWORKS = [
    ipaddress.ip_network("::/128"),             # RFC 4291 Unspecified
    ipaddress.ip_network("::1/128"),            # RFC 4291 Loopback
    ipaddress.ip_network("100::/64"),           # RFC 6666 Discard-Only
    ipaddress.ip_network("2001:db8::/32"),      # RFC 3849 Documentation
    ipaddress.ip_network("fc00::/7"),           # RFC 4193 ULA / Private
    ipaddress.ip_network("fe80::/10"),          # RFC 4291 Link-Local
    ipaddress.ip_network("ff00::/8"),           # RFC 4291 Multicast
]


class UrlRejected(ValueError):
    """Raised when a URL violates the outbound policy."""


def is_ip_blocked(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """Checks whether an IP address belongs to any blocked CIDR range."""
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            return is_ip_blocked(ip.ipv4_mapped)
        return any(ip in net for net in BLOCKED_IPV6_NETWORKS)
    return any(ip in net for net in BLOCKED_IPV4_NETWORKS)


def validate_resolved_ips(ips: List[Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]],
                          allow_private: bool = False) -> List[str]:
    """Pure validator for resolved IP addresses."""
    if not ips:
        raise UrlRejected("no addresses resolved")
    out: List[str] = []
    for raw in ips:
        ip = ipaddress.ip_address(raw) if not isinstance(raw, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else raw
        if not allow_private and is_ip_blocked(ip):
            raise UrlRejected(f"address {ip} is blocked by outbound policy")
        if str(ip) not in out:
            out.append(str(ip))
    return out


def validate_url(url: str, allow_private: bool = False) -> Tuple[urllib.parse.SplitResult, List[str]]:
    """Returns (parsed_url, validated_ips) or raises UrlRejected."""
    if not isinstance(url, str) or not url:
        raise UrlRejected("empty URL")

    # Strict ASCII and character hygiene
    for ch in url:
        code = ord(ch)
        if code > 127:
            raise UrlRejected("non-ASCII character not allowed")
        if code <= 32 or code == 127:
            raise UrlRejected("whitespace or control character in URL")
        if ch == "\\":
            raise UrlRejected("backslash character not allowed in URL")

    if "://" not in url:
        raise UrlRejected("missing scheme delimiter '://'")

    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlRejected(f"scheme '{parts.scheme or '(none)'}' not allowed (http/https only)")

    # Validate authority directly to catch non-standard structures before urllib normalization
    authority = url.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if not authority:
        raise UrlRejected("URL has no host")
    if "@" in authority:
        raise UrlRejected("credentials or '@' not allowed in URL")

    # Extract host and port
    if authority.startswith("["):
        closing = authority.find("]")
        if closing == -1:
            raise UrlRejected("unmatched '[' in IPv6 authority")
        host_str = authority[1:closing]
        port_part = authority[closing + 1:]
        if port_part and not port_part.startswith(":"):
            raise UrlRejected("invalid trailing data after ']'")
        port_str = port_part[1:] if port_part.startswith(":") else None
        is_ipv6 = True
    else:
        if ":" in authority:
            host_str, port_str = authority.split(":", 1)
            if ":" in port_str:
                raise UrlRejected("multiple colons in host without brackets")
        else:
            host_str, port_str = authority, None
        is_ipv6 = False

    if not host_str:
        raise UrlRejected("URL has no host")

    # Port validation
    if port_str is not None:
        if not port_str or not port_str.isdigit():
            raise UrlRejected("invalid port")
        port = int(port_str)
        if port < 1 or port > 65535:
            raise UrlRejected(f"port {port} out of range")
        if not allow_private and port not in ALLOWED_PORTS:
            raise UrlRejected(f"port {port} not allowed")
    else:
        port = 443 if scheme == "https" else 80

    # Host validation: IP literal or DNS name
    literal_ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address, None] = None
    if is_ipv6:
        try:
            literal_ip = ipaddress.IPv6Address(host_str)
        except ValueError as e:
            raise UrlRejected(f"invalid IPv6 literal: {e}")
    else:
        # Check canonical dotted-decimal IPv4
        octets = host_str.split(".")
        if len(octets) == 4 and all(o.isdigit() for o in octets):
            if any(len(o) > 1 and o.startswith("0") for o in octets):
                raise UrlRejected("non-canonical IPv4: octal leading zero not permitted")
            if any(int(o) > 255 for o in octets):
                raise UrlRejected("IPv4 octet exceeds 255")
            literal_ip = ipaddress.IPv4Address(host_str)
        elif any(c.isdigit() for c in host_str) and (
            "." in host_str or host_str.isdigit() or host_str.lower().startswith("0x")
        ):
            # Hex, octal, dword integer (e.g., 2130706433), or partial dotted (127.1)
            raise UrlRejected(f"non-canonical IPv4 format '{host_str}' not allowed")

    # If it is an IP literal, validate directly without network/DNS call
    if literal_ip is not None:
        if not allow_private and is_ip_blocked(literal_ip):
            raise UrlRejected(f"{host_str} resolves to non-public address {literal_ip}")
        return parts, [str(literal_ip)]

    # Domain name resolution
    try:
        infos = socket.getaddrinfo(host_str, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise UrlRejected(f"DNS resolution failed: {e}")

    raw_ips: List[str] = [info[4][0].split("%")[0] for info in infos]
    validated_ips = validate_resolved_ips(raw_ips, allow_private=allow_private)
    return parts, validated_ips
