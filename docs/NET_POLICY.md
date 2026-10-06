# Outbound Network & URL Policy Specification (NetGuard)

## 1. Overview
The Direct Ingestion Pillar enforces strict, defense-in-depth URL and IP validation prior to any outbound network socket connection. This mitigates Server-Side Request Forgery (SSRF), local network enumeration, cloud metadata exfiltration, and DNS rebinding attacks.

## 2. Strict URL Grammar (Pre-Resolution)
The URL parser enforces a strict subset of URIs:
1. **Encoding & Characters**:
   - The entire URL string must contain only visible ASCII characters (`0x21` to `0x7E`).
   - No whitespace, tabs, newlines, carriage returns, or control characters (`< 0x20` or `== 0x7F`).
   - No backslashes (`\`).
2. **Scheme**:
   - Must be `http` or `https` (case-insensitive during match, normalized to lowercase).
   - Any other scheme (`file`, `ftp`, `gopher`, `javascript`, etc.) is rejected.
3. **Authority**:
   - No credentials: the authority component must NOT contain `@` (blocks `user:pass@host` and confusion vectors like `host@internal`).
   - Host must be non-empty.
   - Host must be either:
     - An IPv6 address enclosed in square brackets `[...]`.
     - A canonical dotted-decimal IPv4 address (`d.d.d.d`).
   - Non-canonical IPv4 formats are strictly **rejected**:
     - Octal octets (e.g., `0177.0.0.1`, leading zeros in any octet).
     - Hexadecimal numbers (e.g., `0x7f.0.0.1`, `0x7f000001`).
     - Dword / 32-bit integer literals (e.g., `2130706433`).
     - Shortened dotted addresses (e.g., `127.1`).
   - Port:
     - If explicit port is specified, it must be decimal digits in `1..=65535`.
     - Port 0 and ports > 65535 are rejected.
     - Default port is 80 (`http`) or 443 (`https`).
     - Allowed outbound ports are strictly `{80, 443}`. Any other port is rejected.

## 3. Canonical Blocked CIDR Table
All IP addresses (whether literal in URL or resolved via DNS) are matched against this table. If an IP falls into ANY blocked range, the request is rejected immediately.

### IPv4 Blocked Ranges
| CIDR Block | Specification / RFC | Purpose |
| :--- | :--- | :--- |
| `0.0.0.0/8` | RFC 1122 | "This host on this network" / Unspecified |
| `10.0.0.0/8` | RFC 1918 | Private-use network |
| `100.64.0.0/10` | RFC 6598 | Shared Address Space / Carrier-Grade NAT |
| `127.0.0.0/8` | RFC 1122 | Loopback |
| `169.254.0.0/16` | RFC 3927 | Link-Local / Cloud Metadata (e.g. AWS 169.254.169.254) |
| `172.16.0.0/12` | RFC 1918 | Private-use network |
| `192.0.0.0/24` | RFC 6890 | IETF Protocol Assignments |
| `192.0.2.0/24` | RFC 5737 | Documentation (TEST-NET-1) |
| `192.168.0.0/16` | RFC 1918 | Private-use network |
| `198.18.0.0/15` | RFC 2544 | Benchmark tests |
| `198.51.100.0/24` | RFC 5737 | Documentation (TEST-NET-2) |
| `203.0.113.0/24` | RFC 5737 | Documentation (TEST-NET-3) |
| `224.0.0.0/4` | RFC 5771 | Multicast |
| `240.0.0.0/4` | RFC 1112 | Reserved / Former Class E |
| `255.255.255.255/32`| RFC 919 | Limited Broadcast |

### IPv6 Blocked Ranges
| CIDR Block | Specification / RFC | Purpose |
| :--- | :--- | :--- |
| `::/128` | RFC 4291 | Unspecified address |
| `::1/128` | RFC 4291 | Loopback address |
| `::ffff:0:0/96` | RFC 4291 | IPv4-mapped IPv6 (*must unwrap to IPv4 and apply IPv4 blocked CIDRs*) |
| `100::/64` | RFC 6666 | Discard-Only Address Block |
| `2001:db8::/32` | RFC 3849 | Documentation |
| `fc00::/7` | RFC 4193 | Unique Local Address (ULA) |
| `fe80::/10` | RFC 4291 | Link-Local Unicast |
| `ff00::/8` | RFC 4291 | Multicast |

## 4. Pre-Resolution vs Post-Resolution
- **Pre-Resolution**: The URL parser inspects the authority and, if an IP literal is present, verifies that it is valid canonical notation and not in the blocked CIDR table.
- **Post-Resolution**: In subsequent phases, DNS queries resolve domain names to a list of `IpAddr`. The pure function `validate_resolved_ips(&[IpAddr])` verifies every returned IP against the Blocked CIDR Table. The connection must pin directly to the validated IP to prevent TOCTOU DNS rebinding.
