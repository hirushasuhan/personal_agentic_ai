//! Outbound URL policy and Blocked CIDRs (VS2)
//! Strictly enforces canonical URL parsing, port allowlist {80, 443},
//! and Canonical Blocked CIDR table without external crate dependencies.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedUrl {
    pub scheme: String,
    pub host: IpAddr,
    pub port: u16,
    pub path_and_query: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlRejection {
    pub reason: String,
}

impl UrlRejection {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

pub struct Ipv4Cidr {
    net: u32,
    mask: u32,
}

impl Ipv4Cidr {
    pub const fn new(o1: u8, o2: u8, o3: u8, o4: u8, prefix_len: u32) -> Self {
        let net = ((o1 as u32) << 24) | ((o2 as u32) << 16) | ((o3 as u32) << 8) | (o4 as u32);
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        Self {
            net: net & mask,
            mask,
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from_be_bytes(ip.octets());
        (ip_u32 & self.mask) == self.net
    }
}

pub struct Ipv6Cidr {
    net: u128,
    mask: u128,
}

impl Ipv6Cidr {
    pub const fn new(octets: [u8; 16], prefix_len: u32) -> Self {
        let net = u128::from_be_bytes(octets);
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u128 << (128 - prefix_len)
        };
        Self {
            net: net & mask,
            mask,
        }
    }

    pub fn contains(&self, ip: Ipv6Addr) -> bool {
        let ip_u128 = u128::from_be_bytes(ip.octets());
        (ip_u128 & self.mask) == self.net
    }
}

// Canonical Blocked CIDR table (docs/NET_POLICY.md)
pub static BLOCKED_IPV4_CIDRS: &[Ipv4Cidr] = &[
    Ipv4Cidr::new(0, 0, 0, 0, 8),          // 0.0.0.0/8 (RFC 1122 This host)
    Ipv4Cidr::new(10, 0, 0, 0, 8),         // 10.0.0.0/8 (RFC 1918 Private)
    Ipv4Cidr::new(100, 64, 0, 0, 10),      // 100.64.0.0/10 (RFC 6598 Carrier-Grade NAT)
    Ipv4Cidr::new(127, 0, 0, 0, 8),        // 127.0.0.0/8 (RFC 1122 Loopback)
    Ipv4Cidr::new(169, 254, 0, 0, 16),     // 169.254.0.0/16 (RFC 3927 Link-Local / Metadata)
    Ipv4Cidr::new(172, 16, 0, 0, 12),      // 172.16.0.0/12 (RFC 1918 Private)
    Ipv4Cidr::new(192, 0, 0, 0, 24),       // 192.0.0.0/24 (RFC 6890 IETF Protocol Assignments)
    Ipv4Cidr::new(192, 0, 2, 0, 24),       // 192.0.2.0/24 (RFC 5737 TEST-NET-1)
    Ipv4Cidr::new(192, 168, 0, 0, 16),     // 192.168.0.0/16 (RFC 1918 Private)
    Ipv4Cidr::new(198, 18, 0, 0, 15),      // 198.18.0.0/15 (RFC 2544 Benchmarking)
    Ipv4Cidr::new(198, 51, 100, 0, 24),    // 198.51.100.0/24 (RFC 5737 TEST-NET-2)
    Ipv4Cidr::new(203, 0, 113, 0, 24),     // 203.0.113.0/24 (RFC 5737 TEST-NET-3)
    Ipv4Cidr::new(224, 0, 0, 0, 4),        // 224.0.0.0/4 (RFC 5771 Multicast)
    Ipv4Cidr::new(240, 0, 0, 0, 4),        // 240.0.0.0/4 (RFC 1112 Reserved / Class E)
    Ipv4Cidr::new(255, 255, 255, 255, 32), // 255.255.255.255/32 (RFC 919 Broadcast)
];

pub static BLOCKED_IPV6_CIDRS: &[Ipv6Cidr] = &[
    Ipv6Cidr::new([0; 16], 128), // ::/128 (Unspecified)
    Ipv6Cidr::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128), // ::1/128 (Loopback)
    Ipv6Cidr::new([0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 64), // 100::/64 (Discard-Only)
    Ipv6Cidr::new(
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        32,
    ), // 2001:db8::/32 (Documentation)
    Ipv6Cidr::new([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7), // fc00::/7 (ULA / Private)
    Ipv6Cidr::new([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10), // fe80::/10 (Link-Local)
    Ipv6Cidr::new([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8), // ff00::/8 (Multicast)
];

/// Checks whether an IP address belongs to any blocked CIDR range.
pub fn is_ip_blocked(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => BLOCKED_IPV4_CIDRS.iter().any(|cidr| cidr.contains(*v4)),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            // IPv4-mapped IPv6 (::ffff:0:0/96) must be unwrapped and checked against IPv4 CIDRs
            if octets[0..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
                let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return is_ip_blocked(&IpAddr::V4(v4));
            }
            BLOCKED_IPV6_CIDRS.iter().any(|cidr| cidr.contains(*v6))
        }
    }
}

/// Pure post-resolution validator for DNS queries.
pub fn validate_resolved_ips(ips: &[IpAddr]) -> Result<(), String> {
    if ips.is_empty() {
        return Err("no addresses resolved".to_string());
    }
    for ip in ips {
        if is_ip_blocked(ip) {
            return Err(format!("address {} is blocked by outbound policy", ip));
        }
    }
    Ok(())
}

/// Strict URL validator enforcing scheme, credentials, port, and IP literal policies.
pub fn validate_url(url: &str) -> Result<ValidatedUrl, UrlRejection> {
    if url.is_empty() {
        return Err(UrlRejection::new("empty URL"));
    }

    // Reject non-ASCII, control characters, whitespace, and backslashes
    for b in url.bytes() {
        if b > 127 {
            return Err(UrlRejection::new("non-ASCII character not allowed"));
        }
        if b <= b' ' || b == 0x7F {
            return Err(UrlRejection::new("whitespace or control character in URL"));
        }
        if b == b'\\' {
            return Err(UrlRejection::new("backslash character not allowed in URL"));
        }
    }

    // Find scheme delimiter ://
    let scheme_delim = "://";
    let scheme_idx = match url.find(scheme_delim) {
        Some(idx) => idx,
        None => return Err(UrlRejection::new("missing scheme delimiter '://'")),
    };

    let scheme_str = &url[..scheme_idx];
    let lower_scheme = scheme_str.to_ascii_lowercase();
    if lower_scheme != "http" && lower_scheme != "https" {
        return Err(UrlRejection::new(format!(
            "scheme '{}' not allowed (http/https only)",
            scheme_str
        )));
    }

    let rest = &url[scheme_idx + scheme_delim.len()..];
    let (authority, path_and_query) = match rest.find(['/', '?', '#']) {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };

    if authority.is_empty() {
        return Err(UrlRejection::new("empty host/authority"));
    }

    if authority.contains('@') {
        return Err(UrlRejection::new("credentials or '@' not allowed in URL"));
    }

    let (host_str, port_opt, is_ipv6) = if authority.starts_with('[') {
        let closing = match authority.find(']') {
            Some(idx) => idx,
            None => return Err(UrlRejection::new("unmatched '[' in IPv6 authority")),
        };
        let host_slice = &authority[1..closing];
        let port_part = &authority[closing + 1..];
        let p = if port_part.is_empty() {
            None
        } else if let Some(stripped) = port_part.strip_prefix(':') {
            Some(stripped)
        } else {
            return Err(UrlRejection::new("invalid trailing data after ']'"));
        };
        (host_slice, p, true)
    } else {
        match authority.find(':') {
            Some(idx) => {
                let host_slice = &authority[..idx];
                let port_slice = &authority[idx + 1..];
                if port_slice.contains(':') {
                    return Err(UrlRejection::new(
                        "multiple colons in host without brackets",
                    ));
                }
                (host_slice, Some(port_slice), false)
            }
            None => (authority, None, false),
        }
    };

    if host_str.is_empty() {
        return Err(UrlRejection::new("empty host"));
    }

    // Port validation
    let port: u16 = match port_opt {
        Some(p_str) => {
            if p_str.is_empty() {
                return Err(UrlRejection::new("empty port specification"));
            }
            if !p_str.chars().all(|c| c.is_ascii_digit()) {
                return Err(UrlRejection::new("invalid non-digit port"));
            }
            let p_val: u64 = match p_str.parse() {
                Ok(v) => v,
                Err(_) => return Err(UrlRejection::new("port number out of range")),
            };
            if p_val == 0 || p_val > 65535 {
                return Err(UrlRejection::new(format!("port {} out of range", p_val)));
            }
            if p_val != 80 && p_val != 443 {
                return Err(UrlRejection::new(format!(
                    "port {} not allowed (only 80, 443 permitted)",
                    p_val
                )));
            }
            p_val as u16
        }
        None => {
            if lower_scheme == "https" {
                443
            } else {
                80
            }
        }
    };

    // Host validation and IP parsing
    let host_ip: IpAddr = if is_ipv6 {
        match host_str.parse::<Ipv6Addr>() {
            Ok(v6) => IpAddr::V6(v6),
            Err(e) => return Err(UrlRejection::new(format!("invalid IPv6 address: {}", e))),
        }
    } else {
        // Enforce strict canonical dotted-decimal IPv4
        let octets: Vec<&str> = host_str.split('.').collect();
        if octets.len() != 4 {
            return Err(UrlRejection::new(
                "non-canonical IPv4: must have exactly 4 octets",
            ));
        }
        let mut parsed_octets = [0u8; 4];
        for (i, oct_str) in octets.iter().enumerate() {
            if oct_str.is_empty() {
                return Err(UrlRejection::new("empty octet in IPv4 address"));
            }
            if !oct_str.chars().all(|c| c.is_ascii_digit()) {
                return Err(UrlRejection::new("non-digit character in IPv4 octet"));
            }
            if oct_str.len() > 1 && oct_str.starts_with('0') {
                return Err(UrlRejection::new(
                    "non-canonical IPv4: octal leading zero not permitted",
                ));
            }
            let val: u32 = match oct_str.parse() {
                Ok(v) => v,
                Err(_) => return Err(UrlRejection::new("IPv4 octet parse error")),
            };
            if val > 255 {
                return Err(UrlRejection::new("IPv4 octet exceeds 255"));
            }
            parsed_octets[i] = val as u8;
        }
        IpAddr::V4(Ipv4Addr::new(
            parsed_octets[0],
            parsed_octets[1],
            parsed_octets[2],
            parsed_octets[3],
        ))
    };

    // Blocked CIDR verification
    if is_ip_blocked(&host_ip) {
        return Err(UrlRejection::new(format!(
            "address {} is in blocked network range",
            host_ip
        )));
    }

    Ok(ValidatedUrl {
        scheme: lower_scheme,
        host: host_ip,
        port,
        path_and_query: path_and_query.to_string(),
    })
}

pub fn evaluate_url(url: &str) -> &'static str {
    match validate_url(url) {
        Ok(_) => "accept",
        Err(_) => "reject",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_public_urls() {
        assert_eq!(evaluate_url("http://8.8.8.8/"), "accept");
        assert_eq!(evaluate_url("https://1.1.1.1/dns-query"), "accept");
        assert_eq!(evaluate_url("https://8.8.8.8:443/x"), "accept");
        assert_eq!(evaluate_url("http://[2606:4700:4700::1111]/"), "accept");
        assert_eq!(evaluate_url("HTTP://8.8.8.8/"), "accept");
    }

    #[test]
    fn test_blocked_cidrs() {
        assert_eq!(evaluate_url("http://127.0.0.1/"), "reject");
        assert_eq!(evaluate_url("http://[::1]/"), "reject");
        assert_eq!(evaluate_url("http://0.0.0.0/"), "reject");
        assert_eq!(evaluate_url("http://10.0.0.5/"), "reject");
        assert_eq!(evaluate_url("http://172.16.0.1/"), "reject");
        assert_eq!(evaluate_url("http://192.168.1.1/"), "reject");
        assert_eq!(
            evaluate_url("http://169.254.169.254/latest/meta-data/"),
            "reject"
        );
        assert_eq!(evaluate_url("http://100.64.0.1/"), "reject");
        assert_eq!(evaluate_url("http://224.0.0.1/"), "reject");
        assert_eq!(evaluate_url("http://[fe80::1]/"), "reject");
        assert_eq!(evaluate_url("http://[fc00::1]/"), "reject");
        assert_eq!(evaluate_url("http://[::ffff:127.0.0.1]/"), "reject");
        assert_eq!(evaluate_url("http://[::ffff:10.0.0.1]/"), "reject");
        assert_eq!(evaluate_url("http://[::ffff:7f00:1]/"), "reject");
    }

    #[test]
    fn test_non_canonical_and_credentials_rejected() {
        assert_eq!(evaluate_url("https://user:pw@8.8.8.8/"), "reject");
        assert_eq!(evaluate_url("https://user@8.8.8.8/"), "reject");
        assert_eq!(evaluate_url("http://8.8.8.8@127.0.0.1/"), "reject");
        assert_eq!(evaluate_url("http://8.8.8.8\\@127.0.0.1/"), "reject");
        assert_eq!(evaluate_url("http://2130706433/"), "reject");
        assert_eq!(evaluate_url("http://0x7f.1/"), "reject");
        assert_eq!(evaluate_url("http://127.1/"), "reject");
        assert_eq!(evaluate_url("http://0177.0.0.1/"), "reject");
        assert_eq!(evaluate_url("http://8.8.8.8:8080/"), "reject");
        assert_eq!(evaluate_url("http://8.8.8.8:0/"), "reject");
        assert_eq!(evaluate_url("http://8.8.8.8:65536/"), "reject");
    }
}
