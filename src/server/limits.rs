//! Per-client limits, apron-server-cloudflare's (its SPEC.md, sections 5
//! and 6): who a client is for them, its IP key.

use std::fmt;

use rust_stdlib::net;

/// The principal a client's per-IP limits count: an IPv4 address, with an
/// IPv4-mapped IPv6 one folded into it, or a native IPv6 address's /56, the
/// size ISPs most often delegate to one home or site, so one subscriber
/// cannot multiply its limits across its /64s.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpKey(String);

impl IpKey {
    /// The key of an address, or `None` when `address` is not one.
    pub fn parse(address: &str) -> Option<IpKey> {
        let ip = net::parse_ip(address.trim())?;
        if let Some(v4) = ip.to4() {
            return Some(IpKey(format!("v4:{v4}")));
        }
        let prefix = ip.mask(&net::cidr_mask(56, 128)?)?;
        Some(IpKey(format!("v6:{prefix}/56")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IpKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(address: &str) -> String {
        IpKey::parse(address).expect(address).to_string()
    }

    /// Cloudflare's config-ip-frame.test.ts, "joins dotted and hexadecimal
    /// IPv4-mapped IPv6 with IPv4".
    #[test]
    fn mapped_ipv4_joins_ipv4_and_ipv6_groups_by_56() {
        assert_eq!(key("192.0.2.10"), "v4:192.0.2.10");
        assert_eq!(key("::ffff:192.0.2.10"), "v4:192.0.2.10");
        assert_eq!(key("0:0:0:0:0:ffff:c000:020a"), "v4:192.0.2.10");
        assert_eq!(key("2001:db8:1:2::1"), key("2001:0db8:0001:0002:abcd::5"));
        assert_eq!(key("2001:db8:1:ff::1"), key("2001:db8:1:2::1"));
        assert_ne!(key("2001:db8:1:102::1"), key("2001:db8:1:2::1"));
        assert_eq!(key("2001:db8:1:2::1"), "v6:2001:db8:1::/56");
        assert_eq!(key("2001:db8:1:abcd::1"), "v6:2001:db8:1:ab00::/56");
    }

    #[test]
    fn non_addresses_have_no_key() {
        for value in [
            "",
            "garbage-x",
            "203.0.113.7:80",
            "fe80::1%en0",
            "256.1.1.1",
        ] {
            assert_eq!(IpKey::parse(value), None, "{value:?}");
        }
    }
}
