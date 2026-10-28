//! The checks on addresses the server dials for push and link previews.

use crate::server::outbound::*;

#[test]
fn test_public_address() {
    for (host, want) in [
        ("93.184.215.14", true),
        ("2606:4700::1111", true),
        ("127.0.0.1", false),
        ("10.1.2.3", false),
        ("169.254.169.254", false),
        ("100.64.0.1", false),
        ("100.100.100.200", false),
        ("198.18.0.1", false),
        ("192.0.0.1", false),
        ("240.0.0.1", false),
        ("::ffff:100.64.0.1", false),
        ("64:ff9b::a00:1", false),
        ("2002:a00:1::1", false),
        ("fd00::1", false),
        ("192.0.2.1", false),
        ("198.51.100.1", false),
        ("203.0.113.1", false),
        ("::a00:1", false),
        ("100::1", false),
        ("2001:db8::1", false),
        ("fec0::1", false),
        ("3fff::1", false),
        ("::1", false),
    ] {
        assert_eq!(public_address(host), want, "public_address({host})");
    }
}

#[test]
fn test_public_only() {
    for (address, want) in [
        ("93.184.215.14:443", true),
        ("[2606:4700::1111]:443", true),
        ("10.0.0.1:80", false),
        ("192.168.1.1:443", false),
        ("169.254.169.254:80", false),
        ("[::1]:80", false),
        ("[fe80::1]:80", false),
        ("100.64.0.1:80", false),
        ("example.com:443", false),
        ("93.184.215.14", false),
    ] {
        assert_eq!(public_only()(address), want, "{address}");
    }
}
