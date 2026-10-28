//! HTTP clients for requests the server makes on users' behalf, push
//! deliveries and link previews, which must not reach into the server's own
//! network.

use std::sync::{Arc, LazyLock};

use rust_stdlib::net::http::client::{CheckRedirect, Client};
use rust_stdlib::net::http::transport::Transport;
use rust_stdlib::net::netip::{Addr, Prefix};
use rust_stdlib::net::split_host_port;
use rust_stdlib::time::Duration;

/// Decides whether a dialed address, `host:port` with the host an IP
/// address, may be connected to.
pub type DialCheck = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Admits any address, for tests and `--push.allow-insecure`.
pub fn any_address() -> DialCheck {
    Arc::new(|_: &str| true)
}

/// Admits addresses on the public internet only.
pub fn public_only() -> DialCheck {
    Arc::new(|address: &str| split_host_port(address).is_ok_and(|(host, _)| public_address(&host)))
}

/// A client that dials only addresses `check` admits, checked on the address
/// actually dialed, after each redirect too, so a name resolves once and
/// cannot be rebound to an internal address. `tune` adjusts the transport.
pub fn client(
    check: DialCheck,
    timeout: Duration,
    check_redirect: CheckRedirect,
    tune: impl FnOnce(&mut Transport),
) -> Client {
    let dialer = rust_stdlib_sys::net::Dialer {
        timeout: timeout.as_nanos(),
        control: Some(Box::new(move |_network: &str, address: &str, _raw: &_| {
            if check(address) {
                Ok(())
            } else {
                Err(std::io::Error::other(format!(
                    "{address} is not on the public internet"
                )))
            }
        })),
        ..rust_stdlib_sys::net::Dialer::default()
    };
    let mut transport = Transport {
        // The proxy of the environment would carry requests past the check
        // on the dialed address.
        proxy: None,
        dial_context: Some(rust_stdlib_sysnet::dial_context(dialer)),
        tls_handshake_timeout: timeout,
        ..rust_stdlib_sysnet::transport()
    };
    tune(&mut transport);
    Client {
        timeout,
        transport: Some(Arc::new(transport)),
        check_redirect: Some(check_redirect),
        ..Client::default()
    }
}

/// Special-purpose ranges that netip's classification does not already
/// exclude: this network, shared address space (CGNAT), IETF protocol
/// assignments, documentation, the 6to4 relay anycast, benchmarking, and the
/// reserved class E range; and in IPv6, IPv4-compatible addresses,
/// discard-only, translation and tunneling prefixes that embed IPv4
/// addresses, benchmarking, ORCHID, documentation, deprecated site-local,
/// and segment routing.
static NON_PUBLIC_PREFIXES: LazyLock<Vec<Prefix>> = LazyLock::new(|| {
    [
        "0.0.0.0/8",
        "100.64.0.0/10",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "240.0.0.0/4",
        "::/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/32",
        "2001:2::/48",
        "2001:10::/28",
        "2001:20::/28",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "5f00::/16",
        "fec0::/10",
    ]
    .iter()
    .map(|p| p.parse().expect("constant prefix"))
    .collect()
});

/// Reports whether an IP address is on the public internet.
pub fn public_address(host: &str) -> bool {
    let Ok(addr) = host.parse::<Addr>() else {
        return false;
    };
    let addr = addr.unmap();
    if !addr.is_global_unicast() || addr.is_private() {
        return false;
    }
    !NON_PUBLIC_PREFIXES
        .iter()
        .any(|prefix| prefix.contains(&addr))
}
