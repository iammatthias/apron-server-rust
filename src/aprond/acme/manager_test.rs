use super::jws;
use super::manager::{http_client, next_renewal, valid_cert, Config, Manager, ALPN_PROTO};
use crate::test_gate::GO;
use rust_stdlib::encoding::pem;
use rust_stdlib::net::http;
use rust_stdlib::net::http::httptest::ResponseRecorder;
use rust_stdlib_tls::tls;
use std::sync::Arc;
use std::time::Duration;

const DIFFERENTIAL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tools/differential/acme");

pub(super) struct TempDir(pub String);

impl TempDir {
    pub fn new() -> TempDir {
        TempDir(rust_stdlib::os::mkdir_temp("", "acme-test").unwrap())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A manager whose CA is unreachable, so only its cache can serve.
fn offline(domains: &[&str], cache_dir: &str) -> Manager {
    Manager::new(Config {
        domains: domains.iter().map(|d| d.to_string()).collect(),
        cache_dir: cache_dir.to_string(),
        email: String::new(),
        directory_url: "http://127.0.0.1:1/unreachable".to_string(),
        http: http_client(tls::Config::new()),
        renew_before: Duration::ZERO,
    })
}

fn hello(name: &str, protos: &[&str]) -> tls::ClientHelloInfo {
    tls::ClientHelloInfo {
        server_name: name.to_string(),
        supported_protos: protos.iter().map(|p| p.to_string()).collect(),
        ..Default::default()
    }
}

/// Runs tools/differential/acme, or `None` when `go` cannot be started.
pub(super) fn go(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("go")
        .arg("run")
        .arg(".")
        .args(args)
        .current_dir(DIFFERENTIAL)
        .env("GOFLAGS", "-mod=mod")
        .output()
        .ok()?;
    assert!(
        output.status.success(),
        "go run . {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(String::from_utf8(output.stdout).unwrap())
}

#[test]
fn test_get_certificate_rejects_names_as_autocert() {
    let m = offline(&["chat.example"], "");
    for (name, protos, want) in [
        ("", &[][..], "acme/autocert: missing server name"),
        (
            "localhost",
            &[][..],
            "acme/autocert: server name component count invalid",
        ),
        (
            ".localhost.",
            &[][..],
            "acme/autocert: server name component count invalid",
        ),
        (
            "chät.example",
            &[][..],
            "acme/autocert: server name contains invalid character",
        ),
        (
            "other.example",
            &[][..],
            "acme/autocert: host \"other.example\" not configured in HostWhitelist",
        ),
        (
            "chat.example",
            &[ALPN_PROTO][..],
            "acme/autocert: no token cert for \"chat.example\"",
        ),
    ] {
        let err = m.get_certificate(&hello(name, protos)).expect_err(name);
        assert_eq!(err.to_string(), want, "{name:?}");
    }
}

#[test]
fn test_http_handler_redirects_and_serves_tokens() {
    let dir = TempDir::new();
    std::fs::write(format!("{}/tok-1+http-01", dir.0), "tok-1.thumb").unwrap();
    let handler = offline(&["chat.example"], &dir.0).http_handler();
    let serve = |method: &str, host: &str, target: &str| {
        let mut req = http::Request::new(method, &format!("http://{host}{target}")).unwrap();
        req.host = host.to_string();
        let mut w = ResponseRecorder::new();
        handler.serve_http(&mut w, &mut req);
        let location = w.header_map.get("Location").unwrap_or_default().to_string();
        (
            w.code,
            location,
            String::from_utf8(w.body.clone().unwrap_or_default()).unwrap(),
        )
    };
    assert_eq!(
        serve("GET", "chat.example", "/rooms?x=1"),
        (
            302,
            "https://chat.example/rooms?x=1".to_string(),
            "<a href=\"https://chat.example/rooms?x=1\">Found</a>.\n\n".to_string()
        )
    );
    assert_eq!(
        serve("GET", "chat.example:80", "/").1,
        "https://chat.example:443/"
    );
    assert_eq!(serve("POST", "chat.example", "/").0, 400);
    assert_eq!(serve("POST", "chat.example", "/").2, "Use HTTPS\n");
    assert_eq!(
        serve("GET", "chat.example", "/.well-known/acme-challenge/tok-1"),
        (200, String::new(), "tok-1.thumb".to_string())
    );
    assert_eq!(
        serve("GET", "chat.example", "/.well-known/acme-challenge/tok-2"),
        (
            404,
            String::new(),
            "acme/autocert: certificate cache miss\n".to_string()
        )
    );
    assert_eq!(
        serve("GET", "other.example", "/.well-known/acme-challenge/tok-1"),
        (
            403,
            String::new(),
            "acme/autocert: host \"other.example\" not configured in HostWhitelist\n".to_string()
        )
    );
}

#[test]
fn test_next_renewal_is_a_third_of_the_lifetime_at_most_30_days() {
    let day = 24 * 60 * 60;
    // A 90-day certificate renews 30 days before it expires, less jitter of
    // at most an hour.
    let next = next_renewal(Duration::ZERO, 0, 90 * day, 0).as_secs() as i64;
    assert!((60 * day..=60 * day + 3600).contains(&next), "{next}");
    // A 6-day certificate renews after 4 days, less jitter of a tenth.
    let next = next_renewal(Duration::ZERO, 0, 6 * day, 0).as_secs() as i64;
    assert!((4 * day..=4 * day + 2 * day / 10).contains(&next), "{next}");
    assert_eq!(
        next_renewal(Duration::ZERO, 0, 6 * day, 10 * day),
        Duration::ZERO
    );
    let next = next_renewal(Duration::from_secs(7 * day as u64), 0, 90 * day, 0).as_secs() as i64;
    assert!((83 * day..=83 * day + 3600).contains(&next), "{next}");
}

#[test]
fn test_a_go_written_cache_is_served() {
    let dir = TempDir::new();
    if go(&["write-cache", "testdata/account.pem", &dir.0, "aprond.test"]).is_none() {
        return GO.unavailable("go write-cache");
    }
    let m = offline(&["aprond.test"], &dir.0);
    let cert = m
        .get_certificate(&hello("aprond.test", &["h2", "http/1.1"]))
        .unwrap();
    let leaf = rust_stdlib_crypto::x509::parse_certificate(&cert.certificate[0]).unwrap();
    assert_eq!(leaf.serial_number.unwrap().to_i64(), Some(4242));
}

#[test]
fn test_a_rust_written_cache_is_read_by_go() {
    let dir = TempDir::new();
    let key = jws::generate_key().unwrap();
    let (der, cert_key) = jws::tls_alpn01_challenge_cert(&key, "t", "aprond.test").unwrap();
    // A token cert is a valid self-signed leaf for the domain, so it stands
    // in for an issued certificate here.
    let mut file = jws::encode_key(&cert_key).unwrap();
    file.extend(pem::encode(&pem::Block::new("CERTIFICATE", der.clone())).unwrap());
    super::cache::DirCache(dir.0.clone())
        .put("aprond.test", &file)
        .unwrap();
    valid_cert(
        "aprond.test",
        &[der],
        &cert_key,
        rust_stdlib::time::now().unix(),
    )
    .unwrap();
    match go(&["read-cache", "testdata/account.pem", &dir.0, "aprond.test"]) {
        Some(out) => assert_eq!(out, "serial 1 chain 1\n"),
        None => GO.unavailable("go read-cache"),
    }
}

/// Serves `config` on a loopback port, completing each handshake, and
/// returns the address.
pub(super) fn serve_tls(config: tls::Config) -> String {
    let inner = rust_stdlib::net::listen("tcp", "127.0.0.1:0").unwrap();
    let addr = inner.addr().unwrap().to_string();
    let listener = tls::Listener::new(inner, Arc::new(config));
    std::thread::spawn(move || {
        while let Ok(conn) = rust_stdlib::net::Listener::accept(&listener) {
            std::thread::spawn(move || {
                let _ = conn.handshake();
                let _ = conn.read(&mut [0u8; 1]);
                let _ = conn.close();
            });
        }
    });
    addr
}

pub(super) fn handshake(
    addr: &str,
    name: &str,
    protos: &[&str],
    roots: Option<tls::x509::CertPool>,
) -> Result<tls::ConnectionState, tls::Error> {
    let mut config = tls::Config::new();
    config.server_name = name.to_string();
    config.next_protos = protos.iter().map(|p| p.to_string()).collect();
    match roots {
        Some(roots) => config.root_cas = Some(roots),
        None => config.insecure_skip_verify = true,
    }
    let conn = tls::dial("tcp", addr, Some(Arc::new(config)))?;
    let state = conn.connection_state();
    let _ = conn.close();
    Ok(state)
}

#[test]
fn test_tls_config_answers_acme_tls_1_with_the_token_cert() {
    let dir = TempDir::new();
    if go(&["write-cache", "testdata/account.pem", &dir.0, "aprond.test"]).is_none() {
        return GO.unavailable("go write-cache");
    }
    let m = offline(&["aprond.test"], &dir.0);
    let key = jws::generate_key().unwrap();
    let (der, cert_key) = jws::tls_alpn01_challenge_cert(&key, "tok", "aprond.test").unwrap();
    let mut file = jws::encode_key(&cert_key).unwrap();
    file.extend(pem::encode(&pem::Block::new("CERTIFICATE", der.clone())).unwrap());
    super::cache::DirCache(dir.0.clone())
        .put("aprond.test+token", &file)
        .unwrap();
    let addr = serve_tls(m.tls_config());

    // The rust-stdlib-tls client cannot dial a leaf with the critical
    // acmeIdentifier extension (docs/PORT.md, pending rust-stdlib fixes), so
    // Go's client dials, as Pebble's and Let's Encrypt's validators do.
    let Some(out) = go(&[
        "dial",
        "testdata/account.pem",
        &addr,
        "aprond.test",
        ALPN_PROTO,
    ]) else {
        return GO.unavailable("go dial");
    };
    assert_eq!(
        out, "proto acme-tls/1 serial 1\n",
        "the token cert answers acme-tls/1"
    );

    let state = handshake(&addr, "aprond.test", &["http/1.1"], None).unwrap();
    assert_eq!(state.negotiated_protocol, "http/1.1");
    let leaf =
        rust_stdlib_crypto::x509::parse_certificate(&state.peer_certificates[0].raw).unwrap();
    assert_eq!(
        leaf.serial_number.unwrap().to_i64(),
        Some(4242),
        "the cached cert answers HTTPS"
    );
    assert_eq!(
        go(&["dial", "testdata/account.pem", &addr, "aprond.test", "h2"]).unwrap(),
        "proto h2 serial 4242\n"
    );

    assert!(handshake(&addr, "other.example", &["http/1.1"], None).is_err());
}
