//! The ACME gate: certificates from Pebble, Let's Encrypt's test CA, over
//! TLS-ALPN-01. It looks for `pebble` and `pebble-challtestsrv` in
//! `$PEBBLE_BIN_DIR`, on `PATH`, and in `$(go env GOPATH)/bin`, and for
//! Pebble's module (its configuration and CA certificate) in `$PEBBLE_DIR`
//! or the Go module cache. Without them the test fails, unless
//! `APRON_SKIP_PEBBLE=1`.

use super::manager::{http_client, Config, Manager};
use super::manager_test::{handshake, TempDir};
use crate::test_gate::{GO, PEBBLE};
use rust_stdlib::net::http;
use rust_stdlib_tls::tls;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DOMAIN: &str = "aprond.test";
const DIRECTORY: &str = "https://localhost:14000/dir";

struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn find_binary(name: &str) -> Option<String> {
    let mut dirs: Vec<String> = Vec::new();
    if let Ok(dir) = std::env::var("PEBBLE_BIN_DIR") {
        dirs.push(dir);
    }
    if let Ok(path) = std::env::var("PATH") {
        dirs.extend(path.split(':').map(str::to_string));
    }
    if let Ok(out) = Command::new("go").args(["env", "GOPATH"]).output() {
        dirs.push(format!(
            "{}/bin",
            String::from_utf8_lossy(&out.stdout).trim()
        ));
    }
    dirs.into_iter()
        .map(|d| format!("{d}/{name}"))
        .find(|p| std::path::Path::new(p).is_file())
}

fn pebble_dir() -> Option<String> {
    if let Ok(dir) = std::env::var("PEBBLE_DIR") {
        return Some(dir);
    }
    let out = Command::new("go")
        .args(["env", "GOMODCACHE"])
        .output()
        .ok()?;
    let base = format!(
        "{}/github.com/letsencrypt/pebble",
        String::from_utf8_lossy(&out.stdout).trim()
    );
    let mut versions: Vec<String> = std::fs::read_dir(&base)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path().to_string_lossy().into_owned())
        .filter(|p| p.contains("/v2@"))
        .collect();
    versions.sort();
    versions.pop()
}

fn pebble_client(pebble: &str) -> http::Client {
    let mut roots = tls::x509::CertPool::new();
    let pem = std::fs::read(format!("{pebble}/test/certs/pebble.minica.pem")).unwrap();
    assert!(roots.append_certs_from_pem(&pem));
    let mut config = tls::Config::new();
    config.root_cas = Some(roots);
    http_client(config)
}

fn get(client: &http::Client, url: &str) -> Result<Vec<u8>, String> {
    let res = client.get(url).map_err(|e| e.to_string())?;
    let body = res
        .body
        .as_ref()
        .map(|b| b.read_all().unwrap_or_default())
        .unwrap_or_default();
    if res.status_code != 200 {
        return Err(format!("{url}: {}", res.status_code));
    }
    Ok(body)
}

fn manager(pebble: &http::Client, cache_dir: &str) -> Manager {
    Manager::new(Config {
        domains: vec![DOMAIN.to_string()],
        cache_dir: cache_dir.to_string(),
        email: "ops@example.test".to_string(),
        directory_url: DIRECTORY.to_string(),
        http: pebble.clone(),
        renew_before: Duration::ZERO,
    })
}

/// Serves `config` on `addr` until the test process exits.
fn serve_tls_on(addr: &str, config: tls::Config) {
    let inner = rust_stdlib::net::listen("tcp", addr).unwrap();
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
}

fn leaf_serial(state: &tls::ConnectionState) -> String {
    let leaf =
        rust_stdlib_crypto::x509::parse_certificate(&state.peer_certificates[0].raw).unwrap();
    leaf.serial_number.unwrap().magnitude().to_hex()
}

#[test]
fn test_certificates_from_pebble() {
    let (Some(pebble_bin), Some(challtestsrv), Some(pebble)) = (
        find_binary("pebble"),
        find_binary("pebble-challtestsrv"),
        pebble_dir(),
    ) else {
        return PEBBLE.unavailable("pebble, pebble-challtestsrv or Pebble's module not found");
    };
    let quiet = || Stdio::null();
    let logs = TempDir::new();
    let log_path = format!("{}/pebble.log", logs.0);
    let log = std::fs::File::create(&log_path).unwrap();
    let _dns = Killed(
        Command::new(&challtestsrv)
            .args([
                "-defaultIPv4",
                "127.0.0.1",
                "-defaultIPv6",
                "",
                "-dnsserver",
                "127.0.0.1:8053",
            ])
            .args([
                "-http01",
                "",
                "-https01",
                "",
                "-tlsalpn01",
                "",
                "-doh",
                "",
                "-management",
                "127.0.0.1:8055",
            ])
            .stdout(quiet())
            .stderr(quiet())
            .spawn()
            .unwrap(),
    );
    let start = Instant::now();
    while std::net::TcpStream::connect("127.0.0.1:8053").is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "pebble-challtestsrv did not start"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ca = Killed(
        Command::new(&pebble_bin)
            .args([
                "-config",
                "test/config/pebble-config.json",
                "-dnsserver",
                "127.0.0.1:8053",
            ])
            .current_dir(&pebble)
            .env("PEBBLE_VA_NOSLEEP", "1")
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let client = pebble_client(&pebble);
    let start = Instant::now();
    while get(&client, DIRECTORY).is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "Pebble did not start"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let mut roots = tls::x509::CertPool::new();
    assert!(roots.append_certs_from_pem(&get(&client, "https://localhost:15000/roots/0").unwrap()));

    let cache = TempDir::new();
    let m = manager(&client, &cache.0);
    // Pebble's validator dials the TLS-ALPN-01 port, 5001, on the address
    // pebble-challtestsrv gives aprond.test: 127.0.0.1.
    serve_tls_on("127.0.0.1:5001", m.tls_config());

    let ordered = Instant::now();
    let state = handshake("127.0.0.1:5001", DOMAIN, &["http/1.1"], Some(roots.clone()))
        .unwrap_or_else(|e| {
            panic!(
                "first handshake, which orders the certificate: {e}\n{}",
                std::fs::read_to_string(&log_path).unwrap_or_default()
            )
        });
    assert_eq!(
        state.verified_chains.len(),
        1,
        "the chain verifies against Pebble's root"
    );
    println!("issued in {:?}", ordered.elapsed());
    let issued = leaf_serial(&state);
    let files: Vec<String> = std::fs::read_dir(&cache.0)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let mut files = files;
    files.sort();
    assert_eq!(files, ["acme_account+key", DOMAIN], "cache after issuance");

    let again = handshake("127.0.0.1:5001", DOMAIN, &["http/1.1"], Some(roots.clone())).unwrap();
    assert_eq!(leaf_serial(&again), issued, "the certificate is reused");

    // Renewal orders a new certificate with the same key and the same account.
    std::fs::remove_file(format!("{}/{DOMAIN}", cache.0)).unwrap();
    m.renew(DOMAIN).unwrap();
    let renewed = handshake("127.0.0.1:5001", DOMAIN, &["http/1.1"], Some(roots.clone())).unwrap();
    assert_ne!(
        leaf_serial(&renewed),
        issued,
        "renewal serves the new certificate"
    );

    // The Go autocert reads what this port wrote, without the CA.
    let go = Command::new("go")
        .args([
            "run",
            ".",
            "read-cache",
            "testdata/account.pem",
            &cache.0,
            DOMAIN,
        ])
        .current_dir(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tools/differential/acme"
        ))
        .env("GOFLAGS", "-mod=mod")
        .output();
    match go {
        Ok(out) if out.status.success() => {
            let out = String::from_utf8_lossy(&out.stdout).into_owned();
            assert!(out.ends_with(" chain 2\n"), "go read-cache: {out}");
        }
        Ok(out) => panic!("go read-cache: {}", String::from_utf8_lossy(&out.stderr)),
        Err(_) => GO.unavailable("go read-cache"),
    }
}
