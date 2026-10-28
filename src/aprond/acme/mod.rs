//! A replacement for golang.org/x/crypto/acme/autocert as main.go uses it:
//! an RFC 8555 client, autocert's `Manager` with `DirCache`,
//! `HostWhitelist`, TLS-ALPN-01 and HTTP-01, and the HTTP handler that
//! answers challenges and redirects to HTTPS.

pub mod cache;
pub mod client;
pub mod jws;
pub mod manager;

pub use manager::{http_client, Config, Manager};

#[cfg(test)]
mod manager_test;
#[cfg(test)]
mod pebble_test;
