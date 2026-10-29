//! Test servers: a server on a loopback listener, its configuration, and
//! plain HTTP requests to it.

use std::sync::Arc;

use rust_stdlib::context::Context;
use rust_stdlib::net::http::httptest;

use crate::server::config::Config;
use crate::server::{open, Server};

pub struct TestServer {
    pub app: Arc<Server>,
    pub http: httptest::Server,
    stopped: bool,
    /// The upload directory `open` made when the config named none, which a
    /// shutdown removes; a failed test skips the shutdown and removes it here.
    temp_upload_dir: Option<String>,
}

impl TestServer {
    /// Shuts the server down, closing the store, once.
    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        let (ctx, cancel) =
            Context::background().with_timeout(rust_stdlib::time::Duration::from_secs(10));
        if let Err(e) = self.app.shutdown(&ctx) {
            panic!("shutdown: {e}");
        }
        cancel();
        self.http.close();
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.stop();
        } else if let Some(dir) = &self.temp_upload_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// A temporary directory removed on drop, even when the test fails, as Go's
/// `t.TempDir()` is.
pub struct TempDir(String);

impl TempDir {
    pub fn new(prefix: &str) -> TempDir {
        TempDir(rust_stdlib::os::mkdir_temp("", prefix).unwrap())
    }
}

impl std::ops::Deref for TempDir {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TempDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The server's defaults with guest posting on and no per-client limits:
/// the tests ported from Go sign in as guests to post, all from one
/// address. `guest_posting_test` covers the read-only default, and the
/// limit tests set the limits they test.
pub fn default_config() -> Config {
    Config {
        guest_posting: true,
        max_connections: 0,
        limits: crate::server::limits::Limits::unlimited(),
        ..crate::server::config::default_config()
    }
}

/// `default_config` with frames and texts large enough to reach the
/// server's limits on ext, descriptions and history pages.
pub fn large_frames_config() -> Config {
    let mut config = default_config();
    config.frame.max_bytes = 1 << 20;
    config.frame.max_text_bytes = 1 << 20;
    config
}

pub fn new_test_server(config: Config) -> TestServer {
    let app = open(config).expect("open");
    let http = httptest::Server::new(app.handler()).expect("httptest server");
    let temp_upload_dir = {
        let st = app.lock();
        st.temp_upload_dir.then(|| st.upload_dir.clone())
    };
    TestServer {
        app,
        http,
        stopped: false,
        temp_upload_dir,
    }
}

/// The WebSocket endpoint of a test server.
pub fn ws_url(server: &TestServer) -> String {
    format!("ws{}/ws", &server.http.url["http".len()..])
}

/// Sends one HTTP GET and returns the status and body.
pub fn http_get(url: &str) -> (u16, Vec<u8>) {
    let response =
        rust_stdlib::net::http::client::get(url).unwrap_or_else(|e| panic!("GET {url}: {e}"));
    let body = response
        .body
        .as_ref()
        .map(|b| b.read_all().unwrap())
        .unwrap_or_default();
    (response.status_code, body)
}

/// Sends one HTTP request and returns the status, headers, and body.
pub fn http_do(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    content_type: &str,
) -> (u16, rust_stdlib::net::http::Header, Vec<u8>) {
    let mut request =
        rust_stdlib::net::http::Request::new(method, url).unwrap_or_else(|e| panic!("{url}: {e}"));
    if let Some(body) = body {
        request = request.with_body(body.to_vec());
    }
    if !content_type.is_empty() {
        request.header.set("Content-Type", content_type);
    }
    let response = rust_stdlib::net::http::client::DEFAULT_CLIENT
        .do_request(request)
        .unwrap_or_else(|e| panic!("{method} {url}: {e}"));
    let data = response
        .body
        .as_ref()
        .map(|b| b.read_all().unwrap())
        .unwrap_or_default();
    (response.status_code, response.header, data)
}
