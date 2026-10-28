//! The `aprond` binary: its command line compared byte for byte with the Go
//! `aprond`, and `run` end to end over real listeners.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[path = "../src/test_gate.rs"]
#[allow(dead_code, reason = "PEBBLE gates the library's ACME tests")]
mod test_gate;

use test_gate::GO;

const APROND: &str = env!("CARGO_BIN_EXE_aprond");

/// Go's shutdown timeout in `run`.
const GO_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

struct TempDir(String);

impl TempDir {
    fn new() -> TempDir {
        TempDir(rust_stdlib::os::mkdir_temp("", "aprond-bin-").unwrap())
    }

    fn join(&self, name: &str) -> String {
        format!("{}/{name}", self.0)
    }

    fn write(&self, name: &str, content: &str) -> String {
        let path = self.join(name);
        std::fs::create_dir_all(std::path::Path::new(&path).parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The Go `aprond`, built once from the clone at `$APRON_GO_DIR`, or `None`
/// when `go` cannot be started there.
fn go_aprond() -> Option<&'static str> {
    static BUILT: OnceLock<Option<String>> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let go_dir = std::env::var("APRON_GO_DIR").unwrap_or_else(|_| {
                format!(
                    "{}/Developer/forks/apron-server-go",
                    std::env::var("HOME").unwrap_or_default()
                )
            });
            let binary = format!("{}/go/aprond", env!("CARGO_TARGET_TMPDIR"));
            let status = Command::new("go")
                .args(["build", "-o", &binary, "./cmd/aprond"])
                .current_dir(&go_dir)
                .status()
                .ok()?;
            assert!(
                status.success(),
                "go build ./cmd/aprond in {go_dir}: {status}"
            );
            Some(binary)
        })
        .as_deref()
}

fn output(program: &str, args: &[&str]) -> (i32, Vec<u8>, Vec<u8>) {
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (out.status.code().unwrap_or(-1), out.stdout, out.stderr)
}

/// Drops the `time=` attribute of each slog text line.
fn without_times(log: &[u8]) -> String {
    String::from_utf8_lossy(log)
        .lines()
        .map(|line| match line.strip_prefix("time=") {
            Some(rest) => rest.split_once(' ').map_or("", |(_, rest)| rest),
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Drops the groups of extensions Go lacks, `--apple.app-id` and
/// `--unfurl.enable`, which come last in `--help` and `--print-config`.
fn without_extensions(out: &[u8]) -> String {
    let out = String::from_utf8_lossy(out).into_owned();
    if let (Some(start), Some(end)) = (out.find("\nApple:\n"), out.find("\nHelp Options:\n")) {
        return format!("{}{}", &out[..start], &out[end..]);
    }
    match out.find("\n[apple]\n") {
        Some(start) => out[..start].to_string(),
        None => out,
    }
}

/// Runs both programs with `args` and compares exit status, standard output
/// (without the extension groups) and standard error (without log times).
fn compare_with_go(args: &[&str]) {
    let Some(go) = go_aprond() else {
        return GO.unavailable("go toolchain or apron-server-go clone not found");
    };
    let (go_code, go_out, go_err) = output(go, args);
    let (code, out, err) = output(APROND, args);
    let go_view = (
        go_code,
        String::from_utf8_lossy(&go_out).into_owned(),
        without_times(&go_err),
    );
    let view = (code, without_extensions(&out), without_times(&err));
    assert!(
        go_view == view,
        "{args:?}\n--- go (exit {})\n{}{}\n--- rust (exit {})\n{}{}",
        go_view.0,
        go_view.1,
        go_view.2,
        view.0,
        view.1,
        view.2,
    );
}

fn write_config(text: &str) -> (TempDir, String) {
    let dir = TempDir::new();
    let path = dir.write("aprond.toml", text);
    (dir, path)
}

#[test]
fn test_print_config_matches_go() {
    let (_dir, path) = write_config(
        "public-url = \"https://chat.example\"\nrole = [\"admin=ada\"]\n[upload]\nmax-mb = 5\n[tls]\ndomain = []\n",
    );
    for args in [
        &["--print-config"][..],
        &[
            "--print-config",
            "--origin",
            "https://a.example",
            "--origin",
            "https://b.example",
            "--push.disable",
            "--tls.domain",
            "chat.example",
            "--tls.domain",
            "www.chat.example",
            "--role",
            "admin=ada",
        ][..],
        &[
            "--print-config",
            "--welcome",
            "Line one\nSay \"hi\" \\ tab\there \u{1} del\u{7f} é",
            "--webauthn.origin",
            "https://only.example",
            "--max-connections=0x10",
            "--upload.max-storage-mb",
            "-1",
            "--email.sender",
            "log",
            "--email.enable",
        ][..],
        &["--print-config", "--config", &path, "--upload.max-mb", "9"][..],
    ] {
        compare_with_go(args);
    }
}

#[test]
fn test_help_and_errors_match_go() {
    let (_dir, unknown) = write_config("[upload]\nmax = 1\n");
    let (_dir2, bad_int) = write_config("max-connections = \"many\"\n");
    for args in [
        &["--help"][..],
        &["-h"][..],
        &["--addr", ":1", "-h"][..],
        &["--bogus"][..],
        &["-x"][..],
        &["--addr"][..],
        &["--addr", "--store"][..],
        &["--max-connections", "many"][..],
        &["--push.disable=true"][..],
        &["--email.sender", "mail"][..],
        &["--help=1"][..],
        &["--config", "/nonexistent/aprond.toml"][..],
        &["--config", &unknown][..],
        &["--config", &bad_int][..],
    ] {
        compare_with_go(args);
    }
}

/// The errors `run` stops with before it serves, which Go logs as
/// "server stopped" and exits 1 after.
#[test]
fn test_startup_errors_match_go() {
    let dir = TempDir::new();
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = busy.local_addr().unwrap().to_string();
    let not_a_database = format!("sqlite:{}", dir.write("bad.db", &"x".repeat(128)));
    let uploads = dir.join("uploads");
    let base = ["--upload.dir", &uploads];
    let cases: [Vec<&str>; 7] = [
        vec!["--store", "memory", "--addr", &busy],
        vec!["--store", "bogus:1"],
        vec!["--store", "sqlite:"],
        vec!["--store", "memory", "--role", "nope"],
        vec![
            "--store",
            "memory",
            "--push.vapid-subject",
            "ops@example.test",
        ],
        vec![
            "--store",
            "memory",
            "--public-url",
            "https://chat.example",
            "--push.allow-insecure",
        ],
        vec!["--store", &not_a_database],
    ];
    for case in cases {
        let args: Vec<&str> = base.iter().copied().chain(case).collect();
        compare_with_go(&args);
    }
}

/// A running `aprond` whose standard error is read line by line.
struct Aprond {
    child: Child,
    log: Receiver<String>,
    lines: Vec<String>,
}

impl Aprond {
    fn start(args: &[&str]) -> Aprond {
        let mut child = Command::new(APROND)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, log) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { return };
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        let mut aprond = Aprond {
            child,
            log,
            lines: Vec::new(),
        };
        aprond.wait_for("msg=serving");
        aprond
    }

    /// Waits for a log line containing `text` and returns it.
    fn wait_for(&mut self, text: &str) -> String {
        if let Some(line) = self.lines.iter().find(|l| l.contains(text)) {
            return line.clone();
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.log.recv_timeout(left) {
                Ok(line) => {
                    self.lines.push(line.clone());
                    if line.contains(text) {
                        return line;
                    }
                }
                Err(_) => panic!("no log line with {text:?}; log:\n{}", self.lines.join("\n")),
            }
        }
    }

    /// The `addr` of the "<name> listening" line.
    fn addr(&mut self, name: &str) -> String {
        let line = self.wait_for(&format!("msg=\"{name} listening\""));
        line.rsplit_once("addr=").unwrap().1.to_string()
    }

    fn signal(&self, signal: &str) {
        let status = Command::new("kill")
            .args([&format!("-{signal}"), &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }

    /// Waits for the process to exit, at most `timeout`.
    fn wait(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }
}

impl Drop for Aprond {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct HttpResponse {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }
}

/// One HTTP/1.1 GET with no redirect handling, so a redirect shows.
fn get(addr: &str, path: &str) -> HttpResponse {
    let mut conn = TcpStream::connect(addr).unwrap();
    write!(
        conn,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    conn.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8(raw[..split].to_vec()).unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    HttpResponse {
        status,
        head,
        body: raw[split + 4..].to_vec(),
    }
}

/// SIGTERM and SIGINT end `run` within Go's shutdown timeout, with status 0,
/// while a client holds an idle keep-alive connection.
#[test]
fn test_signals_shut_down_within_gos_timeout() {
    for signal in ["TERM", "INT"] {
        let dir = TempDir::new();
        let uploads = dir.join("uploads");
        let mut aprond = Aprond::start(&[
            "--store",
            "memory",
            "--upload.dir",
            &uploads,
            "--addr",
            "127.0.0.1:0",
        ]);
        let addr = aprond.addr("apron server");
        assert_eq!(get(&addr, "/healthz").status, 200);
        let mut idle = TcpStream::connect(&addr).unwrap();
        write!(idle, "GET /healthz HTTP/1.1\r\nHost: {addr}\r\n\r\n").unwrap();
        let mut first = [0u8; 12];
        idle.read_exact(&mut first).unwrap();
        assert_eq!(&first, b"HTTP/1.1 200");
        let start = Instant::now();
        aprond.signal(signal);
        let status = aprond
            .wait(GO_SHUTDOWN_TIMEOUT)
            .unwrap_or_else(|| panic!("SIG{signal}: still running after {GO_SHUTDOWN_TIMEOUT:?}"));
        assert!(status.success(), "SIG{signal}: {status}");
        println!("SIG{signal}: exited in {:?}", start.elapsed());
    }
}

/// A `--config` file sets the listener, the store, the upload directory,
/// and the static directory `run` serves.
#[test]
fn test_config_file_and_static_dir() {
    let dir = TempDir::new();
    let site = TempDir::new();
    site.write("index.html", "<!doctype html>app");
    site.write("assets/app.js", "js");
    site.write(".env", "SECRET=1");
    let config = dir.write(
        "aprond.toml",
        &format!(
            "addr = \"127.0.0.1:0\"\nstore = \"sqlite:{}\"\nstatic-dir = \"{}\"\n\n[upload]\ndir = \"{}\"\n",
            dir.join("aprond.db"),
            site.0,
            dir.join("uploads"),
        ),
    );
    let mut aprond = Aprond::start(&["--config", &config]);
    let serving = aprond.wait_for("msg=serving");
    assert!(
        serving.contains(&format!("static_dir={}", site.0)),
        "{serving}"
    );
    let addr = aprond.addr("apron server");
    let index = get(&addr, "/");
    assert_eq!(
        (index.status, index.body.as_slice()),
        (200, &b"<!doctype html>app"[..])
    );
    assert_eq!(
        index.header("Content-Type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(get(&addr, "/assets/app.js").status, 200);
    assert_eq!(get(&addr, "/.env").status, 404);
    assert_eq!(get(&addr, "/assets/").status, 404);
    assert!(std::path::Path::new(&dir.join("aprond.db")).exists());
    aprond.signal("TERM");
    assert!(aprond
        .wait(GO_SHUTDOWN_TIMEOUT)
        .is_some_and(|s| s.success()));
}

/// The debug listener serves expvar, and one bound beyond loopback is
/// logged as Go logs it.
#[test]
fn test_debug_listener() {
    let dir = TempDir::new();
    let uploads = dir.join("uploads");
    let mut aprond = Aprond::start(&[
        "--store",
        "memory",
        "--upload.dir",
        &uploads,
        "--addr",
        "127.0.0.1:0",
        "--debug-addr",
        "0.0.0.0:0",
    ]);
    let warning = aprond.wait_for("level=WARN");
    assert!(
        warning.ends_with(
            "level=WARN msg=\"the debug listener is unauthenticated and not bound to loopback\" addr=0.0.0.0:0"
        ),
        "{warning}"
    );
    let port = aprond
        .addr("debug server")
        .rsplit_once(':')
        .unwrap()
        .1
        .to_string();
    let vars = get(&format!("127.0.0.1:{port}"), "/debug/vars");
    assert_eq!(vars.status, 200);
    assert!(String::from_utf8_lossy(&vars.body).contains("\"cmdline\""));
}

/// `--apple.app-id`, an extension: the association file lists exactly the
/// given apps, as JSON, with no redirect, and survives `--print-config`.
#[test]
fn test_apple_app_site_association() {
    let dir = TempDir::new();
    let uploads = dir.join("uploads");
    let base = [
        "--store",
        "memory",
        "--upload.dir",
        &uploads,
        "--addr",
        "127.0.0.1:0",
    ];
    let path = "/.well-known/apple-app-site-association";

    let mut with: Vec<&str> = base.to_vec();
    with.extend([
        "--apple.app-id",
        "ABCDE12345.chat.apron",
        "--apple.app-id",
        "ABCDE12345.chat.apron.dev",
    ]);
    let mut aprond = Aprond::start(&with);
    let addr = aprond.addr("apron server");
    let aasa = get(&addr, path);
    assert_eq!(aasa.status, 200, "{}", aasa.head);
    assert_eq!(aasa.header("Content-Type"), Some("application/json"));
    assert_eq!(aasa.header("Location"), None);
    assert_eq!(
        String::from_utf8(aasa.body).unwrap(),
        r#"{"webcredentials":{"apps":["ABCDE12345.chat.apron","ABCDE12345.chat.apron.dev"]}}"#
    );
    drop(aprond);

    let mut without = Aprond::start(&base);
    let addr = without.addr("apron server");
    let missing = get(&addr, path);
    assert_eq!((missing.status, missing.header("Location")), (404, None));
    drop(without);

    let (code, out, _) = output(
        APROND,
        &["--print-config", "--apple.app-id", "ABCDE12345.chat.apron"],
    );
    assert_eq!(code, 0);
    assert!(String::from_utf8(out).unwrap().contains("\n[apple]\n\n# iOS app allowed to use this server's passkeys, as <team ID>.<bundle ID>, listed in /.well-known/apple-app-site-association; repeat for more (not in the Go aprond)\napp-id = [\"ABCDE12345.chat.apron\"]\n\n[unfurl]\n"));

    let (code, _, err) = output(
        APROND,
        &[&base[..], &["--apple.app-id", "chat.apron"]].concat(),
    );
    assert_eq!(code, 1);
    assert_eq!(
        without_times(&err),
        r#"level=ERROR msg="server stopped" error="invalid --apple.app-id \"chat.apron\": use <team ID>.<bundle ID>, such as ABCDE12345.chat.apron""#
    );
}

/// `--unfurl.enable`, an extension: off by default, and kept by
/// `--print-config`.
#[test]
fn test_unfurl_flag() {
    let (code, out, _) = output(APROND, &["--print-config"]);
    assert_eq!(code, 0);
    let out = String::from_utf8(out).unwrap();
    assert!(out.ends_with("\n[unfurl]\n\n# Fetch the pages that messages link to and attach their OpenGraph previews, with images hosted here; the server then requests any public http(s) URL a user posts (off by default; not in the Go aprond)\nenable = false\n"), "{out}");
    let (code, out, _) = output(APROND, &["--print-config", "--unfurl.enable"]);
    assert_eq!(code, 0);
    assert!(String::from_utf8(out)
        .unwrap()
        .ends_with("\nenable = true\n"));
}
