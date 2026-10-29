//! The `aprond` binary: its command line against the golden files in
//! `tests/golden`, and `run` end to end over real listeners.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

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

/// Runs `aprond` with each case and compares its exit status, standard
/// output and standard error (without log times) with `tests/golden/<name>`.
/// Each `(from, to)` in `masks` replaces a per-run value such as a temp path.
/// `APRON_UPDATE_GOLDEN=1` rewrites the file instead.
fn check_golden(name: &str, cases: &[Vec<&str>], masks: &[(String, &str)]) {
    let mut got = String::new();
    for args in cases {
        // The default store, upload and certificate paths come from the
        // user's directories, and `--help` wraps them. macOS derives them
        // from HOME; Linux reads the XDG variables, set here to the same
        // directories, so both print identical text.
        let out = Command::new(APROND)
            .args(args)
            .env("HOME", "/home/aprond")
            .env("XDG_DATA_HOME", "/home/aprond/Library/Application Support")
            .env("XDG_CACHE_HOME", "/home/aprond/Library/Caches")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        let (code, out, err) = (out.status.code().unwrap_or(-1), out.stdout, out.stderr);
        got.push_str(&format!(
            "$ aprond {}\nexit {code}\n--- stdout\n{}--- stderr\n{}\n\n",
            args.join(" "),
            String::from_utf8_lossy(&out),
            without_times(&err),
        ));
    }
    for (from, to) in masks {
        got = got.replace(from.as_str(), to);
    }
    let path = format!("{}/tests/golden/{name}", env!("CARGO_MANIFEST_DIR"));
    if std::env::var("APRON_UPDATE_GOLDEN").as_deref() == Ok("1") {
        std::fs::write(&path, &got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: {e}; run with APRON_UPDATE_GOLDEN=1"));
    if want != got {
        let line = want
            .lines()
            .zip(got.lines())
            .position(|(w, g)| w != g)
            .unwrap_or(want.lines().count().min(got.lines().count()));
        panic!(
            "{path} differs at line {}:\n--- want\n{}\n--- got\n{}\n(rerun with APRON_UPDATE_GOLDEN=1 if the change is intended)",
            line + 1,
            want.lines().nth(line).unwrap_or("<end>"),
            got.lines().nth(line).unwrap_or("<end>"),
        );
    }
}

fn write_config(text: &str) -> (TempDir, String) {
    let dir = TempDir::new();
    let path = dir.write("aprond.toml", text);
    (dir, path)
}

#[test]
fn test_print_config_matches_golden() {
    let (dir, path) = write_config(
        "public-url = \"https://chat.example\"\nrole = [\"admin=ada\"]\n[upload]\nmax-mb = 5\n[tls]\ndomain = []\n",
    );
    let cases = [
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
    ]
    .map(<[&str]>::to_vec);
    check_golden(
        "print-config.txt",
        &cases,
        &[(format!("{}/", dir.0), "$TMP/")],
    );
}

#[test]
fn test_help_and_errors_match_golden() {
    let (dir, unknown) = write_config("[upload]\nmax = 1\n");
    let (dir2, bad_int) = write_config("max-connections = \"many\"\n");
    let cases = [
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
    ]
    .map(<[&str]>::to_vec);
    check_golden(
        "help-and-errors.txt",
        &cases,
        &[
            (format!("{}/", dir.0), "$TMP/"),
            (format!("{}/", dir2.0), "$TMP2/"),
        ],
    );
}

/// The errors `run` stops with before it serves, logged as "server stopped"
/// with exit status 1, as the Go `aprond` does.
#[test]
fn test_startup_errors_match_golden() {
    let dir = TempDir::new();
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = busy.local_addr().unwrap().to_string();
    let not_a_database = format!("sqlite:{}", dir.write("bad.db", &"x".repeat(128)));
    let uploads = dir.join("uploads");
    let base = ["--upload.dir", &uploads];
    let cases: [Vec<&str>; 8] = [
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
        vec!["--store", "memory", "--frame.max-depth", "0"],
    ];
    let cases: Vec<Vec<&str>> = cases
        .into_iter()
        .map(|case| base.iter().copied().chain(case).collect())
        .collect();
    check_golden(
        "startup-errors.txt",
        &cases,
        &[(format!("{}/", dir.0), "$TMP/"), (busy.clone(), "$BUSY")],
    );
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
    assert!(out.contains("\n[unfurl]\n\n# Fetch the pages that messages link to and attach their OpenGraph previews, with images hosted here; the server then requests any public http(s) URL a user posts (off by default; not in the Go aprond)\nenable = false\n\n[guest]\n"), "{out}");
    let (code, out, _) = output(APROND, &["--print-config", "--unfurl.enable"]);
    assert_eq!(code, 0);
    assert!(String::from_utf8(out)
        .unwrap()
        .contains("\nenable = true\n\n[guest]\n"));
}

/// The first frame a WebSocket client at `addr` reads: the `server` frame.
fn server_frame(addr: &str) -> String {
    let timeout = rust_stdlib::time::SECOND;
    let conn = apron::ws::dial(&format!("ws://{addr}/ws"), &[], timeout).unwrap();
    String::from_utf8(conn.read().unwrap().1).unwrap()
}

/// Guests only read unless `--guest.posting`, and the `server` frame's
/// welcome says so.
#[test]
fn test_guest_posting_flag() {
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
    for (extra, want) in [
        (None, "Guests can read along."),
        (
            Some("--guest.posting"),
            "Guests can post under a new name each visit.",
        ),
    ] {
        let args: Vec<&str> = base.iter().copied().chain(extra).collect();
        let mut aprond = Aprond::start(&args);
        let frame = server_frame(&aprond.addr("apron server"));
        assert!(frame.contains(want), "{extra:?}: {frame}");
    }
}

/// `--frame.max-bytes` bounds what a client may send.
#[test]
fn test_frame_flags() {
    let dir = TempDir::new();
    let uploads = dir.join("uploads");
    let args = [
        "--store",
        "memory",
        "--upload.dir",
        &uploads,
        "--addr",
        "127.0.0.1:0",
        "--frame.max-bytes",
        "100",
    ];
    let mut aprond = Aprond::start(&args);
    let addr = aprond.addr("apron server");
    let timeout = rust_stdlib::time::SECOND;
    let conn = apron::ws::dial(&format!("ws://{addr}/ws"), &[], timeout).unwrap();
    let frame = format!(
        r#"{{"method":"auth","id":"a","params":{{"x":"{}"}}}}"#,
        "x".repeat(100)
    );
    conn.write(apron::ws::MessageType::Text, frame.as_bytes(), timeout)
        .unwrap();
    loop {
        match conn.read() {
            Ok(_) => continue,
            Err(apron::ws::Error::Closed { code, .. }) => {
                assert_eq!(code, apron::ws::STATUS_MESSAGE_TOO_BIG);
                break;
            }
            Err(e) => panic!("{e}"),
        }
    }
}

/// `--guest.posting` and `--history.retention`, extensions: kept by
/// `--print-config`, and a retention that is not a positive Go duration
/// stops the server.
#[test]
fn test_guest_and_history_flags() {
    let (code, out, _) = output(
        APROND,
        &[
            "--print-config",
            "--guest.posting",
            "--history.retention",
            "168h",
        ],
    );
    assert_eq!(code, 0);
    assert!(String::from_utf8(out)
        .unwrap()
        .contains("\nposting = true\n\n[history]\n\n# Delete messages, reactions, and their uploads older than this, such as 168h, checking hourly; emptied threads and private rooms go, other rooms stay (default: keep forever; not in the Go aprond)\nretention = \"168h\"\n\n[frame]\n"));
    for bad in ["7d", "-1h"] {
        let flag = format!("--history.retention={bad}");
        let (code, _, err) = output(APROND, &["--store", "memory", &flag]);
        assert_eq!(code, 1, "{bad}");
        assert_eq!(
            without_times(&err),
            format!("level=ERROR msg=\"server stopped\" error=\"invalid --history.retention \\\"{bad}\\\": use a positive duration, such as 168h\"")
        );
    }
}

/// The admin token comes from `--admin-token-file` or `$APRON_ADMIN_TOKEN`,
/// must be at least 16 bytes, and never shows in `--print-config`.
#[test]
fn test_admin_token_sources() {
    let token = "a-long-admin-token-0123456789";
    let run = |args: &[&str], env: &str| {
        let out = Command::new(APROND)
            .args(args)
            .env("APRON_ADMIN_TOKEN", env)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    let (code, stdout, _) = run(&["--print-config"], token);
    assert!(
        code == 0 && !stdout.contains(token),
        "print-config: {stdout}"
    );
    let (code, _, stderr) = run(&["--store", "memory", "--addr", "127.0.0.1:0"], "short");
    assert!(
        code != 0 && stderr.contains("The admin token is shorter than 16 bytes"),
        "short env token: {code} {stderr}"
    );
    let dir = TempDir::new();
    let path = dir.write("token", "short\n");
    let (code, _, stderr) = run(
        &[
            "--store",
            "memory",
            "--addr",
            "127.0.0.1:0",
            "--admin-token-file",
            &path,
        ],
        token,
    );
    assert!(
        code != 0 && stderr.contains("The admin token is shorter than 16 bytes"),
        "the file wins over the environment: {code} {stderr}"
    );
    let (code, _, stderr) = run(
        &[
            "--store",
            "memory",
            "--addr",
            "127.0.0.1:0",
            "--admin-token-file",
            &dir.join("none"),
        ],
        "",
    );
    assert!(
        code != 0 && stderr.contains("Failed to read --admin-token-file"),
        "missing file: {code} {stderr}"
    );
}
