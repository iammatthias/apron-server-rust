//! cmd/aprond/email_test.go.

use super::email::{HttpSender, SmtpSender};
use rust_stdlib::context::Context;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// A minimal SMTP relay without STARTTLS that keeps the DATA it receives,
/// or, when `stall` is set, never answers after connecting.
fn fake_relay(stall: bool) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (received, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            let received = received.clone();
            std::thread::spawn(move || {
                if stall {
                    let _ = conn.read(&mut [0u8; 1]);
                    return;
                }
                let mut r = BufReader::new(conn.try_clone().unwrap());
                let mut write = |line: &str| {
                    let _ = conn.write_all(format!("{line}\r\n").as_bytes());
                };
                write("220 relay.test ESMTP");
                let mut data = String::new();
                let mut in_data = false;
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if in_data {
                        if line == ".\r\n" {
                            in_data = false;
                            let _ = received.send(std::mem::take(&mut data));
                            write("250 queued");
                            continue;
                        }
                        data.push_str(&line);
                        continue;
                    }
                    let verb = format!("{line} x")
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_uppercase();
                    match verb.as_str() {
                        "EHLO" | "HELO" => write("250 relay.test"),
                        "DATA" => {
                            in_data = true;
                            write("354 go ahead");
                        }
                        "QUIT" => {
                            write("221 bye");
                            return;
                        }
                        _ => write("250 ok"),
                    }
                }
            });
        }
    });
    (addr, rx)
}

const TEXT: &str = "Your sign-in code is 418092.\n\nThe code expires in 10 minutes. If you did not ask for it, ignore this email.\n";

#[test]
fn test_smtp_sender_requires_starttls() {
    let (addr, received) = fake_relay(false);
    let mut sender = SmtpSender::new(&addr, "Apron <chat@example.com>", "", "", false).unwrap();
    let ctx = Context::background();
    match sender.send_sign_in_code(&ctx, "ada@example.com", "418092", false, TEXT) {
        Err(e) if e.to_string().contains("STARTTLS") => {}
        other => panic!("cleartext relay without --email.smtp-insecure: {other:?}"),
    }
    sender.insecure = true;
    sender
        .send_sign_in_code(&ctx, "ada@example.com", "418092", false, TEXT)
        .unwrap();
    let data = received.recv().unwrap();
    assert!(
        data.contains("Subject: Your sign-in code is 418092")
            && data.contains("To: ada@example.com"),
        "message: {data:?}"
    );
    assert!(
        data.contains("From: \"Apron\" <chat@example.com>\r\n"),
        "message: {data:?}"
    );
    assert!(
        data.contains("@example.com>\r\nMIME-Version: 1.0\r\n"),
        "message: {data:?}"
    );
    assert!(
        data.ends_with("ignore this email.\r\n"),
        "message: {data:?}"
    );
}

#[test]
fn test_smtp_sender_stops_at_its_deadline() {
    let (addr, _received) = fake_relay(true);
    let sender = SmtpSender::new(&addr, "chat@example.com", "", "", true).unwrap();
    let (ctx, _cancel) =
        Context::background().with_timeout(rust_stdlib::time::Duration::from_millis(200));
    let start = Instant::now();
    assert!(
        sender
            .send_sign_in_code(&ctx, "ada@example.com", "1", false, "")
            .is_err(),
        "a stalled relay did not fail"
    );
    let elapsed = start.elapsed();
    assert!(
        elapsed <= Duration::from_secs(2),
        "took {elapsed:?} past a 200ms deadline"
    );
}

#[test]
fn test_new_smtp_sender_errors() {
    assert_eq!(
        SmtpSender::new("smtp.example", "chat@example.com", "", "", false).unwrap_err(),
        "invalid --email.smtp-addr \"smtp.example\": use host:port, such as smtp.example.com:587"
    );
    assert_eq!(
        SmtpSender::new(":587", "chat@example.com", "", "", false).unwrap_err(),
        "invalid --email.smtp-addr \":587\": use host:port, such as smtp.example.com:587"
    );
    assert_eq!(
        SmtpSender::new("smtp.example:587", "", "", "", false).unwrap_err(),
        "invalid --email.from \"\": an email address is required"
    );
}

/// A local mail API that records each request's method, path, headers and
/// body, and answers with `status`.
fn capture_api(
    status: u16,
) -> (
    rust_stdlib::net::http::httptest::Server,
    mpsc::Receiver<(String, String, rust_stdlib::net::http::Header, String)>,
) {
    use rust_stdlib::net::http::{handler_func, httptest};
    let (tx, rx) = mpsc::channel();
    let tx = std::sync::Mutex::new(tx);
    let server = httptest::Server::new(handler_func(move |w, r| {
        let body = r
            .body
            .as_ref()
            .map(|b| b.read_all().unwrap())
            .unwrap_or_default();
        let _ = tx.lock().unwrap().send((
            r.method.clone(),
            r.url.path.clone(),
            r.header.clone(),
            String::from_utf8(body).unwrap(),
        ));
        w.write_header(status);
    }))
    .unwrap();
    (server, rx)
}

#[test]
fn test_http_sender_posts_json() {
    let (api, requests) = capture_api(202);
    let sender = HttpSender::new(
        &format!("{}/send", api.url),
        "Apron <chat@example.com>",
        &[
            "Authorization: Bearer secret".to_string(),
            "X-Extra:  yes ".to_string(),
        ],
    )
    .unwrap();
    sender
        .send_sign_in_code(
            &Context::background(),
            "ada@example.com",
            "123456",
            false,
            "Your code is 123456.\n",
        )
        .unwrap();
    let (method, path, header, body) = requests.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!((method.as_str(), path.as_str()), ("POST", "/send"));
    assert_eq!(header.get("Authorization"), Some("Bearer secret"));
    assert_eq!(header.get("X-Extra"), Some("yes"));
    assert_eq!(header.get("Content-Type"), Some("application/json"));
    assert_eq!(
        body,
        r#"{"from":"\"Apron\" <chat@example.com>","subject":"Your sign-in code is 123456","text":"Your code is 123456.\n","to":"ada@example.com"}"#
    );
    sender
        .send_sign_in_code(
            &Context::background(),
            "ada@example.com",
            "654321",
            true,
            "",
        )
        .unwrap();
    let (_, _, _, body) = requests.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(
        body.contains(r#""subject":"Your code to add this address is 654321""#),
        "{body}"
    );
}

#[test]
fn test_http_sender_fails_on_a_refusal() {
    let (api, _requests) = capture_api(401);
    let sender = HttpSender::new(&api.url, "chat@example.com", &[]).unwrap();
    let err = sender
        .send_sign_in_code(
            &Context::background(),
            "ada@example.com",
            "123456",
            false,
            "",
        )
        .unwrap_err();
    assert!(err.to_string().contains("401"), "{err}");
}

#[test]
fn test_new_http_sender_errors() {
    for (url, from, header, want) in [
        (
            "",
            "chat@example.com",
            None,
            "invalid --email.http-url \"\"",
        ),
        (
            "ftp://api.example/",
            "chat@example.com",
            None,
            "invalid --email.http-url",
        ),
        (
            "https://api.example/",
            "",
            None,
            "invalid --email.from \"\"",
        ),
        (
            "https://api.example/",
            "chat@example.com",
            Some("Authorization"),
            "invalid --email.http-header \"Authorization\"",
        ),
        (
            "https://api.example/",
            "chat@example.com",
            Some("Bad Name: x"),
            "invalid --email.http-header",
        ),
    ] {
        let headers: Vec<String> = header.into_iter().map(str::to_string).collect();
        let err = HttpSender::new(url, from, &headers).unwrap_err();
        assert!(err.starts_with(want), "{url} {from} {header:?}: {err}");
    }
}
