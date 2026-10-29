//! Link previews. This file holds the local fixture servers and the tests of
//! URL extraction, page parsing, and the cache. unfurl_fetcher_test.rs and
//! unfurl_embeds_test.rs hold the rest. Pages come from local fixture
//! servers, so nothing reaches the internet.

use std::sync::{Arc, Mutex};

use rust_stdlib::net::http::{handler_func, httptest, ResponseWriter};
use rust_stdlib::net::{split_host_port, url};
use rust_stdlib::time::{self, Duration};

use super::helpers::*;
use crate::obj;
use crate::server::embeds::MAX_EMBEDS_PER_MESSAGE;
use crate::server::outbound::DialCheck;
use crate::server::protocol::*;
use crate::server::unfurl::page::{parse_page, Meta};
use crate::server::unfurl::*;

/// Serves fixture pages by path, counting the requests to each path and
/// keeping the last User-Agent.
pub(super) struct Fixture {
    pub(super) http: httptest::Server,
    hits: Arc<Mutex<Vec<String>>>,
    pub(super) user_agent: Arc<Mutex<String>>,
}

pub(super) type Route = Box<dyn Fn(&mut dyn ResponseWriter, &str) + Send + Sync>;

pub(super) fn fixture(routes: Vec<(&'static str, Route)>) -> Fixture {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let user_agent = Arc::new(Mutex::new(String::new()));
    let (seen, agent) = (hits.clone(), user_agent.clone());
    let http = httptest::Server::new(handler_func(move |w: &mut dyn ResponseWriter, r| {
        let path = r.url.path.clone();
        seen.lock().unwrap().push(path.clone());
        *agent.lock().unwrap() = r.header.get("User-Agent").unwrap_or("").to_owned();
        match routes.iter().find(|(p, _)| *p == path) {
            Some((_, route)) => route(w, &path),
            None => w.write_header(404),
        }
    }))
    .unwrap();
    Fixture {
        http,
        hits,
        user_agent,
    }
}

impl Fixture {
    pub(super) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.http.url)
    }

    pub(super) fn hits(&self, path: &str) -> usize {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|p| *p == path)
            .count()
    }

    pub(super) fn port(&self) -> String {
        split_host_port(&self.http.url["http://".len()..])
            .unwrap()
            .1
    }
}

pub(super) fn respond(content_type: &'static str, body: Vec<u8>) -> Route {
    Box::new(move |w, _| {
        w.header().set("Content-Type", content_type);
        w.write_header(200);
        let _ = std::io::Write::write_all(w, &body);
    })
}

pub(super) fn html(body: &str) -> Route {
    respond("text/html; charset=utf-8", body.as_bytes().to_vec())
}

pub(super) fn redirect(to: String) -> Route {
    Box::new(move |w, _| {
        w.header().set("Location", &to);
        w.write_header(302);
    })
}

/// Holds requests until opened.
#[derive(Clone, Default)]
pub(super) struct Gate(Arc<(Mutex<bool>, std::sync::Condvar)>);

impl Gate {
    pub(super) fn wait(&self) {
        let (open, changed) = &*self.0;
        let mut open = open.lock().unwrap();
        while !*open {
            open = changed.wait(open).unwrap();
        }
    }

    pub(super) fn open(&self) {
        *self.0 .0.lock().unwrap() = true;
        self.0 .1.notify_all();
    }
}

/// A page titled "Slow", answered once the gate opens.
pub(super) fn gated(gate: &Gate) -> Route {
    let gate = gate.clone();
    Box::new(move |w, _| {
        gate.wait();
        w.header().set("Content-Type", "text/html");
        w.write_header(200);
        let _ = std::io::Write::write_all(w, b"<title>Slow</title>");
    })
}

pub(super) fn allow_all() -> DialCheck {
    Arc::new(|_: &str| true)
}

pub(super) fn fetcher(check: DialCheck) -> Fetcher {
    Fetcher::new(check, FETCH_TIMEOUT)
}

pub(super) const ARTICLE: &str = r#"<!doctype html><html><head>
<title>Fallback title</title>
<meta property="og:title" content="Before &amp; after">
<meta property='og:description' content='The fix, explained'>
<meta property=og:site_name content=Example>
<meta property="og:image" content="/before.png">
<meta property="og:image:alt" content="Dashboard before the fix">
</head><body>ignored</body></html>"#;

pub(super) fn body(text: &str, format: &str) -> Object {
    let mut body = obj! {"text" => text};
    if !format.is_empty() {
        body.insert("format".into(), format.into());
    }
    body
}

#[test]
fn test_message_urls() {
    let cases: &[(&str, &str, &[&str])] = &[
        ("see https://a.example/x.", "", &["https://a.example/x"]),
        ("(http://a.example/wiki/Foo_(bar))", "", &["http://a.example/wiki/Foo_(bar)"]),
        ("[docs](https://a.example/docs)!", "markdown", &["https://a.example/docs"]),
        ("<https://a.example/>", "markdown", &["https://a.example/"]),
        ("HTTPS://A.example/ up", "", &["HTTPS://A.example/"]),
        ("xhttps://a.example/ ftp://a.example/ https:// mailto:a@b", "", &[]),
        ("https://a.example/ and https://a.example/ again", "", &["https://a.example/"]),
        ("`https://code.example/` https://prose.example/", "markdown", &["https://prose.example/"]),
        ("``a ` https://code.example/`` https://prose.example/", "markdown", &["https://prose.example/"]),
        ("```\nhttps://fenced.example/\n```\nhttps://prose.example/", "markdown", &["https://prose.example/"]),
        ("~~~~ sh\nhttps://fenced.example/\n~~~\nhttps://still.example/\n~~~~\nhttps://prose.example/", "markdown", &["https://prose.example/"]),
        ("`https://plain.example/`", "", &["https://plain.example/"]),
        ("`unclosed https://prose.example/", "markdown", &["https://prose.example/"]),
    ];
    for (text, format, want) in cases {
        assert_eq!(
            message_urls(Some(&body(text, format))),
            *want,
            "{text:?} {format:?}"
        );
    }
}

#[test]
fn test_message_urls_bounds_its_work() {
    let many: String = (0..25_000).map(|i| format!("http://a{i} ")).collect();
    assert!(many.len() > 200_000);
    let started = time::now();
    let urls = message_urls(Some(&body(&many, "")));
    let took = time::since(&started);
    let want: Vec<String> = (0..MAX_EMBEDS_PER_MESSAGE)
        .map(|i| format!("http://a{i}"))
        .collect();
    assert_eq!(urls, want);
    assert!(took < Duration::from_millis(500), "took {took:?}");

    let late = format!("{} https://late.example/", "x".repeat(MAX_SCANNED_BYTES));
    assert_eq!(message_urls(Some(&body(&late, ""))), Vec::<String>::new());
    let straddling = format!(
        "{}é https://late.example/",
        "x".repeat(MAX_SCANNED_BYTES - 1)
    );
    assert_eq!(
        message_urls(Some(&body(&straddling, ""))),
        Vec::<String>::new()
    );

    for adversarial in [
        "http".repeat(60_000),
        format!("http://a{}", ")".repeat(250_000)),
        "`` ` ".repeat(50_000),
    ] {
        let started = time::now();
        message_urls(Some(&body(&adversarial, "markdown")));
        let took = time::since(&started);
        assert!(took < Duration::from_millis(500), "took {took:?}");
    }
}

#[test]
fn test_parse_page() {
    let base = url::parse("https://a.example/posts/1").unwrap();
    assert_eq!(
        parse_page(ARTICLE, &base),
        Meta {
            title: "Before & after".into(),
            description: "The fix, explained".into(),
            site_name: "Example".into(),
            image: "https://a.example/before.png".into(),
            image_alt: "Dashboard before the fix".into(),
        }
    );
    assert_eq!(
        parse_page("<title>Only a title</title>", &base),
        Meta {
            title: "Only a title".into(),
            ..Meta::default()
        }
    );
    let fallbacks = r#"<html><head><!-- <meta property="og:title" content="commented"> -->
<script>document.write('<meta property="og:title" content="scripted">')</script>
<TITLE>  A
 title &lt;3 </TITLE><META NAME="Description" CONTENT="Meta description">
<meta property="og:image" content="javascript:alert(1)"></head>"#;
    assert_eq!(
        parse_page(fallbacks, &base),
        Meta {
            title: "A title <3".into(),
            description: "Meta description".into(),
            ..Meta::default()
        }
    );
}

#[test]
fn test_cache() {
    let page = fixture(vec![
        ("/post", html(ARTICLE)),
        ("/before.png", respond("image/png", test_png())),
    ]);
    let unfurler = Unfurler::new(fetcher(allow_all()), FETCH_TIMEOUT);
    let first = unfurler.preview(&page.url("/post")).unwrap();
    assert_eq!(unfurler.preview(&page.url("/post")).unwrap(), first);
    assert_eq!(unfurler.preview(&page.url("/missing")), None);
    assert_eq!(unfurler.preview(&page.url("/missing")), None);
    assert_eq!(
        (
            page.hits("/post"),
            page.hits("/before.png"),
            page.hits("/missing")
        ),
        (1, 1, 1)
    );

    let mut cache = Cache::default();
    let now = time::now();
    let found = Unfurled::Preview(first);
    cache.insert("https://a.example/", found.clone(), &now);
    cache.insert("https://b.example/", Unfurled::Nothing, &now);
    let later = |d: Duration| now.add(d);
    assert_eq!(
        cache.get("https://a.example/", &later(CACHE_TTL - time::SECOND)),
        Some(found)
    );
    assert_eq!(cache.get("https://a.example/", &later(CACHE_TTL)), None);
    assert_eq!(
        cache.get("https://b.example/", &later(FAILURE_TTL - time::SECOND)),
        Some(Unfurled::Nothing)
    );
    assert_eq!(cache.get("https://b.example/", &later(FAILURE_TTL)), None);
    for i in 0..MAX_CACHED + 10 {
        cache.insert(&format!("https://{i}.example/"), Unfurled::Nothing, &now);
    }
    assert_eq!(cache.len(), MAX_CACHED);
}

/// A preview whose image is `size` bytes.
fn sized(size: usize) -> Unfurled {
    Unfurled::Preview(Arc::new(Preview {
        meta: Meta::default(),
        image: Some(Image {
            bytes: vec![0; size],
            content_type: "image/png".into(),
            width: 1,
            height: 1,
        }),
    }))
}

#[test]
fn test_cache_byte_budget() {
    let mut cache = Cache::default();
    let now = time::now();
    let quarter = MAX_CACHED_BYTES / 4 + 1;
    for i in 0..4 {
        let at = now.add(Duration::from_secs(i));
        cache.insert(&format!("https://{i}.example/"), sized(quarter), &at);
    }
    let at = now.add(Duration::from_secs(4));
    let held: Vec<bool> = (0..4)
        .map(|i| cache.get(&format!("https://{i}.example/"), &at).is_some())
        .collect();
    assert_eq!(held, vec![false, true, true, true]);
    assert_eq!(cache.bytes(), 3 * quarter);

    cache.insert("https://huge.example/", sized(MAX_CACHED_BYTES + 1), &at);
    assert_eq!(cache.get("https://huge.example/", &at), None);
    assert_eq!(cache.bytes(), 3 * quarter);
}
