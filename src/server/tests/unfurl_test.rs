//! Link previews, an extension Go lacks: URL extraction, page parsing, the
//! fetcher's limits, the cache, and the republished link embeds. Pages come
//! from local fixture servers; nothing reaches the internet.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rust_stdlib::net::http::{handler_func, httptest, ResponseController, ResponseWriter};
use rust_stdlib::net::{split_host_port, url};
use rust_stdlib::time::{self, Duration};

use super::helpers::*;
use crate::obj;
use crate::server::embeds::MAX_EMBEDS_PER_MESSAGE;
use crate::server::outbound::{public_only, DialCheck};
use crate::server::protocol::*;
use crate::server::unfurl::*;
use crate::server::Config;

/// Serves fixture pages by path, counting the requests to each path and
/// keeping the last User-Agent.
struct Fixture {
    http: httptest::Server,
    hits: Arc<Mutex<Vec<String>>>,
    user_agent: Arc<Mutex<String>>,
}

type Route = Box<dyn Fn(&mut dyn ResponseWriter, &str) + Send + Sync>;

fn fixture(routes: Vec<(&'static str, Route)>) -> Fixture {
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
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.http.url)
    }

    fn hits(&self, path: &str) -> usize {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|p| *p == path)
            .count()
    }

    fn port(&self) -> String {
        split_host_port(&self.http.url["http://".len()..])
            .unwrap()
            .1
    }
}

fn respond(content_type: &'static str, body: Vec<u8>) -> Route {
    Box::new(move |w, _| {
        w.header().set("Content-Type", content_type);
        w.write_header(200);
        let _ = std::io::Write::write_all(w, &body);
    })
}

fn html(body: &str) -> Route {
    respond("text/html; charset=utf-8", body.as_bytes().to_vec())
}

fn redirect(to: String) -> Route {
    Box::new(move |w, _| {
        w.header().set("Location", &to);
        w.write_header(302);
    })
}

fn allow_all() -> DialCheck {
    Arc::new(|_: &str| true)
}

/// Admits only the given port, standing in for a public address.
fn allow_port(port: String) -> DialCheck {
    Arc::new(move |address: &str| split_host_port(address).is_ok_and(|(_, p)| p == port))
}

fn fetcher(check: DialCheck) -> Fetcher {
    Fetcher::new(check, FETCH_TIMEOUT)
}

const ARTICLE: &str = r#"<!doctype html><html><head>
<title>Fallback title</title>
<meta property="og:title" content="Before &amp; after">
<meta property='og:description' content='The fix, explained'>
<meta property=og:site_name content=Example>
<meta property="og:image" content="/before.png">
<meta property="og:image:alt" content="Dashboard before the fix">
</head><body>ignored</body></html>"#;

fn body(text: &str, format: &str) -> Object {
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
fn test_fetcher_preview() {
    let page = fixture(vec![
        ("/post", html(ARTICLE)),
        ("/before.png", respond("image/png", test_png())),
    ]);
    let preview = fetcher(allow_all()).preview(&page.url("/post")).unwrap();
    assert_eq!(
        preview,
        Preview {
            meta: Meta {
                title: "Before & after".into(),
                description: "The fix, explained".into(),
                site_name: "Example".into(),
                image: page.url("/before.png"),
                image_alt: "Dashboard before the fix".into(),
            },
            image: Some(Image {
                bytes: test_png(),
                content_type: "image/png".into(),
                width: 3,
                height: 2,
            }),
        }
    );
    assert_eq!(*page.user_agent.lock().unwrap(), USER_AGENT);
    assert!(USER_AGENT.contains("aprond/"), "{USER_AGENT}");
}

#[test]
fn test_fetcher_refuses_internal_addresses() {
    let page = fixture(vec![("/post", html(ARTICLE))]);
    assert_eq!(fetcher(public_only()).preview(&page.url("/post")), None);
    assert_eq!(page.hits("/post"), 0, "loopback was dialed");
    let localhost = page.url("/post").replace("127.0.0.1", "localhost");
    assert_eq!(fetcher(public_only()).preview(&localhost), None);
    assert_eq!(page.hits("/post"), 0, "localhost was dialed");
}

#[test]
fn test_fetcher_rechecks_redirects() {
    let private = fixture(vec![("/post", html(ARTICLE))]);
    let public = fixture(vec![("/go", redirect(private.url("/post")))]);
    let check = allow_port(public.port());
    assert_eq!(fetcher(check).preview(&public.url("/go")), None);
    assert_eq!(public.hits("/go"), 1);
    assert_eq!(private.hits("/post"), 0, "the redirect target was dialed");
}

#[test]
fn test_fetcher_redirect_limits() {
    let base = Arc::new(Mutex::new(String::new()));
    let hop = |next: &'static str| -> Route {
        let base = base.clone();
        Box::new(move |w, _| {
            let to = format!("{}{next}", base.lock().unwrap());
            w.header().set("Location", &to);
            w.write_header(302);
        })
    };
    let page = fixture(vec![
        ("/r4", hop("/r3")),
        ("/r3", hop("/r2")),
        ("/r2", hop("/r1")),
        ("/r1", hop("/post")),
        ("/ftp", redirect("ftp://127.0.0.1/post".into())),
        ("/post", html(ARTICLE)),
    ]);
    *base.lock().unwrap() = page.http.url.clone();
    let f = fetcher(allow_all());
    assert!(f.preview(&page.url("/r3")).is_some(), "3 redirects");
    assert_eq!(f.preview(&page.url("/r4")), None, "4 redirects");
    assert_eq!(f.preview(&page.url("/ftp")), None);
}

#[test]
fn test_fetcher_size_caps() {
    let padding = " ".repeat(MAX_PAGE_BYTES as usize);
    let late = format!("<html><head>{padding}<meta property=\"og:title\" content=\"Late\"></head>");
    let early = format!(
        "<html><head><meta property=\"og:title\" content=\"Early\">{padding}{padding}</head>"
    );
    let mut huge = test_png();
    huge.resize(MAX_IMAGE_BYTES as usize + 1, 0);
    let page = fixture(vec![
        ("/late", html(&late)),
        ("/early", html(&early)),
        (
            "/big-image",
            html(
                r#"<meta property="og:title" content="T"><meta property="og:image" content="/huge.png">"#,
            ),
        ),
        ("/huge.png", respond("image/png", huge)),
        (
            "/svg-image",
            html(
                r#"<meta property="og:title" content="T"><meta property="og:image" content="/i.svg">"#,
            ),
        ),
        (
            "/i.svg",
            respond(
                "image/svg+xml",
                b"<svg xmlns='http://www.w3.org/2000/svg'/>".to_vec(),
            ),
        ),
        (
            "/lying-image",
            html(
                r#"<meta property="og:title" content="T"><meta property="og:image" content="/page.png">"#,
            ),
        ),
        (
            "/page.png",
            respond("image/png", b"<html><script>1</script></html>".to_vec()),
        ),
        (
            "/jpg-image",
            html(
                r#"<meta property="og:title" content="T"><meta property="og:image" content="/i.jpg">"#,
            ),
        ),
        ("/i.jpg", respond("image/jpg", test_png())),
        (
            "/text",
            respond(
                "text/plain",
                b"<meta property=\"og:title\" content=\"T\">".to_vec(),
            ),
        ),
    ]);
    let f = fetcher(allow_all());
    assert_eq!(
        f.preview(&page.url("/late")),
        None,
        "read past the page cap"
    );
    assert_eq!(f.preview(&page.url("/early")).unwrap().meta.title, "Early");
    for path in ["/big-image", "/svg-image", "/lying-image"] {
        let preview = f.preview(&page.url(path)).unwrap();
        assert_eq!(
            (preview.meta.title.as_str(), preview.image),
            ("T", None),
            "{path}"
        );
    }
    assert_eq!(f.preview(&page.url("/text")), None, "not HTML");
    let mislabeled = f.preview(&page.url("/jpg-image")).unwrap().image.unwrap();
    assert_eq!(
        (mislabeled.content_type.as_str(), mislabeled.width),
        ("image/png", 3)
    );
}

#[test]
fn test_fetcher_timeout() {
    let stall: Route = Box::new(|w, _| {
        w.header().set("Content-Type", "text/html");
        w.write_header(200);
        let _ = std::io::Write::write_all(w, b"<html><head>");
        let _ = ResponseController::new(w).flush();
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let _ = std::io::Write::write_all(w, b"<title>Too late</title>");
    });
    let page = fixture(vec![("/slow", stall)]);
    let started = time::now();
    let preview = Fetcher::new(allow_all(), Duration::from_millis(300)).preview(&page.url("/slow"));
    let took = time::since(&started);
    assert_eq!(preview, None);
    assert!(took < Duration::from_millis(1200), "took {took:?}");
}

#[test]
fn test_cache() {
    let page = fixture(vec![
        ("/post", html(ARTICLE)),
        ("/before.png", respond("image/png", test_png())),
    ]);
    let unfurler = Unfurler::new(fetcher(allow_all()));
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

fn unfurl_server() -> (TestServer, TempDir) {
    let dir = TempDir::new("unfurl-uploads-");
    let server = new_test_server(Config {
        unfurl: true,
        unfurl_allow_internal: true,
        upload_dir: dir.to_string(),
        ..Config::default()
    });
    (server, dir)
}

/// Waits for the server's unfurls to land.
fn settle(server: &TestServer) {
    let unfurler = server.app.lock().unfurler.clone().expect("unfurl enabled");
    unfurler.pending.wait();
}

fn post(c: &mut TestClient, text: &str, format: &str) -> String {
    let id = c.next_id("m");
    let (_, result) = c.request("message", &id, obj! {"body" => body(text, format)});
    result["message_id"].as_str().unwrap().to_owned()
}

#[test]
fn test_unfurl_republishes_link_embed() {
    let page = fixture(vec![
        ("/post", html(ARTICLE)),
        ("/before.png", respond("image/png", test_png())),
    ]);
    let (mut server, dir) = unfurl_server();
    let mut c = dial_test_client(&server);
    let target = page.url("/post");
    let message_id = post(&mut c, &format!("Before the fix: {target}"), "");
    settle(&server);
    let snapshot = c.notification("message");
    assert_eq!(snapshot["message_id"].as_str(), Some(message_id.as_str()));
    let embeds = embeds_of(&snapshot);
    assert_eq!(embeds.len(), 1, "{snapshot:?}");
    let image_url = embeds[0]["og"].as_object().unwrap()["image"]
        .as_object()
        .unwrap()["url"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        image_url.starts_with(&format!("{}/files/embed_1/", server.http.url)),
        "{image_url} is not on the server's origin"
    );
    assert_eq!(
        embeds[0],
        obj! {
            "embed_id" => "embed_1",
            "kind" => "link",
            "url" => target.as_str(),
            "og" => obj! {
                "title" => "Before & after",
                "description" => "The fix, explained",
                "site_name" => "Example",
                "image" => obj! {
                    "url" => image_url.as_str(),
                    "type" => "image/png",
                    "width" => 3i64,
                    "height" => 2i64,
                    "alt" => "Dashboard before the fix",
                },
            },
        }
    );
    let (status, bytes) = http_get(&image_url);
    assert_eq!((status, bytes), (200, test_png()));

    // A save that keeps the embed keeps the server's og, even when the
    // client sends its own.
    let id = c.next_id("edit");
    let (before, _) = c.request(
        "message",
        &id,
        obj! {
            "message_id" => message_id.as_str(),
            "body" => obj! {
                "text" => format!("Edited: {target}"),
                "embeds" => vec![Json::from(obj! {"embed_id" => "embed_1", "kind" => "link", "og" => obj! {"title" => "spoofed"}})],
            },
        },
    );
    settle(&server);
    let edited = notification_params(&before[0], "message");
    assert_eq!(embeds_of(&edited), embeds);
    c.expect_quiet();
    assert_eq!(page.hits("/post"), 1);

    // Deleting the message deletes the hosted image.
    let path = server.app.lock().embeds["embed_1"].path.clone();
    assert!(path.starts_with(&dir.to_string()) && std::path::Path::new(&path).exists());
    let id = c.next_id("delete");
    c.request(
        "message",
        &id,
        obj! {"message_id" => message_id.as_str(), "deleted" => true},
    );
    assert!(
        !std::path::Path::new(&path).exists(),
        "image kept after delete"
    );
    assert_eq!(http_get(&image_url).0, 404);
    server.stop();
}

#[test]
fn test_unfurl_limits() {
    let pages: Vec<(&'static str, Route)> = ["/1", "/2", "/3", "/4", "/code", "/text-only"]
        .into_iter()
        .map(|p| (p, html(r#"<title>Page</title>"#)))
        .collect();
    let page = fixture(pages);
    let (mut server, _dir) = unfurl_server();
    let mut c = dial_test_client(&server);

    // The first three URLs, and none in code.
    let text = format!(
        "`{}` {} {} {} {}",
        page.url("/code"),
        page.url("/1"),
        page.url("/2"),
        page.url("/3"),
        page.url("/4")
    );
    post(&mut c, &text, "markdown");
    settle(&server);
    let snapshot = c.notification("message");
    let linked: Vec<String> = embeds_of(&snapshot)
        .iter()
        .map(|e| e["url"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(linked, vec![page.url("/1"), page.url("/2"), page.url("/3")]);
    assert_eq!(
        embeds_of(&snapshot)[0]["og"],
        Json::from(obj! {"title" => "Page"})
    );
    assert_eq!((page.hits("/code"), page.hits("/4")), (0, 0));

    // A user unfurls UNFURLS_PER_MINUTE URLs a minute; 3 are spent.
    let mut fetched = 0;
    for i in 0..UNFURLS_PER_MINUTE {
        post(&mut c, &format!("{}?{i}", page.url("/text-only")), "");
        settle(&server);
        if i < UNFURLS_PER_MINUTE - 3 {
            c.notification("message");
            fetched += 1;
        }
    }
    c.expect_quiet();
    assert_eq!(fetched, UNFURLS_PER_MINUTE - 3);
    assert_eq!(page.hits("/text-only") as i64, UNFURLS_PER_MINUTE - 3);
    server.stop();
}

#[test]
fn test_unfurl_edit_adds_one_url() {
    let pages: Vec<(&'static str, Route)> = ["/1", "/2", "/3", "/4"]
        .into_iter()
        .map(|p| (p, html(r#"<title>Page</title>"#)))
        .collect();
    let page = fixture(pages);
    let (mut server, _dir) = unfurl_server();
    let mut c = dial_test_client(&server);
    let first = [page.url("/1"), page.url("/2"), page.url("/3")].join(" ");
    let message_id = post(&mut c, &first, "");
    settle(&server);
    let embeds: Vec<Json> = embeds_of(&c.notification("message"))
        .into_iter()
        .map(|e| obj! {"embed_id" => e["embed_id"].clone(), "kind" => "link"}.into())
        .collect();
    assert_eq!(embeds.len(), 3);

    let id = c.next_id("edit");
    let (before, _) = c.request(
        "message",
        &id,
        obj! {
            "message_id" => message_id.as_str(),
            "body" => obj! {"text" => format!("{first} {}", page.url("/4")), "embeds" => embeds},
        },
    );
    assert_eq!(
        embeds_of(&notification_params(&before[0], "message")).len(),
        3
    );
    settle(&server);
    let linked: Vec<String> = embeds_of(&c.notification("message"))
        .iter()
        .map(|e| e["url"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        linked,
        vec![
            page.url("/1"),
            page.url("/2"),
            page.url("/3"),
            page.url("/4")
        ]
    );
    let hits: Vec<usize> = ["/1", "/2", "/3", "/4"].map(|p| page.hits(p)).to_vec();
    assert_eq!(hits, vec![1, 1, 1, 1]);
    server.stop();
}

#[test]
fn test_unfurl_off_by_default() {
    let page = fixture(vec![("/post", html(ARTICLE))]);
    let mut server = new_test_server(Config::default());
    assert!(server.app.lock().unfurler.is_none());
    let mut c = dial_test_client(&server);
    post(&mut c, &page.url("/post"), "");
    std::thread::sleep(std::time::Duration::from_millis(200));
    c.expect_quiet();
    assert_eq!(page.hits("/post"), 0);
    server.stop();
}

#[test]
fn test_unfurl_skips_removed_urls() {
    let release = Arc::new(AtomicUsize::new(0));
    let gate = release.clone();
    let slow: Route = Box::new(move |w, _| {
        while gate.load(Ordering::SeqCst) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        w.header().set("Content-Type", "text/html");
        w.write_header(200);
        let _ = std::io::Write::write_all(w, b"<title>Slow</title>");
    });
    let page = fixture(vec![("/slow", slow)]);
    let (mut server, _dir) = unfurl_server();
    let mut c = dial_test_client(&server);
    let message_id = post(&mut c, &page.url("/slow"), "");
    let id = c.next_id("edit");
    c.request(
        "message",
        &id,
        obj! {"message_id" => message_id.as_str(), "body" => obj! {"text" => "never mind"}},
    );
    release.store(1, Ordering::SeqCst);
    settle(&server);
    c.expect_quiet();
    assert!(server.app.lock().embeds.is_empty());
    server.stop();
}
