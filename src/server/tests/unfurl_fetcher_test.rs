//! The link preview fetcher's limits. It refuses internal addresses and
//! checks redirects, image dimensions, sizes, and timeouts. Pages come from
//! the local fixture servers in unfurl_test.rs, so nothing reaches the
//! internet.

use std::sync::{Arc, Mutex};

use rust_stdlib::net::http::ResponseController;
use rust_stdlib::time::{self, Duration};

use super::helpers::*;
use super::unfurl_test::{
    allow_all, fetcher, fixture, html, redirect, respond, Gate, Route, ARTICLE,
};
use crate::server::outbound::{public_only, DialCheck};
use crate::server::unfurl::page::Meta;
use crate::server::unfurl::*;

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
fn test_dial_check_ports() {
    for (address, want) in [
        ("93.184.215.14:80", true),
        ("93.184.215.14:443", true),
        ("[2606:4700::1111]:443", true),
        ("93.184.215.14:8080", false),
        ("93.184.215.14:8443", false),
        ("93.184.215.14:22", false),
        ("10.0.0.1:443", false),
        ("127.0.0.1:80", false),
    ] {
        assert_eq!(dial_check()(address), want, "{address}");
    }
}

/// The redirect target's address is checked when dialed: here its port is
/// not one the check admits.
#[test]
fn test_fetcher_rechecks_redirects() {
    let other = fixture(vec![("/post", html(ARTICLE))]);
    let first = fixture(vec![("/go", redirect(other.url("/post")))]);
    let check = on_ports(allow_all(), vec![first.port()]);
    assert_eq!(fetcher(check).preview(&first.url("/go")), None);
    assert_eq!(first.hits("/go"), 1);
    assert_eq!(other.hits("/post"), 0, "the redirect target was dialed");
}

/// A PNG of `width` by `height` pixels as far as its header says.
fn png_claiming(width: u32, height: u32) -> Vec<u8> {
    let mut png = test_png();
    png[16..20].copy_from_slice(&width.to_be_bytes());
    png[20..24].copy_from_slice(&height.to_be_bytes());
    let crc = rust_stdlib::hash::crc32::checksum_ieee(&png[12..29]);
    png[29..33].copy_from_slice(&crc.to_be_bytes());
    png
}

#[test]
fn test_fetcher_image_dimensions() {
    let page_with = |image: &str| -> Route {
        html(&format!(
            r#"<meta property="og:title" content="T"><meta property="og:image" content="{image}">"#
        ))
    };
    let page = fixture(vec![
        ("/wide", page_with("/wide.png")),
        ("/wide.png", respond("image/png", png_claiming(8193, 1))),
        ("/tall", page_with("/tall.png")),
        ("/tall.png", respond("image/png", png_claiming(1, 8193))),
        ("/many", page_with("/many.png")),
        ("/many.png", respond("image/png", png_claiming(7000, 7000))),
        ("/fits", page_with("/fits.png")),
        ("/fits.png", respond("image/png", png_claiming(8192, 4800))),
    ]);
    let f = fetcher(allow_all());
    let dimensions = |path: &str| {
        f.preview(&page.url(path))
            .unwrap()
            .image
            .map(|i| (i.width, i.height))
    };
    assert_eq!(dimensions("/wide"), None);
    assert_eq!(dimensions("/tall"), None);
    assert_eq!(dimensions("/many"), None);
    assert_eq!(dimensions("/fits"), Some((8192, 4800)));
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
    let gate = Gate::default();
    let held = gate.clone();
    let stall: Route = Box::new(move |w, _| {
        w.header().set("Content-Type", "text/html");
        w.write_header(200);
        let _ = std::io::Write::write_all(w, b"<html><head>");
        let _ = ResponseController::new(w).flush();
        held.wait();
        let _ = std::io::Write::write_all(w, b"<title>Too late</title>");
    });
    let page = fixture(vec![("/slow", stall)]);
    let started = time::now();
    let preview = Fetcher::new(allow_all(), Duration::from_millis(100)).preview(&page.url("/slow"));
    let took = time::since(&started);
    gate.open();
    assert_eq!(preview, None);
    assert!(took < Duration::from_millis(1000), "took {took:?}");
}

/// A dial that blocks the way a lookup with no deadline does is given up
/// on at the unfurler's timeout, not awaited.
#[test]
fn test_unfurler_gives_up_on_a_stuck_dial() {
    let page = fixture(vec![("/post", html(ARTICLE))]);
    let stuck: DialCheck = Arc::new(|_: &str| {
        std::thread::sleep(std::time::Duration::from_secs(3));
        true
    });
    let timeout = Duration::from_millis(100);
    let unfurler = Unfurler::new(Fetcher::new(stuck, timeout), timeout);
    let started = time::now();
    let previews = unfurler.previews(&[page.url("/post")]);
    let took = time::since(&started);
    assert!(previews.is_empty());
    assert!(took < Duration::from_millis(1000), "took {took:?}");
}
