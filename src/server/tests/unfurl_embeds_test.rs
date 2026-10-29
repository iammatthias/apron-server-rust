//! Link embeds through a running server. A message's links are fetched
//! and republished as embeds, within the limits, across edits, evictions,
//! and restarts. Pages come from the local fixture servers in unfurl_test.rs,
//! so nothing reaches the internet.

use std::sync::Arc;

use rust_stdlib::time::{self, Duration};

use super::helpers::*;
use super::persist_test::{start_with, start_with_store};
use super::unfurl_test::{body, fixture, gated, html, respond, Fixture, Gate, Route, ARTICLE};
use crate::obj;
use crate::server::config::Config;
use crate::server::embeds::MAX_EMBEDS_PER_MESSAGE;
use crate::server::protocol::*;
use crate::server::unfurl::*;
use crate::store::{self, Store};

fn unfurl_server() -> (TestServer, TempDir) {
    unfurl_server_with(default_config())
}

fn unfurl_server_with(config: Config) -> (TestServer, TempDir) {
    let dir = TempDir::new("unfurl-uploads-");
    let server = new_test_server(Config {
        unfurl: true,
        unfurl_allow_internal: true,
        upload_dir: dir.to_string(),
        ..config
    });
    (server, dir)
}

/// The upload files in dir.
fn upload_files(dir: &TempDir) -> usize {
    std::fs::read_dir(dir.to_string())
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".upload")
        })
        .count()
}

/// Waits for the server's unfurls to land.
fn settle(server: &TestServer) {
    server.app.unfurler.as_ref().expect("unfurl enabled").wait();
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
    assert_eq!(upload_files(&dir), 1);
    let id = c.next_id("delete");
    c.request(
        "message",
        &id,
        obj! {"message_id" => message_id.as_str(), "deleted" => true},
    );
    assert_eq!(upload_files(&dir), 0, "image kept after delete");
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
    let mut server = new_test_server(default_config());
    let mut c = dial_test_client(&server);
    post(&mut c, &page.url("/post"), "");
    c.expect_quiet();
    assert_eq!(page.hits("/post"), 0);
    server.stop();
}

#[test]
fn test_unfurl_skips_removed_urls() {
    let gate = Gate::default();
    let page = fixture(vec![("/slow", gated(&gate))]);
    let (mut server, _dir) = unfurl_server();
    let mut c = dial_test_client(&server);
    let message_id = post(&mut c, &page.url("/slow"), "");
    let id = c.next_id("edit");
    c.request(
        "message",
        &id,
        obj! {"message_id" => message_id.as_str(), "body" => obj! {"text" => "never mind"}},
    );
    gate.open();
    settle(&server);
    c.expect_quiet();
    server.stop();
}

#[test]
fn test_unfurl_jobs_saturate() {
    let gate = Gate::default();
    let paths: Vec<&'static str> = (0..=MAX_JOBS)
        .map(|i| &*format!("/slow{i}").leak())
        .collect();
    let later: Vec<&'static str> = (0..UNFURLS_PER_MINUTE)
        .map(|i| &*format!("/later{i}").leak())
        .collect();
    let mut routes: Vec<(&'static str, Route)> = paths.iter().map(|p| (*p, gated(&gate))).collect();
    routes.extend(later.iter().map(|p| (*p, html("<title>Later</title>"))));
    let page = fixture(routes);
    let (mut server, _dir) = unfurl_server();
    let mut clients: Vec<TestClient> = paths.iter().map(|_| dial_test_client(&server)).collect();
    for (c, path) in clients.iter_mut().zip(&paths) {
        post(c, &page.url(path), "");
    }
    gate.open();
    settle(&server);
    let hits: Vec<usize> = paths.iter().map(|p| page.hits(p)).collect();
    let mut want = vec![1; MAX_JOBS];
    want.push(0);
    assert_eq!(hits, want);

    // The refused message spent none of its sender's allowance.
    let refused = clients.last_mut().unwrap();
    for chunk in later.chunks(MAX_URLS_PER_MESSAGE) {
        let urls: Vec<String> = chunk.iter().map(|p| page.url(p)).collect();
        post(refused, &urls.join(" "), "");
        settle(&server);
    }
    let hits: Vec<usize> = later.iter().map(|p| page.hits(p)).collect();
    assert_eq!(hits, vec![1; UNFURLS_PER_MINUTE as usize]);
    server.stop();
}

#[test]
fn test_shutdown_with_unfurl_in_flight() {
    let gate = Gate::default();
    let page = fixture(vec![("/slow", gated(&gate))]);
    let (mut server, dir) = unfurl_server_with(Config {
        unfurl_timeout: Duration::from_millis(200),
        ..default_config()
    });
    let mut c = dial_test_client(&server);
    post(&mut c, &page.url("/slow"), "");
    let started = time::now();
    while page.hits("/slow") == 0 {
        assert!(time::since(&started) < time::SECOND, "never fetched");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let started = time::now();
    server.stop();
    let took = time::since(&started);
    gate.open();
    assert!(took < Duration::from_millis(1500), "shutdown took {took:?}");
    assert_eq!(upload_files(&dir), 0);
}

/// A fixture whose /post has ARTICLE's preview and image.
fn article() -> Fixture {
    fixture(vec![
        ("/post", html(ARTICLE)),
        ("/before.png", respond("image/png", test_png())),
    ])
}

fn write_url(result: &Object) -> String {
    result["embeds"].as_list()[0].as_object().unwrap()["write_url"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn put(write_url: &str, size: usize) -> u16 {
    http_do("PUT", write_url, Some(&png_of_size(size)), "image/png").0
}

#[test]
fn test_link_image_is_not_a_message_upload() {
    let page = article();
    let (mut server, _dir) = unfurl_server_with(Config {
        max_message_upload_bytes: 100,
        ..default_config()
    });
    let mut c = dial_test_client(&server);
    let result = post_embeds(
        &mut c,
        "both",
        obj! {"room_id" => "general", "body" => obj! {
            "text" => page.url("/post"),
            "embeds" => vec![Json::from(obj! {"kind" => "upload"})],
        }},
    );
    settle(&server);
    let kinds: Vec<String> = embeds_of(&c.notification("message"))
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(kinds, vec!["upload", "link"]);
    assert_eq!(put(&write_url(&result), 100), 201);
    server.stop();
}

#[test]
fn test_eviction_keeps_link_card() {
    let page = article();
    let (mut server, dir) = unfurl_server_with(Config {
        max_upload_storage_bytes: 100 + test_png().len() as i64 - 1,
        ..default_config()
    });
    let mut c = dial_test_client(&server);
    let result = post_embeds(
        &mut c,
        "upload",
        obj! {"room_id" => "general", "body" => obj! {
            "embeds" => vec![Json::from(obj! {"kind" => "upload"})],
        }},
    );
    assert_eq!(put(&write_url(&result), 100), 201);
    let uploaded = embeds_of(&c.notification("message"));
    let file_url = uploaded[0]["url"].as_str().unwrap().to_owned();

    let message_id = post(&mut c, &page.url("/post"), "");
    settle(&server);
    let linked = embeds_of(&c.notification("message"));
    let image_url = linked[0]["og"].as_object().unwrap()["image"]
        .as_object()
        .unwrap()["url"]
        .as_str()
        .unwrap()
        .to_owned();
    let card = embeds_of(&c.notification("message"));
    assert_eq!(
        card[0],
        obj! {
            "embed_id" => linked[0]["embed_id"].clone(),
            "kind" => "link",
            "url" => page.url("/post"),
            "og" => obj! {
                "title" => "Before & after",
                "description" => "The fix, explained",
                "site_name" => "Example",
            },
        }
    );
    c.expect_quiet();
    assert_eq!(http_get(&image_url).0, 404);
    assert_eq!(http_get(&file_url).0, 200);
    assert_eq!(upload_files(&dir), 1);

    // The server still holds the card, so a save that keeps it gets it back.
    let id = c.next_id("edit");
    let (before, _) = c.request(
        "message",
        &id,
        obj! {
            "message_id" => message_id.as_str(),
            "body" => obj! {
                "text" => format!("Kept: {}", page.url("/post")),
                "embeds" => vec![Json::from(obj! {"embed_id" => card[0]["embed_id"].clone(), "kind" => "link"})],
            },
        },
    );
    assert_eq!(embeds_of(&notification_params(&before[0], "message")), card);
    server.stop();
}

#[test]
fn test_unfurl_respects_embed_cap() {
    let pages: Vec<(&'static str, Route)> = ["/1", "/2"]
        .into_iter()
        .map(|p| (p, html(r#"<title>Page</title>"#)))
        .collect();
    let page = fixture(pages);
    let (mut server, _dir) = unfurl_server();
    let mut c = dial_test_client(&server);
    let notes: Vec<Json> = (0..MAX_EMBEDS_PER_MESSAGE - 1)
        .map(|_| obj! {"kind" => "note"}.into())
        .collect();
    let id = c.next_id("m");
    c.request(
        "message",
        &id,
        obj! {"body" => obj! {
            "text" => format!("{} {}", page.url("/1"), page.url("/2")),
            "embeds" => notes,
        }},
    );
    settle(&server);
    let embeds = embeds_of(&c.notification("message"));
    assert_eq!(embeds.len(), MAX_EMBEDS_PER_MESSAGE);
    assert_eq!(
        embeds[MAX_EMBEDS_PER_MESSAGE - 1]["url"].as_str(),
        Some(page.url("/1").as_str())
    );
    server.stop();
}

#[test]
fn test_link_embed_survives_restart() {
    let page = article();
    let memory: Arc<dyn Store> = Arc::new(store::Memory::new());
    let dir = TempDir::new("unfurl-uploads-");
    let mut first = start_with(memory.clone(), &dir.to_string(), |config| {
        config.unfurl = true;
        config.unfurl_allow_internal = true;
    });
    let mut c = dial_test_client(&first);
    let message_id = post(&mut c, &page.url("/post"), "");
    settle(&first);
    let linked = embeds_of(&c.notification("message"));
    drop(c);
    first.stop();

    let mut second = start_with_store(memory, &dir.to_string());
    let mut c = dial_test_client(&second);
    let image_url = linked[0]["og"].as_object().unwrap()["image"]
        .as_object()
        .unwrap()["url"]
        .as_str()
        .unwrap()
        .replace(&first.http.url, &second.http.url);
    assert_eq!(http_get(&image_url), (200, test_png()));
    let page = history_page(&mut c, "general", Object::new());
    let restored = records(&page, "messages")
        .into_iter()
        .rfind(|m| m["message_id"].as_str() == Some(message_id.as_str()))
        .unwrap();
    assert_eq!(embeds_of(&restored), linked);
    second.stop();
}
