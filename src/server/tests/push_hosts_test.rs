//! The host checks on push endpoints, ported from push_test.go. The relay
//! fixture lives in push_test.rs.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;

use rust_stdlib::net::http::{handler_func, httptest, ResponseWriter};
use rust_stdlib::time::Duration;

use super::helpers::*;
use super::push_test::{
    add_push, has_push, list, new_test_relay, paths, push_client, relay_push, strs,
};
use super::status_test::add_account;
use super::webpush_test::test_subscription;
use crate::obj;
use crate::server::protocol::*;
use crate::server::push::*;
use crate::server::push_delivery::PushDeliverer;

#[test]
fn test_push_refuses_internal_addresses() {
    let hits = Arc::new(AtomicI32::new(0));
    let counter = hits.clone();
    let mut relay = httptest::Server::new(handler_func(move |_w: &mut dyn ResponseWriter, _r| {
        counter.fetch_add(1, Ordering::SeqCst);
    }))
    .unwrap();
    let deliverer = PushDeliverer::new(false, String::new());
    let called = Arc::new(AtomicBool::new(false));
    let flag = called.clone();
    deliverer.deliver(
        PushRegistration {
            url: relay.url.clone(),
            ..PushRegistration::default()
        },
        b"{}".to_vec(),
        "normal",
        String::new(),
        Box::new(move |status| flag.store(status != 0, Ordering::SeqCst)),
    );
    deliverer.wait();
    relay.close();
    assert!(
        hits.load(Ordering::SeqCst) == 0 && !called.load(Ordering::SeqCst),
        "delivered to a loopback address: hits={} called={}",
        hits.load(Ordering::SeqCst),
        called.load(Ordering::SeqCst)
    );
    assert!(
        check_push_url("http://relay.example/p", false, &PushHosts::Any).is_err(),
        "http push URL accepted without allow_insecure_push"
    );
    // Internal address literals, localhost, and hosts ending in a dot are
    // refused at registration.
    for endpoint in [
        "https://10.0.0.1/p",
        "https://[::1]/p",
        "https://[fd00::1]:8443/p",
        "https://169.254.169.254/p",
        "https://localhost/p",
        "https://push.localhost/p",
        "https://192.0.2.1/p",
        "https://push.example.net./p",
        "mailto:a@b.example",
    ] {
        assert!(
            check_push_url(endpoint, false, &PushHosts::Any).is_err(),
            "{endpoint} accepted"
        );
    }
    // Endpoints are kept in one form: scheme and host lowercased, no
    // default port.
    for (endpoint, want) in [
        ("https://93.184.215.14/p", "https://93.184.215.14/p"),
        (
            "https://fcm.googleapis.com/fcm/send/x",
            "https://fcm.googleapis.com/fcm/send/x",
        ),
        (
            "HTTPS://FCM.GoogleAPIs.com:443/fcm/send/x",
            "https://fcm.googleapis.com/fcm/send/x",
        ),
        (
            "https://push.example.net:8443/A?b=C",
            "https://push.example.net:8443/A?b=C",
        ),
        (
            "https://[2606:4700::1111]:443/p",
            "https://[2606:4700::1111]/p",
        ),
    ] {
        assert_eq!(
            check_push_url(endpoint, false, &PushHosts::Any),
            Ok(want.to_owned()),
            "{endpoint}"
        );
    }
}

/// `--push.hosts` (apron-server-cloudflare's `PUSH_HOSTS`): host names and
/// `*.` suffixes, or a standalone `*`; none gives the browsers' services.
#[test]
fn test_push_hosts_parse_and_match() {
    let default = PushHosts::parse(&[]).unwrap();
    assert_eq!(default, PushHosts::default(), "no --push.hosts");
    for (host, allowed) in [
        ("fcm.googleapis.com", true),
        ("updates.push.services.mozilla.com", true),
        ("web.push.apple.com", true),
        ("api.push.apple.com", true),
        ("wns2-by3p.notify.windows.com", true),
        ("push.apple.com", false),
        ("evilfcm.googleapis.com", false),
        ("relay.example", false),
    ] {
        assert_eq!(default.allows(host), allowed, "default allows {host}");
    }
    assert_eq!(PushHosts::parse(&strs(&["*"])).unwrap(), PushHosts::Any);
    let listed = PushHosts::parse(&strs(&["Relay.Example, *.push.example.net"])).unwrap();
    assert_eq!(
        listed,
        PushHosts::Listed(strs(&["relay.example", "*.push.example.net"])),
        "comma-separated and lowercased"
    );
    assert!(listed.allows("relay.example") && listed.allows("a.push.example.net"));
    assert!(
        !listed.allows("fcm.googleapis.com"),
        "a list replaces the default"
    );
    for bad in [
        "localhost",
        "*",
        "*.",
        "-a.example",
        "a_b.example",
        "https://relay.example",
    ] {
        let entries = if bad == "*" {
            strs(&["*", "relay.example"])
        } else {
            strs(&[bad])
        };
        assert!(
            PushHosts::parse(&entries).is_err(),
            "--push.hosts {entries:?} accepted"
        );
    }
}

/// A registration's host must be one `--push.hosts` allows, relay or
/// webpush; a relay is allowed once its host is listed.
#[test]
fn test_push_register_checks_hosts() {
    let server = new_test_server(default_config());
    let mut a = push_client(&server);
    let (_, keys) = test_subscription();
    let refused = reply(
        &mut a,
        "push_register",
        "relay",
        obj! {"kind" => "relay", "url" => "https://relay.example/a"},
    );
    assert_eq!(
        refused["error"],
        Json::from(
            obj! {"code" => CODE_INVALID_PARAMS, "message" => "push service not allowed here"}
        ),
        "an unlisted relay"
    );
    a.expect_error(
        "push_register",
        "webpush",
        obj! {"kind" => "webpush", "url" => "https://push.example.net/x", "keys" => keys.clone()},
        CODE_INVALID_PARAMS,
    );
    a.result(
        "push_register",
        "fcm",
        obj! {"kind" => "webpush", "url" => "https://fcm.googleapis.com/fcm/send/x", "keys" => keys.clone()},
    );
    a.result(
        "push_unregister",
        "off",
        obj! {"url" => "https://fcm.googleapis.com/fcm/send/x"},
    );

    let mut config = default_config();
    config.push_hosts = PushHosts::parse(&strs(&["relay.example"])).unwrap();
    let server = new_test_server(config);
    let mut b = push_client(&server);
    b.result(
        "push_register",
        "listed",
        obj! {"kind" => "relay", "url" => "https://relay.example/b"},
    );
    assert!(has_push(&server, &b.user_id, "https://relay.example/b"));
}

/// `--push.hosts` is checked again before each push: a registration kept
/// from a wider list is passed over.
#[test]
fn test_push_checks_hosts_again_before_each_push() {
    let relay = new_test_relay();
    let mut config = default_config();
    config.allow_insecure_push = true;
    config.push_hosts = PushHosts::parse(&strs(&["127.0.0.1"])).unwrap();
    config.push_delay = Duration::from_secs(0);
    let server = new_test_server(config);
    server.app.lock().badge_delay = Duration::from_secs(0);
    let mut a = push_client(&server);
    add_account(&server, "dora", &[&a]);
    let port = relay.url.rsplit_once(':').unwrap().1.to_owned();
    add_push(
        &server,
        "dora",
        relay_push(
            format!("http://localhost:{port}/retired"),
            WakeScope::DEFAULT,
        ),
    );
    add_push(
        &server,
        "dora",
        relay_push(format!("{}/kept", relay.url), WakeScope::DEFAULT),
    );
    save(
        &mut a,
        "mention",
        obj! {"body" => obj! {"text" => "@dora", "mentions" => list(&["dora"])}},
    );
    assert_eq!(
        paths(&relay.pushes(&server, &mut a)),
        strs(&["/kept"]),
        "deliveries"
    );
}
