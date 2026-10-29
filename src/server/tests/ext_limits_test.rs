//! ext:limits (EXTENSIONS.md): the category a limit's retry_after names,
//! after apron-server-cloudflare's quota.integration.test.ts.

use super::helpers::*;
use crate::obj;
use crate::server::config::Config;
use crate::server::limits::{Limits, Posts};
use crate::server::protocol::*;

fn server(limits: Limits) -> TestServer {
    new_test_server(Config {
        limits,
        ..default_config()
    })
}

/// The category of a retry_after reply, failing on any other reply.
fn category(frame: &Object) -> Option<String> {
    let (_, data) = retry_after_of(frame);
    data.get("ext").map(|ext| {
        ext.as_object().unwrap()["limits"]
            .as_str()
            .unwrap()
            .to_owned()
    })
}

fn upload(text: &str) -> Object {
    obj! {"body" => obj! {"text" => text, "embeds" => vec![Json::from(obj! {"kind" => "upload"})]}}
}

#[test]
fn test_server_frame_lists_ext_limits() {
    let server = server(Limits::unlimited());
    let (_c, frame) = dial_raw(&server);
    let capabilities = frame["params"].as_object().unwrap()["capabilities"].as_list();
    assert!(
        capabilities.contains(&Json::from("ext:limits")),
        "{capabilities:?}"
    );
}

/// Every posting refusal of a request the write row lists names `write`,
/// reactions and memberships included.
#[test]
fn test_write_names_posting_refusals_of_its_row_only() {
    let server = server(Limits {
        guest_posts: Posts { minute: 2, day: 0 },
        ..Limits::unlimited()
    });
    let mut a = dial_test_client(&server);
    let (message_id, _) = save(&mut a, "first", obj! {"body" => obj! {"text" => "1"}});
    save(&mut a, "second", obj! {"body" => obj! {"text" => "2"}});
    let refusals = [
        (
            "message",
            obj! {"room_id" => "general", "body" => obj! {"text" => "3"}},
        ),
        (
            "reactions",
            obj! {"message_id" => message_id.as_str(), "emojis" => strings(&["👍"])},
        ),
        ("room_leave", obj! {"room_id" => "general"}),
    ];
    for (i, (method, params)) in refusals.into_iter().enumerate() {
        let frame = reply_to(&mut a, method, &format!("w{i}"), params);
        assert_eq!(category(&frame).as_deref(), Some("write"), "{method}");
    }
}

#[test]
fn test_me_refusal_names_no_category() {
    let server = server(Limits {
        posts: Posts { minute: 1, day: 0 },
        ..Limits::unlimited()
    });
    let mut a = dial_test_client(&server);
    make_account(&server, &a.user_id);
    let frame = reply_to(&mut a, "me", "one", obj! {"name" => "One"});
    assert!(frame.contains_key("result"), "{frame:?}");
    let frame = reply_to(&mut a, "me", "two", obj! {"name" => "Two"});
    assert_eq!(retry_after_of(&frame).0, "Posting limit reached");
    assert_eq!(category(&frame), None);
}

/// A room listing past the minute names `read`, and the first joined
/// listing after a sign-in is free.
#[test]
fn test_room_list_limit_names_read() {
    let server = server(Limits {
        room_lists_per_user_minute: 1,
        ..Limits::unlimited()
    });
    let mut a = dial_test_client(&server);
    for filter in ["joined", "all"] {
        let frame = reply_to(&mut a, "room_list", filter, obj! {"filter" => filter});
        assert!(frame.contains_key("result"), "{filter}: {frame:?}");
    }
    let frame = reply_to(&mut a, "room_list", "again", obj! {"filter" => "joined"});
    assert_eq!(retry_after_of(&frame).0, "Room listing limited");
    assert_eq!(category(&frame).as_deref(), Some("read"));
}

/// The upload limits count new upload embeds and /avatar, and name
/// `upload`; a message without one is not refused by them.
#[test]
fn test_upload_limits_name_upload() {
    let server = server(Limits {
        uploads_per_user_day: 2,
        uploads_per_day: 3,
        ..Limits::unlimited()
    });
    let mut a = dial_test_client(&server);
    make_account(&server, &a.user_id);
    let frame = reply_to(&mut a, "message", "one", {
        let mut params = upload("one");
        params.insert("room_id".into(), "general".into());
        params
    });
    assert!(frame.contains_key("result"), "{frame:?}");
    let frame = reply_to(&mut a, "command", "avatar", upload("/avatar"));
    assert!(frame.contains_key("result"), "{frame:?}");
    let frame = reply_to(&mut a, "command", "again", upload("/avatar"));
    assert_eq!(retry_after_of(&frame).0, "Daily upload limit reached");
    assert_eq!(category(&frame).as_deref(), Some("upload"));
    save(
        &mut a,
        "text",
        obj! {"body" => obj! {"text" => "no upload"}},
    );

    let mut b = dial_test_client(&server);
    let mut params = upload("two");
    params.insert("room_id".into(), "general".into());
    let frame = reply_to(&mut b, "message", "b1", params.clone());
    assert!(frame.contains_key("result"), "{frame:?}");
    let frame = reply_to(&mut b, "message", "b2", params);
    assert_eq!(
        retry_after_of(&frame).0,
        "Daily upload limit reached for the server"
    );
    assert_eq!(category(&frame).as_deref(), Some("upload"));
}

/// Limits that are not posting, reading or uploads name no category.
#[test]
fn test_other_limits_name_no_category() {
    let server = server(Limits {
        admissions_per_ip_minute: 1,
        ..Limits::unlimited()
    });
    let _held = dial_raw(&server);
    let (refused, _) = dial_server_frame(&server, &[]);
    let frame = refused.read();
    assert_eq!(
        retry_after_of(&frame).0,
        "Connection admission limit reached"
    );
    assert_eq!(category(&frame), None);
}
