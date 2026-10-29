//! The idle bot sweep, ported from apron-server-cloudflare's
//! test/idle-bots.integration.test.ts: a user whose only role is `bot` and
//! that has not signed in, posted or reacted for a week is signed out.

use rust_stdlib::time;

use super::helpers::*;
use super::webauthn_test::passkey_result;
use crate::obj;
use crate::server::protocol::*;

const DAY: i64 = 86_400_000;

fn now_ms() -> i64 {
    time::now().unix_milli()
}

fn set_active(server: &TestServer, ids: &[&str], ms: i64) {
    let mut app = server.app.lock();
    for id in ids {
        app.users.get_mut(*id).unwrap().active = ms;
    }
}

fn active(server: &TestServer, id: &str) -> i64 {
    server.app.lock().users[id].active
}

fn rooms_of(server: &TestServer, id: &str) -> Vec<String> {
    server.app.lock().users[id].joined.iter().cloned().collect()
}

/// Runs the sweep with its due time set to `due`, `None` leaving it as is.
fn sweep(server: &TestServer, due: Option<i64>) {
    let mut app = server.app.lock();
    if let Some(due) = due {
        app.bot_sweep_at = due;
    }
    app.sweep_idle_bots_locked(&time::now());
}

#[test]
fn test_signs_out_idle_bots_keeping_their_posts() {
    let server = admin_test_server();
    let mut admin = admin(&server);
    let mut owner = account(&server);
    let mut poster_owner = account(&server);
    let bot_id = format!("bot_{}", owner.user_id);
    let bot_token = token_in(&private_reply(&mut owner, "/invite-bot"));
    let poster_id = format!("bot_{}", poster_owner.user_id);
    let poster_token = token_in(&private_reply(&mut poster_owner, "/invite-bot"));
    // A user made a bot by /role, and one that is a bot and a friend.
    let script_token = token_in(&private_reply(&mut admin, "/invite-token script"));
    private_reply(&mut admin, "/role script bot");
    private_reply(&mut admin, "/invite-token friend");
    private_reply(&mut admin, "/role friend bot");
    private_reply(&mut admin, "/role friend friend");
    assert!(
        active(&server, "script") > 0,
        "a user just made a bot is active"
    );

    // Signing in, and posting, mark a bot active.
    let long = now_ms() - 10 * DAY;
    set_active(&server, &[&bot_id], long);
    let signed_in_at = now_ms();
    let (mut bot, _) = dial_raw(&server);
    assert_eq!(
        you_of(&passkey_result(&token_auth(&mut bot, &bot_token)))["user_id"],
        Json::from(bot_id.as_str())
    );
    assert!(active(&server, &bot_id) >= signed_in_at);
    bot.drain();
    bot.user_id = bot_id.clone();
    let (kept, _) = save(
        &mut bot,
        "kept",
        obj! {"body" => obj! {"text" => "kept after sign-out"}},
    );
    let (mut poster, _) = dial_raw(&server);
    passkey_result(&token_auth(&mut poster, &poster_token));
    poster.drain();
    poster.user_id = poster_id.clone();
    set_active(&server, &[&poster_id], long);
    let posted_at = now_ms();
    save(
        &mut poster,
        "post",
        obj! {"body" => obj! {"text" => "still here"}},
    );
    assert!(active(&server, &poster_id) >= posted_at);

    // Ten days without either: the bot is signed out, connected or not, as
    // is the user made a bot; the bot with another role stays, as do the
    // active ones.
    set_active(&server, &[&bot_id, "script", "friend"], long);
    let (mut passive, _) = dial_raw(&server);
    passkey_result(&token_auth(&mut passive, &bot_token));
    passive.drain();
    set_active(&server, &[&bot_id], long);
    sweep(&server, Some(1));
    assert!(rooms_of(&server, &bot_id).is_empty());
    assert!(rooms_of(&server, "script").is_empty());
    assert_eq!(active(&server, &bot_id), 0);
    assert_eq!(rooms_of(&server, "friend"), vec!["general".to_owned()]);
    assert_eq!(rooms_of(&server, &poster_id), vec!["general".to_owned()]);
    assert_eq!(
        rooms_of(&server, &owner.user_id),
        vec!["general".to_owned()]
    );
    assert_eq!(server.app.lock().messages[&kept].owner, bot_id);
    let mut closed = String::new();
    while let Ok(payload) = passive.read_raw(time::SECOND) {
        closed.push_str(&String::from_utf8_lossy(&payload));
    }
    assert!(
        closed.contains("Signed out after a week without signing in or posting"),
        "the connected bot: {closed}"
    );
    let (mut gone, _) = dial_raw(&server);
    let error = token_auth(&mut gone, &bot_token);
    assert!(
        format!("{error:?}").contains("Bot token is not valid"),
        "{error:?}"
    );
    let error = token_auth(&mut gone, &script_token);
    assert!(
        format!("{error:?}").contains("invite token is not valid"),
        "{error:?}"
    );

    // A signed-out bot is not swept again, and the next sweep is a day on.
    let due = server.app.lock().bot_sweep_at;
    assert!(due >= signed_in_at + DAY, "next sweep at {due}");
    // The owner can invite their bot again, and it joins rooms anew; a
    // sweep before it signs in leaves the signed-out bot alone.
    let again_token = token_in(&private_reply(&mut owner, "/invite-bot"));
    sweep(&server, Some(1));
    let (mut again, _) = dial_raw(&server);
    passkey_result(&token_auth(&mut again, &again_token));
    assert!(active(&server, &bot_id) > 0);
    again.drain();
    again.user_id = bot_id.clone();
    join_room(&mut again, "general");
}

#[test]
fn test_waits_a_week_before_the_first_sweep() {
    let server = admin_test_server();
    let mut owner = account(&server);
    private_reply(&mut owner, "/invite-bot");
    let bot_id = format!("bot_{}", owner.user_id);
    set_active(&server, &[&bot_id], now_ms() - 10 * DAY);
    let before = now_ms();
    // Never swept: the first sweep is set a week out, and removes nothing.
    sweep(&server, None);
    assert_eq!(rooms_of(&server, &bot_id), vec!["general".to_owned()]);
    assert!(server.app.lock().bot_sweep_at >= before + 7 * DAY);
    // Not yet due.
    sweep(&server, Some(now_ms() + DAY));
    assert_eq!(rooms_of(&server, &bot_id), vec!["general".to_owned()]);
    sweep(&server, Some(1));
    assert!(rooms_of(&server, &bot_id).is_empty());
}
