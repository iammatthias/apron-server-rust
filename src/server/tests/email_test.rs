//! The mailbox fixture and the email sign-in tests of email_test.go. The
//! other email_*_test.rs files hold the rest of email_test.go.

use std::collections::BTreeMap;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;

use rust_stdlib::context::Context;
use rust_stdlib::net::url;
use rust_stdlib::time::{self, Duration};

use super::helpers::*;
use crate::obj;
use crate::server::config::Config;
use crate::server::email::*;
use crate::server::protocol::*;
use crate::server::Server;

/// An EmailSender that keeps what it is asked to send.
pub(super) struct TestMailbox(SyncSender<SignInEmail>);

impl EmailSender for TestMailbox {
    fn send_sign_in_code(&self, _ctx: &Context, message: &SignInEmail) -> Result<(), SendError> {
        // A test that does not read its mail drops it.
        let _ = self.0.try_send(message.clone());
        Ok(())
    }
}

pub(super) struct Mailbox(Receiver<SignInEmail>);

impl Mailbox {
    /// The next message sent to the mailbox.
    pub(super) fn receive(&self) -> SignInEmail {
        self.0
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("no email was sent")
    }
}

pub(super) fn test_mailbox(capacity: usize) -> (Arc<TestMailbox>, Mailbox) {
    let (tx, rx) = sync_channel(capacity);
    (Arc::new(TestMailbox(tx)), Mailbox(rx))
}

pub(super) fn email_test_server(configure: impl FnOnce(&mut Config)) -> (TestServer, Mailbox) {
    let (sender, mailbox) = test_mailbox(16);
    let mut config = default_config();
    config.email_sender = Some(sender);
    config.email_link_url = "https://chat.example/login#ignored".into();
    configure(&mut config);
    (new_test_server(config), mailbox)
}

/// Proposes an email sign-in or addition on c, which must be answered with
/// {} (§4.11).
pub(super) fn propose(c: &mut TestClient, email: &str) {
    let id = c.next_id("propose");
    let result = c.result("auth", &id, obj! {"scheme" => "email", "email" => email});
    assert!(result.is_empty(), "proposal result: {result:?}");
}

/// Approves a proposal on c with token and returns the notifications before
/// the result, then the result.
pub(super) fn approve(c: &mut TestClient, token: &str, extra: Object) -> (Vec<Object>, Object) {
    let mut params = obj! {"scheme" => "email", "token" => token};
    params.extend(extra);
    let id = c.next_id("approve");
    c.request("auth", &id, params)
}

/// Approves a sign-in and returns the notifications before the result, then
/// the result, which must carry you and a token.
pub(super) fn sign_in_by_email(
    c: &mut TestClient,
    token: &str,
    extra: Object,
) -> (Vec<Object>, Object) {
    let (before, result) = approve(c, token, extra);
    assert!(
        result.get("token").and_then(Json::as_str).is_some(),
        "sign-in result without a token: {result:?}"
    );
    c.user_id = user_id_of(&result);
    (before, result)
}

/// The form-encoded fragment of an email's link.
fn link_fragment(message: &SignInEmail) -> BTreeMap<String, Vec<String>> {
    let fragment = message.link.split_once('#').map_or("", |(_, f)| f);
    let (values, err) = url::parse_query(fragment);
    assert!(err.is_none(), "link fragment {:?}: {err:?}", message.link);
    values.0
}

fn fragment_value(message: &SignInEmail, key: &str) -> String {
    link_fragment(message)
        .get(key)
        .and_then(|values| values.first())
        .cloned()
        .unwrap_or_default()
}

/// The token in an email's link.
pub(super) fn link_token(message: &SignInEmail) -> String {
    let token = fragment_value(message, "token");
    assert!(!token.is_empty(), "no link token in {:?}", message.link);
    token
}

/// The code of the proposal pending on a connection of user_id, which may
/// not have been sent.
pub(super) fn pending_code(app: &Server, user_id: &str) -> String {
    let st = app.lock();
    for conn in st.clients.values() {
        if conn.user.as_deref() == Some(user_id) {
            if let Some(p) = conn.proposal.and_then(|id| st.email.proposals.get(&id)) {
                return p.code.clone();
            }
        }
    }
    panic!("no proposal pending for {user_id}");
}

/// Moves an address's sends back by d, as if time had passed.
pub(super) fn age_sends(app: &Server, email: &str, d: Duration) {
    let mut st = app.lock();
    if let Some(state) = st.email.addresses.get_mut(email) {
        for sent in &mut state.sends {
            *sent = sent.add(-d);
        }
    }
}

/// Connects as a client at ip, for a server that reads X-Forwarded-For.
pub(super) fn dial_from(server: &TestServer, ip: &str) -> TestClient {
    let forwarded = format!("203.0.113.9, {ip}");
    dial_headers(server, &[("X-Forwarded-For", &forwarded)]).0
}

fn code_of(frame: &Object) -> Option<Json> {
    frame
        .get("error")
        .and_then(Json::as_object)
        .and_then(|e| e.get("code"))
        .cloned()
}

#[test]
fn test_email_sign_in() {
    let (server, mailbox) =
        email_test_server(|config| config.public_url = "https://chat.example/app/".into());
    let app = &server.app;
    let (mut proposer, frame) = dial_raw(&server);
    let params = frame["params"].as_object().unwrap();
    assert!(
        params.get("auth") == Some(&strings(&["email", "token", "guest"]))
            && params.get("signup") == Some(&strings(&["email", "token"])),
        "auth schemes: {:?}, signup {:?}",
        params.get("auth"),
        params.get("signup")
    );

    // A proposal authenticates nothing, so on a connection not signed in the
    // requests behind it are still denied; the address is normalized.
    let state = "q8Rz/+&=é";
    proposer.write(&obj! {"method" => "auth", "id" => "propose", "params" => obj! {"scheme" => "email", "email" => " Ada@Example.com ", "state" => state}});
    proposer.write(&obj! {"method" => "room_list", "id" => "list", "params" => Object::new()});
    let reply = proposer.read();
    assert!(
        reply.get("id") == Some(&"propose".into())
            && reply
                .get("result")
                .and_then(Json::as_object)
                .is_some_and(|r| r.is_empty()),
        "proposal reply: {reply:?}"
    );
    let reply = proposer.read();
    assert!(
        reply.get("id") == Some(&"list".into()) && code_of(&reply) == Some(CODE_DENIED.into()),
        "request behind a proposal: {reply:?}"
    );
    let message = mailbox.receive();
    assert!(
        message.to == "ada@example.com"
            && !message.add
            && message.code.len() == 6
            && message.code.bytes().all(|b| b.is_ascii_digit()),
        "sent: {message:?}"
    );
    // The link is built from the configured page, with an unguessable token,
    // the proposal's state unchanged, and this server's WebSocket URL in its
    // fragment, and no address (§4.11.2).
    let link = link_token(&message);
    let want = format!(
        "https://chat.example/login#token={link}&state={}&server=wss%3A%2F%2Fchat.example%2Fapp%2Fws",
        url::query_escape(state)
    );
    assert!(
        message.link == want
            && link.len() >= 26
            && !message.link.contains("ada")
            && fragment_value(&message, "state") == state,
        "link {:?}, want {want:?}",
        message.link
    );
    let text = message.text();
    assert!(
        text.contains(&message.code) && text.contains(&message.link),
        "text: {text:?}"
    );
    // Another proposal for the address so soon is retry_after.
    proposer.expect_error(
        "auth",
        "again",
        obj! {"scheme" => "email", "email" => "ada@example.com"},
        CODE_RETRY_AFTER,
    );
    proposer.expect_error(
        "auth",
        "invalid",
        obj! {"scheme" => "email", "email" => "Ada <ada@example.com>"},
        CODE_INVALID_PARAMS,
    );
    proposer.expect_error(
        "auth",
        "missing",
        obj! {"scheme" => "email"},
        CODE_INVALID_PARAMS,
    );
    // state is a string of at most 256 bytes.
    proposer.expect_error(
        "auth",
        "long-state",
        obj! {"scheme" => "email", "email" => "bob@example.com", "state" => "s".repeat(MAX_STATE_BYTES + 1)},
        CODE_TOO_LARGE,
    );
    proposer.expect_error(
        "auth",
        "state-type",
        obj! {"scheme" => "email", "email" => "bob@example.com", "state" => 7i64},
        CODE_INVALID_PARAMS,
    );

    // The code works only on the proposing connection; the link token on any
    // connection not signed in, which it signs in: a new account, which joins
    // general, after the result (§3.2).
    let (mut reader, _) = dial_raw(&server);
    reader.expect_error(
        "auth",
        "code-elsewhere",
        obj! {"scheme" => "email", "token" => message.code.as_str()},
        CODE_DENIED,
    );
    reader.expect_error(
        "auth",
        "wrong",
        obj! {"scheme" => "email", "token" => "wrong"},
        CODE_DENIED,
    );
    let (before, result) = sign_in_by_email(
        &mut reader,
        &link,
        obj! {"name" => "Ada", "user_id" => "ada"},
    );
    let you = you_of(&result);
    assert!(
        you["user_id"] == "ada".into() && you["name"] == "Ada".into(),
        "new account: {result:?}"
    );
    assert!(
        before.is_empty(),
        "frames before the sign-in result: {before:?}"
    );
    expect_joined_default(&reader, "ada");
    // The proposal is consumed: neither token works again.
    let (mut third, _) = dial_raw(&server);
    third.expect_error(
        "auth",
        "reuse",
        obj! {"scheme" => "email", "token" => link.as_str()},
        CODE_DENIED,
    );
    proposer.expect_error(
        "auth",
        "code-after",
        obj! {"scheme" => "email", "token" => message.code.as_str()},
        CODE_DENIED,
    );
    // The bearer token resumes the account on later connections.
    let resumed = third.result(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => result["token"].clone()},
    );
    assert!(
        user_id_of(&resumed) == "ada" && resumed.get("token") == result.get("token"),
        "token resume: {resumed:?}"
    );
    // Signing in again with the code, on the proposing connection, finds the
    // same account.
    age_sends(app, "ada@example.com", time::MINUTE);
    let (mut fourth, _) = dial_raw(&server);
    propose(&mut fourth, "ada@example.com");
    let code = mailbox.receive().code;
    let (_, again) = sign_in_by_email(&mut fourth, &code, obj! {"user_id" => "other"});
    assert_eq!(user_id_of(&again), "ada", "second sign-in: {again:?}");
}

/// A proposal, or a denied approval, changes no authentication, so on a
/// connection signed in the requests behind it run as before (§3.2).
#[test]
fn test_email_requests_leave_authentication_alone() {
    let (server, mailbox) = email_test_server(|_| {});
    let mut c = dial_test_client(&server);
    for params in [
        obj! {"scheme" => "email", "email" => "ada@example.com"},
        obj! {"scheme" => "email", "token" => "000000"},
    ] {
        let (auth, list) = (c.next_id("auth"), c.next_id("list"));
        c.write(&obj! {"method" => "auth", "id" => auth.as_str(), "params" => params.clone()});
        c.write(&obj! {"method" => "room_list", "id" => list.as_str(), "params" => obj! {"filter" => "joined"}});
        c.read(); // the auth reply
        let reply = c.read();
        assert!(
            reply.get("id") == Some(&list.as_str().into()) && reply.contains_key("result"),
            "request behind {params:?}: {reply:?}"
        );
    }
    mailbox.receive();
    let you = you_of(&c.result("me", "me", Object::new()));
    assert_eq!(
        you["user_id"],
        c.user_id.as_str().into(),
        "identity changed: {you:?}"
    );
}

/// Failed attempts count against the proposal a link token names, whichever
/// connection makes them, and a few cancel it (§4.11.1).
#[test]
fn test_email_failed_attempts_count_from_any_connection() {
    let (server, mailbox) = email_test_server(|_| {});
    let (mut c, _) = dial_raw(&server);
    propose(&mut c, "ada@example.com");
    let message = mailbox.receive();
    let link = link_token(&message);
    let wrong = format!(
        "{}{}",
        &link[..LINK_HANDLE_BYTES],
        "A".repeat(link.len() - LINK_HANDLE_BYTES)
    );
    for i in 0..MAX_EMAIL_ATTEMPTS - 1 {
        let (mut guesser, _) = dial_raw(&server);
        guesser.expect_error(
            "auth",
            &format!("guess-{i}"),
            obj! {"scheme" => "email", "token" => wrong.as_str()},
            CODE_DENIED,
        );
    }
    // One more attempt, a wrong code on its own connection, cancels it.
    c.expect_error(
        "auth",
        "last",
        obj! {"scheme" => "email", "token" => "wrong"},
        CODE_DENIED,
    );
    let (mut reader, _) = dial_raw(&server);
    reader.expect_error(
        "auth",
        "cancelled",
        obj! {"scheme" => "email", "token" => link.as_str()},
        CODE_DENIED,
    );
    c.expect_error(
        "auth",
        "cancelled-code",
        obj! {"scheme" => "email", "token" => message.code.as_str()},
        CODE_DENIED,
    );
}

/// Without a public URL, a link carries the WebSocket URL its proposal's
/// connection reached, so a page such as link.apron.chat knows where to sign
/// in.
#[test]
fn test_email_links_name_the_server_without_a_public_url() {
    let (server, mailbox) =
        email_test_server(|config| config.email_link_url = "https://link.apron.chat/".into());
    let (mut c, _) = dial_raw(&server);
    propose(&mut c, "ada@example.com");
    let message = mailbox.receive();
    assert!(
        fragment_value(&message, "server") == ws_url(&server)
            && message.link.starts_with("https://link.apron.chat/#token="),
        "link {:?}, want server {:?}",
        message.link,
        ws_url(&server)
    );
}

/// A link's token approves with scheme token too, as a client presents a
/// link that isn't its own (§4.11.2); wrong tokens still count against the
/// proposal, and a bearer token for no session is still an expired session.
#[test]
fn test_email_approves_with_the_token_scheme() {
    let (server, mailbox) = email_test_server(|_| {});
    let (mut proposer, _) = dial_raw(&server);
    propose(&mut proposer, "ada@example.com");
    let message = mailbox.receive();
    let link = link_token(&message);
    let (mut reader, _) = dial_raw(&server);
    let result = reader.result(
        "auth",
        "link",
        obj! {"scheme" => "token", "token" => link.as_str()},
    );
    assert!(
        you_of(&result).contains_key("user_id") && result.contains_key("token"),
        "sign-in by link with scheme token: {result:?}"
    );
    // Used up, under either scheme.
    let (mut again, _) = dial_raw(&server);
    again.expect_error(
        "auth",
        "reuse",
        obj! {"scheme" => "email", "token" => link.as_str()},
        CODE_DENIED,
    );

    // A code on the proposing connection approves with scheme token as well.
    let (mut second, _) = dial_raw(&server);
    propose(&mut second, "bob@example.com");
    let code = mailbox.receive().code;
    let result = second.result(
        "auth",
        "code",
        obj! {"scheme" => "token", "token" => code.as_str()},
    );
    assert!(
        result.contains_key("you"),
        "sign-in by code with scheme token: {result:?}"
    );

    // Wrong tokens behind a link's handle count against its proposal under
    // scheme token too.
    let (mut third, _) = dial_raw(&server);
    propose(&mut third, "carol@example.com");
    let link = link_token(&mailbox.receive());
    let wrong = format!(
        "{}{}",
        &link[..LINK_HANDLE_BYTES],
        "A".repeat(link.len() - LINK_HANDLE_BYTES)
    );
    for i in 0..MAX_EMAIL_ATTEMPTS {
        let (mut guesser, _) = dial_raw(&server);
        guesser.expect_error(
            "auth",
            &format!("guess-{i}"),
            obj! {"scheme" => "token", "token" => wrong.as_str()},
            CODE_DENIED,
        );
    }
    let (mut late, _) = dial_raw(&server);
    late.expect_error(
        "auth",
        "cancelled",
        obj! {"scheme" => "token", "token" => link.as_str()},
        CODE_DENIED,
    );

    // Any other token is no temporary token: its resume fails as before.
    let (mut stranger, _) = dial_raw(&server);
    let frame = stranger.call(
        "auth",
        "resume",
        obj! {"scheme" => "token", "token" => "st_unknown"},
    );
    let failure = frame["error"].as_object().unwrap();
    assert_eq!(
        failure["message"],
        "Session expired; sign in again".into(),
        "unknown bearer token: {frame:?}"
    );
}
