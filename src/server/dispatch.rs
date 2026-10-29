//! Request dispatch: the methods a connection may call, and process_frame,
//! which parses a frame, deduplicates it (§1.2) and runs its method.

use std::collections::BTreeMap;
use std::sync::Arc;

use rust_stdlib_crypto::sha256;

use super::client::Client;
use super::config::Config;
use super::dedup::DedupEntry;
use super::protocol::*;
use super::server::{Server, State};
use super::toggles::Feature;
use super::users::GUEST_READ_ONLY;
use crate::obj;
use crate::ws;

/// A request handler. When it succeeds and has already queued its own reply,
/// it reports replied. Handlers whose results describe state queue them
/// while holding the lock, so that a result reflects every notification sent
/// before it on the connection, and after the notifications the request
/// causes, which precede its result (§1).
pub type Operation = fn(&Arc<Server>, &Arc<Client>, &Request) -> Result<(Json, bool), RpcError>;

/// Brings a duplicate's result up to date (§1.2).
type Refresh = fn(&State, &str, Json) -> Json;

/// One method a signed-in connection may call (§4). `ping` and `auth` are
/// answered before sign-in and are not here.
pub struct Method {
    pub name: &'static str,
    pub run: Operation,
    /// Changes nothing, so its result is not kept for deduplication (§1.2):
    /// a duplicate after the original finished runs again.
    pub read_only: bool,
    /// Denied outright to a guest while guests only read
    /// (Config.guest_posting). `command` and `activity` decide per request,
    /// and push registration refuses every guest with its own message.
    pub guest_write: bool,
    /// Sent only as a notification (§1.1): its id is ignored, and nothing
    /// about it is answered.
    pub notification: bool,
    /// Off with this feature, when it takes the unsupported-method path.
    pub feature: Option<Feature>,
    /// Push registration, which Config.disable_push removes.
    pub push: bool,
    /// Brings a duplicate's result up to date; other results name what the
    /// request made, which does not change.
    pub refresh: Option<Refresh>,
}

impl Method {
    const fn new(name: &'static str, run: Operation) -> Method {
        Method {
            name,
            run,
            read_only: false,
            guest_write: false,
            notification: false,
            feature: None,
            push: false,
            refresh: None,
        }
    }
}

const METHODS: &[Method] = &[
    Method {
        refresh: Some(State::refresh_profile),
        ..Method::new("me", Server::update_profile)
    },
    Method {
        guest_write: true,
        refresh: Some(State::refresh_writes),
        ..Method::new("message", Server::save_message)
    },
    Method {
        refresh: Some(State::refresh_writes),
        ..Method::new("command", Server::command)
    },
    Method {
        read_only: true,
        ..Method::new("history", Server::history)
    },
    Method {
        guest_write: true,
        ..Method::new("room_set", Server::set_room)
    },
    Method {
        read_only: true,
        ..Method::new("room_list", Server::list_rooms)
    },
    Method {
        guest_write: true,
        ..Method::new("room_join", Server::join_room)
    },
    Method {
        guest_write: true,
        ..Method::new("room_leave", Server::leave_room)
    },
    Method {
        guest_write: true,
        ..Method::new("reactions", Server::react)
    },
    Method {
        notification: true,
        feature: Some(Feature::Activity),
        ..Method::new("activity", Server::activity)
    },
    Method::new("status", Server::status),
    Method {
        push: true,
        ..Method::new("push_register", Server::register_push)
    },
    Method {
        push: true,
        ..Method::new("push_unregister", Server::unregister_push)
    },
];

#[cfg(test)]
const TEST_METHODS: &[Method] = &[
    Method::new("test_panic", Server::test_panic),
    Method::new("test_fail", Server::test_fail),
];

/// The methods `config` serves, by name.
pub(super) fn methods(config: &Config) -> BTreeMap<&'static str, &'static Method> {
    #[cfg(not(test))]
    const TEST_METHODS: &[Method] = &[];
    METHODS
        .iter()
        .chain(TEST_METHODS)
        .filter(|m| !(m.push && config.disable_push))
        .map(|m| (m.name, m))
        .collect()
}

/// Reports whether clients send `method` only as a notification (§1.1). A
/// server may ignore the id of one and handle the frame as a notification,
/// and this one does: nothing about it is answered.
pub fn notification_only(method: &str) -> bool {
    method == "ping" || METHODS.iter().any(|m| m.notification && m.name == method)
}

impl Server {
    pub(crate) fn process_frame(self: &Arc<Self>, c: &Arc<Client>, payload: &[u8]) {
        // Once a connection-level error is queued, any reply would be
        // dropped, and the connection may have lost its sign-in: its later
        // frames are ignored rather than run (docs/DEVIATIONS.md).
        if c.is_closing() {
            return;
        }
        let (req, parse_err) = parse_request(payload, &self.config.frame);
        // The server's and the address's frames are charged before any
        // other work, malformed frames included. A busy server refuses a
        // request and drops a notification; the connection stays open.
        if let Err(refusal) = self.lock().charge_frame_locked(c) {
            if refusal.row == 0 {
                if parse_err.is_none() && req.has_id && !notification_only(&req.method) {
                    c.enqueue(&error_response(Some(&req.id), refusal.error(None)));
                }
            } else {
                c.close_with_code(ws::STATUS_TRY_AGAIN_LATER, refusal.message);
            }
            return;
        }
        if let Some(parse_err) = parse_err {
            // A request's error counts as it is sent; an unanswered fault
            // counts here.
            if !req.has_id || notification_only(&req.method) {
                c.note_violation(parse_err.code);
            }
            if notification_only(&req.method) {
                // The id of a notification method may be ignored, and the
                // frame handled as a notification (§1.1): it is never
                // answered, even with invalid params, and a ping is still a
                // ping.
                if req.method == "ping" {
                    c.pong();
                }
                return;
            }
            // Only an envelope error is answered without an id.
            if !req.has_id && matches!(parse_err.code, CODE_INVALID_PARAMS | CODE_TOO_LARGE) {
                return;
            }
            if req.has_id {
                c.send_error(&req, parse_err);
            } else {
                c.enqueue(&error_response(None, parse_err));
            }
            return;
        }

        // parse_request drops the id of a notification method, which a
        // server may ignore, handling the frame as a notification (§1.1):
        // activity and ping are never answered.
        if req.method == "ping" {
            c.pong();
            return;
        }
        // Clients send every other method they send as a request, with an
        // id. A server may ignore a request method sent without one (§1.1),
        // and this one does, whatever its method and params.
        if !req.has_id && !notification_only(&req.method) {
            return;
        }
        // auth is a barrier (§3.2): the read loop processes one frame at a
        // time, so auth finishes before any later frame on the connection is
        // read.
        if req.method == "auth" {
            if let Err(err) = self.authenticate(c, &req) {
                c.send_error(&req, err);
            }
            return;
        }

        let (user_id, method, entry) = {
            let mut st = self.lock();
            let Some(user_id) = st.client_user(c) else {
                drop(st);
                if req.has_id {
                    c.send_error(
                        &req,
                        RpcError::new(CODE_DENIED, "Sign in before sending requests"),
                    );
                }
                return;
            };
            let method = self
                .methods
                .get(req.method.as_str())
                .copied()
                .filter(|m| m.feature.is_none_or(|f| st.feature_on(f)));
            let Some(method) = method else {
                drop(st);
                if req.has_id {
                    c.send_error(
                        &req,
                        RpcError::new(
                            CODE_UNSUPPORTED,
                            format!("Unsupported method {}", quote(&req.method)),
                        ),
                    );
                }
                return;
            };
            if method.guest_write && st.read_only_guest(&user_id) {
                drop(st);
                c.send_error(&req, RpcError::new(CODE_DENIED, GUEST_READ_ONLY));
                return;
            }
            // Requests deduplicate per user (§1.2): a duplicate waits for the
            // original, even one running on another connection, and replies
            // with its outcome, brought up to date with the current state.
            let mut entry = None;
            if req.has_id {
                let fingerprint = sha256::sum256(request_fingerprint(&req).as_bytes());
                let prior = st.users.get(&user_id).and_then(|u| u.dedup.get(&req.id));
                if let Some(prior) = prior {
                    drop(st);
                    if prior.fingerprint != fingerprint {
                        c.send_error(
                            &req,
                            invalid_params(format!(
                                "Request id {} was already used for another operation",
                                quote(&req.id)
                            )),
                        );
                        return;
                    }
                    match prior.wait() {
                        Err(err) => c.send_error(&req, err),
                        Ok(result) => {
                            let st = self.lock();
                            let result = match method.refresh {
                                Some(refresh) => refresh(&st, &user_id, result),
                                None => result,
                            };
                            c.send_result(&req, result);
                        }
                    }
                    return;
                }
                let new_entry = Arc::new(DedupEntry::new(fingerprint));
                if let Some(u) = st.users.get_mut(&user_id) {
                    for dropped in u.dedup.put(&req.id, new_entry.clone()) {
                        st.dirty.dedup.insert((user_id.clone(), dropped));
                    }
                }
                entry = Some(new_entry);
            }
            (user_id, method, entry)
        };

        let _abandon = entry.as_ref().map(|entry| AbandonDedup {
            server: self,
            client: c,
            user_id: &user_id,
            req_id: &req.id,
            entry,
        });
        let outcome = (method.run)(self, c, &req);
        if req.has_id {
            match &outcome {
                Ok((_, true)) => {}
                Ok((result, false)) => c.send_result(&req, result.clone()),
                Err(err) => c.send_error(&req, err.clone()),
            }
        }
        if let Some(entry) = &entry {
            let mut st = self.lock();
            let user_id = st.dedup_user(c, &user_id);
            let failed = outcome.is_err();
            if failed || method.read_only {
                // Failed operations are not cached, and neither are reads,
                // whose results can be large and which are safe to run
                // again: a retry executes again. Concurrent duplicates still
                // share the outcome.
                if let Some(u) = st.users.get_mut(&user_id) {
                    u.dedup.remove(&req.id, entry);
                }
            }
            let kept = !failed && !method.read_only;
            entry.finish(outcome.map(|(result, _)| result));
            // Kept across restarts for the window (§1.2), for an identity
            // that outlives its connections.
            if kept && st.users.get(&user_id).is_some_and(|u| u.persists()) {
                st.dirty.dedup.insert((user_id.clone(), req.id.clone()));
            }
        }
    }
}

impl State {
    /// The user whose deduplication holds a request that `user_id` sent on
    /// `c`: a /rename while it ran moved them, with their requests, to the
    /// connection's new user_id.
    fn dedup_user(&self, c: &Arc<Client>, user_id: &str) -> String {
        if self.users.contains_key(user_id) {
            return user_id.to_owned();
        }
        self.client_user(c).unwrap_or_else(|| user_id.to_owned())
    }
}

impl Server {
    /// Panics after the request has been registered for deduplication, with
    /// the state lock held, for the cleanup test.
    #[cfg(test)]
    fn test_panic(
        self: &Arc<Self>,
        _c: &Arc<Client>,
        _req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        std::thread::sleep(std::time::Duration::from_millis(300));
        let _st = self.lock();
        panic!("test_panic");
    }

    /// Fails after a while without holding the state lock, so a test can
    /// change the user while it runs.
    #[cfg(test)]
    fn test_fail(
        self: &Arc<Self>,
        _c: &Arc<Client>,
        _req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        std::thread::sleep(std::time::Duration::from_millis(300));
        Err(invalid_params("test_fail"))
    }
}

/// Fails a deduplicated request whose operation unwound before finishing,
/// so the duplicates waiting on it (§1.2) answer instead of waiting forever,
/// and a retry runs again.
struct AbandonDedup<'a> {
    server: &'a Arc<Server>,
    client: &'a Arc<Client>,
    user_id: &'a str,
    req_id: &'a str,
    entry: &'a Arc<DedupEntry>,
}

impl Drop for AbandonDedup<'_> {
    fn drop(&mut self) {
        if self.entry.is_closed() {
            return;
        }
        let mut st = self.server.lock();
        let user_id = st.dedup_user(self.client, self.user_id);
        if let Some(u) = st.users.get_mut(&user_id) {
            u.dedup.remove(self.req_id, self.entry);
        }
        drop(st);
        self.entry
            .finish(Err(RpcError::new(CODE_INTERNAL_ERROR, "Internal error")));
    }
}

impl State {
    /// `me` answers a duplicate with the current profile.
    fn refresh_profile(&self, user_id: &str, result: Json) -> Json {
        match self.users.get(user_id) {
            Some(u) => obj! {"you" => self.you_locked(u)}.into(),
            None => result,
        }
    }

    /// A message or command result lists only the write URLs that are still
    /// unused.
    fn refresh_writes(&self, _user_id: &str, result: Json) -> Json {
        let Json::Object(original) = &result else {
            return result;
        };
        if original.get("embeds").is_none() {
            return result;
        }
        let mut current = original.clone();
        let writes: Vec<Json> = original
            .get("embeds")
            .map(|e| e.as_list().to_vec())
            .unwrap_or_default()
            .into_iter()
            .filter(|written| {
                let id = written
                    .as_object()
                    .and_then(|w| w.get("embed_id"))
                    .and_then(Json::as_str)
                    .unwrap_or("");
                self.embeds
                    .get(id)
                    .is_some_and(|e| !e.started && self.writes.get(&e.token) == Some(&e.id))
            })
            .collect();
        if writes.is_empty() {
            current.remove("embeds");
        } else {
            current.insert("embeds".into(), writes.into());
        }
        current.into()
    }
}
