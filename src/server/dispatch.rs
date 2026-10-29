//! Request dispatch: the methods a connection may call, and process_frame,
//! which parses a frame, deduplicates it (§1.2) and runs its method.

use std::collections::BTreeMap;
use std::sync::Arc;

use rust_stdlib_crypto::sha256;

use super::client::Client;
use super::config::Config;
use super::dedup::DedupEntry;
use super::limits::refused;
use super::protocol::*;
use super::server::{Server, State};
use super::toggles::Feature;
use super::users::{guest_write, GUEST_READ_ONLY};
use crate::obj;
use crate::ws;

/// A request handler. When it succeeds and has already queued its own reply,
/// it reports replied. Handlers whose results describe state queue them
/// while holding the lock, so that a result reflects every notification sent
/// before it on the connection, and after the notifications the request
/// causes, which precede its result (§1).
pub type Operation = fn(&Arc<Server>, &Arc<Client>, &Request) -> Result<(Json, bool), RpcError>;

pub(super) fn operations(config: &Config) -> BTreeMap<&'static str, Operation> {
    let mut ops: BTreeMap<&'static str, Operation> = BTreeMap::new();
    ops.insert("me", Server::update_profile);
    #[cfg(test)]
    ops.insert("test_panic", Server::test_panic);
    #[cfg(test)]
    ops.insert("test_fail", Server::test_fail);
    ops.insert("message", Server::save_message);
    ops.insert("command", Server::command);
    ops.insert("history", Server::history);
    ops.insert("room_set", Server::set_room);
    ops.insert("room_list", Server::list_rooms);
    ops.insert("room_join", Server::join_room);
    ops.insert("room_leave", Server::leave_room);
    ops.insert("reactions", Server::react);
    ops.insert("activity", Server::activity);
    ops.insert("status", Server::status);
    if !config.disable_push {
        ops.insert("push_register", Server::register_push);
        ops.insert("push_unregister", Server::unregister_push);
    }
    ops
}

/// The operations that change nothing, so their results are not kept for
/// deduplication (§1.2): a duplicate after the original finished runs again.
fn read_only_op(method: &str) -> bool {
    matches!(method, "history" | "room_list")
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
                    c.enqueue(&error_response(
                        Some(&req.id),
                        refused(
                            "Server is busy with too many requests",
                            refusal.retry_after(),
                            None,
                        ),
                    ));
                }
            } else {
                c.close_with_code(ws::STATUS_TRY_AGAIN_LATER, "Frame rate limit reached");
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

        let (user_id, op, entry) = {
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
            // Activity turned off takes the unsupported-method path.
            let op = self
                .ops
                .get(req.method.as_str())
                .copied()
                .filter(|_| req.method != "activity" || st.feature_on(Feature::Activity));
            let Some(op) = op else {
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
            if guest_write(&req.method) && st.read_only_guest(&user_id) {
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
                            let result = st.current_result_locked(&user_id, &req.method, result);
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
            (user_id, op, entry)
        };

        let _abandon = entry.as_ref().map(|entry| AbandonDedup {
            server: self,
            client: c,
            user_id: &user_id,
            req_id: &req.id,
            entry,
        });
        let outcome = op(self, c, &req);
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
            if failed || read_only_op(&req.method) {
                // Failed operations are not cached, and neither are reads,
                // whose results can be large and which are safe to run
                // again: a retry executes again. Concurrent duplicates still
                // share the outcome.
                if let Some(u) = st.users.get_mut(&user_id) {
                    u.dedup.remove(&req.id, entry);
                }
            }
            let kept = !failed && !read_only_op(&req.method);
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
    /// Brings a duplicate's result up to date (§1.2): `me` answers with the
    /// current profile, and a message result lists only the write URLs that
    /// are still unused. Other results name what the request made, which
    /// does not change.
    pub fn current_result_locked(&self, user_id: &str, method: &str, result: Json) -> Json {
        match method {
            "me" => match self.users.get(user_id) {
                Some(u) => obj! {"you" => self.you_locked(u)}.into(),
                None => result,
            },
            "message" | "command" => {
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
            _ => result,
        }
    }
}
