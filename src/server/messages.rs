use std::collections::BTreeMap;
use std::sync::Arc;

use rust_stdlib::encoding::json::jsontext::Value;
use rust_stdlib::time;

use super::embeds::MAX_EMBEDS_PER_MESSAGE;
use super::protocol::*;
use super::server::{Client, Frame, LogRecord, RecordKind, Server, State, DEFAULT_ROOM_ID};
use crate::obj;
use crate::rate::{every, Limiter};

#[derive(Clone, Debug, Default)]
pub struct ReactionSet {
    pub from: Object,
    pub emojis: Vec<String>,
}

/// The current state of one message. Only non-empty reaction sets are kept;
/// clearing removes the user's entry.
#[derive(Debug, Default)]
pub struct MessageState {
    pub id: String,
    /// The author identity of every snapshot.
    pub from: Object,
    pub log_id: i64,
    pub owner: String,
    pub room_id: String,
    pub reactions: BTreeMap<String, ReactionSet>,
    /// Every logged snapshot's log_id, for redaction; the last is current.
    pub records: Vec<i64>,
    /// What push counting reads of the current snapshot, decoded once;
    /// `None` until read, and after a new snapshot.
    pub cached: Option<MessageInfo>,
}

/// What unread counts (§4.9) read of a message's current snapshot.
#[derive(Clone, Debug, Default)]
pub struct MessageInfo {
    pub deleted: bool,
    pub mentions: Vec<String>,
    pub reply_to: String,
}

impl MessageState {
    /// Every non-empty reaction set, ordered by user ID.
    pub fn reaction_elements(&self) -> Vec<Json> {
        self.reactions
            .values()
            .map(|set| obj! {"from" => set.from.clone(), "emojis" => set.emojis.clone()}.into())
            .collect()
    }
}

/// Bounds body.mentions.
pub const MAX_MENTIONS: usize = 256;
/// Bounds a message's ext, merged (§4.12), which every snapshot of the
/// message carries.
pub const MAX_MESSAGE_EXT_BYTES: usize = 64 << 10;
pub const MAX_EMOJI_BYTES: usize = 64;
pub const MAX_DISTINCT_EMOJI: usize = 20;

pub fn valid_message_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && (b'1'..=b'9').contains(&bytes[0])
        && bytes.iter().all(|b| b.is_ascii_digit())
}

/// Reads a message reference (reply_to). Clients send bare references; any
/// other keys, such as an echoed snapshot, are ignored.
pub(crate) fn parse_message_ref(params: &Params, name: &str) -> Result<Option<String>, RpcError> {
    let Some(raw) = params.get(name) else {
        return Ok(None);
    };
    let mut reference = Params::new();
    if raw.0.trim_ascii() == b"null"
        || rust_stdlib::encoding::json::v2::unmarshal(&raw.0, &mut reference, &[]).is_err()
    {
        return Err(invalid_params(format!("{name} must be a message object")));
    }
    match parse_string(&reference, "message_id", true) {
        Ok(id) if valid_message_id(&id) => Ok(Some(id)),
        _ => Err(invalid_params(format!(
            "{name}.message_id must be a positive decimal string"
        ))),
    }
}

/// A message body's body.mentions (§3.5).
pub fn mentions(body: Option<&Object>) -> Vec<String> {
    body.and_then(|b| b.get("mentions"))
        .map(|m| {
            m.as_list()
                .iter()
                .filter_map(Json::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn validate_body(body: &Object) -> Result<(), RpcError> {
    if let Some(raw) = body.get("text") {
        if raw.as_str().is_none() {
            return Err(invalid_params("body.text must be a string"));
        }
    }
    if let Some(raw) = body.get("format") {
        match raw.as_str() {
            Some("plain") | Some("markdown") => {}
            _ => return Err(invalid_params("body.format must be plain or markdown")),
        }
    }
    if let Some(raw) = body.get("mentions") {
        let Json::Array(mentions) = raw else {
            return Err(invalid_params(
                "body.mentions must be an array of user_id strings",
            ));
        };
        if mentions.len() > MAX_MENTIONS {
            // A count limit the server sets is denied (§1.1).
            return Err(RpcError::new(
                CODE_DENIED,
                format!("A message mentions at most {MAX_MENTIONS} users"),
            ));
        }
        for value in mentions {
            if !value.as_str().is_some_and(valid_id) {
                return Err(invalid_params(
                    "body.mentions must be an array of user_id strings",
                ));
            }
        }
    }
    if let Some(raw) = body.get("embeds") {
        let Json::Array(embeds) = raw else {
            return Err(invalid_params("body.embeds must be an array"));
        };
        if embeds.len() > MAX_EMBEDS_PER_MESSAGE {
            return Err(RpcError::new(
                CODE_DENIED,
                format!("A message holds at most {MAX_EMBEDS_PER_MESSAGE} embeds"),
            ));
        }
        for (i, value) in embeds.iter().enumerate() {
            let Some(embed) = value.as_object() else {
                return Err(invalid_params(format!(
                    "body.embeds[{i}] must be an object"
                )));
            };
            match embed.get("kind").and_then(Json::as_str) {
                Some(kind) if !kind.is_empty() => {}
                _ => {
                    return Err(invalid_params(format!(
                        "body.embeds[{i}].kind must be a non-empty string"
                    )))
                }
            }
        }
    }
    Ok(())
}

fn parse_emojis(params: &Params) -> Result<Vec<String>, RpcError> {
    let Some(raw) = params.get("emojis") else {
        return Err(invalid_params("Missing emojis"));
    };
    let mut values: Vec<Value> = Vec::new();
    if raw.0.trim_ascii() == b"null"
        || rust_stdlib::encoding::json::v2::unmarshal(&raw.0, &mut values, &[]).is_err()
    {
        return Err(invalid_params("emojis must be an array of strings"));
    }
    let mut emojis: Vec<String> = Vec::with_capacity(values.len());
    for value in values {
        let mut emoji = String::new();
        if rust_stdlib::encoding::json::v2::unmarshal(&value.0, &mut emoji, &[]).is_err()
            || emoji.is_empty()
        {
            return Err(invalid_params("emojis must be non-empty strings"));
        }
        if emoji.len() > MAX_EMOJI_BYTES {
            return Err(RpcError::new(
                CODE_TOO_LARGE,
                format!("An emoji is at most {MAX_EMOJI_BYTES} bytes"),
            ));
        }
        if !emojis.contains(&emoji) {
            emojis.push(emoji);
        }
    }
    if emojis.len() > MAX_DISTINCT_EMOJI {
        // A count limit the server sets is denied (§1.1).
        return Err(RpcError::new(
            CODE_DENIED,
            format!("At most {MAX_DISTINCT_EMOJI} distinct emoji per message"),
        ));
    }
    Ok(emojis)
}

fn same_emoji_set(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().all(|emoji| b.contains(emoji))
}

pub fn tombstone(snapshot: &mut Object) {
    snapshot.remove("body");
    snapshot.remove("ext");
    snapshot.insert("deleted".into(), true.into());
}

impl State {
    /// What unread counts read of the current snapshot.
    pub fn message_info(&mut self, message_id: &str) -> MessageInfo {
        if let Some(cached) = self.messages.get(message_id).and_then(|m| m.cached.clone()) {
            return cached;
        }
        let snapshot = self.snapshot(message_id);
        let body = snapshot.get("body").and_then(Json::as_object);
        let info = MessageInfo {
            deleted: snapshot.get("deleted").is_some_and(Json::is_true),
            mentions: mentions(body),
            reply_to: snapshot
                .get("reply_to")
                .and_then(Json::as_object)
                .and_then(|r| r.get("message_id"))
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_owned(),
        };
        if let Some(m) = self.messages.get_mut(message_id) {
            m.cached = Some(info.clone());
        }
        info
    }

    /// Decodes the message's current snapshot, a copy the caller owns.
    pub fn snapshot(&self, message_id: &str) -> Object {
        self.messages
            .get(message_id)
            .and_then(|m| m.records.last())
            .and_then(|id| self.records.get(id))
            .map(LogRecord::value)
            .unwrap_or_default()
    }

    /// Creates a message (no message_id) or saves an existing one (§4.4):
    /// every client field is replaced by the submitted state. Without
    /// room_id the message goes to the default room (§3.5). A save naming a
    /// different room_id moves the message. The broadcasts precede the
    /// result (§1). A new message with no text and no embeds is neither
    /// logged nor broadcast, and its result is {}.
    pub fn save_message_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        let mut room_id = parse_string(&req.params, "room_id", false)?;
        if !req.params.contains_key("room_id") {
            room_id = DEFAULT_ROOM_ID.into();
        }
        let mut message_id = parse_string(&req.params, "message_id", false)?;
        let replacing = req.params.contains_key("message_id");
        if replacing && !valid_message_id(&message_id) {
            return Err(invalid_params(
                "message_id must be a positive decimal string",
            ));
        }
        let reply_id = parse_message_ref(&req.params, "reply_to")?;
        let deleted = parse_bool(&req.params, "deleted", false)?;
        if deleted && !replacing {
            return Err(invalid_params("Cannot create a deleted message"));
        }
        let mut body: Option<Object> = None;
        if !deleted {
            let parsed = parse_object(&req.params, "body", true)?.unwrap_or_default();
            validate_body(&parsed)?;
            body = Some(parsed);
        }
        let (ext_write, _) = parse_ext(&req.params, "ext")?;

        let Some(user_id) = self.client_user(c) else {
            return Err(RpcError::new(
                CODE_DENIED,
                "Sign in before sending requests",
            ));
        };
        if self.visible_room_locked(&user_id, &room_id).is_none() {
            return Err(invalid_params(format!("Unknown room {}", quote(&room_id))));
        }
        let mut from = self.users[&user_id].from();
        let mut current: Option<String> = None;
        if replacing {
            let Some(m) = self.visible_message_locked(&user_id, &message_id) else {
                return Err(invalid_params(format!(
                    "Unknown message {}",
                    quote(&message_id)
                )));
            };
            if m.owner != user_id {
                return Err(RpcError::new(
                    CODE_DENIED,
                    "Only the author may edit, move, or delete this message",
                ));
            }
            // A move snapshot is logged in both rooms and names both, so a
            // message may not move to a room that some who see its room
            // cannot see, such as a private room.
            if m.room_id != room_id && self.reveals_to(&m.room_id, &room_id) {
                return Err(RpcError::new(
                    CODE_DENIED,
                    "A message cannot move to a room that fewer people can see",
                ));
            }
            from = m.from.clone();
            current = Some(m.id.clone());
        }
        if let Some(reply_id) = &reply_id {
            let Some(target) = self.visible_message_locked(&user_id, reply_id) else {
                return Err(invalid_params(
                    "reply_to must name another existing message",
                ));
            };
            if replacing && *reply_id == message_id {
                return Err(invalid_params(
                    "reply_to must name another existing message",
                ));
            }
            // A reply names its target's message_id to everyone who sees the
            // reply, so it may not name a message some of them cannot see.
            if self.reveals_to(&room_id, &target.room_id) {
                return Err(RpcError::new(
                    CODE_DENIED,
                    "A reply cannot quote a message that fewer people can see",
                ));
            }
        }
        let previous: Option<Object> = current.as_ref().map(|id| self.snapshot(id));
        // ext merges into the current snapshot's, and the limit applies to
        // the result (§4.12). A creation, and a save onto a tombstone,
        // merges into an empty ext, and a save with deleted: true drops it.
        let mut ext = ExtObject::new();
        if !deleted {
            let mut kept = ExtObject::new();
            if let Some(previous) = &previous {
                if !previous.get("deleted").is_some_and(Json::is_true) {
                    kept = ext_of(previous.get("ext"));
                }
            }
            ext = merge_ext(&kept, &ext_write);
            if encoded_size(&Json::Ext(ext.clone())) > MAX_MESSAGE_EXT_BYTES {
                return Err(RpcError::new(
                    CODE_TOO_LARGE,
                    format!("The message's ext would be over {MAX_MESSAGE_EXT_BYTES} bytes"),
                ));
            }
        }
        if !replacing {
            let body_ref = body.as_ref().expect("a creation has a body");
            let text = body_ref.get("text").and_then(Json::as_str).unwrap_or("");
            if text.is_empty() && body_ref.get("embeds").map_or(0, |e| e.as_list().len()) == 0 {
                let result = Object::new();
                c.send_result(req, result.clone().into());
                return Ok((result.into(), true));
            }
            self.admit_post_locked(&user_id)?;
        }

        let log_id = self.next_id_locked();
        if !replacing {
            message_id = format_id(log_id);
        }
        // Embeds are resolved last: a new upload or stream embed reserves a
        // write.
        let mut written: Vec<Json> = Vec::new();
        if let Some(body) = body.as_mut() {
            let (embeds, writes) =
                self.resolve_embeds_locked(c, &message_id, previous.as_ref(), body)?;
            written = writes;
            if !embeds.is_empty() {
                body.insert("embeds".into(), embeds.into());
            } else {
                body.remove("embeds");
            }
        }
        self.release_embeds_locked(previous.as_ref(), body.as_ref());

        let mut snapshot = obj! {
            "message_id" => message_id.as_str(),
            "log_id" => format_id(log_id),
            "room_id" => room_id.as_str(),
            "from" => from.clone(),
        };
        if deleted {
            snapshot.insert("deleted".into(), true.into());
        } else {
            snapshot.insert("body".into(), body.unwrap_or_default().into());
        }
        if let Some(reply_id) = &reply_id {
            snapshot.insert(
                "reply_to".into(),
                obj! {"message_id" => reply_id.as_str()}.into(),
            );
        }
        if !ext.is_empty() {
            snapshot.insert("ext".into(), Json::Ext(ext));
        }

        if current.is_none() {
            self.messages.insert(
                message_id.clone(),
                MessageState {
                    id: message_id.clone(),
                    from,
                    owner: user_id.clone(),
                    ..MessageState::default()
                },
            );
        }
        let source = self.messages[&message_id].room_id.clone();
        let moved = self.commit_snapshot_locked(&message_id, snapshot.clone(), log_id);
        if deleted {
            self.redact_locked(&message_id);
        }
        if moved && !self.messages[&message_id].reactions.is_empty() {
            let elements = self.messages[&message_id].reaction_elements();
            self.commit_reactions_locked(&message_id, elements);
        }
        let moved_from = if moved { Some(source) } else { None };
        self.message_unread_locked(&message_id, previous.as_ref(), moved_from.as_deref());
        if !replacing {
            // The author's own message moves their read position (§4.9).
            self.unread_changed_locked(&user_id, &room_id);
        }
        self.wake_locked(&message_id, &snapshot, previous.as_ref());
        if !deleted {
            self.unfurl_locked(
                &user_id,
                &c.base_url,
                &message_id,
                previous.as_ref(),
                &snapshot,
            );
        }
        let mut result = obj! {"message_id" => message_id.as_str()};
        if !written.is_empty() {
            result.insert("embeds".into(), written.into());
        }
        c.send_result(req, result.clone().into());
        Ok((result.into(), true))
    }

    /// Logs and delivers a message snapshot, adding prev_log_id, in the
    /// message's room and, for a move, the previous one too; a move snapshot
    /// names the previous room in prev_room_id (§4.3.1). Reports whether the
    /// snapshot moved the message.
    pub fn commit_snapshot_locked(
        &mut self,
        message_id: &str,
        mut snapshot: Object,
        log_id: i64,
    ) -> bool {
        snapshot.remove("prev_room_id");
        let m = &self.messages[message_id];
        if m.log_id != 0 {
            snapshot.insert("prev_log_id".into(), format_id(m.log_id).into());
        }
        let destination = snapshot
            .get("room_id")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned();
        let mut rooms = vec![destination.clone()];
        let moved = !m.room_id.is_empty() && m.room_id != destination;
        if moved {
            let source = m.room_id.clone();
            rooms = vec![source.clone(), destination.clone()];
            // A move out of a room that some who see the destination cannot
            // see, such as a private one, does not name it to them.
            if !self.reveals_to(&destination, &source) {
                snapshot.insert("prev_room_id".into(), source.into());
            }
        }
        let (owner, first) = (m.owner.clone(), m.records.is_empty());
        let m = self.messages.get_mut(message_id).expect("message exists");
        m.log_id = log_id;
        m.room_id = destination.clone();
        m.cached = None;
        if !moved && first {
            if let Some(r) = self.rooms.get_mut(&destination) {
                if r.members.contains(&owner) {
                    r.active.insert(owner, log_id);
                }
            }
        }
        let mut record = LogRecord::new(log_id, RecordKind::Message, &snapshot);
        record.message = message_id.to_owned();
        let frame = Frame::from(raw_notification("message", &record.raw));
        self.messages
            .get_mut(message_id)
            .expect("message exists")
            .records
            .push(log_id);
        self.touch_message(message_id);
        self.append_locked(record, &rooms);
        self.deliver_locked(&frame, &rooms);
        moved
    }

    /// Publishes a server-made snapshot of a message, such as a finished
    /// upload or stream (§4.8.3): `edit` rewrites a copy of the current body,
    /// and nothing is published when it reports no change.
    pub fn republish_locked(&mut self, message_id: &str, edit: impl FnOnce(&mut Object) -> bool) {
        let mut snapshot = self.snapshot(message_id);
        if snapshot.get("deleted").is_some_and(Json::is_true) {
            return;
        }
        let Some(Json::Object(body)) = snapshot.get_mut("body") else {
            return;
        };
        if !edit(body) {
            return;
        }
        let log_id = self.next_id_locked();
        snapshot.insert("log_id".into(), format_id(log_id).into());
        self.commit_snapshot_locked(message_id, snapshot, log_id);
    }

    /// Rewrites a deleted message's earlier snapshots into tombstones at
    /// their original log_ids (§4.4).
    pub fn redact_locked(&mut self, message_id: &str) {
        let ids = self
            .messages
            .get(message_id)
            .map(|m| m.records.clone())
            .unwrap_or_default();
        for id in ids {
            if let Some(record) = self.records.get_mut(&id) {
                record.rewrite(tombstone);
            }
            self.touch_record(id);
        }
    }

    /// Applies messages_per_minute to new messages, room_set, and /avatar:
    /// each user may send a burst of messages_per_minute, refilled evenly
    /// over a minute.
    pub fn admit_post_locked(&mut self, user_id: &str) -> Result<(), RpcError> {
        let limit = self.config.messages_per_minute;
        if limit <= 0 {
            return Ok(());
        }
        let Some(u) = self.users.get_mut(user_id) else {
            return Ok(());
        };
        let limiter = u.posts.get_or_insert_with(|| {
            Limiter::new(
                every(rust_stdlib::time::Duration::from_nanos(
                    time::MINUTE.as_nanos() / limit,
                )),
                limit,
            )
        });
        let now = time::now();
        let reservation = limiter.reserve_n(&now, 1);
        let delay = reservation.delay_from(&now);
        if delay.as_nanos() > 0 {
            limiter.cancel_at(&reservation, &now);
            let wait = (delay.as_nanos() + time::SECOND.as_nanos() - 1) / time::SECOND.as_nanos();
            return Err(RpcError::with_data(
                CODE_RETRY_AFTER,
                "Too many messages; slow down",
                obj! {"retry_after" => wait},
            ));
        }
        Ok(())
    }

    /// Replaces the caller's complete reaction set on one message (§4.7).
    /// Duplicates collapse; an unchanged set logs nothing. The broadcast
    /// precedes the result (§1).
    pub fn react_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        let message_id = parse_string(&req.params, "message_id", true)?;
        let emojis = parse_emojis(&req.params)?;
        let Some(user_id) = self.client_user(c) else {
            return Err(RpcError::new(
                CODE_DENIED,
                "Sign in before sending requests",
            ));
        };
        let Some(m) = self.visible_message_locked(&user_id, &message_id) else {
            return Err(invalid_params(format!(
                "Unknown message {}",
                quote(&message_id)
            )));
        };
        let current: Vec<String> = m
            .reactions
            .get(&user_id)
            .map(|s| s.emojis.clone())
            .unwrap_or_default();
        if !same_emoji_set(&current, &emojis) {
            self.touch_message(&message_id);
            let from = self.users[&user_id].from();
            let m = self.messages.get_mut(&message_id).expect("message exists");
            if emojis.is_empty() {
                m.reactions.remove(&user_id);
            } else {
                m.reactions.insert(
                    user_id.clone(),
                    ReactionSet {
                        from: from.clone(),
                        emojis: emojis.clone(),
                    },
                );
            }
            self.commit_reactions_locked(
                &message_id,
                vec![obj! {"from" => from, "emojis" => emojis}.into()],
            );
        }
        let result = Object::new();
        c.send_result(req, result.clone().into());
        Ok((result.into(), true))
    }

    /// Logs and delivers one reactions record in the message's current room.
    /// Reaction sets carry no prev_log_id (§4.3.1).
    pub fn commit_reactions_locked(&mut self, message_id: &str, elements: Vec<Json>) {
        let log_id = self.next_id_locked();
        let room_id = self.messages[message_id].room_id.clone();
        let record = LogRecord::new(
            log_id,
            RecordKind::Reactions,
            &obj! {
                "log_id" => format_id(log_id),
                "message_id" => message_id,
                "room_id" => room_id.as_str(),
                "reactions" => elements,
            },
        );
        let frame = Frame::from(raw_notification("reactions", &record.raw));
        self.append_locked(record, std::slice::from_ref(&room_id));
        self.deliver_locked(&frame, &[room_id]);
    }
}

impl Server {
    pub(crate) fn save_message(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        self.lock().save_message_locked(c, req)
    }
    pub(crate) fn react(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        self.lock().react_locked(c, req)
    }
}
