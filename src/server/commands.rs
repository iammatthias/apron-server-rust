//! Server commands (§4.1): /help, /avatar, /invite-device, /invite-bot, and
//! /kick, run from a `command` request and answered with scoped system
//! notices (Appendix A.1).

use std::sync::Arc;

use super::messages::{mentions, parse_message_ref, validate_body, MessageState};
use super::protocol::*;
use super::rooms::RoomState;
use super::server::{Client, Server, State, DEFAULT_ROOM_ID};
use super::users::UserState;
use crate::obj;

/// Scoped system identities (Appendix A.1). user_ids starting with `~` are
/// reserved for them (Appendix A.3): requestable_user_id never matches one.
pub const ROOM_NOTICE_ID: &str = "~room";
pub const PRIVATE_NOTICE_ID: &str = "~private";

pub const MAX_KICK_REASON_RUNES: usize = 200;

/// Executes a command for the sender in a room, with the message body and
/// the arguments after the command word.
type CommandFn = fn(&mut State, &Arc<Client>, &str, &Object, &str) -> Result<Object, RpcError>;

/// One command this server provides (§4.1).
struct ServerCommand {
    name: &'static str,
    usage: &'static str,
    help: &'static str,
    /// Reports whether the sender may use the command in the room; `None`
    /// means everyone may.
    available: Option<fn(&UserState, &RoomState) -> bool>,
    /// Executes the command, sending the frames it causes, and returns its
    /// result, which the caller sends after them (§1).
    run: CommandFn,
}

/// The commands in the order /help shows them.
const SERVER_COMMANDS: &[ServerCommand] = &[
    ServerCommand {
        name: "help",
        usage: "/help",
        help: "list the commands you can use here",
        available: None,
        run: State::help_command,
    },
    ServerCommand {
        name: "avatar",
        usage: "/avatar",
        help: "with one image attached: set your avatar",
        available: None,
        run: State::avatar_command,
    },
    ServerCommand {
        name: "invite-device",
        usage: "/invite-device <name>",
        help: "get a token that signs in as you on another device, named <name>; at most 3 names, and a name again replaces its token",
        available: Some(|u, _| u.account()),
        run: State::invite_device_command,
    },
    ServerCommand {
        name: "invite-bot",
        usage: "/invite-bot",
        help: "get a token that signs in as your bot, named after you; again, it replaces the token and renames the bot",
        available: Some(|u, _| u.account()),
        run: State::invite_bot_command,
    },
    ServerCommand {
        name: "kick",
        usage: "/kick @user [reason]",
        help: "remove someone from this room (its creator or a moderator)",
        available: Some(|u, r| r.may_remove(u)),
        run: State::kick_command,
    },
];

/// Renders a notice for the one connection it is queued on: unlogged,
/// without message_id or log_id (Appendix A.1).
pub(super) fn private_notice(r: &RoomState, text: &str) -> Object {
    obj! {"method" => "message", "params" => obj! {
        "room_id" => r.id.as_str(),
        "from" => obj! {"user_id" => PRIVATE_NOTICE_ID, "name" => "System message to you"},
        "body" => obj! {"text" => text, "format" => "markdown"},
    }}
}

impl State {
    /// Runs a `command` request (§4.1). It takes the params of a new message
    /// and is never logged, broadcast, or saved: body.text is the command
    /// line, and mentions, reply_to, and embeds are arguments that notify no
    /// one. Without room_id it runs in the default room. The result is {}
    /// or, for new upload embeds, their write URLs; replies arrive as scoped
    /// system notices (Appendix A.1) and effects as the frames they cause,
    /// all before the result (§1).
    pub fn command_locked(
        &mut self,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        for name in ["message_id", "deleted"] {
            if req.params.contains_key(name) {
                return Err(invalid_params(format!(
                    "A command has no {name}; send it as a message instead"
                )));
            }
        }
        let mut room_id = parse_string(&req.params, "room_id", false)?;
        if !req.params.contains_key("room_id") {
            room_id = DEFAULT_ROOM_ID.into();
        }
        let reply_id = parse_message_ref(&req.params, "reply_to")?;
        let body = parse_object(&req.params, "body", true)?.unwrap_or_default();
        validate_body(&body)?;
        parse_ext(&req.params, "ext")?;
        let text = body.get("text").and_then(Json::as_str).unwrap_or("");
        let line = text.trim();
        let Some(rest) = line.strip_prefix('/') else {
            return Err(invalid_params("A command starts with /; try /help"));
        };
        let (word, args) = rest.split_once(' ').unwrap_or((rest, ""));
        let name = word.to_lowercase();

        let Some(user_id) = self.client_user(c) else {
            return Err(RpcError::new(
                CODE_DENIED,
                "Sign in before sending requests",
            ));
        };
        if self.visible_room_locked(&user_id, &room_id).is_none() {
            return Err(invalid_params(format!("Unknown room {}", quote(&room_id))));
        }
        if let Some(reply_id) = &reply_id {
            if self.visible_message_locked(&user_id, reply_id).is_none() {
                return Err(invalid_params("reply_to must name an existing message"));
            }
        }
        for command in SERVER_COMMANDS {
            if command.name == name {
                let result = (command.run)(self, c, &room_id, &body, args.trim())?;
                c.send_result(req, result.clone().into());
                return Ok((result.into(), true));
            }
        }
        Err(invalid_params(format!(
            "Unknown command /{word}; try /help"
        )))
    }

    /// Logs and delivers a message from ~room to the room's members
    /// (Appendix A.1). It mentions no one.
    pub fn post_room_notice_locked(&mut self, room_id: &str, text: &str) {
        let log_id = self.next_id_locked();
        let message_id = format_id(log_id);
        let title = self.rooms[room_id].title();
        let from = obj! {"user_id" => ROOM_NOTICE_ID, "name" => title.as_str()};
        self.messages.insert(
            message_id.clone(),
            MessageState {
                id: message_id.clone(),
                from: from.clone(),
                owner: ROOM_NOTICE_ID.into(),
                ..MessageState::default()
            },
        );
        self.commit_snapshot_locked(
            &message_id,
            obj! {
                "message_id" => message_id.as_str(),
                "log_id" => message_id.as_str(),
                "room_id" => room_id,
                "from" => from,
                "body" => obj! {"text" => text},
            },
            log_id,
        );
    }

    /// Replies with a ~private notice listing the commands available to the
    /// sender in the room.
    fn help_command(
        &mut self,
        c: &Arc<Client>,
        room_id: &str,
        _body: &Object,
        _args: &str,
    ) -> Result<Object, RpcError> {
        let user_id = self.client_user(c).unwrap_or_default();
        let (u, r) = (&self.users[&user_id], &self.rooms[room_id]);
        let lines: Vec<String> = SERVER_COMMANDS
            .iter()
            .filter(|command| command.available.is_none_or(|available| available(u, r)))
            .map(|command| format!("- `{}`: {}", command.usage, command.help))
            .collect();
        c.enqueue(&private_notice(r, &lines.join("\n")));
        Ok(Object::new())
    }

    /// Takes exactly one upload embed, whose file becomes the sender's avatar
    /// when its write finishes (§4.8.6). The result carries the write URL.
    fn avatar_command(
        &mut self,
        c: &Arc<Client>,
        _room_id: &str,
        body: &Object,
        _args: &str,
    ) -> Result<Object, RpcError> {
        let embeds = body.get("embeds").map(Json::as_list).unwrap_or(&[]);
        let one_upload = embeds.len() == 1
            && embeds[0]
                .as_object()
                .and_then(|e| e.get("kind"))
                .and_then(Json::as_str)
                == Some("upload");
        if !one_upload {
            return Err(invalid_params(
                "/avatar takes exactly one upload embed: attach an image",
            ));
        }
        let user_id = self.client_user(c).unwrap_or_default();
        self.admit_post_locked(&user_id)?;
        self.embed_number += 1;
        let id = format!("embed_{}", self.embed_number);
        self.new_write_locked(c, &id, "upload", "");
        let e = self.embeds.get_mut(&id).expect("just registered");
        e.avatar_for = Some(user_id);
        Ok(obj! {
            "embeds" => vec![Json::from(obj! {"embed_id" => id.as_str(), "kind" => "upload", "write_url" => e.write_url()})],
        })
    }

    /// Removes the one mentioned user from the room: the room's members, the
    /// target included, receive the logged leave membership (§4.2.2), the
    /// target room_update left, and the remaining members a ~room notice with
    /// the reason. Only the room's creator and admins or moderators may kick.
    fn kick_command(
        &mut self,
        c: &Arc<Client>,
        room_id: &str,
        body: &Object,
        args: &str,
    ) -> Result<Object, RpcError> {
        let user_id = self.client_user(c).unwrap_or_default();
        let targets = mentions(Some(body));
        if targets.len() != 1 {
            return Err(invalid_params(
                "Usage: /kick @user [reason], mentioning exactly one user",
            ));
        }
        let r = &self.rooms[room_id];
        if !r.may_remove(&self.users[&user_id]) {
            return Err(RpcError::new(
                CODE_DENIED,
                format!(
                    "Only the creator of {} or a moderator can remove people from it",
                    r.title()
                ),
            ));
        }
        let target = targets[0].clone();
        if !r.members.contains(&target) {
            return Err(invalid_params(format!("@{target} is not in {}", r.title())));
        }
        if target == user_id {
            return Err(invalid_params(
                "You cannot remove yourself; leave the room instead",
            ));
        }
        // The first argument names the target as the user typed it. Only
        // body.mentions says who it is (§3.5.5); a user_id has no whitespace
        // (§2.4), so the typed mention ends with the first word at the
        // latest.
        let mut reason = args;
        if let Some((first, rest)) = args.split_once(' ').or(Some((args, ""))) {
            if first.starts_with('@') {
                reason = rest.trim();
            }
        }
        // The reason is one plain line inside a system notice.
        let mut reason = reason.split('\n').next().unwrap_or("").trim().to_owned();
        if reason.chars().count() > MAX_KICK_REASON_RUNES {
            reason = format!(
                "{}…",
                reason
                    .chars()
                    .take(MAX_KICK_REASON_RUNES)
                    .collect::<String>()
                    .trim()
            );
        }
        self.leave_locked(&target, room_id);
        let mut text = format!("@{target} was removed by @{user_id}");
        if !reason.is_empty() {
            text.push_str(": ");
            text.push_str(&reason);
        }
        self.post_room_notice_locked(room_id, &text);
        Ok(Object::new())
    }
}

impl Server {
    pub(crate) fn command(
        self: &Arc<Self>,
        c: &Arc<Client>,
        req: &Request,
    ) -> Result<(Json, bool), RpcError> {
        self.lock().command_locked(c, req)
    }
}
