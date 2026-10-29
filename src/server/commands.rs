//! Server commands (§4.1): /help, /avatar, /invite-device, /invite-bot,
//! /kick and the admin commands, run from a `command` request and answered
//! with scoped system notices (Appendix A.1).

use std::sync::Arc;

use super::embeds::EmbedPurpose;
use super::messages::{parse_message_ref, validate_body, MessageState};
use super::metadata::one_upload;
use super::protocol::*;
use super::rooms::RoomState;
use super::server::{Client, Server, State, DEFAULT_ROOM_ID};
use super::toggles::{Feature, UPLOADS_OFF};
use super::users::{UserState, ADMIN_ROLE, GUEST_READ_ONLY};
use crate::obj;

/// Scoped system identities (Appendix A.1). user_ids starting with `~` are
/// reserved for them (Appendix A.3): requestable_user_id never matches one.
pub const ROOM_NOTICE_ID: &str = "~room";
pub const PRIVATE_NOTICE_ID: &str = "~private";
pub const PRIVATE_NOTICE_NAME: &str = "System message to you";

/// Executes a command for the sender in a room, with the message body and
/// the arguments after the command word.
type CommandFn = fn(&mut State, &Arc<Client>, &str, &Object, &str) -> Result<Object, RpcError>;

/// Who may run a command, as apron-server-cloudflare names them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Audience {
    Everyone,
    /// Accounts, which bots and guests are not.
    Accounts,
    /// Accounts with the admin role.
    Admins,
}

impl Audience {
    /// Reports whether /help lists the command for u.
    fn lists(self, u: &UserState) -> bool {
        self.refusal(u, "").is_none()
    }

    /// The error that refuses u the command `name`, if any.
    fn refusal(self, u: &UserState, name: &str) -> Option<RpcError> {
        let message = match self {
            Audience::Everyone => return None,
            Audience::Accounts if u.account() => return None,
            Audience::Accounts if u.bot() => format!("A bot can't use /{name}"),
            Audience::Accounts => format!("Sign in with a passkey to use /{name}"),
            Audience::Admins if u.account() && u.has_role(ADMIN_ROLE) => return None,
            Audience::Admins => format!("Only an admin can use /{name}"),
        };
        Some(RpcError::new(CODE_DENIED, message))
    }
}

/// One command this server provides (§4.1).
struct ServerCommand {
    name: &'static str,
    usage: &'static str,
    help: &'static str,
    audience: Audience,
    /// Whether it changes anything, which a read-only guest may not do.
    writes: bool,
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
        audience: Audience::Everyone,
        writes: false,
        run: State::help_command,
    },
    ServerCommand {
        name: "avatar",
        usage: "/avatar",
        help: "with one image attached: set your avatar",
        audience: Audience::Accounts,
        writes: true,
        run: State::avatar_command,
    },
    ServerCommand {
        name: "invite-device",
        usage: "/invite-device <name>",
        help: "get a token that signs in as you on another device, named <name>; at most 3 names, and a name again replaces its token",
        audience: Audience::Accounts,
        writes: true,
        run: State::invite_device_command,
    },
    ServerCommand {
        name: "invite-bot",
        usage: "/invite-bot",
        help: "get a token that signs in as your bot, named after you; again, it replaces the token and renames the bot",
        audience: Audience::Accounts,
        writes: true,
        run: State::invite_bot_command,
    },
    ServerCommand {
        name: "passkeys",
        usage: "/passkeys [remove <n>]",
        help: "list your account's passkeys, or remove one of them",
        audience: Audience::Accounts,
        writes: true,
        run: State::passkeys_command,
    },
    ServerCommand {
        name: "kick",
        usage: "/kick <user_id>",
        help: "remove a user from this room",
        audience: Audience::Admins,
        writes: true,
        run: State::kick_command,
    },
    ServerCommand {
        name: "admin",
        usage: "/admin [remove] <user_id>",
        help: "make a registered user an admin, or no longer one",
        audience: Audience::Admins,
        writes: true,
        run: State::admin_command,
    },
    ServerCommand {
        name: "role",
        usage: "/role <user_id> [<role>]",
        help: "show a user's roles, or give or take away one (admin, mod and bot act as such; any other is a label)",
        audience: Audience::Admins,
        writes: true,
        run: State::role_command,
    },
    ServerCommand {
        name: "rename",
        usage: "/rename <old_user_id> <new_user_id>",
        help: "change a registered user's user_id",
        audience: Audience::Admins,
        writes: true,
        run: State::rename_command,
    },
    ServerCommand {
        name: "invite-token",
        usage: "/invite-token <user_id>",
        help: "create a user who signs in with a token instead of a passkey, and get the token",
        audience: Audience::Admins,
        writes: true,
        run: State::invite_token_command,
    },
    ServerCommand {
        name: "invite",
        usage: "/invite <uses>",
        help: "get a token that signs up to <uses> new users (at most 50) for a week, replacing the last one; /invite 0 revokes it",
        audience: Audience::Admins,
        writes: true,
        run: State::invite_command,
    },
    ServerCommand {
        name: "emoji",
        usage: "/emoji add|remove :name:",
        help: "add a custom emoji, or replace its image: send /emoji add :name: with one image attached; /emoji remove :name: removes it",
        audience: Audience::Admins,
        writes: true,
        run: State::emoji_command,
    },
    ServerCommand {
        name: "server",
        usage: "/server [title|description [<text>] | avatar]",
        help: "show this server's title, description and avatar; set one, the avatar with one image attached; or clear one, back to the deployment's",
        audience: Audience::Admins,
        writes: true,
        run: State::server_command,
    },
    ServerCommand {
        name: "toggle",
        usage: "/toggle <activity|uploads|presence|addmember>",
        help: "turn typing activity, uploads, user status (presence), or users adding others to rooms (addmember) off or on for everyone",
        audience: Audience::Admins,
        writes: true,
        run: State::toggle_command,
    },
    ServerCommand {
        name: "purge",
        usage: "/purge <user_id>",
        help: "disconnect a user and delete their account, bot, and everything they posted or uploaded",
        audience: Audience::Admins,
        writes: true,
        run: State::purge_command,
    },
];

/// Renders a notice for the one connection it is queued on: unlogged,
/// without message_id or log_id (Appendix A.1).
pub(super) fn private_notice(r: &RoomState, text: &str) -> Object {
    obj! {"method" => "message", "params" => obj! {
        "room_id" => r.id.as_str(),
        "from" => obj! {"user_id" => PRIVATE_NOTICE_ID, "name" => PRIVATE_NOTICE_NAME},
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
        validate_body(&body, self.config.frame.max_text_bytes)?;
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
                if command.writes && self.read_only_guest(&user_id) {
                    return Err(RpcError::new(CODE_DENIED, GUEST_READ_ONLY));
                }
                if let Some(refusal) = command.audience.refusal(&self.users[&user_id], &name) {
                    return Err(refusal);
                }
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
        let read_only = self.read_only_guest(&user_id);
        let lines: Vec<String> = SERVER_COMMANDS
            .iter()
            .filter(|command| !(command.writes && read_only))
            .filter(|command| command.audience.lists(u))
            .filter(|command| command.name != "avatar" || self.feature_on(Feature::Uploads))
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
        if !self.feature_on(Feature::Uploads) {
            return Err(RpcError::new(CODE_DENIED, UPLOADS_OFF));
        }
        if !one_upload(embeds) {
            return Err(invalid_params(
                "/avatar takes exactly one upload embed: attach an image",
            ));
        }
        let user_id = self.client_user(c).unwrap_or_default();
        self.charge_uploads_locked(&user_id, 1)?;
        Ok(self.new_image_write_locked(c, EmbedPurpose::Avatar(user_id)))
    }

    /// `/kick <user_id>` removes a user, an account or a guest, from the
    /// room of the command, as if they had left it (§4.2.2), and tells the
    /// admin who ran it with a ~private notice.
    fn kick_command(
        &mut self,
        c: &Arc<Client>,
        room_id: &str,
        _body: &Object,
        args: &str,
    ) -> Result<Object, RpcError> {
        let user_id = self.client_user(c).unwrap_or_default();
        let target = args.strip_prefix('@').unwrap_or(args);
        if target.is_empty() || target.contains(char::is_whitespace) {
            return Err(invalid_params("Usage: /kick <user_id>"));
        }
        if target == user_id {
            return Err(RpcError::new(
                CODE_DENIED,
                "You can't kick yourself; leave the room instead",
            ));
        }
        if !self.leave_locked(target, room_id) {
            return Err(invalid_params(format!("{target} is not in this room")));
        }
        c.enqueue(&private_notice(
            &self.rooms[room_id],
            &format!("Removed `{target}` from this room."),
        ));
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
