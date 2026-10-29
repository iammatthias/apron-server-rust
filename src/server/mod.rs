//! The Apron server: the WebSocket protocol handlers and the state they
//! share, ported file by file from `internal/server`.

pub mod activity;
pub mod admin;
pub mod bots;
pub mod client;
pub mod commands;
pub mod config;
pub mod custom_emoji;
pub mod dedup;
pub mod devices;
pub mod dispatch;
pub mod email;
pub mod embeds;
pub mod emoji;
pub mod history;
pub mod invites;
pub mod limits;
pub mod media_types;
pub mod messages;
pub mod metadata;
pub mod outbound;
pub mod passkeys;
pub mod persist;
pub mod protocol;
pub mod purge;
pub mod push;
pub mod push_delivery;
pub mod remap;
pub mod rename;
pub mod restore;
pub mod retention;
pub mod room_list;
pub mod room_set;
pub mod rooms;
#[allow(clippy::module_inception)]
pub mod server;
pub mod server_frame;
pub mod status;
pub mod streams;
pub mod toggles;
pub mod tokens;
pub(crate) mod unfurl;
pub mod unread;
pub mod uploads;
pub mod user_ids;
pub mod users;
pub mod wake;
pub mod webauthn;
pub mod webpush;

#[cfg(test)]
mod tests;

pub use config::{default_config, Config};
pub use server::{open, Server, State};
