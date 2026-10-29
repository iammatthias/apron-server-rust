//! The Apron server: the WebSocket protocol handlers and the state they
//! share, ported file by file from `internal/server`.

pub mod admin;
pub mod bots;
pub mod commands;
pub mod custom_emoji;
pub mod devices;
pub mod email;
pub mod embeds;
pub mod emoji;
pub mod invites;
pub mod messages;
pub mod metadata;
pub mod outbound;
pub mod passkeys;
pub mod persist;
pub mod protocol;
pub mod push;
pub mod retention;
pub mod rooms;
#[allow(clippy::module_inception)]
pub mod server;
pub mod status;
pub mod toggles;
pub(crate) mod unfurl;
pub mod unread;
pub mod users;
pub mod webauthn;
pub mod webpush;

#[cfg(test)]
mod tests;

pub use server::{default_config, open, Config, Server, State};
