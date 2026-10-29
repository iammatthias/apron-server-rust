//! The server tests ported from internal/server/*_test.go. They live inside
//! the crate so the ones that inspect internal state can, as the Go tests
//! do with `app.mu`.

mod account_id_test;
mod activity_test;
mod admin_test;
mod auth_deadline_test;
mod connection_limits_test;
mod connection_status_test;
mod custom_emoji_test;
mod email_test;
mod ext_test;
mod frame_limits_test;
mod guest_posting_test;
mod helpers;
mod idle_bots_test;
mod invite_bot_test;
mod invite_device_test;
mod limits_test;
mod membership_test;
mod metadata_test;
mod outbound_test;
mod passkeys_test;
mod permissions_test;
mod persist_test;
mod posting_test;
mod push_fixture_test;
mod push_test;
mod reactions_test;
mod reference_test;
mod retention_test;
mod server_test;
mod status_test;
mod toggle_test;
mod unfurl_test;
mod wake_test;
mod webauthn_test;
mod webpush_test;
mod welcome_test;
