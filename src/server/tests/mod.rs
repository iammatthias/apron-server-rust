//! The server tests ported from internal/server/*_test.go. They live inside
//! the crate so the ones that inspect internal state can, as the Go tests
//! do with `app.mu`.

mod email_test;
mod ext_test;
mod helpers;
mod invite_bot_test;
mod invite_device_test;
mod limits_test;
mod persist_test;
mod push_fixture_test;
mod push_test;
mod reference_test;
mod server_test;
mod status_test;
mod webauthn_test;
mod webpush_test;
