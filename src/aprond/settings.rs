//! main.go's `serverConfig`, without the server types: the flag cross-checks
//! and conversions, in Go's order and with Go's messages. The core maps
//! [`Settings`] onto `server::Config`.

use super::email::{HttpSender, SmtpSender};
use super::options::Options;
use crate::server::protocol::FrameLimits;
use rust_stdlib::time::Duration;
use std::collections::BTreeMap;

/// How email sign-in codes are delivered.
#[derive(Debug)]
pub enum EmailSender {
    /// `server.LogEmailSender`: codes go to the server log.
    Log,
    Smtp(SmtpSender),
    /// A JSON POST to a mail API.
    Http(HttpSender),
}

/// The passkey relying party, for `webauthn.New`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebAuthnSettings {
    pub rp_id: String,
    pub rp_display_name: &'static str,
    pub rp_origins: Vec<String>,
}

/// The fields of `server.Config` that serverConfig sets from options.
#[derive(Debug, Default)]
pub struct Settings {
    pub static_dir: String,
    pub allow_any_origin: bool,
    pub public_url: String,
    pub max_connections: i64,
    pub max_listed_members: i64,
    pub max_private_rooms: i64,
    pub read_receipts: bool,
    pub welcome: String,
    pub client_ip_header: String,
    /// Holders by lowercased role; empty is Go's nil map.
    pub roles: BTreeMap<String, Vec<String>>,
    /// The SHA-256 of the admin token, from `--admin-token-file` or
    /// `$APRON_ADMIN_TOKEN`.
    pub admin_token: Option<[u8; 32]>,
    pub disable_push: bool,
    pub allow_insecure_push: bool,
    /// `--push.hosts`.
    pub push_hosts: crate::server::push::PushHosts,
    /// `--push.delay`.
    pub push_delay: Duration,
    pub vapid_private_key: String,
    pub vapid_subject: String,
    pub upload_dir: String,
    pub max_upload_bytes: i64,
    pub max_avatar_bytes: i64,
    pub upload_types: Vec<String>,
    pub max_message_upload_bytes: i64,
    pub max_upload_storage_bytes: i64,
    /// `None` keeps the server's default origin patterns.
    pub origin_patterns: Option<Vec<String>>,
    pub email_sender: Option<EmailSender>,
    pub email_link_url: String,
    /// `None` disables passkeys (an empty `--webauthn.rp-id`).
    pub webauthn: Option<WebAuthnSettings>,
    /// `--apple.app-id`.
    pub apple_app_ids: Vec<String>,
    /// `--unfurl.enable`.
    pub unfurl: bool,
    /// `--guest.posting`.
    pub guest_posting: bool,
    /// `--server.*`.
    pub server: crate::server::metadata::ServerMetadata,
    /// `--history.retention`; `None` keeps history.
    pub retention: Option<Duration>,
    /// The `--frame.*` bounds.
    pub frame: FrameLimits,
    /// The `--limit.*` limits, apron-server-cloudflare's.
    pub limits: crate::server::limits::Limits,
}

fn nonnegative(flag: &str, value: i64) -> Result<usize, String> {
    usize::try_from(value)
        .map_err(|_| format!("invalid --{flag} {value}: use a number, or 0 for no limit"))
}

fn rate(flag: &str, value: i64) -> Result<u32, String> {
    u32::try_from(nonnegative(flag, value)?)
        .map_err(|_| format!("invalid --{flag} {value}: use a smaller number"))
}

fn posts(flag: &str, minute: i64, day: i64) -> Result<crate::server::limits::Posts, String> {
    Ok(crate::server::limits::Posts {
        minute: rate(&format!("limit.{flag}-per-minute"), minute)?,
        day: rate(&format!("limit.{flag}-per-day"), day)?,
    })
}

/// A history rate: its burst at least a minute's pages.
fn history_rate(
    prefix: &str,
    per_minute: i64,
    burst: i64,
) -> Result<crate::server::limits::Rate, String> {
    let per_minute = rate(&format!("limit.{prefix}history-per-minute"), per_minute)?;
    let burst = rate(&format!("limit.{prefix}history-burst"), burst)?;
    if burst < per_minute {
        return Err(format!(
            "invalid --limit.{prefix}history-burst {burst}: use at least --limit.{prefix}history-per-minute"
        ));
    }
    Ok(crate::server::limits::Rate { per_minute, burst })
}

fn seconds_to_60(flag: &str, value: i64) -> Result<Duration, String> {
    if !(0..=60).contains(&value) {
        return Err(format!("invalid --{flag} {value}: use 0 to 60"));
    }
    Ok(Duration::from_secs(value))
}

fn positive(flag: &str, value: i64) -> Result<usize, String> {
    usize::try_from(value)
        .ok()
        .filter(|&n| n > 0)
        .ok_or_else(|| format!("invalid --{flag} {value}: use a positive number"))
}

/// main.go's `serverConfig`: turns options into the server's settings, or
/// the first error Go reports for them.
pub fn server_settings(options: &Options) -> Result<Settings, String> {
    let mut config = Settings {
        static_dir: options.static_dir.clone(),
        allow_any_origin: options.allow_any_origin,
        public_url: options.public_url.clone(),
        ..Settings::default()
    };
    if config.public_url.is_empty() {
        if let Some(domain) = options.tls.domains.first() {
            config.public_url = format!("https://{domain}");
        }
    }
    config.max_connections = options.max_connections;
    config.max_listed_members = options.max_listed_members;
    config.max_private_rooms = options.max_private_rooms;
    config.read_receipts = options.read_receipts;
    config.welcome = options.welcome.clone();
    config.client_ip_header = options.client_ip_header.clone();
    for grant in &options.roles {
        let (role, holder, ok) = match grant.split_once('=') {
            Some((role, holder)) => (role, holder, true),
            None => (grant.as_str(), "", false),
        };
        let (mut role, holder) = (role.trim().to_lowercase(), holder.trim());
        if !ok || role.is_empty() || holder.is_empty() {
            return Err(format!(
                "invalid --role {}: use role=user_id, such as admin=ada",
                rust_stdlib::strconv::quote(grant)
            ));
        }
        // Earlier configurations name apron-server-cloudflare's `mod` this way.
        if role == "moderator" {
            role = crate::server::users::MOD_ROLE.to_owned();
        }
        if !crate::server::users::valid_role(&role) {
            return Err(format!(
                "invalid --role {}: {}",
                rust_stdlib::strconv::quote(grant),
                crate::server::users::INVALID_ROLE
            ));
        }
        config
            .roles
            .entry(role)
            .or_default()
            .push(holder.to_string());
    }
    config.admin_token = admin_token(&options.admin_token_file)?;
    config.disable_push = options.push.disable;
    let public = !options.public_url.is_empty() || !options.tls.domains.is_empty();
    if options.push.allow_insecure && public {
        return Err("--push.allow-insecure lets any client make the server POST to http and internal addresses; it is for tests and refused with --public-url or --tls.domain".to_string());
    }
    config.allow_insecure_push = options.push.allow_insecure;
    config.push_hosts = crate::server::push::PushHosts::parse(&options.push.hosts)?;
    config.push_delay = parse_push_delay(&options.push.delay)?;
    config.vapid_private_key = options.push.vapid_private_key.clone();
    config.vapid_subject = options.push.vapid_subject.clone();
    let subject = &config.vapid_subject;
    if !subject.is_empty() && !subject.starts_with("mailto:") && !subject.starts_with("https://") {
        return Err(format!(
            "invalid --push.vapid-subject {}: use a mailto: or https: URL",
            rust_stdlib::strconv::quote(subject)
        ));
    }
    config.upload_dir = options.upload.dir.clone();
    config.max_upload_bytes = options.upload.max_mb << 20;
    config.max_avatar_bytes = options.upload.max_avatar_kb << 10;
    for pattern in &options.upload.types {
        let valid = pattern.split_once('/').is_some_and(|(major, minor)| {
            !major.is_empty()
                && !minor.is_empty()
                && !pattern.contains(char::is_whitespace)
                && (major != "*" || minor == "*")
        });
        if !valid {
            return Err(format!(
                "invalid --upload.type {}: use a MIME type, type/* or */*",
                rust_stdlib::strconv::quote(pattern)
            ));
        }
        config.upload_types.push(pattern.to_ascii_lowercase());
    }
    config.max_message_upload_bytes = options.upload.max_message_mb << 20;
    config.max_upload_storage_bytes = options.upload.max_storage_mb << 20;
    if !options.origins.is_empty() {
        config.origin_patterns = Some(options.origins.clone());
    }
    if !options.email.enable {
        // Email sign-in is a feature flag, off by default.
    } else if options.email.sender == "log" {
        if public {
            return Err("--email.sender log writes sign-in codes to the server log, so anyone who reads it can sign in as anyone; it is for development and refused with --public-url or --tls.domain: use --email.sender smtp".to_string());
        }
        config.email_sender = Some(EmailSender::Log);
    } else if options.email.sender == "smtp" {
        let email = &options.email;
        let sender = SmtpSender::new(
            &email.smtp_addr,
            &email.from,
            &email.smtp_user,
            &email.smtp_password,
            email.smtp_insecure,
        )?;
        config.email_sender = Some(EmailSender::Smtp(sender));
    } else if options.email.sender == "http" {
        let email = &options.email;
        let sender = HttpSender::new(&email.http_url, &email.from, &email.http_headers)?;
        config.email_sender = Some(EmailSender::Http(sender));
    }
    config.email_link_url = options.email.link_url.clone();
    if config.email_link_url.is_empty() {
        config.email_link_url = config.public_url.clone();
    }
    if !options.webauthn.rp_id.is_empty() {
        config.webauthn = Some(WebAuthnSettings {
            rp_id: options.webauthn.rp_id.clone(),
            rp_display_name: "Apron",
            rp_origins: options.webauthn.origins.clone(),
        });
    }
    for id in &options.apple.app_ids {
        if !valid_apple_app_id(id) {
            return Err(format!(
                "invalid --apple.app-id {}: use <team ID>.<bundle ID>, such as ABCDE12345.chat.apron",
                rust_stdlib::strconv::quote(id)
            ));
        }
    }
    config.apple_app_ids = options.apple.app_ids.clone();
    config.unfurl = options.unfurl.enable;
    config.guest_posting = options.guest.posting;
    config.server = server_metadata(options)?;
    config.retention = parse_retention(&options.history.retention)?;
    let f = &options.frame;
    config.frame = FrameLimits {
        max_bytes: positive("frame.max-bytes", f.max_bytes)?,
        max_text_bytes: positive("frame.max-text-bytes", f.max_text_bytes)?,
        max_depth: positive("frame.max-depth", f.max_depth)?,
        max_nodes: positive("frame.max-nodes", f.max_nodes)?,
        max_id_bytes: positive("frame.max-id-bytes", f.max_id_bytes)?,
    };
    let l = &options.limit;
    config.limits = crate::server::limits::Limits {
        connections_per_ip: nonnegative("limit.connections-per-ip", l.connections_per_ip)?,
        guest_connections_per_ip: nonnegative(
            "limit.guest-connections-per-ip",
            l.guest_connections_per_ip,
        )?,
        connections_per_user: nonnegative("limit.connections-per-user", l.connections_per_user)?,
        admissions_per_ip_minute: rate(
            "limit.admissions-per-ip-minute",
            l.admissions_per_ip_minute,
        )?,
        auth_attempts_per_ip_minute: rate(
            "limit.auth-attempts-per-ip-minute",
            l.auth_attempts_per_ip_minute,
        )?,
        guest_posts: posts(
            "guest-posts",
            l.guest_posts_per_minute,
            l.guest_posts_per_day,
        )?,
        posts: posts("posts", l.posts_per_minute, l.posts_per_day)?,
        trusted_posts: posts(
            "trusted-posts",
            l.trusted_posts_per_minute,
            l.trusted_posts_per_day,
        )?,
        ip_posts: posts("ip-posts", l.ip_posts_per_minute, l.ip_posts_per_day)?,
        server_posts: posts(
            "server-posts",
            l.server_posts_per_minute,
            l.server_posts_per_day,
        )?,
        room_lists_per_user_minute: rate("limit.room-lists-per-minute", l.room_lists_per_minute)?,
        uploads_per_user_day: rate("limit.uploads-per-user-day", l.uploads_per_user_day)?,
        uploads_per_day: rate("limit.uploads-per-day", l.uploads_per_day)?,
        frames_per_connection_minute: nonnegative(
            "limit.frames-per-connection-minute",
            l.frames_per_connection_minute,
        )?,
        frames_per_ip_minute: rate("limit.frames-per-ip-minute", l.frames_per_ip_minute)?,
        server_frames_per_minute: rate(
            "limit.server-frames-per-minute",
            l.server_frames_per_minute,
        )?,
        policy_violations: nonnegative("limit.policy-violations", l.policy_violations)?,
        status_coalesce: seconds_to_60("limit.status-coalesce-seconds", l.status_coalesce_seconds)?,
        offline_grace: seconds_to_60("limit.offline-grace-seconds", l.offline_grace_seconds)?,
        user_history: history_rate("", l.history_per_minute, l.history_burst)?,
        ip_history: history_rate("ip-", l.ip_history_per_minute, l.ip_history_burst)?,
        user_history_day: rate("limit.history-per-day", l.history_per_day)?,
        ip_history_day: rate("limit.ip-history-per-day", l.ip_history_per_day)?,
        server_history_day: rate("limit.server-history-per-day", l.server_history_per_day)?,
        registrations_per_ip_day: rate(
            "limit.registrations-per-ip-day",
            l.registrations_per_ip_day,
        )?,
        registrations_per_day: rate("limit.registrations-per-day", l.registrations_per_day)?,
        identities: nonnegative("limit.identities", l.identities)?,
    };
    Ok(config)
}

/// Reads `--server.title`, `--server.description` and `--server.avatar`,
/// each trimmed; empty leaves the field out.
fn server_metadata(options: &Options) -> Result<crate::server::metadata::ServerMetadata, String> {
    use crate::server::metadata::*;
    let o = &options.server;
    let (title, description, avatar) = (o.title.trim(), o.description.trim(), o.avatar.trim());
    if !valid_server_title(title) {
        return Err(format!(
            "invalid --server.title {}: use one line of at most {} characters",
            rust_stdlib::strconv::quote(title),
            crate::server::users::MAX_NAME_RUNES
        ));
    }
    if !valid_server_description(description) {
        return Err(format!(
            "invalid --server.description: use at most {MAX_SERVER_DESCRIPTION_BYTES} bytes of text"
        ));
    }
    if !avatar.is_empty() && !valid_server_avatar(avatar) {
        return Err("invalid --server.avatar: use an https: URL or a small data:image/{png,jpeg,gif,webp};base64, URL".to_string());
    }
    Ok(ServerMetadata {
        title: title.to_owned(),
        description: description.to_owned(),
        avatar: avatar.to_owned(),
    })
}

/// Reads `--history.retention`: empty or zero keeps history forever.
fn parse_retention(value: &str) -> Result<Option<Duration>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    let invalid = || {
        format!(
            "invalid --history.retention {}: use a positive duration, such as 168h",
            rust_stdlib::strconv::quote(value)
        )
    };
    let retention: Duration = value.parse().map_err(|_| invalid())?;
    match retention.as_nanos() {
        0 => Ok(None),
        n if n < 0 => Err(invalid()),
        _ => Ok(Some(retention)),
    }
}

/// `--push.delay`: a duration from 0 to MAX_PUSH_DELAY; empty is 0.
fn parse_push_delay(value: &str) -> Result<Duration, String> {
    if value.is_empty() {
        return Ok(Duration::from_secs(0));
    }
    let max = crate::server::wake::MAX_PUSH_DELAY;
    match value.parse::<Duration>() {
        Ok(delay) if delay.as_nanos() >= 0 && delay <= max => Ok(delay),
        _ => Err(format!(
            "invalid --push.delay {}: use a duration from 0 to 60s, such as 30s",
            rust_stdlib::strconv::quote(value)
        )),
    }
}

/// Apple's application identifier: a ten-character team ID, a dot, and a
/// bundle ID of letters, digits, hyphens, and dots.
fn valid_apple_app_id(id: &str) -> bool {
    let Some((team, bundle)) = id.split_once('.') else {
        return false;
    };
    team.len() == 10
        && team
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        && !bundle.is_empty()
        && bundle
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// The SHA-256 of the admin token: the contents of `path`, or else of
/// `$APRON_ADMIN_TOKEN`, without surrounding whitespace. The token itself
/// never enters the options, so `--print-config` cannot show it.
fn admin_token(path: &str) -> Result<Option<[u8; 32]>, String> {
    let token = if path.is_empty() {
        std::env::var("APRON_ADMIN_TOKEN").unwrap_or_default()
    } else {
        let bytes = rust_stdlib::os::read_file(path)
            .map_err(|e| format!("Failed to read --admin-token-file: {e}"))?;
        String::from_utf8(bytes).map_err(|_| "--admin-token-file is not UTF-8 text".to_string())?
    };
    let token = token.trim();
    if token.is_empty() {
        return Ok(None);
    }
    if token.len() < MIN_ADMIN_TOKEN_BYTES {
        return Err(format!(
            "The admin token is shorter than {MIN_ADMIN_TOKEN_BYTES} bytes; use a long random one"
        ));
    }
    Ok(Some(rust_stdlib_crypto::sha256::sum256(token.as_bytes())))
}

const MIN_ADMIN_TOKEN_BYTES: usize = 16;
