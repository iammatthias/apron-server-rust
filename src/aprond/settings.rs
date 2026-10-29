//! main.go's `serverConfig`, without the server types: the flag cross-checks
//! and conversions, in Go's order and with Go's messages. The core maps
//! [`Settings`] onto `server::Config`.

use super::email::SmtpSender;
use super::options::Options;
use rust_stdlib::time::Duration;
use std::collections::BTreeMap;

/// How email sign-in codes are delivered.
#[derive(Debug)]
pub enum EmailSender {
    /// `server.LogEmailSender`: codes go to the server log.
    Log,
    Smtp(SmtpSender),
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
    pub messages_per_minute: i64,
    pub max_listed_members: i64,
    pub max_private_rooms: i64,
    pub welcome: String,
    pub client_ip_header: String,
    /// Holders by lowercased role; empty is Go's nil map.
    pub roles: BTreeMap<String, Vec<String>>,
    pub disable_push: bool,
    pub allow_insecure_push: bool,
    pub vapid_private_key: String,
    pub vapid_subject: String,
    pub upload_dir: String,
    pub max_upload_bytes: i64,
    pub max_message_upload_bytes: i64,
    pub max_upload_storage_bytes: i64,
    /// `None` keeps the server's default origin patterns.
    pub origin_patterns: Option<Vec<String>>,
    pub email_sender: Option<EmailSender>,
    pub email_link_url: String,
    /// `None` disables passkeys (an empty `--webauthn.rp-id`).
    pub webauthn: Option<WebAuthnSettings>,
    /// `--apple.app-id`, an extension Go lacks.
    pub apple_app_ids: Vec<String>,
    /// `--unfurl.enable`, an extension Go lacks.
    pub unfurl: bool,
    /// `--guest.posting`, an extension Go lacks.
    pub guest_posting: bool,
    /// `--history.retention`, an extension Go lacks; `None` keeps history.
    pub retention: Option<Duration>,
    /// The `--frame.*` bounds, an extension Go lacks.
    pub frame: FrameSettings,
}

/// The `--frame.*` bounds, each positive.
#[derive(Debug, Default)]
pub struct FrameSettings {
    pub max_bytes: usize,
    pub max_text_bytes: usize,
    pub max_depth: usize,
    pub max_nodes: usize,
    pub max_id_bytes: usize,
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
    config.messages_per_minute = options.messages_per_minute;
    config.max_listed_members = options.max_listed_members;
    config.max_private_rooms = options.max_private_rooms;
    config.welcome = options.welcome.clone();
    config.client_ip_header = options.client_ip_header.clone();
    for grant in &options.roles {
        let (role, holder, ok) = match grant.split_once('=') {
            Some((role, holder)) => (role, holder, true),
            None => (grant.as_str(), "", false),
        };
        let (role, holder) = (role.trim().to_lowercase(), holder.trim());
        if !ok || role.is_empty() || holder.is_empty() {
            return Err(format!(
                "invalid --role {}: use role=user_id, such as admin=ada",
                rust_stdlib::strconv::quote(grant)
            ));
        }
        config
            .roles
            .entry(role)
            .or_default()
            .push(holder.to_string());
    }
    config.disable_push = options.push.disable;
    let public = !options.public_url.is_empty() || !options.tls.domains.is_empty();
    if options.push.allow_insecure && public {
        return Err("--push.allow-insecure lets any client make the server POST to http and internal addresses; it is for tests and refused with --public-url or --tls.domain".to_string());
    }
    config.allow_insecure_push = options.push.allow_insecure;
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
    config.retention = parse_retention(&options.history.retention)?;
    let f = &options.frame;
    config.frame = FrameSettings {
        max_bytes: positive("frame.max-bytes", f.max_bytes)?,
        max_text_bytes: positive("frame.max-text-bytes", f.max_text_bytes)?,
        max_depth: positive("frame.max-depth", f.max_depth)?,
        max_nodes: positive("frame.max-nodes", f.max_nodes)?,
        max_id_bytes: positive("frame.max-id-bytes", f.max_id_bytes)?,
    };
    Ok(config)
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
