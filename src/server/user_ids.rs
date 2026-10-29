//! Display names and user_ids: preparing a requested name, which user_ids a
//! client may request, and the user_ids the server issues (§3.3).

use rust_stdlib::encoding::base64::URL_SAFE_NO_PAD;
use rust_stdlib::regexp::Regexp;
use rust_stdlib::unicode;
use rust_stdlib_crypto::rand;

use super::users::MAX_NAME_RUNES;

/// Prepares a requested display name with the PRECIS Nickname profile (RFC
/// 8266): it maps compatibility characters, folds runs of spaces, and
/// trims. Invisible characters, such as controls and bidirectional
/// overrides, are dropped first rather than refused, and a name that still
/// cannot be a nickname becomes empty. The result is capped at
/// MAX_NAME_RUNES. The server may alter names (§3.3) and `you.name` is the
/// answer.
///
/// rust-stdlib has no Unicode normalization (Go's is golang.org/x/text), so
/// NFKC and the FreeformClass check are not applied; see docs/DEVIATIONS.md.
pub fn normalize_name(name: &str) -> String {
    let kept: String = name
        .chars()
        .filter(|&r| {
            !unicode::in_(
                r as i32,
                &[unicode::CC, unicode::CF, unicode::CO, unicode::CS],
            )
        })
        .collect();
    // RFC 8266 §2.1 rule 2: non-ASCII spaces become SPACE, interior runs
    // of spaces collapse to one, and leading and trailing spaces go.
    let mut out = String::new();
    let mut prev_space = false;
    for r in kept.chars() {
        if unicode::is(unicode::ZS, r as i32) {
            prev_space = true;
            continue;
        }
        if prev_space && !out.is_empty() {
            out.push(' ');
        }
        out.push(r);
        prev_space = false;
    }
    if out.chars().count() > MAX_NAME_RUNES {
        out = out
            .chars()
            .take(MAX_NAME_RUNES)
            .collect::<String>()
            .trim()
            .to_owned();
    }
    out
}

/// The shape of a user_id a new email account may request: the suggested convention for
/// user-chosen IDs (Appendix A.3), letters, digits, _, ., and -, starting
/// with a letter, and ending with a letter, digit, or _.
fn requestable_user_id() -> Regexp {
    Regexp::new(r"^[A-Za-z](?:[A-Za-z0-9_.-]{0,62}[A-Za-z0-9_])?$").expect("constant pattern")
}

/// Starts every counter-assigned guest ID. The guest_ namespace, ignoring
/// case, belongs to the counter.
pub const GUEST_ID_PREFIX: &str = "guest_";

/// Reports whether a user may request `id`: it has the requestable shape and
/// lies outside the counters' guest_ and user_ namespaces and the bots'
/// bot_ one (an extension; docs/DEVIATIONS.md).
pub fn requestable(id: &str) -> bool {
    for prefix in [
        GUEST_ID_PREFIX,
        super::email::ACCOUNT_ID_PREFIX,
        super::bots::BOT_ID_PREFIX,
    ] {
        if id.len() >= prefix.len() && id[..prefix.len()].eq_ignore_ascii_case(prefix) {
            return false;
        }
    }
    requestable_user_id().match_string(id)
}

/// The longest name part of a user_id picked from a requested name.
const USER_ID_SLUG_BYTES: usize = 16;
/// The tries at a `<slug>_<4 digits>` user_id before a random one.
pub const USER_ID_SLUG_ATTEMPTS: usize = 8;

/// apron-server-cloudflare's `userIdSlug`: the user_id part a requested
/// name suggests, lowercase ASCII letters and digits with other runs as one
/// `_`, at most 16 characters. Empty when nothing usable is left or when it
/// would pass for a counter's or a bot's user_id. Without NFKD, an accented
/// letter is a run of other characters (docs/DEVIATIONS.md).
pub fn user_id_slug(name: &str) -> String {
    let mut slug = String::new();
    let mut gap = false;
    for ch in name.to_lowercase().chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            if gap && !slug.is_empty() {
                slug.push('_');
            }
            gap = false;
            slug.push(ch);
        } else {
            gap = true;
        }
    }
    slug.truncate(USER_ID_SLUG_BYTES);
    let slug = slug.trim_end_matches('_');
    let reserved = [
        GUEST_ID_PREFIX,
        super::email::ACCOUNT_ID_PREFIX,
        super::bots::BOT_ID_PREFIX,
    ]
    .iter()
    .any(|prefix| slug.starts_with(prefix) || slug == prefix.trim_end_matches('_'));
    if reserved {
        return String::new();
    }
    slug.to_owned()
}

/// apron-server-cloudflare's `candidateUserIdFor`: a new account's user_id,
/// `<slug>_<4 random digits>` for a name with a slug, tried
/// USER_ID_SLUG_ATTEMPTS times while `taken`, else `u_` and 16 random bytes
/// as unpadded base64url.
pub fn candidate_user_id(name: &str, mut taken: impl FnMut(&str) -> bool) -> String {
    let slug = user_id_slug(name);
    if !slug.is_empty() {
        for _ in 0..USER_ID_SLUG_ATTEMPTS {
            let id = format!("{slug}_{}", random_digits::<4>());
            if !taken(&id) {
                return id;
            }
        }
    }
    let mut raw = [0u8; 16];
    rand::read(&mut raw);
    format!("u_{}", URL_SAFE_NO_PAD.encode(raw))
}

/// N decimal digits, each a random u32 modulo 10, as Cloudflare draws them.
fn random_digits<const N: usize>() -> String {
    let mut raw = [[0u8; 4]; N];
    for word in &mut raw {
        rand::read(word);
    }
    raw.iter()
        .map(|word| char::from(b'0' + (u32::from_le_bytes(*word) % 10) as u8))
        .collect()
}
