//! Reaction entries (§4.7): emoji sequences, stored fully qualified and
//! compared without U+FE0F, and custom emoji keys (EXTENSIONS.md,
//! `ext:emoji`), as apron-server-cloudflare's emoji.ts treats them.

use std::collections::HashMap;
use std::sync::LazyLock;

const VS16: char = '\u{FE0F}';

/// The fully-qualified emoji sequences that hold U+FE0F, by their form
/// without it. tools/emoji/generate.mjs writes the table from Unicode's
/// emoji-test.txt.
static QUALIFIED: LazyLock<HashMap<String, &'static str>> = LazyLock::new(|| {
    include_str!("emoji_qualified.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .map(|sequence| (emoji_identity(sequence), sequence))
        .collect()
});

/// Whether a reaction entry is a custom emoji key: `:`, a name of
/// `[A-Za-z0-9_+-]`, and `:`. Keys are case-sensitive.
pub fn is_emoji_key(entry: &str) -> bool {
    entry
        .strip_prefix(':')
        .and_then(|rest| rest.strip_suffix(':'))
        .is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_+-".contains(&b))
        })
}

/// What two entries that differ only in U+FE0F share: the entry without it.
pub fn emoji_identity(entry: &str) -> String {
    entry.chars().filter(|&c| c != VS16).collect()
}

/// An emoji sequence in its fully-qualified form (emoji-test.txt), such as
/// ❤ as ❤️ or 🏳‍🌈 as 🏳️‍🌈. Anything else, a key or text that is no
/// emoji sequence the table knows, is kept as written.
pub fn qualify_emoji(entry: &str) -> String {
    match QUALIFIED.get(&emoji_identity(entry)) {
        Some(qualified) => (*qualified).to_owned(),
        None => entry.to_owned(),
    }
}

/// A reaction entry as the server stores it: a key as written, an emoji
/// sequence fully qualified.
pub fn stored_entry(entry: &str) -> String {
    if is_emoji_key(entry) {
        entry.to_owned()
    } else {
        qualify_emoji(entry)
    }
}

/// Stores each entry of a set and collapses the ones with the same
/// identity, keeping the first.
pub fn normalize_entries(entries: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    entries
        .into_iter()
        .map(|entry| stored_entry(&entry))
        .filter(|entry| seen.insert(emoji_identity(entry)))
        .collect()
}

/// Whether two reaction sets hold the same entries, comparing without
/// U+FE0F.
pub fn same_entries(a: &[String], b: &[String]) -> bool {
    let identities = |set: &[String]| {
        set.iter()
            .map(|entry| emoji_identity(entry))
            .collect::<std::collections::BTreeSet<_>>()
    };
    a.len() == b.len() && identities(a) == identities(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// apron-server-cloudflare's test/emoji.test.ts.
    #[test]
    fn test_stores_emoji_sequences_fully_qualified() {
        assert_eq!(qualify_emoji("\u{2764}"), "\u{2764}\u{FE0F}");
        assert_eq!(qualify_emoji("\u{263A}"), "\u{263A}\u{FE0F}");
        // Keycaps take it before the combining keycap.
        assert_eq!(qualify_emoji("#\u{20E3}"), "#\u{FE0F}\u{20E3}");
        // Each part of a ZWJ sequence that needs it.
        assert_eq!(
            qualify_emoji("\u{1F3F3}\u{200D}\u{1F308}"),
            "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}"
        );
        assert_eq!(
            qualify_emoji("\u{1F441}\u{200D}\u{1F5E8}"),
            "\u{1F441}\u{FE0F}\u{200D}\u{1F5E8}\u{FE0F}"
        );
        assert_eq!(
            qualify_emoji("\u{2764}\u{200D}\u{1F525}"),
            "\u{2764}\u{FE0F}\u{200D}\u{1F525}"
        );
        for entry in ["❤️", "👍", "👍🏽", "🏳️‍🌈", "👨‍👩‍👧", "☝🏽"]
        {
            assert_eq!(qualify_emoji(entry), entry, "kept");
        }
        for entry in ["x", "hello", "👍👍", ":party:", "1"] {
            assert_eq!(qualify_emoji(entry), entry, "not an emoji sequence");
        }
    }

    #[test]
    fn test_compares_entries_without_vs16() {
        assert_eq!(emoji_identity("❤️"), emoji_identity("❤"));
        assert_eq!(emoji_identity("🏳️‍🌈"), "\u{1F3F3}\u{200D}\u{1F308}");
        assert!(same_entries(
            &["❤".into(), "👍".into()],
            &["👍".into(), "❤️".into()]
        ));
        assert!(!same_entries(&["❤".into()], &["👍".into()]));
    }

    #[test]
    fn test_tells_keys_from_sequences() {
        for key in [":partyparrot:", ":+1:", ":a_b-c:", ":Ship_It:"] {
            assert!(is_emoji_key(key), "{key}");
        }
        for entry in [
            "👍",
            "partyparrot",
            ":party parrot:",
            "::",
            ":party",
            ":pärty:",
            ":a::b:",
        ] {
            assert!(!is_emoji_key(entry), "{entry}");
        }
    }

    #[test]
    fn test_normalizes_a_set() {
        let set = ["\u{2764}", "\u{2764}\u{FE0F}", "🏳\u{200D}🌈", "👍🏽", ":k:"];
        assert_eq!(
            normalize_entries(set.map(String::from)),
            ["\u{2764}\u{FE0F}", "🏳️‍🌈", "👍🏽", ":k:"]
        );
    }
}
