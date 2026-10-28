//! Finding the URLs of a message's text.

use std::collections::HashSet;

use rust_stdlib::net::url;

use crate::server::embeds::MAX_EMBEDS_PER_MESSAGE;
use crate::server::protocol::*;

/// The part of a message's text searched for URLs.
pub const MAX_SCANNED_BYTES: usize = 8 << 10;

/// The http(s) URLs in the first MAX_SCANNED_BYTES of a message body's
/// text, in order, without repeats, and at most MAX_EMBEDS_PER_MESSAGE of
/// them. In markdown, URLs in code spans and fenced code blocks are skipped.
pub fn message_urls(body: Option<&Object>) -> Vec<String> {
    let (text, markdown) = text_of(body);
    let mut end = text.len().min(MAX_SCANNED_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let text = &text[..end];
    if markdown {
        scan_urls(&without_code(text), MAX_EMBEDS_PER_MESSAGE)
    } else {
        scan_urls(text, MAX_EMBEDS_PER_MESSAGE)
    }
}

/// A body's text, and whether it is markdown.
pub(super) fn text_of(body: Option<&Object>) -> (&str, bool) {
    let field = |name: &str| body.and_then(|b| b.get(name)).and_then(Json::as_str);
    (
        field("text").unwrap_or(""),
        field("format") == Some("markdown"),
    )
}

/// Replaces markdown code (fenced blocks and code spans) with spaces.
fn without_code(text: &str) -> String {
    let mut prose = String::with_capacity(text.len());
    // The fence character and length of the open fenced block.
    let mut fence: Option<(char, usize)> = None;
    for line in text.split_inclusive('\n') {
        let indent = line.len() - line.trim_start_matches(' ').len();
        let rest = &line[indent..];
        let marker = rest.chars().next().filter(|c| *c == '`' || *c == '~');
        let run = marker.map_or(0, |m| rest.len() - rest.trim_start_matches(m).len());
        match (fence, marker) {
            (None, Some(m)) if indent < 4 && run >= 3 => fence = Some((m, run)),
            (Some((open, length)), Some(m))
                if indent < 4 && m == open && run >= length && rest[run..].trim().is_empty() =>
            {
                fence = None
            }
            (None, _) => {
                prose.push_str(line);
                continue;
            }
            _ => {}
        }
        prose.push('\n');
    }
    without_code_spans(&prose)
}

/// A backtick run opens a code span that the next run of the same length
/// closes; a run that is never closed is literal text.
fn without_code_spans(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'`' {
            let next = text[i..].find('`').map_or(bytes.len(), |n| i + n);
            out.push_str(&text[i..next]);
            i = next;
            continue;
        }
        let run = text[i..].len() - text[i..].trim_start_matches('`').len();
        let mut close = None;
        let mut j = i + run;
        while let Some(n) = text[j..].find('`') {
            let start = j + n;
            let length = text[start..].len() - text[start..].trim_start_matches('`').len();
            if length == run {
                close = Some(start + length);
                break;
            }
            j = start + length;
        }
        match close {
            Some(end) => {
                out.push(' ');
                i = end;
            }
            None => {
                out.push_str(&text[i..i + run]);
                i += run;
            }
        }
    }
    out
}

/// Finds the first `limit` distinct http(s) URLs in text. A URL starts at
/// a word boundary and ends at whitespace or a delimiter; trailing
/// punctuation, and a closing bracket it did not open, are left out.
fn scan_urls(text: &str, limit: usize) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut urls = Vec::new();
    let mut seen = HashSet::new();
    let mut from = 0;
    while urls.len() < limit {
        let Some(found) = lower[from..].find("http") else {
            break;
        };
        let start = from + found;
        let scheme = &lower[start + "http".len()..];
        if !scheme.starts_with("://") && !scheme.starts_with("s://") {
            from = start + "http".len();
            continue;
        }
        let end = text[start..]
            .find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '`'))
            .map_or(text.len(), |n| start + n);
        from = end;
        let boundary = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        if !boundary {
            continue;
        }
        let candidate = trim_url(&text[start..end]);
        let Ok(parsed) = url::parse(candidate) else {
            continue;
        };
        if matches!(parsed.scheme.as_str(), "http" | "https")
            && !parsed.hostname().is_empty()
            && seen.insert(candidate)
        {
            urls.push(candidate.to_owned());
        }
    }
    urls
}

/// Drops trailing punctuation, and closing brackets beyond those opened.
fn trim_url(candidate: &str) -> &str {
    let count = |c: char| candidate.matches(c).count();
    let mut unopened = [
        count(')').saturating_sub(count('(')),
        count(']').saturating_sub(count('[')),
    ];
    let mut candidate = candidate;
    loop {
        let trimmed =
            candidate.trim_end_matches(['.', ',', ';', ':', '!', '?', '\'', '*', '_', '~']);
        let bracket = match trimmed.chars().last() {
            Some(')') => Some(0),
            Some(']') => Some(1),
            _ => None,
        };
        let trimmed = match bracket {
            Some(b) if unopened[b] > 0 => {
                unopened[b] -= 1;
                &trimmed[..trimmed.len() - 1]
            }
            _ => trimmed,
        };
        if trimmed.len() == candidate.len() {
            return candidate;
        }
        candidate = trimmed;
    }
}
