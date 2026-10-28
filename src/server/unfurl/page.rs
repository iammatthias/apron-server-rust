//! Reading what a page says about itself.

use std::collections::BTreeMap;

use rust_stdlib::html;
use rust_stdlib::net::url;

const MAX_TITLE_CHARS: usize = 300;
const MAX_DESCRIPTION_CHARS: usize = 1000;

/// What a page says about itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    pub title: String,
    pub description: String,
    pub site_name: String,
    /// The og:image, resolved against the page's URL.
    pub image: String,
    pub image_alt: String,
}

/// Reads a page's OpenGraph metadata from its `<meta>` tags, with the
/// `<title>` and the meta description as fallbacks. Scripts, styles, and
/// comments are skipped; nothing runs.
pub fn parse_page(html_text: &str, base: &url::Url) -> Meta {
    let lower = html_text.to_ascii_lowercase();
    let mut meta = Meta::default();
    let (mut title, mut description) = (String::new(), String::new());
    let mut i = 0;
    while let Some(n) = lower[i..].find('<') {
        let start = i + n;
        if lower[start..].starts_with("<!--") {
            i = lower[start..]
                .find("-->")
                .map_or(lower.len(), |e| start + e + 3);
            continue;
        }
        let name_end = lower[start + 1..]
            .find(|c: char| !c.is_ascii_alphanumeric())
            .map_or(lower.len(), |e| start + 1 + e);
        let name = &lower[start + 1..name_end];
        let Some(tag_end) = tag_end(html_text, name_end) else {
            break;
        };
        i = tag_end;
        match name {
            "meta" => {
                let attrs = attributes(&html_text[name_end..tag_end]);
                let key = attrs
                    .get("property")
                    .or_else(|| attrs.get("name"))
                    .map(|k| k.to_ascii_lowercase())
                    .unwrap_or_default();
                let content = clean(attrs.get("content").map_or("", String::as_str));
                let field = match key.as_str() {
                    "og:title" => &mut meta.title,
                    "og:description" => &mut meta.description,
                    "og:site_name" => &mut meta.site_name,
                    "og:image" | "og:image:url" | "og:image:secure_url" => &mut meta.image,
                    "og:image:alt" => &mut meta.image_alt,
                    "description" => &mut description,
                    _ => continue,
                };
                if field.is_empty() {
                    *field = content;
                }
            }
            "title" if title.is_empty() => {
                let close = lower[i..].find("</title").map_or(lower.len(), |e| i + e);
                title = clean(&html_text[i..close]);
                i = close;
            }
            "script" | "style" => {
                i = lower[i..]
                    .find(&format!("</{name}"))
                    .map_or(lower.len(), |e| i + e);
            }
            _ => {}
        }
    }
    if meta.title.is_empty() {
        meta.title = title;
    }
    if meta.description.is_empty() {
        meta.description = description;
    }
    meta.title = truncate(&meta.title, MAX_TITLE_CHARS);
    meta.description = truncate(&meta.description, MAX_DESCRIPTION_CHARS);
    meta.site_name = truncate(&meta.site_name, MAX_TITLE_CHARS);
    meta.image_alt = truncate(&meta.image_alt, MAX_DESCRIPTION_CHARS);
    meta.image = Some(meta.image.as_str())
        .filter(|image| !image.is_empty())
        .and_then(|image| url::parse(image).ok())
        .map(|reference| base.resolve_reference(&reference))
        .filter(|u| matches!(u.scheme.as_str(), "http" | "https") && !u.hostname().is_empty())
        .map(|u| u.to_string())
        .unwrap_or_default();
    if meta.image.is_empty() {
        meta.image_alt.clear();
    }
    meta
}

/// The end of the tag whose attributes start at `from`: past its `>`, which
/// a quoted attribute value does not end.
fn tag_end(text: &str, from: usize) -> Option<usize> {
    let mut quote: Option<u8> = None;
    for (i, &b) in text.as_bytes()[from..].iter().enumerate() {
        match (quote, b) {
            (Some(q), _) if b == q => quote = None,
            (Some(_), _) => {}
            (None, b'"' | b'\'') => quote = Some(b),
            (None, b'>') => return Some(from + i + 1),
            _ => {}
        }
    }
    None
}

/// A tag's attributes by lowercased name, values unescaped; the first of a
/// repeated name wins.
fn attributes(tag: &str) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();
    let mut rest = tag.trim_end_matches('>').trim_end_matches('/');
    loop {
        rest = rest.trim_start_matches(|c: char| c.is_whitespace() || c == '/');
        if rest.is_empty() {
            return attrs;
        }
        let name_end = rest
            .find(|c: char| c.is_whitespace() || c == '=' || c == '/')
            .unwrap_or(rest.len());
        let name = rest[..name_end].to_ascii_lowercase();
        rest = rest[name_end..].trim_start();
        let mut value = String::new();
        if let Some(after) = rest.strip_prefix('=') {
            let after = after.trim_start();
            let (raw, remaining) = match after.chars().next() {
                Some(q @ ('"' | '\'')) => {
                    let body = &after[1..];
                    let end = body.find(q).unwrap_or(body.len());
                    (&body[..end], body.get(end + 1..).unwrap_or(""))
                }
                _ => {
                    let end = after.find(char::is_whitespace).unwrap_or(after.len());
                    (&after[..end], &after[end..])
                }
            };
            value = html::unescape(raw);
            rest = remaining;
        }
        attrs.entry(name).or_insert(value);
    }
}

/// Unescapes text and collapses its whitespace.
fn clean(text: &str) -> String {
    html::unescape(text)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn truncate(text: &str, chars: usize) -> String {
    match text.char_indices().nth(chars) {
        Some((end, _)) => text[..end].to_owned(),
        None => text.to_owned(),
    }
}
