//! The unfurl results kept in memory.

use std::collections::BTreeMap;
use std::sync::Arc;

use rust_stdlib::time::{Duration, Time};

use super::fetch::Preview;

pub const CACHE_TTL: Duration = Duration::from_hours(1);
/// How long a page that gave no preview is not fetched again.
pub const FAILURE_TTL: Duration = Duration::from_mins(5);
pub const MAX_CACHED: usize = 256;
/// Bounds the image bytes the cache holds.
pub const MAX_CACHED_BYTES: usize = 32 << 20;

/// What unfurling a URL gave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unfurled {
    Preview(Arc<Preview>),
    Nothing,
}

impl Unfurled {
    fn image_bytes(&self) -> usize {
        match self {
            Unfurled::Preview(preview) => preview.image.as_ref().map_or(0, |i| i.bytes.len()),
            Unfurled::Nothing => 0,
        }
    }
}

struct Cached {
    unfurled: Unfurled,
    expires: Time,
}

/// Unfurl results by URL: a preview for CACHE_TTL, a failure for
/// FAILURE_TTL. Beyond MAX_CACHED entries or MAX_CACHED_BYTES of images, the
/// entries closest to expiring go first.
#[derive(Default)]
pub struct Cache {
    entries: BTreeMap<String, Cached>,
    bytes: usize,
}

impl Cache {
    pub fn get(&self, target: &str, now: &Time) -> Option<Unfurled> {
        self.entries
            .get(target)
            .filter(|c| now.before(&c.expires))
            .map(|c| c.unfurled.clone())
    }

    pub fn insert(&mut self, target: &str, unfurled: Unfurled, now: &Time) {
        let ttl = match unfurled {
            Unfurled::Preview(_) => CACHE_TTL,
            Unfurled::Nothing => FAILURE_TTL,
        };
        let size = unfurled.image_bytes();
        if size > MAX_CACHED_BYTES {
            return;
        }
        let entry = Cached {
            unfurled,
            expires: now.add(ttl),
        };
        self.bytes += size;
        if let Some(old) = self.entries.insert(target.to_owned(), entry) {
            self.bytes -= old.unfurled.image_bytes();
        }
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, c)| !now.before(&c.expires))
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            self.remove(&key);
        }
        while self.entries.len() > MAX_CACHED || self.bytes > MAX_CACHED_BYTES {
            let Some(first) = self
                .entries
                .iter()
                .min_by(|a, b| a.1.expires.compare(&b.1.expires).cmp(&0))
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.remove(&first);
        }
    }

    fn remove(&mut self, target: &str) {
        if let Some(old) = self.entries.remove(target) {
            self.bytes -= old.unfurled.image_bytes();
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }
}
