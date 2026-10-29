//! Request deduplication (§1.2): each user's accepted requests by id, and the
//! outcome their duplicates share.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};

use super::protocol::*;

pub const MAX_DEDUP_ENTRIES: usize = 1024;
/// How long an accepted request's id stays deduplicated (§1.2), in Unix
/// milliseconds: apron-server-cloudflare's 24 hours.
pub const DEDUP_WINDOW_MS: i64 = 24 * 60 * 60 * 1000;

/// The outcome shared with the duplicates of a request (§1.2).
pub struct DedupEntry {
    /// A hash of the request's method and canonical params.
    pub fingerprint: [u8; 32],
    /// When the request was accepted, in Unix milliseconds.
    pub at: i64,
    outcome: Mutex<Option<Result<Json, RpcError>>>,
    done: Condvar,
}

impl DedupEntry {
    pub fn new(fingerprint: [u8; 32]) -> DedupEntry {
        DedupEntry {
            fingerprint,
            at: rust_stdlib::time::now().unix_milli(),
            outcome: Mutex::new(None),
            done: Condvar::new(),
        }
    }

    /// An entry restored from the store, finished with its result.
    pub fn finished(fingerprint: [u8; 32], at: i64, result: Json) -> DedupEntry {
        DedupEntry {
            fingerprint,
            at,
            outcome: Mutex::new(Some(Ok(result))),
            done: Condvar::new(),
        }
    }

    /// The result of an entry that finished well, for the store.
    pub fn result(&self) -> Option<Json> {
        match &*self.outcome.lock().unwrap_or_else(|e| e.into_inner()) {
            Some(Ok(result)) => Some(result.clone()),
            _ => None,
        }
    }

    fn expired(&self, now: i64) -> bool {
        now - self.at >= DEDUP_WINDOW_MS
    }

    pub fn finish(&self, outcome: Result<Json, RpcError>) {
        *self.outcome.lock().unwrap_or_else(|e| e.into_inner()) = Some(outcome);
        self.done.notify_all();
    }

    pub fn is_closed(&self) -> bool {
        self.outcome
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Waits for the original to finish and returns its outcome.
    pub fn wait(&self) -> Result<Json, RpcError> {
        let guard = self.outcome.lock().unwrap_or_else(|e| e.into_inner());
        let guard = self
            .done
            .wait_while(guard, |outcome| outcome.is_none())
            .unwrap_or_else(|e| e.into_inner());
        guard
            .clone()
            .unwrap_or_else(|| Err(RpcError::new(CODE_INTERNAL_ERROR, "Internal error")))
    }
}

/// The request IDs one user sent within DEDUP_WINDOW_MS, the latest
/// MAX_DEDUP_ENTRIES of them, oldest first. Guarded by the state lock.
#[derive(Default)]
pub struct DedupCache {
    entries: BTreeMap<String, Arc<DedupEntry>>,
    order: VecDeque<String>,
}

impl DedupCache {
    /// The entry of an id the window still holds.
    pub fn get(&self, id: &str) -> Option<Arc<DedupEntry>> {
        let now = rust_stdlib::time::now().unix_milli();
        self.entries.get(id).filter(|e| !e.expired(now)).cloned()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &Arc<DedupEntry>)> {
        self.entries.iter()
    }

    /// Adds an entry, and returns the ids it pushed out: past the window,
    /// or past the most kept.
    pub fn put(&mut self, id: &str, entry: Arc<DedupEntry>) -> Vec<String> {
        let now = entry.at;
        self.entries.insert(id.to_owned(), entry);
        self.order.push_back(id.to_owned());
        let mut dropped = Vec::new();
        while let Some(oldest) = self.order.front() {
            let Some(e) = self.entries.get(oldest) else {
                self.order.pop_front();
                continue;
            };
            if !(self.order.len() > MAX_DEDUP_ENTRIES || e.expired(now)) || !e.is_closed() {
                break;
            }
            let oldest = self.order.pop_front().expect("front exists");
            self.entries.remove(&oldest);
            dropped.push(oldest);
        }
        dropped
    }

    pub fn remove(&mut self, id: &str, entry: &Arc<DedupEntry>) {
        if self.entries.get(id).is_some_and(|e| Arc::ptr_eq(e, entry)) {
            self.entries.remove(id);
        }
    }
}
