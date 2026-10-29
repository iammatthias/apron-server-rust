//! The bearer tokens kept by the SHA-256 of the token, with an index by
//! the user each is held by: device, invite and bot tokens, and sessions.

use std::collections::BTreeMap;

use super::remap::{Fate, Remap};
use super::webauthn::SessionKey;

/// A token held by one user.
pub trait Held {
    /// Whether a holder has one token at most: a new one takes the index
    /// from the last, which its owner removes.
    const ONE_PER_HOLDER: bool;
    fn holder(&self) -> &str;
    fn set_holder(&mut self, to: &str);
}

/// Tokens by key, and each holder's keys oldest first.
pub struct TokenTable<T> {
    by_key: BTreeMap<SessionKey, T>,
    by_holder: BTreeMap<String, Vec<SessionKey>>,
}

impl<T> Default for TokenTable<T> {
    fn default() -> Self {
        TokenTable {
            by_key: BTreeMap::new(),
            by_holder: BTreeMap::new(),
        }
    }
}

impl<T: Held> TokenTable<T> {
    pub fn get(&self, key: &SessionKey) -> Option<&T> {
        self.by_key.get(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &SessionKey> {
        self.by_key.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&SessionKey, &T)> {
        self.by_key.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// Adds a token after its holder's others.
    pub fn insert(&mut self, key: SessionKey, token: T) {
        let held = self.by_holder.entry(token.holder().to_owned()).or_default();
        if T::ONE_PER_HOLDER {
            held.clear();
        }
        held.push(key);
        self.by_key.insert(key, token);
    }

    pub fn remove(&mut self, key: &SessionKey) -> Option<T> {
        let token = self.by_key.remove(key)?;
        if let Some(held) = self.by_holder.get_mut(token.holder()) {
            held.retain(|k| k != key);
            if held.is_empty() {
                self.by_holder.remove(token.holder());
            }
        }
        Some(token)
    }

    /// The holder's tokens, oldest first.
    pub fn of<'a>(&'a self, holder: &str) -> impl Iterator<Item = (SessionKey, &'a T)> + 'a {
        self.by_holder
            .get(holder)
            .into_iter()
            .flatten()
            .map(|key| (*key, &self.by_key[key]))
    }

    /// The key of the holder's newest token.
    pub fn last_of(&self, holder: &str) -> Option<SessionKey> {
        self.by_holder
            .get(holder)
            .and_then(|held| held.last())
            .copied()
    }

    /// Removes the tokens of the holders `remap` drops, or moves the renamed
    /// holder's, and returns their keys.
    pub(super) fn remap_holders(&mut self, remap: &Remap) -> Vec<SessionKey> {
        let mut changed = Vec::new();
        for from in remap.sources() {
            let keys = self.by_holder.remove(from).unwrap_or_default();
            changed.extend(keys.iter().copied());
            match remap.fate(from) {
                Fate::Rename(to) if !keys.is_empty() => {
                    for key in &keys {
                        if let Some(token) = self.by_key.get_mut(key) {
                            token.set_holder(to);
                        }
                    }
                    self.by_holder.insert(to.to_owned(), keys);
                }
                _ => {
                    for key in &keys {
                        self.by_key.remove(key);
                    }
                }
            }
        }
        changed
    }

    /// Removes the tokens of every holder `remap` names, dropped or renamed,
    /// and returns their keys.
    pub(super) fn remove_holders(&mut self, remap: &Remap) -> Vec<SessionKey> {
        let keys: Vec<SessionKey> = remap
            .sources()
            .into_iter()
            .flat_map(|holder| self.of(holder).map(|(key, _)| key).collect::<Vec<_>>())
            .collect();
        for key in &keys {
            self.remove(key);
        }
        keys
    }

    /// Mutable access to a token; its holder must not change.
    pub fn get_mut(&mut self, key: &SessionKey) -> Option<&mut T> {
        self.by_key.get_mut(key)
    }
}
