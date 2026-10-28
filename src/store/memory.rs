use std::collections::BTreeMap;
use std::sync::Mutex;

use super::{Entry, Store, StoreError};

/// Keeps entries in this process only. A server started again with the same
/// `Memory` resumes its state, which tests use; a new `Memory` is empty.
#[derive(Default)]
pub struct Memory {
    entries: Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>>,
}

impl Memory {
    pub fn new() -> Memory {
        Memory::default()
    }
}

impl Store for Memory {
    fn load(
        &self,
        visit: &mut dyn FnMut(Entry) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let all: Vec<Entry> = {
            let entries = self.entries.lock().unwrap();
            entries
                .iter()
                .flat_map(|(kind, entries)| {
                    entries
                        .iter()
                        .map(move |(id, value)| Entry::put(kind, id, value.clone()))
                })
                .collect()
        };
        for entry in all {
            visit(entry)?;
        }
        Ok(())
    }

    fn apply(&self, batch: &[Entry]) -> Result<(), StoreError> {
        let mut entries = self.entries.lock().unwrap();
        for entry in batch {
            match &entry.value {
                None => {
                    if let Some(kind) = entries.get_mut(&entry.kind) {
                        kind.remove(&entry.id);
                    }
                }
                Some(value) => {
                    entries
                        .entry(entry.kind.clone())
                        .or_default()
                        .insert(entry.id.clone(), value.clone());
                }
            }
        }
        Ok(())
    }

    fn close(&self) -> Result<(), StoreError> {
        Ok(())
    }
}
