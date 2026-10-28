//! Persists the server's state as entries: opaque values keyed by a kind and
//! an ID. The server decides what each kind holds; a backend only needs to
//! keep entries and apply batches of changes atomically.

mod memory;
mod sqlite;

use std::error::Error;
use std::fmt;
use std::sync::Arc;

pub use memory::Memory;
pub use sqlite::SQLite;

/// One stored value. A `None` value in a batch deletes the entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: String,
    pub id: String,
    pub value: Option<Vec<u8>>,
}

impl Entry {
    pub fn put(kind: &str, id: &str, value: impl Into<Vec<u8>>) -> Entry {
        Entry {
            kind: kind.into(),
            id: id.into(),
            value: Some(value.into()),
        }
    }

    pub fn delete(kind: &str, id: &str) -> Entry {
        Entry {
            kind: kind.into(),
            id: id.into(),
            value: None,
        }
    }
}

pub type StoreError = Box<dyn Error + Send + Sync>;

/// Keeps entries across restarts.
pub trait Store: Send + Sync {
    /// Calls `visit` for every stored entry, in no particular order.
    fn load(
        &self,
        visit: &mut dyn FnMut(Entry) -> Result<(), StoreError>,
    ) -> Result<(), StoreError>;
    /// Writes a batch of puts and deletes atomically.
    fn apply(&self, batch: &[Entry]) -> Result<(), StoreError>;
    /// Releases the store; it must not be used afterwards.
    fn close(&self) -> Result<(), StoreError>;
}

#[derive(Debug)]
struct OpenError(String);

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for OpenError {}

/// Opens a store named by a URL-like string:
///
/// ```text
/// memory             entries kept only in this process
/// sqlite:<path>      a SQLite database file, created if missing
/// ```
pub fn open(name: &str) -> Result<Arc<dyn Store>, StoreError> {
    let (scheme, path) = name.split_once(':').unwrap_or((name, ""));
    match scheme {
        "memory" => Ok(Arc::new(Memory::new())),
        "sqlite" => {
            if path.is_empty() {
                return Err(Box::new(OpenError(
                    "sqlite store needs a path, such as sqlite:aprond.db".into(),
                )));
            }
            Ok(Arc::new(SQLite::open(
                path.strip_prefix("//").unwrap_or(path),
            )?))
        }
        _ => Err(Box::new(OpenError(format!(
            "unknown store {name:?}; use memory or sqlite:<path>"
        )))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn load(s: &dyn Store) -> BTreeMap<String, String> {
        let mut got = BTreeMap::new();
        s.load(&mut |e| {
            got.insert(
                format!("{}/{}", e.kind, e.id),
                String::from_utf8(e.value.unwrap_or_default()).unwrap(),
            );
            Ok(())
        })
        .unwrap();
        got
    }

    /// A database that cannot be opened fails as Go's lazy database/sql
    /// open does, at the schema, with modernc's message and code.
    #[test]
    fn test_sqlite_open_errors_are_gos() {
        let dir = rust_stdlib::os::mkdir_temp("", "apron-store-errors-").unwrap();
        let not_a_database = format!("{dir}/bad.db");
        std::fs::write(&not_a_database, [b'x'; 128]).unwrap();
        let a_directory = format!("{dir}/sub");
        std::fs::create_dir(&a_directory).unwrap();
        for (path, want) in [
            (&not_a_database, "file is not a database (26)"),
            (&a_directory, "unable to open database file (14)"),
        ] {
            let err = open(&format!("sqlite:{path}")).err().unwrap();
            assert_eq!(
                err.to_string(),
                format!("creating the schema in {path}: {want}")
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every backend keeps, replaces, and deletes entries, and a batch
    /// applies as a whole.
    #[test]
    fn test_backends() {
        let dir = std::env::temp_dir().join(format!("apron-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("sub").join("aprond.db");
        let path = path.to_str().unwrap().to_owned();
        type Open<'a> = Box<dyn Fn() -> Arc<dyn Store> + 'a>;
        let backends: Vec<(&str, Open)> = vec![
            ("memory", Box::new(|| Arc::new(Memory::new()))),
            (
                "sqlite",
                Box::new(|| open(&format!("sqlite:{path}")).unwrap()),
            ),
        ];
        for (name, open_store) in backends {
            let mut s = open_store();
            s.apply(&[
                Entry::put("room", "general", r#"{"title":"General"}"#),
                Entry::put("record", "1", "{}"),
                Entry::put("record", "2", "{}"),
            ])
            .unwrap();
            s.apply(&[
                Entry::put("room", "general", r#"{"title":"Ops"}"#),
                Entry::delete("record", "1"),
            ])
            .unwrap();
            let want: BTreeMap<String, String> = [
                ("room/general".to_owned(), r#"{"title":"Ops"}"#.to_owned()),
                ("record/2".to_owned(), "{}".to_owned()),
            ]
            .into_iter()
            .collect();
            assert_eq!(load(s.as_ref()), want, "{name} entries");
            if name == "sqlite" {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "database file mode");
                // A reopened database keeps its entries.
                s.close().unwrap();
                s = open_store();
                assert_eq!(load(s.as_ref()), want, "reopened entries");
            }
            s.close().unwrap();
        }
        assert!(
            open("postgres://x").is_err(),
            "unknown store scheme accepted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
