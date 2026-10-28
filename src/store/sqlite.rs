use std::sync::Mutex;

use rusqlite::{params, Connection, OpenFlags};

use super::{Entry, Store, StoreError};

/// Keeps entries in one table of a SQLite database, in WAL mode so reads do
/// not block the single writer. The schema and pragmas are the Go server's,
/// so a database either server created opens in the other.
pub struct SQLite {
    db: Mutex<Option<Connection>>,
}

const SQLITE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS entries (
	kind  TEXT NOT NULL,
	id    TEXT NOT NULL,
	value BLOB NOT NULL,
	PRIMARY KEY (kind, id)
) WITHOUT ROWID;
";

impl SQLite {
    /// Opens or creates the database at `path`.
    pub fn open(path: &str) -> Result<SQLite, StoreError> {
        let dir = rust_stdlib::path::filepath::dir(path);
        if dir != "." {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)?;
        }
        // database/sql opens lazily, so in Go a database that cannot be
        // opened or configured fails at the schema, with modernc's text.
        let schema_error = |e: rusqlite::Error| match e {
            rusqlite::Error::SqliteFailure(code, message) => format!(
                "creating the schema in {path}: {} ({})",
                message.unwrap_or_else(|| code.to_string()),
                code.extended_code
            ),
            e => format!("creating the schema in {path}: {e}"),
        };
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| match e {
            // rusqlite names the path in its open error; SQLite does not.
            rusqlite::Error::SqliteFailure(code, Some(message)) => {
                schema_error(rusqlite::Error::SqliteFailure(
                    code,
                    Some(
                        message
                            .strip_suffix(&format!(": {path}"))
                            .unwrap_or(&message)
                            .to_string(),
                    ),
                ))
            }
            e => schema_error(e),
        })?;
        // The Go DSN sets these pragmas on every connection.
        let configure = || -> rusqlite::Result<()> {
            db.pragma_update(None, "journal_mode", "WAL")?;
            db.pragma_update(None, "synchronous", "NORMAL")?;
            db.busy_timeout(std::time::Duration::from_millis(5000))?;
            db.pragma_update(None, "foreign_keys", "ON")?;
            db.execute_batch(SQLITE_SCHEMA)
        };
        configure().map_err(schema_error)?;
        // The database holds passkey credentials and session hashes. SQLite
        // gives its WAL and shared-memory files the database file's mode.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(SQLite {
            db: Mutex::new(Some(db)),
        })
    }
}

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

fn closed() -> StoreError {
    "sqlite store is closed".into()
}

impl Store for SQLite {
    fn load(
        &self,
        visit: &mut dyn FnMut(Entry) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let guard = self.db.lock().unwrap();
        let db = guard.as_ref().ok_or_else(closed)?;
        let mut rows = db.prepare("SELECT kind, id, value FROM entries")?;
        let mut rows = rows.query([])?;
        while let Some(row) = rows.next()? {
            visit(Entry {
                kind: row.get(0)?,
                id: row.get(1)?,
                value: Some(row.get(2)?),
            })?;
        }
        Ok(())
    }

    fn apply(&self, batch: &[Entry]) -> Result<(), StoreError> {
        let mut guard = self.db.lock().unwrap();
        let db = guard.as_mut().ok_or_else(closed)?;
        let tx = db.transaction()?;
        {
            let mut put = tx.prepare(
                "INSERT INTO entries (kind, id, value) VALUES (?, ?, ?)
		ON CONFLICT (kind, id) DO UPDATE SET value = excluded.value",
            )?;
            let mut del = tx.prepare("DELETE FROM entries WHERE kind = ? AND id = ?")?;
            for entry in batch {
                match &entry.value {
                    None => del.execute(params![entry.kind, entry.id])?,
                    Some(value) => put.execute(params![entry.kind, entry.id, value])?,
                };
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn close(&self) -> Result<(), StoreError> {
        let mut guard = self.db.lock().unwrap();
        if let Some(db) = guard.take() {
            db.close().map_err(|(_, e)| e)?;
        }
        Ok(())
    }
}
