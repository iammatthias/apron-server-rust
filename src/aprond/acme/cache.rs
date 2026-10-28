//! autocert's `DirCache`: one file per key in a directory, so a cache
//! written by the Go aprond is read here and the other way round.

use rust_stdlib::os;
use rust_stdlib::path::filepath;
use std::io::Write;

/// autocert's `ErrCacheMiss`.
pub const CACHE_MISS: &str = "acme/autocert: certificate cache miss";

#[derive(Debug)]
pub enum CacheError {
    Miss,
    Io(std::io::Error),
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheError::Miss => f.write_str(CACHE_MISS),
            CacheError::Io(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for CacheError {}

#[derive(Clone, Debug)]
pub struct DirCache(pub String);

impl DirCache {
    fn path(&self, name: &str) -> String {
        filepath::join(&[self.0.as_str(), &filepath::clean(&format!("/{name}"))])
    }

    pub fn get(&self, name: &str) -> Result<Vec<u8>, CacheError> {
        match os::read_file(&self.path(name)) {
            Ok(data) => Ok(data),
            Err(e) if os::is_not_exist(&e) => Err(CacheError::Miss),
            Err(e) => Err(CacheError::Io(e)),
        }
    }

    /// Writes through a temporary file and a rename, so a reader never sees
    /// a partial entry.
    pub fn put(&self, name: &str, data: &[u8]) -> Result<(), CacheError> {
        os::mkdir_all(&self.0, os::FileMode(0o700)).map_err(CacheError::Io)?;
        let tmp = os::create_temp(&self.0, name).map_err(CacheError::Io)?;
        let tmp_name = tmp.name().to_string();
        let written = (&tmp).write_all(data).and_then(|_| tmp.close());
        let result = written.and_then(|_| os::rename(&tmp_name, &self.path(name)));
        if result.is_err() {
            let _ = os::remove(&tmp_name);
        }
        result.map_err(CacheError::Io)
    }

    pub fn delete(&self, name: &str) -> Result<(), CacheError> {
        match os::remove(&self.path(name)) {
            Err(e) if !os::is_not_exist(&e) => Err(CacheError::Io(e)),
            _ => Ok(()),
        }
    }
}
