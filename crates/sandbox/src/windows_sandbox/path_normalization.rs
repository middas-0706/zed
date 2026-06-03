//! Path canonicalization for the Windows sandbox.
//!
//! Writable scope and the ACL'd paths must resolve to the same NT path the
//! kernel checks, so we normalize through `dunce::canonicalize` (which avoids
//! the `\\?\` verbatim prefix that some tools mishandle) and fall back to the
//! original path when canonicalization fails (e.g. the path doesn't exist).

use std::path::{Path, PathBuf};

/// Canonicalize a path, falling back to the input when that fails.
pub fn canonicalize_path(path: &Path) -> PathBuf {
    dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}
