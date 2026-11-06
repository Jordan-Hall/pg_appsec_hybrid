//! Atomic OAuth session-state / jti denylist file writer for the connect-time validator.
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Msg(String),
}

/// Write `contents` to `dest` via temp file in the same directory, fsync, chmod 0600, rename.
pub fn atomic_write(dest: &Path, contents: &[u8], mode: u32) -> Result<(), SyncError> {
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let mut tmp = PathBuf::from(parent);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    tmp.push(format!(
        ".{}.{}.tmp",
        dest.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("oauth_state"),
        nanos
    ));
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&tmp)?.permissions();
        perms.set_mode(mode);
        fs::set_permissions(&tmp, perms)?;
    }
    fs::rename(&tmp, dest)?;
    // Best-effort directory fsync for durability of the rename.
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Ensure JSON has generated_at; rewrite session-state file atomically.
pub fn write_session_state_file(dest: &Path, state: &Value) -> Result<(), SyncError> {
    let mut obj = state.as_object().cloned().ok_or_else(|| {
        SyncError::Msg("export_oauth_session_state must return a JSON object".into())
    })?;
    if !obj.contains_key("generated_at") {
        obj.insert(
            "generated_at".into(),
            Value::String(chrono::Utc::now().to_rfc3339()),
        );
    }
    let bytes = serde_json::to_vec_pretty(&Value::Object(obj))?;
    atomic_write(dest, &bytes, 0o600)
}

/// Write one jti per line (plus denied_jtis from state if present).
pub fn write_jti_denylist_file(dest: &Path, state: &Value) -> Result<(), SyncError> {
    let mut lines: Vec<String> = Vec::new();
    if let Some(arr) = state.get("denied_jtis").and_then(|v| v.as_array()) {
        for v in arr {
            if let Some(s) = v.as_str() {
                if !s.is_empty() {
                    lines.push(s.to_string());
                }
            }
        }
    }
    lines.sort();
    lines.dedup();
    let mut body = lines.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    atomic_write(dest, body.as_bytes(), 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn atomic_write_is_0600_and_complete() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("session_state.json");
        atomic_write(&dest, br#"{"ok":true}"#, 0o600).unwrap();
        let meta = fs::metadata(&dest).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(&dest).unwrap(), r#"{"ok":true}"#);
        assert!(!dir.path().read_dir().unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp")));
    }

    #[test]
    fn session_state_adds_generated_at_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("state.json");
        write_session_state_file(&dest, &json!({"active_sessions": []})).unwrap();
        let v: Value = serde_json::from_str(&fs::read_to_string(&dest).unwrap()).unwrap();
        assert!(v.get("generated_at").and_then(|x| x.as_str()).is_some());
    }

    #[test]
    fn jti_file_dedups_and_newlines() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("jti.txt");
        write_jti_denylist_file(&dest, &json!({"denied_jtis": ["aaa", "bbb", "aaa"]})).unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "aaa\nbbb\n");
    }
}
