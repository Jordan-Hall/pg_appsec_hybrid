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

/// Normalise to the validator's strict schema (exactly these four keys, UTC
/// `generated_at` stamped now) and rewrite the session-state file atomically.
pub fn write_session_state_file(dest: &Path, state: &Value) -> Result<(), SyncError> {
    let obj = state.as_object().ok_or_else(|| {
        SyncError::Msg("export_oauth_session_state must return a JSON object".into())
    })?;
    let mut out = serde_json::Map::new();
    out.insert(
        "generated_at".into(),
        Value::String(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
    );
    for key in ["active_sessions", "revoked_sids", "denied_jtis"] {
        let v = obj.get(key).cloned().unwrap_or(Value::Array(vec![]));
        if !v.is_array() {
            return Err(SyncError::Msg(format!("{key} must be an array")));
        }
        out.insert(key.into(), v);
    }
    let bytes = serde_json::to_vec(&Value::Object(out))?;
    atomic_write(dest, &bytes, 0o600)
}

/// Canonical bytes signed for an audit-chain checkpoint.
pub fn checkpoint_message(
    database: &str,
    event_id: i64,
    event_hash: &str,
    signed_at: &str,
) -> String {
    format!("pg_appsec-audit-checkpoint-v1|{database}|{event_id}|{event_hash}|{signed_at}")
}

/// Load a 32-byte Ed25519 seed stored as 64 hex chars.
pub fn load_signing_key(path: &Path) -> Result<ed25519_dalek::SigningKey, SyncError> {
    let raw = fs::read_to_string(path)?;
    let bytes =
        hex::decode(raw.trim()).map_err(|e| SyncError::Msg(format!("signing key hex: {e}")))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SyncError::Msg("signing key must be 32 bytes".into()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
}

pub fn load_verifying_key(path: &Path) -> Result<ed25519_dalek::VerifyingKey, SyncError> {
    let raw = fs::read_to_string(path)?;
    let bytes =
        hex::decode(raw.trim()).map_err(|e| SyncError::Msg(format!("public key hex: {e}")))?;
    let pk: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SyncError::Msg("public key must be 32 bytes".into()))?;
    ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|e| SyncError::Msg(e.to_string()))
}

/// Build a signed checkpoint line (JSON, single line).
pub fn sign_checkpoint(
    key: &ed25519_dalek::SigningKey,
    database: &str,
    event_id: i64,
    event_hash: &str,
) -> Result<String, SyncError> {
    use ed25519_dalek::Signer;
    if event_hash.len() != 64 || !event_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SyncError::Msg("event_hash must be 64 hex chars".into()));
    }
    let signed_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let msg = checkpoint_message(database, event_id, event_hash, &signed_at);
    let sig = key.sign(msg.as_bytes());
    Ok(serde_json::to_string(&serde_json::json!({
        "v": 1,
        "database": database,
        "event_id": event_id,
        "event_hash": event_hash,
        "signed_at": signed_at,
        "public_key": hex::encode(key.verifying_key().to_bytes()),
        "sig": hex::encode(sig.to_bytes()),
    }))?)
}

/// Append one line with O_APPEND + fsync (pair with WORM/append-only storage).
pub fn append_line(path: &Path, line: &str) -> Result<(), SyncError> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    Ok(())
}

/// Verify the signature of the LAST checkpoint line; returns (database, event_id, event_hash).
pub fn verify_last_checkpoint(
    path: &Path,
    key: &ed25519_dalek::VerifyingKey,
) -> Result<(String, i64, String), SyncError> {
    let body = fs::read_to_string(path)?;
    let last = body
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| SyncError::Msg("no checkpoints".into()))?;
    let v: Value = serde_json::from_str(last)?;
    let s = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .ok_or_else(|| SyncError::Msg(format!("checkpoint missing {k}")))
    };
    let database = s("database")?;
    let event_hash = s("event_hash")?;
    let signed_at = s("signed_at")?;
    let sig_hex = s("sig")?;
    let event_id = v
        .get("event_id")
        .and_then(|x| x.as_i64())
        .ok_or_else(|| SyncError::Msg("checkpoint missing event_id".into()))?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)
        .map_err(|e| SyncError::Msg(e.to_string()))?
        .try_into()
        .map_err(|_| SyncError::Msg("signature must be 64 bytes".into()))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let msg = checkpoint_message(&database, event_id, &event_hash, &signed_at);
    key.verify_strict(msg.as_bytes(), &sig)
        .map_err(|_| SyncError::Msg("checkpoint signature invalid".into()))?;
    Ok((database, event_id, event_hash))
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
    fn session_state_is_strict_schema_with_utc_generated_at() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("state.json");
        write_session_state_file(
            &dest,
            &json!({"active_sessions": [], "generated_at": "2000-01-01T00:00:00+05:00", "extra": 1}),
        )
        .unwrap();
        let v: Value = serde_json::from_str(&fs::read_to_string(&dest).unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        let mut keys: Vec<_> = obj.keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "active_sessions",
                "denied_jtis",
                "generated_at",
                "revoked_sids"
            ]
        );
        let g = obj["generated_at"].as_str().unwrap();
        assert!(g.ends_with('Z') && !g.starts_with("2000"));
        assert!(write_session_state_file(&dest, &json!({"active_sessions": {}})).is_err());
    }

    #[test]
    fn checkpoint_sign_verify_and_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("k.hex");
        let pub_path = dir.path().join("p.hex");
        fs::write(&key_path, "11".repeat(32)).unwrap();
        let sk = load_signing_key(&key_path).unwrap();
        fs::write(&pub_path, hex::encode(sk.verifying_key().to_bytes())).unwrap();
        let pk = load_verifying_key(&pub_path).unwrap();
        let cp = dir.path().join("cp.log");
        let h = "ab".repeat(32);
        append_line(&cp, &sign_checkpoint(&sk, "db", 7, &h).unwrap()).unwrap();
        append_line(&cp, &sign_checkpoint(&sk, "db", 9, &h).unwrap()).unwrap();
        let (db, id, hash) = verify_last_checkpoint(&cp, &pk).unwrap();
        assert_eq!((db.as_str(), id, hash.as_str()), ("db", 9, h.as_str()));
        // Tamper: change event_id in the last line.
        let body = fs::read_to_string(&cp)
            .unwrap()
            .replace("\"event_id\":9", "\"event_id\":8");
        fs::write(&cp, body).unwrap();
        assert!(verify_last_checkpoint(&cp, &pk).is_err());
        // Wrong key.
        fs::write(&pub_path, "22".repeat(32)).unwrap();
        let other = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        assert!(verify_last_checkpoint(&cp, &other).is_err());
        assert!(sign_checkpoint(&sk, "db", 1, "zz").is_err());
    }

    #[test]
    fn jti_file_dedups_and_newlines() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("jti.txt");
        write_jti_denylist_file(&dest, &json!({"denied_jtis": ["aaa", "bbb", "aaa"]})).unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "aaa\nbbb\n");
    }
}
