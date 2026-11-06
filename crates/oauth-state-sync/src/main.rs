use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;
use pg_appsec_oauth_state_sync::{
    append_line, load_signing_key, load_verifying_key, sign_checkpoint, verify_last_checkpoint,
    write_jti_denylist_file, write_session_state_file, SyncError,
};
use sqlx::postgres::PgListener;
use sqlx::PgPool;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "oauth-state-sync")]
struct Args {
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    #[arg(long, env = "OAUTH_SESSION_STATE_FILE")]
    session_state_file: Option<PathBuf>,
    /// Optional plain list of DB-denied jtis (one per line). Must NOT be the
    /// validator's own seen-jti file (`pg_appsec.oauth_jti_denylist_file`):
    /// denied jtis already ship inside the session-state file.
    #[arg(long, env = "OAUTH_JTI_DENYLIST_FILE")]
    jti_denylist_file: Option<PathBuf>,
    /// Also export audit chain head hash to this path (optional).
    #[arg(long, env = "AUDIT_CHAIN_HEAD_FILE")]
    audit_chain_head_file: Option<PathBuf>,
    /// Append Ed25519-signed audit head checkpoints to this file (ship to WORM storage).
    #[arg(long, env = "AUDIT_CHECKPOINT_FILE")]
    audit_checkpoint_file: Option<PathBuf>,
    /// 32-byte Ed25519 seed (64 hex chars) used to sign checkpoints.
    #[arg(long, env = "AUDIT_SIGNING_KEY_FILE")]
    audit_signing_key_file: Option<PathBuf>,
    /// Also print each signed checkpoint line to stdout.
    #[arg(long, default_value_t = false)]
    checkpoint_stdout: bool,
    #[arg(long, default_value_t = 60)]
    checkpoint_secs: u64,
    #[arg(long, default_value_t = 5)]
    poll_secs: u64,
    /// Verify mode: check the last checkpoint signature with this public key
    /// (64 hex chars) and the DB chain against it, then exit 0 (ok) / 1 (fail).
    #[arg(long)]
    verify_checkpoint_with: Option<PathBuf>,
    /// Write one checkpoint now and exit.
    #[arg(long, default_value_t = false)]
    checkpoint_once: bool,
}

async fn export_once(pool: &PgPool, args: &Args) -> Result<(), SyncError> {
    let state: serde_json::Value = sqlx::query_scalar("SELECT appsec.export_oauth_session_state()")
        .fetch_one(pool)
        .await
        .map_err(|e| SyncError::Msg(e.to_string()))?;
    if let Some(path) = &args.session_state_file {
        write_session_state_file(path, &state)?;
    }
    if let Some(path) = &args.jti_denylist_file {
        write_jti_denylist_file(path, &state)?;
    }
    if let Some(path) = &args.audit_chain_head_file {
        if let Some(h) = audit_head(pool).await? {
            let bytes = serde_json::to_vec_pretty(&h)?;
            pg_appsec_oauth_state_sync::atomic_write(path, &bytes, 0o600)?;
        }
    }
    Ok(())
}

async fn audit_head(pool: &PgPool) -> Result<Option<serde_json::Value>, SyncError> {
    let head: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT appsec.export_audit_chain_head()")
            .fetch_one(pool)
            .await
            .map_err(|e| SyncError::Msg(e.to_string()))?;
    Ok(head)
}

/// Returns the event_id checkpointed (None if chain empty).
async fn checkpoint_once(
    pool: &PgPool,
    args: &Args,
    last: Option<i64>,
) -> Result<Option<i64>, SyncError> {
    let (Some(path), Some(key_path)) = (&args.audit_checkpoint_file, &args.audit_signing_key_file)
    else {
        return Ok(last);
    };
    let Some(h) = audit_head(pool).await? else {
        return Ok(last);
    };
    let event_id = h
        .get("event_id")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| SyncError::Msg("head missing event_id".into()))?;
    if last == Some(event_id) {
        return Ok(last);
    }
    let event_hash = h
        .get("event_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| SyncError::Msg("head missing event_hash".into()))?;
    let database = h.get("database").and_then(|v| v.as_str()).unwrap_or("");
    let key = load_signing_key(key_path)?;
    let line = sign_checkpoint(&key, database, event_id, event_hash)?;
    append_line(path, &line)?;
    if args.checkpoint_stdout {
        println!("{line}");
    }
    info!("audit checkpoint event_id={event_id}");
    Ok(Some(event_id))
}

async fn verify_mode(pool: &PgPool, args: &Args, pubkey: &Path) -> Result<bool, SyncError> {
    let path = args
        .audit_checkpoint_file
        .as_ref()
        .ok_or_else(|| SyncError::Msg("--audit-checkpoint-file required".into()))?;
    let key = load_verifying_key(pubkey)?;
    let (database, event_id, event_hash) = verify_last_checkpoint(path, &key)?;
    let current_db: String = sqlx::query_scalar("SELECT current_database()::text")
        .fetch_one(pool)
        .await
        .map_err(|e| SyncError::Msg(e.to_string()))?;
    if current_db != database {
        println!("checkpoint_verify=FAIL detail=database mismatch");
        return Ok(false);
    }
    let row: (bool, String) = sqlx::query_as(
        "SELECT ok, detail FROM appsec.verify_audit_chain_against_checkpoint($1, $2)",
    )
    .bind(event_id)
    .bind(&event_hash)
    .fetch_one(pool)
    .await
    .map_err(|e| SyncError::Msg(e.to_string()))?;
    println!(
        "checkpoint_verify={} event_id={event_id} detail={}",
        if row.0 { "OK" } else { "FAIL" },
        row.1
    );
    Ok(row.0)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let pool = PgPool::connect(&args.database_url).await?;
    if let Some(pk) = &args.verify_checkpoint_with {
        let ok = match verify_mode(&pool, &args, pk).await {
            Ok(ok) => ok,
            Err(e) => {
                println!("checkpoint_verify=FAIL detail={e}");
                false
            }
        };
        std::process::exit(if ok { 0 } else { 1 });
    }
    if args.checkpoint_once {
        checkpoint_once(&pool, &args, None).await?;
        return Ok(());
    }
    let mut listener = PgListener::connect(&args.database_url).await?;
    listener.listen("appsec_oauth_state").await?;
    info!(
        "oauth-state-sync listening; session_state={:?} jti={:?}",
        args.session_state_file, args.jti_denylist_file
    );
    export_once(&pool, &args).await?;
    let mut last_cp = checkpoint_once(&pool, &args, None).await?;
    let mut last_cp_at = Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_secs(args.poll_secs.max(1)));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(e) = export_once(&pool, &args).await {
                    error!("poll export failed: {e}");
                }
                if last_cp_at.elapsed() >= Duration::from_secs(args.checkpoint_secs.max(1)) {
                    match checkpoint_once(&pool, &args, last_cp).await {
                        Ok(v) => last_cp = v,
                        Err(e) => error!("checkpoint failed: {e}"),
                    }
                    last_cp_at = Instant::now();
                }
            }
            n = listener.recv() => {
                match n {
                    Ok(notif) => {
                        info!("notify {} payload={}", notif.channel(), notif.payload());
                        if let Err(e) = export_once(&pool, &args).await {
                            error!("notify export failed: {e}");
                        }
                    }
                    Err(e) => {
                        warn!("listener error: {e}");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("shutting down");
                break;
            }
        }
    }
    Ok(())
}
