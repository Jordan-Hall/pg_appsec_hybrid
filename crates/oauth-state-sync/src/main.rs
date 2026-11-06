use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use pg_appsec_oauth_state_sync::{write_jti_denylist_file, write_session_state_file, SyncError};
use sqlx::postgres::PgListener;
use sqlx::PgPool;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "oauth-state-sync")]
struct Args {
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    #[arg(long, env = "OAUTH_SESSION_STATE_FILE")]
    session_state_file: PathBuf,
    #[arg(long, env = "OAUTH_JTI_DENYLIST_FILE")]
    jti_denylist_file: PathBuf,
    /// Also export audit chain head hash to this path (optional WORM anchor).
    #[arg(long, env = "AUDIT_CHAIN_HEAD_FILE")]
    audit_chain_head_file: Option<PathBuf>,
    #[arg(long, default_value_t = 5)]
    poll_secs: u64,
}

async fn export_once(pool: &PgPool, args: &Args) -> Result<(), SyncError> {
    let state: serde_json::Value = sqlx::query_scalar("SELECT appsec.export_oauth_session_state()")
        .fetch_one(pool)
        .await
        .map_err(|e| SyncError::Msg(e.to_string()))?;
    write_session_state_file(&args.session_state_file, &state)?;
    write_jti_denylist_file(&args.jti_denylist_file, &state)?;
    if let Some(path) = &args.audit_chain_head_file {
        let head: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT appsec.export_audit_chain_head()")
                .fetch_optional(pool)
                .await
                .map_err(|e| SyncError::Msg(e.to_string()))?;
        if let Some(h) = head {
            let bytes = serde_json::to_vec_pretty(&h)?;
            pg_appsec_oauth_state_sync::atomic_write(path, &bytes, 0o600)?;
            println!("{}", String::from_utf8_lossy(&bytes));
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    let pool = PgPool::connect(&args.database_url).await?;
    let mut listener = PgListener::connect(&args.database_url).await?;
    listener.listen("appsec_oauth_state").await?;
    info!(
        "oauth-state-sync listening; session_state={:?} jti={:?}",
        args.session_state_file, args.jti_denylist_file
    );
    export_once(&pool, &args).await?;
    let mut ticker = tokio::time::interval(Duration::from_secs(args.poll_secs.max(1)));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(e) = export_once(&pool, &args).await {
                    error!("poll export failed: {e}");
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
