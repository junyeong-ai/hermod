//! `hermodd` — the Hermod daemon.
//!
//! Loads identity and config, opens the SQLite store, and accepts IPC on a Unix socket.

use anyhow::Context;
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

mod bootstrap;
mod dispatcher;
mod federation;
mod inbound;
mod ipc_remote;
mod janitor;
mod observability;
mod outbox;
mod server;
mod services;

use hermod_daemon::{config::Config, identity, paths};

use crate::server::serve;

#[derive(Parser, Debug)]
#[command(name = "hermodd", version, about = "Hermod daemon")]
struct Cli {
    /// Path to config TOML. Defaults to $HERMOD_HOME/config.toml.
    #[arg(long, env = "HERMOD_CONFIG")]
    config: Option<PathBuf>,

    /// Hermod home directory. Defaults to ~/.hermod.
    #[arg(long, env = "HERMOD_HOME")]
    home: Option<PathBuf>,

    /// Override socket path (otherwise from config).
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let home = paths::resolve_home(cli.home.as_deref())?;
    let config = Config::load_or_default(cli.config.as_deref(), &home).context("load config")?;

    info!(home = %home.display(), "starting hermodd");

    let mut effective_socket = paths::expand(&config.daemon.socket_path, &home);
    if let Some(s) = cli.socket {
        effective_socket = s;
    }

    let storage_dsn = paths::expand_dsn(&config.storage.dsn, &home);
    let blob_dsn = paths::expand_dsn(&config.blob.dsn, &home);

    let identity = identity::load(&home)
        .context("load identity (run `hermod init` first to generate an identity)")?;

    // TLS material — generate if missing so federation listener can bind WSS.
    let tls = identity::ensure_tls(&home, &identity).context("load TLS material")?;
    info!(
        tls_fingerprint = %&tls.fingerprint[..23],
        "loaded TLS material"
    );

    let identity = std::sync::Arc::new(identity);
    // Application-level signer — wraps the loaded keypair behind the
    // `Signer` trait so the daemon's signing dependencies don't bind to
    // the file-backed Keypair concretely. Future KMS backends slot in
    // by constructing a different `Arc<dyn Signer>` here.
    let signer: std::sync::Arc<dyn hermod_crypto::Signer> =
        std::sync::Arc::new(hermod_crypto::LocalKeySigner::new(identity.clone()));
    let blobs = hermod_storage::open_blob_store(&blob_dsn)
        .await
        .with_context(|| format!("open blob store at {blob_dsn}"))?;
    info!(blob_dsn = %blob_dsn, "BlobStore ready");
    let db: std::sync::Arc<dyn hermod_storage::Database> =
        match hermod_storage::open_database(&storage_dsn, signer.clone(), blobs).await {
            Ok(db) => db,
            Err(hermod_storage::StorageError::SchemaMismatch { details }) => {
                // The on-disk DB has an applied migration whose checksum
                // no longer matches the bundled SQL — this build edits
                // the migration file in place ("clean-slate schema
                // policy", see DEPLOY.md). Tell the operator how to
                // recover instead of surfacing a raw backend error.
                anyhow::bail!(
                    "schema mismatch: the migrations bundled with this build \
                     don't match the previously-applied schema at {storage_dsn}. \
                     Hermod uses a clean-slate migration policy — archive the \
                     database and re-init. underlying: {details}"
                );
            }
            Err(e) => {
                return Err(anyhow::Error::from(e).context(format!("open storage {storage_dsn}")));
            }
        };

    // Ensure self-agent is registered. Safe to repeat on every start.
    let self_alias = config
        .identity
        .alias
        .as_deref()
        .and_then(|a| a.parse::<hermod_core::AgentAlias>().ok());
    services::ensure_self_agent(&*db, &identity, self_alias).await?;

    let bearer_token = std::sync::Arc::new(hermod_daemon::identity::ensure_bearer_token(&home)?);
    let audit_file_path = config
        .audit
        .file_path
        .as_deref()
        .map(|p| paths::expand(p, &home));
    serve(
        effective_socket,
        db,
        signer,
        identity,
        tls,
        bearer_token,
        audit_file_path,
        home,
        config,
    )
    .await?;
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter =
        EnvFilter::try_from_env("HERMOD_DAEMON_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("HERMOD_DAEMON_LOG_FORMAT").ok().as_deref() == Some("json");
    if json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .json()
            .with_current_span(false)
            .with_span_list(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    }
}
