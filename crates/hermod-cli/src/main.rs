use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod bearer;
mod client;
mod commands;
mod error;
mod mcp;
mod pins;
mod remote;

#[derive(Parser, Debug)]
#[command(name = "hermod", version, about = "Hermod operator CLI")]
struct Cli {
    /// Hermod home directory. Defaults to ~/.hermod.
    #[arg(long, env = "HERMOD_HOME")]
    home: Option<PathBuf>,

    /// Override the local Unix socket path. Ignored when --remote is set.
    #[arg(long, env = "HERMOD_SOCKET")]
    socket: Option<PathBuf>,

    /// Connect to a remote daemon via WSS+Bearer instead of the local Unix
    /// socket. Example: `--remote wss://my-daemon.example.com:7824/`.
    /// One of `--bearer-file`, `--bearer-command`, or
    /// `HERMOD_BEARER_TOKEN` supplies the daemon-layer bearer; with
    /// none of those set the CLI falls back to
    /// `$HERMOD_HOME/agents/<bootstrap_id>/bearer_token`. When the daemon sits
    /// behind an SSO reverse proxy (Google Cloud IAP, oauth2-proxy,
    /// Cloudflare Access, ALB+Cognito, …), additionally configure
    /// `--proxy-bearer-*` to populate the `Proxy-Authorization` header
    /// the proxy expects.
    #[arg(long, env = "HERMOD_REMOTE")]
    remote: Option<String>,

    /// File containing the daemon-layer bearer token for remote IPC,
    /// sent as `Authorization: Bearer <contents>`. Plain-text
    /// contents; surrounding whitespace is trimmed. Read once on the
    /// cold path; re-read only when the daemon rejects the token with
    /// HTTP 401, so a `hermod bearer rotate` (or any external tool
    /// that updates the file) is picked up by the next connect
    /// without restarting the CLI. Mutually exclusive with
    /// `--bearer-command` and `HERMOD_BEARER_TOKEN`.
    #[arg(long, env = "HERMOD_BEARER_FILE", requires = "remote")]
    bearer_file: Option<PathBuf>,

    /// Shell command that prints the daemon-layer bearer token to
    /// stdout, sent as `Authorization: Bearer <stdout>`. Invoked at
    /// connect time and re-invoked exactly once if the daemon rejects
    /// the token with HTTP 401 (e.g. expired OIDC ID token behind
    /// Google Cloud IAP). Single-flight: concurrent retries collapse
    /// into one subprocess invocation. Mutually exclusive with
    /// `--bearer-file` and `HERMOD_BEARER_TOKEN`.
    ///
    /// Example: `--bearer-command "gcloud auth print-identity-token --audiences=$IAP_CLIENT_ID"`
    #[arg(long, env = "HERMOD_BEARER_COMMAND", requires = "remote")]
    bearer_command: Option<String>,

    /// File containing the proxy-layer bearer token for remote IPC,
    /// sent as `Proxy-Authorization: Bearer <contents>` per RFC 7235
    /// §4.4 to authenticate against an SSO reverse proxy fronting the
    /// daemon (Google Cloud IAP, oauth2-proxy, Cloudflare Access,
    /// ALB+Cognito). Plain-text contents; surrounding whitespace is
    /// trimmed. Read once on the cold path; re-read only when the
    /// proxy rejects the token with HTTP 401 / 407. Mutually
    /// exclusive with `--proxy-bearer-command` and
    /// `HERMOD_PROXY_BEARER_TOKEN`.
    #[arg(long, env = "HERMOD_PROXY_BEARER_FILE", requires = "remote")]
    proxy_bearer_file: Option<PathBuf>,

    /// Shell command that prints the proxy-layer bearer token to
    /// stdout, sent as `Proxy-Authorization: Bearer <stdout>` to the
    /// SSO reverse proxy fronting the daemon. Invoked at connect time
    /// and re-invoked exactly once if the proxy rejects the token
    /// with HTTP 401 / 407. Single-flight: concurrent retries
    /// collapse into one subprocess invocation. Mutually exclusive
    /// with `--proxy-bearer-file` and `HERMOD_PROXY_BEARER_TOKEN`.
    ///
    /// Example: `--proxy-bearer-command "gcloud auth print-identity-token --audiences=$IAP_CLIENT_ID"`
    #[arg(long, env = "HERMOD_PROXY_BEARER_COMMAND", requires = "remote")]
    proxy_bearer_command: Option<String>,

    /// TLS verification policy for the remote daemon's cert.
    /// One of:
    ///   * `tofu` (default) — record the daemon's cert SHA-256 to
    ///     `$HERMOD_HOME/remote_pins.json` on first connect; fail loud
    ///     on later mismatch. Right for self-signed / federation /
    ///     LAN.
    ///   * `<sha256>` — explicit fingerprint pin (any case; colons
    ///     optional). Right for production federation where the pin
    ///     is provisioned out-of-band.
    ///   * `public-ca` — validate the daemon's chain via the OS root
    ///     CA store. Right when a public-CA-trusted reverse proxy
    ///     (Cloud Run, Google IAP, Cloudflare Access, ALB+Cognito)
    ///     terminates TLS in front of the daemon — pinning the LB's
    ///     cert would break on every rotation.
    ///   * `none` — skip TLS validation. Strictly opt-in for tests /
    ///     known-LAN where MITM is not a concern.
    #[arg(
        long,
        env = "HERMOD_REMOTE_PIN",
        default_value = "tofu",
        value_name = "MODE | SHA256"
    )]
    pin: pins::PinArg,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Create identity, write config template, prepare home directory.
    Init(commands::init::InitArgs),
    /// Report daemon health and pending-message count.
    Status,
    /// Print this agent's identity (agent id, alias, fingerprint).
    Identity,
    /// Diagnose the local install: identity, TLS, daemon reachability,
    /// audit chain integrity, peer health.
    Doctor,

    /// Send, list, and ack messages.
    #[command(subcommand)]
    Message(MessageCmd),

    /// Agent directory operations.
    #[command(subcommand)]
    Agent(AgentCmd),

    /// Publish or read self-authored briefs (operator summaries) about another agent.
    #[command(subcommand)]
    Brief(BriefCmd),

    /// Set or get presence (online/idle/busy/offline).
    #[command(subcommand)]
    Presence(PresenceCmd),

    /// Workspaces — group container for channels.
    #[command(subcommand)]
    Workspace(WorkspaceCmd),

    /// Channels within a workspace.
    #[command(subcommand)]
    Channel(ChannelCmd),

    /// Broadcast a message to a channel.
    #[command(subcommand)]
    Broadcast(BroadcastCmd),

    /// Inspect and decide pending confirmation-gated inbound actions.
    #[command(subcommand)]
    Confirm(ConfirmCmd),

    /// Operator surface for the Claude Code Channels permission relay —
    /// list pending tool-call prompts, then allow or deny by short id.
    #[command(subcommand)]
    Permission(PermissionCmd),

    /// Federation peers (other hermodd instances).
    #[command(subcommand)]
    Peer(PeerCmd),

    /// Capability tokens (issue / revoke).
    #[command(subcommand)]
    Capability(CapabilityCmd),

    /// Remote IPC bearer token (show / rotate).
    #[command(subcommand)]
    Bearer(BearerCmd),

    /// Manage the daemon's hosted local agents (per-project tenants).
    #[command(subcommand)]
    Local(LocalCmd),

    /// Query and verify the audit log.
    #[command(subcommand)]
    Audit(AuditCmd),

    /// Run the MCP server over stdio (called by Claude Code).
    Mcp,
}

#[derive(Subcommand, Debug)]
enum LocalCmd {
    /// List every agent this daemon hosts.
    List,
    /// Show one agent's identity, alias, and bearer paths.
    Show(commands::local::ShowArgs),
    /// Provision a fresh local agent (keypair + bearer + alias).
    Add(commands::local::AddArgs),
    /// Archive a local agent's on-disk material.
    Rm(commands::local::RemoveArgs),
    /// Generate a new bearer token for a local agent.
    Rotate(commands::local::RotateArgs),
    /// Write `.mcp.json` next to a project root so Claude Code
    /// connects as the named agent when launched from that project.
    #[command(name = "setup-mcp")]
    SetupMcp(commands::local::SetupMcpArgs),
    /// List live MCP sessions for the caller agent (one row per
    /// attached Claude Code window). Surfaces `session_label` so
    /// operators can tell which window is which.
    Sessions,
}

#[derive(Subcommand, Debug)]
enum MessageCmd {
    /// Send a direct text message.
    Send(commands::message::SendArgs),
    /// Send a file (inline payload up to `[policy] max_file_payload_bytes`,
    /// default 1 MiB).
    #[command(name = "send-file")]
    SendFile(commands::message::SendFileArgs),
    /// List inbox.
    List(commands::message::ListArgs),
    /// Mark messages as read.
    Ack(commands::message::AckArgs),
}

#[derive(Subcommand, Debug)]
enum AgentCmd {
    /// List agents currently reachable for synchronous reply (live only).
    List(commands::agent::ListArgs),
    /// Inspect a specific agent regardless of liveness.
    Get(commands::agent::GetArgs),
    /// Register a known agent by pubkey.
    Register(commands::agent::RegisterArgs),
}

#[derive(Subcommand, Debug)]
enum BriefCmd {
    /// Publish a self-authored summary of this agent's recent activity.
    Publish(commands::brief::PublishArgs),
    /// Read another agent's most recent brief.
    Read(commands::brief::ReadArgs),
}

#[derive(Subcommand, Debug)]
enum PresenceCmd {
    /// Override this agent's presence (busy / idle / etc.). Liveness is
    /// otherwise derived automatically from MCP attach state.
    Set(commands::presence::SetArgs),
    /// Drop the manual override and revert to derived presence.
    Clear,
    /// Get another agent's effective presence.
    Get(commands::presence::GetArgs),
}

#[derive(Subcommand, Debug)]
enum WorkspaceCmd {
    /// Create a new workspace (private by default).
    Create(commands::workspace::CreateArgs),
    /// Join an existing private workspace via shared secret.
    Join(commands::workspace::JoinArgs),
    /// List workspaces this agent belongs to.
    List,
    /// Describe one workspace.
    Get(commands::workspace::GetArgs),
    /// Delete a workspace (cascades channels, channel messages, members).
    Delete(commands::workspace::DeleteArgs),
    /// Mute or unmute a workspace.
    Mute(commands::workspace::MuteArgs),
    /// Send a private-workspace invite to another agent.
    Invite(commands::workspace::InviteArgs),
    /// List the gossip-union of every member of a workspace.
    Members(commands::workspace::MembersArgs),
    /// List the gossip-union of every channel in a workspace.
    Channels(commands::workspace::ChannelsArgs),
}

#[derive(Subcommand, Debug)]
enum ChannelCmd {
    /// Create a channel within a workspace.
    Create(commands::channel::CreateArgs),
    /// List channels in a workspace.
    List(commands::channel::ListArgs),
    /// Show recent broadcasts from a channel.
    History(commands::channel::HistoryArgs),
    /// Delete a channel (cascades channel messages).
    Delete(commands::channel::DeleteArgs),
    /// Mute or unmute a channel.
    Mute(commands::channel::MuteArgs),
    /// Push a ChannelAdvertise to all known workspace members.
    Advertise(commands::channel::AdvertiseArgs),
    /// List discovered channels (advertised by other workspace members).
    Discover(commands::channel::DiscoverArgs),
    /// Adopt a discovered channel — re-derives crypto material from the
    /// local workspace secret + channel name and creates the channel locally.
    Adopt(commands::channel::AdoptArgs),
}

#[derive(Subcommand, Debug)]
enum BroadcastCmd {
    /// Send a message to a channel — fans out to known workspace members.
    Send(commands::broadcast::SendArgs),
}

#[derive(Subcommand, Debug)]
enum AuditCmd {
    /// Query audit-log entries.
    Query(commands::audit::QueryArgs),
    /// Verify the hash-chain integrity and signatures of the audit log.
    Verify,
    /// Archive every fully-elapsed UTC day older than the cutoff into
    /// the BlobStore as gzip-compressed JSONL day-buckets.
    Archive(commands::audit::ArchiveNowArgs),
    /// List existing archive day-buckets (newest first).
    #[command(name = "archives-list")]
    ArchivesList(commands::audit::ArchivesListArgs),
    /// Verify the manifest signature + inner row chain of one archive.
    #[command(name = "verify-archive")]
    VerifyArchive(commands::audit::VerifyArchiveArgs),
}

#[derive(Subcommand, Debug)]
enum ConfirmCmd {
    /// List currently held confirmations.
    List(commands::confirmation::ListArgs),
    /// Accept and apply a held confirmation.
    Accept(commands::confirmation::DecideArgs),
    /// Reject (drop) a held confirmation.
    Reject(commands::confirmation::DecideArgs),
}

#[derive(Subcommand, Debug)]
enum PermissionCmd {
    /// Show pending permission requests (oldest first).
    List(commands::permission::ListArgs),
    /// Allow a pending request by short id.
    Allow(commands::permission::DecideArgs),
    /// Deny a pending request by short id.
    Deny(commands::permission::DecideArgs),
    /// Issue + envelope-deliver a `permission:respond` capability so
    /// the named agent can answer this daemon's permission prompts.
    Delegate(commands::permission::DelegateArgs),
}

#[derive(Subcommand, Debug)]
enum PeerCmd {
    /// Add a peer (manual / static peering).
    Add(commands::peer::AddArgs),
    /// List known peers.
    List,
    /// Update a peer's trust level.
    Trust(commands::peer::TrustArgs),
    /// Drop a peer's federation endpoint and TLS pin.
    Remove(commands::peer::RemoveArgs),
    /// Replace a Verified peer's TLS fingerprint after a legitimate cert
    /// rotation (confirm OOB before submitting).
    Repin(commands::peer::RepinArgs),
    /// Push a `PeerAdvertise` envelope listing this daemon's hosted
    /// agents. Without `--target`, fans out to every federated peer
    /// once per distinct host.
    Advertise(commands::peer::AdvertiseArgs),
}

#[derive(Subcommand, Debug)]
enum CapabilityCmd {
    /// Mint a self-issued capability token.
    Issue(commands::capability::IssueArgs),
    /// Revoke a previously-issued token by id.
    Revoke(commands::capability::RevokeArgs),
    /// List capabilities this daemon has issued.
    List(commands::capability::ListArgs),
}

#[derive(Subcommand, Debug)]
enum BearerCmd {
    /// Show the Remote IPC bearer token (masked by default).
    Show(commands::bearer::ShowArgs),
    /// Generate a fresh bearer token. Restart the daemon to apply.
    Rotate,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let home = hermod_daemon::paths::resolve_home(cli.home.as_deref())?;
    let socket = cli
        .socket
        .clone()
        .or_else(|| resolve_socket_from_config(&home).ok());
    let target = build_target(&cli, &home, &socket)?;

    match cli.command {
        Command::Init(args) => commands::init::run(args, &home).await,
        Command::Status => commands::status::run(&target).await,
        Command::Identity => commands::identity::run(&home).await,
        Command::Doctor => commands::doctor::run(&home, &target).await,
        Command::Message(sub) => match sub {
            MessageCmd::Send(a) => commands::message::send(a, &target).await,
            MessageCmd::SendFile(a) => commands::message::send_file(a, &target).await,
            MessageCmd::List(a) => commands::message::list(a, &target).await,
            MessageCmd::Ack(a) => commands::message::ack(a, &target).await,
        },
        Command::Agent(sub) => match sub {
            AgentCmd::List(a) => commands::agent::list(a, &target).await,
            AgentCmd::Get(a) => commands::agent::get(a, &target).await,
            AgentCmd::Register(a) => commands::agent::register(a, &target).await,
        },
        Command::Brief(sub) => match sub {
            BriefCmd::Publish(a) => commands::brief::publish(a, &target).await,
            BriefCmd::Read(a) => commands::brief::read(a, &target).await,
        },
        Command::Presence(sub) => match sub {
            PresenceCmd::Set(a) => commands::presence::set(a, &target).await,
            PresenceCmd::Clear => commands::presence::clear(&target).await,
            PresenceCmd::Get(a) => commands::presence::get(a, &target).await,
        },
        Command::Workspace(sub) => match sub {
            WorkspaceCmd::Create(a) => commands::workspace::create(a, &target).await,
            WorkspaceCmd::Join(a) => commands::workspace::join(a, &target).await,
            WorkspaceCmd::List => commands::workspace::list(&target).await,
            WorkspaceCmd::Get(a) => commands::workspace::get(a, &target).await,
            WorkspaceCmd::Delete(a) => commands::workspace::delete(a, &target).await,
            WorkspaceCmd::Mute(a) => commands::workspace::mute(a, &target).await,
            WorkspaceCmd::Invite(a) => commands::workspace::invite(a, &target).await,
            WorkspaceCmd::Members(a) => commands::workspace::members(a, &target).await,
            WorkspaceCmd::Channels(a) => commands::workspace::channels(a, &target).await,
        },
        Command::Channel(sub) => match sub {
            ChannelCmd::Create(a) => commands::channel::create(a, &target).await,
            ChannelCmd::List(a) => commands::channel::list(a, &target).await,
            ChannelCmd::History(a) => commands::channel::history(a, &target).await,
            ChannelCmd::Delete(a) => commands::channel::delete(a, &target).await,
            ChannelCmd::Mute(a) => commands::channel::mute(a, &target).await,
            ChannelCmd::Advertise(a) => commands::channel::advertise(a, &target).await,
            ChannelCmd::Discover(a) => commands::channel::discover(a, &target).await,
            ChannelCmd::Adopt(a) => commands::channel::adopt(a, &target).await,
        },
        Command::Broadcast(sub) => match sub {
            BroadcastCmd::Send(a) => commands::broadcast::send(a, &target).await,
        },
        Command::Confirm(sub) => match sub {
            ConfirmCmd::List(a) => commands::confirmation::list(a, &target).await,
            ConfirmCmd::Accept(a) => commands::confirmation::accept(a, &target).await,
            ConfirmCmd::Reject(a) => commands::confirmation::reject(a, &target).await,
        },
        Command::Permission(sub) => match sub {
            PermissionCmd::List(a) => commands::permission::list(a, &target).await,
            PermissionCmd::Allow(a) => commands::permission::allow(a, &target).await,
            PermissionCmd::Deny(a) => commands::permission::deny(a, &target).await,
            PermissionCmd::Delegate(a) => commands::permission::delegate(a, &target).await,
        },
        Command::Peer(sub) => match sub {
            PeerCmd::Add(a) => commands::peer::add(a, &target).await,
            PeerCmd::List => commands::peer::list(&target).await,
            PeerCmd::Trust(a) => commands::peer::trust(a, &target).await,
            PeerCmd::Remove(a) => commands::peer::remove(a, &target).await,
            PeerCmd::Repin(a) => commands::peer::repin(a, &target).await,
            PeerCmd::Advertise(a) => commands::peer::advertise(a, &target).await,
        },
        Command::Capability(sub) => match sub {
            CapabilityCmd::Issue(a) => commands::capability::issue(a, &target).await,
            CapabilityCmd::Revoke(a) => commands::capability::revoke(a, &target).await,
            CapabilityCmd::List(a) => commands::capability::list(a, &target).await,
        },
        Command::Bearer(sub) => match sub {
            BearerCmd::Show(a) => commands::bearer::show(a, &home).await,
            BearerCmd::Rotate => commands::bearer::rotate(&home).await,
        },
        Command::Local(sub) => match sub {
            LocalCmd::List => commands::local::list(&home).await,
            LocalCmd::Show(a) => commands::local::show(a, &home).await,
            LocalCmd::Add(a) => commands::local::add(a, &target).await,
            LocalCmd::Rm(a) => commands::local::remove(a, &target).await,
            LocalCmd::Rotate(a) => commands::local::rotate(a, &target).await,
            LocalCmd::SetupMcp(a) => commands::local::setup_mcp(a, &home).await,
            LocalCmd::Sessions => commands::local::sessions(&target).await,
        },
        Command::Audit(sub) => match sub {
            AuditCmd::Query(a) => commands::audit::query(a, &target).await,
            AuditCmd::Verify => commands::audit::verify(&target).await,
            AuditCmd::Archive(a) => commands::audit::archive_now(a, &target).await,
            AuditCmd::ArchivesList(a) => commands::audit::archives_list(a, &target).await,
            AuditCmd::VerifyArchive(a) => commands::audit::verify_archive(a, &target).await,
        },
        Command::Mcp => mcp::run(&target).await,
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    // CLI shares the same convention as the daemon: HERMOD_<SECTION>_<FIELD>.
    // The CLI is operationally part of the `daemon` story (it talks to the
    // daemon over IPC), so it reads the same `HERMOD_DAEMON_LOG` filter
    // rather than introducing a separate `HERMOD_CLI_LOG`. Keeps a single
    // knob for "Hermod logging verbosity" across both processes.
    let filter =
        EnvFilter::try_from_env("HERMOD_DAEMON_LOG").unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

fn resolve_socket_from_config(home: &std::path::Path) -> anyhow::Result<PathBuf> {
    let cfg = hermod_daemon::config::Config::load(None, home)?;
    Ok(hermod_daemon::paths::expand(&cfg.daemon.socket_path, home))
}

fn socket_or_default(home: &std::path::Path, explicit: Option<PathBuf>) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }
    resolve_socket_from_config(home).unwrap_or_else(|_| home.join("sock"))
}

/// Build a `ClientTarget` from the parsed top-level args. Remote IPC takes
/// precedence — when `--remote URL` is set the local socket is ignored.
///
/// Two bearer families are resolved here, both into trait objects:
/// the daemon-layer bearer (always required) and the proxy-layer bearer
/// (optional, only set when the deployment fronts the broker with an
/// SSO reverse proxy). `secret_from_env` wraps each env-supplied token
/// in `Zeroizing` so its heap buffer is wiped on return; the secrets
/// never live in unzeroed memory beyond the factory call. The two
/// families are independently mutually-exclusive: `HERMOD_BEARER_TOKEN`
/// vs `--bearer-command` is one mutex; `HERMOD_PROXY_BEARER_TOKEN` vs
/// `--proxy-bearer-command` is another. Within each family the secret
/// never inherits to a subprocess we spawn (the command source is
/// resolved as the only source if the env source is set).
fn build_target(
    cli: &Cli,
    home: &std::path::Path,
    socket: &Option<PathBuf>,
) -> anyhow::Result<client::ClientTarget> {
    if let Some(raw_url) = &cli.remote {
        let url = url::Url::parse(raw_url)
            .map_err(|e| anyhow::anyhow!("invalid --remote URL {raw_url:?}: {e}"))?;
        let pin = build_pin_policy(cli, &url, home)?;

        let daemon_args = bearer::BearerArgs {
            file: cli.bearer_file.clone(),
            command: cli.bearer_command.clone(),
        };
        let daemon_env = hermod_crypto::secret::secret_from_env("HERMOD_BEARER_TOKEN");
        let daemon_default = hermod_daemon::local_agent::implicit_bearer_default(home);
        let daemon = bearer::daemon_from_env_and_args(&daemon_args, daemon_env, daemon_default)?;

        let proxy_args = bearer::BearerArgs {
            file: cli.proxy_bearer_file.clone(),
            command: cli.proxy_bearer_command.clone(),
        };
        let proxy_env = hermod_crypto::secret::secret_from_env("HERMOD_PROXY_BEARER_TOKEN");
        let proxy = bearer::proxy_from_env_and_args(&proxy_args, proxy_env)?;

        let auth = client::RemoteAuth { daemon, proxy };
        Ok(client::ClientTarget::Remote { url, auth, pin })
    } else {
        Ok(client::ClientTarget::Local(socket_or_default(
            home,
            socket.clone(),
        )))
    }
}

fn build_pin_policy(
    cli: &Cli,
    url: &url::Url,
    home: &std::path::Path,
) -> anyhow::Result<pins::PinPolicy> {
    match &cli.pin {
        pins::PinArg::Insecure => Ok(pins::PinPolicy::Insecure),
        pins::PinArg::PublicCa => Ok(pins::PinPolicy::PublicCa),
        pins::PinArg::Fingerprint(fp) => Ok(pins::PinPolicy::Fingerprint(fp.clone())),
        pins::PinArg::Tofu => {
            let host = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("--remote URL missing host"))?;
            let port = url
                .port_or_known_default()
                .ok_or_else(|| anyhow::anyhow!("--remote URL missing port"))?;
            let host_port = format!("{host}:{port}");
            Ok(pins::PinPolicy::Tofu {
                store: pins::RemotePinStore::at_home(home),
                host_port,
            })
        }
    }
}
