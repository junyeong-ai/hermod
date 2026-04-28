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
    /// `HERMOD_BEARER_TOKEN` supplies the bearer; with none of those
    /// set the CLI falls back to `$HERMOD_HOME/identity/bearer_token`.
    #[arg(long, env = "HERMOD_REMOTE")]
    remote: Option<String>,

    /// File containing the bearer token for remote IPC. Plain-text
    /// contents; surrounding whitespace is trimmed. Re-read on each
    /// connect with a 30 s cache, so a `hermod bearer rotate` (or any
    /// external tool that updates the file) is picked up by the next
    /// connect without restarting the CLI.
    #[arg(long, env = "HERMOD_BEARER_FILE", requires = "remote")]
    bearer_file: Option<PathBuf>,

    /// Shell command that prints the bearer token to stdout. Invoked
    /// at connect time and re-invoked exactly once if the daemon
    /// rejects the token with HTTP 401 (e.g. expired OIDC ID token
    /// behind Google Cloud IAP). The command's trimmed stdout is sent
    /// verbatim as the `Authorization: Bearer <stdout>` value. Mutually
    /// exclusive with `--bearer-file` and `HERMOD_BEARER_TOKEN`.
    ///
    /// Example: `--bearer-command "gcloud auth print-identity-token --audiences=$IAP_CLIENT_ID"`
    #[arg(long, env = "HERMOD_BEARER_COMMAND", requires = "remote")]
    bearer_command: Option<String>,

    /// SHA-256 fingerprint of the remote daemon's TLS cert (any case;
    /// colons optional). When set, the connection fails loud if the
    /// presented cert doesn't match. When unset, the client TOFU-pins
    /// to `$HERMOD_HOME/remote_pins.json` on first connect.
    #[arg(long, env = "HERMOD_REMOTE_PIN")]
    pin: Option<String>,

    /// Skip TLS pinning entirely. Strictly opt-in for tests / known-LAN
    /// deployments where MITM is not a concern. Mutually exclusive with
    /// `--pin`.
    #[arg(long, default_value_t = false)]
    insecure_no_pin: bool,

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

    /// Query and verify the audit log.
    #[command(subcommand)]
    Audit(AuditCmd),

    /// Run the MCP server over stdio (called by Claude Code).
    Mcp,
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
    let cfg = hermod_daemon::config::Config::load_or_default(None, home)?;
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
fn build_target(
    cli: &Cli,
    home: &std::path::Path,
    socket: &Option<PathBuf>,
) -> anyhow::Result<client::ClientTarget> {
    if let Some(raw_url) = &cli.remote {
        let url = url::Url::parse(raw_url)
            .map_err(|e| anyhow::anyhow!("invalid --remote URL {raw_url:?}: {e}"))?;
        let pin = build_pin_policy(cli, &url, home)?;
        let bearer_args = bearer::BearerArgs {
            bearer_file: cli.bearer_file.clone(),
            bearer_command: cli.bearer_command.clone(),
        };
        // `secret_from_env` wraps the raw env String in `Zeroizing` so
        // its heap buffer is wiped when the helper returns; the secret
        // never lives in unzeroed memory beyond the returned
        // SecretString. (Process env-table cleanup is unnecessary
        // here: HERMOD_BEARER_TOKEN and --bearer-command are mutually
        // exclusive at the factory, so the secret never inherits to a
        // subprocess we spawn.)
        let env_token = hermod_crypto::secret::secret_from_env("HERMOD_BEARER_TOKEN");
        let default_path = Some(hermod_daemon::identity::bearer_token_path(home));
        let provider = bearer::from_env_and_args(&bearer_args, env_token, default_path)?;
        Ok(client::ClientTarget::Remote { url, provider, pin })
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
    if cli.insecure_no_pin && cli.pin.is_some() {
        return Err(anyhow::anyhow!(
            "--insecure-no-pin and --pin are mutually exclusive"
        ));
    }
    if cli.insecure_no_pin {
        return Ok(pins::PinPolicy::InsecureNoVerify);
    }
    if let Some(raw) = &cli.pin {
        let normalized = pins::PinPolicy::normalize_fingerprint(raw)?;
        return Ok(pins::PinPolicy::Explicit(normalized));
    }
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
