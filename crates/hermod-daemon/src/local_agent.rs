//! Per-tenant identity material — one entry per local agent the
//! daemon hosts.
//!
//! ```text
//! $HERMOD_HOME/agents/<agent_id>/
//!   ed25519_secret   (mode 0600, 32 raw bytes — agent_keypair, envelope signing)
//!   bearer_token     (mode 0600, hex-encoded random bytes — IPC bearer for this agent)
//!   alias            (mode 0644, optional, single-line text — operator label)
//! ```
//!
//! The agent_keypair is the application-level signing key — every
//! envelope `from.id == agent_id` is signed under it. The bearer
//! token authenticates IPC clients as *this* agent: at the IPC
//! handshake (post-H3) the daemon hashes the presented bearer with
//! blake3 and looks up the matching `local_agents.agent_id` row.
//! The alias file is the operator-set source of truth for the
//! agent's `local_alias`, propagated to the agents directory at
//! every boot via [`merge_with_db`].
//!
//! Host-level material (Noise XX static key, TLS leaf cert) lives
//! in [`crate::host_identity`] — one host, many local agents, no
//! key sharing.

use anyhow::{Context, Result};
use hermod_core::{AgentAlias, AgentId, Timestamp};
use hermod_crypto::{Keypair, SecretString};
use hermod_storage::{AuditEntry, AuditSink, Database, LocalAgentRecord};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::fs_atomic::{write_public_atomic, write_secret_atomic};

pub fn agents_dir(home: &Path) -> PathBuf {
    home.join("agents")
}

pub fn agent_dir(home: &Path, id: &AgentId) -> PathBuf {
    agents_dir(home).join(id.as_str())
}

pub fn secret_path(home: &Path, id: &AgentId) -> PathBuf {
    agent_dir(home, id).join("ed25519_secret")
}

pub fn bearer_token_path(home: &Path, id: &AgentId) -> PathBuf {
    agent_dir(home, id).join("bearer_token")
}

pub fn alias_path(home: &Path, id: &AgentId) -> PathBuf {
    agent_dir(home, id).join("alias")
}

/// One local agent in memory — keypair (envelope signing), bearer
/// token (IPC auth), operator-set label, workspace context, and the
/// timestamp the daemon first persisted this agent.
///
/// The `local_alias` and `workspace_root` fields originate at
/// different times: alias is loaded from disk at scan time;
/// workspace_root flows back from the `local_agents` DB row during
/// [`merge_with_db`]. The DB read happens immediately after
/// scan_disk — by the time any caller outside this module sees a
/// `LocalAgent`, both fields reflect the persisted state.
#[derive(Clone, Debug)]
pub struct LocalAgent {
    pub agent_id: AgentId,
    pub keypair: Arc<Keypair>,
    pub bearer_token: Arc<SecretString>,
    pub local_alias: Option<AgentAlias>,
    pub workspace_root: Option<String>,
    pub created_at: Timestamp,
}

impl LocalAgent {
    pub fn bearer_hash(&self) -> [u8; 32] {
        bearer_hash(&self.bearer_token)
    }
}

/// Snapshot of every agent this daemon hosts. Built at boot from the
/// on-disk `$HERMOD_HOME/agents/<id>/` directories cross-checked
/// against the `local_agents` table; **immutable for the lifetime
/// of the daemon** in H2.
///
/// Phase H3 replaces the snapshot with a mutable, shared registry
/// (`Arc<RwLock<…>>` or similar) so that `hermod local rotate` can
/// atomically rotate a bearer in memory, on disk, in the DB, and
/// invalidate any active IPC session running under the previous
/// bearer (per-agent `Vec<oneshot::Sender<()>>`). Until then, the
/// only way to apply a rotation is to write the new bearer to disk
/// and restart the daemon — `merge_with_db` picks up the drift on
/// next boot.
#[derive(Clone, Debug, Default)]
pub struct LocalAgentRegistry {
    agents: Vec<LocalAgent>,
}

impl LocalAgentRegistry {
    pub fn from_agents(agents: Vec<LocalAgent>) -> Self {
        Self { agents }
    }

    pub fn list(&self) -> &[LocalAgent] {
        &self.agents
    }

    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    pub fn len(&self) -> usize {
        self.agents.len()
    }

    pub fn lookup(&self, id: &AgentId) -> Option<&LocalAgent> {
        self.agents.iter().find(|a| &a.agent_id == id)
    }

    /// Returns the lone hosted agent when the daemon hosts exactly
    /// one — the H2 single-tenant invariant — and `None` otherwise.
    /// Used by:
    ///
    /// - `server.rs::serve` to derive the daemon's envelope-signer
    ///   and self_id (returns an anyhow error on `None`).
    /// - `hermod bearer show` / `rotate` and `hermod identity` to
    ///   resolve the implicit agent without an `--alias` flag.
    /// - `local_agent::implicit_bearer_default` for the
    ///   `$HERMOD_HOME/agents/<bootstrap_id>/bearer_token` fallback
    ///   the CLI falls back to when no `--bearer-file` /
    ///   `HERMOD_BEARER_TOKEN` is set.
    ///
    /// Phase H3 removes the hard dependency in `server.rs` (every
    /// IPC call resolves its caller_agent at handshake time, no
    /// global "primary" needed). Phase H5 introduces multi-agent
    /// CLI flows so this method is purely a CLI-convenience surface
    /// after that.
    pub fn solo(&self) -> Option<&LocalAgent> {
        if self.agents.len() == 1 {
            self.agents.first()
        } else {
            None
        }
    }
}

/// Implicit default bearer-file path for CLI clients that don't pass
/// `--bearer-file` / `HERMOD_BEARER_TOKEN`. In the H2 single-tenant
/// shape every host owns exactly one local agent, and that agent's
/// bearer is the obvious fallback. When the assumption breaks
/// (no agent on disk, or multi-agent post-H5) this returns a sentinel
/// path that fails clearly at `FileBearerProvider::current` — the
/// operator sees the path in the error and reaches for
/// `--bearer-file` explicitly.
pub fn implicit_bearer_default(home: &Path) -> PathBuf {
    if let Ok(agents) = scan_disk_ids(home)
        && agents.len() == 1
    {
        return bearer_token_path(home, &agents[0]);
    }
    agents_dir(home).join("(no-implicit-default)/bearer_token")
}

/// Compute the `local_agents.bearer_hash` value for a token.
/// blake3 of the raw token bytes. Pinned here so the daemon and the
/// (future) `hermod local rotate` CLI agree on the canonical form.
pub fn bearer_hash(token: &SecretString) -> [u8; 32] {
    *blake3::hash(token.expose_secret().as_bytes()).as_bytes()
}

/// Generate a fresh per-agent bearer token: 32 random bytes
/// hex-encoded, 64 ASCII chars. Wrapped in `SecretString` so the
/// wrapper's ZeroizeOnDrop wipes the heap buffer when the caller is
/// done.
pub fn generate_bearer_token() -> SecretString {
    use rand::RngCore;
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *bytes);
    SecretString::new(hex::encode(bytes.as_slice()))
}

/// Materialise the bootstrap local agent on disk: generate a fresh
/// keypair, write `ed25519_secret` + `bearer_token` (mode 0600) and
/// the optional `alias` file (mode 0644) under
/// `$HERMOD_HOME/agents/<agent_id>/`.
///
/// Errors if any local agent already exists on disk — `hermod init
/// --force` is the documented path to wipe and re-provision.
pub fn create_bootstrap(home: &Path, alias: Option<AgentAlias>) -> Result<LocalAgent> {
    if !scan_disk_ids(home)?.is_empty() {
        anyhow::bail!(
            "{} already populated; archive and re-init via `hermod init --force` to provision a new bootstrap",
            agents_dir(home).display()
        );
    }
    let keypair = Arc::new(Keypair::generate());
    let agent_id = keypair.agent_id();
    ensure_agent_dir(home, &agent_id)?;

    let secret_p = secret_path(home, &agent_id);
    write_secret_atomic(&secret_p, &keypair.to_secret_seed())
        .with_context(|| format!("write {}", secret_p.display()))?;

    let bearer = Arc::new(generate_bearer_token());
    let bearer_p = bearer_token_path(home, &agent_id);
    write_secret_atomic(&bearer_p, bearer.expose_secret().as_bytes())
        .with_context(|| format!("write {}", bearer_p.display()))?;

    if let Some(a) = &alias {
        let alias_p = alias_path(home, &agent_id);
        write_public_atomic(&alias_p, a.as_str().as_bytes())
            .with_context(|| format!("write {}", alias_p.display()))?;
    }

    Ok(LocalAgent {
        agent_id,
        keypair,
        bearer_token: bearer,
        local_alias: alias,
        workspace_root: None,
        created_at: Timestamp::now(),
    })
}

/// Load one local agent's on-disk material. The directory name is
/// the agent_id and is verified against the loaded keypair's derived
/// id — a mismatch means filesystem corruption or operator hand-edit
/// and is fail-loud.
pub fn load(home: &Path, id: &AgentId) -> Result<LocalAgent> {
    let secret_p = secret_path(home, id);
    let bytes = fs::read(&secret_p).with_context(|| format!("read {}", secret_p.display()))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "expected 32-byte ed25519 secret at {}, got {} bytes",
            secret_p.display(),
            bytes.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    let keypair = Keypair::from_secret_seed(&seed);
    let derived = keypair.agent_id();
    if &derived != id {
        anyhow::bail!(
            "local agent directory {} contains a keypair whose agent_id is {} — \
             rename the directory or restore the correct secret",
            agent_dir(home, id).display(),
            derived
        );
    }

    let bearer_p = bearer_token_path(home, id);
    let bearer = hermod_crypto::secret::read_secret_file(&bearer_p)
        .with_context(|| format!("read {}", bearer_p.display()))?
        .ok_or_else(|| anyhow::anyhow!("bearer token file {} is empty", bearer_p.display()))?;

    Ok(LocalAgent {
        agent_id: derived,
        keypair: Arc::new(keypair),
        bearer_token: Arc::new(bearer),
        local_alias: read_alias(home, id)?,
        workspace_root: None,
        created_at: Timestamp::now(),
    })
}

/// Read the optional alias file. Missing file → `None`. Present-but-
/// empty after trim is also treated as `None` so an operator
/// `> alias` (truncate) drops the alias cleanly.
fn read_alias(home: &Path, id: &AgentId) -> Result<Option<AgentAlias>> {
    let p = alias_path(home, id);
    if !p.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let alias = AgentAlias::from_str(trimmed)
        .with_context(|| format!("parse alias from {}", p.display()))?;
    Ok(Some(alias))
}

/// Walk `$HERMOD_HOME/agents/` and return one `LocalAgent` per
/// subdirectory whose name parses as an `AgentId`. Subdirectories
/// with malformed names are reported as warnings and skipped — they
/// may be operator scratch (`tmp-*`, dotfiles) and should not crash
/// the daemon.
pub fn scan_disk(home: &Path) -> Result<Vec<LocalAgent>> {
    let dir = agents_dir(home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("read_dir {}", dir.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let id = match AgentId::from_str(name_str) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(
                    entry = name_str,
                    error = %e,
                    "skipping non-agent_id entry in agents/"
                );
                continue;
            }
        };
        out.push(load(home, &id).with_context(|| format!("load local agent {id}"))?);
    }
    Ok(out)
}

/// Just the agent_ids on disk, without loading any keypair / bearer
/// material. Used by `home_layout::audit` (the doctor surface) and
/// by CLI helpers that need to know "which agents exist" without the
/// authority to load their secrets.
pub fn scan_disk_ids(home: &Path) -> Result<Vec<AgentId>> {
    let dir = agents_dir(home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("read_dir {}", dir.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if let Ok(id) = AgentId::from_str(name_str) {
            out.push(id);
        }
    }
    Ok(out)
}

/// Load the boot-time registry by scanning `$HERMOD_HOME/agents/`.
/// Returns whatever's on disk — including an empty registry; this
/// function performs no provisioning, only reading. The daemon's
/// `main` refuses to boot when the registry is empty (the "run
/// `hermod init` first" path); `hermod init` is the only code site
/// that calls [`create_bootstrap`] to materialise the bootstrap on
/// disk.
pub fn load_registry(home: &Path) -> Result<LocalAgentRegistry> {
    Ok(LocalAgentRegistry::from_agents(scan_disk(home)?))
}

/// Cross-reference the in-memory snapshot against the `local_agents`
/// DB rows: every disk-resident agent must have a row, and each row
/// is folded back into the snapshot so `workspace_root` /
/// `created_at` reflect the persisted record (the disk has no notion
/// of either). When the on-disk `bearer_token` hash diverges from
/// the DB row's hash — typically because `hermod bearer rotate`
/// wrote a new file while the daemon was offline — the DB follows
/// disk and the rotation lands as an audit row.
pub async fn merge_with_db(
    db: &dyn Database,
    audit_sink: &dyn AuditSink,
    mut snapshot: LocalAgentRegistry,
) -> Result<LocalAgentRegistry> {
    for agent in snapshot.agents.iter_mut() {
        let bearer_hash = agent.bearer_hash();
        let existing = db
            .local_agents()
            .lookup_by_id(&agent.agent_id)
            .await
            .with_context(|| format!("lookup local_agent {}", agent.agent_id))?;
        if let Some(rec) = existing {
            agent.workspace_root = rec.workspace_root;
            agent.created_at = rec.created_at;
            if rec.bearer_hash != bearer_hash {
                let updated = db
                    .local_agents()
                    .rotate_bearer(&agent.agent_id, bearer_hash)
                    .await
                    .with_context(|| format!("rotate bearer for {}", agent.agent_id))?;
                if !updated {
                    anyhow::bail!(
                        "lookup found row for {} but rotate_bearer reported no rows updated",
                        agent.agent_id
                    );
                }
                audit_sink
                    .record(AuditEntry {
                        id: None,
                        ts: Timestamp::now(),
                        actor: agent.agent_id.clone(),
                        action: "local_agent.bearer_rotated_on_drift".into(),
                        target: Some(agent.agent_id.to_string()),
                        details: Some(serde_json::json!({
                            "previous_hash_prefix": hex::encode(&rec.bearer_hash[..4]),
                            "current_hash_prefix": hex::encode(&bearer_hash[..4]),
                        })),
                        client_ip: None,
                        federation: hermod_storage::AuditFederationPolicy::Default,
                    })
                    .await;
            }
        } else {
            let record = LocalAgentRecord {
                agent_id: agent.agent_id.clone(),
                bearer_hash,
                workspace_root: agent.workspace_root.clone(),
                created_at: agent.created_at,
            };
            db.local_agents()
                .insert(&record)
                .await
                .with_context(|| format!("insert local_agent row {}", agent.agent_id))?;
        }
    }
    Ok(snapshot)
}

#[cfg(unix)]
fn ensure_agent_dir(home: &Path, id: &AgentId) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let parent = agents_dir(home);
    if !parent.exists() {
        fs::create_dir_all(&parent)?;
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
    }
    let dir = agent_dir(home, id);
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_agent_dir(home: &Path, id: &AgentId) -> std::io::Result<()> {
    let parent = agents_dir(home);
    if !parent.exists() {
        fs::create_dir_all(&parent)?;
    }
    let dir = agent_dir(home, id);
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn create_bootstrap_writes_keypair_bearer_and_alias() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let alias = AgentAlias::from_str("projA").unwrap();
        let agent = create_bootstrap(tmp.path(), Some(alias.clone())).unwrap();
        let secret_p = secret_path(tmp.path(), &agent.agent_id);
        let bearer_p = bearer_token_path(tmp.path(), &agent.agent_id);
        let alias_p = alias_path(tmp.path(), &agent.agent_id);
        assert!(secret_p.exists());
        assert!(bearer_p.exists());
        assert!(alias_p.exists());
        assert_eq!(agent.local_alias, Some(alias));
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&secret_p).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&bearer_p).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&alias_p).unwrap().permissions().mode() & 0o777,
                0o644
            );
        }
    }

    #[test]
    fn create_bootstrap_refuses_on_pre_populated_dir() {
        let tmp = TempDir::new().unwrap();
        create_bootstrap(tmp.path(), None).unwrap();
        let err = create_bootstrap(tmp.path(), None).unwrap_err();
        assert!(
            format!("{err:#}").contains("already populated"),
            "got: {err:#}"
        );
    }

    #[test]
    fn load_round_trips_bootstrap_with_alias() {
        let tmp = TempDir::new().unwrap();
        let alias = AgentAlias::from_str("test-agent").unwrap();
        let written = create_bootstrap(tmp.path(), Some(alias.clone())).unwrap();
        let loaded = load(tmp.path(), &written.agent_id).unwrap();
        assert_eq!(loaded.agent_id, written.agent_id);
        assert_eq!(loaded.local_alias, Some(alias));
        assert_eq!(
            loaded.bearer_token.expose_secret(),
            written.bearer_token.expose_secret()
        );
    }

    #[test]
    fn load_treats_empty_alias_file_as_none() {
        let tmp = TempDir::new().unwrap();
        let agent = create_bootstrap(tmp.path(), None).unwrap();
        let alias_p = alias_path(tmp.path(), &agent.agent_id);
        fs::write(&alias_p, "   \n  ").unwrap();
        let loaded = load(tmp.path(), &agent.agent_id).unwrap();
        assert_eq!(loaded.local_alias, None);
    }

    #[test]
    fn load_rejects_mismatched_directory_name() {
        let tmp = TempDir::new().unwrap();
        let agent = create_bootstrap(tmp.path(), None).unwrap();
        let other = Keypair::generate().agent_id();
        fs::rename(
            agent_dir(tmp.path(), &agent.agent_id),
            agent_dir(tmp.path(), &other),
        )
        .unwrap();
        let err = load(tmp.path(), &other).unwrap_err();
        assert!(
            format!("{err:#}").contains("contains a keypair whose agent_id is"),
            "got: {err:#}"
        );
    }

    #[test]
    fn scan_disk_loads_every_agent_directory() {
        let tmp = TempDir::new().unwrap();
        let bootstrap = create_bootstrap(tmp.path(), None).unwrap();
        let got = scan_disk(tmp.path()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].agent_id, bootstrap.agent_id);
    }

    #[test]
    fn scan_disk_is_empty_when_dir_missing() {
        let tmp = TempDir::new().unwrap();
        assert!(scan_disk(tmp.path()).unwrap().is_empty());
    }

    #[test]
    fn scan_disk_skips_non_agent_id_entries() {
        let tmp = TempDir::new().unwrap();
        create_bootstrap(tmp.path(), None).unwrap();
        fs::create_dir_all(agents_dir(tmp.path()).join("tmp-scratch")).unwrap();
        let got = scan_disk(tmp.path()).unwrap();
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn load_registry_returns_empty_when_no_agents_on_disk() {
        let tmp = TempDir::new().unwrap();
        let reg = load_registry(tmp.path()).unwrap();
        assert!(reg.is_empty());
    }

    #[test]
    fn load_registry_returns_provisioned_bootstrap() {
        let tmp = TempDir::new().unwrap();
        let bootstrap = create_bootstrap(tmp.path(), None).unwrap();
        let reg = load_registry(tmp.path()).unwrap();
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.solo().unwrap().agent_id, bootstrap.agent_id);
    }

    #[test]
    fn bearer_hash_matches_blake3_over_token() {
        let token = SecretString::new("deadbeefcafe");
        let want = *blake3::hash(b"deadbeefcafe").as_bytes();
        assert_eq!(bearer_hash(&token), want);
    }

    #[test]
    fn implicit_bearer_default_points_at_lone_agent() {
        let tmp = TempDir::new().unwrap();
        let agent = create_bootstrap(tmp.path(), None).unwrap();
        let path = implicit_bearer_default(tmp.path());
        assert_eq!(path, bearer_token_path(tmp.path(), &agent.agent_id));
    }

    #[test]
    fn implicit_bearer_default_returns_sentinel_when_missing() {
        let tmp = TempDir::new().unwrap();
        let path = implicit_bearer_default(tmp.path());
        assert!(path.to_string_lossy().contains("(no-implicit-default)"));
    }
}
