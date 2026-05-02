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
//! handshake the daemon hashes the presented bearer with blake3 and
//! looks up the matching agent_id via [`LocalAgentRegistry::resolve_bearer`].
//! The alias file is the operator-set source of truth for the
//! agent's `local_alias`.
//!
//! Host-level material (Noise XX static key, TLS leaf cert) lives
//! in [`crate::host_identity`] — one host, many local agents, no
//! key sharing.
//!
//! ## Mutability + active-session invalidation
//!
//! [`LocalAgentRegistry`] is interior-mutable behind an
//! `Arc<RwLock<…>>`. Reads (`list`, `lookup`, `solo`,
//! `resolve_bearer`) take a read lock; mutations (`insert`,
//! `remove`, `replace_bearer`) take a write lock and atomically
//! refresh the bearer-hash → agent_id index. On `remove` /
//! `replace_bearer`, every active IPC session pinned to the
//! agent's previous bearer is force-closed via a per-session
//! `oneshot::Sender<()>` registered by `ipc_remote`.

use anyhow::{Context, Result};
use hermod_core::{AgentAlias, AgentId, Timestamp};
use hermod_crypto::{Keypair, SecretString};
use hermod_storage::{AuditEntry, AuditSink, Database, LocalAgentRecord};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use tokio::sync::oneshot;
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

/// Mutable in-memory registry of every agent this daemon hosts. All
/// services hold a clone (cheap — `Arc<RwLock<...>>`); reads see the
/// current state, mutations are applied atomically + propagated to
/// the bearer-hash index + active IPC sessions.
#[derive(Clone, Debug, Default)]
pub struct LocalAgentRegistry {
    inner: Arc<RwLock<RegistryInner>>,
}

#[derive(Debug, Default)]
struct RegistryInner {
    agents: Vec<LocalAgent>,
    /// blake3(bearer_token) → agent_id, rebuilt on every mutation.
    bearer_index: HashMap<[u8; 32], AgentId>,
    /// Per-agent shutdown channels for active IPC sessions, keyed
    /// by a per-session id so a clean disconnect can remove its own
    /// entry via [`SessionGuard`]. Mutations that invalidate a
    /// bearer (rotate / remove) fire every sender in the agent's
    /// inner map so all of its open connections close out.
    sessions: HashMap<AgentId, HashMap<u64, oneshot::Sender<()>>>,
    /// Monotonic counter for session ids. Wraps after 2^64 — that's
    /// "forever" for a real daemon; the `HashMap` would clash on
    /// wrap, so use saturating semantics on the realistic side.
    next_session_id: u64,
}

impl LocalAgentRegistry {
    pub fn from_agents(agents: Vec<LocalAgent>) -> Self {
        let mut inner = RegistryInner::default();
        for a in agents {
            inner
                .bearer_index
                .insert(a.bearer_hash(), a.agent_id.clone());
            inner.agents.push(a);
        }
        Self {
            inner: Arc::new(RwLock::new(inner)),
        }
    }

    /// Acquire a read lock, recovering from poison. A panic in any
    /// holder of the write lock would otherwise leave the daemon
    /// permanently stuck (every subsequent registry call would
    /// re-panic). After recovery the data may be mid-mutation, but
    /// each mutation site is short and structurally simple — the
    /// half-applied state is "an agent vec slightly stale w.r.t.
    /// its bearer index" which the next successful write repairs.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, RegistryInner> {
        self.inner.read().unwrap_or_else(|p| p.into_inner())
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, RegistryInner> {
        self.inner.write().unwrap_or_else(|p| p.into_inner())
    }

    /// Snapshot of every hosted agent. Cheap clone — the heavy
    /// fields (`keypair`, `bearer_token`) are `Arc`-shared.
    pub fn list(&self) -> Vec<LocalAgent> {
        self.read().agents.clone()
    }

    pub fn is_empty(&self) -> bool {
        self.read().agents.is_empty()
    }

    pub fn len(&self) -> usize {
        self.read().agents.len()
    }

    pub fn lookup(&self, id: &AgentId) -> Option<LocalAgent> {
        self.read()
            .agents
            .iter()
            .find(|a| &a.agent_id == id)
            .cloned()
    }

    /// Returns the lone hosted agent when the daemon hosts exactly
    /// one. Used by the local Unix-socket IPC path to bind a
    /// single-tenant convenience caller, by `hermod identity` to
    /// resolve the implicit agent without an `--alias` flag, and by
    /// `local_agent::implicit_bearer_default`.
    pub fn solo(&self) -> Option<LocalAgent> {
        let g = self.read();
        if g.agents.len() == 1 {
            g.agents.first().cloned()
        } else {
            None
        }
    }

    /// Hash `token` with blake3 and return the matching agent_id.
    /// Read-only — does NOT register a session. Used by tests and
    /// diagnostics; the hot path uses [`Self::resolve_and_register_bearer`]
    /// to close the resolve-vs-rotate race window.
    pub fn resolve_bearer(&self, token: &str) -> Option<AgentId> {
        let hash: [u8; 32] = *blake3::hash(token.as_bytes()).as_bytes();
        self.read().bearer_index.get(&hash).cloned()
    }

    /// Atomic bearer lookup + session registration. Used by the
    /// IPC handshake's auth callback — by combining lookup and
    /// register under one write lock, a concurrent `local rotate`
    /// either:
    ///   - fires before this call: the lookup misses, the connection
    ///     gets 401;
    ///   - fires after: the new session is in the sessions map and
    ///     `replace_bearer` fires its shutdown sender immediately.
    ///
    /// Returns the resolved `agent_id`, an RAII guard that removes
    /// the session on drop (so a clean client disconnect doesn't
    /// leak a `oneshot::Sender` in the registry), and the receiver
    /// the connection's `select!` watches for shutdown.
    pub fn resolve_and_register_bearer(
        &self,
        token: &str,
    ) -> Option<(AgentId, SessionGuard, oneshot::Receiver<()>)> {
        let hash: [u8; 32] = *blake3::hash(token.as_bytes()).as_bytes();
        let mut g = self.write();
        let agent_id = g.bearer_index.get(&hash).cloned()?;
        let session_id = g.next_session_id;
        g.next_session_id = g.next_session_id.wrapping_add(1);
        let (tx, rx) = oneshot::channel();
        g.sessions
            .entry(agent_id.clone())
            .or_default()
            .insert(session_id, tx);
        let guard = SessionGuard {
            inner: self.inner.clone(),
            agent_id: agent_id.clone(),
            session_id,
        };
        Some((agent_id, guard, rx))
    }

    /// Insert a freshly-provisioned agent. Refreshes the bearer
    /// index. Returns an error if `agent_id` already exists — the
    /// caller should `replace_bearer` instead.
    pub fn insert(&self, agent: LocalAgent) -> Result<()> {
        let mut g = self.write();
        if g.agents.iter().any(|a| a.agent_id == agent.agent_id) {
            anyhow::bail!("agent {} already in registry", agent.agent_id);
        }
        g.bearer_index
            .insert(agent.bearer_hash(), agent.agent_id.clone());
        g.agents.push(agent);
        Ok(())
    }

    /// Remove an agent. Drops its bearer from the index, fires every
    /// shutdown sender registered against it, and returns whether a
    /// row was present.
    pub fn remove(&self, id: &AgentId) -> bool {
        let mut g = self.write();
        let pos = g.agents.iter().position(|a| &a.agent_id == id);
        let Some(idx) = pos else {
            return false;
        };
        let removed = g.agents.remove(idx);
        g.bearer_index.remove(&removed.bearer_hash());
        if let Some(senders) = g.sessions.remove(id) {
            for (_id, tx) in senders {
                let _ = tx.send(());
            }
        }
        true
    }

    /// Swap an agent's bearer token. Replaces the bearer-index entry
    /// atomically (old hash dropped, new hash inserted) and force-
    /// closes any session still using the previous bearer.
    pub fn replace_bearer(&self, id: &AgentId, new_bearer: SecretString) -> bool {
        let mut g = self.write();
        let Some(agent) = g.agents.iter_mut().find(|a| &a.agent_id == id) else {
            return false;
        };
        let prior_hash = agent.bearer_hash();
        agent.bearer_token = Arc::new(new_bearer);
        let new_hash = agent.bearer_hash();
        g.bearer_index.remove(&prior_hash);
        g.bearer_index.insert(new_hash, id.clone());
        if let Some(senders) = g.sessions.remove(id) {
            for (_id, tx) in senders {
                let _ = tx.send(());
            }
        }
        true
    }

    /// Update `local_alias` in memory (the disk-side change is
    /// driven by the caller, since registry doesn't know `home`).
    pub fn update_alias(&self, id: &AgentId, alias: Option<AgentAlias>) -> bool {
        let mut g = self.write();
        let Some(agent) = g.agents.iter_mut().find(|a| &a.agent_id == id) else {
            return false;
        };
        agent.local_alias = alias;
        true
    }
}

/// Drop-on-disconnect cleanup for an active IPC session. Returned by
/// [`LocalAgentRegistry::resolve_and_register_bearer`]; held alive by
/// the connection's task tree for the duration of the session.
///
/// On drop (clean disconnect, panic, or any other path that unwinds
/// the connection's stack) the guard removes its own entry from the
/// registry's `sessions` map. Without this, a long-running daemon
/// with frequent connect/disconnect cycles would accumulate
/// `oneshot::Sender`s indefinitely — every closed connection's
/// shutdown channel would stay in the agent's session list forever
/// even though its receiver was already dropped.
///
/// `rotate` / `remove` mutations remove the agent's entire session
/// table in one swap; the guard's drop becomes a no-op in that case
/// (the inner `sessions[agent_id]` HashMap is already gone), which
/// is correct.
#[derive(Debug)]
pub struct SessionGuard {
    inner: Arc<RwLock<RegistryInner>>,
    agent_id: AgentId,
    session_id: u64,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let mut g = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(map) = g.sessions.get_mut(&self.agent_id) {
            map.remove(&self.session_id);
            if map.is_empty() {
                g.sessions.remove(&self.agent_id);
            }
        }
    }
}

/// Implicit default bearer-file path for CLI clients that don't pass
/// `--bearer-file` / `HERMOD_BEARER_TOKEN`. With one local agent on
/// disk, points at its bearer; otherwise returns a sentinel path so
/// `FileBearerProvider::current` fails clearly with the path in the
/// diagnostic.
pub fn implicit_bearer_default(home: &Path) -> PathBuf {
    if let Ok(agents) = scan_disk_ids(home)
        && agents.len() == 1
    {
        return bearer_token_path(home, &agents[0]);
    }
    agents_dir(home).join("(no-implicit-default)/bearer_token")
}

/// Compute the `local_agents.bearer_hash` value for a token.
/// blake3 of the raw token bytes.
pub fn bearer_hash(token: &SecretString) -> [u8; 32] {
    *blake3::hash(token.expose_secret().as_bytes()).as_bytes()
}

/// Generate a fresh per-agent bearer token: 32 random bytes
/// hex-encoded, 64 ASCII chars. Wrapped in `SecretString` so
/// `ZeroizeOnDrop` wipes the heap buffer at end of scope.
pub fn generate_bearer_token() -> SecretString {
    use rand::RngCore;
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *bytes);
    SecretString::new(hex::encode(bytes.as_slice()))
}

/// Materialise the bootstrap local agent on disk.
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
    write_new_agent(home, alias)
}

/// Materialise an *additional* local agent (sibling to an existing
/// bootstrap). Used by `hermod local add`.
pub fn create_additional(home: &Path, alias: Option<AgentAlias>) -> Result<LocalAgent> {
    if let Some(a) = &alias {
        for id in scan_disk_ids(home)? {
            if let Some(existing) = read_alias(home, &id)?
                && existing == *a
            {
                anyhow::bail!(
                    "alias `{}` is already bound to local agent {} — pick another or `hermod local rm` first",
                    a.as_str(),
                    id
                );
            }
        }
    }
    write_new_agent(home, alias)
}

fn write_new_agent(home: &Path, alias: Option<AgentAlias>) -> Result<LocalAgent> {
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

/// Generate and atomically install a fresh bearer token for an
/// existing local agent. Returns the new token; caller is
/// responsible for updating the registry + DB.
pub fn rotate_bearer_on_disk(home: &Path, id: &AgentId) -> Result<SecretString> {
    if !secret_path(home, id).exists() {
        anyhow::bail!(
            "no local agent {id} on disk at {}",
            agent_dir(home, id).display()
        );
    }
    let new_token = generate_bearer_token();
    let bearer_p = bearer_token_path(home, id);
    write_secret_atomic(&bearer_p, new_token.expose_secret().as_bytes())
        .with_context(|| format!("write {}", bearer_p.display()))?;
    Ok(new_token)
}

/// Move `agents/<id>/` into a timestamped archive subtree. The
/// directory's keypair, bearer, and any alias file move together.
pub fn archive_agent(home: &Path, id: &AgentId) -> Result<PathBuf> {
    let src = agent_dir(home, id);
    if !src.exists() {
        anyhow::bail!(
            "no local agent {id} on disk at {} — nothing to archive",
            src.display()
        );
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string());
    let archive_root = home.join("archive").join(stamp).join("agents");
    fs::create_dir_all(&archive_root)
        .with_context(|| format!("create {}", archive_root.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let parent = archive_root
            .parent()
            .expect("archive_root has parent by construction");
        if parent.exists() {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .with_context(|| format!("chmod {}", parent.display()))?;
        }
        fs::set_permissions(&archive_root, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod {}", archive_root.display()))?;
    }
    let dst = archive_root.join(id.as_str());
    fs::rename(&src, &dst)
        .with_context(|| format!("move {} → {}", src.display(), dst.display()))?;
    Ok(dst)
}

/// Load one local agent's on-disk material.
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
/// subdirectory whose name parses as an `AgentId`.
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
pub fn load_registry(home: &Path) -> Result<LocalAgentRegistry> {
    Ok(LocalAgentRegistry::from_agents(scan_disk(home)?))
}

/// Cross-reference the in-memory snapshot against the `local_agents`
/// DB rows and reconcile drift (operator wrote a fresh bearer to
/// disk while the daemon was offline → DB row's `bearer_hash`
/// follows disk + an audit row records the rotation).
pub async fn merge_with_db(
    db: &dyn Database,
    audit_sink: &dyn AuditSink,
    snapshot: LocalAgentRegistry,
) -> Result<LocalAgentRegistry> {
    // Snapshot the agents, mutate fields in a private vec, then
    // overwrite the registry's interior. `from_agents` rebuilds
    // the bearer index on the way back in.
    let mut agents = snapshot.list();
    for agent in agents.iter_mut() {
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
                tags: hermod_core::CapabilityTagSet::empty(),
            };
            db.local_agents()
                .insert(&record)
                .await
                .with_context(|| format!("insert local_agent row {}", agent.agent_id))?;
        }
    }
    Ok(LocalAgentRegistry::from_agents(agents))
}

#[cfg(unix)]
pub(crate) fn ensure_agent_dir(home: &Path, id: &AgentId) -> std::io::Result<()> {
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
pub(crate) fn ensure_agent_dir(home: &Path, id: &AgentId) -> std::io::Result<()> {
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
    fn registry_resolve_bearer_round_trips() {
        let tmp = TempDir::new().unwrap();
        let agent = create_bootstrap(tmp.path(), None).unwrap();
        let token = agent.bearer_token.expose_secret().to_string();
        let registry = LocalAgentRegistry::from_agents(vec![agent.clone()]);
        assert_eq!(registry.resolve_bearer(&token), Some(agent.agent_id));
        assert_eq!(registry.resolve_bearer("nope"), None);
    }

    #[test]
    fn registry_remove_drops_bearer_and_fires_session() {
        let tmp = TempDir::new().unwrap();
        let agent = create_bootstrap(tmp.path(), None).unwrap();
        let token = agent.bearer_token.expose_secret().to_string();
        let registry = LocalAgentRegistry::from_agents(vec![agent.clone()]);
        let (_id, _guard, mut rx) = registry
            .resolve_and_register_bearer(&token)
            .expect("bearer resolves");
        assert!(rx.try_recv().is_err(), "no shutdown until removed");
        assert!(registry.remove(&agent.agent_id));
        assert_eq!(registry.resolve_bearer(&token), None);
        assert!(rx.try_recv().is_ok(), "session shutdown fires on remove");
    }

    #[test]
    fn registry_replace_bearer_swaps_and_fires_session() {
        let tmp = TempDir::new().unwrap();
        let agent = create_bootstrap(tmp.path(), None).unwrap();
        let old = agent.bearer_token.expose_secret().to_string();
        let registry = LocalAgentRegistry::from_agents(vec![agent.clone()]);
        let (_id, _guard, mut rx) = registry
            .resolve_and_register_bearer(&old)
            .expect("bearer resolves");
        let new_token = generate_bearer_token();
        let new_str = new_token.expose_secret().to_string();
        assert!(registry.replace_bearer(&agent.agent_id, new_token));
        assert_eq!(registry.resolve_bearer(&old), None, "old bearer revoked");
        assert_eq!(
            registry.resolve_bearer(&new_str),
            Some(agent.agent_id.clone()),
            "new bearer accepted"
        );
        assert!(rx.try_recv().is_ok(), "session shutdown fires on rotate");
    }

    #[test]
    fn session_guard_drop_cleans_up_on_clean_disconnect() {
        // The leak this test guards against: a connection that closed
        // normally (no rotate / no remove) used to leave its
        // `oneshot::Sender` in `sessions[agent]` forever. Now the
        // RAII guard removes its own entry on drop; sustained
        // connect/disconnect churn no longer accumulates senders.
        let tmp = TempDir::new().unwrap();
        let agent = create_bootstrap(tmp.path(), None).unwrap();
        let token = agent.bearer_token.expose_secret().to_string();
        let registry = LocalAgentRegistry::from_agents(vec![agent.clone()]);

        // Open + drop 100 sessions with no mutation in between. After
        // every drop the agent's session table should be gone (or
        // empty) — the guard's Drop impl removes the entry and, when
        // empty, the agent key.
        for _ in 0..100 {
            let (_id, guard, _rx) = registry
                .resolve_and_register_bearer(&token)
                .expect("bearer resolves");
            drop(guard);
        }
        let g = registry.read();
        assert!(
            g.sessions.get(&agent.agent_id).is_none_or(|m| m.is_empty()),
            "drop-on-disconnect must clean up the per-session entry",
        );
    }

    #[test]
    fn resolve_and_register_returns_none_for_unknown_bearer() {
        // Atomic check: an unknown bearer must not get a session row
        // — otherwise the rotate-vs-resolve race window stays open.
        let tmp = TempDir::new().unwrap();
        let agent = create_bootstrap(tmp.path(), None).unwrap();
        let registry = LocalAgentRegistry::from_agents(vec![agent.clone()]);
        assert!(registry.resolve_and_register_bearer("nope").is_none());
        let g = registry.read();
        assert!(
            g.sessions.is_empty(),
            "unknown bearer must not register a session",
        );
    }

    #[test]
    fn registry_insert_rejects_duplicate_id() {
        let tmp = TempDir::new().unwrap();
        let agent = create_bootstrap(tmp.path(), None).unwrap();
        let registry = LocalAgentRegistry::from_agents(vec![agent.clone()]);
        let err = registry.insert(agent).unwrap_err();
        assert!(format!("{err:#}").contains("already in registry"));
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
