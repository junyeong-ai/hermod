//! Per-agent identity material — one entry per local tenant the daemon
//! hosts.
//!
//! ```text
//! $HERMOD_HOME/agents/<agent_id>/
//!   ed25519_secret   (mode 0600, optional — see "bootstrap shortcut" below)
//!   bearer_token     (mode 0600, hex-encoded random bytes — IPC bearer for this agent)
//! ```
//!
//! The agent_keypair is the application-level signing key — every
//! envelope `from.id == agent_id` is signed under it. The bearer token
//! authenticates IPC clients as *this* agent: at the IPC handshake
//! (post-H3) the daemon hashes the presented bearer with blake3 and
//! looks up the matching `local_agents.agent_id` row.
//!
//! ## Bootstrap shortcut (H2 single-tenant)
//!
//! The very first agent every host owns — the *bootstrap* — re-uses
//! the [`crate::host_identity`] keypair instead of carrying its own
//! `ed25519_secret`. Concretely:
//!
//! - `agent_id == host_id` (same blake3 derivation, identical bytes)
//! - On disk, the keypair lives only at `host/ed25519_secret`; the
//!   `agents/<host_id>/ed25519_secret` file is *absent*.
//! - `bearer_token` is still per-agent and lives under the agent dir.
//!
//! This preserves federation continuity in the H2 codebase: the Noise
//! XX handshake authenticates the host_keypair, and remote peers
//! verify envelope signatures under the same pubkey via the
//! `from.id == host_id` lookup. Phase H5 introduces `hermod local
//! add` which provisions *additional* agents with their own keypairs
//! at `agents/<new_id>/ed25519_secret`; those non-bootstrap agents
//! never share a keypair with the host.

use anyhow::{Context, Result};
use hermod_core::{AgentId, Timestamp};
use hermod_crypto::{Keypair, SecretString};
use hermod_storage::{Database, LocalAgentRecord};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::fs_atomic::write_secret_atomic;

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

/// One local agent in memory: keypair (envelope signing), bearer
/// token (IPC auth), and the operator-set workspace root that the MCP
/// server surfaces to Claude Code. The bootstrap agent's `keypair`
/// `Arc` is shared with the host; non-bootstrap agents own their own
/// `Keypair` instance.
#[derive(Clone, Debug)]
pub struct LocalAgent {
    pub agent_id: AgentId,
    pub keypair: Arc<Keypair>,
    pub bearer_token: Arc<SecretString>,
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
/// against the `local_agents` table; immutable for the lifetime of
/// the daemon. Phase H3 will replace the snapshot with a mutable
/// registry that hot-rotates bearer tokens and force-closes active
/// IPC sessions on rotate.
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

    /// Convenience for single-tenant flows (`hermod bearer show`,
    /// `hermod identity`, the `$HERMOD_HOME/agents/<id>/bearer_token`
    /// default the BearerProvider falls back to). Returns `Some` only
    /// when the daemon hosts exactly one agent — multi-agent
    /// callers must dispatch by agent_id explicitly.
    pub fn primary(&self) -> Option<&LocalAgent> {
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

/// Generate a fresh per-agent bearer token: 32 random bytes hex-encoded,
/// 64 ASCII chars. Wrapped in `SecretString` so the wrapper's
/// ZeroizeOnDrop wipes the heap buffer when the caller is done.
pub fn generate_bearer_token() -> SecretString {
    use rand::RngCore;
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *bytes);
    SecretString::new(hex::encode(bytes.as_slice()))
}

/// Provision the *bootstrap* local agent: agent_id == host_id, the
/// keypair is shared with [`crate::host_identity`], and the only new
/// file written under `agents/<host_id>/` is the bearer token. The
/// caller has already ensured `host/ed25519_secret` exists (via
/// `host_identity::ensure_exists`).
///
/// Idempotent on the bearer-token presence: if a bearer file already
/// exists at the canonical path (an interrupted earlier `hermod init`,
/// or the operator re-running `init` without `--force`), it's loaded
/// rather than overwritten.
pub fn provision_bootstrap(
    home: &Path,
    host_keypair: Arc<Keypair>,
    workspace_root: Option<String>,
) -> Result<LocalAgent> {
    let id = host_keypair.agent_id();
    ensure_agent_dir(home, &id)?;

    let bearer_p = bearer_token_path(home, &id);
    let bearer = if bearer_p.exists() {
        hermod_crypto::secret::read_secret_file(&bearer_p)
            .with_context(|| format!("read {}", bearer_p.display()))?
            .ok_or_else(|| anyhow::anyhow!("bearer token file {} is empty", bearer_p.display()))?
    } else {
        let fresh = generate_bearer_token();
        write_secret_atomic(&bearer_p, fresh.expose_secret().as_bytes())
            .with_context(|| format!("write {}", bearer_p.display()))?;
        fresh
    };

    Ok(LocalAgent {
        agent_id: id,
        keypair: host_keypair,
        bearer_token: Arc::new(bearer),
        workspace_root,
        created_at: Timestamp::now(),
    })
}

/// Load one local agent's on-disk material, given a host_keypair to
/// fall back to when the agent's keypair file is absent (the bootstrap
/// shortcut — see module docs).
///
/// For non-bootstrap agents (no shared host keypair, or `id !=
/// host_id`), `agents/<id>/ed25519_secret` MUST exist. The directory
/// name is the agent_id and is verified against the loaded keypair's
/// derived id — a mismatch means filesystem corruption or operator
/// hand-edit and is fail-loud.
pub fn load(home: &Path, id: &AgentId, host_keypair: Option<Arc<Keypair>>) -> Result<LocalAgent> {
    let secret_p = secret_path(home, id);
    let keypair: Arc<Keypair> = if secret_p.exists() {
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
        let kp = Keypair::from_secret_seed(&seed);
        let derived = kp.agent_id();
        if &derived != id {
            anyhow::bail!(
                "local agent directory {} contains a keypair whose agent_id is {} — \
                 rename the directory or restore the correct secret",
                agent_dir(home, id).display(),
                derived
            );
        }
        Arc::new(kp)
    } else {
        // No per-agent secret on disk — falls into the bootstrap
        // shortcut. The id MUST match the host keypair's id;
        // otherwise we have an orphan agent directory.
        let host = host_keypair.ok_or_else(|| {
            anyhow::anyhow!(
                "local agent {} has no ed25519_secret and no host_keypair fallback was provided",
                id
            )
        })?;
        if host.agent_id() != *id {
            anyhow::bail!(
                "local agent directory {} has no ed25519_secret and id {id} does not match \
                 host_id {host_id} — this is a stale or hand-edited entry; \
                 remove the directory or supply a matching keypair",
                agent_dir(home, id).display(),
                host_id = host.agent_id()
            );
        }
        host
    };

    let bearer_p = bearer_token_path(home, id);
    let bearer = hermod_crypto::secret::read_secret_file(&bearer_p)
        .with_context(|| format!("read {}", bearer_p.display()))?
        .ok_or_else(|| anyhow::anyhow!("bearer token file {} is empty", bearer_p.display()))?;

    Ok(LocalAgent {
        agent_id: id.clone(),
        keypair,
        bearer_token: Arc::new(bearer),
        workspace_root: None, // populated from DB record by the caller
        created_at: Timestamp::now(),
    })
}

/// Walk `$HERMOD_HOME/agents/` and return one `LocalAgent` per
/// subdirectory whose name parses as an `AgentId`. Subdirectories
/// with malformed names are reported as warnings and skipped — they
/// may be operator scratch (`tmp-*`, dotfiles) and should not crash
/// the daemon.
///
/// `host_keypair` is the host's keypair; when an agent dir lacks its
/// own `ed25519_secret`, this is used for the bootstrap shortcut.
/// `None` disables the shortcut, useful for CLI tools that don't load
/// host material (`hermod init` *before* host generation, plain
/// listing for diagnostics).
pub fn scan_disk(home: &Path, host_keypair: Option<Arc<Keypair>>) -> Result<Vec<LocalAgent>> {
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
        out.push(
            load(home, &id, host_keypair.clone())
                .with_context(|| format!("load local agent {id}"))?,
        );
    }
    Ok(out)
}

/// Just the agent_ids on disk, without loading any keypair / bearer
/// material. Used by `home_layout::audit` (the doctor surface) and by
/// CLI helpers that need to know "which agents exist" without the
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

/// Build the boot-time registry by scanning `$HERMOD_HOME/agents/`.
/// Returns whatever's on disk — including an empty registry. The
/// daemon's `main` refuses to boot when the registry is empty (the
/// "run `hermod init` first" path); `hermod init` is the only code
/// site that calls [`provision_bootstrap`] to create the bootstrap.
///
/// This split avoids a footgun: if `agents/` were silently
/// re-populated on daemon boot, an operator who accidentally deletes
/// the directory would wake up to a daemon happily running under a
/// brand-new agent_id and every federation peer's pin failing.
pub fn build_registry(home: &Path, host_keypair: Arc<Keypair>) -> Result<LocalAgentRegistry> {
    let agents = scan_disk(home, Some(host_keypair))?;
    Ok(LocalAgentRegistry::from_agents(agents))
}

/// Cross-reference the in-memory snapshot against the `local_agents`
/// DB rows: every disk-resident agent must have a row, and each row
/// is folded back into the snapshot so `workspace_root` /
/// `created_at` reflect the persisted record (the disk has no notion
/// of either). Returns the merged registry.
///
/// The matching `agents`-table upsert is performed by
/// `services::ensure_local_agents`; this function only touches the
/// `local_agents` sub-relation.
pub async fn merge_with_db(
    db: &dyn Database,
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
            // Disk bearer reflects ground truth; if the DB row drifted
            // (operator edited the file directly) recover by rotating
            // the hash. Same path `hermod local rotate` will use later.
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
            }
        } else {
            let record = LocalAgentRecord {
                agent_id: agent.agent_id.clone(),
                bearer_hash,
                workspace_root: agent.workspace_root.clone(),
                created_at: agent.created_at,
            };
            // The matching `agents` row is inserted by
            // `services::ensure_local_agents` before this call; without
            // it, the `local_agents` FK on agent_id would reject the
            // insert. Enforced by ordering at the caller site.
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

    fn fresh_host_keypair() -> Arc<Keypair> {
        Arc::new(Keypair::generate())
    }

    #[test]
    fn provision_bootstrap_writes_only_bearer_under_agent_dir() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let host = fresh_host_keypair();
        let agent =
            provision_bootstrap(tmp.path(), host.clone(), Some("/tmp/proj".into())).unwrap();
        assert_eq!(agent.agent_id, host.agent_id());
        let secret_p = secret_path(tmp.path(), &agent.agent_id);
        let bearer_p = bearer_token_path(tmp.path(), &agent.agent_id);
        assert!(
            !secret_p.exists(),
            "bootstrap should not write its own ed25519_secret — keypair lives at host/"
        );
        assert!(bearer_p.exists());
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&bearer_p).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(agents_dir(tmp.path()))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(agent_dir(tmp.path(), &agent.agent_id))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn provision_bootstrap_is_idempotent_on_bearer() {
        let tmp = TempDir::new().unwrap();
        let host = fresh_host_keypair();
        let first = provision_bootstrap(tmp.path(), host.clone(), None).unwrap();
        let second = provision_bootstrap(tmp.path(), host, None).unwrap();
        assert_eq!(
            first.bearer_token.expose_secret(),
            second.bearer_token.expose_secret(),
            "second provision_bootstrap must reuse the existing bearer file"
        );
    }

    #[test]
    fn load_uses_host_fallback_for_bootstrap() {
        let tmp = TempDir::new().unwrap();
        let host = fresh_host_keypair();
        let provisioned = provision_bootstrap(tmp.path(), host.clone(), None).unwrap();
        let loaded = load(tmp.path(), &provisioned.agent_id, Some(host.clone())).unwrap();
        assert_eq!(loaded.agent_id, host.agent_id());
        assert_eq!(
            loaded.keypair.to_secret_seed(),
            host.to_secret_seed(),
            "load should hand back the host keypair when the per-agent secret file is absent"
        );
    }

    #[test]
    fn load_rejects_orphan_dir_with_no_secret_and_mismatched_host() {
        let tmp = TempDir::new().unwrap();
        // Create an agents/<other_id>/ directory with no ed25519_secret.
        let other = Keypair::generate().agent_id();
        ensure_agent_dir(tmp.path(), &other).unwrap();
        // Bearer must be present for the read_secret_file step to be reached.
        let bearer = generate_bearer_token();
        write_secret_atomic(
            &bearer_token_path(tmp.path(), &other),
            bearer.expose_secret().as_bytes(),
        )
        .unwrap();

        let host = fresh_host_keypair();
        let err = load(tmp.path(), &other, Some(host)).unwrap_err();
        assert!(
            format!("{err:#}").contains("does not match host_id"),
            "expected host_id mismatch, got: {err:#}"
        );
    }

    #[test]
    fn scan_disk_loads_bootstrap_via_host_fallback() {
        let tmp = TempDir::new().unwrap();
        let host = fresh_host_keypair();
        provision_bootstrap(tmp.path(), host.clone(), None).unwrap();
        let agents = scan_disk(tmp.path(), Some(host.clone())).unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].agent_id, host.agent_id());
    }

    #[test]
    fn scan_disk_is_empty_when_dir_missing() {
        let tmp = TempDir::new().unwrap();
        let agents = scan_disk(tmp.path(), None).unwrap();
        assert!(agents.is_empty());
    }

    #[test]
    fn scan_disk_skips_non_agent_id_entries() {
        let tmp = TempDir::new().unwrap();
        let host = fresh_host_keypair();
        provision_bootstrap(tmp.path(), host.clone(), None).unwrap();
        fs::create_dir_all(agents_dir(tmp.path()).join("tmp-scratch")).unwrap();
        let agents = scan_disk(tmp.path(), Some(host.clone())).unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].agent_id, host.agent_id());
    }

    #[test]
    fn build_registry_returns_empty_when_no_agents_on_disk() {
        let tmp = TempDir::new().unwrap();
        let host = fresh_host_keypair();
        let reg = build_registry(tmp.path(), host).unwrap();
        assert!(reg.is_empty());
    }

    #[test]
    fn build_registry_returns_provisioned_bootstrap() {
        let tmp = TempDir::new().unwrap();
        let host = fresh_host_keypair();
        provision_bootstrap(tmp.path(), host.clone(), None).unwrap();
        let reg = build_registry(tmp.path(), host.clone()).unwrap();
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.primary().unwrap().agent_id, host.agent_id());
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
        let host = fresh_host_keypair();
        let agent = provision_bootstrap(tmp.path(), host.clone(), None).unwrap();
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
