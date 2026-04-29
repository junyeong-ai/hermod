//! Host-level identity material — the daemon's *network* identity,
//! distinct from the per-tenant agent identities the daemon hosts.
//!
//! ```text
//! $HERMOD_HOME/host/
//!   ed25519_secret   (mode 0600, 32 raw bytes — host_keypair)
//!   tls.crt          (mode 0644, PEM cert; SAN covers localhost + 127.0.0.1 + ::1)
//!   tls.key          (mode 0600, PEM private key)
//! ```
//!
//! The host_keypair is used for:
//!
//! - Noise XX static key on inbound + outbound federation handshakes
//! - TLS leaf cert generation (CN tied to host_id)
//! - `actor` field on audit rows the daemon emits for *itself* (outbox
//!   sweeper, janitor, federation accept) — bookkeeping done on behalf
//!   of the host, not any one local agent
//!
//! Per-agent envelope-signing keypairs and bearer tokens live under
//! `$HERMOD_HOME/agents/<agent_id>/` and are managed by
//! [`crate::local_agent`]. The split mirrors the data model: one host
//! address, many tenants.

use anyhow::{Context, Result};
use hermod_crypto::{Keypair, TlsMaterial};
use std::fs;
use std::path::{Path, PathBuf};

use crate::fs_atomic::{write_public_atomic, write_secret_atomic};

pub fn host_dir(home: &Path) -> PathBuf {
    home.join("host")
}

pub fn secret_path(home: &Path) -> PathBuf {
    host_dir(home).join("ed25519_secret")
}

pub fn tls_cert_path(home: &Path) -> PathBuf {
    host_dir(home).join("tls.crt")
}

pub fn tls_key_path(home: &Path) -> PathBuf {
    host_dir(home).join("tls.key")
}

pub fn load(home: &Path) -> Result<Keypair> {
    let p = secret_path(home);
    let bytes = fs::read(&p).with_context(|| format!("read {}", p.display()))?;
    if bytes.len() != 32 {
        anyhow::bail!(
            "expected 32-byte ed25519 secret at {}, got {} bytes",
            p.display(),
            bytes.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(Keypair::from_secret_seed(&seed))
}

pub fn save(home: &Path, keypair: &Keypair) -> Result<PathBuf> {
    ensure_host_dir(home)?;
    let path = secret_path(home);
    write_secret_atomic(&path, &keypair.to_secret_seed())?;
    Ok(path)
}

/// Load the host keypair, generating a fresh one if no secret exists
/// yet. Idempotent on repeated calls.
pub fn ensure_exists(home: &Path) -> Result<(Keypair, PathBuf)> {
    let p = secret_path(home);
    if p.exists() {
        Ok((load(home)?, p))
    } else {
        let kp = Keypair::generate();
        let path = save(home, &kp)?;
        Ok((kp, path))
    }
}

/// Generate (if missing) the TLS keypair tied to this host's identity.
/// Idempotent — an existing `tls.crt` + `tls.key` pair is loaded and
/// returned without regeneration.
pub fn ensure_tls(home: &Path, keypair: &Keypair) -> Result<TlsMaterial> {
    let cert_p = tls_cert_path(home);
    let key_p = tls_key_path(home);
    if cert_p.exists() && key_p.exists() {
        let cert_pem =
            fs::read_to_string(&cert_p).with_context(|| format!("read {}", cert_p.display()))?;
        let key_pem =
            fs::read_to_string(&key_p).with_context(|| format!("read {}", key_p.display()))?;
        return TlsMaterial::from_pem(cert_pem, key_pem)
            .with_context(|| "decode existing tls material");
    }
    ensure_host_dir(home)?;
    let material = TlsMaterial::generate(&keypair.agent_id()).context("generate TLS material")?;
    write_public_atomic(&cert_p, material.cert_pem.as_bytes())?;
    write_secret_atomic(&key_p, material.key_pem.as_bytes())?;
    Ok(material)
}

/// Create `$HERMOD_HOME/host/` at mode 0o700 if missing. Mirrors
/// `home_layout::ensure_dirs`'s discipline — a permissive existing
/// mode is the caller's problem, surfaced via the boot-time
/// `home_layout::enforce` check rather than silently chmod'd.
#[cfg(unix)]
fn ensure_host_dir(home: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = host_dir(home);
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_host_dir(home: &Path) -> std::io::Result<()> {
    let dir = host_dir(home);
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }
    Ok(())
}
