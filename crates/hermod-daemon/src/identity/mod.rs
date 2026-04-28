//! On-disk identity layout and the helpers that read / create the
//! files inside `$HERMOD_HOME/identity/`.
//!
//! Mode policy lives in [`layout`] — every file's required mode and
//! the boot-time enforcement that refuses to start on a breach. The
//! helpers here trust that the layout has already been ensured (boot
//! calls [`layout::ensure_dir`] before any of them run).
//!
//! ```text
//! $HERMOD_HOME/identity/
//!   ed25519_secret   (mode 0600, 32 raw bytes)
//!   tls.crt          (mode 0644, PEM cert; SAN covers localhost + 127.0.0.1 + ::1)
//!   tls.key          (mode 0600, PEM private key)
//!   bearer_token     (mode 0600, hex-encoded random bytes — Remote IPC bearer)
//! ```

pub mod layout;

use anyhow::{Context, Result};
use hermod_crypto::{Keypair, SecretString, TlsMaterial};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub fn identity_dir(home: &Path) -> PathBuf {
    home.join("identity")
}

pub fn secret_path(home: &Path) -> PathBuf {
    identity_dir(home).join("ed25519_secret")
}

pub fn tls_cert_path(home: &Path) -> PathBuf {
    identity_dir(home).join("tls.crt")
}

pub fn tls_key_path(home: &Path) -> PathBuf {
    identity_dir(home).join("tls.key")
}

pub fn bearer_token_path(home: &Path) -> PathBuf {
    identity_dir(home).join("bearer_token")
}

/// Generate (if missing) the bearer token used to authenticate remote IPC
/// clients (`hermod --remote …`). 32 random bytes hex-encoded; mode 0600.
/// Idempotent: an existing file is read, never overwritten.
pub fn ensure_bearer_token(home: &Path) -> Result<SecretString> {
    let p = bearer_token_path(home);
    if p.exists() {
        return hermod_crypto::secret::read_secret_file(&p)
            .with_context(|| format!("read {}", p.display()))?
            .ok_or_else(|| anyhow::anyhow!("bearer token file {} is empty", p.display()));
    }
    write_new_bearer_token(home)
}

/// Generate a fresh bearer token and atomically replace the on-disk file.
/// Returns the new token. After this call, every existing remote IPC
/// client must re-authenticate with the new token; the daemon must be
/// restarted (or the in-memory token hot-swapped) for it to take effect.
pub fn rotate_bearer_token(home: &Path) -> Result<SecretString> {
    write_new_bearer_token(home)
}

fn write_new_bearer_token(home: &Path) -> Result<SecretString> {
    use rand::RngCore;
    layout::ensure_dir(home)?;
    // Wrap the random bytes in `Zeroizing` so the stack array is wiped
    // when this function returns — same hygiene as `Keypair::generate`.
    // The hex-encoded `String` is moved into the returned
    // `SecretString`, which carries ZeroizeOnDrop forward.
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *bytes);
    // Borrow (via `as_slice`) — copying with `*bytes` would leave a
    // 32-byte unzeroed copy on `hex::encode`'s stack frame.
    let token = hex::encode(bytes.as_slice());
    let p = bearer_token_path(home);
    write_secret_atomic(&p, token.as_bytes())?;
    Ok(SecretString::new(token))
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
    layout::ensure_dir(home)?;
    let path = secret_path(home);
    write_secret_atomic(&path, &keypair.to_secret_seed())?;
    Ok(path)
}

/// Generate (if missing) the TLS keypair tied to this agent's identity. Idempotent.
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
    layout::ensure_dir(home)?;
    let material = TlsMaterial::generate(&keypair.agent_id()).context("generate TLS material")?;
    write_public_atomic(&cert_p, material.cert_pem.as_bytes())?;
    write_secret_atomic(&key_p, material.key_pem.as_bytes())?;
    Ok(material)
}

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

/// Atomically write `bytes` to `path` with mode 0600 from creation. The
/// secret never appears on disk in a partially-written or world-readable
/// state: we open a sibling temp file with the restrictive mode, write
/// the full payload, fsync, then rename over `path`. A crash before the
/// rename leaves the original file (or no file) intact.
#[cfg(unix)]
fn write_secret_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomic_with_mode(path, bytes, 0o600)
}

#[cfg(not(unix))]
fn write_secret_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

/// Atomically write `bytes` to `path` with mode 0644 from creation —
/// the public-file equivalent of [`write_secret_atomic`]. Used for
/// `tls.crt`, which peers fetch and the daemon must guarantee remains
/// readable + canonical-mode after every regenerate.
#[cfg(unix)]
fn write_public_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    write_atomic_with_mode(path, bytes, 0o644)
}

#[cfg(not(unix))]
fn write_public_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

#[cfg(unix)]
fn write_atomic_with_mode(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("file"),
        std::process::id()
    ));

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}
