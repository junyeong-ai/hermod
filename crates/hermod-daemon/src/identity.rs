use anyhow::{Context, Result};
use hermod_crypto::{Keypair, TlsMaterial};
use std::fs;
use std::path::{Path, PathBuf};

/// On-disk identity layout:
///
/// ```text
/// $HERMOD_HOME/
///   identity/
///     ed25519_secret   (mode 0600, 32 raw bytes)
///     tls.crt          (PEM cert; SubjectAlternativeNames cover localhost + 127.0.0.1 + ::1)
///     tls.key          (mode 0600, PEM private key)
/// ```
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

pub fn api_token_path(home: &Path) -> PathBuf {
    identity_dir(home).join("api_token")
}

/// Generate (if missing) the bearer token used to authenticate remote IPC
/// clients (`hermod --remote …`). 32 random bytes hex-encoded; mode 0600.
/// Idempotent: an existing file is read, never overwritten.
pub fn ensure_api_token(home: &Path) -> Result<String> {
    let p = api_token_path(home);
    if p.exists() {
        let s = fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
        return Ok(s.trim().to_string());
    }
    write_new_api_token(home)
}

/// Generate a fresh bearer token and atomically replace the on-disk file.
/// Returns the new token. After this call, every existing remote IPC
/// client must re-authenticate with the new token; the daemon must be
/// restarted (or the in-memory token hot-swapped) for it to take effect.
pub fn rotate_api_token(home: &Path) -> Result<String> {
    write_new_api_token(home)
}

fn write_new_api_token(home: &Path) -> Result<String> {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    let dir = identity_dir(home);
    fs::create_dir_all(&dir)?;
    restrict_dir_permissions(&dir)?;
    let p = api_token_path(home);
    write_secret_atomic(&p, token.as_bytes())?;
    Ok(token)
}

pub fn load(home: &Path) -> Result<Keypair> {
    let p = secret_path(home);
    enforce_secret_mode(&p)?;
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

/// Refuse to read the identity secret if it's accessible to anyone but
/// the owner. `hermod doctor` flags the same condition for operators
/// who haven't started the daemon yet; the boot-time check here is
/// the actual enforcement — a daemon that starts on a world-readable
/// secret has already lost the security argument before the first
/// envelope flies.
#[cfg(unix)]
fn enforce_secret_mode(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(p)
        .with_context(|| format!("stat identity secret {}", p.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "identity secret {} has insecure mode {:#o} \
             (group/other readable); refusing to start. \
             Run `chmod 0600 {}` and retry.",
            p.display(),
            mode,
            p.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_secret_mode(_p: &Path) -> Result<()> {
    // Non-Unix platforms have a different ACL model — the daemon
    // can't enforce the equivalent invariant from `metadata`. Operators
    // on those platforms are expected to confine `$HERMOD_HOME` via
    // the platform's native ACL tooling. `hermod doctor` flags the
    // unenforceable case for visibility.
    Ok(())
}

pub fn save(home: &Path, keypair: &Keypair) -> Result<PathBuf> {
    let dir = identity_dir(home);
    fs::create_dir_all(&dir)?;
    restrict_dir_permissions(&dir)?;
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
    let dir = identity_dir(home);
    fs::create_dir_all(&dir)?;
    restrict_dir_permissions(&dir)?;
    let material = TlsMaterial::generate(&keypair.agent_id()).context("generate TLS material")?;
    fs::write(&cert_p, &material.cert_pem)?;
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
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("secret"),
        std::process::id()
    ));

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
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

#[cfg(not(unix))]
fn write_secret_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::write(path, bytes)
}

#[cfg(unix)]
fn restrict_dir_permissions(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(dir, perms)
}

#[cfg(not(unix))]
fn restrict_dir_permissions(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}
