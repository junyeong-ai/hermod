//! Wrapper for an in-memory string secret that zeroizes on drop and refuses
//! to render itself in `Debug`/`Display` output.
//!
//! Used for any text-shaped secret the daemon or CLI holds at runtime —
//! IPC bearer tokens, command-minted OIDC tokens, audit-webhook bearers.
//! The discipline mirrors the rest of the secret types in this crate
//! (`Keypair`, `WorkspaceSecret`, `WorkspaceMacKey`, `ChannelMacKey`):
//! `#[derive(Zeroize, ZeroizeOnDrop)]` so the buffer is wiped on Drop,
//! `Display` is intentionally not implemented so the only way to read
//! the bytes is to call [`SecretString::expose_secret`] explicitly.
//!
//! Equality is also intentionally not derived — generic `==` on secrets
//! leaks timing. Security-sensitive comparison must spell out
//! `expose_secret()` and route through a constant-time primitive.
//!
//! ## Boundary helpers
//!
//! Building a `SecretString` from an external source ([`read_secret_file`],
//! [`secret_from_env`]) routes the raw bytes through a `Zeroizing` buffer
//! so the *source* allocation is wiped after the secret is copied — not
//! just the destination `SecretString`. Without these helpers a naive
//! `SecretString::new(std::fs::read_to_string(p)?.trim().to_string())`
//! leaves the original `String`'s heap buffer un-zeroed at scope exit,
//! defeating the point of the wrapper.

use serde::{Deserialize, Deserializer};
use std::fmt;
use std::io;
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Heap-allocated string secret. `Drop` zeroes the backing buffer.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Expose the underlying bytes for an explicit, named purpose
    /// (Authorization header, constant-time comparison). The caller is
    /// responsible for not propagating the borrowed slice into formatting.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Whether the secret is the empty string. Useful for
    /// "is this populated" checks at boundary points (env-var
    /// processing, file-read validation) without exposing the bytes.
    /// `len()` is intentionally not provided — it's a strictly larger
    /// side-channel (token length distinguishes auth providers) for no
    /// additional caller utility.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

/// `Deserialize` consumes the String produced by the deserializer
/// directly into the `SecretString`, so the bytes never live in an
/// un-zeroed buffer beyond the duration of the deserialization call
/// itself. `Serialize` is intentionally not implemented — secrets
/// should not round-trip through TOML / JSON output. Configuration
/// fields that hold a `SecretString` must be marked
/// `#[serde(skip_serializing)]` to opt out of the default
/// `derive(Serialize)` requirement on their parent struct.
impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(SecretString::new(raw))
    }
}

/// Read a text secret from disk and return it trimmed.
///
/// The intermediate `String` from `std::fs::read_to_string` is wrapped
/// in `Zeroizing` so its heap buffer is wiped on scope exit — the
/// secret bytes don't outlive this function in any allocation but the
/// returned `SecretString`. An empty trimmed result returns
/// `Ok(None)` so the caller can distinguish "file present but empty"
/// from "file missing" without reading the bytes.
pub fn read_secret_file(path: &Path) -> io::Result<Option<SecretString>> {
    let raw = Zeroizing::new(std::fs::read_to_string(path)?);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(SecretString::new(trimmed.to_owned())))
    }
}

/// Read a text secret from the process environment, trimming.
///
/// `std::env::var` clones the raw bytes into a `String`; that buffer
/// is wrapped in `Zeroizing` so it's wiped when this function returns
/// — the secret never lives in unzeroed memory beyond this function
/// except in the returned `SecretString`. Returns `None` for missing
/// or empty (post-trim) values.
pub fn secret_from_env(var: &str) -> Option<SecretString> {
    let raw = Zeroizing::new(std::env::var(var).ok()?);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(SecretString::new(trimmed.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts() {
        let s = SecretString::new("super-secret-token");
        let rendered = format!("{:?}", s);
        assert!(!rendered.contains("super-secret-token"));
        assert_eq!(rendered, "SecretString(<redacted>)");
    }

    #[test]
    fn expose_returns_underlying_bytes() {
        let s = SecretString::new("eyJhbGc...");
        assert_eq!(s.expose_secret(), "eyJhbGc...");
    }

    #[test]
    fn equality_is_explicit_only() {
        // Equality is intentionally not derived — tests and any other
        // non-security comparison must spell out `expose_secret()` on
        // both sides. Security comparisons go through constant-time
        // primitives in the consuming crate (e.g. `constant_time_eq`
        // in hermod-crypto::workspace).
        let a = SecretString::new("a");
        let b = SecretString::new("a");
        assert_eq!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn is_empty_does_not_expose_bytes() {
        assert!(SecretString::new("").is_empty());
        assert!(!SecretString::new("x").is_empty());
    }

    #[test]
    fn read_secret_file_trims_and_handles_empty() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s");

        std::fs::write(&p, "  abc-tok\n  ").unwrap();
        let s = read_secret_file(&p).unwrap().unwrap();
        assert_eq!(s.expose_secret(), "abc-tok");

        std::fs::write(&p, "   \n  ").unwrap();
        assert!(read_secret_file(&p).unwrap().is_none());
    }

    #[test]
    fn read_secret_file_propagates_io_error() {
        let err = read_secret_file(Path::new("/definitely/not/here")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn deserializes_from_toml_and_json() {
        // Verify the Deserialize impl consumes the deserialized String
        // directly (no intermediate copy left behind in the
        // deserializer call frame visible to the caller). We can't
        // observe the heap, so we just verify the value lands intact.
        #[derive(Deserialize)]
        struct Holder {
            tok: SecretString,
        }
        let toml_v: Holder = toml::from_str(r#"tok = "abc""#).unwrap();
        assert_eq!(toml_v.tok.expose_secret(), "abc");

        let json_v: Holder = serde_json::from_str(r#"{"tok":"def"}"#).unwrap();
        assert_eq!(json_v.tok.expose_secret(), "def");
    }

    #[test]
    fn secret_from_env_trims_and_drops_empty() {
        // SAFETY: this test mutates env, but tests in this mod stay
        // single-threaded relative to env access — each uses a unique
        // var name and doesn't read variables modified by sibling
        // tests. The only purpose is exercising the parser; production
        // uses don't mutate env.
        let var = "HERMOD_TEST_SECRET_FROM_ENV";
        // SAFETY notes apply per std::env::set_var documentation.
        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(var, "  zzz-tok\n");
        }
        let s = secret_from_env(var).unwrap();
        assert_eq!(s.expose_secret(), "zzz-tok");

        #[allow(unsafe_code)]
        unsafe {
            std::env::set_var(var, "   ");
        }
        assert!(secret_from_env(var).is_none());

        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var(var);
        }
        assert!(secret_from_env(var).is_none());
    }
}
