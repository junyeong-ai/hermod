//! TLS verification policy for Remote IPC clients.
//!
//! Hermod authenticates the *peer identity* via the bearer token —
//! TLS only provides confidentiality and a way to recognise the same
//! daemon across reconnects. `--pin <MODE>` picks how the TLS chain is
//! validated:
//!
//! | mode | use case |
//! |------|----------|
//! | `tofu` (default) | self-signed daemon, federation peer-to-peer, LAN |
//! | `<sha256>` | explicit fingerprint pin (production federation, audited) |
//! | `public-ca` | broker behind a public-CA-trusted reverse proxy (Cloud Run, IAP, Cloudflare) |
//! | `none` | tests / fully-trusted LAN; skip TLS validation |
//!
//! TOFU records the first-seen fingerprint to
//! `$HERMOD_HOME/remote_pins.json` (a small JSON map keyed by
//! `host:port` → SHA-256 fingerprint, lowercase colon-separated, matching
//! `hermod-crypto::tls::sha256_fingerprint`). Subsequent connects fail
//! loud on mismatch. `public-ca` skips the TOFU store entirely and
//! delegates chain validation to the OS trust store via
//! `rustls-native-certs` (matching reqwest's `rustls-tls-native-roots`
//! used elsewhere in this binary).

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Serialize, Deserialize)]
struct PinFile {
    /// `host:port` → SHA-256 fingerprint string.
    #[serde(default)]
    pins: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct RemotePinStore {
    path: PathBuf,
}

impl RemotePinStore {
    pub fn at_home(home: &Path) -> Self {
        Self {
            path: home.join("remote_pins.json"),
        }
    }

    fn load(&self) -> Result<PinFile> {
        if !self.path.exists() {
            return Ok(PinFile::default());
        }
        let raw = std::fs::read_to_string(&self.path)
            .with_context(|| format!("read {}", self.path.display()))?;
        let parsed: PinFile =
            serde_json::from_str(&raw).with_context(|| format!("parse {}", self.path.display()))?;
        Ok(parsed)
    }

    fn save(&self, file: &PinFile) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let serialized =
            serde_json::to_string_pretty(file).context("serialize remote_pins.json")?;
        std::fs::write(&self.path, serialized)
            .with_context(|| format!("write {}", self.path.display()))?;
        Ok(())
    }

    pub fn lookup(&self, host_port: &str) -> Result<Option<String>> {
        Ok(self.load()?.pins.get(host_port).cloned())
    }

    pub fn pin(&self, host_port: &str, fingerprint: &str) -> Result<()> {
        let mut file = self.load()?;
        file.pins
            .insert(host_port.to_string(), fingerprint.to_string());
        self.save(&file)
    }
}

/// What to do when validating the daemon's TLS cert.
#[derive(Debug, Clone)]
pub enum PinPolicy {
    /// Cert SHA-256 must equal this fingerprint (lowercase, colon-separated).
    Explicit(String),
    /// First-connect: record the observed fingerprint to `store`. Subsequent
    /// connects: fail loud on mismatch. `host_port` is the lookup key.
    Tofu {
        store: RemotePinStore,
        host_port: String,
    },
    /// Validate the daemon's TLS chain via the OS trust store (system
    /// root CAs). The right answer when a public-CA-trusted reverse
    /// proxy (Cloud Run, IAP, Cloudflare Access, ALB+Cognito) sits in
    /// front of the daemon and presents the user-facing cert — pinning
    /// the LB's cert fingerprint would break on every cert rotation.
    /// Hostname is taken from the `--remote` URL and validated against
    /// the cert's SAN list, matching browser semantics.
    PublicCa,
    /// Skip TLS validation entirely. Strictly opt-in for tests / known-LAN.
    InsecureNoVerify,
}

/// CLI argument shape for `--pin`. `clap` parses one of the textual
/// modes (`tofu` | `public-ca` | `none`) or a raw SHA-256 fingerprint.
/// The runtime [`PinPolicy`] needs the resolved `$HERMOD_HOME` and the
/// remote URL's `host:port` (for the TOFU store), so the conversion
/// happens in `build_pin_policy` rather than here.
#[derive(Debug, Clone)]
pub enum PinArg {
    /// Default — record-on-first-use, fail-loud-on-mismatch.
    Tofu,
    /// Validate via the OS root CA store.
    PublicCa,
    /// Skip TLS validation.
    None,
    /// Explicit SHA-256 fingerprint (lowercase, colon-separated form
    /// produced by [`PinPolicy::normalize_fingerprint`]).
    Fingerprint(String),
}

impl std::str::FromStr for PinArg {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "tofu" => Ok(Self::Tofu),
            "public-ca" => Ok(Self::PublicCa),
            "none" => Ok(Self::None),
            other => PinPolicy::normalize_fingerprint(other)
                .map(Self::Fingerprint)
                .map_err(|e| {
                    anyhow!(
                        "--pin must be one of `tofu`, `public-ca`, `none`, or a SHA-256 \
                         hex fingerprint (64 hex chars, optional `:` separators); got {other:?} \
                         ({e})"
                    )
                }),
        }
    }
}

impl PinPolicy {
    /// Normalise a hex fingerprint for storage / comparison.
    /// Accepts colon-separated, space-separated, or unseparated; lowercases.
    pub fn normalize_fingerprint(s: &str) -> Result<String> {
        let cleaned: String = s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != ':')
            .map(|c| c.to_ascii_lowercase())
            .collect();
        if cleaned.len() != 64 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!(
                "TLS fingerprint must be SHA-256 (64 hex chars), got {} chars",
                cleaned.len()
            ));
        }
        let mut out = String::with_capacity(95);
        for (i, ch) in cleaned.chars().enumerate() {
            if i > 0 && i % 2 == 0 {
                out.push(':');
            }
            out.push(ch);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_colon_form() {
        // 32 bytes = 64 hex chars = 31 colons (between byte pairs).
        let fp = "ab:cd:".to_string() + &"00:".repeat(28) + "00:ff";
        let cleaned = PinPolicy::normalize_fingerprint(&fp).unwrap();
        assert!(cleaned.starts_with("ab:cd:"));
        assert_eq!(cleaned.matches(':').count(), 31);
    }

    #[test]
    fn normalize_accepts_unseparated_lowercase() {
        let fp = "AB".to_string() + &"00".repeat(31);
        let cleaned = PinPolicy::normalize_fingerprint(&fp).unwrap();
        assert!(cleaned.starts_with("ab:00:"));
    }

    #[test]
    fn normalize_rejects_short_fp() {
        assert!(PinPolicy::normalize_fingerprint("abcd").is_err());
    }

    #[test]
    fn pin_arg_parses_modes_and_fingerprint() {
        use std::str::FromStr;
        assert!(matches!(PinArg::from_str("tofu").unwrap(), PinArg::Tofu));
        assert!(matches!(
            PinArg::from_str("public-ca").unwrap(),
            PinArg::PublicCa
        ));
        assert!(matches!(PinArg::from_str("none").unwrap(), PinArg::None));
        let fp = "AB".to_string() + &"00".repeat(31);
        match PinArg::from_str(&fp).unwrap() {
            PinArg::Fingerprint(s) => assert!(s.starts_with("ab:00:")),
            other => panic!("expected Fingerprint, got {other:?}"),
        }
    }

    #[test]
    fn pin_arg_rejects_garbage() {
        use std::str::FromStr;
        assert!(PinArg::from_str("maybe").is_err());
        assert!(PinArg::from_str("abc").is_err()); // too short for fingerprint
    }

    #[test]
    fn store_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = RemotePinStore::at_home(dir.path());
        let fp = "ab:".to_string() + &"00:".repeat(30) + "ff";
        store.pin("daemon.example.com:7824", &fp).unwrap();
        assert_eq!(
            store.lookup("daemon.example.com:7824").unwrap(),
            Some(fp.clone())
        );
        assert_eq!(store.lookup("other.example.com:7824").unwrap(), None);
    }
}
