use thiserror::Error;

/// Backend-agnostic storage error. Concrete backend errors (sqlx,
/// future tokio-postgres, gRPC) are flattened to opaque strings at the
/// crate boundary so downstream consumers never depend on a specific
/// driver's error type.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Backend-native failure flattened to a string. Backends format
    /// their typed errors here; consumers display them but should not
    /// pattern-match on the contents.
    #[error("backend: {0}")]
    Backend(String),

    /// On-disk schema does not match the build's bundled migrations.
    /// Recovery is operator-driven: archive the database and re-init.
    /// Surfaced as a typed variant so the daemon can render an
    /// actionable message without grepping driver error text.
    #[error("schema mismatch (recover by archiving the DB and running `hermod init`): {details}")]
    SchemaMismatch { details: String },

    #[error(transparent)]
    Core(#[from] hermod_core::HermodError),

    #[error("decode column {column}: {message}")]
    Decode {
        column: &'static str,
        message: String,
    },

    #[error("cbor: {0}")]
    Cbor(String),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("not found")]
    NotFound,

    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),
}

pub type Result<T, E = StorageError> = std::result::Result<T, E>;

impl StorageError {
    pub(crate) fn decode(column: &'static str, message: impl Into<String>) -> Self {
        StorageError::Decode {
            column,
            message: message.into(),
        }
    }
}

// ── sqlx → StorageError conversions ─────────────────────────────────
//
// sqlx is an internal dependency of the SQLite backend; its error
// types do NOT appear in the public surface. These conversions
// classify schema-mismatch as a typed variant (so the daemon's
// recovery message stays driver-agnostic) and flatten everything else
// to `Backend(String)`.

impl From<sqlx::Error> for StorageError {
    fn from(err: sqlx::Error) -> Self {
        if let sqlx::Error::Migrate(box_err) = &err
            && matches!(
                **box_err,
                sqlx::migrate::MigrateError::VersionMismatch(_)
                    | sqlx::migrate::MigrateError::VersionMissing(_)
            )
        {
            return StorageError::SchemaMismatch {
                details: err.to_string(),
            };
        }
        StorageError::Backend(err.to_string())
    }
}

impl From<sqlx::migrate::MigrateError> for StorageError {
    fn from(err: sqlx::migrate::MigrateError) -> Self {
        if matches!(
            err,
            sqlx::migrate::MigrateError::VersionMismatch(_)
                | sqlx::migrate::MigrateError::VersionMissing(_)
        ) {
            return StorageError::SchemaMismatch {
                details: err.to_string(),
            };
        }
        StorageError::Backend(err.to_string())
    }
}
