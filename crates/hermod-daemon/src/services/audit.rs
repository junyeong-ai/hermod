use hermod_core::{AgentAlias, AgentId, Timestamp};
use hermod_protocol::ipc::methods::{
    AuditArchiveIndexView, AuditArchiveNowParams, AuditArchiveNowResult, AuditArchiveSummaryView,
    AuditArchivesListParams, AuditArchivesListResult, AuditEntryView, AuditQueryParams,
    AuditQueryResult, AuditVerifyArchiveParams, AuditVerifyArchiveResult, AuditVerifyResult,
};
use hermod_storage::{ArchiveVerification, ChainVerification, Database};
use std::str::FromStr;
use std::sync::Arc;

use crate::services::ServiceError;

/// Archives are aligned to UTC midnight. Always one full day per
/// archive bucket; only fully-elapsed days qualify (the in-progress
/// day stays live so a sweep mid-day doesn't strand half its rows).
const ONE_DAY_MS: i64 = 24 * 3600 * 1000;

#[derive(Clone)]
pub struct AuditService {
    db: Arc<dyn Database>,
    default_retention_secs: u64,
}

impl std::fmt::Debug for AuditService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditService")
            .field("default_retention_secs", &self.default_retention_secs)
            .finish_non_exhaustive()
    }
}

impl AuditService {
    pub fn new(db: Arc<dyn Database>, default_retention_secs: u64) -> Self {
        Self {
            db,
            default_retention_secs,
        }
    }

    pub async fn query(&self, params: AuditQueryParams) -> Result<AuditQueryResult, ServiceError> {
        let actor = match params.actor {
            Some(s) => Some(self.resolve_actor(&s).await?),
            None => None,
        };
        let since = params
            .since_secs
            .map(|s| {
                Timestamp::from_unix_ms(Timestamp::now().unix_ms() - s.saturating_mul(1000))
                    .map_err(|e| ServiceError::InvalidParam(format!("since: {e}")))
            })
            .transpose()?;
        let limit = params.limit.unwrap_or(100).min(1000);
        let rows = self
            .db
            .audit()
            .query(actor.as_ref(), params.action.as_deref(), since, limit)
            .await?;
        let entries = rows
            .into_iter()
            .map(|e| AuditEntryView {
                id: e.id.unwrap_or(0),
                created_at: e.ts,
                actor: e.actor,
                action: e.action,
                target: e.target,
                details: e.details,
            })
            .collect();
        Ok(AuditQueryResult { entries })
    }

    pub async fn verify(&self) -> Result<AuditVerifyResult, ServiceError> {
        let v = self.db.audit().verify_chain().await?;
        Ok(match v {
            ChainVerification::Ok { rows } => AuditVerifyResult::Ok { rows },
            ChainVerification::BrokenLink { row_id } => AuditVerifyResult::BrokenLink { row_id },
            ChainVerification::HashMismatch { row_id } => {
                AuditVerifyResult::HashMismatch { row_id }
            }
            ChainVerification::BadSignature { row_id } => {
                AuditVerifyResult::BadSignature { row_id }
            }
        })
    }

    /// Archive every UTC day-bucket strictly older than the cutoff.
    /// Idempotent — re-running on the same day finds no eligible rows
    /// and reports `archives_created: 0`.
    pub async fn archive_now(
        &self,
        params: AuditArchiveNowParams,
    ) -> Result<AuditArchiveNowResult, ServiceError> {
        let cutoff_secs = params
            .older_than_secs
            .unwrap_or(self.default_retention_secs);
        if cutoff_secs == 0 {
            return Ok(AuditArchiveNowResult {
                archives_created: 0,
                rows_archived: 0,
                archives: Vec::new(),
            });
        }
        let now_ms = Timestamp::now().unix_ms();
        let cutoff_ms = now_ms - (cutoff_secs as i64) * 1000;
        // Round cutoff down to the start of the UTC day so we never
        // archive a partial day-bucket.
        let cutoff_day_end = floor_to_utc_day(cutoff_ms);

        let blobs = self.db.blobs();
        let mut archives = Vec::new();
        let mut rows_total: u64 = 0;

        // Find the oldest in-DB row to know where to start; advance one
        // day at a time until we reach the cutoff.
        let oldest_row = self.db.audit().earliest_ts().await?;
        let mut cursor = match oldest_row {
            Some(ts) => floor_to_utc_day(ts),
            None => return Ok(empty_result()),
        };

        while cursor < cutoff_day_end {
            let bucket_end = cursor + ONE_DAY_MS;
            if let Some(summary) = self
                .db
                .audit()
                .archive_day(blobs.as_ref(), cursor, bucket_end)
                .await?
            {
                rows_total = rows_total.saturating_add(summary.row_count);
                archives.push(AuditArchiveSummaryView {
                    epoch_start: Timestamp::from_unix_ms(summary.epoch_start_ms)
                        .map_err(|e| ServiceError::InvalidParam(e.to_string()))?,
                    epoch_end: Timestamp::from_unix_ms(summary.epoch_end_ms)
                        .map_err(|e| ServiceError::InvalidParam(e.to_string()))?,
                    blob_location: summary.blob_location,
                    row_count: summary.row_count,
                    file_size: summary.file_size,
                });
            }
            cursor = bucket_end;
        }

        Ok(AuditArchiveNowResult {
            archives_created: archives.len() as u32,
            rows_archived: rows_total,
            archives,
        })
    }

    pub async fn archives_list(
        &self,
        params: AuditArchivesListParams,
    ) -> Result<AuditArchivesListResult, ServiceError> {
        let limit = params.limit.unwrap_or(100).min(1000);
        let entries = self.db.audit().list_archives(limit).await?;
        let archives = entries
            .into_iter()
            .map(|e| {
                Ok(AuditArchiveIndexView {
                    epoch_start: Timestamp::from_unix_ms(e.epoch_start_ms)
                        .map_err(|e| ServiceError::InvalidParam(e.to_string()))?,
                    epoch_end: Timestamp::from_unix_ms(e.epoch_end_ms)
                        .map_err(|e| ServiceError::InvalidParam(e.to_string()))?,
                    row_count: e.row_count,
                    file_size: e.file_size,
                    blob_location: e.blob_location,
                    archived_at: Timestamp::from_unix_ms(e.archived_at_ms)
                        .map_err(|e| ServiceError::InvalidParam(e.to_string()))?,
                })
            })
            .collect::<Result<Vec<_>, ServiceError>>()?;
        Ok(AuditArchivesListResult { archives })
    }

    pub async fn verify_archive(
        &self,
        params: AuditVerifyArchiveParams,
    ) -> Result<AuditVerifyArchiveResult, ServiceError> {
        let blobs = self.db.blobs();
        let v = self
            .db
            .audit()
            .verify_archive(blobs.as_ref(), params.epoch_start.unix_ms())
            .await?;
        Ok(match v {
            ArchiveVerification::Ok { rows } => AuditVerifyArchiveResult::Ok { rows },
            ArchiveVerification::IndexMissing => AuditVerifyArchiveResult::IndexMissing,
            ArchiveVerification::BlobMissing { blob_location } => {
                AuditVerifyArchiveResult::BlobMissing { blob_location }
            }
            ArchiveVerification::ParseError => AuditVerifyArchiveResult::ParseError,
            ArchiveVerification::SigInvalid => AuditVerifyArchiveResult::SigInvalid,
            ArchiveVerification::ManifestMismatch => AuditVerifyArchiveResult::ManifestMismatch,
            ArchiveVerification::BrokenLink { row_id } => {
                AuditVerifyArchiveResult::BrokenLink { row_id }
            }
            ArchiveVerification::HashMismatch { row_id } => {
                AuditVerifyArchiveResult::HashMismatch { row_id }
            }
        })
    }

    async fn resolve_actor(&self, reference: &str) -> Result<AgentId, ServiceError> {
        if let Some(alias_raw) = reference.strip_prefix('@') {
            let alias = AgentAlias::from_str(alias_raw).map_err(|e| {
                ServiceError::InvalidParam(format!("invalid alias {reference:?}: {e}"))
            })?;
            return self
                .db
                .agents()
                .get_by_local_alias(&alias)
                .await?
                .map(|r| r.id)
                .ok_or(ServiceError::NotFound);
        }
        AgentId::from_str(reference)
            .map_err(|e| ServiceError::InvalidParam(format!("invalid agent id: {e}")))
    }
}

fn floor_to_utc_day(ms: i64) -> i64 {
    (ms / ONE_DAY_MS) * ONE_DAY_MS
}

fn empty_result() -> AuditArchiveNowResult {
    AuditArchiveNowResult {
        archives_created: 0,
        rows_archived: 0,
        archives: Vec::new(),
    }
}
