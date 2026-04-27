//! SQLite implementation of `CapabilityRepository`.

use async_trait::async_trait;
use hermod_core::{AgentId, CapabilityDirection, Timestamp};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;

use crate::error::{Result, StorageError};
use crate::repositories::capabilities::{
    CapabilityFilter, CapabilityRecord, CapabilityRepository,
};

#[derive(Debug, Clone)]
pub struct SqliteCapabilityRepository {
    pool: SqlitePool,
}

impl SqliteCapabilityRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    async fn upsert_with_direction(
        &self,
        cap: &CapabilityRecord,
        direction: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO capabilities
                   (id, issuer, audience, scope, target, expires_at, revoked_at, raw_token, direction)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   audience   = excluded.audience,
                   scope      = excluded.scope,
                   target     = excluded.target,
                   expires_at = excluded.expires_at"#,
        )
        .bind(&cap.id)
        .bind(cap.issuer.as_str())
        .bind(cap.audience.as_ref().map(|a| a.as_str().to_string()))
        .bind(&cap.scope)
        .bind(&cap.target)
        .bind(cap.expires_at.map(|t| t.unix_ms()))
        .bind(cap.revoked_at.map(|t| t.unix_ms()))
        .bind(&cap.raw_token)
        .bind(direction)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl CapabilityRepository for SqliteCapabilityRepository {
    async fn upsert(&self, cap: &CapabilityRecord) -> Result<()> {
        self.upsert_with_direction(cap, "issued").await
    }

    async fn upsert_received(&self, cap: &CapabilityRecord) -> Result<()> {
        self.upsert_with_direction(cap, "received").await
    }

    async fn revoke(&self, id: &str, at: Timestamp) -> Result<bool> {
        let res = sqlx::query(
            r#"UPDATE capabilities SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL"#,
        )
        .bind(at.unix_ms())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn is_revoked(&self, id: &str) -> Result<bool> {
        let row = sqlx::query(r#"SELECT revoked_at FROM capabilities WHERE id = ?"#)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            None => Ok(false),
            Some(r) => {
                let t: Option<i64> = r.try_get("revoked_at")?;
                Ok(t.is_some())
            }
        }
    }

    async fn prune_terminal(&self, now_ms: i64) -> Result<u64> {
        let res = sqlx::query(
            r#"DELETE FROM capabilities
               WHERE expires_at IS NOT NULL AND expires_at <= ?"#,
        )
        .bind(now_ms)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    async fn active_audiences_for_scope(
        &self,
        issuer: &AgentId,
        scope: &str,
        now_ms: i64,
    ) -> Result<Vec<AgentId>> {
        let rows = sqlx::query(
            r#"SELECT DISTINCT audience FROM capabilities
               WHERE direction = 'issued'
                 AND issuer = ?
                 AND scope = ?
                 AND audience IS NOT NULL
                 AND revoked_at IS NULL
                 AND (expires_at IS NULL OR expires_at > ?)"#,
        )
        .bind(issuer.as_str())
        .bind(scope)
        .bind(now_ms)
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let s: String = row.try_get("audience")?;
            out.push(AgentId::from_str(&s).map_err(StorageError::Core)?);
        }
        Ok(out)
    }

    async fn find_active_received(
        &self,
        issuer: &AgentId,
        scope: &str,
        now_ms: i64,
    ) -> Result<Option<CapabilityRecord>> {
        let row = sqlx::query(
            r#"SELECT id, issuer, audience, scope, target, expires_at, revoked_at, raw_token
               FROM capabilities
               WHERE direction = 'received'
                 AND issuer = ?
                 AND scope = ?
                 AND revoked_at IS NULL
                 AND (expires_at IS NULL OR expires_at > ?)
               ORDER BY id DESC
               LIMIT 1"#,
        )
        .bind(issuer.as_str())
        .bind(scope)
        .bind(now_ms)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_capability).transpose()
    }

    async fn list(
        &self,
        self_id: &AgentId,
        now_ms: i64,
        filter: &CapabilityFilter,
    ) -> Result<Vec<CapabilityRecord>> {
        let direction = filter.direction.unwrap_or(CapabilityDirection::Issued);
        let pivot_col = match direction {
            CapabilityDirection::Issued => "issuer",
            CapabilityDirection::Received => "audience",
        };

        let mut sql = format!(
            "SELECT id, issuer, audience, scope, target, expires_at, revoked_at, raw_token \
             FROM capabilities \
             WHERE {pivot_col} = ? AND direction = ?",
        );
        if !filter.include_revoked {
            sql.push_str(" AND revoked_at IS NULL");
        }
        if !filter.include_expired {
            sql.push_str(" AND (expires_at IS NULL OR expires_at > ?)");
        }
        if filter.after_id.is_some() {
            sql.push_str(" AND id > ?");
        }
        sql.push_str(" ORDER BY id ASC");
        if filter.limit.is_some() {
            sql.push_str(" LIMIT ?");
        }

        let mut q = sqlx::query(&sql)
            .bind(self_id.as_str())
            .bind(direction.as_str());
        if !filter.include_expired {
            q = q.bind(now_ms);
        }
        if let Some(after) = &filter.after_id {
            q = q.bind(after);
        }
        if let Some(limit) = filter.limit {
            q = q.bind(limit as i64);
        }
        let rows = q.fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_capability).collect()
    }
}

fn row_to_capability(row: sqlx::sqlite::SqliteRow) -> Result<CapabilityRecord> {
    let id: String = row.try_get("id")?;
    let issuer_s: String = row.try_get("issuer")?;
    let issuer = AgentId::from_str(&issuer_s).map_err(StorageError::Core)?;
    let audience_s: Option<String> = row.try_get("audience")?;
    let audience = audience_s
        .map(|s| AgentId::from_str(&s))
        .transpose()
        .map_err(StorageError::Core)?;
    let scope: String = row.try_get("scope")?;
    let target: Option<String> = row.try_get("target")?;
    let expires_at = row
        .try_get::<Option<i64>, _>("expires_at")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;
    let revoked_at = row
        .try_get::<Option<i64>, _>("revoked_at")?
        .map(Timestamp::from_unix_ms)
        .transpose()
        .map_err(StorageError::Core)?;
    let raw_token: Vec<u8> = row.try_get("raw_token")?;
    Ok(CapabilityRecord {
        id,
        issuer,
        audience,
        scope,
        target,
        expires_at,
        revoked_at,
        raw_token,
    })
}
