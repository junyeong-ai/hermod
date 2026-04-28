//! Inbound acceptors for channel + workspace-invite envelopes:
//! `MessageBody::ChannelBroadcast`, `WorkspaceInvite`, and
//! `ChannelAdvertise`. All three are workspace-/channel-scoped data
//! plane operations that share the workspace MAC + channel-id
//! derivation invariants.

use hermod_core::{Envelope, Timestamp};
use serde_bytes::ByteBuf;
use tracing::debug;

use hermod_storage::AuditEntry;

use super::InboundProcessor;
use super::scope::FederationRejection;
use crate::services::audit_or_warn;

impl InboundProcessor {
    pub(super) async fn accept_channel_broadcast(
        &self,
        envelope: &Envelope,
        ws_bytes: &ByteBuf,
        ch_bytes: &ByteBuf,
        text: &str,
        claimed_hmac: Option<&[u8]>,
    ) -> Result<(), FederationRejection> {
        if ws_bytes.len() != 16 || ch_bytes.len() != 16 {
            return Err(FederationRejection::Invalid(
                "broadcast id wrong length".into(),
            ));
        }
        let mut ws_arr = [0u8; 16];
        ws_arr.copy_from_slice(ws_bytes);
        let mut ch_arr = [0u8; 16];
        ch_arr.copy_from_slice(ch_bytes);
        let channel_id = hermod_crypto::ChannelId(ch_arr);

        let channel = match self.db.channels().get(&channel_id).await {
            Ok(Some(c)) => c,
            Ok(None) => {
                debug!(
                    channel = %channel_id,
                    "broadcast for unknown channel; we are not in this workspace"
                );
                return Err(FederationRejection::NotForUs);
            }
            Err(e) => return Err(FederationRejection::Storage(e.to_string())),
        };

        if channel.workspace_id.0 != ws_arr {
            return Err(FederationRejection::Invalid(
                "broadcast workspace_id does not match channel".into(),
            ));
        }

        if let Some(mac_key) = &channel.mac_key {
            let claimed = claimed_hmac.ok_or_else(|| {
                FederationRejection::Invalid("private broadcast missing hmac".into())
            })?;
            if claimed.len() != 32 {
                return Err(FederationRejection::Invalid(
                    "private broadcast hmac wrong length".into(),
                ));
            }
            let mut got = [0u8; 32];
            got.copy_from_slice(claimed);
            if !mac_key.verify(text.as_bytes(), &got) {
                return Err(FederationRejection::Invalid(
                    "private broadcast hmac mismatch".into(),
                ));
            }
        }

        let now = Timestamp::now();
        self.db
            .channels()
            .record_message(&hermod_storage::ChannelMessage {
                id: envelope.id,
                channel_id,
                from_agent: envelope.from.id.clone(),
                body_text: text.to_string(),
                received_at: now,
            })
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?;
        self.db
            .workspace_members()
            .touch(&channel.workspace_id, &envelope.from.id, now)
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: envelope.from.id.clone(),
                action: "broadcast.delivered".into(),
                target: Some(channel_id.to_hex()),
                details: Some(serde_json::json!({
                    "id": envelope.id.to_string(),
                    "workspace_id": channel.workspace_id.to_hex(),
                    "len": text.len(),
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;

        Ok(())
    }

    pub(super) async fn accept_workspace_invite(
        &self,
        envelope: &Envelope,
        ws_bytes: &ByteBuf,
        name: &str,
        secret_bytes: &ByteBuf,
    ) -> Result<(), FederationRejection> {
        if ws_bytes.len() != 16 {
            return Err(FederationRejection::Invalid(
                "invite workspace_id wrong length".into(),
            ));
        }
        if secret_bytes.len() != 32 {
            return Err(FederationRejection::Invalid(
                "invite secret wrong length".into(),
            ));
        }
        let mut ws_arr = [0u8; 16];
        ws_arr.copy_from_slice(ws_bytes);
        let claimed_id = hermod_crypto::WorkspaceId(ws_arr);

        let mut sec_arr = [0u8; 32];
        sec_arr.copy_from_slice(secret_bytes);
        let secret = hermod_crypto::WorkspaceSecret::from_bytes(sec_arr);

        if secret.workspace_id() != claimed_id {
            return Err(FederationRejection::Invalid(
                "invite workspace_id does not match secret derivation".into(),
            ));
        }

        let now = Timestamp::now();
        self.db
            .workspaces()
            .upsert(&hermod_storage::WorkspaceRecord {
                id: claimed_id,
                name: name.to_string(),
                visibility: hermod_core::WorkspaceVisibility::Private,
                secret: Some(secret),
                created_locally: false,
                muted: false,
                joined_at: now,
                last_active: Some(now),
            })
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?;
        self.db
            .workspace_members()
            .touch(&claimed_id, &self.self_id, now)
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?;
        self.db
            .workspace_members()
            .touch(&claimed_id, &envelope.from.id, now)
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: envelope.from.id.clone(),
                action: "workspace.invite.accepted".into(),
                target: Some(claimed_id.to_hex()),
                details: Some(serde_json::json!({
                    "envelope_id": envelope.id.to_string(),
                    "name": name,
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(())
    }

    pub(super) async fn accept_channel_advertise(
        &self,
        envelope: &Envelope,
        ws_bytes: &ByteBuf,
        ch_bytes: &ByteBuf,
        channel_name: &str,
    ) -> Result<(), FederationRejection> {
        if ws_bytes.len() != 16 || ch_bytes.len() != 16 {
            return Err(FederationRejection::Invalid(
                "advertise id wrong length".into(),
            ));
        }
        let mut ws_arr = [0u8; 16];
        ws_arr.copy_from_slice(ws_bytes);
        let workspace_id = hermod_crypto::WorkspaceId(ws_arr);
        let mut ch_arr = [0u8; 16];
        ch_arr.copy_from_slice(ch_bytes);
        let channel_id = hermod_crypto::ChannelId(ch_arr);

        let workspace = match self
            .db
            .workspaces()
            .get(&workspace_id)
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?
        {
            Some(w) => w,
            None => {
                debug!(
                    workspace = %workspace_id,
                    "advertise for unknown workspace; dropping"
                );
                return Ok(());
            }
        };

        if let Some(secret) = &workspace.secret {
            if secret.channel_id(channel_name) != channel_id {
                return Err(FederationRejection::Invalid(
                    "advertise channel_id does not match (our_secret, name)".into(),
                ));
            }
        } else if hermod_crypto::public_channel_id(&workspace_id, channel_name) != channel_id {
            return Err(FederationRejection::Invalid(
                "advertise channel_id does not match public derivation".into(),
            ));
        }

        let now = Timestamp::now();
        self.db
            .discovered_channels()
            .observe(
                &workspace_id,
                &channel_id,
                channel_name,
                &envelope.from.id,
                now,
            )
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?;
        self.db
            .workspace_members()
            .touch(&workspace_id, &envelope.from.id, now)
            .await
            .map_err(|e| FederationRejection::Storage(e.to_string()))?;

        audit_or_warn(
            &*self.audit_sink,
            AuditEntry {
                id: None,
                ts: now,
                actor: envelope.from.id.clone(),
                action: "channel.advertise.observed".into(),
                target: Some(channel_id.to_hex()),
                details: Some(serde_json::json!({
                    "envelope_id": envelope.id.to_string(),
                    "workspace_id": workspace_id.to_hex(),
                    "channel_name": channel_name,
                })),
                federation: hermod_storage::AuditFederationPolicy::Default,
            },
        )
        .await;
        Ok(())
    }
}
