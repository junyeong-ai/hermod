use hermod_core::{AgentId, CapabilityToken, Timestamp};
use hermod_crypto::{CapabilityClaim, PublicKey, verify_capability};
use hermod_storage::Database;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::trace;

use crate::error::Result;

/// Verdict returned by the access policy gate. Names mirror
/// [`crate::confirmation::Verdict`] so the two policy gates read with
/// the same vocabulary even though their judgments differ in shape.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessVerdict {
    Accept,
    Reject(&'static str),
}

/// Authorization scopes recognised by `AccessController`. Free-form strings on the
/// wire (`CapabilityClaim.scope`); these constants are the well-known ones —
/// one per envelope kind plus a couple of read-side scopes.
pub mod scope {
    pub const MESSAGE_SEND: &str = "message:send";
    pub const BRIEF_PUBLISH: &str = "brief:publish";
    pub const BRIEF_READ: &str = "brief:read";
    pub const CHANNEL_BROADCAST: &str = "channel:broadcast";
    pub const CHANNEL_ADVERTISE: &str = "channel:advertise";
    pub const WORKSPACE_INVITE: &str = "workspace:invite";
    pub const PRESENCE_SET: &str = "presence:set";
    pub const PRESENCE_READ: &str = "presence:read";
    /// Federated permission relay: the audience may answer the
    /// issuer's `PermissionPrompt`s by sending `PermissionResponse`
    /// envelopes back. Always required on inbound `PermissionResponse`
    /// — independent of the daemon's `policy.require_capability` flag.
    pub const PERMISSION_RESPOND: &str = "permission:respond";
    /// Audit federation: sender may ship audit rows to us for
    /// aggregation into our hash-chained log. Operator opt-in is the
    /// primary gate (`[audit] accept_federation`); the scope is here
    /// so the capability subsystem can express it when
    /// `policy.require_capability = true`.
    pub const AUDIT_FEDERATE: &str = "audit:federate";
    /// Workspace roster query/response. Cryptographic gate is the
    /// workspace MAC (private) or `workspace_members` table (public);
    /// the scope is here so `policy.require_capability` can demand
    /// explicit delegation on top.
    pub const WORKSPACE_ROSTER: &str = "workspace:roster";
    /// Workspace channel listing query/response. Same gate model as
    /// `WORKSPACE_ROSTER`.
    pub const WORKSPACE_CHANNELS: &str = "workspace:channels";
    /// Peer-advertise: sender enumerates the agents it hosts. The
    /// inbound acceptor cross-checks self-inclusion + binds each
    /// advertised agent's host_pubkey, so the scope is here only so a
    /// hardened deployment can demand explicit delegation on top.
    pub const PEER_ADVERTISE: &str = "peer:advertise";
}

/// Configuration knob — when `false`, any authenticated Noise peer may send
/// any envelope kind. When `true`, `Envelope.caps[]` must contain a valid
/// token issued by us for the operation's scope.
#[derive(Clone, Debug, Default)]
pub struct AccessPolicy {
    pub require_capability: bool,
}

#[derive(Clone)]
pub struct AccessController {
    db: Arc<dyn Database>,
    /// Map from each local agent_id to its public key. Capability
    /// tokens issued by *any* of our hosted agents pass the strict
    /// inbound check; outbound `check_send` short-circuits when the
    /// sender is any of our agents. Single-tenant deployments have
    /// one entry; multi-tenant has N.
    local_pubkeys: Arc<HashMap<AgentId, Arc<PublicKey>>>,
    policy: AccessPolicy,
}

impl std::fmt::Debug for AccessController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessController")
            .field("local_id_count", &self.local_pubkeys.len())
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl AccessController {
    pub fn new<I: IntoIterator<Item = (AgentId, PublicKey)>>(
        db: Arc<dyn Database>,
        local_agents: I,
        policy: AccessPolicy,
    ) -> Self {
        let local_pubkeys: HashMap<AgentId, Arc<PublicKey>> = local_agents
            .into_iter()
            .map(|(id, pk)| (id, Arc::new(pk)))
            .collect();
        Self {
            db,
            local_pubkeys: Arc::new(local_pubkeys),
            policy,
        }
    }

    fn is_local(&self, id: &AgentId) -> bool {
        self.local_pubkeys.contains_key(id)
    }

    fn local_pubkey(&self, id: &AgentId) -> Option<&PublicKey> {
        self.local_pubkeys.get(id).map(|p| p.as_ref())
    }

    /// Decide whether `sender` may invoke `scope` against `target` (which is
    /// usually our own agent_id). Inspects `caps[]` for a valid self-issued token.
    pub async fn check_caps(
        &self,
        sender: &AgentId,
        required_scope: &str,
        target: Option<&AgentId>,
        caps: &[CapabilityToken],
    ) -> Result<AccessVerdict> {
        if !self.policy.require_capability {
            return Ok(AccessVerdict::Accept);
        }
        self.evaluate_caps(sender, required_scope, target, caps)
            .await
    }

    /// Like [`Self::check_caps`] but enforces the cap check
    /// regardless of `policy.require_capability`. Used by inbound
    /// kinds that carry delegated authority (e.g.
    /// `PermissionResponse`) — those must never accept from an
    /// unauthorised peer no matter the daemon's broader policy.
    pub async fn check_caps_strict(
        &self,
        sender: &AgentId,
        required_scope: &str,
        target: Option<&AgentId>,
        caps: &[CapabilityToken],
    ) -> Result<AccessVerdict> {
        self.evaluate_caps(sender, required_scope, target, caps)
            .await
    }

    async fn evaluate_caps(
        &self,
        sender: &AgentId,
        required_scope: &str,
        target: Option<&AgentId>,
        caps: &[CapabilityToken],
    ) -> Result<AccessVerdict> {
        // Sender is one of our own hosted agents — always allowed.
        if self.is_local(sender) {
            return Ok(AccessVerdict::Accept);
        }
        let now_ms = Timestamp::now().unix_ms();
        for cap in caps {
            match self
                .evaluate_one(cap, sender, required_scope, target, now_ms)
                .await
            {
                CapVerdict::Match => return Ok(AccessVerdict::Accept),
                CapVerdict::NotMatch | CapVerdict::Skip => continue,
            }
        }
        Ok(AccessVerdict::Reject("no valid capability presented"))
    }

    async fn evaluate_one(
        &self,
        cap: &CapabilityToken,
        sender: &AgentId,
        required_scope: &str,
        target: Option<&AgentId>,
        now_ms: i64,
    ) -> CapVerdict {
        // Capability tokens are issued by one of our hosted agents.
        // Look up the issuer's pubkey from the local roster, then
        // verify; a missing issuer means the cap is from someone we
        // don't host (federation-issued caps for inbound use are
        // verified by the issuing peer's directory entry, not here).
        let preview = match hermod_crypto::parse_claim_unverified(cap.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                trace!(error = %e, "skipping cap that fails parse");
                return CapVerdict::Skip;
            }
        };
        let issuer_pk = match self.local_pubkey(&preview.iss) {
            Some(pk) => pk,
            None => return CapVerdict::Skip,
        };
        let claim: CapabilityClaim = match verify_capability(issuer_pk, cap.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                trace!(error = %e, "skipping cap that fails signature");
                return CapVerdict::Skip;
            }
        };
        if !self.is_local(&claim.iss) {
            return CapVerdict::Skip;
        }
        if claim.scope != required_scope {
            return CapVerdict::NotMatch;
        }
        if let Some(aud) = &claim.aud
            && aud.as_str() != sender.as_str()
        {
            return CapVerdict::NotMatch;
        }
        if let Some(tgt) = &claim.target {
            match target {
                Some(t) if tgt == t.as_str() => {}
                Some(_) => return CapVerdict::NotMatch,
                None => return CapVerdict::NotMatch,
            }
        }
        if let Some(exp) = claim.exp
            && now_ms > exp
        {
            return CapVerdict::NotMatch;
        }
        // Revocation check.
        match self.db.capabilities().is_revoked(&claim.jti).await {
            Ok(true) => return CapVerdict::NotMatch,
            Ok(false) => {}
            Err(e) => {
                trace!(error = %e, "revocation lookup failed; treating cap as denied");
                return CapVerdict::NotMatch;
            }
        }
        CapVerdict::Match
    }

    /// Convenience for `message:send`.
    pub async fn check_send(
        &self,
        sender: &AgentId,
        target: &AgentId,
        caps: &[CapabilityToken],
    ) -> Result<AccessVerdict> {
        self.check_caps(sender, scope::MESSAGE_SEND, Some(target), caps)
            .await
    }
}

enum CapVerdict {
    Match,
    NotMatch,
    Skip,
}
