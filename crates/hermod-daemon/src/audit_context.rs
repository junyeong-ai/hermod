//! Per-request audit context — values resolved at the IPC entry point
//! flow to every audit emission inside the connection's task tree
//! without threading explicit parameters through every service method.
//!
//! Backed by [`tokio::task_local!`], so the scope is the tokio task
//! and any task it spawns transitively. The pattern matches
//! `tracing::Span::current()` and `axum::Extensions` in spirit:
//! ambient context that's task-scoped, not thread-local.
//!
//! Two values flow through this layer:
//!
//! - **Client IP** — resolved at the remote-IPC handshake (TCP peer +
//!   trusted-proxy XFF resolution). Daemon-internal sites (outbox,
//!   janitor, federation accept) leave it `None`.
//! - **Caller agent** — set by the IPC handshake after a successful
//!   bearer-token lookup, identifying which local agent the connection
//!   acts on behalf of. Daemon-internal sites leave it `None` and audit
//!   emissions fall back to whatever `actor` the literal carried (the
//!   host id, by convention).
//!
//! Both values surface to audit emissions via `audit_or_warn`'s overlay
//! step — sites stay uniform regardless of whether they're running
//! inside an IPC connection scope or a daemon-internal task.

use hermod_core::AgentId;
use std::future::Future;
use std::net::IpAddr;

tokio::task_local! {
    /// Ambient client IP for the current task tree. Set by
    /// [`with_client_ip`] at the IPC entry point; read by
    /// [`current_client_ip`] from any task spawned underneath.
    static CLIENT_IP: Option<IpAddr>;

    /// Ambient *caller* agent — which local agent this IPC connection
    /// acts on behalf of, resolved via bearer-token lookup against the
    /// `local_agents` table at handshake time. Read by
    /// [`current_caller_agent`] inside the connection's task tree.
    /// `None` outside any IPC scope (daemon-internal tasks).
    static CALLER_AGENT: Option<AgentId>;
}

pub async fn with_client_ip<F: Future>(ip: Option<IpAddr>, fut: F) -> F::Output {
    CLIENT_IP.scope(ip, fut).await
}

pub fn current_client_ip() -> Option<IpAddr> {
    CLIENT_IP.try_with(|ip| *ip).ok().flatten()
}

/// Run `fut` with `agent` bound as the ambient caller agent for the
/// duration of the future's task tree. Nested calls override the outer
/// scope for the inner future, matching the standard task-local
/// semantics.
pub async fn with_caller_agent<F: Future>(agent: Option<AgentId>, fut: F) -> F::Output {
    CALLER_AGENT.scope(agent, fut).await
}

/// Look up the ambient caller agent. Returns `None` if either the
/// caller is outside any [`with_caller_agent`] scope or the scope was
/// set to `None` (Unix-socket IPC without per-call dispatch — H3 does
/// not bearer-auth the local socket).
pub fn current_caller_agent() -> Option<AgentId> {
    CALLER_AGENT.try_with(|c| c.clone()).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[tokio::test]
    async fn client_ip_current_returns_none_outside_scope() {
        assert_eq!(current_client_ip(), None);
    }

    #[tokio::test]
    async fn with_client_ip_makes_inner_observe_some() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let observed = with_client_ip(Some(ip), async { current_client_ip() }).await;
        assert_eq!(observed, Some(ip));
    }

    #[tokio::test]
    async fn explicit_none_scope_returns_none() {
        let observed = with_client_ip(None, async { current_client_ip() }).await;
        assert_eq!(observed, None);
    }

    #[tokio::test]
    async fn nested_scope_overrides_outer() {
        let outer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let inner = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let (before_inner, in_inner, after_inner) = with_client_ip(Some(outer), async {
            let before = current_client_ip();
            let inside = with_client_ip(Some(inner), async { current_client_ip() }).await;
            let after = current_client_ip();
            (before, inside, after)
        })
        .await;
        assert_eq!(before_inner, Some(outer));
        assert_eq!(in_inner, Some(inner));
        assert_eq!(after_inner, Some(outer));
    }

    #[tokio::test]
    async fn spawned_task_does_not_inherit_scope() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let observed_in_spawned = with_client_ip(Some(ip), async {
            tokio::spawn(async { current_client_ip() }).await.unwrap()
        })
        .await;
        assert_eq!(observed_in_spawned, None);
    }

    #[tokio::test]
    async fn caller_agent_current_returns_none_outside_scope() {
        assert_eq!(current_caller_agent(), None);
    }

    #[tokio::test]
    async fn with_caller_agent_makes_inner_observe_some() {
        let id = AgentId::from_str("abcdefghijklmnopqrstuvwxyz").unwrap();
        let observed = with_caller_agent(Some(id.clone()), async { current_caller_agent() }).await;
        assert_eq!(observed, Some(id));
    }

    #[tokio::test]
    async fn caller_agent_does_not_leak_across_independent_scopes() {
        let a = AgentId::from_str("abcdefghijklmnopqrstuvwxyz").unwrap();
        let b = AgentId::from_str("zyxwvutsrqponmlkjihgfedcba").unwrap();
        let (in_a, in_b) = tokio::join!(
            with_caller_agent(Some(a.clone()), async { current_caller_agent() }),
            with_caller_agent(Some(b.clone()), async { current_caller_agent() }),
        );
        assert_eq!(in_a, Some(a));
        assert_eq!(in_b, Some(b));
    }
}
