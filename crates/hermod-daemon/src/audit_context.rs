//! Per-request audit context — the `client_ip` resolved at the IPC
//! entry point flows to every audit emission inside the connection's
//! task tree without threading an explicit parameter through every
//! service method.
//!
//! Backed by [`tokio::task_local!`], so the scope is the tokio task
//! and any task it spawns transitively. The pattern matches
//! `tracing::Span::current()` and `axum::Extensions` in spirit:
//! ambient context that's task-scoped, not thread-local.
//!
//! ## Usage
//!
//! At the entry point (one place per surface):
//!
//! ```ignore
//! audit_context::with_client_ip(Some(client_ip), async move {
//!     dispatcher.handle(req).await
//! }).await
//! ```
//!
//! At the audit emission site (every place is the same):
//!
//! ```ignore
//! services::audit_or_warn(&*sink, AuditEntry {
//!     client_ip: None,  // <- automatically filled from ambient context
//!     ...
//! }).await;
//! ```
//!
//! `audit_or_warn` calls [`current_client_ip`] and overlays the
//! ambient value onto entries that left the field as `None`. Sites
//! that don't carry a client (outbox worker, janitor, daemon-internal
//! periodic tasks) simply emit with `client_ip: None` and the
//! resolver returns `None` because there's no scope.

use std::future::Future;
use std::net::IpAddr;

tokio::task_local! {
    /// Ambient client IP for the current task tree. Set by
    /// [`with_client_ip`] at the IPC entry point; read by
    /// [`current_client_ip`] from any task spawned underneath.
    static CLIENT_IP: Option<IpAddr>;
}

/// Run `fut` with `ip` bound as the ambient client IP for the
/// duration of the future's task tree. Nested calls override the
/// outer scope for the inner future, matching the standard
/// task-local semantics.
pub async fn with_client_ip<F: Future>(ip: Option<IpAddr>, fut: F) -> F::Output {
    CLIENT_IP.scope(ip, fut).await
}

/// Look up the ambient client IP. Returns `None` if either:
///   * the caller is outside any [`with_client_ip`] scope (daemon-
///     internal task, outbox worker, …), or
///   * the scope was set to `None` (e.g. local Unix socket IPC where
///     no remote IP is meaningful).
pub fn current_client_ip() -> Option<IpAddr> {
    CLIENT_IP.try_with(|ip| *ip).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn current_returns_none_outside_scope() {
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
        // Outer scope restored after inner completes.
        assert_eq!(after_inner, Some(outer));
    }

    /// Spawned tokio tasks DO NOT inherit task-local — this is the
    /// standard semantics. Pin it so a future change to the
    /// transport layer that spawns sub-tasks per RPC has to either
    /// re-establish the scope or accept loss of context.
    #[tokio::test]
    async fn spawned_task_does_not_inherit_scope() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let observed_in_spawned = with_client_ip(Some(ip), async {
            tokio::spawn(async { current_client_ip() }).await.unwrap()
        })
        .await;
        assert_eq!(observed_in_spawned, None);
    }
}
