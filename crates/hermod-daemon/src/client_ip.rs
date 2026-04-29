//! Resolve the originating client IP from a chain of trusted reverse
//! proxies.
//!
//! When `daemon.ipc_listen_ws` sits behind a reverse proxy (Cloud
//! Run, Google IAP, oauth2-proxy, Cloudflare Access, ALB+Cognito,
//! k8s ingress) the daemon's TCP `peer` is the proxy IP, not the
//! end user's. The proxy injects an `X-Forwarded-For` header — but
//! that header is **forgeable** by anyone who can reach the daemon
//! directly, so trusting it unconditionally would let an attacker
//! who'd port-scanned the daemon stamp arbitrary client IPs into
//! audit rows. The fix is the well-established "trusted-proxy
//! whitelist" pattern (nginx `set_real_ip_from`, Apache
//! `mod_remoteip`, Envoy `xff_num_trusted_hops`):
//!
//! 1. If the TCP peer is **not** in `daemon.trusted_proxies`,
//!    `X-Forwarded-For` is ignored entirely. The peer IP is the
//!    client IP. (An attacker hitting the daemon directly cannot
//!    forge.)
//! 2. If the TCP peer **is** trusted, walk `X-Forwarded-For`
//!    right-to-left (the rightmost entry was added by the most
//!    recent hop). Stop at the first IP that is **not** in
//!    `trusted_proxies` — that's the originating client. The IPs
//!    to its right were added by trusted proxies and are
//!    authoritative.
//! 3. If every entry in `X-Forwarded-For` is trusted (chain of
//!    trusted proxies, no untrusted hop), fall back to the TCP peer.
//!    The XFF chain doesn't reach a non-proxy attacker, so this case
//!    is "the request originated inside the trusted perimeter".
//!
//! `daemon.trusted_proxies` defaults to `[]` — XFF is ignored, peer
//! IP is used as-is. Operators opt in by listing the **proxy
//! networks**, not the public internet.

use ipnet::IpNet;
use std::net::IpAddr;

/// Pick the originating client IP from `(peer, xff, trusted)`.
///
/// Decision table:
///
/// | peer trusted? | xff present? | result                         |
/// |---------------|--------------|--------------------------------|
/// | no            | any          | peer (XFF unforgeable defence) |
/// | yes           | absent       | peer                           |
/// | yes           | present      | rightmost-untrusted-or-peer    |
///
/// `xff_header` is the raw `X-Forwarded-For` value (comma-separated
/// IPs). Whitespace is tolerated; unparseable entries are skipped.
pub fn resolve_client_ip(peer: IpAddr, xff_header: Option<&str>, trusted: &[IpNet]) -> IpAddr {
    if !is_trusted(peer, trusted) {
        // Peer is the client (or an attacker pretending to be a
        // client). Either way, XFF cannot be trusted.
        return peer;
    }
    let Some(xff) = xff_header else {
        return peer;
    };
    // Right-to-left: rightmost is the most-recent hop's view of *its*
    // peer. As long as that's still in `trusted`, walk left. The
    // first IP not in `trusted` is the actual client.
    xff.split(',')
        .rev()
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .find(|ip| !is_trusted(*ip, trusted))
        .unwrap_or(peer)
}

fn is_trusted(ip: IpAddr, trusted: &[IpNet]) -> bool {
    trusted.iter().any(|net| net.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn cidr(s: &str) -> IpNet {
        IpNet::from_str(s).unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    /// Empty trusted list is the safe default: XFF is ignored entirely,
    /// peer IP is the client IP. Forgery defence.
    #[test]
    fn empty_trusted_list_returns_peer_ignoring_xff() {
        let trusted: Vec<IpNet> = vec![];
        assert_eq!(
            resolve_client_ip(ip("203.0.113.1"), Some("198.51.100.5"), &trusted),
            ip("203.0.113.1")
        );
    }

    /// Untrusted peer cannot influence audit logging by sending an
    /// XFF header. This is the primary spoofing-defence assertion.
    #[test]
    fn untrusted_peer_returns_peer_ignoring_xff() {
        let trusted = vec![cidr("10.0.0.0/8")];
        // Attacker on 203.0.113.1 sends `XFF: 1.2.3.4` claiming to be
        // 1.2.3.4. The resolver MUST NOT believe them.
        assert_eq!(
            resolve_client_ip(ip("203.0.113.1"), Some("1.2.3.4"), &trusted),
            ip("203.0.113.1")
        );
    }

    /// Trusted peer with no XFF header → peer itself is the client
    /// (request originated at a trusted proxy that didn't inject XFF;
    /// safest interpretation is "client = proxy").
    #[test]
    fn trusted_peer_no_xff_returns_peer() {
        let trusted = vec![cidr("10.0.0.0/8")];
        assert_eq!(
            resolve_client_ip(ip("10.0.0.5"), None, &trusted),
            ip("10.0.0.5")
        );
    }

    /// Single trusted proxy injects `XFF: <client>`; resolver
    /// extracts the client.
    #[test]
    fn single_trusted_proxy_extracts_client() {
        let trusted = vec![cidr("10.0.0.0/8")];
        assert_eq!(
            resolve_client_ip(ip("10.0.0.5"), Some("203.0.113.42"), &trusted),
            ip("203.0.113.42")
        );
    }

    /// Chain of trusted proxies: client → trusted-A → trusted-B → daemon.
    /// XFF is appended left-to-right, so the rightmost entry was
    /// trusted-A (closest to client). Right-to-left walk skips trusted
    /// hops and stops at the client.
    #[test]
    fn chain_of_trusted_proxies_extracts_originating_client() {
        let trusted = vec![cidr("10.0.0.0/8"), cidr("172.16.0.0/12")];
        // Wire order: `client, trusted-A`. Rightmost (trusted-A) is
        // skipped because it's in `trusted`; leftmost (client) is the
        // result.
        assert_eq!(
            resolve_client_ip(ip("10.0.0.5"), Some("203.0.113.42, 172.16.0.10"), &trusted),
            ip("203.0.113.42")
        );
    }

    /// Whitespace tolerance — `, ` and `,` and `,\t` are all accepted.
    #[test]
    fn xff_whitespace_tolerated() {
        let trusted = vec![cidr("10.0.0.0/8")];
        assert_eq!(
            resolve_client_ip(
                ip("10.0.0.5"),
                Some("  203.0.113.42 ,\t10.0.0.6 "),
                &trusted
            ),
            ip("203.0.113.42")
        );
    }

    /// All XFF entries trusted (trusted proxy chain with no client
    /// hop visible) → fall back to peer.
    #[test]
    fn all_xff_trusted_falls_back_to_peer() {
        let trusted = vec![cidr("10.0.0.0/8")];
        assert_eq!(
            resolve_client_ip(ip("10.0.0.5"), Some("10.0.0.7, 10.0.0.6"), &trusted),
            ip("10.0.0.5")
        );
    }

    /// Malformed XFF entry (not an IP) is skipped; the next-leftward
    /// untrusted entry wins. A garbage XFF doesn't degrade resolution.
    #[test]
    fn malformed_xff_entry_skipped() {
        let trusted = vec![cidr("10.0.0.0/8")];
        assert_eq!(
            resolve_client_ip(ip("10.0.0.5"), Some("203.0.113.42, garbage"), &trusted),
            ip("203.0.113.42")
        );
    }

    /// Empty XFF (header present but empty value) → fall back to peer.
    #[test]
    fn empty_xff_falls_back_to_peer() {
        let trusted = vec![cidr("10.0.0.0/8")];
        assert_eq!(
            resolve_client_ip(ip("10.0.0.5"), Some(""), &trusted),
            ip("10.0.0.5")
        );
    }

    /// IPv6 trusted range + IPv6 client.
    #[test]
    fn ipv6_trusted_and_client() {
        let trusted = vec![cidr("fd00::/8")];
        assert_eq!(
            resolve_client_ip(ip("fd00::1"), Some("2001:db8::1"), &trusted),
            ip("2001:db8::1")
        );
    }
}
