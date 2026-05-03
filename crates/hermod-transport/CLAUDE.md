# hermod-transport — AI agent guide

Plumbing — not policy. Provides authenticated channels and the
file-permission-tightened Unix socket; never decides whether a
message is allowed.

## Module map

```
ws.rs       WSS client/server with hot-rotatable TLS acceptor
tls.rs      TlsMaterial + PROTOCOL_VERSIONS (TLS 1.3 only)
unix.rs     UnixIpcListener / UnixIpcStream — 0o600-from-creation
pin.rs      TLS fingerprint pin store (TOFU + explicit)
```

## TLS 1.3 only — single source

`tls::PROTOCOL_VERSIONS = &[&rustls::version::TLS13]` is the
project's only acceptable rustls version slice. Every server and
client config in the workspace consumes it. Adding TLS 1.2 fallback
requires changing this constant — and breaking the security
posture deliberately.

## Why `UnixIpcListener` exists

`tokio::net::UnixListener::bind` creates the socket with the
process umask and chmods later — there's a window where the socket
is world-accessible. `UnixIpcListener::bind` chmods inside the same
syscall scope using the file-creation mode mask, so the socket is
0o600 from inode creation onward. Direct
`tokio::net::UnixListener::bind` is forbidden by `clippy.toml`
specifically for this reason.

## TLS hot-rotate

`Transport::reload_tls(cert_pem, key_pem)` swaps the inbound
acceptor atomically. In-flight connections finish on their pinned
acceptor; new accepts use the rotated cert. Outbound dialing is
unaffected (each dial builds a fresh client side).

The daemon wires SIGHUP → `reload_tls` so operators can
`mv new.crt $HERMOD_HOME/host/tls.crt && kill -HUP <pid>` without
restart.

## Pin store semantics

`TlsPinStore` is the cross-restart store for cert fingerprints.
Three pin policies on the dialing side: `Insecure` (Noise XX
already provides peer auth — reasonable default for federation),
`Tofu` (SSH-style first-use pinning), `Fingerprint(<sha256>)`
(explicit pin, fail-closed on mismatch).
