# Deploying Hermod

Five canonical deployment modes share the same daemon binary (`hermodd`)
and the same configuration surface. Pick the one that matches your
situation; later sections layer on top.

| Mode                          | When                                                              | Section |
| ----------------------------- | ----------------------------------------------------------------- | ------- |
| Single-user laptop            | Two Claude Code sessions on one machine want to message           | [§1](#1-single-user-laptop) |
| Two-machine federation        | You and a colleague on different laptops, same LAN or over WAN    | [§2](#2-two-machine-federation) |
| Cloud daemon + thin clients   | Your daemon lives in cloud; Claude Code connects from any device  | [§3](#3-cloud-daemon--thin-clients-remote-ipc) |
| Docker / Compose              | Quick reproducible test bed; CI for federation                    | [§4](#4-docker--compose) |
| Kubernetes                    | Long-running per-user daemon as a sidecar / Deployment            | [§5](#5-kubernetes) |
| Claude Code wiring            | Wires any of the above into Claude Code                           | [§6](#6-claude-code) |

`hermodd` always speaks the same JSON-RPC surface to local clients (Unix
socket) and to remote clients (WSS+Bearer), and the same WSS+Noise
federation protocol to remote daemons. There is no separate "cloud
edition" — every binary can run any role.

---

## 1. Single-user laptop

```sh
# Build (one-time).
cargo install --path crates/hermod-cli   --bin hermod
cargo install --path crates/hermod-daemon --bin hermodd

# Bootstrap.
hermod init --alias me

# Run as a foreground process for the demo, or use the system unit
# files in deploy/ for launchd (macOS) / systemd (Linux user unit).
hermodd
```

Default state directory is `$HOME/.hermod`:

```
~/.hermod/
  config.toml                        # editable
  hermod.db                          # sqlite, WAL
  identity/
    ed25519_secret                   # mode 0600
    tls_cert.pem  tls_key.pem
  sock                               # IPC
```

To run multiple identities on the same machine, set `HERMOD_HOME`:

```sh
HERMOD_HOME=~/.hermod-work hermod init --alias work
HERMOD_HOME=~/.hermod-work hermodd
```

---

## 2. Two-machine federation

Two daemons that want to exchange messages need three things:

1. **Reachable WSS port.** Each daemon binds `[daemon] listen_ws`
   (default off; set to `0.0.0.0:7823` in `config.toml` or via
   `HERMOD_DAEMON_LISTEN_WS`). Open the port on both firewalls.
2. **Identity exchange.** `hermod identity` prints the agent_id, the
   pubkey hex, and the base32 fingerprint. Share these out of band
   (e.g. Signal, in-person QR scan).
3. **TOFU pinning.** First connect captures the peer's TLS cert
   fingerprint into `agents.tls_fingerprint`. After that, fingerprint
   mismatches refuse the connection. Re-pinning requires
   `hermod peer trust` after manual review.

```sh
# On host A (alpha):
echo '[federation]
enabled = true' >> ~/.hermod/config.toml
echo '[daemon]
listen_ws = "0.0.0.0:7823"' >> ~/.hermod/config.toml
hermodd &
hermod identity         # copy alpha's pubkey + ip

# On host B (beta), after exchanging A's pubkey:
hermod peer add --endpoint wss://alpha-host:7823 \
                --pubkey-hex <alpha-pubkey-hex>
hermod message send --to <alpha-agent-id> --body "hello from beta"
```

For LAN auto-discovery, set `[federation] discover_mdns = true` on both
sides — they will find each other on `_hermod._tcp.local.` and
auto-`peer add` (TOFU); the operator still has to promote trust with
`hermod peer trust <peer_id> verified`.

### Behind NAT

Currently no built-in NAT traversal. Either:
- Both daemons run on machines with a public IP (or one in front of a
  port-forwarded NAT).
- Use a relay daemon at a publicly reachable host that both endpoints
  federate with — they then route via that relay.

---

## 3. Cloud daemon + thin clients (Remote IPC)

When the daemon lives somewhere other than the device running Claude
Code — a small VPS, a homelab box, a k8s pod — `hermod` and the MCP
server connect to it over WSS+Bearer instead of a Unix socket.

```
   ┌─────────────────────────┐                   ┌─────────────────────────┐
   │  laptop / desktop       │                   │  cloud / homelab        │
   │                         │                   │                         │
   │  Claude Code            │   wss://…/        │  hermodd                │
   │   └─ hermod mcp ─────── │ ──── Bearer ────► │   ipc_listen_wss        │
   │      --remote URL       │                   │   listen_ws (federation)│
   │                         │                   │                         │
   └─────────────────────────┘                   └─────────────────────────┘
```

The daemon stays single-tenant — its identity is its keypair. Multiple
**users** still each run their own daemon and federate via WSS+Noise (see
§2). What this mode unlocks is **multiple devices for one identity**: my
laptop, my tablet, and my desktop all see the same inbox, the same
workspaces, the same audit log, because they all talk to the same daemon.

### Configure the daemon

```toml
# config.toml on the cloud host
[daemon]
listen_ws       = "0.0.0.0:7823"   # federation (peers reach us here)
ipc_listen_wss  = "0.0.0.0:7824"   # remote IPC (we reach the daemon here)
```

…or via env vars on a container:

```sh
HERMOD_DAEMON_IPC_LISTEN_WSS=0.0.0.0:7824 hermodd
```

The bearer token is auto-generated on first `hermod init` at
`$HERMOD_HOME/identity/bearer_token` (mode 0600). Copy it to your
client machine over a secure channel (SSH, password manager, Signal):

```sh
# on the daemon host:
hermod bearer show          # prints the token (masked by default)
cat $HERMOD_HOME/identity/bearer_token   # raw token (for scripted copy)
```

### Connect from a client

```sh
# Explicit token file:
hermod --remote wss://my-daemon.example.com:7824/ \
       --bearer-file ~/.hermod/remote_bearer \
       status

# Env-var-driven — fits Claude Code MCP server config:
export HERMOD_REMOTE=wss://my-daemon.example.com:7824/
export HERMOD_BEARER_TOKEN=<paste>
hermod status
```

If the daemon's bearer rotates while the CLI is running, the next
connect 401s on the cached token, the file is re-read, and the retry
succeeds — no restart needed. The same shape works for short-lived
OIDC tokens via `--bearer-command` (see the SSO-proxy subsection
below).

`hermod doctor` works against a remote target too — it switches the
"daemon reachable on Unix socket" check to "remote daemon reachable
(WSS+Bearer)" automatically.

### TLS pinning

The daemon presents its self-signed cert on `:7824`. Clients TOFU-pin
the cert fingerprint at the application layer; the bearer token is the
credential, the pin protects against MITM.

Four modes, picked by `--pin <MODE | SHA256>`:

```sh
# 1. TOFU (default — no flags). First connect records the fingerprint
#    to `$HERMOD_HOME/remote_pins.json`; later connects fail loud on
#    mismatch. Right for self-signed federation peers and LAN.
hermod --remote wss://my-daemon.example.com:7824/ status

# 2. Explicit pin. The fingerprint is printed by `hermod init` on the
#    daemon host (`tls_fingerprint: aa:bb:…`), or by `hermod identity`
#    after init. Right for production federation where the pin is
#    provisioned out-of-band.
hermod --remote wss://my-daemon.example.com:7824/ \
       --pin aa:bb:cc:…:ff status

# 3. Public CA. Validate the daemon's chain via the OS root CA store.
#    Right when a public-CA-trusted reverse proxy fronts the daemon
#    (Cloud Run, Google IAP, Cloudflare Access, ALB+Cognito) — pinning
#    the LB's cert breaks on every rotation; system-CA validation is
#    what browsers do.
hermod --remote wss://hermod.example.com/ --pin public-ca status

# 4. Disabled. Strictly opt-in for known-LAN / test deployments where
#    MITM is not a concern.
hermod --remote wss://daemon.local:7824/ --pin none status
```

If you'd rather use a publicly trusted cert (browser compatibility,
middlebox-friendliness), terminate TLS at a reverse proxy (caddy,
nginx, traefik, Cloud Run, IAP, …) and either:

* set `[daemon] ipc_listen_ws = "0.0.0.0:7824"` (plaintext WS — the
  proxy carries TLS) and connect with `--pin public-ca`, or
* keep `ipc_listen_wss = "0.0.0.0:7824"` (TLS at hermod) and connect
  with `--pin <sha256>` of the daemon's self-signed cert.

The bearer token still authenticates each request in both shapes.

### Recovering the originating client IP behind a reverse proxy

When the daemon sits behind a reverse proxy (Cloud Run, IAP, ALB,
ingress-nginx, …) the TCP `peer` it sees is the proxy IP, not the
end user's. The proxy injects `X-Forwarded-For`, and the daemon
uses it to record the originating client IP in `audit_log.client_ip`
for every operator-meaningful event triggered through that
connection (peer.add, capability.attach, message.send, …).

Trusting XFF unconditionally would let an attacker who can reach
the daemon directly forge audit IPs. Configure
`daemon.trusted_proxies` to opt in, listing the **proxy networks**
(never public-internet ranges):

```toml
[daemon]
ipc_listen_ws = "0.0.0.0:7824"
trusted_proxies = [
  "10.0.0.0/8",          # internal LB
  "172.16.0.0/12",       # ingress controller pods
]
```

Resolution rule (matches nginx `set_real_ip_from`, Apache
`mod_remoteip`, Envoy `xff_num_trusted_hops`):

1. If the TCP peer is **not** in `trusted_proxies` → XFF ignored,
   peer IP is the client IP. (Forgery defence.)
2. If the peer is trusted, walk `X-Forwarded-For` right-to-left and
   stop at the first IP that is **not** in `trusted_proxies`. That's
   the originating client.
3. If every entry is trusted → fall back to peer.

Default: empty list. XFF is ignored, peer IP is used as-is.

The env-var equivalent is `HERMOD_DAEMON_TRUSTED_PROXIES`
(comma-separated CIDRs).

Audit forensics:

```sql
-- Pull every event from a specific client IP across the audit log.
SELECT id, ts, action, target FROM audit_log WHERE client_ip = ?;
```

The `client_ip` column carries the resolved value (post-XFF) for
every row triggered by a remote IPC connection; `NULL` for rows from
daemon-internal tasks (outbox, janitor) or federation accept.

### Behind an SSO reverse proxy (IAP / oauth2-proxy / Cloudflare Access)

Corporate / zero-trust deployments commonly front the broker with an
SSO reverse proxy that demands its own OIDC bearer alongside the
daemon's. The two credentials live in two distinct headers per
[RFC 7235 §4.4](https://www.rfc-editor.org/rfc/rfc7235.html#section-4.4):

| Header | Audience | Source |
| --- | --- | --- |
| `Authorization: Bearer <X>` | hermod daemon (`ipc_remote::serve`) | `--bearer-{file,command}` / `HERMOD_BEARER_TOKEN` |
| `Proxy-Authorization: Bearer <Y>` | SSO proxy (IAP / oauth2-proxy / …) | `--proxy-bearer-{file,command}` / `HERMOD_PROXY_BEARER_TOKEN` |

Real reverse proxies strip `Proxy-Authorization` before forwarding,
so the daemon never sees it; the daemon's check on `Authorization`
is unchanged.

#### Google Cloud IAP (Cloud Run / GCE backend)

```sh
# Daemon-layer bearer is the long-lived one operators rotate; proxy
# layer is the short-lived OIDC ID token gcloud mints on demand.
hermod --remote wss://hermod.your-domain/ \
       --bearer-file       ~/.hermod/remote_bearer \
       --proxy-bearer-command \
         "gcloud auth print-identity-token --audiences=$IAP_CLIENT_ID" \
       status
```

`gcloud auth print-identity-token` typically returns a token valid for
~1 hour; on expiry IAP responds with HTTP 401, and the CLI re-runs the
command exactly once (single-flight, dedup'd across concurrent
connects) before retrying.

#### oauth2-proxy + ingress-nginx

```sh
# When the proxy validates a separate OIDC token but preserves the
# upstream Authorization header (ingress-nginx
# auth-response-headers: Authorization configuration), the same shape
# applies — only the proxy-token mint command differs.
hermod --remote wss://hermod.your-domain/ \
       --bearer-file ~/.hermod/remote_bearer \
       --proxy-bearer-command "your-oidc-mint-script" \
       status
```

#### Container / Kubernetes

The bearer-family flags have matching env-var aliases, suitable for
`Deployment` / `CronJob` specs:

```yaml
env:
  - name: HERMOD_REMOTE
    value: "wss://hermod.your-domain/"
  - name: HERMOD_BEARER_FILE
    value: "/etc/hermod/bearer"          # mounted from a Secret
  - name: HERMOD_PROXY_BEARER_COMMAND
    value: "gcloud auth print-identity-token --audiences=$(IAP_CLIENT_ID)"
```

The two families are independently mutually-exclusive: at most one of
`--bearer-file` / `--bearer-command` / `HERMOD_BEARER_TOKEN`, and at
most one of `--proxy-bearer-file` / `--proxy-bearer-command` /
`HERMOD_PROXY_BEARER_TOKEN`.

If only the daemon family is set the CLI sends only `Authorization`
(non-SSO deployments). If neither family is set, the CLI falls back
to `$HERMOD_HOME/identity/bearer_token` for `Authorization` and
sends no `Proxy-Authorization` — the on-host "just works" shape.

## 4. Docker / Compose

The repo's [`Dockerfile`](./Dockerfile) builds both binaries into a
distroless image (~30–50 MB). State persists in a volume mounted at
`/var/lib/hermod`.

```sh
docker build -t hermod:dev .

# One-shot init in the volume:
docker run --rm -v hermod-home:/var/lib/hermod hermod:dev hermod init --alias prod

# Run the daemon:
docker run --rm \
  -v hermod-home:/var/lib/hermod \
  -p 7823:7823 -p 9690:9690 \
  -e HERMOD_DAEMON_LISTEN_WS=0.0.0.0:7823 \
  -e HERMOD_DAEMON_METRICS_LISTEN=0.0.0.0:9690 \
  -e HERMOD_FEDERATION_ENABLED=1 \
  -e HERMOD_DAEMON_LOG_FORMAT=json \
  hermod:dev
```

Two daemons federating on a shared bridge network:
[`docker-compose.yml`](./docker-compose.yml).

### Environment-variable configuration

Every field in `[identity] [daemon] [storage] [federation] [policy]
[audit]` can be overridden via `HERMOD_<SECTION>_<FIELD>` env vars — e.g.

| Var                                          | Maps to                                  |
| -------------------------------------------- | ---------------------------------------- |
| `HERMOD_DAEMON_LISTEN_WS=0.0.0.0:7823`       | `[daemon] listen_ws`                     |
| `HERMOD_DAEMON_METRICS_LISTEN=0.0.0.0:9690`  | `[daemon] metrics_listen`                |
| `HERMOD_STORAGE_URL=sqlite:///path/to/db`    | `[storage] url` (DSN; scheme = backend)  |
| `HERMOD_STORAGE_URL=postgres://u:p@host/db`  | (postgres backend — see below)           |
| `HERMOD_STORAGE_BLOB_ROOT=/var/lib/hermod`   | `[storage] blob_root`                    |
| `HERMOD_FEDERATION_ENABLED=true`             | `[federation] enabled`                   |
| `HERMOD_FEDERATION_DISCOVER_MDNS=true`       | `[federation] discover_mdns`             |
| `HERMOD_FEDERATION_PEERS=wss://a:7823#hex,…` | `[federation] peers` (static seed)       |
| `HERMOD_FEDERATION_UPSTREAM_BROKER=wss://…#hex` | `[federation] upstream_broker` (smarthost) |
| `HERMOD_POLICY_REQUIRE_CAPABILITY=true`      | `[policy] require_capability`            |
| `HERMOD_POLICY_REPLAY_WINDOW_SECS=300`       | `[policy] replay_window_secs`            |
| `HERMOD_POLICY_RATE_LIMIT_PER_SENDER=120`    | `[policy] rate_limit_per_sender`         |
| `HERMOD_POLICY_CONFIRMATION_RETENTION_SECS`  | `[policy] confirmation_retention_secs`   |
| `HERMOD_AUDIT_FILE_PATH=/var/log/hermod.log` | `[audit] file_path` (JSONL mirror)       |
| `HERMOD_AUDIT_AGGREGATORS=<id1>,<id2>,…`     | `[audit] aggregators` (HA fan-out list)  |
| `HERMOD_AUDIT_ACCEPT_FEDERATION=true`        | `[audit] accept_federation` (act as agg) |
| `HERMOD_AUDIT_WEBHOOK_URL=https://…`         | `[audit] webhook_url` (HTTP push sink)   |
| `HERMOD_AUDIT_WEBHOOK_BEARER_TOKEN=<token>`  | `[audit] webhook_bearer_token`           |
| `HERMOD_BROKER_MODE=disabled\|relay_only\|relay_and_witness` | `[broker] mode` (relay role + audit policy) |
| `HERMOD_DAEMON_LOG=info,hermod_daemon=debug` | tracing filter                           |
| `HERMOD_DAEMON_LOG_FORMAT=json`              | structured JSON output to stderr         |

#### Audit log shipping

`[audit] file_path` (or `HERMOD_AUDIT_FILE_PATH`) appends every audit row
as one JSON object per line to the given file, in addition to the
hash-chained SQLite log. Operators tail-follow with promtail / vector /
fluent-bit / filebeat to ship to Loki / Splunk / DataDog without the
daemon taking on a network sink dependency. The sink reopens the file
per write, so external rotation (logrotate `create`, vector `move +
truncate`) just works. Schema:

```json
{"ts":"2026-04-27T...","ts_ms":1745800000000,"actor":"...","action":"workspace.create","target":"...","details":{...}}
```

#### Cross-Hermod audit federation (HA fan-out)

`[audit] aggregators = ["<agent_id>", …]` (or
`HERMOD_AUDIT_AGGREGATORS=<id1>,<id2>,…`) ships every local audit row
as an `AuditFederate` envelope to **every** listed peer daemon, in
parallel. Each aggregator opts in via `[audit] accept_federation =
true` (or `HERMOD_AUDIT_ACCEPT_FEDERATION=true`); without that, it
rejects every federation envelope with `unauthorized`. Both ends opt
in explicitly — random peers cannot pollute an aggregator's audit log.

Multiple aggregators are first-class: name as many as you want and the
fan-out is parallel, so a primary down/restarting does not delay
secondary delivery. Audit rows are small (typically <1 KiB), so
replication cost is dominated by the WS frame overhead — cheap
relative to the value of HA.

On each aggregator, federated rows land under
`audit.federate.<original_action>` with `actor` set to the original
emitter (so cross-daemon timelines reconstruct from `actor` alone) and
`details` embedding the original `target` / `details` / timestamp.

Loop prevention is automatic: the sender filters `audit.federate.*`
(echo) and `message.sent` (the audit row emitted by the federation send
itself) at the source, so federation cannot recurse. Operators who
want `message.sent` traffic on the aggregator can configure
`[audit] file_path` on each daemon instead and aggregate at log-pipeline
level — federation is for operator-meaningful state mutations
(workspace.create, peer.add, capability.deliver, …), not message-
machinery internals.

Operational layout for an HA fleet aggregator pair:

```toml
# Each member daemon — fans out to BOTH aggregators in parallel
[audit]
aggregators = [
  "0123456789abcdef0123456789",  # primary aggregator agent_id
  "fedcba9876543210fedcba9876",  # secondary aggregator agent_id
]

# Each aggregator daemon
[audit]
accept_federation = true
```

#### HTTP webhook push (managed log aggregators)

`[audit] webhook_url = "https://…"` (or `HERMOD_AUDIT_WEBHOOK_URL`)
POSTs every audit row as a single JSON object to the given endpoint.
Drop-in for DataDog Logs, Loki HTTP push, OpenTelemetry collector
OTLP/HTTP-JSON, or any generic webhook accepting JSON. Optional
`webhook_bearer_token` (or `HERMOD_AUDIT_WEBHOOK_BEARER_TOKEN`) sends
`Authorization: Bearer <token>` — keep secrets in the env var so the
TOML config can be checked in.

Architecture: `record()` is non-blocking (drops the row into a bounded
queue and returns); a background worker drains the queue and POSTs
sequentially. Queue overflow drops with a warn — a wedged or
misconfigured webhook never blocks a `workspace.create` call. The
SQLite hash-chain remains the source of truth regardless of webhook
health.

Example for DataDog:

```toml
[audit]
webhook_url = "https://http-intake.logs.datadoghq.com/api/v2/logs"
# webhook_bearer_token via env: HERMOD_AUDIT_WEBHOOK_BEARER_TOKEN=<DD_API_KEY>
```

Body shape (one POST per row, same schema as `[audit] file_path`):

```json
{"ts":"2026-04-27T...","ts_ms":1745800000000,"actor":"…","action":"workspace.create","target":"…","details":{…}}
```

A missing/empty config file is fine — env-var-only is supported.

#### TLS hot-rotate (cert renewal without restart)

The federation listener's TLS material can be rotated in place by
replacing the on-disk PEM files and sending the daemon `SIGHUP`. The
running listener swaps its acceptor atomically — in-flight handshakes
finish on their pinned acceptor, new accepts pick up the rotated
cert. Outbound dialing is unaffected (each dial builds a fresh client
side).

Operator runbook:

```sh
# 1. Stage the new cert + key alongside the old ones
mv new.crt $HERMOD_HOME/identity/tls.crt
mv new.key $HERMOD_HOME/identity/tls.key

# 2. Tell the daemon to pick them up
kill -HUP $(pgrep -f hermodd)
```

Successful rotates log:

```text
INFO TLS hot-rotate: federation listener swapped backend=wss-noise
```

Failures (parse error, IO error, transport rejected the new
material) log a `warn` and **leave the previous cert in place** — a
partial-state rotate is worse than the operator getting a clear
error to react to. The daemon never crashes on a bad SIGHUP.

#### Broker mode (Matrix homeserver / SMTP smarthost pattern)

Two complementary roles share one daemon binary. Operator opts in via env:

* **Broker host** — set `HERMOD_BROKER_MODE=relay_and_witness` (or
  `relay_only` to forward without per-envelope audit rows) to make
  the daemon forward envelopes addressed to other peers in its
  directory. With `relay_and_witness`, every relay attempt emits a
  `broker.relay.{forwarded|rejected}` row in the hash-chained audit
  log. The signature is preserved verbatim — the broker cannot
  tamper with content.
* **Broker client** — set `HERMOD_FEDERATION_UPSTREAM_BROKER=wss://broker_host:port#<broker_pubkey_hex>`
  on a client daemon to route outbound envelopes via the broker
  whenever the recipient is in the local directory but lacks an
  endpoint of its own. The router stamps `route: brokered` on the
  `message.sent` audit row so operators can see which envelopes
  traversed the broker. Configure `agent register --pubkey-hex <peer_pk>`
  for each remote agent the operator wants to reach — no `peer add`
  with an endpoint required.

Pair the two for an enterprise deployment that wants centralised egress
audit, NAT-traversal, or rate-limited outbound: every client points
its `upstream_broker` at the broker host, and the broker host alone
sees the whole org's traffic. Clients still verify signatures
end-to-end (the broker's relayed envelope carries the original
sender's signature), so a malicious broker cannot impersonate a peer
— it can only refuse to forward.

#### Storage backends

Backend selection is by URL scheme on `[storage] url`. Built-in:

| Scheme       | Status   | DSN form                                       |
| ------------ | -------- | ---------------------------------------------- |
| `sqlite`     | full     | `sqlite:///$HERMOD_HOME/hermod.db`             |
| `postgres`   | full\*   | `postgres://user:pass@host:5432/dbname`        |

\* The PostgreSQL backend is gated behind the crate feature
`hermod-storage/postgres`; build with
`cargo build --release --features hermod-storage/postgres` (default
builds are SQLite-only — the daemon binary stays lean for the
single-host case). Every `Database` repository is implemented and
integration-tested against PostgreSQL 16, including hash-chain
audit append under concurrent load (per-chain `pg_advisory_xact_lock`)
and the outbox claim race (`FOR UPDATE SKIP LOCKED`). The
hash-chain canonicalisation is bit-for-bit identical between the two
backends, so an audit-archive blob exported from one verifies under
the other — useful for migrations and disaster recovery.

Switching backends is a one-field config change:

```toml
[storage]
# url = "sqlite:///$HERMOD_HOME/hermod.db"   # default, single-host
url = "postgres://hermod:secret@db.internal/hermod"
```

No service-layer code, no env vars beyond `HERMOD_STORAGE_URL`, and
no migration tooling needs to change — the backend abstraction is
genuinely driver-agnostic.

---

## 5. Kubernetes

Run one Pod per identity. SQLite + WAL works on a `PersistentVolume`
(ext4 / xfs); two replicas writing the same volume will corrupt the
database, so use `replicas: 1` with a `StatefulSet`.

Sketch:

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata: { name: hermod }
spec:
  serviceName: hermod
  replicas: 1
  selector: { matchLabels: { app: hermod } }
  template:
    metadata: { labels: { app: hermod } }
    spec:
      containers:
      - name: hermodd
        image: ghcr.io/your-org/hermod:1
        env:
        - { name: HERMOD_DAEMON_LISTEN_WS,       value: "0.0.0.0:7823" }
        - { name: HERMOD_DAEMON_METRICS_LISTEN,  value: "0.0.0.0:9690" }
        - { name: HERMOD_FEDERATION_ENABLED,     value: "true" }
        - { name: HERMOD_DAEMON_LOG_FORMAT,             value: "json" }
        ports:
        - { name: federation, containerPort: 7823 }
        - { name: metrics,    containerPort: 9690 }
        livenessProbe:
          httpGet: { path: /healthz, port: metrics }
          periodSeconds: 30
        readinessProbe:
          httpGet: { path: /healthz, port: metrics }
          periodSeconds: 10
        volumeMounts:
        - { name: hermod-home, mountPath: /var/lib/hermod }
  volumeClaimTemplates:
  - metadata: { name: hermod-home }
    spec:
      accessModes: ["ReadWriteOnce"]
      resources: { requests: { storage: 1Gi } }
```

Expose the federation port via a `Service` (typically `LoadBalancer` or
`NodePort` for a cluster reachable from peers). Keep the metrics port
internal — scrape via Prometheus `ServiceMonitor` / pod annotations.

The identity key is on the `PersistentVolume`. For HSM / KMS storage,
generate the key out-of-band and write it to a `Secret` mounted at
`/var/lib/hermod/identity/ed25519_secret` with `defaultMode: 0o600`;
`hermodd` will pick it up.

### Multiple agents per cluster

Each unique agent_id needs its own daemon (the daemon's identity is its
keypair). Run one StatefulSet per user / agent. There is no
multi-tenant single-binary mode by design — separation of identity is
the threat-model boundary.

---

## 6. Claude Code

Register the MCP server once at user scope:

```sh
claude mcp add hermod hermod mcp --scope user
```

Then launch Claude Code with the channel feature flag enabled (research
preview requirement until the API stabilises):

```sh
claude --dangerously-load-development-channels server:hermod
```

The MCP server speaks JSON-RPC over stdio; Claude Code launches it on
first use. It declares the `experimental.claude/channel` capability and
runs a polling emitter that watches the local daemon for new inbox events
and confirmations. Each event becomes a `notifications/claude/channel`
notification — the agent sees a fresh `<channel source="hermod">` block
per item.

Tools surfaced (22): `message_send`, `message_list`, `message_ack`,
`agent_list`, `agent_get`, `brief_publish`, `brief_read`,
`presence_set_manual`, `presence_clear_manual`, `presence_get`,
`workspace_create`, `workspace_join`, `workspace_list`,
`workspace_invite`, `channel_create`, `channel_list`, `channel_history`,
`channel_advertise`, `channel_discover`, `channel_adopt`,
`broadcast_send`, `confirmation_list`. Trust-gate acceptance/rejection
is operator-only via `hermod confirm` CLI — agents observe held
confirmations but cannot decide.

Identity vs display — every agent has a stable `id` (ed25519 pubkey
hash) used for routing, crypto, audit and a separate display layer
exposed as three optional aliases:

- `local_alias` — operator-set nickname (`peer add --alias`,
  `init --alias`). Sacred, UNIQUE, the only field consulted for
  `--to @alias` resolution.
- `peer_asserted_alias` — what the peer itself claims in their signed
  Hello / Presence / mDNS TXT. Advisory.
- `effective_alias` — derived: local wins, peer fallback. UIs render
  this.

Peer self-claims that collide with an existing `local_alias` are
silently dropped and audited as `peer.alias_collision` — no peer can
take a name the operator already bound.

Liveness — the MCP server registers itself via `mcp.attach` on
initialize, heartbeats every 30 s, and detaches on stdin EOF. The
daemon derives self liveness from atomic transactions on `mcp_sessions`
(no read-then-write races on attach / detach / janitor sweep); the
janitor reaps any session whose heartbeat is older than 90 s (3×
heartbeat). Genuine offline ↔ online transitions trigger a
`MessageBody::Presence` fanout to workspace members so peers'
`presence.get` reflects reality without polling.

### Pointing the MCP server at a remote daemon

When the daemon lives somewhere other than the device running Claude
Code (laptop ↔ cloud, see [§3](#3-cloud-daemon--thin-clients-remote-ipc)),
the MCP subprocess connects to the daemon over WSS+Bearer. Same MCP
tool surface, different transport underneath.

```jsonc
{
  "mcpServers": {
    "hermod-cloud": {
      "command": "hermod",
      "args": [
        "--remote", "wss://my-daemon.example.com:7824/",
        "mcp"
      ],
      "env": {
        "HERMOD_BEARER_TOKEN": "<paste from the cloud host's identity/bearer_token>"
      }
    }
  }
}
```

For multiple identities (work / personal / cloud), point each MCP
server entry at a different `HERMOD_HOME` (local) or `--remote` URL
(cloud) — Claude Code will list each as its own toolset.

## 7. Diagnostics

`hermod doctor` is the first thing to run when something doesn't work:

```
hermod doctor:
  ok    $HERMOD_HOME exists and is readable
  ok    config.toml present
  ok    identity/ed25519_secret present
  ok    identity secret has restricted permissions
  ok    identity loadable
  ok    TLS certificate readable / generatable
  ok    daemon reachable on Unix socket
  ok    daemon status: agent_id=…, peers=2, pending=0, uptime=3621s
  ok    audit chain intact (218 rows)
  note  2 federation peer(s) known

  → all checks passed
```

It exits non-zero when any check fails, so it's safe to invoke from
container `livenessProbe` (`exec` form) or CI.

## 8. Backup / restore

A daemon's persistent state is `$HERMOD_HOME`:

```
$HERMOD_HOME/
  config.toml
  hermod.db                      # SQLite (or use [storage] url for Postgres)
  blobs/                         # file payloads + audit archives
  identity/
    ed25519_secret               # 32-byte seed — agent_id derives from this
    tls.crt                      # regenerable from ed25519_secret
    tls.key                      # regenerable from ed25519_secret
    bearer_token                 # remote-IPC bearer
```

### What to back up

| Asset | Loss impact | Backup cadence |
| --- | --- | --- |
| `identity/ed25519_secret` | Permanent identity loss — `agent_id` is `blake3(pubkey)[:26]`; new seed = new agent. No recovery path. | One-time at provisioning, rotate only when key is compromised. **Encrypt with operator passphrase before storing offline.** |
| `hermod.db` | Inbox + peer directory + audit history. SQLite WAL is crash-safe; backup with `VACUUM INTO '/path/backup.db'` for a transactionally consistent snapshot. Postgres: `pg_basebackup` + WAL archiving for PITR. | Per-deployment SLA. Hourly snapshot is typical for an active daemon. |
| `blobs/` | File payloads + audit archive day-buckets. Loss of an audit archive day-bucket fails `hermod audit verify-archive` for that day; live audit log unaffected. | Same cadence as `hermod.db`. `rsync` for LocalFs; S3 lifecycle for cloud. |
| `tls.crt` / `tls.key` | Regenerable from `ed25519_secret` — `hermod init` rebuilds them on missing. Peers re-pin via TOFU on first reconnect. | No backup required; just keep the seed. |
| `bearer_token` | Remote-IPC bearer rotation. Regenerable via `hermod bearer rotate` (or just delete the file and restart). | No backup required. |

### Identity-seed backup procedure

The seed is 32 raw bytes. Encrypt and store offline:

```sh
# On the daemon host:
age -p < $HERMOD_HOME/identity/ed25519_secret > /secure/offline/hermod-seed.age
# (or: gpg -c --output hermod-seed.gpg)

# Verify the encrypted blob actually decrypts before walking away:
age -d /secure/offline/hermod-seed.age | wc -c  # → expect 32
```

Restore:

```sh
mkdir -p $HERMOD_HOME/identity
age -d /secure/offline/hermod-seed.age > $HERMOD_HOME/identity/ed25519_secret
chmod 0600 $HERMOD_HOME/identity/ed25519_secret
# Daemon refuses to start on world-readable mode — the chmod is mandatory.
hermodd  # tls.crt + tls.key regenerate on first start.
```

### Restore a daemon on a new host

```sh
# 1. Restore identity (the load-bearing artifact).
mkdir -p $HERMOD_HOME/identity
age -d /secure/offline/hermod-seed.age > $HERMOD_HOME/identity/ed25519_secret
chmod 0600 $HERMOD_HOME/identity/ed25519_secret

# 2. Restore the database snapshot.
cp /backup/hermod-2026-04-27.db $HERMOD_HOME/hermod.db   # SQLite
# or: pg_restore -d $HERMOD_DB_URL /backup/hermod-2026-04-27.dump

# 3. Restore the BlobStore (file payloads + audit archives).
rsync -a /backup/blobs/ $HERMOD_HOME/blobs/

# 4. Re-derive TLS material from the seed.
hermod init --tls-only       # idempotent; regenerates tls.crt + tls.key

# 5. Verify integrity end-to-end.
hermod doctor                # 0600 mode + identity loadable + audit verify
hermod audit verify          # walks the full hash chain (live + archives)

# 6. Start.
hermodd
```

The new host now serves the original `agent_id`. Peers that pinned the
old TLS fingerprint will reject the new self-signed cert; the operator
re-pins on each peer with `hermod peer repin <agent_id> <new_fingerprint>`,
which the receiving operator must approve out of band — fingerprint
rotation is intentionally manual to keep TOFU's "first connect"
guarantee meaningful.

---

## Out of scope (today)

- **STUN / ICE NAT hole-punching.** Pure-P2P NAT traversal between two
  consumer-grade NATs is not built in. The supported pattern for
  reachability behind NAT is broker mode (see "Broker mode" above):
  a publicly reachable daemon hosts the relay/witness role, NATed
  clients set `[federation] upstream_broker` and route outbound
  through it.
- **Centralised directory.** Each daemon is autonomous; peer lists
  are per-daemon.
- **Multi-replica per identity.** A single Hermod identity is one
  active daemon by design — envelope ordering and the hash-chained
  audit log assume a single writer. For HA, deploy single-pod and
  let your Postgres provider handle DB-layer HA (RDS Multi-AZ,
  Aurora, Cloud SQL HA, Patroni); the daemon connects to one
  Postgres endpoint that can be highly available underneath. K8s
  pod restart on failure typically gives sub-10s recovery.
- **Let's Encrypt automation.** The TLS cert is self-signed and TOFU-
  pinned; ACME isn't necessary for the protocol's security. If you
  want a publicly trusted cert (e.g. middlebox compatibility),
  terminate TLS at a reverse proxy and proxy plain WS to `hermodd`
  with `[daemon] listen_ws = 127.0.0.1:7823`.
