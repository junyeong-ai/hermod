---
description: Suffix taxonomy for new types + RPC method shape
---

# Naming taxonomy

Pick the right suffix before introducing a type. Mismatch surfaces as
test or review noise.

| Suffix | Meaning | Example |
| --- | --- | --- |
| `*Verdict` | Policy-gate judgment | `AccessVerdict { Accept, Reject }`, `confirmation::Verdict { Accept, Reject, Confirm }` |
| `*Outcome` | Operation result with success-path branches | `RelayOutcome`, `DeliveryOutcome`, `MessagePruneOutcome`, `AliasOutcome`, `RepinOutcome`, `DetachOutcome`, `TransitionOutcome`, `ForgetOutcome`, `presence::PruneOutcome` |
| `*Result` | RPC response payload paired with `*Params` | `MessageSendResult`, `WorkspaceRosterResult` |
| `*Response` | Protocol message-pair counterpart inside an envelope body | `WorkspaceRosterResponse` |
| `*Chunk` | One peer's slice of an aggregated fan-out | `RosterChunk`, `ChannelsChunk` |
| `*Repository` | Per-collection storage trait | `AgentRepository`, `MessageRepository` |
| `*Service` | Daemon service held by the dispatcher | `MessageService`, `BrokerService` |
| `*Sink` | Composable audit destination | `StorageAuditSink`, `RemoteAuditSink`, `TeeAuditSink` |
| `*Provider` | External credential / dynamic input supplier — caching policy is encapsulated inside the implementation, callers see only `current()` / `refresh()` | `BearerProvider`, `StaticBearerProvider`, `FileBearerProvider`, `CommandBearerProvider` |
| `*Mode` | Operator enum collapsing previously-conflicting bool combos | `BrokerMode { Disabled, RelayOnly, RelayAndWitness }` |
| `*Auditor` | Side-channel observer (e.g. `BeaconAuditor`) | |
| `*Forwarder` / `*Responder` | Async trait for cross-service callbacks (broken circular dep) | `PromptForwarder`, `RelayResponder` |

## RPC method shape

Every IPC method = `<namespace>.<verb>`, snake_case lowercase. The
const lives in `crates/hermod-protocol/src/ipc/methods.rs`:

```rust
pub const MESSAGE_SEND: &str = "message.send";
```

Const ident = `<NAMESPACE>_<VERB>`. `scripts/check_naming.sh` enforces
both the const-name shape and the dispatcher-arm coverage.

`*Params` / `*Result` types follow `<Namespace><Verb>Params|Result`:
`MessageSendParams`, `MessageSendResult`.
