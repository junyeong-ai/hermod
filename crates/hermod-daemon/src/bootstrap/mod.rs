//! Daemon-startup helpers extracted from `server::serve` so each
//! construction phase has its own home and per-module unit tests.
//!
//! The orchestration sequence still lives in `crate::server::serve`;
//! these submodules host the heavier *self-contained* phases:
//!
//!   * [`audit_sink`] — composes the operator's `[audit]` config into
//!     a single `Arc<dyn AuditSink>` via the `TeeAuditSink` stack.
//!
//! Future phases (transport, services, workers) will land here too;
//! the `serve()` function progressively shrinks to a free-function
//! orchestrator that reads top-to-bottom.

pub mod audit_sink;
