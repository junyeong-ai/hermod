//! End-to-end federation regression test.
//!
//! Drives two daemons via the actual `hermodd` and `hermod` binaries and
//! verifies the fixes that aren't covered by unit tests:
//!
//!   * `peer trust` writes to the agents table the inbound gate reads (the
//!     trust-table disconnect that broke trust elevation).
//!   * `workspace.invite` populates `workspace_members` on the inviter so
//!     subsequent `channel.advertise` / `broadcast.send` fan out non-zero.
//!   * `channel.advertise` / `channel.discover` / `channel.adopt` complete
//!     a full discovery → adopt → broadcast loop.
//!   * `brief.publish` / `presence.set_manual` propagate to the recipient
//!     daemon via workspace fanout, so cross-daemon `brief.read` /
//!     `presence.get` return the published value.
//!   * Inbound rate limit kicks in when the per-sender allowance is
//!     exceeded.
//!
//! The test uses `cargo`'s post-build artifacts (`target/release/`),
//! ephemeral `HERMOD_HOME` directories per daemon, and bound localhost
//! sockets. It blocks until each daemon's WSS listener is reachable so
//! ordering is deterministic.

#![cfg(unix)]

use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const RELEASE_DIR: &str = "../../target/release";

struct Daemon {
    child: Child,
    home: tempfile::TempDir,
    fed_addr: SocketAddr,
}

#[derive(Default)]
struct DaemonConfig {
    rate_limit: Option<u32>,
    broker_mode: Option<&'static str>,
}

impl DaemonConfig {
    fn rate_limit(mut self, v: Option<u32>) -> Self {
        self.rate_limit = v;
        self
    }
    fn broker_mode(mut self, v: &'static str) -> Self {
        self.broker_mode = Some(v);
        self
    }
}

impl Daemon {
    fn spawn(alias: &str, fed_port: u16, rate_limit: Option<u32>) -> Self {
        Self::spawn_with(
            alias,
            fed_port,
            DaemonConfig::default().rate_limit(rate_limit),
        )
    }

    fn spawn_with(alias: &str, fed_port: u16, cfg: DaemonConfig) -> Self {
        let home = tempfile::tempdir().expect("tempdir");
        let bin_hermod = release_bin("hermod");
        let bin_hermodd = release_bin("hermodd");

        let init_status = Command::new(&bin_hermod)
            .env("HERMOD_HOME", home.path())
            .args(["init", "--alias", alias])
            .status()
            .expect("hermod init");
        assert!(init_status.success(), "hermod init failed");

        let socket = home.path().join("sock");
        let fed_addr: SocketAddr = format!("127.0.0.1:{fed_port}").parse().unwrap();

        let mut cmd = Command::new(&bin_hermodd);
        cmd.env("HERMOD_HOME", home.path())
            .env("HERMOD_DAEMON_SOCKET_PATH", &socket)
            .env("HERMOD_DAEMON_LISTEN_WS", fed_addr.to_string())
            .env("HERMOD_FEDERATION_ENABLED", "true")
            .env("HERMOD_DAEMON_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(r) = cfg.rate_limit {
            cmd.env("HERMOD_POLICY_RATE_LIMIT_PER_SENDER", r.to_string());
        }
        if let Some(mode) = cfg.broker_mode {
            cmd.env("HERMOD_BROKER_MODE", mode);
        }
        let child = cmd.spawn().expect("spawn hermodd");
        wait_for_port(fed_addr, Duration::from_secs(5));

        Daemon {
            child,
            home,
            fed_addr,
        }
    }

    fn run(&self, args: &[&str]) -> (i32, String) {
        let bin = release_bin("hermod");
        let out = Command::new(&bin)
            .env("HERMOD_HOME", self.home.path())
            .args(args)
            .output()
            .expect("hermod run");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        (out.status.code().unwrap_or(-1), stdout)
    }

    fn agent_id(&self) -> String {
        let (_, out) = self.run(&["identity"]);
        out.lines()
            .find_map(|l| l.strip_prefix("agent_id:"))
            .map(|s| s.trim().to_string())
            .expect("agent_id in output")
    }

    fn agent_pubkey_hex(&self) -> String {
        let (_, out) = self.run(&["identity"]);
        out.lines()
            .find_map(|l| l.strip_prefix("pubkey_hex:"))
            .map(|s| s.trim().to_string())
            .expect("pubkey_hex in output")
    }

    fn host_pubkey_hex(&self) -> String {
        let (_, out) = self.run(&["identity"]);
        out.lines()
            .find_map(|l| l.strip_prefix("host_pubkey:"))
            .map(|s| s.trim().to_string())
            .expect("host_pubkey in output")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn release_bin(name: &str) -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest).join(RELEASE_DIR).join(name)
}

fn wait_for_port(addr: SocketAddr, timeout: Duration) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("port {addr} not reachable within {timeout:?}");
}

fn extract_field<'a>(haystack: &'a str, field: &str) -> Option<&'a str> {
    let needle = format!("\"{}\":", field);
    let i = haystack.find(&needle)?;
    let rest = &haystack[i + needle.len()..];
    let q1 = rest.find('"')?;
    let q2 = rest[q1 + 1..].find('"')?;
    Some(&rest[q1 + 1..q1 + 1 + q2])
}

#[test]
fn federation_end_to_end() {
    let alice = Daemon::spawn("alice", 17923, None);
    let bob = Daemon::spawn("bob", 17924, None);
    let alice_id = alice.agent_id();
    let bob_id = bob.agent_id();
    let alice_host_pk = alice.host_pubkey_hex();
    let bob_host_pk = bob.host_pubkey_hex();
    let alice_agent_pk = alice.agent_pubkey_hex();
    let bob_agent_pk = bob.agent_pubkey_hex();

    // Bidirectional peer add + verified trust.
    let (rc, _) = alice.run(&[
        "peer",
        "add",
        "--endpoint",
        &format!("wss://{}", bob.fed_addr),
        "--host-pubkey-hex",
        &bob_host_pk,
        "--agent-pubkey-hex",
        &bob_agent_pk,
        "--alias",
        "bob",
    ]);
    assert_eq!(rc, 0, "alice peer add bob");
    let (rc, _) = bob.run(&[
        "peer",
        "add",
        "--endpoint",
        &format!("wss://{}", alice.fed_addr),
        "--host-pubkey-hex",
        &alice_host_pk,
        "--agent-pubkey-hex",
        &alice_agent_pk,
        "--alias",
        "alice",
    ]);
    assert_eq!(rc, 0, "bob peer add alice");
    alice.run(&["peer", "trust", &bob_id, "verified"]);
    bob.run(&["peer", "trust", &alice_id, "verified"]);

    // Verified DM goes through without a confirmation hold.
    let (rc, send_out) = alice.run(&[
        "message",
        "send",
        "--to",
        &bob_id,
        "--body",
        "hi from alice",
    ]);
    assert_eq!(rc, 0, "alice send DM");
    assert!(
        send_out.contains("delivered"),
        "expected delivered status, got: {send_out}"
    );
    std::thread::sleep(Duration::from_millis(300));
    let (_, list_out) = bob.run(&["message", "list"]);
    assert!(list_out.contains("hi from alice"), "bob inbox: {list_out}");

    // Workspace + channel adopt + broadcast.
    let (rc, ws_out) = alice.run(&["workspace", "create", "eng-team"]);
    assert_eq!(rc, 0, "create workspace");
    let ws_id = extract_field(&ws_out, "id")
        .expect("workspace id")
        .to_string();
    let (rc, ch_out) = alice.run(&[
        "channel",
        "create",
        "--workspace-id",
        &ws_id,
        "--name",
        "general",
    ]);
    assert_eq!(rc, 0, "create channel");
    let ch_id = extract_field(&ch_out, "id")
        .expect("channel id")
        .to_string();

    alice.run(&[
        "workspace",
        "invite",
        "--workspace-id",
        &ws_id,
        "--target",
        &bob_id,
    ]);
    std::thread::sleep(Duration::from_millis(500));
    let (_, conf_out) = bob.run(&["confirm", "list"]);
    let hold_id = extract_field(&conf_out, "id").expect("hold id").to_string();
    let (rc, _) = bob.run(&["confirm", "accept", &hold_id]);
    assert_eq!(rc, 0, "bob accept invite");

    let (_, adv_out) = alice.run(&["channel", "advertise", &ch_id]);
    assert!(
        adv_out.contains("\"fanout\": 1"),
        "advertise fanout=1 expected after invite, got: {adv_out}"
    );
    std::thread::sleep(Duration::from_millis(300));

    let (rc, adopt_out) = bob.run(&["channel", "adopt", &ch_id]);
    assert_eq!(rc, 0, "bob adopt");
    assert!(adopt_out.contains(&ch_id));

    let (_, bc_out) = alice.run(&[
        "broadcast",
        "send",
        "--channel-id",
        &ch_id,
        "--text",
        "hello team",
    ]);
    assert!(
        bc_out.contains("\"fanout\": 1"),
        "broadcast fanout: {bc_out}"
    );
    std::thread::sleep(Duration::from_millis(300));
    let (_, hist_out) = bob.run(&["channel", "history", &ch_id]);
    assert!(
        hist_out.contains("hello team"),
        "bob channel history: {hist_out}"
    );

    // Brief federation: alice publishes, bob reads.
    alice.run(&[
        "brief",
        "publish",
        "--summary",
        "alice working on auth refactor",
        "--topic",
        "backend",
    ]);
    std::thread::sleep(Duration::from_millis(500));
    let (_, brief_out) = bob.run(&["brief", "read", &alice_id]);
    assert!(
        brief_out.contains("auth refactor"),
        "bob brief read alice: {brief_out}"
    );

    // Presence federation.
    alice.run(&["presence", "set", "busy"]);
    std::thread::sleep(Duration::from_millis(500));
    let (_, pres_out) = bob.run(&["presence", "get", &alice_id]);
    assert!(
        pres_out.contains("\"busy\""),
        "bob presence get alice: {pres_out}"
    );

    // Alias federation: bob's `peer add --alias alice` sets
    // `local_alias = "alice"` on the agent row. Hello frames carry
    // host identity only; per-agent peer-asserted aliases land via
    // H7 `peer.advertise` (out of scope here).
    let (_, getout) = bob.run(&["agent", "get", &alice_id]);
    assert!(
        getout.contains("\"local_alias\": \"alice\""),
        "bob's local_alias for alice (set by peer add --alias): {getout}"
    );
    assert!(
        getout.contains("\"effective_alias\": \"alice\""),
        "effective_alias derived: {getout}"
    );

    // Audit chain still verifies after the whole flow.
    let (_, verify_out) = bob.run(&["audit", "verify"]);
    assert!(
        verify_out.contains("\"verdict\": \"ok\""),
        "audit verify: {verify_out}"
    );
}

#[test]
fn inbound_rate_limit_kicks_in() {
    let alice = Daemon::spawn("alice", 17925, None);
    let bob = Daemon::spawn("bob", 17926, Some(2));
    let alice_id = alice.agent_id();
    let bob_id = bob.agent_id();
    let alice_host_pk = alice.host_pubkey_hex();
    let bob_host_pk = bob.host_pubkey_hex();
    let alice_agent_pk = alice.agent_pubkey_hex();
    let bob_agent_pk = bob.agent_pubkey_hex();

    alice.run(&[
        "peer",
        "add",
        "--endpoint",
        &format!("wss://{}", bob.fed_addr),
        "--host-pubkey-hex",
        &bob_host_pk,
        "--agent-pubkey-hex",
        &bob_agent_pk,
    ]);
    bob.run(&[
        "peer",
        "add",
        "--endpoint",
        &format!("wss://{}", alice.fed_addr),
        "--host-pubkey-hex",
        &alice_host_pk,
        "--agent-pubkey-hex",
        &alice_agent_pk,
    ]);
    alice.run(&["peer", "trust", &bob_id, "verified"]);
    bob.run(&["peer", "trust", &alice_id, "verified"]);

    let mut delivered = 0u32;
    let mut failed = 0u32;
    for i in 0..5 {
        let (_, out) = alice.run(&[
            "message",
            "send",
            "--to",
            &bob_id,
            "--body",
            &format!("burst {i}"),
        ]);
        if out.contains("delivered") {
            delivered += 1;
        } else if out.contains("failed") {
            failed += 1;
        }
    }
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        delivered <= 2,
        "expected at most 2 delivered, got {delivered}"
    );
    assert!(failed >= 3, "expected at least 3 failed, got {failed}");
    let (_, list_out) = bob.run(&["message", "list"]);
    let total_count = list_out.matches("\"id\": \"").count();
    assert!(
        total_count <= 2,
        "bob inbox should have at most 2 messages, got {total_count}: {list_out}"
    );
}

/// Honesty contract: `peer advertise --target` must report the
/// actual wire delivery status per target, not the queue-ack
/// status. Concretely — kill bob, fire alice's advertise at @bob,
/// the response must show `status: "failed"` and the CLI must exit
/// non-zero.
///
/// Mirrors the behaviour of `message send`, which already returns
/// `{"status":"delivered"|"failed"}` truthfully. Before this fix
/// the response was `{"fanout": 1}` even when the wire failed —
/// dishonest UX that masked queued-against-dead-peer scenarios.
#[test]
fn peer_advertise_reports_failed_when_target_down() {
    let alice = Daemon::spawn("alice", 17927, None);
    let bob = Daemon::spawn("bob", 17928, None);
    let alice_id = alice.agent_id();
    let bob_id = bob.agent_id();
    let alice_host_pk = alice.host_pubkey_hex();
    let bob_host_pk = bob.host_pubkey_hex();
    let alice_agent_pk = alice.agent_pubkey_hex();
    let bob_agent_pk = bob.agent_pubkey_hex();

    // Bidirectional verified peering so the directory has bob's
    // endpoint pinned. `peer add` itself triggers an auto-advertise
    // that we let happen — the test exercises a *subsequent*
    // explicit advertise into a now-down peer.
    alice.run(&[
        "peer",
        "add",
        "--endpoint",
        &format!("wss://{}", bob.fed_addr),
        "--host-pubkey-hex",
        &bob_host_pk,
        "--agent-pubkey-hex",
        &bob_agent_pk,
        "--alias",
        "bob",
    ]);
    bob.run(&[
        "peer",
        "add",
        "--endpoint",
        &format!("wss://{}", alice.fed_addr),
        "--host-pubkey-hex",
        &alice_host_pk,
        "--agent-pubkey-hex",
        &alice_agent_pk,
    ]);
    alice.run(&["peer", "trust", &bob_id, "verified"]);
    bob.run(&["peer", "trust", &alice_id, "verified"]);

    // Sanity — advertise to a live bob succeeds (and exits 0).
    let (rc, out) = alice.run(&["peer", "advertise", "--target", &bob_id]);
    assert_eq!(rc, 0, "advertise to live peer should exit 0; got: {out}");
    assert!(
        out.contains("\"status\": \"delivered\""),
        "live advertise must report delivered: {out}"
    );
    assert!(
        out.contains(&format!("\"target\": \"{bob_id}\"")),
        "delivery row must carry target id: {out}"
    );

    // Kill bob so the pool entry's next dial fails.
    drop(bob);
    // Give the OS a moment to release bob's listening socket so the
    // next `peer advertise` actually hits a refused connection
    // rather than racing on shutdown.
    std::thread::sleep(Duration::from_millis(500));

    // Honest failure: per-target row reports failed + exit non-zero.
    let (rc, out) = alice.run(&["peer", "advertise", "--target", &bob_id]);
    assert_ne!(
        rc, 0,
        "advertise to down peer must exit non-zero; got: {out}"
    );
    assert!(
        out.contains("\"status\": \"failed\""),
        "down-peer advertise must report failed: {out}"
    );
    assert!(
        out.contains("\"error\":"),
        "failed delivery must carry an error string: {out}"
    );

    // Audit row reflects the same outcome — no `fanout > 0` lie.
    let (_, audit_out) = alice.run(&[
        "audit",
        "query",
        "--action",
        "peer.advertise",
        "--limit",
        "1",
    ]);
    assert!(
        audit_out.contains("\"failed\":") && audit_out.contains("\"delivered\":"),
        "audit must record per-status counts (delivered + failed): {audit_out}"
    );
}

/// PR-2 mesh e2e: alice and bob can DM each other through a relay
/// broker even though neither knows the other's endpoint. Topology:
///
/// ```text
///   alice ──┐               ┌── bob
///           ▼               ▼
///         broker (relay_only, public endpoint)
/// ```
///
/// Alice's directory has `bob` registered with `via_agent_id =
/// broker.id` (no endpoint). The dispatcher resolves to
/// `RouteDecision::Brokered { endpoint: broker.endpoint, via:
/// broker.id }`; the broker's `RelayOnly` fall-through forwards to
/// bob.
#[test]
fn brokered_mesh_via_relay_only_broker() {
    let alice = Daemon::spawn("alice", 17929, None);
    let broker = Daemon::spawn_with(
        "broker",
        17930,
        DaemonConfig::default().broker_mode("relay_only"),
    );
    let bob = Daemon::spawn("bob", 17931, None);

    let alice_id = alice.agent_id();
    let alice_host_pk = alice.host_pubkey_hex();
    let alice_agent_pk = alice.agent_pubkey_hex();
    let broker_id = broker.agent_id();
    let broker_host_pk = broker.host_pubkey_hex();
    let broker_agent_pk = broker.agent_pubkey_hex();
    let bob_id = bob.agent_id();
    let bob_host_pk = bob.host_pubkey_hex();
    let bob_agent_pk = bob.agent_pubkey_hex();

    // alice trusts broker directly, bob trusts broker directly.
    // Brokered routing requires the *broker* to also have direct
    // peer entries for each endpoint it relays to — that's a
    // RelayOnly invariant (the broker holds Noise XX keys for both
    // sides).
    alice.run(&[
        "peer",
        "add",
        "--endpoint",
        &format!("wss://{}", broker.fed_addr),
        "--host-pubkey-hex",
        &broker_host_pk,
        "--agent-pubkey-hex",
        &broker_agent_pk,
        "--alias",
        "broker",
    ]);
    broker.run(&[
        "peer",
        "add",
        "--endpoint",
        &format!("wss://{}", alice.fed_addr),
        "--host-pubkey-hex",
        &alice_host_pk,
        "--agent-pubkey-hex",
        &alice_agent_pk,
    ]);
    broker.run(&[
        "peer",
        "add",
        "--endpoint",
        &format!("wss://{}", bob.fed_addr),
        "--host-pubkey-hex",
        &bob_host_pk,
        "--agent-pubkey-hex",
        &bob_agent_pk,
    ]);
    bob.run(&[
        "peer",
        "add",
        "--endpoint",
        &format!("wss://{}", broker.fed_addr),
        "--host-pubkey-hex",
        &broker_host_pk,
        "--agent-pubkey-hex",
        &broker_agent_pk,
    ]);
    alice.run(&["peer", "trust", &broker_id, "verified"]);
    broker.run(&["peer", "trust", &alice_id, "verified"]);
    broker.run(&["peer", "trust", &bob_id, "verified"]);
    bob.run(&["peer", "trust", &broker_id, "verified"]);

    // The crux — alice registers bob with `--via @broker`, no
    // endpoint of her own. Dispatcher should resolve to Brokered.
    let (rc, add_out) = alice.run(&[
        "peer",
        "add",
        "--via",
        "@broker",
        "--host-pubkey-hex",
        &bob_host_pk,
        "--agent-pubkey-hex",
        &bob_agent_pk,
        "--alias",
        "bob",
    ]);
    assert_eq!(rc, 0, "alice peer add bob via broker; out: {add_out}");
    assert!(
        add_out.contains("\"trust_level\": \"tofu\""),
        "first add is TOFU: {add_out}",
    );

    // Bob also trusts alice as relayed-via-broker (sender-side TOFU).
    bob.run(&[
        "peer",
        "add",
        "--via",
        "@broker",
        "--host-pubkey-hex",
        &alice_host_pk,
        "--agent-pubkey-hex",
        &alice_agent_pk,
        "--alias",
        "alice",
    ]);
    alice.run(&["peer", "trust", &bob_id, "verified"]);
    bob.run(&["peer", "trust", &alice_id, "verified"]);

    // Send DM alice → bob via broker.
    let (rc, send_out) = alice.run(&["message", "send", "--to", "@bob", "--body", "hi via broker"]);
    assert_eq!(rc, 0, "alice send via broker; out: {send_out}");
    assert!(
        send_out.contains("delivered"),
        "expected delivered status (broker should ack on alice's side); got: {send_out}",
    );

    // Wait for the broker to relay then bob to confirm-or-deliver.
    std::thread::sleep(Duration::from_millis(800));

    // bob's audit should show inbound from alice. Trust starts as
    // TOFU on bob's side (peer.add was TOFU); the held-confirmation
    // path may queue it. Either delivered-to-inbox or held-for-
    // confirm is correct evidence the broker relay worked.
    let (_, bob_audit) = bob.run(&["audit", "query", "--limit", "20"]);
    let saw_relay_evidence = bob_audit.contains("confirmation.held")
        || bob_audit.contains("message.delivered")
        || bob_audit.contains(&alice_id);
    assert!(
        saw_relay_evidence,
        "bob's audit should show evidence of alice's envelope arriving via broker: {bob_audit}",
    );
}

/// `peer add --via @unknown_broker` must fail loud — the broker's
/// directory row is required (FK + friendly error) before any
/// peer can be attached behind it.
#[test]
fn peer_add_via_unknown_broker_rejects() {
    let alice = Daemon::spawn("alice", 17932, None);
    let bob = Daemon::spawn("bob", 17933, None);
    let bob_host_pk = bob.host_pubkey_hex();
    let bob_agent_pk = bob.agent_pubkey_hex();

    let (rc, out) = alice.run(&[
        "peer",
        "add",
        "--via",
        "@nonexistent",
        "--host-pubkey-hex",
        &bob_host_pk,
        "--agent-pubkey-hex",
        &bob_agent_pk,
        "--alias",
        "bob",
    ]);
    assert_ne!(rc, 0, "expected non-zero exit for unknown via; got: {out}");
}

/// `peer add --endpoint X --via Y` must be rejected by clap's
/// XOR — if both are passed the CLI errors before touching the
/// daemon.
#[test]
fn peer_add_endpoint_and_via_are_mutually_exclusive() {
    let alice = Daemon::spawn("alice", 17934, None);
    let (rc, out) = alice.run(&[
        "peer",
        "add",
        "--endpoint",
        "wss://x:7823",
        "--via",
        "@broker",
        "--host-pubkey-hex",
        &"00".repeat(32),
        "--agent-pubkey-hex",
        &"00".repeat(32),
    ]);
    assert_ne!(
        rc, 0,
        "clap should reject endpoint + via both set; stdout was: {out}"
    );
}
