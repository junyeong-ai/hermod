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

impl Daemon {
    fn spawn(alias: &str, fed_port: u16, rate_limit: Option<u32>) -> Self {
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
        if let Some(r) = rate_limit {
            cmd.env("HERMOD_POLICY_RATE_LIMIT_PER_SENDER", r.to_string());
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

    fn pubkey_hex(&self) -> String {
        let (_, out) = self.run(&["identity"]);
        out.lines()
            .find_map(|l| l.strip_prefix("pubkey_hex:"))
            .map(|s| s.trim().to_string())
            .expect("pubkey_hex in output")
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
    let alice_pk = alice.pubkey_hex();
    let bob_pk = bob.pubkey_hex();

    // Bidirectional peer add + verified trust.
    let (rc, _) = alice.run(&[
        "peer",
        "add",
        "--endpoint",
        &format!("wss://{}", bob.fed_addr),
        "--pubkey-hex",
        &bob_pk,
        "--alias",
        "bob",
    ]);
    assert_eq!(rc, 0, "alice peer add bob");
    let (rc, _) = bob.run(&[
        "peer",
        "add",
        "--endpoint",
        &format!("wss://{}", alice.fed_addr),
        "--pubkey-hex",
        &alice_pk,
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

    // Alias federation. Both pathways populate distinct columns:
    //   * `local_alias` — set by bob's `peer add --alias alice` earlier.
    //   * `peer_asserted_alias` — set by alice's signed Hello frame
    //     (carried through Noise handshake) when she connected to bob.
    // Both happen to be "alice" here because the test uses matching
    // labels; the assertion verifies both columns are populated, not
    // just one.
    let (_, getout) = bob.run(&["agent", "get", &alice_id]);
    assert!(
        getout.contains("\"local_alias\": \"alice\""),
        "bob's local_alias for alice (set by peer add --alias): {getout}"
    );
    assert!(
        getout.contains("\"peer_asserted_alias\": \"alice\""),
        "alice's self-asserted alias from Hello frame: {getout}"
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
    let alice_pk = alice.pubkey_hex();
    let bob_pk = bob.pubkey_hex();

    alice.run(&[
        "peer",
        "add",
        "--endpoint",
        &format!("wss://{}", bob.fed_addr),
        "--pubkey-hex",
        &bob_pk,
    ]);
    bob.run(&[
        "peer",
        "add",
        "--endpoint",
        &format!("wss://{}", alice.fed_addr),
        "--pubkey-hex",
        &alice_pk,
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
