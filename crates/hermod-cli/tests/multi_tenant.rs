//! Multi-tenant runtime: one daemon hosts N local agents, each
//! addressable independently over Remote IPC.
//!
//! Boots a daemon whose `$HERMOD_HOME` was provisioned with two local
//! agents (the `hermod init` bootstrap + a second one created via
//! `hermod local add --alias projB`). Each agent's bearer file is the
//! credential that picks which agent the connection authenticates as.
//!
//! Pins the full bearer-dispatch chain end-to-end:
//!   `--bearer-file` → WS Authorization header → `BearerAuthenticator
//!   ::resolve` → `CALLER_AGENT` task_local → `StatusService::identity`
//!   reading the caller's registry row → returned `agent_id`.
//!
//! Without this, the H3 (bearer dispatch) + H4 (per-call signer) +
//! H5 (CLI provisioning) + H6 (caller-aware identity) stack has no
//! whole-pipeline regression test — channels.rs and federation.rs
//! both run with one local agent.

#![cfg(unix)]

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const RELEASE_DIR: &str = "../../target/release";

fn release_bin(name: &str) -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest).join(RELEASE_DIR).join(name)
}

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let p = l.local_addr().expect("local_addr").port();
    drop(l);
    p
}

fn wait_for_port(addr: SocketAddr, timeout: Duration) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("port {addr} unreachable after {timeout:?}");
}

fn wait_for_socket(socket: &Path, timeout: Duration) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if socket.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "ipc socket {} not created within {timeout:?}",
        socket.display(),
    );
}

struct MultiAgentDaemon {
    child: Child,
    home: tempfile::TempDir,
    ws_addr: SocketAddr,
    /// Each local agent's `(agent_id, bearer_file_path)`.
    agents: Vec<(String, PathBuf)>,
}

impl MultiAgentDaemon {
    fn spawn() -> Self {
        let home = tempfile::tempdir().expect("tempdir");
        let bin_hermod = release_bin("hermod");
        let bin_hermodd = release_bin("hermodd");

        // Bootstrap agent (the one `hermod init` provisions).
        let init_status = Command::new(&bin_hermod)
            .env("HERMOD_HOME", home.path())
            .args(["init", "--alias", "projA"])
            .status()
            .expect("hermod init");
        assert!(init_status.success(), "hermod init failed");

        // Spawn the daemon — at this point only the bootstrap agent is
        // in its registry.
        let ws_port = pick_free_port();
        let ws_addr: SocketAddr = format!("127.0.0.1:{ws_port}").parse().unwrap();
        let socket = home.path().join("sock");
        let stderr_file =
            std::fs::File::create(home.path().join("daemon.stderr")).expect("daemon stderr");
        let child = Command::new(&bin_hermodd)
            .env("HERMOD_HOME", home.path())
            .env("HERMOD_DAEMON_SOCKET_PATH", &socket)
            .env("HERMOD_DAEMON_IPC_LISTEN_WS", ws_addr.to_string())
            .env("HERMOD_DAEMON_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(stderr_file)
            .spawn()
            .expect("spawn hermodd");
        wait_for_port(ws_addr, Duration::from_secs(15));
        wait_for_socket(&socket, Duration::from_secs(5));

        // Provision the second agent over IPC — exercises the live
        // `local.add` path: daemon writes disk + DB + registry +
        // bearer index in lockstep, no restart needed.
        let add_status = Command::new(&bin_hermod)
            .env("HERMOD_HOME", home.path())
            .args(["local", "add", "--alias", "projB"])
            .status()
            .expect("hermod local add");
        assert!(add_status.success(), "hermod local add failed");

        // Discover both agent dirs after provisioning.
        let agents_root = home.path().join("agents");
        let mut entries: Vec<_> = std::fs::read_dir(&agents_root)
            .expect("read agents/")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .collect();
        entries.sort_by_key(|e| e.file_name());
        assert_eq!(
            entries.len(),
            2,
            "expected exactly two local agents on disk after init + local add",
        );
        let agents: Vec<(String, PathBuf)> = entries
            .into_iter()
            .map(|entry| {
                let id = entry.file_name().to_string_lossy().into_owned();
                let bearer = entry.path().join("bearer_token");
                (id, bearer)
            })
            .collect();

        Self {
            child,
            home,
            ws_addr,
            agents,
        }
    }

    fn url(&self) -> String {
        format!("ws://{}/", self.ws_addr)
    }

    fn cli_identity(&self, bearer_file: &Path) -> std::process::Output {
        let bin_hermod = release_bin("hermod");
        // `hermod identity` is local-disk-only; the test wants the
        // *daemon-backed* identity. Use `hermod status` against
        // the remote endpoint with the chosen bearer — its output
        // includes `agent_id:`, derived from the daemon's
        // `IdentityGetResult`.
        Command::new(bin_hermod)
            .env("HERMOD_HOME", self.home.path())
            .args([
                "--remote",
                &self.url(),
                "--bearer-file",
                bearer_file.to_str().expect("bearer-file utf-8"),
                "--pin",
                "none",
                "status",
            ])
            .output()
            .expect("invoke hermod status")
    }
}

impl Drop for MultiAgentDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn extract_agent_id(stdout: &str) -> Option<String> {
    // `hermod status` indents fields under the `hermod vX.Y.Z` header,
    // so the line shape is `  agent_id:         <value>`. Trim the
    // leading whitespace before checking the prefix so the test
    // works against either form (status' indented `  agent_id:` or
    // `hermod identity`'s flush-left `agent_id:`).
    stdout
        .lines()
        .map(str::trim_start)
        .find_map(|l| l.strip_prefix("agent_id:"))
        .map(|s| s.trim().to_string())
}

/// Each bearer authenticates as a different local agent. The daemon's
/// `identity.get` (called via `hermod status`) reports the caller's
/// agent_id, which must match the agent whose bearer was presented.
#[test]
fn each_local_agent_resolves_to_its_own_identity() {
    let daemon = MultiAgentDaemon::spawn();
    assert_eq!(daemon.agents.len(), 2);

    for (expected_id, bearer_path) in &daemon.agents {
        let out = daemon.cli_identity(bearer_path);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "hermod status failed for bearer {} (expecting agent_id {expected_id})\n\
             stdout: {stdout}\nstderr: {stderr}",
            bearer_path.display(),
        );
        let observed = extract_agent_id(&stdout).unwrap_or_else(|| {
            panic!(
                "no agent_id: line in status output for bearer {}\nstdout: {stdout}",
                bearer_path.display(),
            )
        });
        assert_eq!(
            &observed,
            expected_id,
            "bearer {} should authenticate as agent {expected_id} but daemon \
             reported {observed} — bearer dispatch is misrouting",
            bearer_path.display(),
        );
    }
}

/// `local rotate` over IPC must:
///   1. write a fresh bearer to disk + DB,
///   2. swap the bearer-index entry in the live registry, and
///   3. force-close any active session pinned to the prior bearer.
///
/// Pins the H3.5 contract: between (a) the operator running
/// `hermod local rotate` and (b) a stale-bearer client failing with
/// 401 / a live client losing its connection, no manual restart of
/// the daemon is required.
#[test]
fn local_rotate_revokes_old_bearer_immediately() {
    let daemon = MultiAgentDaemon::spawn();
    // Pick the bootstrap (`projA`) — index 0 after sort. Either works.
    let (target_id, bearer_path) = daemon.agents[0].clone();
    let old_bearer = std::fs::read_to_string(&bearer_path)
        .expect("read original bearer")
        .trim()
        .to_string();

    // Sanity: the old bearer authenticates before the rotation.
    let pre = daemon.cli_identity(&bearer_path);
    assert!(
        pre.status.success(),
        "old bearer must work pre-rotation; got: {:?}",
        String::from_utf8_lossy(&pre.stderr),
    );

    // Run `hermod local rotate <agent_id>` — IPC path materialises
    // a fresh bearer in disk + DB + registry.
    let bin_hermod = release_bin("hermod");
    let rotate_out = Command::new(&bin_hermod)
        .env("HERMOD_HOME", daemon.home.path())
        .args(["local", "rotate", &target_id])
        .output()
        .expect("hermod local rotate");
    let rotate_stderr = String::from_utf8_lossy(&rotate_out.stderr);
    assert!(
        rotate_out.status.success(),
        "rotate failed: stderr={rotate_stderr}",
    );

    // Old bearer must now fail. Write the captured pre-rotation
    // value to a side file so the rotated `bearer_token` file
    // doesn't shadow it.
    let stale_path = daemon.home.path().join("stale_bearer");
    std::fs::write(&stale_path, &old_bearer).unwrap();
    let post_old = daemon.cli_identity(&stale_path);
    assert!(
        !post_old.status.success(),
        "stale bearer must be rejected after rotate; got success",
    );

    // The newly-written bearer file authenticates the same agent.
    let post_new = daemon.cli_identity(&bearer_path);
    let stdout = String::from_utf8_lossy(&post_new.stdout);
    assert!(
        post_new.status.success(),
        "rotated bearer must authenticate; stderr={:?}",
        String::from_utf8_lossy(&post_new.stderr),
    );
    let observed = extract_agent_id(&stdout)
        .unwrap_or_else(|| panic!("no agent_id: line in post-rotate status: {stdout}"));
    assert_eq!(
        observed, target_id,
        "post-rotate identity should still resolve to the same agent_id",
    );
}

/// `local remove` over IPC archives the agent's directory and drops
/// the bearer from the registry — subsequent connect attempts with
/// that bearer must fail.
#[test]
fn local_remove_revokes_bearer_immediately() {
    let daemon = MultiAgentDaemon::spawn();
    // Remove the second agent (`projB`) — keeping the bootstrap
    // around so the daemon stays usable for the post-remove probe.
    let (target_id, bearer_path) = daemon.agents[1].clone();
    let stale_path = daemon.home.path().join("removed_bearer");
    std::fs::copy(&bearer_path, &stale_path).expect("snapshot bearer");

    let bin_hermod = release_bin("hermod");
    let remove_out = Command::new(&bin_hermod)
        .env("HERMOD_HOME", daemon.home.path())
        .args(["local", "rm", "--force", &target_id])
        .output()
        .expect("hermod local rm");
    assert!(
        remove_out.status.success(),
        "remove failed: {}",
        String::from_utf8_lossy(&remove_out.stderr),
    );

    // The removed agent's bearer must no longer authenticate.
    let post = daemon.cli_identity(&stale_path);
    assert!(
        !post.status.success(),
        "removed agent's bearer must be rejected; got success",
    );
}

/// A bearer file that doesn't correspond to any hosted agent's
/// recorded blake3 hash must be rejected at the WS upgrade with HTTP
/// 401 — multi-tenant must not silently fall through to "any agent
/// will do".
#[test]
fn unknown_bearer_is_rejected_in_multi_agent_setup() {
    let daemon = MultiAgentDaemon::spawn();
    let bogus = daemon.home.path().join("bogus_bearer");
    std::fs::write(&bogus, "definitely-not-a-real-token").unwrap();

    let out = daemon.cli_identity(&bogus);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "an unrecognised bearer must fail; got success\nstdout: {stdout}\nstderr: {stderr}",
    );
    assert!(
        stderr.contains("401") || stderr.contains("rejected") || stderr.contains("unauthorized"),
        "expected an auth-rejection diagnostic; got:\n{stderr}",
    );
}
