//! End-to-end test: Claude Code channels emission via the MCP server.
//!
//! Spawns a real daemon + a real `hermod mcp` subprocess. Sends a message
//! into the daemon, then verifies the MCP server emits a
//! `notifications/claude/channel` JSON-RPC frame on stdout containing the
//! message body and the right `meta` fields.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const RELEASE_DIR: &str = "../../target/release";

/// Pick a free localhost port by binding to `:0` and reading back what
/// the OS assigned. Avoids the wedge where a previous test run left a
/// daemon holding a fixed port and the new run picks the same number.
fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let p = l.local_addr().expect("local_addr").port();
    drop(l);
    p
}

struct Daemon {
    child: Child,
    home: tempfile::TempDir,
    fed_addr: SocketAddr,
    stderr_path: PathBuf,
}

impl Daemon {
    fn spawn(alias: &str) -> Self {
        let home = tempfile::tempdir().expect("tempdir");
        let bin_hermod = release_bin("hermod");
        let bin_hermodd = release_bin("hermodd");

        let init_status = Command::new(&bin_hermod)
            .env("HERMOD_HOME", home.path())
            .args(["init", "--alias", alias])
            .status()
            .expect("hermod init");
        assert!(init_status.success());

        let fed_port = pick_free_port();
        let fed_addr: SocketAddr = format!("127.0.0.1:{fed_port}").parse().unwrap();
        let socket = home.path().join("sock");
        let stderr_path = home.path().join("daemon.stderr");
        let stderr_file = std::fs::File::create(&stderr_path).expect("daemon stderr file");
        let child = Command::new(&bin_hermodd)
            .env("HERMOD_HOME", home.path())
            .env("HERMOD_DAEMON_SOCKET_PATH", &socket)
            .env("HERMOD_DAEMON_LISTEN_WS", fed_addr.to_string())
            .env("HERMOD_FEDERATION_ENABLED", "true")
            .env("HERMOD_DAEMON_LOG", "info")
            .stdout(Stdio::null())
            .stderr(stderr_file)
            .spawn()
            .expect("spawn hermodd");
        wait_for_port(fed_addr, Duration::from_secs(15));
        wait_for_socket(&socket, Duration::from_secs(5), &stderr_path);

        Daemon {
            child,
            home,
            fed_addr,
            stderr_path,
        }
    }

    #[allow(dead_code)]
    fn read_stderr(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }

    fn run(&self, args: &[&str]) -> String {
        let bin = release_bin("hermod");
        let out = Command::new(&bin)
            .env("HERMOD_HOME", self.home.path())
            .args(args)
            .output()
            .expect("hermod run");
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            panic!(
                "hermod {args:?} failed (status={:?}):\nstdout:{stdout}\nstderr:{stderr}",
                out.status.code()
            );
        }
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    fn agent_id(&self) -> String {
        self.run(&["identity"])
            .lines()
            .find_map(|l| l.strip_prefix("agent_id:"))
            .map(|s| s.trim().to_string())
            .expect("agent_id")
    }

    fn pubkey_hex(&self) -> String {
        self.run(&["identity"])
            .lines()
            .find_map(|l| l.strip_prefix("pubkey_hex:"))
            .map(|s| s.trim().to_string())
            .expect("pubkey_hex")
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
    panic!("port {addr} unreachable");
}

fn wait_for_socket(socket: &std::path::Path, timeout: Duration, stderr_path: &std::path::Path) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if socket.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let stderr = std::fs::read_to_string(stderr_path).unwrap_or_default();
    panic!(
        "ipc socket {} not created within {:?}\nDAEMON STDERR:\n{stderr}",
        socket.display(),
        timeout
    );
}

#[test]
fn mcp_channel_emits_on_inbox_delivery() {
    let alice = Daemon::spawn("alice");
    let bob = Daemon::spawn("bob");
    let alice_id = alice.agent_id();
    let bob_id = bob.agent_id();
    let alice_pk = alice.pubkey_hex();
    let bob_pk = bob.pubkey_hex();

    // Bidirectional verified peer.
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

    // Spawn alice's MCP subprocess, drive initialize.
    let bin = release_bin("hermod");
    let mut mcp = Command::new(&bin)
        .env("HERMOD_HOME", alice.home.path())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mcp");
    let mut stdin = mcp.stdin.take().unwrap();
    let stdout = mcp.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    // First line should be the initialize response with both channel
    // capabilities + the instructions system prompt + serverInfo.name set
    // so Claude Code derives `<channel source="hermod" …>` automatically.
    let mut init_line = String::new();
    reader.read_line(&mut init_line).unwrap();
    assert!(
        init_line.contains("\"claude/channel\":{}"),
        "initialize response missing channel capability: {init_line}"
    );
    assert!(
        init_line.contains("\"claude/channel/permission\":{}"),
        "initialize response missing permission relay capability: {init_line}"
    );
    assert!(
        init_line.contains("\"instructions\""),
        "initialize response missing instructions string: {init_line}"
    );
    assert!(
        init_line.contains("\"name\":\"hermod\""),
        "initialize response missing serverInfo.name=hermod: {init_line}"
    );

    // Bob delivers a DM after initialize — emitter should pick it up.
    bob.run(&[
        "message",
        "send",
        "--to",
        &alice_id,
        "--body",
        "channel hello",
        "--priority",
        "high",
    ]);

    // Read up to a few lines until we see a channel notification.
    let deadline = Instant::now() + Duration::from_secs(5);
    let notif = loop {
        if Instant::now() > deadline {
            panic!("timed out waiting for channel notification");
        }
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line.contains("notifications/claude/channel") {
            break line;
        }
    };

    // The Channels reference says `source` is derived from `serverInfo.name`
    // automatically — the params object should NOT carry a `source` field.
    assert!(
        !notif.contains("\"source\":"),
        "params.source must be omitted: {notif}"
    );
    assert!(
        notif.contains("\"kind\":\"direct\""),
        "missing kind: {notif}"
    );
    assert!(notif.contains("channel hello"), "missing body: {notif}");
    assert!(
        notif.contains("\"priority\":\"high\""),
        "missing priority: {notif}"
    );
    assert!(notif.contains(&bob_id), "missing from: {notif}");

    let _ = mcp.kill();
    let _ = mcp.wait();
}

/// Confirmation-held envelopes also flow through the channel emitter.
/// Trust gate matrix: TOFU peer + Sensitive body (workspace invite) → hold.
/// We invite alice from bob (so bob's daemon issues the invite envelope and
/// alice's confirmation queue receives it); alice's MCP server should emit
/// a `kind="confirmation"` notification.
#[test]
fn mcp_channel_emits_held_confirmation() {
    let alice = Daemon::spawn("alice");
    let bob = Daemon::spawn("bob");
    let alice_id = alice.agent_id();
    let bob_id = bob.agent_id();
    let alice_pk = alice.pubkey_hex();
    let bob_pk = bob.pubkey_hex();

    // Both peers paired but trust stays TOFU (so DM/invite are gated).
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

    // Bob creates a workspace and invites alice. WorkspaceInvite is always
    // Sensitivity::Sensitive — even a Verified peer would land in the hold
    // queue, so TOFU here is overkill but matches the realistic flow.
    let ws_out = bob.run(&["workspace", "create", "team-x"]);
    let ws_id = extract_field(&ws_out, "id")
        .expect("workspace id")
        .to_string();
    bob.run(&[
        "workspace",
        "invite",
        "--workspace-id",
        &ws_id,
        "--target",
        &alice_id,
    ]);

    // Spawn alice's MCP subprocess.
    let bin = release_bin("hermod");
    let mut mcp = Command::new(&bin)
        .env("HERMOD_HOME", alice.home.path())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mcp");
    let mut stdin = mcp.stdin.take().unwrap();
    let stdout = mcp.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    // initialize response.
    let mut init_line = String::new();
    reader.read_line(&mut init_line).unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    let notif = loop {
        if Instant::now() > deadline {
            panic!("timed out waiting for confirmation notification");
        }
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line.contains("\"kind\":\"confirmation\"") {
            break line;
        }
    };

    assert!(
        !notif.contains("\"source\":"),
        "params.source must be omitted: {notif}"
    );
    assert!(
        notif.contains("\"intent\":\"workspace.invite\""),
        "missing intent: {notif}"
    );
    assert!(
        notif.contains("\"sensitivity\":\"sensitive\""),
        "missing sensitivity: {notif}"
    );
    assert!(notif.contains(&bob_id), "missing from: {notif}");

    let _ = mcp.kill();
    let _ = mcp.wait();
}

/// End-to-end permission-relay round trip:
///   1. Inject a `notifications/claude/channel/permission_request` into the
///      MCP server's stdin (simulating Claude Code).
///   2. The MCP server should call `permission.request` on the daemon and
///      emit a `<channel kind="permission" …>` event with a 5-letter
///      short id from `[a-km-z]`.
///   3. We answer via `hermod permission allow <id>` (operator path).
///   4. The MCP server's verdict-emitter should detect the resolution
///      and emit `notifications/claude/channel/permission` with
///      `behavior:"allow"` back to Claude Code.
#[test]
fn mcp_permission_relay_round_trip() {
    let alice = Daemon::spawn("alice");

    let bin = release_bin("hermod");
    let mut mcp = Command::new(&bin)
        .env("HERMOD_HOME", alice.home.path())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mcp");
    let mut stdin = mcp.stdin.take().unwrap();
    let stdout = mcp.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();
    let mut init_line = String::new();
    reader.read_line(&mut init_line).unwrap();
    assert!(
        init_line.contains("\"claude/channel/permission\":{}"),
        "permission capability missing: {init_line}"
    );

    // Simulate Claude Code asking for approval to run Bash.
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","method":"notifications/claude/channel/permission_request","params":{{"tool_name":"Bash","description":"list files","input_preview":"{{\"command\":\"ls\"}}"}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    // Wait for the operator-facing channel event.
    let prompt = read_until(&mut reader, |s| s.contains("\"kind\":\"permission\""));
    let request_id = extract_field(&prompt, "request_id")
        .expect("permission event must carry request_id")
        .to_string();
    assert_eq!(request_id.len(), 5, "short id must be 5 chars: {request_id}");
    assert!(
        request_id
            .chars()
            .all(|c| c.is_ascii_lowercase() && c != 'l'),
        "short id must be lowercase [a-km-z]: {request_id}"
    );

    // Operator answers via the CLI.
    alice.run(&["permission", "allow", &request_id]);

    // Verdict notification flows back to Claude Code.
    let verdict = read_until(&mut reader, |s| {
        s.contains("notifications/claude/channel/permission") && !s.contains("permission_request")
    });
    assert!(
        verdict.contains("\"behavior\":\"allow\""),
        "verdict must be allow: {verdict}"
    );
    assert!(
        verdict.contains(&format!("\"request_id\":\"{request_id}\"")),
        "verdict must echo same request_id: {verdict}"
    );

    let _ = mcp.kill();
    let _ = mcp.wait();
}

/// End-to-end File delivery: alice peers with bob (Verified trust),
/// bob sends a small file, alice's MCP server emits a `kind="file"`
/// channel notification carrying name / mime / size / hash / location.
#[test]
fn mcp_channel_emits_file_delivery() {
    let alice = Daemon::spawn("alice");
    let bob = Daemon::spawn("bob");
    let alice_id = alice.agent_id();
    let bob_id = bob.agent_id();
    let alice_pk = alice.pubkey_hex();
    let bob_pk = bob.pubkey_hex();

    alice.run(&[
        "peer", "add", "--endpoint", &format!("wss://{}", bob.fed_addr),
        "--pubkey-hex", &bob_pk,
    ]);
    bob.run(&[
        "peer", "add", "--endpoint", &format!("wss://{}", alice.fed_addr),
        "--pubkey-hex", &alice_pk,
    ]);
    alice.run(&["peer", "trust", &bob_id, "verified"]);
    bob.run(&["peer", "trust", &alice_id, "verified"]);

    // Stage a file on bob.
    let file_path = bob.home.path().join("snippet.txt");
    let payload = b"hello from bob - small test snippet\n";
    std::fs::write(&file_path, payload).unwrap();

    let bin = release_bin("hermod");
    let mut mcp = Command::new(&bin)
        .env("HERMOD_HOME", alice.home.path())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mcp");
    let mut stdin = mcp.stdin.take().unwrap();
    let stdout = mcp.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();
    let mut init_line = String::new();
    reader.read_line(&mut init_line).unwrap();

    bob.run(&[
        "message", "send-file",
        "--to", &alice_id,
        "--file", file_path.to_str().unwrap(),
        "--mime", "text/plain",
        "--name", "snippet.txt",
    ]);

    let notif = read_until(&mut reader, |s| s.contains("\"kind\":\"file\""));

    assert!(notif.contains("\"name\":\"snippet.txt\""), "name: {notif}");
    assert!(notif.contains("\"mime\":\"text/plain\""), "mime: {notif}");
    assert!(
        notif.contains(&format!("\"size\":\"{}\"", payload.len())),
        "size: {notif}"
    );
    assert!(
        notif.contains("\"location\":\"local-fs://files/"),
        "location must be a local-fs:// URL: {notif}"
    );
    assert!(notif.contains(&bob_id), "from agent_id: {notif}");

    // The blob really exists on alice's side and round-trips bit-exact.
    let location = extract_field(&notif, "location").unwrap();
    let suffix = location.strip_prefix("local-fs://").unwrap();
    let blob_path = alice.home.path().join("blob-store").join(suffix);
    assert!(blob_path.exists(), "blob file at {blob_path:?}");
    assert_eq!(std::fs::read(&blob_path).unwrap(), payload);

    let _ = mcp.kill();
    let _ = mcp.wait();
}

fn read_until<R: BufRead>(reader: &mut R, predicate: impl Fn(&str) -> bool) -> String {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if Instant::now() > deadline {
            panic!("timed out waiting for line matching predicate");
        }
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap();
        if n == 0 {
            // Avoid a busy loop on unexpected EOF.
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        if predicate(&line) {
            return line;
        }
    }
}

/// End-to-end federated permission relay:
///   1. originator (Olive) issues + ships a `permission:respond`
///      capability to delegate (Damon) via `hermod permission delegate`.
///      Damon imports the cap on inbound (audience-side `received` row).
///   2. Olive's MCP receives a `notifications/claude/channel/
///      permission_request` from a simulated Claude Code, which makes
///      Olive's daemon allocate a short id and forward a
///      `PermissionPrompt` envelope to Damon.
///   3. Damon's operator answers via `hermod permission allow <id>`;
///      Damon's daemon ships a `PermissionResponse` envelope back to
///      Olive carrying the imported cap in `caps[]`.
///   4. Olive's daemon applies the verdict to its `PermissionService`,
///      which surfaces through `permission.list_resolved`. The MCP
///      verdict-emitter writes the
///      `notifications/claude/channel/permission` frame back to
///      Claude Code with `behavior:"allow"` and the same `request_id`.
///
/// Proves Critical 1 (verdict apply path) and Critical 2 (cap
/// attachment) — without either fix, Claude Code never sees the
/// remote operator's verdict.
#[test]
fn federated_permission_relay_round_trip() {
    let olive = Daemon::spawn("olive");
    let damon = Daemon::spawn("damon");
    let olive_id = olive.agent_id();
    let damon_id = damon.agent_id();
    let olive_pk = olive.pubkey_hex();
    let damon_pk = damon.pubkey_hex();

    // Bidirectional verified peering — needed so PermissionPrompt
    // (Sensitivity::Review) reaches Damon without confirmation hold,
    // and PermissionResponse reaches Olive without hold.
    olive.run(&[
        "peer", "add", "--endpoint", &format!("wss://{}", damon.fed_addr),
        "--pubkey-hex", &damon_pk,
    ]);
    damon.run(&[
        "peer", "add", "--endpoint", &format!("wss://{}", olive.fed_addr),
        "--pubkey-hex", &olive_pk,
    ]);
    olive.run(&["peer", "trust", &damon_id, "verified"]);
    damon.run(&["peer", "trust", &olive_id, "verified"]);

    // Step 1: Olive delegates to Damon. The `CapabilityGrant` envelope
    // is classified Sensitivity::Sensitive — even from a Verified peer
    // it lands in Damon's confirmation queue, by design (importing
    // authority always requires explicit operator review). The
    // operator approves, which replays the envelope through
    // accept_capability_grant and writes the audience-side row.
    let delegate_out = olive.run(&["permission", "delegate", &damon_id]);
    eprintln!("DELEGATE OUTPUT:\n{delegate_out}");

    let confirm_deadline = Instant::now() + Duration::from_secs(10);
    let mut held_id: Option<String> = None;
    while Instant::now() < confirm_deadline {
        let listing = damon.run(&["confirm", "list"]);
        if let Some(id) = extract_held_capability_grant_id(&listing) {
            held_id = Some(id);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let held_id = held_id.unwrap_or_else(|| {
        let damon_audit = damon.run(&["audit", "query", "--limit", "20"]);
        let olive_audit = olive.run(&["audit", "query", "--limit", "20"]);
        let damon_stderr = damon.read_stderr();
        let olive_stderr = olive.read_stderr();
        panic!(
            "damon never received the CapabilityGrant.\n\nDELEGATE: {delegate_out}\n\nOLIVE AUDIT:\n{olive_audit}\n\nDAMON AUDIT:\n{damon_audit}\n\nOLIVE STDERR:\n{olive_stderr}\n\nDAMON STDERR:\n{damon_stderr}",
        )
    });
    damon.run(&["confirm", "accept", &held_id]);

    // Wait until the audit log records the auto-import — `confirm
    // accept` replays through accept_capability_grant.
    let import_deadline = Instant::now() + Duration::from_secs(5);
    let mut imported = false;
    while Instant::now() < import_deadline {
        let audit = damon.run(&["audit", "query", "--action", "capability.observed"]);
        if audit.contains("\"action\": \"capability.observed\"")
            || audit.contains("\"action\":\"capability.observed\"")
        {
            imported = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(imported, "damon never imported the delegated capability");

    // Step 2: Spawn Olive's MCP and inject a permission_request.
    let bin = release_bin("hermod");
    let mut olive_mcp = Command::new(&bin)
        .env("HERMOD_HOME", olive.home.path())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn olive mcp");
    let mut olive_stdin = olive_mcp.stdin.take().unwrap();
    let olive_stdout = olive_mcp.stdout.take().unwrap();
    let mut olive_reader = BufReader::new(olive_stdout);

    writeln!(
        olive_stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .unwrap();
    olive_stdin.flush().unwrap();
    let mut init_line = String::new();
    olive_reader.read_line(&mut init_line).unwrap();

    writeln!(
        olive_stdin,
        r#"{{"jsonrpc":"2.0","method":"notifications/claude/channel/permission_request","params":{{"tool_name":"Bash","description":"federated test","input_preview":"{{\"command\":\"ls\"}}"}}}}"#
    )
    .unwrap();
    olive_stdin.flush().unwrap();

    // Olive's MCP emits the operator-facing prompt with the short id.
    let olive_prompt = read_until(&mut olive_reader, |s| s.contains("\"kind\":\"permission\""));
    let request_id = extract_field(&olive_prompt, "request_id")
        .expect("permission event must carry request_id")
        .to_string();
    assert_eq!(request_id.len(), 5);

    // Step 3: Damon receives the relayed prompt + answers via CLI.
    // Allow some time for the federated PermissionPrompt to arrive.
    let prompt_deadline = Instant::now() + Duration::from_secs(8);
    let mut damon_sees_it = false;
    while Instant::now() < prompt_deadline {
        let listing = damon.run(&["permission", "list"]);
        if listing.contains(&request_id) {
            damon_sees_it = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        damon_sees_it,
        "damon never received the relayed PermissionPrompt for {request_id}"
    );

    damon.run(&["permission", "allow", &request_id]);

    // Step 4: Olive's MCP emits the verdict back to Claude Code.
    let verdict = read_until(&mut olive_reader, |s| {
        s.contains("notifications/claude/channel/permission") && !s.contains("permission_request")
    });
    assert!(
        verdict.contains("\"behavior\":\"allow\""),
        "federated verdict must be allow: {verdict}"
    );
    assert!(
        verdict.contains(&format!("\"request_id\":\"{request_id}\"")),
        "verdict must echo same request_id: {verdict}"
    );

    let _ = olive_mcp.kill();
    let _ = olive_mcp.wait();
}

/// Pluck the first held confirmation id whose `action` is the
/// CapabilityGrant deliver action from a `hermod confirm list` JSON
/// listing. Walks backwards from the matching action to the
/// preceding `"id"` field of the same entry.
fn extract_held_capability_grant_id(listing: &str) -> Option<String> {
    // `confirm list` emits the typed `HoldedIntent` as a JSON string
    // under the `intent` field on `PendingConfirmationView`. Locate
    // the row whose intent is `capability.deliver`, then walk back
    // to the row's `id`.
    let needles = [
        "\"intent\": \"capability.deliver\"",
        "\"intent\":\"capability.deliver\"",
    ];
    let pos = needles.iter().filter_map(|n| listing.find(n)).min()?;
    let head = &listing[..pos];
    let id_start = head.rfind("\"id\":")?;
    let after = &listing[id_start..];
    extract_field(after, "id").map(str::to_string)
}

fn extract_field<'a>(haystack: &'a str, field: &str) -> Option<&'a str> {
    let needle = format!("\"{}\":", field);
    let i = haystack.find(&needle)?;
    let rest = &haystack[i + needle.len()..];
    let q1 = rest.find('"')?;
    let q2 = rest[q1 + 1..].find('"')?;
    Some(&rest[q1 + 1..q1 + 1 + q2])
}
