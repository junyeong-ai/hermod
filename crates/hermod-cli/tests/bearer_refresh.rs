//! End-to-end test: `--bearer-command` re-mints on HTTP 401.
//!
//! Spawns a real `hermodd` with WSS+Bearer enabled. Runs `hermod status`
//! against it via `--remote --bearer-command <stub>`, where `<stub>` is a
//! shell that emits a wrong token first, then the right token on the
//! second invocation. The CLI's connect path must:
//!
//!   1. Send the bad token, get HTTP 401.
//!   2. Re-invoke the bearer command (single-flight refresh).
//!   3. Send the new token, succeed.
//!
//! The stub records its invocation count to a sidecar file; the test
//! asserts it ran exactly twice (one for the doomed initial connect,
//! one for the post-401 refresh).

#![cfg(unix)]

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
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
    panic!("port {addr} unreachable");
}

fn wait_for_socket(socket: &std::path::Path, timeout: Duration) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if socket.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "ipc socket {} not created within {:?}",
        socket.display(),
        timeout
    );
}

struct Daemon {
    child: Child,
    home: tempfile::TempDir,
    wss_addr: SocketAddr,
    real_token: String,
}

impl Daemon {
    fn spawn() -> Self {
        let home = tempfile::tempdir().expect("tempdir");
        let bin_hermod = release_bin("hermod");
        let bin_hermodd = release_bin("hermodd");

        let init_status = Command::new(&bin_hermod)
            .env("HERMOD_HOME", home.path())
            .args(["init", "--alias", "bearer-refresh-test"])
            .status()
            .expect("hermod init");
        assert!(init_status.success());

        // Post-H2: per-agent bearer at agents/<bootstrap_id>/bearer_token.
        // Single bootstrap agent ⇒ exactly one entry under agents/.
        let agents_dir = home.path().join("agents");
        let mut agent_subdirs = std::fs::read_dir(&agents_dir)
            .expect("read agents dir")
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .collect::<Vec<_>>();
        assert_eq!(
            agent_subdirs.len(),
            1,
            "expected exactly one bootstrap agent under agents/, got {}",
            agent_subdirs.len()
        );
        let real_token = std::fs::read_to_string(
            agent_subdirs
                .pop()
                .expect("len == 1")
                .path()
                .join("bearer_token"),
        )
        .expect("bearer_token file")
        .trim()
        .to_string();

        let wss_port = pick_free_port();
        let wss_addr: SocketAddr = format!("127.0.0.1:{wss_port}").parse().unwrap();
        let socket = home.path().join("sock");
        let stderr_file =
            std::fs::File::create(home.path().join("daemon.stderr")).expect("daemon stderr");
        let child = Command::new(&bin_hermodd)
            .env("HERMOD_HOME", home.path())
            .env("HERMOD_DAEMON_SOCKET_PATH", &socket)
            .env("HERMOD_DAEMON_IPC_LISTEN_WSS", wss_addr.to_string())
            .env("HERMOD_DAEMON_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(stderr_file)
            .spawn()
            .expect("spawn hermodd");
        wait_for_port(wss_addr, Duration::from_secs(15));
        wait_for_socket(&socket, Duration::from_secs(5));
        Daemon {
            child,
            home,
            wss_addr,
            real_token,
        }
    }

    fn tls_fingerprint(&self) -> String {
        // Compute SHA-256 of the cert DER, lowercase colon-separated.
        // Post-H2: TLS material lives at host/, not identity/.
        let cert_pem =
            std::fs::read_to_string(self.home.path().join("host").join("tls.crt")).unwrap();
        let cert: Vec<rustls_pki_types::CertificateDer> =
            rustls_pki_types::pem::PemObject::pem_slice_iter(cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .unwrap();
        let der = cert[0].as_ref();
        let digest = sha2::Sha256::digest(der);
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

use sha2::Digest;

#[test]
fn bearer_command_remints_after_initial_401() {
    let daemon = Daemon::spawn();

    // Stub bearer command:
    //   - increments a counter file each invocation.
    //   - first call: prints `wrong-token` (the daemon will 401 it).
    //   - subsequent calls: prints the daemon's real bearer.
    // Layout:
    //   $HOME/count    invocation counter
    //   $HOME/script   bash script the CLI runs
    let stub_dir = tempfile::tempdir().expect("stub tempdir");
    let counter = stub_dir.path().join("count");
    let script = stub_dir.path().join("stub.sh");
    std::fs::write(&counter, "0").unwrap();
    let real_token = daemon.real_token.clone();
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh
n=$(cat '{c}')
n=$((n+1))
printf '%s' \"$n\" > '{c}'
if [ \"$n\" = \"1\" ]; then
    printf '%s' wrong-token
else
    printf '%s' '{real}'
fi
",
            c = counter.display(),
            real = real_token,
        ),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();

    let url = format!("wss://{}", daemon.wss_addr);
    let pin = daemon.tls_fingerprint();
    let bin = release_bin("hermod");
    let stub_home = tempfile::tempdir().expect("client home");

    // The client uses a *separate* HERMOD_HOME so its own (unrelated)
    // identity files don't interfere with the bearer factory's
    // implicit-fallback path. Forces the CLI to dispatch through the
    // command provider.
    let out = Command::new(&bin)
        .env("HERMOD_HOME", stub_home.path())
        .args([
            "--remote",
            &url,
            "--pin",
            &pin,
            "--bearer-command",
            &script.display().to_string(),
            "status",
        ])
        .output()
        .expect("hermod status");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "hermod status failed:\nstdout:{stdout}\nstderr:{stderr}"
    );

    // Two invocations exactly: one for the doomed initial connect, one
    // for the 401-triggered refresh. (More would mean the cache isn't
    // engaging; fewer would mean the 401 path didn't fire.)
    let invocations: usize = std::fs::read_to_string(&counter)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!(
        invocations, 2,
        "stub bearer command must be invoked exactly twice (got {invocations}); \
         stdout:{stdout}\nstderr:{stderr}"
    );
}

/// `HERMOD_BEARER_TOKEN` is the `StaticBearerProvider` source — it has
/// no notion of refresh. A wrong token must fail fast on the first 401:
/// `connect_remote_with_refresh` calls `refresh()`, the provider returns
/// the same epoch as `current()`, and the connect path escalates to fatal
/// without a second handshake. This is the path that prevents an
/// infinite-retry loop when an operator misconfigures the env var.
#[test]
fn static_bearer_wrong_token_escalates_to_fatal() {
    let daemon = Daemon::spawn();

    let url = format!("wss://{}", daemon.wss_addr);
    let pin = daemon.tls_fingerprint();
    let bin = release_bin("hermod");
    let stub_home = tempfile::tempdir().expect("client home");

    let start = std::time::Instant::now();
    let out = Command::new(&bin)
        .env("HERMOD_HOME", stub_home.path())
        .env("HERMOD_BEARER_TOKEN", "definitely-not-the-real-token")
        .args(["--remote", &url, "--pin", &pin, "status"])
        .output()
        .expect("hermod status");
    let elapsed = start.elapsed();

    assert!(
        !out.status.success(),
        "hermod status must fail when the static bearer is wrong"
    );
    // Fatal-on-first-401 path: must finish well under any reasonable
    // exponential-backoff loop. 5 s is generous; in practice ~hundreds of ms.
    assert!(
        elapsed < Duration::from_secs(5),
        "static bearer fatal path took {elapsed:?} — expected fast failure"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("declined to renew"),
        "expected 'declined to renew' in stderr; got: {stderr}"
    );
}

#[test]
fn bearer_command_persistent_failure_is_fatal() {
    let daemon = Daemon::spawn();

    // Stub always emits the wrong token. Connect must fail after the
    // single re-mint retry (two 401s in a row → fatal).
    let stub_dir = tempfile::tempdir().expect("stub tempdir");
    let script = stub_dir.path().join("stub.sh");
    std::fs::write(&script, "#!/bin/sh\nprintf '%s' wrong-token\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();

    let url = format!("wss://{}", daemon.wss_addr);
    let pin = daemon.tls_fingerprint();
    let bin = release_bin("hermod");
    let stub_home = tempfile::tempdir().expect("client home");
    let out = Command::new(&bin)
        .env("HERMOD_HOME", stub_home.path())
        .args([
            "--remote",
            &url,
            "--pin",
            &pin,
            "--bearer-command",
            &script.display().to_string(),
            "status",
        ])
        .output()
        .expect("hermod status");
    assert!(
        !out.status.success(),
        "hermod status must fail when bearer is persistently invalid"
    );
}
