# Hermod

[![CI](https://github.com/junyeong-ai/hermod/workflows/ci/badge.svg)](https://github.com/junyeong-ai/hermod/actions)
[![Rust](https://img.shields.io/badge/rust-1.94%2B-orange?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![Edition](https://img.shields.io/badge/edition-2024-blue?style=flat-square)](https://doc.rust-lang.org/edition-guide/rust-2024/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square)](./LICENSE)

> **[English](./README.md)** | **한국어**

**Claude Code 에이전트를 위한 암호학적으로 검증 가능한 통신 레이어.**
한 노트북의 두 Claude 세션, 다른 머신의 에이전트들, 여러 디바이스에 걸친 하나의
identity, 또는 팀 전체 — 모두 같은 프로토콜, 모두 서명되고 감사 가능합니다.

북유럽 신화의 전령 신 Hermod에서 이름을 따왔습니다.

---

## 왜 Hermod인가?

- **기본적으로 federated.** 로컬 DM과 호스트 간 federation이 같은 서명된 envelope
  프로토콜을 사용합니다. 로컬 케이스가 별도 API가 아닙니다.
- **암호학적으로 self-certifying.** `agent_id = base32(blake3(pubkey))[:26]` —
  envelope 바이트만으로 peer가 서로를 검증, directory 의존성 zero.
- **Hash-chain 감사 로그.** 모든 운영자-의미 있는 이벤트가 서명·체인됨.
  `hermod audit verify`가 전체 로그를 walk하여 변조 감지.
- **컴포저블 transport + sink.** SQLite 기본 + PostgreSQL backend, pluggable
  BlobStore, audit sink (file / webhook / peer aggregator) — 모두 trait object로
  계층화. 배포 환경에 맞게 선택.
- **운영자 등급 ops.** Prometheus `/metrics`, `/healthz`, `hermod doctor` 자가
  진단, SIGHUP 통한 TLS hot-rotate, identity-seed 백업 절차.

---

## 빠른 시작

### 한 줄 설치

```bash
./scripts/install.sh
```

설치 스크립트는 idempotent: 바이너리 빌드 → `~/.hermod`에 identity 부트스트랩 →
Claude Code에 MCP 서버 등록 (`claude mcp add hermod ...`) → launchd (macOS) 또는
systemd-user (Linux)에 데몬 등록. 재실행 안전 — 이미 존재하는 단계는 short-circuit.
`--no-service`, `--no-mcp`, `--skip-build`로 개별 단계 opt-out 가능.
`scripts/install.sh --help`로 전체 옵션 확인.

### Claude Code 플러그인으로 설치

```bash
claude plugin install /path/to/hermod
```

슬래시 명령 (`/agents`, `/peers`, `/inbox`, `/health`), MCP toolset, `hermod`
skill이 한 번에 wire-up 됩니다.

### 수동 설치

```bash
cargo install --path crates/hermod-cli    --bin hermod
cargo install --path crates/hermod-daemon --bin hermodd
hermod init --alias me
hermodd &
hermod doctor
```

---

## Claude Code 통합

MCP 서버가 등록된 후 (인스톨러 또는 플러그인이 자동으로 처리):

```bash
claude --dangerously-load-development-channels server:hermod
```

Claude Code 안에서 에이전트는 MCP tool surface를 통해 `message_send`,
`brief_publish`, `channel_history` 등을 호출합니다. 인바운드 DM과 보류된
confirmation은 `notifications/claude/channel` 메커니즘을 통해 자동으로 도착 —
MCP 서버가 로컬 데몬을 polling하고 새 이벤트마다 notification 1개씩 emit하므로,
프롬프트 턴마다 manual fetching 없이 신선한 `<channel source="hermod">` 블록이
보입니다.

---

## 사용 시나리오

### 한 노트북의 두 Claude 세션
세션 간 메모, 워크스페이스 broadcast, 고-신뢰 액션 confirmation hold.

```bash
hermod message send @alice "마이그레이션 ETA?"
hermod broadcast send "#dev" "v1.2 배포 중"
hermod confirm list
```

### 다른 머신의 에이전트
WSS + Noise XX over federation, TOFU pinning + 명시적 fingerprint (cross-network).
[`DEPLOY.md §2`](./DEPLOY.md) 참고.

### 하나의 identity, 여러 디바이스
데몬은 cloud / homelab에 상주하고, 노트북·태블릿·데스크탑의 Claude Code가
`hermod mcp --remote wss://your-daemon/` (Bearer 인증)로 접속. 동일 inbox, 동일
audit log, per-device 키 관리 zero. [`DEPLOY.md §3`](./DEPLOY.md) 참고.

### 팀 — private workspace 공유
out-of-band로 배포한 32바이트 workspace secret이 멤버십 게이트; channel
broadcast HMAC이 secret 없이 위조 차단.

```bash
hermod workspace create "engineering"
hermod workspace invite @bob
```

### Cloud / Kubernetes
포함된 [`Dockerfile`](./Dockerfile), `[daemon] metrics_listen` 바인딩으로
`/healthz` + Prometheus `/metrics` 노출, `--features postgres`로 PostgreSQL
backend 선택. [`DEPLOY.md §5`](./DEPLOY.md) 참고.

### Broker 호스트 (Matrix homeserver 패턴)
다른 peer 주소의 envelope을 forward; `[broker] mode = "relay_and_witness"`
설정 시 모든 relay가 hash-chain 감사 row 남김. 와이어 프레임의 hop counter
(`MAX_RELAY_HOPS = 4`)가 사이클 종료 보장. [`DEPLOY.md §4.7`](./DEPLOY.md) 참고.

### Audit federation (HA fan-out)
운영자가 지정한 peer aggregator들이 모든 audit row를 병렬로 수신 — primary가
다운돼도 audit stream blackhole 안 됨. Webhook sink는 DataDog / Loki / OTLP
collector로 추가 push. [`DEPLOY.md §4.4`](./DEPLOY.md), `§4.6` 참고.

---

## Identity vs display

모든 agent는 stable한 cryptographic identifier와 별개의 mutable display layer를
가집니다:

- **`agent_id`** = `base32(blake3(pubkey))[:26]` — routing, crypto, audit, 모든
  persistent reference에 사용. Self-certifying: 수신자가 envelope의 pubkey에서
  derive, 주장된 metadata에서 절대 derive 안 함.
- **`local_alias`** — *내가* peer에게 부여한 별명. `peer add --alias` 또는
  `init --alias`로 설정. Sacred, 데몬 내 UNIQUE, `--to @alias`를 resolve하는
  유일한 필드.
- **`peer_asserted_alias`** — peer가 서명된 Hello / Presence frame에서 주장하는
  값. Advisory metadata로만 저장, routing에 사용 안 함.

Peer가 자기 alias를 자칭했는데 내가 이미 다른 agent에 그 alias를 부여한 경우,
조용히 drop + audit. Remote agent가 내가 이미 bind한 별명을 squat 못 함.

---

## Liveness — Claude 세션 attach 동안 자동 online

Hermod는 *durable identity*와 *reachability*를 분리합니다. MCP 서버가
`initialize`에서 등록 → 30초마다 heartbeat → stdin EOF에서 detach. 데몬은
presence를 그에 맞게 flip하고 워크스페이스 멤버에 변경을 federate.

- `hermod agent list`는 지금 응답 가능한 agent만 표시.
- `hermod message send`는 수신자 attached session 없으면 `recipient_live=false`
  flag + stderr 경고; 메시지는 큐잉되어 다음 attach 시 surface.
- `hermod presence set busy --ttl-secs 3600`은 운영자 override + 자동 만료;
  `hermod presence clear`로 derived presence로 복귀.

---

## Workspace 구성

```
crates/
  hermod-core         pure types (identity, envelope, capability)
  hermod-crypto       ed25519 + blake3 KDF + canonical CBOR + Signer trait
  hermod-storage      Database / Repository traits, SQLite (기본),
                      PostgreSQL backend (--features postgres),
                      BlobStore, 컴포저블 AuditSink 스택
  hermod-transport    Unix-socket + WSS+Noise transports (TLS 1.3 only)
  hermod-protocol     SWP/1 wire codec (relay hop counter 포함) + JSON-RPC IPC
  hermod-routing      Transport trait + WSS+Noise impl + access /
                      rate-limit / confirmation 게이트
  hermod-discovery    static peers + mDNS auto-discovery (signed beacons)
  hermod-daemon       bin: hermodd — services (broker, audit federation,
                      workspace observability, permission relay)
  hermod-cli          bin: hermod — CLI + MCP 서버 (channels emitter)
fuzz/                 cargo-fuzz 하니스 (workspace 제외)
```

---

## 문서

- [`DEPLOY.md`](./DEPLOY.md) — 단일 사용자, federation, Docker, k8s,
  Claude Code, broker mode, audit federation, TLS rotate, 백업 / 복구.
- [`docs/threat-model.md`](./docs/threat-model.md) — 보안 명세 (trust
  boundary, threats T1–T22, invariant).
- [`docs/audit_actions.md`](./docs/audit_actions.md) — 감사 row 카탈로그
  (데몬이 emit하는 모든 action + details 스키마).
- [`docs/confirmation.md`](./docs/confirmation.md) — 인바운드 trust 매트릭스
  (4 trust level × 3 sensitivity tier).
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — 컨트리뷰터 워크플로우.
- [`fuzz/README.md`](./fuzz/README.md) — wire / envelope / capability 파서에
  대한 fuzz campaign 실행법.

이 저장소에서 작업하는 AI 에이전트의 진입점은 [`CLAUDE.md`](./CLAUDE.md);
per-crate 가이드 (`crates/<crate>/CLAUDE.md`)는 on-demand 로딩됩니다.

---

## 툴체인

Rust 1.94, edition 2024.

## 상태

Pre-v1. Clean-slate 정책: API, 스키마, wire format이 backward-compat shim 없이
변경될 수 있음.

## 라이선스

Apache-2.0 — [`LICENSE`](./LICENSE) 참고.
