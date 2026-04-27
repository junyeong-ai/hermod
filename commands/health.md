---
description: Daemon health snapshot — status + doctor summary.
allowed-tools: Bash
---

Run `hermod status` and `hermod doctor` and produce a single short summary:
- agent_id (short) + alias
- attached_sessions, pending_messages, peer_count, uptime
- doctor verdict per check (one line each)
Flag any failing doctor check explicitly.
