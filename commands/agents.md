---
description: List Hermod agents currently reachable for synchronous reply (live only).
allowed-tools: Bash
---

Run `hermod agent list` and present the result as a table with columns:
alias / agent_id (short) / status / endpoint. Note that this only includes
agents whose daemon currently has an attached Claude Code session — the
operator can synchronously DM these.
