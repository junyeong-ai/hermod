---
description: Show recent inbox messages (defaults to last 10).
allowed-tools: Bash
---

Run `hermod message list --limit 10` and present each entry compactly: id
short / from short / priority / created_at / body excerpt. Mention if any
priority is `high` or `urgent`.
