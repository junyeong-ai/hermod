---
description: List configured federation peers with cached liveness.
allowed-tools: Bash
---

Run `hermod peer list` and show: alias / agent_id (short) / endpoint /
trust_level / status / live. Peers are surfaced regardless of liveness —
this is the operator's "who am I federated with?" view, not "who can I
talk to right now".
