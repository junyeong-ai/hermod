//! MCP tool definitions — JSON Schema for inputs, dispatchers that call the daemon.

use anyhow::{Context, Result, anyhow};
use hermod_core::PresenceStatus;
use hermod_core::{AgentAddress, AgentAlias, AgentId, MessageBody, MessageId, MessagePriority};
use hermod_protocol::ipc::methods::{
    self as proto, AgentGetParams, AgentListParams, BriefPublishParams, BriefReadParams,
    BroadcastSendParams, ChannelAdoptParams, ChannelAdvertiseParams, ChannelCreateParams,
    ChannelDiscoverParams, ChannelHistoryParams, ChannelListParams, ConfirmationListParams,
    InboxListParams, MessageAckParams, MessageSendParams, PresenceClearManualParams,
    PresenceGetParams, PresenceSetManualParams, WorkspaceChannelsParams, WorkspaceCreateParams,
    WorkspaceInviteParams, WorkspaceJoinParams, WorkspaceRosterParams,
};
use serde_json::{Value, json};

use std::str::FromStr;

use crate::client::{ClientTarget, DaemonClient};

pub fn schemas() -> Value {
    json!([
        {
            "name": "message_send",
            "description": "Send a direct message to another agent (by agent_id or @alias).",
            "inputSchema": {
                "type": "object",
                "required": ["to", "body"],
                "properties": {
                    "to":       { "type":"string", "description":"Recipient: agent_id or @alias" },
                    "body":     { "type":"string", "description":"Message text" },
                    "priority": { "type":"string", "enum":["low","normal","high","urgent"], "default":"normal" },
                    "ttl_secs": { "type":"integer", "minimum": 1 }
                }
            }
        },
        {
            "name": "inbox_list",
            "description": "List inbox messages addressed to me. Use to fetch beyond what arrives via channel notifications, to filter by priority, or to inspect rows the routing engine kept silent.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit":        { "type":"integer", "minimum": 1, "maximum": 500 },
                    "priority_min": { "type":"string", "enum":["low","normal","high","urgent"] },
                    "disposition":  { "type":"string", "enum":["push","silent","all"], "default":"all", "description":"Filter by recipient-side disposition. `silent` shows rows the routing engine kept off the channel; `push` matches what arrived via channel events; `all` shows both." }
                }
            }
        },
        {
            "name": "message_ack",
            "description": "Mark messages as read. Required after processing — unacked messages keep arriving as channel notifications every poll cycle until acked.",
            "inputSchema": {
                "type": "object",
                "required": ["message_ids"],
                "properties": {
                    "message_ids": { "type":"array", "items":{ "type":"string" }, "minItems": 1 }
                }
            }
        },
        {
            "name": "agent_list",
            "description": "List agents currently reachable for synchronous reply (live=true, i.e. they have an attached Claude Code session). Offline agents are not surfaced here — use agent_get on a known id, or check the audit log, when you need to inspect an offline identity.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "agent_get",
            "description": "Inspect a single agent (by id or @alias) regardless of liveness. Returns identity, trust, endpoint, fingerprint, and effective presence.",
            "inputSchema": {
                "type": "object",
                "required": ["agent"],
                "properties": { "agent": { "type":"string" } }
            }
        },
        {
            "name": "brief_publish",
            "description": "Publish a one-line summary of what I'm working on right now. Other agents in shared workspaces will see this when they call brief_read on me. Call when starting a substantial task or when context is likely to be useful to collaborators.",
            "inputSchema": {
                "type": "object",
                "required": ["summary"],
                "properties": {
                    "summary":  { "type":"string", "description":"Active task in your own words. ≤4096 bytes." },
                    "topic":    { "type":"string", "description":"Optional tag, e.g. 'backend', 'incident'. Each topic gets its own slot." },
                    "ttl_secs": { "type":"integer", "minimum": 60, "maximum": 86400, "description":"Defaults to 3600 (1 hour)." }
                }
            }
        },
        {
            "name": "brief_read",
            "description": "Look up another agent's most recent brief. Use when the user asks 'what is X working on?' or before starting work that might overlap with a collaborator.",
            "inputSchema": {
                "type": "object",
                "required": ["agent"],
                "properties": {
                    "agent": { "type":"string", "description":"agent_id or @alias" },
                    "topic": { "type":"string", "description":"If set, returns the brief for that topic; otherwise the most recent brief on any topic." }
                }
            }
        },
        {
            "name": "presence_set_manual",
            "description": "Set my manual presence hint. Liveness (whether I have an attached Claude session) is derived automatically — set this only to override (e.g. 'busy' for deep work, 'idle' when stepping away). Pass `ttl_secs` to make the override decay; omit it to make it permanent until next set.",
            "inputSchema": {
                "type": "object",
                "required": ["status"],
                "properties": {
                    "status":   { "type":"string", "enum":["online","idle","busy","offline"] },
                    "ttl_secs": { "type":"integer", "minimum": 1 }
                }
            }
        },
        {
            "name": "presence_clear_manual",
            "description": "Drop my manual presence hint. After clearing, my status reverts to whatever liveness derives (online iff a Claude session is attached). Idempotent.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "presence_get",
            "description": "Look up an agent's effective presence + live flag. Use before a synchronous DM where waiting for a reply matters.",
            "inputSchema": {
                "type": "object",
                "required": ["agent"],
                "properties": {
                    "agent": { "type":"string", "description":"agent_id or @alias" }
                }
            }
        },
        {
            "name": "workspace_create",
            "description": "Create a workspace (group container for channels). Private workspaces return a 32-byte secret to share OOB.",
            "inputSchema": {
                "type": "object",
                "required": ["name"],
                "properties": {
                    "name":       { "type":"string", "minLength":1, "maxLength":64 },
                    "visibility": { "type":"string", "enum":["public","private"], "default":"private" }
                }
            }
        },
        {
            "name": "workspace_join",
            "description": "Join a private workspace via shared 32-byte secret (hex).",
            "inputSchema": {
                "type": "object",
                "required": ["name", "secret_hex"],
                "properties": {
                    "name":       { "type":"string" },
                    "secret_hex": { "type":"string" }
                }
            }
        },
        {
            "name": "workspace_list",
            "description": "List workspaces this agent belongs to.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "workspace_invite",
            "description": "Invite a target agent to join a private workspace by sending them a confirmation-gated WorkspaceInvite envelope.",
            "inputSchema": {
                "type": "object",
                "required": ["workspace_id", "target"],
                "properties": {
                    "workspace_id": { "type":"string", "description":"hex" },
                    "target":       { "type":"string", "description":"recipient agent_id or @alias" }
                }
            }
        },
        {
            "name": "workspace_members",
            "description": "Gossip-union of every member of a workspace as observed by every responding peer. Daemon authorises via workspace MAC (private) or membership-table (public).",
            "inputSchema": {
                "type": "object",
                "required": ["workspace_id"],
                "properties": {
                    "workspace_id": { "type":"string", "description":"hex 16 bytes" }
                }
            }
        },
        {
            "name": "workspace_channels",
            "description": "Gossip-union of every channel known to any member of a workspace. Same auth model as workspace_members.",
            "inputSchema": {
                "type": "object",
                "required": ["workspace_id"],
                "properties": {
                    "workspace_id": { "type":"string", "description":"hex 16 bytes" }
                }
            }
        },
        {
            "name": "channel_create",
            "description": "Create a channel inside a workspace.",
            "inputSchema": {
                "type": "object",
                "required": ["workspace_id", "name"],
                "properties": {
                    "workspace_id": { "type":"string", "description":"hex" },
                    "name":         { "type":"string", "minLength":1, "maxLength":64 }
                }
            }
        },
        {
            "name": "channel_list",
            "description": "List channels in a workspace.",
            "inputSchema": {
                "type": "object",
                "required": ["workspace_id"],
                "properties": { "workspace_id": { "type":"string" } }
            }
        },
        {
            "name": "channel_history",
            "description": "Show recent broadcasts from a channel.",
            "inputSchema": {
                "type": "object",
                "required": ["channel_id"],
                "properties": {
                    "channel_id": { "type":"string", "description":"hex" },
                    "limit":      { "type":"integer", "minimum": 1, "maximum": 500 }
                }
            }
        },
        {
            "name": "broadcast_send",
            "description": "Send a message to a channel; fans out to known workspace members.",
            "inputSchema": {
                "type": "object",
                "required": ["channel_id", "text"],
                "properties": {
                    "channel_id": { "type":"string" },
                    "text":       { "type":"string", "minLength":1 }
                }
            }
        },
        {
            "name": "channel_advertise",
            "description": "Push a ChannelAdvertise to every known workspace member so they learn about this channel.",
            "inputSchema": {
                "type": "object",
                "required": ["channel_id"],
                "properties": {
                    "channel_id": { "type":"string", "description":"channel id (hex)" }
                }
            }
        },
        {
            "name": "channel_discover",
            "description": "List channels advertised by other workspace members but not yet adopted locally.",
            "inputSchema": {
                "type": "object",
                "required": ["workspace_id"],
                "properties": {
                    "workspace_id": { "type":"string" }
                }
            }
        },
        {
            "name": "channel_adopt",
            "description": "Adopt a discovered channel — re-derives crypto material from the local workspace secret + channel name and creates the channel locally.",
            "inputSchema": {
                "type": "object",
                "required": ["channel_id"],
                "properties": {
                    "channel_id": { "type":"string", "description":"channel id (hex), as listed by channel_discover" }
                }
            }
        },
        {
            "name": "confirmation_list",
            "description": "List inbound actions held by the trust gate awaiting the operator's decision. Read-only — surface these to the user; accept/reject is operator-only via `hermod confirm` CLI.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": { "type":"integer", "minimum": 1, "maximum": 500 }
                }
            }
        }
    ])
}

pub async fn dispatch(id: Value, params: Value, target: &ClientTarget) -> Value {
    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    let result = match name {
        "message_send" => do_message_send(args, target).await,
        "inbox_list" => do_inbox_list(args, target).await,
        "message_ack" => do_message_ack(args, target).await,
        "agent_list" => do_agent_list(args, target).await,
        "agent_get" => do_agent_get(args, target).await,
        "brief_publish" => do_brief_publish(args, target).await,
        "brief_read" => do_brief_read(args, target).await,
        "presence_set_manual" => do_presence_set_manual(args, target).await,
        "presence_clear_manual" => do_presence_clear_manual(target).await,
        "presence_get" => do_presence_get(args, target).await,
        "workspace_create" => do_workspace_create(args, target).await,
        "workspace_join" => do_workspace_join(args, target).await,
        "workspace_list" => do_workspace_list(target).await,
        "workspace_invite" => do_workspace_invite(args, target).await,
        "workspace_members" => do_workspace_members(args, target).await,
        "workspace_channels" => do_workspace_channels(args, target).await,
        "channel_create" => do_channel_create(args, target).await,
        "channel_advertise" => do_channel_advertise(args, target).await,
        "channel_discover" => do_channel_discover(args, target).await,
        "channel_adopt" => do_channel_adopt(args, target).await,
        "channel_list" => do_channel_list(args, target).await,
        "channel_history" => do_channel_history(args, target).await,
        "broadcast_send" => do_broadcast_send(args, target).await,
        "confirmation_list" => do_confirmation_list(args, target).await,
        other => Err(anyhow!("unknown tool: {other}")),
    };

    match result {
        Ok(payload) => json!({
            "jsonrpc":"2.0",
            "id": id,
            "result": {
                "content": [{ "type":"text", "text": text_of(&payload) }],
                "isError": false
            }
        }),
        Err(e) => json!({
            "jsonrpc":"2.0",
            "id": id,
            "result": {
                "content": [{ "type":"text", "text": format!("hermod error: {e:#}") }],
                "isError": true
            }
        }),
    }
}

fn text_of(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

async fn do_message_send(args: Value, target: &ClientTarget) -> Result<Value> {
    let to_ref: String = take_str(&args, "to")?;
    let body_text: String = take_str(&args, "body")?;
    let priority = args
        .get("priority")
        .and_then(|v| v.as_str())
        .map(MessagePriority::from_str)
        .transpose()
        .map_err(|e| anyhow!("invalid priority: {e}"))?;
    let ttl = args
        .get("ttl_secs")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);

    let mut client = target.connect().await?;
    let to = resolve_to(&to_ref, &mut client).await?;

    let res = client
        .message_send(MessageSendParams {
            to,
            body: MessageBody::Direct { text: body_text },
            priority,
            thread: None,
            ttl_secs: ttl,
            caps: None,
        })
        .await
        .context("daemon message.send")?;

    Ok(serde_json::to_value(res)?)
}

async fn do_inbox_list(args: Value, target: &ClientTarget) -> Result<Value> {
    let limit = args.get("limit").and_then(|v| v.as_u64()).map(|n| n as u32);
    let priority_min = args
        .get("priority_min")
        .and_then(|v| v.as_str())
        .map(MessagePriority::from_str)
        .transpose()
        .map_err(|e| anyhow!("invalid priority_min: {e}"))?;
    let dispositions = match args.get("disposition").and_then(|v| v.as_str()) {
        Some("push") => Some(vec![hermod_core::MessageDisposition::Push]),
        Some("silent") => Some(vec![hermod_core::MessageDisposition::Silent]),
        Some("all") | None => None,
        Some(other) => return Err(anyhow!("invalid disposition: {other}")),
    };

    let mut client = target.connect().await?;
    let r = client
        .inbox_list(InboxListParams {
            limit,
            priority_min,
            statuses: None,
            after_id: None,
            dispositions,
        })
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_message_ack(args: Value, target: &ClientTarget) -> Result<Value> {
    let ids_val = args
        .get("message_ids")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("`message_ids` must be an array of strings"))?;
    let message_ids: Vec<MessageId> = ids_val
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| anyhow!("message_id must be a string"))
                .and_then(|s| MessageId::from_str(s).map_err(|e| anyhow!("invalid id: {e}")))
        })
        .collect::<Result<_, _>>()?;

    let mut client = target.connect().await?;
    let r = client.message_ack(MessageAckParams { message_ids }).await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_agent_list(_args: Value, target: &ClientTarget) -> Result<Value> {
    let mut client = target.connect().await?;
    let r = client.agent_list(AgentListParams {}).await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_agent_get(args: Value, target: &ClientTarget) -> Result<Value> {
    let agent: String = take_str(&args, "agent")?;
    let mut client = target.connect().await?;
    let r = client.agent_get(AgentGetParams { agent }).await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_brief_publish(args: Value, target: &ClientTarget) -> Result<Value> {
    let summary = take_str(&args, "summary")?;
    let topic = args.get("topic").and_then(|v| v.as_str()).map(String::from);
    let ttl_secs = args
        .get("ttl_secs")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);

    let mut client = target.connect().await?;
    let r = client
        .brief_publish(BriefPublishParams {
            summary,
            topic,
            ttl_secs,
        })
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_brief_read(args: Value, target: &ClientTarget) -> Result<Value> {
    let agent = take_str(&args, "agent")?;
    let topic = args.get("topic").and_then(|v| v.as_str()).map(String::from);
    let mut client = target.connect().await?;
    let r = client.brief_read(BriefReadParams { agent, topic }).await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_presence_set_manual(args: Value, target: &ClientTarget) -> Result<Value> {
    let status_str = take_str(&args, "status")?;
    let status = PresenceStatus::from_str(&status_str)?;
    let ttl_secs = args
        .get("ttl_secs")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);
    let mut client = target.connect().await?;
    let r = client
        .presence_set_manual(PresenceSetManualParams { status, ttl_secs })
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_presence_clear_manual(target: &ClientTarget) -> Result<Value> {
    let mut client = target.connect().await?;
    let r = client
        .presence_clear_manual(PresenceClearManualParams {})
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_presence_get(args: Value, target: &ClientTarget) -> Result<Value> {
    let agent = take_str(&args, "agent")?;
    let mut client = target.connect().await?;
    let r = client.presence_get(PresenceGetParams { agent }).await?;
    Ok(serde_json::to_value(r)?)
}

fn take_str(v: &Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("missing string `{}`", key))
}

async fn resolve_to(reference: &str, client: &mut DaemonClient) -> Result<AgentAddress> {
    if let Some(alias_raw) = reference.strip_prefix('@') {
        let alias = AgentAlias::from_str(alias_raw)
            .map_err(|e| anyhow!("invalid alias {alias_raw:?}: {e}"))?;
        let desc = client
            .agent_get(AgentGetParams {
                agent: alias.to_string(),
            })
            .await
            .map_err(|e| anyhow!("agent {alias} not found in directory: {e}"))?;
        Ok(match desc.endpoint {
            Some(ep) => AgentAddress::with_endpoint(desc.id, ep),
            None => AgentAddress::local(desc.id),
        })
    } else {
        let id = AgentId::from_str(reference).map_err(|e| anyhow!("{e}"))?;
        Ok(AgentAddress::local(id))
    }
}

async fn do_workspace_create(args: Value, target: &ClientTarget) -> Result<Value> {
    let name = take_str(&args, "name")?;
    let visibility = match args
        .get("visibility")
        .and_then(|v| v.as_str())
        .unwrap_or("private")
    {
        "public" => proto::WorkspaceVisibility::Public,
        "private" => proto::WorkspaceVisibility::Private,
        other => return Err(anyhow!("visibility must be public|private, got {other:?}")),
    };
    let mut client = target.connect().await?;
    let r = client
        .workspace_create(WorkspaceCreateParams { name, visibility })
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_workspace_join(args: Value, target: &ClientTarget) -> Result<Value> {
    let name = take_str(&args, "name")?;
    let secret_hex = take_str(&args, "secret_hex")?;
    let mut client = target.connect().await?;
    let r = client
        .workspace_join(WorkspaceJoinParams { name, secret_hex })
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_workspace_list(target: &ClientTarget) -> Result<Value> {
    let mut client = target.connect().await?;
    let r = client.workspace_list().await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_channel_create(args: Value, target: &ClientTarget) -> Result<Value> {
    let workspace_id = take_str(&args, "workspace_id")?;
    let name = take_str(&args, "name")?;
    let mut client = target.connect().await?;
    let r = client
        .channel_create(ChannelCreateParams { workspace_id, name })
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_channel_list(args: Value, target: &ClientTarget) -> Result<Value> {
    let workspace_id = take_str(&args, "workspace_id")?;
    let mut client = target.connect().await?;
    let r = client
        .channel_list(ChannelListParams { workspace_id })
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_channel_history(args: Value, target: &ClientTarget) -> Result<Value> {
    let channel_id = take_str(&args, "channel_id")?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).map(|n| n as u32);
    let mut client = target.connect().await?;
    let r = client
        .channel_history(ChannelHistoryParams { channel_id, limit })
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_broadcast_send(args: Value, target: &ClientTarget) -> Result<Value> {
    let channel_id = take_str(&args, "channel_id")?;
    let text = take_str(&args, "text")?;
    let mut client = target.connect().await?;
    let r = client
        .broadcast_send(BroadcastSendParams { channel_id, text })
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_confirmation_list(args: Value, target: &ClientTarget) -> Result<Value> {
    let limit = args.get("limit").and_then(|v| v.as_u64()).map(|n| n as u32);
    let mut client = target.connect().await?;
    let r = client
        .confirmation_list(ConfirmationListParams {
            limit,
            after_id: None,
        })
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_workspace_invite(args: Value, target: &ClientTarget) -> Result<Value> {
    let workspace_id = take_str(&args, "workspace_id")?;
    let recipient = take_str(&args, "target")?;
    let mut client = target.connect().await?;
    let r = client
        .workspace_invite(WorkspaceInviteParams {
            workspace_id,
            target: recipient,
        })
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_workspace_members(args: Value, target: &ClientTarget) -> Result<Value> {
    let workspace_id = take_str(&args, "workspace_id")?;
    let mut client = target.connect().await?;
    let r = client
        .workspace_roster(WorkspaceRosterParams { workspace_id })
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_workspace_channels(args: Value, target: &ClientTarget) -> Result<Value> {
    let workspace_id = take_str(&args, "workspace_id")?;
    let mut client = target.connect().await?;
    let r = client
        .workspace_channels(WorkspaceChannelsParams { workspace_id })
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_channel_advertise(args: Value, target: &ClientTarget) -> Result<Value> {
    let channel_id = take_str(&args, "channel_id")?;
    let mut client = target.connect().await?;
    let r = client
        .channel_advertise(ChannelAdvertiseParams { channel_id })
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_channel_discover(args: Value, target: &ClientTarget) -> Result<Value> {
    let workspace_id = take_str(&args, "workspace_id")?;
    let mut client = target.connect().await?;
    let r = client
        .channel_discover(ChannelDiscoverParams { workspace_id })
        .await?;
    Ok(serde_json::to_value(r)?)
}

async fn do_channel_adopt(args: Value, target: &ClientTarget) -> Result<Value> {
    let channel_id = take_str(&args, "channel_id")?;
    let mut client = target.connect().await?;
    let r = client
        .channel_adopt(ChannelAdoptParams { channel_id })
        .await?;
    Ok(serde_json::to_value(r)?)
}
