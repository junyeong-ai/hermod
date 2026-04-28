use anyhow::{Context, Result};
use clap::Args;
use hermod_core::{
    AgentAddress, AgentAlias, AgentId, CapabilityToken, MessageBody, MessageId, MessagePriority,
};
use hermod_protocol::ipc::methods::{MessageAckParams, MessageListParams, MessageSendParams};
use serde_bytes::ByteBuf;

use std::path::PathBuf;
use std::str::FromStr;

use crate::client::{ClientTarget, DaemonClient};
use crate::error::{from_underlying, invalid, not_found};

#[derive(Args, Debug)]
pub struct SendArgs {
    /// Recipient: `<agent_id>` or `@alias`.
    #[arg(long)]
    pub to: String,
    /// Message text (Direct message body).
    #[arg(long)]
    pub body: String,
    /// Priority: low | normal | high | urgent
    #[arg(long, default_value = "normal")]
    pub priority: String,
    /// Time to live in seconds.
    #[arg(long)]
    pub ttl: Option<u32>,
    /// Hex-encoded capability token to attach to envelope.caps. Repeat for multiple.
    #[arg(long = "capability", value_name = "HEX")]
    pub capability: Vec<String>,
}

#[derive(Args, Debug)]
pub struct ListArgs {
    #[arg(long)]
    pub limit: Option<u32>,
    /// Minimum priority (low|normal|high|urgent).
    #[arg(long)]
    pub priority_min: Option<String>,
}

#[derive(Args, Debug)]
pub struct SendFileArgs {
    /// Recipient: `<agent_id>` or `@alias`.
    #[arg(long)]
    pub to: String,
    /// Path to the file to send. Read into memory; cap is `[policy]
    /// max_file_payload_bytes` (default 1 MiB).
    #[arg(long)]
    pub file: PathBuf,
    /// IANA media type. Inferred from file extension if omitted, with
    /// `application/octet-stream` as the final fallback.
    #[arg(long)]
    pub mime: Option<String>,
    /// Display name override. Defaults to the file's basename.
    #[arg(long)]
    pub name: Option<String>,
    /// Priority: low | normal | high | urgent
    #[arg(long, default_value = "normal")]
    pub priority: String,
    /// Time to live in seconds.
    #[arg(long)]
    pub ttl: Option<u32>,
}

#[derive(Args, Debug)]
pub struct AckArgs {
    /// One or more message ULIDs.
    #[arg(required = true)]
    pub ids: Vec<String>,
}

pub async fn send(args: SendArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let to = resolve_to(&args.to, &mut c).await?;
    let priority = MessagePriority::from_str(&args.priority)
        .map_err(|e| invalid("priority", &args.priority, e))?;
    let caps_vec: Vec<CapabilityToken> = args
        .capability
        .iter()
        .map(|h| {
            hex::decode(h)
                .map(CapabilityToken::from_bytes)
                .map_err(|e| from_underlying("capability hex", e))
        })
        .collect::<Result<_>>()?;
    let params = MessageSendParams {
        to,
        body: MessageBody::Direct { text: args.body },
        priority: Some(priority),
        thread: None,
        ttl_secs: args.ttl,
        caps: if caps_vec.is_empty() {
            None
        } else {
            Some(caps_vec)
        },
    };
    let r = c.message_send(params).await?;
    if !r.recipient_live {
        // Stderr so JSON on stdout stays parseable. Operators piping the
        // result through `jq` or similar still get a clean payload; the
        // human at the terminal sees the heads-up.
        eprintln!(
            "warning: recipient has no attached Claude Code session (live=false). \
             message queued; they will see it on next session attach."
        );
    }
    println!(
        "{{\"id\":\"{}\",\"status\":\"{}\",\"recipient_live\":{}}}",
        r.id,
        r.status.as_str(),
        r.recipient_live
    );
    Ok(())
}

pub async fn send_file(args: SendFileArgs, target: &ClientTarget) -> Result<()> {
    let data =
        std::fs::read(&args.file).with_context(|| format!("read {}", args.file.display()))?;
    if data.len() > hermod_core::MAX_FILE_PAYLOAD_BYTES {
        anyhow::bail!(
            "file is {} bytes; cap is {} bytes ({})",
            data.len(),
            hermod_core::MAX_FILE_PAYLOAD_BYTES,
            args.file.display()
        );
    }
    let name = match args.name.clone() {
        Some(n) => n,
        None => args
            .file
            .file_name()
            .and_then(|n| n.to_str().map(str::to_string))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "could not derive a UTF-8 file name from {}",
                    args.file.display()
                )
            })?,
    };
    let mime = args.mime.clone().unwrap_or_else(|| guess_mime(&args.file));
    let hash = blake3::hash(&data);

    let mut c = target.connect().await?;
    let to = resolve_to(&args.to, &mut c).await?;
    let priority = MessagePriority::from_str(&args.priority)
        .map_err(|e| invalid("priority", &args.priority, e))?;
    let params = MessageSendParams {
        to,
        body: MessageBody::File {
            name,
            mime,
            hash: ByteBuf::from(hash.as_bytes().to_vec()),
            data: ByteBuf::from(data),
        },
        priority: Some(priority),
        thread: None,
        ttl_secs: args.ttl,
        caps: None,
    };
    let r = c.message_send(params).await?;
    println!(
        "{{\"id\":\"{}\",\"status\":\"{}\",\"recipient_live\":{}}}",
        r.id,
        r.status.as_str(),
        r.recipient_live
    );
    Ok(())
}

/// Best-effort MIME detection from filename extension. Kept tiny on
/// purpose — operators always have `--mime` for cases this misses.
/// Defaults to `application/octet-stream` so the wire never carries a
/// blank type.
fn guess_mime(path: &std::path::Path) -> String {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("txt") | Some("md") | Some("log") => "text/plain",
        Some("json") => "application/json",
        Some("yaml") | Some("yml") => "application/yaml",
        Some("toml") => "application/toml",
        Some("html") | Some("htm") => "text/html",
        Some("css") => "text/css",
        Some("js") | Some("mjs") => "application/javascript",
        Some("rs") | Some("py") | Some("go") | Some("ts") | Some("tsx") | Some("jsx") => {
            "text/plain"
        }
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("svg") => "image/svg+xml",
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        Some("gz") => "application/gzip",
        Some("tar") => "application/x-tar",
        _ => "application/octet-stream",
    }
    .to_string()
}

pub async fn list(args: ListArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let priority_min = args
        .priority_min
        .as_deref()
        .map(MessagePriority::from_str)
        .transpose()
        .map_err(|e| from_underlying("priority_min", e))?;
    let r = c
        .message_list(MessageListParams {
            limit: args.limit,
            priority_min,
            statuses: None,
            after_id: None,
        })
        .await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

pub async fn ack(args: AckArgs, target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let message_ids: Vec<MessageId> = args
        .ids
        .iter()
        .map(|s| MessageId::from_str(s))
        .collect::<Result<_, _>>()
        .map_err(|e| from_underlying("id", e))?;
    let r = c.message_ack(MessageAckParams { message_ids }).await?;
    println!("{}", serde_json::to_string_pretty(&r)?);
    Ok(())
}

async fn resolve_to(reference: &str, client: &mut DaemonClient) -> Result<AgentAddress> {
    // 1. Full address syntax `<id>@<endpoint>` (no leading @).
    if !reference.starts_with('@') && reference.contains('@') {
        return AgentAddress::from_str(reference).map_err(|e| invalid("address", reference, e));
    }
    // 2. Alias.
    if let Some(alias_raw) = reference.strip_prefix('@') {
        let alias = AgentAlias::from_str(alias_raw).map_err(|e| invalid("alias", alias_raw, e))?;
        let desc = client
            .agent_get(hermod_protocol::ipc::methods::AgentGetParams {
                agent: alias.to_string(),
            })
            .await
            .map_err(|_| not_found("agent", alias.to_string(), "directory"))?;
        return Ok(match desc.endpoint {
            Some(ep) => AgentAddress::with_endpoint(desc.id, ep),
            None => AgentAddress::local(desc.id),
        });
    }
    // 3. Raw agent_id — try the directory for an endpoint hint.
    let id = AgentId::from_str(reference).map_err(|e| invalid("agent_id", reference, e))?;
    match client
        .agent_get(hermod_protocol::ipc::methods::AgentGetParams {
            agent: id.to_string(),
        })
        .await
    {
        Ok(desc) => Ok(match desc.endpoint {
            Some(ep) => AgentAddress::with_endpoint(desc.id, ep),
            None => AgentAddress::local(desc.id),
        }),
        Err(_) => Ok(AgentAddress::local(id)),
    }
}
