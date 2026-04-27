use anyhow::Result;

use crate::client::ClientTarget;

pub async fn run(target: &ClientTarget) -> Result<()> {
    let mut c = target.connect().await?;
    let s = c.status().await?;
    println!("hermod v{}", s.version);
    println!("  agent_id:         {}", s.agent_id);
    if let Some(a) = &s.alias {
        println!("  alias:            {a}");
    }
    println!("  pending_messages:  {}", s.pending_messages);
    println!("  peer_count:        {}", s.peer_count);
    println!("  attached_sessions: {}", s.attached_sessions);
    println!("  uptime_secs:       {}", s.uptime_secs);
    Ok(())
}
