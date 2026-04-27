use anyhow::Result;
use std::path::Path;

use hermod_daemon::identity;

pub async fn run(home: &Path) -> Result<()> {
    let kp = identity::load(home)?;
    println!("agent_id:    {}", kp.agent_id());
    println!("fingerprint: {}", kp.fingerprint().to_human_prefix(8));
    println!(
        "pubkey_hex:  {}",
        hex::encode(kp.to_pubkey_bytes().as_slice())
    );
    Ok(())
}
