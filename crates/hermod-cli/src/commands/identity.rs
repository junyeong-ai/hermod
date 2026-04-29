use anyhow::Result;
use std::path::Path;

use hermod_daemon::{host_identity, local_agent};

pub async fn run(home: &Path) -> Result<()> {
    let host_kp = host_identity::load(home)?;
    println!("host_id:     {}", host_kp.agent_id());
    println!("host_fp:     {}", host_kp.fingerprint().to_human_prefix(8));
    println!(
        "host_pubkey: {}",
        hex::encode(host_kp.to_pubkey_bytes().as_slice())
    );

    let agent_ids = local_agent::scan_disk_ids(home)?;
    // In the H2 single-tenant shape every host has exactly one local
    // agent (the bootstrap). Its `agent_id` and pubkey are identical
    // to the host's — see the `local_agent` module's "bootstrap
    // shortcut" docs. Surface the values under the legacy
    // `agent_id:` / `pubkey_hex:` labels so operators (and the e2e
    // harness) keep their muscle memory.
    if let [primary_id] = agent_ids.as_slice()
        && primary_id == &host_kp.agent_id()
    {
        println!("agent_id:    {primary_id}");
        println!(
            "pubkey_hex:  {}",
            hex::encode(host_kp.to_pubkey_bytes().as_slice())
        );
    }

    if agent_ids.is_empty() {
        println!("local agents: (none — run `hermod init` to provision the bootstrap)");
    } else {
        println!("local agents ({}):", agent_ids.len());
        for id in agent_ids {
            println!("  - {id}");
        }
    }
    Ok(())
}
