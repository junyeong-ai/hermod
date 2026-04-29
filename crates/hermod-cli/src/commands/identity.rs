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

    let agents = local_agent::scan_disk(home)?;
    // In the H2 single-tenant shape every host has exactly one local
    // agent (the bootstrap). Surface its identifiers under the
    // `agent_id:` / `pubkey_hex:` labels for operators (and the e2e
    // harness) to address with — these are distinct from the host's
    // identifiers above. Multi-agent (H5+) drops these single-line
    // fields and prints the full per-agent table.
    if let [agent] = agents.as_slice() {
        println!("agent_id:    {}", agent.agent_id);
        println!(
            "pubkey_hex:  {}",
            hex::encode(agent.keypair.to_pubkey_bytes().as_slice())
        );
    }

    if agents.is_empty() {
        println!("local agents: (none — run `hermod init` to provision the bootstrap)");
    } else {
        println!("local agents ({}):", agents.len());
        for agent in agents {
            let alias = agent
                .local_alias
                .as_ref()
                .map(|a| format!(" ({})", a.as_str()))
                .unwrap_or_default();
            println!("  - {}{alias}", agent.agent_id);
        }
    }
    Ok(())
}
