pub mod agent;
pub mod audit;
pub mod bearer;
pub mod brief;
pub mod broadcast;
pub mod capability;
pub mod channel;
pub mod confirmation;
pub mod doctor;
pub mod identity;
pub mod init;
pub mod local;
pub mod message;
pub mod peer;
pub mod permission;
pub mod presence;
pub mod status;
pub mod workspace;

use clap::ValueEnum;

/// Two-state toggle used wherever a CLI subcommand wants a positional
/// on/off argument. Typed enum (vs bare `bool`) gives clap a clear
/// required-positional with a finite value set: help renders `<on|off>`
/// and typos fail fast at parse time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[clap(rename_all = "lowercase")]
pub enum MuteState {
    On,
    Off,
}

impl MuteState {
    pub fn into_bool(self) -> bool {
        matches!(self, MuteState::On)
    }
}
