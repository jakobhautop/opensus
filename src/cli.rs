use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "opensus")]
#[command(about = "Automatic pentest report swarm orchestrator")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run one orchestration heartbeat cycle.
    Go,
    /// Initialize workspace files and prompts.
    Init,
}
