use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "opensus")]
#[command(about = "LLM pentest orchestration runtime")]
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
    /// Reset runtime artifacts while keeping brief and susfile.
    Reset,
}
