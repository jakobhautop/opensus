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
    /// Run continuous orchestration heartbeats.
    Go,
    /// Initialize workspace files and prompts.
    Init,
}
