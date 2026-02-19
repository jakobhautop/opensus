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
    Go {
        /// Continuously run heartbeats by starting a new one when the previous heartbeat ends.
        #[arg(long)]
        fullauto: bool,
    },
    /// Initialize workspace files and prompts.
    Init,
    /// Reset runtime artifacts while keeping brief and susfile.
    Reset,
    /// Search local CVE database.
    Cve {
        #[command(subcommand)]
        command: CveCommands,
    },
    /// Install and manage the local CVE database.
    #[command(name = "cvedb")]
    CveDb {
        #[command(subcommand)]
        command: CveDbCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum CveCommands {
    /// Search CVE database by text query.
    Search { query: String },
    /// Show a CVE entry with matching products.
    Show { id: String },
}

#[derive(Subcommand, Debug)]
pub enum CveDbCommands {
    /// Download latest cvelistV5 release snapshot and rebuild local CVE database.
    Install,
}
