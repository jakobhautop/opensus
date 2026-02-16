mod chat;
mod cli;
mod config;
mod cve;
mod plan;
mod runtime;
mod tools;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands, CveCommands};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = std::env::current_dir().context("failed to resolve current directory")?;

    match cli.command {
        Commands::Go => runtime::handle_go(&root).await,
        Commands::Init => runtime::handle_init(&root),
        Commands::Reset => runtime::handle_reset(&root),
        Commands::Cve { command } => match command {
            CveCommands::Search { query } => {
                let rows = cve::search_local_db(&query)?;
                println!("{}", serde_json::to_string_pretty(&rows)?);
                Ok(())
            }
            CveCommands::Show { id } => {
                let row = cve::show_local_db(&id)?;
                println!("{}", serde_json::to_string_pretty(&row)?);
                Ok(())
            }
        },
        Commands::UpdateCveDb => {
            let path = cve::rebuild_local_database()?;
            println!("{}", path.display());
            Ok(())
        }
    }
}
