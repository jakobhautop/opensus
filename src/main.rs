mod chat;
mod cli;
mod config;
mod plan;
mod runtime;
mod tools;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = std::env::current_dir().context("failed to resolve current directory")?;

    match cli.command {
        Commands::Go => runtime::handle_go(&root).await,
        Commands::Init => runtime::handle_init(&root),
        Commands::Reset => runtime::handle_reset(&root),
    }
}
