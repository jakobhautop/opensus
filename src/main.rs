mod chat;
mod cli;
mod config;
mod plan;
mod runtime;
mod swarm;
mod tools;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = std::env::current_dir().context("failed to resolve current directory")?;

    match cli.command {
        Commands::Go => runtime::handle_go(&root),
        Commands::Init => runtime::ensure_layout(&root),
        Commands::InternalPlanAgent => {
            runtime::ensure_internal_invocation()?;
            runtime::handle_plan_agent(&root)
        }
        Commands::InternalWorkAgent { task_id } => {
            runtime::ensure_internal_invocation()?;
            runtime::handle_work_agent(&root, &task_id)
        }
        Commands::InternalReporterAgent => {
            runtime::ensure_internal_invocation()?;
            runtime::handle_reporter_agent(&root)
        }
    }
}
