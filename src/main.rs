use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "susmos")]
#[command(about = "Process-based multi-agent orchestration")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run one orchestration heartbeat cycle.
    Go,
    /// Run a worker or orchestrator agent once.
    Agent {
        name: String,
        #[arg(required = true)]
        task: Vec<String>,
    },
    /// Initialize the local filesystem scaffold.
    Init,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SwarmEntry {
    id: String,
    agent: String,
    status: AgentStatus,
    task: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum AgentStatus {
    Running,
    Complete,
    Crashed,
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            AgentStatus::Running => "running",
            AgentStatus::Complete => "complete",
            AgentStatus::Crashed => "crashed",
        };
        write!(f, "{value}")
    }
}

trait Tool {
    fn name(&self) -> &str;
    fn spec(&self) -> ToolSpec;
    fn call(&self, args: Value) -> Result<String>;
}

#[derive(Debug, Clone, Serialize)]
struct ToolSpec {
    name: String,
    description: String,
    parameters: Value,
}

struct SpawnAgentTool {
    root: PathBuf,
}

impl Tool for SpawnAgentTool {
    fn name(&self) -> &str {
        "spawn_agent"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: self.name().to_string(),
            description: "Spawn a new LLM agent process".to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "task": { "type": "string" }
                },
                "required": ["name", "task"]
            }),
        }
    }

    fn call(&self, args: Value) -> Result<String> {
        let name = args
            .get("name")
            .and_then(Value::as_str)
            .context("spawn_agent missing `name`")?;
        let task = args
            .get("task")
            .and_then(Value::as_str)
            .context("spawn_agent missing `task`")?;

        let id = Uuid::new_v4().to_string();
        update_swarm_spawn(&self.root, &id, name, task)?;

        let binary = env::current_exe().unwrap_or_else(|_| PathBuf::from("susmos"));
        let status = Command::new(binary)
            .current_dir(&self.root)
            .arg("agent")
            .arg(name)
            .arg(task)
            .spawn();

        if let Err(error) = status {
            update_swarm_status(&self.root, &id, AgentStatus::Crashed)?;
            return Err(error).context("failed to spawn child agent process");
        }

        Ok(format!("Spawned agent {id} ({name})"))
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = std::env::current_dir().context("failed to resolve current directory")?;

    match cli.command {
        Commands::Go => handle_go(&root),
        Commands::Agent { name, task } => handle_agent(&root, &name, &task.join(" ")),
        Commands::Init => ensure_layout(&root),
    }
}

fn handle_go(root: &Path) -> Result<()> {
    ensure_layout(root)?;
    let mission = read_state_status(root)?;
    if mission.eq_ignore_ascii_case("complete") {
        println!("Mission already complete.");
        return Ok(());
    }

    let objective = read_mission_objective(root)?;
    let swarm = load_swarm(root)?;

    let main_task = format!(
        "Mission objective:\n{objective}\n\nCurrent swarm entries: {}\n\nIf work remains, use spawn_agent for workers and mark mission complete when done.",
        swarm.len()
    );

    handle_agent(root, "main", &main_task)
}

fn handle_agent(root: &Path, name: &str, task: &str) -> Result<()> {
    ensure_layout(root)?;
    let prompt_path = root.join("prompts").join(format!("{name}.md"));
    let prompt = fs::read_to_string(&prompt_path)
        .with_context(|| format!("failed to read prompt file: {}", prompt_path.display()))?;

    println!("=== Running agent: {name} ===");
    println!("Task: {task}");
    println!("Prompt loaded from {}", prompt_path.display());

    if name == "main" {
        run_main_orchestration(root, &prompt, task)?;
    } else {
        run_worker_agent(root, name, &prompt, task)?;
    }

    update_swarm_complete_by_name(root, name)?;
    println!("=== Agent complete: {name} ===");
    Ok(())
}

fn run_main_orchestration(root: &Path, _prompt: &str, task: &str) -> Result<()> {
    let status = read_state_status(root)?;
    if status.eq_ignore_ascii_case("complete") {
        return Ok(());
    }

    let objective = read_mission_objective(root)?;
    let swarm = load_swarm(root)?;

    let has_running = swarm
        .iter()
        .any(|entry| matches!(entry.status, AgentStatus::Running));
    if has_running {
        println!("Main agent: workers already running; waiting for next heartbeat.");
        return Ok(());
    }

    let has_coder = swarm
        .iter()
        .any(|entry| entry.agent == "coder" && matches!(entry.status, AgentStatus::Complete));
    let has_reviewer = swarm
        .iter()
        .any(|entry| entry.agent == "reviewer" && matches!(entry.status, AgentStatus::Complete));

    let spawn_tool = SpawnAgentTool {
        root: root.to_path_buf(),
    };
    let _tool_spec = spawn_tool.spec();

    if !has_coder {
        spawn_tool.call(serde_json::json!({
            "name": "coder",
            "task": format!("Implement mission objective: {objective}")
        }))?;
        println!("Main agent: spawned coder.");
        return Ok(());
    }

    if !has_reviewer {
        spawn_tool.call(serde_json::json!({
            "name": "reviewer",
            "task": "Review coder changes and run tests"
        }))?;
        println!("Main agent: spawned reviewer.");
        return Ok(());
    }

    if task.contains("mark mission complete") || (has_coder && has_reviewer) {
        write_state_status(root, "complete")?;
        println!("Main agent: mission marked complete.");
    }

    Ok(())
}

fn run_worker_agent(root: &Path, name: &str, _prompt: &str, task: &str) -> Result<()> {
    let log_path = root.join(format!(".{name}.log"));
    let entry = format!("task: {task}\nstatus: completed\n\n");
    fs::write(log_path, entry).context("failed to write worker log")?;
    Ok(())
}

fn ensure_layout(root: &Path) -> Result<()> {
    fs::create_dir_all(root.join("prompts")).context("failed to create prompts/ directory")?;
    fs::create_dir_all(root.join(".susmos")).context("failed to create .susmos/ directory")?;

    write_if_missing(
        &root.join("prompts/main.md"),
        "# Main Agent\n\nYou are the orchestrator. Read state.md and swarm.md, then use spawn_agent(name, task) when work remains.\n",
    )?;
    write_if_missing(
        &root.join("prompts/coder.md"),
        "# Coder Agent\n\nImplement requested task safely and report completion.\n",
    )?;
    write_if_missing(
        &root.join("prompts/reviewer.md"),
        "# Reviewer Agent\n\nReview worker outputs and confirm quality and tests.\n",
    )?;
    write_if_missing(&root.join("prompts/swarm.md"), "# Swarm Status\n\n")?;
    write_if_missing(
        &root.join("state.md"),
        "# Mission\n\nDefine your mission objective here.\n\n## Status\nincomplete\n",
    )?;
    write_if_missing(
        &root.join("assignment.txt"),
        "Describe the high-level assignment for this mission.\n",
    )?;
    write_if_missing(&root.join("input.txt"), "Input context for agents.\n")?;
    write_if_missing(
        &root.join(".susmos/config.json"),
        "{\n  \"provider\": \"mock\"\n}\n",
    )?;

    // Ensure swarm file is always generated from current entries.
    let entries = load_swarm(root)?;
    write_swarm(root, &entries)?;

    Ok(())
}

fn write_if_missing(path: &Path, content: &str) -> Result<()> {
    if !path.exists() {
        fs::write(path, content)
            .with_context(|| format!("failed to write file {}", path.display()))?;
    }
    Ok(())
}

fn read_mission_objective(root: &Path) -> Result<String> {
    let content = fs::read_to_string(root.join("state.md")).context("failed to read state.md")?;
    let mut lines = content.lines();
    let mut objective_lines = Vec::new();
    while let Some(line) = lines.next() {
        if line.trim_start().starts_with("## Status") {
            break;
        }
        if !line.trim_start().starts_with("# Mission") {
            objective_lines.push(line);
        }
    }

    Ok(objective_lines.join("\n").trim().to_string())
}

fn read_state_status(root: &Path) -> Result<String> {
    let content = fs::read_to_string(root.join("state.md")).context("failed to read state.md")?;
    let mut status_section = false;
    for line in content.lines() {
        if line.trim().starts_with("## Status") {
            status_section = true;
            continue;
        }
        if status_section && !line.trim().is_empty() {
            return Ok(line.trim().to_string());
        }
    }
    Ok("incomplete".to_string())
}

fn write_state_status(root: &Path, status: &str) -> Result<()> {
    let state_path = root.join("state.md");
    let content = fs::read_to_string(&state_path).context("failed to read state.md")?;
    let mut result = Vec::new();
    let mut in_status = false;
    let mut status_written = false;

    for line in content.lines() {
        if line.trim_start().starts_with("## Status") {
            in_status = true;
            result.push(line.to_string());
            result.push(status.to_string());
            status_written = true;
            continue;
        }

        if in_status {
            if line.trim_start().starts_with("## ") {
                in_status = false;
                result.push(line.to_string());
            }
            continue;
        }

        result.push(line.to_string());
    }

    if !status_written {
        result.push("".to_string());
        result.push("## Status".to_string());
        result.push(status.to_string());
    }

    let rebuilt = result.join("\n") + "\n";
    fs::write(state_path, rebuilt).context("failed to write state.md")?;
    Ok(())
}

fn load_swarm(root: &Path) -> Result<Vec<SwarmEntry>> {
    let path = root.join("prompts/swarm.md");
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(path).context("failed to read prompts/swarm.md")?;
    let mut entries = Vec::new();
    let mut current = SwarmEntry {
        id: String::new(),
        agent: String::new(),
        status: AgentStatus::Running,
        task: String::new(),
    };
    let mut seen = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("- id:") {
            if seen {
                entries.push(current.clone());
                current = SwarmEntry {
                    id: String::new(),
                    agent: String::new(),
                    status: AgentStatus::Running,
                    task: String::new(),
                };
            }
            current.id = value.trim().to_string();
            seen = true;
        } else if let Some(value) = trimmed.strip_prefix("agent:") {
            current.agent = value.trim().to_string();
        } else if let Some(value) = trimmed.strip_prefix("status:") {
            current.status = match value.trim() {
                "complete" => AgentStatus::Complete,
                "crashed" => AgentStatus::Crashed,
                _ => AgentStatus::Running,
            };
        } else if let Some(value) = trimmed.strip_prefix("task:") {
            current.task = value.trim().to_string();
        }
    }

    if seen {
        entries.push(current);
    }

    Ok(entries)
}

fn write_swarm(root: &Path, entries: &[SwarmEntry]) -> Result<()> {
    let mut out = String::from("# Swarm Status\n\n");
    for entry in entries {
        out.push_str(&format!(
            "- id: {}\n  agent: {}\n  status: {}\n  task: {}\n\n",
            entry.id, entry.agent, entry.status, entry.task
        ));
    }

    fs::write(root.join("prompts/swarm.md"), out).context("failed to write prompts/swarm.md")?;
    Ok(())
}

fn update_swarm_spawn(root: &Path, id: &str, name: &str, task: &str) -> Result<()> {
    let mut entries = load_swarm(root)?;
    entries.push(SwarmEntry {
        id: id.to_string(),
        agent: name.to_string(),
        status: AgentStatus::Running,
        task: task.to_string(),
    });
    write_swarm(root, &entries)
}

fn update_swarm_status(root: &Path, id: &str, status: AgentStatus) -> Result<()> {
    let mut entries = load_swarm(root)?;
    for entry in &mut entries {
        if entry.id == id {
            entry.status = status.clone();
        }
    }
    write_swarm(root, &entries)
}

fn update_swarm_complete_by_name(root: &Path, name: &str) -> Result<()> {
    let mut entries = load_swarm(root)?;
    if let Some(entry) = entries.iter_mut().rev().find(|entry| entry.agent == name) {
        entry.status = AgentStatus::Complete;
    }
    write_swarm(root, &entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_incomplete_status() {
        let tmp = tempfile::tempdir().expect("tempdir");
        fs::write(
            tmp.path().join("state.md"),
            "# Mission\n\nHello\n\n## Status\nincomplete\n",
        )
        .expect("write state");
        assert_eq!(read_state_status(tmp.path()).expect("status"), "incomplete");
    }
}
