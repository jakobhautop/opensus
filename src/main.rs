use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "opensus")]
#[command(about = "Automatic pentest report swarm orchestrator")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run one orchestration heartbeat cycle.
    Go,
    #[command(hide = true)]
    InternalAgent {
        name: String,
        #[arg(required = true)]
        task: Vec<String>,
    },
    /// Initialize workspace files for an opensus mission.
    Init,
}

#[derive(Debug, Clone, Deserialize)]
struct Susfile {
    api: String,
    model: String,
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
    fn call(&self, args: Value) -> Result<String>;
}

struct NmapVerifyTool;

impl Tool for NmapVerifyTool {
    fn call(&self, _args: Value) -> Result<String> {
        let output = Command::new("nmap")
            .arg("--version")
            .output()
            .context("failed to execute nmap --version")?;

        if !output.status.success() {
            bail!("nmap --version failed with status {}", output.status);
        }

        let stdout = String::from_utf8(output.stdout).context("nmap output was not valid UTF-8")?;
        let first_line = stdout
            .lines()
            .next()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .context("nmap --version returned empty output")?;

        Ok(format!("nmap_verify: {first_line}"))
    }
}

struct SpawnAgentTool {
    root: PathBuf,
}

impl Tool for SpawnAgentTool {
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

        let binary = env::current_exe().unwrap_or_else(|_| PathBuf::from("opensus"));
        let status = Command::new(binary)
            .current_dir(&self.root)
            .arg("internal-agent")
            .arg(name)
            .arg(task)
            .env("OPENSUS_INTERNAL_AGENT", "1")
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
        Commands::InternalAgent { name, task } => {
            ensure_internal_invocation()?;
            handle_agent(&root, &name, &task.join(" "))
        }
        Commands::Init => ensure_layout(&root),
    }
}

fn ensure_internal_invocation() -> Result<()> {
    let marker = std::env::var("OPENSUS_INTERNAL_AGENT").unwrap_or_default();
    if marker != "1" {
        bail!("`opensus agent` is internal-only; use `opensus go` or `opensus init`");
    }
    Ok(())
}

fn handle_go(root: &Path) -> Result<()> {
    ensure_layout(root)?;
    let cfg = load_susfile(root)?;
    let mission = read_state_status(root)?;
    if mission.eq_ignore_ascii_case("complete") {
        println!("Mission already complete.");
        return Ok(());
    }

    let objective = read_mission_objective(root)?;
    let swarm = load_swarm(root)?;

    let main_task = format!(
        "Model: {}\nPentest objective:\n{}\n\nCurrent swarm entries: {}\n\nCoordinate intel -> exploit -> reporter and mark mission complete when report is done.",
        cfg.model,
        objective,
        swarm.len(),
    );

    handle_agent(root, "main", &main_task)
}

fn handle_agent(root: &Path, name: &str, task: &str) -> Result<()> {
    ensure_layout(root)?;
    let cfg = load_susfile(root)?;

    let prompt_path = root.join("prompts").join(format!("{name}.md"));
    let prompt = fs::read_to_string(&prompt_path)
        .with_context(|| format!("failed to read prompt file: {}", prompt_path.display()))?;

    println!("=== Running agent: {name} ===");
    println!("Model: {} (api: {})", cfg.model, cfg.api);
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

    if swarm
        .iter()
        .any(|entry| matches!(entry.status, AgentStatus::Running))
    {
        println!("Main agent: workers already running; waiting for next heartbeat.");
        return Ok(());
    }

    let intel_done = swarm
        .iter()
        .any(|entry| entry.agent == "intel" && matches!(entry.status, AgentStatus::Complete));
    let exploit_done = swarm
        .iter()
        .any(|entry| entry.agent == "exploit" && matches!(entry.status, AgentStatus::Complete));
    let reporter_done = swarm
        .iter()
        .any(|entry| entry.agent == "reporter" && matches!(entry.status, AgentStatus::Complete));

    let spawn_tool = SpawnAgentTool {
        root: root.to_path_buf(),
    };

    if !intel_done {
        spawn_tool.call(serde_json::json!({
            "name": "intel",
            "task": format!("Perform recon and collect findings for: {objective}")
        }))?;
        println!("Main agent: spawned intel.");
        return Ok(());
    }

    if !exploit_done {
        spawn_tool.call(serde_json::json!({
            "name": "exploit",
            "task": "Attempt validated exploitation paths from intel findings"
        }))?;
        println!("Main agent: spawned exploit.");
        return Ok(());
    }

    if !reporter_done {
        spawn_tool.call(serde_json::json!({
            "name": "reporter",
            "task": "Generate final automatic pentest report with evidence and remediation"
        }))?;
        println!("Main agent: spawned reporter.");
        return Ok(());
    }

    if task.contains("mark mission complete") || (intel_done && exploit_done && reporter_done) {
        write_state_status(root, "complete")?;
        println!("Main agent: mission marked complete.");
    }

    Ok(())
}

fn run_worker_agent(root: &Path, name: &str, _prompt: &str, task: &str) -> Result<()> {
    let nmap_verify = NmapVerifyTool.call(serde_json::json!({}))?;

    let log_path = root.join(format!(".{name}.log"));
    let entry = format!("task: {task}\n{nmap_verify}\nstatus: completed\n\n");
    fs::write(log_path, entry).context("failed to write worker log")?;
    Ok(())
}

fn ensure_layout(root: &Path) -> Result<()> {
    fs::create_dir_all(root.join("prompts")).context("failed to create prompts/ directory")?;

    write_if_missing(
        &root.join("prompts/main.md"),
        "# Main Agent\n\nYou are the pentest orchestrator. Read state.md and swarm.md, spawn intel/exploit/reporter as needed, then mark mission complete when the report is finalized.\n",
    )?;
    write_if_missing(
        &root.join("prompts/intel.md"),
        "# Intel Agent\n\nCollect reconnaissance data, map attack surface, and output actionable findings.\n",
    )?;
    write_if_missing(
        &root.join("prompts/exploit.md"),
        "# Exploit Agent\n\nValidate exploitable weaknesses safely and collect evidence.\n",
    )?;
    write_if_missing(
        &root.join("prompts/reporter.md"),
        "# Reporter Agent\n\nProduce a clear pentest report with severity, evidence, and remediation guidance.\n",
    )?;
    write_if_missing(&root.join("prompts/swarm.md"), "# Swarm Status\n\n")?;
    write_if_missing(
        &root.join("state.md"),
        "# Mission\n\nGenerate an automatic pentest report for the target scope.\n\n## Status\nincomplete\n",
    )?;
    write_if_missing(
        &root.join("susfile"),
        "{\n  \"api\": \"openai\",\n  \"model\": \"gpt-4.1\"\n}\n",
    )?;

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

fn load_susfile(root: &Path) -> Result<Susfile> {
    let path = root.join("susfile");
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read susfile in {}", root.display()))?;
    let cfg: Susfile = serde_json::from_str(&content).context("susfile must be valid JSON")?;
    if cfg.api.to_lowercase() != "openai" {
        bail!(
            "unsupported api `{}` in susfile; only `openai` is supported",
            cfg.api
        );
    }
    if cfg.model.trim().is_empty() {
        bail!("susfile.model must not be empty");
    }
    Ok(cfg)
}

fn read_mission_objective(root: &Path) -> Result<String> {
    let content = fs::read_to_string(root.join("state.md")).context("failed to read state.md")?;
    let mut objective_lines = Vec::new();
    for line in content.lines() {
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

    fs::write(state_path, result.join("\n") + "\n").context("failed to write state.md")?;
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

    #[test]
    fn validates_openai_susfile() {
        let tmp = tempfile::tempdir().expect("tempdir");
        fs::write(
            tmp.path().join("susfile"),
            "{\"api\":\"openai\",\"model\":\"gpt-4.1\"}",
        )
        .expect("write susfile");
        let cfg = load_susfile(tmp.path()).expect("config should parse");
        assert_eq!(cfg.api, "openai");
    }
}
