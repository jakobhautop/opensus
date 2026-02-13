use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use uuid::Uuid;

use crate::swarm::{update_swarm_spawn, update_swarm_status, AgentStatus};

fn spawn_internal(root: &Path, agent: &str, args: &[&str], task_id: Option<&str>) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    update_swarm_spawn(root, &id, agent, task_id)?;

    let binary = env::current_exe().unwrap_or_else(|_| PathBuf::from("opensus"));
    let mut cmd = Command::new(binary);
    cmd.current_dir(root)
        .env("OPENSUS_INTERNAL_AGENT", "1")
        .env("OPENSUS_SWARM_ID", &id)
        .arg(args[0]);
    for arg in &args[1..] {
        cmd.arg(arg);
    }

    if let Err(error) = cmd.spawn() {
        update_swarm_status(root, &id, AgentStatus::Crashed)?;
        return Err(error).context("failed to spawn child agent process");
    }

    Ok(())
}

pub fn spawn_plan_agent(root: &Path) -> Result<()> {
    spawn_internal(root, "plan_agent", &["internal-plan-agent"], None)
}

pub fn spawn_work_agent(root: &Path, task_id: &str) -> Result<()> {
    spawn_internal(
        root,
        "work_agent",
        &["internal-work-agent", task_id],
        Some(task_id),
    )
}

pub fn spawn_reporter_agent(root: &Path) -> Result<()> {
    spawn_internal(root, "reporter_agent", &["internal-reporter-agent"], None)
}

pub fn mark_internal_swarm_complete(root: &Path) -> Result<()> {
    let id = env::var("OPENSUS_SWARM_ID").context("missing OPENSUS_SWARM_ID")?;
    update_swarm_status(root, &id, AgentStatus::Complete)
}

pub fn mark_internal_swarm_crashed(root: &Path) -> Result<()> {
    let id = env::var("OPENSUS_SWARM_ID").context("missing OPENSUS_SWARM_ID")?;
    update_swarm_status(root, &id, AgentStatus::Crashed)
}

pub fn nmap_verify() -> Result<(String, String, String)> {
    let output = Command::new("nmap")
        .arg("--version")
        .output()
        .context("failed to execute nmap --version")?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        bail!("nmap --version failed: {}", stderr.trim());
    }
    Ok(("nmap --version".to_string(), stdout, stderr))
}

pub fn nmap_scan_aggressive(ip: &str) -> Result<(String, String, String)> {
    if ip.trim().is_empty() {
        bail!("ip must not be empty");
    }
    let output = Command::new("nmap")
        .arg("-A")
        .arg(ip)
        .output()
        .context("failed to execute nmap -A")?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        bail!("nmap -A failed: {}", stderr.trim());
    }
    Ok((format!("nmap -A {ip}"), stdout, stderr))
}
