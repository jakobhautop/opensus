use std::{fs, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmEntry {
    pub id: String,
    pub agent: String,
    pub status: AgentStatus,
    pub task_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
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

pub fn read_swarm(root: &Path) -> Result<Vec<SwarmEntry>> {
    let path = root.join("swarm.md");
    if !path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(path).context("failed to read swarm.md")?;
    let mut entries = Vec::new();
    let mut current = SwarmEntry {
        id: String::new(),
        agent: String::new(),
        status: AgentStatus::Running,
        task_id: None,
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
                    task_id: None,
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
        } else if let Some(value) = trimmed.strip_prefix("task_id:") {
            let v = value.trim();
            current.task_id = if v.is_empty() || v == "-" {
                None
            } else {
                Some(v.to_string())
            };
        }
    }

    if seen {
        entries.push(current);
    }
    Ok(entries)
}

pub fn write_swarm(root: &Path, entries: &[SwarmEntry]) -> Result<()> {
    let mut out = String::from("# Swarm Status\n\n");
    for entry in entries {
        out.push_str(&format!(
            "- id: {}\n  agent: {}\n  status: {}\n  task_id: {}\n\n",
            entry.id,
            entry.agent,
            entry.status,
            entry.task_id.clone().unwrap_or_else(|| "-".to_string())
        ));
    }

    fs::write(root.join("swarm.md"), out).context("failed to write swarm.md")?;
    Ok(())
}

pub fn update_swarm_spawn(root: &Path, id: &str, agent: &str, task_id: Option<&str>) -> Result<()> {
    let mut entries = read_swarm(root)?;
    entries.push(SwarmEntry {
        id: id.to_string(),
        agent: agent.to_string(),
        status: AgentStatus::Running,
        task_id: task_id.map(ToString::to_string),
    });
    write_swarm(root, &entries)
}

pub fn update_swarm_status(root: &Path, id: &str, status: AgentStatus) -> Result<()> {
    let mut entries = read_swarm(root)?;
    for entry in &mut entries {
        if entry.id == id {
            entry.status = status.clone();
        }
    }
    write_swarm(root, &entries)
}

pub fn running_workers_for_task(entries: &[SwarmEntry], task_id: &str) -> bool {
    entries.iter().any(|entry| {
        entry.task_id.as_deref() == Some(task_id)
            && entry.status == AgentStatus::Running
            && entry.agent == "work_agent"
    })
}
