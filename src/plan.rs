use std::{fs, path::Path};

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskStatus {
    Open,
    Pending,
    Complete,
    Crashed,
}

#[derive(Debug, Clone)]
pub struct PlanTask {
    pub id: String,
    pub title: String,
    pub status: TaskStatus,
}

pub fn read_plan(root: &Path) -> Result<String> {
    fs::read_to_string(root.join("plan.md")).context("failed to read plan.md")
}

pub fn write_plan(root: &Path, markdown: &str) -> Result<()> {
    fs::write(root.join("plan.md"), markdown).context("failed to write plan.md")
}

pub fn parse_tasks(markdown: &str) -> Vec<PlanTask> {
    let mut tasks = Vec::new();
    for line in markdown.lines() {
        let trimmed = line.trim();
        let (status, rest) = if let Some(v) = trimmed.strip_prefix("- [ ] ") {
            (TaskStatus::Open, v)
        } else if let Some(v) = trimmed.strip_prefix("- [~] ") {
            (TaskStatus::Pending, v)
        } else if let Some(v) = trimmed.strip_prefix("- [x] ") {
            (TaskStatus::Complete, v)
        } else if let Some(v) = trimmed.strip_prefix("- [!] ") {
            (TaskStatus::Crashed, v)
        } else {
            continue;
        };

        if let Some((id, title)) = rest.split_once(" - ") {
            tasks.push(PlanTask {
                id: id.trim().to_string(),
                title: title.trim().to_string(),
                status,
            });
        }
    }
    tasks
}

pub fn planning_complete(markdown: &str) -> bool {
    markdown
        .lines()
        .any(|l| l.trim() == "planning_status: complete")
}

pub fn update_task_status(root: &Path, task_id: &str, status: TaskStatus) -> Result<()> {
    let markdown = read_plan(root)?;
    let marker = match status {
        TaskStatus::Open => "[ ]",
        TaskStatus::Pending => "[~]",
        TaskStatus::Complete => "[x]",
        TaskStatus::Crashed => "[!]",
    };

    let mut changed = false;
    let mut out = Vec::new();
    for line in markdown.lines() {
        let t = line.trim_start();
        let task_line = t.starts_with("- [ ")
            || t.starts_with("- [~]")
            || t.starts_with("- [x]")
            || t.starts_with("- [!]");
        if task_line && t.contains(task_id) {
            if let Some((_, rest)) = t.split_once("] ") {
                out.push(format!("- {} {}", marker, rest));
                changed = true;
                continue;
            }
        }
        out.push(line.to_string());
    }

    if !changed {
        bail!("task id `{}` not found", task_id);
    }

    write_plan(root, &(out.join("\n") + "\n"))
}
