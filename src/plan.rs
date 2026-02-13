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

pub fn read_plan(root: &Path) -> Result<Option<String>> {
    let path = root.join("plan.md");
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path).context("failed to read plan.md")?;
    Ok(Some(content))
}

pub fn write_plan(root: &Path, markdown: &str) -> Result<()> {
    fs::write(root.join("plan.md"), markdown).context("failed to write plan.md")
}

pub fn planning_complete(markdown: &str) -> bool {
    markdown.lines().any(|line| {
        line.trim()
            .eq_ignore_ascii_case("planning_status: complete")
    })
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

pub fn update_task_status(root: &Path, task_id: &str, status: TaskStatus) -> Result<()> {
    let mut markdown = read_plan(root)?.context("plan.md does not exist")?;
    let marker = match status {
        TaskStatus::Open => "[ ]",
        TaskStatus::Pending => "[~]",
        TaskStatus::Complete => "[x]",
        TaskStatus::Crashed => "[!]",
    };

    let mut changed = false;
    let mut out = Vec::new();
    for line in markdown.lines() {
        let trimmed = line.trim_start();
        let matches = trimmed.starts_with("- [ ")
            || trimmed.starts_with("- [~]")
            || trimmed.starts_with("- [x]")
            || trimmed.starts_with("- [!]");
        if matches && trimmed.contains(task_id) {
            if let Some((_, rest)) = trimmed.split_once("] ") {
                out.push(format!("- {} {}", marker, rest));
                changed = true;
                continue;
            }
        }
        out.push(line.to_string());
    }

    if !changed {
        bail!("task id `{}` not found in plan.md", task_id);
    }

    markdown = out.join("\n") + "\n";
    write_plan(root, &markdown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_task_statuses() {
        let md = "- [ ] T001 - one\n- [~] T002 - two\n- [x] T003 - three\n- [!] T004 - four\n";
        let tasks = parse_tasks(md);
        assert_eq!(tasks.len(), 4);
        assert!(matches!(tasks[1].status, TaskStatus::Pending));
        assert!(planning_complete("planning_status: complete"));
    }
}
