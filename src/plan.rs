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

        if let Some((id, title)) = parse_task_id_and_title(rest) {
            tasks.push(PlanTask { id, title, status });
        }
    }
    tasks
}

fn parse_task_id_and_title(rest: &str) -> Option<(String, String)> {
    let trimmed = rest.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some((id, title)) = trimmed.split_once(" - ") {
        return Some((id.trim().to_string(), title.trim().to_string()));
    }

    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let id = parts.next()?.trim();
    if id.is_empty() {
        return None;
    }
    let title = parts.next().unwrap_or("").trim();
    Some((id.to_string(), title.to_string()))
}

pub fn planning_complete(markdown: &str) -> bool {
    markdown.lines().any(|l| l.trim() == "status: complete")
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

pub fn append_tool_request(root: &Path, request: &str) -> Result<()> {
    let markdown = read_plan(root)?;
    let mut lines: Vec<String> = markdown.lines().map(ToString::to_string).collect();

    if let Some(header_idx) = lines
        .iter()
        .position(|line| line.trim().eq_ignore_ascii_case("# Tool Request"))
    {
        let mut insert_idx = header_idx + 1;
        while insert_idx < lines.len() && lines[insert_idx].trim().is_empty() {
            insert_idx += 1;
        }
        lines.insert(insert_idx, format!("- {}", request.trim()));
    } else {
        if !lines.is_empty() && !lines.last().is_some_and(|line| line.trim().is_empty()) {
            lines.push(String::new());
        }
        lines.push("# Tool Request".to_string());
        lines.push(format!("- {}", request.trim()));
    }

    write_plan(root, &(lines.join("\n") + "\n"))
}

pub fn append_review_finding(root: &Path, finding: &str) -> Result<()> {
    let markdown = read_plan(root)?;
    let mut lines: Vec<String> = markdown.lines().map(ToString::to_string).collect();

    if let Some(header_idx) = lines
        .iter()
        .position(|line| line.trim().eq_ignore_ascii_case("# Review Findings"))
    {
        let mut insert_idx = header_idx + 1;
        while insert_idx < lines.len() && lines[insert_idx].trim().is_empty() {
            insert_idx += 1;
        }
        lines.insert(insert_idx, format!("- [ ] {}", finding.trim()));
    } else {
        if !lines.is_empty() && !lines.last().is_some_and(|line| line.trim().is_empty()) {
            lines.push(String::new());
        }
        lines.push("# Review Findings".to_string());
        lines.push(format!("- [ ] {}", finding.trim()));
    }

    write_plan(root, &(lines.join("\n") + "\n"))
}

pub fn mark_review_findings_read(root: &Path, task_id: &str) -> Result<usize> {
    let markdown = read_plan(root)?;
    let mut changed = 0usize;
    let mut out = Vec::new();

    for line in markdown.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("- [ ] ") {
            let starts_with_id = rest.starts_with(task_id)
                && rest
                    .chars()
                    .nth(task_id.len())
                    .is_none_or(|c| c.is_whitespace() || c == '|');
            if starts_with_id {
                out.push(format!("- [x] {rest}"));
                changed += 1;
                continue;
            }
        }
        out.push(line.to_string());
    }

    if changed > 0 {
        write_plan(root, &(out.join("\n") + "\n"))?;
    }

    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn append_tool_request_creates_section_when_missing() {
        let tmp = tempdir().expect("tempdir");
        write_plan(
            tmp.path(),
            "# Plan\n\n## Phase 1\n- [ ] T0001 - Scan target\n",
        )
        .expect("write plan");

        append_tool_request(tmp.path(), "nikto -h http://10.10.10.5").expect("append");
        let updated = read_plan(tmp.path()).expect("read");

        assert!(updated.contains("# Tool Request\n- nikto -h http://10.10.10.5\n"));
    }

    #[test]
    fn append_tool_request_inserts_into_existing_section() {
        let tmp = tempdir().expect("tempdir");
        write_plan(
            tmp.path(),
            "# Plan\n\n# Tool Request\n- gobuster dir -u http://10.10.10.5 -w /tmp/words.txt\n",
        )
        .expect("write plan");

        append_tool_request(
            tmp.path(),
            "ffuf -u http://10.10.10.5/FUZZ -w /tmp/words.txt",
        )
        .expect("append");
        let updated = read_plan(tmp.path()).expect("read");

        assert!(updated.contains(
            "# Tool Request\n- ffuf -u http://10.10.10.5/FUZZ -w /tmp/words.txt\n- gobuster dir -u http://10.10.10.5 -w /tmp/words.txt"
        ));
    }
    #[test]
    fn parse_tasks_accepts_titles_without_dash_separator() {
        let plan = "# Plan
- [ ] T0001 Perform network scan with version detection
";
        let tasks = parse_tasks(plan);
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, "T0001");
        assert_eq!(
            tasks[0].title,
            "Perform network scan with version detection"
        );
        assert_eq!(tasks[0].status, TaskStatus::Open);
    }

    #[test]
    fn append_review_finding_creates_section_when_missing() {
        let tmp = tempdir().expect("tempdir");
        write_plan(tmp.path(), "# Plan\n\n- [ ] T0001 - Scan target\n").expect("write plan");

        append_review_finding(tmp.path(), "T0001 | note | Found HTTP 200 on /admin")
            .expect("append");
        let updated = read_plan(tmp.path()).expect("read");

        assert!(
            updated.contains("# Review Findings\n- [ ] T0001 | note | Found HTTP 200 on /admin\n")
        );
    }

    #[test]
    fn mark_review_findings_read_marks_only_matching_task_id() {
        let tmp = tempdir().expect("tempdir");
        write_plan(
            tmp.path(),
            "# Plan\n\n# Review Findings\n- [ ] T0001 | note | Found admin panel\n- [ ] T0002 | tool:nmap | Open ports\n",
        )
        .expect("write plan");

        let changed = mark_review_findings_read(tmp.path(), "T0001").expect("mark read");
        let updated = read_plan(tmp.path()).expect("read");

        assert_eq!(changed, 1);
        assert!(updated.contains("- [x] T0001 | note | Found admin panel"));
        assert!(updated.contains("- [ ] T0002 | tool:nmap | Open ports"));
    }
}
