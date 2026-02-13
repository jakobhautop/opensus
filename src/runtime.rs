use std::{
    fs,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use anyhow::{bail, Context, Result};
use tokio::task::JoinSet;

use crate::{
    chat::{
        main_agent_tool_defs, planning_agent_tool_defs, report_agent_tool_defs,
        worker_agent_tool_defs,
    },
    config::{default_susfile, load_susfile},
    plan::{parse_tasks, planning_complete, read_plan, update_task_status, write_plan, TaskStatus},
    tools::{nmap_scan_aggressive, nmap_verify},
};

#[derive(Clone)]
struct RuntimeCtx {
    root: Arc<std::path::PathBuf>,
    active_workers: Arc<AtomicUsize>,
}

#[derive(Clone, Copy)]
enum AgentKind {
    Planning,
    Worker,
    Report,
}

pub fn handle_init(root: &Path) -> Result<()> {
    let cfg = default_susfile();
    write_if_missing(
        &root.join("susfile"),
        &(serde_json::to_string_pretty(&cfg)? + "\n"),
    )?;

    let loaded = load_susfile(root)?;
    if loaded.api.eq_ignore_ascii_case("openai") && std::env::var("OPENAI_API_KEY").is_err() {
        bail!("OPENAI_API_KEY is required when susfile.api=openai");
    }

    fs::create_dir_all(root.join("notes")).context("failed to create notes/")?;
    write_if_missing(&root.join("plan.md"), "")?;

    fs::create_dir_all(root.join("prompts")).context("failed to create prompts/")?;
    write_if_missing(
        &root.join("prompts/main_agent.md"),
        "# main_agent\n\nRead plan and spawn planning/worker/report agents as needed.\n",
    )?;
    write_if_missing(
        &root.join("prompts/planning_agent.md"),
        "# planning_agent\n\nCreate or update plan.md with actionable tasks.\n",
    )?;
    write_if_missing(
        &root.join("prompts/worker_agent.md"),
        "# worker_agent\n\nClaim task, run tools, write notes, and complete or crash task.\n",
    )?;
    write_if_missing(
        &root.join("prompts/report_agent.md"),
        "# report_agent\n\nGenerate report.md once planning is complete and no tasks remain.\n",
    )?;
    Ok(())
}

pub async fn handle_go(root: &Path) -> Result<()> {
    handle_init(root)?;
    let cfg = load_susfile(root)?;
    let ctx = RuntimeCtx {
        root: Arc::new(root.to_path_buf()),
        active_workers: Arc::new(AtomicUsize::new(0)),
    };

    // main_agent invoked with tool definitions (OpenAI style payloads)
    let _main_tools = main_agent_tool_defs();

    let plan_md = read_plan(root)?;
    if plan_md.trim().is_empty() {
        spawn_agent(ctx.clone(), AgentKind::Planning, None).await?;
        return Ok(());
    }

    let tasks = parse_tasks(&plan_md);
    let mut joinset = JoinSet::new();
    for task in tasks {
        if !matches!(task.status, TaskStatus::Open) {
            continue;
        }
        if ctx.active_workers.load(Ordering::SeqCst) >= cfg.max_agents_per_time {
            break;
        }
        ctx.active_workers.fetch_add(1, Ordering::SeqCst);
        let ctx_clone = ctx.clone();
        let task_id = task.id.clone();
        joinset.spawn(async move {
            let result = run_agent(ctx_clone.clone(), AgentKind::Worker, Some(task_id)).await;
            ctx_clone.active_workers.fetch_sub(1, Ordering::SeqCst);
            result
        });
    }

    while let Some(res) = joinset.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                eprintln!("worker agent failed: {err}");
            }
            Err(err) => {
                eprintln!("worker task join failure: {err}");
            }
        }
    }

    let post_plan = read_plan(root)?;
    let post_tasks = parse_tasks(&post_plan);
    let no_tasks_left = post_tasks
        .iter()
        .all(|t| matches!(t.status, TaskStatus::Complete));

    if planning_complete(&post_plan) && !post_tasks.is_empty() && no_tasks_left {
        spawn_agent(ctx, AgentKind::Report, None).await?;
    }

    Ok(())
}

async fn spawn_agent(ctx: RuntimeCtx, kind: AgentKind, task_id: Option<String>) -> Result<()> {
    // single spawn function for all agent types
    let handle = tokio::spawn(async move { run_agent(ctx, kind, task_id).await });
    handle.await?
}

async fn run_agent(ctx: RuntimeCtx, kind: AgentKind, task_id: Option<String>) -> Result<()> {
    let (prompt_file, _tool_defs) = match kind {
        AgentKind::Planning => ("planning_agent.md", planning_agent_tool_defs()),
        AgentKind::Worker => ("worker_agent.md", worker_agent_tool_defs()),
        AgentKind::Report => ("report_agent.md", report_agent_tool_defs()),
    };

    let _prompt = fs::read_to_string(ctx.root.join("prompts").join(prompt_file))
        .with_context(|| format!("failed to load prompt {}", prompt_file))?;

    match kind {
        AgentKind::Planning => run_planning_agent(&ctx.root),
        AgentKind::Worker => {
            let id = task_id.context("worker task_id required")?;
            match run_worker_agent(&ctx.root, &id) {
                Ok(()) => Ok(()),
                Err(err) => {
                    let _ = mark_task_crashed(&ctx.root, &id, &err.to_string());
                    Err(err)
                }
            }
        }
        AgentKind::Report => run_report_agent(&ctx.root),
    }
}

fn run_planning_agent(root: &Path) -> Result<()> {
    let current = read_plan(root)?;
    if current.trim().is_empty() {
        let cfg = load_susfile(root)?;
        let mut tasks = String::new();
        for (idx, ip) in cfg.tools.nmap.ips.iter().enumerate() {
            tasks.push_str(&format!("- [ ] T{:03} - Aggressive scan {}\n", idx + 1, ip));
        }
        let markdown = format!(
            "# Plan\n\nplanning_status: complete\n\n## Intelligence gathering\n\n### nmap tasks\n\n{}",
            tasks
        );
        write_plan(root, &markdown)?;
    }
    Ok(())
}

fn run_worker_agent(root: &Path, task_id: &str) -> Result<()> {
    let plan = read_plan(root)?;
    let task = parse_tasks(&plan)
        .into_iter()
        .find(|t| t.id == task_id)
        .context("task not found")?;

    claim_task(root, &task.id, &task.title)?;

    let (cmd_verify, out_verify, err_verify) = nmap_verify()?;
    record_tool_call(
        root,
        &task.id,
        "nmap_verify",
        &cmd_verify,
        &out_verify,
        &err_verify,
    )?;

    let cfg = load_susfile(root)?;
    let target_ip = select_scan_ip(&task.title, &cfg.tools.nmap.ips)?;
    let (cmd_scan, out_scan, err_scan) = nmap_scan_aggressive(&target_ip)?;
    record_tool_call(
        root,
        &task.id,
        "nmap_aggressive_scan",
        &cmd_scan,
        &out_scan,
        &err_scan,
    )?;

    add_note(root, &task.id, &format!("Completed task on {target_ip}"))?;
    complete_task(root, &task.id)
}

fn run_report_agent(root: &Path) -> Result<()> {
    let plan = read_plan(root)?;
    let tasks = parse_tasks(&plan);
    let remaining = tasks
        .iter()
        .filter(|t| !matches!(t.status, TaskStatus::Complete))
        .count();
    let report = format!(
        "# Pentest Report\n\nGenerated by report_agent.\n\n- Tasks: {}\n- Remaining: {}\n",
        tasks.len(),
        remaining
    );
    fs::write(root.join("report.md"), report).context("failed to write report.md")
}

fn select_scan_ip(task_title: &str, allowlisted_ips: &[String]) -> Result<String> {
    for token in task_title.split_whitespace() {
        let cleaned = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.');
        if allowlisted_ips.iter().any(|ip| ip == cleaned) {
            return Ok(cleaned.to_string());
        }
    }
    bail!("task title does not contain allowlisted IP")
}

fn claim_task(root: &Path, task_id: &str, title: &str) -> Result<()> {
    update_task_status(root, task_id, TaskStatus::Pending)?;
    ensure_task_note(root, task_id, title, "open")
}

fn complete_task(root: &Path, task_id: &str) -> Result<()> {
    update_task_status(root, task_id, TaskStatus::Complete)?;
    set_note_state(root, task_id, "complete")
}

fn mark_task_crashed(root: &Path, task_id: &str, reason: &str) -> Result<()> {
    update_task_status(root, task_id, TaskStatus::Crashed)?;
    set_note_state(root, task_id, "crashed")?;
    add_note(root, task_id, &format!("Agent crashed: {reason}"))
}

fn ensure_task_note(root: &Path, task_id: &str, title: &str, state: &str) -> Result<()> {
    let path = root.join("notes").join(format!("{task_id}.md"));
    if !path.exists() {
        let body = format!("---\nstate: {state}\n---\n# Task: {title}\n## Tools\n\n## Notes\n");
        fs::write(path, body).context("failed to write task note")?;
    }
    Ok(())
}

fn set_note_state(root: &Path, task_id: &str, state: &str) -> Result<()> {
    let path = root.join("notes").join(format!("{task_id}.md"));
    let content = fs::read_to_string(&path).context("failed to read note")?;
    let replaced = content
        .lines()
        .map(|line| {
            if line.starts_with("state:") {
                format!("state: {state}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(path, replaced).context("failed to write note")
}

fn add_note(root: &Path, task_id: &str, note: &str) -> Result<()> {
    let path = root.join("notes").join(format!("{task_id}.md"));
    let mut content = fs::read_to_string(&path).context("failed to read note")?;
    content.push_str(&format!("- {note}\n"));
    fs::write(path, content).context("failed to append note")
}

fn record_tool_call(
    root: &Path,
    task_id: &str,
    tool: &str,
    stdin: &str,
    stdout: &str,
    stderr: &str,
) -> Result<()> {
    let path = root.join("notes").join(format!("{task_id}.md"));
    let mut content = fs::read_to_string(&path).context("failed to read note")?;
    content.push_str(&format!(
        "\n### {tool}\n- stdin:\n```\n{stdin}\n```\n- stdout:\n```\n{stdout}\n```\n- stderr:\n```\n{stderr}\n```\n"
    ));
    fs::write(path, content).context("failed to append tool record")
}

fn write_if_missing(path: &Path, content: &str) -> Result<()> {
    if !path.exists() {
        fs::write(path, content).with_context(|| format!("failed writing {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_ip_match_not_substring() {
        let allow = vec!["10.0.0.1".to_string(), "10.0.0.10".to_string()];
        let ip = select_scan_ip("Aggressive scan 10.0.0.10", &allow).expect("match");
        assert_eq!(ip, "10.0.0.10");
    }

    #[test]
    fn missing_ip_fails() {
        let allow = vec!["10.0.0.1".to_string()];
        assert!(select_scan_ip("Aggressive scan host-a", &allow).is_err());
    }
}
