use std::{fs, path::Path};

use anyhow::{bail, Context, Result};

use crate::{
    chat::{main_agent_brief, plan_agent_brief, reporter_agent_brief, work_agent_brief},
    config::load_susfile,
    plan::{parse_tasks, planning_complete, read_plan, update_task_status, write_plan, TaskStatus},
    swarm::{read_swarm, running_workers_for_task, AgentStatus},
    tools::{
        mark_internal_swarm_complete, mark_internal_swarm_crashed, nmap_scan_aggressive,
        nmap_verify, spawn_plan_agent, spawn_reporter_agent, spawn_work_agent,
    },
};

pub fn ensure_internal_invocation() -> Result<()> {
    let marker = std::env::var("OPENSUS_INTERNAL_AGENT").unwrap_or_default();
    if marker != "1" {
        bail!("internal agent commands are not user-facing; use `opensus go` or `opensus init`");
    }
    Ok(())
}

pub fn handle_go(root: &Path) -> Result<()> {
    ensure_layout(root)?;
    run_main_agent(root)
}

fn run_main_agent(root: &Path) -> Result<()> {
    let cfg = load_susfile(root)?;
    println!("{}", main_agent_brief());

    // read_plan()
    let plan_markdown = read_plan(root)?;
    if plan_markdown.is_none() {
        println!("main_agent: no plan.md found, spawning plan_agent.");
        spawn_plan_agent(root)?;
        return Ok(());
    }
    let plan_markdown = plan_markdown.expect("checked is_some");

    // read_swarm()
    let swarm = read_swarm(root)?;

    let tasks = parse_tasks(&plan_markdown);
    let remaining_tasks = tasks
        .iter()
        .filter(|t| !matches!(t.status, TaskStatus::Complete))
        .count();

    let running_workers = swarm
        .iter()
        .filter(|entry| entry.agent == "work_agent" && entry.status == AgentStatus::Running)
        .count();

    if planning_complete(&plan_markdown)
        && remaining_tasks == 0
        && !swarm
            .iter()
            .any(|entry| entry.agent == "reporter_agent" && entry.status == AgentStatus::Running)
    {
        println!("main_agent: plan complete and no tasks left; spawning reporter_agent.");
        spawn_reporter_agent(root)?;
        return Ok(());
    }

    let capacity = cfg.max_agents_per_time.saturating_sub(running_workers);
    if capacity == 0 {
        println!("main_agent: max_agents_per_time reached; sleeping until next heartbeat.");
        return Ok(());
    }

    let mut spawned = 0usize;
    for task in tasks {
        if spawned >= capacity {
            break;
        }
        if !matches!(task.status, TaskStatus::Open) {
            continue;
        }
        if running_workers_for_task(&swarm, &task.id) {
            continue;
        }
        println!("main_agent: spawning work_agent for task {}", task.id);
        // spawn_agent(task_id)
        spawn_work_agent(root, &task.id)?;
        spawned += 1;
    }

    println!("main_agent: cycle complete; sleeping until next heartbeat.");
    Ok(())
}

pub fn handle_plan_agent(root: &Path) -> Result<()> {
    let result = (|| {
        println!("{}", plan_agent_brief());
        // read_plan()
        let existing = read_plan(root)?;
        if existing.is_none() {
            // write_plan(markdown)
            let markdown = build_default_plan(root)?;
            write_plan(root, &markdown)?;
        } else if !planning_complete(existing.as_ref().expect("exists")) {
            // write_plan(markdown) update path
            let mut content = existing.expect("exists");
            if !content.contains("planning_status:") {
                content = format!("planning_status: complete\n\n{content}");
            } else {
                content =
                    content.replace("planning_status: incomplete", "planning_status: complete");
            }
            write_plan(root, &content)?;
        }
        Ok(())
    })();

    finalize_internal_agent(root, result)
}

pub fn handle_work_agent(root: &Path, task_id: &str) -> Result<()> {
    let result = (|| {
        println!("{}", work_agent_brief());
        // read_plan()
        let markdown = read_plan(root)?.context("plan.md does not exist")?;
        let task = parse_tasks(&markdown)
            .into_iter()
            .find(|t| t.id == task_id)
            .context("task id not found")?;

        // claim_task(id)
        claim_task(root, &task.id, &task.title)?;

        // nmap_verify()
        let (stdin_verify, stdout_verify, stderr_verify) = nmap_verify()?;
        record_tool_call(
            root,
            &task.id,
            "nmap_verify",
            &stdin_verify,
            &stdout_verify,
            &stderr_verify,
        )?;

        // nmap_aggressive_scan()
        let cfg = load_susfile(root)?;
        let scan_ip = cfg
            .tools
            .nmap
            .ips
            .iter()
            .find(|ip| task.title.contains(ip.as_str()))
            .cloned()
            .unwrap_or_else(|| cfg.tools.nmap.ips[0].clone());
        let (stdin_scan, stdout_scan, stderr_scan) = nmap_scan_aggressive(&scan_ip)?;
        record_tool_call(
            root,
            &task.id,
            "nmap_aggressive_scan",
            &stdin_scan,
            &stdout_scan,
            &stderr_scan,
        )?;

        // add_note(string)
        add_note(
            root,
            &task.id,
            &format!("Completed task {} using target {}.", task.id, scan_ip),
        )?;

        // complete_task(id)
        complete_task(root, &task.id)?;
        Ok(())
    })();

    finalize_work_agent(root, task_id, result)
}

pub fn handle_reporter_agent(root: &Path) -> Result<()> {
    let result = (|| {
        println!("{}", reporter_agent_brief());
        let plan = read_plan(root)?.context("plan.md does not exist")?;
        let tasks = parse_tasks(&plan);
        let open = tasks
            .iter()
            .filter(|t| !matches!(t.status, TaskStatus::Complete))
            .count();

        let report = format!(
            "# Pentest Report\n\nGenerated by reporter_agent.\n\n- Tasks total: {}\n- Remaining non-complete: {}\n",
            tasks.len(), open
        );
        fs::write(root.join("report.md"), report).context("failed to write report.md")?;
        Ok(())
    })();

    finalize_internal_agent(root, result)
}

fn finalize_work_agent(root: &Path, task_id: &str, result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => {
            mark_internal_swarm_complete(root)?;
            Ok(())
        }
        Err(err) => {
            let _ = mark_task_crashed(root, task_id, &err.to_string());
            let _ = mark_internal_swarm_crashed(root);
            Err(err)
        }
    }
}

fn finalize_internal_agent(root: &Path, result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => {
            mark_internal_swarm_complete(root)?;
            Ok(())
        }
        Err(err) => {
            let _ = mark_internal_swarm_crashed(root);
            Err(err)
        }
    }
}

fn build_default_plan(root: &Path) -> Result<String> {
    let cfg = load_susfile(root)?;
    let mut tasks = String::new();
    for (idx, ip) in cfg.tools.nmap.ips.iter().enumerate() {
        tasks.push_str(&format!("- [ ] T{:03} - Aggressive scan {}\n", idx + 1, ip));
    }

    Ok(format!(
        "# Plan\n\nplanning_status: complete\n\n## Intelligence gathering\n\n### nmap tasks\n\n{}",
        tasks
    ))
}

fn claim_task(root: &Path, task_id: &str, title: &str) -> Result<()> {
    update_task_status(root, task_id, TaskStatus::Pending)?;
    ensure_task_note(root, task_id, title, "open")
}

fn complete_task(root: &Path, task_id: &str) -> Result<()> {
    update_task_status(root, task_id, TaskStatus::Complete)?;
    set_task_note_state(root, task_id, "complete")
}

fn mark_task_crashed(root: &Path, task_id: &str, reason: &str) -> Result<()> {
    update_task_status(root, task_id, TaskStatus::Crashed)?;
    set_task_note_state(root, task_id, "crashed")?;
    add_note(root, task_id, &format!("Agent crashed: {reason}"))
}

fn ensure_task_note(root: &Path, task_id: &str, title: &str, state: &str) -> Result<()> {
    let notes_dir = root.join("notes");
    fs::create_dir_all(&notes_dir).context("failed to create notes directory")?;
    let path = notes_dir.join(format!("{task_id}.md"));
    if !path.exists() {
        let body = format!("---\nstate: {state}\n---\n# Task: {title}\n## Tools\n\n## Notes\n");
        fs::write(path, body).context("failed to write task note")?;
    }
    Ok(())
}

fn set_task_note_state(root: &Path, task_id: &str, state: &str) -> Result<()> {
    let path = root.join("notes").join(format!("{task_id}.md"));
    let content = fs::read_to_string(&path).context("failed to read task note")?;
    let mut lines: Vec<String> = content.lines().map(ToString::to_string).collect();
    for line in &mut lines {
        if line.starts_with("state:") {
            *line = format!("state: {state}");
        }
    }
    fs::write(path, lines.join("\n") + "\n").context("failed to write task note state")
}

fn add_note(root: &Path, task_id: &str, note: &str) -> Result<()> {
    let path = root.join("notes").join(format!("{task_id}.md"));
    let mut content = fs::read_to_string(&path).context("failed to read task note")?;
    content.push_str(&format!("- {note}\n"));
    fs::write(path, content).context("failed to append task note")
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
    let mut content = fs::read_to_string(&path).context("failed to read task note")?;
    let block = format!(
        "\n### {tool}\n- stdin:\n```\n{stdin}\n```\n- stdout:\n```\n{stdout}\n```\n- stderr:\n```\n{stderr}\n```\n"
    );
    content.push_str(&block);
    fs::write(path, content).context("failed to append tool record")
}

pub fn ensure_layout(root: &Path) -> Result<()> {
    write_if_missing(
        &root.join("susfile"),
        "{\n  \"api\": \"openai\",\n  \"model\": \"gpt-4.1\",\n  \"max_agents_per_time\": 2,\n  \"tools\": {\n    \"nmap\": {\n      \"ips\": [\"127.0.0.1\"]\n    }\n  }\n}\n",
    )?;
    write_if_missing(&root.join("swarm.md"), "# Swarm Status\n\n")?;
    fs::create_dir_all(root.join("notes")).context("failed to create notes directory")?;
    Ok(())
}

fn write_if_missing(path: &Path, content: &str) -> Result<()> {
    if !path.exists() {
        fs::write(path, content)
            .with_context(|| format!("failed to write file {}", path.display()))?;
    }
    Ok(())
}
