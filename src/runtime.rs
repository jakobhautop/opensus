use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde_json::{json, Value};
use tokio::task::JoinHandle;

const MAIN_AGENT_PROMPT: &str = include_str!("../prompts/main_agent.md");
const PLANNING_AGENT_PROMPT: &str = include_str!("../prompts/planning_agent.md");
const WORKER_AGENT_PROMPT: &str = include_str!("../prompts/worker_agent.md");
const REPORT_AGENT_PROMPT: &str = include_str!("../prompts/report_agent.md");

fn embedded_prompt(agent_name: &str) -> Result<&'static str> {
    match agent_name {
        "main_agent" => Ok(MAIN_AGENT_PROMPT),
        "planning_agent" => Ok(PLANNING_AGENT_PROMPT),
        "worker_agent" => Ok(WORKER_AGENT_PROMPT),
        "report_agent" => Ok(REPORT_AGENT_PROMPT),
        _ => bail!("unknown agent: {agent_name}"),
    }
}

use crate::{
    chat::{create_chat_completion, tools_for_agent},
    config::{default_susfile, load_susfile, Susfile},
    plan::{parse_tasks, read_plan, update_task_status, write_plan, TaskStatus},
    tools::{nmap_scan_aggressive, nmap_verify},
};

#[derive(Clone)]
struct RuntimeCtx {
    root: Arc<PathBuf>,
    cfg: Susfile,
    api_key: Arc<String>,
    client: Client,
    active_workers: Arc<AtomicUsize>,
    handles: Arc<std::sync::Mutex<Vec<JoinHandle<Result<()>>>>>,
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
    write_if_missing(
        &root.join("brief.md"),
        "# Brief\n\nDescribe assignment scope and goals for agents.\n",
    )?;

    Ok(())
}

pub async fn handle_go(root: &Path) -> Result<()> {
    handle_init(root)?;
    let cfg = load_susfile(root)?;
    let api_key = std::env::var("OPENAI_API_KEY").context("missing OPENAI_API_KEY")?;

    let ctx = RuntimeCtx {
        root: Arc::new(root.to_path_buf()),
        cfg,
        api_key: Arc::new(api_key),
        client: Client::new(),
        active_workers: Arc::new(AtomicUsize::new(0)),
        handles: Arc::new(std::sync::Mutex::new(Vec::new())),
    };

    run_llm_agent(ctx.clone(), "main_agent", None).await?;

    // wait for spawned agents from this heartbeat
    let drained = {
        let mut handles = ctx.handles.lock().expect("handles mutex poisoned");
        std::mem::take(&mut *handles)
    };

    for h in drained {
        match h.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => eprintln!("spawned agent error: {err}"),
            Err(err) => eprintln!("spawned task join error: {err}"),
        }
    }

    Ok(())
}

async fn run_llm_agent(ctx: RuntimeCtx, agent_name: &str, task_hint: Option<String>) -> Result<()> {
    let system_prompt = embedded_prompt(agent_name)?;
    let tools = tools_for_agent(agent_name);

    let brief = fs::read_to_string(ctx.root.join("brief.md")).unwrap_or_default();
    let user_task = task_hint.unwrap_or_else(|| {
        format!(
            "Use brief.md + plan.md to progress the mission.\n\nBrief:\n{}",
            brief
        )
    });

    let mut messages = vec![
        json!({"role":"system","content":system_prompt}),
        json!({"role":"user","content":user_task}),
    ];

    for _ in 0..12 {
        let response =
            create_chat_completion(&ctx.client, &ctx.api_key, &ctx.cfg.model, &messages, &tools)
                .await?;

        let message = response["choices"][0]["message"].clone();
        let tool_calls = message["tool_calls"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        messages.push(message.clone());

        if tool_calls.is_empty() {
            break;
        }

        for tc in tool_calls {
            let id = tc["id"].as_str().unwrap_or_default();
            let name = tc["function"]["name"].as_str().unwrap_or_default();
            let args_raw = tc["function"]["arguments"].as_str().unwrap_or("{}");
            let args: Value = serde_json::from_str(args_raw).unwrap_or_else(|_| json!({}));

            let tool_result = execute_tool_call(ctx.clone(), agent_name, name, args);
            let content = match tool_result {
                Ok(v) => v,
                Err(err) => format!("tool error: {err}"),
            };

            messages.push(json!({
                "role": "tool",
                "tool_call_id": id,
                "content": content
            }));
        }
    }

    Ok(())
}

fn execute_tool_call(
    ctx: RuntimeCtx,
    caller_agent: &str,
    name: &str,
    args: Value,
) -> Result<String> {
    match name {
        "read_plan" => Ok(read_plan(&ctx.root)?),
        "write_plan" => {
            let markdown = args["markdown"]
                .as_str()
                .context("write_plan requires markdown")?;
            write_plan(&ctx.root, markdown)?;
            Ok("ok".to_string())
        }
        "read_worker_count" => Ok(ctx.active_workers.load(Ordering::SeqCst).to_string()),
        "spawn_agent" => {
            if caller_agent != "main_agent" {
                bail!("spawn_agent only allowed for main_agent");
            }
            let agent = args["name"].as_str().context("spawn_agent requires name")?;
            let task_id = args
                .get("task_id")
                .and_then(Value::as_str)
                .map(ToString::to_string);

            if agent == "worker_agent"
                && ctx.active_workers.load(Ordering::SeqCst) >= ctx.cfg.max_agents_per_time
            {
                return Ok("worker capacity reached".to_string());
            }

            if agent == "worker_agent" {
                ctx.active_workers.fetch_add(1, Ordering::SeqCst);
            }

            let ctx_clone = ctx.clone();
            let agent_name = agent.to_string();
            let handle = tokio::spawn(async move {
                let result = run_llm_agent(ctx_clone.clone(), &agent_name, task_id).await;
                if agent_name == "worker_agent" {
                    ctx_clone.active_workers.fetch_sub(1, Ordering::SeqCst);
                }
                result
            });
            ctx.handles
                .lock()
                .expect("handles mutex poisoned")
                .push(handle);
            Ok(format!("spawned {agent}"))
        }
        "claim_task" => {
            let id = args["id"].as_str().context("claim_task requires id")?;
            let plan = read_plan(&ctx.root)?;
            let task = parse_tasks(&plan)
                .into_iter()
                .find(|t| t.id == id)
                .context("task not found")?;
            claim_task(&ctx.root, &task.id, &task.title)?;
            Ok("claimed".to_string())
        }
        "complete_task" => {
            let id = args["id"].as_str().context("complete_task requires id")?;
            complete_task(&ctx.root, id)?;
            Ok("completed".to_string())
        }
        "add_note" => {
            let id = args["id"].as_str().context("add_note requires id")?;
            let note = args["note"].as_str().context("add_note requires note")?;
            add_note(&ctx.root, id, note)?;
            Ok("noted".to_string())
        }
        "nmap_verify" => {
            let (stdin, stdout, stderr) = nmap_verify()?;
            Ok(format!(
                "stdin:\n{stdin}\nstdout:\n{stdout}\nstderr:\n{stderr}"
            ))
        }
        "nmap_aggressive_scan" => {
            let ip = args["ip"]
                .as_str()
                .context("nmap_aggressive_scan requires ip")?;
            if !ctx.cfg.tools.nmap.ips.iter().any(|allowed| allowed == ip) {
                bail!("ip not allowlisted in susfile.tools.nmap.ips");
            }
            let (stdin, stdout, stderr) = nmap_scan_aggressive(ip)?;
            Ok(format!(
                "stdin:\n{stdin}\nstdout:\n{stdout}\nstderr:\n{stderr}"
            ))
        }
        _ => bail!("unknown tool: {name}"),
    }
}

fn claim_task(root: &Path, task_id: &str, title: &str) -> Result<()> {
    update_task_status(root, task_id, TaskStatus::Pending)?;
    ensure_task_note(root, task_id, title, "open")
}

fn complete_task(root: &Path, task_id: &str) -> Result<()> {
    update_task_status(root, task_id, TaskStatus::Complete)?;
    set_note_state(root, task_id, "complete")
}

#[cfg_attr(not(test), allow(dead_code))]
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
    fn crash_marking_updates_plan() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("notes")).expect("notes");
        write_plan(
            tmp.path(),
            "# Plan\n\nplanning_status: complete\n\n- [ ] T001 - Aggressive scan 10.0.0.1\n",
        )
        .expect("plan");
        ensure_task_note(tmp.path(), "T001", "Aggressive scan 10.0.0.1", "open").expect("note");
        mark_task_crashed(tmp.path(), "T001", "boom").expect("crash");
        let p = read_plan(tmp.path()).expect("read plan");
        assert!(p.contains("- [!] T001"));
    }
}
