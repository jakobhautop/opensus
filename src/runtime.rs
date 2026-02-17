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
const STRATEGIST_AGENT_PROMPT: &str = include_str!("../prompts/strategist_agent.md");
const ANALYST_AGENT_PROMPT: &str = include_str!("../prompts/analyst_agent.md");
const REPORT_AGENT_PROMPT: &str = include_str!("../prompts/report_agent.md");
const HEARTBEAT_PROMPT: &str = include_str!("../prompts/heartbeat.md");

fn log_event(message: impl AsRef<str>) {
    println!("[opensus] {}", message.as_ref());
}

fn map_spawn_role_to_agent(role: &str) -> Result<&'static str> {
    match role {
        "analyst" => Ok("analyst_agent"),
        "strategist" => Ok("strategist_agent"),
        "reporter" => Ok("report_agent"),
        _ => bail!("spawn_agent.name must be one of: analyst, strategist, reporter"),
    }
}

fn embedded_prompt(agent_name: &str) -> Result<&'static str> {
    match agent_name {
        "main_agent" => Ok(MAIN_AGENT_PROMPT),
        "strategist_agent" => Ok(STRATEGIST_AGENT_PROMPT),
        "analyst_agent" => Ok(ANALYST_AGENT_PROMPT),
        "report_agent" => Ok(REPORT_AGENT_PROMPT),
        _ => bail!("unknown agent: {agent_name}"),
    }
}

fn role_custom_prompt_path(cfg: &Susfile, agent_name: &str) -> Option<String> {
    let agents = cfg.agents.as_ref()?;
    match agent_name {
        "analyst_agent" => agents.analyst.as_ref().map(|c| c.prompt.clone()),
        "strategist_agent" => agents.strategist.as_ref().map(|c| c.prompt.clone()),
        "report_agent" => agents.reporter.as_ref().map(|c| c.prompt.clone()),
        _ => None,
    }
}

fn render_agent_prompt(cfg: &Susfile, root: &Path, agent_name: &str) -> Result<String> {
    let base = embedded_prompt(agent_name)?;
    let custom_prompt = if let Some(path) = role_custom_prompt_path(cfg, agent_name) {
        let prompt_path = root.join(path);
        fs::read_to_string(&prompt_path).with_context(|| {
            format!(
                "failed to read custom prompt file {}",
                prompt_path.display()
            )
        })?
    } else {
        String::new()
    };

    Ok(base.replace("{{USER_INPUT}}", &custom_prompt))
}

use crate::{
    chat::{create_chat_completion, tools_for_agent},
    config::{default_susfile, load_susfile, Susfile},
    cve,
    plan::{parse_tasks, read_plan, update_task_status, write_plan, TaskStatus},
    tools::run_cli_tool,
};

#[derive(Clone)]
struct RuntimeCtx {
    root: Arc<PathBuf>,
    cfg: Susfile,
    api_key: Arc<String>,
    client: Client,
    active_analysts: Arc<AtomicUsize>,
    handles: Arc<std::sync::Mutex<Vec<JoinHandle<Result<()>>>>>,
}

pub fn handle_init(root: &Path) -> Result<()> {
    log_event("Starting opensus init");
    let cfg = default_susfile();
    write_if_missing(
        &root.join("susfile"),
        &(serde_json::to_string_pretty(&cfg)? + "\n"),
    )?;

    let loaded = load_susfile(root)?;
    if loaded.api.eq_ignore_ascii_case("openai") && std::env::var("OPENAI_API_KEY").is_err() {
        bail!("OPENAI_API_KEY is required when susfile.api=openai");
    }

    if let Err(err) = cve::ensure_local_db() {
        log_event(format!(
            "CVE database not installed yet ({}). Run `opensus cvedb install` to enable CVE search.",
            err
        ));
    }

    fs::create_dir_all(root.join("notes")).context("failed to create notes/")?;
    log_event("Ensured notes/ exists");
    fs::create_dir_all(root.join("tool_data")).context("failed to create tool_data/")?;
    log_event("Ensured tool_data/ exists");
    write_if_missing(&root.join("plan.md"), "")?;
    log_event("Ensured plan.md exists");
    write_if_missing(
        &root.join("brief.md"),
        "# Brief\n\nDescribe assignment scope and goals for agents.\n",
    )?;
    log_event("Ensured brief.md exists");

    Ok(())
}

pub fn handle_reset(root: &Path) -> Result<()> {
    log_event("Starting opensus reset");
    handle_init(root)?;

    let notes_path = root.join("notes");
    if notes_path.exists() {
        fs::remove_dir_all(&notes_path).context("failed to remove notes/")?;
    }

    fs::create_dir_all(&notes_path).context("failed to recreate notes/")?;
    log_event("Reset notes/ directory");

    let tool_data_path = root.join("tool_data");
    if tool_data_path.exists() {
        fs::remove_dir_all(&tool_data_path).context("failed to remove tool_data/")?;
    }

    fs::create_dir_all(&tool_data_path).context("failed to recreate tool_data/")?;
    log_event("Reset tool_data/ directory");
    fs::write(root.join("plan.md"), "").context("failed to reset plan.md")?;
    log_event("Plan updated (plan.md reset)");

    Ok(())
}

pub async fn handle_go(root: &Path) -> Result<()> {
    log_event("Starting opensus go");
    handle_init(root)?;
    let cfg = load_susfile(root)?;
    let api_key = std::env::var("OPENAI_API_KEY").context("missing OPENAI_API_KEY")?;

    let ctx = RuntimeCtx {
        root: Arc::new(root.to_path_buf()),
        cfg,
        api_key: Arc::new(api_key),
        client: Client::new(),
        active_analysts: Arc::new(AtomicUsize::new(0)),
        handles: Arc::new(std::sync::Mutex::new(Vec::new())),
    };

    log_event("Spawn main_agent");
    run_llm_agent(ctx.clone(), "main_agent", None).await?;

    // wait for spawned agents from this heartbeat
    let drained = {
        let mut handles = ctx.handles.lock().expect("handles mutex poisoned");
        std::mem::take(&mut *handles)
    };

    if !drained.is_empty() {
        log_event(format!("Waiting for {} spawned agent(s)", drained.len()));
    }

    for h in drained {
        match h.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => log_event(format!("spawned agent error: {err}")),
            Err(err) => log_event(format!("spawned task join error: {err}")),
        }
    }

    log_event("opensus go heartbeat complete");

    Ok(())
}

async fn run_llm_agent(ctx: RuntimeCtx, agent_name: &str, task_hint: Option<String>) -> Result<()> {
    let task_label = task_hint.clone();
    if let Some(task_id) = task_label.as_deref() {
        log_event(format!("{agent_name} started task {task_id}"));
    } else {
        log_event(format!("{agent_name} started"));
    }

    let system_prompt =
        build_system_prompt(&ctx.cfg, &ctx.root, agent_name, task_label.as_deref())?;
    if matches!(
        agent_name,
        "main_agent" | "analyst_agent" | "strategist_agent"
    ) {
        log_event(format!("System prompt for {agent_name}:\n{system_prompt}"));
    }
    let tools = tools_for_agent(agent_name, &ctx.cfg);

    let brief = fs::read_to_string(ctx.root.join("brief.md")).unwrap_or_default();
    let user_task = task_hint.unwrap_or_else(|| format!("{}{}", HEARTBEAT_PROMPT, brief));

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

            log_event(format!("{agent_name} called tool {name}"));
            let tool_result = execute_tool_call(ctx.clone(), agent_name, name, args.clone());
            let content = match tool_result {
                Ok(v) => {
                    log_event(format!("{agent_name} called tool {name} .. COMPLETE"));
                    v
                }
                Err(err) => {
                    log_event(format!("{agent_name} called tool {name} .. ERROR: {err}"));
                    format!("tool error: {err}")
                }
            };

            if agent_name == "analyst_agent" {
                if let Some(task_id) = task_label.as_deref() {
                    if let Err(err) = append_tool_data(&ctx.root, task_id, name, &args, &content) {
                        log_event(format!("failed to write tool_data for {task_id}: {err}"));
                    }
                }
            }

            messages.push(json!({
                "role": "tool",
                "tool_call_id": id,
                "content": content
            }));
        }
    }

    if let Some(task_id) = task_label {
        log_event(format!("{agent_name} finished task {task_id}"));
    } else {
        log_event(format!("{agent_name} finished"));
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
            log_event("Plan updated".to_string());
            Ok("ok".to_string())
        }
        "read_analyst_count" => Ok(ctx.active_analysts.load(Ordering::SeqCst).to_string()),
        "read_tool_data" => Ok(read_tool_data(&ctx.root)?),
        "spawn_agent" => {
            if caller_agent != "main_agent" {
                bail!("spawn_agent only allowed for main_agent");
            }
            let role = args["name"].as_str().context("spawn_agent requires name")?;
            let agent = map_spawn_role_to_agent(role)?;
            let task_id = args
                .get("task_id")
                .and_then(Value::as_str)
                .map(ToString::to_string);

            if agent == "analyst_agent"
                && ctx.active_analysts.load(Ordering::SeqCst) >= ctx.cfg.max_agents_per_time
            {
                log_event("analyst capacity reached".to_string());
                return Ok("analyst capacity reached".to_string());
            }

            if agent == "analyst_agent" {
                if task_id.is_none() {
                    bail!("spawn_agent with name=analyst requires task_id");
                }
                ctx.active_analysts.fetch_add(1, Ordering::SeqCst);
            }

            let ctx_clone = ctx.clone();
            let agent_name = agent.to_string();
            if let Some(id) = task_id.as_deref() {
                log_event(format!("Spawn {agent} for task {id}"));
            } else {
                log_event(format!("Spawn {agent}"));
            }
            let handle = tokio::spawn(async move {
                let result = run_llm_agent(ctx_clone.clone(), &agent_name, task_id).await;
                if agent_name == "analyst_agent" {
                    ctx_clone.active_analysts.fetch_sub(1, Ordering::SeqCst);
                }
                result
            });
            ctx.handles
                .lock()
                .expect("handles mutex poisoned")
                .push(handle);
            Ok(format!("spawned {role}"))
        }
        "claim_task" => {
            let id = args["id"].as_str().context("claim_task requires id")?;
            let plan = read_plan(&ctx.root)?;
            let task = parse_tasks(&plan)
                .into_iter()
                .find(|t| t.id == id)
                .context("task not found")?;
            claim_task(&ctx.root, &task.id, &task.title)?;
            log_event(format!("{caller_agent} claimed task {id}"));
            Ok("claimed".to_string())
        }
        "complete_task" => {
            let id = args["id"].as_str().context("complete_task requires id")?;
            complete_task(&ctx.root, id)?;
            log_event(format!("{caller_agent} completed task {id}"));
            Ok("completed".to_string())
        }
        "add_note" => {
            let id = args["id"].as_str().context("add_note requires id")?;
            let note = args["note"].as_str().context("add_note requires note")?;
            add_note(&ctx.root, id, note)?;
            Ok("noted".to_string())
        }
        "cve_search" => {
            let query = args["query"]
                .as_str()
                .context("cve_search requires query")?;
            let rows = cve::search_local_db(query)?;
            Ok(serde_json::to_string(&rows).context("failed to serialize cve_search rows")?)
        }
        "cve_show" => {
            let id = args["id"].as_str().context("cve_show requires id")?;
            let row = cve::show_local_db(id)?;
            Ok(serde_json::to_string(&row).context("failed to serialize cve_show row")?)
        }
        _ => execute_configured_cli_tool(&ctx.cfg, name, &args),
    }
}

fn build_system_prompt(
    cfg: &Susfile,
    root: &Path,
    agent_name: &str,
    task_hint: Option<&str>,
) -> Result<String> {
    let base = render_agent_prompt(cfg, root, agent_name)?;
    let base = if agent_name == "analyst_agent" {
        base.replace("{{TASK}}", task_hint.unwrap_or_default())
    } else {
        base.replace("{{TASK}}", "")
    };

    let mut tools_list = String::new();
    for tool in &cfg.tools.cli {
        let arg_list = tool
            .args
            .iter()
            .map(|arg| format!("{}: {}", arg.name, arg.description))
            .collect::<Vec<_>>()
            .join(", ");
        tools_list.push_str(&format!(
            "- {}: {} (command: {}; args: {})\n",
            tool.name, tool.description, tool.command, arg_list
        ));
    }

    if agent_name == "strategist_agent" {
        return Ok(format!(
            "{base}\n\nAvailable analyst CLI tools from susfile:\n{tools_list}\nUse read_tool_data() to correlate analyst tool outputs in tool_data/ with notes/ when updating attack_model.md and plan.md."
        ));
    }

    if agent_name == "analyst_agent" {
        return Ok(format!(
            "{base}\n\nAvailable analyst CLI tools from susfile:\n{tools_list}\nAll tool call outputs are automatically written to tool_data/Dxxxx.md for your task. You do not need to copy raw tool output into notes."
        ));
    }

    Ok(base.to_string())
}

fn execute_configured_cli_tool(cfg: &Susfile, name: &str, args: &Value) -> Result<String> {
    let cli_tool = cfg
        .tools
        .cli
        .iter()
        .find(|tool| tool.name == name)
        .with_context(|| format!("unknown tool: {name}"))?;

    let mut mapped_args = std::collections::HashMap::new();
    for arg in &cli_tool.args {
        let value = args[arg.name.as_str()]
            .as_str()
            .with_context(|| format!("{} requires {}", name, arg.name))?;
        mapped_args.insert(arg.name.clone(), value.to_string());
    }

    let (stdin, stdout, stderr) = run_cli_tool(cli_tool, &mapped_args)?;
    Ok(format!(
        "stdin:\n{stdin}\nstdout:\n{stdout}\nstderr:\n{stderr}"
    ))
}

fn claim_task(root: &Path, task_id: &str, title: &str) -> Result<()> {
    update_task_status(root, task_id, TaskStatus::Pending)?;
    log_event(format!("Plan updated (task {task_id} -> pending)"));
    ensure_task_note(root, task_id, title, "open")
}

fn complete_task(root: &Path, task_id: &str) -> Result<()> {
    update_task_status(root, task_id, TaskStatus::Complete)?;
    log_event(format!("Plan updated (task {task_id} -> complete)"));
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
        log_event(format!("Task created at notes/{task_id}.md"));
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
    fs::write(path, replaced).context("failed to write note")?;
    log_event(format!("Task {task_id} marked {state}"));
    Ok(())
}

fn add_note(root: &Path, task_id: &str, note: &str) -> Result<()> {
    let path = root.join("notes").join(format!("{task_id}.md"));
    let mut content = fs::read_to_string(&path).context("failed to read note")?;
    content.push_str(&format!("- {note}\n"));
    fs::write(path, content).context("failed to append note")?;
    log_event(format!("Note appended to task {task_id}"));
    Ok(())
}

fn task_data_path(root: &Path, task_id: &str) -> PathBuf {
    let data_id = if let Some(rest) = task_id.strip_prefix('T') {
        format!("D{rest}")
    } else {
        format!("D{task_id}")
    };
    root.join("tool_data").join(format!("{data_id}.md"))
}

fn append_tool_data(
    root: &Path,
    task_id: &str,
    tool_name: &str,
    args: &Value,
    output: &str,
) -> Result<()> {
    fs::create_dir_all(root.join("tool_data")).context("failed to create tool_data/")?;
    let path = task_data_path(root, task_id);
    let mut content = if path.exists() {
        fs::read_to_string(&path).context("failed to read tool data")?
    } else {
        format!(
            "# Tool data for {task_id}
"
        )
    };

    content.push_str(&format!(
        "
## Tool: {tool_name}
args: {}

```
{}
```
",
        serde_json::to_string(args).unwrap_or_else(|_| "{}".to_string()),
        output
    ));

    fs::write(path, content).context("failed to write tool data")?;
    Ok(())
}

fn read_tool_data(root: &Path) -> Result<String> {
    let dir = root.join("tool_data");
    if !dir.exists() {
        return Ok(String::new());
    }

    let mut entries = fs::read_dir(&dir)
        .context("failed to read tool_data/")?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to list tool_data/")?;
    entries.sort_by_key(|entry| entry.file_name());

    let mut combined = String::new();
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("md") {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let body = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        combined.push_str(&format!(
            "
# {file_name}
{body}
"
        ));
    }

    Ok(combined)
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
    #[test]
    fn reset_keeps_brief_and_susfile_and_clears_runtime_artifacts() {
        unsafe {
            std::env::set_var("OPENAI_API_KEY", "test-key");
        }

        let tmp = tempfile::tempdir().expect("tmp");
        handle_init(tmp.path()).expect("init");

        fs::write(tmp.path().join("brief.md"), "custom brief").expect("brief");
        fs::write(
            tmp.path().join("plan.md"),
            "- [ ] T001 - Keep this?
",
        )
        .expect("plan");
        fs::write(tmp.path().join("notes").join("T001.md"), "note").expect("note");
        fs::create_dir_all(tmp.path().join("tool_data")).expect("tool_data");
        fs::write(tmp.path().join("tool_data").join("D001.md"), "tool output")
            .expect("tool output");

        handle_reset(tmp.path()).expect("reset");

        assert_eq!(
            fs::read_to_string(tmp.path().join("brief.md")).expect("read brief"),
            "custom brief"
        );
        assert!(tmp.path().join("susfile").exists());
        assert_eq!(
            fs::read_to_string(tmp.path().join("plan.md")).expect("read plan"),
            ""
        );
        assert!(tmp.path().join("notes").exists());
        assert!(fs::read_dir(tmp.path().join("notes"))
            .expect("read notes dir")
            .next()
            .is_none());
        assert!(tmp.path().join("tool_data").exists());
        assert!(fs::read_dir(tmp.path().join("tool_data"))
            .expect("read tool_data dir")
            .next()
            .is_none());
    }

    #[test]
    fn build_system_prompt_injects_custom_user_prompt() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::write(
            tmp.path().join("report-extra.md"),
            "Focus only on web targets.",
        )
        .expect("prompt");

        let mut cfg = default_susfile();
        cfg.agents = Some(crate::config::AgentsConfig {
            analyst: None,
            strategist: None,
            reporter: Some(crate::config::AgentPromptConfig {
                prompt: "report-extra.md".to_string(),
            }),
        });

        let rendered = build_system_prompt(&cfg, tmp.path(), "report_agent", None)
            .expect("system prompt should render");

        assert!(rendered.contains("<User input>"));
        assert!(rendered.contains("Focus only on web targets."));
        assert!(rendered.contains("</User input>"));
        assert!(!rendered.contains("{{USER_INPUT}}"));
    }
}
