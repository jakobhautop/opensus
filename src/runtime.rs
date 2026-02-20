use std::{
    collections::HashSet,
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

const DISPATCH_AGENT_PROMPT: &str = include_str!("../prompts/dispatch_agent.md");
const STRATEGIST_AGENT_PROMPT: &str = include_str!("../prompts/strategist_agent.md");
const ANALYST_AGENT_PROMPT: &str = include_str!("../prompts/analyst_agent.md");
const REPORT_AGENT_PROMPT: &str = include_str!("../prompts/report_agent.md");
const HEARTBEAT_PROMPT: &str = include_str!("../prompts/heartbeat.md");
const HEARTBEAT_EKG: &str =
    r"____/‾\____/\/\_____/‾‾\____/‾\____/\/\/\_____/‾‾\____________________";

fn log_event(message: impl AsRef<str>) {
    println!("[opensus] {}", message.as_ref());
}

fn heartbeat_capacity_status(ctx: &RuntimeCtx) -> String {
    let analysts = ctx.active_analysts.load(Ordering::SeqCst);
    let strategists = ctx.active_strategists.load(Ordering::SeqCst);

    let mut lines = Vec::new();
    if analysts >= ctx.cfg.max_agents_per_time {
        lines.push("Max number of analysts are running! Do NOT spawn new analyst.".to_string());
    }
    if strategists >= ctx.cfg.max_strategists_per_time {
        lines.push(
            "Max number of strategist are running! Do NOT spawn a new strategist.".to_string(),
        );
    }

    if lines.is_empty() {
        "Capacity status: analyst and strategist slots are available.".to_string()
    } else {
        lines.join(
            "
",
        )
    }
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
        "dispatch_agent" => Ok(DISPATCH_AGENT_PROMPT),
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

fn render_agent_prompt(
    cfg: &Susfile,
    root: &Path,
    agent_name: &str,
    capacity_status: &str,
) -> Result<String> {
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

    let susfile_json = serde_json::to_string_pretty(cfg).context("failed to render susfile")?;

    Ok(base
        .replace("{{USER_INPUT}}", &custom_prompt)
        .replace(
            "{{HEARTBEAT_MESSAGE}}",
            &HEARTBEAT_PROMPT.replace("{{CAPACITY_STATUS}}", capacity_status),
        )
        .replace("{{SUSFILE}}", &susfile_json))
}

use crate::{
    chat::{create_chat_completion, tools_for_agent},
    config::{default_susfile, load_susfile, Susfile},
    cve,
    plan::{
        append_review_finding, append_tool_request, mark_review_findings_read, parse_tasks,
        read_plan, update_task_status, write_plan, TaskStatus,
    },
    tools::run_cli_tool,
};

#[derive(Clone)]
struct RuntimeCtx {
    root: Arc<PathBuf>,
    cfg: Susfile,
    api_key: Arc<String>,
    client: Client,
    active_analysts: Arc<AtomicUsize>,
    active_strategists: Arc<AtomicUsize>,
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
    write_if_missing(&root.join("attack_model.md"), "")?;
    log_event("Ensured attack_model.md exists");

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

pub async fn handle_go(root: &Path, fullauto: bool) -> Result<()> {
    log_event("Starting opensus go");
    handle_init(root)?;

    loop {
        run_heartbeat(root).await?;
        if !fullauto {
            break;
        }
    }

    Ok(())
}

async fn run_heartbeat(root: &Path) -> Result<()> {
    println!("{HEARTBEAT_EKG}");
    let cfg = load_susfile(root)?;
    let api_key = std::env::var("OPENAI_API_KEY").context("missing OPENAI_API_KEY")?;

    let ctx = RuntimeCtx {
        root: Arc::new(root.to_path_buf()),
        cfg,
        api_key: Arc::new(api_key),
        client: Client::new(),
        active_analysts: Arc::new(AtomicUsize::new(0)),
        active_strategists: Arc::new(AtomicUsize::new(0)),
        handles: Arc::new(std::sync::Mutex::new(Vec::new())),
    };

    let analysts_at_limit =
        ctx.active_analysts.load(Ordering::SeqCst) >= ctx.cfg.max_agents_per_time;
    let strategists_at_limit =
        ctx.active_strategists.load(Ordering::SeqCst) >= ctx.cfg.max_strategists_per_time;

    if analysts_at_limit && strategists_at_limit {
        log_event("Heartbeat skipped: analyst and strategist capacities are both reached");
        return Ok(());
    }

    log_event("Spawn dispatch_agent");
    run_llm_agent(ctx.clone(), "dispatch_agent", None).await?;

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

    let system_prompt = build_system_prompt(
        &ctx.cfg,
        &ctx.root,
        agent_name,
        task_label.as_deref(),
        &heartbeat_capacity_status(&ctx),
    )?;
    let cve_tools_enabled = cve::ensure_local_db().is_ok();
    let tools = tools_for_agent(agent_name, &ctx.cfg, cve_tools_enabled);

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

            log_event(format!("{agent_name} called tool {name} args={args_raw}"));
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
    enforce_allowed_ips(&ctx.cfg, name, &args)?;

    match name {
        "read_plan" => Ok(read_plan(&ctx.root)?),
        "read_attack_plan" => Ok(read_plan(&ctx.root)?),
        "update_plan" | "write_plan" => {
            let markdown = args["updated_markdown"]
                .as_str()
                .or_else(|| args["markdown"].as_str())
                .context("update_plan requires updated_markdown")?;
            write_plan(&ctx.root, markdown)?;
            log_event("Plan updated".to_string());
            Ok("ok".to_string())
        }
        "read_note" => {
            let id = args["id"].as_str().context("read_note requires id")?;
            let note = fs::read_to_string(ctx.root.join("notes").join(format!("{id}.md")))
                .with_context(|| format!("failed to read notes/{id}.md"))?;
            if caller_agent == "strategist_agent" {
                let marked = mark_review_findings_read(&ctx.root, id)?;
                if marked > 0 {
                    log_event(format!(
                        "Review findings updated (task {id}: marked {marked} item(s) read)"
                    ));
                }
            }
            Ok(note)
        }
        "read_attack_model" => Ok(read_attack_model(&ctx.root)?),
        "update_attack_model" => {
            let markdown = args["updated_model"]
                .as_str()
                .context("update_attack_model requires updated_model")?;
            write_attack_model(&ctx.root, markdown)?;
            log_event("Attack model updated".to_string());
            Ok("ok".to_string())
        }
        "write_report" => {
            let markdown = args["markdown"]
                .as_str()
                .context("write_report requires markdown")?;
            write_report(&ctx.root, markdown)?;
            log_event("Report updated".to_string());
            Ok("ok".to_string())
        }
        "read_tool_data" => Ok(read_tool_data(&ctx.root)?),
        "request_tooling" => {
            let request = args["request"]
                .as_str()
                .context("request_tooling requires request")?;
            append_tool_request(&ctx.root, request)?;
            log_event("Tool request appended to plan".to_string());
            Ok("requested".to_string())
        }
        "new_analyst" => {
            let task_id = args["task_id"]
                .as_str()
                .context("new_analyst requires task_id")?
                .to_string();
            spawn_agent(&ctx, caller_agent, "analyst", Some(task_id))
        }
        "new_strategist" => spawn_agent(&ctx, caller_agent, "strategist", None),
        "new_reporter" => spawn_agent(&ctx, caller_agent, "reporter", None),
        "spawn_agent" => {
            let role = args["name"].as_str().context("spawn_agent requires name")?;
            let task_id = args
                .get("task_id")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            spawn_agent(&ctx, caller_agent, role, task_id)
        }
        "claim_task" => {
            let id = args["id"].as_str().context("claim_task requires id")?;
            let plan = read_plan(&ctx.root)?;
            let task = parse_tasks(&plan)
                .into_iter()
                .find(|t| t.id == id)
                .with_context(|| format!("task `{id}` not found in plan.md"))?;
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

fn enforce_allowed_ips(cfg: &Susfile, tool_name: &str, args: &Value) -> Result<()> {
    let allowed_hosts: HashSet<String> = cfg
        .allowed_hosts
        .iter()
        .map(|host| {
            host.parse::<std::net::Ipv4Addr>()
                .map(|parsed| parsed.to_string())
                .unwrap_or_else(|_| host.to_lowercase())
        })
        .collect();

    let mut disallowed: Vec<String> = extract_ipv4s_from_json(args)
        .into_iter()
        .filter(|ip| !allowed_hosts.contains(ip))
        .collect();

    let hostnames = extract_url_hosts_from_json(args);
    if !hostnames.is_empty() {
        let mut blocked_hosts = Vec::new();
        for host in hostnames {
            if let Ok(parsed) = host.parse::<std::net::Ipv4Addr>() {
                if !allowed_hosts.contains(&parsed.to_string()) {
                    disallowed.push(parsed.to_string());
                }
                continue;
            }

            if host.eq_ignore_ascii_case("localhost") {
                if !(allowed_hosts.contains("127.0.0.1") || allowed_hosts.contains("localhost")) {
                    disallowed.push("127.0.0.1".to_string());
                }
                continue;
            }

            if allowed_hosts.contains(&host.to_lowercase()) {
                continue;
            }

            blocked_hosts.push(host);
        }

        blocked_hosts.sort();
        blocked_hosts.dedup();
        if !blocked_hosts.is_empty() {
            bail!(
                "tool call `{tool_name}` blocked: hostname(s) [{}] are not allowed. Use entries from susfile.allowed_hosts",
                blocked_hosts.join(", ")
            );
        }
    }

    disallowed.sort();
    disallowed.dedup();

    if disallowed.is_empty() {
        return Ok(());
    }

    bail!(
        "tool call `{tool_name}` blocked: disallowed IP(s) [{}]. Allowed hosts come from susfile.allowed_hosts",
        disallowed.join(", ")
    );
}

fn extract_ipv4s_from_json(value: &Value) -> Vec<String> {
    let mut out = Vec::new();

    match value {
        Value::String(s) => out.extend(extract_ipv4s_from_text(s)),
        Value::Array(items) => {
            for item in items {
                out.extend(extract_ipv4s_from_json(item));
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                out.extend(extract_ipv4s_from_json(v));
            }
        }
        _ => {}
    }

    out
}

fn extract_ipv4s_from_text(text: &str) -> Vec<String> {
    let mut ips = Vec::new();
    let mut token = String::new();

    for ch in text.chars().chain(std::iter::once(' ')) {
        if ch.is_ascii_digit() || ch == '.' {
            token.push(ch);
            continue;
        }

        if token.matches('.').count() == 3 {
            if let Ok(parsed) = token.parse::<std::net::Ipv4Addr>() {
                ips.push(parsed.to_string());
            }
        }

        token.clear();
    }

    ips
}

fn extract_url_hosts_from_json(value: &Value) -> Vec<String> {
    let mut out = Vec::new();

    match value {
        Value::String(s) => out.extend(extract_url_hosts_from_text(s)),
        Value::Array(items) => {
            for item in items {
                out.extend(extract_url_hosts_from_json(item));
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                out.extend(extract_url_hosts_from_json(v));
            }
        }
        _ => {}
    }

    out
}

fn extract_url_hosts_from_text(text: &str) -> Vec<String> {
    let mut hosts = Vec::new();

    for token in text.split_whitespace() {
        let candidate = token.trim_matches(|c: char| {
            matches!(
                c,
                '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ',' | ';'
            )
        });

        let rest = if let Some(rem) = candidate.strip_prefix("http://") {
            rem
        } else if let Some(rem) = candidate.strip_prefix("https://") {
            rem
        } else {
            continue;
        };

        let host_port = rest.split(['/', '?', '#']).next().unwrap_or("").trim();

        if host_port.is_empty() {
            continue;
        }

        let host = if host_port.starts_with('[') {
            host_port
                .split(']')
                .next()
                .unwrap_or("")
                .trim_start_matches('[')
                .to_string()
        } else {
            host_port.split(':').next().unwrap_or("").to_string()
        };

        if !host.is_empty() {
            hosts.push(host);
        }
    }

    hosts
}

fn spawn_agent(
    ctx: &RuntimeCtx,
    caller_agent: &str,
    role: &str,
    task_id: Option<String>,
) -> Result<String> {
    if caller_agent != "dispatch_agent" {
        bail!("spawn_agent only allowed for dispatch_agent");
    }

    let agent = map_spawn_role_to_agent(role)?;

    if agent == "analyst_agent"
        && ctx.active_analysts.load(Ordering::SeqCst) >= ctx.cfg.max_agents_per_time
    {
        log_event("analyst capacity reached".to_string());
        return Ok("analyst capacity reached".to_string());
    }

    if agent == "strategist_agent"
        && ctx.active_strategists.load(Ordering::SeqCst) >= ctx.cfg.max_strategists_per_time
    {
        log_event("strategist capacity reached".to_string());
        return Ok("strategist capacity reached".to_string());
    }

    if agent == "analyst_agent" {
        if task_id.is_none() {
            bail!("spawn_agent with name=analyst requires task_id");
        }
        ctx.active_analysts.fetch_add(1, Ordering::SeqCst);
    }

    if agent == "strategist_agent" {
        ctx.active_strategists.fetch_add(1, Ordering::SeqCst);
    }

    let ctx_clone = ctx.clone();
    let agent_name = agent.to_string();
    let spawned_task_id = task_id.clone();
    if let Some(id) = task_id.as_deref() {
        log_event(format!("Spawn {agent} for task {id}"));
    } else {
        log_event(format!("Spawn {agent}"));
    }
    let handle = tokio::spawn(async move {
        let result = run_llm_agent(ctx_clone.clone(), &agent_name, task_id).await;
        if agent_name == "analyst_agent" {
            if let (Some(task_id), Err(err)) = (spawned_task_id.as_deref(), result.as_ref()) {
                if let Err(mark_err) = mark_task_crashed(&ctx_clone.root, task_id, &err.to_string())
                {
                    log_event(format!(
                        "failed to mark task {task_id} as crashed: {mark_err}"
                    ));
                } else {
                    log_event(format!("Task {task_id} marked crashed after analyst error"));
                }
            }
        }
        if agent_name == "analyst_agent" {
            ctx_clone.active_analysts.fetch_sub(1, Ordering::SeqCst);
        }
        if agent_name == "strategist_agent" {
            ctx_clone.active_strategists.fetch_sub(1, Ordering::SeqCst);
        }
        result
    });
    ctx.handles
        .lock()
        .expect("handles mutex poisoned")
        .push(handle);
    Ok(format!("spawned {role}"))
}

fn build_system_prompt(
    cfg: &Susfile,
    root: &Path,
    agent_name: &str,
    task_hint: Option<&str>,
    capacity_status: &str,
) -> Result<String> {
    let base = render_agent_prompt(cfg, root, agent_name, capacity_status)?;

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

    if agent_name == "analyst_agent" {
        return Ok(base
            .replace("{{TASK}}", task_hint.unwrap_or_default())
            .replace("{{ENVIRONMENT_TOOLS}}", &tools_list));
    }

    Ok(base
        .replace("{{TASK}}", "")
        .replace("{{ENVIRONMENT_TOOLS}}", ""))
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

    append_review_finding(root, &format!("{task_id} | note | {note}"))?;
    log_event(format!("Review finding appended for note {task_id}"));

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
    let compact_output = output.replace('\n', " ");
    let summary = compact_output.chars().take(160).collect::<String>();
    let truncated = if compact_output.chars().count() > 160 {
        format!("{summary}...")
    } else {
        summary
    };
    append_review_finding(
        root,
        &format!(
            "{task_id} | tool:{tool_name} | args={} | output={truncated}",
            args
        ),
    )?;
    log_event(format!(
        "Review finding appended for tool output {task_id}/{tool_name}"
    ));

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

fn read_attack_model(root: &Path) -> Result<String> {
    Ok(fs::read_to_string(root.join("attack_model.md")).unwrap_or_default())
}

fn write_attack_model(root: &Path, markdown: &str) -> Result<()> {
    fs::write(root.join("attack_model.md"), markdown).context("failed to write attack_model.md")?;
    Ok(())
}

fn write_report(root: &Path, markdown: &str) -> Result<()> {
    fs::write(root.join("report.md"), markdown).context("failed to write report.md")?;
    Ok(())
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
    fn strategist_spawn_respects_capacity_limit() {
        let mut cfg = default_susfile();
        cfg.max_strategists_per_time = 1;

        let ctx = RuntimeCtx {
            root: Arc::new(std::env::temp_dir()),
            cfg,
            api_key: Arc::new("test-key".to_string()),
            client: Client::new(),
            active_analysts: Arc::new(AtomicUsize::new(0)),
            active_strategists: Arc::new(AtomicUsize::new(1)),
            handles: Arc::new(std::sync::Mutex::new(Vec::new())),
        };

        let result = spawn_agent(&ctx, "dispatch_agent", "strategist", None)
            .expect("spawn should return capacity result");

        assert_eq!(result, "strategist capacity reached");
        assert_eq!(ctx.active_strategists.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn crash_marking_updates_plan() {
        let tmp = tempfile::tempdir().expect("tmp");
        fs::create_dir_all(tmp.path().join("notes")).expect("notes");
        write_plan(
            tmp.path(),
            "# Plan\n\nstatus: complete\n\n- [ ] T001 - Aggressive scan 10.0.0.1\n",
        )
        .expect("plan");
        ensure_task_note(tmp.path(), "T001", "Aggressive scan 10.0.0.1", "open").expect("note");
        mark_task_crashed(tmp.path(), "T001", "boom").expect("crash");
        let p = read_plan(tmp.path()).expect("read plan");
        assert!(p.contains("- [!] T001"));
    }
    #[test]
    fn blocks_tool_calls_with_disallowed_ip_arguments() {
        let mut cfg = default_susfile();
        cfg.allowed_hosts = vec!["89.167.60.165".to_string()];

        let err = enforce_allowed_ips(
            &cfg,
            "nmap_targeted_scan",
            &json!({"target": "10.10.10.5", "notes": "scan 10.10.10.5 now"}),
        )
        .expect_err("expected blocked IP");

        assert!(err
            .to_string()
            .contains("tool call `nmap_targeted_scan` blocked"));
    }

    #[test]
    fn allows_tool_calls_when_all_ips_are_approved() {
        let mut cfg = default_susfile();
        cfg.allowed_hosts = vec!["89.167.60.165".to_string()];

        enforce_allowed_ips(
            &cfg,
            "nmap_targeted_scan",
            &json!({"target": "89.167.60.165", "comment": "scan host 89.167.60.165"}),
        )
        .expect("approved IP should pass");
    }

    #[test]
    fn blocks_tool_calls_with_hostname_urls() {
        let mut cfg = default_susfile();
        cfg.allowed_hosts = vec!["89.167.60.165".to_string()];

        let err = enforce_allowed_ips(&cfg, "curl_raw", &json!({"args": "-i http://example.com/"}))
            .expect_err("expected blocked hostname");

        assert!(err.to_string().contains("hostname(s)"));
        assert!(err.to_string().contains("example.com"));
    }

    #[test]
    fn allows_tool_calls_with_allowed_hostname_url() {
        let mut cfg = default_susfile();
        cfg.allowed_hosts = vec!["example.com".to_string()];

        enforce_allowed_ips(
            &cfg,
            "curl_raw",
            &json!({"args": "-i https://example.com/"}),
        )
        .expect("allowed hostname should pass");
    }

    #[test]
    fn allows_tool_calls_with_localhost_when_loopback_allowed() {
        let mut cfg = default_susfile();
        cfg.allowed_hosts = vec!["127.0.0.1".to_string()];

        enforce_allowed_ips(
            &cfg,
            "curl_raw",
            &json!({"args": "-i http://localhost:8080/"}),
        )
        .expect("localhost should map to loopback");
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
    fn heartbeat_capacity_status_reports_limits() {
        let mut cfg = default_susfile();
        cfg.max_agents_per_time = 1;
        cfg.max_strategists_per_time = 1;

        let ctx = RuntimeCtx {
            root: Arc::new(std::env::temp_dir()),
            cfg,
            api_key: Arc::new("test-key".to_string()),
            client: Client::new(),
            active_analysts: Arc::new(AtomicUsize::new(1)),
            active_strategists: Arc::new(AtomicUsize::new(1)),
            handles: Arc::new(std::sync::Mutex::new(Vec::new())),
        };

        let status = heartbeat_capacity_status(&ctx);

        assert!(status.contains("Max number of analysts are running"));
        assert!(status.contains("Max number of strategist are running"));
    }

    #[test]
    fn build_system_prompt_injects_capacity_status_into_heartbeat_message() {
        let tmp = tempfile::tempdir().expect("tmp");
        let cfg = default_susfile();

        let rendered = build_system_prompt(
            &cfg,
            tmp.path(),
            "dispatch_agent",
            None,
            "Max number of analysts are running! Do NOT spawn new analyst.",
        )
        .expect("system prompt should render");

        assert!(rendered.contains("Max number of analysts are running! Do NOT spawn new analyst."));
        assert!(!rendered.contains("{{CAPACITY_STATUS}}"));
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

        let rendered = build_system_prompt(
            &cfg,
            tmp.path(),
            "report_agent",
            None,
            "Capacity status: analyst and strategist slots are available.",
        )
        .expect("system prompt should render");

        assert!(rendered.contains("<User input>"));
        assert!(rendered.contains("Focus only on web targets."));
        assert!(rendered.contains("</User input>"));
        assert!(!rendered.contains("{{USER_INPUT}}"));
    }
}
