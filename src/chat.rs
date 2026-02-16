use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::{json, Value};

use crate::config::Susfile;

pub fn tools_for_agent(agent: &str, cfg: &Susfile) -> Vec<Value> {
    match agent {
        "main_agent" => vec![
            tool_no_args("read_plan", "Read plan.md"),
            tool_write_plan(),
            tool_spawn_agent(),
            tool_no_args("read_worker_count", "Read current active worker count"),
        ],
        "planning_agent" => vec![
            tool_no_args("read_plan", "Read plan.md"),
            tool_write_plan(),
            json!({"type":"function","function":{"name":"cve_search","description":"Search CVE database by query text and return raw records","parameters":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}}}),
            json!({"type":"function","function":{"name":"cve_show","description":"Get one CVE and affected products by CVE ID","parameters":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}}}),
        ],
        "worker_agent" => {
            let mut tools = vec![
                tool_no_args("read_plan", "Read plan.md"),
                tool_single_id("claim_task", "Claim task and set to pending"),
                tool_single_id("complete_task", "Mark task complete"),
                json!({"type":"function","function":{"name":"add_note","description":"Append note text to notes/<task-id>.md","parameters":{"type":"object","properties":{"id":{"type":"string"},"note":{"type":"string"}},"required":["id","note"]}}}),
                json!({"type":"function","function":{"name":"cve_search","description":"Search CVE database by query text and return raw records","parameters":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}}}),
                json!({"type":"function","function":{"name":"cve_show","description":"Get one CVE and affected products by CVE ID","parameters":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}}}),
            ];

            for cli_tool in &cfg.tools.cli {
                let mut properties = serde_json::Map::new();
                let mut required = Vec::new();
                for arg in &cli_tool.args {
                    properties.insert(
                        arg.name.clone(),
                        json!({"type": "string", "description": arg.description}),
                    );
                    required.push(arg.name.clone());
                }

                tools.push(json!({
                    "type": "function",
                    "function": {
                        "name": cli_tool.name,
                        "description": cli_tool.description,
                        "parameters": {
                            "type": "object",
                            "properties": properties,
                            "required": required
                        }
                    }
                }));
            }

            tools
        }
        "report_agent" => vec![tool_no_args("read_plan", "Read plan.md")],
        _ => vec![],
    }
}

fn tool_no_args(name: &str, description: &str) -> Value {
    json!({"type":"function","function":{"name":name,"description":description,"parameters":{"type":"object","properties":{}}}})
}

fn tool_single_id(name: &str, description: &str) -> Value {
    json!({"type":"function","function":{"name":name,"description":description,"parameters":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}}})
}

fn tool_write_plan() -> Value {
    json!({"type":"function","function":{"name":"write_plan","description":"Write full markdown to plan.md","parameters":{"type":"object","properties":{"markdown":{"type":"string"}},"required":["markdown"]}}})
}

fn tool_spawn_agent() -> Value {
    json!({"type":"function","function":{"name":"spawn_agent","description":"Spawn an agent by role name: worker, planner, or reporter. For worker include task_id.","parameters":{"type":"object","properties":{"name":{"type":"string","enum":["worker","planner","reporter"]},"task_id":{"type":"string"}},"required":["name"]}}})
}

pub async fn create_chat_completion(
    client: &Client,
    api_key: &str,
    model: &str,
    messages: &[Value],
    tools: &[Value],
) -> Result<Value> {
    let body = json!({
        "model": model,
        "messages": messages,
        "tools": tools,
        "tool_choice": "auto"
    });

    let response = client
        .post("https://api.openai.com/v1/chat/completions")
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await
        .context("failed to call OpenAI chat completions")?;

    let status = response.status();
    let value: Value = response
        .json()
        .await
        .context("failed to parse OpenAI response JSON")?;

    if !status.is_success() {
        return Err(anyhow::anyhow!("OpenAI error {}: {}", status, value));
    }

    Ok(value)
}
