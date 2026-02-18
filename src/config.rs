use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Susfile {
    pub api: String,
    pub model: String,
    pub max_agents_per_time: usize,
    pub tools: ToolsConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<AgentsConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analyst: Option<AgentPromptConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reporter: Option<AgentPromptConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategist: Option<AgentPromptConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentPromptConfig {
    pub prompt: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolsConfig {
    pub cli: Vec<CliToolConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CliToolConfig {
    pub name: String,
    pub description: String,
    pub command: String,
    pub args: Vec<CliArgConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CliArgConfig {
    pub name: String,
    pub description: String,
}

pub fn load_susfile(root: &Path) -> Result<Susfile> {
    let content = fs::read_to_string(root.join("susfile")).context("failed to read susfile")?;
    let cfg: Susfile = serde_json::from_str(&content).context("susfile must be valid JSON")?;
    validate_susfile(&cfg)?;
    Ok(cfg)
}

pub fn validate_susfile(cfg: &Susfile) -> Result<()> {
    if cfg.api.to_lowercase() != "openai" {
        bail!("unsupported api `{}`; only `openai` is supported", cfg.api);
    }
    if cfg.model.trim().is_empty() {
        bail!("susfile.model must not be empty");
    }
    if cfg.max_agents_per_time == 0 {
        bail!("susfile.max_agents_per_time must be > 0");
    }
    if cfg.tools.cli.is_empty() {
        bail!("susfile.tools.cli must include at least one CLI tool definition");
    }

    let mut seen_tool_names = std::collections::HashSet::new();
    let reserved_tool_names = [
        "read_plan",
        "write_plan",
        "update_plan",
        "spawn_agent",
        "new_analyst",
        "new_strategist",
        "new_reporter",
        "read_note",
        "read_attack_model",
        "update_attack_model",
        "read_tool_data",
        "write_report",
        "claim_task",
        "complete_task",
        "add_note",
    ];

    if let Some(agents) = cfg.agents.as_ref() {
        for (role, prompt_cfg) in [
            ("analyst", agents.analyst.as_ref()),
            ("reporter", agents.reporter.as_ref()),
            ("strategist", agents.strategist.as_ref()),
        ] {
            if let Some(prompt_cfg) = prompt_cfg {
                if prompt_cfg.prompt.trim().is_empty() {
                    bail!("susfile.agents.{role}.prompt must not be empty");
                }
            }
        }
    }
    for tool in &cfg.tools.cli {
        let tool_name = tool.name.trim();
        if tool_name.is_empty() {
            bail!("each susfile.tools.cli definition requires a non-empty name");
        }
        if reserved_tool_names.contains(&tool_name) {
            bail!(
                "susfile.tools.cli name `{tool_name}` collides with a reserved runtime tool name"
            );
        }
        if !seen_tool_names.insert(tool_name.to_string()) {
            bail!("duplicate susfile.tools.cli name `{tool_name}`");
        }

        if tool.description.trim().is_empty() {
            bail!("susfile.tools.cli `{tool_name}` requires a non-empty description");
        }
        if tool.command.trim().is_empty() {
            bail!("susfile.tools.cli `{tool_name}` requires a non-empty command");
        }

        let placeholders = extract_placeholders(&tool.command);
        let mut seen_args = std::collections::HashSet::new();
        for arg in &tool.args {
            let arg_name = arg.name.trim();
            if arg_name.is_empty() {
                bail!("susfile.tools.cli `{tool_name}` has an argument with empty name");
            }
            if !seen_args.insert(arg_name.to_string()) {
                bail!("susfile.tools.cli `{tool_name}` has duplicate argument `{arg_name}`");
            }
            if arg.description.trim().is_empty() {
                bail!(
                    "susfile.tools.cli `{tool_name}` argument `{arg_name}` requires a description"
                );
            }
            if !placeholders.contains(arg_name) {
                bail!(
                    "susfile.tools.cli `{tool_name}` command must include placeholder <{arg_name}>"
                );
            }
        }

        for placeholder in placeholders {
            if !seen_args.contains(&placeholder) {
                bail!(
                    "susfile.tools.cli `{tool_name}` command placeholder <{placeholder}> has no matching args entry"
                );
            }
        }
    }

    Ok(())
}

fn extract_placeholders(command: &str) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let bytes = command.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            if let Some(rel_end) = command[i + 1..].find('>') {
                let end = i + 1 + rel_end;
                let token = command[i + 1..end].trim();
                if !token.is_empty() {
                    out.insert(token.to_string());
                }
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

pub fn default_susfile() -> Susfile {
    Susfile {
        api: "openai".to_string(),
        model: "gpt-4.1".to_string(),
        max_agents_per_time: 2,
        tools: ToolsConfig {
            cli: vec![CliToolConfig {
                name: "nmap_targeted_scan".to_string(),
                description: "Run an nmap aggressive scan against a target host".to_string(),
                command: "nmap -A <target>".to_string(),
                args: vec![CliArgConfig {
                    name: "target".to_string(),
                    description: "Target hostname or IP to scan".to_string(),
                }],
            }],
        },
        agents: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_susfile_has_cli_tools() {
        let cfg = default_susfile();
        validate_susfile(&cfg).expect("default config should validate");
        assert!(!cfg.tools.cli.is_empty());
    }

    #[test]
    fn validation_fails_when_placeholder_has_no_arg_mapping() {
        let mut cfg = default_susfile();
        cfg.tools.cli[0].command = "nmap -A <target> <extra>".to_string();
        let err = validate_susfile(&cfg).expect_err("expected validation error");
        assert!(err.to_string().contains("<extra>"));
    }

    #[test]
    fn validation_fails_for_empty_agent_prompt_path() {
        let mut cfg = default_susfile();
        cfg.agents = Some(AgentsConfig {
            analyst: Some(AgentPromptConfig {
                prompt: "   ".to_string(),
            }),
            reporter: None,
            strategist: None,
        });

        let err = validate_susfile(&cfg).expect_err("expected validation error");
        assert!(err
            .to_string()
            .contains("susfile.agents.analyst.prompt must not be empty"));
    }
}
