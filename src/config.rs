use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Susfile {
    pub api: String,
    pub model: String,
    #[serde(default = "default_secs_between_tics")]
    pub secs_between_tics: u64,
    pub max_agents_per_time: usize,
    #[serde(default = "default_max_strategists_per_time")]
    pub max_strategists_per_time: usize,
    #[serde(default, alias = "allowed_ips")]
    pub allowed_hosts: Vec<String>,
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

fn default_max_strategists_per_time() -> usize {
    1
}

fn default_secs_between_tics() -> u64 {
    30
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
    if cfg.secs_between_tics == 0 {
        bail!("susfile.secs_between_tics must be > 0");
    }
    if cfg.max_strategists_per_time == 0 {
        bail!("susfile.max_strategists_per_time must be > 0");
    }

    for host in &cfg.allowed_hosts {
        let candidate = host.trim();
        if candidate.is_empty() {
            bail!("susfile.allowed_hosts entries must not be empty");
        }

        let is_ipv4 = candidate.parse::<std::net::Ipv4Addr>().is_ok();
        let is_localhost = candidate.eq_ignore_ascii_case("localhost");
        let is_hostname = candidate
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            && candidate.chars().any(|c| c.is_ascii_alphabetic());

        if !(is_ipv4 || is_localhost || is_hostname) {
            bail!(
                "susfile.allowed_hosts contains invalid host `{candidate}` (expected IPv4, localhost, or hostname)"
            );
        }
    }
    if cfg.tools.cli.is_empty() {
        bail!("susfile.tools.cli must include at least one CLI tool definition");
    }

    let mut seen_tool_names = std::collections::HashSet::new();
    let reserved_tool_names = [
        "read_plan",
        "read_attack_plan",
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
        secs_between_tics: 30,
        max_agents_per_time: 2,
        max_strategists_per_time: 1,
        allowed_hosts: vec!["127.0.0.1".to_string()],
        tools: ToolsConfig {
            cli: vec![
                CliToolConfig {
                    name: "nmap_targeted_scan".to_string(),
                    description: "Run an nmap aggressive scan against a target host".to_string(),
                    command: "nmap -A <target>".to_string(),
                    args: vec![CliArgConfig {
                        name: "target".to_string(),
                        description: "Target hostname or IP to scan".to_string(),
                    }],
                },
                CliToolConfig {
                    name: "nmap_service_scan".to_string(),
                    description:
                        "Run nmap service/version scan with default scripts without host discovery"
                            .to_string(),
                    command: "nmap -sV -sC -Pn <target>".to_string(),
                    args: vec![CliArgConfig {
                        name: "target".to_string(),
                        description: "Target hostname or IP to scan".to_string(),
                    }],
                },
                CliToolConfig {
                    name: "gobuster_dir".to_string(),
                    description: "Enumerate HTTP directories/files using Kali default wordlists"
                        .to_string(),
                    command: "gobuster dir -u <url> -w /usr/share/wordlists/dirb/common.txt"
                        .to_string(),
                    args: vec![CliArgConfig {
                        name: "url".to_string(),
                        description: "Target base URL (for example http://127.0.0.1)".to_string(),
                    }],
                },
                CliToolConfig {
                    name: "gobuster_dir_with_wordlist".to_string(),
                    description: "Enumerate HTTP directories/files with a provided wordlist"
                        .to_string(),
                    command: "gobuster dir -u <url> -w <wordlist>".to_string(),
                    args: vec![
                        CliArgConfig {
                            name: "url".to_string(),
                            description: "Target base URL (for example http://127.0.0.1)"
                                .to_string(),
                        },
                        CliArgConfig {
                            name: "wordlist".to_string(),
                            description: "Path to wordlist file for content discovery".to_string(),
                        },
                    ],
                },
                CliToolConfig {
                    name: "gobuster_vhost".to_string(),
                    description: "Enumerate HTTP virtual hosts using Kali default wordlists"
                        .to_string(),
                    command: "gobuster vhost -u <url> -w /usr/share/wordlists/dnsmap.txt"
                        .to_string(),
                    args: vec![CliArgConfig {
                        name: "url".to_string(),
                        description: "Target base URL (for example http://127.0.0.1)".to_string(),
                    }],
                },
                CliToolConfig {
                    name: "gobuster_vhost_with_wordlist".to_string(),
                    description: "Enumerate HTTP virtual hosts with a provided wordlist"
                        .to_string(),
                    command: "gobuster vhost -u <url> -w <wordlist>".to_string(),
                    args: vec![
                        CliArgConfig {
                            name: "url".to_string(),
                            description: "Target base URL (for example http://127.0.0.1)"
                                .to_string(),
                        },
                        CliArgConfig {
                            name: "wordlist".to_string(),
                            description: "Path to wordlist file for vhost discovery".to_string(),
                        },
                    ],
                },
                CliToolConfig {
                    name: "nikto_scan".to_string(),
                    description: "Run Nikto web vulnerability scan against an HTTP target"
                        .to_string(),
                    command: "nikto -h <url>".to_string(),
                    args: vec![CliArgConfig {
                        name: "url".to_string(),
                        description: "Target base URL (for example http://127.0.0.1)".to_string(),
                    }],
                },
                CliToolConfig {
                    name: "sqlmap_scan".to_string(),
                    description: "Run SQLMap against a target URL in non-interactive mode"
                        .to_string(),
                    command: "sqlmap -u <url> --batch".to_string(),
                    args: vec![CliArgConfig {
                        name: "url".to_string(),
                        description: "Target URL to test for SQL injection".to_string(),
                    }],
                },
                CliToolConfig {
                    name: "fetch_robots_txt".to_string(),
                    description: "Fetch robots.txt from a target web service".to_string(),
                    command: "curl -fsSL <url>/robots.txt".to_string(),
                    args: vec![CliArgConfig {
                        name: "url".to_string(),
                        description: "Target base URL without trailing slash".to_string(),
                    }],
                },
                CliToolConfig {
                    name: "path_traversal_probe".to_string(),
                    description: "Probe a potentially vulnerable web path using --path-as-is"
                        .to_string(),
                    command: "curl -i --path-as-is <url><path>".to_string(),
                    args: vec![
                        CliArgConfig {
                            name: "url".to_string(),
                            description: "Target base URL (for example http://127.0.0.1)"
                                .to_string(),
                        },
                        CliArgConfig {
                            name: "path".to_string(),
                            description: "Request path to probe (for example /../../etc/passwd)"
                                .to_string(),
                        },
                    ],
                },
                CliToolConfig {
                    name: "curl_raw".to_string(),
                    description: "Run a raw curl command by supplying argument string".to_string(),
                    command: "curl <args>".to_string(),
                    args: vec![CliArgConfig {
                        name: "args".to_string(),
                        description: "Arguments passed to curl (for example -i http://127.0.0.1/)"
                            .to_string(),
                    }],
                },
                CliToolConfig {
                    name: "vmdk_strings".to_string(),
                    description: "Extract printable strings from a disk image file".to_string(),
                    command: "strings -a <image_path>".to_string(),
                    args: vec![CliArgConfig {
                        name: "image_path".to_string(),
                        description: "Path to disk image file (for example challenge.vmdk)"
                            .to_string(),
                    }],
                },
                CliToolConfig {
                    name: "vmdk_binwalk".to_string(),
                    description: "Run binwalk signature scan against a disk image file".to_string(),
                    command: "binwalk <image_path>".to_string(),
                    args: vec![CliArgConfig {
                        name: "image_path".to_string(),
                        description: "Path to disk image file (for example challenge.vmdk)"
                            .to_string(),
                    }],
                },
                CliToolConfig {
                    name: "list_wordlists".to_string(),
                    description: "List common Kali wordlists and their paths".to_string(),
                    command: "ls -l /usr/share/wordlists/".to_string(),
                    args: vec![],
                },
            ],
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
    fn default_susfile_includes_expected_recon_tools() {
        let cfg = default_susfile();
        let names: std::collections::HashSet<_> = cfg
            .tools
            .cli
            .iter()
            .map(|tool| tool.name.as_str())
            .collect();

        assert!(names.contains("gobuster_dir"));
        assert!(names.contains("gobuster_vhost"));
        assert!(names.contains("gobuster_dir_with_wordlist"));
        assert!(names.contains("gobuster_vhost_with_wordlist"));
        assert!(names.contains("nikto_scan"));
        assert!(names.contains("sqlmap_scan"));
        assert!(names.contains("fetch_robots_txt"));
        assert!(names.contains("path_traversal_probe"));
        assert!(names.contains("curl_raw"));
        assert!(names.contains("vmdk_strings"));
        assert!(names.contains("vmdk_binwalk"));
        assert!(names.contains("list_wordlists"));
    }

    #[test]
    fn load_defaults_max_strategists_per_time_when_missing() {
        let cfg: Susfile = serde_json::from_str(
            r#"{
                "api": "openai",
                "model": "gpt-4.1",
                "secs_between_tics": 30,
                "max_agents_per_time": 1,
                "allowed_hosts": ["127.0.0.1"],
                "tools": {
                    "cli": [
                        {
                            "name": "nmap_targeted_scan",
                            "description": "Run scan",
                            "command": "nmap -A <target>",
                            "args": [{"name": "target", "description": "Target"}]
                        }
                    ]
                }
            }"#,
        )
        .expect("missing max_strategists_per_time should deserialize");

        assert_eq!(cfg.max_strategists_per_time, 1);
    }

    #[test]
    fn validation_fails_for_zero_max_strategists_per_time() {
        let mut cfg = default_susfile();
        cfg.max_strategists_per_time = 0;

        let err = validate_susfile(&cfg).expect_err("expected validation error");
        assert!(err
            .to_string()
            .contains("susfile.max_strategists_per_time must be > 0"));
    }

    #[test]
    fn load_supports_legacy_allowed_ips_key() {
        let cfg: Susfile = serde_json::from_str(
            r#"{
                "api": "openai",
                "model": "gpt-4.1",
                "secs_between_tics": 30,
                "max_agents_per_time": 1,
                "allowed_ips": ["127.0.0.1"],
                "tools": {
                    "cli": [
                        {
                            "name": "nmap_targeted_scan",
                            "description": "Run scan",
                            "command": "nmap -A <target>",
                            "args": [{"name": "target", "description": "Target"}]
                        }
                    ]
                }
            }"#,
        )
        .expect("legacy allowed_ips should deserialize");

        assert_eq!(cfg.allowed_hosts, vec!["127.0.0.1"]);
    }

    #[test]
    fn validation_fails_when_placeholder_has_no_arg_mapping() {
        let mut cfg = default_susfile();
        cfg.tools.cli[0].command = "nmap -A <target> <extra>".to_string();
        let err = validate_susfile(&cfg).expect_err("expected validation error");
        assert!(err.to_string().contains("<extra>"));
    }

    #[test]
    fn validation_fails_for_invalid_allowed_host() {
        let mut cfg = default_susfile();
        cfg.allowed_hosts = vec!["bad host value".to_string()];

        let err = validate_susfile(&cfg).expect_err("expected validation error");
        assert!(err
            .to_string()
            .contains("susfile.allowed_hosts contains invalid host"));
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

    #[test]
    fn load_defaults_secs_between_tics_when_missing() {
        let cfg: Susfile = serde_json::from_str(
            r#"{
                "api": "openai",
                "model": "gpt-4.1",
                "max_agents_per_time": 1,
                "allowed_hosts": ["127.0.0.1"],
                "tools": {
                    "cli": [
                        {
                            "name": "nmap_targeted_scan",
                            "description": "Run scan",
                            "command": "nmap -A <target>",
                            "args": [{"name": "target", "description": "Target"}]
                        }
                    ]
                }
            }"#,
        )
        .expect("missing secs_between_tics should deserialize");

        assert_eq!(cfg.secs_between_tics, 30);
    }

    #[test]
    fn validation_fails_for_zero_secs_between_tics() {
        let mut cfg = default_susfile();
        cfg.secs_between_tics = 0;

        let err = validate_susfile(&cfg).expect_err("expected validation error");
        assert!(err
            .to_string()
            .contains("susfile.secs_between_tics must be > 0"));
    }
}
