use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Susfile {
    pub api: String,
    pub model: String,
    pub max_agents_per_time: usize,
    pub tools: ToolsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolsConfig {
    pub nmap: NmapConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NmapConfig {
    pub ips: Vec<String>,
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
    if cfg.tools.nmap.ips.is_empty() {
        bail!("susfile.tools.nmap.ips must include at least one IP");
    }
    Ok(())
}

pub fn default_susfile() -> Susfile {
    Susfile {
        api: "openai".to_string(),
        model: "gpt-4.1".to_string(),
        max_agents_per_time: 2,
        tools: ToolsConfig {
            nmap: NmapConfig {
                ips: vec!["127.0.0.1".to_string()],
            },
        },
    }
}
