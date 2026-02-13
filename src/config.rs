use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Susfile {
    pub api: String,
    pub model: String,
    pub max_agents_per_time: usize,
    pub tools: ToolsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolsConfig {
    pub nmap: NmapConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NmapConfig {
    pub ips: Vec<String>,
}

pub fn load_susfile(root: &Path) -> Result<Susfile> {
    let path = root.join("susfile");
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read susfile in {}", root.display()))?;
    let cfg: Susfile = serde_json::from_str(&content).context("susfile must be valid JSON")?;
    if cfg.api.to_lowercase() != "openai" {
        bail!(
            "unsupported api `{}` in susfile; only `openai` is supported",
            cfg.api
        );
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
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_openai_susfile_with_limits() {
        let tmp = tempfile::tempdir().expect("tempdir");
        fs::write(
            tmp.path().join("susfile"),
            "{\"api\":\"openai\",\"model\":\"gpt-4.1\",\"max_agents_per_time\":2,\"tools\":{\"nmap\":{\"ips\":[\"127.0.0.1\"]}}}",
        )
        .expect("write susfile");
        let cfg = load_susfile(tmp.path()).expect("config should parse");
        assert_eq!(cfg.max_agents_per_time, 2);
    }
}
