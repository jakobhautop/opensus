use std::{collections::HashMap, process::Command};

use anyhow::{bail, Context, Result};

use crate::config::CliToolConfig;

pub fn run_cli_tool(
    definition: &CliToolConfig,
    args: &HashMap<String, String>,
) -> Result<(String, String, String)> {
    let rendered = render_command_template(&definition.command, args)?;

    let output = Command::new("bash")
        .arg("-lc")
        .arg(&rendered)
        .output()
        .with_context(|| {
            format!(
                "failed to execute configured CLI command `{}`",
                definition.name
            )
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        bail!(
            "configured CLI command `{}` failed: {}",
            definition.name,
            stderr.trim()
        );
    }

    Ok((rendered, stdout, stderr))
}

fn render_command_template(template: &str, args: &HashMap<String, String>) -> Result<String> {
    let mut rendered = template.to_string();
    for (name, value) in args {
        let placeholder = format!("<{name}>");
        rendered = rendered.replace(&placeholder, value);
    }

    if let Some(unresolved) = find_unresolved_placeholder(&rendered) {
        bail!("missing required argument `{unresolved}` for configured CLI command");
    }

    Ok(rendered)
}

fn find_unresolved_placeholder(command: &str) -> Option<String> {
    let bytes = command.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            if let Some(rel_end) = command[i + 1..].find('>') {
                let end = i + 1 + rel_end;
                let token = command[i + 1..end].trim();
                if !token.is_empty() {
                    return Some(token.to_string());
                }
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    None
}
