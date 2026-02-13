use std::process::Command;

use anyhow::{bail, Context, Result};

pub fn nmap_verify() -> Result<(String, String, String)> {
    let output = Command::new("nmap")
        .arg("--version")
        .output()
        .context("failed to execute nmap --version")?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        bail!("nmap --version failed: {}", stderr.trim());
    }
    Ok(("nmap --version".to_string(), stdout, stderr))
}

pub fn nmap_scan_aggressive(ip: &str) -> Result<(String, String, String)> {
    if ip.trim().is_empty() {
        bail!("ip must not be empty");
    }
    let output = Command::new("nmap")
        .arg("-A")
        .arg(ip)
        .output()
        .context("failed to execute nmap -A")?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        bail!("nmap -A failed: {}", stderr.trim());
    }
    Ok((format!("nmap -A {ip}"), stdout, stderr))
}
