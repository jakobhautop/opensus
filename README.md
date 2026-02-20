# OpenSus - LLMs for Pentesting

OpenSus is a self-orchestrating pentest lab running multiple concurrent LLM analysts all commited to one assignment. OpenSus is meant to run in an environment with nmap, metasploit and other pentest tools (Kali Linux for example). User runs "opensus init" to scaffold a project. They then write an assignment "brief.md" that provides opensus agents the context they need and adjust the susfile with config. User then runs "opensus go" to start the dispatch_agent which will coordinate strategist, analyst and reporting agents until assignment is completed.

## Public commands

- `opensus init`
- `opensus go [--fullauto]`
- `opensus reset`
- `opensus cve search <query>`
- `opensus cve show <CVE-ID>`
- `opensus cvedb install`

## Prompt files

Prompts are compiled into the binary from:

- `prompts/dispatch_agent.md`
- `prompts/strategist_agent.md`
- `prompts/analyst_agent.md`
- `prompts/report_agent.md`

Users do not edit runtime prompt files after build; `init` does not scaffold prompts.

## init scaffold

`opensus init` creates:
- `susfile` defaults
- validates `OPENAI_API_KEY` when provider is openai
- `notes/`
- empty `plan.md`
- `brief.md`

## Concurrency limits

`susfile` supports separate concurrency limits:

- `max_agents_per_time`: maximum concurrent analyst agents
- `max_strategists_per_time`: maximum concurrent strategist agents (defaults to `1` when omitted)

## Susfile CLI tools

`susfile` now defines analyst CLI tooling under `tools.cli`. Each tool includes:

- `name` (function name exposed to analyst tool calls)
- `description` (short natural-language behavior)
- `command` (CLI template, for example `nmap -A <target>`)
- `args` (argument definitions used to map model-provided parameters into command placeholders)
- `allowed_hosts` (list of allowed hosts for tool call arguments, such as IPv4 addresses, hostnames, or `localhost`; requests outside this list are blocked at runtime)

Example:

```json
{
  "allowed_hosts": [],
  "tools": {
    "cli": [
      {
        "name": "nmap_targeted_scan",
        "description": "Run nmap aggressive scan",
        "command": "nmap -A <target>",
        "args": [
          {"name": "target", "description": "Host or IP"}
        ]
      }
    ]
  }
}
```

Example host allow-list setup:

```json
{
  "allowed_hosts": [
    "89.167.60.165",
    "localhost",
    "internal.lab.local"
  ]
}
```

## Agent-specific custom prompts

`susfile` can optionally specify per-agent prompt files. When set, OpenSus reads each file and injects its content into the corresponding embedded prompt template inside:

```md
<User input>
...custom prompt file content...
</User input>
```

Supported keys:

- `agents.analyst.prompt`
- `agents.reporter.prompt`
- `agents.strategist.prompt`

Example:

```json
{
  "agents": {
    "analyst": {"prompt": "prompts/analyst.md"},
    "reporter": {"prompt": "prompts/reporter.md"},
    "strategist": {"prompt": "prompts/strategist.md"}
  }
}
```

## LLM runtime model

`opensus go` invokes `dispatch_agent` via OpenAI Chat Completions and provides tool definitions in the request. Agents decide tool usage themselves. OpenSus executes returned tool calls and feeds results back to the LLM until the agent completes. Use `opensus go --fullauto` to continuously start a new heartbeat after each completion.

## reset runtime artifacts

`opensus reset` keeps `brief.md` and `susfile`, but clears runtime progress by emptying `plan.md` and recreating empty `notes/` and `tool_data/` directories.


## CVE database

OpenSus uses a local CVE SQLite database at `~/.opensus/cve.db`. Install or refresh it with `opensus cvedb install`, which downloads the latest cvelistV5 release zip from GitHub and rebuilds the local DB.

- `opensus cve search <query>` returns at most 10 JSON rows using both description full-text match and product/vendor matching.
- `opensus cve show <CVE-ID>` returns one CVE JSON record plus affected products.
- `opensus cvedb install` downloads the latest cvelistV5 release zip from GitHub and rebuilds the local DB.
