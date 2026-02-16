# OpenSus - LLMs for Pentesting

OpenSus is a self-orchestrating pentest lab running multiple concurrent LLM workers all commited to one assignment. OpenSus is meant to run in an environment with nmap, metasploit and other pentest tools (Kali Linux for example). User runs "opensus init" to scaffold a project. They then write an assignment "brief.md" that provides opensus agents the context they need and adjust the susfile with config. User then runs "opensus go" to start the main_agent which will coordinate planning, working and reporting agents until assignment is completed.

## Public commands

- `opensus init`
- `opensus go`
- `opensus reset`
- `opensus cve search <query>`
- `opensus cve show <CVE-ID>`
- `opensus update-cve-db`

## Prompt files

Prompts are compiled into the binary from:

- `prompts/main_agent.md`
- `prompts/planning_agent.md`
- `prompts/worker_agent.md`
- `prompts/report_agent.md`

Users do not edit runtime prompt files after build; `init` does not scaffold prompts.

## init scaffold

`opensus init` creates:
- `susfile` defaults
- validates `OPENAI_API_KEY` when provider is openai
- `notes/`
- empty `plan.md`
- `brief.md`

## Susfile CLI tools

`susfile` now defines worker CLI tooling under `tools.cli`. Each tool includes:

- `name` (function name exposed to worker tool calls)
- `description` (short natural-language behavior)
- `command` (CLI template, for example `nmap -A <target>`)
- `args` (argument definitions used to map model-provided parameters into command placeholders)

Example:

```json
{
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

## Agent-specific custom prompts

`susfile` can optionally specify per-agent prompt files. When set, OpenSus reads each file and injects its content into the corresponding embedded prompt template inside:

```md
<User input>
...custom prompt file content...
</User input>
```

Supported keys:

- `agents.worker.prompt`
- `agents.reporter.prompt`
- `agents.planner.prompt`

Example:

```json
{
  "agents": {
    "worker": {"prompt": "prompts/worker.custom.md"},
    "reporter": {"prompt": "prompts/reporter.custom.md"},
    "planner": {"prompt": "prompts/planner.custom.md"}
  }
}
```

## LLM runtime model

`opensus go` invokes `main_agent` via OpenAI Chat Completions and provides tool definitions in the request. Agents decide tool usage themselves. OpenSus executes returned tool calls and feeds results back to the LLM until the agent completes.

## reset runtime artifacts

`opensus reset` keeps `brief.md` and `susfile`, but clears runtime progress by emptying `plan.md` and recreating an empty `notes/` directory.


## CVE database

Release builds ship with an embedded CVE SQLite snapshot and extract it on `opensus init` into `~/.opensus/cve.db`. If a local/dev build has no embedded snapshot, run `opensus update-cve-db` once to create it locally.

- `opensus cve search <query>` returns at most 10 JSON rows using both description full-text match and product/vendor matching.
- `opensus cve show <CVE-ID>` returns one CVE JSON record plus affected products.
- `opensus update-cve-db` clones `https://github.com/CVEProject/cvelistV5` and rebuilds the local DB.
