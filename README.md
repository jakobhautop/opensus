# OpenSus

OpenSus is a heartbeat-driven multi-agent system for automatic pentest reporting.

## Public commands

- `opensus init`
- `opensus go`

## Runtime prompts

OpenSus uses these prompt files:

- `prompts/main_agent.md`
- `prompts/planning_agent.md`
- `prompts/worker_agent.md`
- `prompts/report_agent.md`

## `opensus init`

`init` performs:
1. create `susfile` defaults
2. validate `OPENAI_API_KEY` exists when `susfile.api` is `openai`
3. create `notes/`
4. create empty `plan.md`

## `susfile`

```json
{
  "api": "openai",
  "model": "gpt-4.1",
  "max_agents_per_time": 2,
  "tools": {
    "nmap": {
      "ips": ["127.0.0.1"]
    }
  }
}
```

- `max_agents_per_time` limits concurrent worker agents per heartbeat.
- `tools.nmap.ips` is allowlist for aggressive scans.

## `go` flow

- `main_agent` reads `plan.md`.
- If empty, it spawns `planning_agent`.
- Otherwise it spawns `worker_agent` tasks up to `max_agents_per_time`.
- When planning is complete and all tasks are complete, it spawns `report_agent`.

## Notes format

Each claimed task creates `notes/<task-id>.md`:

```md
---
state: open|complete|crashed
---
# Task: <title>
## Tools
## Notes
```

Tool calls append stdin/stdout/stderr blocks under `## Tools`.
