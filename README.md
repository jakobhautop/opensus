# OpenSus

OpenSus is a heartbeat-driven multi-agent system for automatic pentest reporting.

## Public commands

- `opensus init`
- `opensus go`

Users only run those two commands. Worker/plan/reporter agent commands are internal.

## Heartbeat model (`go`)

When `opensus go` runs:

1. `main_agent` runs with conceptual tools:
   - `read_plan()`
   - `write_plan(markdown)`
   - `spawn_agent(task_id)`
   - `read_swarm()`
2. If `plan.md` does not exist, `main_agent` spawns `plan_agent`.
3. `main_agent` reads plan + swarm and spawns work agents for open tasks (respecting `susfile.max_agents_per_time`).
4. If planning is complete and no tasks remain, `main_agent` spawns `reporter_agent`.
5. `main_agent` exits (sleeps until next heartbeat).

## `susfile`

Created by `opensus init` in workspace root:

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

- Only `openai` is accepted.
- `max_agents_per_time` controls parallel work agents.
- `tools.nmap.ips` is the allowlist for aggressive nmap scans.

## Plan format (`plan.md`)

`plan_agent` creates/updates plan markdown like:

```md
# Plan

planning_status: complete

## Intelligence gathering

### nmap tasks

- [ ] T001 - Aggressive scan 127.0.0.1
```

Task states:
- `[ ]` open
- `[~]` pending/claimed
- `[x]` complete
- `[!]` crashed

## Work-agent tools

Work agents operate with:
- `read_plan()`
- `claim_task(id)`
- `complete_task(id)`
- `add_note(string)`
- `nmap_verify()`
- `nmap_aggressive_scan()`

`nmap_aggressive_scan()` executes `nmap -A <ip>` and only uses allowlisted IPs from `susfile.tools.nmap.ips`.

## Notes and crash tracking

Claiming a task creates `notes/<task-id>.md`:

```md
---
state: open|complete|crashed
---
# Task: <title>
## Tools
## Notes
```

Every tool call appends stdin/stdout/stderr into the task note under **Tools**.

If an agent crashes:
- task note state is set to `crashed`
- task in `plan.md` is marked `[!]`
- swarm status is marked `crashed`
