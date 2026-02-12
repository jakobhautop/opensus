# Susmos

Susmos is a process-based multi-agent orchestration CLI.

## Commands

- `susmos init`: creates the required filesystem layout.
- `susmos go`: runs one orchestration heartbeat.
- `susmos agent <name> <task>`: runs one named agent process.

## Runtime files

- `prompts/main.md`: orchestrator prompt.
- `prompts/coder.md`: worker prompt.
- `prompts/reviewer.md`: reviewer prompt.
- `prompts/swarm.md`: auto-generated swarm registry.
- `state.md`: mission objective + completion status.
- `.susmos/config.json`: provider config placeholder.

## Execution model

1. `susmos go` reads `state.md`.
2. If mission is incomplete, it runs `main`.
3. `main` can invoke `spawn_agent(name, task)`.
4. Each worker runs as an independent OS process via `susmos agent ...`.
5. `prompts/swarm.md` is updated on spawn/completion/crash.
6. Next `susmos go` resumes from file-backed state.
