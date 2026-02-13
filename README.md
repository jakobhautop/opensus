# OpenSus

OpenSus is a process-based multi-agent system for **automatic pentest reports**.

## Commands

- `opensus init`: create required mission files.
- `opensus go`: run one orchestration heartbeat.

Users interact only with `go` and `init`.

## Required workspace files

- `susfile`: JSON config in the working directory with OpenAI API + model.
- `prompts/main.md`: orchestrator prompt.
- `prompts/intel.md`: reconnaissance worker prompt.
- `prompts/exploit.md`: exploitation worker prompt.
- `prompts/reporter.md`: reporting worker prompt.
- `prompts/swarm.md`: auto-generated swarm registry.
- `state.md`: mission objective + completion status.

Example `susfile`:

```json
{
  "api": "openai",
  "model": "gpt-4.1"
}
```

## Execution model

1. `opensus go` reads `state.md` and `susfile`.
2. If mission is incomplete, it runs `main`.
3. `main` can invoke `spawn_agent(name, task)`.
4. Workers run as independent OS processes via internal runtime spawning.
5. `prompts/swarm.md` is updated on spawn/completion/crash.
6. Next `opensus go` resumes deterministically from filesystem state.
