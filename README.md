# OpenSus - LLMs for Pentesting

OpenSus is a self-orchestrating pentest lab running multiple concurrent LLM workers all commited to one assignment. OpenSus is meant to run in an environment with nmap, metasploit and other pentest tools (Kali Linux for example). User runs "opensus init" to scaffold a project. They then write an assignment "brief.md" that provides opensus agents the context they need and adjust the susfile with config. User then runs "opensus go" to start the main_agent which will coordinate planning, working and reporting agents until assignment is completed.

## Public commands

- `opensus init`
- `opensus go`

## Prompt files

Prompts are compiled into the binary from:

- `prompts/main_agent.md`
- `prompts/planning_agent.md`
- `prompts/worker_agent.md`
- `prompts/report_agent.md`

Users do not edit runtime prompt files after build; `init` does not scaffold prompts.

## init scaffold

`opensus init` creates:
- `susfile` defaults (`max_agents_per_time`, `heartbeat_seconds`, tool allowlists)
- validates `OPENAI_API_KEY` when provider is openai
- `notes/`
- empty `plan.md`
- `brief.md`

## LLM runtime model

`opensus go` invokes `main_agent` via OpenAI Chat Completions and provides tool definitions in the request. Agents decide tool usage themselves. OpenSus executes returned tool calls and feeds results back to the LLM until the agent completes.
