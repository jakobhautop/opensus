pub fn main_agent_brief() -> &'static str {
    "main_agent tools: read_plan(), write_plan(), spawn_agent(task_id), read_swarm()"
}

pub fn plan_agent_brief() -> &'static str {
    "plan_agent tools: read_plan(), write_plan(markdown)"
}

pub fn work_agent_brief() -> &'static str {
    "work_agent tools: read_plan(), claim_task(id), complete_task(id), add_note(string), nmap_verify(), nmap_aggressive_scan()"
}

pub fn reporter_agent_brief() -> &'static str {
    "reporter_agent waits for completed plan/tasks and writes report.md"
}
