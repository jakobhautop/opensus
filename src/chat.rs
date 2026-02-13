use serde_json::{json, Value};

pub fn main_agent_tool_defs() -> Vec<Value> {
    vec![
        json!({"type":"function","function":{"name":"read_plan","description":"Read current plan.md","parameters":{"type":"object","properties":{}}}}),
        json!({"type":"function","function":{"name":"write_plan","description":"Write plan.md markdown","parameters":{"type":"object","properties":{"markdown":{"type":"string"}},"required":["markdown"]}}}),
        json!({"type":"function","function":{"name":"spawn_agent","description":"Spawn worker by task id","parameters":{"type":"object","properties":{"task_id":{"type":"string"}},"required":["task_id"]}}}),
        json!({"type":"function","function":{"name":"read_worker_count","description":"Read concurrent running worker count","parameters":{"type":"object","properties":{}}}}),
    ]
}

pub fn planning_agent_tool_defs() -> Vec<Value> {
    vec![
        json!({"type":"function","function":{"name":"read_plan","description":"Read current plan.md","parameters":{"type":"object","properties":{}}}}),
        json!({"type":"function","function":{"name":"write_plan","description":"Write plan.md markdown","parameters":{"type":"object","properties":{"markdown":{"type":"string"}},"required":["markdown"]}}}),
    ]
}

pub fn worker_agent_tool_defs() -> Vec<Value> {
    vec![
        json!({"type":"function","function":{"name":"read_plan","description":"Read current plan.md","parameters":{"type":"object","properties":{}}}}),
        json!({"type":"function","function":{"name":"claim_task","description":"Claim task and set pending","parameters":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}}}),
        json!({"type":"function","function":{"name":"complete_task","description":"Complete task","parameters":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}}}),
        json!({"type":"function","function":{"name":"add_note","description":"Append note to task note","parameters":{"type":"object","properties":{"id":{"type":"string"},"note":{"type":"string"}},"required":["id","note"]}}}),
        json!({"type":"function","function":{"name":"nmap_verify","description":"Verify nmap installation","parameters":{"type":"object","properties":{}}}}),
        json!({"type":"function","function":{"name":"nmap_aggressive_scan","description":"Run nmap -A against task host","parameters":{"type":"object","properties":{"ip":{"type":"string"}},"required":["ip"]}}}),
    ]
}

pub fn report_agent_tool_defs() -> Vec<Value> {
    vec![
        json!({"type":"function","function":{"name":"read_plan","description":"Read current plan.md","parameters":{"type":"object","properties":{}}}}),
    ]
}
