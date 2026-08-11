use ed25519_dalek::SigningKey;
use scopepact_guard::{GuardEngine, GuardPolicy, ResourcePolicy, ToolRule};
use serde_json::{Value, json};

fn main() {
    let policy = GuardPolicy {
        policy_version: 1,
        policy_epoch: 7,
        principal: "vector-principal".into(),
        agent: "vector-agent".into(),
        valid_for_ms: 60_000,
        rules: vec![ToolRule {
            id: "vector-file-write".into(),
            tool: "write_file".into(),
            resource: ResourcePolicy::Argument {
                pointer: "/path".into(),
                prefix: "/workspace/project/".into(),
            },
            max_calls: 1,
            payment: None,
        }],
    };
    let request = json!({
        "jsonrpc": "2.0",
        "id": "receipt-vector-1",
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {
                "path": "/workspace/project/vector.txt",
                "content": "portable receipt"
            }
        }
    });
    let receipt = GuardEngine::new(policy.clone(), SigningKey::from_bytes(&[42; 32]), 1_000_000)
        .unwrap()
        .evaluate_json_rpc(&request, 1_000_001)
        .unwrap()
        .unwrap();
    let vector: Value = json!({
        "format": "scopepact-guard-receipt-vector-v1",
        "signing_seed_hex": hex::encode([42; 32]),
        "policy": policy,
        "request": request,
        "evaluated_at_ms": 1_000_001,
        "signed_receipt": receipt
    });
    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}
