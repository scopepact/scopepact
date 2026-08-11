use scopepact_guard::key_provider::{generate_protected_key, load_protected_key};
use scopepact_guard::{GuardDecision, GuardEngine, GuardPolicy, ResourcePolicy, ToolRule};
use serde_json::{Value, json};

const PASSPHRASE: &[u8] = b"correct horse battery staple";
const NOW_MS: i64 = 1_000_000;

fn policy() -> GuardPolicy {
    GuardPolicy {
        policy_version: 1,
        policy_epoch: 7,
        principal: "local-developer".into(),
        agent: "coding-agent".into(),
        valid_for_ms: 60_000,
        rules: vec![ToolRule {
            id: "project-files".into(),
            tool: "write_file".into(),
            resource: ResourcePolicy::Argument {
                pointer: "/path".into(),
                prefix: "/workspace/project/".into(),
            },
            max_calls: 2,
            payment: None,
        }],
    }
}

fn tool_call() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "write_file",
            "arguments": {"path": "/workspace/project/a", "content": "one"}
        }
    })
}

#[test]
fn protected_key_signs_verifiable_receipts() {
    let generated = generate_protected_key(PASSPHRASE).unwrap();
    let signer = load_protected_key(&generated.encoded, PASSPHRASE).unwrap();
    assert_eq!(hex::encode(signer.public_key()), generated.public_key);
    assert_eq!(hex::encode(signer.key_id().0), generated.key_id);

    let mut engine = GuardEngine::new_with_signer(policy(), signer, NOW_MS).unwrap();
    let receipt = engine
        .evaluate_json_rpc(&tool_call(), NOW_MS)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.receipt.decision, GuardDecision::Allowed);
    receipt.verify().unwrap();
}

#[test]
fn wrong_passphrase_and_tampering_are_rejected() {
    let generated = generate_protected_key(PASSPHRASE).unwrap();
    let wrong = load_protected_key(&generated.encoded, b"this is the wrong passphrase")
        .err()
        .expect("wrong passphrase should fail");
    assert!(wrong.to_string().contains("cannot decrypt protected key"));

    let mut file: Value = serde_json::from_slice(&generated.encoded).unwrap();
    file["public_key"] = Value::String("00".repeat(32));
    let tampered = serde_json::to_vec(&file).unwrap();
    let error = load_protected_key(&tampered, PASSPHRASE)
        .err()
        .expect("tampered metadata should fail");
    assert!(error.to_string().contains("cannot decrypt protected key"));
}

#[test]
fn unsafe_passphrases_are_rejected() {
    let error = generate_protected_key(b"too short")
        .err()
        .expect("short passphrase should fail");
    assert!(error.to_string().contains("16 to 4096 bytes"));
}
