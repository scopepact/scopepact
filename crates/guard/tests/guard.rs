use ed25519_dalek::SigningKey;
use scopepact_guard::{
    GuardDecision, GuardEngine, GuardPolicy, PaymentPolicy, ResourcePolicy, ToolRule,
};
use serde_json::{Value, json};

const NOW_MS: i64 = 1_000_000;

fn policy() -> GuardPolicy {
    GuardPolicy {
        policy_version: 1,
        policy_epoch: 7,
        principal: "local-developer".into(),
        agent: "coding-agent".into(),
        valid_for_ms: 60_000,
        rules: vec![
            ToolRule {
                id: "project-files".into(),
                tool: "write_file".into(),
                resource: ResourcePolicy::Argument {
                    pointer: "/path".into(),
                    prefix: "/workspace/project/".into(),
                },
                max_calls: 2,
                payment: None,
            },
            ToolRule {
                id: "small-vendor-payment".into(),
                tool: "send_payment".into(),
                resource: ResourcePolicy::Literal {
                    value: "urn:payments:vendor".into(),
                },
                max_calls: 2,
                payment: Some(PaymentPolicy {
                    currency: "USD-CENTS".into(),
                    amount_pointer: "/amount_cents".into(),
                    payee_pointer: "/payee".into(),
                    max_spend_atomic: 500,
                    allowed_payees: vec!["vendor-a".into()],
                }),
            },
        ],
    }
}

fn engine() -> GuardEngine {
    GuardEngine::new(policy(), SigningKey::from_bytes(&[42; 32]), NOW_MS).unwrap()
}

fn tool_call(id: u64, tool: &str, arguments: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments}
    })
}

#[test]
fn allows_an_in_scope_tool_call_and_signs_the_receipt() {
    let receipt = engine()
        .evaluate_json_rpc(
            &tool_call(
                1,
                "write_file",
                &json!({"path": "/workspace/project/README.md", "content": "hello"}),
            ),
            NOW_MS,
        )
        .unwrap()
        .unwrap();

    assert_eq!(receipt.receipt.decision, GuardDecision::Allowed);
    assert_eq!(receipt.receipt.rule_id.as_deref(), Some("project-files"));
    receipt.verify().unwrap();
}

#[test]
fn blocks_tools_and_resources_outside_policy() {
    let mut guard = engine();
    let unknown = guard
        .evaluate_json_rpc(&tool_call(1, "run_shell", &json!({})), NOW_MS)
        .unwrap()
        .unwrap();
    assert_eq!(unknown.receipt.decision, GuardDecision::Blocked);
    assert_eq!(unknown.receipt.reason, "tool is not granted");

    let outside = guard
        .evaluate_json_rpc(
            &tool_call(
                2,
                "write_file",
                &json!({"path": "/etc/hosts", "content": "blocked"}),
            ),
            NOW_MS,
        )
        .unwrap()
        .unwrap();
    assert_eq!(outside.receipt.decision, GuardDecision::Blocked);
    assert!(outside.receipt.reason.contains("resource is outside"));
    outside.verify().unwrap();

    let traversal = guard
        .evaluate_json_rpc(
            &tool_call(
                3,
                "write_file",
                &json!({"path": "/workspace/project/../secrets", "content": "blocked"}),
            ),
            NOW_MS,
        )
        .unwrap()
        .unwrap();
    assert_eq!(traversal.receipt.decision, GuardDecision::Blocked);
    assert!(traversal.receipt.reason.contains("parent traversal"));
}

#[test]
fn suppresses_duplicate_effects_and_conflicting_request_ids() {
    let mut guard = engine();
    let request = tool_call(
        9,
        "write_file",
        &json!({"path": "/workspace/project/a", "content": "one"}),
    );
    let first = guard.evaluate_json_rpc(&request, NOW_MS).unwrap().unwrap();
    let duplicate = guard.evaluate_json_rpc(&request, NOW_MS).unwrap().unwrap();
    assert_eq!(first.receipt.decision, GuardDecision::Allowed);
    assert_eq!(duplicate.receipt.decision, GuardDecision::Blocked);
    assert!(duplicate.receipt.duplicate);

    let conflict = guard
        .evaluate_json_rpc(
            &tool_call(
                9,
                "write_file",
                &json!({"path": "/workspace/project/a", "content": "two"}),
            ),
            NOW_MS,
        )
        .unwrap()
        .unwrap();
    assert_eq!(conflict.receipt.decision, GuardDecision::Blocked);
    assert!(conflict.receipt.reason.contains("different content"));
}

#[test]
fn enforces_call_count_and_cumulative_payment_limits() {
    let mut guard = engine();
    for (id, amount) in [(1, 200), (2, 300)] {
        let receipt = guard
            .evaluate_json_rpc(
                &tool_call(
                    id,
                    "send_payment",
                    &json!({"amount_cents": amount, "payee": "vendor-a"}),
                ),
                NOW_MS,
            )
            .unwrap()
            .unwrap();
        assert_eq!(receipt.receipt.decision, GuardDecision::Allowed);
    }
    let over_limit = guard
        .evaluate_json_rpc(
            &tool_call(
                3,
                "send_payment",
                &json!({"amount_cents": 1, "payee": "vendor-a"}),
            ),
            NOW_MS,
        )
        .unwrap()
        .unwrap();
    assert_eq!(over_limit.receipt.decision, GuardDecision::Blocked);
    assert!(
        over_limit
            .receipt
            .reason
            .contains("call allowance exhausted")
    );
}

#[test]
fn blocks_unapproved_payees_and_tampered_receipts() {
    let mut guard = engine();
    let mut receipt = guard
        .evaluate_json_rpc(
            &tool_call(
                1,
                "send_payment",
                &json!({"amount_cents": 10, "payee": "vendor-b"}),
            ),
            NOW_MS,
        )
        .unwrap()
        .unwrap();
    assert_eq!(receipt.receipt.decision, GuardDecision::Blocked);
    assert!(receipt.receipt.reason.contains("payee is not granted"));
    receipt.verify().unwrap();

    receipt.receipt.reason = "allowed after editing".into();
    assert!(receipt.verify().is_err());
}

#[test]
fn ignores_non_tool_messages_and_rejects_malformed_policy() {
    let mut guard = engine();
    assert!(
        guard
            .evaluate_json_rpc(
                &json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
                NOW_MS,
            )
            .unwrap()
            .is_none()
    );

    let mut invalid = policy();
    invalid.rules[0].max_calls = 0;
    assert!(GuardEngine::new(invalid, SigningKey::from_bytes(&[42; 32]), NOW_MS).is_err());
}

#[test]
fn rejects_json_rpc_batches_instead_of_bypassing_tool_enforcement() {
    let mut guard = engine();
    let batch = json!([tool_call(
        1,
        "write_file",
        &json!({"path": "/etc/hosts", "content": "blocked"})
    )]);

    assert!(guard.evaluate_json_rpc(&batch, NOW_MS).is_err());
}

#[test]
fn rejects_fractional_and_unsafe_numeric_request_ids() {
    let mut guard = engine();
    for id in [json!(1.5), json!(9_007_199_254_740_992_u64)] {
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": "/workspace/project/a", "content": "x"}
            }
        });
        assert!(guard.evaluate_json_rpc(&request, NOW_MS).is_err());
    }
}
