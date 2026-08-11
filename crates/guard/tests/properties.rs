use ed25519_dalek::SigningKey;
use proptest::prelude::*;
use scopepact_guard::{
    GuardDecision, GuardEngine, GuardPolicy, PaymentPolicy, ResourcePolicy, ToolRule,
};
use serde_json::{Value, json};

const NOW_MS: i64 = 1_000_000;

fn call_policy(max_calls: u64) -> GuardPolicy {
    GuardPolicy {
        policy_version: 1,
        policy_epoch: 1,
        principal: "property-principal".into(),
        agent: "property-agent".into(),
        valid_for_ms: 60_000,
        rules: vec![ToolRule {
            id: "writes".into(),
            tool: "write_file".into(),
            resource: ResourcePolicy::Argument {
                pointer: "/path".into(),
                prefix: "/workspace/".into(),
            },
            max_calls,
            payment: None,
        }],
    }
}

fn payment_policy(max_spend_atomic: u128, max_calls: u64) -> GuardPolicy {
    GuardPolicy {
        policy_version: 1,
        policy_epoch: 1,
        principal: "property-principal".into(),
        agent: "property-agent".into(),
        valid_for_ms: 60_000,
        rules: vec![ToolRule {
            id: "payments".into(),
            tool: "send_payment".into(),
            resource: ResourcePolicy::Literal {
                value: "urn:vendor".into(),
            },
            max_calls,
            payment: Some(PaymentPolicy {
                currency: "USD-CENTS".into(),
                amount_pointer: "/amount".into(),
                payee_pointer: "/payee".into(),
                max_spend_atomic,
                allowed_payees: vec!["vendor-a".into()],
            }),
        }],
    }
}

fn tool_call(id: u64, tool: &str, arguments: &Value) -> Value {
    json!({
        "jsonrpc":"2.0",
        "id":id,
        "method":"tools/call",
        "params":{"name":tool, "arguments":arguments}
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn call_allowance_is_monotonic(max_calls in 1_u64..32, attempts in 1_u64..64) {
        let mut guard = GuardEngine::new(
            call_policy(max_calls),
            SigningKey::from_bytes(&[42; 32]),
            NOW_MS,
        ).unwrap();
        let mut allowed = 0_u64;
        for id in 0..attempts {
            let receipt = guard.evaluate_json_rpc(
                &tool_call(id, "write_file", &json!({"path":format!("/workspace/{id}")})),
                NOW_MS,
            ).unwrap().unwrap();
            if receipt.receipt.decision == GuardDecision::Allowed {
                allowed += 1;
            }
            receipt.verify().unwrap();
        }
        prop_assert_eq!(allowed, attempts.min(max_calls));
    }

    #[test]
    fn cumulative_spend_never_exceeds_the_grant(
        limit in 1_u64..10_000,
        amounts in proptest::collection::vec(1_u64..2_000, 1..64),
    ) {
        let mut guard = GuardEngine::new(
            payment_policy(u128::from(limit), amounts.len() as u64 + 1),
            SigningKey::from_bytes(&[42; 32]),
            NOW_MS,
        ).unwrap();
        let mut spent = 0_u128;
        for (index, amount) in amounts.into_iter().enumerate() {
            let receipt = guard.evaluate_json_rpc(
                &tool_call(
                    index as u64,
                    "send_payment",
                    &json!({"amount":amount, "payee":"vendor-a"}),
                ),
                NOW_MS,
            ).unwrap().unwrap();
            if receipt.receipt.decision == GuardDecision::Allowed {
                spent += u128::from(amount);
            }
            prop_assert!(spent <= u128::from(limit));
        }
    }

    #[test]
    fn duplicate_requests_are_idempotent(id in 0_u64..1_000_000, content in "[a-z0-9]{0,64}") {
        let mut guard = GuardEngine::new(
            call_policy(2),
            SigningKey::from_bytes(&[42; 32]),
            NOW_MS,
        ).unwrap();
        let request = tool_call(id, "write_file", &json!({
            "path":"/workspace/file",
            "content":content,
        }));
        let first = guard.evaluate_json_rpc(&request, NOW_MS).unwrap().unwrap();
        let duplicate = guard.evaluate_json_rpc(&request, NOW_MS).unwrap().unwrap();
        prop_assert_eq!(&first.receipt.decision, &GuardDecision::Allowed);
        prop_assert_eq!(&duplicate.receipt.decision, &GuardDecision::Blocked);
        prop_assert!(duplicate.receipt.duplicate);
        let encoded = serde_json::to_vec(&duplicate).unwrap();
        let decoded = serde_json::from_slice::<scopepact_guard::SignedDecisionReceipt>(&encoded).unwrap();
        decoded.verify().unwrap();
        prop_assert_eq!(serde_json::to_value(decoded).unwrap(), serde_json::to_value(duplicate).unwrap());
    }
}
