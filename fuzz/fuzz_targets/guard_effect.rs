#![no_main]

use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use scopepact_guard::{GuardEngine, GuardPolicy, PaymentPolicy, ResourcePolicy, ToolRule};
use serde_json::json;

fuzz_target!(|data: &[u8]| {
    let sample = &data[..data.len().min(512)];
    let selector = sample.first().copied().unwrap_or_default() % 3;
    let suffix = hex::encode(sample);
    let path = match selector {
        0 => format!("/workspace/{suffix}"),
        1 => format!("/workspace/../{suffix}"),
        _ => String::from_utf8_lossy(sample).into_owned(),
    };
    let policy = GuardPolicy {
        policy_version: 1,
        policy_epoch: 1,
        principal: "fuzz-principal".into(),
        agent: "fuzz-agent".into(),
        valid_for_ms: 60_000,
        rules: vec![
            ToolRule {
                id: "files".into(),
                tool: "write_file".into(),
                resource: ResourcePolicy::Argument {
                    pointer: "/path".into(),
                    prefix: "/workspace/".into(),
                },
                max_calls: 2,
                payment: None,
            },
            ToolRule {
                id: "payments".into(),
                tool: "send_payment".into(),
                resource: ResourcePolicy::Literal {
                    value: "urn:fuzz:vendor".into(),
                },
                max_calls: 2,
                payment: Some(PaymentPolicy {
                    currency: "FUZZ".into(),
                    amount_pointer: "/amount".into(),
                    payee_pointer: "/payee".into(),
                    max_spend_atomic: 255,
                    allowed_payees: vec!["vendor".into()],
                }),
            },
        ],
    };
    let Ok(mut guard) = GuardEngine::new(policy, SigningKey::from_bytes(&[42; 32]), 1_000_000)
    else {
        return;
    };
    let id = u64::from(sample.get(1).copied().unwrap_or_default());
    let write = json!({
        "jsonrpc":"2.0",
        "id":id,
        "method":"tools/call",
        "params":{"name":"write_file", "arguments":{"path":path, "content":suffix}}
    });
    if let Ok(Some(receipt)) = guard.evaluate_json_rpc(&write, 1_000_001) {
        let _ = receipt.verify();
    }
    let conflicting = json!({
        "jsonrpc":"2.0",
        "id":id,
        "method":"tools/call",
        "params":{"name":"write_file", "arguments":{"path":"/workspace/conflict"}}
    });
    if let Ok(Some(receipt)) = guard.evaluate_json_rpc(&conflicting, 1_000_002) {
        let _ = receipt.verify();
    }
    let amount = u64::from(sample.get(2).copied().unwrap_or(1));
    let payee = if selector == 0 { "vendor" } else { "other" };
    let payment = json!({
        "jsonrpc":"2.0",
        "id":format!("payment-{id}"),
        "method":"tools/call",
        "params":{"name":"send_payment", "arguments":{"amount":amount, "payee":payee}}
    });
    if let Ok(Some(receipt)) = guard.evaluate_json_rpc(&payment, 1_000_003) {
        let _ = receipt.verify();
    }
});
