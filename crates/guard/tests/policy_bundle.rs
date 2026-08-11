use ed25519_dalek::SigningKey;
use scopepact_guard::policy_bundle::{
    PolicyBundleSigningRequest, PolicyIssuerStatus, PolicyIssuerTrust, TrustedPolicyIssuer,
    sign_policy_bundle, verify_policy_bundle,
};
use scopepact_guard::{
    GuardDecision, GuardEngine, GuardPolicy, ResourcePolicy, ToolRule, signer_key_id,
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

fn issuer_trust(key: &SigningKey) -> PolicyIssuerTrust {
    PolicyIssuerTrust::pinned(
        "guard:local-development".into(),
        "scopepact-demo-policy-issuer".into(),
        hex::encode(key.verifying_key().as_bytes()),
        hex::encode(signer_key_id(key).0),
        NOW_MS - 1_000,
        None,
    )
    .unwrap()
}

#[test]
fn verified_bundle_activates_explicit_revocations() {
    let issuer = SigningKey::from_bytes(&[11; 32]);
    let signed = sign_policy_bundle(
        PolicyBundleSigningRequest {
            policy: policy(),
            issuer: "scopepact-demo-policy-issuer".into(),
            audience: "guard:local-development".into(),
            issued_at_ms: NOW_MS,
            not_before_ms: NOW_MS,
            expires_at_ms: NOW_MS + 60_000,
            revoked_rule_ids: vec!["project-files".into()],
        },
        &issuer,
    )
    .unwrap();
    let verified = verify_policy_bundle(
        &signed,
        &issuer_trust(&issuer),
        "guard:local-development",
        NOW_MS,
    )
    .unwrap();
    assert!(verified.revoked_rule_ids.contains("project-files"));

    let receipt_key = SigningKey::from_bytes(&[42; 32]);
    let mut engine = GuardEngine::new_with_signer_and_revocations(
        verified.policy,
        Box::new(receipt_key),
        verified.activated_at_ms,
        &verified.revoked_rule_ids,
    )
    .unwrap();
    let receipt = engine
        .evaluate_json_rpc(&tool_call(), NOW_MS)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.receipt.decision, GuardDecision::Blocked);
    assert_eq!(receipt.receipt.reason, "tool is not granted");
}

#[test]
fn tamper_wrong_audience_and_expiry_fail_closed() {
    let issuer = SigningKey::from_bytes(&[11; 32]);
    let signed = sign_policy_bundle(
        PolicyBundleSigningRequest {
            policy: policy(),
            issuer: "scopepact-demo-policy-issuer".into(),
            audience: "guard:local-development".into(),
            issued_at_ms: NOW_MS,
            not_before_ms: NOW_MS,
            expires_at_ms: NOW_MS + 60_000,
            revoked_rule_ids: Vec::new(),
        },
        &issuer,
    )
    .unwrap();
    let trust = issuer_trust(&issuer);

    let wrong_audience = verify_policy_bundle(&signed, &trust, "guard:production", NOW_MS)
        .expect_err("wrong audience should fail");
    assert!(wrong_audience.to_string().contains("audience"));

    let expired = verify_policy_bundle(
        &signed,
        &trust,
        "guard:local-development",
        NOW_MS + 60_000 + 5 * 60_000 + 1,
    )
    .expect_err("expired bundle should fail");
    assert!(expired.to_string().contains("not currently active"));

    let mut tampered = signed.clone();
    tampered.bundle.policy.rules[0].max_calls += 1;
    let error = verify_policy_bundle(&tampered, &trust, "guard:local-development", NOW_MS)
        .expect_err("tampered policy should fail");
    assert!(error.to_string().contains("content digest"));
}

#[test]
fn invalid_revocation_and_untrusted_issuer_are_rejected() {
    let issuer = SigningKey::from_bytes(&[11; 32]);
    assert!(
        sign_policy_bundle(
            PolicyBundleSigningRequest {
                policy: policy(),
                issuer: "scopepact-demo-policy-issuer".into(),
                audience: "guard:local-development".into(),
                issued_at_ms: NOW_MS,
                not_before_ms: NOW_MS,
                expires_at_ms: NOW_MS + 60_000,
                revoked_rule_ids: vec!["missing-rule".into()],
            },
            &issuer,
        )
        .is_err()
    );

    let signed = sign_policy_bundle(
        PolicyBundleSigningRequest {
            policy: policy(),
            issuer: "scopepact-demo-policy-issuer".into(),
            audience: "guard:local-development".into(),
            issued_at_ms: NOW_MS,
            not_before_ms: NOW_MS,
            expires_at_ms: NOW_MS + 60_000,
            revoked_rule_ids: Vec::new(),
        },
        &issuer,
    )
    .unwrap();
    let other = SigningKey::from_bytes(&[12; 32]);
    let error = verify_policy_bundle(
        &signed,
        &issuer_trust(&other),
        "guard:local-development",
        NOW_MS,
    )
    .expect_err("untrusted issuer should fail");
    assert!(error.to_string().contains("not trusted"));
}

#[test]
fn malformed_or_ambiguous_issuer_trust_is_rejected() {
    let issuer = SigningKey::from_bytes(&[11; 32]);
    let signed = sign_policy_bundle(
        PolicyBundleSigningRequest {
            policy: policy(),
            issuer: "scopepact-demo-policy-issuer".into(),
            audience: "guard:local-development".into(),
            issued_at_ms: NOW_MS,
            not_before_ms: NOW_MS,
            expires_at_ms: NOW_MS + 60_000,
            revoked_rule_ids: Vec::new(),
        },
        &issuer,
    )
    .unwrap();

    let mut duplicate = issuer_trust(&issuer);
    duplicate.issuers.push(duplicate.issuers[0].clone());
    let error = verify_policy_bundle(&signed, &duplicate, "guard:local-development", NOW_MS)
        .expect_err("duplicate trust identity should fail");
    assert!(error.to_string().contains("duplicate issuer/key"));

    let key_id = hex::encode(signer_key_id(&issuer).0);
    let public_key = hex::encode(issuer.verifying_key().as_bytes());
    let oversized = PolicyIssuerTrust {
        format: "scopepact-policy-issuer-trust-v1".into(),
        audience: "guard:local-development".into(),
        issuers: (0..65)
            .map(|index| TrustedPolicyIssuer {
                issuer: format!("issuer-{index}"),
                public_key: public_key.clone(),
                key_id: key_id.clone(),
                not_before_ms: NOW_MS - 1,
                not_after_ms: None,
                status: PolicyIssuerStatus::Active,
            })
            .collect(),
    };
    let error = verify_policy_bundle(&signed, &oversized, "guard:local-development", NOW_MS)
        .expect_err("oversized trust list should fail");
    assert!(error.to_string().contains("1 to 64 issuers"));
}
