use ed25519_dalek::SigningKey;
use scopepact_guard::{GuardEngine, GuardPolicy, SignedDecisionReceipt};
use serde_json::Value;

#[test]
fn rust_reproduces_the_portable_guard_receipt_vector() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../conformance/vectors/guard-receipt-v1.json"
    ))
    .unwrap();
    let policy: GuardPolicy = serde_json::from_value(vector["policy"].clone()).unwrap();
    let seed: [u8; 32] = hex::decode(vector["signing_seed_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let actual = GuardEngine::new(policy, SigningKey::from_bytes(&seed), 1_000_000)
        .unwrap()
        .evaluate_json_rpc(
            &vector["request"],
            vector["evaluated_at_ms"].as_i64().unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(&actual).unwrap(),
        vector["signed_receipt"]
    );
    actual.verify().unwrap();

    let mut tampered: SignedDecisionReceipt =
        serde_json::from_value(vector["signed_receipt"].clone()).unwrap();
    tampered.receipt.resource = Some("/workspace/project/other.txt".into());
    assert!(tampered.verify().is_err());
}
