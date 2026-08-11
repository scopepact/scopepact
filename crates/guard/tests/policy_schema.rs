use scopepact_guard::{GuardPolicy, validate_policy};
use serde_json::{Value, json};

fn schema() -> Value {
    serde_json::from_str(include_str!("../../../schemas/guard-policy-v1.schema.json")).unwrap()
}

fn example() -> Value {
    serde_json::from_str(include_str!("../../../examples/mcp-guard-policy.json")).unwrap()
}

fn set_value(document: &mut Value, pointer: &str, value: Value) {
    let (parent, field) = pointer.rsplit_once('/').unwrap();
    document
        .pointer_mut(parent)
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(field.to_owned(), value);
}

#[test]
fn schema_is_valid_and_accepts_the_shipped_example() {
    let schema = schema();
    jsonschema::draft202012::meta::validate(&schema).unwrap();
    jsonschema::draft202012::validate(&schema, &example()).unwrap();

    let policy: GuardPolicy = serde_json::from_value(example()).unwrap();
    validate_policy(&policy).unwrap();
}

#[test]
fn schema_rejects_unknown_missing_and_out_of_range_fields() {
    for mutate in [
        |policy: &mut Value| policy["unexpected"] = json!(true),
        |policy: &mut Value| policy["policy_version"] = json!(2),
        |policy: &mut Value| policy["policy_epoch"] = json!(0),
        |policy: &mut Value| policy["valid_for_ms"] = json!(2_678_400_001_i64),
        |policy: &mut Value| policy["rules"] = json!([]),
    ] {
        let mut policy = example();
        mutate(&mut policy);
        assert!(!jsonschema::draft202012::is_valid(&schema(), &policy));
    }

    let mut missing = example();
    missing.as_object_mut().unwrap().remove("principal");
    assert!(!jsonschema::draft202012::is_valid(&schema(), &missing));
}

#[test]
fn schema_rejects_malformed_rules_resources_and_payments() {
    let invalid_values = [
        ("/rules/0/unexpected", json!(true)),
        ("/rules/0/max_calls", json!(0)),
        ("/rules/0/resource/unexpected", json!(true)),
        ("/rules/0/resource/prefix", json!("/workspace/project")),
        ("/rules/1/payment/max_spend_atomic", json!(0)),
        ("/rules/1/payment/allowed_payees", json!([])),
    ];
    for (pointer, value) in invalid_values {
        let mut policy = example();
        set_value(&mut policy, pointer, value);
        assert!(
            !jsonschema::draft202012::is_valid(&schema(), &policy),
            "schema unexpectedly accepted mutation at {pointer}"
        );
    }
}
