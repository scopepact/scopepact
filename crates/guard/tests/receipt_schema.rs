use serde_json::{Value, json};

fn schema() -> Value {
    serde_json::from_str(include_str!(
        "../../../schemas/guard-receipt-v1.schema.json"
    ))
    .unwrap()
}

fn receipt() -> Value {
    serde_json::from_str(include_str!(
        "../../../conformance/vectors/guard-receipt-v1.json"
    ))
    .unwrap()
}

#[test]
fn receipt_schema_is_valid_and_accepts_the_portable_vector() {
    let schema = schema();
    jsonschema::draft202012::meta::validate(&schema).unwrap();
    jsonschema::draft202012::validate(&schema, &receipt()["signed_receipt"]).unwrap();
}

#[test]
fn receipt_schema_rejects_unknown_fields_bad_lengths_and_unsafe_ids() {
    let mut unknown = receipt()["signed_receipt"].clone();
    unknown["receipt"]["unexpected"] = json!(true);
    assert!(!jsonschema::draft202012::is_valid(&schema(), &unknown));

    let mut bad_signature = receipt()["signed_receipt"].clone();
    bad_signature["signature"] = json!("00");
    assert!(!jsonschema::draft202012::is_valid(
        &schema(),
        &bad_signature
    ));

    let mut unsafe_id = receipt()["signed_receipt"].clone();
    unsafe_id["receipt"]["request_id"] = json!(9_007_199_254_740_992_u64);
    assert!(!jsonschema::draft202012::is_valid(&schema(), &unsafe_id));
}
