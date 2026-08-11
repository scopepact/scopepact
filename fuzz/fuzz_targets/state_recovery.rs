#![no_main]

use std::fs;

use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use scopepact_guard::state::DurableState;
use scopepact_guard::{GuardPolicy, ResourcePolicy, ToolRule, signer_key_id};

fuzz_target!(|data: &[u8]| {
    let split = data
        .first()
        .map_or(0, |value| usize::from(*value) * data.len() / 255);
    let Ok(directory) = tempfile::tempdir() else {
        return;
    };
    let journal = directory.path().join("state.jsonl");
    let head = directory.path().join("state.jsonl.head");
    if fs::write(&journal, &data[..split]).is_err() || fs::write(&head, &data[split..]).is_err() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = fs::set_permissions(&journal, fs::Permissions::from_mode(0o600));
        let _ = fs::set_permissions(&head, fs::Permissions::from_mode(0o600));
    }
    let policy = GuardPolicy {
        policy_version: 1,
        policy_epoch: 1,
        principal: "fuzz-principal".into(),
        agent: "fuzz-agent".into(),
        valid_for_ms: 60_000,
        rules: vec![ToolRule {
            id: "fuzz-rule".into(),
            tool: "fuzz-tool".into(),
            resource: ResourcePolicy::Literal {
                value: "urn:fuzz".into(),
            },
            max_calls: 1,
            payment: None,
        }],
    };
    let key = SigningKey::from_bytes(&[42; 32]);
    let _ = DurableState::open(
        &journal,
        &policy,
        &hex::encode(key.verifying_key().as_bytes()),
        &hex::encode(signer_key_id(&key).0),
        1_000_000,
    );
});
