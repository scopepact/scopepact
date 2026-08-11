use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;
use scopepact_guard::policy_bundle::{
    PolicyBundleSigningRequest, PolicyIssuerTrust, VerifiedPolicyBundle, sign_policy_bundle,
    verify_policy_bundle,
};
use scopepact_guard::state::{DurableState, SignerStatus, verify_receipt_with_trust};
use scopepact_guard::{
    GuardDecision, GuardEngine, GuardPolicy, PaymentPolicy, ResourcePolicy, ToolRule, signer_key_id,
};
use serde_json::{Value, json};

const NOW_MS: i64 = 1_000_000;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "scopepact-guard-state-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn join(&self, path: &str) -> PathBuf {
        self.0.join(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

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

fn tool_call(id: u64, tool: &str, arguments: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments}
    })
}

fn key_id(key: &SigningKey) -> String {
    hex::encode(signer_key_id(key).0)
}

fn public_key(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().as_bytes())
}

fn head_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap().to_os_string();
    name.push(".head");
    path.with_file_name(name)
}

fn truncate_last_complete_line(path: &Path) {
    let bytes = fs::read(path).unwrap();
    assert_eq!(bytes.last(), Some(&b'\n'));
    let previous_newline = bytes[..bytes.len() - 1]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .unwrap();
    OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_len(u64::try_from(previous_newline + 1).unwrap())
        .unwrap();
}

fn verified_policy(
    policy: GuardPolicy,
    issuer: &SigningKey,
    now_ms: i64,
    revoked_rule_ids: Vec<String>,
) -> VerifiedPolicyBundle {
    let trust = PolicyIssuerTrust::pinned(
        "guard:test".into(),
        "test-policy-issuer".into(),
        public_key(issuer),
        key_id(issuer),
        NOW_MS - 1,
        None,
    )
    .unwrap();
    let expires_at_ms = now_ms + policy.valid_for_ms;
    let signed = sign_policy_bundle(
        PolicyBundleSigningRequest {
            policy,
            issuer: "test-policy-issuer".into(),
            audience: "guard:test".into(),
            issued_at_ms: now_ms,
            not_before_ms: now_ms,
            expires_at_ms,
            revoked_rule_ids,
        },
        issuer,
    )
    .unwrap();
    verify_policy_bundle(&signed, &trust, "guard:test", now_ms).unwrap()
}

fn open_engine(
    path: &Path,
    policy: GuardPolicy,
    key: &SigningKey,
    now_ms: i64,
) -> (DurableState, GuardEngine) {
    let (state, recovered) =
        DurableState::open(path, &policy, &public_key(key), &key_id(key), now_ms).unwrap();
    let mut engine = GuardEngine::new(policy, key.clone(), recovered.activated_at_ms).unwrap();
    for commitment in &recovered.commitments {
        engine.restore_commitment(commitment).unwrap();
    }
    (state, engine)
}

#[test]
fn committed_effect_is_suppressed_after_restart() {
    let directory = TestDirectory::new();
    let path = directory.join("state.jsonl");
    let key = SigningKey::from_bytes(&[42; 32]);
    let request = tool_call(
        9,
        "write_file",
        &json!({"path": "/workspace/project/a", "content": "one"}),
    );

    let (mut state, mut engine) = open_engine(&path, policy(), &key, NOW_MS);
    let first = engine
        .evaluate_json_rpc_transactional(&request, NOW_MS)
        .unwrap()
        .unwrap();
    assert_eq!(first.receipt.receipt.decision, GuardDecision::Allowed);
    state.commit(&first).unwrap();
    drop(state);

    let (state, mut engine) = open_engine(&path, policy(), &key, NOW_MS + 1_000);
    let duplicate = engine
        .evaluate_json_rpc_transactional(&request, NOW_MS + 1_000)
        .unwrap()
        .unwrap();
    assert_eq!(duplicate.receipt.receipt.decision, GuardDecision::Blocked);
    assert!(duplicate.receipt.receipt.duplicate);
    drop(state);
}

#[test]
fn payment_and_call_budgets_survive_restart() {
    let directory = TestDirectory::new();
    let path = directory.join("state.jsonl");
    let key = SigningKey::from_bytes(&[42; 32]);

    let (mut state, mut engine) = open_engine(&path, policy(), &key, NOW_MS);
    let first = engine
        .evaluate_json_rpc_transactional(
            &tool_call(
                1,
                "send_payment",
                &json!({"amount_cents": 200, "payee": "vendor-a"}),
            ),
            NOW_MS,
        )
        .unwrap()
        .unwrap();
    state.commit(&first).unwrap();
    drop(state);

    let (mut state, mut engine) = open_engine(&path, policy(), &key, NOW_MS + 1_000);
    let second = engine
        .evaluate_json_rpc_transactional(
            &tool_call(
                2,
                "send_payment",
                &json!({"amount_cents": 300, "payee": "vendor-a"}),
            ),
            NOW_MS + 1_000,
        )
        .unwrap()
        .unwrap();
    assert_eq!(second.receipt.receipt.decision, GuardDecision::Allowed);
    state.commit(&second).unwrap();
    drop(state);

    let (state, mut engine) = open_engine(&path, policy(), &key, NOW_MS + 2_000);
    let exhausted = engine
        .evaluate_json_rpc_transactional(
            &tool_call(
                3,
                "send_payment",
                &json!({"amount_cents": 1, "payee": "vendor-a"}),
            ),
            NOW_MS + 2_000,
        )
        .unwrap()
        .unwrap();
    assert_eq!(exhausted.receipt.receipt.decision, GuardDecision::Blocked);
    assert!(
        exhausted
            .receipt
            .receipt
            .reason
            .contains("call allowance exhausted")
    );
    drop(state);
}

#[test]
fn stopped_backup_and_restore_preserve_duplicate_suppression() {
    let directory = TestDirectory::new();
    let live_path = directory.join("live-state.jsonl");
    let restored_path = directory.join("restored-state.jsonl");
    let key = SigningKey::from_bytes(&[42; 32]);
    let request = tool_call(
        9,
        "write_file",
        &json!({"path": "/workspace/project/a", "content": "one"}),
    );
    let (mut state, mut engine) = open_engine(&live_path, policy(), &key, NOW_MS);
    let evaluation = engine
        .evaluate_json_rpc_transactional(&request, NOW_MS)
        .unwrap()
        .unwrap();
    state.commit(&evaluation).unwrap();
    drop(state);

    fs::copy(&live_path, &restored_path).unwrap();
    fs::copy(head_path(&live_path), head_path(&restored_path)).unwrap();
    let (state, mut restored_engine) = open_engine(&restored_path, policy(), &key, NOW_MS + 1);
    let duplicate = restored_engine
        .evaluate_json_rpc_transactional(&request, NOW_MS + 1)
        .unwrap()
        .unwrap();
    assert_eq!(duplicate.receipt.receipt.decision, GuardDecision::Blocked);
    assert!(duplicate.receipt.receipt.duplicate);
    drop(state);
}

#[test]
fn concurrent_writer_is_rejected() {
    let directory = TestDirectory::new();
    let path = directory.join("state.jsonl");
    let key = SigningKey::from_bytes(&[42; 32]);
    let (state, _) = open_engine(&path, policy(), &key, NOW_MS);

    let error = DurableState::open(&path, &policy(), &public_key(&key), &key_id(&key), NOW_MS)
        .err()
        .expect("second writer should fail");
    assert!(error.to_string().contains("exclusively lock"));
    drop(state);
}

#[test]
fn policy_and_signer_mismatch_fail_closed() {
    let directory = TestDirectory::new();
    let path = directory.join("state.jsonl");
    let key = SigningKey::from_bytes(&[42; 32]);
    let (state, _) = open_engine(&path, policy(), &key, NOW_MS);
    drop(state);

    let mut changed_policy = policy();
    changed_policy.rules[0].max_calls += 1;
    let policy_error = DurableState::open(
        &path,
        &changed_policy,
        &public_key(&key),
        &key_id(&key),
        NOW_MS,
    )
    .err()
    .expect("changed policy should fail");
    assert!(policy_error.to_string().contains("policy does not match"));

    let other_key = SigningKey::from_bytes(&[43; 32]);
    let signer_error = DurableState::open(
        &path,
        &policy(),
        &public_key(&other_key),
        &key_id(&other_key),
        NOW_MS,
    )
    .err()
    .expect("changed signer should fail");
    assert!(signer_error.to_string().contains("signer does not match"));
}

#[test]
fn corrupted_journal_fails_closed() {
    let directory = TestDirectory::new();
    let path = directory.join("state.jsonl");
    let key = SigningKey::from_bytes(&[42; 32]);
    let (state, _) = open_engine(&path, policy(), &key, NOW_MS);
    drop(state);

    let mut journal = OpenOptions::new().append(true).open(&path).unwrap();
    journal.write_all(b"{\"partial\":true}").unwrap();
    journal.sync_all().unwrap();

    let error = DurableState::open(&path, &policy(), &public_key(&key), &key_id(&key), NOW_MS)
        .err()
        .expect("corrupt journal should fail");
    assert!(error.to_string().contains("partial trailing record"));

    let recovery =
        DurableState::recover_partial_tail(&path, &policy(), &public_key(&key), &key_id(&key))
            .unwrap();
    assert_eq!(recovery.journal_bytes_removed, 16);
    assert_eq!(recovery.head_bytes_removed, 0);

    let (state, _) = open_engine(&path, policy(), &key, NOW_MS);
    drop(state);
}

#[test]
fn journal_ahead_of_head_is_repaired_after_commit_crash() {
    let directory = TestDirectory::new();
    let path = directory.join("state.jsonl");
    let key = SigningKey::from_bytes(&[42; 32]);
    let (mut state, mut engine) = open_engine(&path, policy(), &key, NOW_MS);
    let evaluation = engine
        .evaluate_json_rpc_transactional(
            &tool_call(
                1,
                "write_file",
                &json!({"path": "/workspace/project/a", "content": "one"}),
            ),
            NOW_MS,
        )
        .unwrap()
        .unwrap();
    state.commit(&evaluation).unwrap();
    drop(state);

    let head = head_path(&path);
    truncate_last_complete_line(&head);
    let (state, _) = open_engine(&path, policy(), &key, NOW_MS + 1);
    drop(state);
    assert_eq!(
        fs::read_to_string(&path).unwrap().lines().count(),
        fs::read_to_string(&head).unwrap().lines().count()
    );
}

#[test]
fn journal_genesis_with_empty_head_recovers_initialization_crash() {
    let directory = TestDirectory::new();
    let path = directory.join("state.jsonl");
    let key = SigningKey::from_bytes(&[42; 32]);
    let (state, _) = open_engine(&path, policy(), &key, NOW_MS);
    drop(state);

    let head = head_path(&path);
    OpenOptions::new()
        .write(true)
        .open(&head)
        .unwrap()
        .set_len(0)
        .unwrap();
    let (state, _) = open_engine(&path, policy(), &key, NOW_MS + 1);
    assert_eq!(state.sequence(), 0);
    drop(state);
    assert_eq!(fs::read_to_string(&head).unwrap().lines().count(), 1);
}

#[test]
fn multiple_missing_head_records_are_rebuilt_from_validated_journal() {
    let directory = TestDirectory::new();
    let path = directory.join("state.jsonl");
    let key = SigningKey::from_bytes(&[42; 32]);
    let (mut state, mut engine) = open_engine(&path, policy(), &key, NOW_MS);
    for (id, name) in [(1, "a"), (2, "b")] {
        let evaluation = engine
            .evaluate_json_rpc_transactional(
                &tool_call(
                    id,
                    "write_file",
                    &json!({"path": format!("/workspace/project/{name}"), "content": name}),
                ),
                NOW_MS + i64::try_from(id).unwrap(),
            )
            .unwrap()
            .unwrap();
        state.commit(&evaluation).unwrap();
    }
    drop(state);

    let head = head_path(&path);
    let first_line_bytes = fs::read(&head)
        .unwrap()
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap()
        + 1;
    OpenOptions::new()
        .write(true)
        .open(&head)
        .unwrap()
        .set_len(u64::try_from(first_line_bytes).unwrap())
        .unwrap();

    let (state, mut engine) = open_engine(&path, policy(), &key, NOW_MS + 10);
    assert_eq!(state.sequence(), 2);
    let duplicate = engine
        .evaluate_json_rpc_transactional(
            &tool_call(
                2,
                "write_file",
                &json!({"path": "/workspace/project/b", "content": "b"}),
            ),
            NOW_MS + 10,
        )
        .unwrap()
        .unwrap();
    assert!(duplicate.receipt.receipt.duplicate);
    drop(state);
    assert_eq!(
        fs::read_to_string(&path).unwrap().lines().count(),
        fs::read_to_string(&head).unwrap().lines().count()
    );
}

#[test]
fn partial_head_tail_recovery_preserves_committed_effect() {
    let directory = TestDirectory::new();
    let path = directory.join("state.jsonl");
    let key = SigningKey::from_bytes(&[42; 32]);
    let request = tool_call(
        1,
        "write_file",
        &json!({"path": "/workspace/project/a", "content": "one"}),
    );
    let (mut state, mut engine) = open_engine(&path, policy(), &key, NOW_MS);
    let evaluation = engine
        .evaluate_json_rpc_transactional(&request, NOW_MS + 1)
        .unwrap()
        .unwrap();
    state.commit(&evaluation).unwrap();
    drop(state);

    let head = head_path(&path);
    truncate_last_complete_line(&head);
    let mut head_file = OpenOptions::new().append(true).open(&head).unwrap();
    head_file.write_all(b"{\"partial\":true}").unwrap();
    head_file.sync_all().unwrap();
    let error = DurableState::open(
        &path,
        &policy(),
        &public_key(&key),
        &key_id(&key),
        NOW_MS + 2,
    )
    .err()
    .expect("partial head must fail closed");
    assert!(error.to_string().contains("partial trailing record"));

    let recovery =
        DurableState::recover_partial_tail(&path, &policy(), &public_key(&key), &key_id(&key))
            .unwrap();
    assert_eq!(recovery.journal_bytes_removed, 0);
    assert_eq!(recovery.head_bytes_removed, 16);
    let (state, mut engine) = open_engine(&path, policy(), &key, NOW_MS + 3);
    let duplicate = engine
        .evaluate_json_rpc_transactional(&request, NOW_MS + 3)
        .unwrap()
        .unwrap();
    assert!(duplicate.receipt.receipt.duplicate);
    drop(state);
}

#[cfg(unix)]
#[test]
fn insecure_permissions_and_symlink_state_paths_fail_closed() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let directory = TestDirectory::new();
    let path = directory.join("state.jsonl");
    let key = SigningKey::from_bytes(&[42; 32]);
    let (state, _) = open_engine(&path, policy(), &key, NOW_MS);
    drop(state);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let error = DurableState::open(
        &path,
        &policy(),
        &public_key(&key),
        &key_id(&key),
        NOW_MS + 1,
    )
    .err()
    .expect("group-readable state must fail");
    assert!(error.to_string().contains("permissions must not grant"));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    let head = head_path(&path);
    fs::set_permissions(&head, fs::Permissions::from_mode(0o640)).unwrap();
    let error = DurableState::open(
        &path,
        &policy(),
        &public_key(&key),
        &key_id(&key),
        NOW_MS + 2,
    )
    .err()
    .expect("group-readable head must fail");
    assert!(error.to_string().contains("permissions must not grant"));
    fs::set_permissions(&head, fs::Permissions::from_mode(0o600)).unwrap();

    let linked = directory.join("linked-state.jsonl");
    symlink(&path, &linked).unwrap();
    let error = DurableState::open(
        &linked,
        &policy(),
        &public_key(&key),
        &key_id(&key),
        NOW_MS + 3,
    )
    .err()
    .expect("symlink state must fail");
    assert!(error.to_string().contains("cannot open"));
}

#[test]
fn head_ahead_of_journal_fails_closed_after_commit_crash() {
    let directory = TestDirectory::new();
    let path = directory.join("state.jsonl");
    let key = SigningKey::from_bytes(&[42; 32]);
    let (mut state, mut engine) = open_engine(&path, policy(), &key, NOW_MS);
    let evaluation = engine
        .evaluate_json_rpc_transactional(
            &tool_call(
                1,
                "write_file",
                &json!({"path": "/workspace/project/a", "content": "one"}),
            ),
            NOW_MS,
        )
        .unwrap()
        .unwrap();
    state.commit(&evaluation).unwrap();
    drop(state);

    truncate_last_complete_line(&path);
    let error = DurableState::open(
        &path,
        &policy(),
        &public_key(&key),
        &key_id(&key),
        NOW_MS + 1,
    )
    .err()
    .expect("head-ahead state must fail closed");
    assert!(error.to_string().contains("head log is ahead"));
}

#[test]
fn cross_signed_rotation_preserves_historical_receipt_trust() {
    let directory = TestDirectory::new();
    let path = directory.join("state.jsonl");
    let old_key = SigningKey::from_bytes(&[42; 32]);
    let new_key = SigningKey::from_bytes(&[43; 32]);
    let (mut state, mut engine) = open_engine(&path, policy(), &old_key, NOW_MS);
    let old_evaluation = engine
        .evaluate_json_rpc_transactional(
            &tool_call(
                1,
                "write_file",
                &json!({"path": "/workspace/project/a", "content": "one"}),
            ),
            NOW_MS,
        )
        .unwrap()
        .unwrap();
    let old_receipt = old_evaluation.receipt.clone();
    state.commit(&old_evaluation).unwrap();
    state
        .rotate_signer(&old_key, &new_key, NOW_MS + 100)
        .unwrap();
    drop(state);

    let old_error = DurableState::open(
        &path,
        &policy(),
        &public_key(&old_key),
        &key_id(&old_key),
        NOW_MS + 200,
    )
    .err()
    .expect("retired signer should not reopen the journal");
    assert!(old_error.to_string().contains("active signer"));

    let (mut state, mut engine) = open_engine(&path, policy(), &new_key, NOW_MS + 200);
    let new_evaluation = engine
        .evaluate_json_rpc_transactional(
            &tool_call(
                2,
                "write_file",
                &json!({"path": "/workspace/project/b", "content": "two"}),
            ),
            NOW_MS + 200,
        )
        .unwrap()
        .unwrap();
    let new_receipt = new_evaluation.receipt.clone();
    state.commit(&new_evaluation).unwrap();
    let trust = state.signer_trust();
    assert_eq!(trust.keys.len(), 2);
    assert_eq!(trust.keys[0].status, SignerStatus::Retired);
    assert_eq!(trust.keys[1].status, SignerStatus::Active);
    verify_receipt_with_trust(&old_receipt, trust).unwrap();
    verify_receipt_with_trust(&new_receipt, trust).unwrap();
}

#[test]
fn revoked_signer_status_rejects_an_otherwise_valid_receipt() {
    let directory = TestDirectory::new();
    let path = directory.join("state.jsonl");
    let old_key = SigningKey::from_bytes(&[42; 32]);
    let new_key = SigningKey::from_bytes(&[43; 32]);
    let (mut state, mut engine) = open_engine(&path, policy(), &old_key, NOW_MS);
    let evaluation = engine
        .evaluate_json_rpc_transactional(
            &tool_call(
                1,
                "write_file",
                &json!({"path": "/workspace/project/a", "content": "one"}),
            ),
            NOW_MS,
        )
        .unwrap()
        .unwrap();
    let receipt = evaluation.receipt.clone();
    state.commit(&evaluation).unwrap();
    state
        .rotate_signer(&old_key, &new_key, NOW_MS + 100)
        .unwrap();
    let mut compromised_trust = state.signer_trust().clone();
    compromised_trust.keys[0].status = SignerStatus::Revoked;

    let error = verify_receipt_with_trust(&receipt, &compromised_trust).unwrap_err();
    assert!(error.to_string().contains("revoked"));
}

#[test]
fn signed_policy_activation_is_monotonic_and_preserves_history() {
    let directory = TestDirectory::new();
    let path = directory.join("state.jsonl");
    let receipt_key = SigningKey::from_bytes(&[42; 32]);
    let issuer = SigningKey::from_bytes(&[11; 32]);
    let initial = verified_policy(policy(), &issuer, NOW_MS, Vec::new());
    let (mut state, recovered) = DurableState::open_verified(
        &path,
        &initial,
        &public_key(&receipt_key),
        &key_id(&receipt_key),
        NOW_MS,
    )
    .unwrap();
    let mut engine = GuardEngine::new_with_signer_and_revocations(
        initial.policy.clone(),
        Box::new(receipt_key.clone()),
        recovered.activated_at_ms,
        &initial.revoked_rule_ids,
    )
    .unwrap();
    let request = tool_call(
        9,
        "write_file",
        &json!({"path": "/workspace/project/a", "content": "one"}),
    );
    let old_evaluation = engine
        .evaluate_json_rpc_transactional(&request, NOW_MS)
        .unwrap()
        .unwrap();
    let old_receipt = old_evaluation.receipt.clone();
    state.commit(&old_evaluation).unwrap();

    let mut next_policy = policy();
    next_policy.policy_epoch = 8;
    let next = verified_policy(next_policy, &issuer, NOW_MS + 100, Vec::new());
    state
        .activate_policy(&next, &receipt_key, NOW_MS + 100)
        .unwrap();
    assert_eq!(state.signer_trust().policies.len(), 2);
    verify_receipt_with_trust(&old_receipt, state.signer_trust()).unwrap();

    let rollback_error = state
        .activate_policy(&initial, &receipt_key, NOW_MS + 200)
        .unwrap_err();
    assert!(rollback_error.to_string().contains("greater"));
    drop(state);

    let old_bundle_error = DurableState::open_verified(
        &path,
        &initial,
        &public_key(&receipt_key),
        &key_id(&receipt_key),
        NOW_MS + 200,
    )
    .err()
    .expect("old policy bundle should be rejected after activation");
    assert!(
        old_bundle_error
            .to_string()
            .contains("active signed bundle")
    );

    let (mut state, recovered) = DurableState::open_verified(
        &path,
        &next,
        &public_key(&receipt_key),
        &key_id(&receipt_key),
        NOW_MS + 200,
    )
    .unwrap();
    assert!(recovered.commitments.is_empty());
    let mut engine = GuardEngine::new_with_signer_and_revocations(
        next.policy.clone(),
        Box::new(receipt_key),
        recovered.activated_at_ms,
        &next.revoked_rule_ids,
    )
    .unwrap();
    let new_evaluation = engine
        .evaluate_json_rpc_transactional(&request, NOW_MS + 200)
        .unwrap()
        .unwrap();
    assert_eq!(
        new_evaluation.receipt.receipt.decision,
        GuardDecision::Allowed
    );
    let new_receipt = new_evaluation.receipt.clone();
    state.commit(&new_evaluation).unwrap();
    verify_receipt_with_trust(&old_receipt, state.signer_trust()).unwrap();
    verify_receipt_with_trust(&new_receipt, state.signer_trust()).unwrap();
}

#[test]
fn durable_state_binds_the_exact_revocation_set() {
    let directory = TestDirectory::new();
    let path = directory.join("state.jsonl");
    let receipt_key = SigningKey::from_bytes(&[42; 32]);
    let issuer = SigningKey::from_bytes(&[11; 32]);
    let initial = verified_policy(policy(), &issuer, NOW_MS, Vec::new());
    let (state, _) = DurableState::open_verified(
        &path,
        &initial,
        &public_key(&receipt_key),
        &key_id(&receipt_key),
        NOW_MS,
    )
    .unwrap();
    drop(state);

    let revoked = verified_policy(policy(), &issuer, NOW_MS, vec!["project-files".into()]);
    let error = DurableState::open_verified(
        &path,
        &revoked,
        &public_key(&receipt_key),
        &key_id(&receipt_key),
        NOW_MS,
    )
    .err()
    .expect("a changed revocation set should be rejected");
    assert!(error.to_string().contains("active signed bundle"));
}
