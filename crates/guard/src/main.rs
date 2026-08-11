use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex, Weak, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use scopepact_guard::key_provider::{generate_protected_key, load_protected_key};
use scopepact_guard::mcp::{
    ConnectionTracker, Direction, ForwardDisposition, MessageClass, classify_message,
};
use scopepact_guard::policy_bundle::{
    PolicyBundleSigningRequest, PolicyIssuerTrust, SignedPolicyBundle, VerifiedPolicyBundle,
    sign_policy_bundle, verify_policy_bundle,
};
use scopepact_guard::state::{DurableState, SignerTrustBundle, verify_receipt_with_trust};
use scopepact_guard::{
    GuardDecision, GuardEngine, GuardPolicy, ReceiptSigner, SignedDecisionReceipt, now_ms,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_MCP_MESSAGE_BYTES: u64 = MAX_INPUT_BYTES;
const MAX_DECISION_LATENCY: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct CliError(String);

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct GuardOptions {
    key: PathBuf,
    key_passphrase_file: PathBuf,
}

struct CheckOptions {
    guard: GuardOptions,
    policy: PathBuf,
}

struct SignedPolicyOptions {
    bundle: PathBuf,
    trust: PathBuf,
    audience: String,
}

struct ProxyOptions {
    guard: GuardOptions,
    policy: SignedPolicyOptions,
    state: PathBuf,
    audit: Option<PathBuf>,
    command: Vec<String>,
}

struct StateOptions {
    guard: GuardOptions,
    policy: SignedPolicyOptions,
    state: PathBuf,
}

struct LoadedPolicy {
    verified: VerifiedPolicyBundle,
    signed: SignedPolicyBundle,
    from_cache: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("scopepact-guard: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let mut arguments: Vec<String> = env::args().skip(1).collect();
    if arguments.is_empty() || matches!(arguments[0].as_str(), "help" | "--help" | "-h") {
        print_help();
        return Ok(ExitCode::SUCCESS);
    }
    let command = arguments.remove(0);
    match command.as_str() {
        "keygen" => run_keygen(&arguments),
        "check" => run_check(&arguments),
        "verify" => run_verify(&arguments),
        "mcp" => run_mcp(&arguments),
        "state" => run_state(&arguments),
        "policy" => run_policy(&arguments),
        "version" | "--version" | "-V" => {
            println!("scopepact-guard {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        _ => Err(CliError(format!("unknown command {command:?}; run with --help")).into()),
    }
}

fn run_state(arguments: &[String]) -> Result<ExitCode> {
    let (command, option_arguments) = arguments.split_first().ok_or_else(|| {
        CliError(
            "state requires inspect, export-audit, export-trust, activate-policy, rotate-signer, or recover-tail".into(),
        )
    })?;
    match command.as_str() {
        "inspect" => run_state_inspect(option_arguments),
        "export-audit" => run_state_export_audit(option_arguments),
        "export-trust" => run_state_export_trust(option_arguments),
        "activate-policy" => run_state_activate_policy(option_arguments),
        "rotate-signer" => run_state_rotate_signer(option_arguments),
        "recover-tail" => run_state_recover_tail(option_arguments),
        _ => Err(CliError(format!(
            "unknown state command {command:?}; expected inspect, export-audit, export-trust, activate-policy, rotate-signer, or recover-tail"
        ))
        .into()),
    }
}

fn run_policy(arguments: &[String]) -> Result<ExitCode> {
    let (command, option_arguments) = arguments
        .split_first()
        .ok_or_else(|| CliError("policy requires trust-init, sign, or verify".into()))?;
    match command.as_str() {
        "trust-init" => run_policy_trust_init(option_arguments),
        "sign" => run_policy_sign(option_arguments),
        "verify" => run_policy_verify(option_arguments),
        _ => Err(CliError(format!(
            "unknown policy command {command:?}; expected trust-init, sign, or verify"
        ))
        .into()),
    }
}

fn run_policy_trust_init(arguments: &[String]) -> Result<ExitCode> {
    let guard = parse_guard_options(arguments)?;
    let issuer = value_after(arguments, "--issuer")?.to_owned();
    let audience = value_after(arguments, "--audience")?.to_owned();
    let output = PathBuf::from(value_after(arguments, "--out")?);
    reject_unknown(
        arguments,
        &[
            "--issuer",
            "--audience",
            "--key",
            "--key-passphrase-file",
            "--out",
        ],
    )?;
    let signer = load_signer(&guard)?;
    let trust = PolicyIssuerTrust::pinned(
        audience,
        issuer,
        hex::encode(signer.public_key()),
        hex::encode(signer.key_id().0),
        now_ms()?,
        None,
    )?;
    let mut file = create_private_file(&output, "policy issuer trust")?;
    serde_json::to_writer_pretty(&mut file, &trust)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "created": output,
            "format": trust.format,
            "issuer": trust.issuers[0].issuer,
            "key_id": trust.issuers[0].key_id,
        }))?
    );
    Ok(ExitCode::SUCCESS)
}

fn run_policy_sign(arguments: &[String]) -> Result<ExitCode> {
    let guard = parse_guard_options(arguments)?;
    let policy_path = PathBuf::from(value_after(arguments, "--policy")?);
    let issuer = value_after(arguments, "--issuer")?.to_owned();
    let audience = value_after(arguments, "--audience")?.to_owned();
    let output = PathBuf::from(value_after(arguments, "--out")?);
    let revoked_rule_ids = values_after(arguments, "--revoke-rule")?;
    reject_unknown(
        arguments,
        &[
            "--policy",
            "--issuer",
            "--audience",
            "--key",
            "--key-passphrase-file",
            "--revoke-rule",
            "--out",
        ],
    )?;
    let policy = load_policy(&policy_path)?;
    let signer = load_signer(&guard)?;
    let issued_at_ms = now_ms()?;
    let expires_at_ms = issued_at_ms
        .checked_add(policy.valid_for_ms)
        .ok_or_else(|| CliError("policy validity interval overflows".into()))?;
    let signed_bundle = sign_policy_bundle(
        PolicyBundleSigningRequest {
            policy,
            issuer,
            audience,
            issued_at_ms,
            not_before_ms: issued_at_ms,
            expires_at_ms,
            revoked_rule_ids,
        },
        signer.as_ref(),
    )?;
    let mut file = create_private_file(&output, "signed policy bundle")?;
    serde_json::to_writer_pretty(&mut file, &signed_bundle)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "created": output,
            "policy_epoch": signed_bundle.bundle.policy.policy_epoch,
            "issuer": signed_bundle.bundle.issuer,
            "audience": signed_bundle.bundle.audience,
            "expires_at_ms": signed_bundle.bundle.expires_at_ms,
            "policy_digest": signed_bundle.bundle.policy_digest,
            "signer_key_id": signed_bundle.signer_key_id,
        }))?
    );
    Ok(ExitCode::SUCCESS)
}

fn run_policy_verify(arguments: &[String]) -> Result<ExitCode> {
    let options = parse_signed_policy_options(arguments)?;
    reject_unknown(
        arguments,
        &["--policy-bundle", "--policy-trust", "--policy-audience"],
    )?;
    let verified = load_verified_policy(&options)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "valid": true,
            "policy_epoch": verified.policy.policy_epoch,
            "issuer": verified.issuer,
            "audience": options.audience,
            "activated_at_ms": verified.activated_at_ms,
            "expires_at_ms": verified.expires_at_ms,
            "policy_digest": verified.policy_digest,
            "bundle_digest": verified.bundle_digest,
            "revoked_rule_ids": verified.revoked_rule_ids,
            "signer_key_id": verified.signer_key_id,
        }))?
    );
    Ok(ExitCode::SUCCESS)
}

fn run_state_inspect(arguments: &[String]) -> Result<ExitCode> {
    let options = parse_state_options(arguments)?;
    reject_unknown(
        arguments,
        &[
            "--policy-bundle",
            "--policy-trust",
            "--policy-audience",
            "--key",
            "--key-passphrase-file",
            "--state",
        ],
    )?;
    let verified = load_verified_policy(&options.policy)?;
    let signer = load_signer(&options.guard)?;
    let public_key = hex::encode(signer.public_key());
    let key_id = hex::encode(signer.key_id().0);
    let (state, recovered) =
        DurableState::open_verified(&options.state, &verified, &public_key, &key_id, now_ms()?)?;
    let mut engine = GuardEngine::new_with_signer_and_revocations(
        verified.policy.clone(),
        signer,
        recovered.activated_at_ms,
        &verified.revoked_rule_ids,
    )?;
    for commitment in &recovered.commitments {
        engine.restore_commitment(commitment)?;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "valid": true,
            "state_version": state.state_version(),
            "sequence": state.sequence(),
            "record_hash": state.record_hash(),
            "activated_at_ms": recovered.activated_at_ms,
            "decisions": recovered.receipts.len(),
            "committed_effects": recovered.commitments.len(),
            "trusted_signers": recovered.signer_trust.keys.len(),
            "policy_history": recovered.signer_trust.policies.len(),
            "active_policy_epoch": verified.policy.policy_epoch,
            "active_bundle_digest": verified.bundle_digest,
            "active_signer_key_id": state.signer_trust().keys.last().map(|key| &key.key_id),
        }))?
    );
    Ok(ExitCode::SUCCESS)
}

fn run_state_export_trust(arguments: &[String]) -> Result<ExitCode> {
    let options = parse_state_options(arguments)?;
    let output = optional_value_after(arguments, "--out")?.map(PathBuf::from);
    reject_unknown(
        arguments,
        &[
            "--policy-bundle",
            "--policy-trust",
            "--policy-audience",
            "--key",
            "--key-passphrase-file",
            "--state",
            "--out",
        ],
    )?;
    let verified = load_verified_policy(&options.policy)?;
    let signer = load_signer(&options.guard)?;
    let public_key = hex::encode(signer.public_key());
    let key_id = hex::encode(signer.key_id().0);
    let (state, _) =
        DurableState::open_verified(&options.state, &verified, &public_key, &key_id, now_ms()?)?;
    let mut encoded = serde_json::to_vec_pretty(state.signer_trust())?;
    encoded.push(b'\n');
    if let Some(path) = output {
        let mut file = create_private_file(&path, "signer trust export")?;
        file.write_all(&encoded)?;
        file.sync_all()?;
    } else {
        io::stdout().write_all(&encoded)?;
    }
    Ok(ExitCode::SUCCESS)
}

fn run_state_rotate_signer(arguments: &[String]) -> Result<ExitCode> {
    let options = parse_state_options(arguments)?;
    let new_key = PathBuf::from(value_after(arguments, "--new-key")?);
    let new_passphrase = PathBuf::from(value_after(arguments, "--new-key-passphrase-file")?);
    reject_unknown(
        arguments,
        &[
            "--policy-bundle",
            "--policy-trust",
            "--policy-audience",
            "--key",
            "--key-passphrase-file",
            "--state",
            "--new-key",
            "--new-key-passphrase-file",
        ],
    )?;
    let verified = load_verified_policy(&options.policy)?;
    let current = load_signer(&options.guard)?;
    let current_public_key = hex::encode(current.public_key());
    let current_key_id = hex::encode(current.key_id().0);
    let replacement = load_signer_from_paths(&new_key, &new_passphrase)?;
    let new_key_id = hex::encode(replacement.key_id().0);
    let (mut state, _) = DurableState::open_verified(
        &options.state,
        &verified,
        &current_public_key,
        &current_key_id,
        now_ms()?,
    )?;
    let activated_at_ms = now_ms()?;
    state.rotate_signer(current.as_ref(), replacement.as_ref(), activated_at_ms)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "rotated": true,
            "previous_key_id": current_key_id,
            "new_key_id": new_key_id,
            "activated_at_ms": activated_at_ms,
            "state_sequence": state.sequence(),
        }))?
    );
    Ok(ExitCode::SUCCESS)
}

fn run_state_activate_policy(arguments: &[String]) -> Result<ExitCode> {
    let options = parse_state_options(arguments)?;
    let next_options = SignedPolicyOptions {
        bundle: PathBuf::from(value_after(arguments, "--new-policy-bundle")?),
        trust: PathBuf::from(value_after(arguments, "--new-policy-trust")?),
        audience: value_after(arguments, "--new-policy-audience")?.to_owned(),
    };
    reject_unknown(
        arguments,
        &[
            "--policy-bundle",
            "--policy-trust",
            "--policy-audience",
            "--new-policy-bundle",
            "--new-policy-trust",
            "--new-policy-audience",
            "--key",
            "--key-passphrase-file",
            "--state",
        ],
    )?;
    let current = load_verified_policy(&options.policy)?;
    let next_loaded = load_signed_policy_set(&next_options)?;
    let next = next_loaded.verified;
    let signer = load_signer(&options.guard)?;
    let public_key = hex::encode(signer.public_key());
    let key_id = hex::encode(signer.key_id().0);
    let activated_at_ms = now_ms()?;
    let (mut state, _) = DurableState::open_verified(
        &options.state,
        &current,
        &public_key,
        &key_id,
        activated_at_ms,
    )?;
    state.activate_policy(&next, signer.as_ref(), activated_at_ms)?;
    persist_policy_cache(&options.state, &next_loaded.signed)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "activated": true,
            "previous_policy_epoch": current.policy.policy_epoch,
            "new_policy_epoch": next.policy.policy_epoch,
            "new_policy_digest": next.policy_digest,
            "new_bundle_digest": next.bundle_digest,
            "activated_at_ms": activated_at_ms.max(next.activated_at_ms),
            "state_sequence": state.sequence(),
        }))?
    );
    Ok(ExitCode::SUCCESS)
}

fn run_state_export_audit(arguments: &[String]) -> Result<ExitCode> {
    let options = parse_state_options(arguments)?;
    let output = optional_value_after(arguments, "--out")?.map(PathBuf::from);
    reject_unknown(
        arguments,
        &[
            "--policy-bundle",
            "--policy-trust",
            "--policy-audience",
            "--key",
            "--key-passphrase-file",
            "--state",
            "--out",
        ],
    )?;
    let verified = load_verified_policy(&options.policy)?;
    let signer = load_signer(&options.guard)?;
    let public_key = hex::encode(signer.public_key());
    let key_id = hex::encode(signer.key_id().0);
    let (_state, recovered) =
        DurableState::open_verified(&options.state, &verified, &public_key, &key_id, now_ms()?)?;
    let mut engine = GuardEngine::new_with_signer_and_revocations(
        verified.policy,
        signer,
        recovered.activated_at_ms,
        &verified.revoked_rule_ids,
    )?;
    for commitment in &recovered.commitments {
        engine.restore_commitment(commitment)?;
    }

    if let Some(path) = output {
        let mut file = create_private_file(&path, "audit export")?;
        write_receipts(&mut file, &recovered.receipts)?;
        file.sync_all()?;
    } else {
        let mut stdout = io::stdout();
        write_receipts(&mut stdout, &recovered.receipts)?;
        stdout.flush()?;
    }
    Ok(ExitCode::SUCCESS)
}

fn run_state_recover_tail(arguments: &[String]) -> Result<ExitCode> {
    let options = parse_state_options(arguments)?;
    reject_unknown(
        arguments,
        &[
            "--policy-bundle",
            "--policy-trust",
            "--policy-audience",
            "--key",
            "--key-passphrase-file",
            "--state",
        ],
    )?;
    let verified = load_verified_policy(&options.policy)?;
    let signer = load_signer(&options.guard)?;
    let public_key = hex::encode(signer.public_key());
    let key_id = hex::encode(signer.key_id().0);
    let recovery = DurableState::recover_partial_tail_verified(
        &options.state,
        &verified,
        &public_key,
        &key_id,
    )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "recovered": true,
            "journal_bytes_removed": recovery.journal_bytes_removed,
            "head_bytes_removed": recovery.head_bytes_removed,
        }))?
    );
    Ok(ExitCode::SUCCESS)
}

fn run_keygen(arguments: &[String]) -> Result<ExitCode> {
    let output = value_after(arguments, "--out")?;
    let passphrase_file = value_after(arguments, "--passphrase-file")?;
    reject_unknown(arguments, &["--out", "--passphrase-file"])?;
    let passphrase = read_passphrase(Path::new(passphrase_file))?;
    let generated = generate_protected_key(&passphrase)?;
    let mut key_file = create_private_file(Path::new(output), "protected key")?;
    key_file.write_all(&generated.encoded)?;
    key_file.sync_all()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "created": output,
            "format": "scopepact-ed25519-encrypted-key-v2",
            "public_key": generated.public_key,
            "key_id": generated.key_id,
        }))?
    );
    Ok(ExitCode::SUCCESS)
}

fn run_check(arguments: &[String]) -> Result<ExitCode> {
    let options = parse_check_options(arguments)?;
    reject_unknown(arguments, &["--policy", "--key", "--key-passphrase-file"])?;
    let policy = load_policy(&options.policy)?;
    let signer = load_signer(&options.guard)?;
    let timestamp = now_ms()?;
    let mut engine = GuardEngine::new_with_signer(policy, signer, timestamp)?;
    let input = read_limited(io::stdin().lock(), "input")?;
    let message: Value = serde_json::from_slice(&input)?;
    let receipt = engine
        .evaluate_json_rpc(&message, timestamp)?
        .ok_or_else(|| CliError("check expects an MCP tools/call request".into()))?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(if receipt.receipt.decision == GuardDecision::Allowed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    })
}

fn run_verify(arguments: &[String]) -> Result<ExitCode> {
    let expected_key_id = optional_value_after(arguments, "--expect-key-id")?;
    let trust_bundle = optional_value_after(arguments, "--trust-bundle")?;
    reject_unknown(arguments, &["--expect-key-id", "--trust-bundle"])?;
    let input = read_limited(io::stdin().lock(), "input")?;
    let receipt: SignedDecisionReceipt = serde_json::from_slice(&input)?;
    receipt.verify()?;
    if let Some(path) = trust_bundle {
        let bytes = read_limited_file(Path::new(path), "trust bundle")?;
        let trust: SignerTrustBundle = serde_json::from_slice(&bytes)
            .map_err(|error| CliError(format!("cannot parse trust bundle {path}: {error}")))?;
        verify_receipt_with_trust(&receipt, &trust)?;
    }
    if let Some(expected) = expected_key_id {
        if receipt.signer_key_id != expected {
            return Err(CliError(format!(
                "receipt key ID {} does not match expected {expected}",
                receipt.signer_key_id
            ))
            .into());
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "valid": true,
            "key_id": receipt.signer_key_id,
            "decision": receipt.receipt.decision,
            "effect_id": receipt.receipt.effect_id,
        }))?
    );
    Ok(ExitCode::SUCCESS)
}

fn run_mcp(arguments: &[String]) -> Result<ExitCode> {
    let options = parse_proxy_options(arguments)?;
    let (mut engine, mut durable_state) = load_proxy_runtime(&options)?;
    emit_operational_event(&json!({
        "format":"scopepact-guard-event-v1",
        "event":"proxy_started",
        "level":"info",
        "timestamp_ms":now_ms()?,
        "state_version":durable_state.state_version(),
        "state_sequence":durable_state.sequence(),
    }))?;
    let (mut child, child_input, child_output) = spawn_mcp_child(&options.command)?;
    let audit = options.audit.as_deref().map(open_audit).transpose()?;
    let tracker = Arc::new(Mutex::new(ConnectionTracker::default()));
    let child_input = Arc::new(Mutex::new(child_input));
    let output_child_input = Arc::downgrade(&child_input);
    let (events, worker_events) = mpsc::channel();

    let input_events = events.clone();
    let input_tracker = Arc::clone(&tracker);
    let input_thread = thread::spawn(move || {
        let result = proxy_input(
            &mut engine,
            &mut durable_state,
            &child_input,
            audit,
            &input_tracker,
        )
        .map_err(|error| error.to_string());
        let _ = input_events.send((ProxyWorker::Input, result));
    });
    let output_thread = thread::spawn(move || {
        let result = proxy_output(child_output, &output_child_input, &tracker)
            .map_err(|error| error.to_string());
        let _ = events.send((ProxyWorker::Output, result));
    });
    supervise_proxy(&mut child, &worker_events, input_thread, output_thread)
}

fn load_proxy_runtime(options: &ProxyOptions) -> Result<(GuardEngine, DurableState)> {
    let loaded = load_policy_with_cache(&options.policy, &options.state)?;
    let verified = loaded.verified;
    let signer = load_signer(&options.guard)?;
    let signer_public_key = hex::encode(signer.public_key());
    let signer_key_id = hex::encode(signer.key_id().0);
    let (durable_state, recovered) = DurableState::open_verified(
        &options.state,
        &verified,
        &signer_public_key,
        &signer_key_id,
        now_ms()?,
    )?;
    if !loaded.from_cache {
        persist_policy_cache(&options.state, &loaded.signed)?;
    }
    let mut engine = GuardEngine::new_with_signer_and_revocations(
        verified.policy.clone(),
        signer,
        recovered.activated_at_ms,
        &verified.revoked_rule_ids,
    )?;
    for commitment in &recovered.commitments {
        engine.restore_commitment(commitment)?;
    }
    Ok((engine, durable_state))
}

fn spawn_mcp_child(command: &[String]) -> Result<(Child, ChildStdin, ChildStdout)> {
    let executable = command
        .first()
        .ok_or_else(|| CliError("mcp requires a command after --".into()))?;
    let mut child = Command::new(executable)
        .args(&command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| CliError(format!("failed to start {executable:?}: {error}")))?;
    let child_input = child
        .stdin
        .take()
        .ok_or_else(|| CliError("failed to open child stdin".into()))?;
    let child_output = child
        .stdout
        .take()
        .ok_or_else(|| CliError("failed to open child stdout".into()))?;
    Ok((child, child_input, child_output))
}

fn supervise_proxy(
    child: &mut Child,
    worker_events: &mpsc::Receiver<(ProxyWorker, std::result::Result<(), String>)>,
    input_thread: thread::JoinHandle<()>,
    output_thread: thread::JoinHandle<()>,
) -> Result<ExitCode> {
    let (first_worker, first_result) = worker_events
        .recv()
        .map_err(|_| CliError("MCP proxy workers exited without a result".into()))?;
    if let Err(error) = first_result {
        let _ = child.kill();
        let _ = child.wait();
        return proxy_worker_failure(first_worker, &error);
    }

    let child_status = child.wait()?;
    match first_worker {
        ProxyWorker::Input => {
            let (worker, result) = worker_events
                .recv()
                .map_err(|_| CliError("MCP output worker exited without a result".into()))?;
            if !matches!(worker, ProxyWorker::Output) {
                return Err(CliError("MCP input worker reported twice".into()).into());
            }
            input_thread
                .join()
                .map_err(|_| CliError("MCP input worker panicked".into()))?;
            output_thread
                .join()
                .map_err(|_| CliError("MCP output worker panicked".into()))?;
            if let Err(error) = result {
                return proxy_worker_failure(worker, &error);
            }
        }
        ProxyWorker::Output => {
            output_thread
                .join()
                .map_err(|_| CliError("MCP output worker panicked".into()))?;
            drop(input_thread);
        }
    }
    emit_operational_event(&json!({
        "format":"scopepact-guard-event-v1",
        "event":"proxy_stopped",
        "level":if child_status.success() { "info" } else { "error" },
        "timestamp_ms":now_ms()?,
        "child_success":child_status.success(),
        "child_code":child_status.code(),
    }))?;
    Ok(if child_status.success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn proxy_worker_failure(worker: ProxyWorker, error: &str) -> Result<ExitCode> {
    emit_operational_event(&json!({
        "format":"scopepact-guard-event-v1",
        "event":"proxy_worker_failed",
        "level":"error",
        "timestamp_ms":now_ms()?,
        "worker":format!("{worker:?}").to_lowercase(),
    }))?;
    Err(CliError(format!("MCP {worker:?} worker failed: {error}")).into())
}

#[derive(Clone, Copy, Debug)]
enum ProxyWorker {
    Input,
    Output,
}

struct ToolCallContext<'a> {
    engine: &'a mut GuardEngine,
    state: &'a mut DurableState,
    child_input: &'a Arc<Mutex<ChildStdin>>,
    audit: &'a mut Option<File>,
    tracker: &'a Arc<Mutex<ConnectionTracker>>,
}

fn proxy_input(
    engine: &mut GuardEngine,
    state: &mut DurableState,
    child_input: &Arc<Mutex<ChildStdin>>,
    mut audit: Option<File>,
    tracker: &Arc<Mutex<ConnectionTracker>>,
) -> Result<()> {
    let stdin = io::stdin();
    let mut input = BufReader::new(stdin.lock());
    let mut stdout = io::stdout();

    loop {
        let Some(buffer) = read_mcp_line(&mut input, "MCP message")? else {
            break;
        };
        let Some((message, class)) = parse_client_message(&buffer, &mut stdout)? else {
            continue;
        };
        let is_tool_call = matches!(
            &class,
            MessageClass::Request { method, .. } if method == "tools/call"
        );
        if is_tool_call {
            let mut context = ToolCallContext {
                engine,
                state,
                child_input,
                audit: &mut audit,
                tracker,
            };
            handle_tool_call(&mut context, &mut stdout, &message, &class, &buffer)?;
        } else {
            forward_client_message(child_input, tracker, &message, &class, &buffer)?;
        }
    }
    Ok(())
}

fn read_mcp_line(input: &mut impl BufRead, source: &str) -> Result<Option<Vec<u8>>> {
    let mut buffer = Vec::new();
    let bytes_read = input
        .take(MAX_MCP_MESSAGE_BYTES + 1)
        .read_until(b'\n', &mut buffer)?;
    if bytes_read == 0 {
        return Ok(None);
    }
    if u64::try_from(buffer.len()).unwrap_or(u64::MAX) > MAX_MCP_MESSAGE_BYTES {
        return Err(CliError(format!("{source} exceeds the 4 MiB limit")).into());
    }
    Ok(Some(buffer))
}

fn parse_client_message(
    buffer: &[u8],
    stdout: &mut impl Write,
) -> Result<Option<(Value, MessageClass)>> {
    let message: Value = match serde_json::from_slice(buffer) {
        Ok(message) => message,
        Err(error) => {
            write_json_line(
                stdout,
                &json_rpc_error(
                    &Value::Null,
                    -32700,
                    "ScopePact rejected invalid JSON",
                    &json!({"reason": error.to_string()}),
                ),
            )?;
            return Ok(None);
        }
    };
    let class = match classify_message(&message) {
        Ok(class) => class,
        Err(error) => {
            write_json_line(
                stdout,
                &json_rpc_error(
                    message.get("id").unwrap_or(&Value::Null),
                    -32600,
                    "ScopePact rejected invalid MCP message",
                    &json!({"reason": error.to_string()}),
                ),
            )?;
            return Ok(None);
        }
    };
    Ok(Some((message, class)))
}

fn forward_client_message(
    child_input: &Arc<Mutex<ChildStdin>>,
    tracker: &Arc<Mutex<ConnectionTracker>>,
    message: &Value,
    class: &MessageClass,
    buffer: &[u8],
) -> Result<()> {
    accept_client_message(tracker, message, class)?;
    let mut child_input = child_input
        .lock()
        .map_err(|_| CliError("MCP child input lock is poisoned".into()))?;
    forward_line(&mut *child_input, buffer)?;
    Ok(())
}

fn accept_client_message(
    tracker: &Arc<Mutex<ConnectionTracker>>,
    message: &Value,
    class: &MessageClass,
) -> Result<()> {
    let disposition = tracker
        .lock()
        .map_err(|_| CliError("MCP connection tracker is poisoned".into()))?
        .accept(Direction::ClientToServer, message, class)?;
    if disposition != ForwardDisposition::Forward {
        return Err(CliError("unexpected client message disposition".into()).into());
    }
    Ok(())
}

fn handle_tool_call(
    context: &mut ToolCallContext<'_>,
    stdout: &mut impl Write,
    message: &Value,
    class: &MessageClass,
    buffer: &[u8],
) -> Result<()> {
    let request_id = message
        .get("id")
        .cloned()
        .ok_or_else(|| CliError("validated tools/call request is missing its id".into()))?;
    accept_client_message(context.tracker, message, class)?;
    let decision_started = Instant::now();
    let evaluation = match context
        .engine
        .evaluate_json_rpc_transactional(message, now_ms()?)
    {
        Ok(Some(evaluation)) => evaluation,
        Ok(None) => {
            return Err(CliError("tools/call was not evaluated by the Guard".into()).into());
        }
        Err(error) => {
            return reject_client_request(
                context.tracker,
                stdout,
                &request_id,
                -32602,
                "ScopePact rejected malformed tool call",
                &json!({"reason": error.to_string()}),
            );
        }
    };
    if decision_started.elapsed() > MAX_DECISION_LATENCY {
        return reject_client_request(
            context.tracker,
            stdout,
            &request_id,
            -32044,
            "ScopePact decision deadline exceeded",
            &json!({"limit_ms": MAX_DECISION_LATENCY.as_millis()}),
        );
    }
    context.state.commit(&evaluation)?;
    let receipt = evaluation.receipt;
    write_audit(context.audit.as_mut(), &receipt)?;
    emit_decision_event(&receipt)?;
    if receipt.receipt.decision == GuardDecision::Allowed {
        let mut child_input = context
            .child_input
            .lock()
            .map_err(|_| CliError("MCP child input lock is poisoned".into()))?;
        forward_line(&mut *child_input, buffer)?;
        Ok(())
    } else {
        reject_client_request(
            context.tracker,
            stdout,
            &request_id,
            -32042,
            "ScopePact blocked tool call",
            &json!({"receipt": receipt}),
        )
    }
}

fn reject_client_request(
    tracker: &Arc<Mutex<ConnectionTracker>>,
    stdout: &mut impl Write,
    request_id: &Value,
    code: i32,
    message: &str,
    data: &Value,
) -> Result<()> {
    tracker
        .lock()
        .map_err(|_| CliError("MCP connection tracker is poisoned".into()))?
        .complete_locally(Direction::ClientToServer, request_id)?;
    write_json_line(stdout, &json_rpc_error(request_id, code, message, data))
}

fn proxy_output(
    child_output: impl Read,
    child_input: &Weak<Mutex<ChildStdin>>,
    tracker: &Arc<Mutex<ConnectionTracker>>,
) -> Result<()> {
    let mut output = BufReader::new(child_output);
    let mut stdout = io::stdout();
    loop {
        let mut buffer = Vec::new();
        let bytes_read = output
            .by_ref()
            .take(MAX_MCP_MESSAGE_BYTES + 1)
            .read_until(b'\n', &mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        if u64::try_from(buffer.len()).unwrap_or(u64::MAX) > MAX_MCP_MESSAGE_BYTES {
            return Err(CliError("MCP child output exceeds the 4 MiB limit".into()).into());
        }
        let message: Value = serde_json::from_slice(&buffer).map_err(|error| {
            CliError(format!("wrapped MCP server emitted invalid JSON: {error}"))
        })?;
        let class = classify_message(&message)?;
        let disposition = tracker
            .lock()
            .map_err(|_| CliError("MCP connection tracker is poisoned".into()))?
            .accept(Direction::ServerToClient, &message, &class)?;
        match disposition {
            ForwardDisposition::Forward => forward_line(&mut stdout, &buffer)?,
            ForwardDisposition::RejectServerRequest { id, method } => {
                let child_input = child_input.upgrade().ok_or_else(|| {
                    CliError("cannot reject server request after child stdin closed".into())
                })?;
                let mut child_input = child_input
                    .lock()
                    .map_err(|_| CliError("MCP child input lock is poisoned".into()))?;
                write_json_line(
                    &mut *child_input,
                    &json_rpc_error(
                        &id,
                        -32043,
                        "ScopePact blocked server-initiated request",
                        &json!({"method": method}),
                    ),
                )?;
            }
        }
    }
    stdout.flush()?;
    Ok(())
}

fn json_rpc_error(id: &Value, code: i32, message: &str, data: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message, "data": data}
    })
}

fn forward_line(output: &mut impl Write, buffer: &[u8]) -> io::Result<()> {
    output.write_all(buffer)?;
    if !buffer.ends_with(b"\n") {
        output.write_all(b"\n")?;
    }
    output.flush()
}

fn write_json_line(output: &mut impl Write, value: &Value) -> Result<()> {
    let mut line = serde_json::to_vec(value)?;
    line.push(b'\n');
    output.write_all(&line)?;
    output.flush()?;
    Ok(())
}

fn write_audit(output: Option<&mut File>, receipt: &SignedDecisionReceipt) -> Result<()> {
    if let Some(output) = output {
        serde_json::to_writer(&mut *output, receipt)?;
        output.write_all(b"\n")?;
        output.flush()?;
        output.sync_data()?;
    }
    Ok(())
}

fn emit_decision_event(receipt: &SignedDecisionReceipt) -> Result<()> {
    let outcome = if receipt.receipt.duplicate {
        "duplicate"
    } else if receipt.receipt.decision == GuardDecision::Allowed {
        "allowed"
    } else {
        "blocked"
    };
    emit_operational_event(&json!({
        "format":"scopepact-guard-event-v1",
        "event":"decision_committed",
        "level":if receipt.receipt.decision == GuardDecision::Allowed { "info" } else { "warn" },
        "timestamp_ms":receipt.receipt.issued_at_ms,
        "policy_epoch":receipt.receipt.policy_epoch,
        "outcome":outcome,
        "effect_id":receipt.receipt.effect_id,
        "signer_key_id":receipt.signer_key_id,
    }))
}

fn emit_operational_event(event: &Value) -> Result<()> {
    let mut stderr = io::stderr().lock();
    serde_json::to_writer(&mut stderr, event)?;
    stderr.write_all(b"\n")?;
    stderr.flush()?;
    Ok(())
}

fn write_receipts(output: &mut impl Write, receipts: &[SignedDecisionReceipt]) -> Result<()> {
    for receipt in receipts {
        serde_json::to_writer(&mut *output, receipt)?;
        output.write_all(b"\n")?;
    }
    Ok(())
}

fn load_policy(path: &Path) -> Result<GuardPolicy> {
    let bytes = read_limited_file(path, "policy")?;
    serde_json::from_slice(&bytes).map_err(|error| {
        CliError(format!("cannot parse policy {}: {error}", path.display())).into()
    })
}

fn load_verified_policy(options: &SignedPolicyOptions) -> Result<VerifiedPolicyBundle> {
    Ok(load_signed_policy_set(options)?.verified)
}

fn load_signed_policy_set(options: &SignedPolicyOptions) -> Result<LoadedPolicy> {
    let trust = load_policy_trust(&options.trust)?;
    let signed = load_signed_policy(&options.bundle)?;
    let verified = verify_policy_bundle(&signed, &trust, &options.audience, now_ms()?)?;
    Ok(LoadedPolicy {
        verified,
        signed,
        from_cache: false,
    })
}

fn load_policy_with_cache(
    options: &SignedPolicyOptions,
    state_path: &Path,
) -> Result<LoadedPolicy> {
    let trust = load_policy_trust(&options.trust)?;
    let timestamp = now_ms()?;
    let primary = load_signed_policy(&options.bundle).and_then(|signed| {
        let verified = verify_policy_bundle(&signed, &trust, &options.audience, timestamp)?;
        Ok(LoadedPolicy {
            verified,
            signed,
            from_cache: false,
        })
    });
    match primary {
        Ok(policy) => Ok(policy),
        Err(primary_error) => {
            let cache_path = policy_cache_path(state_path)?;
            let signed = load_private_signed_policy(&cache_path).map_err(|cache_error| {
                CliError(format!(
                    "configured policy failed ({primary_error}); last-known-good cache failed ({cache_error})"
                ))
            })?;
            let verified = verify_policy_bundle(&signed, &trust, &options.audience, timestamp)
                .map_err(|cache_error| {
                    CliError(format!(
                        "configured policy failed ({primary_error}); last-known-good cache failed ({cache_error})"
                    ))
                })?;
            Ok(LoadedPolicy {
                verified,
                signed,
                from_cache: true,
            })
        }
    }
}

fn load_signed_policy(path: &Path) -> Result<SignedPolicyBundle> {
    let bundle_bytes = read_limited_file(path, "policy bundle")?;
    serde_json::from_slice(&bundle_bytes).map_err(|error| {
        CliError(format!(
            "cannot parse policy bundle {}: {error}",
            path.display()
        ))
        .into()
    })
}

fn load_private_signed_policy(path: &Path) -> Result<SignedPolicyBundle> {
    let bundle_bytes = read_private_regular_file(path, "policy cache")?;
    serde_json::from_slice(&bundle_bytes).map_err(|error| {
        CliError(format!(
            "cannot parse policy cache {}: {error}",
            path.display()
        ))
        .into()
    })
}

fn load_policy_trust(path: &Path) -> Result<PolicyIssuerTrust> {
    let trust_bytes = read_limited_file(path, "policy trust")?;
    serde_json::from_slice(&trust_bytes).map_err(|error| {
        CliError(format!(
            "cannot parse policy trust {}: {error}",
            path.display()
        ))
        .into()
    })
}

fn policy_cache_path(state_path: &Path) -> Result<PathBuf> {
    let file_name = state_path
        .file_name()
        .ok_or_else(|| CliError("state path must name a file".into()))?;
    let mut cache_name = file_name.to_os_string();
    cache_name.push(".policy-cache.json");
    Ok(state_path.with_file_name(cache_name))
}

fn persist_policy_cache(state_path: &Path, signed: &SignedPolicyBundle) -> Result<()> {
    let cache_path = policy_cache_path(state_path)?;
    if let Ok(metadata) = fs::symlink_metadata(&cache_path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CliError(format!(
                "policy cache {} must be a regular file",
                cache_path.display()
            ))
            .into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(CliError(format!(
                    "policy cache {} permissions must not grant group or other access",
                    cache_path.display()
                ))
                .into());
            }
        }
    }
    let mut temporary_name = cache_path.as_os_str().to_os_string();
    temporary_name.push(format!(".tmp-{}", std::process::id()));
    let temporary_path = PathBuf::from(temporary_name);
    let mut temporary = create_private_file(&temporary_path, "temporary policy cache")?;
    let write_result = (|| -> Result<()> {
        serde_json::to_writer_pretty(&mut temporary, signed)?;
        temporary.write_all(b"\n")?;
        temporary.sync_all()?;
        fs::rename(&temporary_path, &cache_path).map_err(|error| {
            CliError(format!(
                "cannot replace policy cache {}: {error}",
                cache_path.display()
            ))
        })?;
        if let Some(parent) = cache_path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    write_result
}

fn create_private_file(path: &Path, label: &str) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(|error| {
        CliError(format!("cannot create {label} {}: {error}", path.display())).into()
    })
}

fn load_signer(options: &GuardOptions) -> Result<Box<dyn ReceiptSigner>> {
    load_signer_from_paths(&options.key, &options.key_passphrase_file)
}

fn load_signer_from_paths(
    key_path: &Path,
    passphrase_path: &Path,
) -> Result<Box<dyn ReceiptSigner>> {
    let encoded = read_private_regular_file(key_path, "protected key")?;
    let passphrase = read_passphrase(passphrase_path)?;
    load_protected_key(&encoded, &passphrase).map_err(Into::into)
}

fn read_passphrase(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut passphrase = Zeroizing::new(read_private_regular_file(path, "passphrase file")?);
    if passphrase.ends_with(b"\n") {
        passphrase.pop();
        if passphrase.ends_with(b"\r") {
            passphrase.pop();
        }
    }
    Ok(passphrase)
}

fn read_private_regular_file(path: &Path, label: &str) -> Result<Vec<u8>> {
    #[cfg(not(unix))]
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CliError(format!(
                "{label} {} must be a regular file, not a symlink or special file",
                path.display()
            ))
            .into());
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|error| CliError(format!("cannot open {label} {}: {error}", path.display())))?;
    let metadata = file.metadata().map_err(|error| {
        CliError(format!(
            "cannot inspect opened {label} {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(CliError(format!(
            "{label} {} must be a regular file, not a special file",
            path.display()
        ))
        .into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError(format!(
                "{label} {} permissions must not grant group or other access",
                path.display()
            ))
            .into());
        }
    }
    read_limited(file, label)
}

fn read_limited_file(path: &Path, label: &str) -> Result<Vec<u8>> {
    let file = File::open(path)
        .map_err(|error| CliError(format!("cannot read {label} {}: {error}", path.display())))?;
    read_limited(file, label)
}

fn read_limited(input: impl Read, label: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    input
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| CliError(format!("cannot read {label}: {error}")))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_INPUT_BYTES {
        return Err(CliError(format!("{label} exceeds the 4 MiB limit")).into());
    }
    Ok(bytes)
}

fn open_audit(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| {
            CliError(format!("cannot open audit log {}: {error}", path.display())).into()
        })
}

fn parse_guard_options(arguments: &[String]) -> Result<GuardOptions> {
    Ok(GuardOptions {
        key: PathBuf::from(value_after(arguments, "--key")?),
        key_passphrase_file: PathBuf::from(value_after(arguments, "--key-passphrase-file")?),
    })
}

fn parse_check_options(arguments: &[String]) -> Result<CheckOptions> {
    Ok(CheckOptions {
        guard: parse_guard_options(arguments)?,
        policy: PathBuf::from(value_after(arguments, "--policy")?),
    })
}

fn parse_signed_policy_options(arguments: &[String]) -> Result<SignedPolicyOptions> {
    Ok(SignedPolicyOptions {
        bundle: PathBuf::from(value_after(arguments, "--policy-bundle")?),
        trust: PathBuf::from(value_after(arguments, "--policy-trust")?),
        audience: value_after(arguments, "--policy-audience")?.to_owned(),
    })
}

fn parse_proxy_options(arguments: &[String]) -> Result<ProxyOptions> {
    let separator = arguments
        .iter()
        .position(|argument| argument == "--")
        .ok_or_else(|| CliError("mcp requires -- before the server command".into()))?;
    let option_arguments = &arguments[..separator];
    let guard = parse_guard_options(option_arguments)?;
    let policy = parse_signed_policy_options(option_arguments)?;
    let state = PathBuf::from(value_after(option_arguments, "--state")?);
    let audit = optional_value_after(option_arguments, "--audit")?.map(PathBuf::from);
    reject_unknown(
        option_arguments,
        &[
            "--policy-bundle",
            "--policy-trust",
            "--policy-audience",
            "--key",
            "--key-passphrase-file",
            "--state",
            "--audit",
        ],
    )?;
    let command = arguments[separator + 1..].to_vec();
    if command.is_empty() {
        return Err(CliError("mcp requires a server command after --".into()).into());
    }
    Ok(ProxyOptions {
        guard,
        policy,
        state,
        audit,
        command,
    })
}

fn parse_state_options(arguments: &[String]) -> Result<StateOptions> {
    Ok(StateOptions {
        guard: parse_guard_options(arguments)?,
        policy: parse_signed_policy_options(arguments)?,
        state: PathBuf::from(value_after(arguments, "--state")?),
    })
}

fn value_after<'a>(arguments: &'a [String], option: &str) -> Result<&'a str> {
    optional_value_after(arguments, option)?
        .ok_or_else(|| CliError(format!("missing required option {option}")).into())
}

fn optional_value_after<'a>(arguments: &'a [String], option: &str) -> Result<Option<&'a str>> {
    let positions: Vec<_> = arguments
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| (argument == option).then_some(index))
        .collect();
    if positions.len() > 1 {
        return Err(CliError(format!("option {option} may be provided only once")).into());
    }
    let Some(position) = positions.first().copied() else {
        return Ok(None);
    };
    arguments
        .get(position + 1)
        .filter(|value| !value.starts_with("--"))
        .map(String::as_str)
        .map(Some)
        .ok_or_else(|| CliError(format!("option {option} requires a value")).into())
}

fn values_after(arguments: &[String], option: &str) -> Result<Vec<String>> {
    arguments
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| (argument == option).then_some(index))
        .map(|position| {
            arguments
                .get(position + 1)
                .filter(|value| !value.starts_with("--"))
                .cloned()
                .ok_or_else(|| CliError(format!("option {option} requires a value")).into())
        })
        .collect()
}

fn reject_unknown(arguments: &[String], known: &[&str]) -> Result<()> {
    let mut index = 0;
    while index < arguments.len() {
        let option = &arguments[index];
        if !known.contains(&option.as_str()) {
            return Err(CliError(format!("unknown option {option:?}")).into());
        }
        index += 2;
    }
    Ok(())
}

fn print_help() {
    println!(
        "ScopePact Guard - capability enforcement for MCP tool calls\n\n\
Usage:\n  \
scopepact-guard keygen --out KEY.json --passphrase-file PASSPHRASE\n  \
scopepact-guard check --policy POLICY.json --key KEY.json --key-passphrase-file PASSPHRASE < request.json\n  \
scopepact-guard verify [--expect-key-id HEX] [--trust-bundle TRUST.json] < receipt.json\n  \
scopepact-guard policy trust-init --issuer ISSUER --audience AUDIENCE --key ISSUER_KEY.json --key-passphrase-file PASSPHRASE --out POLICY_TRUST.json\n  \
scopepact-guard policy sign --policy POLICY.json --issuer ISSUER --audience AUDIENCE --key ISSUER_KEY.json --key-passphrase-file PASSPHRASE [--revoke-rule RULE_ID ...] --out POLICY_BUNDLE.json\n  \
scopepact-guard policy verify --policy-bundle POLICY_BUNDLE.json --policy-trust POLICY_TRUST.json --policy-audience AUDIENCE\n  \
scopepact-guard mcp --policy-bundle POLICY_BUNDLE.json --policy-trust POLICY_TRUST.json --policy-audience AUDIENCE --key KEY.json --key-passphrase-file PASSPHRASE --state STATE.jsonl [--audit FILE] -- COMMAND [ARG...]\n  \
scopepact-guard state inspect --policy-bundle POLICY_BUNDLE.json --policy-trust POLICY_TRUST.json --policy-audience AUDIENCE --key KEY.json --key-passphrase-file PASSPHRASE --state STATE.jsonl\n  \
scopepact-guard state export-audit --policy-bundle POLICY_BUNDLE.json --policy-trust POLICY_TRUST.json --policy-audience AUDIENCE --key KEY.json --key-passphrase-file PASSPHRASE --state STATE.jsonl [--out AUDIT.jsonl]\n  \
scopepact-guard state export-trust --policy-bundle POLICY_BUNDLE.json --policy-trust POLICY_TRUST.json --policy-audience AUDIENCE --key KEY.json --key-passphrase-file PASSPHRASE --state STATE.jsonl [--out TRUST.json]\n  \
scopepact-guard state activate-policy --policy-bundle CURRENT.json --policy-trust CURRENT_TRUST.json --policy-audience CURRENT_AUDIENCE --new-policy-bundle NEXT.json --new-policy-trust NEXT_TRUST.json --new-policy-audience NEXT_AUDIENCE --key KEY.json --key-passphrase-file PASSPHRASE --state STATE.jsonl\n  \
scopepact-guard state rotate-signer --policy-bundle POLICY_BUNDLE.json --policy-trust POLICY_TRUST.json --policy-audience AUDIENCE --key OLD.json --key-passphrase-file OLD_PASS --new-key NEW.json --new-key-passphrase-file NEW_PASS --state STATE.jsonl\n  \
scopepact-guard state recover-tail --policy-bundle POLICY_BUNDLE.json --policy-trust POLICY_TRUST.json --policy-audience AUDIENCE --key KEY.json --key-passphrase-file PASSPHRASE --state STATE.jsonl\n\n\
Exit codes:\n  0  success or allowed check\n  1  wrapped MCP server failed\n  2  configuration or input error\n  3  tool call blocked by policy"
    );
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{MAX_INPUT_BYTES, read_limited};

    #[test]
    fn bounded_reader_rejects_before_consuming_unlimited_input() {
        let maximum = usize::try_from(MAX_INPUT_BYTES).unwrap();
        assert_eq!(
            read_limited(Cursor::new(vec![b'a'; maximum]), "test input")
                .unwrap()
                .len(),
            maximum
        );
        let error = read_limited(Cursor::new(vec![b'a'; maximum + 1]), "test input")
            .expect_err("oversized input should fail");
        assert!(error.to_string().contains("exceeds the 4 MiB limit"));
    }
}
