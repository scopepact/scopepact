use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use scopepact_guard::state::DurableState;
use scopepact_guard::{
    GuardDecision, GuardEngine, GuardPolicy, PaymentPolicy, ResourcePolicy, ToolRule, signer_key_id,
};
use serde::Serialize;
use serde_json::{Value, json};

const NOW_MS: i64 = 1_000_000;
const DEFAULT_ITERATIONS: usize = 10_000;
const DEFAULT_STATE_RECORDS: usize = 100;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

#[derive(Serialize)]
struct BenchmarkReport {
    format: &'static str,
    guard_version: &'static str,
    optimized_build: bool,
    operating_system: &'static str,
    architecture: &'static str,
    logical_cpus: usize,
    iterations: usize,
    state_records: usize,
    scenarios: Vec<ScenarioResult>,
    durable_state: DurableStateResult,
}

#[derive(Serialize)]
struct ScenarioResult {
    name: &'static str,
    operations: usize,
    observed_decisions: usize,
    elapsed_ns: u64,
    ns_per_operation: u64,
    operations_per_second: u64,
}

#[derive(Serialize)]
struct DurableStateResult {
    records: usize,
    append_elapsed_ns: u64,
    append_ns_per_record: u64,
    recovery_elapsed_ns: u64,
    journal_bytes: u64,
    head_bytes: u64,
    recovered_commitments: usize,
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Result<Self, Box<dyn Error>> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "scopepact-guard-benchmark-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let (iterations, state_records) = parse_options()?;
    let key = SigningKey::from_bytes(&[42; 32]);
    let scenarios = vec![
        benchmark_allowed(iterations, &key)?,
        benchmark_blocked(iterations, &key)?,
        benchmark_duplicate(iterations, &key)?,
        benchmark_payment(iterations, &key)?,
    ];
    let durable_state = benchmark_durable_state(state_records, &key)?;
    let report = BenchmarkReport {
        format: "scopepact-guard-benchmark-v1",
        guard_version: env!("CARGO_PKG_VERSION"),
        optimized_build: !cfg!(debug_assertions),
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        logical_cpus: std::thread::available_parallelism().map_or(1, usize::from),
        iterations,
        state_records,
        scenarios,
        durable_state,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn parse_options() -> Result<(usize, usize), Box<dyn Error>> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let iterations = option_value(&arguments, "--iterations")?.unwrap_or(DEFAULT_ITERATIONS);
    let state_records =
        option_value(&arguments, "--state-records")?.unwrap_or(DEFAULT_STATE_RECORDS);
    if iterations == 0 || state_records == 0 || state_records > 10_000 {
        return Err(
            "iterations must be positive and state-records must be between 1 and 10000".into(),
        );
    }
    Ok((iterations, state_records))
}

fn option_value(arguments: &[String], option: &str) -> Result<Option<usize>, Box<dyn Error>> {
    let Some(index) = arguments.iter().position(|argument| argument == option) else {
        return Ok(None);
    };
    let value = arguments
        .get(index + 1)
        .ok_or_else(|| format!("{option} requires a value"))?
        .parse()?;
    Ok(Some(value))
}

fn benchmark_allowed(
    iterations: usize,
    key: &SigningKey,
) -> Result<ScenarioResult, Box<dyn Error>> {
    let mut guard = GuardEngine::new(policy(iterations, false), key.clone(), NOW_MS)?;
    benchmark_scenario("allowed", iterations, |index| {
        let receipt = guard
            .evaluate_json_rpc(&tool_call(index, "write", &json!({})), NOW_MS)
            .expect("benchmark request must evaluate")
            .expect("benchmark request must produce a receipt");
        receipt.receipt.decision == GuardDecision::Allowed
    })
}

fn benchmark_blocked(
    iterations: usize,
    key: &SigningKey,
) -> Result<ScenarioResult, Box<dyn Error>> {
    let mut guard = GuardEngine::new(policy(iterations, false), key.clone(), NOW_MS)?;
    benchmark_scenario("blocked", iterations, |index| {
        let receipt = guard
            .evaluate_json_rpc(&tool_call(index, "ungranted", &json!({})), NOW_MS)
            .expect("benchmark request must evaluate")
            .expect("benchmark request must produce a receipt");
        receipt.receipt.decision == GuardDecision::Blocked
    })
}

fn benchmark_duplicate(
    iterations: usize,
    key: &SigningKey,
) -> Result<ScenarioResult, Box<dyn Error>> {
    let mut guard = GuardEngine::new(policy(1, false), key.clone(), NOW_MS)?;
    let request = tool_call(1, "write", &json!({}));
    let _first = guard.evaluate_json_rpc(&request, NOW_MS)?.unwrap();
    benchmark_scenario("duplicate", iterations, |_| {
        let receipt = guard
            .evaluate_json_rpc(&request, NOW_MS)
            .expect("benchmark request must evaluate")
            .expect("benchmark request must produce a receipt");
        receipt.receipt.duplicate
    })
}

fn benchmark_payment(
    iterations: usize,
    key: &SigningKey,
) -> Result<ScenarioResult, Box<dyn Error>> {
    let mut guard = GuardEngine::new(policy(iterations, true), key.clone(), NOW_MS)?;
    benchmark_scenario("payment", iterations, |index| {
        let receipt = guard
            .evaluate_json_rpc(
                &tool_call(index, "write", &json!({"amount":1, "payee":"vendor"})),
                NOW_MS,
            )
            .expect("benchmark request must evaluate")
            .expect("benchmark request must produce a receipt");
        receipt.receipt.decision == GuardDecision::Allowed
    })
}

fn benchmark_scenario(
    name: &'static str,
    iterations: usize,
    mut operation: impl FnMut(usize) -> bool,
) -> Result<ScenarioResult, Box<dyn Error>> {
    let started = Instant::now();
    let mut observed_decisions = 0_usize;
    for index in 0..iterations {
        observed_decisions += usize::from(operation(index));
    }
    let elapsed_ns = duration_ns(started.elapsed().as_nanos());
    let operations = u64::try_from(iterations)?;
    Ok(ScenarioResult {
        name,
        operations: iterations,
        observed_decisions,
        elapsed_ns,
        ns_per_operation: elapsed_ns / operations,
        operations_per_second: operations.saturating_mul(1_000_000_000) / elapsed_ns.max(1),
    })
}

fn benchmark_durable_state(
    records: usize,
    key: &SigningKey,
) -> Result<DurableStateResult, Box<dyn Error>> {
    let directory = TestDirectory::new()?;
    let path = directory.0.join("state.jsonl");
    let head_path = directory.0.join("state.jsonl.head");
    let benchmark_policy = policy(records, false);
    let public_key = hex::encode(key.verifying_key().as_bytes());
    let key_id = hex::encode(signer_key_id(key).0);
    let (mut state, recovered) =
        DurableState::open(&path, &benchmark_policy, &public_key, &key_id, NOW_MS)?;
    let mut guard = GuardEngine::new(
        benchmark_policy.clone(),
        key.clone(),
        recovered.activated_at_ms,
    )?;
    let append_started = Instant::now();
    for index in 0..records {
        let evaluation = guard
            .evaluate_json_rpc_transactional(&tool_call(index, "write", &json!({})), NOW_MS)?
            .ok_or("benchmark tool call was not evaluated")?;
        state.commit(&evaluation)?;
    }
    let append_elapsed_ns = duration_ns(append_started.elapsed().as_nanos());
    drop(state);

    let recovery_started = Instant::now();
    let (state, recovered) =
        DurableState::open(&path, &benchmark_policy, &public_key, &key_id, NOW_MS)?;
    let recovery_elapsed_ns = duration_ns(recovery_started.elapsed().as_nanos());
    let result = DurableStateResult {
        records,
        append_elapsed_ns,
        append_ns_per_record: append_elapsed_ns / u64::try_from(records)?,
        recovery_elapsed_ns,
        journal_bytes: fs::metadata(&path)?.len(),
        head_bytes: fs::metadata(&head_path)?.len(),
        recovered_commitments: recovered.commitments.len(),
    };
    drop(state);
    Ok(result)
}

fn duration_ns(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn policy(max_calls: usize, payment: bool) -> GuardPolicy {
    GuardPolicy {
        policy_version: 1,
        policy_epoch: 1,
        principal: "benchmark-principal".into(),
        agent: "benchmark-agent".into(),
        valid_for_ms: 60_000,
        rules: vec![ToolRule {
            id: "benchmark-rule".into(),
            tool: "write".into(),
            resource: ResourcePolicy::Literal {
                value: "urn:benchmark".into(),
            },
            max_calls: u64::try_from(max_calls).unwrap_or(u64::MAX),
            payment: payment.then(|| PaymentPolicy {
                currency: "BENCH".into(),
                amount_pointer: "/amount".into(),
                payee_pointer: "/payee".into(),
                max_spend_atomic: max_calls as u128,
                allowed_payees: vec!["vendor".into()],
            }),
        }],
    }
}

fn tool_call(id: usize, tool: &str, arguments: &Value) -> Value {
    json!({
        "jsonrpc":"2.0",
        "id":u64::try_from(id).unwrap_or(u64::MAX),
        "method":"tools/call",
        "params":{"name":tool, "arguments":arguments}
    })
}
