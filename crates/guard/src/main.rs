use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, ExitCode, Stdio};
use std::thread;

use ed25519_dalek::SigningKey;
use scopepact_guard::{
    GuardDecision, GuardEngine, GuardPolicy, SignedDecisionReceipt, generate_signing_key, now_ms,
    signer_key_id,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const MAX_MCP_MESSAGE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
struct CliError(String);

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CliError {}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    format: String,
    seed: String,
    public_key: String,
    key_id: String,
}

struct GuardOptions {
    policy: PathBuf,
    key: PathBuf,
}

struct ProxyOptions {
    guard: GuardOptions,
    audit: Option<PathBuf>,
    command: Vec<String>,
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
        "version" | "--version" | "-V" => {
            println!("scopepact-guard {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        _ => Err(CliError(format!("unknown command {command:?}; run with --help")).into()),
    }
}

fn run_keygen(arguments: &[String]) -> Result<ExitCode> {
    let output = value_after(arguments, "--out")?;
    reject_unknown(arguments, &["--out"])?;
    let signing_key = generate_signing_key()?;
    write_key_file(Path::new(output), &signing_key)?;
    let verifying_key = signing_key.verifying_key();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "created": output,
            "public_key": hex::encode(verifying_key.as_bytes()),
            "key_id": hex::encode(signer_key_id(&signing_key).0),
        }))?
    );
    Ok(ExitCode::SUCCESS)
}

fn run_check(arguments: &[String]) -> Result<ExitCode> {
    let options = parse_guard_options(arguments)?;
    reject_unknown(arguments, &["--policy", "--key"])?;
    let policy = load_policy(&options.policy)?;
    let key = load_key(&options.key)?;
    let timestamp = now_ms()?;
    let mut engine = GuardEngine::new(policy, key, timestamp)?;
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    if input.len() > usize::try_from(MAX_MCP_MESSAGE_BYTES).unwrap_or(usize::MAX) {
        return Err(CliError("input exceeds the 4 MiB limit".into()).into());
    }
    let message: Value = serde_json::from_str(&input)?;
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
    reject_unknown(arguments, &["--expect-key-id"])?;
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let receipt: SignedDecisionReceipt = serde_json::from_str(&input)?;
    receipt.verify()?;
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
    let policy = load_policy(&options.guard.policy)?;
    let key = load_key(&options.guard.key)?;
    let mut engine = GuardEngine::new(policy, key, now_ms()?)?;
    let executable = options
        .command
        .first()
        .ok_or_else(|| CliError("mcp requires a command after --".into()))?;
    let mut child = Command::new(executable)
        .args(&options.command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| CliError(format!("failed to start {executable:?}: {error}")))?;
    let mut child_input = child
        .stdin
        .take()
        .ok_or_else(|| CliError("failed to open child stdin".into()))?;
    let child_output = child
        .stdout
        .take()
        .ok_or_else(|| CliError("failed to open child stdout".into()))?;
    let output_thread = thread::spawn(move || -> io::Result<()> {
        let mut output = child_output;
        let mut stdout = io::stdout();
        io::copy(&mut output, &mut stdout)?;
        stdout.flush()
    });
    let mut audit = options.audit.as_deref().map(open_audit).transpose()?;
    let proxy_result = proxy_input(&mut engine, &mut child_input, audit.as_mut());
    drop(child_input);
    let child_status = child.wait()?;
    output_thread
        .join()
        .map_err(|_| CliError("child output thread panicked".into()))??;
    proxy_result?;
    Ok(if child_status.success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn proxy_input(
    engine: &mut GuardEngine,
    child_input: &mut ChildStdin,
    mut audit: Option<&mut File>,
) -> Result<()> {
    let stdin = io::stdin();
    let mut input = BufReader::new(stdin.lock());
    let mut stdout = io::stdout();

    loop {
        let mut buffer = Vec::new();
        let bytes_read = input
            .by_ref()
            .take(MAX_MCP_MESSAGE_BYTES + 1)
            .read_until(b'\n', &mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        if u64::try_from(buffer.len()).unwrap_or(u64::MAX) > MAX_MCP_MESSAGE_BYTES {
            return Err(CliError("MCP message exceeds the 4 MiB limit".into()).into());
        }
        let message: Value = match serde_json::from_slice(&buffer) {
            Ok(message) => message,
            Err(error) => {
                write_json_line(
                    &mut stdout,
                    &json_rpc_error(
                        &Value::Null,
                        -32700,
                        "ScopePact rejected invalid JSON",
                        &json!({"reason": error.to_string()}),
                    ),
                )?;
                continue;
            }
        };
        match engine.evaluate_json_rpc(&message, now_ms()?) {
            Ok(None) => forward_line(child_input, &buffer)?,
            Ok(Some(receipt)) => {
                write_audit(audit.as_deref_mut(), &receipt)?;
                if receipt.receipt.decision == GuardDecision::Allowed {
                    forward_line(child_input, &buffer)?;
                } else {
                    let request_id = message.get("id").cloned().unwrap_or(Value::Null);
                    write_json_line(
                        &mut stdout,
                        &json_rpc_error(
                            &request_id,
                            -32042,
                            "ScopePact blocked tool call",
                            &json!({"receipt": receipt}),
                        ),
                    )?;
                }
            }
            Err(error) => {
                let request_id = message.get("id").cloned().unwrap_or(Value::Null);
                write_json_line(
                    &mut stdout,
                    &json_rpc_error(
                        &request_id,
                        -32602,
                        "ScopePact rejected malformed tool call",
                        &json!({"reason": error.to_string()}),
                    ),
                )?;
            }
        }
    }
    Ok(())
}

fn json_rpc_error(id: &Value, code: i32, message: &str, data: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message, "data": data}
    })
}

fn forward_line(output: &mut ChildStdin, buffer: &[u8]) -> io::Result<()> {
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
    } else {
        eprintln!("SCOPEPACT_RECEIPT {}", serde_json::to_string(receipt)?);
    }
    Ok(())
}

fn load_policy(path: &Path) -> Result<GuardPolicy> {
    let bytes = fs::read(path)
        .map_err(|error| CliError(format!("cannot read policy {}: {error}", path.display())))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        CliError(format!("cannot parse policy {}: {error}", path.display())).into()
    })
}

fn write_key_file(path: &Path, signing_key: &SigningKey) -> Result<()> {
    let verifying_key = signing_key.verifying_key();
    let key_file = KeyFile {
        format: "scopepact-ed25519-private-key-v1".into(),
        seed: hex::encode(signing_key.to_bytes()),
        public_key: hex::encode(verifying_key.as_bytes()),
        key_id: hex::encode(signer_key_id(signing_key).0),
    };
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut output = options
        .open(path)
        .map_err(|error| CliError(format!("cannot create key {}: {error}", path.display())))?;
    serde_json::to_writer_pretty(&mut output, &key_file)?;
    output.write_all(b"\n")?;
    Ok(())
}

fn load_key(path: &Path) -> Result<SigningKey> {
    let bytes = fs::read(path)
        .map_err(|error| CliError(format!("cannot read key {}: {error}", path.display())))?;
    let key_file: KeyFile = serde_json::from_slice(&bytes)
        .map_err(|error| CliError(format!("cannot parse key {}: {error}", path.display())))?;
    if key_file.format != "scopepact-ed25519-private-key-v1" {
        return Err(CliError("unsupported key file format".into()).into());
    }
    let seed: [u8; 32] = decode_hex(&key_file.seed, "private seed")?;
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    if key_file.public_key != hex::encode(verifying_key.as_bytes())
        || key_file.key_id != hex::encode(signer_key_id(&signing_key).0)
    {
        return Err(CliError("key file public metadata does not match its seed".into()).into());
    }
    Ok(signing_key)
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
        policy: PathBuf::from(value_after(arguments, "--policy")?),
        key: PathBuf::from(value_after(arguments, "--key")?),
    })
}

fn parse_proxy_options(arguments: &[String]) -> Result<ProxyOptions> {
    let separator = arguments
        .iter()
        .position(|argument| argument == "--")
        .ok_or_else(|| CliError("mcp requires -- before the server command".into()))?;
    let option_arguments = &arguments[..separator];
    let guard = parse_guard_options(option_arguments)?;
    let audit = optional_value_after(option_arguments, "--audit")?.map(PathBuf::from);
    reject_unknown(option_arguments, &["--policy", "--key", "--audit"])?;
    let command = arguments[separator + 1..].to_vec();
    if command.is_empty() {
        return Err(CliError("mcp requires a server command after --".into()).into());
    }
    Ok(ProxyOptions {
        guard,
        audit,
        command,
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

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value).map_err(|_| CliError(format!("invalid {label} hex")))?;
    bytes
        .try_into()
        .map_err(|_| CliError(format!("invalid {label} length")).into())
}

fn print_help() {
    println!(
        "ScopePact Guard - capability enforcement for MCP tool calls\n\n\
Usage:\n  \
scopepact-guard keygen --out KEY.json\n  \
scopepact-guard check --policy POLICY.json --key KEY.json < request.json\n  \
scopepact-guard verify [--expect-key-id HEX] < receipt.json\n  \
scopepact-guard mcp --policy POLICY.json --key KEY.json [--audit FILE] -- COMMAND [ARG...]\n\n\
Exit codes:\n  0  success or allowed check\n  1  wrapped MCP server failed\n  2  configuration or input error\n  3  tool call blocked by policy"
    );
}
