//! `ScopePact` policy enforcement for MCP tool calls.
//!
//! The guard translates a valid MCP `tools/call` request into the authority
//! kernel's typed effect request. Every decision is returned as a signed,
//! independently verifiable receipt.

use std::collections::{BTreeSet, HashSet};
use std::path::{Component, Path};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use scopepact_core::authorization::{
    ActionRequest, AuthorityKernel, AuthorizationOutcome, CapabilityGrant, PaymentLimit,
    PaymentRequest, ResourceScope,
};
use scopepact_core::signing::key_id;
use scopepact_core::types::{ActorId, Digest, EffectId, GrantId, KeyId};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const RECEIPT_DOMAIN: &[u8] = b"SCOPEPACT-GUARD-RECEIPT-V0\0";
const ACTION_PREFIX: &str = "mcp.tool.call:";
const MAX_POLICY_RULES: usize = 1_024;
const MAX_VALID_FOR_MS: i64 = 31 * 24 * 60 * 60 * 1_000;
const MAX_SAFE_JSON_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Error)]
pub enum GuardError {
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),
    #[error("invalid MCP request: {0}")]
    InvalidRequest(String),
    #[error("receipt serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("receipt signature is invalid")]
    InvalidReceiptSignature,
    #[error("receipt signing key does not match its key ID")]
    ReceiptKeyMismatch,
    #[error("receipt field is malformed: {0}")]
    MalformedReceipt(&'static str),
    #[error("system clock is before the Unix epoch")]
    InvalidSystemClock,
}

pub type Result<T> = std::result::Result<T, GuardError>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GuardPolicy {
    pub policy_version: u16,
    pub policy_epoch: u64,
    pub principal: String,
    pub agent: String,
    pub valid_for_ms: i64,
    pub rules: Vec<ToolRule>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRule {
    pub id: String,
    pub tool: String,
    pub resource: ResourcePolicy,
    pub max_calls: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment: Option<PaymentPolicy>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourcePolicy {
    Literal { value: String },
    Argument { pointer: String, prefix: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentPolicy {
    pub currency: String,
    pub amount_pointer: String,
    pub payee_pointer: String,
    pub max_spend_atomic: u128,
    pub allowed_payees: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardDecision {
    Allowed,
    Blocked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReceipt {
    pub receipt_version: u16,
    pub decision: GuardDecision,
    pub reason: String,
    pub policy_epoch: u64,
    pub principal: String,
    pub agent: String,
    pub request_id: Value,
    pub tool: String,
    pub resource: Option<String>,
    pub rule_id: Option<String>,
    pub effect_id: String,
    pub effect_digest: String,
    pub issued_at_ms: i64,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDecisionReceipt {
    pub receipt: DecisionReceipt,
    pub signer_public_key: String,
    pub signer_key_id: String,
    pub signature: String,
}

impl SignedDecisionReceipt {
    /// Verifies the embedded key ID and Ed25519 signature.
    ///
    /// This proves receipt integrity. A deployment must separately trust the
    /// returned key ID or compare it with an expected key ID.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed key material, a mismatched key ID, or an
    /// invalid signature.
    pub fn verify(&self) -> Result<()> {
        let public_key: [u8; 32] =
            decode_hex(&self.signer_public_key).map_err(|_| GuardError::InvalidReceiptSignature)?;
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| GuardError::InvalidReceiptSignature)?;
        let expected_key_id = hex::encode(key_id(&verifying_key).0);
        if self.signer_key_id != expected_key_id {
            return Err(GuardError::ReceiptKeyMismatch);
        }
        let signature_bytes: [u8; 64] =
            decode_hex(&self.signature).map_err(|_| GuardError::InvalidReceiptSignature)?;
        let signature = Signature::from_bytes(&signature_bytes);
        let transcript = receipt_transcript(&self.receipt)?;
        verifying_key
            .verify(&transcript, &signature)
            .map_err(|_| GuardError::InvalidReceiptSignature)
    }
}

#[derive(Clone, Debug)]
struct InstalledRule {
    policy: ToolRule,
    grant_id: GrantId,
}

#[derive(Clone, Debug)]
struct ToolCall {
    request_id: Value,
    tool: String,
    arguments: Value,
}

struct ReceiptFields<'a> {
    rule_id: Option<&'a str>,
    resource: Option<String>,
    effect_id: EffectId,
    effect_digest: Digest,
    decision: GuardDecision,
    reason: String,
    duplicate: bool,
    issued_at_ms: i64,
}

/// Stateful effect authorization for MCP traffic.
pub struct GuardEngine {
    policy: GuardPolicy,
    kernel: AuthorityKernel,
    rules: Vec<InstalledRule>,
    signing_key: SigningKey,
    agent_id: ActorId,
}

impl GuardEngine {
    /// Validates a policy, installs one capability per rule, and starts a guard.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy cannot produce valid capability grants.
    pub fn new(policy: GuardPolicy, signing_key: SigningKey, now_ms: i64) -> Result<Self> {
        validate_policy(&policy)?;
        let issuer = actor_id("principal", &policy.principal);
        let agent_id = actor_id("agent", &policy.agent);
        let expires_at_ms = now_ms
            .checked_add(policy.valid_for_ms)
            .ok_or_else(|| GuardError::InvalidPolicy("validity interval overflows".into()))?;
        let mut kernel = AuthorityKernel::new(policy.policy_epoch);
        let mut installed_rules = Vec::with_capacity(policy.rules.len());

        for rule in &policy.rules {
            let grant_id = grant_id(policy.policy_epoch, &rule.id);
            let action = action_for_tool(&rule.tool);
            let payment = rule.payment.as_ref().map(|payment| PaymentLimit {
                payment_actions: BTreeSet::from([action.clone()]),
                currency: payment.currency.clone(),
                max_spend_atomic: payment.max_spend_atomic,
                allowed_payees: payment
                    .allowed_payees
                    .iter()
                    .map(|payee| actor_id("payee", payee))
                    .collect(),
            });
            let resource = match &rule.resource {
                ResourcePolicy::Literal { value } => ResourceScope::Exact(value.clone()),
                ResourcePolicy::Argument { prefix, .. } => ResourceScope::Prefix(prefix.clone()),
            };
            let grant = CapabilityGrant {
                id: grant_id,
                issuer,
                subject: agent_id,
                actions: BTreeSet::from([action]),
                resource,
                not_before_ms: now_ms.saturating_sub(1_000),
                expires_at_ms,
                max_calls: rule.max_calls,
                interaction: None,
                payment,
                remaining_delegation_depth: 0,
                policy_epoch: policy.policy_epoch,
                parent: None,
            };
            kernel
                .install_root(grant)
                .map_err(|error| GuardError::InvalidPolicy(error.to_string()))?;
            installed_rules.push(InstalledRule {
                policy: rule.clone(),
                grant_id,
            });
        }

        Ok(Self {
            policy,
            kernel,
            rules: installed_rules,
            signing_key,
            agent_id,
        })
    }

    /// Evaluates one JSON-RPC message.
    ///
    /// Returns `None` for messages other than MCP `tools/call`. Those messages
    /// are outside the guard's enforcement boundary and should be forwarded.
    ///
    /// # Errors
    ///
    /// Returns an error when a `tools/call` request is malformed or a receipt
    /// cannot be serialized.
    pub fn evaluate_json_rpc(
        &mut self,
        message: &Value,
        now_ms: i64,
    ) -> Result<Option<SignedDecisionReceipt>> {
        if !message.is_object() {
            return Err(GuardError::InvalidRequest(
                "JSON-RPC message must be an object; batches are not supported".into(),
            ));
        }
        if message.get("method").and_then(Value::as_str) != Some("tools/call") {
            return Ok(None);
        }
        let call = parse_tool_call(message)?;
        let effect_digest = effect_digest(&call.tool, &call.arguments)?;
        let effect_id = effect_id(&call.request_id)?;
        self.evaluate_tool_call(&call, effect_id, effect_digest, now_ms)
            .map(Some)
    }

    fn evaluate_tool_call(
        &mut self,
        call: &ToolCall,
        effect_id: EffectId,
        effect_digest: Digest,
        now_ms: i64,
    ) -> Result<SignedDecisionReceipt> {
        let matching_rules: Vec<_> = self
            .rules
            .iter()
            .filter(|rule| rule.policy.tool == call.tool)
            .cloned()
            .collect();
        if matching_rules.is_empty() {
            return self.sign_receipt(
                call,
                ReceiptFields {
                    rule_id: None,
                    resource: None,
                    effect_id,
                    effect_digest,
                    decision: GuardDecision::Blocked,
                    reason: "tool is not granted".into(),
                    duplicate: false,
                    issued_at_ms: now_ms,
                },
            );
        }

        let mut last_reason = "resource is outside grant scope".to_owned();
        let mut observed_resource = None;
        for installed in matching_rules {
            let resource = match resolve_resource(&installed.policy.resource, &call.arguments) {
                Ok(resource) => resource,
                Err(error) => {
                    last_reason = error.to_string();
                    continue;
                }
            };
            observed_resource = Some(resource.clone());
            let payment = match resolve_payment(installed.policy.payment.as_ref(), &call.arguments)
            {
                Ok(payment) => payment,
                Err(error) => {
                    last_reason = error.to_string();
                    continue;
                }
            };
            let request = ActionRequest {
                effect_id,
                effect_digest,
                actor: self.agent_id,
                interaction: None,
                action: action_for_tool(&call.tool),
                resource: resource.clone(),
                payment,
            };
            match self
                .kernel
                .authorize_effect(installed.grant_id, &request, now_ms)
            {
                Ok(AuthorizationOutcome::Reserved) => {
                    return self.sign_receipt(
                        call,
                        ReceiptFields {
                            rule_id: Some(&installed.policy.id),
                            resource: Some(resource),
                            effect_id,
                            effect_digest,
                            decision: GuardDecision::Allowed,
                            reason: "effect reserved under capability grant".into(),
                            duplicate: false,
                            issued_at_ms: now_ms,
                        },
                    );
                }
                Ok(AuthorizationOutcome::Duplicate) => {
                    return self.sign_receipt(
                        call,
                        ReceiptFields {
                            rule_id: Some(&installed.policy.id),
                            resource: Some(resource),
                            effect_id,
                            effect_digest,
                            decision: GuardDecision::Blocked,
                            reason: "duplicate effect suppressed".into(),
                            duplicate: true,
                            issued_at_ms: now_ms,
                        },
                    );
                }
                Err(error) => last_reason = error.to_string(),
            }
        }

        self.sign_receipt(
            call,
            ReceiptFields {
                rule_id: None,
                resource: observed_resource,
                effect_id,
                effect_digest,
                decision: GuardDecision::Blocked,
                reason: last_reason,
                duplicate: false,
                issued_at_ms: now_ms,
            },
        )
    }

    fn sign_receipt(
        &self,
        call: &ToolCall,
        fields: ReceiptFields<'_>,
    ) -> Result<SignedDecisionReceipt> {
        let receipt = DecisionReceipt {
            receipt_version: 1,
            decision: fields.decision,
            reason: fields.reason,
            policy_epoch: self.policy.policy_epoch,
            principal: self.policy.principal.clone(),
            agent: self.policy.agent.clone(),
            request_id: call.request_id.clone(),
            tool: call.tool.clone(),
            resource: fields.resource,
            rule_id: fields.rule_id.map(str::to_owned),
            effect_id: hex::encode(fields.effect_id.0),
            effect_digest: hex::encode(fields.effect_digest.0),
            issued_at_ms: fields.issued_at_ms,
            duplicate: fields.duplicate,
        };
        let transcript = receipt_transcript(&receipt)?;
        let signature = self.signing_key.sign(&transcript);
        let verifying_key = self.signing_key.verifying_key();
        Ok(SignedDecisionReceipt {
            receipt,
            signer_public_key: hex::encode(verifying_key.as_bytes()),
            signer_key_id: hex::encode(key_id(&verifying_key).0),
            signature: hex::encode(signature.to_bytes()),
        })
    }
}

/// Returns Unix time in milliseconds.
///
/// # Errors
///
/// Returns an error when the system clock predates the Unix epoch or the value
/// cannot fit into an `i64`.
pub fn now_ms() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| GuardError::InvalidSystemClock)?;
    i64::try_from(duration.as_millis()).map_err(|_| GuardError::InvalidSystemClock)
}

/// Generates a fresh Ed25519 signing key from the operating system RNG.
///
/// # Errors
///
/// Returns an error if the operating system random source is unavailable.
pub fn generate_signing_key() -> Result<SigningKey> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|error| GuardError::InvalidPolicy(format!("OS random source failed: {error}")))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn validate_policy(policy: &GuardPolicy) -> Result<()> {
    if policy.policy_version != 1 {
        return Err(GuardError::InvalidPolicy("policy_version must be 1".into()));
    }
    if policy.policy_epoch == 0 {
        return Err(GuardError::InvalidPolicy(
            "policy_epoch must be non-zero".into(),
        ));
    }
    if !valid_name(&policy.principal) || !valid_name(&policy.agent) {
        return Err(GuardError::InvalidPolicy(
            "principal and agent must be 1 to 256 characters".into(),
        ));
    }
    if !(1..=MAX_VALID_FOR_MS).contains(&policy.valid_for_ms) {
        return Err(GuardError::InvalidPolicy(format!(
            "valid_for_ms must be between 1 and {MAX_VALID_FOR_MS}"
        )));
    }
    if policy.rules.is_empty() || policy.rules.len() > MAX_POLICY_RULES {
        return Err(GuardError::InvalidPolicy(format!(
            "rules must contain 1 to {MAX_POLICY_RULES} entries"
        )));
    }
    let mut ids = HashSet::new();
    for rule in &policy.rules {
        if !valid_name(&rule.id) || !ids.insert(&rule.id) {
            return Err(GuardError::InvalidPolicy(
                "rule IDs must be unique and 1 to 256 characters".into(),
            ));
        }
        if !valid_name(&rule.tool) || rule.max_calls == 0 {
            return Err(GuardError::InvalidPolicy(format!(
                "rule {} has an invalid tool or max_calls",
                rule.id
            )));
        }
        match &rule.resource {
            ResourcePolicy::Literal { value } if !valid_resource(value) => {
                return Err(GuardError::InvalidPolicy(format!(
                    "rule {} has an invalid literal resource",
                    rule.id
                )));
            }
            ResourcePolicy::Argument { pointer, prefix }
                if !valid_pointer(pointer)
                    || !valid_resource(prefix)
                    || (prefix.starts_with('/') && !prefix.ends_with('/')) =>
            {
                return Err(GuardError::InvalidPolicy(format!(
                    "rule {} has an invalid resource pointer or prefix",
                    rule.id
                )));
            }
            _ => {}
        }
        if let Some(payment) = &rule.payment {
            if payment.currency.is_empty()
                || payment.currency.len() > 32
                || !payment.currency.is_ascii()
                || !valid_pointer(&payment.amount_pointer)
                || !valid_pointer(&payment.payee_pointer)
                || payment.max_spend_atomic == 0
                || payment.allowed_payees.is_empty()
                || payment
                    .allowed_payees
                    .iter()
                    .any(|payee| !valid_name(payee))
            {
                return Err(GuardError::InvalidPolicy(format!(
                    "rule {} has invalid payment limits",
                    rule.id
                )));
            }
        }
    }
    Ok(())
}

fn parse_tool_call(message: &Value) -> Result<ToolCall> {
    let request_id = message
        .get("id")
        .ok_or_else(|| GuardError::InvalidRequest("tools/call requires an id".into()))?;
    let request_id = normalize_request_id(request_id)?;
    let params = message
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(|| GuardError::InvalidRequest("tools/call requires params".into()))?;
    let tool = params
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| valid_name(name))
        .ok_or_else(|| GuardError::InvalidRequest("tools/call requires a valid name".into()))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    if !arguments.is_object() {
        return Err(GuardError::InvalidRequest(
            "tools/call arguments must be an object".into(),
        ));
    }
    Ok(ToolCall {
        request_id,
        tool: tool.to_owned(),
        arguments,
    })
}

fn normalize_request_id(value: &Value) -> Result<Value> {
    if let Some(value) = value.as_str() {
        return Ok(Value::String(value.to_owned()));
    }
    if let Some(value) = value.as_i64() {
        if (-MAX_SAFE_JSON_INTEGER..=MAX_SAFE_JSON_INTEGER).contains(&value) {
            return Ok(Value::from(value));
        }
    }
    Err(GuardError::InvalidRequest(
        "tools/call id must be a string or JavaScript-safe integer".into(),
    ))
}

fn resolve_resource(policy: &ResourcePolicy, arguments: &Value) -> Result<String> {
    match policy {
        ResourcePolicy::Literal { value } => Ok(value.clone()),
        ResourcePolicy::Argument { pointer, prefix } => {
            let resource = arguments
                .pointer(pointer)
                .and_then(Value::as_str)
                .filter(|resource| valid_resource(resource))
                .ok_or_else(|| {
                    GuardError::InvalidRequest(format!(
                        "resource argument at {pointer} must be a non-empty string"
                    ))
                })?;
            if prefix.starts_with('/')
                && (!resource.starts_with('/')
                    || Path::new(resource)
                        .components()
                        .any(|component| component == Component::ParentDir))
            {
                return Err(GuardError::InvalidRequest(format!(
                    "resource path at {pointer} must be absolute and cannot contain parent traversal"
                )));
            }
            Ok(resource.to_owned())
        }
    }
}

fn resolve_payment(
    policy: Option<&PaymentPolicy>,
    arguments: &Value,
) -> Result<Option<PaymentRequest>> {
    let Some(policy) = policy else {
        return Ok(None);
    };
    let amount_atomic = arguments
        .pointer(&policy.amount_pointer)
        .and_then(Value::as_u64)
        .map(u128::from)
        .ok_or_else(|| {
            GuardError::InvalidRequest(format!(
                "payment amount at {} must be a positive integer",
                policy.amount_pointer
            ))
        })?;
    let payee = arguments
        .pointer(&policy.payee_pointer)
        .and_then(Value::as_str)
        .filter(|payee| valid_name(payee))
        .ok_or_else(|| {
            GuardError::InvalidRequest(format!(
                "payment payee at {} must be a non-empty string",
                policy.payee_pointer
            ))
        })?;
    Ok(Some(PaymentRequest {
        currency: policy.currency.clone(),
        amount_atomic,
        payee: actor_id("payee", payee),
    }))
}

fn receipt_transcript(receipt: &DecisionReceipt) -> Result<Vec<u8>> {
    let mut transcript = Vec::with_capacity(512);
    transcript.extend_from_slice(RECEIPT_DOMAIN);
    transcript.extend_from_slice(&receipt.receipt_version.to_be_bytes());
    transcript.push(match receipt.decision {
        GuardDecision::Allowed => 1,
        GuardDecision::Blocked => 2,
    });
    append_receipt_field(&mut transcript, receipt.reason.as_bytes())?;
    transcript.extend_from_slice(&receipt.policy_epoch.to_be_bytes());
    append_receipt_field(&mut transcript, receipt.principal.as_bytes())?;
    append_receipt_field(&mut transcript, receipt.agent.as_bytes())?;
    let request_id = serde_json::to_vec(&receipt.request_id)?;
    append_receipt_field(&mut transcript, &request_id)?;
    append_receipt_field(&mut transcript, receipt.tool.as_bytes())?;
    append_optional_field(&mut transcript, receipt.resource.as_deref())?;
    append_optional_field(&mut transcript, receipt.rule_id.as_deref())?;
    transcript.extend_from_slice(
        &decode_hex::<16>(&receipt.effect_id)
            .map_err(|_| GuardError::MalformedReceipt("effect_id"))?,
    );
    transcript.extend_from_slice(
        &decode_hex::<32>(&receipt.effect_digest)
            .map_err(|_| GuardError::MalformedReceipt("effect_digest"))?,
    );
    transcript.extend_from_slice(&receipt.issued_at_ms.to_be_bytes());
    transcript.push(u8::from(receipt.duplicate));
    Ok(transcript)
}

fn append_optional_field(output: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    if let Some(value) = value {
        output.push(1);
        append_receipt_field(output, value.as_bytes())
    } else {
        output.push(0);
        Ok(())
    }
}

fn append_receipt_field(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| GuardError::MalformedReceipt("field exceeds u32 length"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn effect_digest(tool: &str, arguments: &Value) -> Result<Digest> {
    let canonical = canonical_json(arguments);
    let arguments = serde_json::to_vec(&canonical)?;
    let mut hash = Sha256::new();
    hash.update(b"SCOPEPACT-MCP-EFFECT-DIGEST-V0\0");
    hash.update(
        u64::try_from(tool.len())
            .expect("validated tool length fits u64")
            .to_be_bytes(),
    );
    hash.update(tool.as_bytes());
    hash.update(
        u64::try_from(arguments.len())
            .expect("serialized arguments length fits u64")
            .to_be_bytes(),
    );
    hash.update(arguments);
    Ok(Digest(hash.finalize().into()))
}

fn effect_id(request_id: &Value) -> Result<EffectId> {
    let request_id = serde_json::to_vec(request_id)?;
    let mut hash = Sha256::new();
    hash.update(b"SCOPEPACT-MCP-EFFECT-ID-V0\0");
    hash.update(
        u64::try_from(request_id.len())
            .expect("validated request ID length fits u64")
            .to_be_bytes(),
    );
    hash.update(request_id);
    let digest: [u8; 32] = hash.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    Ok(EffectId(id))
}

fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonical_json).collect()),
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_unstable();
            let mut canonical = Map::new();
            for key in keys {
                canonical.insert(key.clone(), canonical_json(&values[key]));
            }
            Value::Object(canonical)
        }
        _ => value.clone(),
    }
}

fn actor_id(kind: &str, value: &str) -> ActorId {
    let mut hash = Sha256::new();
    hash.update(b"SCOPEPACT-GUARD-ACTOR-V0\0");
    hash.update(kind.as_bytes());
    hash.update([0]);
    hash.update(value.as_bytes());
    ActorId(hash.finalize().into())
}

fn grant_id(epoch: u64, rule_id: &str) -> GrantId {
    let mut hash = Sha256::new();
    hash.update(b"SCOPEPACT-GUARD-GRANT-V0\0");
    hash.update(epoch.to_be_bytes());
    hash.update(rule_id.as_bytes());
    let digest: [u8; 32] = hash.finalize().into();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    GrantId(id)
}

fn action_for_tool(tool: &str) -> String {
    format!("{ACTION_PREFIX}{tool}")
}

fn valid_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn valid_resource(value: &str) -> bool {
    !value.is_empty() && value.len() <= 1_024 && !value.chars().any(char::is_control)
}

fn valid_pointer(value: &str) -> bool {
    value.starts_with('/') && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn decode_hex<const N: usize>(value: &str) -> std::result::Result<[u8; N], hex::FromHexError> {
    let bytes = hex::decode(value)?;
    bytes
        .try_into()
        .map_err(|_| hex::FromHexError::InvalidStringLength)
}

#[must_use]
pub fn signer_key_id(key: &SigningKey) -> KeyId {
    key_id(&key.verifying_key())
}
