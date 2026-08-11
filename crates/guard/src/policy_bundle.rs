//! Signed Guard policy bundles and pinned issuer trust.

use std::collections::HashSet;

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use scopepact_core::signing::key_id;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{GuardError, GuardPolicy, ReceiptSigner, Result, validate_policy};

const POLICY_BUNDLE_DOMAIN: &[u8] = b"SCOPEPACT-GUARD-POLICY-BUNDLE-V1\0";
const POLICY_DIGEST_DOMAIN: &[u8] = b"SCOPEPACT-GUARD-POLICY-DIGEST-V1\0";
const POLICY_BUNDLE_VERSION: u16 = 1;
const POLICY_TRUST_FORMAT: &str = "scopepact-policy-issuer-trust-v1";
const MAX_CLOCK_SKEW_MS: i64 = 5 * 60 * 1_000;
const MAX_BUNDLE_LIFETIME_MS: i64 = 31 * 24 * 60 * 60 * 1_000;
const MAX_TRUSTED_POLICY_ISSUERS: usize = 64;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundle {
    pub bundle_version: u16,
    pub issuer: String,
    pub audience: String,
    pub issued_at_ms: i64,
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub policy_digest: String,
    pub policy: GuardPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_rule_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyBundle {
    pub bundle: PolicyBundle,
    pub signer_public_key: String,
    pub signer_key_id: String,
    pub signature: String,
}

#[derive(Clone, Debug)]
pub struct PolicyBundleSigningRequest {
    pub policy: GuardPolicy,
    pub issuer: String,
    pub audience: String,
    pub issued_at_ms: i64,
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub revoked_rule_ids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyIssuerTrust {
    pub format: String,
    pub audience: String,
    pub issuers: Vec<TrustedPolicyIssuer>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedPolicyIssuer {
    pub issuer: String,
    pub public_key: String,
    pub key_id: String,
    pub not_before_ms: i64,
    pub not_after_ms: Option<i64>,
    pub status: PolicyIssuerStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyIssuerStatus {
    Active,
    Retired,
    Revoked,
}

#[derive(Clone, Debug)]
pub struct VerifiedPolicyBundle {
    pub policy: GuardPolicy,
    pub policy_digest: String,
    pub bundle_digest: String,
    pub activated_at_ms: i64,
    pub expires_at_ms: i64,
    pub revoked_rule_ids: HashSet<String>,
    pub issuer: String,
    pub signer_key_id: String,
}

/// Signs a complete, fixed-lifetime Guard policy bundle.
///
/// # Errors
///
/// Returns an error for invalid policy, identity, time, revocation data, or a
/// provider signing failure.
pub fn sign_policy_bundle(
    request: PolicyBundleSigningRequest,
    signer: &dyn ReceiptSigner,
) -> Result<SignedPolicyBundle> {
    let policy_digest = policy_content_digest(&request.policy)?;
    let bundle = PolicyBundle {
        bundle_version: POLICY_BUNDLE_VERSION,
        issuer: request.issuer,
        audience: request.audience,
        issued_at_ms: request.issued_at_ms,
        not_before_ms: request.not_before_ms,
        expires_at_ms: request.expires_at_ms,
        policy_digest,
        policy: request.policy,
        revoked_rule_ids: request.revoked_rule_ids,
    };
    validate_bundle(&bundle)?;
    let transcript = bundle_transcript(&bundle)?;
    Ok(SignedPolicyBundle {
        bundle,
        signer_public_key: hex::encode(signer.public_key()),
        signer_key_id: hex::encode(signer.key_id().0),
        signature: hex::encode(signer.sign(&transcript)?),
    })
}

/// Verifies a policy bundle against pinned issuer and audience trust.
///
/// # Errors
///
/// Returns an error for invalid signature, unknown or revoked issuer,
/// audience mismatch, inactive time window, or malformed policy/revocations.
pub fn verify_policy_bundle(
    signed: &SignedPolicyBundle,
    trust: &PolicyIssuerTrust,
    expected_audience: &str,
    now_ms: i64,
) -> Result<VerifiedPolicyBundle> {
    validate_bundle(&signed.bundle)?;
    validate_trust(trust)?;
    if trust.audience != expected_audience || signed.bundle.audience != expected_audience {
        return Err(GuardError::InvalidPolicy(
            "policy bundle audience or trust format mismatch".into(),
        ));
    }
    let trusted = trust
        .issuers
        .iter()
        .find(|issuer| {
            issuer.issuer == signed.bundle.issuer && issuer.key_id == signed.signer_key_id
        })
        .ok_or_else(|| GuardError::InvalidPolicy("policy issuer is not trusted".into()))?;
    validate_issuer(trusted)?;
    if trusted.status == PolicyIssuerStatus::Revoked
        || trusted.public_key != signed.signer_public_key
        || signed.bundle.issued_at_ms < trusted.not_before_ms
        || trusted
            .not_after_ms
            .is_some_and(|not_after| signed.bundle.issued_at_ms > not_after)
    {
        return Err(GuardError::InvalidPolicy(
            "policy issuer is revoked, mismatched, or outside its validity window".into(),
        ));
    }
    if now_ms
        .checked_add(MAX_CLOCK_SKEW_MS)
        .is_none_or(|now| now < signed.bundle.not_before_ms)
        || now_ms > signed.bundle.expires_at_ms
    {
        return Err(GuardError::InvalidPolicy(
            "policy bundle is not currently active".into(),
        ));
    }
    let public_key = VerifyingKey::from_bytes(&decode_hex(
        &signed.signer_public_key,
        "policy signer public key",
    )?)
    .map_err(|_| GuardError::InvalidPolicy("policy signer public key is invalid".into()))?;
    let expected_key_id = hex::encode(key_id(&public_key).0);
    if signed.signer_key_id != expected_key_id {
        return Err(GuardError::InvalidPolicy(
            "policy signer key ID does not match public key".into(),
        ));
    }
    let signature =
        Signature::from_bytes(&decode_hex(&signed.signature, "policy bundle signature")?);
    public_key
        .verify(&bundle_transcript(&signed.bundle)?, &signature)
        .map_err(|_| GuardError::InvalidPolicy("policy bundle signature is invalid".into()))?;

    Ok(VerifiedPolicyBundle {
        policy: signed.bundle.policy.clone(),
        policy_digest: signed.bundle.policy_digest.clone(),
        bundle_digest: hex::encode(Sha256::digest(bundle_transcript(&signed.bundle)?)),
        activated_at_ms: signed.bundle.not_before_ms,
        expires_at_ms: signed.bundle.expires_at_ms,
        revoked_rule_ids: signed.bundle.revoked_rule_ids.iter().cloned().collect(),
        issuer: signed.bundle.issuer.clone(),
        signer_key_id: signed.signer_key_id.clone(),
    })
}

impl PolicyIssuerTrust {
    /// Creates a single-issuer pinned trust file.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity, key metadata, or time window.
    pub fn pinned(
        audience: String,
        issuer: String,
        public_key: String,
        key_id: String,
        not_before_ms: i64,
        not_after_ms: Option<i64>,
    ) -> Result<Self> {
        let trusted = TrustedPolicyIssuer {
            issuer,
            public_key,
            key_id,
            not_before_ms,
            not_after_ms,
            status: PolicyIssuerStatus::Active,
        };
        let trust = Self {
            format: POLICY_TRUST_FORMAT.into(),
            audience,
            issuers: vec![trusted],
        };
        validate_trust(&trust)?;
        Ok(trust)
    }
}

fn validate_trust(trust: &PolicyIssuerTrust) -> Result<()> {
    validate_name(&trust.audience, "policy audience")?;
    if trust.format != POLICY_TRUST_FORMAT
        || trust.issuers.is_empty()
        || trust.issuers.len() > MAX_TRUSTED_POLICY_ISSUERS
    {
        return Err(GuardError::InvalidPolicy(format!(
            "policy issuer trust must use {POLICY_TRUST_FORMAT} and contain 1 to {MAX_TRUSTED_POLICY_ISSUERS} issuers"
        )));
    }
    let mut identities = HashSet::new();
    for issuer in &trust.issuers {
        validate_issuer(issuer)?;
        if !identities.insert((&issuer.issuer, &issuer.key_id)) {
            return Err(GuardError::InvalidPolicy(
                "policy issuer trust contains a duplicate issuer/key identity".into(),
            ));
        }
    }
    Ok(())
}

fn validate_bundle(bundle: &PolicyBundle) -> Result<()> {
    validate_policy(&bundle.policy)?;
    if bundle.policy_digest != policy_content_digest(&bundle.policy)? {
        return Err(GuardError::InvalidPolicy(
            "policy content digest does not match the embedded policy".into(),
        ));
    }
    validate_name(&bundle.issuer, "policy issuer")?;
    validate_name(&bundle.audience, "policy audience")?;
    if bundle.bundle_version != POLICY_BUNDLE_VERSION
        || bundle.issued_at_ms > bundle.not_before_ms
        || bundle.not_before_ms >= bundle.expires_at_ms
        || bundle.expires_at_ms - bundle.not_before_ms > MAX_BUNDLE_LIFETIME_MS
        || bundle.expires_at_ms - bundle.not_before_ms != bundle.policy.valid_for_ms
    {
        return Err(GuardError::InvalidPolicy(
            "policy bundle has invalid version or validity interval".into(),
        ));
    }
    let rule_ids: HashSet<_> = bundle
        .policy
        .rules
        .iter()
        .map(|rule| rule.id.as_str())
        .collect();
    let mut revocations = HashSet::new();
    if bundle
        .revoked_rule_ids
        .iter()
        .any(|rule| !rule_ids.contains(rule.as_str()) || !revocations.insert(rule.as_str()))
    {
        return Err(GuardError::InvalidPolicy(
            "policy revocations must be unique installed rule IDs".into(),
        ));
    }
    Ok(())
}

/// Computes the versioned digest used to bind policy content to signed bundles
/// and durable state.
///
/// # Errors
///
/// Returns an error if the policy cannot be serialized.
pub fn policy_content_digest(policy: &GuardPolicy) -> Result<String> {
    let encoded = serde_json::to_vec(policy)?;
    let mut hash = Sha256::new();
    hash.update(POLICY_DIGEST_DOMAIN);
    hash.update(
        u64::try_from(encoded.len())
            .map_err(|_| GuardError::InvalidPolicy("policy is too large".into()))?
            .to_be_bytes(),
    );
    hash.update(encoded);
    Ok(hex::encode(hash.finalize()))
}

fn validate_issuer(issuer: &TrustedPolicyIssuer) -> Result<()> {
    validate_name(&issuer.issuer, "policy issuer")?;
    if issuer
        .not_after_ms
        .is_some_and(|not_after| not_after < issuer.not_before_ms)
    {
        return Err(GuardError::InvalidPolicy(
            "policy issuer validity interval is invalid".into(),
        ));
    }
    let public_key: [u8; 32] = decode_hex(&issuer.public_key, "policy issuer public key")?;
    let public_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| GuardError::InvalidPolicy("policy issuer public key is invalid".into()))?;
    if issuer.key_id != hex::encode(key_id(&public_key).0) {
        return Err(GuardError::InvalidPolicy(
            "policy issuer key ID does not match public key".into(),
        ));
    }
    Ok(())
}

fn bundle_transcript(bundle: &PolicyBundle) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(bundle)?;
    let mut transcript = Vec::with_capacity(POLICY_BUNDLE_DOMAIN.len() + 8 + encoded.len());
    transcript.extend_from_slice(POLICY_BUNDLE_DOMAIN);
    transcript.extend_from_slice(
        &u64::try_from(encoded.len())
            .map_err(|_| GuardError::InvalidPolicy("policy bundle is too large".into()))?
            .to_be_bytes(),
    );
    transcript.extend_from_slice(&encoded);
    Ok(transcript)
}

fn validate_name(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(GuardError::InvalidPolicy(format!("{label} is invalid")));
    }
    Ok(())
}

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value)
        .map_err(|_| GuardError::InvalidPolicy(format!("{label} is not valid hex")))?;
    bytes
        .try_into()
        .map_err(|_| GuardError::InvalidPolicy(format!("{label} has the wrong length")))
}
