//! Optional federation profiles for credentials issued outside `ScopePact`.
//!
//! A validated credential produces identity evidence. It never installs a
//! capability or authorizes an effect; local policy must perform that step.

use ed25519_dalek::VerifyingKey;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;

use crate::error::{ProtocolError, Result};
use crate::types::{Digest, KeyId, SessionId};

pub const SCOPEPACT_SESSION_JWT_TYPE: &str = "scopepact-session+jwt";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JwtFederationPolicy {
    issuer: String,
    audience: String,
    key_id: String,
    max_token_bytes: usize,
    max_lifetime_secs: u64,
    max_clock_skew_secs: u64,
}

impl JwtFederationPolicy {
    /// Creates a strict policy for one trusted issuer key and audience.
    ///
    /// # Errors
    ///
    /// Returns an error when a trust identifier is empty or unreasonably long.
    pub fn new(issuer: &str, audience: &str, key_id: &str) -> Result<Self> {
        if !valid_text(issuer, 1024) || !valid_text(audience, 1024) || !valid_text(key_id, 128) {
            return Err(ProtocolError::Malformed(
                "invalid JWT federation trust identifier",
            ));
        }
        Ok(Self {
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            key_id: key_id.to_owned(),
            max_token_bytes: 8_192,
            max_lifetime_secs: 300,
            max_clock_skew_secs: 5,
        })
    }

    /// Applies bounded parsing, lifetime, and clock-skew limits.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or excessive limits.
    pub fn with_limits(
        mut self,
        max_token_bytes: usize,
        max_lifetime_secs: u64,
        max_clock_skew_secs: u64,
    ) -> Result<Self> {
        if !(256..=65_536).contains(&max_token_bytes)
            || max_lifetime_secs == 0
            || max_lifetime_secs > 3_600
            || max_clock_skew_secs > 300
        {
            return Err(ProtocolError::Malformed(
                "invalid JWT federation resource or time limit",
            ));
        }
        self.max_token_bytes = max_token_bytes;
        self.max_lifetime_secs = max_lifetime_secs;
        self.max_clock_skew_secs = max_clock_skew_secs;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedJwtBinding<'a> {
    pub sender: KeyId,
    pub session: SessionId,
    pub policy_epoch: u64,
    pub grant_digest: Digest,
    /// RFC 7638 SHA-256 JWK thumbprint from the sender-constrained proof.
    pub proof_key_thumbprint: &'a str,
    pub now_unix_secs: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederatedIdentityEvidence {
    pub issuer: String,
    pub subject: String,
    pub token_id: String,
    pub proof_key_thumbprint: String,
    pub sender: KeyId,
    pub session: SessionId,
    pub policy_epoch: u64,
    pub grant_digest: Digest,
}

#[derive(Clone, Debug)]
pub struct JwtFederationValidator {
    policy: JwtFederationPolicy,
    issuer_key: DecodingKey,
}

impl JwtFederationValidator {
    /// Pins an Ed25519 issuer key to a strict federation policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied Ed25519 public key is invalid.
    pub fn new(policy: JwtFederationPolicy, issuer_public_key: [u8; 32]) -> Result<Self> {
        VerifyingKey::from_bytes(&issuer_public_key)
            .map_err(|_| ProtocolError::CredentialRejected("invalid trusted issuer key"))?;
        Ok(Self {
            policy,
            issuer_key: DecodingKey::from_ed_der(&issuer_public_key),
        })
    }

    /// Validates a dedicated `ScopePact` JWT and returns non-authoritative
    /// identity evidence bound to the current handshake context.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, ambiguous, incorrectly
    /// signed, stale, misaddressed, or context-mismatched credentials.
    pub fn validate(
        &self,
        token: &str,
        expected: ExpectedJwtBinding<'_>,
    ) -> Result<FederatedIdentityEvidence> {
        if token.len() > self.policy.max_token_bytes {
            return Err(ProtocolError::CredentialRejected("JWT exceeds size limit"));
        }
        if !valid_thumbprint(expected.proof_key_thumbprint) {
            return Err(ProtocolError::CredentialRejected(
                "invalid expected proof-key thumbprint",
            ));
        }

        let header = decode_header(token)
            .map_err(|_| ProtocolError::CredentialRejected("malformed JWT header"))?;
        if header.alg != Algorithm::EdDSA {
            return Err(ProtocolError::CredentialRejected(
                "JWT algorithm is not EdDSA",
            ));
        }
        if header.typ.as_deref() != Some(SCOPEPACT_SESSION_JWT_TYPE) {
            return Err(ProtocolError::CredentialRejected("JWT type mismatch"));
        }
        if header.kid.as_deref() != Some(self.policy.key_id.as_str()) {
            return Err(ProtocolError::CredentialRejected("JWT key ID mismatch"));
        }
        if has_untrusted_header_parameters(&header) {
            return Err(ProtocolError::CredentialRejected(
                "JWT contains untrusted header parameters",
            ));
        }

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.leeway = self.policy.max_clock_skew_secs;
        validation.validate_nbf = true;
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "sub", "aud"]);
        validation.set_issuer(&[self.policy.issuer.as_str()]);
        validation.set_audience(&[self.policy.audience.as_str()]);
        let claims = decode::<JwtClaims>(token, &self.issuer_key, &validation)
            .map_err(|_| {
                ProtocolError::CredentialRejected(
                    "JWT signature or registered claim validation failed",
                )
            })?
            .claims;

        validate_claim_shape(&claims)?;
        if claims.iat
            > expected
                .now_unix_secs
                .saturating_add(self.policy.max_clock_skew_secs)
        {
            return Err(ProtocolError::CredentialRejected(
                "JWT issued in the future",
            ));
        }
        if claims.exp < claims.iat
            || claims.nbf > claims.exp
            || claims.exp.saturating_sub(claims.iat) > self.policy.max_lifetime_secs
        {
            return Err(ProtocolError::CredentialRejected(
                "JWT validity interval exceeds policy",
            ));
        }
        if claims.cnf.jkt != expected.proof_key_thumbprint {
            return Err(ProtocolError::CredentialRejected(
                "JWT proof-key binding mismatch",
            ));
        }

        let sender = KeyId(decode_canonical_hex::<32>(
            &claims.scopepact.sender_key_id,
            "invalid JWT sender key ID",
        )?);
        let session = SessionId(decode_canonical_hex::<16>(
            &claims.scopepact.session_id,
            "invalid JWT session ID",
        )?);
        let grant_digest = Digest(decode_canonical_hex::<32>(
            &claims.scopepact.grant_digest,
            "invalid JWT grant digest",
        )?);
        if sender != expected.sender {
            return Err(ProtocolError::SenderKeyMismatch);
        }
        if session != expected.session {
            return Err(ProtocolError::SessionMismatch);
        }
        if claims.scopepact.policy_epoch != expected.policy_epoch {
            return Err(ProtocolError::PolicyEpochMismatch);
        }
        if grant_digest != expected.grant_digest {
            return Err(ProtocolError::CredentialRejected(
                "JWT grant digest binding mismatch",
            ));
        }

        Ok(FederatedIdentityEvidence {
            issuer: claims.iss,
            subject: claims.sub,
            token_id: claims.jti,
            proof_key_thumbprint: claims.cnf.jkt,
            sender,
            session,
            policy_epoch: claims.scopepact.policy_epoch,
            grant_digest,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JwtClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    nbf: u64,
    iat: u64,
    jti: String,
    cnf: ConfirmationClaims,
    scopepact: ScopePactBindingClaims,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmationClaims {
    jkt: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopePactBindingClaims {
    sender_key_id: String,
    session_id: String,
    policy_epoch: u64,
    grant_digest: String,
}

fn validate_claim_shape(claims: &JwtClaims) -> Result<()> {
    if !valid_text(&claims.iss, 1024)
        || !valid_text(&claims.sub, 256)
        || !valid_text(&claims.aud, 1024)
        || !valid_token_id(&claims.jti)
        || !valid_thumbprint(&claims.cnf.jkt)
    {
        return Err(ProtocolError::CredentialRejected(
            "JWT contains malformed identity claims",
        ));
    }
    Ok(())
}

fn has_untrusted_header_parameters(header: &jsonwebtoken::Header) -> bool {
    header.cty.is_some()
        || header.jku.is_some()
        || header.jwk.is_some()
        || header.x5u.is_some()
        || header.x5c.is_some()
        || header.x5t.is_some()
        || header.x5t_s256.is_some()
        || header.crit.is_some()
        || header.enc.is_some()
        || header.zip.is_some()
        || header.url.is_some()
        || header.nonce.is_some()
        || !header.extras.is_empty()
}

fn valid_text(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && !value.chars().any(char::is_control)
}

fn valid_token_id(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_thumbprint(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn decode_canonical_hex<const N: usize>(value: &str, error: &'static str) -> Result<[u8; N]> {
    let mut output = [0; N];
    hex::decode_to_slice(value, &mut output)
        .map_err(|_| ProtocolError::CredentialRejected(error))?;
    if value != hex::encode(output) {
        return Err(ProtocolError::CredentialRejected(error));
    }
    Ok(output)
}
