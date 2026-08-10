use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::error::{ProtocolError, Result};
use crate::signing::{append_bytes, key_id};
use crate::types::{ChallengeId, Digest, KeyId, Nonce, SessionId};

const NEGOTIATION_DOMAIN: &[u8] = b"SCOPEPACT-NEGOTIATION-V0\0";
const IDENTITY_PROOF_DOMAIN: &[u8] = b"SCOPEPACT-IDENTITY-PROOF-V0\0";
const MAX_VERSIONS: usize = 32;
const MAX_CODECS: usize = 32;
const MAX_EXTENSIONS: usize = 32;
const MAX_CREDENTIAL_TYPES: usize = 16;
const MAX_NAME_BYTES: usize = 256;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

pub const NATIVE_CREDENTIAL_TYPE: &str = "scopepact-native-ed25519-v0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentHello {
    pub supported_versions: BTreeSet<ProtocolVersion>,
    pub codecs: BTreeSet<String>,
    pub extensions: BTreeSet<String>,
    pub max_frame_bytes: u64,
    pub max_concurrent_interactions: u32,
}

impl AgentHello {
    /// Validates the bounds and names advertised by a peer.
    ///
    /// # Errors
    ///
    /// Returns an error when required sets are empty, advertised collections
    /// exceed protocol limits, names are malformed, or resource limits are zero.
    pub fn validate(&self) -> Result<()> {
        if self.supported_versions.is_empty() || self.supported_versions.len() > MAX_VERSIONS {
            return Err(ProtocolError::Malformed("invalid supported version list"));
        }
        if self.codecs.is_empty()
            || self.codecs.len() > MAX_CODECS
            || self.codecs.iter().any(|codec| !valid_name(codec))
        {
            return Err(ProtocolError::Malformed("invalid codec list"));
        }
        if self.extensions.len() > MAX_EXTENSIONS
            || self
                .extensions
                .iter()
                .any(|extension| !valid_name(extension))
        {
            return Err(ProtocolError::Malformed("invalid extension list"));
        }
        if self.max_frame_bytes == 0 || self.max_concurrent_interactions == 0 {
            return Err(ProtocolError::Malformed("zero hello resource limit"));
        }
        Ok(())
    }

    fn transcript(&self) -> Vec<u8> {
        let mut output = Vec::new();
        append_count(&mut output, self.supported_versions.len());
        for version in &self.supported_versions {
            output.extend_from_slice(&version.major.to_be_bytes());
            output.extend_from_slice(&version.minor.to_be_bytes());
        }
        append_strings(&mut output, &self.codecs);
        append_strings(&mut output, &self.extensions);
        output.extend_from_slice(&self.max_frame_bytes.to_be_bytes());
        output.extend_from_slice(&self.max_concurrent_interactions.to_be_bytes());
        output
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedParameters {
    version: ProtocolVersion,
    codec: String,
    extensions: BTreeSet<String>,
    max_frame_bytes: u64,
    max_concurrent_interactions: u32,
    transcript_digest: Digest,
}

impl NegotiatedParameters {
    /// Selects deterministic parameters from an initiator and responder hello.
    ///
    /// The greatest common version and lexicographically first common codec are
    /// selected. Extensions are enabled only when both peers advertise them.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed hello or when there is no common
    /// protocol version or codec.
    pub fn negotiate(initiator: &AgentHello, responder: &AgentHello) -> Result<Self> {
        initiator.validate()?;
        responder.validate()?;

        let version = initiator
            .supported_versions
            .intersection(&responder.supported_versions)
            .max()
            .copied()
            .ok_or(ProtocolError::NoCommonVersion)?;
        let codec = initiator
            .codecs
            .intersection(&responder.codecs)
            .next()
            .cloned()
            .ok_or(ProtocolError::NoCommonCodec)?;
        let extensions = initiator
            .extensions
            .intersection(&responder.extensions)
            .cloned()
            .collect();
        let max_frame_bytes = initiator.max_frame_bytes.min(responder.max_frame_bytes);
        let max_concurrent_interactions = initiator
            .max_concurrent_interactions
            .min(responder.max_concurrent_interactions);

        let mut negotiated = Self {
            version,
            codec,
            extensions,
            max_frame_bytes,
            max_concurrent_interactions,
            transcript_digest: Digest([0; 32]),
        };
        negotiated.transcript_digest = negotiated.compute_transcript_digest(initiator, responder);
        Ok(negotiated)
    }

    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    #[must_use]
    pub fn codec(&self) -> &str {
        &self.codec
    }

    #[must_use]
    pub const fn extensions(&self) -> &BTreeSet<String> {
        &self.extensions
    }

    #[must_use]
    pub const fn max_frame_bytes(&self) -> u64 {
        self.max_frame_bytes
    }

    #[must_use]
    pub const fn max_concurrent_interactions(&self) -> u32 {
        self.max_concurrent_interactions
    }

    #[must_use]
    pub const fn transcript_digest(&self) -> Digest {
        self.transcript_digest
    }

    fn compute_transcript_digest(&self, initiator: &AgentHello, responder: &AgentHello) -> Digest {
        let mut transcript = NEGOTIATION_DOMAIN.to_vec();
        append_bytes(&mut transcript, &initiator.transcript());
        append_bytes(&mut transcript, &responder.transcript());
        transcript.extend_from_slice(&self.version.major.to_be_bytes());
        transcript.extend_from_slice(&self.version.minor.to_be_bytes());
        append_bytes(&mut transcript, self.codec.as_bytes());
        append_strings(&mut transcript, &self.extensions);
        transcript.extend_from_slice(&self.max_frame_bytes.to_be_bytes());
        transcript.extend_from_slice(&self.max_concurrent_interactions.to_be_bytes());
        Digest(Sha256::digest(transcript).into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HandshakeRole {
    Initiator = 1,
    Responder = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityChallenge {
    pub id: ChallengeId,
    pub nonce: Nonce,
    pub negotiation_digest: Digest,
    pub accepted_credential_types: BTreeSet<String>,
}

impl IdentityChallenge {
    /// Validates a challenge against the authenticated hello negotiation.
    ///
    /// # Errors
    ///
    /// Returns an error for zero identifiers, a mismatched transcript, or an
    /// invalid credential type list.
    pub fn validate(&self, expected_negotiation_digest: Digest) -> Result<()> {
        if self.id.is_zero() || self.nonce.is_zero() || self.negotiation_digest.is_zero() {
            return Err(ProtocolError::Malformed("zero identity challenge field"));
        }
        if self.negotiation_digest != expected_negotiation_digest {
            return Err(ProtocolError::HandshakeTranscriptMismatch);
        }
        if self.accepted_credential_types.is_empty()
            || self.accepted_credential_types.len() > MAX_CREDENTIAL_TYPES
            || self
                .accepted_credential_types
                .iter()
                .any(|credential_type| !valid_name(credential_type))
        {
            return Err(ProtocolError::Malformed(
                "invalid accepted credential type list",
            ));
        }
        Ok(())
    }

    fn append_transcript(&self, output: &mut Vec<u8>) {
        append_bytes(output, &self.id.0);
        append_bytes(output, &self.nonce.0);
        append_bytes(output, &self.negotiation_digest.0);
        append_strings(output, &self.accepted_credential_types);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityProofContext {
    pub session: SessionId,
    pub prover_role: HandshakeRole,
    pub audience: KeyId,
    pub transport_binding: Digest,
}

impl IdentityProofContext {
    fn validate(self) -> Result<()> {
        if self.session.is_zero() || self.audience.is_zero() || self.transport_binding.is_zero() {
            return Err(ProtocolError::Malformed(
                "zero identity proof context field",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct IdentityProof {
    pub challenge_id: ChallengeId,
    pub agent_key_id: KeyId,
    pub credential_type: String,
    pub principal_credential: Vec<u8>,
    pub workload_credential: Vec<u8>,
    pub transport_binding: Digest,
    pub signature: [u8; 64],
}

impl IdentityProof {
    /// Creates proof that the agent key participated in this exact secure
    /// channel and negotiation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid context, challenge, credential type, or
    /// oversized credentials.
    pub fn sign(
        key: &SigningKey,
        context: IdentityProofContext,
        challenge: &IdentityChallenge,
        negotiation: &NegotiatedParameters,
        credential_type: &str,
        principal_credential: Vec<u8>,
        workload_credential: Vec<u8>,
    ) -> Result<Self> {
        context.validate()?;
        challenge.validate(negotiation.transcript_digest())?;
        validate_credentials(
            challenge,
            credential_type,
            &principal_credential,
            &workload_credential,
        )?;

        let mut proof = Self {
            challenge_id: challenge.id,
            agent_key_id: key_id(&key.verifying_key()),
            credential_type: credential_type.to_owned(),
            principal_credential,
            workload_credential,
            transport_binding: context.transport_binding,
            signature: [0; 64],
        };
        proof.signature = key
            .sign(&proof.signing_transcript(context, challenge))
            .to_bytes();
        Ok(proof)
    }

    fn verify(
        &self,
        key: &VerifyingKey,
        context: IdentityProofContext,
        challenge: &IdentityChallenge,
        expected_negotiation_digest: Digest,
    ) -> Result<AuthenticatedPeer> {
        context.validate()?;
        challenge.validate(expected_negotiation_digest)?;
        if self.challenge_id != challenge.id {
            return Err(ProtocolError::ChallengeMismatch);
        }
        if self.agent_key_id != key_id(key) {
            return Err(ProtocolError::SenderKeyMismatch);
        }
        if self.transport_binding != context.transport_binding {
            return Err(ProtocolError::TransportBindingMismatch);
        }
        validate_credentials(
            challenge,
            &self.credential_type,
            &self.principal_credential,
            &self.workload_credential,
        )?;

        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(&self.signing_transcript(context, challenge), &signature)
            .map_err(|_| ProtocolError::InvalidSignature)?;

        Ok(AuthenticatedPeer {
            key_id: self.agent_key_id,
            credential_type: self.credential_type.clone(),
            principal_credential: self.principal_credential.clone(),
            workload_credential: self.workload_credential.clone(),
            negotiation_digest: expected_negotiation_digest,
        })
    }

    fn signing_transcript(
        &self,
        context: IdentityProofContext,
        challenge: &IdentityChallenge,
    ) -> Vec<u8> {
        let mut output = IDENTITY_PROOF_DOMAIN.to_vec();
        output.push(context.prover_role as u8);
        append_bytes(&mut output, &context.session.0);
        append_bytes(&mut output, &self.agent_key_id.0);
        append_bytes(&mut output, &context.audience.0);
        challenge.append_transcript(&mut output);
        append_bytes(&mut output, &context.transport_binding.0);
        append_bytes(&mut output, self.credential_type.as_bytes());
        append_bytes(&mut output, &self.principal_credential);
        append_bytes(&mut output, &self.workload_credential);
        output
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedPeer {
    pub key_id: KeyId,
    pub credential_type: String,
    pub principal_credential: Vec<u8>,
    pub workload_credential: Vec<u8>,
    pub negotiation_digest: Digest,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConnectionState {
    #[default]
    New,
    Secure,
    Authenticated,
    Authorized,
    Active,
    Closed,
}

impl ConnectionState {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Secure => "secure",
            Self::Authenticated => "authenticated",
            Self::Authorized => "authorized",
            Self::Active => "active",
            Self::Closed => "closed",
        }
    }
}

struct PendingAuthentication {
    context: IdentityProofContext,
    challenge: IdentityChallenge,
    negotiation_digest: Digest,
}

#[derive(Default)]
pub struct Handshake {
    state: ConnectionState,
    pending: Option<PendingAuthentication>,
    authenticated_peer: Option<AuthenticatedPeer>,
}

impl Handshake {
    #[must_use]
    pub const fn state(&self) -> ConnectionState {
        self.state
    }

    #[must_use]
    pub const fn authenticated_peer(&self) -> Option<&AuthenticatedPeer> {
        self.authenticated_peer.as_ref()
    }

    /// Records the secure transport and installs the one-time peer challenge.
    ///
    /// # Errors
    ///
    /// Returns an error unless the connection is new or if the proof context
    /// and challenge do not match the negotiated hello transcript.
    pub fn secure_transport(
        &mut self,
        context: IdentityProofContext,
        negotiation: &NegotiatedParameters,
        challenge: IdentityChallenge,
    ) -> Result<()> {
        if self.state != ConnectionState::New {
            return Err(invalid_transition(self.state, ConnectionState::Secure));
        }
        context.validate()?;
        challenge.validate(negotiation.transcript_digest())?;
        self.pending = Some(PendingAuthentication {
            context,
            challenge,
            negotiation_digest: negotiation.transcript_digest(),
        });
        self.state = ConnectionState::Secure;
        Ok(())
    }

    /// Verifies and consumes the pending identity challenge.
    ///
    /// # Errors
    ///
    /// Returns an error unless a secure transport has installed a challenge,
    /// or when any key, transcript, channel binding, credential, or signature
    /// check fails.
    pub fn authenticate_peer(
        &mut self,
        proof: &IdentityProof,
        peer_key: &VerifyingKey,
    ) -> Result<AuthenticatedPeer> {
        if self.state != ConnectionState::Secure {
            return Err(invalid_transition(
                self.state,
                ConnectionState::Authenticated,
            ));
        }
        let pending = self
            .pending
            .as_ref()
            .ok_or(ProtocolError::ChallengeMismatch)?;
        let authenticated_peer = proof.verify(
            peer_key,
            pending.context,
            &pending.challenge,
            pending.negotiation_digest,
        )?;

        self.pending = None;
        self.authenticated_peer = Some(authenticated_peer.clone());
        self.state = ConnectionState::Authenticated;
        Ok(authenticated_peer)
    }

    /// Records issuance of a session authorization grant.
    ///
    /// # Errors
    ///
    /// Returns an error unless the peer is authenticated.
    pub fn authorize(&mut self) -> Result<()> {
        self.transition(ConnectionState::Authorized)
    }

    /// Activates the authorized session.
    ///
    /// # Errors
    ///
    /// Returns an error unless the session is authorized.
    pub fn activate(&mut self) -> Result<()> {
        self.transition(ConnectionState::Active)
    }

    pub fn close(&mut self) {
        self.pending = None;
        self.authenticated_peer = None;
        self.state = ConnectionState::Closed;
    }

    fn transition(&mut self, next: ConnectionState) -> Result<()> {
        let valid = matches!(
            (self.state, next),
            (ConnectionState::Authenticated, ConnectionState::Authorized)
                | (ConnectionState::Authorized, ConnectionState::Active)
        );
        if !valid {
            return Err(invalid_transition(self.state, next));
        }
        self.state = next;
        Ok(())
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME_BYTES
        && value.is_ascii()
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn validate_credentials(
    challenge: &IdentityChallenge,
    credential_type: &str,
    principal_credential: &[u8],
    workload_credential: &[u8],
) -> Result<()> {
    if !valid_name(credential_type)
        || !challenge
            .accepted_credential_types
            .contains(credential_type)
    {
        return Err(ProtocolError::CredentialRejected(
            "credential type was not offered",
        ));
    }
    if principal_credential.len() > MAX_CREDENTIAL_BYTES
        || workload_credential.len() > MAX_CREDENTIAL_BYTES
    {
        return Err(ProtocolError::CredentialRejected(
            "identity credential exceeds size limit",
        ));
    }
    Ok(())
}

fn append_count(output: &mut Vec<u8>, count: usize) {
    output.extend_from_slice(
        &u32::try_from(count)
            .expect("validated handshake collection length must fit u32")
            .to_be_bytes(),
    );
}

fn append_strings(output: &mut Vec<u8>, values: &BTreeSet<String>) {
    append_count(output, values.len());
    for value in values {
        append_bytes(output, value.as_bytes());
    }
}

fn invalid_transition(from: ConnectionState, to: ConnectionState) -> ProtocolError {
    ProtocolError::InvalidTransition {
        from: from.name(),
        to: to.name(),
    }
}
