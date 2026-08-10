use std::collections::BTreeSet;

use ed25519_dalek::VerifyingKey;

use crate::error::{ProtocolError, Result};
use crate::replay::ReplayGuard;
use crate::signing::{SignedEnvelope, append_bytes, payload_digest, transcript_prefix};
use crate::types::{Digest, InteractionId, KeyId, Nonce, SessionId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum MessageKind {
    Hello = 1,
    IdentityChallenge = 2,
    IdentityProof = 3,
    SessionGrant = 4,
    TaskOffer = 10,
    TaskAccept = 11,
    TaskProgress = 12,
    TaskResult = 13,
    TaskCancel = 14,
    EffectMandate = 20,
    EffectReceipt = 21,
    Error = 30,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub session: SessionId,
    pub interaction: Option<InteractionId>,
    pub sequence: u64,
    pub nonce: Nonce,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub sender: KeyId,
    pub audience: KeyId,
    pub policy_epoch: u64,
    pub message_kind: MessageKind,
    pub payload_schema: Digest,
    pub payload_digest: Digest,
    pub critical_extensions: Vec<String>,
}

impl Envelope {
    pub(crate) fn signing_transcript(&self) -> Vec<u8> {
        let mut output = transcript_prefix();
        output.extend_from_slice(&self.protocol_major.to_be_bytes());
        output.extend_from_slice(&self.protocol_minor.to_be_bytes());
        append_bytes(&mut output, &self.session.0);
        match self.interaction {
            Some(interaction) => {
                output.push(1);
                append_bytes(&mut output, &interaction.0);
            }
            None => output.push(0),
        }
        output.extend_from_slice(&self.sequence.to_be_bytes());
        append_bytes(&mut output, &self.nonce.0);
        output.extend_from_slice(&self.issued_at_ms.to_be_bytes());
        output.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        append_bytes(&mut output, &self.sender.0);
        append_bytes(&mut output, &self.audience.0);
        output.extend_from_slice(&self.policy_epoch.to_be_bytes());
        output.extend_from_slice(&(self.message_kind as u16).to_be_bytes());
        append_bytes(&mut output, &self.payload_schema.0);
        append_bytes(&mut output, &self.payload_digest.0);
        output.extend_from_slice(
            &u32::try_from(self.critical_extensions.len())
                .expect("extension count must fit u32")
                .to_be_bytes(),
        );
        for extension in &self.critical_extensions {
            append_bytes(&mut output, extension.as_bytes());
        }
        output
    }
}

#[derive(Clone, Debug)]
pub struct ReceiveContext {
    pub now_ms: i64,
    pub expected_session: SessionId,
    pub local_audience: KeyId,
    pub policy_epoch: u64,
    pub supported_major: u16,
    pub supported_minor: u16,
    pub max_clock_skew_ms: i64,
    pub max_lifetime_ms: i64,
    pub max_payload_bytes: usize,
    pub known_critical_extensions: BTreeSet<String>,
}

pub struct EnvelopeGuard {
    replay: ReplayGuard,
}

impl EnvelopeGuard {
    #[must_use]
    pub fn new(replay_window: u64, max_messages: u64) -> Self {
        Self {
            replay: ReplayGuard::new(replay_window, max_messages),
        }
    }

    /// Authenticates and validates a frame, then consumes its replay slot.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, tampered, stale, misaddressed,
    /// unsupported, oversized, or replayed frames.
    pub fn verify_and_record(
        &mut self,
        signed: &SignedEnvelope,
        payload: &[u8],
        key: &VerifyingKey,
        context: &ReceiveContext,
    ) -> Result<()> {
        Self::validate_shape(signed, payload, context)?;
        signed.verify(key)?;
        Self::validate_context(&signed.envelope, context)?;
        self.replay.check_and_record(
            signed.envelope.sender,
            signed.envelope.sequence,
            signed.envelope.nonce,
        )
    }

    fn validate_shape(
        signed: &SignedEnvelope,
        payload: &[u8],
        context: &ReceiveContext,
    ) -> Result<()> {
        let envelope = &signed.envelope;
        if payload.len() > context.max_payload_bytes {
            return Err(ProtocolError::PayloadTooLarge);
        }
        if envelope.session.is_zero()
            || envelope.nonce.is_zero()
            || envelope.sender.is_zero()
            || envelope.audience.is_zero()
            || envelope.payload_schema.is_zero()
            || envelope.payload_digest.is_zero()
            || envelope.sequence == 0
        {
            return Err(ProtocolError::Malformed("zero identifier or digest"));
        }
        if envelope.expires_at_ms < envelope.issued_at_ms {
            return Err(ProtocolError::Malformed("expiry precedes issue time"));
        }
        if payload_digest(payload) != envelope.payload_digest {
            return Err(ProtocolError::PayloadDigestMismatch);
        }
        if envelope.critical_extensions.len() > 32
            || envelope
                .critical_extensions
                .iter()
                .any(|extension| extension.is_empty() || extension.len() > 256)
        {
            return Err(ProtocolError::Malformed("invalid critical extension list"));
        }
        Ok(())
    }

    fn validate_context(envelope: &Envelope, context: &ReceiveContext) -> Result<()> {
        if envelope.protocol_major != context.supported_major
            || envelope.protocol_minor > context.supported_minor
        {
            return Err(ProtocolError::UnsupportedVersion {
                major: envelope.protocol_major,
                minor: envelope.protocol_minor,
            });
        }
        if envelope.session != context.expected_session {
            return Err(ProtocolError::SessionMismatch);
        }
        if envelope.audience != context.local_audience {
            return Err(ProtocolError::AudienceMismatch);
        }
        if envelope.policy_epoch != context.policy_epoch {
            return Err(ProtocolError::PolicyEpochMismatch);
        }
        if envelope.issued_at_ms > context.now_ms.saturating_add(context.max_clock_skew_ms) {
            return Err(ProtocolError::IssuedInFuture);
        }
        if context.now_ms > envelope.expires_at_ms {
            return Err(ProtocolError::Expired);
        }
        if envelope.expires_at_ms.saturating_sub(envelope.issued_at_ms) > context.max_lifetime_ms {
            return Err(ProtocolError::LifetimeTooLong);
        }
        for extension in &envelope.critical_extensions {
            if !context.known_critical_extensions.contains(extension) {
                return Err(ProtocolError::UnknownCriticalExtension(extension.clone()));
            }
        }
        Ok(())
    }
}
