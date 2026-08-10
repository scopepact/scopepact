use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::envelope::Envelope;
use crate::error::{ProtocolError, Result};
use crate::types::{Digest, KeyId};

const ENVELOPE_DOMAIN: &[u8] = b"SCOPEPACT-ENVELOPE-V0\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedEnvelope {
    pub envelope: Envelope,
    pub signature: [u8; 64],
}

impl SignedEnvelope {
    /// Signs an envelope after confirming that it declares this key.
    ///
    /// # Errors
    ///
    /// Returns an error when the envelope's sender key ID does not match.
    pub fn sign(envelope: Envelope, key: &SigningKey) -> Result<Self> {
        if envelope.sender != key_id(&key.verifying_key()) {
            return Err(ProtocolError::SenderKeyMismatch);
        }
        let signature = key.sign(&envelope.signing_transcript()).to_bytes();
        Ok(Self {
            envelope,
            signature,
        })
    }

    /// Verifies the sender key ID and Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns an error when the key ID or signature does not match.
    pub fn verify(&self, key: &VerifyingKey) -> Result<()> {
        if self.envelope.sender != key_id(key) {
            return Err(ProtocolError::SenderKeyMismatch);
        }
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(&self.envelope.signing_transcript(), &signature)
            .map_err(|_| ProtocolError::InvalidSignature)
    }
}

#[must_use]
pub fn key_id(key: &VerifyingKey) -> KeyId {
    KeyId(Sha256::digest(key.as_bytes()).into())
}

#[must_use]
pub fn payload_digest(payload: &[u8]) -> Digest {
    Digest(Sha256::digest(payload).into())
}

pub(crate) fn transcript_prefix() -> Vec<u8> {
    ENVELOPE_DOMAIN.to_vec()
}

pub(crate) fn append_bytes(target: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("transcript field length must fit u32");
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
}
