use std::collections::{BTreeSet, HashSet};

use crate::error::{ProtocolError, Result};
use crate::types::{KeyId, Nonce};

pub struct ReplayGuard {
    sender: Option<KeyId>,
    highest_sequence: u64,
    seen_sequences: BTreeSet<u64>,
    seen_nonces: HashSet<Nonce>,
    window: u64,
    accepted_messages: u64,
    max_messages: u64,
}

impl ReplayGuard {
    #[must_use]
    pub fn new(window: u64, max_messages: u64) -> Self {
        Self {
            sender: None,
            highest_sequence: 0,
            seen_sequences: BTreeSet::new(),
            seen_nonces: HashSet::new(),
            window: window.max(1),
            accepted_messages: 0,
            max_messages,
        }
    }

    /// Validates and consumes a sender sequence and nonce.
    ///
    /// # Errors
    ///
    /// Returns an error for another sender, a duplicate or old value, or an
    /// exhausted session message budget.
    pub fn check_and_record(&mut self, sender: KeyId, sequence: u64, nonce: Nonce) -> Result<()> {
        if self.accepted_messages >= self.max_messages {
            return Err(ProtocolError::SessionMessageLimit);
        }
        if let Some(existing_sender) = self.sender {
            if existing_sender != sender {
                return Err(ProtocolError::SenderKeyMismatch);
            }
        }
        if self.seen_nonces.contains(&nonce) {
            return Err(ProtocolError::ReplayNonce);
        }
        if self.seen_sequences.contains(&sequence) {
            return Err(ProtocolError::ReplaySequence);
        }
        let minimum = self
            .highest_sequence
            .saturating_sub(self.window.saturating_sub(1));
        if self.highest_sequence != 0 && sequence < minimum {
            return Err(ProtocolError::SequenceTooOld);
        }

        self.sender = Some(sender);
        self.highest_sequence = self.highest_sequence.max(sequence);
        self.seen_sequences.insert(sequence);
        self.seen_nonces.insert(nonce);
        self.accepted_messages += 1;

        let new_minimum = self
            .highest_sequence
            .saturating_sub(self.window.saturating_sub(1));
        self.seen_sequences = self.seen_sequences.split_off(&new_minimum);
        Ok(())
    }
}
