//! Crash-safe Guard decision journal.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use scopepact_core::authorization::{ActionRequest, PaymentRequest};
use scopepact_core::types::{ActorId, Digest, EffectId, GrantId, InteractionId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    EffectCommitment, GuardDecision, GuardError, GuardEvaluation, GuardPolicy, ReceiptSigner,
    Result, SignedDecisionReceipt,
    policy_bundle::{VerifiedPolicyBundle, policy_content_digest},
};

const STATE_RECORD_DOMAIN: &[u8] = b"SCOPEPACT-GUARD-STATE-RECORD-V3\0";
const SIGNER_ROTATION_DOMAIN: &[u8] = b"SCOPEPACT-GUARD-SIGNER-ROTATION-V1\0";
const POLICY_ACTIVATION_DOMAIN: &[u8] = b"SCOPEPACT-GUARD-POLICY-ACTIVATION-V1\0";
const STATE_VERSION: u16 = 3;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
const MAX_HEAD_RECORD_BYTES: usize = 1_024;
const MAX_STATE_RECORDS: usize = 50_000;
const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_HEAD_BYTES: usize = 16 * 1024 * 1024;

/// State recovered from a validated decision journal.
pub struct RecoveredState {
    pub activated_at_ms: i64,
    pub commitments: Vec<EffectCommitment>,
    pub receipts: Vec<SignedDecisionReceipt>,
    pub signer_trust: SignerTrustBundle,
}

/// Public signer history derived from the state journal.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerTrustBundle {
    pub format: String,
    pub principal: String,
    pub agent: String,
    pub policies: Vec<PolicyTrustScope>,
    pub keys: Vec<SignerTrustKey>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyTrustScope {
    pub policy_epoch: u64,
    pub policy_digest: String,
    pub bundle_digest: String,
    pub not_before_ms: i64,
    pub not_after_ms: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerTrustKey {
    pub key_id: String,
    pub public_key: String,
    pub not_before_ms: i64,
    pub not_after_ms: Option<i64>,
    pub status: SignerStatus,
    pub replaces: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerStatus {
    Active,
    Retired,
    Revoked,
}

/// Result of removing incomplete, uncommitted bytes from state file tails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TailRecovery {
    pub journal_bytes_removed: usize,
    pub head_bytes_removed: usize,
}

/// Exclusive append handle for the durable decision journal and its head log.
pub struct DurableState {
    journal: File,
    head: File,
    poisoned: bool,
    sequence: u64,
    record_hash: String,
    policy_epoch: u64,
    policy_digest: String,
    bundle_digest: String,
    revoked_rule_ids: Vec<String>,
    policy_activated_at_ms: i64,
    policy_expires_at_ms: i64,
    principal: String,
    agent: String,
    active_signer_key_id: String,
    active_signer_public_key: String,
    last_event_at_ms: i64,
    signer_trust: SignerTrustBundle,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    state_version: u16,
    sequence: u64,
    previous_hash: String,
    entry: JournalEntry,
    record_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
enum JournalEntry {
    Genesis(GenesisEntry),
    Decision(Box<DecisionEntry>),
    SignerRotation(SignerRotationEntry),
    PolicyActivation(PolicyActivationEntry),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenesisEntry {
    policy_epoch: u64,
    policy_digest: String,
    bundle_digest: String,
    revoked_rule_ids: Vec<String>,
    principal: String,
    agent: String,
    activated_at_ms: i64,
    expires_at_ms: i64,
    initial_signer_key_id: String,
    initial_signer_public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignerRotationEntry {
    rotation_sequence: u64,
    policy_epoch: u64,
    policy_digest: String,
    previous_key_id: String,
    previous_public_key: String,
    new_key_id: String,
    new_public_key: String,
    activated_at_ms: i64,
    previous_signature: String,
    new_signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyActivationEntry {
    activation_sequence: u64,
    previous_policy_epoch: u64,
    previous_policy_digest: String,
    new_policy_epoch: u64,
    new_policy_digest: String,
    new_bundle_digest: String,
    new_revoked_rule_ids: Vec<String>,
    principal: String,
    agent: String,
    activated_at_ms: i64,
    expires_at_ms: i64,
    receipt_signer_key_id: String,
    signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DecisionEntry {
    receipt: SignedDecisionReceipt,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commitment: Option<StoredCommitment>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredCommitment {
    grant_id: String,
    effect_id: String,
    effect_digest: String,
    actor: String,
    interaction: Option<String>,
    action: String,
    resource: String,
    payment: Option<StoredPayment>,
    authorized_at_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredPayment {
    currency: String,
    amount_atomic: String,
    payee: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HeadRecord {
    state_version: u16,
    sequence: u64,
    record_hash: String,
}

#[derive(Serialize)]
struct RecordHashInput<'a> {
    state_version: u16,
    sequence: u64,
    previous_hash: &'a str,
    entry: &'a JournalEntry,
}

#[derive(Serialize)]
struct RotationTranscript<'a> {
    rotation_sequence: u64,
    policy_epoch: u64,
    policy_digest: &'a str,
    previous_key_id: &'a str,
    previous_public_key: &'a str,
    new_key_id: &'a str,
    new_public_key: &'a str,
    activated_at_ms: i64,
}

#[derive(Serialize)]
struct PolicyActivationTranscript<'a> {
    activation_sequence: u64,
    previous_policy_epoch: u64,
    previous_policy_digest: &'a str,
    new_policy_epoch: u64,
    new_policy_digest: &'a str,
    new_bundle_digest: &'a str,
    new_revoked_rule_ids: &'a [String],
    principal: &'a str,
    agent: &'a str,
    activated_at_ms: i64,
    expires_at_ms: i64,
    receipt_signer_key_id: &'a str,
}

struct ValidatedJournal {
    genesis: GenesisEntry,
    active_policy_epoch: u64,
    active_policy_digest: String,
    active_bundle_digest: String,
    active_revoked_rule_ids: Vec<String>,
    active_policy_activated_at_ms: i64,
    active_policy_expires_at_ms: i64,
    commitments: Vec<EffectCommitment>,
    receipts: Vec<SignedDecisionReceipt>,
    active_signer_key_id: String,
    active_signer_public_key: String,
    last_event_at_ms: i64,
    signer_trust: SignerTrustBundle,
}

struct PolicyBinding {
    policy: GuardPolicy,
    policy_digest: String,
    bundle_digest: String,
    revoked_rule_ids: Vec<String>,
    activated_at_ms: i64,
    expires_at_ms: i64,
}

struct OpenStateFiles {
    journal: File,
    head: File,
    head_path: PathBuf,
}

impl PolicyBinding {
    fn unsigned(policy: &GuardPolicy, now_ms: i64) -> Result<Self> {
        let digest = policy_content_digest(policy)?;
        Ok(Self {
            policy: policy.clone(),
            policy_digest: digest.clone(),
            bundle_digest: format!("unsigned:{digest}"),
            revoked_rule_ids: Vec::new(),
            activated_at_ms: now_ms,
            expires_at_ms: now_ms.checked_add(policy.valid_for_ms).ok_or_else(|| {
                GuardError::DurableState("policy validity interval overflows".into())
            })?,
        })
    }

    fn verified(policy: &VerifiedPolicyBundle) -> Self {
        let mut revoked_rule_ids: Vec<_> = policy.revoked_rule_ids.iter().cloned().collect();
        revoked_rule_ids.sort_unstable();
        Self {
            policy: policy.policy.clone(),
            policy_digest: policy.policy_digest.clone(),
            bundle_digest: policy.bundle_digest.clone(),
            revoked_rule_ids,
            activated_at_ms: policy.activated_at_ms,
            expires_at_ms: policy.expires_at_ms,
        }
    }
}

impl DurableState {
    /// Opens and exclusively locks a state journal, creating its genesis record
    /// when both state files are empty.
    ///
    /// # Errors
    ///
    /// Returns an error for concurrent use, I/O failure, corruption, rollback,
    /// policy mismatch, signer mismatch, or an invalid receipt or commitment.
    pub fn open(
        path: &Path,
        policy: &GuardPolicy,
        signer_public_key: &str,
        signer_key_id: &str,
        now_ms: i64,
    ) -> Result<(Self, RecoveredState)> {
        Self::open_binding(
            path,
            &PolicyBinding::unsigned(policy, now_ms)?,
            signer_public_key,
            signer_key_id,
            now_ms,
        )
    }

    /// Opens a journal bound to an authenticated policy bundle.
    ///
    /// # Errors
    ///
    /// Returns an error for an expired bundle, policy rollback or mismatch,
    /// signer mismatch, corrupt state, contention, or durable I/O failure.
    pub fn open_verified(
        path: &Path,
        policy: &VerifiedPolicyBundle,
        signer_public_key: &str,
        signer_key_id: &str,
        now_ms: i64,
    ) -> Result<(Self, RecoveredState)> {
        if now_ms > policy.expires_at_ms {
            return Err(GuardError::DurableState(
                "active policy bundle has expired".into(),
            ));
        }
        Self::open_binding(
            path,
            &PolicyBinding::verified(policy),
            signer_public_key,
            signer_key_id,
            now_ms,
        )
    }

    fn open_binding(
        path: &Path,
        binding: &PolicyBinding,
        signer_public_key: &str,
        signer_key_id: &str,
        now_ms: i64,
    ) -> Result<(Self, RecoveredState)> {
        let (files, empty) = open_state_files(path)?;
        if empty {
            Self::initialize_state(files, binding, signer_public_key, signer_key_id, now_ms)
        } else {
            Self::recover_state(files, path, binding, signer_public_key, signer_key_id)
        }
    }

    fn initialize_state(
        files: OpenStateFiles,
        binding: &PolicyBinding,
        signer_public_key: &str,
        signer_key_id: &str,
        now_ms: i64,
    ) -> Result<(Self, RecoveredState)> {
        validate_signer_identity(signer_public_key, signer_key_id)?;
        let activated_at_ms = binding.activated_at_ms.max(now_ms);
        let genesis = GenesisEntry {
            policy_epoch: binding.policy.policy_epoch,
            policy_digest: binding.policy_digest.clone(),
            bundle_digest: binding.bundle_digest.clone(),
            revoked_rule_ids: binding.revoked_rule_ids.clone(),
            principal: binding.policy.principal.clone(),
            agent: binding.policy.agent.clone(),
            activated_at_ms,
            expires_at_ms: binding.expires_at_ms,
            initial_signer_key_id: signer_key_id.to_owned(),
            initial_signer_public_key: signer_public_key.to_owned(),
        };
        let signer_trust = trust_from_genesis(&genesis);
        let mut state = Self {
            journal: files.journal,
            head: files.head,
            poisoned: false,
            sequence: 0,
            record_hash: ZERO_HASH.into(),
            policy_epoch: binding.policy.policy_epoch,
            policy_digest: genesis.policy_digest.clone(),
            bundle_digest: binding.bundle_digest.clone(),
            revoked_rule_ids: binding.revoked_rule_ids.clone(),
            policy_activated_at_ms: activated_at_ms,
            policy_expires_at_ms: binding.expires_at_ms,
            principal: binding.policy.principal.clone(),
            agent: binding.policy.agent.clone(),
            active_signer_key_id: signer_key_id.to_owned(),
            active_signer_public_key: signer_public_key.to_owned(),
            last_event_at_ms: activated_at_ms,
            signer_trust: signer_trust.clone(),
        };
        state.append_entry(JournalEntry::Genesis(genesis))?;
        Ok((
            state,
            RecoveredState {
                activated_at_ms,
                commitments: Vec::new(),
                receipts: Vec::new(),
                signer_trust,
            },
        ))
    }

    fn recover_state(
        mut files: OpenStateFiles,
        path: &Path,
        binding: &PolicyBinding,
        signer_public_key: &str,
        signer_key_id: &str,
    ) -> Result<(Self, RecoveredState)> {
        files
            .journal
            .seek(SeekFrom::Start(0))
            .map_err(|error| state_io(path, "rewind", &error))?;
        let records = read_records(&files.journal, path)?;
        let validated = validate_records(&records)?;
        validate_active_policy(&validated, binding)?;
        if validated.active_signer_key_id != signer_key_id
            || validated.active_signer_public_key != signer_public_key
        {
            return Err(GuardError::DurableState(
                "receipt signer does not match the journal's active signer".into(),
            ));
        }
        files
            .head
            .seek(SeekFrom::Start(0))
            .map_err(|error| state_io(&files.head_path, "rewind", &error))?;
        let head_record_count = validate_head_log(&files.head, &files.head_path, &records)?;

        let last = records.last().ok_or_else(|| {
            GuardError::DurableState("non-empty journal contains no records".into())
        })?;
        let mut state = Self {
            journal: files.journal,
            head: files.head,
            poisoned: false,
            sequence: last.sequence,
            record_hash: last.record_hash.clone(),
            policy_epoch: validated.active_policy_epoch,
            policy_digest: validated.active_policy_digest.clone(),
            bundle_digest: validated.active_bundle_digest.clone(),
            revoked_rule_ids: validated.active_revoked_rule_ids.clone(),
            policy_activated_at_ms: validated.active_policy_activated_at_ms,
            policy_expires_at_ms: validated.active_policy_expires_at_ms,
            principal: validated.genesis.principal.clone(),
            agent: validated.genesis.agent.clone(),
            active_signer_key_id: validated.active_signer_key_id.clone(),
            active_signer_public_key: validated.active_signer_public_key.clone(),
            last_event_at_ms: validated.last_event_at_ms,
            signer_trust: validated.signer_trust.clone(),
        };
        for record in &records[head_record_count..] {
            append_head_record(&mut state.head, record.sequence, &record.record_hash)?;
        }
        Ok((
            state,
            RecoveredState {
                activated_at_ms: validated.active_policy_activated_at_ms,
                commitments: validated.commitments,
                receipts: validated.receipts,
                signer_trust: validated.signer_trust,
            },
        ))
    }

    /// Commits and synchronizes a signed decision before its effect is
    /// forwarded.
    ///
    /// # Errors
    ///
    /// Returns an error if the evaluation is inconsistent or either durable
    /// file cannot be synchronized.
    pub fn commit(&mut self, evaluation: &GuardEvaluation) -> Result<()> {
        validate_evaluation(evaluation)?;
        if evaluation.receipt.receipt.policy_epoch != self.policy_epoch
            || evaluation.receipt.receipt.principal != self.principal
            || evaluation.receipt.receipt.agent != self.agent
        {
            return Err(GuardError::DurableState(
                "decision does not match the journal's active policy".into(),
            ));
        }
        if evaluation.receipt.signer_key_id != self.active_signer_key_id
            || evaluation.receipt.signer_public_key != self.active_signer_public_key
        {
            return Err(GuardError::DurableState(
                "decision was not signed by the journal's active signer".into(),
            ));
        }
        if evaluation.receipt.receipt.issued_at_ms < self.last_event_at_ms {
            return Err(GuardError::DurableState(
                "decision timestamp precedes the last durable event".into(),
            ));
        }
        let commitment = evaluation.commitment.as_ref().map(StoredCommitment::from);
        self.append_entry(JournalEntry::Decision(Box::new(DecisionEntry {
            receipt: evaluation.receipt.clone(),
            commitment,
        })))?;
        self.last_event_at_ms = evaluation.receipt.receipt.issued_at_ms;
        Ok(())
    }

    /// Authenticates and commits a monotonic transition to a verified policy
    /// bundle. The caller must restart its policy engine after this operation.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale epoch, changed principal or agent, inactive
    /// time window, wrong signer, provider failure, or durable I/O failure.
    pub fn activate_policy(
        &mut self,
        policy: &VerifiedPolicyBundle,
        signer: &dyn ReceiptSigner,
        activated_at_ms: i64,
    ) -> Result<()> {
        let binding = PolicyBinding::verified(policy);
        let signer_key_id = hex::encode(signer.key_id().0);
        let signer_public_key = hex::encode(signer.public_key());
        if signer_key_id != self.active_signer_key_id
            || signer_public_key != self.active_signer_public_key
        {
            return Err(GuardError::DurableState(
                "policy activation signer is not the journal's active signer".into(),
            ));
        }
        if binding.policy.policy_epoch <= self.policy_epoch {
            return Err(GuardError::DurableState(
                "new policy epoch must be greater than the active epoch".into(),
            ));
        }
        if binding.policy.principal != self.principal || binding.policy.agent != self.agent {
            return Err(GuardError::DurableState(
                "policy activation cannot change the principal or agent".into(),
            ));
        }
        let activated_at_ms = activated_at_ms.max(binding.activated_at_ms);
        if activated_at_ms < self.last_event_at_ms || activated_at_ms >= binding.expires_at_ms {
            return Err(GuardError::DurableState(
                "policy activation time is non-monotonic or outside the bundle window".into(),
            ));
        }
        let activation_sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| GuardError::DurableState("state sequence exhausted".into()))?;
        let mut activation = PolicyActivationEntry {
            activation_sequence,
            previous_policy_epoch: self.policy_epoch,
            previous_policy_digest: self.policy_digest.clone(),
            new_policy_epoch: binding.policy.policy_epoch,
            new_policy_digest: binding.policy_digest.clone(),
            new_bundle_digest: binding.bundle_digest.clone(),
            new_revoked_rule_ids: binding.revoked_rule_ids.clone(),
            principal: binding.policy.principal.clone(),
            agent: binding.policy.agent.clone(),
            activated_at_ms,
            expires_at_ms: binding.expires_at_ms,
            receipt_signer_key_id: signer_key_id,
            signature: String::new(),
        };
        activation.signature =
            hex::encode(signer.sign(&policy_activation_transcript(&activation)?)?);
        self.append_entry(JournalEntry::PolicyActivation(activation))?;

        let previous_policy = self.signer_trust.policies.last_mut().ok_or_else(|| {
            GuardError::DurableState("active policy trust scope is missing".into())
        })?;
        previous_policy.not_after_ms = Some(activated_at_ms);
        self.signer_trust.policies.push(PolicyTrustScope {
            policy_epoch: binding.policy.policy_epoch,
            policy_digest: binding.policy_digest.clone(),
            bundle_digest: binding.bundle_digest.clone(),
            not_before_ms: activated_at_ms,
            not_after_ms: None,
        });
        self.policy_epoch = binding.policy.policy_epoch;
        self.policy_digest = binding.policy_digest;
        self.bundle_digest = binding.bundle_digest;
        self.revoked_rule_ids = binding.revoked_rule_ids;
        self.policy_activated_at_ms = activated_at_ms;
        self.policy_expires_at_ms = binding.expires_at_ms;
        self.last_event_at_ms = activated_at_ms;
        Ok(())
    }

    /// Cross-signs and commits a transition from the active signer to a new
    /// signer. Historical keys remain in the exported trust bundle.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong current signer, reused key, non-monotonic
    /// activation time, invalid key metadata, provider failure, or durable I/O
    /// failure.
    pub fn rotate_signer(
        &mut self,
        current: &dyn ReceiptSigner,
        replacement: &dyn ReceiptSigner,
        activated_at_ms: i64,
    ) -> Result<()> {
        let current_public_key = hex::encode(current.public_key());
        let current_key_id = hex::encode(current.key_id().0);
        let new_public_key = hex::encode(replacement.public_key());
        let new_key_id = hex::encode(replacement.key_id().0);
        validate_signer_identity(&current_public_key, &current_key_id)?;
        validate_signer_identity(&new_public_key, &new_key_id)?;
        if current_key_id != self.active_signer_key_id
            || current_public_key != self.active_signer_public_key
        {
            return Err(GuardError::DurableState(
                "rotation current signer is not the journal's active signer".into(),
            ));
        }
        if new_key_id == current_key_id
            || self
                .signer_trust
                .keys
                .iter()
                .any(|key| key.key_id == new_key_id)
        {
            return Err(GuardError::DurableState(
                "rotation replacement key has already been used".into(),
            ));
        }
        if activated_at_ms < self.last_event_at_ms {
            return Err(GuardError::DurableState(
                "rotation activation precedes the last durable event".into(),
            ));
        }
        let rotation_sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| GuardError::DurableState("state sequence exhausted".into()))?;
        let mut rotation = SignerRotationEntry {
            rotation_sequence,
            policy_epoch: self.policy_epoch,
            policy_digest: self.policy_digest.clone(),
            previous_key_id: current_key_id.clone(),
            previous_public_key: current_public_key,
            new_key_id: new_key_id.clone(),
            new_public_key: new_public_key.clone(),
            activated_at_ms,
            previous_signature: String::new(),
            new_signature: String::new(),
        };
        let transcript = rotation_transcript(&rotation)?;
        rotation.previous_signature = hex::encode(current.sign(&transcript)?);
        rotation.new_signature = hex::encode(replacement.sign(&transcript)?);
        self.append_entry(JournalEntry::SignerRotation(rotation))?;

        let previous = self
            .signer_trust
            .keys
            .iter_mut()
            .find(|key| key.key_id == current_key_id)
            .ok_or_else(|| GuardError::DurableState("active trust key is missing".into()))?;
        previous.status = SignerStatus::Retired;
        previous.not_after_ms = Some(activated_at_ms);
        self.signer_trust.keys.push(SignerTrustKey {
            key_id: new_key_id.clone(),
            public_key: new_public_key.clone(),
            not_before_ms: activated_at_ms,
            not_after_ms: None,
            status: SignerStatus::Active,
            replaces: Some(current_key_id),
        });
        self.active_signer_key_id = new_key_id;
        self.active_signer_public_key = new_public_key;
        self.last_event_at_ms = activated_at_ms;
        Ok(())
    }

    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub fn record_hash(&self) -> &str {
        &self.record_hash
    }

    #[must_use]
    pub const fn state_version(&self) -> u16 {
        STATE_VERSION
    }

    #[must_use]
    pub fn signer_trust(&self) -> &SignerTrustBundle {
        &self.signer_trust
    }

    /// Removes only incomplete bytes after the final newline in the journal or
    /// head log. Every complete prefix is validated before either file changes.
    ///
    /// # Errors
    ///
    /// Returns an error when no partial tail exists, a complete prefix is
    /// invalid, or the durable files cannot be locked and synchronized.
    pub fn recover_partial_tail(
        path: &Path,
        policy: &GuardPolicy,
        signer_public_key: &str,
        signer_key_id: &str,
    ) -> Result<TailRecovery> {
        Self::recover_partial_tail_binding(
            path,
            &PolicyBinding::unsigned(policy, 0)?,
            signer_public_key,
            signer_key_id,
        )
    }

    /// Recovers an incomplete tail after validating the active signed-policy
    /// binding.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid complete records, policy or signer
    /// mismatch, contention, or durable I/O failure.
    pub fn recover_partial_tail_verified(
        path: &Path,
        policy: &VerifiedPolicyBundle,
        signer_public_key: &str,
        signer_key_id: &str,
    ) -> Result<TailRecovery> {
        Self::recover_partial_tail_binding(
            path,
            &PolicyBinding::verified(policy),
            signer_public_key,
            signer_key_id,
        )
    }

    fn recover_partial_tail_binding(
        path: &Path,
        binding: &PolicyBinding,
        signer_public_key: &str,
        signer_key_id: &str,
    ) -> Result<TailRecovery> {
        let head_path = head_path(path)?;
        let mut journal = open_private_append_file(path)?;
        fs2::FileExt::try_lock_exclusive(&journal).map_err(|error| {
            GuardError::DurableState(format!(
                "cannot exclusively lock {}: {error}",
                path.display()
            ))
        })?;
        let mut head = open_private_append_file(&head_path)?;
        let journal_bytes = read_file_bytes(&mut journal, path)?;
        let head_bytes = read_file_bytes(&mut head, &head_path)?;
        let (journal_prefix, journal_bytes_removed) = complete_prefix(&journal_bytes, path)?;
        let (head_prefix, head_bytes_removed) = complete_prefix(&head_bytes, &head_path)?;
        if journal_bytes_removed == 0 && head_bytes_removed == 0 {
            return Err(GuardError::DurableState(
                "state files have no partial trailing record to recover".into(),
            ));
        }

        let records = parse_record_lines(journal_prefix, path)?;
        let validated = validate_records(&records)?;
        validate_active_policy(&validated, binding)?;
        if validated.active_signer_key_id != signer_key_id
            || validated.active_signer_public_key != signer_public_key
        {
            return Err(GuardError::DurableState(
                "receipt signer does not match the journal's active signer".into(),
            ));
        }
        let heads = parse_head_lines(head_prefix, &head_path)?;
        validate_heads(&heads, &records)?;

        journal
            .set_len(u64::try_from(journal_prefix.len()).map_err(|_| {
                GuardError::DurableState("journal recovery length exceeds u64".into())
            })?)
            .map_err(|error| state_io(path, "truncate partial tail from", &error))?;
        journal
            .sync_all()
            .map_err(|error| state_io(path, "synchronize", &error))?;
        head.set_len(
            u64::try_from(head_prefix.len())
                .map_err(|_| GuardError::DurableState("head recovery length exceeds u64".into()))?,
        )
        .map_err(|error| state_io(&head_path, "truncate partial tail from", &error))?;
        head.sync_all()
            .map_err(|error| state_io(&head_path, "synchronize", &error))?;

        Ok(TailRecovery {
            journal_bytes_removed,
            head_bytes_removed,
        })
    }

    fn append_entry(&mut self, entry: JournalEntry) -> Result<()> {
        if self.poisoned {
            return Err(GuardError::DurableState(
                "state writer is poisoned after a prior append failure; restart and validate the journal"
                    .into(),
            ));
        }
        if let Err(error) = self.append_entry_inner(entry) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(())
    }

    fn append_entry_inner(&mut self, entry: JournalEntry) -> Result<()> {
        let sequence = if self.record_hash == ZERO_HASH {
            0
        } else {
            self.sequence
                .checked_add(1)
                .ok_or_else(|| GuardError::DurableState("state sequence exhausted".into()))?
        };
        let record_hash = record_hash(sequence, &self.record_hash, &entry)?;
        let record = JournalRecord {
            state_version: STATE_VERSION,
            sequence,
            previous_hash: self.record_hash.clone(),
            entry,
            record_hash: record_hash.clone(),
        };
        let mut encoded = serde_json::to_vec(&record)?;
        if encoded.len() > MAX_RECORD_BYTES {
            return Err(GuardError::DurableState(
                "state record exceeds the 8 MiB limit".into(),
            ));
        }
        encoded.push(b'\n');
        self.journal
            .seek(SeekFrom::End(0))
            .map_err(|error| GuardError::DurableState(format!("cannot seek journal: {error}")))?;
        self.journal
            .write_all(&encoded)
            .map_err(|error| GuardError::DurableState(format!("cannot append journal: {error}")))?;
        self.journal.sync_all().map_err(|error| {
            GuardError::DurableState(format!("cannot synchronize journal: {error}"))
        })?;
        self.sequence = sequence;
        self.record_hash = record_hash;
        self.append_head()
    }

    fn append_head(&mut self) -> Result<()> {
        append_head_record(&mut self.head, self.sequence, &self.record_hash)
    }
}

fn append_head_record(head: &mut File, sequence: u64, record_hash: &str) -> Result<()> {
    let record = HeadRecord {
        state_version: STATE_VERSION,
        sequence,
        record_hash: record_hash.to_owned(),
    };
    let mut encoded = serde_json::to_vec(&record)?;
    if encoded.len() > MAX_HEAD_RECORD_BYTES {
        return Err(GuardError::DurableState(
            "head record exceeds the 1 KiB limit".into(),
        ));
    }
    encoded.push(b'\n');
    head.seek(SeekFrom::End(0))
        .map_err(|error| GuardError::DurableState(format!("cannot seek head log: {error}")))?;
    head.write_all(&encoded)
        .map_err(|error| GuardError::DurableState(format!("cannot append head log: {error}")))?;
    head.sync_all()
        .map_err(|error| GuardError::DurableState(format!("cannot synchronize head log: {error}")))
}

impl From<&EffectCommitment> for StoredCommitment {
    fn from(commitment: &EffectCommitment) -> Self {
        Self {
            grant_id: hex::encode(commitment.grant_id.0),
            effect_id: hex::encode(commitment.request.effect_id.0),
            effect_digest: hex::encode(commitment.request.effect_digest.0),
            actor: hex::encode(commitment.request.actor.0),
            interaction: commitment
                .request
                .interaction
                .map(|value| hex::encode(value.0)),
            action: commitment.request.action.clone(),
            resource: commitment.request.resource.clone(),
            payment: commitment
                .request
                .payment
                .as_ref()
                .map(|payment| StoredPayment {
                    currency: payment.currency.clone(),
                    amount_atomic: payment.amount_atomic.to_string(),
                    payee: hex::encode(payment.payee.0),
                }),
            authorized_at_ms: commitment.authorized_at_ms,
        }
    }
}

impl StoredCommitment {
    fn decode(&self) -> Result<EffectCommitment> {
        let payment = self
            .payment
            .as_ref()
            .map(|payment| -> Result<PaymentRequest> {
                Ok(PaymentRequest {
                    currency: payment.currency.clone(),
                    amount_atomic: payment.amount_atomic.parse().map_err(|_| {
                        GuardError::DurableState(
                            "journal payment amount is not a valid u128".into(),
                        )
                    })?,
                    payee: ActorId(decode_hex(&payment.payee, "payment payee")?),
                })
            })
            .transpose()?;
        Ok(EffectCommitment {
            grant_id: GrantId(decode_hex(&self.grant_id, "grant ID")?),
            request: ActionRequest {
                effect_id: EffectId(decode_hex(&self.effect_id, "effect ID")?),
                effect_digest: Digest(decode_hex(&self.effect_digest, "effect digest")?),
                actor: ActorId(decode_hex(&self.actor, "actor ID")?),
                interaction: self
                    .interaction
                    .as_deref()
                    .map(|value| decode_hex(value, "interaction ID").map(InteractionId))
                    .transpose()?,
                action: self.action.clone(),
                resource: self.resource.clone(),
                payment,
            },
            authorized_at_ms: self.authorized_at_ms,
        })
    }
}

fn open_state_files(path: &Path) -> Result<(OpenStateFiles, bool)> {
    let head_path = head_path(path)?;
    let journal = open_private_append_file(path)?;
    fs2::FileExt::try_lock_exclusive(&journal).map_err(|error| {
        GuardError::DurableState(format!(
            "cannot exclusively lock {}: {error}",
            path.display()
        ))
    })?;
    let head = open_private_append_file(&head_path)?;
    let journal_empty = journal
        .metadata()
        .map_err(|error| state_io(path, "inspect", &error))?
        .len()
        == 0;
    let head_empty = head
        .metadata()
        .map_err(|error| state_io(&head_path, "inspect", &error))?
        .len()
        == 0;
    if journal_empty && !head_empty {
        return Err(GuardError::DurableState(
            "head log is ahead of an empty journal; explicit rollback recovery is required".into(),
        ));
    }
    Ok((
        OpenStateFiles {
            journal,
            head,
            head_path,
        },
        journal_empty,
    ))
}

fn open_private_append_file(path: &Path) -> Result<File> {
    #[cfg(not(unix))]
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(GuardError::DurableState(format!(
                "{} must be a regular file, not a symlink or special file",
                path.display()
            )));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|error| state_io(path, "open", &error))?;
    let metadata = file
        .metadata()
        .map_err(|error| state_io(path, "inspect", &error))?;
    if !metadata.is_file() {
        return Err(GuardError::DurableState(format!(
            "{} must be a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(GuardError::DurableState(format!(
                "{} permissions must not grant group or other access",
                path.display()
            )));
        }
    }
    Ok(file)
}

fn head_path(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| GuardError::DurableState("state path must name a file".into()))?;
    let mut head_name = file_name.to_os_string();
    head_name.push(".head");
    Ok(path.with_file_name(head_name))
}

fn read_records(file: &File, path: &Path) -> Result<Vec<JournalRecord>> {
    parse_record_lines_from_reader(file, path)
}

fn validated_genesis(records: &[JournalRecord]) -> Result<&GenesisEntry> {
    let first = records
        .first()
        .ok_or_else(|| GuardError::DurableState("state journal is empty".into()))?;
    let JournalEntry::Genesis(genesis) = &first.entry else {
        return Err(GuardError::DurableState(
            "first state record is not genesis".into(),
        ));
    };
    if genesis.policy_epoch == 0
        || genesis.policy_digest.len() != 64
        || genesis.bundle_digest.is_empty()
        || genesis.principal.is_empty()
        || genesis.agent.is_empty()
        || genesis.expires_at_ms <= genesis.activated_at_ms
        || !sorted_unique(&genesis.revoked_rule_ids)
    {
        return Err(GuardError::DurableState(
            "state journal genesis has an invalid policy binding".into(),
        ));
    }
    validate_signer_identity(
        &genesis.initial_signer_public_key,
        &genesis.initial_signer_key_id,
    )?;
    Ok(genesis)
}

fn validate_record_chain(records: &[JournalRecord]) -> Result<()> {
    let mut previous_hash = ZERO_HASH.to_owned();
    for (index, record) in records.iter().enumerate() {
        let expected_sequence = u64::try_from(index)
            .map_err(|_| GuardError::DurableState("too many state records".into()))?;
        if record.state_version != STATE_VERSION
            || record.sequence != expected_sequence
            || record.previous_hash != previous_hash
            || record.record_hash
                != record_hash(record.sequence, &record.previous_hash, &record.entry)?
        {
            return Err(GuardError::DurableState(format!(
                "state record {index} failed version, sequence, or hash validation"
            )));
        }
        if index > 0 && matches!(&record.entry, JournalEntry::Genesis(_)) {
            return Err(GuardError::DurableState(
                "state journal contains more than one genesis record".into(),
            ));
        }
        previous_hash.clone_from(&record.record_hash);
    }
    Ok(())
}

struct JournalAccumulator {
    genesis: GenesisEntry,
    active_policy_epoch: u64,
    active_policy_digest: String,
    active_bundle_digest: String,
    active_revoked_rule_ids: Vec<String>,
    active_policy_activated_at_ms: i64,
    active_policy_expires_at_ms: i64,
    commitments: Vec<EffectCommitment>,
    receipts: Vec<SignedDecisionReceipt>,
    active_signer_key_id: String,
    active_signer_public_key: String,
    last_event_at_ms: i64,
    signer_trust: SignerTrustBundle,
}

impl JournalAccumulator {
    fn new(genesis: &GenesisEntry) -> Self {
        Self {
            genesis: genesis.clone(),
            active_policy_epoch: genesis.policy_epoch,
            active_policy_digest: genesis.policy_digest.clone(),
            active_bundle_digest: genesis.bundle_digest.clone(),
            active_revoked_rule_ids: genesis.revoked_rule_ids.clone(),
            active_policy_activated_at_ms: genesis.activated_at_ms,
            active_policy_expires_at_ms: genesis.expires_at_ms,
            commitments: Vec::new(),
            receipts: Vec::new(),
            active_signer_key_id: genesis.initial_signer_key_id.clone(),
            active_signer_public_key: genesis.initial_signer_public_key.clone(),
            last_event_at_ms: genesis.activated_at_ms,
            signer_trust: trust_from_genesis(genesis),
        }
    }

    fn apply(&mut self, record: &JournalRecord) -> Result<()> {
        match &record.entry {
            JournalEntry::Genesis(_) => Ok(()),
            JournalEntry::Decision(decision) => self.apply_decision(decision),
            JournalEntry::SignerRotation(rotation) => {
                self.apply_rotation(rotation, record.sequence)
            }
            JournalEntry::PolicyActivation(activation) => {
                self.apply_policy_activation(activation, record.sequence)
            }
        }
    }

    fn apply_decision(&mut self, decision: &DecisionEntry) -> Result<()> {
        decision.receipt.verify()?;
        validate_recovered_decision(
            decision,
            self.active_policy_epoch,
            &self.genesis.principal,
            &self.genesis.agent,
        )?;
        if decision.receipt.signer_key_id != self.active_signer_key_id
            || decision.receipt.signer_public_key != self.active_signer_public_key
        {
            return Err(GuardError::DurableState(
                "receipt was not signed by the active journal signer".into(),
            ));
        }
        if decision.receipt.receipt.issued_at_ms < self.last_event_at_ms {
            return Err(GuardError::DurableState(
                "receipt timestamp precedes the prior durable event".into(),
            ));
        }
        self.last_event_at_ms = decision.receipt.receipt.issued_at_ms;
        if let Some(commitment) = &decision.commitment {
            self.commitments.push(commitment.decode()?);
        }
        self.receipts.push(decision.receipt.clone());
        Ok(())
    }

    fn apply_rotation(&mut self, rotation: &SignerRotationEntry, sequence: u64) -> Result<()> {
        validate_rotation(
            rotation,
            sequence,
            self.active_policy_epoch,
            &self.active_policy_digest,
            &self.active_signer_key_id,
            &self.active_signer_public_key,
            self.last_event_at_ms,
        )?;
        if self
            .signer_trust
            .keys
            .iter()
            .any(|key| key.key_id == rotation.new_key_id)
        {
            return Err(GuardError::DurableState(
                "rotation reuses a historical signer key".into(),
            ));
        }
        let previous = self
            .signer_trust
            .keys
            .iter_mut()
            .find(|key| key.key_id == self.active_signer_key_id)
            .ok_or_else(|| GuardError::DurableState("active trust key is missing".into()))?;
        previous.status = SignerStatus::Retired;
        previous.not_after_ms = Some(rotation.activated_at_ms);
        self.signer_trust.keys.push(SignerTrustKey {
            key_id: rotation.new_key_id.clone(),
            public_key: rotation.new_public_key.clone(),
            not_before_ms: rotation.activated_at_ms,
            not_after_ms: None,
            status: SignerStatus::Active,
            replaces: Some(self.active_signer_key_id.clone()),
        });
        self.active_signer_key_id.clone_from(&rotation.new_key_id);
        self.active_signer_public_key
            .clone_from(&rotation.new_public_key);
        self.last_event_at_ms = rotation.activated_at_ms;
        Ok(())
    }

    fn apply_policy_activation(
        &mut self,
        activation: &PolicyActivationEntry,
        sequence: u64,
    ) -> Result<()> {
        validate_policy_activation(
            activation,
            sequence,
            self.active_policy_epoch,
            &self.active_policy_digest,
            &self.genesis.principal,
            &self.genesis.agent,
            &self.active_signer_key_id,
            &self.active_signer_public_key,
            self.last_event_at_ms,
        )?;
        let previous_policy = self.signer_trust.policies.last_mut().ok_or_else(|| {
            GuardError::DurableState("active policy trust scope is missing".into())
        })?;
        previous_policy.not_after_ms = Some(activation.activated_at_ms);
        self.signer_trust.policies.push(PolicyTrustScope {
            policy_epoch: activation.new_policy_epoch,
            policy_digest: activation.new_policy_digest.clone(),
            bundle_digest: activation.new_bundle_digest.clone(),
            not_before_ms: activation.activated_at_ms,
            not_after_ms: None,
        });
        self.active_policy_epoch = activation.new_policy_epoch;
        self.active_policy_digest
            .clone_from(&activation.new_policy_digest);
        self.active_bundle_digest
            .clone_from(&activation.new_bundle_digest);
        self.active_revoked_rule_ids
            .clone_from(&activation.new_revoked_rule_ids);
        self.active_policy_activated_at_ms = activation.activated_at_ms;
        self.active_policy_expires_at_ms = activation.expires_at_ms;
        self.last_event_at_ms = activation.activated_at_ms;
        self.commitments.clear();
        Ok(())
    }

    fn finish(self) -> ValidatedJournal {
        ValidatedJournal {
            genesis: self.genesis,
            active_policy_epoch: self.active_policy_epoch,
            active_policy_digest: self.active_policy_digest,
            active_bundle_digest: self.active_bundle_digest,
            active_revoked_rule_ids: self.active_revoked_rule_ids,
            active_policy_activated_at_ms: self.active_policy_activated_at_ms,
            active_policy_expires_at_ms: self.active_policy_expires_at_ms,
            commitments: self.commitments,
            receipts: self.receipts,
            active_signer_key_id: self.active_signer_key_id,
            active_signer_public_key: self.active_signer_public_key,
            last_event_at_ms: self.last_event_at_ms,
            signer_trust: self.signer_trust,
        }
    }
}

fn validate_records(records: &[JournalRecord]) -> Result<ValidatedJournal> {
    let genesis = validated_genesis(records)?;
    validate_record_chain(records)?;
    let mut accumulator = JournalAccumulator::new(genesis);
    for record in records.iter().skip(1) {
        accumulator.apply(record)?;
    }
    Ok(accumulator.finish())
}

fn validate_active_policy(validated: &ValidatedJournal, binding: &PolicyBinding) -> Result<()> {
    if validated.active_policy_epoch != binding.policy.policy_epoch
        || validated.active_policy_digest != binding.policy_digest
        || validated.active_bundle_digest != binding.bundle_digest
        || validated.active_revoked_rule_ids != binding.revoked_rule_ids
        || validated.genesis.principal != binding.policy.principal
        || validated.genesis.agent != binding.policy.agent
    {
        return Err(GuardError::DurableState(
            "policy does not match the state journal's active signed bundle".into(),
        ));
    }
    Ok(())
}

fn validate_recovered_decision(
    decision: &DecisionEntry,
    policy_epoch: u64,
    principal: &str,
    agent: &str,
) -> Result<()> {
    let receipt = &decision.receipt.receipt;
    if receipt.policy_epoch != policy_epoch
        || receipt.principal != principal
        || receipt.agent != agent
    {
        return Err(GuardError::DurableState(
            "receipt identity or policy epoch does not match journal genesis".into(),
        ));
    }
    match (&receipt.decision, &decision.commitment) {
        (GuardDecision::Allowed, Some(commitment)) => {
            if receipt.duplicate
                || commitment.effect_id != receipt.effect_id
                || commitment.effect_digest != receipt.effect_digest
                || commitment.authorized_at_ms != receipt.issued_at_ms
                || commitment.action != format!("mcp.tool.call:{}", receipt.tool)
                || receipt.resource.as_deref() != Some(commitment.resource.as_str())
            {
                return Err(GuardError::DurableState(
                    "allowed receipt does not match its authority commitment".into(),
                ));
            }
        }
        (GuardDecision::Blocked, None) => {}
        _ => {
            return Err(GuardError::DurableState(
                "allowed decisions require one commitment and blocked decisions require none"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn validate_evaluation(evaluation: &GuardEvaluation) -> Result<()> {
    evaluation.receipt.verify()?;
    let stored = DecisionEntry {
        receipt: evaluation.receipt.clone(),
        commitment: evaluation.commitment.as_ref().map(StoredCommitment::from),
    };
    validate_recovered_decision(
        &stored,
        evaluation.receipt.receipt.policy_epoch,
        &evaluation.receipt.receipt.principal,
        &evaluation.receipt.receipt.agent,
    )
}

fn validate_rotation(
    rotation: &SignerRotationEntry,
    sequence: u64,
    policy_epoch: u64,
    policy_digest: &str,
    active_key_id: &str,
    active_public_key: &str,
    last_event_at_ms: i64,
) -> Result<()> {
    if rotation.rotation_sequence != sequence
        || rotation.policy_epoch != policy_epoch
        || rotation.policy_digest != policy_digest
        || rotation.previous_key_id != active_key_id
        || rotation.previous_public_key != active_public_key
        || rotation.new_key_id == active_key_id
        || rotation.activated_at_ms < last_event_at_ms
    {
        return Err(GuardError::DurableState(
            "signer rotation does not match journal state".into(),
        ));
    }
    validate_signer_identity(&rotation.previous_public_key, &rotation.previous_key_id)?;
    validate_signer_identity(&rotation.new_public_key, &rotation.new_key_id)?;
    let transcript = rotation_transcript(rotation)?;
    verify_rotation_signature(
        &rotation.previous_public_key,
        &rotation.previous_signature,
        &transcript,
    )?;
    verify_rotation_signature(
        &rotation.new_public_key,
        &rotation.new_signature,
        &transcript,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_policy_activation(
    activation: &PolicyActivationEntry,
    sequence: u64,
    active_policy_epoch: u64,
    active_policy_digest: &str,
    principal: &str,
    agent: &str,
    active_signer_key_id: &str,
    active_signer_public_key: &str,
    last_event_at_ms: i64,
) -> Result<()> {
    if activation.activation_sequence != sequence
        || activation.previous_policy_epoch != active_policy_epoch
        || activation.previous_policy_digest != active_policy_digest
        || activation.new_policy_epoch <= active_policy_epoch
        || activation.new_policy_digest.len() != 64
        || hex::decode(&activation.new_policy_digest).is_err()
        || activation.new_bundle_digest.is_empty()
        || !sorted_unique(&activation.new_revoked_rule_ids)
        || activation.principal != principal
        || activation.agent != agent
        || activation.activated_at_ms < last_event_at_ms
        || activation.expires_at_ms <= activation.activated_at_ms
        || activation.receipt_signer_key_id != active_signer_key_id
    {
        return Err(GuardError::DurableState(
            "policy activation does not match journal state".into(),
        ));
    }
    verify_rotation_signature(
        active_signer_public_key,
        &activation.signature,
        &policy_activation_transcript(activation)?,
    )
}

fn policy_activation_transcript(activation: &PolicyActivationEntry) -> Result<Vec<u8>> {
    let input = PolicyActivationTranscript {
        activation_sequence: activation.activation_sequence,
        previous_policy_epoch: activation.previous_policy_epoch,
        previous_policy_digest: &activation.previous_policy_digest,
        new_policy_epoch: activation.new_policy_epoch,
        new_policy_digest: &activation.new_policy_digest,
        new_bundle_digest: &activation.new_bundle_digest,
        new_revoked_rule_ids: &activation.new_revoked_rule_ids,
        principal: &activation.principal,
        agent: &activation.agent,
        activated_at_ms: activation.activated_at_ms,
        expires_at_ms: activation.expires_at_ms,
        receipt_signer_key_id: &activation.receipt_signer_key_id,
    };
    let encoded = serde_json::to_vec(&input)?;
    let mut transcript = Vec::with_capacity(POLICY_ACTIVATION_DOMAIN.len() + 8 + encoded.len());
    transcript.extend_from_slice(POLICY_ACTIVATION_DOMAIN);
    transcript.extend_from_slice(
        &u64::try_from(encoded.len())
            .map_err(|_| GuardError::DurableState("policy activation is too large".into()))?
            .to_be_bytes(),
    );
    transcript.extend_from_slice(&encoded);
    Ok(transcript)
}

fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn rotation_transcript(rotation: &SignerRotationEntry) -> Result<Vec<u8>> {
    let input = RotationTranscript {
        rotation_sequence: rotation.rotation_sequence,
        policy_epoch: rotation.policy_epoch,
        policy_digest: &rotation.policy_digest,
        previous_key_id: &rotation.previous_key_id,
        previous_public_key: &rotation.previous_public_key,
        new_key_id: &rotation.new_key_id,
        new_public_key: &rotation.new_public_key,
        activated_at_ms: rotation.activated_at_ms,
    };
    let encoded = serde_json::to_vec(&input)?;
    let mut transcript = Vec::with_capacity(SIGNER_ROTATION_DOMAIN.len() + 8 + encoded.len());
    transcript.extend_from_slice(SIGNER_ROTATION_DOMAIN);
    transcript.extend_from_slice(
        &u64::try_from(encoded.len())
            .map_err(|_| GuardError::DurableState("rotation transcript is too large".into()))?
            .to_be_bytes(),
    );
    transcript.extend_from_slice(&encoded);
    Ok(transcript)
}

fn verify_rotation_signature(public_key: &str, signature: &str, transcript: &[u8]) -> Result<()> {
    let public_key = VerifyingKey::from_bytes(&decode_hex(public_key, "rotation public key")?)
        .map_err(|_| GuardError::DurableState("rotation public key is invalid".into()))?;
    let signature = Signature::from_bytes(&decode_hex(signature, "rotation signature")?);
    public_key
        .verify(transcript, &signature)
        .map_err(|_| GuardError::DurableState("signer rotation signature is invalid".into()))
}

fn validate_signer_identity(public_key: &str, key_id: &str) -> Result<()> {
    let public_bytes: [u8; 32] = decode_hex(public_key, "signer public key")?;
    VerifyingKey::from_bytes(&public_bytes)
        .map_err(|_| GuardError::DurableState("signer public key is invalid".into()))?;
    let expected = hex::encode(Sha256::digest(public_bytes));
    if key_id != expected {
        return Err(GuardError::DurableState(
            "signer key ID does not match its public key".into(),
        ));
    }
    Ok(())
}

fn trust_from_genesis(genesis: &GenesisEntry) -> SignerTrustBundle {
    SignerTrustBundle {
        format: "scopepact-signer-trust-v2".into(),
        principal: genesis.principal.clone(),
        agent: genesis.agent.clone(),
        policies: vec![PolicyTrustScope {
            policy_epoch: genesis.policy_epoch,
            policy_digest: genesis.policy_digest.clone(),
            bundle_digest: genesis.bundle_digest.clone(),
            not_before_ms: genesis.activated_at_ms,
            not_after_ms: None,
        }],
        keys: vec![SignerTrustKey {
            key_id: genesis.initial_signer_key_id.clone(),
            public_key: genesis.initial_signer_public_key.clone(),
            not_before_ms: genesis.activated_at_ms,
            not_after_ms: None,
            status: SignerStatus::Active,
            replaces: None,
        }],
    }
}

/// Verifies receipt integrity and its signer, identity, policy epoch, and issue
/// time against a journal-derived trust bundle.
///
/// # Errors
///
/// Returns an error for an invalid receipt, unknown/revoked signer, mismatched
/// identity or epoch, or an issue time outside the signer's validity window.
pub fn verify_receipt_with_trust(
    receipt: &SignedDecisionReceipt,
    trust: &SignerTrustBundle,
) -> Result<()> {
    receipt.verify()?;
    if trust.format != "scopepact-signer-trust-v2"
        || receipt.receipt.principal != trust.principal
        || receipt.receipt.agent != trust.agent
    {
        return Err(GuardError::DurableState(
            "receipt does not match signer trust scope".into(),
        ));
    }
    let policy = trust
        .policies
        .iter()
        .find(|policy| policy.policy_epoch == receipt.receipt.policy_epoch)
        .ok_or_else(|| GuardError::DurableState("receipt policy epoch is not trusted".into()))?;
    if receipt.receipt.issued_at_ms < policy.not_before_ms
        || policy
            .not_after_ms
            .is_some_and(|not_after| receipt.receipt.issued_at_ms > not_after)
    {
        return Err(GuardError::DurableState(
            "receipt is outside its policy epoch validity window".into(),
        ));
    }
    let key = trust
        .keys
        .iter()
        .find(|key| key.key_id == receipt.signer_key_id)
        .ok_or_else(|| GuardError::DurableState("receipt signer is not trusted".into()))?;
    if key.public_key != receipt.signer_public_key
        || key.status == SignerStatus::Revoked
        || receipt.receipt.issued_at_ms < key.not_before_ms
        || key
            .not_after_ms
            .is_some_and(|not_after| receipt.receipt.issued_at_ms > not_after)
    {
        return Err(GuardError::DurableState(
            "receipt signer is revoked, mismatched, or outside its validity window".into(),
        ));
    }
    Ok(())
}

fn validate_head_log(file: &File, path: &Path, records: &[JournalRecord]) -> Result<usize> {
    let heads = parse_head_lines_from_reader(file, path)?;
    validate_heads(&heads, records)?;
    Ok(heads.len())
}

fn validate_heads(heads: &[HeadRecord], records: &[JournalRecord]) -> Result<()> {
    let mut previous_sequence = None;
    for head in heads {
        let index = usize::try_from(head.sequence)
            .map_err(|_| GuardError::DurableState("head sequence exceeds usize".into()))?;
        let record = records.get(index).ok_or_else(|| {
            GuardError::DurableState("head log is ahead of the decision journal".into())
        })?;
        if head.state_version != STATE_VERSION
            || head.record_hash != record.record_hash
            || previous_sequence.is_some_and(|previous| head.sequence != previous + 1)
        {
            return Err(GuardError::DurableState(
                "head log failed version, sequence, or hash validation".into(),
            ));
        }
        previous_sequence = Some(head.sequence);
    }
    if !heads.is_empty()
        && previous_sequence != Some(u64::try_from(heads.len() - 1).unwrap_or(u64::MAX))
    {
        return Err(GuardError::DurableState(
            "head log does not begin at sequence zero".into(),
        ));
    }
    Ok(())
}

fn parse_record_lines(bytes: &[u8], path: &Path) -> Result<Vec<JournalRecord>> {
    parse_record_lines_from_reader(std::io::Cursor::new(bytes), path)
}

fn parse_record_lines_from_reader(reader: impl Read, path: &Path) -> Result<Vec<JournalRecord>> {
    let mut records = Vec::new();
    for line in read_complete_lines(
        reader,
        path,
        MAX_STATE_RECORDS,
        MAX_RECORD_BYTES,
        MAX_STATE_BYTES,
    )? {
        records.push(serde_json::from_slice(&line).map_err(|error| {
            GuardError::DurableState(format!(
                "{} contains an invalid record: {error}",
                path.display()
            ))
        })?);
    }
    Ok(records)
}

fn parse_head_lines(bytes: &[u8], path: &Path) -> Result<Vec<HeadRecord>> {
    parse_head_lines_from_reader(std::io::Cursor::new(bytes), path)
}

fn parse_head_lines_from_reader(reader: impl Read, path: &Path) -> Result<Vec<HeadRecord>> {
    read_complete_lines(
        reader,
        path,
        MAX_STATE_RECORDS,
        MAX_HEAD_RECORD_BYTES,
        MAX_HEAD_BYTES,
    )?
    .into_iter()
    .map(|line| {
        serde_json::from_slice(&line).map_err(|error| {
            GuardError::DurableState(format!(
                "{} contains an invalid head record: {error}",
                path.display()
            ))
        })
    })
    .collect()
}

fn read_complete_lines(
    reader: impl Read,
    path: &Path,
    max_lines: usize,
    max_line_bytes: usize,
    max_total_bytes: usize,
) -> Result<Vec<Vec<u8>>> {
    let mut reader = BufReader::new(reader);
    let mut lines = Vec::new();
    let mut total_bytes = 0_usize;
    loop {
        let mut line = Vec::new();
        let bytes = reader
            .by_ref()
            .take(u64::try_from(max_line_bytes).unwrap_or(u64::MAX) + 2)
            .read_until(b'\n', &mut line)
            .map_err(|error| state_io(path, "read", &error))?;
        if bytes == 0 {
            break;
        }
        if line.len() > max_line_bytes.saturating_add(1) {
            return Err(GuardError::DurableState(format!(
                "{} contains an oversized record",
                path.display()
            )));
        }
        total_bytes = total_bytes.checked_add(bytes).ok_or_else(|| {
            GuardError::DurableState(format!("{} size exceeds usize", path.display()))
        })?;
        if total_bytes > max_total_bytes {
            return Err(GuardError::DurableState(format!(
                "{} exceeds the supported state size",
                path.display()
            )));
        }
        if lines.len() >= max_lines {
            return Err(GuardError::DurableState(format!(
                "{} exceeds the supported record count",
                path.display()
            )));
        }
        if !line.ends_with(b"\n") {
            return Err(GuardError::DurableState(format!(
                "{} has a partial trailing record; explicit tail recovery is required",
                path.display()
            )));
        }
        line.pop();
        if line.is_empty() {
            return Err(GuardError::DurableState(format!(
                "{} contains an empty record",
                path.display()
            )));
        }
        lines.push(line);
    }
    Ok(lines)
}

fn read_file_bytes(file: &mut File, path: &Path) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| state_io(path, "rewind", &error))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| state_io(path, "read", &error))?;
    Ok(bytes)
}

fn complete_prefix<'a>(bytes: &'a [u8], path: &Path) -> Result<(&'a [u8], usize)> {
    if bytes.is_empty() {
        return Err(GuardError::DurableState(format!(
            "{} is empty and cannot be recovered",
            path.display()
        )));
    }
    if bytes.ends_with(b"\n") {
        return Ok((bytes, 0));
    }
    let last_newline = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .ok_or_else(|| {
            GuardError::DurableState(format!(
                "{} contains no complete record and cannot be recovered",
                path.display()
            ))
        })?;
    let prefix_length = last_newline + 1;
    Ok((&bytes[..prefix_length], bytes.len() - prefix_length))
}

fn record_hash(sequence: u64, previous_hash: &str, entry: &JournalEntry) -> Result<String> {
    let previous: [u8; 32] = decode_hex(previous_hash, "previous record hash")?;
    let input = RecordHashInput {
        state_version: STATE_VERSION,
        sequence,
        previous_hash,
        entry,
    };
    let encoded = serde_json::to_vec(&input)?;
    let mut hash = Sha256::new();
    hash.update(STATE_RECORD_DOMAIN);
    hash.update(previous);
    hash.update(
        u64::try_from(encoded.len())
            .map_err(|_| GuardError::DurableState("state hash input is too large".into()))?
            .to_be_bytes(),
    );
    hash.update(encoded);
    Ok(hex::encode(hash.finalize()))
}

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(value)
        .map_err(|_| GuardError::DurableState(format!("journal {label} is not valid hex")))?;
    bytes
        .try_into()
        .map_err(|_| GuardError::DurableState(format!("journal {label} has the wrong length")))
}

fn state_io(path: &Path, operation: &str, error: &std::io::Error) -> GuardError {
    GuardError::DurableState(format!("cannot {operation} {}: {error}", path.display()))
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicU64, Ordering};

    use ed25519_dalek::SigningKey;
    use serde_json::json;

    use super::{DurableState, MAX_RECORD_BYTES, MAX_STATE_RECORDS, parse_record_lines};
    use crate::{GuardDecision, GuardEngine, GuardPolicy, ResourcePolicy, ToolRule, signer_key_id};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "scopepact-state-failure-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn policy() -> GuardPolicy {
        GuardPolicy {
            policy_version: 1,
            policy_epoch: 1,
            principal: "failure-test-principal".into(),
            agent: "failure-test-agent".into(),
            valid_for_ms: 60_000,
            rules: vec![ToolRule {
                id: "writes".into(),
                tool: "write_file".into(),
                resource: ResourcePolicy::Literal {
                    value: "urn:test:file".into(),
                },
                max_calls: 1,
                payment: None,
            }],
        }
    }

    #[test]
    fn append_failure_poisons_writer_and_recovery_preserves_commitment() {
        let directory = TestDirectory::new();
        let path = directory.0.join("state.jsonl");
        let key = SigningKey::from_bytes(&[42; 32]);
        let public_key = hex::encode(key.verifying_key().as_bytes());
        let key_id = hex::encode(signer_key_id(&key).0);
        let request = json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"tools/call",
            "params":{"name":"write_file", "arguments":{}}
        });
        let (mut state, recovered) =
            DurableState::open(&path, &policy(), &public_key, &key_id, 1_000_000).unwrap();
        let mut engine =
            GuardEngine::new(policy(), key.clone(), recovered.activated_at_ms).unwrap();
        let evaluation = engine
            .evaluate_json_rpc_transactional(&request, 1_000_001)
            .unwrap()
            .unwrap();

        let (broken_head, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let owned: OwnedFd = broken_head.into();
        state.head = owned.into();
        assert!(state.commit(&evaluation).is_err());
        let poisoned = state.commit(&evaluation).unwrap_err();
        assert!(poisoned.to_string().contains("writer is poisoned"));
        drop(state);

        let (state, recovered) =
            DurableState::open(&path, &policy(), &public_key, &key_id, 1_000_002).unwrap();
        assert_eq!(recovered.commitments.len(), 1);
        let mut engine = GuardEngine::new(policy(), key, recovered.activated_at_ms).unwrap();
        engine
            .restore_commitment(&recovered.commitments[0])
            .unwrap();
        let duplicate = engine
            .evaluate_json_rpc_transactional(&request, 1_000_002)
            .unwrap()
            .unwrap();
        assert_eq!(duplicate.receipt.receipt.decision, GuardDecision::Blocked);
        assert!(duplicate.receipt.receipt.duplicate);
        drop(state);
    }

    #[test]
    fn unavailable_journal_poisons_writer_without_durable_commitment() {
        let directory = TestDirectory::new();
        let path = directory.0.join("state.jsonl");
        let key = SigningKey::from_bytes(&[42; 32]);
        let public_key = hex::encode(key.verifying_key().as_bytes());
        let key_id = hex::encode(signer_key_id(&key).0);
        let request = json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"tools/call",
            "params":{"name":"write_file", "arguments":{}}
        });
        let (mut state, recovered) =
            DurableState::open(&path, &policy(), &public_key, &key_id, 1_000_000).unwrap();
        let mut engine =
            GuardEngine::new(policy(), key.clone(), recovered.activated_at_ms).unwrap();
        let evaluation = engine
            .evaluate_json_rpc_transactional(&request, 1_000_001)
            .unwrap()
            .unwrap();

        let (broken_journal, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let owned: OwnedFd = broken_journal.into();
        state.journal = owned.into();
        assert!(state.commit(&evaluation).is_err());
        assert!(
            state
                .commit(&evaluation)
                .unwrap_err()
                .to_string()
                .contains("poisoned")
        );
        drop(state);

        let (state, recovered) =
            DurableState::open(&path, &policy(), &public_key, &key_id, 1_000_002).unwrap();
        assert!(recovered.commitments.is_empty());
        let mut engine = GuardEngine::new(policy(), key, recovered.activated_at_ms).unwrap();
        let retry = engine
            .evaluate_json_rpc_transactional(&request, 1_000_002)
            .unwrap()
            .unwrap();
        assert_eq!(retry.receipt.receipt.decision, GuardDecision::Allowed);
        drop(state);
    }

    #[test]
    fn state_parser_rejects_unbounded_lines_and_record_counts() {
        let path = std::path::Path::new("hostile-state.jsonl");
        let too_many = b"{}\n".repeat(MAX_STATE_RECORDS + 1);
        let count_error = parse_record_lines(&too_many, path).unwrap_err();
        assert!(count_error.to_string().contains("record count"));

        let mut oversized = vec![b'a'; MAX_RECORD_BYTES + 1];
        oversized.push(b'\n');
        let size_error = parse_record_lines(&oversized, path).unwrap_err();
        assert!(size_error.to_string().contains("oversized record"));
    }
}
