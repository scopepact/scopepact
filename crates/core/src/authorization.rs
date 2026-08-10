use std::collections::{BTreeSet, HashMap, HashSet};

use sha2::{Digest as _, Sha256};

use crate::error::{ProtocolError, Result};
use crate::types::{ActorId, Digest, EffectId, GrantId, InteractionId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceScope {
    Exact(String),
    Prefix(String),
}

impl ResourceScope {
    fn allows(&self, resource: &str) -> bool {
        match self {
            Self::Exact(expected) => expected == resource,
            Self::Prefix(prefix) => resource.starts_with(prefix),
        }
    }

    fn is_subset_of(&self, parent: &Self) -> bool {
        match (self, parent) {
            (Self::Exact(child), Self::Exact(parent)) => child == parent,
            (Self::Exact(child) | Self::Prefix(child), Self::Prefix(parent)) => {
                child.starts_with(parent)
            }
            (Self::Prefix(_), Self::Exact(_)) => false,
        }
    }

    fn is_valid(&self) -> bool {
        let value = match self {
            Self::Exact(value) | Self::Prefix(value) => value,
        };
        !value.is_empty() && value.len() <= 1024
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentLimit {
    pub payment_actions: BTreeSet<String>,
    pub currency: String,
    pub max_spend_atomic: u128,
    pub allowed_payees: BTreeSet<ActorId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityGrant {
    pub id: GrantId,
    pub issuer: ActorId,
    pub subject: ActorId,
    pub actions: BTreeSet<String>,
    pub resource: ResourceScope,
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub max_calls: u64,
    pub interaction: Option<InteractionId>,
    pub payment: Option<PaymentLimit>,
    pub remaining_delegation_depth: u8,
    pub policy_epoch: u64,
    pub parent: Option<GrantId>,
}

impl CapabilityGrant {
    /// Validates the structural constraints of a capability.
    ///
    /// # Errors
    ///
    /// Returns an error for zero identifiers, empty scopes, invalid time
    /// ranges, or unusable payment limits.
    pub fn validate(&self) -> Result<()> {
        if self.id.is_zero() || self.issuer.is_zero() || self.subject.is_zero() {
            return Err(ProtocolError::Malformed("zero grant actor or identifier"));
        }
        if self.actions.is_empty()
            || self
                .actions
                .iter()
                .any(|action| action.is_empty() || action.len() > 256)
            || !self.resource.is_valid()
        {
            return Err(ProtocolError::Malformed("invalid capability scope"));
        }
        if self.expires_at_ms < self.not_before_ms {
            return Err(ProtocolError::Malformed("grant expiry precedes start"));
        }
        if let Some(payment) = &self.payment {
            if payment.payment_actions.is_empty()
                || !payment.payment_actions.is_subset(&self.actions)
                || payment.currency.is_empty()
                || payment.currency.len() > 32
                || !payment.currency.is_ascii()
                || payment.max_spend_atomic == 0
                || payment.allowed_payees.is_empty()
                || payment.allowed_payees.iter().any(|payee| payee.is_zero())
            {
                return Err(ProtocolError::Malformed("invalid payment limit"));
            }
        }
        Ok(())
    }

    /// Proves that this delegated grant is no broader than `parent`.
    ///
    /// # Errors
    ///
    /// Returns an error when either grant is malformed or any authority
    /// dimension is expanded.
    pub fn verify_attenuation(&self, parent: &Self) -> Result<()> {
        self.validate()?;
        parent.validate()?;
        if self.parent != Some(parent.id) || self.issuer != parent.subject {
            return Err(ProtocolError::AuthorityAmplification(
                "delegation chain does not match parent",
            ));
        }
        if self.id == parent.id {
            return Err(ProtocolError::AuthorityAmplification(
                "delegation must use a new grant identifier",
            ));
        }
        if self.policy_epoch != parent.policy_epoch {
            return Err(ProtocolError::AuthorityAmplification(
                "policy epoch changed",
            ));
        }
        if !self.actions.is_subset(&parent.actions) {
            return Err(ProtocolError::AuthorityAmplification("actions expanded"));
        }
        if !self.resource.is_subset_of(&parent.resource) {
            return Err(ProtocolError::AuthorityAmplification(
                "resource scope expanded",
            ));
        }
        if self.not_before_ms < parent.not_before_ms || self.expires_at_ms > parent.expires_at_ms {
            return Err(ProtocolError::AuthorityAmplification(
                "validity interval expanded",
            ));
        }
        if self.max_calls > parent.max_calls {
            return Err(ProtocolError::AuthorityAmplification(
                "call allowance increased",
            ));
        }
        if let Some(parent_interaction) = parent.interaction {
            if self.interaction != Some(parent_interaction) {
                return Err(ProtocolError::AuthorityAmplification(
                    "interaction binding removed or changed",
                ));
            }
        }
        if parent.remaining_delegation_depth == 0
            || self.remaining_delegation_depth >= parent.remaining_delegation_depth
        {
            return Err(ProtocolError::AuthorityAmplification(
                "delegation depth did not decrease",
            ));
        }
        match (&self.payment, &parent.payment) {
            (None, Some(parent_payment))
                if !self.actions.is_disjoint(&parent_payment.payment_actions) =>
            {
                return Err(ProtocolError::AuthorityAmplification(
                    "payment requirement removed",
                ));
            }
            (None, _) => {}
            (Some(_), None) => {
                return Err(ProtocolError::AuthorityAmplification(
                    "payment authority added",
                ));
            }
            (Some(child), Some(parent)) => {
                let inherited_payment_actions: BTreeSet<_> = self
                    .actions
                    .intersection(&parent.payment_actions)
                    .cloned()
                    .collect();
                if child.payment_actions != inherited_payment_actions {
                    return Err(ProtocolError::AuthorityAmplification(
                        "payment action binding changed",
                    ));
                }
                if child.currency != parent.currency {
                    return Err(ProtocolError::AuthorityAmplification(
                        "payment currency changed",
                    ));
                }
                if child.max_spend_atomic > parent.max_spend_atomic {
                    return Err(ProtocolError::AuthorityAmplification(
                        "spending limit increased",
                    ));
                }
                if !child.allowed_payees.is_subset(&parent.allowed_payees) {
                    return Err(ProtocolError::AuthorityAmplification("payee set expanded"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentRequest {
    pub currency: String,
    pub amount_atomic: u128,
    pub payee: ActorId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionRequest {
    pub effect_id: EffectId,
    pub effect_digest: Digest,
    pub actor: ActorId,
    pub interaction: Option<InteractionId>,
    pub action: String,
    pub resource: String,
    pub payment: Option<PaymentRequest>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationOutcome {
    Reserved,
    Duplicate,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GrantUsage {
    pub calls: u64,
    pub spent_atomic: u128,
}

pub struct AuthorityKernel {
    policy_epoch: u64,
    grants: HashMap<GrantId, CapabilityGrant>,
    revoked: HashSet<GrantId>,
    usage: HashMap<GrantId, GrantUsage>,
    effects: HashMap<EffectId, [u8; 32]>,
}

impl AuthorityKernel {
    #[must_use]
    pub fn new(policy_epoch: u64) -> Self {
        Self {
            policy_epoch,
            grants: HashMap::new(),
            revoked: HashSet::new(),
            usage: HashMap::new(),
            effects: HashMap::new(),
        }
    }

    /// Installs a root grant after its issuer has been authenticated by the
    /// calling credential layer.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, duplicate, parented, or stale grants.
    pub fn install_root(&mut self, grant: CapabilityGrant) -> Result<()> {
        grant.validate()?;
        if grant.parent.is_some() {
            return Err(ProtocolError::Malformed("root grant has a parent"));
        }
        if grant.policy_epoch != self.policy_epoch {
            return Err(ProtocolError::PolicyEpochMismatch);
        }
        self.install_unique(grant)
    }

    /// Installs a delegated grant after checking monotonic attenuation.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent is absent or revoked, or if the child
    /// expands authority.
    pub fn install_delegated(&mut self, parent_id: GrantId, grant: CapabilityGrant) -> Result<()> {
        let parent = self
            .grants
            .get(&parent_id)
            .ok_or(ProtocolError::InsufficientAuthority(
                "parent grant not installed",
            ))?;
        if self.is_revoked(parent_id) {
            return Err(ProtocolError::GrantRevoked);
        }
        if parent.policy_epoch != self.policy_epoch {
            return Err(ProtocolError::PolicyEpochMismatch);
        }
        grant.verify_attenuation(parent)?;
        self.install_unique(grant)
    }

    /// Revokes a grant. Descendants are rejected through parent traversal.
    ///
    /// # Errors
    ///
    /// Returns an error when the grant is not installed.
    pub fn revoke(&mut self, grant_id: GrantId) -> Result<()> {
        if !self.grants.contains_key(&grant_id) {
            return Err(ProtocolError::InsufficientAuthority("grant not installed"));
        }
        self.revoked.insert(grant_id);
        Ok(())
    }

    /// Advances the active policy epoch, invalidating every older grant.
    ///
    /// # Errors
    ///
    /// Returns an error unless the epoch increases monotonically.
    pub fn advance_policy_epoch(&mut self, new_epoch: u64) -> Result<()> {
        if new_epoch <= self.policy_epoch {
            return Err(ProtocolError::Malformed(
                "policy epoch must increase monotonically",
            ));
        }
        self.policy_epoch = new_epoch;
        Ok(())
    }

    /// Checks and reserves one consequential effect.
    ///
    /// # Errors
    ///
    /// Returns an error when the grant is absent, revoked, stale, exhausted,
    /// or does not cover every field of the effect request.
    pub fn authorize_effect(
        &mut self,
        grant_id: GrantId,
        request: &ActionRequest,
        now_ms: i64,
    ) -> Result<AuthorizationOutcome> {
        let grant = self
            .grants
            .get(&grant_id)
            .cloned()
            .ok_or(ProtocolError::InsufficientAuthority("grant not installed"))?;
        if self.is_revoked(grant_id) {
            return Err(ProtocolError::GrantRevoked);
        }
        if grant.policy_epoch != self.policy_epoch {
            return Err(ProtocolError::PolicyEpochMismatch);
        }
        Self::validate_request(&grant, request, now_ms)?;

        let fingerprint = request_fingerprint(request);
        if let Some(existing) = self.effects.get(&request.effect_id) {
            return if existing == &fingerprint {
                Ok(AuthorizationOutcome::Duplicate)
            } else {
                Err(ProtocolError::EffectConflict)
            };
        }

        let usage = self.usage.entry(grant_id).or_default();
        if usage.calls >= grant.max_calls {
            return Err(ProtocolError::InsufficientAuthority(
                "call allowance exhausted",
            ));
        }
        let additional_spend = request
            .payment
            .as_ref()
            .map_or(0, |payment| payment.amount_atomic);
        let new_spend = usage
            .spent_atomic
            .checked_add(additional_spend)
            .ok_or(ProtocolError::AccountingOverflow)?;
        if let Some(limit) = &grant.payment {
            if new_spend > limit.max_spend_atomic {
                return Err(ProtocolError::InsufficientAuthority(
                    "spending limit exceeded",
                ));
            }
        }

        usage.calls += 1;
        usage.spent_atomic = new_spend;
        self.effects.insert(request.effect_id, fingerprint);
        Ok(AuthorizationOutcome::Reserved)
    }

    #[must_use]
    pub fn usage(&self, grant_id: GrantId) -> GrantUsage {
        self.usage.get(&grant_id).copied().unwrap_or_default()
    }

    fn install_unique(&mut self, grant: CapabilityGrant) -> Result<()> {
        if self.grants.contains_key(&grant.id) {
            return Err(ProtocolError::Malformed(
                "grant identifier already installed",
            ));
        }
        self.grants.insert(grant.id, grant);
        Ok(())
    }

    fn is_revoked(&self, grant_id: GrantId) -> bool {
        let mut current = Some(grant_id);
        let mut remaining = self.grants.len().saturating_add(1);
        while let Some(id) = current {
            if self.revoked.contains(&id) {
                return true;
            }
            if remaining == 0 {
                return true;
            }
            remaining -= 1;
            current = self.grants.get(&id).and_then(|grant| grant.parent);
        }
        false
    }

    fn validate_request(
        grant: &CapabilityGrant,
        request: &ActionRequest,
        now_ms: i64,
    ) -> Result<()> {
        if request.effect_id.is_zero()
            || request.effect_digest.is_zero()
            || request.actor.is_zero()
            || request.action.is_empty()
            || request.action.len() > 256
            || request.resource.is_empty()
            || request.resource.len() > 1024
        {
            return Err(ProtocolError::Malformed("invalid effect request"));
        }
        if request.actor != grant.subject {
            return Err(ProtocolError::InsufficientAuthority("subject mismatch"));
        }
        if now_ms < grant.not_before_ms || now_ms > grant.expires_at_ms {
            return Err(ProtocolError::InsufficientAuthority(
                "grant is not currently valid",
            ));
        }
        if !grant.actions.contains(&request.action) {
            return Err(ProtocolError::InsufficientAuthority(
                "action is not granted",
            ));
        }
        if !grant.resource.allows(&request.resource) {
            return Err(ProtocolError::InsufficientAuthority(
                "resource is outside grant scope",
            ));
        }
        if let Some(interaction) = grant.interaction {
            if request.interaction != Some(interaction) {
                return Err(ProtocolError::InsufficientAuthority(
                    "interaction binding mismatch",
                ));
            }
        }
        let payment_required = grant
            .payment
            .as_ref()
            .is_some_and(|limit| limit.payment_actions.contains(&request.action));
        if payment_required && request.payment.is_none() {
            return Err(ProtocolError::InsufficientAuthority(
                "payment metadata required for action",
            ));
        }
        if let Some(payment) = &request.payment {
            if payment.amount_atomic == 0 || payment.payee.is_zero() {
                return Err(ProtocolError::Malformed("invalid payment request"));
            }
            let limit = grant
                .payment
                .as_ref()
                .ok_or(ProtocolError::InsufficientAuthority(
                    "payment authority not granted",
                ))?;
            if !limit.payment_actions.contains(&request.action) {
                return Err(ProtocolError::InsufficientAuthority(
                    "payment is not authorized for action",
                ));
            }
            if payment.currency != limit.currency {
                return Err(ProtocolError::InsufficientAuthority(
                    "payment currency mismatch",
                ));
            }
            if !limit.allowed_payees.contains(&payment.payee) {
                return Err(ProtocolError::InsufficientAuthority("payee is not granted"));
            }
        }
        Ok(())
    }
}

fn request_fingerprint(request: &ActionRequest) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"SCOPEPACT-EFFECT-V0\0");
    hash.update(request.effect_id.0);
    hash.update(request.effect_digest.0);
    hash.update(request.actor.0);
    match request.interaction {
        Some(interaction) => {
            hash.update([1]);
            hash.update(interaction.0);
        }
        None => hash.update([0]),
    }
    update_length_delimited(&mut hash, request.action.as_bytes());
    update_length_delimited(&mut hash, request.resource.as_bytes());
    match &request.payment {
        Some(payment) => {
            hash.update([1]);
            update_length_delimited(&mut hash, payment.currency.as_bytes());
            hash.update(payment.amount_atomic.to_be_bytes());
            hash.update(payment.payee.0);
        }
        None => hash.update([0]),
    }
    hash.finalize().into()
}

fn update_length_delimited(hash: &mut Sha256, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("validated value length must fit u32");
    hash.update(length.to_be_bytes());
    hash.update(value);
}
