use std::collections::BTreeSet;

use proptest::prelude::*;
use scopepact_core::authorization::{
    AuthorityKernel, CapabilityGrant, PaymentLimit, ResourceScope,
};
use scopepact_core::types::{ActorId, GrantId};

fn actor(byte: u8) -> ActorId {
    ActorId([byte; 32])
}

fn parent(max_calls: u64, max_spend: u128, depth: u8, epoch: u64) -> CapabilityGrant {
    CapabilityGrant {
        id: GrantId([1; 16]),
        issuer: actor(1),
        subject: actor(2),
        actions: BTreeSet::from(["payment.send".into(), "market.read".into()]),
        resource: ResourceScope::Prefix("urn:market:".into()),
        not_before_ms: 1_000,
        expires_at_ms: 10_000,
        max_calls,
        interaction: None,
        payment: Some(PaymentLimit {
            payment_actions: BTreeSet::from(["payment.send".into()]),
            currency: "USD-CENTS".into(),
            max_spend_atomic: max_spend,
            allowed_payees: BTreeSet::from([actor(8), actor(9)]),
        }),
        remaining_delegation_depth: depth,
        policy_epoch: epoch,
        parent: None,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn valid_delegation_is_monotonically_attenuated(
        parent_calls in 1_u64..10_000,
        child_calls_seed in any::<u64>(),
        parent_spend in 1_u64..1_000_000,
        child_spend_seed in any::<u64>(),
        parent_depth in 1_u8..16,
        starts_later in 0_i64..4_000,
        ends_earlier in 0_i64..4_000,
        retain_second_payee in any::<bool>(),
    ) {
        let parent = parent(
            parent_calls,
            u128::from(parent_spend),
            parent_depth,
            7,
        );
        let child_calls = 1 + child_calls_seed % parent_calls;
        let child_spend = 1 + child_spend_seed % parent_spend;
        let mut payees = BTreeSet::from([actor(8)]);
        if retain_second_payee {
            payees.insert(actor(9));
        }
        let child = CapabilityGrant {
            id: GrantId([2; 16]),
            issuer: parent.subject,
            subject: actor(3),
            actions: BTreeSet::from(["payment.send".into()]),
            resource: ResourceScope::Exact("urn:market:invoice:42".into()),
            not_before_ms: parent.not_before_ms + starts_later,
            expires_at_ms: parent.expires_at_ms - ends_earlier,
            max_calls: child_calls,
            interaction: None,
            payment: Some(PaymentLimit {
                payment_actions: BTreeSet::from(["payment.send".into()]),
                currency: "USD-CENTS".into(),
                max_spend_atomic: u128::from(child_spend),
                allowed_payees: payees,
            }),
            remaining_delegation_depth: parent_depth - 1,
            policy_epoch: parent.policy_epoch,
            parent: Some(parent.id),
        };
        prop_assert!(child.verify_attenuation(&parent).is_ok());
    }

    #[test]
    fn expanded_numeric_authority_is_always_rejected(
        parent_calls in 1_u64..u64::MAX,
        parent_spend in 1_u128..u128::MAX,
    ) {
        let parent = parent(parent_calls, parent_spend, 2, 7);
        let mut calls_expanded = parent.clone();
        calls_expanded.id = GrantId([2; 16]);
        calls_expanded.issuer = parent.subject;
        calls_expanded.subject = actor(3);
        calls_expanded.parent = Some(parent.id);
        calls_expanded.remaining_delegation_depth = 1;
        calls_expanded.max_calls = parent_calls + 1;
        prop_assert!(calls_expanded.verify_attenuation(&parent).is_err());

        let mut spend_expanded = calls_expanded;
        spend_expanded.max_calls = parent_calls;
        spend_expanded.payment.as_mut().unwrap().max_spend_atomic = parent_spend + 1;
        prop_assert!(spend_expanded.verify_attenuation(&parent).is_err());
    }

    #[test]
    fn policy_epoch_only_moves_forward(epoch in 1_u64..u64::MAX, delta in 1_u64..1_000) {
        let mut kernel = AuthorityKernel::new(epoch);
        let next = epoch.saturating_add(delta);
        prop_assume!(next > epoch);
        prop_assert!(kernel.advance_policy_epoch(next).is_ok());
        prop_assert!(kernel.advance_policy_epoch(epoch).is_err());
        prop_assert!(kernel.advance_policy_epoch(next).is_err());
    }
}
