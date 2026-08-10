use std::collections::BTreeSet;
use std::fmt::Write as _;

use ed25519_dalek::SigningKey;
use scopepact_core::authorization::{
    ActionRequest, AuthorityKernel, AuthorizationOutcome, CapabilityGrant, PaymentLimit,
    PaymentRequest, ResourceScope,
};
use scopepact_core::envelope::{Envelope, EnvelopeGuard, MessageKind, ReceiveContext};
use scopepact_core::error::ProtocolError;
use scopepact_core::interaction::{Interaction, InteractionState};
use scopepact_core::signing::{SignedEnvelope, key_id, payload_digest};
use scopepact_core::types::{
    ActorId, Digest, EffectId, GrantId, InteractionId, KeyId, Nonce, SessionId,
};

const POLICY_EPOCH: u64 = 7;
const NOW_MS: i64 = 10_000;

fn actor(byte: u8) -> ActorId {
    ActorId([byte; 32])
}

fn root_grant() -> CapabilityGrant {
    CapabilityGrant {
        id: GrantId([1; 16]),
        issuer: actor(1),
        subject: actor(2),
        actions: BTreeSet::from(["market.read".to_owned(), "payment.send".to_owned()]),
        resource: ResourceScope::Prefix("urn:market:".to_owned()),
        not_before_ms: 1_000,
        expires_at_ms: 20_000,
        max_calls: 3,
        interaction: Some(InteractionId([3; 16])),
        payment: Some(PaymentLimit {
            payment_actions: BTreeSet::from(["payment.send".to_owned()]),
            currency: "USD-CENTS".to_owned(),
            max_spend_atomic: 1_000,
            allowed_payees: BTreeSet::from([actor(8), actor(9)]),
        }),
        remaining_delegation_depth: 2,
        policy_epoch: POLICY_EPOCH,
        parent: None,
    }
}

fn delegated_grant() -> CapabilityGrant {
    CapabilityGrant {
        id: GrantId([2; 16]),
        issuer: actor(2),
        subject: actor(3),
        actions: BTreeSet::from(["payment.send".to_owned()]),
        resource: ResourceScope::Exact("urn:market:invoice:42".to_owned()),
        not_before_ms: 2_000,
        expires_at_ms: 15_000,
        max_calls: 2,
        interaction: Some(InteractionId([3; 16])),
        payment: Some(PaymentLimit {
            payment_actions: BTreeSet::from(["payment.send".to_owned()]),
            currency: "USD-CENTS".to_owned(),
            max_spend_atomic: 500,
            allowed_payees: BTreeSet::from([actor(8)]),
        }),
        remaining_delegation_depth: 1,
        policy_epoch: POLICY_EPOCH,
        parent: Some(GrantId([1; 16])),
    }
}

fn payment_effect(id_byte: u8, amount: u128) -> ActionRequest {
    ActionRequest {
        effect_id: EffectId([id_byte; 16]),
        effect_digest: Digest([id_byte; 32]),
        actor: actor(3),
        interaction: Some(InteractionId([3; 16])),
        action: "payment.send".to_owned(),
        resource: "urn:market:invoice:42".to_owned(),
        payment: Some(PaymentRequest {
            currency: "USD-CENTS".to_owned(),
            amount_atomic: amount,
            payee: actor(8),
        }),
    }
}

fn delegated_kernel() -> AuthorityKernel {
    let mut kernel = AuthorityKernel::new(POLICY_EPOCH);
    kernel.install_root(root_grant()).unwrap();
    kernel
        .install_delegated(GrantId([1; 16]), delegated_grant())
        .unwrap();
    kernel
}

#[test]
fn delegation_cannot_expand_any_authority_dimension() {
    let parent = root_grant();
    let baseline = delegated_grant();

    let mut expanded = baseline.clone();
    expanded.actions.insert("admin.delete".to_owned());
    assert!(matches!(
        expanded.verify_attenuation(&parent),
        Err(ProtocolError::AuthorityAmplification("actions expanded"))
    ));

    let mut expanded = baseline.clone();
    expanded.resource = ResourceScope::Prefix("urn:".to_owned());
    assert!(matches!(
        expanded.verify_attenuation(&parent),
        Err(ProtocolError::AuthorityAmplification(
            "resource scope expanded"
        ))
    ));

    let mut expanded = baseline.clone();
    expanded.not_before_ms = parent.not_before_ms - 1;
    assert!(matches!(
        expanded.verify_attenuation(&parent),
        Err(ProtocolError::AuthorityAmplification(
            "validity interval expanded"
        ))
    ));

    let mut expanded = baseline.clone();
    expanded.max_calls = parent.max_calls + 1;
    assert!(matches!(
        expanded.verify_attenuation(&parent),
        Err(ProtocolError::AuthorityAmplification(
            "call allowance increased"
        ))
    ));

    let mut expanded = baseline.clone();
    expanded.interaction = None;
    assert!(matches!(
        expanded.verify_attenuation(&parent),
        Err(ProtocolError::AuthorityAmplification(
            "interaction binding removed or changed"
        ))
    ));

    let mut expanded = baseline.clone();
    expanded.payment.as_mut().unwrap().max_spend_atomic = 1_001;
    assert!(matches!(
        expanded.verify_attenuation(&parent),
        Err(ProtocolError::AuthorityAmplification(
            "spending limit increased"
        ))
    ));

    let mut expanded = baseline.clone();
    expanded.payment.as_mut().unwrap().currency = "EUR-CENTS".to_owned();
    assert!(matches!(
        expanded.verify_attenuation(&parent),
        Err(ProtocolError::AuthorityAmplification(
            "payment currency changed"
        ))
    ));

    let mut expanded = baseline.clone();
    expanded
        .payment
        .as_mut()
        .unwrap()
        .allowed_payees
        .insert(actor(10));
    assert!(matches!(
        expanded.verify_attenuation(&parent),
        Err(ProtocolError::AuthorityAmplification("payee set expanded"))
    ));

    let mut expanded = baseline.clone();
    expanded.payment = None;
    assert!(matches!(
        expanded.verify_attenuation(&parent),
        Err(ProtocolError::AuthorityAmplification(
            "payment requirement removed"
        ))
    ));

    let mut expanded = baseline;
    expanded.remaining_delegation_depth = parent.remaining_delegation_depth;
    assert!(matches!(
        expanded.verify_attenuation(&parent),
        Err(ProtocolError::AuthorityAmplification(
            "delegation depth did not decrease"
        ))
    ));
}

#[test]
fn parent_revocation_invalidates_descendants() {
    let mut kernel = delegated_kernel();
    kernel.revoke(GrantId([1; 16])).unwrap();

    assert_eq!(
        kernel.authorize_effect(GrantId([2; 16]), &payment_effect(4, 100), NOW_MS),
        Err(ProtocolError::GrantRevoked)
    );
}

#[test]
fn policy_epoch_rollover_invalidates_installed_grants() {
    let mut kernel = delegated_kernel();
    kernel.advance_policy_epoch(POLICY_EPOCH + 1).unwrap();

    assert_eq!(
        kernel.authorize_effect(GrantId([2; 16]), &payment_effect(4, 100), NOW_MS),
        Err(ProtocolError::PolicyEpochMismatch)
    );
}

#[test]
fn relationship_cannot_substitute_for_the_granted_subject() {
    let mut kernel = delegated_kernel();
    let mut request = payment_effect(4, 100);
    // The caller may claim any social relationship; the kernel only compares
    // the authenticated actor to the installed grant subject.
    request.actor = actor(99);

    assert_eq!(
        kernel.authorize_effect(GrantId([2; 16]), &request, NOW_MS),
        Err(ProtocolError::InsufficientAuthority("subject mismatch"))
    );
}

#[test]
fn duplicate_effects_are_not_authorized_twice() {
    let mut kernel = delegated_kernel();
    let request = payment_effect(4, 200);

    assert_eq!(
        kernel
            .authorize_effect(GrantId([2; 16]), &request, NOW_MS)
            .unwrap(),
        AuthorizationOutcome::Reserved
    );
    assert_eq!(
        kernel
            .authorize_effect(GrantId([2; 16]), &request, NOW_MS)
            .unwrap(),
        AuthorizationOutcome::Duplicate
    );
    assert_eq!(kernel.usage(GrantId([2; 16])).calls, 1);
    assert_eq!(kernel.usage(GrantId([2; 16])).spent_atomic, 200);

    let mut conflict = request;
    conflict.payment.as_mut().unwrap().amount_atomic = 201;
    assert_eq!(
        kernel.authorize_effect(GrantId([2; 16]), &conflict, NOW_MS),
        Err(ProtocolError::EffectConflict)
    );
}

#[test]
fn spend_and_payee_are_bounded_across_effects() {
    let mut kernel = delegated_kernel();
    assert_eq!(
        kernel
            .authorize_effect(GrantId([2; 16]), &payment_effect(4, 300), NOW_MS)
            .unwrap(),
        AuthorizationOutcome::Reserved
    );

    assert_eq!(
        kernel.authorize_effect(GrantId([2; 16]), &payment_effect(5, 201), NOW_MS),
        Err(ProtocolError::InsufficientAuthority(
            "spending limit exceeded"
        ))
    );

    let mut wrong_payee = payment_effect(6, 1);
    wrong_payee.payment.as_mut().unwrap().payee = actor(9);
    assert_eq!(
        kernel.authorize_effect(GrantId([2; 16]), &wrong_payee, NOW_MS),
        Err(ProtocolError::InsufficientAuthority("payee is not granted"))
    );
}

#[test]
fn action_resource_currency_and_call_count_are_bound() {
    let mut kernel = delegated_kernel();

    let mut wrong_action = payment_effect(4, 1);
    wrong_action.action = "admin.delete".to_owned();
    assert_eq!(
        kernel.authorize_effect(GrantId([2; 16]), &wrong_action, NOW_MS),
        Err(ProtocolError::InsufficientAuthority(
            "action is not granted"
        ))
    );

    let mut wrong_resource = payment_effect(5, 1);
    wrong_resource.resource = "urn:market:invoice:43".to_owned();
    assert_eq!(
        kernel.authorize_effect(GrantId([2; 16]), &wrong_resource, NOW_MS),
        Err(ProtocolError::InsufficientAuthority(
            "resource is outside grant scope"
        ))
    );

    let mut wrong_currency = payment_effect(6, 1);
    wrong_currency.payment.as_mut().unwrap().currency = "EUR-CENTS".to_owned();
    assert_eq!(
        kernel.authorize_effect(GrantId([2; 16]), &wrong_currency, NOW_MS),
        Err(ProtocolError::InsufficientAuthority(
            "payment currency mismatch"
        ))
    );

    kernel
        .authorize_effect(GrantId([2; 16]), &payment_effect(7, 1), NOW_MS)
        .unwrap();
    kernel
        .authorize_effect(GrantId([2; 16]), &payment_effect(8, 1), NOW_MS)
        .unwrap();
    assert_eq!(
        kernel.authorize_effect(GrantId([2; 16]), &payment_effect(9, 1), NOW_MS),
        Err(ProtocolError::InsufficientAuthority(
            "call allowance exhausted"
        ))
    );
}

#[test]
fn payment_actions_require_typed_payment_fields() {
    let mut kernel = delegated_kernel();
    let mut request = payment_effect(4, 100);
    request.payment = None;

    assert_eq!(
        kernel.authorize_effect(GrantId([2; 16]), &request, NOW_MS),
        Err(ProtocolError::InsufficientAuthority(
            "payment metadata required for action"
        ))
    );
}

fn signed_message(
    sequence: u64,
    nonce_byte: u8,
) -> (
    SignedEnvelope,
    Vec<u8>,
    SigningKey,
    SigningKey,
    ReceiveContext,
) {
    let sender = SigningKey::from_bytes(&[11; 32]);
    let receiver = SigningKey::from_bytes(&[12; 32]);
    let payload = b"typed protocol payload".to_vec();
    let session = SessionId([13; 16]);
    let envelope = Envelope {
        protocol_major: 0,
        protocol_minor: 1,
        session,
        interaction: Some(InteractionId([14; 16])),
        sequence,
        nonce: Nonce([nonce_byte; 16]),
        issued_at_ms: NOW_MS - 100,
        expires_at_ms: NOW_MS + 1_000,
        sender: key_id(&sender.verifying_key()),
        audience: key_id(&receiver.verifying_key()),
        policy_epoch: POLICY_EPOCH,
        message_kind: MessageKind::TaskOffer,
        payload_schema: Digest([15; 32]),
        payload_digest: payload_digest(&payload),
        critical_extensions: Vec::new(),
    };
    let signed = SignedEnvelope::sign(envelope, &sender).unwrap();
    let context = ReceiveContext {
        now_ms: NOW_MS,
        expected_session: session,
        local_audience: key_id(&receiver.verifying_key()),
        policy_epoch: POLICY_EPOCH,
        supported_major: 0,
        supported_minor: 1,
        max_clock_skew_ms: 500,
        max_lifetime_ms: 5_000,
        max_payload_bytes: 4_096,
        known_critical_extensions: BTreeSet::new(),
    };
    (signed, payload, sender, receiver, context)
}

#[test]
fn signed_envelope_detects_payload_tampering_and_replay() {
    let (signed, payload, sender, _receiver, context) = signed_message(1, 1);
    let mut guard = EnvelopeGuard::new(32, 100);

    assert_eq!(
        guard.verify_and_record(&signed, b"tampered", &sender.verifying_key(), &context),
        Err(ProtocolError::PayloadDigestMismatch)
    );
    guard
        .verify_and_record(&signed, &payload, &sender.verifying_key(), &context)
        .unwrap();
    assert_eq!(
        guard.verify_and_record(&signed, &payload, &sender.verifying_key(), &context),
        Err(ProtocolError::ReplayNonce)
    );
}

#[test]
fn shared_runtime_signature_vector_matches_rust_kernel() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../conformance/vectors/envelope-v0.json"
    ))
    .unwrap();
    let sender = SigningKey::from_bytes(&[11; 32]);
    let receiver = SigningKey::from_bytes(&[12; 32]);
    let payload = br#"{"relationship":"customer"}"#;
    let envelope = Envelope {
        protocol_major: 0,
        protocol_minor: 1,
        session: SessionId([13; 16]),
        interaction: Some(InteractionId([14; 16])),
        sequence: 1,
        nonce: Nonce([15; 16]),
        issued_at_ms: 1_700_000_000_000,
        expires_at_ms: 1_700_000_060_000,
        sender: key_id(&sender.verifying_key()),
        audience: key_id(&receiver.verifying_key()),
        policy_epoch: POLICY_EPOCH,
        message_kind: MessageKind::TaskOffer,
        payload_schema: payload_digest(b"scopepact.demo.task-offer.v0"),
        payload_digest: payload_digest(payload),
        critical_extensions: Vec::new(),
    };
    let signed = SignedEnvelope::sign(envelope, &sender).unwrap();

    let signature_hex = signed.signature.iter().fold(
        String::with_capacity(signed.signature.len() * 2),
        |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
            output
        },
    );
    assert_eq!(
        signature_hex,
        vector["frame"]["signature"].as_str().unwrap()
    );
}

#[test]
fn envelope_rejects_bad_signature_expiry_and_version() {
    let (mut signed, payload, sender, _receiver, context) = signed_message(1, 1);
    signed.signature[0] ^= 0x80;
    let mut guard = EnvelopeGuard::new(32, 100);
    assert_eq!(
        guard.verify_and_record(&signed, &payload, &sender.verifying_key(), &context),
        Err(ProtocolError::InvalidSignature)
    );

    let (signed, payload, sender, _receiver, mut expired_context) = signed_message(1, 1);
    expired_context.now_ms = signed.envelope.expires_at_ms + 1;
    assert_eq!(
        guard.verify_and_record(&signed, &payload, &sender.verifying_key(), &expired_context),
        Err(ProtocolError::Expired)
    );

    let mut unsupported = signed.envelope.clone();
    unsupported.protocol_major = 1;
    let unsupported = SignedEnvelope::sign(unsupported, &sender).unwrap();
    assert_eq!(
        guard.verify_and_record(&unsupported, &payload, &sender.verifying_key(), &context),
        Err(ProtocolError::UnsupportedVersion { major: 1, minor: 1 })
    );
}

#[test]
fn envelope_rejects_wrong_audience_policy_and_unknown_critical_extension() {
    let (signed, payload, sender, _receiver, mut context) = signed_message(1, 1);
    let mut guard = EnvelopeGuard::new(32, 100);

    context.local_audience = KeyId([99; 32]);
    assert_eq!(
        guard.verify_and_record(&signed, &payload, &sender.verifying_key(), &context),
        Err(ProtocolError::AudienceMismatch)
    );

    context.local_audience = signed.envelope.audience;
    context.policy_epoch += 1;
    assert_eq!(
        guard.verify_and_record(&signed, &payload, &sender.verifying_key(), &context),
        Err(ProtocolError::PolicyEpochMismatch)
    );

    context.policy_epoch = POLICY_EPOCH;
    let mut extended = signed.envelope.clone();
    extended.critical_extensions = vec!["urn:scopepact:critical:unknown".to_owned()];
    let extended = SignedEnvelope::sign(extended, &sender).unwrap();
    assert!(matches!(
        guard.verify_and_record(&extended, &payload, &sender.verifying_key(), &context),
        Err(ProtocolError::UnknownCriticalExtension(_))
    ));
}

#[test]
fn replay_window_allows_bounded_reordering_but_rejects_old_sequences() {
    let mut guard = EnvelopeGuard::new(3, 100);
    for (sequence, nonce) in [(4, 4), (2, 2), (3, 3)] {
        let (signed, payload, sender, _receiver, context) = signed_message(sequence, nonce);
        guard
            .verify_and_record(&signed, &payload, &sender.verifying_key(), &context)
            .unwrap();
    }

    let (old, payload, sender, _receiver, context) = signed_message(1, 1);
    assert_eq!(
        guard.verify_and_record(&old, &payload, &sender.verifying_key(), &context),
        Err(ProtocolError::SequenceTooOld)
    );
}

#[test]
fn interaction_state_machine_fails_closed() {
    let mut interaction = Interaction::default();
    assert!(interaction.transition(InteractionState::Completed).is_err());
    interaction.transition(InteractionState::Accepted).unwrap();
    interaction.transition(InteractionState::Running).unwrap();
    interaction.transition(InteractionState::Completed).unwrap();
    assert!(interaction.transition(InteractionState::Running).is_err());
}

#[test]
fn protobuf_schema_exposes_native_frame_types() {
    let frame = scopepact_core::wire::Frame {
        signed_envelope: None,
        payload: vec![1, 2, 3],
    };
    assert_eq!(frame.payload.as_slice(), &[1, 2, 3]);

    let hello = scopepact_core::wire::AgentHello {
        supported_versions: vec![scopepact_core::wire::ProtocolVersion { major: 0, minor: 1 }],
        codecs: vec!["application/protobuf".to_owned()],
        extensions: Vec::new(),
        max_frame_bytes: 4_096,
        max_concurrent_interactions: 4,
    };
    assert_eq!(hello.supported_versions[0].minor, 1);

    let proof = scopepact_core::wire::IdentityProof {
        challenge_id: vec![1; 16],
        agent_key_id: vec![2; 32],
        principal_credential: Vec::new(),
        workload_credential: Vec::new(),
        transport_binding: vec![3; 32],
        signature: vec![4; 64],
        credential_type: "scopepact-native-ed25519-v0".to_owned(),
    };
    assert_eq!(proof.credential_type, "scopepact-native-ed25519-v0");
}
