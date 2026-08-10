use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use scopepact_core::error::ProtocolError;
use scopepact_core::handshake::{
    AgentHello, ConnectionState, Handshake, HandshakeRole, IdentityChallenge, IdentityProof,
    IdentityProofContext, NATIVE_CREDENTIAL_TYPE, NegotiatedParameters, ProtocolVersion,
};
use scopepact_core::signing::key_id;
use scopepact_core::types::{ChallengeId, Digest, Nonce, SessionId};

fn hello(
    versions: &[(u16, u16)],
    codecs: &[&str],
    extensions: &[&str],
    max_frame_bytes: u64,
    max_concurrent_interactions: u32,
) -> AgentHello {
    AgentHello {
        supported_versions: versions
            .iter()
            .map(|&(major, minor)| ProtocolVersion { major, minor })
            .collect(),
        codecs: codecs.iter().map(ToString::to_string).collect(),
        extensions: extensions.iter().map(ToString::to_string).collect(),
        max_frame_bytes,
        max_concurrent_interactions,
    }
}

fn compatible_hellos() -> (AgentHello, AgentHello) {
    (
        hello(
            &[(0, 1), (0, 2), (1, 0)],
            &["application/cbor", "application/protobuf"],
            &["urn:scopepact:extension:a", "urn:scopepact:extension:b"],
            1_048_576,
            32,
        ),
        hello(
            &[(0, 1), (0, 2)],
            &["application/json", "application/protobuf"],
            &["urn:scopepact:extension:b", "urn:scopepact:extension:c"],
            262_144,
            8,
        ),
    )
}

fn challenge(negotiation: &NegotiatedParameters) -> IdentityChallenge {
    IdentityChallenge {
        id: ChallengeId([4; 16]),
        nonce: Nonce([5; 16]),
        negotiation_digest: negotiation.transcript_digest(),
        accepted_credential_types: BTreeSet::from([NATIVE_CREDENTIAL_TYPE.to_owned()]),
    }
}

fn proof_context(audience_key: &SigningKey) -> IdentityProofContext {
    IdentityProofContext {
        session: SessionId([6; 16]),
        prover_role: HandshakeRole::Initiator,
        audience: key_id(&audience_key.verifying_key()),
        transport_binding: Digest([7; 32]),
    }
}

fn pending_handshake(
    context: IdentityProofContext,
    negotiation: &NegotiatedParameters,
    challenge: &IdentityChallenge,
) -> Handshake {
    let mut handshake = Handshake::default();
    handshake
        .secure_transport(context, negotiation, challenge.clone())
        .unwrap();
    handshake
}

#[test]
fn hello_negotiation_is_deterministic_and_bounded() {
    let (initiator, responder) = compatible_hellos();
    let negotiated = NegotiatedParameters::negotiate(&initiator, &responder).unwrap();

    assert_eq!(negotiated.version(), ProtocolVersion { major: 0, minor: 2 });
    assert_eq!(negotiated.codec(), "application/protobuf");
    assert_eq!(
        negotiated.extensions(),
        &BTreeSet::from(["urn:scopepact:extension:b".to_owned()])
    );
    assert_eq!(negotiated.max_frame_bytes(), 262_144);
    assert_eq!(negotiated.max_concurrent_interactions(), 8);

    let reversed = NegotiatedParameters::negotiate(&responder, &initiator).unwrap();
    assert_ne!(negotiated.transcript_digest(), reversed.transcript_digest());

    let mut changed_initiator = initiator;
    changed_initiator.max_frame_bytes -= 1;
    let changed = NegotiatedParameters::negotiate(&changed_initiator, &responder).unwrap();
    assert_ne!(negotiated.transcript_digest(), changed.transcript_digest());
}

#[test]
fn hello_negotiation_fails_closed() {
    let (initiator, responder) = compatible_hellos();

    let incompatible_version = hello(&[(9, 0)], &["application/protobuf"], &[], 1_024, 1);
    assert_eq!(
        NegotiatedParameters::negotiate(&initiator, &incompatible_version),
        Err(ProtocolError::NoCommonVersion)
    );

    let incompatible_codec = hello(&[(0, 2)], &["application/other"], &[], 1_024, 1);
    assert_eq!(
        NegotiatedParameters::negotiate(&initiator, &incompatible_codec),
        Err(ProtocolError::NoCommonCodec)
    );

    let mut malformed = responder;
    malformed.max_frame_bytes = 0;
    assert!(matches!(
        NegotiatedParameters::negotiate(&initiator, &malformed),
        Err(ProtocolError::Malformed("zero hello resource limit"))
    ));
}

#[test]
fn verified_identity_proof_is_required_for_session_activation() {
    let peer_key = SigningKey::from_bytes(&[1; 32]);
    let local_key = SigningKey::from_bytes(&[2; 32]);
    let (initiator, responder) = compatible_hellos();
    let negotiation = NegotiatedParameters::negotiate(&initiator, &responder).unwrap();
    let challenge = challenge(&negotiation);
    let context = proof_context(&local_key);
    let proof = IdentityProof::sign(
        &peer_key,
        context,
        &challenge,
        &negotiation,
        NATIVE_CREDENTIAL_TYPE,
        b"principal fixture".to_vec(),
        b"workload fixture".to_vec(),
    )
    .unwrap();
    assert_eq!(
        negotiation.transcript_digest().0,
        [
            0x0c, 0xf0, 0x43, 0xda, 0x09, 0x28, 0xca, 0xcd, 0xa2, 0x5e, 0x9a, 0x64, 0x49, 0x2a,
            0xc3, 0x38, 0x4a, 0x15, 0xa1, 0xb5, 0x82, 0x68, 0xee, 0xf9, 0x31, 0xda, 0x79, 0x73,
            0x05, 0x11, 0xea, 0x50,
        ]
    );
    assert_eq!(
        proof.signature,
        [
            0x99, 0x2e, 0xd0, 0x56, 0xd1, 0x8a, 0x53, 0x45, 0xcd, 0x54, 0xd1, 0x60, 0x10, 0x29,
            0x0b, 0x08, 0x27, 0x87, 0x5f, 0xaa, 0x81, 0x56, 0xc6, 0xfd, 0xf5, 0xae, 0x22, 0xc0,
            0x4a, 0x5d, 0xf8, 0xeb, 0x98, 0xb2, 0x89, 0x12, 0x07, 0x41, 0x04, 0x93, 0x84, 0x1f,
            0x02, 0x98, 0x8d, 0xdc, 0x28, 0xe1, 0x62, 0x15, 0xa3, 0xb9, 0x7e, 0xcc, 0x61, 0x3e,
            0xf2, 0xa2, 0x6c, 0x4c, 0x37, 0x6c, 0xf9, 0x07,
        ]
    );

    let mut handshake = Handshake::default();
    assert!(matches!(
        handshake.authenticate_peer(&proof, &peer_key.verifying_key()),
        Err(ProtocolError::InvalidTransition {
            from: "new",
            to: "authenticated"
        })
    ));
    assert!(handshake.authorize().is_err());

    handshake
        .secure_transport(context, &negotiation, challenge)
        .unwrap();
    let peer = handshake
        .authenticate_peer(&proof, &peer_key.verifying_key())
        .unwrap();
    assert_eq!(peer.key_id, key_id(&peer_key.verifying_key()));
    assert_eq!(peer.credential_type, NATIVE_CREDENTIAL_TYPE);
    assert_eq!(peer.principal_credential, b"principal fixture");
    assert_eq!(handshake.state(), ConnectionState::Authenticated);
    assert!(handshake.authenticated_peer().is_some());

    assert!(
        handshake
            .authenticate_peer(&proof, &peer_key.verifying_key())
            .is_err()
    );
    handshake.authorize().unwrap();
    handshake.activate().unwrap();
    assert_eq!(handshake.state(), ConnectionState::Active);
    handshake.close();
    assert!(handshake.authenticated_peer().is_none());
    assert!(handshake.activate().is_err());
}

#[test]
fn identity_proof_binds_transport_session_role_challenge_and_credentials() {
    let peer_key = SigningKey::from_bytes(&[1; 32]);
    let wrong_key = SigningKey::from_bytes(&[9; 32]);
    let local_key = SigningKey::from_bytes(&[2; 32]);
    let (initiator, responder) = compatible_hellos();
    let negotiation = NegotiatedParameters::negotiate(&initiator, &responder).unwrap();
    let challenge = challenge(&negotiation);
    let context = proof_context(&local_key);
    let proof = IdentityProof::sign(
        &peer_key,
        context,
        &challenge,
        &negotiation,
        NATIVE_CREDENTIAL_TYPE,
        b"principal fixture".to_vec(),
        Vec::new(),
    )
    .unwrap();

    let mut handshake = pending_handshake(context, &negotiation, &challenge);
    assert!(matches!(
        handshake.authenticate_peer(&proof, &wrong_key.verifying_key()),
        Err(ProtocolError::SenderKeyMismatch)
    ));

    let mut other_transport = context;
    other_transport.transport_binding = Digest([8; 32]);
    let mut handshake = pending_handshake(other_transport, &negotiation, &challenge);
    assert!(matches!(
        handshake.authenticate_peer(&proof, &peer_key.verifying_key()),
        Err(ProtocolError::TransportBindingMismatch)
    ));

    let mut other_session = context;
    other_session.session = SessionId([8; 16]);
    let mut handshake = pending_handshake(other_session, &negotiation, &challenge);
    assert!(matches!(
        handshake.authenticate_peer(&proof, &peer_key.verifying_key()),
        Err(ProtocolError::InvalidSignature)
    ));

    let mut other_role = context;
    other_role.prover_role = HandshakeRole::Responder;
    let mut handshake = pending_handshake(other_role, &negotiation, &challenge);
    assert!(matches!(
        handshake.authenticate_peer(&proof, &peer_key.verifying_key()),
        Err(ProtocolError::InvalidSignature)
    ));

    let mut other_challenge = challenge.clone();
    other_challenge.id = ChallengeId([8; 16]);
    let mut handshake = pending_handshake(context, &negotiation, &other_challenge);
    assert!(matches!(
        handshake.authenticate_peer(&proof, &peer_key.verifying_key()),
        Err(ProtocolError::ChallengeMismatch)
    ));

    let mut tampered_credential = proof;
    tampered_credential.principal_credential[0] ^= 1;
    let mut handshake = pending_handshake(context, &negotiation, &challenge);
    assert!(matches!(
        handshake.authenticate_peer(&tampered_credential, &peer_key.verifying_key()),
        Err(ProtocolError::InvalidSignature)
    ));
}

#[test]
fn negotiation_downgrade_and_credential_smuggling_are_rejected() {
    let peer_key = SigningKey::from_bytes(&[1; 32]);
    let local_key = SigningKey::from_bytes(&[2; 32]);
    let (initiator, responder) = compatible_hellos();
    let negotiation = NegotiatedParameters::negotiate(&initiator, &responder).unwrap();
    let challenge = challenge(&negotiation);
    let context = proof_context(&local_key);

    let mut downgraded_initiator = initiator;
    downgraded_initiator
        .supported_versions
        .remove(&ProtocolVersion { major: 0, minor: 2 });
    let downgraded = NegotiatedParameters::negotiate(&downgraded_initiator, &responder).unwrap();
    let mut handshake = Handshake::default();
    assert!(matches!(
        handshake.secure_transport(context, &downgraded, challenge.clone()),
        Err(ProtocolError::HandshakeTranscriptMismatch)
    ));

    assert!(matches!(
        IdentityProof::sign(
            &peer_key,
            context,
            &challenge,
            &negotiation,
            "unoffered-bearer-token",
            Vec::new(),
            Vec::new(),
        ),
        Err(ProtocolError::CredentialRejected(
            "credential type was not offered"
        ))
    ));

    assert!(matches!(
        IdentityProof::sign(
            &peer_key,
            context,
            &challenge,
            &negotiation,
            NATIVE_CREDENTIAL_TYPE,
            vec![0; 65 * 1024],
            Vec::new(),
        ),
        Err(ProtocolError::CredentialRejected(
            "identity credential exceeds size limit"
        ))
    ));
}
