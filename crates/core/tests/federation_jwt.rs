#![cfg(feature = "jwt-federation")]

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use scopepact_core::error::ProtocolError;
use scopepact_core::federation::{
    ExpectedJwtBinding, JwtFederationPolicy, JwtFederationValidator, SCOPEPACT_SESSION_JWT_TYPE,
};
use scopepact_core::signing::key_id;
use scopepact_core::types::{Digest, KeyId, SessionId};
use serde::Serialize;

const ISSUER: &str = "https://identity.example";
const AUDIENCE: &str = "scopepact:agent-b";
const ISSUER_KEY_ID: &str = "issuer-key-2026-08";
const PROOF_JKT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[derive(Clone, Serialize)]
struct TestClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    nbf: u64,
    iat: u64,
    jti: String,
    cnf: TestConfirmation,
    scopepact: TestBinding,
    #[serde(flatten)]
    extra: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Serialize)]
struct TestConfirmation {
    jkt: String,
}

#[derive(Clone, Serialize)]
struct TestBinding {
    sender_key_id: String,
    session_id: String,
    policy_epoch: u64,
    grant_digest: String,
}

struct Fixture {
    now: u64,
    issuer: SigningKey,
    sender: KeyId,
    session: SessionId,
    grant_digest: Digest,
}

impl Fixture {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sender_key = SigningKey::from_bytes(&[42; 32]);
        Self {
            now,
            issuer: SigningKey::from_bytes(&[41; 32]),
            sender: key_id(&sender_key.verifying_key()),
            session: SessionId([43; 16]),
            grant_digest: Digest([44; 32]),
        }
    }

    fn claims(&self) -> TestClaims {
        TestClaims {
            iss: ISSUER.to_owned(),
            sub: "agent:research-17".to_owned(),
            aud: AUDIENCE.to_owned(),
            exp: self.now + 60,
            nbf: self.now.saturating_sub(1),
            iat: self.now.saturating_sub(1),
            jti: "token-id-00000001".to_owned(),
            cnf: TestConfirmation {
                jkt: PROOF_JKT.to_owned(),
            },
            scopepact: TestBinding {
                sender_key_id: hex::encode(self.sender.0),
                session_id: hex::encode(self.session.0),
                policy_epoch: 7,
                grant_digest: hex::encode(self.grant_digest.0),
            },
            extra: BTreeMap::new(),
        }
    }

    fn policy() -> JwtFederationPolicy {
        JwtFederationPolicy::new(ISSUER, AUDIENCE, ISSUER_KEY_ID)
            .unwrap()
            .with_limits(4_096, 300, 2)
            .unwrap()
    }

    fn validator(&self) -> JwtFederationValidator {
        JwtFederationValidator::new(Self::policy(), self.issuer.verifying_key().to_bytes()).unwrap()
    }

    fn expected(&self) -> ExpectedJwtBinding<'static> {
        ExpectedJwtBinding {
            sender: self.sender,
            session: self.session,
            policy_epoch: 7,
            grant_digest: self.grant_digest,
            proof_key_thumbprint: PROOF_JKT,
            now_unix_secs: self.now,
        }
    }

    fn header() -> Header {
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some(SCOPEPACT_SESSION_JWT_TYPE.to_owned());
        header.kid = Some(ISSUER_KEY_ID.to_owned());
        header
    }

    fn token(&self, header: &Header, claims: &TestClaims) -> String {
        encode(header, claims, &issuer_encoding_key(&self.issuer)).unwrap()
    }
}

#[test]
fn valid_jwt_produces_non_authoritative_identity_evidence() {
    let fixture = Fixture::new();
    let evidence = fixture
        .validator()
        .validate(
            &fixture.token(&Fixture::header(), &fixture.claims()),
            fixture.expected(),
        )
        .unwrap();

    assert_eq!(evidence.issuer, ISSUER);
    assert_eq!(evidence.subject, "agent:research-17");
    assert_eq!(evidence.sender, fixture.sender);
    assert_eq!(evidence.session, fixture.session);
    assert_eq!(evidence.grant_digest, fixture.grant_digest);
}

#[test]
fn wrong_audience_or_issuer_is_rejected() {
    let fixture = Fixture::new();
    let validator = fixture.validator();

    let mut claims = fixture.claims();
    claims.aud = "scopepact:other-agent".to_owned();
    assert!(matches!(
        validator.validate(
            &fixture.token(&Fixture::header(), &claims),
            fixture.expected()
        ),
        Err(ProtocolError::CredentialRejected(
            "JWT signature or registered claim validation failed"
        ))
    ));

    let mut claims = fixture.claims();
    claims.iss = "https://attacker.example".to_owned();
    assert!(matches!(
        validator.validate(
            &fixture.token(&Fixture::header(), &claims),
            fixture.expected()
        ),
        Err(ProtocolError::CredentialRejected(
            "JWT signature or registered claim validation failed"
        ))
    ));
}

#[test]
fn expired_or_excessively_long_credentials_are_rejected() {
    let fixture = Fixture::new();
    let validator = fixture.validator();

    let mut claims = fixture.claims();
    claims.exp = fixture.now.saturating_sub(10);
    assert!(
        validator
            .validate(
                &fixture.token(&Fixture::header(), &claims),
                fixture.expected()
            )
            .is_err()
    );

    let mut claims = fixture.claims();
    claims.exp = fixture.now + 600;
    assert_eq!(
        validator.validate(
            &fixture.token(&Fixture::header(), &claims),
            fixture.expected()
        ),
        Err(ProtocolError::CredentialRejected(
            "JWT validity interval exceeds policy"
        ))
    );
}

#[test]
fn token_type_and_algorithm_confusion_are_rejected() {
    let fixture = Fixture::new();
    let validator = fixture.validator();

    let mut header = Fixture::header();
    header.typ = Some("at+jwt".to_owned());
    assert_eq!(
        validator.validate(
            &fixture.token(&header, &fixture.claims()),
            fixture.expected()
        ),
        Err(ProtocolError::CredentialRejected("JWT type mismatch"))
    );

    let mut header = Header::new(Algorithm::HS256);
    header.typ = Some(SCOPEPACT_SESSION_JWT_TYPE.to_owned());
    header.kid = Some(ISSUER_KEY_ID.to_owned());
    let token = encode(
        &header,
        &fixture.claims(),
        &EncodingKey::from_secret(b"not-an-issuer-key"),
    )
    .unwrap();
    assert_eq!(
        validator.validate(&token, fixture.expected()),
        Err(ProtocolError::CredentialRejected(
            "JWT algorithm is not EdDSA"
        ))
    );
}

#[test]
fn dynamic_key_discovery_headers_are_rejected() {
    let fixture = Fixture::new();
    let mut header = Fixture::header();
    header.jku = Some("https://attacker.example/keys.json".to_owned());

    assert_eq!(
        fixture.validator().validate(
            &fixture.token(&header, &fixture.claims()),
            fixture.expected()
        ),
        Err(ProtocolError::CredentialRejected(
            "JWT contains untrusted header parameters"
        ))
    );
}

#[test]
fn sender_session_epoch_and_grant_bindings_are_enforced() {
    let fixture = Fixture::new();
    let validator = fixture.validator();

    let mut claims = fixture.claims();
    claims.scopepact.sender_key_id = hex::encode([99; 32]);
    assert_eq!(
        validator.validate(
            &fixture.token(&Fixture::header(), &claims),
            fixture.expected()
        ),
        Err(ProtocolError::SenderKeyMismatch)
    );

    let mut claims = fixture.claims();
    claims.scopepact.session_id = hex::encode([99; 16]);
    assert_eq!(
        validator.validate(
            &fixture.token(&Fixture::header(), &claims),
            fixture.expected()
        ),
        Err(ProtocolError::SessionMismatch)
    );

    let mut claims = fixture.claims();
    claims.scopepact.policy_epoch = 8;
    assert_eq!(
        validator.validate(
            &fixture.token(&Fixture::header(), &claims),
            fixture.expected()
        ),
        Err(ProtocolError::PolicyEpochMismatch)
    );

    let mut claims = fixture.claims();
    claims.scopepact.grant_digest = hex::encode([99; 32]);
    assert_eq!(
        validator.validate(
            &fixture.token(&Fixture::header(), &claims),
            fixture.expected()
        ),
        Err(ProtocolError::CredentialRejected(
            "JWT grant digest binding mismatch"
        ))
    );
}

#[test]
fn proof_of_possession_binding_is_enforced() {
    let fixture = Fixture::new();
    let mut claims = fixture.claims();
    claims.cnf.jkt = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned();

    assert_eq!(
        fixture.validator().validate(
            &fixture.token(&Fixture::header(), &claims),
            fixture.expected()
        ),
        Err(ProtocolError::CredentialRejected(
            "JWT proof-key binding mismatch"
        ))
    );
}

#[test]
fn signed_authority_claims_are_rejected_instead_of_granted() {
    let fixture = Fixture::new();
    let mut claims = fixture.claims();
    claims.extra.insert(
        "actions".to_owned(),
        vec!["payment.send".to_owned(), "admin.delete".to_owned()],
    );

    assert!(matches!(
        fixture.validator().validate(
            &fixture.token(&Fixture::header(), &claims),
            fixture.expected()
        ),
        Err(ProtocolError::CredentialRejected(
            "JWT signature or registered claim validation failed"
        ))
    ));
}

#[test]
fn wrong_signature_key_and_oversized_tokens_are_rejected() {
    let fixture = Fixture::new();
    let attacker = SigningKey::from_bytes(&[77; 32]);
    let token = encode(
        &Fixture::header(),
        &fixture.claims(),
        &issuer_encoding_key(&attacker),
    )
    .unwrap();
    assert!(
        fixture
            .validator()
            .validate(&token, fixture.expected())
            .is_err()
    );

    let max_bytes = token.len().saturating_sub(1).max(256);
    let policy = JwtFederationPolicy::new(ISSUER, AUDIENCE, ISSUER_KEY_ID)
        .unwrap()
        .with_limits(max_bytes, 300, 2)
        .unwrap();
    let validator =
        JwtFederationValidator::new(policy, fixture.issuer.verifying_key().to_bytes()).unwrap();
    assert_eq!(
        validator.validate(&token, fixture.expected()),
        Err(ProtocolError::CredentialRejected("JWT exceeds size limit"))
    );
}

fn issuer_encoding_key(signing_key: &SigningKey) -> EncodingKey {
    let mut pkcs8 = Vec::with_capacity(48);
    pkcs8.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    pkcs8.extend_from_slice(&signing_key.to_bytes());
    EncodingKey::from_ed_der(&pkcs8)
}
