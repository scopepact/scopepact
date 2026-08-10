use thiserror::Error;

pub type Result<T> = std::result::Result<T, ProtocolError>;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ProtocolError {
    #[error("malformed protocol value: {0}")]
    Malformed(&'static str),
    #[error("unsupported protocol version {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },
    #[error("peers have no protocol version in common")]
    NoCommonVersion,
    #[error("peers have no payload codec in common")]
    NoCommonCodec,
    #[error("message signature is invalid")]
    InvalidSignature,
    #[error("declared sender does not match the verification key")]
    SenderKeyMismatch,
    #[error("message targets another audience")]
    AudienceMismatch,
    #[error("message belongs to another session")]
    SessionMismatch,
    #[error("message was issued under another policy epoch")]
    PolicyEpochMismatch,
    #[error("message has expired")]
    Expired,
    #[error("message issue time is too far in the future")]
    IssuedInFuture,
    #[error("message validity period exceeds the configured limit")]
    LifetimeTooLong,
    #[error("identity credential rejected: {0}")]
    CredentialRejected(&'static str),
    #[error("identity proof references another challenge")]
    ChallengeMismatch,
    #[error("handshake negotiation transcript mismatch")]
    HandshakeTranscriptMismatch,
    #[error("identity proof belongs to another secure transport")]
    TransportBindingMismatch,
    #[error("payload digest mismatch")]
    PayloadDigestMismatch,
    #[error("payload exceeds the configured size limit")]
    PayloadTooLarge,
    #[error("unknown critical extension: {0}")]
    UnknownCriticalExtension(String),
    #[error("nonce has already been used")]
    ReplayNonce,
    #[error("sequence number has already been used")]
    ReplaySequence,
    #[error("sequence number is outside the replay window")]
    SequenceTooOld,
    #[error("session message limit reached")]
    SessionMessageLimit,
    #[error("invalid state transition from {from} to {to}")]
    InvalidTransition {
        from: &'static str,
        to: &'static str,
    },
    #[error("capability grant is revoked")]
    GrantRevoked,
    #[error("capability does not authorize this effect: {0}")]
    InsufficientAuthority(&'static str),
    #[error("delegation broadens authority: {0}")]
    AuthorityAmplification(&'static str),
    #[error("effect identifier was reused with different content")]
    EffectConflict,
    #[error("numeric accounting overflow")]
    AccountingOverflow,
}
