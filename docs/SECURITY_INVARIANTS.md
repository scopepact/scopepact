# Security Invariants

These properties are normative goals. The Rust tests cover the portions
implemented in v0.1; later formal models must cover concurrency and networks.

## I1. Authenticated peer

An envelope is accepted only when its signature matches its declared sender
key and it targets the local audience and active session.

## I2. Fresh message

Accepted envelopes are within their validity interval, have bounded lifetime,
use an unseen nonce, and advance the sender's sequence monotonically.

## I3. Downgrade resistance

Unsupported protocol versions and stale policy epochs fail closed. Hello role
order, complete advertisements, selected parameters, and resource limits are
bound into the identity proof.

## I4. No authority amplification

A delegated grant cannot add actions, broaden resources or payees, extend
time, increase calls or spend, change currency, or increase delegation depth.

## I5. Relationship is not authority

Friend, family, customer, organizational, and reputation evidence cannot
authorize an action without a matching capability grant.

## I6. Bounded effect

Every external effect must match the grant's subject, action, resource, time,
interaction, payee, currency, call count, and spending constraints.

## I7. At-most-once effect

An effect identifier is reserved once. An exact retry is identified as a
duplicate and must not execute again. Reusing the identifier with different
content is rejected as a conflict.

## I8. Revocation effective

Revoked grants and grants issued under an obsolete policy epoch are rejected
before an effect is executed.

## I9. No cross-session authority

Session identifiers, audiences, and interaction bindings cannot be silently
reused in another session or interaction.

## I10. Key non-exposure

Protocol APIs accept typed signing operations. Natural-language payloads are
never interpreted as signing instructions or private-key material.

## I11. Secure-channel possession

Peer authentication succeeds only when the identity proof binds the expected
session, prover role, local audience, one-time challenge, negotiation digest,
credentials, and transport exporter. A proof from another connection fails.
